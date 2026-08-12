"""Task boundary engine — scope drift detection.

Converts user requests into structured task contracts, then continuously
checks whether agent actions stay within the defined scope.
"""

from __future__ import annotations

import logging
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.models.events import ConfidenceLevel, EventBase, PolicyFindingEvent
from agenttrace.models.task_contract import (
    DriftType,
    RiskLevel,
    ScopeDriftResult,
    TaskContract,
)

logger = logging.getLogger(__name__)

# Commands that indicate destructive or risky operations
_DESTRUCTIVE_COMMANDS = {
    "rm", "del", "rmdir", "rd", "format",
    "drop", "truncate", "delete",
}

_PRIVILEGE_COMMANDS = {
    "sudo", "runas", "su", "chmod", "chown",
    "net user", "net localgroup", "icacls",
}

_NETWORK_COMMANDS = {
    "curl", "wget", "ssh", "scp", "ftp",
    "invoke-webrequest", "invoke-restmethod",
}


class TaskBoundaryEngine:
    """Detects scope drift by comparing actions against the task contract.

    Each check returns a list of drift results. The caller (daemon/policy
    engine) decides whether to block, warn, or require approval.
    """

    def __init__(self, contract: TaskContract) -> None:
        self.contract = contract

    def check_file_mutation(
        self,
        file_path: str,
        mutation_type: str,
    ) -> ScopeDriftResult | None:
        """Check if a file mutation is within scope."""
        # Check prohibited paths
        for pattern in self.contract.prohibited_paths:
            if fnmatch(file_path, pattern) or pattern in file_path:
                return ScopeDriftResult(
                    contract_id=self.contract.contract_id,
                    drift_type=DriftType.FILE_OUTSIDE_SCOPE,
                    severity="high",
                    description=f"File mutation in prohibited path: {file_path}",
                    affected_path=file_path,
                    confidence=1.0,
                    evidence=[f"Matches prohibited pattern: {pattern}"],
                )

        # Check if within allowed paths (if specified)
        if self.contract.allowed_paths:
            is_allowed = any(
                fnmatch(file_path, pattern) or pattern in file_path
                for pattern in self.contract.allowed_paths
            )
            if not is_allowed:
                return ScopeDriftResult(
                    contract_id=self.contract.contract_id,
                    drift_type=DriftType.FILE_OUTSIDE_SCOPE,
                    severity="medium",
                    description=f"File mutation outside allowed paths: {file_path}",
                    affected_path=file_path,
                    confidence=0.8,
                    evidence=[
                        f"Not matched by any allowed pattern: {self.contract.allowed_paths}"
                    ],
                )

        return None

    def check_command(self, command: str) -> list[ScopeDriftResult]:
        """Check a command for scope drift and risk."""
        results: list[ScopeDriftResult] = []
        cmd_lower = command.lower().strip()
        cmd_parts = cmd_lower.split()
        base_cmd = cmd_parts[0] if cmd_parts else ""

        # Check for destructive commands
        if base_cmd in _DESTRUCTIVE_COMMANDS:
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.DESTRUCTIVE_OPERATION,
                severity="high",
                description=f"Destructive command detected: {command}",
                affected_command=command,
                confidence=0.95,
                evidence=[f"Command '{base_cmd}' is classified as destructive"],
            ))

        # Check for privilege escalation
        if base_cmd in _PRIVILEGE_COMMANDS:
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.PRIVILEGE_ESCALATION,
                severity="critical",
                description=f"Privilege escalation detected: {command}",
                affected_command=command,
                confidence=0.95,
                evidence=[f"Command '{base_cmd}' requires elevated privileges"],
            ))

        # Check for network egress
        if base_cmd in _NETWORK_COMMANDS:
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.NETWORK_EGRESS,
                severity="medium",
                description=f"Network egress command: {command}",
                affected_command=command,
                confidence=0.9,
                evidence=[f"Command '{base_cmd}' performs network operations"],
            ))

        # Check allowed tools
        if self.contract.allowed_tools:
            if base_cmd not in self.contract.allowed_tools:
                results.append(ScopeDriftResult(
                    contract_id=self.contract.contract_id,
                    drift_type=DriftType.SEMANTIC_DRIFT,
                    severity="low",
                    description=f"Command not in allowed tools: {base_cmd}",
                    affected_command=command,
                    confidence=0.7,
                    evidence=[
                        f"Tool '{base_cmd}' not in allowed list: {self.contract.allowed_tools}"
                    ],
                ))

        return results

    def check_dependency_change(
        self,
        file_path: str,
        before_content: str,
        after_content: str,
    ) -> ScopeDriftResult | None:
        """Check if a dependency file change is expected."""
        manifest_names = {
            "package.json", "requirements.txt", "pyproject.toml",
            "go.mod", "Cargo.toml", "Gemfile", "composer.json",
        }
        file_name = Path(file_path).name

        if file_name in manifest_names:
            return ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.UNEXPECTED_DEPENDENCY,
                severity="medium",
                description=f"Dependency manifest modified: {file_name}",
                affected_path=file_path,
                confidence=0.85,
                evidence=[f"Manifest file '{file_name}' was modified"],
            )

        return None

    def check_credential_access(self, content: str) -> ScopeDriftResult | None:
        """Check if content appears to access or contain credentials."""
        credential_patterns = [
            re.compile(r"(?:password|passwd|pwd)\s*[:=]", re.IGNORECASE),
            re.compile(r"(?:api[_-]?key|apikey)\s*[:=]", re.IGNORECASE),
            re.compile(r"(?:secret|token)\s*[:=]", re.IGNORECASE),
            re.compile(r"(?:access[_-]?key|secret[_-]?key)\s*[:=]", re.IGNORECASE),
            re.compile(r"BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY", re.IGNORECASE),
        ]

        for pattern in credential_patterns:
            if pattern.search(content):
                return ScopeDriftResult(
                    contract_id=self.contract.contract_id,
                    drift_type=DriftType.CREDENTIAL_ACCESS,
                    severity="critical",
                    description="Credential access or exposure detected",
                    confidence=0.9,
                    evidence=[f"Pattern match: {pattern.pattern}"],
                )

        return None

    def evaluate_risk(self, drifts: list[ScopeDriftResult]) -> RiskLevel:
        """Evaluate overall risk from a collection of drift results."""
        if not drifts:
            return RiskLevel.LOW

        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_score = max(
            severity_scores.get(d.severity, 0) for d in drifts
        )

        if max_score >= 4:
            return RiskLevel.CRITICAL
        if max_score >= 3:
            return RiskLevel.HIGH
        if max_score >= 2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
