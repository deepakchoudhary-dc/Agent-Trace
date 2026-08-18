"""Task boundary engine — scope drift detection.

Converts user requests into structured task contracts, then continuously
checks whether agent actions stay within the defined scope.
"""

from __future__ import annotations

import logging
import re
from fnmatch import fnmatch
from pathlib import Path

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

# Containment-evasion patterns from the 2025–26 sandbox-escape case studies:
# path tricks (/proc/self/root/...), direct dynamic-linker invocation
# (ld-linux.so.2, ld.so — loads code via mmap, bypassing execve gates),
# and explicit sandbox-disable flags.
_SANDBOX_EVASION_PATTERNS = [
    re.compile(r"/proc/self/root", re.IGNORECASE),
    re.compile(r"\bld-linux(?:-x86-64)?\.so\.2?\b", re.IGNORECASE),
    re.compile(r"\bld\.so(?:\.\d+)?\b", re.IGNORECASE),
    re.compile(r"--no-sandbox", re.IGNORECASE),
    re.compile(r"--disable-sandbox", re.IGNORECASE),
    re.compile(r"-no-sandbox", re.IGNORECASE),
    re.compile(r"--unsafe-perm", re.IGNORECASE),
]

# Package-manager / registry operations — the supply-chain attack surface
# (malicious PyPI package incident, dependency-manifest tampering).
_PACKAGE_OPERATION_RE = re.compile(
    r"""(
        ^(?:pip(?:3)?|python|python3|py|conda)\s+(?:-m\s+pip\s+)?(?:install|uninstall)\b
        |^(?:npm|yarn|pnpm)\s+(?:install|add|i|ci|publish)\b
        |^cargo\s+(?:add|install|publish)\b
        |^gem\s+(?:install|push)\b
        |^twine\s+upload\b
        |^go\s+get\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# References to credential material OUTSIDE the workspace — the read side of
# the credential-exfiltration chain (Opus 4.7 credential theft; Claude Code
# CLI shell-injection CVEs).
_CREDENTIAL_PATH_RE = re.compile(
    r"""(
        /etc/(?:passwd|shadow|ssh/|ssl/private|git-credentials)
        |(?:~|%USERPROFILE%|%HOME%)[\\/]\.(?:ssh|aws|gnupg|kube|docker)(?:[\\/]|$)
        |\.git-credentials
        |C:[\\/]Windows[\\/]System32[\\/]config
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# HF intrusion kill-chain patterns (July 2026 technical timeline): cloud
# metadata endpoints (the first credential-gathering step of the pivot) and
# Kubernetes service-account token reads (the exact first commands of the
# in-cluster lateral movement).
_CLOUD_METADATA_RE = re.compile(r"\b169\.254\.169\.254\b", re.IGNORECASE)
_K8S_SA_PATH_RE = re.compile(r"/var/run/secrets/kubernetes\.io/", re.IGNORECASE)

# Payload staging / dropper patterns: obfuscated exec of packed blobs and
# download-then-execute chains (the HF dropper phase: gzip+base64 exec,
# staged downloads to /tmp, chmod +x).
_STAGING_PATTERNS = [
    re.compile(r"exec\s*\(\s*gzip\.decompress\s*\(\s*base64\.b64decode", re.IGNORECASE),
    re.compile(r"base64\s+-d.*\|.*(?:ba)?sh\b", re.IGNORECASE),
    re.compile(r"(?:curl|wget)\s+.*-o\s+/tmp/\S+", re.IGNORECASE),
    re.compile(r"chmod\s+\+x\s+/tmp/\S+", re.IGNORECASE),
]


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

        # Check for sandbox/containment evasion (casestudy Part 5A)
        if any(pat.search(cmd_lower) for pat in _SANDBOX_EVASION_PATTERNS):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.SANDBOX_EVASION,
                severity="critical",
                description=f"Sandbox/containment evasion pattern detected: {command}",
                affected_command=command,
                confidence=0.95,
                evidence=[
                    "Matches known evasion patterns: path tricks, dynamic-linker "
                    "invocation, or sandbox-disable flags"
                ],
            ))

        # Check for package-manager / registry operations (supply chain)
        if _PACKAGE_OPERATION_RE.match(cmd_lower):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.UNEXPECTED_DEPENDENCY,
                severity="high",
                description=f"Package/registry operation detected: {command}",
                affected_command=command,
                confidence=0.9,
                evidence=[
                    "Installing/publishing dependencies changes the supply chain "
                    "and can pull in untrusted code"
                ],
            ))

        # Check for reads of credential material outside the workspace
        if _CREDENTIAL_PATH_RE.search(command):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.CREDENTIAL_ACCESS,
                severity="critical",
                description="Command references credential material outside the workspace",
                affected_command=command,
                confidence=0.92,
                evidence=["Sensitive path (SSH keys, cloud creds, /etc shadow) referenced"],
            ))

        # Cloud metadata endpoint — the HF intrusion's credential-gathering
        # step (the pivot read the pod's IAM role from 169.254.169.254)
        if _CLOUD_METADATA_RE.search(command):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.CREDENTIAL_ACCESS,
                severity="critical",
                description="Command accesses the cloud metadata service (169.254.169.254)",
                affected_command=command,
                confidence=0.95,
                evidence=[
                    "Cloud metadata endpoints expose instance IAM credentials — "
                    "the first credential-gathering step of the HF intrusion pivot"
                ],
            ))

        # Kubernetes service-account token reads — in-cluster credential theft
        if _K8S_SA_PATH_RE.search(command):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.CREDENTIAL_ACCESS,
                severity="critical",
                description="Command reads Kubernetes service-account credentials",
                affected_command=command,
                confidence=0.95,
                evidence=[
                    "/var/run/secrets/kubernetes.io/ holds the pod's projected "
                    "service-account token — reading it is the first step of "
                    "in-cluster lateral movement (HF intrusion)"
                ],
            ))

        # Payload staging / dropper chains
        if any(pat.search(command) for pat in _STAGING_PATTERNS):
            results.append(ScopeDriftResult(
                contract_id=self.contract.contract_id,
                drift_type=DriftType.PAYLOAD_STAGING,
                severity="high",
                description="Payload staging / dropper pattern detected",
                affected_command=command,
                confidence=0.9,
                evidence=[
                    "Packed/obfuscated execution or download-then-execute chain — "
                    "the dropper pattern from the HF intrusion campaign"
                ],
            ))

        # Check allowed tools
        if self.contract.allowed_tools and base_cmd not in self.contract.allowed_tools:
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
