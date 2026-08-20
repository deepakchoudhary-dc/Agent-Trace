"""Policy engine — risk-tiered approval gates.

Evaluates events against configurable security policies. Default policy
observes reads silently and requires approval for destructive operations,
writes outside scope, credential access, privilege escalation, dependency
changes, network egress, and high-impact Git operations.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    GitEvent,
    NetworkEvent,
    PolicyFindingEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.task_contract import TaskContract

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    """What to do when a policy triggers."""

    ALLOW = "allow"  # Silently allow
    LOG = "log"  # Log but allow
    WARN = "warn"  # Warn the user
    PAUSE = "pause"  # Pause and require approval
    BLOCK = "block"  # Block the action


@dataclass
class PolicyRule:
    """A single policy rule that evaluates events."""

    rule_id: str
    name: str
    description: str
    action: PolicyAction = PolicyAction.PAUSE
    severity: str = "medium"
    enabled: bool = True


# Default policy rules
_DEFAULT_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="destructive_file_op",
        name="Destructive File Operation",
        description="File deletion or overwrite of important files",
        action=PolicyAction.PAUSE,
        severity="high",
    ),
    PolicyRule(
        rule_id="write_outside_scope",
        name="Write Outside Task Scope",
        description="File modification outside the task's allowed paths",
        action=PolicyAction.PAUSE,
        severity="medium",
    ),
    PolicyRule(
        rule_id="credential_access",
        name="Credential Access",
        description="Access to files or content containing credentials",
        action=PolicyAction.PAUSE,
        severity="critical",
    ),
    PolicyRule(
        rule_id="privilege_escalation",
        name="Privilege Escalation",
        description="Commands requiring elevated privileges",
        action=PolicyAction.BLOCK,
        severity="critical",
    ),
    PolicyRule(
        rule_id="dependency_change",
        name="Dependency Change",
        description="Modification of dependency manifests or lockfiles",
        action=PolicyAction.PAUSE,
        severity="medium",
    ),
    PolicyRule(
        rule_id="network_egress",
        name="Network Egress",
        description="Network connection to a new or unknown destination",
        action=PolicyAction.PAUSE,
        severity="medium",
    ),
    PolicyRule(
        rule_id="external_state_change",
        name="External State-Changing Request",
        description="State-changing HTTP request (POST/PUT/PATCH/DELETE) to a public/external host",
        action=PolicyAction.PAUSE,
        severity="high",
    ),
    PolicyRule(
        rule_id="high_impact_git",
        name="High-Impact Git Operation",
        description="Force push, rebase, or reset operations",
        action=PolicyAction.PAUSE,
        severity="high",
    ),
    PolicyRule(
        rule_id="script_execution",
        name="Script Execution",
        description="Execution of downloaded or untrusted scripts",
        action=PolicyAction.PAUSE,
        severity="high",
    ),
    PolicyRule(
        rule_id="seal_violation",
        name="Sealed-Environment Egress",
        description="Network egress from an environment declared to have no internet access",
        action=PolicyAction.PAUSE,
        severity="critical",
    ),
    PolicyRule(
        rule_id="destination_allowlist",
        name="Destination Allowlist Violation",
        description="Connection to a destination outside the environment's declared allowlist",
        action=PolicyAction.PAUSE,
        severity="high",
    ),
]

# Dependency manifest filenames
_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock", "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock",
}

# High-impact git commands
_HIGH_IMPACT_GIT = {"force-push", "rebase", "reset", "push --force", "push -f"}


@dataclass
class PolicyEvaluation:
    """Result of evaluating an event against policies."""

    event_id: UUID
    triggered_rules: list[PolicyRule] = field(default_factory=list)
    action: PolicyAction = PolicyAction.ALLOW
    findings: list[PolicyFindingEvent] = field(default_factory=list)
    requires_approval: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.action == PolicyAction.BLOCK

    @property
    def is_paused(self) -> bool:
        return self.action == PolicyAction.PAUSE


class PolicyEngine:
    """Evaluates events against configurable security policies.

    The engine maintains a set of policy rules and evaluates each
    incoming event against them. The most restrictive matching
    action is applied.
    """

    def __init__(
        self,
        session_id: UUID,
        contract: TaskContract | None = None,
        rules: list[PolicyRule] | None = None,
        internet_allowed: bool | None = None,
        allowed_destinations: list[str] | None = None,
        baseline_destinations: set[str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.contract = contract
        self._rules = {r.rule_id: copy.deepcopy(r) for r in (rules or _DEFAULT_RULES)}
        self._known_destinations: set[str] = set(baseline_destinations or ())
        # Declared network boundary (sealed-eval detection)
        self._internet_allowed = internet_allowed
        self._allowed_destinations = set(allowed_destinations or [])

    def evaluate(self, event: EventBase) -> PolicyEvaluation:
        """Evaluate an event against all active policy rules."""
        result = PolicyEvaluation(event_id=event.event_id)

        if isinstance(event, FileMutationEvent):
            self._check_file_policies(event, result)
        elif isinstance(event, CommandEvent):
            self._check_command_policies(event, result)
        elif isinstance(event, NetworkEvent):
            self._check_network_policies(event, result)
        elif isinstance(event, GitEvent):
            self._check_git_policies(event, result)

        # Determine overall action (most restrictive wins)
        if result.triggered_rules:
            actions = [r.action for r in result.triggered_rules]
            for action in (
                PolicyAction.BLOCK,
                PolicyAction.PAUSE,
                PolicyAction.WARN,
                PolicyAction.LOG,
            ):
                if action in actions:
                    result.action = action
                    break
            result.requires_approval = result.action in (PolicyAction.PAUSE, PolicyAction.BLOCK)

        return result

    def _check_file_policies(
        self, event: FileMutationEvent, result: PolicyEvaluation
    ) -> None:
        """Check file mutation events against policies."""
        from pathlib import Path

        file_name = Path(event.file_path).name

        # Destructive operations
        if event.mutation_type == "delete":
            rule = self._rules.get("destructive_file_op")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"File deleted: {event.file_path}", event.file_path,
                ))

        # Dependency changes
        if file_name in _MANIFEST_NAMES:
            rule = self._rules.get("dependency_change")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"Dependency manifest modified: {file_name}", event.file_path,
                ))

        # Write outside scope
        if self.contract and self.contract.allowed_paths:
            from fnmatch import fnmatch

            is_allowed = any(
                fnmatch(event.file_path, p) or p in event.file_path
                for p in self.contract.allowed_paths
            )
            if not is_allowed:
                rule = self._rules.get("write_outside_scope")
                if rule and rule.enabled:
                    result.triggered_rules.append(rule)
                    result.findings.append(self._make_finding(
                        rule, f"Write outside scope: {event.file_path}", event.file_path,
                    ))

        # Credential access detection on sensitive files
        sensitive_patterns = [".env*", "*secret*", "*credential*", "*.pem", "*.key"]
        from fnmatch import fnmatch
        if any(fnmatch(file_name.lower(), pat) for pat in sensitive_patterns):
            rule = self._rules.get("credential_access")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"Credential file access or mutation: {event.file_path}", event.file_path,
                ))

    def _check_command_policies(
        self, event: CommandEvent, result: PolicyEvaluation
    ) -> None:
        """Check command events against policies."""
        cmd = event.command.lower()

        # Privilege escalation
        privilege_cmds = {"sudo", "runas", "su"}
        cmd_base = cmd.split()[0] if cmd.split() else ""
        if cmd_base in privilege_cmds:
            rule = self._rules.get("privilege_escalation")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"Privilege escalation: {event.command}", "",
                    command=event.command,
                ))

        # Script downloads/execution
        if ("curl" in cmd or "wget" in cmd) and ("|" in cmd or "bash" in cmd or "sh" in cmd):
            rule = self._rules.get("script_execution")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"Piped script execution: {event.command}", "",
                    command=event.command,
                ))

        # Credential keyword or token in command line
        cred_keywords = ["passwd", "password", "api_key", "secret_key", "bearer ", "token "]
        if any(k in cmd for k in cred_keywords):
            rule = self._rules.get("credential_access")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, "Credential exposure in command line arguments", "",
                    command=event.command[:80],
                ))

    def _check_network_policies(
        self, event: NetworkEvent, result: PolicyEvaluation
    ) -> None:
        """Check network events against policies."""
        from agenttrace.security.netutil import is_public_ip

        destination = f"{event.destination_ip}:{event.destination_port}"

        # Sealed-environment egress — the eval misconfiguration pattern from
        # the Anthropic CTF incidents (environment declared offline but live
        # on the internet). Any public egress from a sealed env is critical.
        if self._internet_allowed is False and is_public_ip(event.destination_ip):
            rule = self._rules.get("seal_violation")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule,
                    f"Egress from sealed environment (declared offline): {destination}",
                    "",
                ))

        # Destination allowlist — connections outside the declared set
        if (
            self._allowed_destinations
            and is_public_ip(event.destination_ip)
            and event.destination_ip not in self._allowed_destinations
        ):
            rule = self._rules.get("destination_allowlist")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule,
                    f"Destination outside allowlist: {destination}",
                    "",
                ))

        # State-changing requests to public/external hosts — irreversible
        # side effects on real systems (the gym-booking incident pattern).
        method = (event.http_method or "").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE") and is_public_ip(event.destination_ip):
            rule = self._rules.get("external_state_change")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"State-changing request to external host: {destination}", "",
                ))
            # Still register as known to avoid double-flagging below
            self._known_destinations.add(destination)

        if destination not in self._known_destinations:
            rule = self._rules.get("network_egress")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                finding = self._make_finding(
                    rule, f"New network destination: {destination}", "",
                )
                # Structured destination so the daemon can persist this
                # destination into the workspace baseline after approval.
                finding.payload["destination"] = destination
                result.findings.append(finding)
            self._known_destinations.add(destination)

    def _check_git_policies(
        self, event: GitEvent, result: PolicyEvaluation
    ) -> None:
        """Check git events against policies."""
        action = event.git_action.lower()
        if action in _HIGH_IMPACT_GIT:
            rule = self._rules.get("high_impact_git")
            if rule and rule.enabled:
                result.triggered_rules.append(rule)
                result.findings.append(self._make_finding(
                    rule, f"High-impact git operation: {action}", "",
                ))

    def _make_finding(
        self,
        rule: PolicyRule,
        description: str,
        affected_path: str,
        command: str = "",
    ) -> PolicyFindingEvent:
        """Create a PolicyFindingEvent from a triggered rule."""
        return PolicyFindingEvent(
            session_id=self.session_id,
            actor_id="policy_engine",
            source_adapter="policy_engine",
            confidence=ConfidenceLevel.HIGH,
            finding_type=rule.rule_id,
            severity=rule.severity,
            description=description,
            affected_path=affected_path,
            affected_command=command,
            requires_approval=rule.action in (PolicyAction.PAUSE, PolicyAction.BLOCK),
        )

    def add_known_destination(self, destination: str) -> None:
        """Register a known network destination to avoid false positives."""
        self._known_destinations.add(destination)

    def add_known_destinations(self, destinations: set[str]) -> None:
        """Register established destinations (e.g. a persisted baseline)."""
        self._known_destinations.update(destinations)

    def get_rules(self) -> dict[str, PolicyRule]:
        """Get all policy rules."""
        return dict(self._rules)

    def update_rule(self, rule_id: str, **kwargs: Any) -> bool:
        """Update a policy rule's properties."""
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        return True
