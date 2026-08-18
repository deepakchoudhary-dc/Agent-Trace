"""Incident correlation engine — detects multi-stage agent attack patterns.

Maps the failure modes documented in the 2025–26 sandbox-escape case studies
(``casestudy.md``) onto real-time event streams:

- **credential_exfiltration** — credential-access finding followed by network
  egress (Anthropic's Opus 4.7 / Mythos 5 incidents, Claude Code CLI CVEs).
- **sandbox_escape_attempt** — a chain of boundary violations (privilege
  escalation, out-of-scope writes, sandbox-evasion commands, egress) within a
  short window (OpenAI's ExploitGym escape, Claude Code denylist/bubblewrap
  escapes).
- **supply_chain_tampering** — dependency/package changes correlated with
  network activity (Mythos 5's booby-trapped PyPI package).
- **external_state_change** — state-changing HTTP requests (POST/PUT/PATCH/
  DELETE) to public, non-sandbox hosts (the Australia gym booking incident).
- **approval_fatigue** — a burst of approvals in a short window, the
  rubber-stamp failure mode from the Claude Code denylist escape.
- **unexpected_egress** — network egress from an environment *declared* to
  have no internet access (or outside a declared destination allowlist) —
  the exact "eval said no internet but had internet" misconfiguration
  behind the Anthropic CTF incidents, made detectable at runtime.

Incidents are advisory, evidence-backed records: every incident carries the
event IDs of its constituent evidence and is itself appended to the
hash-chained ledger so the correlation is auditable.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import (
    ApprovalEvent,
    ConfidenceLevel,
    EventBase,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
)
from agenttrace.security.netutil import is_public_ip

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

logger = logging.getLogger(__name__)

# Correlation windows (seconds)
_EXFILTRATION_WINDOW_SECONDS = 60
_GENERAL_WINDOW_SECONDS = 120
_FATIGUE_WINDOW_SECONDS = 120
_FATIGUE_THRESHOLD = 3

# Cooldown between identical incident types (prevents spam)
_INCIDENT_COOLDOWN = timedelta(minutes=5)

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Finding types that indicate containment/boundary violations
_ESCAPE_FINDING_TYPES = {
    "privilege_escalation",
    "write_outside_scope",
    "file_outside_scope",
    "sandbox_evasion",
    "network_egress",
}

_SUPPLY_CHAIN_FINDING_TYPES = {"unexpected_dependency", "dependency_change"}


class IncidentCorrelationEngine:
    """Correlates events/findings into multi-stage incident records."""

    def __init__(
        self,
        session_id: UUID,
        internet_allowed: bool | None = None,
        allowed_destinations: list[str] | None = None,
    ) -> None:
        self.session_id = session_id
        # Declared network boundary (sealed-eval detection)
        self._internet_allowed = internet_allowed
        self._allowed_destinations = set(allowed_destinations or [])
        # Rolling log of recent events/findings within the correlation window
        self._recent: deque[EventBase] = deque(maxlen=256)
        self._last_emitted: dict[str, datetime] = {}

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed an event into the engine; return incidents it completes."""
        # Incident events themselves are not further correlated
        if isinstance(event, IncidentEvent):
            return []

        self._recent.append(event)
        self._prune()

        incidents: list[IncidentEvent] = []
        incidents.extend(self._check_credential_exfiltration())
        incidents.extend(self._check_sandbox_escape())
        incidents.extend(self._check_supply_chain())
        incidents.extend(self._check_external_state_change())
        incidents.extend(self._check_approval_fatigue())
        incidents.extend(self._check_unexpected_egress())
        return incidents

    # -- Helpers --

    def _prune(self) -> None:
        """Drop events outside the longest correlation window."""
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=_GENERAL_WINDOW_SECONDS
        )
        while self._recent and self._recent[0].timestamp < cutoff:
            self._recent.popleft()

    def _events_of_type(self, *types: Any) -> list[EventBase]:
        """Events in the window of the given types (subclass-checked)."""
        return [e for e in self._recent if isinstance(e, types)]

    def _findings_with_types(self, finding_types: set[str]) -> list[PolicyFindingEvent]:
        return [
            e for e in self._recent
            if isinstance(e, PolicyFindingEvent) and e.finding_type in finding_types
        ]

    def _can_emit(self, incident_type: str) -> bool:
        now = datetime.now(timezone.utc)
        last = self._last_emitted.get(incident_type)
        if last and (now - last) < _INCIDENT_COOLDOWN:
            return False
        self._last_emitted[incident_type] = now
        return True

    def _make_incident(
        self,
        incident_type: str,
        severity: str,
        title: str,
        description: str,
        related_events: Sequence[EventBase],
    ) -> IncidentEvent:
        return IncidentEvent(
            session_id=self.session_id,
            actor_id="incident_engine",
            source_adapter="incident_engine",
            confidence=ConfidenceLevel.HIGH,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            related_events=[str(e.event_id) for e in related_events],
            causal_path=[str(e.event_id) for e in related_events],
        )

    # -- Patterns --

    def _check_credential_exfiltration(self) -> list[IncidentEvent]:
        """Credential finding + network egress within a short window."""
        cred_findings = self._findings_with_types(
            {"credential_access", "credential_exposure"}
        )
        net_events = self._events_of_type(NetworkEvent)
        if not cred_findings or not net_events:
            return []

        for f in cred_findings:
            for n in net_events:
                if not isinstance(n, NetworkEvent):
                    continue
                delta = abs((n.timestamp - f.timestamp).total_seconds())
                if delta <= _EXFILTRATION_WINDOW_SECONDS:
                    if not self._can_emit("credential_exfiltration"):
                        return []
                    logger.warning(
                        "INCIDENT credential_exfiltration: finding %s + network %s",
                        f.event_id,
                        n.event_id,
                    )
                    return [self._make_incident(
                        "credential_exfiltration",
                        "critical",
                        "Possible credential exfiltration",
                        (
                            f"Credential access ({f.finding_type}) was followed by "
                            f"a network connection to {n.destination_ip}:{n.destination_port} "
                            "within the correlation window — the pattern of an "
                            "exfiltration chain."
                        ),
                        [f, n],
                    )]
        return []

    def _check_sandbox_escape(self) -> list[IncidentEvent]:
        """≥2 distinct containment violations within the window."""
        findings = self._findings_with_types(_ESCAPE_FINDING_TYPES)
        distinct = {f.finding_type for f in findings}
        if len(distinct) < 2:
            return []
        if not self._can_emit("sandbox_escape_attempt"):
            return []
        logger.warning(
            "INCIDENT sandbox_escape_attempt: %s", sorted(distinct)
        )
        return [self._make_incident(
            "sandbox_escape_attempt",
            "critical",
            "Sandbox escape attempt",
            (
                "Multiple containment boundaries were crossed in sequence: "
                + ", ".join(sorted(distinct))
                + ". This matches the multi-stage escape pattern observed in "
                "the 2025–26 sandbox-escape incidents."
            ),
            findings,
        )]

    def _check_supply_chain(self) -> list[IncidentEvent]:
        """Dependency/package change correlated with network activity."""
        findings = self._findings_with_types(_SUPPLY_CHAIN_FINDING_TYPES)
        net_events = self._events_of_type(NetworkEvent)
        if not findings or not net_events:
            return []
        if not self._can_emit("supply_chain_tampering"):
            return []
        return [self._make_incident(
            "supply_chain_tampering",
            "high",
            "Supply-chain activity",
            (
                "A dependency/package change was detected alongside network "
                "activity — the signature of package installation, publication, "
                "or tampering (see the Mythos 5 malicious-PyPI incident)."
            ),
            findings + net_events,
        )]

    def _check_external_state_change(self) -> list[IncidentEvent]:
        """State-changing HTTP request to a public (real-world) host."""
        for e in self._recent:
            if not isinstance(e, NetworkEvent):
                continue
            method = (e.http_method or "").upper()
            if method in _STATE_CHANGING_METHODS and is_public_ip(e.destination_ip):
                if not self._can_emit("external_state_change"):
                    return []
                logger.warning(
                    "INCIDENT external_state_change: %s %s:%s",
                    method,
                    e.destination_ip,
                    e.destination_port,
                )
                return [self._make_incident(
                    "external_state_change",
                    "high",
                    f"State-changing request to external host ({method})",
                    (
                        f"{method} to {e.destination_ip}:{e.destination_port} — an "
                        "irreversible side effect on a real external system, the "
                        "failure mode of the Australia gym-booking incident."
                    ),
                    [e],
                )]
        return []

    def _check_unexpected_egress(self) -> list[IncidentEvent]:
        """Egress from a sealed environment or beyond the destination allowlist.

        This is the detectable form of the misconfiguration behind the
        Anthropic CTF incidents: an environment declared to have no internet
        access that actually does — the moment the agent reaches the open
        internet is the moment a sealed-eval violation is proven.
        """
        for e in self._recent:
            if not isinstance(e, NetworkEvent):
                continue
            if not is_public_ip(e.destination_ip):
                continue

            if self._internet_allowed is False:
                if not self._can_emit("unexpected_egress"):
                    return []
                logger.warning(
                    "INCIDENT unexpected_egress: egress from sealed env to %s:%s",
                    e.destination_ip,
                    e.destination_port,
                )
                return [self._make_incident(
                    "unexpected_egress",
                    "critical",
                    "Egress from sealed environment",
                    (
                        f"Network egress to {e.destination_ip}:{e.destination_port} "
                        "from an environment declared to have no internet access — "
                        "the eval-seal misconfiguration pattern from the Anthropic "
                        "CTF incidents, detected at runtime."
                    ),
                    [e],
                )]

            if self._allowed_destinations and e.destination_ip not in self._allowed_destinations:
                if not self._can_emit("unexpected_egress"):
                    return []
                logger.warning(
                    "INCIDENT unexpected_egress: %s outside allowlist",
                    e.destination_ip,
                )
                return [self._make_incident(
                    "unexpected_egress",
                    "high",
                    "Destination outside declared allowlist",
                    (
                        f"Connection to {e.destination_ip}:{e.destination_port} "
                        "outside the environment's declared destination allowlist."
                    ),
                    [e],
                )]
        return []

    def _check_approval_fatigue(self) -> list[IncidentEvent]:
        """Burst of approvals in a short window (rubber-stamp risk)."""
        approvals = [
            e for e in self._recent
            if isinstance(e, ApprovalEvent) and e.approved
        ]
        if len(approvals) < _FATIGUE_THRESHOLD:
            return []
        newest = max(a.timestamp for a in approvals)
        oldest = min(a.timestamp for a in approvals)
        if (newest - oldest).total_seconds() > _FATIGUE_WINDOW_SECONDS:
            return []
        if not self._can_emit("approval_fatigue"):
            return []
        return [self._make_incident(
            "approval_fatigue",
            "medium",
            "Approval fatigue / rubber-stamp risk",
            (
                f"{len(approvals)} approvals were granted within "
                f"{_FATIGUE_WINDOW_SECONDS}s — the consent-fatigue failure mode "
                "that let sandbox-escape prompts get a single 'yes'."
            ),
            approvals,
        )]

    def reset(self) -> None:
        """Clear correlation state (e.g., on session restart)."""
        self._recent.clear()
        self._last_emitted.clear()
