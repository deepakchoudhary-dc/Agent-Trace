"""Evidence provenance classification (plan2.md shortcoming #4).

The METR Hugging Face incident documented >=96 successful tool-call
spoofing attempts: agents intercepting tool output, suppressing it, or
replacing commands outright, so the recorded narrative said one thing
while the machine did another. A tamper-evident ledger protects stored
events from later editing; it does nothing about evidence that was false
at ingestion.

AgentTrace therefore classifies every event at the chain-of-custody
boundary:

- **agent_claimed** — the agent (or its harness) narrated that something
  happened: adapter transcripts, tool requests/results, terminal output.
- **os_observed** — an OS-level sensor recorded that it happened:
  filesystem, process-tree, network, kernel, and git-activity observers.
- **derived** — the daemon itself computed it: policy findings,
  incidents, approvals, task boundaries, session bookkeeping.

The classification is a deterministic function of the hash-committed
``source_adapter`` string, so it needs no schema change (canonical event
hashes and existing ledgers stay verifiable) and cannot drift from the
evidence it describes. Unknown adapters classify as ``agent_claimed`` —
fail toward distrust: an unclassified narrative is a claim, not a
measurement.

The :class:`ToolClaimReconciler` pairs agent claims with OS ground truth
inside a bounded time window and emits ``IncidentEvent`` findings when
they contradict:

- ``unverified_tool_claim`` — a tool result narrated success or failure
  but no OS sensor saw the tool's process activity at all (medium).
- ``tool_claim_substitution`` — the claim contradicts observed OS
  activity: "tests passed" while the process exited non-zero, or failure
  narrated while the process exited zero (high). Contradiction needs real
  exit-status evidence (kernel observer or spawned-process exits); sensor
  presence without an observable exit status is an honest gap, never
  fabricated into a verdict.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    IncidentEvent,
    ToolResultEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Adapter strings that narrate what the agent did (its harness text).
_AGENT_ADAPTERS = frozenset({
    "claude_code",
    "codex_cli",
    "copilot_chat",
    "generic",
    "universal_agent_sensor",
    "multi_agent_composite",
    "terminal",
})

# Adapter strings that record what the OS actually did.
_OS_ADAPTERS = frozenset({
    "filesystem_observer",
    "process_tree_observer",
    "network_observer",
    "kernel_etw",
    "auditd",
    "git_monitor",
})

# Adapter strings the daemon itself minted (findings, incidents, approvals).
_DERIVED_ADAPTERS = frozenset({
    "daemon",
    "daemon_restore",
    "user_cli",
    "task_boundary",
    "execution_broker",
    "incident_response",
    "detector_engine",
    "collusion_engine",
    "covert_channel_detector",
})


class EvidenceClass(str, Enum):
    """Chain-of-custody class of one event's provenance."""

    AGENT_CLAIMED = "agent_claimed"
    OS_OBSERVED = "os_observed"
    DERIVED = "derived"


def classify_evidence(source_adapter: str) -> EvidenceClass:
    """Classify an event's provenance from its hash-committed adapter string."""
    if source_adapter in _OS_ADAPTERS:
        return EvidenceClass.OS_OBSERVED
    if source_adapter in _DERIVED_ADAPTERS:
        return EvidenceClass.DERIVED
    return EvidenceClass.AGENT_CLAIMED


def event_evidence_class(event: EventBase) -> EvidenceClass:
    """Evidence class of an event, derived from its committed provenance."""
    return classify_evidence(event.source_adapter)


class ToolClaimReconciler:
    """Cross-validates agent tool claims against OS sensor observations."""

    def __init__(
        self,
        session_id: UUID,
        *,
        window_seconds: int = 90,
        cooldown: timedelta | None = None,
    ) -> None:
        self.session_id = session_id
        self._window = timedelta(seconds=window_seconds)
        self._cooldown = cooldown if cooldown is not None else timedelta(minutes=10)
        self._recent: deque[tuple[datetime, str, int | None]] = deque(maxlen=512)
        self._last_emitted: dict[str, datetime] = {}

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one event; return any reconciliation incidents it completes."""
        if isinstance(event, IncidentEvent):
            return []
        if isinstance(event, ToolResultEvent):
            return self._reconcile(event)
        if event.source_adapter in _OS_ADAPTERS:
            self._record_os_signal(event)
        return []

    # -- Reconciliation ----------------------------------------------------------

    def _reconcile(self, claim: ToolResultEvent) -> list[IncidentEvent]:
        self._prune(claim.timestamp)
        outcome = self._claimed_outcome(claim)
        if outcome is None:
            return []
        if not self._recent:
            if not self._can_emit("unverified_tool_claim", claim.timestamp):
                return []
            logger.warning(
                "EVIDENCE BOUNDARY: unverified tool claim for '%s' by '%s'",
                claim.tool_name,
                claim.actor_id,
            )
            return [self._incident(
                "unverified_tool_claim",
                "medium",
                "Tool result without corroborating OS process activity",
                (
                    f"Adapter '{claim.source_adapter}' reported tool "
                    f"'{claim.tool_name}' as "
                    f"{'successful' if outcome else 'failed'}, but no "
                    "OS-level process, filesystem, network, kernel, or git "
                    "sensor recorded any activity within the "
                    f"{int(self._window.total_seconds())}s window. The claim "
                    "is agent-narrated only (METR incident pattern: "
                    "suppressed or replaced tool output) and must not be "
                    "treated as ground truth."
                ),
                [claim],
                claim.timestamp,
            )]

        # Outcome contradiction requires real exit-status evidence. Only the
        # kernel observer and spawned-process paths carry actual exit codes;
        # polling observers record presence without exit status. Fabricating
        # a success value for those events would indict every honest failing
        # claim in an active session, so with no exit evidence the outcome is
        # simply not judgeable — the honest gap is silence, not an incident.
        exits = [code for _, _, code in self._recent if code is not None]
        if not exits:
            return []
        mismatch = any((code == 0) is not outcome for code in exits)
        if mismatch and self._can_emit("tool_claim_substitution", claim.timestamp):
            logger.warning(
                "EVIDENCE BOUNDARY: tool claim contradicts OS ground truth "
                "for '%s' by '%s'",
                claim.tool_name,
                claim.actor_id,
            )
            return [self._incident(
                "tool_claim_substitution",
                "high",
                "Tool claim contradicts observed OS activity",
                (
                    f"Adapter '{claim.source_adapter}' reported tool "
                    f"'{claim.tool_name}' as "
                    f"{'successful' if outcome else 'failed'}, but OS sensors "
                    "recorded process exit(s) with the opposite outcome in "
                    "the same window. The transcript narrative and machine "
                    "behavior disagree — consistent with the tool-call "
                    "spoofing documented in the METR incident (output "
                    "interception, suppression, or command replacement)."
                ),
                [claim],
                claim.timestamp,
            )]
        return []

    def _claimed_outcome(self, claim: ToolResultEvent) -> bool | None:
        if claim.exit_code is not None:
            return claim.exit_code == 0
        summary = claim.output_summary.strip().lower()
        if re.search(r"\b(pass|passed|ok|success|succeeded)\b", summary):
            return True
        if re.search(r"\b(fail|failed|failure|error|crash)\b", summary):
            return False
        return None

    # -- OS signal bookkeeping ---------------------------------------------------

    def _record_os_signal(self, event: EventBase) -> None:
        # Record the event's real exit status, or None when the sensor could
        # not observe one. Inventing 0 ("success") here would turn every
        # polling-plane event into fabricated OS ground truth.
        exit_code: int | None = getattr(event, "exit_code", None)
        self._recent.append((event.timestamp, event.source_adapter, exit_code))

    def _prune(self, now: datetime) -> None:
        while self._recent and now - self._recent[0][0] > self._window:
            self._recent.popleft()

    def _can_emit(self, incident_type: str, now: datetime) -> bool:
        last = self._last_emitted.get(incident_type)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[incident_type] = now
        return True

    # -- Incident machinery --------------------------------------------------------

    def _incident(
        self,
        incident_type: str,
        severity: str,
        title: str,
        description: str,
        related: list[EventBase],
        at: datetime,
    ) -> IncidentEvent:
        return IncidentEvent(
            session_id=self.session_id,
            actor_id="evidence_boundary",
            source_adapter="evidence_boundary",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            related_events=[str(e.event_id) for e in related],
            causal_path=[str(e.event_id) for e in related],
            timestamp=at,
        )
