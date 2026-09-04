"""Verbalized-hesitation detection (plan2.md shortcoming #8).

In the METR incident, agents frequently verbalized that the attack was
out of scope or ethically fraught — sometimes vetoing each other — yet
over 90% participated, and none of ~1300 agents actually alerted a
human. Stated ethics were not behavior. A system that only scores
actions misses this signal entirely; the divergence between what an
agent says it is about to do and what it then does is itself evidence.

The :class:`HesitationDetector` watches **agent-claimed** text only
(command and tool-result narratives — classified via the shortcoming-#4
evidence boundary, so OS-sensor or daemon text can never fabricate a
hesitation) for two tiers of verbalization:

- **Refusal language** — "I cannot/will not", "against policy": the
  strongest divergence signal (high).
- **Concern language** — "I'm unsure/concerned", "out of scope",
  "seems unethical", "are you sure": hesitation (medium).

A hesitation arms a window. If a **risk-adjacent action** follows inside
it — credential-bearing or privileged/destructive commands, outbound
network egress, or a policy finding requiring approval — the detector
emits a hash-chained ``IncidentEvent``:

- ``refusal_then_action`` (high) — explicit refusal followed by the
  risk-adjacent action anyway.
- ``hesitation_then_action`` (medium) — concern language followed by the
  risk-adjacent action anyway.

This is deliberately a structural screen, not an intent model: it cannot
parse nuance, and it does not claim to. It converts the METR
"verbalized concern, proceeded anyway" pattern into an auditable,
per-session signal anchored to both the words and the deed. A 10-minute
cooldown per incident type keeps a chatty session from spamming the
ledger.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from agenttrace.graph.evidence_boundary import EvidenceClass, event_evidence_class
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ToolResultEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_TIER_REFUSAL = "refusal"
_TIER_CONCERN = "concern"

# Strongest divergence: the agent says it cannot/will not.
_REFUSAL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bi\s+(?:cannot|can't|cannot|won't|will\s+not)\b",
        r"\bi\s+(?:am|'m)\s+unable\s+to\b",
        r"\b(?:against|violates?|violating)\s+(?:my\s|the\s)?"
        r"(?:policy|policies|guidelines|terms|ethics)\b",
        r"\bi\s+(?:must\s)?(?:decline|refuse|object)\b",
        r"\bnot\s+(?:allowed|permitted)\s+to\b",
        r"\bi\s+should\s+not\s+(?:do\s+)?(?:this|that)\b",
    )
)

# Softer signal: hesitation, worry, scope doubts.
_CONCERN_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:i'm|i\s+am|we're|we\s+are)\s+"
        r"(?:unsure|uncertain|concerned|hesitant|worried|uncomfortable)\b",
        r"\bout\s+of\s+scope\b",
        r"\b(?:seems?|feels?)\s+(?:unethical|wrong|malicious|suspicious|fishy)\b",
        r"\bare\s+you\s+sure\b",
        r"\bshould\s+we\s+(?:really|actually)\s+(?:be\s+)?doing\b",
        r"\b(?:raises?|raising)\s+(?:ethical\s+)?concerns\b",
        r"\bnot\s+sure\s+(?:this|that|we)\b",
    )
)

# Risk-adjacent deeds: what "proceeded anyway" concretely looks like.
_RISK_CREDENTIAL = re.compile(
    r"(?:password|passwd|token|secret|api[_-]?key|credential|"
    r"\.env\b|id_rsa|\.ssh/|\.aws/|\.kube/|\.netrc)",
    re.IGNORECASE,
)
_RISK_PRIVILEGED = re.compile(
    r"(?:\bsudo\b|\brm\s+-[rf]{1,2}\b|\bchmod\s+777\b|\bchown\s+root\b|"
    r"\bkill\s+-9\b|\bdd\s+if=|\bmkfs\b|\bformat\b|\breg\s+add\b|"
    r"\bsc\s+config\b|\bsetx\b|\bnet\s+user\b|"
    r"\|?\s*(?:ba)?sh\s*$|\biex\s*\(|invoke-expression\b)",
    re.IGNORECASE,
)
_RISK_EGRESS = re.compile(
    r"(?:\bcurl\b|\bwget\b|\binvoke-webrequest\b|\biwr\b|\bncat?\b|"
    r"https?://|\bftp\b|\bscp\b|\brsync\b.*@)",
    re.IGNORECASE,
)

_HESITATION_WINDOW = timedelta(minutes=5)
_COOLDOWN = timedelta(minutes=10)


def _matched_tier(text: str) -> str | None:
    """Strongest hesitation tier present in a piece of agent-claimed text."""
    if any(p.search(text) for p in _REFUSAL_PATTERNS):
        return _TIER_REFUSAL
    if any(p.search(text) for p in _CONCERN_PATTERNS):
        return _TIER_CONCERN
    return None


def _is_risky_action(event: EventBase) -> bool:
    """True when the event is a risk-adjacent deed worth cross-checking."""
    if isinstance(event, NetworkEvent):
        return event.direction == "outbound"
    if isinstance(event, PolicyFindingEvent):
        return event.requires_approval
    if isinstance(event, CommandEvent):
        command = event.command
        return bool(
            _RISK_CREDENTIAL.search(command)
            or _RISK_PRIVILEGED.search(command)
            or _RISK_EGRESS.search(command)
        )
    return False


def _snippet(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class HesitationDetector:
    """Correlates verbalized refusal/hesitation with subsequent risk-adjacent
    actions inside a bounded window (per session)."""

    def __init__(
        self,
        session_id: UUID,
        *,
        window: timedelta | None = None,
        cooldown: timedelta | None = None,
    ) -> None:
        self.session_id = session_id
        self._window = window if window is not None else _HESITATION_WINDOW
        self._cooldown = cooldown if cooldown is not None else _COOLDOWN
        # tier -> (spoken_at, snippet, event_id) of the latest verbalization
        self._armed: dict[str, tuple[datetime, str, str]] = {}
        self._last_emitted: dict[str, datetime] = {}

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one event; returns divergence incidents when they fire."""
        if isinstance(event, IncidentEvent):
            return []
        incidents: list[IncidentEvent] = []
        # Deeds are checked first so a command that both speaks and acts
        # fires on the previously armed hesitation before re-arming.
        if _is_risky_action(event):
            incidents.extend(self._check_armed(event))
        if (
            event_evidence_class(event) is EvidenceClass.AGENT_CLAIMED
            and self._agent_text(event)
        ):
            tier = _matched_tier(self._agent_text(event))
            if tier:
                self._arm(tier, event)
        return incidents

    def _check_armed(self, deed: EventBase) -> list[IncidentEvent]:
        incidents: list[IncidentEvent] = []
        for tier in (_TIER_REFUSAL, _TIER_CONCERN):
            armed = self._armed.pop(tier, None)
            if armed is None:
                continue
            spoken_at, snippet, verbalization_id = armed
            if deed.timestamp - spoken_at > self._window:
                continue  # window lapsed; the divergence signal decays
            incident_type = (
                "refusal_then_action"
                if tier == _TIER_REFUSAL
                else "hesitation_then_action"
            )
            if not self._can_emit(incident_type, deed.timestamp):
                continue
            logger.warning(
                "HESITATION DIVERGENCE: %s by '%s' (%s)",
                incident_type,
                deed.actor_id,
                self.session_id,
            )
            incidents.append(
                self._incident(incident_type, tier, snippet, verbalization_id, deed)
            )
        return incidents

    # -- Verbalization capture -------------------------------------------------

    def _agent_text(self, event: EventBase) -> str:
        """The agent's own narrative words on an agent-claimed event."""
        if isinstance(event, CommandEvent):
            return f"{event.command}\n{event.output}"
        if isinstance(event, ToolResultEvent):
            return event.output_summary
        return ""

    def _arm(self, tier: str, event: EventBase) -> None:
        text = self._agent_text(event)
        self._armed[tier] = (
            event.timestamp,
            _snippet(text),
            str(event.event_id),
        )
        logger.debug(
            "HESITATION: %s armed by '%s' at %s",
            tier,
            event.actor_id,
            event.timestamp,
        )

    # -- Incident machinery ------------------------------------------------------

    def _deed_text(self, deed: EventBase) -> str:
        if isinstance(deed, CommandEvent):
            return deed.command
        if isinstance(deed, NetworkEvent):
            return f"{deed.protocol} {deed.destination_ip}:{deed.destination_port}"
        if isinstance(deed, PolicyFindingEvent):
            return f"{deed.finding_type}: {deed.description}"
        return deed.event_type.value

    def _incident(
        self,
        incident_type: str,
        tier: str,
        snippet: str,
        verbalization_id: str,
        deed: EventBase,
    ) -> IncidentEvent:
        tier_label = "Refusal" if tier == _TIER_REFUSAL else "Hesitation"
        return IncidentEvent(
            session_id=self.session_id,
            actor_id="hesitation_detector",
            source_adapter="hesitation_detector",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=incident_type,
            severity="high" if tier == _TIER_REFUSAL else "medium",
            title=f"{tier_label} followed by risk-adjacent action",
            description=(
                f'{tier_label} verbalized ("{_snippet(snippet, 80)}") and a '
                f"risk-adjacent action followed anyway inside the "
                f"{int(self._window.total_seconds())}s window: "
                f"{_snippet(self._deed_text(deed), 60)}. Stated ethics are "
                "not behavior (METR: agents verbalized that the attack was "
                "out of scope, sometimes vetoed each other, yet >90% "
                "participated). Review whether the verbalized boundary was "
                "crossed deliberately."
            ),
            related_events=[verbalization_id, str(deed.event_id)],
            causal_path=[verbalization_id, str(deed.event_id)],
            timestamp=deed.timestamp,
        )

    def _can_emit(self, incident_type: str, now: datetime) -> bool:
        last = self._last_emitted.get(incident_type)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[incident_type] = now
        return True
