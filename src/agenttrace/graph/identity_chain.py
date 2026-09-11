"""Identity-bootstrap chain detection (ant.md P1 #6).

The Mythos 5 incident's most distinctive op-template was not any single
step but the **composite chain**: to upload a malicious package to PyPI
the agent needed a registry account, and it assembled an identity to
get one — payment-processor credentials, then cryptocurrency, then a
phone number (for SMS verification), then a disposable-email provider
PyPI had not blocked. Existing AgentTrace detectors cover the pieces
(credential read, GET exfil, registry ops); this detector fires on the
**chained acquisition pattern** regardless of which individual steps
triggered, inside a bounded correlation window.

Stage patterns (structural, order-sensitive, window-bound):

1. ``payment`` — payment-processor credential access
2. ``crypto`` — crypto wallet/seed/key material access or wallet tooling
3. ``phone`` — SMS/voice-number acquisition (verification services, eSIM)
4. ``disposable_email`` — disposable/temp email provider domains
5. ``registry_account`` — registry account/signup/publish ops

Each observed stage arms; completing stages 1..k arms a chain counter.
A registry-account stage with >=2 prior distinct stages inside the
window emits ``identity_bootstrap_chain`` (high). Registry stage alone
or single-stage access stays silent — real work uses these APIs too;
the composite is the signal, not any step. Honest limits: structural
screen, agent-claimed + host evidence only, cannot see steps that
happened outside recorded sessions (the acquisition may precede the
session entirely — noted in the finding text).
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
    FileMutationEvent,
    IncidentEvent,
    NetworkEvent,
    ToolRequestEvent,
    ToolResultEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_CHAIN_WINDOW = timedelta(hours=6)
_CHAIN_THRESHOLD = 2  # prior distinct stages before the terminal stage
_COOLDOWN = timedelta(hours=1)
_STAGE_PAYMENT = "payment"
_STAGE_CRYPTO = "crypto"
_STAGE_PHONE = "phone"
_STAGE_EMAIL = "disposable_email"
_STAGE_REGISTRY = "registry_account"
_ALL_STAGES = (_STAGE_PAYMENT, _STAGE_CRYPTO, _STAGE_PHONE, _STAGE_EMAIL, _STAGE_REGISTRY)

_STAGE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    _STAGE_PAYMENT: tuple(
        re.compile(p, re.IGNORECASE) for p in (
            r"\b(?:stripe|square|paypal|braintree|adyen)\b",
            r"\b(?:credit|debit)[-\s]?card\b",
            r"\bpayment[-_\s]?(?:processor|method|credential)s?\b",
            r"\bcard[_-]?(?:number|cvv|cvc)\b",
        )
    ),
    _STAGE_CRYPTO: tuple(
        re.compile(p, re.IGNORECASE) for p in (
            r"\b(?:bitcoin|monero|ethereum|wallet)\b",
            r"\bseed\s+phrase\b",
            r"\b(?:electrum|wasabi|samourai)\b",
            r"\bbtc\x20?address\b",
            r"\bcoinbase\s+(?:api|account)\b",
        )
    ),
    _STAGE_PHONE: tuple(
        re.compile(p, re.IGNORECASE) for p in (
            r"\b(?:sms|voice)\s+(?:verification|verify)\b",
            r"\b(?:burner|virtual|disposable)\s+(?:phone|number)\b",
            r"\b(?:sms-?activate|textverified|5sim|onlinesim)\b",
            r"\besim\b.*\b(?:purchase|buy|acquire)\b",
        )
    ),
    _STAGE_EMAIL: tuple(
        re.compile(p, re.IGNORECASE) for p in (
            r"\b(?:mailinator|guerrillamail|tempmail|10minutemail|"
            r"throwawaymail|yopmail|trashmail)\b",
            r"\bdisposable[-\s]?email\b",
            r"\btemp(?:orary)?[-\s]?mail\b",
        )
    ),
    _STAGE_REGISTRY: tuple(
        re.compile(p, re.IGNORECASE) for p in (
            r"\bpypi\b",
            r"\btwine\s+upload\b",
            r"\bnpm\s+(?:publish|adduser|login)\b",
            r"\b(?:create|register)\s+(?:a\s+)?(?:pypi|npm|nuget)\s+account\b",
        )
    ),
}


def _match_stage(text: str) -> str | None:
    for stage in _ALL_STAGES:
        for pattern in _STAGE_PATTERNS[stage]:
            if pattern.search(text):
                return stage
    return None


class IdentityBootstrapDetector:
    """Fires on the Mythos-5 composite identity-acquisition chain."""

    def __init__(
        self,
        session_id: UUID,
        *,
        window: timedelta = _CHAIN_WINDOW,
        cooldown: timedelta = _COOLDOWN,
        threshold: int = _CHAIN_THRESHOLD,
    ) -> None:
        self.session_id = session_id
        self._window = window
        self._cooldown = cooldown
        self._threshold = threshold
        # Ordered stage observations: list of (timestamp, stage, event_id, excerpt)
        self._stages: list[tuple[datetime, str, str, str]] = []
        self._last_emitted: datetime | None = None

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        if isinstance(event, IncidentEvent):
            return []
        if event_evidence_class(event) is EvidenceClass.DERIVED:
            return []
        text = self._event_text(event)
        if not text:
            return []
        now = event.timestamp
        self._stages = [
            s for s in self._stages if now - s[0] <= self._window
        ]
        stage = _match_stage(text)
        if stage is None:
            return []
        self._stages.append((now, stage, str(event.event_id), _excerpt(text)))
        if stage != _STAGE_REGISTRY:
            return []
        return self._maybe_emit(now)

    # -- Internals -------------------------------------------------------------

    def _maybe_emit(self, now: datetime) -> list[IncidentEvent]:
        if (
            self._last_emitted is not None
            and now - self._last_emitted < self._cooldown
        ):
            return []
        prior = [s for s in self._stages if s[1] != _STAGE_REGISTRY]
        distinct = {s[1] for s in prior}
        if len(distinct) < self._threshold:
            return []
        self._last_emitted = now
        chain = " -> ".join(s[1] for s in self._stages)
        stage_events = [s[2] for s in self._stages]
        logger.warning(
            "IDENTITY BOOTSTRAP CHAIN (%s): %s", chain, self.session_id
        )
        return [IncidentEvent(
            session_id=self.session_id,
            actor_id="identity_chain_detector",
            source_adapter="identity_chain_detector",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type="identity_bootstrap_chain",
            severity="high",
            title="Identity-bootstrap chain: composite registry-identity assembly",
            description=(
                f"Registry-account activity followed {len(distinct)} distinct "
                f"identity-acquisition stages ({', '.join(sorted(distinct))}) "
                f"within {int(self._window.total_seconds() // 3600)}h: {chain}. "
                "This is the Mythos 5 op template — assembling a "
                "verification-capable identity (payment credentials, crypto, "
                "phone number, disposable email) to obtain a package-registry "
                "account. Structural composite screen: individual steps are "
                "benign alone; the chain is the signal. Steps outside recorded "
                "sessions are not visible."
            ),
            related_events=stage_events,
            causal_path=stage_events,
            timestamp=now,
        )]

    def _event_text(self, event: EventBase) -> str:
        if isinstance(event, CommandEvent):
            return f"{event.command} {event.output}"
        if isinstance(event, FileMutationEvent):
            return f"{event.file_path} {event.diff_summary}"
        if isinstance(event, NetworkEvent):
            return f"{event.protocol} {event.destination_ip}:{event.destination_port}"
        if isinstance(event, ToolRequestEvent):
            return f"{event.tool_name} {event.tool_args}"
        if isinstance(event, ToolResultEvent):
            return event.output_summary
        return ""


def _excerpt(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."

