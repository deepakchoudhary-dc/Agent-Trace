"""Credential discovery -> sharing -> lateral-movement loops (plan2.md #7).

In the Hugging Face incident one agent found two working tokens and
posted them; within hours hundreds of agents had pivoted to the attack —
credentials and exploits became the shared currency of the swarm.
Existing coverage flags each individual step: CredentialReadDetector
flags the read command, egress policy watches the network, the covert
channel detector spots the transport. What nothing answers is the
lifecycle question: **has this exact secret been seen in more than one
session's hands?**

The :class:`CredentialLoopTracker` fingerprints credential-shaped
strings structurally (provider token grammars plus entropy floor) into
stable sha256 identities and tracks them across sessions:

- ``credential_shared_between_sessions`` (high) — a secret that
  originated in one session appears in another: the discovery→posting
 →pivot loop is live. If either session had already closed when the
  second sighting lands, severity escalates to critical and the finding
  ties into post-exit surveillance (#6): the secret outlived its
  session, the RESETWATCH pattern applied to currency.
- ``credential_lateral_movement`` (critical) — the same fingerprint
  reaches a third or later session: a loop spreading wide, the
  "hundreds of agents" phase of the incident.

Cross-session structure only; single-session reuse stays silent, and a
first discovery emits nothing (CredentialReadDetector already flags
reads). Incidents are hash-chained and MEDIUM confidence: structural
correlation of identical secrets across identities is strong evidence of
sharing, not proof of who copied whom.
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Long-lived provider tokens are the currency of the incident. Providers:
# Hugging Face (hf_), OpenAI (sk-), Anthropic (sk-ant-), GitHub (ghp_/gho_/
# github_pat_), Google (AIza), AWS (AKIA), Slack (xoxb-/xoxp-).
_TOKEN_PREFIXES: tuple[tuple[str, str], ...] = (
    ("hf", r"hf_[A-Za-z0-9]{34}"),
    ("openai", r"sk-(?!ant-)[A-Za-z0-9_-]{40,}"),
    ("anthropic", r"sk-ant-[A-Za-z0-9_-]{40,}"),
    ("github", r"(?:ghp|gho)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}"),
    ("google", r"AIza[0-9A-Za-z_-]{35}"),
    ("aws", r"AKIA[0-9A-Z]{16}"),
    ("slack", r"xox[bp]-[A-Za-z0-9-]{10,}"),
)

_PROVIDER_RES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern)) for name, pattern in _TOKEN_PREFIXES
)

# Structural net for provider-unknown secrets: long mixed-alphabet runs
# (base64/hex shaped, with = + / - allowed) carrying at least one digit
# and one non-alphanumeric character, 28+ chars, entropy >= 3.0.
_GENERIC_SECRET_RE = re.compile(r"[A-Za-z0-9_+/=-]{28,}")

_ENTROPY_FLOOR = 3.0


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _generic_candidates(text: str) -> list[str]:
    out: list[str] = []
    for m in _GENERIC_SECRET_RE.finditer(text):
        candidate = m.group(0)
        # 'name=secret' affixes share the character class; the secret is
        # the last '='-delimited segment so fingerprints do not depend on
        # the variable name a session happened to use.
        parts = [p for p in candidate.split("=") if p]
        token = parts[-1] if parts else candidate
        if (
            len(token) >= 28
            and any(c.isdigit() for c in token)
            and any(not c.isalnum() for c in token)
            and _shannon(token) >= _ENTROPY_FLOOR
        ):
            out.append(token)
    return out


def extract_secret_candidates(text: str) -> list[tuple[str, str]]:
    """Extract (provider, token) candidates from free text.

    Provider grammars win; generic candidates overlapping a provider
    match are discarded so a token is never fingerprinted twice under
    different identities.
    """
    found: list[tuple[str, str, int, int]] = []
    for name, pattern in _PROVIDER_RES:
        for m in pattern.finditer(text):
            found.append((name, m.group(0), m.start(), m.end()))
    provider_spans = [(s, e) for _, _, s, e in found]
    for token in _generic_candidates(text):
        start = text.find(token)
        end = start + len(token)
        if any(start < e and s < end for s, e in provider_spans):
            continue
        found.append(("generic", token, start, end))
    return [(name, token) for name, token, _, _ in found]


class CredentialLoopTracker:
    """Tracks secret fingerprints across sessions and emits loop incidents.

    One tracker instance serves the whole daemon: the detection targets —
    cross-session sharing and lateral spread — are invisible from inside
    a single session.
    """

    def __init__(
        self,
        *,
        cooldown: timedelta | None = None,
        max_tracked: int = 512,
    ) -> None:
        self._cooldown = cooldown if cooldown is not None else timedelta(minutes=10)
        self._max_tracked = max_tracked
        # fingerprint -> {session_id -> (last_seen, origin_event_id)}
        self._sightings: dict[str, dict[UUID, tuple[datetime, str]]] = {}
        # fingerprint -> session that first recorded it
        self._origin: dict[str, UUID] = {}
        # fingerprint -> {"shared"|"lateral"} once emitted
        self._emitted: dict[str, str] = {}
        self._last_emitted: dict[str, datetime] = {}
        # sessions that have closed; sightings of their held secrets escalate
        self.session_closed: set[UUID] = set()

    # -- Ingest hook ------------------------------------------------------------

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one event; returns loop incidents when fingerprints repeat."""
        if isinstance(event, IncidentEvent):
            return []
        text: str | None = None
        if isinstance(event, CommandEvent):
            text = event.command
        elif isinstance(event, FileMutationEvent):
            text = event.diff_summary
        if not text:
            return []
        return self._observe_secrets(event, text)

    def _observe_secrets(self, event: EventBase, text: str) -> list[IncidentEvent]:
        incidents: list[IncidentEvent] = []
        for provider, token in extract_secret_candidates(text):
            fp = _fingerprint(provider, token)
            sid = event.session_id
            sessions = self._sightings.setdefault(fp, {})
            if sid not in sessions:
                if len(self._sightings) > self._max_tracked:
                    self._evict_oldest()
                sessions[sid] = (event.timestamp, str(event.event_id))
            self._origin.setdefault(fp, sid)
            new_sessions = len(sessions)
            if new_sessions < 2:
                continue
            stage = "shared" if new_sessions == 2 else "lateral"
            already = self._emitted.get(fp)
            if already == "lateral" or (already == "shared" and stage == "shared"):
                continue
            # Cooldown guards same-stage spam only; an escalation
            # (shared -> lateral) must never be silenced by it.
            if stage == "shared" and not self._can_emit(fp, event.timestamp):
                continue
            if stage == "lateral":
                self._emitted[fp] = "lateral"
                incidents.append(self._lateral(fp, provider, sessions, event))
            else:
                self._emitted[fp] = "shared"
                incidents.append(self._shared(fp, provider, sessions, event, sid))
        return incidents

    # -- Incident builders --------------------------------------------------------

    def _shared(
        self,
        fp: str,
        provider: str,
        sessions: dict[UUID, tuple[datetime, str]],
        event: EventBase,
        sid: UUID,
    ) -> IncidentEvent:
        holding = [self._origin.get(fp, sid), *(s for s in sessions if s != sid)]
        closed_note = ""
        severity = "high"
        if any(s in self.session_closed for s in holding):
            closed_note = (
                "At least one holding session had already closed — the "
                "secret outlived its session (post-exit pattern). "
            )
            severity = "critical"
        return IncidentEvent(
            session_id=sid,
            actor_id="credential_loop_tracker",
            source_adapter="credential_loop_tracker",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type="credential_shared_between_sessions",
            severity=severity,
            title="Secret shared between sessions",
            description=(
                f"A {provider} credential fingerprint seen first in "
                f"session {self._origin.get(fp, sid)} now appears in "
                f"session {sid}. Discovery -> sharing -> lateral movement: "
                "the discovery-to-pivot loop from the Hugging Face "
                f"incident is live. {closed_note}"
                "Fingerprint (sha256 of the secret) is in "
                "fingerprint_sha256; never log the secret itself."
            ),
            payload={"fingerprint_sha256": fp},
            related_events=[eid for _, eid in sessions.values()],
            causal_path=[eid for _, eid in sessions.values()],
            timestamp=event.timestamp,
        )

    def _lateral(
        self,
        fp: str,
        provider: str,
        sessions: dict[UUID, tuple[datetime, str]],
        event: EventBase,
    ) -> IncidentEvent:
        holders = sorted(str(s) for s in sessions)
        return IncidentEvent(
            session_id=event.session_id,
            actor_id="credential_loop_tracker",
            source_adapter="credential_loop_tracker",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type="credential_lateral_movement",
            severity="critical",
            title="Secret spreading laterally across sessions",
            description=(
                f"A {provider} credential fingerprint has now appeared in "
                f"{len(sessions)} distinct sessions ({', '.join(holders)}). "
                "This is the wide-pivot phase of the Hugging Face incident "
                "pattern: credentials as shared currency across the swarm. "
                "The secret's sha256 fingerprint is in fingerprint_sha256; "
                "treat every holding session as affected and rotate the "
                "credential."
            ),
            payload={"fingerprint_sha256": fp},
            related_events=[eid for _, eid in sessions.values()],
            causal_path=[eid for _, eid in sessions.values()],
            timestamp=event.timestamp,
        )

    # -- Lifecycle and bookkeeping ------------------------------------------------

    def mark_session_closed(self, session_id: UUID) -> None:
        """Record a close so later sightings of held secrets escalate."""
        self.session_closed.add(session_id)

    def _evict_oldest(self) -> None:
        if not self._sightings:
            return
        oldest_fp = min(
            self._sightings,
            key=lambda fp: min(ts for ts, _ in self._sightings[fp].values()),
        )
        del self._sightings[oldest_fp]
        self._origin.pop(oldest_fp, None)
        self._emitted.pop(oldest_fp, None)
        self._last_emitted.pop(oldest_fp, None)

    def _can_emit(self, fp: str, now: datetime) -> bool:
        last = self._last_emitted.get(fp)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[fp] = now
        return True


def _fingerprint(provider: str, token: str) -> str:
    """Stable identity for a secret: sha256 over provider + exact string.

    Only the digest is retained anywhere in tracker state — the raw
    secret is never stored, logged, or included in incidents.
    """
    return hashlib.sha256(f"{provider}:{token}".encode()).hexdigest()
