"""Persistent actor-identity graph (plan2 METR #2 — the deeper half).

The collusion, credential-loop, and shared-infrastructure engines correlate
signals *within or across runs*; none of them remembers WHO the adversary
was. The METR Hugging Face incident was a persistent collective: agents held
stable handles across containers, passed dossiers between runs
(PHASEONE10841 -> PHASEONE[big]), and specialized into lanes. Attribution
that evaporates at session close cannot see that shape.

This module is the memory:

- **actor_reincarnated** (medium) — the same actor handle observed in two
  or more distinct sessions. Individually innocuous (a developer reruns a
  CLI); as accumulated memory it is the identity-rotation baseline the
  other engines lack, and it is the hook that turns per-run correlation
  into an adversary history.
- **workstream_shift_suspected** (medium) — an actor's command stream
  starts working in a directory tree its recent stream never touched,
  while its own established tree went quiet — the lane-switching half of
  the specialized-collective shape (statistics, never motive).
- **handoff_dossier_suspected** (high) — a session installs a large file
  shortly before it closes, and a DIFFERENT session's actor later writes
  into the same directory: the observable half of a run-to-run handoff.
  Statistics only, never motive (invariant #3) — correlation is not proof
  of coordination.

Honest boundaries: identity is the agent-harness-provided actor_id string
(claim-class evidence, not kernel-attested — that remains P1 attribution
work); the dossier signal uses file volume and directory reuse because
file *reads* are not observable at this sensor plane.
"""

from __future__ import annotations

import logging
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

_DOSSIER_WINDOW = timedelta(minutes=10)
_DOSSIER_MIN_BYTES = 4096
_DOSSIER_DIR_DECAY = timedelta(hours=24)

_DOSSIER_COOLDOWN = timedelta(minutes=10)
_REINCARNATION_COOLDOWN = timedelta(hours=1)

# Workstream clustering (architectural item 7): an actor's recent working
# directories form its behavioral fingerprint; a pivot into a tree it has
# never touched — while its own tree went quiet — is the observable half
# of lane-switching.
_WORKSTREAM_MIN_EVENTS = 3
_WORKSTREAM_RECENT = timedelta(minutes=30)
_WORKSTREAM_COOLDOWN = timedelta(hours=1)


class ActorIdentityGraph:
    """Daemon-wide memory of which actor handles operated which sessions.

    State is rebuilt silently from the ledger on daemon restart
    (:meth:`seed_event`), so identity memory survives restarts (dossier
    candidacy for pre-restart closes too, via the restore loop marking
    stopped sessions closed); live events arrive through :meth:`observe` and
    emit hash-chained incidents. State growth is bounded for the
    dossier cache (decay-pruned); actor/session presence grows with real
    usage and is disclosed here rather than silently dropped — a forgotten
    identity is exactly the failure this module exists to prevent.
    """

    def __init__(self) -> None:
        # actor_id -> {session_id -> first seen}
        self._actors: dict[str, dict[UUID, datetime]] = {}
        # session_id -> closing time
        self._closed: dict[UUID, datetime] = {}
        # session_id -> {directory -> (bytes, timestamp)} recent large writes
        self._dossier_writes: dict[UUID, dict[str, tuple[int, datetime]]] = {}
        # actor_id -> {session_id -> {directory -> last seen}} — the
        # workstream fingerprint (command working directories).
        self._workstreams: dict[str, dict[UUID, dict[str, datetime]]] = {}
        self._last_emitted: dict[str, datetime] = {}

    # -- State ------------------------------------------------------------------

    def _absorb(self, event: EventBase) -> None:
        """Update memory without emitting (used by seeding)."""
        if isinstance(event, IncidentEvent):
            return
        # An empty handle is not an identity: correlating all anonymous
        # actors into one would manufacture a phantom adversary.
        if not event.actor_id:
            return
        sessions = self._actors.setdefault(event.actor_id, {})
        sessions.setdefault(event.session_id, event.timestamp)
        if (
            isinstance(event, FileMutationEvent)
            and event.size_delta >= _DOSSIER_MIN_BYTES
            # Post-close writes are post-close behavior (#6 machinery), not
            # dossier candidates: absorbing them would fabricate a
            # "written inside the final minutes" claim with a negative age.
            and event.session_id not in self._closed
        ):
            # Normalize separators first (Windows paths) — meta_detection
            # does the same; without it, backslash paths degrade pairing
            # to same-exact-file.
            path = str(event.file_path).replace("\\", "/")
            directory = path.rsplit("/", 1)[0] if "/" in path else path
            writes = self._dossier_writes.setdefault(event.session_id, {})
            if directory not in writes or event.timestamp > writes[directory][1]:
                writes[directory] = (event.size_delta, event.timestamp)
        if isinstance(event, CommandEvent) and event.working_dir:
            directory = str(event.working_dir).replace("\\", "/").rstrip("/")
            per_session = self._workstreams.setdefault(event.actor_id, {})
            per_session.setdefault(event.session_id, {})[directory] = event.timestamp

    def seed_event(self, event: EventBase) -> None:
        """Silent state build from ledger history (restart memory)."""
        self._absorb(event)

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one live event; return any identity incidents it completes."""
        if isinstance(event, IncidentEvent):
            return []
        self._absorb(event)
        incidents = self._reincarnation(event) or []
        incidents.extend(self._handoff(event))
        incidents.extend(self._workstream_shift(event))
        return incidents

    def _workstream_shift(self, event: EventBase) -> list[IncidentEvent]:
        """A command outside the actor's established working tree while its
        own tree went quiet — the observable half of lane-switching."""
        if not isinstance(event, CommandEvent) or not event.working_dir:
            return []
        directory = str(event.working_dir).replace("\\", "/").rstrip("/")
        window_start = event.timestamp - _WORKSTREAM_RECENT
        known: set[str] = set()
        recent_in_owned = False
        for session_dirs in self._workstreams.get(event.actor_id, {}).values():
            for seen_dir, seen_at in session_dirs.items():
                if seen_at < window_start:
                    continue
                known.add(seen_dir)
                if seen_dir == directory and seen_at < event.timestamp:
                    recent_in_owned = True
        if directory in known or recent_in_owned:
            return []
        if len(known) < _WORKSTREAM_MIN_EVENTS:
            return []
        if not self._can_emit(
            f"workstream:{event.actor_id}", event.timestamp, _WORKSTREAM_COOLDOWN
        ):
            return []
        plural = "y" if len(known) == 1 else "ies"
        return [self._incident(
            event,
            "workstream_shift_suspected",
            "medium",
            "Actor working outside its established tree",
            (
                f"Actor '{event.actor_id}' ran a command in '{directory}', "
                "a directory its recent command stream never touched "
                f"({len(known)} established working director{plural} in "
                f"the last {int(_WORKSTREAM_RECENT.total_seconds() / 60)} "
                "minutes). The lane-switching shape of a specialized "
                "collective — statistics, not a motive claim."
            ),
        )]

    # -- Detectors ----------------------------------------------------------------

    def _reincarnation(self, event: EventBase) -> list[IncidentEvent]:
        sessions = self._actors.get(event.actor_id, {})
        if len(sessions) < 2:
            return []
        key = f"reincarnated:{event.actor_id}"
        if not self._can_emit(key, event.timestamp, _REINCARNATION_COOLDOWN):
            return []
        others = sorted(str(s) for s in sessions if s != event.session_id)
        logger.warning(
            "ACTOR IDENTITY: '%s' now spans %d sessions (previously %s)",
            event.actor_id,
            len(sessions),
            others[0] if others else "?",
        )
        return [self._incident(
            event,
            "actor_reincarnated",
            "medium",
            "Actor handle spans multiple sessions",
            (
                f"Actor '{event.actor_id}' has now been observed in "
                f"{len(sessions)} distinct sessions (this session plus "
                f"{others[0] if others else 'another'}). Individually benign — "
                "an operator reruns a CLI — but persistent identity is the "
                "substrate the METR collective built coordination on, and "
                "per-run correlation forgets it the moment a session ends. "
                "Recorded as identity memory for the other engines."
            ),
        )]

    def _handoff(self, event: EventBase) -> list[IncidentEvent]:
        sid = event.session_id
        if sid in self._closed:
            return []
        if not isinstance(event, FileMutationEvent):
            return []
        path = str(event.file_path).replace("\\", "/")
        directory = path.rsplit("/", 1)[0] if "/" in path else path

        for closed_sid, closed_at in self._closed.items():
            if closed_sid == sid:
                continue
            writes = self._dossier_writes.get(closed_sid, {})
            record = writes.pop(directory, None)
            # Decayed candidates are pruned on sight: without this, memory
            # grows for the process lifetime.
            if record is not None and event.timestamp - record[1] > _DOSSIER_DIR_DECAY:
                continue
            if record is None:
                continue
            size, written_at = record
            # The dossier window: installed near the closing session's end
            # (both bounds checked — a post-close write absorbed before the
            # close was registered must not masquerade as pre-close).
            if written_at < closed_at - _DOSSIER_WINDOW or written_at > closed_at:
                continue
            if event.timestamp - closed_at > _DOSSIER_DIR_DECAY:
                continue
            if not self._can_emit(f"dossier:{directory}", event.timestamp, _DOSSIER_COOLDOWN):
                return []
            logger.warning(
                "ACTOR IDENTITY: %d-byte file in '%s' written %s before "
                "session close; a different session is now writing there",
                size,
                directory,
                closed_at - written_at,
            )
            return [self._incident(
                event,
                "handoff_dossier_suspected",
                "high",
                "Cross-session handoff pattern",
                (
                    f"Session {closed_sid} wrote a {size}-byte artifact to "
                    f"'{directory}' inside its final "
                    f"{int(_DOSSIER_WINDOW.total_seconds() / 60)} minutes; "
                    f"after it closed, actor '{event.actor_id}' from another "
                    "session is writing into the same directory. The "
                    "observable half of the METR run-to-run dossier handoff "
                    "(PHASEONE10841 -> PHASEONE[big]). Statistics, not a "
                    "motive claim."
                ),
            )]
        return []

    # -- Lifecycle ------------------------------------------------------------------

    def close_session(self, session_id: UUID, now: datetime) -> None:
        """Record a close so later cross-session writes can pair with the
        closing session's late large writes."""
        self._closed[session_id] = now

    def _can_emit(self, key: str, now: datetime, cooldown: timedelta) -> bool:
        last = self._last_emitted.get(key)
        if last is not None and now - last < cooldown:
            return False
        self._last_emitted[key] = now
        return True

    def _incident(
        self,
        event: EventBase,
        incident_type: str,
        severity: str,
        title: str,
        description: str,
    ) -> IncidentEvent:
        return IncidentEvent(
            session_id=event.session_id,
            actor_id="actor_identity",
            source_adapter="actor_identity",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            related_events=[str(event.event_id)],
            causal_path=[str(event.event_id)],
            timestamp=event.timestamp,
        )
