"""Sensor coverage accounting (plan2.md METR shortcoming #9, architectural item 5).

In the METR incident, the first dataset covered roughly 30% of relevant agent
activity and materially misled early analysis; only ~90% coverage was ever
achieved, and the report treats completeness estimation as first-class
methodology. AgentTrace had the inverse failure mode: durable
``evidence_incomplete`` semantics existed for storage loss, but nothing
measured or reported per-session *sensor coverage* — so a report could look
definitive while a whole sensor plane was silently down.

The :class:`CoverageMonitor` closes that gap from three angles:

- **Watch** -- the daemon records each sensor in ``_start_observers`` only
  after its start actually succeeded, under the plane id it feeds
  (``filesystem_plane``, ``process_plane``, ``network_plane``,
  ``terminal_plane``). A sensor that fails to launch is never watched,
  and the close report says so.
- **Notice** -- ``observe(event)`` attributes each event's volume to its
  plane via the hash-committed ``source_adapter``; agent narration is
  excluded (it is not a sensor), and unknown adapters land in
  ``unattributed_events``. ``blind_from(timestamp, session)`` marks every
  watched plane blind when the daemon knows observation stopped (session
  stop, containment path).
- **Account** -- ``close_session()`` emits a low-severity
  ``sensor_coverage`` finding stating, per plane: event volume, "DEGRADED
  — watched but silent while the session was otherwise active", "watched,
  no events", or "DOWN from session start (never watched)". Coverage is
  stated as observations, never inferred into a completeness percentage —
  correlated silence is not proven absence (polling-only attribution is
  the documented ceiling, architectural item 2).

Because event volume is attributed through the #4 evidence boundary, the
account inherits its honesty: unknown adapters fail toward distrust and land
in ``unattributed_events`` rather than being silently assigned to a plane.
Findings are low-severity, hash-chained ``PolicyFindingEvent`` s.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agenttrace.graph.evidence_boundary import EvidenceClass, classify_evidence
from agenttrace.models.events import ConfidenceLevel, EventBase, PolicyFindingEvent

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

logger = logging.getLogger(__name__)

# Structural floor: a session with at least this many sensor events was
# operationally active — a watched plane with zero events in an operating
# session is reported as degraded, not merely idle.
_ACTIVE_PLANE_MIN_EVENTS = 2

# The five sensor planes, their hash-committed source_adapter tokens (the
# same registry the evidence boundary uses), and the sensor id the daemon
# watches them under.
_PLANE_BY_SOURCE: dict[str, str] = {
    "filesystem_observer": "filesystem",
    "git_monitor": "filesystem",
    "process_tree_observer": "process",
    "kernel_etw": "process",
    "network_observer": "network",
    "terminal_observer": "terminal",
}

# Agent adapters are a distinct evidence class, not a sensor plane: their
# stream is the agent's own narration.
_ADAPTIVE_SOURCES: frozenset[str] = frozenset({"claude_code", "codex_cli", "terminal"})

_PLANES = ("filesystem", "process", "network", "terminal")


def _source_plane(source_adapter: str) -> str | None:
    """Map a hash-committed source_adapter to its sensor plane, or None."""
    plane = _PLANE_BY_SOURCE.get(source_adapter)
    if plane is not None:
        return plane
    if classify_evidence(source_adapter) is EvidenceClass.AGENT_CLAIMED:
        return "agent_stream"
    return None


class CoverageMonitor:
    """Daemon-wide per-sensor coverage ledger for all sessions.

    Watches the sensors the daemon actually started, attributes event
    volume per plane through the #4 evidence boundary, silence is never
    upgraded to health, and at session close emits the ``sensor_coverage``
    finding the METR completeness methodology demands — observations
    only, no inferred completeness percentage.
    """

    def __init__(
        self,
        *,
        min_active_events: int | None = None,
    ) -> None:
        self._min_active = (
            min_active_events
            if min_active_events is not None
            else _ACTIVE_PLANE_MIN_EVENTS
        )
        # session -> sensor id -> True (watched), or (blind since, reason)
        self._watched: dict[UUID, dict[str, bool | tuple[datetime, str]]] = {}
        # session -> plane -> event count
        self._events_by_plane: dict[UUID, dict[str, int]] = {}
        self._unattributed: dict[UUID, int] = {}

    # -- Watching (daemon calls at session start) -------------------------------

    def watch(self, sensor: str, session: UUID) -> None:
        """Record that a session's observation includes this sensor."""
        self._watched.setdefault(session, {})[sensor] = True

    def blind_from(self, timestamp: datetime, session: UUID) -> None:
        """Mark every watched plane blind from ``timestamp`` (known stop)."""
        for sensor, state in self._watched.get(session, {}).items():
            if state is True:
                self._watched[session][sensor] = (timestamp, "observation stopped")

    # -- Event volume ------------------------------------------------------

    def observe(self, event: EventBase) -> None:
        """Attribute one event to a plane by its committed source_adapter."""
        if isinstance(event, PolicyFindingEvent):
            return
        if event.source_adapter in _ADAPTIVE_SOURCES:
            return  # the agent's own narration, not a sensor plane
        plane = _source_plane(event.source_adapter)
        if plane in ("filesystem", "process", "network", "terminal"):
            counts = self._events_by_plane.setdefault(event.session_id, {})
            counts[plane] = counts.get(plane, 0) + 1
        else:
            self._unattributed[event.session_id] = (
                self._unattributed.get(event.session_id, 0) + 1
            )

    # -- Close-time accounting -------------------------------------------------

    def close_session(
        self, session: UUID, now: datetime
    ) -> list[PolicyFindingEvent]:
        """Emit the session's coverage finding and release its state.

        The finding states observed facts only: which planes saw events,
        which were never watched, which were watched but produced no
        events, and which went blind mid-session. It never infers a
        completeness percentage — correlated silence is not proven absence.
        """
        watched = self._watched.pop(session, {})
        events_by_plane = self._events_by_plane.pop(session, {})
        unattributed = self._unattributed.pop(session, 0)
        # A session the monitor never saw (no watch, no events) has no
        # account to give — fabricating DOWN rows for it would itself be
        # dishonest reporting.
        if not watched and not events_by_plane and not unattributed:
            return []
        parts: list[str] = []
        blind_reason: str | None = None
        total_sensor_events = sum(events_by_plane.values())

        for plane in _PLANES:
            sensor = f"{plane}_plane"
            is_watched = watched.get(sensor) is True
            blind = self._blind_reason_from(watched, sensor)
            if blind is not None:
                blind_reason = blind
            count = events_by_plane.get(plane, 0)
            if count > 0:
                parts.append(f"{plane}: {count} event(s)")
            elif is_watched and total_sensor_events >= self._min_active:
                parts.append(
                    f"{plane}: DEGRADED — watched but silent while the "
                    "session was otherwise active (silence is not health)"
                )
            elif is_watched:
                parts.append(f"{plane}: watched, no events")
            else:
                parts.append(f"{plane}: DOWN from session start (never watched)")

        if unattributed:
            parts.append(f"unattributed_events: {unattributed}")

        return [self._coverage_finding(session, parts, blind_reason, now)]

    @staticmethod
    def _blind_reason_from(
        watched: dict[str, bool | tuple[datetime, str]], sensor: str
    ) -> str | None:
        state = watched.get(sensor)
        return state[1] if isinstance(state, tuple) else None

    def _coverage_finding(
        self,
        session: UUID,
        parts: list[str],
        blind_reason: str | None,
        now: datetime,
    ) -> PolicyFindingEvent:
        description = (
            "Sensor coverage at session close: "
            + "; ".join(parts)
            + ". Coverage is stated as observations, not a completeness "
            "percentage — a silent plane is correlated silence, not proven "
            "absence (polling-only attribution remains the documented "
            "ceiling). This finding is about the observation instrument, "
            "not the audited agent."
        )
        if blind_reason is not None:
            description += f" Known blind interval: {blind_reason}."
        logger.info("COVERAGE: session %s — %s", session, "; ".join(parts))
        return PolicyFindingEvent(
            session_id=session,
            actor_id="coverage_monitor",
            source_adapter="coverage_monitor",
            confidence=ConfidenceLevel.HIGH,
            finding_type="sensor_coverage",
            severity="low",
            description=description,
            requires_approval=False,
            timestamp=now,
        )
