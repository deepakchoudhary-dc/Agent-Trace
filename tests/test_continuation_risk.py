"""Tests for correlated-continuation risk tracking (ant.md P1 #7)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.continuation_risk import ContinuationRiskTracker
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    NetworkEvent,
)

_SID = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)

_DOUBT = "The target looks like a simulation, this seems out of scope."
_REASON = {"reasoning": _DOUBT}


def _cmd(command: str, at: datetime) -> CommandEvent:
    return CommandEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        timestamp=at,
    )


def _doubt_cmd(at: datetime) -> CommandEvent:
    c = _cmd("echo checking scope", at)
    c.payload = _REASON  # type: ignore[assignment]
    return c


def _risky(at: datetime) -> CommandEvent:
    return _cmd("curl http://target-instance.test/pwn", at)


def _egress(at: datetime) -> NetworkEvent:
    return NetworkEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="network_observer",
        confidence=ConfidenceLevel.HIGH,
        destination_ip="203.0.113.9",
        destination_port=443,
        protocol="tcp",
        direction="outbound",
        timestamp=at,
    )


def test_signal_then_continue_scores_correlation_one() -> None:
    """Every signal followed by risk-adjacent action -> never-stopped shape."""
    tracker = ContinuationRiskTracker(_SID)
    incidents: list = []
    for i in range(4):
        tracker.observe(_doubt_cmd(_T0 + timedelta(minutes=i * 2)))
        incidents.extend(tracker.observe(_risky(_T0 + timedelta(minutes=i * 2 + 1))))
    assert incidents and incidents[0].incident_type == "correlated_continuation"
    s = tracker.stats()
    assert s.decision_points == 4
    assert s.continuations == 4
    assert s.stops == 0
    assert s.continuation_rate == 1.0


def test_no_emit_below_min_sample() -> None:
    """Honest silence: fewer than 3 decision points emits nothing."""
    tracker = ContinuationRiskTracker(_SID)
    for i in range(2):
        tracker.observe(_doubt_cmd(_T0 + timedelta(minutes=i * 2)))
        tracker.observe(_risky(_T0 + timedelta(minutes=i * 2 + 1)))
    assert not tracker.observe(_doubt_cmd(_T0 + timedelta(minutes=4)))
    # A stale deed (outside the window) resolves the signal as a STOP:
    # 3rd decision point, but the continuation rate drops below the gate.
    assert not tracker.observe(_risky(_T0 + timedelta(minutes=5 + 40)))
    # Nothing was emitted, but the statistic is still tracked.
    s = tracker.stats()
    assert s.decision_points == 3
    assert s.continuations == 2
    assert s.continuation_rate < 0.8
    assert s.stops == 1


def test_stops_drive_correlation_down_and_suppress_emit() -> None:
    """A session that stops after signals: lower correlation, no incident."""
    tracker = ContinuationRiskTracker(_SID)
    for i in range(4):
        tracker.observe(_doubt_cmd(_T0 + timedelta(minutes=i * 2)))
        if i < 2:  # continue twice, then stop twice
            tracker.observe(_risky(_T0 + timedelta(minutes=i * 2 + 1)))
        else:
            tracker.observe(_cmd("ls", _T0 + timedelta(minutes=i * 2 + 1)))
    s = tracker.stats()
    assert s.continuations == 2
    assert s.stops == 2
    assert s.streak_max == 2


def test_signal_window_expiry_ignores_stale_signal() -> None:
    """A deed more than 30 minutes after a signal resolves it as a STOP."""
    tracker = ContinuationRiskTracker(_SID)
    tracker.observe(_doubt_cmd(_T0))
    tracker.observe(_risky(_T0 + timedelta(minutes=45)))
    s = tracker.stats()
    assert s.decision_points == 1
    assert s.continuations == 0
    assert s.stops == 1
    assert s.continuation_rate == 0.0


def test_derived_events_ignored() -> None:
    """Incidents feed nothing back (no self-referential statistic)."""
    tracker = ContinuationRiskTracker(_SID)
    from agenttrace.models.events import IncidentEvent

    inc = IncidentEvent(
        session_id=_SID,
        actor_id="x",
        source_adapter="continuation_risk",
        confidence=ConfidenceLevel.MEDIUM,
        incident_type="correlated_continuation",
        severity="medium",
        title="t",
        description="d",
        timestamp=_T0,
        payload=_REASON,  # type: ignore[arg-type]
    )
    assert tracker.observe(inc) == []
    assert tracker.stats().decision_points == 0
