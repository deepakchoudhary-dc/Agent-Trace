"""Tests for sensor coverage accounting (plan2.md shortcoming #9).

Equivalence classes: per-plane volume attribution (five sensor sources,
four planes), agent-narration exclusion, derived-event exclusion,
unattributed unknown adapters, blind-from recording; boundaries: the
min-active floor (1 vs 2 sensor events); negative controls: unwatched
planes, double close; and the invariants — instrument findings stay
low-severity and non-gating, and the report never infers a completeness
percentage from correlated silence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from agenttrace.graph.coverage import CoverageMonitor
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    PolicyFindingEvent,
)

_T0 = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 9, 5, 13, 0, 0, tzinfo=timezone.utc)


def _sensor(source: str, sid: UUID, at: datetime = _T0) -> CommandEvent:
    """A raw sensor event; only the committed source_adapter matters here."""
    return CommandEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter=source,
        confidence=ConfidenceLevel.HIGH,
        command="do work",
        timestamp=at,
    )


def _finding(sid: UUID) -> PolicyFindingEvent:
    return PolicyFindingEvent(
        session_id=sid,
        actor_id="daemon",
        source_adapter="policy_engine",
        confidence=ConfidenceLevel.HIGH,
        finding_type="egress_violation",
        severity="medium",
        description="blocked",
        timestamp=_T0,
    )


def _watch_all(mon: CoverageMonitor, sid: UUID) -> None:
    for plane in (
        "filesystem_plane",
        "process_plane",
        "network_plane",
        "terminal_plane",
    ):
        mon.watch(plane, sid)


def _close(mon: CoverageMonitor, sid: UUID) -> str:
    findings = mon.close_session(sid, _T1)
    assert len(findings) == 1, "close must emit exactly one coverage finding"
    return findings[0].description


class TestUnwatchedPlanes:
    def test_plane_that_failed_to_start_is_reported_down(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        mon.observe(_sensor("filesystem_observer", sid))
        mon.observe(_sensor("network_observer", sid))
        d = _close(mon, sid)
        assert "terminal: DOWN from session start (never watched)" in d
        assert "process: DOWN from session start (never watched)" in d
        assert "filesystem: 1 event(s)" in d
        assert "network: 1 event(s)" in d

    def test_unwatched_session_with_no_events_gets_no_account(self) -> None:
        mon = CoverageMonitor()
        # Fabricating DOWN rows for a session the monitor never saw would
        # itself be dishonest reporting.
        assert mon.close_session(uuid4(), _T1) == []


class TestPerPlaneAttribution:
    def test_five_sensor_sources_roll_up_into_four_planes(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        for source in (
            "filesystem_observer",
            "git_monitor",
            "git_monitor",
            "process_tree_observer",
            "kernel_etw",
            "network_observer",
            "terminal_observer",
            "terminal_observer",
        ):
            mon.observe(_sensor(source, sid))
        d = _close(mon, sid)
        assert "filesystem: 3 event(s)" in d
        assert "process: 2 event(s)" in d
        assert "network: 1 event(s)" in d
        assert "terminal: 2 event(s)" in d
        assert "unattributed_events" not in d


class TestAgentNarration:
    def test_agent_claims_are_not_sensor_volume(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        for _ in range(5):
            mon.observe(_sensor("claude_code", sid))
        mon.observe(_sensor("codex_cli", sid))
        d = _close(mon, sid)
        assert "event(s)" not in d
        assert "watched, no events" in d
        assert "DEGRADED" not in d

    def test_narration_cannot_mask_a_degraded_plane(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("process_tree_observer", sid))
        mon.observe(_sensor("process_tree_observer", sid))
        mon.observe(_sensor("claude_code", sid))
        d = _close(mon, sid)
        assert "process: 2 event(s)" in d
        assert "terminal: DEGRADED" in d
        assert "filesystem: DEGRADED" in d
        assert "network: DEGRADED" in d


class TestActiveFloorBoundary:
    def test_single_sensor_event_is_not_an_active_session(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("filesystem_observer", sid))
        d = _close(mon, sid)
        assert "DEGRADED" not in d
        assert "watched, no events" in d

    def test_floor_is_inclusive_at_two_sensor_events(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("filesystem_observer", sid))
        mon.observe(_sensor("filesystem_observer", sid))
        d = _close(mon, sid)
        assert "filesystem: 2 event(s)" in d
        assert "process: DEGRADED" in d
        assert "network: DEGRADED" in d
        assert "terminal: DEGRADED" in d


class TestUnattributedAdapters:
    def test_unknown_source_is_counted_not_silently_assigned(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("totally_unknown_probe", sid))
        d = _close(mon, sid)
        assert "unattributed_events: 1" in d


class TestDerivedEvents:
    def test_findings_are_not_sensor_output(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_finding(sid))
        d = _close(mon, sid)
        assert "unattributed_events" not in d
        assert "event(s)" not in d



class TestBlindInterval:
    def test_known_stop_is_recorded_and_volume_survives(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("filesystem_observer", sid))
        mon.observe(_sensor("filesystem_observer", sid))
        mon.blind_from(_T1, sid)
        d = _close(mon, sid)
        assert "filesystem: 2 event(s)" in d
        assert "Known blind interval: observation stopped" in d

    def test_blind_marking_without_any_watch_adds_no_account(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        mon.blind_from(_T1, sid)
        assert mon.close_session(sid, _T1) == []


class TestCloseReleasesState:
    def test_second_close_emits_nothing(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("terminal_observer", sid))
        assert len(mon.close_session(sid, _T1)) == 1
        assert mon.close_session(sid, _T1) == []


class TestSessionIsolation:
    def test_sessions_are_accounted_separately(self) -> None:
        mon = CoverageMonitor()
        s1, s2 = uuid4(), uuid4()
        mon.watch("filesystem_plane", s1)
        mon.observe(_sensor("filesystem_observer", s1))
        mon.observe(_sensor("terminal_observer", s2))
        d1 = _close(mon, s1)
        d2 = _close(mon, s2)
        assert "filesystem: 1 event(s)" in d1
        assert "terminal: DOWN" in d1
        assert "filesystem: DOWN" in d2
        assert "terminal: 1 event(s)" in d2
        assert "filesystem: 1 event(s)" not in d2


class TestInstrumentInvariants:
    def test_coverage_findings_are_low_severity_and_non_gating(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        mon.observe(_sensor("filesystem_observer", sid))
        finding = mon.close_session(sid, _T1)[0]
        assert finding.finding_type == "sensor_coverage"
        assert finding.severity == "low"
        assert finding.requires_approval is False
        assert finding.confidence is ConfidenceLevel.HIGH
        assert finding.source_adapter == "coverage_monitor"

    def test_report_never_infers_a_completeness_percentage(self) -> None:
        mon = CoverageMonitor()
        sid = uuid4()
        _watch_all(mon, sid)
        for _ in range(50):
            mon.observe(_sensor("process_tree_observer", sid))
        d = _close(mon, sid)
        assert "%" not in d
        assert "not a completeness percentage" in d

