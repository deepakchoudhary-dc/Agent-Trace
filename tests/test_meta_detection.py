"""Tests for convention-free meta-detection and detector-decay monitoring
(plan2.md shortcoming #10)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.meta_detection import (
    DetectorStalenessMonitor,
    MetaAnomalyDetector,
)
from agenttrace.models.events import FileMutationEvent

_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _fme(
    path: str,
    size: int = 100,
    sid: object = None,
) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=uuid4() if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="filesystem_observer",
        file_path=path,
        mutation_type="create",
        size_delta=size,
        timestamp=_T0,
    )


# -- MetaAnomalyDetector -----------------------------------------------------


def test_benign_directory_produces_no_finding() -> None:
    detector = MetaAnomalyDetector()
    names = ["main.py", "utils.py", "models.py", "storage.py", "cli.py",
             "api.py", "graph.py", "policy.py", "daemon.py", "events.py"]
    for i, name in enumerate(names):
        assert detector.observe(_fme(f"/ws/src/{name}", size=90 + i * 37)) == []


def test_uniform_shapes_and_chunk_sizes_fire() -> None:
    detector = MetaAnomalyDetector()
    findings: list = []
    for i in range(1, 9):  # threshold reaches at the 8th sibling
        findings = detector.observe(_fme(f"/ws/board/zzCHUNK_{i:04d}", size=4096))
    assert len(findings) == 1
    assert findings[0].finding_type == "structural_anomaly"


def test_below_min_siblings_stays_silent() -> None:
    detector = MetaAnomalyDetector()
    for i in range(1, 6):
        assert detector.observe(_fme(f"/ws/board/zzCHUNK_{i:04d}", size=4096)) == []


def test_finding_reports_statistics_not_purpose() -> None:
    detector = MetaAnomalyDetector()
    findings: list = []
    for i in range(1, 9):
        findings = detector.observe(_fme(f"/ws/b/zzX_{i:03d}", size=512))
    assert findings
    description = findings[0].description
    assert "shape_uniformity=" in description
    assert "score=" in description
    assert "does not identify a protocol" in description


def test_cross_session_sharing_reported_in_statistics() -> None:
    detector = MetaAnomalyDetector(cooldown=timedelta(0))
    session_a, session_b = uuid4(), uuid4()
    for i in range(1, 9):  # solo session: fires with cross_session=0.00
        detector.observe(_fme(f"/ws/solo/zzS_{i:03d}", size=4096, sid=session_a))
    for i in range(1, 8):  # mixed dir: 8 from session a...
        detector.observe(_fme(f"/ws/mixed/zzS_{i:03d}", size=4096, sid=session_a))
    findings = detector.observe(  # ...the 9th from session b tips sharing
        _fme("/ws/mixed/zzS_009", size=4096, sid=session_b)
    )
    assert len(findings) == 1
    assert "cross_session=2.00" in findings[0].description


def test_cooldown_prevents_refire_same_directory() -> None:
    detector = MetaAnomalyDetector()
    first: list = []
    for i in range(1, 9):
        first = detector.observe(_fme(f"/ws/b/zzC_{i:03d}", size=4096))
    assert len(first) == 1
    assert detector.observe(_fme("/ws/b/zzC_009", size=4096)) == []


# -- DetectorStalenessMonitor ----------------------------------------------------


def test_census_needs_min_sessions() -> None:
    monitor = DetectorStalenessMonitor(detector_ids=["alpha", "beta"], min_sessions=3)
    now = _T0
    for _i in range(2):
        sid = uuid4()
        monitor.record_event(sid)
        assert monitor.close_session(sid, now) == []
    # The close that reaches min_sessions runs the census.
    assert monitor.close_session(uuid4(), now)


def test_stale_detector_flagged_after_min_sessions() -> None:
    monitor = DetectorStalenessMonitor(detector_ids=["alpha", "beta"], min_sessions=5)
    now = _T0
    findings: list = []
    for _i in range(5):
        sid = uuid4()
        monitor.record_event(sid)  # events evaluated; beta never fires
        monitor.record_fire(sid, "alpha")
        findings = monitor.close_session(sid, now)
    stale = [f for f in findings if f.finding_type == "detector_staleness"]
    assert any("beta" in f.description for f in stale)


def test_overfiring_detector_flagged() -> None:
    monitor = DetectorStalenessMonitor(
        detector_ids=["alpha", "beta"],
        min_sessions=5,
        overfire_event_ratio=0.5,
    )
    now = _T0
    for _i in range(5):
        sid = uuid4()
        for _j in range(10):
            monitor.record_event(sid)
            monitor.record_fire(sid, "alpha")  # fires on every event
        monitor.record_fire(sid, "beta")
        findings = monitor.close_session(sid, now)
    overfire = [f for f in findings if f.finding_type == "detector_overfire"]
    assert any("alpha" in f.description for f in overfire)


def test_decay_findings_are_maintenance_signals() -> None:
    monitor = DetectorStalenessMonitor(detector_ids=["alpha"], min_sessions=5)
    now = _T0
    findings: list = []
    for _i in range(5):
        sid = uuid4()
        monitor.record_event(sid)
        findings = monitor.close_session(sid, now)
    assert findings  # the threshold close emitted the census
    for finding in findings:
        assert finding.severity == "low"
        assert "not a finding about the audited agent" in finding.description


def test_cooldown_throttles_census() -> None:
    monitor = DetectorStalenessMonitor(detector_ids=["alpha"], min_sessions=5)
    threshold_findings: list = []
    for _i in range(5):
        sid = uuid4()
        monitor.record_event(sid)
        threshold_findings = monitor.close_session(sid, _T0)
    assert threshold_findings  # census fired at the threshold close
    assert monitor.close_session(uuid4(), _T0 + timedelta(minutes=30)) == []
    assert monitor.close_session(uuid4(), _T0 + timedelta(hours=6, minutes=1))
    assert monitor.close_session(uuid4(), _T0 + timedelta(hours=6, minutes=2)) == []


def test_cap_of_four_findings_per_census() -> None:
    monitor = DetectorStalenessMonitor(
        detector_ids=[f"d{i}" for i in range(10)], min_sessions=5
    )
    now = _T0
    for _i in range(5):
        sid = uuid4()
        monitor.record_event(sid)
        findings = monitor.close_session(sid, now)
    assert len(findings) == 4
