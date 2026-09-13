"""Tests for containment-escape lineage (Bengio 2026, "escaping containment")."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.containment_escape import ContainmentEscapeDetector
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    ContextBoundaryEvent,
    FileMutationEvent,
)

_SID = uuid4()
_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc)


def _framing(reasoning: str, at: datetime | None = None) -> ContextBoundaryEvent:
    return ContextBoundaryEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.MEDIUM,
        payload={"reasoning": reasoning},
        timestamp=at or _T0,
    )


def _write(
    path: str, at: datetime | None = None, adapter: str = "filesystem_observer"
) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter=adapter,
        confidence=ConfidenceLevel.HIGH,
        file_path=path,
        mutation_type="create",
        timestamp=at or _T0,
    )


def test_escape_after_sim_framing_fires() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox"
    )
    detector.observe(_framing("This is a simulation; we are still in a sandbox."))
    incidents = detector.observe(
        _write(r"C:\Users\Shared\exfil.txt", at=_T0 + timedelta(minutes=1))
    )
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.incident_type == "containment_escape_suspected"
    assert incident.severity == "high"
    assert "C:\\Users\\Shared\\exfil.txt" in incident.description
    # Both halves of the chain are anchored as evidence.
    assert len(incident.related_events) == 2


def test_within_workspace_is_not_an_escape() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox"
    )
    detector.observe(_framing("This is a sandbox; traffic stays inside it."))
    incidents = detector.observe(
        _write(r"C:\work\sandbox\src\main.py", at=_T0 + timedelta(minutes=1))
    )
    assert incidents == []


def test_allowed_paths_boundary_is_tighter() -> None:
    detector = ContainmentEscapeDetector(
        _SID,
        workspace_root=r"C:\work",
        allowed_paths=[r"C:\work\sandbox"],
    )
    detector.observe(_framing("we are in a simulated environment"))
    # Inside workspace but OUTSIDE the declared allowed path: escape.
    incidents = detector.observe(
        _write(r"C:\work\other\leak.txt", at=_T0 + timedelta(minutes=1))
    )
    assert len(incidents) == 1
    assert "task-contract allowed paths" in incidents[0].description


def test_stale_framing_does_not_fire() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox", window=timedelta(minutes=5)
    )
    detector.observe(_framing("This is a sandbox, not real infrastructure."))
    incidents = detector.observe(
        _write(r"C:\Users\Shared\x.bin", at=_T0 + timedelta(minutes=30))
    )
    assert incidents == []


def test_no_framing_is_silent() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox"
    )
    # Sensor mutation with no preceding framing: nothing to chain.
    incidents = detector.observe(_write(r"C:\Users\Shared\x.bin"))
    assert incidents == []


def test_non_sim_reasoning_does_not_frame() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox"
    )
    detector.observe(_framing("The refactor touches three modules."))
    incidents = detector.observe(_write(r"C:\Users\Shared\x.bin"))
    assert incidents == []


def test_agent_claimed_framing_on_command_event() -> None:
    detector = ContainmentEscapeDetector(
        _SID, workspace_root=r"C:\work\sandbox"
    )
    cmd = CommandEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.MEDIUM,
        command="rm -rf /tmp/payload",
        payload={"reasoning": "its fine, all traffic is contained in the simulation"},
        timestamp=_T0,
    )
    detector.observe(cmd)
    incidents = detector.observe(
        _write(r"C:\work\real\company_db.csv", at=_T0 + timedelta(minutes=2))
    )
    assert len(incidents) == 1
