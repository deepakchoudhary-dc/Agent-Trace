"""Tests for the persistent actor-identity graph (plan2 METR #2 deeper half).

Collusion and credential loops correlate within runs; this module is the
memory of WHO operated across them. Tests pin the two incident families,
the silent restart seeding, and the cooldown behavior.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.actor_identity import ActorIdentityGraph
from agenttrace.models.events import CommandEvent, ConfidenceLevel

_T0 = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
_SID_A = uuid4()
_SID_B = uuid4()


def _cmd(
    sid: object,
    command: str,
    actor: str = "agent-x",
    at: datetime | None = None,
) -> CommandEvent:
    return CommandEvent(
        session_id=sid,  # type: ignore[arg-type]
        actor_id=actor,
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        timestamp=at or _T0,
    )


def _fme(
    sid: object,
    path: str,
    size: int,
    at: datetime,
    actor: str = "agent-a",
) -> object:
    from agenttrace.models.events import FileMutationEvent

    return FileMutationEvent(
        session_id=sid,  # type: ignore[arg-type]
        actor_id=actor,
        source_adapter="filesystem_observer",
        file_path=path,
        mutation_type="create",
        size_delta=size,
        timestamp=at,
    )


# -- Reincarnation ------------------------------------------------------------------


def test_actor_spanning_two_sessions_fires() -> None:
    graph = ActorIdentityGraph()
    assert graph.observe(_cmd(_SID_A, "echo 1")) == []
    incidents = graph.observe(_cmd(_SID_B, "echo 2"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "actor_reincarnated"
    assert incidents[0].severity == "medium"
    assert incidents[0].session_id == _SID_B


def test_reincarnation_cooldown_and_persistence() -> None:
    graph = ActorIdentityGraph()
    graph.observe(_cmd(_SID_A, "echo 1"))
    graph.observe(_cmd(_SID_B, "echo 2"))
    # Same actor, third session inside the cooldown window: silent.
    assert graph.observe(_cmd(uuid4(), "echo 3")) == []
    # After the cooldown: fires again with updated session count.
    later = _T0 + timedelta(hours=2)
    incidents = graph.observe(_cmd(uuid4(), "echo 4", at=later))
    assert len(incidents) == 1


def test_distinct_actors_stay_silent() -> None:
    graph = ActorIdentityGraph()
    assert graph.observe(_cmd(_SID_A, "echo 1", actor="a")) == []
    assert graph.observe(_cmd(_SID_B, "echo 2", actor="b")) == []


# -- Handoff dossiers -----------------------------------------------------------------


def test_dossier_handoff_fires_high() -> None:
    """Session A installs a large artifact minutes before closing; a
    different session writes into the same directory after the close."""
    graph = ActorIdentityGraph()
    big = "C:/ws/board/zzDOSSIER.bin"
    graph.observe(_fme(_SID_A, big, 8192, _T0))
    graph.close_session(_SID_A, _T0 + timedelta(minutes=5))

    handoff = graph.observe(
        _fme(_SID_B, "C:/ws/board/next.bin", 10, _T0 + timedelta(minutes=30), actor="agent-b")
    )
    assert len(handoff) == 1
    assert handoff[0].incident_type == "handoff_dossier_suspected"
    assert handoff[0].severity == "high"


def test_write_outside_dossier_window_is_silent() -> None:
    """A large write long before close is not a handoff candidate."""
    graph = ActorIdentityGraph()
    graph.observe(_fme(_SID_A, "C:/ws/board/d.bin", 8192, _T0))
    graph.close_session(_SID_A, _T0 + timedelta(hours=2))
    assert graph.observe(
        _fme(_SID_B, "C:/ws/board/next.bin", 10, _T0 + timedelta(hours=3), actor="agent-b")
    ) == []


def test_small_files_are_not_dossiers() -> None:
    graph = ActorIdentityGraph()
    graph.observe(_fme(_SID_A, "C:/ws/board/notes.txt", 100, _T0))
    graph.close_session(_SID_A, _T0 + timedelta(minutes=5))
    assert graph.observe(
        _fme(_SID_B, "C:/ws/board/next.txt", 10, _T0 + timedelta(minutes=30), actor="agent-b")
    ) == []


def test_same_directory_pairing_only(tmp_path: object) -> None:
    graph = ActorIdentityGraph()
    graph.observe(_fme(_SID_A, "C:/ws/board/d.bin", 8192, _T0))
    graph.close_session(_SID_A, _T0 + timedelta(minutes=5))
    assert graph.observe(
        _fme(_SID_B, "C:/ws/elsewhere/next.bin", 10, _T0 + timedelta(minutes=30), actor="agent-b")
    ) == []


# -- Restart memory ---------------------------------------------------------------------


def test_seed_is_silent_but_remembers() -> None:
    graph = ActorIdentityGraph()
    graph.seed_event(_cmd(_SID_A, "echo 1"))
    # Seeding emits nothing for already-recorded history...
    assert graph.seed_event(_cmd(_SID_B, "echo 2")) is None
    # ...but the memory is live: a THIRD session for the same actor fires.
    incidents = graph.observe(_cmd(uuid4(), "echo 3"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "actor_reincarnated"


def test_incident_events_are_never_absorbed() -> None:
    from agenttrace.models.events import IncidentEvent

    graph = ActorIdentityGraph()
    incident = IncidentEvent(
        session_id=_SID_A,
        actor_id="actor_identity",
        source_adapter="actor_identity",
        incident_type="actor_reincarnated",
        severity="medium",
        title="t",
        description="d",
    )
    assert graph.observe(incident) == []
    assert graph._actors.get("actor_identity") is None


# -- Reviewer findings: Windows paths, post-close writes, empty handles ----------


def test_windows_backslash_paths_still_pair_by_directory() -> None:
    """Backslash paths contain no '/', so without normalization the
    'directory' becomes the full path and pairing degrades to
    same-exact-file — confirmed empirically before the fix."""
    graph = ActorIdentityGraph()
    graph.observe(_fme(_SID_A, "C:\\ws\\board\\d.bin", 8192, _T0))
    graph.close_session(_SID_A, _T0 + timedelta(minutes=5))
    handoff = graph.observe(
        _fme(_SID_B, "C:\\ws\\board\\next.bin", 10, _T0 + timedelta(minutes=30), actor="agent-b")
    )
    assert len(handoff) == 1
    assert handoff[0].incident_type == "handoff_dossier_suspected"


def test_post_close_large_write_is_not_a_dossier_candidate() -> None:
    """A large write attributed to an already-closed session is post-close
    behavior (#6 machinery): absorbing it as a dossier candidate would
    fabricate a 'written inside the final minutes' claim."""
    graph = ActorIdentityGraph()
    graph.close_session(_SID_A, _T0)
    graph.observe(_fme(_SID_A, "C:/ws/board/late.bin", 8192, _T0 + timedelta(minutes=2)))
    assert graph.observe(
        _fme(_SID_B, "C:/ws/board/next.bin", 10, _T0 + timedelta(minutes=30), actor="agent-b")
    ) == []


def test_empty_actor_id_is_not_an_identity() -> None:
    """Two anonymous handles in different sessions must not correlate into
    a phantom reincarnated adversary."""
    graph = ActorIdentityGraph()
    graph.observe(_cmd(_SID_A, "echo 1", actor=""))
    assert graph.observe(_cmd(_SID_B, "echo 2", actor="")) == []
