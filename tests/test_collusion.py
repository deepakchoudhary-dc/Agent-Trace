"""S5-4: multi-agent collusion correlation - observable half only."""

from pathlib import Path
from uuid import UUID, uuid4

from agenttrace.graph.collusion import CollusionCandidate, CollusionCorrelationEngine
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    NetworkEvent,
)
from agenttrace.security.encryption import EncryptionManager
from agenttrace.storage.ledger import EventLedger


def _ledger(tmp_path: Path) -> EventLedger:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = EncryptionManager(key_dir)
    return EventLedger(tmp_path / "collusion.db", encryption_mgr=mgr)


def _session(ledger: EventLedger, workspace: str, task: str) -> UUID:
    sid = uuid4()
    ledger.create_session(
        sid,
        '{"workspace_path": "' + workspace + '", "internet_access_allowed": null}',
        task,
        "2026-01-01T00:00:00Z",
    )
    return sid


class TestSharedArtifact:
    def test_cross_session_same_file_is_candidate(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")

        ev1 = FileMutationEvent(
            session_id=s1,
            actor_id="agentA",
            source_adapter="fs",
            file_path="/ws/shared.py",
            mutation_type="modify",
        )
        ev2 = FileMutationEvent(
            session_id=s2,
            actor_id="agentB",
            source_adapter="fs",
            file_path="/ws/shared.py",
            mutation_type="modify",
        )
        ledger.append_event(ev1)
        ledger.append_event(ev2)

        candidates = CollusionCorrelationEngine(ledger).candidates()
        shared = [c for c in candidates if c.signal == "shared_artifact"]
        assert len(shared) == 1
        c = shared[0]
        assert set(c.session_ids) == {str(s1), str(s2)}
        assert set(c.actors) == {"agentA", "agentB"}
        assert c.confidence == ConfidenceLevel.HIGH
        assert c.detail == "/ws/shared.py"
        assert set(c.evidence_event_ids) == {str(ev1.event_id), str(ev2.event_id)}
        assert "not observable" in c.reasoning_gap

    def test_same_actor_twice_is_not_a_candidate(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")
        for sid, actor in ((s1, "agentA"), (s2, "agentA")):
            ledger.append_event(FileMutationEvent(
                session_id=sid, actor_id=actor, source_adapter="fs",
                file_path="/ws/own.py", mutation_type="modify",
            ))
        ledger.append_event(FileMutationEvent(
            session_id=s1, actor_id="agentA", source_adapter="fs",
            file_path="/ws/own.py", mutation_type="modify",
        ))
        shared = [
            c for c in CollusionCorrelationEngine(ledger).candidates()
            if c.signal == "shared_artifact"
        ]
        assert shared == []


class TestReusedEgress:
    def test_same_destination_two_sessions(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")
        for sid, actor in ((s1, "agentA"), (s2, "agentB")):
            ledger.append_event(NetworkEvent(
                session_id=sid, actor_id=actor, source_adapter="net",
                destination_ip="203.0.113.9", destination_port=443,
                protocol="tcp", direction="outbound",
            ))
        reused = [
            c for c in CollusionCorrelationEngine(ledger).candidates()
            if c.signal == "reused_egress"
        ]
        assert len(reused) == 1
        c = reused[0]
        assert c.detail == "203.0.113.9:443"
        assert set(c.session_ids) == {str(s1), str(s2)}
        assert c.confidence == ConfidenceLevel.MEDIUM


class TestSharedActor:
    def test_actor_driving_two_sessions(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")
        for sid in (s1, s2):
            ledger.append_event(CommandEvent(
                session_id=sid, actor_id="codex", source_adapter="shell",
                command="ls", working_dir="/ws",
            ))
        shared = [
            c for c in CollusionCorrelationEngine(ledger).candidates()
            if c.signal == "shared_actor"
        ]
        assert len(shared) == 1
        assert shared[0].detail == "codex"
        assert set(shared[0].session_ids) == {str(s1), str(s2)}
        assert shared[0].confidence == ConfidenceLevel.HIGH

    def test_infra_actors_are_excluded(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")
        for sid in (s1, s2):
            ledger.append_event(CommandEvent(
                session_id=sid, actor_id="user", source_adapter="shell",
                command="ls", working_dir="/ws",
            ))
        assert CollusionCorrelationEngine(ledger).candidates() == []


class TestIsolation:
    def test_single_session_workspace_yields_nothing(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "only")
        ledger.append_event(CommandEvent(
            session_id=s1, actor_id="agentA", source_adapter="shell",
            command="ls", working_dir="/ws",
        ))
        assert CollusionCorrelationEngine(ledger).candidates() == []
        assert CollusionCorrelationEngine(ledger).for_session(uuid4()) == []

    def test_to_dict_serializes_enums(self) -> None:
        c = CollusionCandidate(
            signal="shared_actor",
            session_ids=["a"],
            actors=["agentA"],
            detail="agentA",
            confidence=ConfidenceLevel.HIGH,
            evidence_event_ids=["e1"],
            reasoning_gap="gap",
        )
        d = c.to_dict()
        assert d["confidence"] == "high"
        assert isinstance(d, dict)


class TestComplementaryRoles:
    def test_escalation_cleanup_pairing_across_linked_sessions(
        self, tmp_path: Path
    ) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")

        # Session 1 reaches for privilege; session 2 erases traces; both
        # share actor identity "agentA" (same identity driving both).
        ledger.append_event(CommandEvent(
            session_id=s1, actor_id="agentA", source_adapter="shell",
            command="sudo chmod 4755 /usr/bin/env",
        ))
        ledger.append_event(CommandEvent(
            session_id=s2, actor_id="agentA", source_adapter="shell",
            command="shred ~/.bash_history",
        ))

        candidates = CollusionCorrelationEngine(ledger).candidates()
        comp = [c for c in candidates if c.signal == "complementary_roles"]
        assert len(comp) == 1
        assert set(comp[0].session_ids) == {str(s1), str(s2)}
        assert comp[0].confidence == ConfidenceLevel.MEDIUM

    def test_unlinked_sessions_are_not_candidates(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        s2 = _session(ledger, "/ws", "b")

        # Same behavior families but NO shared actor or egress destination.
        ledger.append_event(CommandEvent(
            session_id=s1, actor_id="soloA", source_adapter="shell",
            command="sudo chmod 4755 /usr/bin/env",
        ))
        ledger.append_event(CommandEvent(
            session_id=s2, actor_id="soloB", source_adapter="shell",
            command="shred ~/.bash_history",
        ))

        candidates = CollusionCorrelationEngine(ledger).candidates()
        assert not any(c.signal == "complementary_roles" for c in candidates)

    def test_single_session_doing_both_is_not_a_pair(self, tmp_path: Path) -> None:
        ledger = _ledger(tmp_path)
        s1 = _session(ledger, "/ws", "a")
        _session(ledger, "/ws", "b")
        # Both behaviors inside ONE session; other session is quiet.
        ledger.append_event(CommandEvent(
            session_id=s1, actor_id="agentA", source_adapter="shell",
            command="sudo chmod 4755 /usr/bin/env",
        ))
        ledger.append_event(CommandEvent(
            session_id=s1, actor_id="agentA", source_adapter="shell",
            command="shred ~/.bash_history",
        ))
        candidates = CollusionCorrelationEngine(ledger).candidates()
        assert not any(c.signal == "complementary_roles" for c in candidates)
