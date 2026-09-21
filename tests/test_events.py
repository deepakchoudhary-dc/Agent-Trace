"""Tests for canonical event models and hash-chain integrity."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from agenttrace.models.events import (
    ApprovalEvent,
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    EventType,
    FileMutationEvent,
    InvocationEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ProcessEvent,
    ToolRequestEvent,
    event_from_dict,
)


class TestEventBase:
    """Tests for EventBase model and hash computation."""

    def test_event_creation(self) -> None:
        event = EventBase(
            event_type=EventType.FILE_MUTATION,
            actor_id="test-actor",
            session_id=uuid4(),
            source_adapter="test",
        )
        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.confidence == ConfidenceLevel.HIGH
        assert event.prev_hash == ""
        assert event.event_hash == ""

    def test_hash_computation(self) -> None:
        session_id = uuid4()
        event = EventBase(
            event_type=EventType.FILE_MUTATION,
            actor_id="test-actor",
            session_id=session_id,
            source_adapter="test",
        )
        hash1 = event.compute_hash()
        assert len(hash1) == 64  # SHA-256 hex
        assert hash1 == event.compute_hash()  # Deterministic

    def test_seal_with_chain(self) -> None:
        session_id = uuid4()
        event1 = EventBase(
            event_type=EventType.FILE_MUTATION,
            actor_id="actor",
            session_id=session_id,
            source_adapter="test",
        )
        event1.seal("")
        assert event1.prev_hash == ""
        assert len(event1.event_hash) == 64

        event2 = EventBase(
            event_type=EventType.COMMAND,
            actor_id="actor",
            session_id=session_id,
            source_adapter="test",
        )
        event2.seal(event1.event_hash)
        assert event2.prev_hash == event1.event_hash
        assert event2.event_hash != event1.event_hash

    def test_hash_chain_integrity(self) -> None:
        """Verify that modifying an event breaks the chain."""
        session_id = uuid4()
        event = EventBase(
            event_type=EventType.COMMAND,
            actor_id="actor",
            session_id=session_id,
            source_adapter="test",
            payload={"cmd": "ls"},
        )
        event.seal("prev123")
        original_hash = event.event_hash

        # Modify payload
        event.payload = {"cmd": "rm -rf /"}
        new_hash = event.compute_hash()
        assert new_hash != original_hash  # Tampering detected


class TestSpecificEvents:
    """Tests for specific event type models."""

    def test_file_mutation_event(self) -> None:
        event = FileMutationEvent(
            actor_id="fs_watcher",
            session_id=uuid4(),
            source_adapter="filesystem_observer",
            file_path="/workspace/main.py",
            mutation_type="modify",
            before_hash="abc123",
            after_hash="def456",
        )
        assert event.event_type == EventType.FILE_MUTATION
        assert event.file_path == "/workspace/main.py"

    def test_invocation_event(self) -> None:
        event = InvocationEvent(
            actor_id="codex:session1",
            session_id=uuid4(),
            source_adapter="codex_cli",
            user_intent="Fix the authentication bug",
            agent_name="codex",
            agent_version="1.0",
        )
        assert event.event_type == EventType.INVOCATION
        assert event.user_intent == "Fix the authentication bug"

    def test_tool_request_event(self) -> None:
        event = ToolRequestEvent(
            actor_id="codex:session1",
            session_id=uuid4(),
            source_adapter="codex_cli",
            tool_name="shell",
            tool_args={"command": "pytest"},
            requires_approval=False,
        )
        assert event.event_type == EventType.TOOL_REQUEST
        assert event.tool_name == "shell"

    def test_process_event(self) -> None:
        event = ProcessEvent(
            actor_id="process:1234",
            session_id=uuid4(),
            source_adapter="process_tree_observer",
            pid=1234,
            ppid=1000,
            command_line="python -m pytest",
        )
        assert event.event_type == EventType.PROCESS
        assert event.pid == 1234

    def test_network_event(self) -> None:
        event = NetworkEvent(
            actor_id="process:5678",
            session_id=uuid4(),
            source_adapter="network_observer",
            destination_ip="1.2.3.4",
            destination_port=443,
            protocol="tcp",
            direction="outbound",
        )
        assert event.event_type == EventType.NETWORK
        assert event.destination_ip == "1.2.3.4"

    def test_approval_event(self) -> None:
        event = ApprovalEvent(
            actor_id="user",
            session_id=uuid4(),
            source_adapter="approval_manager",
            finding_id="finding-001",
            approved=True,
            reason="Verified safe",
            scope="workspace",
            affected_paths=["/workspace/config.py"],
        )
        assert event.event_type == EventType.APPROVAL
        assert event.approved is True

    def test_policy_finding_event(self) -> None:
        event = PolicyFindingEvent(
            actor_id="policy_engine",
            session_id=uuid4(),
            source_adapter="policy_engine",
            finding_type="credential_access",
            severity="critical",
            description="Credential file accessed",
            requires_approval=True,
        )
        assert event.event_type == EventType.POLICY_FINDING
        assert event.severity == "critical"


class TestCanonicalEnvelopeBackwardCompatibility:
    """Adding a field to the hash preimage must not invalidate sealed history.

    The verifier rebuilds the event from its stored envelope and RECOMPUTES the
    hash from the model, so a field added to `canonical_dict` after events were
    already sealed would recompute every historical row to a different digest —
    the whole ledger would read as "cryptographic tamper detected". `observed_at`
    is therefore omitted from the preimage while unset, and committed once set.
    """

    def _seal_as_legacy(self, event: EventBase) -> str:
        """Hash the event the way it was hashed BEFORE observed_at existed."""
        envelope = event.model_dump(mode="json")
        envelope.pop("observed_at", None)
        envelope.pop("event_hash", None)
        canonical = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def test_envelope_without_observed_at_still_verifies(self) -> None:
        event = CommandEvent(
            session_id=uuid4(),
            actor_id="codex:abc",
            source_adapter="codex_cli",
            command="ls",
        )
        legacy_hash = self._seal_as_legacy(event)

        # Exactly what the ledger does on read: rebuild from the stored envelope.
        stored = event.model_dump(mode="json")
        stored.pop("observed_at", None)
        rebuilt = event_from_dict(stored)

        assert rebuilt.compute_hash() == legacy_hash
        assert rebuilt.observed_at is None

    def test_observed_at_is_committed_once_set(self) -> None:
        event = CommandEvent(
            session_id=uuid4(),
            actor_id="codex:abc",
            source_adapter="codex_cli",
            command="ls",
        )
        event.observed_at = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

        assert "observed_at" in event.canonical_dict()
        assert event_from_dict(event.canonical_dict()).compute_hash() == event.compute_hash()

    def test_backdating_the_observation_clock_is_detected(self) -> None:
        """The value is genuinely protected, not merely present."""
        event = CommandEvent(
            session_id=uuid4(),
            actor_id="codex:abc",
            source_adapter="codex_cli",
            command="ls",
        )
        event.observed_at = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        original = event.compute_hash()

        tampered = event_from_dict(event.canonical_dict())
        tampered.observed_at = datetime(2020, 1, 1, tzinfo=timezone.utc)

        assert tampered.compute_hash() != original
