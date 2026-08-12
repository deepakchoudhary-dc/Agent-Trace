"""Tests for the event ledger — hash chain integrity and CRUD operations."""

import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    EventType,
    FileMutationEvent,
)
from agenttrace.storage.ledger import EventLedger


@pytest.fixture
def ledger(tmp_path: Path) -> EventLedger:
    """Create a fresh ledger for each test."""
    db_path = tmp_path / "test_ledger.db"
    return EventLedger(db_path)


@pytest.fixture
def session_id():
    return uuid4()


class TestEventLedger:
    """Tests for EventLedger operations."""

    def test_create_session(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(
            session_id=session_id,
            config_json='{"workspace_path": "/test"}',
            task_desc="Test task",
            started_at="2024-01-01T00:00:00Z",
        )
        session = ledger.get_session(session_id)
        assert session is not None
        assert session["task_desc"] == "Test task"

    def test_append_event(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        event = EventBase(
            event_type=EventType.FILE_MUTATION,
            actor_id="test",
            session_id=session_id,
            source_adapter="test",
        )
        event_hash = ledger.append_event(event)
        assert len(event_hash) == 64

    def test_hash_chain(self, ledger: EventLedger, session_id) -> None:
        """Verify that events form a proper hash chain."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        events = []
        for i in range(5):
            event = EventBase(
                event_type=EventType.COMMAND,
                actor_id=f"actor-{i}",
                session_id=session_id,
                source_adapter="test",
                payload={"index": i},
            )
            ledger.append_event(event)
            events.append(event)

        # Verify chain integrity
        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid, f"Chain should be valid: {error}"

    def test_chain_verification_empty(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid

    def test_query_events(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        # Add events of different types
        for etype in [EventType.FILE_MUTATION, EventType.COMMAND, EventType.FILE_MUTATION]:
            event = EventBase(
                event_type=etype,
                actor_id="test",
                session_id=session_id,
                source_adapter="test",
            )
            ledger.append_event(event)

        # Query all
        all_events = ledger.query_events(session_id)
        assert len(all_events) == 3

        # Query by type
        file_events = ledger.query_events(session_id, event_type=EventType.FILE_MUTATION)
        assert len(file_events) == 2

    def test_session_event_count(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        for _ in range(3):
            event = EventBase(
                event_type=EventType.COMMAND,
                actor_id="test",
                session_id=session_id,
                source_adapter="test",
            )
            ledger.append_event(event)

        session = ledger.get_session(session_id)
        assert session is not None
        assert session["event_count"] == 3

    def test_graph_node_storage(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        node_id = uuid4()
        ledger.store_graph_node(
            node_id=node_id,
            session_id=session_id,
            node_type="source_file",
            label="main.py",
            timestamp="2024-01-01T00:00:00Z",
        )

        nodes = ledger.get_graph_nodes(session_id)
        assert len(nodes) == 1
        assert nodes[0]["label"] == "main.py"

    def test_approval_storage(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        approval_id = uuid4()
        ledger.store_approval(
            approval_id=approval_id,
            session_id=session_id,
            finding_id="finding-001",
            approved=True,
            reason="Safe operation",
            created_at="2024-01-01T00:00:00Z",
        )
        # No error means success
