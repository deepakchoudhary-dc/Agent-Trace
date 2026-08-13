"""Tests for the event ledger — hash chain integrity, field tampering, and encrypted storage."""

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    EventType,
    FileMutationEvent,
    ToolRequestEvent,
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

    def test_append_typed_event(self, ledger: EventLedger, session_id) -> None:
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        event = FileMutationEvent(
            session_id=session_id,
            actor_id="test_worker",
            source_adapter="test_adapter",
            file_path="src/main.py",
            mutation_type="modify",
            before_hash="a" * 64,
            after_hash="b" * 64,
            diff_summary="+ new code",
        )
        event_hash = ledger.append_event(event)
        assert len(event_hash) == 64

        # Retrieve and verify concrete typed attributes
        retrieved = ledger.get_event(event.event_id)
        assert isinstance(retrieved, FileMutationEvent)
        assert retrieved.file_path == "src/main.py"
        assert retrieved.before_hash == "a" * 64
        assert retrieved.diff_summary == "+ new code"

    def test_hash_chain_verification(self, ledger: EventLedger, session_id) -> None:
        """Verify that events form a continuous, verifiable cryptographic hash chain."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        # Ingest sequence of heterogeneous events
        e1 = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="git status",
        )
        e2 = FileMutationEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="filesystem",
            file_path="app.py",
            mutation_type="modify",
        )
        e3 = ToolRequestEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="codex",
            tool_name="read_file",
            tool_args={"path": "app.py"},
        )

        h1 = ledger.append_event(e1)
        h2 = ledger.append_event(e2)
        h3 = ledger.append_event(e3)

        assert e2.prev_hash == h1
        assert e3.prev_hash == h2

        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid, f"Chain should be verified: {error}"

    def test_tamper_detection_on_field_modification(self, ledger: EventLedger, session_id) -> None:
        """Adversarial test: direct database tampering of any field breaks chain verification."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        event = FileMutationEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="filesystem",
            file_path="sensitive.py",
            mutation_type="modify",
        )
        ledger.append_event(event)

        # Directly tamper with canonical_json in SQLite
        db_path = ledger._db_path
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT canonical_json FROM events WHERE session_id = ?", (str(session_id),)).fetchone()
        data = json.loads(row[0])
        data["file_path"] = "attacker_modified.py"  # Tamper field!
        conn.execute("UPDATE events SET canonical_json = ? WHERE session_id = ?", (json.dumps(data), str(session_id)))
        conn.commit()
        conn.close()

        # Chain verification must detect the tamper
        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Cryptographic tamper detected" in error

    def test_tamper_detection_on_sequence_discontinuity(self, ledger: EventLedger, session_id) -> None:
        """Adversarial test: sequence skip or deletion is detected."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        e1 = CommandEvent(session_id=session_id, actor_id="agent", source_adapter="terminal", command="cmd 1")
        e2 = CommandEvent(session_id=session_id, actor_id="agent", source_adapter="terminal", command="cmd 2")
        ledger.append_event(e1)
        ledger.append_event(e2)

        # Tamper sequence number
        conn = sqlite3.connect(str(ledger._db_path))
        conn.execute("UPDATE events SET seq = 5 WHERE event_id = ?", (str(e2.event_id),))
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Sequence discontinuity" in error

    def test_database_at_rest_encryption(self, ledger: EventLedger, session_id) -> None:
        """Verify that raw database rows store ciphertext and no plaintext secrets."""
        secret_task = "Super secret project description with key API_KEY_999"
        secret_reason = "Approved because token secret_xyz is verified"

        ledger.create_session(session_id, '{"env": "secret"}', task_desc=secret_task)
        ledger.store_approval(
            approval_id=uuid4(),
            session_id=session_id,
            finding_id="find-1",
            approved=True,
            reason=secret_reason,
            scope="secret_path",
        )

        # Read raw SQLite bytes directly without ledger abstraction
        conn = sqlite3.connect(str(ledger._db_path))
        session_row = conn.execute("SELECT config_enc, task_desc_enc FROM sessions WHERE session_id = ?", (str(session_id),)).fetchone()
        approval_row = conn.execute("SELECT reason_enc, scope_enc FROM approvals WHERE session_id = ?", (str(session_id),)).fetchone()
        conn.close()

        # Plaintext secrets must NOT be in the raw DB bytes
        assert isinstance(session_row[0], bytes)
        assert isinstance(session_row[1], bytes)
        assert b"API_KEY_999" not in session_row[1]
        assert b"secret_xyz" not in approval_row[0]

        # But decrypted getters should return sanitized plaintext
        s = ledger.get_session(session_id)
        assert s is not None
        assert "Super secret project" in s["task_desc"]
