"""Tests for the event ledger — hash chain integrity, field tampering, and encrypted storage."""

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.models.events import (
    CommandEvent,
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

    def test_adapter_cursor_roundtrip(self, ledger: EventLedger) -> None:
        sid = uuid4()
        ledger.create_session(
            session_id=sid,
            config_json='{"workspace_path": "/test"}',
            task_desc="Cursor",
            started_at="2024-01-01T00:00:00Z",
        )
        assert ledger.get_adapter_cursor(sid) is None

        ledger.save_adapter_cursor(
            sid,
            "claude_code",
            {"positions": {"/home/u/.claude/s.jsonl": 12345}, "invoked": ["/x"]},
        )
        cursor = ledger.get_adapter_cursor(sid)
        assert cursor is not None
        assert cursor["adapter_name"] == "claude_code"
        assert cursor["cursor"]["positions"]["/home/u/.claude/s.jsonl"] == 12345

        # Upsert replaces the previous cursor in place
        ledger.save_adapter_cursor(sid, "claude_code", {"positions": {}})
        cursor2 = ledger.get_adapter_cursor(sid)
        assert cursor2 is not None
        assert cursor2["cursor"] == {"positions": {}}

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
        ledger.append_event(e3)

        assert e2.prev_hash == h1
        assert e3.prev_hash == h2

        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid, f"Chain should be verified: {error}"

    def test_tamper_detection_on_envelope_hash(self, ledger: EventLedger, session_id) -> None:
        """Adversarial test: rewriting the stored envelope tamper hash is detected."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        event = FileMutationEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="filesystem",
            file_path="sensitive.py",
            mutation_type="modify",
        )
        ledger.append_event(event)

        # Tamper the stored envelope hash column (an attacker with DB write
        # access rewrites it to match their forged envelope)
        conn = sqlite3.connect(str(ledger._db_path))
        conn.execute(
            "UPDATE events SET canonical_json_hash = ? WHERE session_id = ?",
            ("0" * 64, str(session_id)),
        )
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Envelope tamper detected" in error

    def test_tamper_detection_on_encrypted_envelope(self, ledger: EventLedger, session_id) -> None:
        """Adversarial test: flipping bytes in the encrypted envelope is detected."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        event = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="rm -rf --no-preserve-root",
        )
        ledger.append_event(event)

        conn = sqlite3.connect(str(ledger._db_path))
        row = conn.execute(
            "SELECT canonical_json_enc FROM events WHERE session_id = ?", (str(session_id),),
        ).fetchone()
        assert row is not None and row[0] is not None
        tampered = bytearray(row[0])
        tampered[-1] ^= 0xFF  # AES-GCM tag will fail
        conn.execute(
            "UPDATE events SET canonical_json_enc = ? WHERE session_id = ?",
            (bytes(tampered), str(session_id)),
        )
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid

    def test_tamper_detection_on_sequence_discontinuity(
        self, ledger: EventLedger, session_id
    ) -> None:
        """Adversarial test: sequence skip or deletion is detected."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")

        e1 = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="cmd 1",
        )
        e2 = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="cmd 2",
        )
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
        # Deliberately NOT redactable by the redactor's regexes, so this assertion
        # proves at-rest ENCRYPTION (not redaction) hides it from the raw DB
        secret_command = "echo DB_PASSWORD_xyz > /tmp/creds.txt"

        ledger.create_session(session_id, '{"env": "secret"}', task_desc=secret_task)
        ledger.store_approval(
            approval_id=uuid4(),
            session_id=session_id,
            finding_id="find-1",
            approved=True,
            reason=secret_reason,
            scope="secret_path",
        )
        # A command event whose full envelope would previously have been plaintext
        ledger.append_event(CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command=secret_command,
        ))

        # Read raw SQLite bytes directly without ledger abstraction
        conn = sqlite3.connect(str(ledger._db_path))
        session_row = conn.execute(
            "SELECT config_enc, task_desc_enc FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        approval_row = conn.execute(
            "SELECT reason_enc, scope_enc FROM approvals WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        event_row = conn.execute(
            "SELECT canonical_json, canonical_json_enc, canonical_json_hash "
            "FROM events WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        conn.close()

        # Plaintext secrets must NOT be in the raw DB bytes
        assert isinstance(session_row[0], bytes)
        assert isinstance(session_row[1], bytes)
        assert b"API_KEY_999" not in session_row[1]
        assert b"secret_xyz" not in approval_row[0]

        # Event envelopes are encrypted at rest: no plaintext column, encrypted blob,
        # and a 64-hex tamper hash — with no plaintext command anywhere in the DB
        # (check both the main DB file and the WAL, where un-checkpointed rows live)
        assert event_row[0] == ""  # legacy plaintext column is intentionally empty
        assert isinstance(event_row[1], bytes)
        assert len(event_row[2]) == 64
        raw_bytes = Path(ledger._db_path).read_bytes()
        wal_path = Path(str(ledger._db_path) + "-wal")
        if wal_path.exists():
            raw_bytes += wal_path.read_bytes()
        assert secret_command.encode() not in raw_bytes

        # But decrypted getters should return the plaintext round-trip
        s = ledger.get_session(session_id)
        assert s is not None
        assert "Super secret project" in s["task_desc"]

        events = ledger.query_events(session_id)
        assert any(isinstance(e, CommandEvent) and e.command == secret_command for e in events)

    def test_tamper_detection_on_index_binding(self, ledger: EventLedger, session_id) -> None:
        """Adversarial test: rewriting an indexed column without touching the
        envelope is detected — the binding hash authenticates the projection."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        event = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="git push",
        )
        ledger.append_event(event)

        # Rewrite an indexed column (e.g. re-attribute the action to another
        # actor). The encrypted envelope still holds the true actor_id, so the
        # old code's hash-chain verification would pass.
        conn = sqlite3.connect(str(ledger._db_path))
        conn.execute(
            "UPDATE events SET actor_id = 'innocent_user' WHERE event_id = ?",
            (str(event.event_id),),
        )
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Index binding tamper detected" in error

    def test_tamper_detection_on_seq_rewrite(self, ledger: EventLedger, session_id) -> None:
        """Row-order swaps are blocked at two levels: the UNIQUE(session_id,
        seq) index rejects the direct swap, and the binding hash catches a
        stepwise swap that keeps monotonicity and prev links superficially
        valid — which the old chain checks would have passed completely."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        e1 = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="cmd 1",
        )
        e2 = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="cmd 2",
        )
        h1 = ledger.append_event(e1)
        ledger.append_event(e2)

        conn = sqlite3.connect(str(ledger._db_path))

        # Level 1: the unique index rejects the direct swap outright
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE events SET seq = 0 WHERE event_id = ?",
                (str(e2.event_id),),
            )
        conn.rollback()

        # Level 2: a stepwise swap (temporary seq avoids the unique index)
        # with patched prev_hash columns still trips the binding hash.
        conn.execute("UPDATE events SET seq = 2 WHERE event_id = ?", (str(e2.event_id),))
        conn.execute(
            "UPDATE events SET seq = 1, prev_hash = ? WHERE event_id = ?",
            (h1, str(e1.event_id)),
        )
        conn.execute(
            "UPDATE events SET seq = 0, prev_hash = '' WHERE event_id = ?",
            (str(e2.event_id),),
        )
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Index binding tamper detected" in error

    def test_read_path_rejects_tampered_event(self, ledger: EventLedger, session_id) -> None:
        """The read path must surface tampering instead of silently returning
        or skipping a compromised row."""
        from agenttrace.storage.ledger import LedgerError

        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        event = FileMutationEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="filesystem",
            file_path="app.py",
            mutation_type="modify",
        )
        ledger.append_event(event)

        conn = sqlite3.connect(str(ledger._db_path))
        conn.execute(
            "UPDATE events SET canonical_json_hash = ? WHERE event_id = ?",
            ("0" * 64, str(event.event_id)),
        )
        conn.commit()
        conn.close()

        with pytest.raises(LedgerError):
            ledger.get_event(event.event_id)
        with pytest.raises(LedgerError):
            ledger.query_events(session_id)

    def test_payload_drift_detected(self, ledger: EventLedger, session_id) -> None:
        """A payload_enc that no longer matches the envelope payload is drift."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        event = ToolRequestEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="codex",
            tool_name="read_file",
            tool_args={"path": "app.py"},
            payload={"rollout": "r1"},
        )
        ledger.append_event(event)

        # Swap payload_enc with an encryption of different content
        from agenttrace.security.encryption import EncryptionManager

        conn = sqlite3.connect(str(ledger._db_path))
        swapped = EncryptionManager().encrypt_json({"rollout": "FORGED"})
        conn.execute(
            "UPDATE events SET payload_enc = ? WHERE event_id = ?",
            (swapped, str(event.event_id)),
        )
        conn.commit()
        conn.close()

        is_valid, error = ledger.verify_chain(session_id)
        assert not is_valid
        assert "Payload drift detected" in error

    def test_query_events_limit_none(self, ledger: EventLedger, session_id) -> None:
        """limit=None returns the full session chain, no truncation."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        for i in range(5):
            ledger.append_event(CommandEvent(
                session_id=session_id,
                actor_id="agent",
                source_adapter="terminal",
                command=f"cmd {i}",
            ))

        assert len(ledger.query_events(session_id, limit=None)) == 5
        assert len(ledger.query_events(session_id, limit=2)) == 2
        assert [e.seq for e in ledger.query_events(session_id, limit=None)] == [0, 1, 2, 3, 4]

    def test_query_events_default_limit_truncates_but_none_does_not(
        self, ledger: EventLedger, session_id
    ) -> None:
        """A session longer than the default 1000-event cap must not silently
        truncate reports — the report path passes limit=None."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        for i in range(1005):
            ledger.append_event(CommandEvent(
                session_id=session_id,
                actor_id="agent",
                source_adapter="terminal",
                command=f"cmd {i}",
            ))

        assert len(ledger.query_events(session_id)) == 1000
        assert len(ledger.query_events(session_id, limit=None)) == 1005

    def test_unique_seq_per_session_enforced(self, ledger: EventLedger, session_id) -> None:
        """(session_id, seq) is unique — duplicate chains are impossible."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        event = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="cmd",
        )
        ledger.append_event(event)

        conn = sqlite3.connect(str(ledger._db_path))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO events
                   (event_id, session_id, event_type, timestamp, actor_id,
                    source_adapter, confidence, canonical_json, canonical_json_enc,
                    canonical_json_hash, payload_enc, event_hash, prev_hash, seq,
                    index_binding_hash)
                   VALUES (?, ?, 'command', '2024-01-01T00:00:00+00:00', 'x',
                           'terminal', 'high', '', NULL, '', NULL, 'f' * 64, 'e' * 64,
                           0, '')""",
                (str(uuid4()), str(session_id)),
            )
        conn.close()

    def test_append_transaction_rolls_back_on_failure(
        self, ledger: EventLedger, session_id
    ) -> None:
        """A failing append must not leave a partial row or corrupt the chain."""
        ledger.create_session(session_id, "{}", "test", "2024-01-01T00:00:00Z")
        good = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="ok",
        )
        ledger.append_event(good)

        # A second event with the same event_id collides on the PK
        duplicate = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="collision",
        )
        duplicate.event_id = good.event_id
        with pytest.raises(sqlite3.IntegrityError):
            ledger.append_event(duplicate)

        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid, f"Chain must stay valid after a rolled-back append: {error}"
        assert ledger.get_session(session_id)["event_count"] == 1

    def test_rotate_encryption_reencrypts_everything(self, tmp_path: Path, session_id) -> None:
        """Full key rotation: all data readable under the new key, chain intact."""
        from agenttrace.security.encryption import EncryptionManager

        key_dir = tmp_path / "keys"
        ledger = EventLedger(tmp_path / "rot.db", encryption_mgr=EncryptionManager(key_dir))

        ledger.create_session(
            session_id, '{"workspace": "/ws"}', "secret task", "2024-01-01T00:00:00Z"
        )
        event = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="git push --force",
            payload={"extra": "sensitive"},
        )
        ledger.append_event(event)
        ledger.store_approval(
            approval_id=uuid4(),
            session_id=session_id,
            finding_id="f-1",
            approved=True,
            reason="approved because secret_token_abc",
        )
        ledger.store_graph_node(
            node_id=uuid4(),
            session_id=session_id,
            node_type="file",
            label="src/main.py",
            timestamp="2024-01-01T00:00:00Z",
        )
        ledger.store_task_contract(
            contract_id=uuid4(),
            session_id=session_id,
            goal="build feature",
        )

        new_key = ledger._encryption.prepare_rotation()
        ledger.rotate_encryption(new_key)
        ledger._encryption.commit_rotation(new_key)

        # Everything still readable and the chain verifies
        assert ledger.get_session(session_id)["task_desc"] == "secret task"
        retrieved = ledger.get_event(event.event_id)
        assert retrieved is not None and retrieved.command == "git push --force"
        assert retrieved.payload == {"extra": "sensitive"}
        assert ledger.get_approvals(session_id)[0]["reason"].endswith("secret_token_abc")
        assert ledger.get_graph_nodes(session_id)[0]["label"] == "src/main.py"
        assert ledger.get_task_contract(session_id)["goal"] == "build feature"
        is_valid, error = ledger.verify_chain(session_id)
        assert is_valid, f"Chain must verify after rotation: {error}"

    def test_rotate_encryption_failure_rolls_back(self, tmp_path: Path, session_id) -> None:
        """A rotation that fails mid-way must leave every row under the OLD key."""
        from agenttrace.security.encryption import EncryptionError, EncryptionManager

        ledger = EventLedger(
            tmp_path / "rot_fail.db",
            encryption_mgr=EncryptionManager(tmp_path / "keys_fail"),
        )
        ledger.create_session(session_id, "{}", "task", "2024-01-01T00:00:00Z")
        event = CommandEvent(
            session_id=session_id,
            actor_id="agent",
            source_adapter="terminal",
            command="keep me",
            payload={"k": "v"},
        )
        ledger.append_event(event)
        old_key = ledger._encryption._key

        new_key = ledger._encryption.prepare_rotation()
        original_decrypt = ledger._encryption.decrypt

        def broken_decrypt(data: bytes, associated_data: bytes | None = None) -> bytes:
            raise EncryptionError("simulated mid-rotation failure")

        ledger._encryption.decrypt = broken_decrypt  # type: ignore[method-assign]
        try:
            with pytest.raises(EncryptionError):
                ledger.rotate_encryption(new_key)
        finally:
            ledger._encryption.decrypt = original_decrypt

        # Nothing was committed: rows still decrypt with the old key
        assert ledger._encryption._key == old_key
        retrieved = ledger.get_event(event.event_id)
        assert retrieved is not None and retrieved.command == "keep me"
        assert ledger.get_session(session_id)["task_desc"] == "task"

    def test_rotation_survives_fresh_manager_on_same_key_dir(self, tmp_path: Path) -> None:
        """After rotation, a brand-new manager (fresh load from disk) reads data."""
        from agenttrace.security.encryption import EncryptionManager

        key_dir = tmp_path / "keys"
        db_path = tmp_path / "rot.db"
        mgr1 = EncryptionManager(key_dir)
        ledger = EventLedger(db_path, encryption_mgr=mgr1)
        sid = uuid4()
        ledger.create_session(sid, "{}", "rotate me", "2024-01-01T00:00:00Z")
        evt = CommandEvent(session_id=sid, actor_id="a", source_adapter="t", command="cmd")
        ledger.append_event(evt)

        new_key = mgr1.prepare_rotation()
        ledger.rotate_encryption(new_key)
        mgr1.commit_rotation(new_key)

        mgr2 = EncryptionManager(key_dir)  # loads the NEW key file
        ledger2 = EventLedger(db_path, encryption_mgr=mgr2)
        assert ledger2.get_session(sid)["task_desc"] == "rotate me"
        assert ledger2.get_event(evt.event_id).command == "cmd"  # type: ignore[union-attr]


class TestDestinationBaseline:
    def test_roundtrip_and_idempotency(self, ledger: EventLedger) -> None:
        ledger.add_destination_baseline("/ws", "142.250.72.14:443")
        ledger.add_destination_baseline("/ws", "142.250.72.14:443")
        ledger.add_destination_baseline("/ws", "185.220.101.1:9050")
        ledger.add_destination_baseline("/other", "10.0.0.1:80")

        assert ledger.get_destination_baseline("/ws") == {
            "142.250.72.14:443",
            "185.220.101.1:9050",
        }
        assert ledger.get_destination_baseline("/other") == {"10.0.0.1:80"}
        assert ledger.get_destination_baseline("/nowhere") == set()



class TestIntegritySurfacing:
    """Corrupt/tampered evidence must surface, never vanish into defaults."""

    def test_corrupt_session_config_is_counted_and_flagged(self, tmp_path: Path) -> None:
        ledger = EventLedger(tmp_path / "integrity.db")
        sid = uuid4()
        ledger.create_session(
            session_id=sid,
            config_json='{"goal": "x"}',
            task_desc="t",
            started_at="2026-08-20T12:00:00Z",
        )

        # Corrupt the stored ciphertext out-of-band (simulated tampering):
        # valid column, invalid ciphertext -> decrypt fails on read.
        ledger._conn.execute(
            "UPDATE sessions SET config_enc = '!!not-ciphertext!!' WHERE session_id = ?",
            (str(sid),),
        )
        before = ledger.integrity_failure_count

        row = ledger.get_session(sid)
        assert row is not None
        assert row["config_json"] == "{}"  # degraded placeholder, readable
        assert ledger.integrity_failure_count == before + 1

        rows = ledger.list_sessions()
        target = next(r for r in rows if r["session_id"] == str(sid))
        assert target.get("integrity_degraded") is True

    def test_clean_reads_do_not_increment_integrity_counter(
        self, tmp_path: Path
    ) -> None:
        ledger = EventLedger(tmp_path / "clean.db")
        sid = uuid4()
        ledger.create_session(
            session_id=sid,
            config_json="{}",
            task_desc="t",
            started_at="2026-08-20T12:00:00Z",
        )
        assert ledger.get_session(sid) is not None
        ledger.list_sessions()
        assert ledger.integrity_failure_count == 0
