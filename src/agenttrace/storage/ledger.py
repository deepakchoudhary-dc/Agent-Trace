"""Immutable, full-fidelity, hash-chained event ledger backed by SQLite.

Each event is appended to the ledger with a SHA-256 hash that commits to ALL
typed fields and the previous event's hash — forming an authentic, tamper-evident chain.
Sensitive columns and payloads are encrypted at rest using AES-256-GCM.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    EventType,
    event_from_dict,
)
from agenttrace.security.encryption import EncryptionManager
from agenttrace.security.redaction import SecretRedactor

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class LedgerError(Exception):
    """Raised when ledger operations fail."""


class EventLedger:
    """Append-only, cryptographically verified event store.

    The ledger uses standard SQLite with application-level AES-256-GCM encryption
    and full-field SHA-256 hash chaining.
    """

    def __init__(
        self,
        db_path: str | Path,
        encryption_mgr: EncryptionManager | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption = encryption_mgr or EncryptionManager()
        self._redactor = redactor or SecretRedactor()

        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Apply the database schema."""
        schema_sql = _SCHEMA_PATH.read_text(encoding="utf-8")
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    # -- Session management --

    def create_session(
        self,
        session_id: UUID,
        config_json: str,
        task_desc: str = "",
        started_at: str = "",
        agents: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Create a new audit session record with encrypted metadata."""
        redacted_task = self._redactor.redact(task_desc)
        config_enc = self._encryption.encrypt_str(config_json)
        task_desc_enc = self._encryption.encrypt_str(redacted_task)
        metadata_enc = self._encryption.encrypt_json(metadata or {})

        self._conn.execute(
            """INSERT INTO sessions
               (session_id, config_enc, task_desc_enc, status, agents_json,
                started_at, metadata_enc)
               VALUES (?, ?, ?, 'active', ?, ?, ?)""",
            (
                str(session_id),
                config_enc,
                task_desc_enc,
                json.dumps(agents or []),
                started_at,
                metadata_enc,
            ),
        )
        self._conn.commit()

    def update_session_status(self, session_id: UUID, status: str, stopped_at: str | None = None) -> None:
        """Update session status."""
        if stopped_at:
            self._conn.execute(
                "UPDATE sessions SET status = ?, stopped_at = ? WHERE session_id = ?",
                (status, stopped_at, str(session_id)),
            )
        else:
            self._conn.execute(
                "UPDATE sessions SET status = ? WHERE session_id = ?",
                (status, str(session_id)),
            )
        self._conn.commit()

    def get_session(self, session_id: UUID) -> dict[str, Any] | None:
        """Retrieve a session by ID, decrypting sensitive fields."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if not row:
            return None

        row_dict = dict(row)
        try:
            row_dict["config_json"] = self._encryption.decrypt_str(row_dict["config_enc"])
        except Exception:
            row_dict["config_json"] = "{}"

        try:
            row_dict["task_desc"] = self._encryption.decrypt_str(row_dict["task_desc_enc"])
        except Exception:
            row_dict["task_desc"] = ""

        try:
            row_dict["metadata"] = self._encryption.decrypt_json(row_dict["metadata_enc"])
        except Exception:
            row_dict["metadata"] = {}

        try:
            row_dict["agents"] = json.loads(row_dict.get("agents_json", "[]"))
        except Exception:
            row_dict["agents"] = []

        return row_dict

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions with decrypted descriptions."""
        rows = self._conn.execute("SELECT * FROM sessions ORDER BY started_at DESC").fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["task_desc"] = self._encryption.decrypt_str(d["task_desc_enc"])
            except Exception:
                d["task_desc"] = ""
            try:
                d["config"] = json.loads(self._encryption.decrypt_str(d["config_enc"]))
            except Exception:
                d["config"] = {}
            result.append(d)
        return result

    # -- Event ledger --

    def get_last_hash(self, session_id: UUID) -> str:
        """Get the hash of the last event in the session's chain."""
        row = self._conn.execute(
            "SELECT event_hash FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
            (str(session_id),),
        ).fetchone()
        return row["event_hash"] if row else ""

    def get_next_seq(self, session_id: UUID) -> int:
        """Get the next sequence number for the session."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), -1) + 1 AS next_seq FROM events WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        return row["next_seq"]  # type: ignore[return-value]

    def append_event(self, event: EventBase) -> str:
        """Append an event to the ledger, extending the hash chain.

        Redacts sensitive data, seals with previous hash & sequence,
        encrypts payload, and stores the full canonical JSON.
        """
        # Redact any sensitive content in the event dictionary
        raw_dict = event.model_dump(mode="json")
        redacted_dict = self._redactor.redact_any(raw_dict)
        clean_event = event_from_dict(redacted_dict)

        prev_hash = self.get_last_hash(clean_event.session_id)
        seq = self.get_next_seq(clean_event.session_id)

        clean_event.seal(prev_hash=prev_hash, seq=seq)
        event.prev_hash = clean_event.prev_hash
        event.event_hash = clean_event.event_hash
        event.seq = clean_event.seq

        # Encrypt the payload
        payload_enc: bytes | None = None
        if clean_event.payload:
            payload_enc = self._encryption.encrypt_json(clean_event.payload)

        canonical_json = json.dumps(
            clean_event.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        self._conn.execute(
            """INSERT INTO events
               (event_id, session_id, event_type, timestamp, actor_id,
                source_adapter, confidence, canonical_json, payload_enc,
                event_hash, prev_hash, seq)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(clean_event.event_id),
                str(clean_event.session_id),
                clean_event.event_type.value if hasattr(clean_event.event_type, "value") else str(clean_event.event_type),
                clean_event.timestamp.isoformat(),
                clean_event.actor_id,
                clean_event.source_adapter,
                clean_event.confidence.value if hasattr(clean_event.confidence, "value") else str(clean_event.confidence),
                canonical_json,
                payload_enc,
                clean_event.event_hash,
                clean_event.prev_hash,
                seq,
            ),
        )

        # Update session counters
        self._conn.execute(
            """UPDATE sessions
               SET event_count = event_count + 1,
                   last_event_hash = ?
               WHERE session_id = ?""",
            (clean_event.event_hash, str(clean_event.session_id)),
        )
        self._conn.commit()
        return clean_event.event_hash

    def get_event(self, event_id: UUID) -> EventBase | None:
        """Retrieve a single event by ID, deserializing to its concrete Event class."""
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()
        if not row:
            return None

        event_data = json.loads(row["canonical_json"])
        event_data["event_hash"] = row["event_hash"]
        event = event_from_dict(event_data)

        # Decrypt payload if stored separately
        if row["payload_enc"]:
            try:
                event.payload = self._encryption.decrypt_json(row["payload_enc"])
            except Exception:
                pass

        return event

    def query_events(
        self,
        session_id: UUID,
        event_type: EventType | None = None,
        actor_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 1000,
    ) -> list[EventBase]:
        """Query events with optional filters."""
        conditions = ["session_id = ?"]
        params: list[Any] = [str(session_id)]

        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type.value if hasattr(event_type, "value") else str(event_type))
        if actor_id is not None:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if after is not None:
            conditions.append("timestamp > ?")
            params.append(after)
        if before is not None:
            conditions.append("timestamp < ?")
            params.append(before)

        params.append(limit)
        where = " AND ".join(conditions)

        rows = self._conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY seq ASC LIMIT ?",
            params,
        ).fetchall()

        events: list[EventBase] = []
        for r in rows:
            try:
                event_data = json.loads(r["canonical_json"])
                event_data["event_hash"] = r["event_hash"]
                evt = event_from_dict(event_data)
                if r["payload_enc"]:
                    try:
                        evt.payload = self._encryption.decrypt_json(r["payload_enc"])
                    except Exception:
                        pass
                events.append(evt)
            except Exception:
                continue

        return events

    # -- Complete cryptographic chain verification --

    def verify_chain(self, session_id: UUID) -> tuple[bool, str]:
        """Verify the complete hash chain integrity for a session.

        Recomputes the SHA-256 hash of EVERY event from its canonical data,
        verifies that the recomputed hash matches the stored `event_hash`,
        checks that `prev_hash` links without interruption,
        and verifies strict monotonic sequence numbers.

        Returns (is_valid, error_message).
        """
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY seq ASC",
            (str(session_id),),
        ).fetchall()

        if not rows:
            return True, ""

        expected_prev_hash = ""
        expected_seq = 0

        for idx, row in enumerate(rows):
            stored_hash = row["event_hash"]
            stored_prev_hash = row["prev_hash"]
            stored_seq = row["seq"]
            canonical_json = row["canonical_json"]

            # 1. Verify sequence monotonicity
            if stored_seq != expected_seq:
                return False, (
                    f"Sequence discontinuity at index {idx}: "
                    f"expected seq={expected_seq}, found seq={stored_seq}"
                )

            # 2. Verify previous hash chaining
            if stored_prev_hash != expected_prev_hash:
                return False, (
                    f"Chain link broken at seq={stored_seq} (event {row['event_id']}): "
                    f"expected prev_hash={expected_prev_hash!r}, got {stored_prev_hash!r}"
                )

            # 3. Full hash recomputation over canonical data
            try:
                event_data = json.loads(canonical_json)
                event_data["event_hash"] = stored_hash
                evt = event_from_dict(event_data)
                recomputed_hash = evt.compute_hash()

                if recomputed_hash != stored_hash:
                    return False, (
                        f"Cryptographic tamper detected at seq={stored_seq} (event {row['event_id']}): "
                        f"stored_hash={stored_hash}, recomputed_hash={recomputed_hash}"
                    )
            except Exception as e:
                return False, f"Failed to recompute hash at seq={stored_seq}: {e}"

            expected_prev_hash = stored_hash
            expected_seq += 1

        return True, ""

    # -- Graph node/edge storage --

    def store_graph_node(
        self,
        node_id: UUID,
        session_id: UUID,
        node_type: str,
        label: str,
        timestamp: str,
        actor_id: str = "",
        source_adapter: str = "",
        confidence: str = "high",
        content_hash: str = "",
        evidence_json: str = "[]",
        data: dict[str, Any] | None = None,
    ) -> None:
        """Store a Context Graph node with encrypted label and data."""
        redacted_label = self._redactor.redact(label)
        label_enc = self._encryption.encrypt_str(redacted_label)
        data_enc = self._encryption.encrypt_json(self._redactor.redact_any(data or {}))

        self._conn.execute(
            """INSERT OR REPLACE INTO graph_nodes
               (node_id, session_id, node_type, label_enc, timestamp,
                actor_id, source_adapter, confidence, content_hash,
                evidence_json, data_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(node_id),
                str(session_id),
                node_type,
                label_enc,
                timestamp,
                actor_id,
                source_adapter,
                confidence,
                content_hash,
                evidence_json,
                data_enc,
            ),
        )
        self._conn.commit()

    def store_graph_edge(
        self,
        edge_id: UUID,
        session_id: UUID,
        source_node_id: UUID,
        target_node_id: UUID,
        edge_type: str,
        timestamp: str,
        actor_id: str = "",
        source_adapter: str = "",
        confidence: str = "high",
        evidence_json: str = "[]",
        data: dict[str, Any] | None = None,
    ) -> None:
        """Store a Context Graph edge with full session isolation."""
        data_enc = self._encryption.encrypt_json(self._redactor.redact_any(data or {}))

        self._conn.execute(
            """INSERT OR REPLACE INTO graph_edges
               (edge_id, session_id, source_node_id, target_node_id, edge_type,
                timestamp, actor_id, source_adapter, confidence,
                evidence_json, data_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(edge_id),
                str(session_id),
                str(source_node_id),
                str(target_node_id),
                edge_type,
                timestamp,
                actor_id,
                source_adapter,
                confidence,
                evidence_json,
                data_enc,
            ),
        )
        self._conn.commit()

    def get_graph_nodes(
        self,
        session_id: UUID,
        node_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve graph nodes for a session, decrypting labels and data."""
        if node_type:
            rows = self._conn.execute(
                "SELECT * FROM graph_nodes WHERE session_id = ? AND node_type = ?",
                (str(session_id), node_type),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM graph_nodes WHERE session_id = ?",
                (str(session_id),),
            ).fetchall()

        nodes: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["label"] = self._encryption.decrypt_str(d["label_enc"])
            except Exception:
                d["label"] = ""
            try:
                d["data"] = self._encryption.decrypt_json(d["data_enc"])
            except Exception:
                d["data"] = {}
            nodes.append(d)
        return nodes

    def get_graph_edges(
        self,
        session_id: UUID,
        source_node_id: UUID | None = None,
        target_node_id: UUID | None = None,
        edge_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve graph edges strictly scoped to session_id."""
        conditions: list[str] = ["session_id = ?"]
        params: list[Any] = [str(session_id)]

        if source_node_id:
            conditions.append("source_node_id = ?")
            params.append(str(source_node_id))
        if target_node_id:
            conditions.append("target_node_id = ?")
            params.append(str(target_node_id))
        if edge_type:
            conditions.append("edge_type = ?")
            params.append(edge_type)

        where = " AND ".join(conditions)
        rows = self._conn.execute(
            f"SELECT * FROM graph_edges WHERE {where}",
            params,
        ).fetchall()

        edges: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["data"] = self._encryption.decrypt_json(d["data_enc"])
            except Exception:
                d["data"] = {}
            edges.append(d)
        return edges

    # -- Approval storage --

    def store_approval(
        self,
        approval_id: UUID,
        session_id: UUID,
        finding_id: str,
        approved: bool,
        reason: str = "",
        scope: str = "",
        expiry: str | None = None,
        affected_paths: list[str] | None = None,
        created_at: str = "",
        event_hash: str = "",
    ) -> None:
        """Store an approval record with encrypted reason and scope."""
        redacted_reason = self._redactor.redact(reason)
        reason_enc = self._encryption.encrypt_str(redacted_reason)
        scope_enc = self._encryption.encrypt_str(scope)
        affected_enc = self._encryption.encrypt_json(affected_paths or [])

        self._conn.execute(
            """INSERT INTO approvals
               (approval_id, session_id, finding_id, approved, reason_enc,
                scope_enc, expiry, affected_enc, created_at, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(approval_id),
                str(session_id),
                finding_id,
                1 if approved else 0,
                reason_enc,
                scope_enc,
                expiry,
                affected_enc,
                created_at,
                event_hash,
            ),
        )
        self._conn.commit()

    def get_approvals(self, session_id: UUID) -> list[dict[str, Any]]:
        """Retrieve approvals for a session with decrypted reasons."""
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE session_id = ?",
            (str(session_id),),
        ).fetchall()

        approvals: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["reason"] = self._encryption.decrypt_str(d["reason_enc"])
            except Exception:
                d["reason"] = ""
            try:
                d["scope"] = self._encryption.decrypt_str(d["scope_enc"])
            except Exception:
                d["scope"] = ""
            try:
                d["affected_paths"] = self._encryption.decrypt_json(d["affected_enc"])
            except Exception:
                d["affected_paths"] = []
            approvals.append(d)
        return approvals

    # -- Task contract storage --

    def store_task_contract(
        self,
        contract_id: UUID,
        session_id: UUID,
        goal: str,
        allowed_paths: list[str] | None = None,
        prohibited_paths: list[str] | None = None,
        expected_tests: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        risk_level: str = "medium",
        created_at: str = "",
        updated_at: str = "",
        notes: str = "",
    ) -> None:
        """Store or update an encrypted task contract."""
        redacted_goal = self._redactor.redact(goal)
        goal_enc = self._encryption.encrypt_str(redacted_goal)
        allowed_enc = self._encryption.encrypt_json(allowed_paths or [])
        prohibited_enc = self._encryption.encrypt_json(prohibited_paths or [])
        tests_enc = self._encryption.encrypt_json(expected_tests or [])
        tools_enc = self._encryption.encrypt_json(allowed_tools or [])
        notes_enc = self._encryption.encrypt_str(self._redactor.redact(notes))

        self._conn.execute(
            """INSERT OR REPLACE INTO task_contracts
               (contract_id, session_id, goal_enc, allowed_enc,
                prohibited_enc, tests_enc, tools_enc,
                risk_level, created_at, updated_at, notes_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(contract_id),
                str(session_id),
                goal_enc,
                allowed_enc,
                prohibited_enc,
                tests_enc,
                tools_enc,
                risk_level,
                created_at,
                updated_at,
                notes_enc,
            ),
        )
        self._conn.commit()

    def get_task_contract(self, session_id: UUID) -> dict[str, Any] | None:
        """Retrieve the task contract for a session, decrypting fields."""
        row = self._conn.execute(
            "SELECT * FROM task_contracts WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if not row:
            return None

        d = dict(row)
        try:
            d["goal"] = self._encryption.decrypt_str(d["goal_enc"])
        except Exception:
            d["goal"] = ""
        try:
            d["allowed_paths"] = self._encryption.decrypt_json(d["allowed_enc"])
        except Exception:
            d["allowed_paths"] = []
        try:
            d["prohibited_paths"] = self._encryption.decrypt_json(d["prohibited_enc"])
        except Exception:
            d["prohibited_paths"] = []
        try:
            d["expected_tests"] = self._encryption.decrypt_json(d["tests_enc"])
        except Exception:
            d["expected_tests"] = []
        try:
            d["allowed_tools"] = self._encryption.decrypt_json(d["tools_enc"])
        except Exception:
            d["allowed_tools"] = []
        try:
            d["notes"] = self._encryption.decrypt_str(d["notes_enc"]) if d.get("notes_enc") else ""
        except Exception:
            d["notes"] = ""

        return d

    # -- Blob indexing --

    def store_blob_index(
        self,
        blob_hash: str,
        session_id: UUID,
        file_path: str,
        size_bytes: int,
        created_at: str,
    ) -> None:
        """Index an encrypted blob reference."""
        self._conn.execute(
            """INSERT OR REPLACE INTO blobs
               (blob_hash, session_id, file_path, size_bytes, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (blob_hash, str(session_id), file_path, size_bytes, created_at),
        )
        self._conn.commit()
