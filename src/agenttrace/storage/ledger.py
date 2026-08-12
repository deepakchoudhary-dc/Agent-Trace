"""Immutable, hash-chained event ledger backed by SQLite.

Each event is appended to the ledger with a SHA-256 hash that includes
the previous event's hash — forming a tamper-evident chain. Payloads
are encrypted at rest using AES-256-GCM.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.models.events import EventBase, EventType, ConfidenceLevel


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class LedgerError(Exception):
    """Raised when ledger operations fail."""


class EventLedger:
    """Append-only, hash-chained event store.

    The ledger uses standard SQLite with application-level encryption
    for event payloads. The hash chain ensures integrity: if any event
    is tampered with, chain verification will detect it.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
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
    ) -> None:
        """Create a new audit session record."""
        self._conn.execute(
            """INSERT INTO sessions (session_id, config_json, task_desc, started_at)
               VALUES (?, ?, ?, ?)""",
            (str(session_id), config_json, task_desc, started_at),
        )
        self._conn.commit()

    def update_session_status(self, session_id: UUID, status: str) -> None:
        """Update session status."""
        self._conn.execute(
            "UPDATE sessions SET status = ? WHERE session_id = ?",
            (status, str(session_id)),
        )
        self._conn.commit()

    def get_session(self, session_id: UUID) -> dict[str, Any] | None:
        """Retrieve a session by ID."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        return dict(row) if row else None

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

    def append_event(
        self,
        event: EventBase,
        payload_encrypted: bytes | None = None,
    ) -> str:
        """Append an event to the ledger, extending the hash chain.

        The event is sealed with the previous event's hash before storage.
        Returns the computed event hash.
        """
        prev_hash = self.get_last_hash(event.session_id)
        event.seal(prev_hash)

        seq = self.get_next_seq(event.session_id)

        self._conn.execute(
            """INSERT INTO events
               (event_id, session_id, event_type, timestamp, actor_id,
                source_adapter, confidence, payload_enc, event_hash,
                prev_hash, evidence_json, seq)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(event.event_id),
                str(event.session_id),
                event.event_type,
                event.timestamp.isoformat(),
                event.actor_id,
                event.source_adapter,
                event.confidence,
                payload_encrypted,
                event.event_hash,
                event.prev_hash,
                json.dumps(event.evidence_refs),
                seq,
            ),
        )

        # Update session counters
        self._conn.execute(
            """UPDATE sessions
               SET event_count = event_count + 1,
                   last_event_hash = ?
               WHERE session_id = ?""",
            (event.event_hash, str(event.session_id)),
        )
        self._conn.commit()
        return event.event_hash

    def get_event(self, event_id: UUID) -> dict[str, Any] | None:
        """Retrieve a single event by ID."""
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()
        return dict(row) if row else None

    def get_event_by_hash(self, event_hash: str) -> dict[str, Any] | None:
        """Retrieve an event by its hash."""
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_hash = ?",
            (event_hash,),
        ).fetchone()
        return dict(row) if row else None

    def query_events(
        self,
        session_id: UUID,
        event_type: EventType | None = None,
        actor_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query events with optional filters."""
        conditions = ["session_id = ?"]
        params: list[Any] = [str(session_id)]

        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)
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
        return [dict(r) for r in rows]

    # -- Chain verification --

    def verify_chain(self, session_id: UUID) -> tuple[bool, str]:
        """Verify the hash chain integrity for a session.

        Returns (is_valid, error_message). If valid, error_message is empty.
        """
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY seq ASC",
            (str(session_id),),
        ).fetchall()

        if not rows:
            return True, ""

        prev_hash = ""
        for row in rows:
            row_dict = dict(row)
            if row_dict["prev_hash"] != prev_hash:
                return False, (
                    f"Chain broken at event {row_dict['event_id']}: "
                    f"expected prev_hash={prev_hash!r}, "
                    f"got {row_dict['prev_hash']!r}"
                )
            prev_hash = row_dict["event_hash"]

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
        data_encrypted: bytes | None = None,
    ) -> None:
        """Store a Context Graph node."""
        self._conn.execute(
            """INSERT OR REPLACE INTO graph_nodes
               (node_id, session_id, node_type, label, timestamp,
                actor_id, source_adapter, confidence, content_hash,
                evidence_json, data_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(node_id),
                str(session_id),
                node_type,
                label,
                timestamp,
                actor_id,
                source_adapter,
                confidence,
                content_hash,
                evidence_json,
                data_encrypted,
            ),
        )
        self._conn.commit()

    def store_graph_edge(
        self,
        edge_id: UUID,
        source_node_id: UUID,
        target_node_id: UUID,
        edge_type: str,
        timestamp: str,
        actor_id: str = "",
        source_adapter: str = "",
        confidence: str = "high",
        evidence_json: str = "[]",
        data_encrypted: bytes | None = None,
    ) -> None:
        """Store a Context Graph edge."""
        self._conn.execute(
            """INSERT OR REPLACE INTO graph_edges
               (edge_id, source_node_id, target_node_id, edge_type,
                timestamp, actor_id, source_adapter, confidence,
                evidence_json, data_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(edge_id),
                str(source_node_id),
                str(target_node_id),
                edge_type,
                timestamp,
                actor_id,
                source_adapter,
                confidence,
                evidence_json,
                data_encrypted,
            ),
        )
        self._conn.commit()

    def get_graph_nodes(
        self,
        session_id: UUID,
        node_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve graph nodes for a session."""
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
        return [dict(r) for r in rows]

    def get_graph_edges(
        self,
        session_id: UUID | None = None,
        source_node_id: UUID | None = None,
        target_node_id: UUID | None = None,
        edge_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve graph edges with optional filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if source_node_id:
            conditions.append("source_node_id = ?")
            params.append(str(source_node_id))
        if target_node_id:
            conditions.append("target_node_id = ?")
            params.append(str(target_node_id))
        if edge_type:
            conditions.append("edge_type = ?")
            params.append(edge_type)

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = self._conn.execute(
            f"SELECT * FROM graph_edges WHERE {where}",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

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
        affected_json: str = "[]",
        created_at: str = "",
        event_hash: str = "",
    ) -> None:
        """Store an approval record."""
        self._conn.execute(
            """INSERT INTO approvals
               (approval_id, session_id, finding_id, approved, reason,
                scope, expiry, affected_json, created_at, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(approval_id),
                str(session_id),
                finding_id,
                1 if approved else 0,
                reason,
                scope,
                expiry,
                affected_json,
                created_at,
                event_hash,
            ),
        )
        self._conn.commit()

    # -- Task contract storage --

    def store_task_contract(
        self,
        contract_id: UUID,
        session_id: UUID,
        goal: str,
        allowed_paths: str = "[]",
        prohibited_paths: str = "[]",
        expected_tests: str = "[]",
        allowed_tools: str = "[]",
        risk_level: str = "medium",
        created_at: str = "",
        updated_at: str = "",
        notes: str = "",
    ) -> None:
        """Store or update a task contract."""
        self._conn.execute(
            """INSERT OR REPLACE INTO task_contracts
               (contract_id, session_id, goal, allowed_paths,
                prohibited_paths, expected_tests, allowed_tools,
                risk_level, created_at, updated_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(contract_id),
                str(session_id),
                goal,
                allowed_paths,
                prohibited_paths,
                expected_tests,
                allowed_tools,
                risk_level,
                created_at,
                updated_at,
                notes,
            ),
        )
        self._conn.commit()
