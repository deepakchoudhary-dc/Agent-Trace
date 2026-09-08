"""Immutable, full-fidelity, hash-chained event ledger backed by SQLite.

Each event is appended to the ledger with a SHA-256 hash that commits to ALL
typed fields and the previous event's hash — forming an authentic, tamper-evident chain.
Sensitive columns and payloads are encrypted at rest using AES-256-GCM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, cast

from agenttrace.models.events import (
    EventBase,
    EventType,
    event_from_dict,
)
from agenttrace.security.encryption import EncryptionError, EncryptionManager
from agenttrace.security.redaction import SecretRedactor

if TYPE_CHECKING:
    from uuid import UUID

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _locked(fn: F) -> F:
    """Synchronize ledger database access with an internal reentrant lock."""
    @wraps(fn)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return fn(self, *args, **kwargs)
    return cast("F", wrapper)


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
        max_storage_bytes: int | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption = encryption_mgr or EncryptionManager()
        self._redactor = redactor or SecretRedactor()
        # P0.5: optional hard ceiling on total ledger storage (DB + WAL/SHM).
        self._max_storage_bytes = max_storage_bytes
        # Count of decrypt/integrity failures on read paths. A failure means
        # stored evidence was corrupted or tampered with; it is logged loudly
        # AND surfaced via integrity_failure_count / row flags — never
        # silently swallowed into an empty-looking clean result.
        self.integrity_failure_count: int = 0

        # Single-writer by design (only the daemon writes); threaded ASGI
        # servers (and TestClient) may touch it from different threads.
        with self._lock:
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._init_schema()

    def _record_integrity_failure(self, context: str) -> None:
        """Log and count a decrypt/integrity failure on stored evidence."""
        self.integrity_failure_count += 1
        logger.error(
            "INTEGRITY: could not decrypt/parse stored data (%s) — the "
            "record may be corrupted or tampered with; returning a "
            "degraded placeholder",
            context,
        )

    @_locked
    def _init_schema(self) -> None:
        """Apply the database schema and migrate existing databases in place."""
        schema_sql = _SCHEMA_PATH.read_text(encoding="utf-8")
        self._conn.executescript(schema_sql)
        self._migrate_schema()
        self._conn.commit()

    @_locked
    def _migrate_schema(self) -> None:
        """Add columns introduced after v0.2 to databases created before them."""
        # P0.5: durable evidence-incomplete markers (survive daemon restarts).
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_state ("
            "session_id TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "reason TEXT NOT NULL, recorded_at TEXT NOT NULL)"
        )
        # P0.4 residual: keyed MACs over graph projection snapshots — a
        # forged projection is detected against the key, not merely
        # different from the ledger.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS projection_mac ("
            "session_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
            "stored_at TEXT NOT NULL)"
        )
        cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(events)")}
        if "canonical_json_enc" not in cols:
            self._conn.execute("ALTER TABLE events ADD COLUMN canonical_json_enc BLOB")
        if "canonical_json_hash" not in cols:
            self._conn.execute(
                "ALTER TABLE events ADD COLUMN canonical_json_hash TEXT NOT NULL DEFAULT ''"
            )
        if "index_binding_hash" not in cols:
            self._conn.execute(
                "ALTER TABLE events ADD COLUMN index_binding_hash TEXT NOT NULL DEFAULT ''"
            )

        approval_cols = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(approvals)")
        }
        if "status" not in approval_cols:
            self._conn.execute(
                "ALTER TABLE approvals ADD COLUMN status TEXT NOT NULL DEFAULT 'granted'"
            )
            # Backfill: pre-status rows were either granted or denied
            self._conn.execute(
                "UPDATE approvals SET status = CASE WHEN approved = 1 "
                "THEN 'granted' ELSE 'denied' END "
                "WHERE status = 'granted' AND approved = 0"
            )
        # Enforce a single canonical chain per session. A pre-existing database
        # may already contain duplicate (session_id, seq) rows from the old
        # race-prone append path — do not fail the upgrade; the verification
        # pass will surface them.
        try:
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_seq_unique "
                "ON events(session_id, seq)"
            )
        except sqlite3.IntegrityError:
            logger.warning(
                "events(session_id, seq) not unique in existing database; "
                "skipping unique index creation"
            )
        self._backfill_index_bindings()

    @_locked
    def _backfill_index_bindings(self) -> None:
        """Compute binding hashes for rows written before the column existed."""
        rows = self._conn.execute(
            "SELECT event_id, session_id, event_type, timestamp, actor_id, "
            "source_adapter, confidence, seq, prev_hash, event_hash "
            "FROM events WHERE index_binding_hash = ''"
        ).fetchall()
        for r in rows:
            binding = self._compute_index_binding_hash(
                event_id=r["event_id"],
                session_id=r["session_id"],
                event_type=r["event_type"],
                timestamp=r["timestamp"],
                actor_id=r["actor_id"],
                source_adapter=r["source_adapter"],
                confidence=r["confidence"],
                seq=r["seq"],
                prev_hash=r["prev_hash"],
                event_hash=r["event_hash"],
            )
            self._conn.execute(
                "UPDATE events SET index_binding_hash = ? WHERE event_id = ?",
                (binding, r["event_id"]),
            )

    @staticmethod
    def _compute_index_binding_hash(
        *,
        event_id: str,
        session_id: str,
        event_type: str,
        timestamp: str,
        actor_id: str,
        source_adapter: str,
        confidence: str,
        seq: int,
        prev_hash: str,
        event_hash: str,
    ) -> str:
        """SHA-256 over the indexed projection of a stored event row.

        The indexed columns are the query surface of the ledger (WHERE/ORDER
        BY on event_type, actor_id, timestamp, seq). They are stored plaintext,
        so write access to the DB could rewrite them without touching the
        encrypted envelope. The binding hash authenticates the projection to
        the chain so verification detects any drift.
        """
        projection = {
            "event_id": event_id,
            "session_id": session_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "actor_id": actor_id,
            "source_adapter": source_adapter,
            "confidence": confidence,
            "seq": seq,
            "prev_hash": prev_hash,
            "event_hash": event_hash,
        }
        canonical = json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _verify_row_integrity(self, row: Any) -> str:
        """Verify every authenticated property of one stored event row.

        Returns "" when the row is fully verified, otherwise a descriptive
        error message naming the tampered property.
        """
        stored_seq = row["seq"]
        stored_event_id = row["event_id"]

        # 1. Index binding — authenticates the plaintext indexed projection
        if row["index_binding_hash"]:
            recomputed_binding = self._compute_index_binding_hash(
                event_id=row["event_id"],
                session_id=row["session_id"],
                event_type=row["event_type"],
                timestamp=row["timestamp"],
                actor_id=row["actor_id"],
                source_adapter=row["source_adapter"],
                confidence=row["confidence"],
                seq=row["seq"],
                prev_hash=row["prev_hash"],
                event_hash=row["event_hash"],
            )
            if recomputed_binding != row["index_binding_hash"]:
                return (
                    f"Index binding tamper detected at seq={stored_seq} "
                    f"(event {stored_event_id}): "
                    f"stored_binding={row['index_binding_hash']}, "
                    f"recomputed_binding={recomputed_binding}"
                )

        # 2. Envelope decryption + tamper hash
        try:
            canonical_json = self._read_canonical_json(row)
        except Exception as e:
            return (
                f"Envelope decryption failed at seq={stored_seq} "
                f"(event {stored_event_id}): {e}"
            )

        if row["canonical_json_hash"]:
            recomputed_canonical_hash = hashlib.sha256(
                canonical_json.encode("utf-8")
            ).hexdigest()
            if recomputed_canonical_hash != row["canonical_json_hash"]:
                return (
                    f"Envelope tamper detected at seq={stored_seq} "
                    f"(event {stored_event_id}): "
                    f"stored_canonical_hash={row['canonical_json_hash']}, "
                    f"recomputed_canonical_hash={recomputed_canonical_hash}"
                )

        # 3. Event hash recomputation over the canonical envelope
        try:
            event_data = json.loads(canonical_json)
            event_data["event_hash"] = row["event_hash"]
            evt = event_from_dict(event_data)
            recomputed_hash = evt.compute_hash()
        except Exception as e:
            return (
                f"Failed to recompute hash at seq={stored_seq} "
                f"(event {stored_event_id}): {e}"
            )

        if recomputed_hash != row["event_hash"]:
            return (
                f"Cryptographic tamper detected at seq={stored_seq} "
                f"(event {stored_event_id}): "
                f"stored_hash={row['event_hash']}, "
                f"recomputed_hash={recomputed_hash}"
            )

        # 4. Indexed columns must agree with the authenticated envelope
        envelope_fields = evt.model_dump(mode="json")
        drift_checks = [
            ("event_id", envelope_fields["event_id"], row["event_id"]),
            ("session_id", envelope_fields["session_id"], row["session_id"]),
            ("event_type", envelope_fields["event_type"], row["event_type"]),
            ("actor_id", envelope_fields["actor_id"], row["actor_id"]),
            ("source_adapter", envelope_fields["source_adapter"], row["source_adapter"]),
            ("confidence", envelope_fields["confidence"], row["confidence"]),
            ("seq", envelope_fields["seq"], row["seq"]),
            ("prev_hash", envelope_fields["prev_hash"], row["prev_hash"]),
        ]
        for field, envelope_value, column_value in drift_checks:
            if envelope_value != column_value:
                return (
                    f"Indexed column drift detected at seq={stored_seq} "
                    f"(event {stored_event_id}): envelope {field}={envelope_value!r}, "
                    f"column {field}={column_value!r}"
                )

        # Timestamps may serialize as "Z" (pydantic JSON) or "+00:00"
        # (datetime.isoformat) — normalize before comparing.
        envelope_ts = envelope_fields["timestamp"]
        column_ts = row["timestamp"]
        envelope_ts = envelope_ts[:-1] + "+00:00" if envelope_ts.endswith("Z") else envelope_ts
        column_ts = column_ts[:-1] + "+00:00" if column_ts.endswith("Z") else column_ts
        if envelope_ts != column_ts:
            return (
                f"Indexed column drift detected at seq={stored_seq} "
                f"(event {stored_event_id}): envelope timestamp={envelope_ts!r}, "
                f"column timestamp={column_ts!r}"
            )

        # 5. Payload cross-check — payload_enc must decrypt to the envelope payload
        envelope_payload = envelope_fields.get("payload") or {}
        if row["payload_enc"]:
            try:
                stored_payload = json.loads(
                    self._decrypt_event_value(row, row["payload_enc"], "payload")
                )
            except Exception as e:
                return (
                    f"Payload decryption failed at seq={stored_seq} "
                    f"(event {stored_event_id}): {e}"
                )
            if stored_payload != envelope_payload:
                return (
                    f"Payload drift detected at seq={stored_seq} "
                    f"(event {stored_event_id}): payload_enc does not match envelope payload"
                )
        elif envelope_payload and row["canonical_json_enc"]:
            return (
                f"Payload drift detected at seq={stored_seq} "
                f"(event {stored_event_id}): envelope carries payload but payload_enc is empty"
            )

        return ""

    @_locked
    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    # -- Session management --

    @_locked
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
        aad = self._row_aad("sessions", str(session_id), str(session_id))
        config_enc = self._encryption.encrypt_str(config_json, associated_data=aad)
        task_desc_enc = self._encryption.encrypt_str(redacted_task, associated_data=aad)
        metadata_enc = self._encryption.encrypt_json(metadata or {}, associated_data=aad)

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

    @_locked
    def update_session_status(
        self, session_id: UUID, status: str, stopped_at: str | None = None
    ) -> None:
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

    @_locked
    def get_session(self, session_id: UUID) -> dict[str, Any] | None:
        """Retrieve a session by ID, decrypting sensitive fields."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if not row:
            return None

        row_dict = dict(row)
        sess_aad = self._row_aad("sessions", str(session_id), str(session_id))
        try:
            row_dict["config_json"] = self._decrypt_bound_or_legacy(
                lambda associated_data: self._encryption.decrypt_str(
                    row_dict["config_enc"], associated_data=associated_data
                ),
                sess_aad,
            )
        except Exception:
            self._record_integrity_failure(f"session {session_id} config")
            row_dict["config_json"] = "{}"

        try:
            row_dict["task_desc"] = self._decrypt_bound_or_legacy(
                lambda associated_data: self._encryption.decrypt_str(
                    row_dict["task_desc_enc"], associated_data=associated_data
                ),
                sess_aad,
            )
        except Exception:
            self._record_integrity_failure(f"session {session_id} task_desc")
            row_dict["task_desc"] = ""

        try:
            row_dict["metadata"] = self._decrypt_bound_or_legacy(
                lambda associated_data: self._encryption.decrypt_json(
                    row_dict["metadata_enc"], associated_data=associated_data
                ),
                sess_aad,
            )
        except Exception:
            self._record_integrity_failure(f"session {session_id} metadata")
            row_dict["metadata"] = {}

        try:
            row_dict["agents"] = json.loads(row_dict.get("agents_json", "[]"))
        except Exception:
            self._record_integrity_failure(f"session {session_id} agents")
            row_dict["agents"] = []

        return row_dict

    @_locked
    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions with decrypted descriptions."""
        rows = self._conn.execute("SELECT * FROM sessions ORDER BY started_at DESC").fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            degraded: list[str] = []
            row_aad = self._row_aad("sessions", str(d.get("session_id")), str(d.get("session_id")))
            try:
                d["task_desc"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_str(
                        d["task_desc_enc"], associated_data=associated_data
                    ),
                    row_aad,
                )
            except Exception:
                degraded.append("task_desc")
                d["task_desc"] = ""
            try:
                d["config"] = json.loads(
                    self._decrypt_bound_or_legacy(
                        lambda associated_data, d=d: self._encryption.decrypt_str(
                            d["config_enc"], associated_data=associated_data
                        ),
                        row_aad,
                    )
                )
            except Exception:
                degraded.append("config")
                d["config"] = {}
            if degraded:
                self._record_integrity_failure(
                    f"session listing row {d.get('session_id')}: {', '.join(degraded)}"
                )
                d["integrity_degraded"] = True
            result.append(d)
        return result

    # -- Adapter resume cursors --

    @_locked
    def save_adapter_cursor(
        self, session_id: UUID, adapter_name: str, cursor: dict[str, Any]
    ) -> None:
        """Persist an adapter's resume state (file offsets, seen records)."""
        cursor_enc = self._encryption.encrypt_json(
            cursor or {},
            associated_data=self._row_aad(
                "adapter_cursors", str(session_id), str(session_id)
            ),
        )
        self._conn.execute(
            """INSERT INTO adapter_cursors (session_id, adapter_name, cursor_enc, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET
                   adapter_name = excluded.adapter_name,
                   cursor_enc = excluded.cursor_enc,
                   updated_at = excluded.updated_at""",
            (
                str(session_id),
                adapter_name,
                cursor_enc,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    @_locked
    def get_adapter_cursor(self, session_id: UUID) -> dict[str, Any] | None:
        """Load a session's persisted adapter cursor, or None if never saved."""
        row = self._conn.execute(
            "SELECT adapter_name, cursor_enc FROM adapter_cursors WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if not row:
            return None
        try:
            cursor = self._decrypt_bound_or_legacy(
                lambda associated_data: self._encryption.decrypt_json(
                    row["cursor_enc"], associated_data=associated_data
                ),
                self._row_aad("adapter_cursors", str(session_id), str(session_id)),
            )
        except Exception:
            self._record_integrity_failure(
                f"adapter cursor {row['adapter_name']} for session {session_id}"
            )
            cursor = {}
        return {
            "adapter_name": row["adapter_name"],
            "cursor": cursor,
        }

    # -- Event ledger --

    @_locked
    def get_last_hash(self, session_id: UUID) -> str:
        """Get the hash of the last event in the session's chain."""
        row = self._conn.execute(
            "SELECT event_hash FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
            (str(session_id),),
        ).fetchone()
        return row["event_hash"] if row else ""

    @_locked
    def get_next_seq(self, session_id: UUID) -> int:
        """Get the next sequence number for the session."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), -1) + 1 AS next_seq FROM events WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        return int(row["next_seq"])

    @property
    def encryption(self) -> EncryptionManager:
        """The encryption manager (for domain-separated key derivation)."""
        return self._encryption

    def _storage_usage(self) -> int:
        """Total bytes used by the ledger DB (including WAL/SHM sidecars)."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            sidecar = Path(str(self._db_path) + suffix)
            try:
                total += sidecar.stat().st_size
            except OSError:
                continue
        return total

    def _set_evidence_incomplete(self, session_id: str, reason: str) -> None:
        """Persist an evidence-incomplete marker for a session (P0.5)."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO evidence_state "
                "(session_id, state, reason, recorded_at) VALUES (?, ?, ?, ?)",
                (
                    session_id,
                    "evidence_incomplete",
                    reason,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()

    @_locked
    def is_evidence_incomplete(self, session_id: str) -> bool:
        """Whether the session was marked evidence-incomplete (quota/truncation)."""
        row = self._conn.execute(
            "SELECT state FROM evidence_state WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        return row is not None and row["state"] == "evidence_incomplete"

    @_locked
    def append_event(self, event: EventBase) -> str:
        """Append an event to the ledger, extending the hash chain.

        Redacts sensitive data, seals with previous hash & sequence,
        encrypts payload, and stores the full canonical JSON.

        The append runs inside an IMMEDIATE write transaction so concurrent
        appends cannot observe the same tail and duplicate a sequence number.
        """
        # P0.5: storage quota. Mark the session evidence-incomplete BEFORE
        # refusing the write, so a report can never present a silently
        # truncated record as complete.
        if (
            self._max_storage_bytes is not None
            and self._storage_usage() > self._max_storage_bytes
        ):
            self._set_evidence_incomplete(
                str(event.session_id), "storage_quota_exceeded"
            )
            raise LedgerError(
                f"storage_quota_exceeded: ledger storage exceeds quota of "
                f"{self._max_storage_bytes} bytes; session marked "
                f"evidence_incomplete"
            )

        # Redact any sensitive content in the event dictionary
        raw_dict = event.model_dump(mode="json")
        redacted_dict = self._redactor.redact_any(raw_dict)
        clean_event = event_from_dict(redacted_dict)

        try:
            self._conn.execute("BEGIN IMMEDIATE")

            prev_hash = self.get_last_hash(clean_event.session_id)
            seq = self.get_next_seq(clean_event.session_id)

            clean_event.seal(prev_hash=prev_hash, seq=seq)
            event.prev_hash = clean_event.prev_hash
            event.event_hash = clean_event.event_hash
            event.seq = clean_event.seq

            # Encrypt the payload, bound to this row's identity (P1.1)
            payload_enc: bytes | None = None
            if clean_event.payload:
                payload_enc = self._encryption.encrypt_json(
                    clean_event.payload,
                    associated_data=self._event_aad(
                        str(clean_event.session_id), str(clean_event.event_id), "payload"
                    ),
                )

            # The canonical envelope is the full event content (commands, prompts,
            # tool args, diffs). It is AES-256-GCM encrypted at rest; its SHA-256 is
            # stored separately so tamper verification never needs the plaintext.
            canonical_json = json.dumps(
                clean_event.canonical_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            canonical_json_enc = self._encryption.encrypt_str(
                canonical_json,
                associated_data=self._event_aad(
                    str(clean_event.session_id), str(clean_event.event_id), "canonical"
                ),
            )
            canonical_json_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

            index_binding_hash = self._compute_index_binding_hash(
                event_id=str(clean_event.event_id),
                session_id=str(clean_event.session_id),
                event_type=clean_event.event_type.value
                if hasattr(clean_event.event_type, "value")
                else str(clean_event.event_type),
                timestamp=clean_event.timestamp.isoformat(),
                actor_id=clean_event.actor_id,
                source_adapter=clean_event.source_adapter,
                confidence=clean_event.confidence.value
                if hasattr(clean_event.confidence, "value")
                else str(clean_event.confidence),
                seq=seq,
                prev_hash=clean_event.prev_hash,
                event_hash=clean_event.event_hash,
            )

            self._conn.execute(
                """INSERT INTO events
                   (event_id, session_id, event_type, timestamp, actor_id,
                    source_adapter, confidence, canonical_json, canonical_json_enc,
                    canonical_json_hash, payload_enc, event_hash, prev_hash, seq,
                    index_binding_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(clean_event.event_id),
                    str(clean_event.session_id),
                    clean_event.event_type.value
                    if hasattr(clean_event.event_type, "value")
                    else str(clean_event.event_type),
                    clean_event.timestamp.isoformat(),
                    clean_event.actor_id,
                    clean_event.source_adapter,
                    clean_event.confidence.value
                    if hasattr(clean_event.confidence, "value")
                    else str(clean_event.confidence),
                    "",  # canonical_json (legacy column) intentionally left empty
                    canonical_json_enc,
                    canonical_json_hash,
                    payload_enc,
                    clean_event.event_hash,
                    clean_event.prev_hash,
                    seq,
                    index_binding_hash,
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
        except Exception:
            self._conn.rollback()
            raise
        return clean_event.event_hash

    # -- AAD binding (plan2 P1.1): event ciphertexts are authenticated
    # against their row identity, so a payload encrypted for one event fails
    # GCM verification if moved to any other row, column, or session. The
    # payload-replay that P1.1 named is structurally impossible for bound rows.

    _EVENT_COLUMN_AAD = {"payload_enc": "payload", "canonical_json_enc": "canonical"}

    # P1 residual: AAD binding for non-event encrypted columns. Each
    # row's ciphertexts are bound to (table, session_id, row identity) so a
    # ciphertext cannot be moved between rows or sessions without failing
    # authentication. Rows written before this binding decrypt without AAD
    # (legacy fallback); rotation upgrades them in place.
    _ROW_ID_COLUMN: dict[str, str] = {
        "sessions": "session_id",
        "adapter_cursors": "session_id",
        "graph_nodes": "node_id",
        "graph_edges": "edge_id",
        "approvals": "approval_id",
        "task_contracts": "contract_id",
        "review_runs": "loop_id",
    }

    @staticmethod
    def _row_aad(table: str, session_id: str, row_id: str) -> bytes:
        """The associated data a row's encrypted columns are bound to."""
        return f"agenttrace:v1:row:{table}:{session_id}:{row_id}".encode()

    def _decrypt_bound_or_legacy(self, decrypt: Any, aad: bytes) -> Any:
        """Decrypt a bound column, tolerating pre-binding legacy rows.

        ``decrypt`` is a callable receiving the keyword ``associated_data``;
        it is called first with the row AAD, then without (legacy row). Any
        failure propagates so the caller's integrity handling applies — a
        ciphertext that matches neither binding is never silently accepted.
        """
        try:
            return decrypt(associated_data=aad)
        except EncryptionError:
            return decrypt(associated_data=None)

    @staticmethod
    def _event_aad(session_id: str, event_id: str, column: str) -> bytes:
        return f"agenttrace/event:{session_id}:{event_id}:{column}".encode()

    def _decrypt_event_value(self, row: Any, encrypted: bytes, column: str) -> bytes:
        """Decrypt an event ciphertext with its row binding.

        Legacy rows written before binding are still covered by the
        four-layer row integrity check; new rows are always bound, and key
        rotation upgrades legacy rows in place."""
        aad = self._event_aad(row["session_id"], row["event_id"], column)
        try:
            return self._encryption.decrypt(encrypted, associated_data=aad)
        except EncryptionError:
            return self._encryption.decrypt(encrypted)

    @_locked
    def get_event(self, event_id: UUID) -> EventBase | None:
        """Retrieve a single event by ID, deserializing to its concrete Event class.

        Raises LedgerError if the stored row fails integrity verification —
        tampered rows are surfaced, never silently returned.
        """
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()
        if not row:
            return None

        integrity_error = self._verify_row_integrity(row)
        if integrity_error:
            raise LedgerError(
                f"Event {event_id} failed integrity verification: {integrity_error}"
            )

        event_data = json.loads(self._read_canonical_json(row))
        event_data["event_hash"] = row["event_hash"]
        event = event_from_dict(event_data)

        # Decrypt payload if stored separately (integrity already verified)
        if row["payload_enc"]:
            event.payload = json.loads(
                self._decrypt_event_value(row, row["payload_enc"], "payload")
            )

        return event

    @_locked
    def event_count(self) -> int:
        """Total events across all sessions, without decrypting anything.

        Cheap gate for periodic full-ledger scans: a scan that decrypts and
        verifies every event must only run when the ledger has actually
        grown since the last pass.
        """
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0])

    @_locked
    def query_events(
        self,
        session_id: UUID,
        event_type: EventType | None = None,
        actor_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int | None = 1000,
    ) -> list[EventBase]:
        """Query events with optional filters.

        Every returned row is verified on read; a tampered row raises
        LedgerError instead of being silently skipped. Pass limit=None to
        disable the default cap.
        """
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

        where = " AND ".join(conditions)

        if limit is None:
            rows = self._conn.execute(
                f"SELECT * FROM events WHERE {where} ORDER BY seq ASC",
                params,
            ).fetchall()
        else:
            params.append(limit)
            rows = self._conn.execute(
                f"SELECT * FROM events WHERE {where} ORDER BY seq ASC LIMIT ?",
                params,
            ).fetchall()

        events: list[EventBase] = []
        for r in rows:
            integrity_error = self._verify_row_integrity(r)
            if integrity_error:
                raise LedgerError(
                    f"Event {r['event_id']} failed integrity verification: {integrity_error}"
                )
            event_data = json.loads(self._read_canonical_json(r))
            event_data["event_hash"] = r["event_hash"]
            evt = event_from_dict(event_data)
            if r["payload_enc"]:
                evt.payload = json.loads(
                    self._decrypt_event_value(r, r["payload_enc"], "payload")
                )
            events.append(evt)

        return events

    def _read_canonical_json(self, row: Any) -> str:
        """Read and decrypt the canonical envelope for a stored event row.

        New rows store an encrypted envelope plus a tamper hash; legacy rows
        store the plaintext envelope in the pre-v0.3 `canonical_json` column.
        """
        if row["canonical_json_enc"]:
            return self._decrypt_event_value(
                row, row["canonical_json_enc"], "canonical"
            ).decode("utf-8")
        return str(row["canonical_json"])

    # -- Complete cryptographic chain verification --

    @_locked
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

            # 3. Verify binding hash, envelope tamper hash, event hash,
            #    indexed-column drift, and payload cross-check
            integrity_error = self._verify_row_integrity(row)
            if integrity_error:
                return False, integrity_error

            expected_prev_hash = stored_hash
            expected_seq += 1

        # 4. Verify the session-level chain head and count stay consistent
        session_row = self._conn.execute(
            "SELECT event_count, last_event_hash FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if session_row and session_row["last_event_hash"]:
            if session_row["last_event_hash"] != expected_prev_hash:
                return False, (
                    "Session head mismatch: ledger chain ends at "
                    f"{expected_prev_hash!r} but sessions.last_event_hash="
                    f"{session_row['last_event_hash']!r}"
                )
            if session_row["event_count"] != expected_seq:
                return False, (
                    "Session count mismatch: ledger contains "
                    f"{expected_seq} events but sessions.event_count="
                    f"{session_row['event_count']}"
                )

        return True, ""

    # -- Graph node/edge storage --

    @_locked
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
        node_aad = self._row_aad("graph_nodes", str(session_id), str(node_id))
        label_enc = self._encryption.encrypt_str(
            redacted_label, associated_data=node_aad
        )
        data_enc = self._encryption.encrypt_json(
            self._redactor.redact_any(data or {}), associated_data=node_aad
        )

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

    @_locked
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
        edge_aad = self._row_aad("graph_edges", str(session_id), str(edge_id))
        data_enc = self._encryption.encrypt_json(
            self._redactor.redact_any(data or {}), associated_data=edge_aad
        )
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

    @_locked
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
            node_aad = self._row_aad(
                "graph_nodes", str(session_id), str(d.get("node_id"))
            )
            try:
                d["label"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_str(
                        d["label_enc"], associated_data=associated_data
                    ),
                    node_aad,
                )
            except Exception:
                self._record_integrity_failure(
                    f"graph node {d.get('node_id')} label"
                )
                d["label"] = ""
            try:
                d["data"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_json(
                        d["data_enc"], associated_data=associated_data
                    ),
                    node_aad,
                )
            except Exception:
                self._record_integrity_failure(
                    f"graph node {d.get('node_id')} data"
                )
                d["data"] = {}
            nodes.append(d)
        return nodes

    @_locked
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
            edge_aad = self._row_aad(
                "graph_edges", str(session_id), str(d.get("edge_id"))
            )
            try:
                d["data"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_json(
                        d["data_enc"], associated_data=associated_data
                    ),
                    edge_aad,
                )
            except Exception:
                self._record_integrity_failure(
                    f"graph edge {d.get('edge_id')} data"
                )
                d["data"] = {}
            edges.append(d)
        return edges

    # -- Approval storage --

    @_locked
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
        affected_commands: list[str] | None = None,
        created_at: str = "",
        event_hash: str = "",
        status: str = "granted",
    ) -> None:
        """Store an approval record with encrypted reason, scope, and scope items.

        If a pending (status='requested') record already exists for the same
        (session_id, finding_id), the decision updates it in place instead of
        creating a duplicate — a request followed by its verdict is one record.
        """
        approval_aad = self._row_aad(
            "approvals", str(session_id), str(approval_id)
        )
        redacted_reason = self._redactor.redact(reason)
        reason_enc = self._encryption.encrypt_str(
            redacted_reason, associated_data=approval_aad
        )
        scope_enc = self._encryption.encrypt_str(
            scope, associated_data=approval_aad
        )
        affected_enc = self._encryption.encrypt_json(
            {
                "paths": affected_paths or [],
                "commands": affected_commands or [],
            },
            associated_data=approval_aad,
        )

        pending = self._conn.execute(
            "SELECT approval_id FROM approvals "
            "WHERE session_id = ? AND finding_id = ? AND status = 'requested' "
            "ORDER BY created_at ASC LIMIT 1",
            (str(session_id), finding_id),
        ).fetchone()

        if pending:
            self._conn.execute(
                """UPDATE approvals
                   SET approved = ?, status = ?, reason_enc = ?, scope_enc = ?,
                       expiry = ?, affected_enc = ?, event_hash = ?
                   WHERE approval_id = ?""",
                (
                    1 if approved else 0,
                    status,
                    reason_enc,
                    scope_enc,
                    expiry,
                    affected_enc,
                    event_hash,
                    pending["approval_id"],
                ),
            )
        else:
            self._conn.execute(
                """INSERT INTO approvals
                   (approval_id, session_id, finding_id, approved, status,
                    reason_enc, scope_enc, expiry, affected_enc, created_at, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(approval_id),
                    str(session_id),
                    finding_id,
                    1 if approved else 0,
                    status,
                    reason_enc,
                    scope_enc,
                    expiry,
                    affected_enc,
                    created_at,
                    event_hash,
                ),
            )
        self._conn.commit()

    @_locked
    def revoke_approval(self, session_id: UUID, finding_id: str) -> None:
        """Mark an approval record as revoked in the database."""
        self._conn.execute(
            """UPDATE approvals SET status = 'revoked', approved = 0
               WHERE session_id = ? AND finding_id = ?""",
            (str(session_id), finding_id),
        )
        self._conn.commit()

    def event_hash_exists(self, session_id: UUID, event_hash: str) -> bool:
        """True when event_hash is present in this session's hash-chained events.

        Used to authenticate approval rows on reload: a grant whose anchor
        hash does not exist in the tamper-evident event chain was inserted
        or mutated out-of-band and must never be honored.
        """
        if not event_hash:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM events WHERE session_id = ? AND event_hash = ? LIMIT 1",
                (str(session_id), event_hash),
            ).fetchone()
        return row is not None

    @_locked
    def get_approvals(self, session_id: UUID) -> list[dict[str, Any]]:
        """Retrieve approvals for a session with decrypted reasons."""
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE session_id = ?",
            (str(session_id),),
        ).fetchall()

        approvals: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            row_aad = self._row_aad(
                "approvals", str(session_id), str(d.get("approval_id"))
            )
            try:
                d["reason"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_str(
                        d["reason_enc"], associated_data=associated_data
                    ),
                    row_aad,
                )
            except Exception:
                self._record_integrity_failure(
                    f"approval {d.get('finding_id')} reason"
                )
                d["reason"] = ""
            try:
                d["scope"] = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_str(
                        d["scope_enc"], associated_data=associated_data
                    ),
                    row_aad,
                )
            except Exception:
                self._record_integrity_failure(f"approval {d.get('finding_id')} scope")
                d["scope"] = ""
            try:
                affected = self._decrypt_bound_or_legacy(
                    lambda associated_data, d=d: self._encryption.decrypt_json(
                        d["affected_enc"], associated_data=associated_data
                    ),
                    row_aad,
                )
                if isinstance(affected, dict):
                    d["affected"] = affected
                    d["affected_paths"] = affected.get("paths", [])
                    d["affected_commands"] = affected.get("commands", [])
                else:
                    # Legacy rows stored a bare list of paths
                    d["affected"] = {"paths": affected or [], "commands": []}
                    d["affected_paths"] = affected or []
                    d["affected_commands"] = []
            except Exception:
                self._record_integrity_failure(
                    f"approval {d.get('finding_id')} scopes"
                )
                d["affected"] = {"paths": [], "commands": []}
                d["affected_paths"] = []
                d["affected_commands"] = []
            approvals.append(d)
        return approvals

    # -- Task contract storage --

    @_locked
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
        """Store or update an encrypted task contract (row-bound ciphertext)."""
        redacted_goal = self._redactor.redact(goal)
        contract_aad = self._row_aad(
            "task_contracts", str(session_id), str(contract_id)
        )
        goal_enc = self._encryption.encrypt_str(
            redacted_goal, associated_data=contract_aad
        )
        allowed_enc = self._encryption.encrypt_json(
            allowed_paths or [], associated_data=contract_aad
        )
        prohibited_enc = self._encryption.encrypt_json(
            prohibited_paths or [], associated_data=contract_aad
        )
        tests_enc = self._encryption.encrypt_json(
            expected_tests or [], associated_data=contract_aad
        )
        tools_enc = self._encryption.encrypt_json(
            allowed_tools or [], associated_data=contract_aad
        )
        notes_enc = self._encryption.encrypt_str(
            self._redactor.redact(notes), associated_data=contract_aad
        )

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

    @_locked
    def get_task_contract(self, session_id: UUID) -> dict[str, Any] | None:
        """Retrieve the task contract for a session, decrypting fields."""
        row = self._conn.execute(
            "SELECT * FROM task_contracts WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if not row:
            return None

        d = dict(row)
        contract_aad = self._row_aad(
            "task_contracts", str(session_id), str(d.get("contract_id", ""))
        )
        for field, key, default in (
            ("goal", "goal_enc", ""),
            ("allowed_paths", "allowed_enc", []),
            ("prohibited_paths", "prohibited_enc", []),
            ("expected_tests", "tests_enc", []),
            ("allowed_tools", "tools_enc", []),
        ):
            try:
                if field == "goal":
                    d[field] = self._decrypt_bound_or_legacy(
                        lambda associated_data, k=key: self._encryption.decrypt_str(
                            d[k], associated_data=associated_data
                        ),
                        contract_aad,
                    )
                else:
                    d[field] = self._decrypt_bound_or_legacy(
                        lambda associated_data, k=key: self._encryption.decrypt_json(
                            d[k], associated_data=associated_data
                        ),
                        contract_aad,
                    )
            except Exception:
                self._record_integrity_failure(f"task contract {field}")
                d[field] = default
        try:
            if d.get("notes_enc"):
                d["notes"] = self._decrypt_bound_or_legacy(
                    lambda associated_data: self._encryption.decrypt_str(
                        d["notes_enc"], associated_data=associated_data
                    ),
                    contract_aad,
                )
            else:
                d["notes"] = ""
        except Exception:
            self._record_integrity_failure("task contract notes")
            d["notes"] = ""

        return d

    # -- Review loop runs --

    @_locked
    def store_review_run(
        self,
        loop_id: UUID,
        session_id: UUID,
        passed: bool,
        iterations: int,
        payload_json: str,
    ) -> None:
        """Persist a review loop result (encrypted, redacted at the boundary).

        The payload is scrubbed by the write-boundary redactor BEFORE
        encryption, so no caller can bypass sanitization by passing raw
        review evidence (agent reasoning, tool output) directly.
        """
        redacted_payload = SecretRedactor().redact(payload_json)
        run_aad = self._row_aad("review_runs", str(session_id), str(loop_id))
        payload = self._encryption.encrypt_str(
            redacted_payload, associated_data=run_aad
        )
        self._conn.execute(
            """INSERT OR REPLACE INTO review_runs
               (loop_id, session_id, passed, iterations, payload_enc, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                str(loop_id),
                str(session_id),
                int(passed),
                iterations,
                payload,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    @_locked
    def get_review_runs(self, session_id: UUID) -> list[dict[str, Any]]:
        """Return all review runs for a session, newest first (decrypted)."""
        rows = self._conn.execute(
            "SELECT loop_id, session_id, passed, iterations, payload_enc, created_at "
            "FROM review_runs WHERE session_id = ? ORDER BY created_at DESC",
            (str(session_id),),
        ).fetchall()
        runs: list[dict[str, Any]] = []
        for r in rows:
            run_aad = self._row_aad(
                "review_runs", str(r["session_id"]), r["loop_id"]
            )
            try:
                payload = json.loads(
                    self._decrypt_bound_or_legacy(
                        lambda associated_data, row=r: self._encryption.decrypt_str(
                            row["payload_enc"], associated_data=associated_data
                        ),
                        run_aad,
                    )
                )
            except Exception as e:  # noqa: BLE001 — corrupt rows must not crash reads
                logger.warning("Failed to decrypt review run %s: %s", r["loop_id"], e)
                continue
            runs.append({
                "loop_id": r["loop_id"],
                "session_id": r["session_id"],
                "passed": bool(r["passed"]),
                "iterations": r["iterations"],
                "payload": payload,
                "created_at": r["created_at"],
            })
        return runs

    # -- Blob indexing --

    @_locked
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

    # -- Egress destination baseline --

    @_locked
    def add_destination_baseline(self, workspace_path: str, destination: str) -> None:
        """Record a destination as established for a workspace."""
        self._conn.execute(
            """INSERT OR IGNORE INTO destination_baseline
               (workspace_path, destination, first_seen)
               VALUES (?, ?, ?)""",
            (workspace_path, destination, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    @_locked
    def get_destination_baseline(self, workspace_path: str) -> set[str]:
        """All baseline destinations learned for a workspace."""
        rows = self._conn.execute(
            "SELECT destination FROM destination_baseline WHERE workspace_path = ?",
            (workspace_path,),
        ).fetchall()
        return {row[0] for row in rows}

    # -- Keyed projection snapshots (plan2.md P0.4 residual) ----------------

    @staticmethod
    def _projection_key(encryption: EncryptionManager) -> bytes:
        """Derive the projection-MAC subkey from the master key.

        A fixed context string plus HKDF (RFC 5869, SHA-256) keeps this key
        purpose-bound: the projection MAC key is never the master key itself,
        so leaking one does not expose the other, and a projection digest
        cannot be transplanted into an event-column MAC position (or vice
        versa). 32-byte output matches AES-256/HMAC-SHA-256 strength.
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"agenttrace/projection-mac/v1",
            ).derive(encryption.key_bytes)
        except ImportError:  # pragma: no cover - cryptography is a hard dep
            return hmac.new(
                b"agenttrace/projection-mac/v1", encryption.key_bytes, hashlib.sha256
            ).digest()

    @staticmethod
    def _projection_digest(
        snapshot_json: str, session_id: UUID, mac_key: bytes
    ) -> str:
        """HMAC-SHA-256 over snapshot + session id (domain-separated)."""
        material = (
            b"agenttrace/projection-snapshot/v1"
            + str(session_id).encode()
            + b"\x00"
            + snapshot_json.encode("utf-8")
        )
        return hmac.new(mac_key, material, hashlib.sha256).hexdigest()

    @_locked
    def store_projection_snapshot(self, session_id: UUID, snapshot_json: str) -> str:
        """Persist the keyed MAC of one projection snapshot (latest wins).

        Returns the stored digest. The snapshot body itself is NOT stored —
        the MAC only authenticates the snapshot a client or analyst holds,
        so a forged projection cannot be minted without the key.
        """
        digest = self._projection_digest(
            snapshot_json, session_id, self._projection_key(self._encryption)
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO projection_mac (session_id, digest, stored_at) "
            "VALUES (?, ?, ?)",
            (
                str(session_id),
                digest,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return digest

    @_locked
    def verify_projection_snapshot(
        self, session_id: UUID, snapshot_json: str
    ) -> bool | None:
        """Verify a projection snapshot against its stored MAC.

        True = key-authenticated match. False = forgery or mismatch (the
        snapshot differs from what this host last committed). None = no
        snapshot was ever committed for this session — 'not checked', never
        conflated with a pass.
        """
        row = self._conn.execute(
            "SELECT digest FROM projection_mac WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if row is None:
            return None
        expected = self._projection_digest(
            snapshot_json, session_id, self._projection_key(self._encryption)
        )
        return hmac.compare_digest(str(row["digest"]), expected)

    @_locked
    def get_projection_digest(self, session_id: UUID) -> str | None:
        """The stored MAC for a session's latest projection snapshot."""
        row = self._conn.execute(
            "SELECT digest FROM projection_mac WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        return str(row["digest"]) if row else None

    # -- Key rotation --

    # Every encrypted column, grouped by table. Table and column names are
    # constants — never interpolated from caller input.
    _ENCRYPTED_COLUMNS: dict[str, tuple[str, ...]] = {
        "sessions": ("config_enc", "task_desc_enc", "metadata_enc"),
        "events": ("canonical_json_enc", "payload_enc"),
        "graph_nodes": ("label_enc", "data_enc"),
        "graph_edges": ("data_enc",),
        "approvals": ("reason_enc", "scope_enc", "affected_enc"),
        "task_contracts": (
            "goal_enc",
            "allowed_enc",
            "prohibited_enc",
            "tests_enc",
            "tools_enc",
            "notes_enc",
        ),
        "review_runs": ("payload_enc",),
    }

    @_locked
    def rotate_encryption(
        self,
        new_key: bytes,
        blob_store: Any = None,
    ) -> None:
        """Re-encrypt ALL encrypted data with a new master key.

        Decrypts every encrypted column (and every blob file, if a BlobStore
        is supplied) with the current key and re-encrypts with `new_key`,
        inside one write transaction. Nothing on disk changes for the key
        itself — callers must invoke EncryptionManager.commit_rotation()
        AFTER this succeeds, so a failure rolls back cleanly.

        Blobs are re-encrypted before the transaction commits; a failure
        during blob re-encryption aborts the whole rotation.
        """
        if blob_store is not None:
            blob_store.reencrypt_all(new_key)

        try:
            self._conn.execute("BEGIN IMMEDIATE")
            for table, columns in self._ENCRYPTED_COLUMNS.items():
                for column in columns:
                    self._reencrypt_column(table, column, new_key)
            # Projection MACs are keyed under the (old) master key and their
            # snapshot bodies are deliberately not stored, so they cannot be
            # re-derived under the new key. Clear them: verification then
            # reports 'not checked' instead of failing everything; the next
            # projection write re-anchors under the new key.
            self._conn.execute("DELETE FROM projection_mac")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # Every table's row-identity columns for AAD binding: (key column(s)
    # selected per row, key argument(s) for _row_aad). Events keep their
    # dedicated P1.1 map; this covers the non-event encrypted tables.
    _TABLE_ROW_AAD: dict[str, tuple[str, str, str]] = {
        "sessions": ("session_id", "session_id", "session_id"),
        "adapter_cursors": ("session_id", "session_id", "session_id"),
        "graph_nodes": ("session_id, node_id", "session_id", "node_id"),
        "graph_edges": ("session_id, edge_id", "session_id", "edge_id"),
        "approvals": ("session_id, approval_id", "session_id", "approval_id"),
        "task_contracts": ("session_id, contract_id", "session_id", "contract_id"),
        "review_runs": ("session_id, loop_id", "session_id", "loop_id"),
    }

    @_locked
    def _reencrypt_column(self, table: str, column: str, new_key: bytes) -> None:
        """Re-encrypt one column: decrypt with the current key, encrypt with the new one.

        Row-bound columns (P1.1 event columns and every bound non-event
        table) keep their row binding across rotation; legacy unbound rows
        are upgraded to bound in place."""
        if table == "events":
            aad_column = self._EVENT_COLUMN_AAD.get(column)
            id_select = "session_id, event_id"
        else:
            aad_column = column
            id_select = self._TABLE_ROW_AAD[table][0]
        rows = self._conn.execute(
            f"SELECT rowid, {column}, {id_select} FROM {table} "
            f"WHERE {column} IS NOT NULL"
        ).fetchall()
        for r in rows:
            aad: bytes | None
            if table == "events" and aad_column:
                aad = self._event_aad(r["session_id"], r["event_id"], aad_column)
                try:
                    plaintext = self._encryption.decrypt(r[column], associated_data=aad)
                except EncryptionError:
                    plaintext = self._encryption.decrypt(r[column])
            elif table != "events":
                keys = self._TABLE_ROW_AAD[table]
                aad = self._row_aad(table, r[keys[1]], r[keys[2]])
                try:
                    plaintext = self._encryption.decrypt(r[column], associated_data=aad)
                except EncryptionError:
                    plaintext = self._encryption.decrypt(r[column])
            else:
                aad = None
                plaintext = self._encryption.decrypt(r[column])
            new_cipher = self._encryption.encrypt_with(
                new_key, plaintext, associated_data=aad
            )
            self._conn.execute(
                f"UPDATE {table} SET {column} = ? WHERE rowid = ?",
                (new_cipher, r["rowid"]),
            )
