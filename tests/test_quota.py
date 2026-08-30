"""Tests for storage quotas and evidence-incomplete semantics (plan2.md P0.5)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from agenttrace.models.events import ConfidenceLevel, InvocationEvent
from agenttrace.storage.ledger import EventLedger, LedgerError

if TYPE_CHECKING:
    from pathlib import Path


def _event() -> InvocationEvent:
    return InvocationEvent(
        session_id=uuid4(),
        actor_id="test",
        source_adapter="test",
        confidence=ConfidenceLevel.HIGH,
    )


def test_quota_exceeded_marks_evidence_incomplete(tmp_path: Path) -> None:
    """Over-quota writes are refused AND the session is marked incomplete."""
    ledger = EventLedger(tmp_path / "q.db", max_storage_bytes=1)
    sid = uuid4()
    event = _event()
    event.session_id = sid
    with pytest.raises(LedgerError, match="storage_quota_exceeded"):
        ledger.append_event(event)
    assert ledger.is_evidence_incomplete(str(sid))


def test_no_quota_by_default(tmp_path: Path) -> None:
    ledger = EventLedger(tmp_path / "q.db")
    sid = uuid4()
    ledger.create_session(sid, "{}", "quota-test", "2026-01-01T00:00:00Z")
    event = _event()
    event.session_id = sid
    ledger.append_event(event)
    assert not ledger.is_evidence_incomplete(str(sid))


def test_evidence_incomplete_survives_reopen(tmp_path: Path) -> None:
    """The marker is durable: it must survive a daemon restart (reopen)."""
    db = tmp_path / "q.db"
    ledger = EventLedger(db, max_storage_bytes=1)
    sid = uuid4()
    event = _event()
    event.session_id = sid
    with pytest.raises(LedgerError):
        ledger.append_event(event)

    reopened = EventLedger(db)
    assert reopened.is_evidence_incomplete(str(sid))
