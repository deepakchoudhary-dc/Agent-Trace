"""The forensic manifest must be complete, self-consistent, and signed.

The artifact that motivated these tests claimed 31 events in one field and 500
in another, carried a chain tip that did not match its own timeline's last hash,
showed no severity or confidence anywhere, and shipped with no signature at all.
Each test below pins one of those failures shut.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from agenttrace.models.events import ConfidenceLevel, PolicyFindingEvent
from agenttrace.security.forensic_manifest import (
    MANIFEST_VERSION,
    MAX_TIMELINE_EVENTS,
    ManifestInconsistencyError,
    ManifestInputs,
    build_forensic_manifest,
)
from agenttrace.security.report_auth import derive_report_key, verify_report_signature

SESSION = UUID("ba8de62a-2891-4a62-b320-38594177e460")
WINDOW_START = datetime(2026, 9, 18, 11, 51, 15, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 18, 11, 52, 37, tzinfo=timezone.utc)
MASTER_KEY = b"test-master-key-for-manifest"


def _finding(
    seq: int,
    prev_hash: str,
    *,
    timestamp: datetime | None = None,
    observed: bool = True,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    severity: str = "high",
) -> PolicyFindingEvent:
    event = PolicyFindingEvent(
        session_id=SESSION,
        actor_id="detector_engine",
        source_adapter="detector_engine",
        confidence=confidence,
        severity=severity,
        finding_type="credential_access",
        description="read a credential file",
        timestamp=timestamp or WINDOW_START + timedelta(seconds=seq),
    )
    # observed_at must be set before seal(): the hash commits to every typed
    # field, so stamping it afterwards would invalidate the chain.
    if observed:
        event.observed_at = WINDOW_START + timedelta(seconds=seq)
    event.seal(prev_hash=prev_hash, seq=seq)
    return event


def _chain(count: int, **kwargs: object) -> list[PolicyFindingEvent]:
    events: list[PolicyFindingEvent] = []
    prev = ""
    for seq in range(count):
        event = _finding(seq, prev, **kwargs)  # type: ignore[arg-type]
        prev = event.event_hash
        events.append(event)
    return events


def _inputs(events: list[PolicyFindingEvent], **overrides: object) -> ManifestInputs:
    base: dict[str, object] = {
        "session_id": SESSION,
        "task_description": "Refactor the ledger append path",
        "workspace_path": "E:\\Blackbox",
        "status": "stopped",
        "started_at": WINDOW_START,
        "stopped_at": WINDOW_END,
        "events": list(events),
        "findings": list(events),
        "incidents": [],
        "approvals_count": 0,
        "context_nodes": 12,
        "context_edges": 8,
        "chain_valid": True,
        "chain_error": None,
        "chain_tip": events[-1].event_hash if events else "",
        "ledger_event_count": len(events),
        "master_key": MASTER_KEY,
        "reasoning_trail": [],
    }
    base.update(overrides)
    return ManifestInputs(**base)  # type: ignore[arg-type]


def test_manifest_carries_severity_and_confidence_everywhere() -> None:
    """The ledger had both all along; the export dropped them."""
    events = _chain(3, confidence=ConfidenceLevel.MEDIUM)
    manifest = build_forensic_manifest(_inputs(events))

    assert manifest["manifest_version"] == MANIFEST_VERSION
    for row in manifest["tamper_evident_timeline"]:
        assert row["confidence"] == "medium"
        assert row["severity"] == "high"
    for finding in manifest["findings_summary"]:
        assert finding["confidence"] == "medium"
        assert finding["severity"] == "high"
    assert manifest["audit_statistics"]["by_severity"]["counts"]["high"] == 3


def test_manifest_refuses_a_truncated_event_list() -> None:
    """A page of events must never be reported as the session's total."""
    events = _chain(3)
    with pytest.raises(ManifestInconsistencyError, match="ledger holds 500 events"):
        build_forensic_manifest(_inputs(events, ledger_event_count=500))


def test_manifest_refuses_a_tip_that_is_not_the_last_event() -> None:
    """This is exactly the defect that shipped: a chain tip the report's own
    timeline could not reach, meaning the timeline was truncated."""
    events = _chain(3)
    with pytest.raises(ManifestInconsistencyError, match="final timeline entry"):
        build_forensic_manifest(_inputs(events, chain_tip="f" * 64))


def test_manifest_counts_reconcile_across_blocks() -> None:
    events = _chain(4)
    manifest = build_forensic_manifest(_inputs(events))

    stats = manifest["audit_statistics"]
    timeline = manifest["tamper_evident_timeline"]
    assert stats["total_events"] == len(timeline) == manifest["chain"]["chain_length"] == 4
    assert stats["findings"] == len(manifest["findings_summary"]) == 4
    assert sum(manifest["agent_scope"]["counts"].values()) == 4
    assert manifest["chain"]["head_event_hash"] == timeline[-1]["event_hash"]
    assert manifest["timeline"]["truncated"] is False
    assert manifest["timeline"]["returned"] == 4
    assert "Every sealed event" in manifest["timeline"]["note"]


def test_oversized_timeline_is_capped_and_the_omission_is_stated() -> None:
    """A 500k-event session must not be serialized in full — the manifest is
    dumped twice on the way out and then parsed by a browser — but the cap must
    be REPORTED. A silent cap is what let a 500-row page masquerade as a
    session's complete audit trail."""
    events = _chain(MAX_TIMELINE_EVENTS + 5)
    manifest = build_forensic_manifest(_inputs(events))

    block = manifest["timeline"]
    assert block["truncated"] is True
    assert block["returned"] == MAX_TIMELINE_EVENTS
    assert block["total_events"] == MAX_TIMELINE_EVENTS + 5
    assert len(manifest["tamper_evident_timeline"]) == MAX_TIMELINE_EVENTS
    assert "not in this document" in block["note"]

    # The MOST RECENT window is kept, so the document still reaches the tip.
    assert block["first_seq"] == 5
    rows = manifest["tamper_evident_timeline"]
    assert rows[-1]["event_hash"] == events[-1].event_hash
    assert manifest["chain"]["head_event_hash"] == rows[-1]["event_hash"]
    assert rows[0]["seq"] == 5

    # Counts still describe the WHOLE session, not the embedded window.
    assert manifest["audit_statistics"]["total_events"] == MAX_TIMELINE_EVENTS + 5
    assert sum(manifest["agent_scope"]["counts"].values()) == MAX_TIMELINE_EVENTS + 5


def test_timeline_is_complete_ordered_and_chain_linked() -> None:
    events = _chain(5)
    timeline = build_forensic_manifest(_inputs(events))["tamper_evident_timeline"]

    assert [row["seq"] for row in timeline] == [0, 1, 2, 3, 4]
    assert timeline[0]["prev_hash"] == ""
    for previous, current in zip(timeline, timeline[1:], strict=False):
        assert current["prev_hash"] == previous["event_hash"]


def test_backfilled_events_are_labelled_not_hidden() -> None:
    """A replayed transcript keeps the source file's clock. The event is real;
    its timestamp belongs to a different clock, and the report must say so."""
    stale = WINDOW_START - timedelta(days=56)
    events = _chain(2)
    events[1] = _finding(1, events[0].event_hash, timestamp=stale)
    events = [events[0], events[1]]

    manifest = build_forensic_manifest(_inputs(events))
    temporal = manifest["temporal_integrity"]

    assert temporal["events_outside_session_window"] == 1
    assert manifest["tamper_evident_timeline"][1]["time_basis"] == "backfilled"
    assert manifest["tamper_evident_timeline"][0]["time_basis"] == "observed"
    assert temporal["observation_time"]["captured"] == 2
    assert temporal["session_window"]["started_at"] == WINDOW_START.isoformat()


def test_missing_observation_time_is_reported_not_invented() -> None:
    events = _chain(2, observed=False)
    temporal = build_forensic_manifest(_inputs(events))["temporal_integrity"]
    assert temporal["observation_time"]["captured"] == 0
    assert temporal["observation_time"]["missing"] == 2
    assert temporal["ordering_basis"] == "seq"


def test_one_character_task_description_is_flagged_unanchored() -> None:
    """`task_description: "4"` shipped in the original artifact."""
    manifest = build_forensic_manifest(_inputs(_chain(1), task_description="4"))
    contract = manifest["task_contract"]
    assert contract["usable"] is False
    assert "unanchored" in contract["note"] or "cannot be evaluated" in contract["note"]


def test_anchoring_truth_is_stated_not_implied() -> None:
    """`anchored: true` beside `operator_anchor: null` was ambiguous."""
    binding = build_forensic_manifest(_inputs(_chain(1)))["chain"]["binding"]
    assert binding["chain_anchored"] is True
    assert binding["operator_anchored"] is False
    assert binding["anchored"] is True
    assert binding["operator_anchor"] is None


def test_manifest_is_signed_and_verifies_offline() -> None:
    events = _chain(3)
    manifest = build_forensic_manifest(_inputs(events))

    assert "report_signature" in manifest
    key = derive_report_key(
        MASTER_KEY,
        chain_tip=events[-1].event_hash,
        chain_length=3,
    )
    assert verify_report_signature(manifest, key) is True
    assert verify_report_signature(manifest, b"wrong-key") is False


def test_tampering_with_a_count_breaks_the_signature() -> None:
    events = _chain(3)
    manifest = build_forensic_manifest(_inputs(events))
    key = derive_report_key(MASTER_KEY, chain_tip=events[-1].event_hash, chain_length=3)

    manifest["audit_statistics"]["total_events"] = 999
    assert verify_report_signature(manifest, key) is False


def test_actor_classes_appear_on_every_timeline_row() -> None:
    events = _chain(2)
    timeline = build_forensic_manifest(_inputs(events))["tamper_evident_timeline"]
    assert {row["actor_class"] for row in timeline} == {"detector"}


def test_empty_session_is_representable() -> None:
    manifest = build_forensic_manifest(_inputs([], findings=[], chain_tip=""))
    assert manifest["audit_statistics"]["total_events"] == 0
    assert manifest["tamper_evident_timeline"] == []
    assert manifest["agent_scope"]["total"] == 0


def test_report_id_is_stable_for_a_session_and_tip() -> None:
    events = _chain(2)
    first = build_forensic_manifest(_inputs(events))["report_id"]
    second = build_forensic_manifest(_inputs(events))["report_id"]
    assert first == second
    UUID(first)  # must be a well-formed UUID
