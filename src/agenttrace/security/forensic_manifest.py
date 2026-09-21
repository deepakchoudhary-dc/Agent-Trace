"""The canonical, self-checking, signed forensic manifest.

Why this module exists
----------------------
The first exported manifest was assembled in the browser from three different
sources — the client's `timeline` state, the client's `graphData` state, and the
daemon's `/report` response — and the three were never reconciled. The result
was a document that contradicted itself: `event_count: 31` next to
`total_events: 500`, a `chain_tip` that did not match the last hash in its own
"tamper_evident_timeline", 134 findings with no severity anywhere in the file,
and a signature field the server never emitted at all. An auditor cannot use
such a document, and worse, an adversary can use it to discredit a sound ledger.

So the manifest is now built in ONE place, from ONE set of inputs, on the daemon
side, and it **refuses to sign itself if its own numbers do not reconcile**.
That refusal is the point: a forensic artifact that is internally inconsistent
is worse than an error, because its inconsistency is indistinguishable from
tampering. Fail closed (invariant: no fabricated explanations).

Every count here comes from the same event list, and the timeline is complete —
never a page. Truncation is what let a 500-row browser page masquerade as a
31-event session's audit trail.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from typing import TYPE_CHECKING, Any
from uuid import UUID

from agenttrace.graph.actor_scope import classify_event, summarize_scope
from agenttrace.graph.severity import calibrate
from agenttrace.security.report_auth import (
    chain_binding_block,
    derive_report_key,
    sign_report,
)

if TYPE_CHECKING:
    from agenttrace.models.events import EventBase

MANIFEST_VERSION = "2.0.0"

#: How far outside the session window an event's own `timestamp` may fall before
#: it is treated as back-filled source time rather than observation time. Kept
#: equal to the daemon's clock-jump tolerance so the report and the ledger agree
#: on what counts as anomalous.
WINDOW_TOLERANCE = timedelta(seconds=300)

#: A task description shorter than this cannot anchor scope or intent checks.
_MIN_USABLE_TASK_CHARS = 8

#: The timeline is embedded in full unless the session exceeds this many events,
#: in which case the MOST RECENT window is embedded and the omission is stated.
#: The cap exists because the manifest is serialized twice on the way out (once
#: to sign it, once as the HTTP response) and then parsed by a browser: a
#: 500k-event session would be ~240 MB of JSON, which hangs a tab or a machine.
#: The cap is deliberately explicit and reported rather than silent — a silent
#: cap is exactly what let a 500-row browser page masquerade as a 31-event
#: session's audit trail in the first place.
MAX_TIMELINE_EVENTS = 20_000


class ManifestInconsistencyError(RuntimeError):
    """The manifest's own numbers disagree; refusing to sign a contradictory report."""


@dataclass(frozen=True)
class ManifestInputs:
    """Everything the manifest is allowed to be built from.

    ``ledger_event_count`` is passed separately from ``events`` on purpose: the
    two must agree, and requiring the caller to state both is what makes a
    truncated event list detectable instead of silently plausible.
    """

    session_id: UUID
    task_description: str
    workspace_path: str
    status: str
    started_at: datetime | None
    stopped_at: datetime | None
    events: list[EventBase]
    findings: list[EventBase]
    incidents: list[EventBase]
    approvals_count: int
    context_nodes: int
    context_edges: int
    chain_valid: bool
    chain_error: str | None
    chain_tip: str
    ledger_event_count: int
    master_key: bytes
    reasoning_trail: list[dict[str, Any]] = field(default_factory=list)
    operator_anchor: str | None = None


def _task_contract_block(description: str) -> dict[str, Any]:
    """State whether the task description can actually anchor an audit.

    A one-character description is not a task contract, and pretending it is
    would let scope and intent findings look authoritative when they had nothing
    to compare against.
    """
    stripped = (description or "").strip()
    usable = len(stripped) >= _MIN_USABLE_TASK_CHARS and any(
        ch.isalpha() for ch in stripped
    )
    if usable:
        note = "Task description is sufficient to anchor scope and intent checks."
    elif not stripped:
        note = (
            "No task description was recorded. Scope, intent and drift findings "
            "cannot be evaluated against a declared task."
        )
    else:
        note = (
            f"Task description is {len(stripped)} character(s) and carries no "
            "usable intent. Scope, intent and drift findings cannot be evaluated "
            "against it; treat them as unanchored."
        )
    return {
        "description": description,
        "usable": usable,
        "note": note,
    }


def _event_time_basis(
    timestamp: datetime | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> str:
    """Whether an event's own timestamp is consistent with the audit window.

    ``observed`` — the timestamp sits inside the session window (with tolerance),
    so it plausibly came from the same clock as the rest of the audit.
    ``backfilled`` — it does not, which is what happens when an adapter replays
    an existing transcript and stamps the SOURCE file's original time. The event
    is real; its timestamp simply belongs to a different clock.
    """
    if timestamp is None:
        return "unknown"
    if window_start is None:
        return "observed"
    reference_end = window_end or window_start
    if timestamp < window_start - WINDOW_TOLERANCE:
        return "backfilled"
    if timestamp > reference_end + WINDOW_TOLERANCE:
        return "backfilled"
    return "observed"


def _temporal_block(events: list[EventBase], inputs: ManifestInputs) -> dict[str, Any]:
    """Quantify the two clocks instead of silently interleaving them."""
    observed_present = sum(1 for e in events if e.observed_at is not None)
    outside = sum(
        1
        for e in events
        if _event_time_basis(e.timestamp, inputs.started_at, inputs.stopped_at)
        == "backfilled"
    )

    if observed_present == len(events) and events:
        ordering = "observed_at"
    elif observed_present:
        ordering = "observed_at with seq fallback"
    else:
        ordering = "seq"

    return {
        "ordering_basis": ordering,
        "note": (
            "The timeline is ordered by the ledger's append sequence, which is "
            "the order this daemon OBSERVED the events. `timestamp` is the "
            "event's own claim about when it happened and is not comparable "
            "across events when some were back-filled from a replayed "
            "transcript; `observed_at` is the daemon clock at ingest."
        ),
        "session_window": {
            "started_at": inputs.started_at.isoformat() if inputs.started_at else None,
            "stopped_at": inputs.stopped_at.isoformat() if inputs.stopped_at else None,
        },
        "observation_time": {
            "captured": observed_present,
            "missing": len(events) - observed_present,
        },
        "events_outside_session_window": outside,
    }


def _timeline_entry(event: EventBase, inputs: ManifestInputs) -> dict[str, Any]:
    """One timeline row, carrying the classification the export used to drop."""
    severity = getattr(event, "severity", "") or ""
    return {
        "seq": event.seq,
        "event_id": str(event.event_id),
        "event_type": event.event_type.value,
        "actor_id": event.actor_id,
        "actor_class": classify_event(event).value,
        "source_adapter": event.source_adapter,
        "timestamp": event.timestamp.isoformat(),
        "observed_at": event.observed_at.isoformat() if event.observed_at else None,
        "time_basis": _event_time_basis(
            event.timestamp, inputs.started_at, inputs.stopped_at
        ),
        "confidence": event.confidence.value,
        "severity": severity or None,
        "event_hash": event.event_hash,
        "prev_hash": event.prev_hash,
    }


def _severity_block(findings: list[EventBase], incidents: list[EventBase]) -> dict[str, Any]:
    """Severity distribution over findings and incidents, via the shared ladder."""
    calibration = calibrate([*findings, *incidents])
    return calibration.to_payload()


def _assert_self_consistent(manifest: dict[str, Any]) -> None:
    """Refuse to sign a manifest whose own numbers do not reconcile.

    Each check below corresponds to a defect that actually shipped in the first
    exported manifest. Failing closed here is deliberate: an internally
    contradictory forensic document is indistinguishable from a tampered one.
    """
    stats = manifest["audit_statistics"]
    chain = manifest["chain"]
    block = manifest["timeline"]
    timeline = manifest["tamper_evident_timeline"]

    if block["returned"] != len(timeline):
        raise ManifestInconsistencyError(
            f"timeline block reports {block['returned']} rows but {len(timeline)} are present"
        )
    if stats["total_events"] != block["total_events"]:
        raise ManifestInconsistencyError(
            f"total_events={stats['total_events']} disagrees with the timeline "
            f"block's {block['total_events']}"
        )
    if chain["chain_length"] != stats["total_events"]:
        raise ManifestInconsistencyError(
            f"chain_length={chain['chain_length']} disagrees with "
            f"total_events={stats['total_events']}"
        )
    if stats["findings"] != len(manifest["findings_summary"]):
        raise ManifestInconsistencyError("findings count disagrees with findings_summary")
    if stats["incidents"] != len(manifest["incidents_summary"]):
        raise ManifestInconsistencyError("incidents count disagrees with incidents_summary")

    # Classification covers every sealed event, not just the embedded window.
    actor_total = sum(manifest["agent_scope"]["counts"].values())
    if actor_total != stats["total_events"]:
        raise ManifestInconsistencyError(
            f"actor classification covers {actor_total} of {stats['total_events']} events"
        )

    if block["truncated"] and block["returned"] != MAX_TIMELINE_EVENTS:
        raise ManifestInconsistencyError(
            "a truncated timeline must be exactly the capped window"
        )

    if timeline:
        first_seq = stats["total_events"] - len(timeline)
        seqs = [row["seq"] for row in timeline]
        if seqs != list(range(first_seq, first_seq + len(timeline))):
            raise ManifestInconsistencyError(
                f"timeline sequence numbers are not contiguous from {first_seq}"
            )
        # The tip must be the last embedded row, or the document describes a
        # chain it does not actually reach — the defect that started all this.
        if chain["head_event_hash"] != timeline[-1]["event_hash"]:
            raise ManifestInconsistencyError(
                "head_event_hash does not match the final timeline entry — the "
                "timeline is not the complete chain"
            )
        if not block["truncated"] and timeline[0]["prev_hash"] != "":
            raise ManifestInconsistencyError(
                "a complete timeline must start at the chain genesis"
            )
    elif chain["head_event_hash"]:
        raise ManifestInconsistencyError("empty timeline but a non-empty chain tip")

    for previous, current in pairwise(timeline):
        if current["prev_hash"] != previous["event_hash"]:
            raise ManifestInconsistencyError(
                f"timeline chain break at seq {current['seq']}"
            )


def build_forensic_manifest(inputs: ManifestInputs) -> dict[str, Any]:
    """Build and sign the complete forensic manifest for one session.

    Raises ``ManifestInconsistencyError`` rather than emit a contradictory
    document.
    """
    events = inputs.events
    chain_length = inputs.ledger_event_count
    if chain_length != len(events):
        # The caller's event list is not the whole chain — a page, or a stale
        # client array. Reporting either as a session total is the original bug.
        raise ManifestInconsistencyError(
            f"ledger holds {chain_length} events for this session but "
            f"{len(events)} were supplied"
        )

    scope = summarize_scope(events)
    total_events = len(events)
    truncated = total_events > MAX_TIMELINE_EVENTS
    window = events[-MAX_TIMELINE_EVENTS:] if truncated else events
    timeline = [_timeline_entry(event, inputs) for event in window]

    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "report_id": str(
            UUID(
                int=int.from_bytes(
                    hashlib.sha256(
                        f"{inputs.session_id}:{inputs.chain_tip}".encode()
                    ).digest()[:16],
                    "big",
                )
            )
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": {
            "session_id": str(inputs.session_id),
            "task_description": inputs.task_description,
            "workspace_path": inputs.workspace_path,
            "status": inputs.status,
            "started_at": inputs.started_at.isoformat() if inputs.started_at else None,
            "stopped_at": inputs.stopped_at.isoformat() if inputs.stopped_at else None,
        },
        "task_contract": _task_contract_block(inputs.task_description),
        "chain": {
            "integrity_status": "TAMPER_VERIFIED" if inputs.chain_valid else "TAMPER_DETECTED",
            "integrity_error": inputs.chain_error,
            "head_event_hash": inputs.chain_tip,
            "chain_length": chain_length,
            "genesis_present": bool(events) and events[0].prev_hash == "",
            "binding": chain_binding_block(
                inputs.chain_tip, chain_length, inputs.operator_anchor
            ),
        },
        "temporal_integrity": _temporal_block(events, inputs),
        "audit_statistics": {
            "total_events": len(events),
            "findings": len(inputs.findings),
            "incidents": len(inputs.incidents),
            "approvals": inputs.approvals_count,
            "by_severity": _severity_block(inputs.findings, inputs.incidents),
            "by_actor_class": dict(sorted(scope.counts.items())),
            "context_nodes": inputs.context_nodes,
            "context_edges": inputs.context_edges,
        },
        "agent_scope": scope.to_payload(),
        "timeline": {
            "returned": len(timeline),
            "total_events": total_events,
            "truncated": truncated,
            "first_seq": timeline[0]["seq"] if timeline else None,
            "last_seq": timeline[-1]["seq"] if timeline else None,
            "tail_hash": timeline[-1]["event_hash"] if timeline else None,
            "note": (
                f"The most recent {len(timeline):,} of {total_events:,} sealed "
                "events are embedded; the earlier events are not in this document."
                if truncated
                else "Every sealed event in this session is embedded."
            ),
        },
        "tamper_evident_timeline": timeline,
        "findings_summary": [
            {
                "finding_id": str(f.event_id),
                "type": getattr(f, "finding_type", "") or "policy_finding",
                "severity": getattr(f, "severity", "") or None,
                "confidence": f.confidence.value,
                "description": getattr(f, "description", ""),
            }
            for f in inputs.findings
        ],
        "incidents_summary": [
            {
                "incident_id": str(i.event_id),
                "incident_type": getattr(i, "incident_type", ""),
                "severity": getattr(i, "severity", "") or None,
                "confidence": i.confidence.value,
                "title": getattr(i, "title", ""),
                "related_events": list(getattr(i, "related_events", []) or []),
            }
            for i in inputs.incidents
        ],
        "reasoning_trail": inputs.reasoning_trail,
    }

    _assert_self_consistent(manifest)

    key = derive_report_key(
        inputs.master_key,
        chain_tip=inputs.chain_tip,
        chain_length=chain_length,
        operator_anchor=inputs.operator_anchor,
    )
    return sign_report(manifest, key)
