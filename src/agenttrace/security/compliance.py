"""Compliance evidence bundles over the verified ledger chain.

Auto-generated report manifests for EU AI Act Art. 12/50, ISO/IEC 42001,
and SOC 2: every artifact set is digested with SHA-256 over its canonical
JSON, and the bundle is anchored to the ledger's last chain hash so any
recipient can recompute and re-verify without trusting the sender.

The bundle covers observable artifacts only — it never claims to prove
model internals, coordination, or anything the host could not see.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from agenttrace.storage.ledger import EventLedger

# Standard -> artifact evidence mapping (what each standard can point at).
_STANDARDS: dict[str, list[str]] = {
    "EU AI Act Art. 12 (logging)": [
        "events",
        "findings",
        "approvals",
        "chain_anchor",
    ],
    "EU AI Act Art. 50 (transparency)": [
        "incidents",
        "graph",
        "baseline",
    ],
    "ISO/IEC 42001 (AI management system)": [
        "events",
        "findings",
        "incidents",
        "approvals",
    ],
    "SOC 2 (CC7 system operations)": [
        "events",
        "findings",
        "incidents",
        "chain_anchor",
    ],
}


def _json_safe(value: Any) -> Any:
    """Convert non-JSON values (e.g. encrypted BLOBs) into digests."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _sha256(items: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        _json_safe(items),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest(events: list[Any]) -> dict[str, Any]:
    canonical = [e.canonical_dict() for e in events]
    return {
        "count": len(canonical),
        "sha256": _sha256(canonical),
    }


def build_compliance_bundle(
    ledger: EventLedger,
    session_id: UUID,
    workspace_path: str,
    *,
    get_findings: list[Any],
    get_incidents: list[Any],
) -> dict[str, Any]:
    """Build a verifiable compliance manifest anchored to the chain."""
    events = ledger.query_events(session_id, limit=None)
    chain_ok, error = ledger.verify_chain(session_id)

    artifacts: dict[str, dict[str, Any]] = {
        "events": _digest(events),
        "findings": _digest(get_findings),
        "incidents": _digest(get_incidents),
        "approvals": _digest(ledger.get_approvals(session_id)),
        "graph": {
            "nodes": len(ledger.get_graph_nodes(session_id)),
            "edges": len(ledger.get_graph_edges(session_id)),
            "sha256": _sha256([
                *ledger.get_graph_nodes(session_id),
                *ledger.get_graph_edges(session_id),
            ]),
        },
        "baseline": {
            "count": len(ledger.get_destination_baseline(workspace_path)),
            "sha256": _sha256([
                {"destination": d}
                for d in sorted(ledger.get_destination_baseline(workspace_path))
            ]),
        },
    }
    last_hash = ledger.get_last_hash(session_id) or ""

    bundle: dict[str, Any] = {
        "bundle_id": str(uuid4()),
        "session_id": str(session_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain": {
            "verified": chain_ok,
            "error": error or "",
            "last_hash": last_hash,
            "event_count": len(events),
        },
        "artifacts": artifacts,
        "standards": {
            standard: artifact_names
            for standard, artifact_names in _STANDARDS.items()
        },
        "note": (
            "Covers observable artifacts only; nothing inside this bundle "
            "claims visibility into unobserved activity."
        ),
    }

    # Anchor: digest of the manifest plus the chain's last hash. Any holder
    # of the bundle and the chain can recompute this value.
    bundle["bundle_hash"] = _sha256([
        json.loads(json.dumps(bundle, sort_keys=True, default=str)),
        {"last_hash": last_hash},
    ])
    return bundle


def verify_compliance_bundle(bundle: dict[str, Any]) -> bool:
    """Recompute the bundle hash to detect tampering."""
    expected = bundle.get("bundle_hash", "")
    payload = {k: v for k, v in bundle.items() if k != "bundle_hash"}
    recomputed = _sha256([
        json.loads(json.dumps(payload, sort_keys=True, default=str)),
        {"last_hash": bundle.get("chain", {}).get("last_hash", "")},
    ])
    return bool(recomputed == expected)
