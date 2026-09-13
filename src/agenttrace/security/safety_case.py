"""Deployment safety cases: one assembled, chain-anchored, signed bundle.

Answers the "safety case for deployments" call (ant.md P2 #8; Bengio
2026): a single reviewer-readable document that assembles — over the
*same* verified chain — the signed forensic report, the retro-scan
calibration with its negative-result statement, the environment
attestation, and the compliance manifest.

Every section covers observable artifacts only. The bundle never claims
to prove model internals, coordination, or anything the host could not
see; the reasoning gap is stated, not papered over.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from agenttrace.graph.retro_scan import RetroScanReport

from agenttrace.security.compliance import build_compliance_bundle
from agenttrace.security.report_auth import (
    chain_binding_block,
    derive_report_key,
    sign_report,
)

_SAFETY_CASE_VERSION = 1


def build_safety_case(
    ledger: Any,
    session_id: UUID,
    workspace_path: str,
    *,
    signed_report: dict[str, Any],
    retro_report: RetroScanReport,
    attestation_payload: dict[str, Any] | None,
    get_findings: list[Any],
    get_incidents: list[Any],
) -> dict[str, Any]:
    """Assemble the deployment safety case over the verified ledger chain.

    Args:
        ledger: the session's event ledger (chain source of truth).
        session_id: the audited session.
        workspace_path: declared workspace (baseline digests).
        signed_report: the already-signed forensic report envelope
            (HMAC signature participates verbatim — not re-signed).
        retro_report: the retro-scan's detector verdict over stored
            history, with calibration and negative-result statement.
        attestation_payload: sealed environment attestation
            (``AttestationResult.to_payload()``) or None when the
            session never declared isolation — recorded as a gap,
            never fabricated.
        get_findings: session policy findings.
        get_incidents: session correlated incidents.
    """
    is_valid, error = ledger.verify_chain(session_id)
    events = ledger.query_events(session_id, limit=None)
    chain_tip = ledger.get_last_hash(session_id)
    chain_length = ledger.get_next_seq(session_id)

    calibration = retro_report.calibration()
    compliance = build_compliance_bundle(
        ledger,
        session_id,
        workspace_path,
        get_findings=get_findings,
        get_incidents=get_incidents,
    )

    safety_case: dict[str, Any] = {
        "safety_case_id": str(uuid4()),
        "version": _SAFETY_CASE_VERSION,
        "session_id": str(session_id),
        "workspace_path": workspace_path,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain": {
            "integrity_status": "TAMPER_VERIFIED" if is_valid else "TAMPER_DETECTED",
            "integrity_error": error,
            "head_event_hash": chain_tip,
            "event_count": len(events),
            "chain_binding": chain_binding_block(chain_tip, chain_length),
        },
        "signed_forensic_report": signed_report,
        "retro_scan": {
            "summary": retro_report.summary(),
            "incident_count": len(retro_report.retro_incidents),
            "calibration": calibration.to_payload(),
            "negative_result_statement": retro_report.negative_result(),
        },
        "environment_attestation": (
            attestation_payload
            if attestation_payload is not None
            else {
                "recorded": False,
                "note": (
                    "Session never declared isolation; no environment "
                    "attestation exists. Nothing is fabricated here."
                ),
            }
        ),
        "compliance_bundle": compliance,
        "coverage_boundary": {
            "covers": [
                "sealed ledger events on this host",
                "policy findings, approvals, correlated incidents",
                "detector verdicts over stored history",
                "declared-vs-measured environment state",
            ],
            "does_not_cover": [
                "model internals (reasoning is only observable where the adapter captured it)",
                "actions on other machines (single-host visibility)",
                "processes running as the operating user (same-user trust boundary)",
            ],
            "witness_status": (
                "local-only: hashes are recomputable by any holder of the "
                "ledger, but no out-of-band witness exists; deletion of the "
                "ledger destroys the evidence trail."
            ),
        },
    }

    # The safety case's own digest — computed over everything above — so a
    # recipient can verify the bundle is intact without re-deriving each
    # section. The whole document is then signed with the same
    # chain-tip-bound key as forensic reports: a forged safety case cannot
    # restate a different history and still verify.
    digest = hashlib.sha256(
        json.dumps(safety_case, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    safety_case["safety_case_sha256"] = digest
    return sign_report(
        safety_case,
        derive_report_key(
            ledger.encryption.key_bytes,
            chain_tip=chain_tip,
            chain_length=chain_length,
        ),
    )


def verify_safety_case(safety_case: dict[str, Any], key: bytes) -> bool:
    """Offline verification: digest integrity then HMAC signature."""
    digest = safety_case.get("safety_case_sha256")
    if not isinstance(digest, str):
        return False
    # The digest was computed over the bundle BEFORE its own digest field
    # was attached; the HMAC was computed over the bundle AFTER (the digest
    # field is part of the signed payload). Both exclusions must differ.
    without_digest = {
        k: v for k, v in safety_case.items() if k not in ("report_signature", "safety_case_sha256")
    }
    recomputed = hashlib.sha256(
        json.dumps(without_digest, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    if recomputed != digest:
        return False
    from agenttrace.security.report_auth import verify_report_signature

    # The signature block must stay present: verify_report_signature strips
    # it internally to recompute the HMAC over the as-signed payload.
    return verify_report_signature(safety_case, key)
