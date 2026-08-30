"""Keyed authentication for forensic reports and projection snapshots (P0.4).

The previous "report signature" was a bare SHA-256 of the manifest — unkeyed,
so anyone who could modify the report could also recompute its signature.
Reports are now signed with an HMAC-SHA256 derived from a dedicated key
(separated from the ledger encryption key via a domain-specific derivation),
and any offline verifier can validate a report without the live daemon.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_ALGO = "hmac-sha256"
_SIGNATURE_KEY = b"agenttrace/report-signing/v1"
_KEY_ID = "report-key-v1"


class ReportAuthenticationError(ValueError):
    """The report carries no valid signature block."""


def derive_report_key(master_key: bytes) -> bytes:
    """Derive the report-signing key from a master key (domain-separated)."""
    return hmac.new(master_key, _SIGNATURE_KEY, hashlib.sha256).digest()


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical JSON bytes of a payload (sorted keys, tight separators)."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sign_report(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Return the payload with an added keyed ``report_signature`` block."""
    signature = hmac.new(key, canonical_payload_bytes(payload), hashlib.sha256)
    signed = dict(payload)
    signed["report_signature"] = {
        "algo": _ALGO,
        "key_id": _KEY_ID,
        "signature": signature.hexdigest(),
    }
    return signed


def verify_report_signature(payload: dict[str, Any], key: bytes) -> bool:
    """Verify a signed report offline. Constant-time; fails on any mismatch."""
    block = payload.get("report_signature")
    if not isinstance(block, dict):
        return False
    if block.get("algo") != _ALGO or block.get("key_id") != _KEY_ID:
        return False
    signature = block.get("signature")
    if not isinstance(signature, str):
        return False
    unsigned = {k: v for k, v in payload.items() if k != "report_signature"}
    expected = hmac.new(key, canonical_payload_bytes(unsigned), hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), signature)
