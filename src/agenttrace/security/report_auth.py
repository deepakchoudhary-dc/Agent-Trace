"""Keyed authentication for forensic reports and projection snapshots (P0.4,
root-of-trust binding per shortcoming #10).

The previous "report signature" was a bare SHA-256 of the manifest — unkeyed,
so anyone who could modify the report could also recompute its signature.
Reports are now signed with an HMAC-SHA256 derived from a dedicated key
(separated from the ledger encryption key via a domain-specific derivation),
and any offline verifier can validate a report without the live daemon.

Root of trust (shortcoming #10): the METR incident showed self-issued
identity gets trusted exactly once and then propagates — Ed25519 signing
with no root of trust made forgery a feature. Report keys therefore bind
to a chain the recorder does not control:

- **Ledger chain anchor** (default): the report-signing key is folded with
  the session's chain tip hash and length at signing time. The signature
  then attests *this report describes the ledger exactly up to this tip* —
  a report whose stated tip disagrees with the key used to sign it cannot
  verify. The chain tip is self-certifying (hash-chain genesis), so no
  party can re-anchor history without breaking the chain.
- **Operator anchor** (optional): an out-of-band anchor string the operator
  publishes elsewhere (e.g. a commit hash of the chain head) is folded
  into the key too. A report signed without knowledge of the published
  anchor fails verification, defeating a compromised local recorder.

Unanchored derivation (no tip, no anchor) remains available and byte-
compatible with the v1 key for existing callers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_ALGO = "hmac-sha256"
_SIGNATURE_KEY = b"agenttrace/report-signing/v1"
_CHAIN_BINDING_KEY = b"agenttrace/report-chain-binding/v1"
_KEY_ID = "report-key-v1"


class ReportAuthenticationError(ValueError):
    """The report carries no valid signature block."""


def derive_report_key(
    master_key: bytes,
    *,
    chain_tip: str | None = None,
    chain_length: int | None = None,
    operator_anchor: str | None = None,
) -> bytes:
    """Derive the report-signing key from a master key (domain-separated).

    When ``chain_tip``/``chain_length`` are provided they are folded into
    the key (chain-anchored root of trust); ``operator_anchor`` folds an
    out-of-band anchor on top. Unanchored derivation is byte-compatible
    with the original v1 key.
    """
    key = hmac.new(master_key, _SIGNATURE_KEY, hashlib.sha256).digest()
    binding_parts: list[str] = []
    if chain_tip is not None:
        binding_parts.append(f"tip={chain_tip}")
    if chain_length is not None:
        binding_parts.append(f"len={chain_length}")
    if operator_anchor is not None:
        binding_parts.append(f"anchor={operator_anchor}")
    if not binding_parts:
        return key
    binding_material = ";".join(binding_parts).encode("utf-8")
    return hmac.new(key, _CHAIN_BINDING_KEY + binding_material, hashlib.sha256).digest()


def chain_binding_block(
    chain_tip: str | None = None,
    chain_length: int | None = None,
    operator_anchor: str | None = None,
) -> dict[str, Any]:
    """The root-of-trust block embedded (and signed) inside a report."""
    return {
        "chain_tip": chain_tip,
        "chain_length": chain_length,
        "operator_anchor": operator_anchor,
        "anchored": chain_tip is not None or operator_anchor is not None,
    }


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
