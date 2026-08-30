"""Tests for keyed report authentication (plan2.md P0.4)."""

from __future__ import annotations

from agenttrace.security.report_auth import (
    canonical_payload_bytes,
    derive_report_key,
    sign_report,
    verify_report_signature,
)


def _report() -> dict[str, object]:
    return {
        "session_id": "abc",
        "event_count": 42,
        "integrity_status": "TAMPER_VERIFIED",
        "findings_summary": [{"type": "x", "severity": "high"}],
    }


def test_sign_and_verify_roundtrip() -> None:
    master = b"0" * 32
    key = derive_report_key(master)
    signed = sign_report(_report(), key)
    assert signed["report_signature"]["algo"] == "hmac-sha256"
    assert verify_report_signature(signed, key)


def test_tampered_payload_fails() -> None:
    key = derive_report_key(b"k" * 32)
    signed = sign_report(_report(), key)
    signed["event_count"] = 0  # attacker inflates/deflates the record
    assert not verify_report_signature(signed, key)


def test_wrong_key_fails() -> None:
    signed = sign_report(_report(), derive_report_key(b"a" * 32))
    assert not verify_report_signature(signed, derive_report_key(b"b" * 32))


def test_unsigned_report_fails() -> None:
    assert not verify_report_signature(_report(), derive_report_key(b"k" * 32))


def test_signature_stripped_payload_is_canonical_input() -> None:
    """Verification recomputes over the payload WITHOUT the signature block."""
    key = derive_report_key(b"k" * 32)
    signed = sign_report(_report(), key)
    stripped = {k: v for k, v in signed.items() if k != "report_signature"}
    expected_block = signed["report_signature"]
    assert expected_block is not None  # keep type checkers honest
    import hashlib
    import hmac

    from agenttrace.security.report_auth import _ALGO, _KEY_ID  # noqa: SLF001

    expected = hmac.new(
        key, canonical_payload_bytes(stripped), hashlib.sha256
    ).hexdigest()
    assert signed["report_signature"]["signature"] == expected  # type: ignore[index]
    assert _ALGO == "hmac-sha256" and _KEY_ID


def test_derived_key_differs_from_master() -> None:
    master = b"m" * 32
    assert derive_report_key(master) != master
    assert derive_report_key(master) == derive_report_key(master)
