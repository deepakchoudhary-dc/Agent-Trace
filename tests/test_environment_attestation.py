"""Unit tests for the pre-flight environment attester (ant.md P1 #5).

``security/attestation.py`` shipped in the METR-gap sprint with no test file of
its own — ``tests/test_attestation.py`` covers ``graph/attestation.py``, the
kernel-bound process-attribution engine, which is a different module. These
tests pin the declared-vs-measured verdict matrix with every probe
monkeypatched, so no test touches the real network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import TYPE_CHECKING

from agenttrace.security.attestation import (
    EnvironmentAttester,
    EnvironmentContract,
)

if TYPE_CHECKING:
    import pytest

_MOD = "agenttrace.security.attestation"


def _patch_probes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    canary: tuple[bool, str] = (False, "1.1.1.1"),
    dns: tuple[str, ...] = (),
    gateway: str = "",
    raise_on_probe: bool = False,
) -> None:
    """Replace the three host probes with deterministic doubles."""

    def _probe() -> tuple[bool, str]:
        if raise_on_probe:
            raise OSError("probe exploded")
        return canary

    monkeypatch.setattr(f"{_MOD}._probe_canary", _probe)
    monkeypatch.setattr(f"{_MOD}._read_dns_servers", lambda: dns)
    monkeypatch.setattr(f"{_MOD}._read_default_gateway", lambda: gateway)


SEALED = EnvironmentContract(internet_access_allowed=False)
UNSEALED = EnvironmentContract(internet_access_allowed=True)


def test_contract_sealed_tracks_the_isolation_claim() -> None:
    assert SEALED.sealed
    assert not UNSEALED.sealed


def test_sealed_contract_with_reachable_canary_is_isolation_broken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Anthropic misconfiguration shape: declared isolated, egress works."""
    _patch_probes(monkeypatch, canary=(True, "8.8.8.8"), dns=("10.0.0.1",), gateway="10.0.0.1")
    result = EnvironmentAttester().preflight(SEALED)
    assert result.verdict == "isolation_broken"
    assert result.measurement is not None
    assert result.measurement.canary_reachable is True
    assert any("egress" in reason for reason in result.reasons)


def test_sealed_contract_with_clean_boundary_is_isolated_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probes(monkeypatch)
    result = EnvironmentAttester().preflight(SEALED)
    assert result.verdict == "isolated_verified"
    assert result.measurement is not None
    assert result.measurement.canary_reachable is False


def test_sealed_contract_with_gateway_but_no_egress_still_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway/DNS pair alone is not egress — it stays runtime-monitored."""
    _patch_probes(monkeypatch, dns=("10.0.0.1",), gateway="10.0.0.1")
    result = EnvironmentAttester().preflight(SEALED)
    assert result.verdict == "isolated_verified"
    assert any("runtime-monitored" in reason for reason in result.reasons)


def test_unsealed_contract_records_boundary_without_a_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probes(monkeypatch, canary=(True, "1.1.1.1"))
    result = EnvironmentAttester().preflight(UNSEALED)
    assert result.verdict == "unsealed_recorded"
    assert any("declares internet access allowed" in reason for reason in result.reasons)


def test_probe_failure_is_unverifiable_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unmeasurable boundary must never be reported as verified."""
    _patch_probes(monkeypatch, raise_on_probe=True)
    result = EnvironmentAttester().preflight(SEALED)
    assert result.verdict == "unverifiable"
    assert result.measurement is None
    assert any("fail-closed" in reason for reason in result.reasons)


def test_result_is_hmac_sealed_over_the_canonical_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hash must be reproducible from the payload — and key-dependent."""
    _patch_probes(monkeypatch)
    result = EnvironmentAttester(report_key=b"unit-test-key").preflight(SEALED)

    payload = result.to_payload()
    payload["attestation_hash"] = ""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(b"unit-test-key", canonical, hashlib.sha256).hexdigest()
    assert result.attestation_hash == expected

    wrong = hmac.new(b"another-key", canonical, hashlib.sha256).hexdigest()
    assert result.attestation_hash != wrong


def test_payload_is_json_serializable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The daemon persists this payload into the ledger, so it must dump."""
    _patch_probes(monkeypatch, canary=(True, "1.1.1.1"), dns=("10.0.0.1",), gateway="10.0.0.1")
    payload = EnvironmentAttester().preflight(SEALED).to_payload()
    assert json.loads(json.dumps(payload))["version"]
    assert payload["contract"]["internet_access_allowed"] is False
