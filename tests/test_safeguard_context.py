"""Tests for safeguard-context metadata (ant.md P2 #11)."""

from __future__ import annotations

from agenttrace.models.session import SessionConfig
from agenttrace.security.safeguard_context import (
    FINDING_TYPE,
    build_safeguard_context_payload,
    emit_safeguard_context,
)

_SID = __import__("uuid").uuid4()


def _config(net: bool | None = False) -> SessionConfig:
    return SessionConfig(
        workspace_path="/ws",
        internet_access_allowed=net,
        allowed_destinations=(["10.0.0.1"] if net is False else []),
    )


def test_payload_records_per_session_and_daemon_wide_state() -> None:
    payload = build_safeguard_context_payload(
        config=_config(False),
        per_session_detectors={
            "policy_engine": True,
            "covert_channel": True,
            "containment_escape": False,  # the honest gap this feature exposes
        },
        daemon_wide_engines={"post_exit_surveillance": True},
        containment_active=False,
        kernel_observer_active=True,
        auditd_observer_active=False,
    )
    assert payload["network_contract"] == "sealed (no internet declared)"
    assert payload["allowed_destinations_count"] == 1
    assert payload["per_session_detectors"]["containment_escape"] is False
    assert payload["daemon_wide_engines"]["post_exit_surveillance"] is True
    assert payload["observation_planes"]["platform"] == "polling+etw"
    assert "single-host visibility" in " ".join(payload["declared_limits"])


def test_network_contract_variants() -> None:
    sealed = build_safeguard_context_payload(
        config=_config(False),
        per_session_detectors={},
        daemon_wide_engines={},
        containment_active=False,
        kernel_observer_active=False,
        auditd_observer_active=False,
    )
    assert "sealed" in sealed["network_contract"]

    open_net = build_safeguard_context_payload(
        config=_config(True),
        per_session_detectors={},
        daemon_wide_engines={},
        containment_active=False,
        kernel_observer_active=False,
        auditd_observer_active=False,
    )
    assert "open" in open_net["network_contract"]

    undeclared = build_safeguard_context_payload(
        config=_config(None),
        per_session_detectors={},
        daemon_wide_engines={},
        containment_active=False,
        kernel_observer_active=False,
        auditd_observer_active=False,
    )
    assert "undeclared" in undeclared["network_contract"]


def test_emit_is_info_and_carries_chain_anchor() -> None:
    payload = build_safeguard_context_payload(
        config=_config(None),
        per_session_detectors={"policy_engine": True},
        daemon_wide_engines={},
        containment_active=False,
        kernel_observer_active=True,
        auditd_observer_active=False,
    )
    event = emit_safeguard_context(
        session_id=_SID,
        chain_anchor="a" * 64,
        payload=payload,
    )
    assert event.finding_type == FINDING_TYPE
    assert event.severity == "info"
    assert event.source_adapter == "safeguard_context"
    assert event.evidence_refs == ["a" * 64]
    assert event.payload["per_session_detectors"]["policy_engine"] is True


def test_fresh_session_has_no_anchor_and_stays_honest() -> None:
    event = emit_safeguard_context(
        session_id=_SID,
        chain_anchor=None,
        payload={"network_contract": "undeclared"},
    )
    assert event.evidence_refs == []
    # info severity: context must never gate or alarm on its own
    assert event.severity == "info"
