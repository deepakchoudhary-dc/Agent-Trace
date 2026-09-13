"""Tests for the deployment safety case bundle (ant.md P2 #8; Bengio 2026)."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from agenttrace.security.safety_case import build_safety_case, verify_safety_case

_SID = uuid4()


class _StubLedger:
    """Minimal ledger surface consumed by the safety-case builder."""

    def __init__(self) -> None:
        self.encryption = SimpleNamespace(key_bytes=b"k" * 32)

    def verify_chain(self, session_id):
        return True, None

    def query_events(self, session_id, limit=None):
        return []

    def get_last_hash(self, session_id):
        return "a" * 64

    def get_next_seq(self, session_id):
        return 7

    def get_approvals(self, session_id):
        return []

    def get_graph_nodes(self, session_id):
        return []

    def get_graph_edges(self, session_id):
        return []

    def get_destination_baseline(self, workspace_path):
        return []


class _StubRetroReport:
    def __init__(self, incidents: tuple = ()) -> None:
        self.retro_incidents = incidents

    def summary(self) -> str:
        return "1 session, 5 events scanned."

    def calibration(self):
        from agenttrace.graph.severity import calibrate

        return calibrate(self.retro_incidents)

    def negative_result(self, *, threshold: str = "high") -> str:
        return "negative_result_statement"


def _base_kwargs() -> dict[str, object]:
    return {
        "signed_report": {
            "report_id": str(uuid4()),
            "integrity_status": "TAMPER_VERIFIED",
        },
        "retro_report": _StubRetroReport(),
        "attestation_payload": None,
        "get_findings": [],
        "get_incidents": [],
    }


def test_safety_case_builds_and_verifies() -> None:
    case = build_safety_case(
        _StubLedger(),
        _SID,
        r"C:\work\demo",
        **_base_kwargs(),  # type: ignore[arg-type]
    )
    assert case["session_id"] == str(_SID)
    assert case["chain"]["integrity_status"] == "TAMPER_VERIFIED"
    assert case["chain"]["event_count"] == 0
    assert "negative_result_statement" in case["retro_scan"]
    assert case["environment_attestation"]["recorded"] is False
    assert "safety_case_sha256" in case
    assert case["report_signature"]["algo"] == "hmac-sha256"

    # The bundle is self-verifying offline with the derived key.
    from agenttrace.security.report_auth import derive_report_key

    assert verify_safety_case(
        case,
        derive_report_key(b"k" * 32, chain_tip="a" * 64, chain_length=7),
    )


def test_safety_case_detects_mutation() -> None:
    case = build_safety_case(
        _StubLedger(),
        _SID,
        r"C:\work\demo",
        **_base_kwargs(),  # type: ignore[arg-type]
    )
    case["retro_scan"]["incident_count"] = 99  # attacker inflates the record
    from agenttrace.security.report_auth import derive_report_key

    assert not verify_safety_case(
        case,
        derive_report_key(b"k" * 32, chain_tip="a" * 64, chain_length=7),
    )


def test_safety_case_includes_affected_third_parties() -> None:
    """The bundle carries the P2 #9 third-party enumeration with its
    extraction limits, so the notification list is reviewer-ready."""
    from datetime import datetime, timezone

    from agenttrace.models.events import (
        CommandEvent,
        ConfidenceLevel,
        NetworkEvent,
    )

    net = NetworkEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="network_observer",
        confidence=ConfidenceLevel.HIGH,
        destination_ip="93.184.216.34",
        destination_port=443,
        protocol="tcp",
        direction="outbound",
        timestamp=datetime.now(timezone.utc),
    )

    class _EventLedger(_StubLedger):
        def query_events(self, session_id, limit=None):
            return [
                net,
                CommandEvent(
                    session_id=_SID,
                    actor_id="agent",
                    source_adapter="sdk",
                    confidence=ConfidenceLevel.LOW,
                    command="echo local only",
                ),
            ]

    case = build_safety_case(
        _EventLedger(),
        _SID,
        r"C:\work\demo",
        **_base_kwargs(),  # type: ignore[arg-type]
    )
    parties = case["affected_third_parties"]
    assert parties["party_count"] == 1
    assert parties["parties"][0]["identifier"] == "93.184.216.34"
    assert parties["extraction_limits"]


def test_safety_case_with_attestation_records_verdict() -> None:
    case = build_safety_case(
        _StubLedger(),
        _SID,
        r"C:\work\demo",
        **{
            **_base_kwargs(),
            "attestation_payload": {
                "verdict": "isolated_verified",
                "reasons": ["canary unreachable"],
            },
        },  # type: ignore[arg-type]
    )
    assert case["environment_attestation"]["verdict"] == "isolated_verified"
