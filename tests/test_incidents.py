"""Tests for the incident correlation engine — multi-stage attack patterns."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.incidents import IncidentCorrelationEngine
from agenttrace.models.events import (
    ApprovalEvent,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
)

_SESSION = uuid4()


def _finding(finding_type: str, seconds_ago: float = 0) -> PolicyFindingEvent:
    return PolicyFindingEvent(
        session_id=_SESSION,
        actor_id="policy",
        source_adapter="policy_engine",
        finding_type=finding_type,
        severity="high",
        description=f"test {finding_type}",
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
    )


def _network(ip: str = "8.8.8.8", method: str = "GET", seconds_ago: float = 0) -> NetworkEvent:
    return NetworkEvent(
        session_id=_SESSION,
        actor_id="agent",
        source_adapter="network_observer",
        destination_ip=ip,
        destination_port=443,
        protocol="tcp",
        http_method=method,
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
    )


def _approval(seconds_ago: float) -> ApprovalEvent:
    return ApprovalEvent(
        session_id=_SESSION,
        actor_id="user",
        source_adapter="approval_manager",
        finding_id="f",
        approved=True,
        reason="ok",
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
    )


class TestIncidentCorrelationEngine:
    def test_credential_exfiltration(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        # Feed in chronological order: finding first, then network egress
        assert engine.observe(_finding("credential_access", seconds_ago=30)) == []
        incidents = engine.observe(_network(method="POST", seconds_ago=5))
        # A POST to a public host legitimately completes BOTH the exfiltration
        # chain and the external-state-change pattern
        exfil = [i for i in incidents if i.incident_type == "credential_exfiltration"]
        assert len(exfil) == 1
        assert exfil[0].severity == "critical"
        assert len(exfil[0].related_events) == 2

    def test_exfiltration_cooldown(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        engine.observe(_finding("credential_access", seconds_ago=30))
        engine.observe(_network(method="POST", seconds_ago=5))
        # Same pattern again within cooldown → no duplicate incident
        assert engine.observe(_finding("credential_access")) == []
        assert engine.observe(_network(method="GET")) == []

    def test_sandbox_escape_chain(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        assert engine.observe(_finding("privilege_escalation", seconds_ago=10)) == []
        incidents = engine.observe(_finding("sandbox_evasion", seconds_ago=2))
        assert len(incidents) == 1
        assert incidents[0].incident_type == "sandbox_escape_attempt"
        assert incidents[0].severity == "critical"

    def test_single_finding_is_not_an_escape(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        assert engine.observe(_finding("privilege_escalation")) == []

    def test_supply_chain_pattern(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        assert engine.observe(_finding("unexpected_dependency", seconds_ago=20)) == []
        incidents = engine.observe(_network(method="GET", seconds_ago=5))
        assert any(i.incident_type == "supply_chain_tampering" for i in incidents)

    def test_external_state_change_public(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        incidents = engine.observe(_network(method="DELETE"))
        assert any(i.incident_type == "external_state_change" for i in incidents)

    def test_external_state_change_private_ip(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        incidents = engine.observe(_network(ip="192.168.1.10", method="POST"))
        assert not any(i.incident_type == "external_state_change" for i in incidents)

    def test_external_state_change_read_method(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        incidents = engine.observe(_network(method="GET"))
        assert not any(i.incident_type == "external_state_change" for i in incidents)

    def test_approval_fatigue(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        assert engine.observe(_approval(seconds_ago=3)) == []
        assert engine.observe(_approval(seconds_ago=2)) == []
        incidents = engine.observe(_approval(seconds_ago=1))
        assert any(i.incident_type == "approval_fatigue" for i in incidents)

    def test_approval_fatigue_spread_out(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        # Oldest approval falls outside the 120s window and is pruned
        engine.observe(_approval(seconds_ago=130))
        engine.observe(_approval(seconds_ago=100))
        incidents = engine.observe(_approval(seconds_ago=60))
        assert not any(i.incident_type == "approval_fatigue" for i in incidents)

    def test_incident_events_are_not_recorrelated(self) -> None:
        engine = IncidentCorrelationEngine(_SESSION)
        incident = IncidentEvent(
            session_id=_SESSION,
            actor_id="incident_engine",
            source_adapter="incident_engine",
            incident_type="credential_exfiltration",
            severity="critical",
            title="t",
            description="d",
        )
        assert engine.observe(incident) == []
