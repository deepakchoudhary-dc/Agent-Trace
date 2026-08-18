"""Tests for the declared network boundary — sealed-environment egress.

Maps the "eval said no internet but had internet" misconfiguration behind
the Anthropic CTF incidents onto runtime detection: when a workspace is
declared sealed (internet_access_allowed=False), ANY public egress is a
critical finding and an unexpected_egress incident.
"""

from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.incidents import IncidentCorrelationEngine
from agenttrace.models.events import NetworkEvent
from agenttrace.models.session import AgentType
from agenttrace.models.task_contract import TaskContract
from agenttrace.security.policy import PolicyAction, PolicyEngine

_SESSION = uuid4()


def _net(ip: str = "8.8.8.8", method: str = "GET") -> NetworkEvent:
    return NetworkEvent(
        session_id=_SESSION,
        actor_id="agent",
        source_adapter="network_observer",
        destination_ip=ip,
        destination_port=443,
        protocol="tcp",
        http_method=method,
    )


class TestSealedPolicyEngine:
    def test_sealed_env_public_egress_is_critical_finding(self) -> None:
        contract = TaskContract(session_id=uuid4(), goal="eval")
        engine = PolicyEngine(
            uuid4(), contract, internet_allowed=False
        )
        res = engine.evaluate(_net())
        seal = [f for f in res.findings if f.finding_type == "seal_violation"]
        assert seal, "public egress from a sealed env must produce a seal_violation finding"
        assert seal[0].severity == "critical"
        assert res.action == PolicyAction.PAUSE

    def test_sealed_env_private_egress_not_flagged(self) -> None:
        engine = PolicyEngine(uuid4(), TaskContract(session_id=uuid4(), goal="x"),
                              internet_allowed=False)
        res = engine.evaluate(_net(ip="192.168.1.5"))
        assert not any(f.finding_type == "seal_violation" for f in res.findings)

    def test_destination_allowlist_violation(self) -> None:
        engine = PolicyEngine(
            uuid4(), TaskContract(session_id=uuid4(), goal="x"),
            allowed_destinations=["10.0.0.5"],
        )
        res = engine.evaluate(_net(ip="8.8.8.8"))
        assert any(f.finding_type == "destination_allowlist" for f in res.findings)

    def test_allowed_destination_not_flagged(self) -> None:
        engine = PolicyEngine(
            uuid4(), TaskContract(session_id=uuid4(), goal="x"),
            allowed_destinations=["10.0.0.5"],
        )
        res = engine.evaluate(_net(ip="10.0.0.5"))
        assert not any(f.finding_type == "destination_allowlist" for f in res.findings)


class TestUnexpectedEgressIncident:
    def test_sealed_env_egress_incident(self) -> None:
        engine = IncidentCorrelationEngine(uuid4(), internet_allowed=False)
        incidents = engine.observe(_net())
        egress = [i for i in incidents if i.incident_type == "unexpected_egress"]
        assert len(egress) == 1
        assert egress[0].severity == "critical"
        assert len(egress[0].related_events) == 1

    def test_unsealed_env_no_egress_incident(self) -> None:
        engine = IncidentCorrelationEngine(uuid4(), internet_allowed=True)
        incidents = engine.observe(_net())
        assert not any(i.incident_type == "unexpected_egress" for i in incidents)

    def test_allowlist_egress_incident(self) -> None:
        engine = IncidentCorrelationEngine(
            uuid4(), allowed_destinations=["10.0.0.5"]
        )
        incidents = engine.observe(_net(ip="8.8.8.8"))
        assert any(i.incident_type == "unexpected_egress" for i in incidents)
        # In-allowlist destination → no incident
        engine2 = IncidentCorrelationEngine(uuid4(), allowed_destinations=["10.0.0.5"])
        assert not any(
            i.incident_type == "unexpected_egress" for i in engine2.observe(_net(ip="10.0.0.5"))
        )


@pytest.mark.asyncio
async def test_daemon_sealed_wiring(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Sealed eval session",
        agent_type=AgentType.GENERIC,
        internet_access_allowed=False,
    )
    sid = session.session_id

    await daemon.ingest_event(NetworkEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="network_observer",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
        http_method="GET",
    ))

    findings = daemon.get_findings(sid)
    assert any(
        getattr(f, "finding_type", "") == "seal_violation" for f in findings
    ), "seal_violation finding should be produced via the daemon pipeline"

    incidents = daemon.get_incidents(sid)
    assert any(
        getattr(i, "incident_type", "") == "unexpected_egress" for i in incidents
    ), "unexpected_egress incident should be correlated via the daemon pipeline"

    await daemon.stop()
