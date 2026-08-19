"""Tests for the §11 gap-closure batch: N1–N14, R2, R3, R6, R7.

Covers write-boundary redaction, port consistency, observability gaps,
detector/observer error surfacing, token expiry/rotation, incident-window
seeding, restore integrity findings, response ladder, collusion wiring,
anti-forensic guards, and replay hardening.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

import agenttrace.api as api
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.incidents import IncidentCorrelationEngine
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    ContextBoundaryEvent,
    FileMutationEvent,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
    event_from_dict,
)
from agenttrace.models.session import AgentType, SessionStatus
from agenttrace.security.detectors.engine import DetectionEngine
from agenttrace.security.token import ApiTokenManager

if TYPE_CHECKING:
    from agenttrace.security.detectors.base import DetectionContext, DetectorFinding

SK = "sk_live_" + "a" * 40


def _command_event(cmd: str, sid=None) -> CommandEvent:
    return CommandEvent(
        actor_id="test",
        session_id=sid or uuid4(),
        source_adapter="test",
        command=cmd,
        working_dir="/workspace",
    )


# -- N1: blob write-boundary redaction ---------------------------------------

@pytest.mark.asyncio
async def test_blob_payload_is_redacted_before_store(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    try:
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=str(tmp_path), agent_type=AgentType.GENERIC
        )
        event = CommandEvent(
            actor_id="test",
            session_id=session.session_id,
            source_adapter="test",
            command="cat .env",
            working_dir="/workspace",
        )
        secret = f"export AWS_SECRET={SK}"
        await daemon.ingest_event(event, raw_payload=secret.encode("utf-8"))

        blob_ref = next(r for r in event.evidence_refs if r.startswith("blob:"))
        stored = daemon._blob_store.retrieve_blob(blob_ref[len("blob:"):])
        assert SK.encode() not in stored
        assert b"[REDACTED]" in stored
        assert stored.startswith(b"export ")
    finally:
        await daemon.stop()


# -- N2: store_review_run redacts internally ---------------------------------

def test_store_review_run_redacts_internal(tmp_path: Path) -> None:
    from agenttrace.storage.ledger import EventLedger

    ledger = EventLedger(
        tmp_path / "ledger.db",
        encryption_mgr=None,
        redactor=None,
    )
    sid = uuid4()
    loop_id = uuid4()
    ledger.create_session(
        session_id=sid,
        config_json="{}",
        task_desc="t",
        started_at="2026-01-01T00:00:00+00:00",
    )
    ledger.store_review_run(
        loop_id=loop_id,
        session_id=sid,
        passed=True,
        iterations=1,
        payload_json=f'{{"evidence": "token={SK}"}}',
    )
    row = ledger._conn.execute(
        "SELECT payload_enc FROM review_runs WHERE session_id = ?", (str(sid),)
    ).fetchone()
    assert row is not None
    stored = ledger._encryption.decrypt_str(row[0])
    assert SK not in stored
    assert "[REDACTED]" in stored


# -- N6: allowed_paths derived from workspace when wildcard -------------------

def test_allowed_paths_wildcard_is_derived_from_workspace(tmp_path, monkeypatch):
    test_daemon = AgentTraceDaemon(tmp_path)
    test_tokens = ApiTokenManager(tmp_path)
    monkeypatch.setattr(api, "daemon", test_daemon)
    monkeypatch.setattr(api, "token_manager", test_tokens)
    monkeypatch.setenv("AGENTTRACE_DATA_DIR", str(tmp_path))

    with TestClient(api.app) as c:
        res = c.post(
            "/sessions",
            json={
                "workspace_path": str(tmp_path),
                "task_description": "t",
                "agent_type": "generic",
            },
            headers={"X-AgentTrace-Token": test_tokens.token()},
        )
        assert res.status_code == 200, res.text
        sid = res.json()["session_id"]
        contract = test_daemon._contracts[UUID(sid)]
        assert "*" not in contract.allowed_paths
        assert str(tmp_path) in contract.allowed_paths


# -- N4: list_sessions exposes observability gaps ----------------------------

@pytest.fixture()
def daemon_env(tmp_path, monkeypatch):
    """Point the API module at an isolated data dir and daemon instance."""
    test_daemon = AgentTraceDaemon(tmp_path)
    test_tokens = ApiTokenManager(tmp_path)
    monkeypatch.setattr(api, "daemon", test_daemon)
    monkeypatch.setattr(api, "token_manager", test_tokens)
    monkeypatch.setenv("AGENTTRACE_DATA_DIR", str(tmp_path))
    return test_daemon, test_tokens


def test_list_sessions_includes_observability_gaps(daemon_env):
    test_daemon, test_tokens = daemon_env
    with TestClient(api.app) as c:
        c.post(
            "/sessions",
            json={
                "workspace_path": str(Path.cwd()),
                "task_description": "t",
                "agent_type": "generic",
            },
            headers={"X-AgentTrace-Token": test_tokens.token()},
        )
        res = c.get("/sessions", headers={"X-AgentTrace-Token": test_tokens.token()})
        assert res.status_code == 200
        sessions = res.json()
        assert sessions
        assert "observability_gaps" in sessions[0]


# -- N9: reasoning trail excerpts are redacted -------------------------------

def test_reasoning_trail_excerpts_redacted(daemon_env):
    test_daemon, test_tokens = daemon_env
    with TestClient(api.app) as c:
        sid = _create_session(c, test_tokens, str(Path.cwd()))
        ctx = ContextBoundaryEvent(
            actor_id="agent",
            session_id=UUID(sid),
            source_adapter="sdk",
            payload={
                "reasoning": f"the token is {SK}",
                "reasoning_kind": "thinking",
            },
        )
        _ingest_sync(test_daemon, ctx)
        res = c.get(
            f"/sessions/{sid}/report",
            headers={"X-AgentTrace-Token": test_tokens.token()},
        )
        assert res.status_code == 200
        trail = res.json()["reasoning_trail"]
        assert trail, "expected reasoning trail entries"
        assert all(SK not in entry["excerpt"] for entry in trail)


def _create_session(client, tokens, workspace: str) -> str:
    res = client.post(
        "/sessions",
        json={
            "workspace_path": workspace,
            "task_description": "test task",
            "agent_type": "generic",
        },
        headers={"X-AgentTrace-Token": tokens.token()},
    )
    assert res.status_code == 200, res.text
    return res.json()["session_id"]


def _ingest_sync(daemon: AgentTraceDaemon, event) -> None:
    asyncio.run(daemon.ingest_event(event))


# -- R6: token expiry + rotation ---------------------------------------------

def test_token_rotation_invalidates_old_token(tmp_path: Path) -> None:
    manager = ApiTokenManager(tmp_path)
    first = manager.token()
    second = manager.rotate()
    assert first != second
    assert not manager.verify(first)
    assert manager.verify(second)
    assert manager.token_expiry() is not None


def test_expired_token_fails_closed(tmp_path: Path) -> None:
    import datetime

    manager = ApiTokenManager(tmp_path)
    token = manager.token()
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    manager._expiry_path.write_text(past.isoformat() + "\n", encoding="utf-8")
    assert manager.is_expired()
    assert not manager.verify(token)


# -- N13: event_from_dict degradation tag ------------------------------------

def test_event_from_dict_tags_degraded_events() -> None:
    data = {
        "event_type": "file_mutation",
        "actor_id": "a",
        "session_id": str(uuid4()),
        "source_adapter": "t",
        "file_path": None,  # invalid for FileMutationEvent (str) but valid for base
        "mutation_type": "modify",
    }
    event = event_from_dict(data)
    assert "_degraded" in event.payload
    assert "source_event_type" in event.payload["_degraded"]


# -- N5 + N8: errors are surfaced --------------------------------------------

def test_detector_error_produces_surfaced_finding() -> None:
    class BrokenDetector:
        detector_id = "broken"
        name = "Broken"

        def evaluate(self, event, ctx: DetectionContext) -> list[DetectorFinding]:
            raise ValueError("detector exploded")

    engine = DetectionEngine(uuid4(), detectors=[BrokenDetector()])
    findings = engine.evaluate(_command_event("ls"))
    assert any(f.detector_id == "detector_engine_error" for f in findings)
    assert any("detector exploded" in f.description for f in findings)


@pytest.mark.asyncio
async def test_observer_gap_recorded_on_callback_failure() -> None:
    from agenttrace.observers.base import BaseObserver

    class DummyObserver(BaseObserver):
        async def _run(self) -> None:
            return None

    def bad_callback(event, payload):
        raise RuntimeError("callback down")

    obs = DummyObserver(uuid4(), "/ws", bad_callback)
    await obs.emit(_command_event("x"))
    assert obs.dropped_events == 1
    assert obs.observability_gaps
    assert "callback down" in obs.observability_gaps[0]


# -- N10: network AccessDenied records a gap instead of silence --------------

@pytest.mark.asyncio
async def test_network_access_denied_records_gap(monkeypatch) -> None:
    import psutil  # type: ignore[import-untyped]

    from agenttrace.observers.network import NetworkObserver

    def deny(*args, **kwargs):
        raise psutil.AccessDenied("elevation required")

    monkeypatch.setattr(psutil, "net_connections", deny)
    obs = NetworkObserver(uuid4(), "/ws", lambda e, p: None, poll_interval=0.01)
    obs.update_tracked_pids({123})
    await obs._scan_connections()
    assert obs.observability_gaps
    assert "Cannot access network connections" in obs.observability_gaps[0]


# -- R2: response ladder freezes session on critical incident ----------------

@pytest.mark.asyncio
async def test_critical_incident_freezes_session_and_revokes_approvals(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    try:
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=str(tmp_path), agent_type=AgentType.GENERIC
        )
        sid = session.session_id

        daemon._approvals[sid].record_approval(
            finding_id="f-1", approved=True, reason="ok"
        )
        assert daemon._approvals[sid].get_active_approvals()

        incident = IncidentEvent(
            session_id=sid,
            actor_id="incident_engine",
            source_adapter="incident_engine",
            confidence=ConfidenceLevel.HIGH,
            incident_type="credential_exfiltration",
            severity="critical",
            title="Possible credential exfiltration",
            description="cred exfil",
        )
        await daemon.ingest_event(incident)

        assert daemon._sessions[sid].status == SessionStatus.PAUSED
        assert not daemon._approvals[sid].get_active_approvals()
        findings = daemon.get_findings(sid)
        assert any(f.finding_type == "session_frozen" for f in findings)
    finally:
        await daemon.stop()


# -- R3: collusion scan surfaces candidates as findings ----------------------

@pytest.mark.asyncio
async def test_collusion_scan_surfaces_candidate(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    try:
        await daemon.start()
        s1 = await daemon.create_session(workspace_path=str(tmp_path), agent_type=AgentType.GENERIC)
        s2 = await daemon.create_session(workspace_path=str(tmp_path), agent_type=AgentType.GENERIC)

        for s in (s1, s2):
            await daemon.ingest_event(
                FileMutationEvent(
                    actor_id=f"agent-{s.session_id}",
                    session_id=s.session_id,
                    source_adapter="test",
                    file_path="/shared/secret.txt",
                    mutation_type="modify",
                )
            )

        # The scan is throttled to every 5s; reset the throttle and force a
        # scan by ingesting a fresh event in each session.
        for s in (s1, s2):
            daemon._collusion_last_scan.pop(s.session_id, None)
        for s in (s1, s2):
            await daemon.ingest_event(_command_event("ls", s.session_id))

        for s in (s1, s2):
            findings = daemon.get_findings(s.session_id)
            assert any(
                f.finding_type == "collusion:shared_artifact" for f in findings
            )
    finally:
        await daemon.stop()


# -- R7: incident window seeding across restart ------------------------------

@pytest.mark.asyncio
async def test_incident_engine_seeds_window(tmp_path: Path) -> None:
    engine = IncidentCorrelationEngine(uuid4(), internet_allowed=False)
    sid = uuid4()
    finding = PolicyFindingEvent(
        session_id=sid,
        actor_id="detector_engine",
        source_adapter="detector_engine",
        confidence=ConfidenceLevel.HIGH,
        finding_type="credential_access",
        severity="medium",
        description="credential touched",
    )
    engine.seed_events([finding])
    egress = NetworkEvent(
        session_id=sid,
        actor_id="process:1",
        source_adapter="network_observer",
        destination_ip="8.8.8.8",
        destination_port=443,
        direction="outbound",
    )
    incidents = engine.observe(egress)
    assert any(i.incident_type == "credential_exfiltration" for i in incidents)


# -- P2: flood guard + clock anomaly ----------------------------------------

@pytest.mark.asyncio
async def test_event_flood_flags_and_skips_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agenttrace.daemon as daemon_mod

    # The flood window is wall-clock speed dependent: 505 ingests can take
    # longer than the 5s window on a slow runner, silently resetting the
    # counter. Patch the clock so the window never expires mid-test.
    clock = {"t": 0.0}

    def fake_monotonic() -> float:
        clock["t"] += 0.001
        return clock["t"]

    monkeypatch.setattr(daemon_mod.time, "monotonic", fake_monotonic)

    daemon = daemon_mod.AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path), agent_type=AgentType.GENERIC
    )
    sid = session.session_id

    for i in range(505):
        evt = CommandEvent(
            actor_id="test",
            session_id=sid,
            source_adapter="test",
            command=f"echo {i}",
            working_dir="/workspace",
        )
        await daemon.ingest_event(evt)

    findings = daemon.get_findings(sid)
    assert any(f.finding_type == "event_flood" for f in findings)
    await daemon.stop()


@pytest.mark.asyncio
async def test_clock_anomaly_flagged(tmp_path: Path) -> None:
    import datetime

    daemon = AgentTraceDaemon(tmp_path / "data")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path), agent_type=AgentType.GENERIC
    )
    sid = session.session_id
    daemon._clock_findings.pop(sid, None)
    evt = CommandEvent(
        actor_id="test",
        session_id=sid,
        source_adapter="test",
        command="echo hi",
        working_dir="/workspace",
        timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=3),
    )
    await daemon.ingest_event(evt)
    findings = daemon.get_findings(sid)
    assert any(f.finding_type == "clock_anomaly" for f in findings)
    await daemon.stop()


# -- N7/R4: replay hardening -------------------------------------------------

def test_replay_rejects_interactive_flags() -> None:
    from agenttrace.graph.replay import ReplayEngine

    engine = ReplayEngine("/tmp/ws")
    allowed, reason = engine.verify_command_allowed("pytest --pdb tests/")
    assert not allowed
    assert "pdb" in reason.lower()
    allowed, reason = engine.verify_command_allowed("go test -exec /bin/sh ./...")
    assert not allowed
    assert "exec" in reason.lower()


@pytest.mark.asyncio
async def test_replay_runs_with_stdin_detached(tmp_path: Path) -> None:
    from agenttrace.graph.replay import ReplayEngine

    (tmp_path / "test_stdin.py").write_text(
        "import sys\n"
        "def test_stdin_is_detached():\n"
        "    assert not sys.stdin.isatty()\n",
        encoding="utf-8",
    )
    engine = ReplayEngine(str(tmp_path))
    result = engine._run_command("python -m pytest test_stdin.py", tmp_path)
    assert result["exit_code"] == 0, result["stderr"]


# -- S9: data-dir hardening --------------------------------------------------

def test_harden_data_dir_covers_artifacts(tmp_path: Path) -> None:
    from agenttrace.daemon_entry import harden_data_dir

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "ledger.db").write_text("encrypted", encoding="utf-8")
    (data_dir / "api_token").write_text("tok", encoding="utf-8")
    (data_dir / "keys").mkdir()
    (data_dir / "blobs").mkdir()

    harden_data_dir(data_dir)
    assert (data_dir / "ledger.db").exists()
    assert (data_dir / "api_token").exists()


def test_harden_data_dir_creates_missing_dir(tmp_path: Path) -> None:
    from agenttrace.daemon_entry import harden_data_dir

    target = tmp_path / "nonexistent" / "data"
    harden_data_dir(target)
    assert target.is_dir()


def test_apply_restrictive_perms_is_directory_aware(tmp_path: Path) -> None:
    import os
    import stat

    from agenttrace.security.permissions import apply_restrictive_perms

    sub = tmp_path / "sub"
    sub.mkdir()
    inner = sub / "file"
    inner.write_text("x", encoding="utf-8")

    apply_restrictive_perms(sub)
    apply_restrictive_perms(inner)

    if os.name == "posix":
        sub_stat = sub.stat()
        file_stat = inner.stat()
        # Directories keep the owner search bit; 0600 would break traversal.
        assert sub_stat.st_mode & stat.S_IXUSR
        assert sub_stat.st_mode & (stat.S_IRUSR | stat.S_IWUSR)
        assert not (sub_stat.st_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH))
        # Files stay 0600: no execute bit.
        assert file_stat.st_mode & (stat.S_IRUSR | stat.S_IWUSR)
        assert not (file_stat.st_mode & stat.S_IXUSR)

    # The owner must still be able to traverse and read after hardening.
    assert sub.joinpath("file").exists()


# -- S10: daemon watchdog ----------------------------------------------------

def test_run_server_watchdog_restarts_and_gives_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agenttrace.daemon_entry import run_server

    attempts = {"count": 0}
    failures_left = {"count": 3}

    def fake_run(app, **kwargs):
        attempts["count"] += 1
        if failures_left["count"] > 0:
            failures_left["count"] -= 1
            raise RuntimeError("crash")

    monkeypatch.setattr("agenttrace.daemon_entry.uvicorn.run", fake_run)
    monkeypatch.setattr("agenttrace.daemon_entry.time.sleep", lambda _s: None)

    run_server(tmp_path / "data", 8765)

    assert attempts["count"] == 4  # 3 crashes + 1 clean bind
    assert failures_left["count"] == 0


def test_run_server_watchdog_raises_after_many_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agenttrace.daemon_entry import run_server

    def always_crash(app, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("agenttrace.daemon_entry.uvicorn.run", always_crash)
    monkeypatch.setattr("agenttrace.daemon_entry.time.sleep", lambda _s: None)

    with pytest.raises(RuntimeError):
        run_server(tmp_path / "data", 8765)
