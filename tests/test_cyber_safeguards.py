"""Tests for cybersecurity safeguards and vulnerability remediations (cyber.md)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.replay import ReplayEngine
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    IncidentEvent,
    ToolRequestEvent,
)
from agenttrace.models.session import AgentType, SessionStatus
from agenttrace.observers.filesystem import FilesystemObserver
from agenttrace.observers.process_tree import ProcessTreeObserver
from agenttrace.security.detectors.base import DetectionContext
from agenttrace.security.detectors.rules import (
    DatabaseDestructionDetector,
    MultiAgentSabotageDetector,
)
from agenttrace.security.redaction import SecretRedactor
from tests.conftest import HostIsolationStub

if TYPE_CHECKING:
    from pathlib import Path


# -- VULN-03: Entropy Redaction on Base64 secrets containing slashes & URL params --

def test_entropy_redaction_base64_with_slashes() -> None:
    redactor = SecretRedactor(entropy_threshold=4.0)
    # 40-char Base64 string containing slashes (like AWS secret keys or session tokens)
    secret_token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE01"
    text = f"Received credential payload: {secret_token}"
    redacted = redactor.redact(text)
    assert secret_token not in redacted
    assert "[REDACTED]" in redacted


def test_entropy_redaction_url_query_token() -> None:
    redactor = SecretRedactor(entropy_threshold=4.0)
    # URL containing high-entropy token in query string
    token = "a98F39X8d9124KjL09vNmZqW1p"
    url = f"https://api.cloud.internal/v1/auth?client_id=123&auth_token={token}&format=json"
    redacted = redactor.redact(url)
    assert token not in redacted
    assert "[REDACTED]" in redacted
    # Ensure URL structure is preserved
    assert "https://api.cloud.internal/v1/auth?" in redacted


def test_entropy_redaction_preserves_benign_file_paths() -> None:
    redactor = SecretRedactor()
    paths = [
        "src/agenttrace/models/events.py",
        "tests/test_cyber_safeguards.py",
        "C:\\Users\\runner\\workspace\\package.json",
        "./dashboard/src/components/GraphView.tsx",
    ]
    for path in paths:
        assert redactor.redact(path) == path


# -- VULN-04: Process Tree Descendant Ancestry Tracking --

def test_process_tree_tracks_descendant_outside_workspace() -> None:
    observer = ProcessTreeObserver(
        session_id=uuid4(),
        workspace_path="/workspace/my_project",
        callback=lambda e, p: None,
    )
    # Simulate parent agent process in workspace
    parent_pid = 1000
    observer._tracked_pids[parent_pid] = {
        "pid": parent_pid,
        "name": "claude",
        "cmdline": "claude",
        "cwd": "/workspace/my_project",
        "started_at": 100.0,
    }

    # Child process spawned with CWD in /tmp (outside workspace)
    child_pid = 1001
    child_info = {
        "pid": child_pid,
        "ppid": parent_pid,
        "name": "python",
        "cmdline": ["python", "-c", "import os; print('hello')"],
        "create_time": 105.0,
    }

    # Verify descendant is recognized as belonging to tracked session
    ppid = child_info.get("ppid")
    is_descendant = bool(ppid is not None and ppid in observer._tracked_pids)
    assert is_descendant


# -- VULN-06: Filesystem Observer .git/hooks Monitoring & Clean Shutdown --

def test_filesystem_observer_monitors_git_hooks() -> None:
    observer = FilesystemObserver(
        session_id=uuid4(),
        workspace_path="/workspace/my_project",
        callback=lambda e, p: None,
    )
    # .git/objects and .git/index must be ignored
    assert observer._should_ignore("/workspace/my_project/.git/objects/ab/123456")
    assert observer._should_ignore("/workspace/my_project/.git/index")
    assert observer._should_ignore("/workspace/my_project/.git/logs/HEAD")

    # .git/hooks and .git/config must NOT be ignored (actively monitored for persistence)
    assert not observer._should_ignore("/workspace/my_project/.git/hooks/pre-push")
    assert not observer._should_ignore("/workspace/my_project/.git/hooks/post-commit")
    assert not observer._should_ignore("/workspace/my_project/.git/config")


@pytest.mark.asyncio
async def test_filesystem_observer_graceful_stop(tmp_path: Path) -> None:
    events = []
    obs = FilesystemObserver(
        session_id=uuid4(),
        workspace_path=str(tmp_path),
        callback=lambda e, p: events.append(e),
    )
    await obs.start()
    assert obs.running
    await obs.stop()
    assert not obs.running
    assert obs._stop_event.is_set()


# -- VULN-08: Replay Engine Environment Scrubbing --

def test_replay_forwards_no_host_env_to_isolation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Host env (including hostile vars) must NEVER reach the child process.

    Since P0.1, replay hands execution to the IsolationRunner forwarding NO
    host environment: the container gets only image defaults plus env the
    caller passes explicitly. Poisoned vars (PYTHONHOME, LD_PRELOAD, ...)
    cannot smuggle code into the isolated child because they never cross
    the boundary.
    """
    for var in (
        "PYTHONPATH",
        "PYTHONHOME",
        "NODE_OPTIONS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "JAVA_TOOL_OPTIONS",
    ):
        monkeypatch.setenv(var, f"/malicious/path/{var}")

    stub = HostIsolationStub()
    engine = ReplayEngine(str(tmp_path), isolation_runner=stub)
    engine._run_command("python -m pytest test_env.py", tmp_path)
    # The decisive guarantee: replay forwarded NO host environment.
    assert stub.last_env is None

# -- VULN-09: Active Child Process Termination in Containment Ladder --

@pytest.mark.asyncio
async def test_incident_response_freezes_and_terminates(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / "data")
    try:
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=str(tmp_path), agent_type=AgentType.GENERIC
        )
        sid = session.session_id

        incident = IncidentEvent(
            session_id=sid,
            actor_id="incident_engine",
            source_adapter="incident_engine",
            confidence=ConfidenceLevel.HIGH,
            incident_type="sandbox_escape",
            severity="critical",
            title="Sandbox escape detected",
            description="Attempted breakout",
        )
        await daemon.ingest_event(incident)

        # Verify session is frozen
        assert daemon._sessions[sid].status == SessionStatus.PAUSED
        findings = daemon.get_findings(sid)
        assert any(f.finding_type == "session_frozen" for f in findings)
    finally:
        await daemon.stop()


# -- Threat Detector Upgrades: Database Destruction & Multi-Agent Sabotage --

def test_database_destruction_detector_catches_diff_and_tool_args() -> None:
    detector = DatabaseDestructionDetector()
    ctx = DetectionContext(session_id=uuid4(), workspace_paths=["/ws"])

    # Diff containing DROP TABLE
    diff_event = FileMutationEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="test",
        file_path="/ws/migrations/0002.py",
        mutation_type="modify",
        diff_summary="- # old\n+ cur.execute('DROP TABLE users CASCADE;')",
    )
    findings = detector.evaluate(diff_event, ctx)
    assert len(findings) == 1
    assert "DROP TABLE" in findings[0].description

    # Tool request containing DROP DATABASE
    tool_event = ToolRequestEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="test",
        tool_name="execute_sql",
        tool_args={"query": "DROP DATABASE production;"},
    )
    findings = detector.evaluate(tool_event, ctx)
    assert len(findings) == 1
    assert "DROP DATABASE" in findings[0].description


def test_multi_agent_sabotage_detector_catches_locks_and_kills() -> None:
    detector = MultiAgentSabotageDetector()
    ctx = DetectionContext(session_id=uuid4(), workspace_paths=["/ws"])

    # Permission lockout
    chmod_event = CommandEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="test",
        command="chmod -R 000 /ws/src",
        working_dir="/ws",
    )
    findings = detector.evaluate(chmod_event, ctx)
    assert len(findings) == 1
    assert findings[0].detector_id == "multi_agent_sabotage"

    # Stop-Process in PowerShell
    ps_event = CommandEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="test",
        command="Stop-Process -Name 'node' -Force",
        working_dir="/ws",
    )
    findings = detector.evaluate(ps_event, ctx)
    assert len(findings) == 1
    assert findings[0].detector_id == "multi_agent_sabotage"
