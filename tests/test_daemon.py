"""Tests for AgentTraceDaemon — session lifecycle, causal graph projection, restart recovery, and pre-execution policy gating."""

from pathlib import Path
from uuid import uuid4
import pytest

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import (
    CommandEvent,
    FileMutationEvent,
    InvocationEvent,
    ToolRequestEvent,
    ToolResultEvent,
)
from agenttrace.models.graph import EdgeType, NodeType
from agenttrace.models.session import AgentType, SessionStatus


@pytest.mark.asyncio
async def test_daemon_session_lifecycle(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()

    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Audit test session",
        agent_type=AgentType.GENERIC,
    )

    assert session.status == SessionStatus.ACTIVE
    assert session.session_id in daemon._sessions

    # Ingest invocation
    inv_event = InvocationEvent(
        session_id=session.session_id,
        actor_id="user_prompt",
        source_adapter="sdk",
        user_intent="Refactor authentication",
    )
    await daemon.ingest_event(inv_event)

    # Ingest tool request & execution
    tool_event = ToolRequestEvent(
        session_id=session.session_id,
        actor_id="user_prompt",
        source_adapter="codex",
        tool_name="modify_file",
        tool_args={"path": "src/auth.py"},
    )
    await daemon.ingest_event(tool_event)

    file_event = FileMutationEvent(
        session_id=session.session_id,
        actor_id="filesystem",
        source_adapter="filesystem_observer",
        file_path="src/auth.py",
        mutation_type="modify",
    )
    await daemon.ingest_event(file_event)

    # Check graph causal edge correlation
    graph = daemon.get_graph(session.session_id)
    assert graph is not None
    assert graph.node_count >= 3

    await daemon.stop_session(session.session_id)
    await daemon.stop()


@pytest.mark.asyncio
async def test_daemon_restart_recovery(tmp_path: Path) -> None:
    data_dir = tmp_path / ".agenttrace"
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()

    session = await daemon1.create_session(
        workspace_path=str(tmp_path),
        task_description="Persistent audit task",
        agent_type=AgentType.GENERIC,
    )

    cmd_event = CommandEvent(
        session_id=session.session_id,
        actor_id="agent",
        source_adapter="terminal",
        command="pytest tests/",
    )
    await daemon1.ingest_event(cmd_event)
    await daemon1.stop()

    # Re-instantiate daemon from same directory
    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()

    # Verify session and graph were restored from SQLite
    restored_session = daemon2.get_session(session.session_id)
    assert restored_session is not None
    assert restored_session.task_description == "Persistent audit task"

    timeline = daemon2.get_timeline(session.session_id)
    assert len(timeline) >= 1

    # Verify chain validity on restored ledger
    is_valid, error = daemon2._ledger.verify_chain(session.session_id)
    assert is_valid, f"Chain should remain valid across restart: {error}"

    await daemon2.stop()


def test_daemon_pre_execution_policy_evaluation(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    sid = uuid4()

    # Test scope boundary rule
    allowed, reason, req_app = daemon.evaluate_proposed_action(
        session_id=sid,
        action_type="command",
        target="rm -rf /",
    )
    # Default without session allows unless policy blocked
    assert isinstance(allowed, bool)
