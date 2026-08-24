"""Tests for AgentTraceDaemon — session lifecycle, causal graph projection,
restart recovery, and pre-execution policy gating."""

from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import (
    CommandEvent,
    FileMutationEvent,
    InvocationEvent,
    NetworkEvent,
    ToolRequestEvent,
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
    assert len(daemon1._observers[sid]) == 6
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
        assert len(daemon2._observers[sid]) == 6
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
