"""AgentTrace daemon — main process orchestrating all components.

Manages audit sessions: supervised observers, adapter polling tasks,
the cryptographic event pipeline (redact → hash-chain → store → graph → policy),
persistence/restoration across restarts, and mediated pre-execution gates.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agenttrace.adapters.codex import CodexAdapter
from agenttrace.adapters.generic import GenericAdapter
from agenttrace.adapters.sdk import AdapterBase
from agenttrace.graph.baseline import BaselineGenerator
from agenttrace.graph.context_graph import ContextGraph
from agenttrace.graph.task_boundary import TaskBoundaryEngine
from agenttrace.models.events import (
    ApprovalEvent,
    CommandEvent,
    ConfidenceLevel,
    ContextBoundaryEvent,
    EventBase,
    EventType,
    FileMutationEvent,
    GitEvent,
    InvocationEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ProcessEvent,
    TestResultEvent,
    ToolRequestEvent,
    ToolResultEvent,
)
from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType
from agenttrace.models.session import (
    AgentType,
    AuditSession,
    SessionConfig,
    SessionStatus,
)
from agenttrace.models.task_contract import RiskLevel, TaskContract
from agenttrace.observers.base import BaseObserver
from agenttrace.observers.filesystem import FilesystemObserver
from agenttrace.observers.git_monitor import GitMonitor
from agenttrace.observers.network import NetworkObserver
from agenttrace.observers.process_tree import ProcessTreeObserver
from agenttrace.observers.terminal import TerminalObserver
from agenttrace.security.approval import ApprovalManager
from agenttrace.security.encryption import EncryptionManager
from agenttrace.security.policy import PolicyAction, PolicyEngine, PolicyEvaluation
from agenttrace.security.redaction import SecretRedactor
from agenttrace.storage.blob_store import BlobStore
from agenttrace.storage.ledger import EventLedger

logger = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = Path.home() / ".agenttrace"


class DaemonError(Exception):
    """Raised when daemon operations fail."""


class AgentTraceDaemon:
    """Main daemon process for AgentTrace.

    Manages the lifecycle of audit sessions and coordinates:
    - Observers (filesystem, process, git, terminal, network)
    - Active adapter polling (Codex CLI, generic)
    - Cryptographic event pipeline (redact → encrypt → hash → store → graph → policy)
    - Context Graph causal edge correlation & persistence
    - Pre-execution policy enforcement & task boundary checking
    """

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else _DEFAULT_DATA_DIR
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._encryptor = EncryptionManager(self._data_dir / "keys")
        self._redactor = SecretRedactor()
        self._ledger = EventLedger(
            self._data_dir / "ledger.db",
            encryption_mgr=self._encryptor,
            redactor=self._redactor,
        )
        self._blob_store = BlobStore(self._data_dir / "blobs")

        # Operational state
        self._sessions: dict[UUID, AuditSession] = {}
        self._graphs: dict[UUID, ContextGraph] = {}
        self._observers: dict[UUID, list[BaseObserver]] = {}
        self._adapters: dict[UUID, AdapterBase] = {}
        self._adapter_tasks: dict[UUID, asyncio.Task[None]] = {}
        self._policies: dict[UUID, PolicyEngine] = {}
        self._approvals: dict[UUID, ApprovalManager] = {}
        self._contracts: dict[UUID, TaskContract] = {}
        self._boundaries: dict[UUID, TaskBoundaryEngine] = {}
        self._network_observers: dict[UUID, NetworkObserver] = {}

        self._running = False

    async def start(self) -> None:
        """Start the daemon and restore historical sessions from storage."""
        self._running = True
        self._restore_from_storage()
        logger.info("AgentTrace daemon started, data_dir=%s", self._data_dir)

    async def stop(self) -> None:
        """Stop the daemon, cancel tasks, and clean up active sessions."""
        self._running = False

        # Cancel adapter polling tasks
        for task in self._adapter_tasks.values():
            task.cancel()
        self._adapter_tasks.clear()

        for session_id in list(self._sessions.keys()):
            await self.stop_session(session_id)

        self._ledger.close()
        logger.info("AgentTrace daemon stopped")

    def _restore_from_storage(self) -> None:
        """Restore sessions, graphs, contracts, and approvals from the SQLite ledger."""
        try:
            stored_sessions = self._ledger.list_sessions()
            for s_dict in stored_sessions:
                try:
                    sid = UUID(s_dict["session_id"])
                    config_dict = s_dict.get("config", {})
                    config = SessionConfig.model_validate(config_dict)
                    session = AuditSession(
                        session_id=sid,
                        config=config,
                        task_description=s_dict.get("task_desc", ""),
                        status=SessionStatus(s_dict.get("status", "stopped")),
                        started_at=datetime.fromisoformat(s_dict["started_at"]),
                        event_count=s_dict.get("event_count", 0),
                        last_event_hash=s_dict.get("last_event_hash", ""),
                    )
                    self._sessions[sid] = session

                    # Restore task contract
                    contract_dict = self._ledger.get_task_contract(sid)
                    if contract_dict:
                        contract = TaskContract(
                            contract_id=UUID(contract_dict["contract_id"]),
                            session_id=sid,
                            goal=contract_dict.get("goal", ""),
                            allowed_paths=contract_dict.get("allowed_paths", []),
                            prohibited_paths=contract_dict.get("prohibited_paths", []),
                            expected_tests=contract_dict.get("expected_tests", []),
                            allowed_tools=contract_dict.get("allowed_tools", []),
                            risk_level=RiskLevel(contract_dict.get("risk_level", "medium")),
                        )
                        self._contracts[sid] = contract
                        self._boundaries[sid] = TaskBoundaryEngine(contract)
                        self._policies[sid] = PolicyEngine(sid, contract)

                    # Restore approval manager
                    self._approvals[sid] = ApprovalManager(sid, self._ledger)

                    # Reconstruct ContextGraph from persisted nodes and edges
                    graph = ContextGraph(sid)
                    nodes_data = self._ledger.get_graph_nodes(sid)
                    for n in nodes_data:
                        try:
                            node = GraphNode(
                                node_id=UUID(n["node_id"]),
                                session_id=sid,
                                node_type=NodeType(n["node_type"]),
                                label=n.get("label", ""),
                                timestamp=datetime.fromisoformat(n["timestamp"]),
                                actor_id=n.get("actor_id", ""),
                                source_adapter=n.get("source_adapter", ""),
                                confidence=ConfidenceLevel(n.get("confidence", "high")),
                                content_hash=n.get("content_hash", ""),
                                data=n.get("data", {}),
                            )
                            graph.add_node(node)
                        except Exception:
                            continue

                    edges_data = self._ledger.get_graph_edges(sid)
                    for e in edges_data:
                        try:
                            edge = GraphEdge(
                                edge_id=UUID(e["edge_id"]),
                                source_node_id=UUID(e["source_node_id"]),
                                target_node_id=UUID(e["target_node_id"]),
                                edge_type=EdgeType(e["edge_type"]),
                                timestamp=datetime.fromisoformat(e["timestamp"]),
                                actor_id=e.get("actor_id", ""),
                                source_adapter=e.get("source_adapter", ""),
                                confidence=ConfidenceLevel(e.get("confidence", "high")),
                                data=e.get("data", {}),
                            )
                            graph.add_edge(edge)
                        except Exception:
                            continue

                    self._graphs[sid] = graph
                except Exception as e:
                    logger.warning("Could not restore session record: %s", e)
        except Exception as e:
            logger.warning("Error during daemon storage recovery: %s", e)

    # -- Session management --

    async def create_session(
        self,
        workspace_path: str,
        task_description: str = "",
        agent_type: AgentType = AgentType.AUTO,
        allowed_paths: list[str] | None = None,
        prohibited_paths: list[str] | None = None,
        expected_tests: list[str] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AuditSession:
        """Create and start a new audit session."""
        config = SessionConfig(
            workspace_path=str(Path(workspace_path).resolve()),
            agent_type=agent_type,
        )

        session = AuditSession(
            config=config,
            task_description=task_description,
            status=SessionStatus.ACTIVE,
        )

        # 1. Store session in ledger
        self._ledger.create_session(
            session_id=session.session_id,
            config_json=config.model_dump_json(),
            task_desc=task_description,
            started_at=session.started_at.isoformat(),
        )

        # 2. Task Contract & Boundary Engine
        contract = TaskContract(
            session_id=session.session_id,
            goal=task_description,
            allowed_paths=allowed_paths or ["*"],
            prohibited_paths=prohibited_paths or [".env*", "*.pem", "*.key"],
            expected_tests=expected_tests or [],
            allowed_tools=allowed_tools or [],
        )
        self._contracts[session.session_id] = contract
        self._boundaries[session.session_id] = TaskBoundaryEngine(contract)
        self._ledger.store_task_contract(
            contract_id=contract.contract_id,
            session_id=session.session_id,
            goal=contract.goal,
            allowed_paths=contract.allowed_paths,
            prohibited_paths=contract.prohibited_paths,
            expected_tests=contract.expected_tests,
            allowed_tools=contract.allowed_tools,
            risk_level=contract.risk_level.value,
            created_at=contract.created_at.isoformat(),
            updated_at=contract.updated_at.isoformat(),
            notes=contract.notes,
        )

        # 3. Policy Engine & Approvals
        policy = PolicyEngine(session.session_id, contract)
        self._policies[session.session_id] = policy
        approvals = ApprovalManager(session.session_id, self._ledger)
        self._approvals[session.session_id] = approvals

        # 4. Generate Baseline Graph & Persist Nodes
        baseline_gen = BaselineGenerator(session.session_id, config.workspace_path)
        graph = baseline_gen.generate()
        self._graphs[session.session_id] = graph

        # Persist baseline nodes
        for node in graph.to_snapshot().nodes:
            self._ledger.store_graph_node(
                node_id=node.node_id,
                session_id=session.session_id,
                node_type=node.node_type.value,
                label=node.label,
                timestamp=node.timestamp.isoformat(),
                actor_id=node.actor_id,
                source_adapter=node.source_adapter,
                confidence=node.confidence.value,
                content_hash=node.content_hash,
                data=node.data,
            )

        # 5. Create Root Task Intent Node in Graph
        task_node = GraphNode(
            node_type=NodeType.TASK_INTENT,
            label=f"Task: {task_description or 'Workspace Audit'}",
            actor_id="user",
            source_adapter="user_cli",
            confidence=ConfidenceLevel.HIGH,
            session_id=session.session_id,
            data={"goal": task_description},
        )
        graph.add_node(task_node)
        self._ledger.store_graph_node(
            node_id=task_node.node_id,
            session_id=session.session_id,
            node_type=task_node.node_type.value,
            label=task_node.label,
            timestamp=task_node.timestamp.isoformat(),
            actor_id=task_node.actor_id,
            source_adapter=task_node.source_adapter,
            confidence=task_node.confidence.value,
            data=task_node.data,
        )

        # 6. Start Observers
        observers = await self._start_observers(session)
        self._observers[session.session_id] = observers

        # 7. Select, Start, and Supervise Adapter Polling
        adapter = self._select_adapter(session)
        self._adapters[session.session_id] = adapter
        await adapter.start()

        # Start supervised adapter polling task
        poll_task = asyncio.create_task(self._adapter_poll_loop(session.session_id, adapter))
        self._adapter_tasks[session.session_id] = poll_task

        self._sessions[session.session_id] = session
        logger.info("Session %s active for %s (adapter=%s)", session.session_id, config.workspace_path, adapter.adapter_name)
        return session

    async def _adapter_poll_loop(self, session_id: UUID, adapter: AdapterBase) -> None:
        """Supervised polling loop for active agent adapters."""
        logger.info("Supervised adapter polling started for session: %s", session_id)
        while self._running and session_id in self._sessions:
            try:
                events = await adapter.poll()
                for event in events:
                    if adapter.validate_event(event):
                        await self.ingest_event(event)
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Adapter polling error in session %s: %s", session_id, e)
                await asyncio.sleep(3.0)

    async def stop_session(self, session_id: UUID) -> None:
        """Stop an active session."""
        session = self._sessions.get(session_id)
        if not session:
            return

        # Cancel adapter polling
        poll_task = self._adapter_tasks.pop(session_id, None)
        if poll_task:
            poll_task.cancel()

        for observer in self._observers.get(session_id, []):
            await observer.stop()
        self._observers.pop(session_id, None)

        adapter = self._adapters.pop(session_id, None)
        if adapter:
            await adapter.stop()

        session.status = SessionStatus.STOPPED
        session.stopped_at = datetime.now(timezone.utc)
        self._ledger.update_session_status(
            session_id,
            SessionStatus.STOPPED,
            stopped_at=session.stopped_at.isoformat(),
        )
        logger.info("Session %s stopped", session_id)

    def get_session(self, session_id: UUID) -> AuditSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[AuditSession]:
        return list(self._sessions.values())

    # -- Event ingestion & Causal Graph pipeline --

    async def ingest_event(self, event: EventBase, raw_payload: bytes | None = None) -> str:
        """Process event: Redact → Encrypt → Hash-Chain → Store → Graph Projection → Policy."""
        # 1. Store Large Blobs
        if raw_payload:
            blob_hash = self._blob_store.store_blob(raw_payload)
            self._ledger.store_blob_index(
                blob_hash=blob_hash,
                session_id=event.session_id,
                file_path=str(self._data_dir / "blobs" / blob_hash[:2] / blob_hash[2:]),
                size_bytes=len(raw_payload),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            event.evidence_refs.append(f"blob:{blob_hash}")

        # 2. Append to cryptographic event ledger
        event_hash = self._ledger.append_event(event)

        # 3. Context Graph Causal Projection & DB Storage
        graph = self._graphs.get(event.session_id)
        if graph:
            self._update_graph(graph, event)

        # 4. Scope Drift & Task Boundary Check
        boundary = self._boundaries.get(event.session_id)
        if boundary:
            if isinstance(event, FileMutationEvent):
                drift = boundary.check_file_mutation(event.file_path, event.mutation_type)
                if drift:
                    finding = PolicyFindingEvent(
                        session_id=event.session_id,
                        actor_id="task_boundary_engine",
                        source_adapter="task_boundary_engine",
                        confidence=ConfidenceLevel.HIGH,
                        finding_type=drift.drift_type.value,
                        severity=drift.severity,
                        description=drift.description,
                        affected_path=drift.affected_path,
                        requires_approval=drift.requires_approval,
                    )
                    await self.ingest_event(finding)

            elif isinstance(event, CommandEvent):
                drifts = boundary.check_command(event.command)
                for drift in drifts:
                    finding = PolicyFindingEvent(
                        session_id=event.session_id,
                        actor_id="task_boundary_engine",
                        source_adapter="task_boundary_engine",
                        confidence=ConfidenceLevel.HIGH,
                        finding_type=drift.drift_type.value,
                        severity=drift.severity,
                        description=drift.description,
                        affected_command=drift.affected_command,
                        requires_approval=drift.requires_approval,
                    )
                    await self.ingest_event(finding)

        # 5. Security Policy Evaluation
        policy = self._policies.get(event.session_id)
        if policy and not isinstance(event, PolicyFindingEvent):
            evaluation = policy.evaluate(event)
            for finding in evaluation.findings:
                await self.ingest_event(finding)

        # 6. Update Session In-Memory Status
        session = self._sessions.get(event.session_id)
        if session:
            session.event_count += 1
            session.last_event_hash = event_hash

        return event_hash

    def _update_graph(self, graph: ContextGraph, event: EventBase) -> None:
        """Update Context Graph with rich, multi-hop causal correlation rules."""
        node_type_map: dict[EventType, NodeType] = {
            EventType.FILE_MUTATION: NodeType.FILESYSTEM_MUTATION,
            EventType.PROCESS: NodeType.PROCESS,
            EventType.COMMAND: NodeType.COMMAND,
            EventType.NETWORK: NodeType.NETWORK_REQUEST,
            EventType.GIT: NodeType.GIT_COMMIT_DIFF,
            EventType.TEST_RESULT: NodeType.TEST_RESULT,
            EventType.BUILD_RESULT: NodeType.BUILD_RESULT,
            EventType.TOOL_REQUEST: NodeType.TOOL_REQUEST,
            EventType.TOOL_RESULT: NodeType.TOOL_RESULT,
            EventType.APPROVAL: NodeType.APPROVAL,
            EventType.POLICY_FINDING: NodeType.POLICY_FINDING,
            EventType.INCIDENT: NodeType.INCIDENT,
            EventType.INVOCATION: NodeType.AGENT_SESSION,
            EventType.CONTEXT_BOUNDARY: NodeType.CONTEXTUAL_DOCUMENT,
        }

        node_type = node_type_map.get(event.event_type)
        if not node_type:
            return

        label = self._make_node_label(event)
        node = GraphNode(
            node_type=node_type,
            label=label,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            source_adapter=event.source_adapter,
            confidence=event.confidence,
            session_id=event.session_id,
            data=event.canonical_dict(),
        )
        graph.add_node(node)

        # Persist node to SQLite
        self._ledger.store_graph_node(
            node_id=node.node_id,
            session_id=event.session_id,
            node_type=node.node_type.value,
            label=node.label,
            timestamp=node.timestamp.isoformat(),
            actor_id=node.actor_id,
            source_adapter=node.source_adapter,
            confidence=node.confidence.value,
            data=node.data,
        )

        # Multi-Hop Causal Edge Inference
        new_edges: list[GraphEdge] = []

        # 1. Invocations connect to root task_intent
        if isinstance(event, InvocationEvent):
            for t_node in graph.get_nodes_by_type(NodeType.TASK_INTENT):
                new_edges.append(GraphEdge(
                    source_node_id=t_node.node_id,
                    target_node_id=node.node_id,
                    edge_type=EdgeType.PROVIDES_CONTEXT_TO,
                    actor_id=event.actor_id,
                    source_adapter=event.source_adapter,
                    confidence=ConfidenceLevel.HIGH,
                ))

        # 2. Tool requests connect to agent sessions
        elif isinstance(event, ToolRequestEvent):
            for s_node in graph.get_nodes_by_type(NodeType.AGENT_SESSION):
                if s_node.actor_id == event.actor_id:
                    new_edges.append(GraphEdge(
                        source_node_id=s_node.node_id,
                        target_node_id=node.node_id,
                        edge_type=EdgeType.REQUESTS,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))

        # 3. Tool results connect to tool requests
        elif isinstance(event, ToolResultEvent):
            for req_node in graph.get_nodes_by_type(NodeType.TOOL_REQUEST):
                if req_node.data.get("tool_name") == event.tool_name:
                    new_edges.append(GraphEdge(
                        source_node_id=req_node.node_id,
                        target_node_id=node.node_id,
                        edge_type=EdgeType.EXECUTES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))
                    break

        # 4. Commands connect to agent session / tool request
        elif isinstance(event, CommandEvent):
            for req_node in graph.get_nodes_by_type(NodeType.TOOL_REQUEST):
                if event.command in str(req_node.data):
                    new_edges.append(GraphEdge(
                        source_node_id=req_node.node_id,
                        target_node_id=node.node_id,
                        edge_type=EdgeType.EXECUTES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))

        # 5. File mutations connect to commands / processes & baseline source files
        elif isinstance(event, FileMutationEvent):
            # Connect to executing command/process
            for cmd_node in graph.get_nodes_by_type(NodeType.COMMAND):
                new_edges.append(GraphEdge(
                    source_node_id=cmd_node.node_id,
                    target_node_id=node.node_id,
                    edge_type=EdgeType.MODIFIES,
                    actor_id=event.actor_id,
                    source_adapter=event.source_adapter,
                    confidence=ConfidenceLevel.MEDIUM,
                ))
                break

            # Connect to baseline source file
            for file_node in graph.get_nodes_by_type(NodeType.SOURCE_FILE):
                if file_node.data.get("path") == event.file_path:
                    new_edges.append(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=file_node.node_id,
                        edge_type=EdgeType.MODIFIES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))
                    break

        # 6. Network connections connect to spawning process
        elif isinstance(event, NetworkEvent):
            if event.process_pid:
                for p_node in graph.get_nodes_by_type(NodeType.PROCESS):
                    if p_node.data.get("pid") == event.process_pid:
                        new_edges.append(GraphEdge(
                            source_node_id=p_node.node_id,
                            target_node_id=node.node_id,
                            edge_type=EdgeType.SPAWNS,
                            actor_id=event.actor_id,
                            source_adapter=event.source_adapter,
                            confidence=ConfidenceLevel.HIGH,
                        ))
                        break

        # 7. Policy findings connect to triggering nodes
        elif isinstance(event, PolicyFindingEvent):
            for candidate in reversed(list(graph._nodes.values())):
                if candidate.node_id != node.node_id:
                    new_edges.append(GraphEdge(
                        source_node_id=candidate.node_id,
                        target_node_id=node.node_id,
                        edge_type=EdgeType.VIOLATES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))
                    break

        # 8. Approvals connect to findings
        elif isinstance(event, ApprovalEvent):
            for f_node in graph.get_nodes_by_type(NodeType.POLICY_FINDING):
                if f_node.data.get("event_id") == event.finding_id or f_node.data.get("finding_type") == event.finding_id:
                    new_edges.append(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=f_node.node_id,
                        edge_type=EdgeType.APPROVED_BY,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))

        # Add and persist all edges
        for edge in new_edges:
            graph.add_edge(edge)
            self._ledger.store_graph_edge(
                edge_id=edge.edge_id,
                session_id=event.session_id,
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                edge_type=edge.edge_type.value,
                timestamp=edge.timestamp.isoformat(),
                actor_id=edge.actor_id,
                source_adapter=edge.source_adapter,
                confidence=edge.confidence.value,
                data=edge.data,
            )

    @staticmethod
    def _make_node_label(event: EventBase) -> str:
        if isinstance(event, FileMutationEvent):
            return f"{event.mutation_type}: {Path(event.file_path).name}"
        elif isinstance(event, CommandEvent):
            return f"cmd: {event.command[:60]}"
        elif isinstance(event, ToolRequestEvent):
            return f"tool: {event.tool_name}"
        elif isinstance(event, NetworkEvent):
            return f"net: {event.destination_ip}:{event.destination_port}"
        elif isinstance(event, PolicyFindingEvent):
            return f"finding: {event.finding_type} ({event.severity})"
        return event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)

    # -- Pre-Execution Mediated Policy Gate (P0-6) --

    def evaluate_proposed_action(
        self,
        session_id: UUID,
        action_type: str,
        target: str,
        details: dict[str, Any] | None = None,
    ) -> tuple[bool, str, str]:
        """Pre-execution policy evaluation for mediated actions.

        Returns (allowed, reason, required_approval_id).
        """
        contract = self._contracts.get(session_id)
        boundary = self._boundaries.get(session_id)
        approvals = self._approvals.get(session_id)

        # 1. Scope boundary check
        if boundary:
            if action_type == "file_mutation":
                drift = boundary.check_file_mutation(target, details.get("mutation_type", "modify") if details else "modify")
                if drift:
                    # Check active approval
                    if approvals and approvals.is_approved(drift.drift_type.value, path=target):
                        return True, "Pre-approved by active approval record", ""
                    return False, f"Blocked: {drift.description}", drift.drift_type.value

            elif action_type == "command":
                drifts = boundary.check_command(target)
                if drifts:
                    for drift in drifts:
                        if approvals and approvals.is_approved(drift.drift_type.value, command=target):
                            continue
                        return False, f"Blocked: {drift.description}", drift.drift_type.value

        return True, "Allowed by policy", ""

    # -- Observers & Adapter Selection --

    async def _start_observers(self, session: AuditSession) -> list[BaseObserver]:
        callback = lambda event, payload=None: self.ingest_event(event, payload)
        workspace = session.config.workspace_path

        net_observer = NetworkObserver(session.session_id, workspace, callback)
        self._network_observers[session.session_id] = net_observer

        proc_observer = ProcessTreeObserver(
            session.session_id,
            workspace,
            callback,
            on_pids_updated=lambda pids: net_observer.update_tracked_pids(pids),
        )

        observers: list[BaseObserver] = [
            FilesystemObserver(session.session_id, workspace, callback, session.config.ignore_patterns),
            proc_observer,
            GitMonitor(session.session_id, workspace, callback),
            TerminalObserver(session.session_id, workspace, callback),
            net_observer,
        ]

        for observer in observers:
            await observer.start()

        return observers

    def _select_adapter(self, session: AuditSession) -> AdapterBase:
        agent_type = session.config.agent_type
        workspace = session.config.workspace_path

        if agent_type == AgentType.CODEX:
            return CodexAdapter(session.session_id, workspace)
        elif agent_type == AgentType.AUTO:
            codex = CodexAdapter(session.session_id, workspace)
            if codex._log_dir:
                return codex
            return GenericAdapter(session.session_id, workspace)
        return GenericAdapter(session.session_id, workspace)

    # -- Queries --

    def get_graph(self, session_id: UUID) -> ContextGraph | None:
        return self._graphs.get(session_id)

    def get_timeline(self, session_id: UUID) -> list[EventBase]:
        return self._ledger.query_events(session_id)

    def get_findings(self, session_id: UUID) -> list[EventBase]:
        return self._ledger.query_events(session_id, event_type=EventType.POLICY_FINDING)

    def get_contract(self, session_id: UUID) -> TaskContract | None:
        return self._contracts.get(session_id)

    def get_approval_manager(self, session_id: UUID) -> ApprovalManager | None:
        return self._approvals.get(session_id)
