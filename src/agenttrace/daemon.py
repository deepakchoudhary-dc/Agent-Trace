"""AgentTrace daemon — main process orchestrating all components.

The daemon manages audit sessions: starting/stopping observers,
ingesting events through the pipeline (redact → hash-chain → store →
graph update → policy check), and serving the local API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.adapters.codex import CodexAdapter
from agenttrace.adapters.generic import GenericAdapter
from agenttrace.adapters.sdk import AdapterBase
from agenttrace.graph.baseline import BaselineGenerator
from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    EventType,
    FileMutationEvent,
)
from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType
from agenttrace.models.session import (
    AgentType,
    AuditSession,
    SessionConfig,
    SessionStatus,
)
from agenttrace.models.task_contract import TaskContract
from agenttrace.observers.base import BaseObserver
from agenttrace.observers.filesystem import FilesystemObserver
from agenttrace.observers.git_monitor import GitMonitor
from agenttrace.observers.network import NetworkObserver
from agenttrace.observers.process_tree import ProcessTreeObserver
from agenttrace.observers.terminal import TerminalObserver
from agenttrace.security.approval import ApprovalManager
from agenttrace.security.encryption import EncryptionManager
from agenttrace.security.policy import PolicyEngine
from agenttrace.security.redaction import SecretRedactor
from agenttrace.storage.blob_store import BlobStore
from agenttrace.storage.ledger import EventLedger

logger = logging.getLogger(__name__)

# Default data directory
_DEFAULT_DATA_DIR = Path.home() / ".agenttrace"


class DaemonError(Exception):
    """Raised when daemon operations fail."""


class AgentTraceDaemon:
    """Main daemon process for AgentTrace.

    Manages the lifecycle of audit sessions and coordinates:
    - Observers (filesystem, process, git, terminal, network)
    - Adapters (Codex CLI, generic)
    - Event pipeline (redact → encrypt → hash → store → graph → policy)
    - Context Graph updates
    - Policy evaluation
    """

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else _DEFAULT_DATA_DIR
        self._data_dir.mkdir(parents=True, exist_ok=True)

        # Core components
        self._ledger = EventLedger(self._data_dir / "ledger.db")
        self._blob_store = BlobStore(self._data_dir / "blobs")
        self._redactor = SecretRedactor()
        self._encryptor = EncryptionManager(self._data_dir / "keys")

        # Active sessions
        self._sessions: dict[UUID, AuditSession] = {}
        self._graphs: dict[UUID, ContextGraph] = {}
        self._observers: dict[UUID, list[BaseObserver]] = {}
        self._adapters: dict[UUID, AdapterBase] = {}
        self._policies: dict[UUID, PolicyEngine] = {}
        self._approvals: dict[UUID, ApprovalManager] = {}
        self._contracts: dict[UUID, TaskContract] = {}

        self._running = False

    async def start(self) -> None:
        """Start the daemon."""
        self._running = True
        logger.info("AgentTrace daemon started, data_dir=%s", self._data_dir)

    async def stop(self) -> None:
        """Stop the daemon and all active sessions."""
        self._running = False

        for session_id in list(self._sessions.keys()):
            await self.stop_session(session_id)

        self._ledger.close()
        logger.info("AgentTrace daemon stopped")

    # -- Session management --

    async def create_session(
        self,
        workspace_path: str,
        task_description: str = "",
        agent_type: AgentType = AgentType.AUTO,
    ) -> AuditSession:
        """Create and start a new audit session."""
        config = SessionConfig(
            workspace_path=workspace_path,
            agent_type=agent_type,
        )

        session = AuditSession(
            config=config,
            task_description=task_description,
        )

        # Store session in ledger
        self._ledger.create_session(
            session_id=session.session_id,
            config_json=config.model_dump_json(),
            task_desc=task_description,
            started_at=session.started_at.isoformat(),
        )

        # Generate baseline graph
        baseline_gen = BaselineGenerator(session.session_id, workspace_path)
        graph = baseline_gen.generate()
        self._graphs[session.session_id] = graph

        # Create task contract
        contract = TaskContract(
            session_id=session.session_id,
            goal=task_description,
        )
        self._contracts[session.session_id] = contract

        # Initialize policy engine
        policy = PolicyEngine(session.session_id, contract)
        self._policies[session.session_id] = policy

        # Initialize approval manager
        approvals = ApprovalManager(session.session_id, self._ledger)
        self._approvals[session.session_id] = approvals

        # Start observers
        observers = await self._start_observers(session)
        self._observers[session.session_id] = observers

        # Select and start adapter
        adapter = self._select_adapter(session)
        self._adapters[session.session_id] = adapter
        await adapter.start()

        # Update session status
        session.status = SessionStatus.ACTIVE
        self._sessions[session.session_id] = session
        self._ledger.update_session_status(session.session_id, SessionStatus.ACTIVE)

        logger.info(
            "Session %s started for %s (adapter=%s)",
            session.session_id,
            workspace_path,
            adapter.adapter_name,
        )

        return session

    async def stop_session(self, session_id: UUID) -> None:
        """Stop an active session and clean up resources."""
        session = self._sessions.get(session_id)
        if not session:
            return

        # Stop observers
        for observer in self._observers.get(session_id, []):
            await observer.stop()
        self._observers.pop(session_id, None)

        # Stop adapter
        adapter = self._adapters.pop(session_id, None)
        if adapter:
            await adapter.stop()

        # Update session
        session.status = SessionStatus.STOPPED
        session.stopped_at = datetime.now(timezone.utc)
        self._ledger.update_session_status(session_id, SessionStatus.STOPPED)

        logger.info("Session %s stopped", session_id)

    def get_session(self, session_id: UUID) -> AuditSession | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[AuditSession]:
        """List all active sessions."""
        return list(self._sessions.values())

    # -- Event pipeline --

    async def ingest_event(
        self,
        event: EventBase,
        raw_payload: bytes | None = None,
    ) -> str:
        """Process an event through the ingestion pipeline.

        Pipeline: redact → encrypt → hash-chain → store → graph → policy
        """
        # Step 1: Redact secrets
        if event.payload:
            event.payload = self._redactor.redact_dict(event.payload)  # type: ignore[assignment]

        # Step 2: Encrypt payload
        encrypted_payload = None
        if event.payload:
            encrypted_payload = self._encryptor.encrypt_json(event.payload)  # type: ignore[arg-type]

        # Step 3: Store in ledger (hash-chain)
        event_hash = self._ledger.append_event(event, encrypted_payload)

        # Step 4: Store large payloads as blobs
        if raw_payload:
            redacted = self._redactor.redact(raw_payload.decode("utf-8", errors="replace"))
            encrypted_blob = self._encryptor.encrypt(redacted.encode("utf-8"))
            self._blob_store.store_blob(encrypted_blob)

        # Step 5: Update context graph
        graph = self._graphs.get(event.session_id)
        if graph:
            self._update_graph(graph, event)

        # Step 6: Policy evaluation
        policy = self._policies.get(event.session_id)
        if policy:
            evaluation = policy.evaluate(event)
            if evaluation.requires_approval:
                for finding in evaluation.findings:
                    await self.ingest_event(finding)
                    logger.warning(
                        "Policy triggered: %s — %s",
                        finding.finding_type,
                        finding.description,
                    )

        # Step 7: Update session counters
        session = self._sessions.get(event.session_id)
        if session:
            session.event_count += 1
            session.last_event_hash = event_hash

        return event_hash

    def _update_graph(self, graph: ContextGraph, event: EventBase) -> None:
        """Update the Context Graph with a new event."""
        # Map event to graph node
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
        }

        node_type = node_type_map.get(event.event_type)
        if not node_type:
            return

        # Create label based on event type
        label = self._make_node_label(event)

        node = GraphNode(
            node_type=node_type,
            label=label,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            source_adapter=event.source_adapter,
            confidence=event.confidence,
            session_id=event.session_id,
            data=event.payload,
        )
        graph.add_node(node)

        # Create causal edges based on event type
        if isinstance(event, FileMutationEvent):
            # Connect to source file if exists
            for file_node in graph.get_nodes_by_type(NodeType.SOURCE_FILE):
                if file_node.data.get("path") == event.file_path:
                    graph.add_edge(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=file_node.node_id,
                        edge_type=EdgeType.MODIFIES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=event.confidence,
                    ))
                    break

    @staticmethod
    def _make_node_label(event: EventBase) -> str:
        """Create a human-readable label for a graph node."""
        if isinstance(event, FileMutationEvent):
            return f"{event.mutation_type}: {Path(event.file_path).name}"
        elif hasattr(event, "command") and event.command:  # type: ignore[union-attr]
            cmd = event.command  # type: ignore[union-attr]
            return f"cmd: {cmd[:50]}"
        elif hasattr(event, "tool_name") and event.tool_name:  # type: ignore[union-attr]
            return f"tool: {event.tool_name}"  # type: ignore[union-attr]
        return event.event_type

    # -- Observer management --

    async def _start_observers(self, session: AuditSession) -> list[BaseObserver]:
        """Start all observers for a session."""
        callback = lambda event, payload: self.ingest_event(event, payload)
        workspace = session.config.workspace_path

        observers: list[BaseObserver] = [
            FilesystemObserver(
                session.session_id,
                workspace,
                callback,
                session.config.ignore_patterns,
            ),
            ProcessTreeObserver(session.session_id, workspace, callback),
            GitMonitor(session.session_id, workspace, callback),
            TerminalObserver(session.session_id, workspace, callback),
            NetworkObserver(session.session_id, workspace, callback),
        ]

        for observer in observers:
            await observer.start()

        return observers

    def _select_adapter(self, session: AuditSession) -> AdapterBase:
        """Select the appropriate adapter based on config."""
        agent_type = session.config.agent_type
        workspace = session.config.workspace_path

        if agent_type == AgentType.CODEX:
            return CodexAdapter(session.session_id, workspace)
        elif agent_type == AgentType.AUTO:
            # Try Codex first, fall back to generic
            codex = CodexAdapter(session.session_id, workspace)
            if codex._log_dir:
                return codex
            return GenericAdapter(session.session_id, workspace)
        else:
            return GenericAdapter(session.session_id, workspace)

    # -- Query methods (used by API) --

    def get_graph(self, session_id: UUID) -> ContextGraph | None:
        """Get the Context Graph for a session."""
        return self._graphs.get(session_id)

    def get_timeline(self, session_id: UUID) -> list[dict[str, Any]]:
        """Get event timeline for a session."""
        events = self._ledger.query_events(session_id)
        return events

    def get_findings(self, session_id: UUID) -> list[dict[str, Any]]:
        """Get policy findings for a session."""
        return self._ledger.query_events(
            session_id,
            event_type=EventType.POLICY_FINDING,
        )

    def get_contract(self, session_id: UUID) -> TaskContract | None:
        """Get the task contract for a session."""
        return self._contracts.get(session_id)

    def get_approval_manager(self, session_id: UUID) -> ApprovalManager | None:
        """Get the approval manager for a session."""
        return self._approvals.get(session_id)
