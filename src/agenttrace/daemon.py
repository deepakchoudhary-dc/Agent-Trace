"""AgentTrace daemon — main process orchestrating all components.

Manages audit sessions: supervised observers, adapter polling tasks,
the cryptographic event pipeline (redact → hash-chain → store → graph → policy),
persistence/restoration across restarts, and mediated pre-execution gates.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from agenttrace.adapters.claude import ClaudeAdapter
from agenttrace.adapters.codex import CodexAdapter
from agenttrace.adapters.composite import CompositeAdapter
from agenttrace.adapters.copilot import CopilotAdapter
from agenttrace.adapters.universal import UniversalAgentAdapter
from agenttrace.graph.baseline import BaselineGenerator
from agenttrace.graph.collusion import CollusionCandidate, CollusionCorrelationEngine
from agenttrace.graph.context_graph import ContextGraph
from agenttrace.graph.covert_channel import CovertChannelDetector
from agenttrace.graph.evidence_boundary import ToolClaimReconciler
from agenttrace.graph.incidents import IncidentCorrelationEngine
from agenttrace.graph.post_exit import PostExitRegistry
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
    IncidentEvent,
    InvocationEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ProcessEvent,
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
from agenttrace.models.task_contract import RiskLevel, ScopeDriftResult, TaskContract
from agenttrace.observers.filesystem import FilesystemObserver
from agenttrace.observers.git_monitor import GitMonitor
from agenttrace.observers.job_object_process import WindowsJobObject
from agenttrace.observers.kernel import KernelObserver
from agenttrace.observers.network import NetworkObserver
from agenttrace.observers.process_tree import ProcessTreeObserver
from agenttrace.observers.terminal import TerminalObserver
from agenttrace.security.approval import ApprovalManager
from agenttrace.security.detectors import DetectionEngine, DetectorFinding
from agenttrace.security.encryption import EncryptionManager
from agenttrace.security.policy import PolicyEngine
from agenttrace.security.redaction import SecretRedactor
from agenttrace.storage.blob_store import BlobStore
from agenttrace.storage.ledger import EventLedger

if TYPE_CHECKING:
    from agenttrace.adapters.sdk import AdapterBase
    from agenttrace.observers.base import BaseObserver

logger = logging.getLogger(__name__)


_DEFAULT_DATA_DIR = Path.home() / ".agenttrace"

# Anti-forensic flood guard window/threshold (events per window)
_FLOOD_WINDOW_SECONDS = 5.0
_FLOOD_EVENT_THRESHOLD = 500

# Clock-jump tolerance and finding cooldown (seconds)
_CLOCK_JUMP_TOLERANCE_SECONDS = 300.0

# Gate hits that approval SCOPE can never satisfy. Secret access always
# pauses and needs its own finding-specific decision: a broad (possibly
# orphaned) path/command scope must not silently clear credential gates.
_SCOPE_IMMUNE_HITS = frozenset({
    "credential_access",
    "credential_read",
    "credential_read_heuristic",
    "credential_access_drift",
})


def _over_broad_scope_entries(paths: list[str]) -> list[str]:
    """Return allowed-path entries that effectively disable scope gating."""
    home = Path.home()
    over_broad: list[str] = []
    for p in paths:
        raw = (p or "").strip()
        if not raw or raw in {"*", "**", "/", "~"}:
            over_broad.append(raw or "(empty)")
            continue
        try:
            resolved = Path(raw).expanduser().resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        # Filesystem root ("/", "C:\") or the user's home directory itself.
        # A root path's parent is itself - the portable root check.
        if resolved.parent == resolved or len(resolved.parts) <= 1 or resolved == home:
            over_broad.append(raw)
    return over_broad
_CLOCK_FINDING_COOLDOWN_SECONDS = 300.0

# Shell-capable tool names whose tool requests may legitimately explain a
# CommandEvent (used for explicit command↔tool-request correlation).
_SHELL_TOOL_NAMES = frozenset({
    "bash",
    "shell",
    "shell_command",
    "local_shell_call",
    "terminal",
    "cmd",
    "powershell",
    "windows_terminal",
    "run_shell_command",
})


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
        self._data_dir = Path(data_dir) if data_dir else Path(_DEFAULT_DATA_DIR)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._encryptor = EncryptionManager(self._data_dir / "keys")
        self._redactor = SecretRedactor()
        self._ledger = EventLedger(
            self._data_dir / "ledger.db",
            encryption_mgr=self._encryptor,
            redactor=self._redactor,
        )
        self._blob_store = BlobStore(self._data_dir / "blobs", encryption_mgr=self._encryptor)

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
        self._incidents: dict[UUID, IncidentCorrelationEngine] = {}
        self._covert: dict[UUID, CovertChannelDetector] = {}
        self._reconcilers: dict[UUID, ToolClaimReconciler] = {}
        # Post-exit surveillance is daemon-wide: shared-infrastructure and
        # post-close detection only work across sessions.
        self._post_exit: PostExitRegistry = PostExitRegistry()
        self._detectors: dict[UUID, DetectionEngine] = {}
        self._job_objects: dict[UUID, WindowsJobObject] = {}
        # Most-recent node index per (session, node_type, actor) for causal
        # correlation: links events to the *latest* cause, not the first match
        self._latest: dict[tuple[UUID, NodeType, str], UUID] = {}

        # Cross-session collusion correlation (R3) — pull-based engine over the
        # ledger, scanned on a throttle so ingest stays O(1) per event.
        self._collusion = CollusionCorrelationEngine(self._ledger)
        self._collusion_cache: dict[tuple[str, str, tuple[str, ...]], CollusionCandidate] = {}
        self._collusion_last_scan: dict[UUID, float] = {}

        # Anti-forensic flood guard: (start_monotonic, count, flagged)
        self._flood_state: dict[UUID, tuple[float, int, bool]] = {}
        # Clock-jump finding cooldown per session
        self._clock_findings: dict[UUID, float] = {}

        self._running = False

    async def start(self) -> None:
        """Start the daemon and restore historical sessions from storage."""
        if self._running:
            return
        self._running = True
        await self._restore_from_storage()
        logger.info("AgentTrace daemon started, data_dir=%s", self._data_dir)

    async def stop(self) -> None:
        """Stop the daemon, cancel tasks, and clean up active sessions."""
        if not self._running:
            return
        self._running = False

        # Cancel adapter polling tasks
        for task in self._adapter_tasks.values():
            task.cancel()
        self._adapter_tasks.clear()

        for session_id in list(self._sessions.keys()):
            await self.stop_session(session_id)

        self._ledger.close()
        logger.info("AgentTrace daemon stopped")

    async def _restore_from_storage(self) -> None:
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
                        self._policies[sid] = PolicyEngine(
                            sid,
                            contract,
                            internet_allowed=config.internet_access_allowed,
                            allowed_destinations=config.allowed_destinations,
                        )

                    # Restore approval manager and its active (non-expired) cache
                    approvals = ApprovalManager(sid, self._ledger)
                    approvals.reload_from_storage()
                    self._approvals[sid] = approvals

                    # Incident correlation engine (starts fresh; past incidents
                    # remain persisted in the ledger)
                    self._incidents[sid] = IncidentCorrelationEngine(
                        sid,
                        internet_allowed=config.internet_access_allowed,
                        allowed_destinations=config.allowed_destinations,
                    )
                    self._covert[sid] = CovertChannelDetector(sid)
                    self._reconcilers[sid] = ToolClaimReconciler(sid)

                    # Threat-detection rule engine
                    self._detectors[sid] = DetectionEngine(
                        sid,
                        workspace_paths=contract.allowed_paths,
                        internet_allowed=config.internet_access_allowed,
                    )

                    # Egress baseline: destinations established for this
                    # workspace are not re-flagged as new after restarts.
                    baseline = self._ledger.get_destination_baseline(
                        config.workspace_path
                    )
                    self._policies[sid].add_known_destinations(baseline)

                    # Reconstruct ContextGraph from persisted nodes and edges
                    graph = ContextGraph(sid)
                    nodes_data = self._ledger.get_graph_nodes(sid)
                    skipped_nodes = 0
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
                            skipped_nodes += 1
                            continue

                    edges_data = self._ledger.get_graph_edges(sid)
                    skipped_edges = 0
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
                            skipped_edges += 1
                            continue

                    self._graphs[sid] = graph

                    # R9/N14: a skipped row is a silent integrity loss — surface
                    # it as a ledger-backed finding instead of swallowing it.
                    if skipped_nodes or skipped_edges:
                        integrity_event = PolicyFindingEvent(
                            session_id=sid,
                            actor_id="daemon",
                            source_adapter="daemon_restore",
                            confidence=ConfidenceLevel.HIGH,
                            finding_type="restore_integrity",
                            severity="low",
                            description=(
                                f"{skipped_nodes} graph node(s) and {skipped_edges} "
                                "edge(s) could not be restored from the ledger "
                                "(corrupt or unknown row format). Graph history "
                                "is incomplete for this session."
                            ),
                        )
                        try:
                            self._ledger.append_event(integrity_event)
                        except Exception:
                            logger.warning(
                                "Could not record restore-integrity finding",
                                exc_info=True,
                            )

                    # R7: seed incident correlation with the persisted window so
                    # a restart does not forget pre-restart evidence (a finding
                    # seconds before shutdown must still pair with post-restart
                    # egress).
                    try:
                        self._incidents[sid].seed_events(
                            self._ledger.query_events(sid, limit=None)
                        )
                    except Exception:
                        logger.warning(
                            "Could not seed incident correlation state",
                            exc_info=True,
                        )

                    # Zombie sessions: a restored ACTIVE session has live
                    # state but nothing observing it. Resume observers and
                    # the adapter (with its persisted cursor) so `status`
                    # truthfully reflects a watched session.
                    if session.status == SessionStatus.ACTIVE:
                        await self._resume_session(session)
                except Exception as e:
                    logger.warning("Could not restore session record: %s", e)
        except Exception as e:
            logger.warning("Error during daemon storage recovery: %s", e)

    async def _resume_session(self, session: AuditSession) -> None:
        """Resume observers/adapters for a restored ACTIVE session."""
        sid = session.session_id
        try:
            observers = await self._start_observers(session)
            self._observers[sid] = observers

            adapter = self._select_adapter(session)
            cursor_state = self._ledger.get_adapter_cursor(sid)
            if cursor_state:
                adapter.restore_cursor(cursor_state.get("cursor", {}))
            self._adapters[sid] = adapter
            await adapter.start()

            poll_task = asyncio.create_task(
                self._adapter_poll_loop(sid, adapter)
            )
            self._adapter_tasks[sid] = poll_task
            logger.info(
                "Resumed observation for restored ACTIVE session %s (adapter=%s)",
                sid,
                adapter.adapter_name,
            )
        except Exception as e:
            logger.warning(
                "Could not resume observation for session %s: %s", sid, e
            )

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
        internet_access_allowed: bool | None = None,
        allowed_destinations: list[str] | None = None,
    ) -> AuditSession:
        """Create and start a new audit session."""
        config = SessionConfig(
            workspace_path=str(Path(workspace_path).resolve()),
            agent_type=agent_type,
            internet_access_allowed=internet_access_allowed,
            allowed_destinations=list(allowed_destinations or []),
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
        explicit_paths = allowed_paths is not None
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

        # Misconfigured-scope tripwire: an explicitly supplied allowed_paths
        # that covers the filesystem at large (root, drive, home, glob-all)
        # silently disables the write_outside_scope gate for everything.
        # Record it as a HIGH finding so the misconfiguration is visible in
        # findings, timeline, and reports instead of passing silently.
        if explicit_paths:
            over_broad = _over_broad_scope_entries(contract.allowed_paths)
            if over_broad:
                logger.warning(
                    "Session %s started with over-broad allowed scope: %s",
                    session.session_id,
                    over_broad,
                )
                with contextlib.suppress(Exception):
                    self._ledger.append_event(PolicyFindingEvent(
                        session_id=session.session_id,
                        actor_id="daemon",
                        source_adapter="task_boundary",
                        confidence=ConfidenceLevel.HIGH,
                        finding_type="over_broad_scope",
                        severity="high",
                        description=(
                            "Session scope allowlist is over-broad "
                            f"({', '.join(over_broad[:5])}) — writes outside "
                            "meaningful boundaries will not be flagged. Narrow "
                            "allowed_paths to real workspace subtrees."
                        ),
                        evidence_refs=[str(session.session_id)],
                    ))
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

        # 3. Policy Engine, Approvals & Incident Correlation
        policy = PolicyEngine(
            session.session_id,
            contract,
            internet_allowed=config.internet_access_allowed,
            allowed_destinations=config.allowed_destinations,
        )
        self._policies[session.session_id] = policy
        approvals = ApprovalManager(session.session_id, self._ledger)
        self._approvals[session.session_id] = approvals
        self._incidents[session.session_id] = IncidentCorrelationEngine(
            session.session_id,
            internet_allowed=config.internet_access_allowed,
            allowed_destinations=config.allowed_destinations,
        )
        self._covert[session.session_id] = CovertChannelDetector(session.session_id)
        self._reconcilers[session.session_id] = ToolClaimReconciler(session.session_id)

        # Threat-detection rule engine
        self._detectors[session.session_id] = DetectionEngine(
            session.session_id,
            workspace_paths=contract.allowed_paths,
            internet_allowed=config.internet_access_allowed,
        )

        # Egress baseline: destinations established for this workspace are
        # not re-flagged as new after restarts.
        baseline = self._ledger.get_destination_baseline(config.workspace_path)
        policy.add_known_destinations(baseline)

        # 4. Generate Baseline Graph & Persist Nodes
        baseline_gen = BaselineGenerator(session.session_id, config.workspace_path)
        # Off-thread: hashing a real workspace is disk-bound and can take
        # seconds-to-minutes; running it inline stalls the event loop (API,
        # observers, adapter polls) for the whole daemon.
        graph = await asyncio.to_thread(baseline_gen.generate)
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

        # 6. Windows Job Object Containment & Observers
        if session.session_id not in self._job_objects:
            self._job_objects[session.session_id] = WindowsJobObject(session.session_id)

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
        logger.info(
            "Session %s active for %s (adapter=%s)",
            session.session_id,
            config.workspace_path,
            adapter.adapter_name,
        )
        return session

    async def _adapter_poll_loop(self, session_id: UUID, adapter: AdapterBase) -> None:
        """Supervised polling loop for active agent adapters."""
        logger.info("Supervised adapter polling started for session: %s", session_id)
        while self._running and session_id in self._sessions:
            try:
                pre_cursor = adapter.cursor_state()
                events = await adapter.poll()
                for event in events:
                    if adapter.validate_event(event) and self._event_in_workspace(
                        session_id, adapter, event
                    ):
                        await self.ingest_event(event)
                # Confirm the batch only after everything ingested cleanly;
                # on failure the adapter rewinds so nothing is silently lost.
                adapter.commit_cursor()
                self._ledger.save_adapter_cursor(
                    session_id, adapter.adapter_name, adapter.cursor_state()
                )
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                adapter.rollback_cursor()
                self._ledger.save_adapter_cursor(
                    session_id, adapter.adapter_name, pre_cursor
                )
                logger.warning("Adapter polling error in session %s: %s", session_id, e)
                await asyncio.sleep(3.0)

    def _workspace_path(self, session_id: UUID) -> str:
        session = self._sessions.get(session_id)
        if session is not None:
            return str(session.config.workspace_path)
        return ""

    @staticmethod
    def _path_within(candidate: Path, workspace: Path) -> bool:
        """Segment-exact containment: ``C:\\proj`` must NOT contain ``C:\\proj2``."""
        try:
            resolved = candidate.resolve()
        except (OSError, ValueError):
            return False
        return resolved == workspace or resolved.is_relative_to(workspace)

    def _event_in_workspace(
        self, session_id: UUID, adapter: AdapterBase, event: EventBase
    ) -> bool:
        """Ensure adapter-reported paths anchor inside the workspace.

        Vendors may emit absolute paths anywhere on the host; anything outside
        the session workspace is surfaced as a low-confidence boundary anomaly
        rather than silently accepted or silently dropped. Unknown sessions
        have no verifiable boundary and are rejected.
        """
        workspace_raw = self._workspace_path(session_id)
        if not workspace_raw:
            logger.warning(
                "Adapter %s event for unknown session %s rejected",
                adapter.adapter_name,
                session_id,
            )
            return False
        workspace = Path(workspace_raw).resolve()
        anchors: list[str] = []
        if isinstance(event, FileMutationEvent) and event.file_path:
            anchors.append(event.file_path)
        if isinstance(event, (CommandEvent, ProcessEvent)) and event.working_dir:
            anchors.append(event.working_dir)
        if isinstance(event, ContextBoundaryEvent):
            anchors.extend(f for f in event.files_visible if f)
        if not anchors:
            return True
        try:
            outside = [p for p in anchors if not self._path_within(Path(p), workspace)]
        except (OSError, ValueError):
            logger.debug(
                "Adapter event path unparseable for session %s: %r", session_id, anchors
            )
            return False
        if outside:
            logger.warning(
                "Adapter %s reported paths outside session workspace: %s",
                adapter.adapter_name,
                outside,
            )
            return False
        return True

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
            # Persist the final cursor so a later resume continues exactly
            # where observation stopped.
            try:
                self._ledger.save_adapter_cursor(
                    session_id, adapter.adapter_name, adapter.cursor_state()
                )
            except Exception:
                logger.warning(
                    "Could not persist adapter cursor for session %s", session_id
                )
            await adapter.stop()

        job = self._job_objects.pop(session_id, None)
        if job:
            job.close()

        session.status = SessionStatus.STOPPED
        session.stopped_at = datetime.now(timezone.utc)
        self._ledger.update_session_status(
            session_id,
            SessionStatus.STOPPED,
            stopped_at=session.stopped_at.isoformat(),
        )
        # Post-exit accounting (METR shortcoming #6): emit the close-time
        # persistence summary and mark the session closed so later events
        # become post-close signals.
        for incident in self._post_exit.close_session(session_id, session.stopped_at):
            await self.ingest_event(incident)
        logger.info("Session %s stopped", session_id)

    def register_session_pid(self, session_id: UUID, pid: int) -> bool:
        """Register an agent launcher PID to be trapped in the Job Object and tracked."""
        job = self._job_objects.get(session_id)
        assigned = False
        if job:
            assigned = job.assign_pid(pid)
        for obs in self._observers.get(session_id, []):
            if isinstance(obs, ProcessTreeObserver):
                obs.boost_polling(2.0)
        return assigned

    def get_session(self, session_id: UUID) -> AuditSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[AuditSession]:
        return list(self._sessions.values())

    # -- Event ingestion & Causal Graph pipeline --

    async def ingest_event(self, event: EventBase, raw_payload: bytes | None = None) -> str:
        """Process event: Redact → Encrypt → Hash-Chain → Store → Graph Projection → Policy."""
        # 0. Anti-forensic guards (bounded work before append; the ledger
        #    always keeps full integrity even when projection is degraded).
        flooded = self._check_event_flood(event)
        self._check_clock_jump(event)

        # 1. Store Large Blobs — every byte that reaches the blob store passes
        #    through the write-boundary redactor first (invariant #6).
        if raw_payload:
            redacted_payload = self._redactor.redact_bytes(raw_payload)
            blob_hash = self._blob_store.store_blob(redacted_payload)
            self._ledger.store_blob_index(
                blob_hash=blob_hash,
                session_id=event.session_id,
                file_path=str(self._blob_store.path_for(blob_hash)),
                size_bytes=len(redacted_payload),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            event.evidence_refs.append(f"blob:{blob_hash}")

        # 2. Append to cryptographic event ledger
        event_hash = self._ledger.append_event(event)

        # 3-6. Graph projection, boundary/policy evaluation, session state.
        #    Under an active flood the append still lands (integrity) but the
        #    expensive projection is skipped so the flood cannot DoS the
        #    pipeline; the ledger remains replayable.
        if flooded:
            session = self._sessions.get(event.session_id)
            if session:
                session.event_count += 1
                session.last_event_hash = event_hash
        else:
            await self.project_event(event)

        return event_hash

    async def project_event(self, event: EventBase) -> None:
        """Apply graph projection, boundary/policy evaluation, and session state
        for an event that has already been appended to the ledger.

        Split from ingest_event so approvals (which self-append via the
        ApprovalManager) can be projected exactly once.
        """
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
                    await self.ingest_event(self._boundary_finding(event, drift))

            elif isinstance(event, CommandEvent):
                for drift in boundary.check_command(event.command):
                    await self.ingest_event(self._boundary_finding(event, drift))

            # 4b. Credential content check (P1-6) — scans actual content for
            #     credential patterns rather than only filenames/keywords
            if isinstance(event, CommandEvent) and event.command:
                drift = boundary.check_credential_access(event.command)
                if drift:
                    await self.ingest_event(
                        self._boundary_finding(event, drift, affected_command=event.command[:80])
                    )
            elif isinstance(event, FileMutationEvent) and event.diff_summary:
                drift = boundary.check_credential_access(event.diff_summary)
                if drift:
                    await self.ingest_event(
                        self._boundary_finding(event, drift, affected_path=event.file_path)
                    )

        # 5. Security Policy Evaluation
        policy = self._policies.get(event.session_id)
        if (
            policy
            and not isinstance(event, PolicyFindingEvent)
            and not event.payload.get("gate_proposal")
        ):
            evaluation = policy.evaluate(event)
            for finding in evaluation.findings:
                await self.ingest_event(finding)

        # 5b. Incident correlation — multi-stage attack patterns
        incident_engine = self._incidents.get(event.session_id)
        if incident_engine:
            for incident in incident_engine.observe(event):
                await self.ingest_event(incident)

        # 5b-2. Covert-channel structural detection (METR incident pattern):
        # improvised message boards, chunked encoded transfers, encoded names.
        covert_engine = self._covert.get(event.session_id)
        if covert_engine and not isinstance(event, IncidentEvent):
            for incident in covert_engine.observe(event):
                await self.ingest_event(incident)

        # 5b-3. Evidence-boundary reconciliation (METR shortcoming #4):
        # cross-validate agent tool claims against OS sensor ground truth.
        reconciler = self._reconcilers.get(event.session_id)
        if reconciler and not isinstance(event, IncidentEvent):
            for incident in reconciler.observe(event):
                await self.ingest_event(incident)

        # 5b-4. Post-exit surveillance (METR shortcoming #6): persistence
        # artifacts outliving the session, events arriving after close,
        # and persistence infrastructure shared across sessions.
        if not isinstance(event, IncidentEvent):
            for incident in self._post_exit.observe(event):
                await self.ingest_event(incident)

        # R2: response ladder — any critical incident reaching the pipeline
        # (created live, restored, or injected) freezes the session.
        if isinstance(event, IncidentEvent) and event.severity == "critical":
            await self._apply_incident_response(event)

        # 5c. Threat-detection rule engine — host-observable attack patterns
        detector_engine = self._detectors.get(event.session_id)
        if detector_engine and not isinstance(event, PolicyFindingEvent):
            for detection in detector_engine.evaluate(event):
                await self.ingest_event(self._detector_finding(event, detection))

        # 5d. Egress baseline learning — an approved egress destination becomes
        #     an established destination for the workspace so restarts do not
        #     re-flag it as "new".
        if isinstance(event, ApprovalEvent) and event.approved:
            await self._learn_approved_egress(event)

        # 5e. Cross-session collusion scan (throttled — the engine is
        #     pull-based over the ledger, so per-event cost must stay O(1)).
        await self._scan_collusion(event.session_id)

        # 6. Update Session In-Memory Status
        session = self._sessions.get(event.session_id)
        if session:
            session.event_count += 1
            session.last_event_hash = event.event_hash

    async def _learn_approved_egress(self, event: ApprovalEvent) -> None:
        """Persist an approved egress destination into the workspace baseline."""
        session = self._sessions.get(event.session_id)
        policy = self._policies.get(event.session_id)
        if not session or not policy:
            return
        workspace_path = session.config.workspace_path
        for evt in self._ledger.query_events(event.session_id, limit=None):
            if str(evt.event_id) != event.finding_id:
                continue
            destination = evt.payload.get("destination")
            if destination:
                policy.add_known_destination(destination)
                self._ledger.add_destination_baseline(workspace_path, destination)
            return

    def _terminate_contained(self, session_id: UUID) -> int:
        """Terminate only kernel-verified members of the session's Job Object.

        Heuristic signals ("descendant of a tracked process") are observation
        metadata, never a kill criterion: a wrong guess would terminate an
        unrelated developer process. If the daemon's own PID tree somehow
        appears inside the job, containment is broken — refuse to arm rather
        than kill ourselves.
        """
        job = self._job_objects.get(session_id)
        if not job or not job.is_active:
            return 0

        verified = set(job.get_pids())
        if not verified:
            return 0

        if os.getpid() in verified or os.getppid() in verified:
            logger.critical(
                "Daemon PID %d/%d present in session %s Job Object; "
                "refusing to terminate",
                os.getpid(),
                os.getppid(),
                session_id,
            )
            return 0

        if job.terminate():
            logger.info(
                "Terminated %d kernel-verified contained process(es) for session %s",
                len(verified),
                session_id,
            )
            return len(verified)
        return 0

    async def _apply_incident_response(self, incident: IncidentEvent) -> None:
        """Response ladder (R2): critical incidents freeze the session.

        Freezing stops further observation, revokes every pending approval
        (no pre-incident consent survives the incident), and records an
        audited containment finding. The ledger keeps its integrity —
        nothing is deleted or rewritten.
        """
        sid = incident.session_id
        session = self._sessions.get(sid)
        if not session or session.status != SessionStatus.ACTIVE:
            return

        session.status = SessionStatus.PAUSED
        try:
            self._ledger.update_session_status(session_id=sid, status=session.status.value)
        except Exception:
            logger.warning("Could not persist frozen session status", exc_info=True)

        revoked = 0
        approvals = self._approvals.get(sid)
        if approvals:
            for approval in approvals.get_active_approvals():
                try:
                    if approvals.revoke_approval(approval.finding_id):
                        revoked += 1
                except Exception:
                    logger.warning("Could not revoke approval %s", approval.finding_id)

        # Terminate only kernel-verified Job Object members (P1.19).
        terminated_pids = self._terminate_contained(sid)

        for observer in self._observers.get(sid, []):
            try:
                await observer.stop()
            except Exception:
                logger.warning("Could not stop observer during containment", exc_info=True)

        # Cancel adapter polling tasks and stop adapter
        poll_task = self._adapter_tasks.pop(sid, None)
        if poll_task:
            poll_task.cancel()
        adapter = self._adapters.pop(sid, None)
        if adapter:
            with contextlib.suppress(Exception):
                await adapter.stop()

        containment = PolicyFindingEvent(
            session_id=sid,
            actor_id="daemon",
            source_adapter="incident_response",
            confidence=ConfidenceLevel.HIGH,
            finding_type="session_frozen",
            severity="high",
            description=(
                f"Critical {incident.incident_type} incident ({incident.title}) — "
                f"session frozen, {terminated_pids} process(es) terminated, "
                f"{revoked} approval(s) revoked."
            ),
            evidence_refs=[str(incident.event_id)],
        )
        try:
            self._ledger.append_event(containment)
        except Exception:
            logger.warning("Could not record containment finding", exc_info=True)

    async def _scan_collusion(self, session_id: UUID) -> None:
        """Cross-session collusion scan (R3), throttled to every 5s per session.

        Newly detected candidates are surfaced as ledger-backed findings so
        the signal is auditable, not just visible in a dashboard pull.
        """
        now = time.monotonic()
        last = self._collusion_last_scan.get(session_id)
        if last is not None and now - last < 5.0:
            return
        self._collusion_last_scan[session_id] = now
        try:
            for candidate in self._collusion.for_session(session_id):
                key = (
                    candidate.signal,
                    candidate.detail,
                    tuple(sorted(candidate.session_ids)),
                )
                if key in self._collusion_cache:
                    continue
                self._collusion_cache[key] = candidate
                # Surface the signal in EVERY session it implicates, so the
                # finding is visible from either side of the correlation.
                for implicated in candidate.session_ids:
                    finding = PolicyFindingEvent(
                        session_id=UUID(implicated),
                        actor_id="collusion_engine",
                        source_adapter="collusion_engine",
                        confidence=candidate.confidence,
                        finding_type=f"collusion:{candidate.signal}",
                        severity="medium",
                        description=(
                            f"{candidate.signal}: {candidate.detail} — "
                            f"sessions {', '.join(candidate.session_ids)}. "
                            f"{candidate.reasoning_gap}"
                        ),
                        evidence_refs=candidate.evidence_event_ids,
                    )
                    try:
                        self._ledger.append_event(finding)
                    except Exception:
                        logger.warning(
                            "Could not record collusion finding", exc_info=True
                        )
        except Exception:
            logger.warning("Collusion scan failed", exc_info=True)

    def _check_event_flood(self, event: EventBase) -> bool:
        """Return True while a session is under an event flood (anti-forensic).

        Flags once per episode with a ledger-backed finding; the ledger keeps
        appending (integrity) but projection is skipped until the rate drops.
        """
        if isinstance(event, PolicyFindingEvent) and event.finding_type == "event_flood":
            return False
        now = time.monotonic()
        start, count, flagged = self._flood_state.get(event.session_id, (now, 0, False))
        if now - start > _FLOOD_WINDOW_SECONDS:
            self._flood_state[event.session_id] = (now, 1, False)
            return False
        count += 1
        if count >= _FLOOD_EVENT_THRESHOLD and not flagged:
            self._flood_state[event.session_id] = (start, count, True)
            finding = PolicyFindingEvent(
                session_id=event.session_id,
                actor_id="daemon",
                source_adapter="daemon",
                confidence=ConfidenceLevel.HIGH,
                finding_type="event_flood",
                severity="medium",
                description=(
                    f"More than {_FLOOD_EVENT_THRESHOLD} events in "
                    f"{_FLOOD_WINDOW_SECONDS:.0f}s — a rate consistent with "
                    "anti-forensic flooding. Projection is paused until the "
                    "rate drops; the ledger continues appending."
                ),
                evidence_refs=[str(event.event_id)],
            )
            try:
                self._ledger.append_event(finding)
            except Exception:
                logger.warning("Could not record flood finding", exc_info=True)
            return True
        self._flood_state[event.session_id] = (start, count, flagged)
        return flagged

    def _check_clock_jump(self, event: EventBase) -> None:
        """Flag events whose timestamps deviate from wall clock (clock gaming)."""
        delta = abs((datetime.now(timezone.utc) - event.timestamp).total_seconds())
        if delta <= _CLOCK_JUMP_TOLERANCE_SECONDS:
            return
        last = self._clock_findings.get(event.session_id)
        now = time.monotonic()
        if last is not None and now - last < _CLOCK_FINDING_COOLDOWN_SECONDS:
            return
        self._clock_findings[event.session_id] = now
        finding = PolicyFindingEvent(
            session_id=event.session_id,
            actor_id="daemon",
            source_adapter="daemon",
            confidence=ConfidenceLevel.MEDIUM,
            finding_type="clock_anomaly",
            severity="low",
            description=(
                f"Event timestamp {event.timestamp.isoformat()} deviates from "
                f"wall clock by {delta:.0f}s — clock manipulation or skewed "
                "capture timestamps."
            ),
            evidence_refs=[str(event.event_id)],
        )
        try:
            self._ledger.append_event(finding)
        except Exception:
            logger.warning("Could not record clock-anomaly finding", exc_info=True)

    @staticmethod
    def _detector_finding(event: EventBase, finding: DetectorFinding) -> PolicyFindingEvent:
        """Build a PolicyFindingEvent from a detector finding."""
        return PolicyFindingEvent(
            session_id=event.session_id,
            actor_id="detector_engine",
            source_adapter="detector_engine",
            confidence=finding.confidence,
            evidence_refs=finding.evidence_refs,
            finding_type=finding.detector_id,
            severity=finding.severity,
            description=finding.description,
            affected_path=finding.affected_path,
            affected_command=finding.affected_command,
            requires_approval=finding.requires_approval,
        )

    @staticmethod
    def _boundary_finding(
        event: EventBase,
        drift: ScopeDriftResult,
        affected_path: str = "",
        affected_command: str = "",
    ) -> PolicyFindingEvent:
        """Build a PolicyFindingEvent from a scope drift result."""
        return PolicyFindingEvent(
            session_id=event.session_id,
            actor_id="task_boundary_engine",
            source_adapter="task_boundary_engine",
            confidence=ConfidenceLevel.HIGH,
            finding_type=drift.drift_type.value,
            severity=drift.severity,
            description=drift.description,
            affected_path=affected_path or drift.affected_path,
            affected_command=affected_command or drift.affected_command,
            requires_approval=drift.requires_approval,
        )

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

        # Redact at projection: the in-memory graph and every API response
        # derived from it must never contain unredacted event content.
        label = self._redactor.redact(self._make_node_label(event))
        node = GraphNode(
            node_type=node_type,
            label=label,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            source_adapter=event.source_adapter,
            confidence=event.confidence,
            session_id=event.session_id,
            data=self._redactor.redact_any(event.canonical_dict()),
        )
        graph.add_node(node)

        # Index the most recent node per (session, type, actor) for correlation
        self._latest[(event.session_id, node.node_type, event.actor_id)] = node.node_id

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

        def link_edge(
            source_id: UUID, edge_type: EdgeType, confidence: ConfidenceLevel = ConfidenceLevel.HIGH
        ) -> GraphEdge:
            """Helper: edge from a cause node to the just-added node."""
            return GraphEdge(
                source_node_id=source_id,
                target_node_id=node.node_id,
                edge_type=edge_type,
                actor_id=event.actor_id,
                source_adapter=event.source_adapter,
                confidence=confidence,
            )

        # 1. Invocations connect to root task_intent
        if isinstance(event, InvocationEvent):
            for t_node in graph.get_nodes_by_type(NodeType.TASK_INTENT):
                new_edges.append(link_edge(t_node.node_id, EdgeType.PROVIDES_CONTEXT_TO))

        # 2. Tool requests connect to the most recent agent session of that actor
        elif isinstance(event, ToolRequestEvent):
            s_node = self._latest_matching(graph, NodeType.AGENT_SESSION, actor_id=event.actor_id)
            if s_node:
                new_edges.append(link_edge(s_node.node_id, EdgeType.REQUESTS))

        # 3. Tool results connect to the most recent matching tool request
        elif isinstance(event, ToolResultEvent):
            req_node = self._latest_matching(
                graph, NodeType.TOOL_REQUEST,
                predicate=lambda n: n.data.get("tool_name") == event.tool_name,
            )
            if req_node:
                new_edges.append(link_edge(req_node.node_id, EdgeType.EXECUTES))

        # 4. Commands connect to the most recent agent session and the matching
        #    shell tool request. Correlation is explicit: the tool request must
        #    be a shell-type tool (never an arbitrary substring scan).
        elif isinstance(event, CommandEvent):
            s_node = self._latest_matching(graph, NodeType.AGENT_SESSION, actor_id=event.actor_id)
            if s_node:
                new_edges.append(link_edge(s_node.node_id, EdgeType.EXECUTES))
            req_node = self._latest_matching(
                graph, NodeType.TOOL_REQUEST,
                predicate=lambda n: str(n.data.get("tool_name", "")).lower()
                in _SHELL_TOOL_NAMES
                and event.command in self._tool_request_command(n.data),
            )
            if req_node:
                new_edges.append(link_edge(req_node.node_id, EdgeType.EXECUTES))

        # 5. File mutations connect to the most recent command & baseline source file
        elif isinstance(event, FileMutationEvent):
            cmd_node = self._latest_matching(graph, NodeType.COMMAND)
            if cmd_node:
                new_edges.append(
                    link_edge(cmd_node.node_id, EdgeType.MODIFIES, ConfidenceLevel.MEDIUM)
                )

            for file_node in graph.get_nodes_by_type(NodeType.SOURCE_FILE):
                if file_node.data.get("path") == event.file_path:
                    # mutation node MODIFIES the baseline source file
                    new_edges.append(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=file_node.node_id,
                        edge_type=EdgeType.MODIFIES,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))
                    break

            # Multi-actor artifact sharing: a different actor previously touched
            # this same file. Observable fact, inference-labeled — coordination
            # is never claimed (visible half only).
            prev = self._latest_matching(
                graph, NodeType.FILESYSTEM_MUTATION,
                predicate=lambda n: n.data.get("file_path") == event.file_path
                and n.actor_id != event.actor_id,
            )
            if prev:
                new_edges.append(GraphEdge(
                    source_node_id=prev.node_id,
                    target_node_id=node.node_id,
                    edge_type=EdgeType.SHARED_ARTIFACT,
                    actor_id=event.actor_id,
                    source_adapter=event.source_adapter,
                    confidence=ConfidenceLevel.MEDIUM,
                ))

        # 6. Network connections connect to the most recent spawning process
        elif isinstance(event, NetworkEvent):
            if event.process_pid:
                p_node = self._latest_matching(
                    graph, NodeType.PROCESS,
                    predicate=lambda n: n.data.get("pid") == event.process_pid,
                )
                if p_node:
                    new_edges.append(link_edge(p_node.node_id, EdgeType.SPAWNS))

        # 6b. Process events link to their parent process when the parent is
        # observed in this session — the process tree becomes visible graph
        # topology (SPAWNS), not just per-process isolated nodes. The ppid
        # match is an observed fact (HIGH); unattributed kernel events keep
        # their node but never claim a parent they cannot name.
        elif isinstance(event, ProcessEvent):
            parent_pid = event.ppid
            if parent_pid:
                parent = self._latest_matching(
                    graph, NodeType.PROCESS,
                    predicate=lambda n: n.data.get("pid") == parent_pid,
                )
                if parent and parent.data.get("pid") != event.pid:
                    new_edges.append(
                        link_edge(parent.node_id, EdgeType.SPAWNS, ConfidenceLevel.HIGH)
                    )

        # 7. Policy findings link VIOLATES to the node that actually triggered
        #    them (matching command/path), never to an arbitrary recent node.
        elif isinstance(event, PolicyFindingEvent):
            trigger = self._policy_trigger_node(graph, event)
            if trigger:
                new_edges.append(link_edge(trigger.node_id, EdgeType.VIOLATES))

        # 8. Approvals connect to findings (approval node → finding node)
        elif isinstance(event, ApprovalEvent):
            for f_node in graph.get_nodes_by_type(NodeType.POLICY_FINDING):
                is_target = (
                    f_node.data.get("event_id") == event.finding_id
                    or f_node.data.get("finding_type") == event.finding_id
                )
                if is_target:
                    new_edges.append(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=f_node.node_id,
                        edge_type=EdgeType.APPROVED_BY,
                        actor_id=event.actor_id,
                        source_adapter=event.source_adapter,
                        confidence=ConfidenceLevel.HIGH,
                    ))

        # Add and persist all edges
        for new_edge in new_edges:
            graph.add_edge(new_edge)
            self._ledger.store_graph_edge(
                edge_id=new_edge.edge_id,
                session_id=event.session_id,
                source_node_id=new_edge.source_node_id,
                target_node_id=new_edge.target_node_id,
                edge_type=new_edge.edge_type.value,
                timestamp=new_edge.timestamp.isoformat(),
                actor_id=new_edge.actor_id,
                source_adapter=new_edge.source_adapter,
                confidence=new_edge.confidence.value,
                data=new_edge.data,
            )

    def _latest_matching(
        self,
        graph: ContextGraph,
        node_type: NodeType,
        actor_id: str = "",
        predicate: Any | None = None,
    ) -> GraphNode | None:
        """Return the most recent node of a type, preferring same-actor matches.

        Uses the O(1) recent-node index when possible, falling back to a
        timestamp-ordered scan of the graph.
        """
        if not predicate and actor_id:
            nid = self._latest.get((graph.session_id, node_type, actor_id))
            if nid:
                node = graph.get_node(nid)
                if node:
                    return node

        candidates = graph.get_nodes_by_type(node_type)
        if actor_id:
            same_actor = [n for n in candidates if n.actor_id == actor_id]
            if same_actor:
                candidates = same_actor
        if predicate:
            candidates = [n for n in candidates if predicate(n)]
        if not candidates:
            return None
        return max(candidates, key=lambda n: n.timestamp)

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
        return (
            event.event_type.value
            if hasattr(event.event_type, "value")
            else str(event.event_type)
        )

    @staticmethod
    def _tool_request_command(data: dict[str, Any]) -> str:
        """Extract the shell command embedded in a tool request's arguments."""
        args = data.get("tool_args")
        if isinstance(args, dict):
            for key in ("command", "cmd", "shell_command"):
                value = args.get(key)
                if isinstance(value, str):
                    return value
            return str(args)
        if isinstance(args, str):
            return args
        return ""

    def _policy_trigger_node(
        self, graph: ContextGraph, event: PolicyFindingEvent
    ) -> GraphNode | None:
        """Find the node that triggered a policy finding, by exact content match.

        Matches the finding's affected_command against recorded COMMAND nodes
        and its affected_path against FILESYSTEM_MUTATION nodes; falls back to
        the most recent NETWORK_REQUEST node for network findings. Returns None
        when nothing matches, so findings never get arbitrarily attributed.
        """
        if event.affected_command:
            for n in graph.get_nodes_by_type(NodeType.COMMAND):
                if event.affected_command == str(n.data.get("command", "")):
                    return n
        if event.affected_path:
            for n in graph.get_nodes_by_type(NodeType.FILESYSTEM_MUTATION):
                if event.affected_path == str(n.data.get("file_path", "")):
                    return n
        if "network" in str(event.finding_type).lower():
            return self._latest_matching(graph, NodeType.NETWORK_REQUEST)
        return None

    # -- Pre-Execution Mediated Policy Gate (P0-6) --

    async def evaluate_proposed_action(
        self,
        session_id: UUID,
        action_type: str,
        target: str,
        details: dict[str, Any] | None = None,
    ) -> tuple[bool, str, str]:
        """Pre-execution mediated policy gate (P0-6).

        Evaluates a *proposed* action against the task boundary AND the full
        policy engine before it is executed. Returns
        (allowed, reason, required_approval_id):

        - allowed=True  → action may proceed
        - allowed=False + required_approval_id non-empty → action is PAUSED;
          proceed only after the user approves the given finding/scope
        - allowed=False + required_approval_id empty → action is BLOCKED outright

        Reason strings are prefixed with "APPROVAL REQUIRED:" or "BLOCKED:"
        so callers (API, CLI) can distinguish pause from block.

        Network proposals carry the http_method the observer layer can never
        see; they are recorded as low-confidence events so the incident
        engine's external_state_change detection can fire on them (without
        re-running policy — the gate already evaluated it).
        """
        boundary = self._boundaries.get(session_id)
        approvals = self._approvals.get(session_id)
        policy = self._policies.get(session_id)

        # 1. Task-boundary scope checks (file paths, destructive/privilege/network commands)
        boundary_hits: list[tuple[str, str, str, str]] = []
        # (drift_type, description, path, command)
        if boundary:
            if action_type == "file_mutation":
                mutation_type = (details or {}).get("mutation_type", "modify")
                drift = boundary.check_file_mutation(target, mutation_type)
                if drift:
                    boundary_hits.append(
                        (
                            drift.drift_type.value,
                            drift.description,
                            drift.affected_path,
                            drift.affected_command,
                        )
                    )
            elif action_type == "command":
                for drift in boundary.check_command(target):
                    boundary_hits.append(
                        (
                            drift.drift_type.value,
                            drift.description,
                            drift.affected_path,
                            drift.affected_command,
                        )
                    )

        # 2. Full policy engine over a synthetic event (destructive ops,
        #    credential files, dependency manifests, network egress, git ops)
        policy_blocked = False
        policy_hits: list[tuple[str, str]] = []  # (rule_id, description)
        synthetic: EventBase | None = self._synthetic_event_for_gate(action_type, target, details)
        if policy and synthetic is not None:
            evaluation = policy.evaluate(synthetic)
            for finding in evaluation.findings:
                policy_hits.append((finding.finding_type, finding.description))
            if evaluation.is_blocked:
                policy_blocked = True

        # 2b. Record network proposals as low-confidence evidence. They carry
        #     http_method — invisible to the observer layer — which the
        #     incident engine needs for external_state_change detection.
        #     Policy is NOT re-evaluated on ingestion (gate_proposal flag).
        if action_type == "network" and isinstance(synthetic, NetworkEvent):
            synthetic.session_id = session_id
            synthetic.confidence = ConfidenceLevel.LOW
            synthetic.payload["gate_proposal"] = True
            await self.ingest_event(synthetic)

        # 2c. Threat detection engine dry-run over the synthetic event
        detector_engine = self._detectors.get(session_id)
        if detector_engine and synthetic is not None:
            synthetic.session_id = session_id
            detector_findings = detector_engine.evaluate(synthetic)
            for f in detector_findings:
                if f.severity in {"critical", "high"}:
                    policy_blocked = True
                    policy_hits.append((f.detector_id, f.description))
                else:
                    policy_hits.append((f.detector_id, f.description))

        # 3. BLOCK outright (privilege escalation, database destruction, malware, etc.)
        if policy_blocked:
            desc = policy_hits[0][1] if policy_hits else "action is not permitted by policy"
            rule_id = policy_hits[0][0] if policy_hits else "shield_blocked_threat"
            # Record the pre-execution blocked attack to the cryptographic ledger
            blocked_event = PolicyFindingEvent(
                session_id=session_id,
                actor_id="shield_gate",
                source_adapter="gate",
                confidence=ConfidenceLevel.HIGH,
                finding_type="shield_blocked_threat",
                severity="critical",
                description=f"Shield blocked execution: {desc}",
                policy_rule=rule_id,
            )
            with contextlib.suppress(Exception):
                self._ledger.append_event(blocked_event)
            return False, f"BLOCKED: {desc}", ""

        # 4. Boundary hits — pause unless covered by an active approval.
        # Credential-family drift is scope-immune: an approval's path/command
        # scope can never pre-clear secret access, no matter how the scope
        # was worded — that is the "orphaned approval enables later misuse"
        # failure mode.
        for drift_type, desc, path, cmd in boundary_hits:
            if drift_type not in _SCOPE_IMMUNE_HITS and approvals and approvals.check_approval(
                finding_id=None, path=path or None, command=cmd or None
            ):
                continue
            return False, f"APPROVAL REQUIRED: {desc}", drift_type

        # 5. Policy hits — same rule: credential gates always pause.
        for rule_id, desc in policy_hits:
            if rule_id not in _SCOPE_IMMUNE_HITS and approvals and approvals.check_approval(
                finding_id=None,
                path=None if action_type == "command" else target,
                command=target if action_type == "command" else None,
            ):
                continue
            return False, f"APPROVAL REQUIRED: {desc}", rule_id

        return True, "Allowed by policy", ""

    # Alias for API/Gate consistency
    evaluate_action = evaluate_proposed_action

    @staticmethod
    def _split_host_port(target: str) -> tuple[str, int]:
        """Split a ``host:port`` target, supporting IPv6 literals.

        Accepts bracketed IPv6 (``[2001:db8::1]:443``), plain IPv4
        (``8.8.8.8:53``), and bare hosts (``8.8.8.8``). Unbracketed IPv6
        literals without a port are returned whole with port 0.
        """
        t = target.strip()
        if not t:
            return "0.0.0.0", 0
        if t.startswith("["):
            end = t.find("]")
            if end != -1:
                host = t[1:end]
                rest = t[end + 1:]
                if rest.startswith(":"):
                    port_s = rest[1:]
                    return host, int(port_s) if port_s.isdigit() else 0
                return host, 0
        if t.count(":") == 1:
            host, _, port_s = t.rpartition(":")
            if port_s.isdigit():
                return host or "0.0.0.0", int(port_s)
            return host, 0
        # Unbracketed IPv6 literal (or bare host) — no port can be split off
        return t, 0

    @staticmethod
    def _synthetic_event_for_gate(
        action_type: str,
        target: str,
        details: dict[str, Any] | None,
    ) -> EventBase | None:
        """Build a throwaway event for pre-execution policy evaluation."""
        details = details or {}
        if action_type == "file_mutation":
            return FileMutationEvent(
                session_id=uuid4(),
                actor_id="gate",
                source_adapter="gate",
                file_path=target,
                mutation_type=details.get("mutation_type", "modify"),
            )
        if action_type == "command":
            return CommandEvent(
                session_id=uuid4(),
                actor_id="gate",
                source_adapter="gate",
                command=target,
            )
        if action_type == "network":
            host, port = AgentTraceDaemon._split_host_port(target)
            return NetworkEvent(
                session_id=uuid4(),
                actor_id="gate",
                source_adapter="gate",
                destination_ip=host,
                destination_port=port,
                protocol=details.get("protocol", "tcp"),
                http_method=details.get("http_method"),
            )
        if action_type == "git":
            return GitEvent(
                session_id=uuid4(),
                actor_id="gate",
                source_adapter="gate",
                git_action=target,
            )
        return None

    # -- Observers & Adapter Selection --

    async def _start_observers(self, session: AuditSession) -> list[BaseObserver]:
        def callback(event: EventBase, payload: bytes | None = None) -> Any:
            return self.ingest_event(event, payload)
        workspace = session.config.workspace_path

        net_observer = NetworkObserver(session.session_id, workspace, callback)
        self._network_observers[session.session_id] = net_observer

        proc_observer = ProcessTreeObserver(
            session.session_id,
            workspace,
            callback,
            on_pids_updated=lambda pids: net_observer.update_tracked_pids(pids),
            job_object=self._job_objects.get(session.session_id),
        )

        observers: list[BaseObserver] = [
            FilesystemObserver(
                session.session_id, workspace, callback, session.config.ignore_patterns
            ),
            proc_observer,
            GitMonitor(session.session_id, workspace, callback),
            TerminalObserver(
                session.session_id,
                workspace,
                callback,
                track_global_history=session.config.track_global_shell_history,
            ),
            net_observer,
            # Kernel-tier: ETW process audit where available; Job-Object and
            # MXC containment are declared as honest gaps on hosts without
            # those capabilities.
            KernelObserver(session.session_id, workspace, callback),
        ]

        # Reconcile hash sources: seed the observer's hash cache from the
        # baseline graph's SOURCE_FILE content hashes so the first mutation
        # has a real before_hash (the baseline generator and the observer
        # compute hashes independently and must not drift apart).
        graph = self._graphs.get(session.session_id)
        if graph is not None:
            baseline_hashes = {
                str(node.data.get("path", "")): node.content_hash
                for node in graph.to_snapshot().nodes
                if node.node_type == NodeType.SOURCE_FILE
                and node.content_hash
                and node.data.get("path")
            }
            if baseline_hashes:
                filesystem_observer = cast(
                    "FilesystemObserver", observers[0]
                )
                filesystem_observer.seed_hashes(baseline_hashes)

        for observer in observers:
            await observer.start()

        return observers

    def _select_adapter(self, session: AuditSession) -> AdapterBase:
        agent_type = session.config.agent_type
        workspace = session.config.workspace_path

        if agent_type == AgentType.CODEX:
            return CodexAdapter(session.session_id, workspace)
        elif agent_type == AgentType.COPILOT:
            return CopilotAdapter(session.session_id, workspace)
        elif agent_type == AgentType.CLAUDE:
            return ClaudeAdapter(session.session_id, workspace)
        elif agent_type == AgentType.GENERIC:
            return UniversalAgentAdapter(session.session_id, workspace)
        return CompositeAdapter(session.session_id, workspace)

    # -- Queries --

    def get_graph(self, session_id: UUID) -> ContextGraph | None:
        return self._graphs.get(session_id)

    def get_timeline(self, session_id: UUID) -> list[EventBase]:
        return self._ledger.query_events(session_id)

    def get_findings(self, session_id: UUID) -> list[EventBase]:
        return self._ledger.query_events(
            session_id, event_type=EventType.POLICY_FINDING, limit=None
        )

    def get_incidents(self, session_id: UUID) -> list[EventBase]:
        """Return all persisted incident records for a session."""
        return self._ledger.query_events(session_id, event_type=EventType.INCIDENT, limit=None)

    def get_contract(self, session_id: UUID) -> TaskContract | None:
        return self._contracts.get(session_id)

    def get_approval_manager(self, session_id: UUID) -> ApprovalManager | None:
        return self._approvals.get(session_id)
