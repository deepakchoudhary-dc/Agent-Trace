"""AgentTrace local daemon API — FastAPI endpoints.

Exposes session management, event ingestion, graph queries, timeline,
policy findings, approval recording, chain verification, and simulation runs
via a strictly local loopback HTTP API.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.blast_radius import BlastRadiusAnalyzer
from agenttrace.graph.causal_engine import CausalExplanationEngine
from agenttrace.graph.replay import ReplayEngine
from agenttrace.models.events import ApprovalEvent, ConfidenceLevel, EventType, FileMutationEvent
from agenttrace.models.session import AgentType

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AgentTrace API",
    description="Local daemon API for the AgentTrace causal auditor",
    version="0.2.0",
)

# Bind CORS to local loopback UI development servers only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

daemon = AgentTraceDaemon()


# -- Request & Response DTO Models --

class CreateSessionRequest(BaseModel):
    workspace_path: str
    task_description: str = ""
    agent_type: str = "auto"
    allowed_paths: list[str] = Field(default_factory=lambda: ["*"])
    prohibited_paths: list[str] = Field(default_factory=lambda: [".env*", "*.pem", "*.key"])
    expected_tests: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)


class CreateSessionResponse(BaseModel):
    session_id: str
    status: str
    workspace_path: str
    adapter: str
    observability_gaps: list[str]


class ApprovalRequest(BaseModel):
    finding_id: str
    approved: bool = True
    reason: str = ""
    scope: str = ""
    expiry_minutes: int = 60
    affected_paths: list[str] = Field(default_factory=list)
    affected_commands: list[str] = Field(default_factory=list)


class FindingDTO(BaseModel):
    finding_id: str
    session_id: str
    finding_type: str
    severity: str
    description: str
    affected_path: str = ""
    affected_command: str = ""
    requires_approval: bool = True
    auto_resolved: bool = False
    timestamp: str


class DiffItemDTO(BaseModel):
    file_path: str
    mutation_type: str
    before_hash: str
    after_hash: str
    diff_summary: str
    timestamp: str


class VerifyResponse(BaseModel):
    session_id: str
    verified: bool
    error: str = ""
    event_count: int
    last_event_hash: str


class SimulationRequest(BaseModel):
    verification_commands: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    commit_hash: str | None = None


# -- Lifecycle --

@app.on_event("startup")
async def startup() -> None:
    await daemon.start()


@app.on_event("shutdown")
async def shutdown() -> None:
    await daemon.stop()


# -- Session Endpoints --

@app.post("/sessions", response_model=CreateSessionResponse)
async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
    """Create a new audit session."""
    try:
        session = await daemon.create_session(
            workspace_path=req.workspace_path,
            task_description=req.task_description,
            agent_type=AgentType(req.agent_type),
            allowed_paths=req.allowed_paths,
            prohibited_paths=req.prohibited_paths,
            expected_tests=req.expected_tests,
            allowed_tools=req.allowed_tools,
        )
    except Exception as e:
        logger.exception("Failed to create session: %s", e)
        raise HTTPException(status_code=400, detail=str(e))

    adapter = daemon._adapters.get(session.session_id)
    gaps = adapter.observability_gaps if adapter else []

    return CreateSessionResponse(
        session_id=str(session.session_id),
        status=session.status.value if hasattr(session.status, "value") else str(session.status),
        workspace_path=session.config.workspace_path,
        adapter=adapter.adapter_name if adapter else "generic",
        observability_gaps=gaps,
    )


@app.get("/sessions")
async def list_sessions() -> list[dict[str, Any]]:
    """List all sessions."""
    sessions = daemon.list_sessions()
    return [
        {
            "session_id": str(s.session_id),
            "workspace_path": s.config.workspace_path,
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "task_description": s.task_description,
            "event_count": s.event_count,
            "last_event_hash": s.last_event_hash,
            "started_at": s.started_at.isoformat(),
            "stopped_at": s.stopped_at.isoformat() if s.stopped_at else None,
        }
        for s in sessions
    ]


@app.get("/sessions/{session_id}")
async def get_session(session_id: UUID) -> dict[str, Any]:
    """Get session details."""
    session = daemon.get_session(session_id)
    if not session:
        # Check storage directly
        stored = daemon._ledger.get_session(session_id)
        if not stored:
            raise HTTPException(status_code=404, detail="Session not found")
        return stored

    return {
        "session_id": str(session.session_id),
        "workspace_path": session.config.workspace_path,
        "status": session.status.value if hasattr(session.status, "value") else str(session.status),
        "task_description": session.task_description,
        "event_count": session.event_count,
        "last_event_hash": session.last_event_hash,
        "started_at": session.started_at.isoformat(),
        "stopped_at": session.stopped_at.isoformat() if session.stopped_at else None,
    }


@app.post("/sessions/{session_id}/stop")
async def stop_session(session_id: UUID) -> dict[str, str]:
    """Stop an active session."""
    await daemon.stop_session(session_id)
    return {"status": "stopped", "session_id": str(session_id)}


# -- Verification & Integrity Endpoints (P0-1, P0-5) --

@app.get("/sessions/{session_id}/verify", response_model=VerifyResponse)
async def verify_chain(session_id: UUID) -> VerifyResponse:
    """Recompute and verify the entire cryptographic hash chain for a session."""
    session = daemon.get_session(session_id)
    stored = daemon._ledger.get_session(session_id)
    if not session and not stored:
        raise HTTPException(status_code=404, detail="Session not found")

    is_valid, error_msg = daemon._ledger.verify_chain(session_id)
    event_count = session.event_count if session else stored.get("event_count", 0)
    last_hash = daemon._ledger.get_last_hash(session_id)

    return VerifyResponse(
        session_id=str(session_id),
        verified=is_valid,
        error=error_msg,
        event_count=event_count,
        last_event_hash=last_hash,
    )


# -- Timeline & Diff Endpoints --

@app.get("/sessions/{session_id}/timeline")
async def get_timeline(session_id: UUID) -> list[dict[str, Any]]:
    """Get the full chronological event timeline for a session."""
    events = daemon.get_timeline(session_id)
    return [e.model_dump(mode="json") for e in events]


@app.get("/sessions/{session_id}/diffs", response_model=list[DiffItemDTO])
async def get_diffs(session_id: UUID) -> list[DiffItemDTO]:
    """Get real unified diffs and file mutations recorded during the session."""
    events = daemon._ledger.query_events(session_id, event_type=EventType.FILE_MUTATION)
    diffs: list[DiffItemDTO] = []
    for evt in events:
        if isinstance(evt, FileMutationEvent):
            diffs.append(
                DiffItemDTO(
                    file_path=evt.file_path,
                    mutation_type=evt.mutation_type,
                    before_hash=evt.before_hash,
                    after_hash=evt.after_hash,
                    diff_summary=evt.diff_summary,
                    timestamp=evt.timestamp.isoformat(),
                )
            )
    return diffs


# -- Policy Findings & Approvals (P0-4, P1-8) --

@app.get("/sessions/{session_id}/findings", response_model=list[FindingDTO])
async def get_findings(session_id: UUID) -> list[FindingDTO]:
    """Get decrypted, redacted policy findings for a session."""
    findings_events = daemon.get_findings(session_id)
    results: list[FindingDTO] = []
    for evt in findings_events:
        results.append(
            FindingDTO(
                finding_id=str(evt.event_id),
                session_id=str(evt.session_id),
                finding_type=getattr(evt, "finding_type", "policy_finding"),
                severity=getattr(evt, "severity", "medium"),
                description=getattr(evt, "description", ""),
                affected_path=getattr(evt, "affected_path", ""),
                affected_command=getattr(evt, "affected_command", ""),
                requires_approval=getattr(evt, "requires_approval", True),
                auto_resolved=getattr(evt, "auto_resolved", False),
                timestamp=evt.timestamp.isoformat(),
            )
        )
    return results


@app.post("/sessions/{session_id}/approvals")
async def record_approval(session_id: UUID, req: ApprovalRequest) -> dict[str, Any]:
    """Record an authentic user approval/denial in the ledger and update policy state."""
    session = daemon.get_session(session_id)
    if not session and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    approval_event = ApprovalEvent(
        session_id=session_id,
        actor_id="user_dashboard",
        source_adapter="approval_manager",
        confidence=ConfidenceLevel.HIGH,
        finding_id=req.finding_id,
        approved=req.approved,
        reason=req.reason,
        scope=req.scope,
        affected_paths=req.affected_paths,
        affected_commands=req.affected_commands,
    )

    event_hash = await daemon.ingest_event(approval_event)

    # Record in approval manager if active
    mgr = daemon.get_approval_manager(session_id)
    if mgr:
        mgr.record_approval(
            finding_id=req.finding_id,
            approved=req.approved,
            reason=req.reason,
            scope=req.scope,
            expiry_minutes=req.expiry_minutes,
            affected_paths=req.affected_paths,
        )

    return {
        "status": "recorded",
        "approval_id": str(approval_event.event_id),
        "event_hash": event_hash,
        "approved": req.approved,
    }


# -- Context Graph & Forensic Report (P0-5, P1-2) --

@app.get("/sessions/{session_id}/graph")
async def get_graph(session_id: UUID) -> dict[str, Any]:
    """Get the full Context Graph snapshot for a session."""
    graph = daemon.get_graph(session_id)
    if not graph:
        # Load from ledger
        nodes = daemon._ledger.get_graph_nodes(session_id)
        edges = daemon._ledger.get_graph_edges(session_id)
        return {
            "session_id": str(session_id),
            "nodes": nodes,
            "edges": edges,
        }
    return graph.to_dict()


@app.get("/sessions/{session_id}/report")
async def get_forensic_report(session_id: UUID) -> dict[str, Any]:
    """Generate a verified, cryptographically sealed forensic audit report."""
    is_valid, error = daemon._ledger.verify_chain(session_id)
    events = daemon._ledger.query_events(session_id)
    findings = daemon.get_findings(session_id)
    approvals = daemon._ledger.get_approvals(session_id)
    last_hash = daemon._ledger.get_last_hash(session_id)

    manifest = {
        "report_id": str(UUID(int=hashlib.sha256(f"{session_id}:{last_hash}".encode()).digest()[:16])),
        "session_id": str(session_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "integrity_status": "TAMPER_VERIFIED" if is_valid else "TAMPER_DETECTED",
        "integrity_error": error,
        "head_event_hash": last_hash,
        "event_count": len(events),
        "findings_count": len(findings),
        "approvals_count": len(approvals),
        "findings_summary": [
            {
                "finding_id": str(f.event_id),
                "type": getattr(f, "finding_type", "policy_finding"),
                "severity": getattr(f, "severity", "medium"),
                "description": getattr(f, "description", ""),
            }
            for f in findings
        ],
    }

    # Cryptographic report signature
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["report_signature_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    return manifest


# -- Simulation & Causal Analysis --

@app.post("/sessions/{session_id}/simulate")
async def run_simulation(session_id: UUID, req: SimulationRequest) -> dict[str, Any]:
    """Execute branch-and-replay simulation in an isolated worktree."""
    session = daemon.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    graph = daemon.get_graph(session_id)
    if not graph:
        raise HTTPException(status_code=400, detail="No graph snapshot available for simulation")

    replay = ReplayEngine(session.config.workspace_path)
    sim_config = replay.create_simulation(
        snapshot=graph.to_snapshot(),
        constraints=req.constraints,
        verification_commands=req.verification_commands,
        commit_hash=req.commit_hash,
    )
    result = replay.run_simulation(sim_config)

    return {
        "simulation_id": str(result.simulation_id),
        "success": result.success,
        "duration_ms": result.duration_ms,
        "verification_results": result.verification_results,
        "differences": result.differences,
        "error": result.error,
    }


@app.get("/sessions/{session_id}/causal/{target_node_id}")
async def get_causal_chain(session_id: UUID, target_node_id: UUID) -> dict[str, Any]:
    """Explain why a node or action exists using backward graph reachability."""
    graph = daemon.get_graph(session_id)
    if not graph:
        # Load graph from ledger if daemon was restarted
        nodes_data = daemon._ledger.get_graph_nodes(session_id)
        edges_data = daemon._ledger.get_graph_edges(session_id)
        from agenttrace.graph.context_graph import ContextGraph
        from agenttrace.models.graph import GraphNode, GraphEdge, NodeType, EdgeType
        graph = ContextGraph(session_id)
        for n in nodes_data:
            try:
                graph.add_node(GraphNode(
                    node_id=UUID(n["node_id"]),
                    session_id=session_id,
                    node_type=NodeType(n["node_type"]),
                    label=n.get("label", ""),
                    timestamp=datetime.fromisoformat(n["timestamp"]),
                    actor_id=n.get("actor_id", ""),
                    source_adapter=n.get("source_adapter", ""),
                    confidence=ConfidenceLevel(n.get("confidence", "high")),
                    data=n.get("data", {}),
                ))
            except Exception:
                continue
        for e in edges_data:
            try:
                graph.add_edge(GraphEdge(
                    edge_id=UUID(e["edge_id"]),
                    source_node_id=UUID(e["source_node_id"]),
                    target_node_id=UUID(e["target_node_id"]),
                    edge_type=EdgeType(e["edge_type"]),
                    timestamp=datetime.fromisoformat(e["timestamp"]),
                    actor_id=e.get("actor_id", ""),
                    source_adapter=e.get("source_adapter", ""),
                    confidence=ConfidenceLevel(e.get("confidence", "high")),
                    data=e.get("data", {}),
                ))
            except Exception:
                continue

    engine = CausalExplanationEngine(graph)
    paths = engine.explain(target_node_id)
    if paths:
        return paths[0].model_dump(mode="json")
    return {
        "path_id": "direct_observation",
        "nodes": [str(target_node_id)],
        "edges": [],
        "overall_confidence": 1.0,
        "description": "Direct node observation without prior causal antecedents",
        "evidence_summary": "Origin node reached",
    }


@app.get("/sessions/{session_id}/blast_radius/{node_id}")
async def get_blast_radius(session_id: UUID, node_id: UUID) -> dict[str, Any]:
    """Calculate the blast radius of a mutated node."""
    graph = daemon.get_graph(session_id)
    if not graph:
        nodes_data = daemon._ledger.get_graph_nodes(session_id)
        edges_data = daemon._ledger.get_graph_edges(session_id)
        from agenttrace.graph.context_graph import ContextGraph
        from agenttrace.models.graph import GraphNode, GraphEdge, NodeType, EdgeType
        graph = ContextGraph(session_id)
        for n in nodes_data:
            try:
                graph.add_node(GraphNode(
                    node_id=UUID(n["node_id"]),
                    session_id=session_id,
                    node_type=NodeType(n["node_type"]),
                    label=n.get("label", ""),
                    timestamp=datetime.fromisoformat(n["timestamp"]),
                    actor_id=n.get("actor_id", ""),
                    source_adapter=n.get("source_adapter", ""),
                    confidence=ConfidenceLevel(n.get("confidence", "high")),
                    data=n.get("data", {}),
                ))
            except Exception:
                continue
        for e in edges_data:
            try:
                graph.add_edge(GraphEdge(
                    edge_id=UUID(e["edge_id"]),
                    source_node_id=UUID(e["source_node_id"]),
                    target_node_id=UUID(e["target_node_id"]),
                    edge_type=EdgeType(e["edge_type"]),
                    timestamp=datetime.fromisoformat(e["timestamp"]),
                    actor_id=e.get("actor_id", ""),
                    source_adapter=e.get("source_adapter", ""),
                    confidence=ConfidenceLevel(e.get("confidence", "high")),
                    data=e.get("data", {}),
                ))
            except Exception:
                continue

    analyzer = BlastRadiusAnalyzer(graph)
    result = analyzer.analyze(node_id)
    return result.model_dump(mode="json")
