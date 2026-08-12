"""AgentTrace local daemon API — FastAPI endpoints.

Exposes session management, event ingestion, graph queries, timeline
replay, policy findings, approvals, and simulation runs via a local
HTTP API consumed by the dashboard.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.blast_radius import BlastRadiusAnalyzer
from agenttrace.graph.causal_engine import CausalExplanationEngine
from agenttrace.graph.replay import ReplayEngine
from agenttrace.models.session import AgentType

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AgentTrace API",
    description="Local daemon API for the AgentTrace causal auditor",
    version="0.1.0",
)

# Allow dashboard to connect from localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global daemon instance
daemon = AgentTraceDaemon()


# -- Request/Response models --

class CreateSessionRequest(BaseModel):
    workspace_path: str
    task_description: str = ""
    agent_type: str = "auto"


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


class SimulationRequest(BaseModel):
    verification_commands: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)


class EventIngestRequest(BaseModel):
    event_type: str
    actor_id: str
    source_adapter: str
    confidence: str = "high"
    payload: dict[str, Any] = Field(default_factory=dict)


# -- Lifecycle --

@app.on_event("startup")
async def startup() -> None:
    await daemon.start()


@app.on_event("shutdown")
async def shutdown() -> None:
    await daemon.stop()


# -- Session endpoints --

@app.post("/sessions", response_model=CreateSessionResponse)
async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
    """Create a new audit session."""
    session = await daemon.create_session(
        workspace_path=req.workspace_path,
        task_description=req.task_description,
        agent_type=AgentType(req.agent_type),
    )

    adapter = daemon._adapters.get(session.session_id)
    gaps = adapter.observability_gaps if adapter else []

    return CreateSessionResponse(
        session_id=str(session.session_id),
        status=session.status,
        workspace_path=session.config.workspace_path,
        adapter=adapter.adapter_name if adapter else "generic",
        observability_gaps=gaps,
    )


@app.get("/sessions")
async def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    sessions = daemon.list_sessions()
    return [
        {
            "session_id": str(s.session_id),
            "workspace_path": s.config.workspace_path,
            "status": s.status,
            "task_description": s.task_description,
            "event_count": s.event_count,
            "started_at": s.started_at.isoformat(),
        }
        for s in sessions
    ]


@app.get("/sessions/{session_id}")
async def get_session(session_id: str) -> dict[str, Any]:
    """Get session details."""
    sid = UUID(session_id)
    session = daemon.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    adapter = daemon._adapters.get(sid)
    return {
        "session_id": str(sid),
        "workspace_path": session.config.workspace_path,
        "status": session.status,
        "task_description": session.task_description,
        "event_count": session.event_count,
        "started_at": session.started_at.isoformat(),
        "adapter": adapter.adapter_name if adapter else "generic",
        "capabilities": adapter.capabilities if adapter else {},
        "observability_gaps": adapter.observability_gaps if adapter else [],
    }


@app.delete("/sessions/{session_id}")
async def stop_session(session_id: str) -> dict[str, str]:
    """Stop a session."""
    sid = UUID(session_id)
    await daemon.stop_session(sid)
    return {"status": "stopped"}


# -- Event endpoints --

@app.post("/sessions/{session_id}/events")
async def ingest_event(session_id: str, req: EventIngestRequest) -> dict[str, str]:
    """Ingest an event into the session."""
    from agenttrace.models.events import ConfidenceLevel, EventBase, EventType

    sid = UUID(session_id)
    session = daemon.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    event = EventBase(
        event_type=EventType(req.event_type),
        actor_id=req.actor_id,
        session_id=sid,
        source_adapter=req.source_adapter,
        confidence=ConfidenceLevel(req.confidence),
        payload=req.payload,
    )

    event_hash = await daemon.ingest_event(event)
    return {"event_hash": event_hash}


# -- Graph endpoints --

@app.get("/sessions/{session_id}/graph")
async def get_graph(session_id: str) -> dict[str, Any]:
    """Get the full Context Graph."""
    sid = UUID(session_id)
    graph = daemon.get_graph(sid)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    return graph.to_dict()


@app.get("/sessions/{session_id}/graph/subgraph/{node_id}")
async def get_subgraph(
    session_id: str,
    node_id: str,
    depth: int = 2,
    direction: str = "both",
) -> dict[str, Any]:
    """Get a subgraph around a specific node."""
    sid = UUID(session_id)
    nid = UUID(node_id)
    graph = daemon.get_graph(sid)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    nodes, edges = graph.get_subgraph(nid, depth, direction)
    return {
        "nodes": [n.model_dump(mode="json") for n in nodes],
        "edges": [e.model_dump(mode="json") for e in edges],
    }


# -- Timeline endpoint --

@app.get("/sessions/{session_id}/timeline")
async def get_timeline(
    session_id: str,
    after: str | None = None,
    before: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Get the event timeline."""
    from agenttrace.models.events import EventType as ET

    sid = UUID(session_id)
    return daemon._ledger.query_events(
        sid,
        event_type=ET(event_type) if event_type else None,
        actor_id=actor_id,
        after=after,
        before=before,
        limit=limit,
    )


# -- Findings endpoint --

@app.get("/sessions/{session_id}/findings")
async def get_findings(session_id: str) -> list[dict[str, Any]]:
    """Get policy findings."""
    sid = UUID(session_id)
    return daemon.get_findings(sid)


# -- Approval endpoints --

@app.post("/sessions/{session_id}/approvals")
async def record_approval(session_id: str, req: ApprovalRequest) -> dict[str, str]:
    """Record an approval or denial."""
    sid = UUID(session_id)
    approval_mgr = daemon.get_approval_manager(sid)
    if not approval_mgr:
        raise HTTPException(status_code=404, detail="Session not found")

    event = approval_mgr.record_approval(
        finding_id=req.finding_id,
        approved=req.approved,
        reason=req.reason,
        scope=req.scope,
        expiry_minutes=req.expiry_minutes,
        affected_paths=req.affected_paths,
        affected_commands=req.affected_commands,
    )

    return {"approval_id": str(event.event_id), "status": "approved" if req.approved else "denied"}


@app.get("/sessions/{session_id}/approvals")
async def get_approvals(session_id: str) -> list[dict[str, Any]]:
    """Get active approvals."""
    sid = UUID(session_id)
    approval_mgr = daemon.get_approval_manager(sid)
    if not approval_mgr:
        raise HTTPException(status_code=404, detail="Session not found")

    approvals = approval_mgr.get_active_approvals()
    return [a.model_dump(mode="json") for a in approvals]


# -- Analysis endpoints --

@app.get("/sessions/{session_id}/causal/{node_id}")
async def get_causal_explanation(
    session_id: str,
    node_id: str,
    max_depth: int = 10,
    max_paths: int = 5,
) -> list[dict[str, Any]]:
    """Get causal explanation paths for a node."""
    sid = UUID(session_id)
    nid = UUID(node_id)
    graph = daemon.get_graph(sid)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    engine = CausalExplanationEngine(graph)
    paths = engine.explain(nid, max_depth, max_paths)
    return [p.model_dump(mode="json") for p in paths]


@app.get("/sessions/{session_id}/blast-radius/{node_id}")
async def get_blast_radius(
    session_id: str,
    node_id: str,
    max_depth: int = 8,
) -> dict[str, Any]:
    """Get blast radius analysis for a node."""
    sid = UUID(session_id)
    nid = UUID(node_id)
    graph = daemon.get_graph(sid)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    analyzer = BlastRadiusAnalyzer(graph)
    result = analyzer.analyze(nid, max_depth)
    return result.model_dump(mode="json")


# -- Simulation endpoint --

@app.post("/sessions/{session_id}/simulate")
async def run_simulation(session_id: str, req: SimulationRequest) -> dict[str, Any]:
    """Run a branch-and-replay simulation."""
    sid = UUID(session_id)
    session = daemon.get_session(sid)
    graph = daemon.get_graph(sid)
    if not session or not graph:
        raise HTTPException(status_code=404, detail="Session not found")

    replay = ReplayEngine(session.config.workspace_path)
    snapshot = graph.to_snapshot()
    config = replay.create_simulation(
        snapshot=snapshot,
        constraints=req.constraints,
        verification_commands=req.verification_commands,
    )
    result = replay.run_simulation(config)

    return {
        "simulation_id": str(result.simulation_id),
        "success": result.success,
        "duration_ms": result.duration_ms,
        "verification_results": result.verification_results,
        "error": result.error,
    }


# -- Report endpoint --

@app.get("/sessions/{session_id}/report")
async def get_report(session_id: str) -> dict[str, Any]:
    """Generate a forensic report."""
    sid = UUID(session_id)
    session = daemon.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    graph = daemon.get_graph(sid)
    contract = daemon.get_contract(sid)
    timeline = daemon.get_timeline(sid)
    findings = daemon.get_findings(sid)

    report: dict[str, Any] = {
        "session_id": str(sid),
        "workspace": session.config.workspace_path,
        "task_description": session.task_description,
        "status": session.status,
        "started_at": session.started_at.isoformat(),
        "stopped_at": session.stopped_at.isoformat() if session.stopped_at else None,
        "event_count": session.event_count,
        "timeline_summary": {
            "total_events": len(timeline),
        },
        "findings_summary": {
            "total_findings": len(findings),
        },
    }

    if contract:
        report["task_contract"] = contract.model_dump(mode="json")

    if graph:
        report["graph_summary"] = {
            "total_nodes": graph.node_count,
            "total_edges": graph.edge_count,
        }

    return report
