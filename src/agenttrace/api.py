"""AgentTrace local daemon API — FastAPI endpoints.

Exposes session management, event ingestion, graph queries, timeline,
policy findings, approval recording, chain verification, and simulation runs
via a strictly local loopback HTTP API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.graph.blast_radius import BlastRadiusAnalyzer
from agenttrace.graph.causal_engine import CausalExplanationEngine
from agenttrace.graph.replay import ReplayEngine
from agenttrace.models.events import ConfidenceLevel, EventType, FileMutationEvent
from agenttrace.models.session import AgentType
from agenttrace.review_loop.loop import ReviewLoop
from agenttrace.review_loop.serialization import loop_result_to_dict
from agenttrace.security.token import ApiTokenManager

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AgentTrace API",
    description="Local daemon API for the AgentTrace causal auditor",
    version="0.2.0",
)

daemon = AgentTraceDaemon(os.environ.get("AGENTTRACE_DATA_DIR"))

token_manager = ApiTokenManager(daemon._data_dir)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Bind daemon lifecycle to the ASGI server's startup/shutdown."""
    await daemon.start()
    try:
        yield
    finally:
        await daemon.stop()

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


@app.middleware("http")
async def require_token(request: Request, call_next: Any) -> Response:
    """Authenticate every request except /health via X-AgentTrace-Token.

    The token is scoped to the data directory and created by the daemon at
    startup (see daemon_entry.run_server). Verification is constant-time.
    """
    if request.method == "OPTIONS" or request.url.path == "/health":
        return cast("Response", await call_next(request))
    presented = request.headers.get("X-AgentTrace-Token", "")
    if not token_manager.verify(presented):
        return JSONResponse(status_code=401, content={"detail": "Missing or invalid API token"})
    return cast("Response", await call_next(request))


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe used by the CLI to detect a running daemon (unauthenticated)."""
    return {"status": "ok"}


# -- Request & Response DTO Models --

class CreateSessionRequest(BaseModel):
    workspace_path: str
    task_description: str = ""
    agent_type: str = "auto"
    allowed_paths: list[str] = Field(default_factory=lambda: ["*"])
    prohibited_paths: list[str] = Field(default_factory=lambda: [".env*", "*.pem", "*.key"])
    expected_tests: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    # Declared network boundary for the audited environment (sealed-eval
    # detection). internet_access_allowed=False seals the env: any public
    # egress is a critical finding + unexpected_egress incident.
    internet_access_allowed: bool | None = None
    allowed_destinations: list[str] = Field(default_factory=list)


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


class EvaluateRequest(BaseModel):
    """A proposed action to run through the pre-execution policy gate."""

    action_type: str  # file_mutation | command | network | git
    target: str
    details: dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    session_id: str
    allowed: bool
    action: str = "allow"  # allow | pause | block
    reason: str
    required_approval_id: str = ""


class ReviewRunRequest(BaseModel):
    max_iterations: int = Field(default=3, ge=1, le=5)


# -- Session Endpoints --

@app.post("/sessions", response_model=CreateSessionResponse)
async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
    """Create a new audit session."""
    # N6: the wildcard default ("*") or an empty list defeats every
    # "outside the workspace" check — SandboxEscapeDetector cannot reason
    # about scope, and a literal "*" never matches a real path, producing a
    # false-positive storm. Derive an explicit allowlist from the workspace
    # path instead; explicit caller-provided paths are respected verbatim.
    workspace_resolved = os.path.abspath(req.workspace_path)
    if not req.allowed_paths or "*" in req.allowed_paths:
        allowed_paths = [workspace_resolved]
    else:
        allowed_paths = req.allowed_paths
    try:
        session = await daemon.create_session(
            workspace_path=req.workspace_path,
            task_description=req.task_description,
            agent_type=AgentType(req.agent_type),
            allowed_paths=allowed_paths,
            prohibited_paths=req.prohibited_paths,
            expected_tests=req.expected_tests,
            allowed_tools=req.allowed_tools,
            internet_access_allowed=req.internet_access_allowed,
            allowed_destinations=req.allowed_destinations,
        )
    except Exception as e:
        logger.exception("Failed to create session: %s", e)
        raise HTTPException(status_code=400, detail=str(e)) from e

    adapter = daemon._adapters.get(session.session_id)
    gaps = list(adapter.observability_gaps) if adapter else []
    for observer in daemon._observers.get(session.session_id, []):
        gaps.extend(getattr(observer, "observability_gaps", []))

    return CreateSessionResponse(
        session_id=str(session.session_id),
        status=session.status.value if hasattr(session.status, "value") else str(session.status),
        workspace_path=session.config.workspace_path,
        adapter=adapter.adapter_name if adapter else "generic",
        observability_gaps=sorted(set(gaps)),
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
            "observability_gaps": sorted(
                set(
                    list(getattr(s, "observability_gaps", []) or [])
                    + _collect_session_gaps(s)
                )
            ),
        }
        for s in sessions
    ]


def _collect_session_gaps(session: object) -> list[str]:
    """Aggregate adapter + observer observability gaps for a session."""
    gaps: list[str] = []
    adapter = daemon._adapters.get(session.session_id)  # type: ignore[attr-defined]
    if adapter:
        gaps.extend(adapter.observability_gaps)
    for observer in daemon._observers.get(session.session_id, []):  # type: ignore[attr-defined]
        gaps.extend(getattr(observer, "observability_gaps", []))
    return gaps


@app.get("/sessions/{session_id}")
async def get_session(session_id: UUID) -> dict[str, Any]:
    """Get session details (clean DTO — never raw storage rows)."""
    session = daemon.get_session(session_id)
    if not session:
        # Check storage directly; rebuild the DTO so encrypted columns and
        # internal storage fields are never exposed.
        stored = daemon._ledger.get_session(session_id)
        if not stored:
            raise HTTPException(status_code=404, detail="Session not found")
        try:
            config: dict[str, Any] = json.loads(stored.get("config_json", "{}"))
        except (ValueError, TypeError):
            config = {}
        config = daemon._redactor.redact_any(config)
        return {
            "session_id": str(session_id),
            "workspace_path": str(config.get("workspace_path", "")),
            "status": stored.get("status", "unknown"),
            "task_description": stored.get("task_desc", ""),
            "event_count": stored.get("event_count", 0),
            "last_event_hash": stored.get("last_event_hash", ""),
            "started_at": stored.get("started_at", ""),
            "stopped_at": stored.get("stopped_at"),
        }

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


@app.post("/shutdown")
async def shutdown_daemon() -> dict[str, str]:
    """Stop all sessions, seal the ledger, and exit the daemon process.

    The response is flushed before the process exits (daemon.stop() has
    already persisted and closed the ledger, so no state is lost).
    """
    await daemon.stop()
    threading.Timer(0.5, lambda: os._exit(0)).start()  # noqa: SLF001 (deliberate hard exit after clean close)
    return {"status": "stopped", "message": "AgentTrace daemon shutting down"}


# -- Verification & Integrity Endpoints (P0-1, P0-5) --

@app.get("/sessions/{session_id}/verify", response_model=VerifyResponse)
async def verify_chain(session_id: UUID) -> VerifyResponse:
    """Recompute and verify the entire cryptographic hash chain for a session."""
    session = daemon.get_session(session_id)
    stored = daemon._ledger.get_session(session_id)
    if not session and not stored:
        raise HTTPException(status_code=404, detail="Session not found")

    is_valid, error_msg = daemon._ledger.verify_chain(session_id)
    event_count = session.event_count if session else (stored or {}).get("event_count", 0)
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


# -- Review Loop (P0-7): real artifacts, real verdicts --

@app.post("/sessions/{session_id}/review")
def run_session_review(session_id: UUID, req: ReviewRunRequest | None = None) -> dict[str, Any]:
    """Run the self-improving review loop over a session's real artifacts.

    The Worker gathers the session's actual file mutations as scope, reads
    real file content, and executes allowlisted verification commands
    (`pytest`, `ruff`, `mypy`, ...) against the audited workspace. Reviewers
    judge that real evidence; the result is redacted, persisted encrypted,
    and returned. Runs in the threadpool (verification commands are slow).
    """
    max_iterations = req.max_iterations if req else 3
    session = daemon.get_session(session_id)
    stored = daemon._ledger.get_session(session_id)
    if not session and not stored:
        raise HTTPException(status_code=404, detail="Session not found")

    workspace_path = ""
    task_description = ""
    if session:
        workspace_path = session.config.workspace_path
        task_description = session.task_description
    elif stored:
        try:
            config = json.loads(stored.get("config_json", "{}"))
        except (ValueError, TypeError):
            config = {}
        workspace_path = str(config.get("workspace_path", ""))
        task_description = stored.get("task_desc", "")

    scope_files: list[str] = []
    diff_summaries: dict[str, str] = {}
    for evt in daemon._ledger.query_events(session_id, event_type=EventType.FILE_MUTATION):
        if isinstance(evt, FileMutationEvent):
            if evt.file_path and evt.file_path not in scope_files:
                scope_files.append(evt.file_path)
            if evt.file_path and evt.diff_summary:
                diff_summaries.setdefault(evt.file_path, evt.diff_summary)

    # Only files that still exist can be reviewed — deleted files cannot be
    # read or compiled, and compiling them would fabricate a failure.
    if workspace_path:
        existing: list[str] = []
        for file_path in scope_files:
            candidate = (
                os.path.join(workspace_path, file_path)
                if not os.path.isabs(file_path)
                else file_path
            )
            if os.path.isfile(candidate):
                existing.append(file_path)
        scope_files = existing

    # Never write review lessons into the audited workspace; results are
    # persisted in the ledger via the response path below.
    loop = ReviewLoop(
        workspace_path=workspace_path,
        max_iterations=max_iterations,
        log_lessons=False,
    )
    result = loop.run(task_description or "Untitled session", context={
        "scope_files": scope_files,
        "diff_summaries": diff_summaries,
    })

    payload = loop_result_to_dict(result)
    redacted = cast("dict[str, Any]", daemon._redactor.redact_any(payload))
    daemon._ledger.store_review_run(
        loop_id=result.loop_id,
        session_id=session_id,
        passed=result.final_passed,
        iterations=result.total_iterations,
        payload_json=json.dumps(redacted, ensure_ascii=False),
    )
    return redacted


@app.get("/sessions/{session_id}/review")
def get_session_review(session_id: UUID) -> dict[str, Any]:
    """Return the latest persisted review run for a session."""
    if not daemon.get_session(session_id) and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    runs = daemon._ledger.get_review_runs(session_id)
    if not runs:
        raise HTTPException(status_code=404, detail="No review run recorded for this session")
    latest = runs[0]
    return {
        "loop_id": latest["loop_id"],
        "session_id": latest["session_id"],
        "passed": latest["passed"],
        "iterations": latest["iterations"],
        "created_at": latest["created_at"],
        "payload": latest["payload"],
    }


# -- Policy Findings & Approvals (P0-4, P1-8) --

@app.get("/sessions/{session_id}/findings", response_model=list[FindingDTO])
async def get_findings(session_id: UUID) -> list[FindingDTO]:
    """Get decrypted, redacted policy findings for a session.

    `auto_resolved` is computed at read time: a finding is resolved when an
    active (non-expired) approval covers its exact ID or path/command scope.
    Findings are immutable chain records, so resolution is never written back.
    """
    findings_events = daemon.get_findings(session_id)
    mgr = daemon.get_approval_manager(session_id)
    results: list[FindingDTO] = []
    for evt in findings_events:
        resolved = bool(getattr(evt, "auto_resolved", False))
        if mgr and not resolved:
            resolved = mgr.check_approval(
                finding_id=str(evt.event_id),
                path=getattr(evt, "affected_path", "") or None,
                command=getattr(evt, "affected_command", "") or None,
            )
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
                auto_resolved=resolved,
                timestamp=evt.timestamp.isoformat(),
            )
        )
    return results


@app.post("/sessions/{session_id}/approvals")
async def record_approval(session_id: UUID, req: ApprovalRequest) -> dict[str, Any]:
    """Record an authentic user approval/denial in the ledger and update policy state.

    Single-path recording: the ApprovalManager appends exactly one hash-chained
    ledger event and one approval record; the daemon then projects it into the
    context graph once. Approval scope (paths/commands) is derived from the
    finding when the client did not supply it, so later pre-execution gates on
    the same path/command are honored.
    """
    session = daemon.get_session(session_id)
    if not session and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    mgr = daemon.get_approval_manager(session_id)
    if not mgr:
        raise HTTPException(status_code=409, detail="No active approval manager for this session")

    affected_paths = list(req.affected_paths)
    affected_commands = list(req.affected_commands)
    if not affected_paths and not affected_commands:
        finding_evt = None
        try:
            finding_evt = daemon._ledger.get_event(UUID(req.finding_id))
        except (ValueError, AttributeError):
            finding_evt = None
        if finding_evt is None:
            for evt in daemon.get_findings(session_id):
                if getattr(evt, "finding_type", "") == req.finding_id:
                    finding_evt = evt
                    break
        if finding_evt is not None:
            path = getattr(finding_evt, "affected_path", "") or ""
            command = getattr(finding_evt, "affected_command", "") or ""
            if path:
                affected_paths.append(path)
            if command:
                affected_commands.append(command)

    event = mgr.record_approval(
        finding_id=req.finding_id,
        approved=req.approved,
        reason=req.reason,
        scope=req.scope,
        expiry_minutes=req.expiry_minutes,
        affected_paths=affected_paths,
        affected_commands=affected_commands,
    )

    # Project the approval into the graph/session state exactly once
    await daemon.project_event(event)

    return {
        "status": "recorded",
        "approval_id": str(event.event_id),
        "event_hash": event.event_hash,
        "approved": req.approved,
    }


@app.post("/sessions/{session_id}/evaluate", response_model=EvaluateResponse)
async def evaluate_proposed_action(session_id: UUID, req: EvaluateRequest) -> EvaluateResponse:
    """Pre-execution mediated policy gate (P0-6).

    Evaluate a proposed action before it runs. Returns whether it is allowed,
    the policy action (allow | pause | block), and — when paused — the
    approval ID the user must approve to proceed.
    """
    session = daemon.get_session(session_id)
    if not session and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")

    allowed, reason, approval_id = await daemon.evaluate_proposed_action(
        session_id, req.action_type, req.target, req.details
    )

    if reason.startswith("BLOCKED:"):
        action = "block"
    elif reason.startswith("APPROVAL REQUIRED:"):
        action = "pause"
    else:
        action = "allow"

    return EvaluateResponse(
        session_id=str(session_id),
        allowed=allowed,
        action=action,
        reason=reason,
        required_approval_id=approval_id,
    )


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


@app.get("/sessions/{session_id}/incidents")
async def get_incidents(session_id: UUID) -> list[dict[str, Any]]:
    """List correlated multi-stage incidents for a session (evidence-backed)."""
    if not daemon.get_session(session_id) and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    incidents = daemon.get_incidents(session_id)
    return [e.model_dump(mode="json") for e in incidents]


@app.get("/sessions/{session_id}/collusion")
async def get_collusion(session_id: UUID) -> list[dict[str, object]]:
    """Cross-session coordination signals involving this session.

    Observable half only: shared artifacts, reused egress destinations,
    reused agent identities. Every candidate carries an explicit reasoning
    gap — coordination itself is never claimed.
    """
    if not daemon.get_session(session_id) and not daemon._ledger.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    from agenttrace.graph.collusion import CollusionCorrelationEngine

    engine = CollusionCorrelationEngine(daemon._ledger)
    return [c.to_dict() for c in engine.for_session(session_id)]


@app.get("/sessions/{session_id}/compliance")
async def get_compliance_bundle(session_id: UUID) -> dict[str, Any]:
    """Verifiable compliance evidence manifest (EU AI Act / ISO 42001 / SOC 2)."""
    session_row = daemon._ledger.get_session(session_id)
    if not session_row:
        raise HTTPException(status_code=404, detail="Session not found")
    from agenttrace.security.compliance import build_compliance_bundle

    try:
        config = json.loads(session_row.get("config_json") or "{}")
    except json.JSONDecodeError:
        config = {}
    workspace_path = config.get("workspace_path", "")
    return build_compliance_bundle(
        daemon._ledger,
        session_id,
        workspace_path,
        get_findings=daemon.get_findings(session_id),
        get_incidents=daemon.get_incidents(session_id),
    )


@app.get("/sessions/{session_id}/report")
async def get_forensic_report(session_id: UUID) -> dict[str, Any]:
    """Generate a verified, cryptographically sealed forensic audit report."""
    is_valid, error = daemon._ledger.verify_chain(session_id)
    # No truncation: the report must cover every sealed event.
    events = daemon._ledger.query_events(session_id, limit=None)
    findings = daemon.get_findings(session_id)
    approvals = daemon._ledger.get_approvals(session_id)
    incidents = daemon.get_incidents(session_id)
    last_hash = daemon._ledger.get_last_hash(session_id)

    # Reasoning trail — the model's own thinking around risky actions, from
    # adapter-captured context-boundary events. This is the "why" evidence
    # (Opus rationalizing a real target as part of the exercise; Mythos
    # convincing itself it was still in a simulation).
    reasoning_trail: list[dict[str, Any]] = []
    for evt in events:
        if getattr(evt, "event_type", None) == EventType.CONTEXT_BOUNDARY:
            reasoning = evt.payload.get("reasoning") or ""
            response_text = evt.payload.get("response_text") or ""
            excerpt = reasoning or response_text
            if excerpt:
                # Excerpts leave the sealed store to be rendered in the
                # dashboard/report — run them through the write-boundary
                # redactor so no credential captured in agent reasoning is
                # re-exposed outside the audit view.
                redacted_excerpt = daemon._redactor.redact(str(excerpt))
                reasoning_trail.append({
                    "event_id": str(evt.event_id),
                    "timestamp": evt.timestamp.isoformat(),
                    "kind": evt.payload.get("reasoning_kind", "thinking"),
                    "excerpt": redacted_excerpt[:500],
                })

    manifest = {
        "report_id": str(UUID(int=int.from_bytes(
            hashlib.sha256(f"{session_id}:{last_hash}".encode()).digest()[:16], "big"
        ))),
        "session_id": str(session_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "integrity_status": "TAMPER_VERIFIED" if is_valid else "TAMPER_DETECTED",
        "integrity_error": error,
        "head_event_hash": last_hash,
        "event_count": len(events),
        "findings_count": len(findings),
        "approvals_count": len(approvals),
        "incidents_count": len(incidents),
        "reasoning_trail": reasoning_trail,
        "findings_summary": [
            {
                "finding_id": str(f.event_id),
                "type": getattr(f, "finding_type", "policy_finding"),
                "severity": getattr(f, "severity", "medium"),
                "description": getattr(f, "description", ""),
            }
            for f in findings
        ],
        "incidents_summary": [
            {
                "incident_id": str(i.event_id),
                "incident_type": getattr(i, "incident_type", "incident"),
                "severity": getattr(i, "severity", "medium"),
                "title": getattr(i, "title", ""),
                "related_events": getattr(i, "related_events", []),
            }
            for i in incidents
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

    # Server-side allowlist: never execute arbitrary API-supplied command text
    rejected = [
        cmd for cmd in req.verification_commands
        if not ReplayEngine.verify_command_allowed(cmd)[0]
    ]
    if rejected:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Verification commands not on the server-side allowlist",
                "commands": rejected,
            },
        )

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
        from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType
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
        from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType
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
