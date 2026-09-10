"""API boundary hardening tests (plan2.md P2.2/P2.3).

Covers: pagination contracts (limit/offset + X-Total-Count) on collection
endpoints, server-side input limits on request DTOs, the request body size
cap, and CORS origin restrictions.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import agenttrace.api as api
from agenttrace.api import MAX_BODY_BYTES
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import (
    CommandEvent,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
    PolicyFindingEvent,
)
from agenttrace.security.token import ApiTokenManager


@pytest.fixture()
def daemon_env(tmp_path, monkeypatch):
    """Point the API module at an isolated data dir and daemon instance."""
    test_daemon = AgentTraceDaemon(tmp_path)
    test_tokens = ApiTokenManager(tmp_path)
    monkeypatch.setattr(api, "daemon", test_daemon)
    monkeypatch.setattr(api, "token_manager", test_tokens)
    monkeypatch.setenv("AGENTTRACE_DATA_DIR", str(tmp_path))
    return test_daemon, test_tokens


@pytest.fixture()
def client(daemon_env):
    with TestClient(api.app) as c:
        yield c, daemon_env


def _auth_headers(tokens: ApiTokenManager) -> dict[str, str]:
    return {"X-AgentTrace-Token": tokens.token()}


def _create_session(client: TestClient, tokens: ApiTokenManager, workspace: str) -> str:
    res = client.post(
        "/sessions",
        json={
            "workspace_path": workspace,
            "task_description": "boundary tests",
            "agent_type": "generic",
        },
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 200, res.text
    return res.json()["session_id"]


async def _seed_events(test_daemon: AgentTraceDaemon, sid: str, count: int) -> None:
    """Persist ``count`` command events into the session ledger."""
    session = test_daemon.get_session(UUID(sid))
    assert session is not None
    for i in range(count):
        await test_daemon.ingest_event(
            CommandEvent(
                session_id=session.session_id,
                actor_id="test-agent",
                source_adapter="test",
                command=f"echo page-{i}",
            )
        )


def _seed_event(collection: str, session: object, i: int, workspace: str) -> object:
    """One event of the type backing ``collection`` (i-th of a series)."""
    if collection == "timeline":
        return CommandEvent(
            session_id=session.session_id,  # type: ignore[attr-defined]
            actor_id="test-agent",
            source_adapter="test",
            command=f"echo page-{i}",
        )
    if collection == "diffs":
        return FileMutationEvent(
            session_id=session.session_id,  # type: ignore[attr-defined]
            actor_id="test-agent",
            source_adapter="test",
            # Absolute in-workspace path: relative paths are treated as
            # out-of-scope by the boundary check and flagged as escapes.
            file_path=str(Path(workspace) / f"page_{i}.py"),
            mutation_type="modify",
            before_hash="",
            after_hash=f"h{i}",
            diff_summary=f"diff {i}",
        )
    if collection == "findings":
        return PolicyFindingEvent(
            session_id=session.session_id,  # type: ignore[attr-defined]
            actor_id="test-agent",
            source_adapter="test",
            finding_type="probe",
            severity="medium",
            description=f"finding {i}",
        )
    return IncidentEvent(
        session_id=session.session_id,  # type: ignore[attr-defined]
        actor_id="test-agent",
        source_adapter="test",
        incident_type="probe",
        severity="medium",
        title=f"incident {i}",
        description=f"incident {i}",
    )


# -- Pagination contracts (P2.2) ----------------------------------------------

PAGE_PATHS = ("timeline", "diffs", "findings", "incidents")


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", PAGE_PATHS)
async def test_collection_pages_respect_limit_and_offset(client, tmp_path, collection):
    """limit/offset slice every collection; X-Total-Count carries the full size."""
    c, (test_daemon, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))
    session = test_daemon.get_session(UUID(sid))
    assert session is not None
    for i in range(5):
        evt = _seed_event(collection, session, i, tmp_path)
        assert isinstance(evt, EventBase)
        await test_daemon.ingest_event(evt)

    res = c.get(
        f"/sessions/{sid}/{collection}?limit=2&offset=1",
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 200, res.text
    total = int(res.headers["X-Total-Count"])
    assert total >= 5
    assert len(res.json()) == min(2, total - 1)

    full = c.get(f"/sessions/{sid}/{collection}", headers=_auth_headers(tokens))
    assert full.status_code == 200
    assert int(full.headers["X-Total-Count"]) == total
    assert len(full.json()) == total


@pytest.mark.asyncio
async def test_timeline_pages_concatenate_exactly(client, tmp_path):
    """Paging through the timeline yields every event exactly once, in order."""
    c, (test_daemon, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))
    await _seed_events(test_daemon, sid, 7)

    headers = _auth_headers(tokens)
    first = c.get(f"/sessions/{sid}/timeline?limit=1&offset=0", headers=headers)
    assert first.status_code == 200
    total = int(first.headers["X-Total-Count"])
    assert total >= 7

    flat: list[dict] = []
    offset = 0
    while offset < total:
        res = c.get(
            f"/sessions/{sid}/timeline?limit=3&offset={offset}", headers=headers
        )
        assert res.status_code == 200
        page = res.json()
        if not page:
            break  # background projections grew the session mid-walk
        flat.extend(page)
        offset += 3
    # Pages never overlap and never lose events (dedupe by event hash).
    assert len({e["event_hash"] for e in flat}) == len(flat)
    seeded = [e["command"] for e in flat if e.get("command", "").startswith("echo page-")]
    assert seeded == [f"echo page-{i}" for i in range(7)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("query", "fragment"),
    [
        ("limit=0", "limit must be between 1"),
        ("limit=501", "limit must be between 1"),
        ("offset=-1", "offset must be non-negative"),
    ],
)
async def test_bad_pagination_is_rejected(client, tmp_path, query, fragment):
    """Out-of-range limit/offset values are rejected, not silently clamped."""
    c, (_, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))
    res = c.get(
        f"/sessions/{sid}/timeline?{query}", headers=_auth_headers(tokens)
    )
    assert res.status_code == 422
    assert fragment in str(res.json())


def test_sessions_list_bounded_and_counted(client, tmp_path):
    """/sessions honors limit and reports the total in X-Total-Count."""
    c, (_, tokens) = client
    for _ in range(3):
        _create_session(c, tokens, str(tmp_path))
    res = c.get("/sessions?limit=2", headers=_auth_headers(tokens))
    assert res.status_code == 200
    assert len(res.json()) == 2
    assert res.headers["X-Total-Count"] == "3"



# -- Input limits (P2.3) -------------------------------------------------------

def test_oversize_task_description_is_rejected(client, tmp_path):
    """Server-side string caps reject oversized inputs with 422."""
    c, (_, tokens) = client
    res = c.post(
        "/sessions",
        json={
            "workspace_path": str(tmp_path),
            "task_description": "x" * 8193,
            "agent_type": "generic",
        },
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 422
    body = str(res.json())
    assert "task_description" in body or "String should have at most" in body


def test_oversize_path_field_is_rejected(client, tmp_path):
    """The 1 KiB path bound holds even when the path itself is hostile."""
    c, (_, tokens) = client
    res = c.post(
        "/sessions",
        json={
            "workspace_path": "C:" + "\\" + "x" * 2000,
            "agent_type": "generic",
        },
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 422


@pytest.mark.parametrize(
    "field",
    ["allowed_paths", "prohibited_paths", "expected_tests", "allowed_tools"],
)
def test_oversize_list_field_is_rejected(client, tmp_path, field):
    """List inputs are bounded server-side (128/128/256/256 entries)."""
    c, (_, tokens) = client
    res = c.post(
        "/sessions",
        json={
            "workspace_path": str(tmp_path),
            "agent_type": "generic",
            field: ["item"] * 300,
        },
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_timeline_limit_above_page_cap_is_rejected(client, tmp_path):
    """/timeline refuses limits beyond the hard page cap (500)."""
    c, (test_daemon, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))
    await _seed_events(test_daemon, sid, 1)
    res = c.get(
        f"/sessions/{sid}/timeline?limit={api.MAX_PAGE_LIMIT + 1}",
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 422


# -- Request body cap (P2.3) ---------------------------------------------------

def test_oversize_body_is_rejected_with_413(client):
    """A declared body larger than 1 MiB is rejected before any handler runs."""
    c, (_, tokens) = client
    huge = MAX_BODY_BYTES + 1
    res = c.post(
        "/sessions",
        content=b"x" * huge,
        headers={
            **_auth_headers(tokens),
            "Content-Type": "application/json",
            "Content-Length": str(huge),
        },
    )
    assert res.status_code == 413
    assert "too large" in res.text


# -- CORS origin checks (P2.2) -------------------------------------------------

def test_cors_rejects_unknown_origin(client):
    """CORS allowlist is loopback-only: foreign origins get no echo header."""
    c, (_, tokens) = client
    res = c.get(
        "/health",
        headers={"Origin": "http://evil.example.com"},
    )
    assert res.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in res.headers}


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
)
def test_cors_allows_only_loopback_dev_origins(client, origin):
    """The dev-UI loopback origins remain the only reflected origins."""
    c, (_, tokens) = client
    res = c.get("/health", headers={"Origin": origin})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == origin

