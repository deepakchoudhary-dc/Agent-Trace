"""Tests for the local daemon API: token auth, clean DTOs, redacted graph."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import agenttrace.api as api
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.events import CommandEvent
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
            "task_description": "test task",
            "agent_type": "generic",
        },
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 200, res.text
    return res.json()["session_id"]


def test_health_is_unauthenticated(client):
    c, _ = client
    res = c.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_missing_token_is_rejected(client):
    c, _ = client
    res = c.get("/sessions")
    assert res.status_code == 401


def test_invalid_token_is_rejected(client):
    c, _ = client
    res = c.get("/sessions", headers={"X-AgentTrace-Token": "not-the-token"})
    assert res.status_code == 401


def test_valid_token_accepted(client):
    c, (_, tokens) = client
    res = c.get("/sessions", headers=_auth_headers(tokens))
    assert res.status_code == 200
    assert res.json() == []


def test_rotate_token_invalidates_old(client):
    c, (_, tokens) = client
    old = tokens.token()
    assert c.get("/sessions", headers={"X-AgentTrace-Token": old}).status_code == 200
    tokens.rotate()
    assert c.get("/sessions", headers={"X-AgentTrace-Token": old}).status_code == 401


def test_session_dto_from_storage_has_no_encrypted_columns(client, tmp_path):
    c, (test_daemon, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))

    # Simulate a daemon restart: in-memory session gone, storage remains.
    test_daemon._sessions.clear()
    res = c.get(f"/sessions/{sid}", headers=_auth_headers(tokens))
    assert res.status_code == 200
    body = res.json()
    assert body["session_id"] == sid
    assert body["workspace_path"] == str(tmp_path)
    assert not any(key.startswith("_enc") for key in body)
    assert "config" not in body
    assert body["status"]


@pytest.mark.asyncio
async def test_graph_nodes_never_contain_secrets(client, tmp_path):
    c, (test_daemon, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))

    session = test_daemon.get_session(UUID(sid))
    assert session is not None
    await test_daemon.project_event(
        CommandEvent(
            session_id=session.session_id,
            actor_id="test-agent",
            source_adapter="test",
            command="curl -H 'Authorization: Bearer sk-secretvalue12345' https://example.com/api",
        )
    )

    res = c.get(f"/sessions/{sid}/graph", headers=_auth_headers(tokens))
    assert res.status_code == 200
    body = res.json()
    serialized = str(body)
    assert "sk-secretvalue12345" not in serialized
    assert any(n["node_type"] == "command" for n in body.get("nodes", []))


# -- Review loop endpoints (P0-7) --

GOOD_MODULE = '''\
"""Math utilities."""

from __future__ import annotations


def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b
'''

GOOD_TEST = '''\
"""Tests for math utilities."""

from __future__ import annotations

from math_utils import add


def test_add() -> None:
    """Addition works."""
    assert add(1, 2) == 3
'''


def _make_workspace(tmp_path) -> str:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "math_utils.py").write_text(GOOD_MODULE, encoding="utf-8")
    (ws / "test_math_utils.py").write_text(GOOD_TEST, encoding="utf-8")
    return str(ws)


async def _append_file_mutation(client, tokens, sid: str, workspace: str) -> None:
    from agenttrace.models.events import FileMutationEvent

    session = api.daemon.get_session(UUID(sid))
    assert session is not None
    await api.daemon.ingest_event(
        FileMutationEvent(
            session_id=session.session_id,
            actor_id="test-agent",
            source_adapter="test",
            file_path="math_utils.py",
            mutation_type="modify",
            before_hash="",
            after_hash="abc",
            diff_summary="added add()",
        )
    )
    _ = client, tokens, workspace


@pytest.mark.asyncio
async def test_review_run_endpoint_produces_real_verdicts(client, tmp_path):
    c, (test_daemon, tokens) = client
    workspace = _make_workspace(tmp_path)
    sid = _create_session(c, tokens, workspace)
    await _append_file_mutation(c, tokens, sid, workspace)

    res = c.post(f"/sessions/{sid}/review", headers=_auth_headers(tokens))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["loop_id"]
    assert body["final_passed"] is True
    assert body["total_iterations"] >= 1
    assert body["iterations"][0]["review_results"]
    names = {r["reviewer_name"] for r in body["iterations"][0]["review_results"]}
    assert names == {"spec_compliance", "security", "convention"}
    assert any("math_utils.py" in s for s in body["scope_files"])


@pytest.mark.asyncio
async def test_review_run_endpoint_redacts_secrets(client, tmp_path):
    c, (test_daemon, tokens) = client
    workspace = _make_workspace(tmp_path)
    # A real file in the audited workspace containing a credential
    (Path(workspace) / "app_config.py").write_text(
        'token = "sk-verysecretapikey12345"\n',
        encoding="utf-8",
    )
    sid = _create_session(c, tokens, workspace)
    from agenttrace.models.events import FileMutationEvent

    session = test_daemon.get_session(UUID(sid))
    assert session is not None
    await test_daemon.ingest_event(
        FileMutationEvent(
            session_id=session.session_id,
            actor_id="test-agent",
            source_adapter="test",
            file_path="app_config.py",
            mutation_type="create",
            before_hash="",
            after_hash="def",
            diff_summary="added app config",
        )
    )

    res = c.post(f"/sessions/{sid}/review", headers=_auth_headers(tokens))
    assert res.status_code == 200, res.text
    assert "sk-verysecretapikey12345" not in str(res.json())


@pytest.mark.asyncio
async def test_review_run_persisted_and_fetchable(client, tmp_path):
    c, (test_daemon, tokens) = client
    workspace = _make_workspace(tmp_path)
    sid = _create_session(c, tokens, workspace)
    await _append_file_mutation(c, tokens, sid, workspace)

    res = c.post(f"/sessions/{sid}/review", headers=_auth_headers(tokens))
    assert res.status_code == 200, res.text
    loop_id = res.json()["loop_id"]

    got = c.get(f"/sessions/{sid}/review", headers=_auth_headers(tokens))
    assert got.status_code == 200
    stored = got.json()
    assert stored["loop_id"] == loop_id
    assert stored["passed"] is True
    assert stored["payload"]["final_passed"] is True


def test_review_run_requires_existing_session(client):
    c, (_, tokens) = client
    res = c.post(
        f"/sessions/{UUID(int=1)}/review",
        headers=_auth_headers(tokens),
    )
    assert res.status_code == 404


def test_review_run_missing_record_returns_404(client, tmp_path):
    c, (_, tokens) = client
    sid = _create_session(c, tokens, str(tmp_path))
    res = c.get(f"/sessions/{sid}/review", headers=_auth_headers(tokens))
    assert res.status_code == 404
