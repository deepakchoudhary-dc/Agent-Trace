"""Tests for the local daemon API: token auth, clean DTOs, redacted graph."""

from __future__ import annotations

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
