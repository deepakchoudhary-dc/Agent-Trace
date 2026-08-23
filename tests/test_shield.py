"""Tests for the shield — the mediated execution gate (launcher mediation).

BLOCKED commands are refused before execution; APPROVAL REQUIRED commands
pause for scoped consent; ALLOWED commands execute. `install` writes PATH
wrappers that route agent-launched tools through the gate.

Every test runs against a REAL detached daemon over HTTP: the CLI must never
fall back to direct ledger access, so verdicts and approvals are exercised
end-to-end through the API.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from contextlib import suppress
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from agenttrace.cli import _call_api, main, shield
from agenttrace.daemon_entry import spawn_daemon, wait_until_running

if TYPE_CHECKING:
    from pathlib import Path


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture()
def live_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Spawn a real detached daemon for the test's data dir and point the CLI at it."""
    data_dir = tmp_path / ".agenttrace"
    port = _free_port()
    monkeypatch.setenv("AGENTTRACE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("AGENTTRACE_PORT", str(port))
    spawn_daemon(data_dir, port)
    assert wait_until_running(data_dir, port, timeout=20), "daemon failed to start"
    yield data_dir, port
    # Shut the daemon down cleanly (it owns the ledger; never kill -9).
    with suppress(Exception):
        _call_api("/shutdown", method="POST")


def _create_session(data_dir: Path, port: int, workspace: str) -> str:
    token = (data_dir / "api_token").read_text(encoding="utf-8").strip()
    payload = json.dumps(
        {"workspace_path": workspace, "task_description": "shield test", "agent_type": "generic"}
    ).encode()
    req = urllib.request.Request(  # noqa: S310 (loopback only)
        f"http://127.0.0.1:{port}/sessions",
        method="POST",
        data=payload,
        headers={"Content-Type": "application/json", "X-AgentTrace-Token": token},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
        return json.loads(resp.read().decode())["session_id"]


class TestShieldVerdicts:
    def test_blocked_command_refused(self, tmp_path: Path, live_daemon) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(shield, ["check", sid, "sudo", "rm", "-rf", "/"])
        assert result.exit_code == 2, result.output
        assert "BLOCKED" in result.output

    def test_risky_command_pauses(self, tmp_path: Path, live_daemon) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(shield, ["check", sid, "pip", "install", "requests"])
        assert result.exit_code == 0, result.output
        assert "APPROVAL REQUIRED" in result.output

    def test_safe_command_allowed(self, tmp_path: Path, live_daemon) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(shield, ["check", sid, "pytest", "tests/"])
        assert result.exit_code == 0, result.output
        assert "ALLOWED" in result.output

    def test_run_executes_allowed_command(
        self, tmp_path: Path, live_daemon, capfd: pytest.CaptureFixture[str]
    ) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(shield, ["run", sid, "--", sys.executable, "-c", "print(42)"])
        assert result.exit_code == 0, result.output
        # The allowed command's subprocess writes to the OS-level stdout fd,
        # so capfd (fd-level capture) sees it — capsys (sys-level) does not.
        captured = capfd.readouterr()
        assert "42" in captured.out

    def test_approve_records_through_api(self, tmp_path: Path, live_daemon) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        # Approve a real policy rule id (pre-execution gates pause on rule
        # ids before any finding exists). Arbitrary ids like "finding-x" are
        # rejected by the API with 404.
        result = runner.invoke(
            main,
            ["approve", "destructive_file_op", "--scope", "/some/path", "--session-id", sid],
        )
        assert result.exit_code == 0, result.output
        assert "Approval granted" in result.output
        # The approval was recorded in the daemon's ledger, not a CLI-side copy.
        status = _call_api(f"/sessions/{sid}/verify")
        assert isinstance(status, dict) and status["verified"] is True

    def test_approve_rejects_unknown_finding(self, tmp_path: Path, live_daemon) -> None:
        data_dir, port = live_daemon
        sid = _create_session(data_dir, port, str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(
            main, ["approve", "finding-x", "--scope", "/some/path", "--session-id", sid]
        )
        assert "Unknown finding" in result.output or "404" in result.output


class TestShieldInstall:
    def test_writes_path_wrappers(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sid = "00000000-0000-0000-0000-000000000000"
        runner = CliRunner()
        result = runner.invoke(
            shield, ["install", sid, "--workspace", str(workspace)]
        )
        assert result.exit_code == 0, result.output

        bin_dir = workspace / ".agenttrace" / "shield" / "bin"
        for tool in ["git", "npm", "python", "curl"]:
            bash_wrapper = bin_dir / tool
            assert bash_wrapper.exists(), f"missing wrapper {tool}"
            assert sid in bash_wrapper.read_text(encoding="utf-8")
            assert (bin_dir / f"{tool}.cmd").exists()


def test_cli_fails_loudly_when_daemon_is_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: no silent fallback — a stopped daemon must not allow writes."""
    data_dir = tmp_path / ".agenttrace"
    monkeypatch.setenv("AGENTTRACE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("AGENTTRACE_PORT", str(_free_port()))
    runner = CliRunner()
    result = runner.invoke(main, ["verify", "00000000-0000-0000-0000-000000000000"])
    assert result.exit_code == 0
    assert "Daemon not reachable" in result.output or "not running" in result.output
    assert "TAMPER" not in result.output
