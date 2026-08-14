"""Tests for the shield — the mediated execution gate (launcher mediation).

BLOCKED commands are refused before execution; APPROVAL REQUIRED commands
pause for scoped consent; ALLOWED commands execute. `install` writes PATH
wrappers that route agent-launched tools through the gate.
"""

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from click.testing import CliRunner

from agenttrace.cli import shield
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.session import AgentType


@pytest.fixture()
def no_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the CLI's API client at an unroutable port so it falls back to
    the local ledger, and pin the daemon data dir to the test area."""
    monkeypatch.setattr("agenttrace.cli._DEFAULT_API_URL", "http://127.0.0.1:59999")


def _make_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    data_dir = tmp_path / ".agenttrace"
    monkeypatch.setattr("agenttrace.daemon._DEFAULT_DATA_DIR", str(data_dir))

    import asyncio

    async def _create() -> str:
        daemon = AgentTraceDaemon(data_dir)
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=str(tmp_path),
            task_description="shield test",
            agent_type=AgentType.GENERIC,
        )
        sid = str(session.session_id)
        await daemon.stop()
        return sid

    return asyncio.run(_create())


class TestShieldVerdicts:
    def test_blocked_command_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_api: None) -> None:
        sid = _make_session(tmp_path, monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            shield, ["check", sid, "sudo", "rm", "-rf", "/"]
        )
        assert result.exit_code == 2, result.output
        assert "BLOCKED" in result.output

    def test_risky_command_pauses(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_api: None) -> None:
        sid = _make_session(tmp_path, monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            shield, ["check", sid, "pip", "install", "requests"]
        )
        assert result.exit_code == 0, result.output
        assert "APPROVAL REQUIRED" in result.output

    def test_safe_command_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_api: None) -> None:
        sid = _make_session(tmp_path, monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            shield, ["check", sid, "pytest", "tests/"]
        )
        assert result.exit_code == 0, result.output
        assert "ALLOWED" in result.output

    def test_run_executes_allowed_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_api: None, capfd: pytest.CaptureFixture[str]
    ) -> None:
        sid = _make_session(tmp_path, monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            shield, ["run", sid, "--", sys.executable, "-c", "print(42)"]
        )
        assert result.exit_code == 0, result.output
        # The allowed command's subprocess writes to the OS-level stdout fd,
        # so capfd (fd-level capture) sees it — capsys (sys-level) does not.
        captured = capfd.readouterr()
        assert "42" in captured.out


class TestShieldInstall:
    def test_writes_path_wrappers(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sid = str(uuid4())
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
