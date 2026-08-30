"""Tests for the fail-closed IsolationRunner (plan2.md P0.1)."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from agenttrace.security.isolation import IsolationError, IsolationRunner

if TYPE_CHECKING:
    from pathlib import Path


def test_no_engine_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a container runtime, preflight raises isolation_unavailable."""
    monkeypatch.setattr(
        "agenttrace.security.isolation._find_engine_name", lambda: ""
    )
    runner = IsolationRunner()
    with pytest.raises(IsolationError, match="isolation_unavailable"):
        runner.preflight()


def test_run_never_executes_on_host_without_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run() must fail closed — subprocess is never invoked for host exec."""
    monkeypatch.setattr(
        "agenttrace.security.isolation._find_engine_name", lambda: ""
    )

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.run must not be called on the host path")

    monkeypatch.setattr("agenttrace.security.isolation.subprocess.run", _boom)
    runner = IsolationRunner()
    with pytest.raises(IsolationError, match="isolation_unavailable"):
        runner.run(["pytest", "--version"], workspace_path=tmp_path)


def test_run_builds_hardened_container_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The container command disables network, drops caps, limits resources."""
    monkeypatch.setattr(
        "agenttrace.security.isolation._find_engine_name", lambda: "docker"
    )
    captured: dict[str, object] = {}

    class FakeProc:
        returncode = 0
        stdout = "sha256:abc123\n"
        stderr = ""

    def fake_run(cmd: list[str], **kwargs: object) -> FakeProc:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr("agenttrace.security.isolation.subprocess.run", fake_run)

    runner = IsolationRunner(memory_limit_mb=256, pids_limit=64)
    result = runner.run(["pytest", "-q"], workspace_path=tmp_path)

    cmd = captured["cmd"]
    assert cmd[0] == "docker"
    # stdin is always detached: an interactive debugger must never get a tty
    assert captured["kwargs"].get("stdin") == subprocess.DEVNULL
    for flag in (
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
    ):
        assert flag in cmd
    assert "256m" in cmd
    assert "python:3.11-slim" in cmd
    assert cmd[-2:] == ["python:3.11-slim", "pytest"] or "pytest" in cmd
    assert any("/workspace:ro" in part for part in cmd)
    assert result.metadata is not None
    assert result.metadata.image_digest == "sha256:abc123"
    assert result.exit_code == 0 and result.succeeded


def test_missing_image_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A missing container image is isolation_unavailable, not a host run."""
    monkeypatch.setattr(
        "agenttrace.security.isolation._find_engine_name", lambda: "docker"
    )

    class FakeProc:
        returncode = 1
        stdout = ""
        stderr = "No such image"

    monkeypatch.setattr(
        "agenttrace.security.isolation.subprocess.run",
        lambda cmd, **kw: FakeProc(),
    )
    runner = IsolationRunner()
    with pytest.raises(IsolationError, match="isolation_unavailable"):
        runner.run(["pytest"], workspace_path=tmp_path)


def test_invalid_argv_rejected(tmp_path: Path) -> None:
    runner = IsolationRunner()
    with pytest.raises(IsolationError, match="invalid argv"):
        runner.run(["pytest", ""], workspace_path=tmp_path)
