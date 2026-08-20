"""Tests for Containerized Replay Isolation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agenttrace.graph.replay import ReplayEngine

if TYPE_CHECKING:
    from pathlib import Path


def test_replay_engine_container_engine_detection(tmp_path: Path) -> None:
    """ReplayEngine detects or cleanly falls back on container engine detection."""
    engine = ReplayEngine(str(tmp_path), container_isolation=True)
    assert engine.container_isolation is True
    # Container engine is either a detected string (docker/podman) or None
    assert engine._container_engine in ("docker", "podman", None)


def test_replay_engine_safe_command_execution(tmp_path: Path) -> None:
    """ReplayEngine executes verification command safely in worktree."""
    engine = ReplayEngine(str(tmp_path), container_isolation=False)
    result = engine._run_command("pytest --version", tmp_path)
    assert result["success"] is True
    assert "pytest" in (result["stdout"] + result["stderr"]).lower()
