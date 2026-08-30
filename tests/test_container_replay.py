"""Tests for Containerized Replay Isolation (plan2.md P0.1: fail closed)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agenttrace.graph.replay import ReplayEngine

if TYPE_CHECKING:
    from pathlib import Path


def test_replay_engine_container_engine_detection(tmp_path: Path) -> None:
    """ReplayEngine detects the container engine or stays fail-closed."""
    engine = ReplayEngine(str(tmp_path), container_isolation=True)
    assert engine.container_isolation is True
    # Container engine is either a detected string (docker/podman) or None
    assert engine._container_engine in ("docker", "podman", None)


def test_replay_without_isolation_fails_closed(tmp_path: Path) -> None:
    """Without container isolation the command must NEVER run on the host."""
    engine = ReplayEngine(str(tmp_path), container_isolation=False)
    result = engine._run_command("pytest --version", tmp_path)
    assert result["success"] is False
    assert "isolation_unavailable" in result["stderr"]

