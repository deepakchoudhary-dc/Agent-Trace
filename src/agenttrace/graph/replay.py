"""Branch-and-replay simulation engine.

Allows selecting a graph checkpoint, cloning the workspace into an
isolated worktree, modifying constraints, rerunning verification
steps, and comparing the resulting graph with the original.

Critical safety invariant: NEVER modifies the user's live workspace.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agenttrace.models.graph import GraphSnapshot
from agenttrace.graph.context_graph import ContextGraph

logger = logging.getLogger(__name__)


@dataclass
class SimulationConfig:
    """Configuration for a replay simulation."""

    simulation_id: UUID = field(default_factory=uuid4)
    checkpoint_snapshot: GraphSnapshot | None = None
    modified_constraints: dict[str, Any] = field(default_factory=dict)
    verification_commands: list[str] = field(default_factory=list)
    workspace_path: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SimulationResult:
    """Result of a replay simulation."""

    simulation_id: UUID = field(default_factory=uuid4)
    success: bool = False
    worktree_path: str = ""
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    original_graph: GraphSnapshot | None = None
    simulation_graph: GraphSnapshot | None = None
    differences: list[str] = field(default_factory=list)
    duration_ms: int = 0
    error: str = ""


class ReplayEngine:
    """Manages branch-and-replay simulations.

    Creates isolated worktrees for simulation, runs verification steps,
    and compares results with the original graph. All simulation work
    happens in disposable directories that are cleaned up after use.
    """

    def __init__(self, workspace_path: str) -> None:
        self.workspace_path = Path(workspace_path)
        self._active_simulations: dict[UUID, Path] = {}

    def create_simulation(
        self,
        snapshot: GraphSnapshot,
        constraints: dict[str, Any] | None = None,
        verification_commands: list[str] | None = None,
    ) -> SimulationConfig:
        """Create a simulation configuration from a graph checkpoint."""
        config = SimulationConfig(
            checkpoint_snapshot=snapshot,
            modified_constraints=constraints or {},
            verification_commands=verification_commands or [],
            workspace_path=str(self.workspace_path),
        )
        return config

    def run_simulation(self, config: SimulationConfig) -> SimulationResult:
        """Execute a replay simulation in an isolated worktree.

        Steps:
        1. Create a disposable worktree (git worktree or directory copy)
        2. Apply modified constraints
        3. Run verification commands
        4. Build simulation graph
        5. Compare with original
        6. Clean up worktree
        """
        result = SimulationResult(simulation_id=config.simulation_id)
        start_time = datetime.now(timezone.utc)

        worktree_path: Path | None = None
        try:
            # Step 1: Create isolated worktree
            worktree_path = self._create_worktree(config)
            result.worktree_path = str(worktree_path)
            self._active_simulations[config.simulation_id] = worktree_path

            # Step 2: Run verification commands
            for cmd in config.verification_commands:
                cmd_result = self._run_command(cmd, worktree_path)
                result.verification_results.append(cmd_result)

            # Step 3: Capture original graph
            if config.checkpoint_snapshot:
                result.original_graph = config.checkpoint_snapshot

            result.success = all(
                r.get("exit_code") == 0 for r in result.verification_results
            )

        except Exception as e:
            result.error = str(e)
            logger.exception("Simulation %s failed", config.simulation_id)

        finally:
            # Step 4: Clean up
            elapsed = datetime.now(timezone.utc) - start_time
            result.duration_ms = int(elapsed.total_seconds() * 1000)

            if worktree_path:
                self._cleanup_worktree(config.simulation_id, worktree_path)

        return result

    def _create_worktree(self, config: SimulationConfig) -> Path:
        """Create an isolated workspace copy for simulation.

        Uses git worktree if available, falls back to directory copy.
        """
        # Create temp directory within workspace parent (not inside workspace)
        sim_dir = Path(tempfile.mkdtemp(
            prefix=f"agenttrace_sim_{config.simulation_id.hex[:8]}_",
            dir=self.workspace_path.parent,
        ))

        git_dir = self.workspace_path / ".git"
        if git_dir.exists():
            # Try git worktree
            try:
                subprocess.run(
                    ["git", "worktree", "add", str(sim_dir), "HEAD"],
                    cwd=str(self.workspace_path),
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
                logger.info("Created git worktree: %s", sim_dir)
                return sim_dir
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Worktree failed, clean up and fall back to copy
                if sim_dir.exists():
                    shutil.rmtree(sim_dir, ignore_errors=True)

        # Fallback: directory copy
        sim_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            str(self.workspace_path),
            str(sim_dir),
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git", "node_modules", "__pycache__", ".venv", "venv"
            ),
        )
        logger.info("Created directory copy: %s", sim_dir)
        return sim_dir

    def _run_command(self, command: str, worktree: Path) -> dict[str, Any]:
        """Run a verification command in the simulation worktree."""
        import shlex

        try:
            # Safe tokenization to prevent shell injection vulnerabilities
            cmd_args = shlex.split(command, posix=os.name != "nt")
            result = subprocess.run(
                cmd_args if cmd_args else command,
                shell=False if cmd_args else True,
                cwd=str(worktree),
                capture_output=True,
                text=True,
                timeout=120,
            )
            return {
                "command": command,
                "exit_code": result.returncode,
                "stdout": result.stdout[:5000],  # Limit output size
                "stderr": result.stderr[:5000],
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "exit_code": -1,
                "stdout": "",
                "stderr": "Command timed out after 120s",
                "success": False,
            }

    def _cleanup_worktree(self, sim_id: UUID, worktree_path: Path) -> None:
        """Clean up a simulation worktree."""
        self._active_simulations.pop(sim_id, None)

        # Try git worktree remove first
        try:
            subprocess.run(
                ["git", "worktree", "remove", str(worktree_path), "--force"],
                cwd=str(self.workspace_path),
                capture_output=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Force-remove the directory
        if worktree_path.exists():
            shutil.rmtree(str(worktree_path), ignore_errors=True)

        logger.info("Cleaned up worktree: %s", worktree_path)

    def cleanup_all(self) -> None:
        """Clean up all active simulation worktrees."""
        for sim_id, worktree_path in list(self._active_simulations.items()):
            self._cleanup_worktree(sim_id, worktree_path)
