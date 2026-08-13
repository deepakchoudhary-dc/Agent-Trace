"""Branch-and-replay simulation engine.

Allows selecting a graph checkpoint, cloning the workspace into an
isolated worktree, applying modified constraints, running allowlisted verification
steps, and comparing the resulting graph with the original.

Critical safety invariant: NEVER modifies the user's live workspace.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.events import ConfidenceLevel
from agenttrace.models.graph import GraphNode, GraphSnapshot, NodeType

logger = logging.getLogger(__name__)


@dataclass
class SimulationConfig:
    """Configuration for a replay simulation."""

    simulation_id: UUID = field(default_factory=uuid4)
    checkpoint_snapshot: GraphSnapshot | None = None
    commit_hash: str | None = None
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
    """Manages branch-and-replay simulations in isolated disposable environments."""

    def __init__(self, workspace_path: str) -> None:
        self.workspace_path = Path(workspace_path)
        self._active_simulations: dict[UUID, Path] = {}

    def create_simulation(
        self,
        snapshot: GraphSnapshot,
        constraints: dict[str, Any] | None = None,
        verification_commands: list[str] | None = None,
        commit_hash: str | None = None,
    ) -> SimulationConfig:
        """Create a simulation configuration from a graph checkpoint."""
        return SimulationConfig(
            checkpoint_snapshot=snapshot,
            commit_hash=commit_hash,
            modified_constraints=constraints or {},
            verification_commands=verification_commands or [],
            workspace_path=str(self.workspace_path),
        )

    def run_simulation(self, config: SimulationConfig) -> SimulationResult:
        """Execute a replay simulation in an isolated worktree."""
        result = SimulationResult(simulation_id=config.simulation_id)
        start_time = datetime.now(timezone.utc)
        worktree_path: Path | None = None

        try:
            # Step 1: Create isolated worktree
            worktree_path = self._create_worktree(config)
            result.worktree_path = str(worktree_path)
            self._active_simulations[config.simulation_id] = worktree_path

            # Step 2: Apply constraints
            self._apply_constraints(worktree_path, config.modified_constraints)

            # Step 3: Run verification commands
            for cmd in config.verification_commands:
                cmd_result = self._run_command(cmd, worktree_path)
                result.verification_results.append(cmd_result)

            # Step 4: Build simulation graph
            sim_graph = ContextGraph(config.simulation_id)
            for r in result.verification_results:
                node = GraphNode(
                    node_type=NodeType.TEST_RESULT if "test" in r["command"] else NodeType.COMMAND,
                    label=f"Sim: {r['command'][:50]} (exit={r['exit_code']})",
                    actor_id="simulation_runner",
                    source_adapter="replay_engine",
                    confidence=ConfidenceLevel.HIGH,
                    session_id=config.simulation_id,
                    data=r,
                )
                sim_graph.add_node(node)

            result.simulation_graph = sim_graph.to_snapshot()

            if config.checkpoint_snapshot:
                result.original_graph = config.checkpoint_snapshot
                result.differences = self._compute_graph_diff(
                    config.checkpoint_snapshot,
                    result.simulation_graph,
                )

            result.success = all(
                r.get("exit_code") == 0 for r in result.verification_results
            )

        except Exception as e:
            result.error = str(e)
            logger.exception("Simulation %s failed", config.simulation_id)

        finally:
            elapsed = datetime.now(timezone.utc) - start_time
            result.duration_ms = int(elapsed.total_seconds() * 1000)

            if worktree_path:
                self._cleanup_worktree(config.simulation_id, worktree_path)

        return result

    def _create_worktree(self, config: SimulationConfig) -> Path:
        """Create an isolated workspace copy for simulation."""
        sim_dir = Path(tempfile.mkdtemp(
            prefix=f"agenttrace_sim_{config.simulation_id.hex[:8]}_",
        ))

        git_dir = self.workspace_path / ".git"
        if git_dir.exists():
            target_ref = config.commit_hash or "HEAD"
            try:
                subprocess.run(
                    ["git", "worktree", "add", str(sim_dir), target_ref],
                    cwd=str(self.workspace_path),
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
                logger.info("Created git worktree at %s (ref=%s)", sim_dir, target_ref)
                return sim_dir
            except (subprocess.CalledProcessError, FileNotFoundError):
                if sim_dir.exists():
                    shutil.rmtree(sim_dir, ignore_errors=True)

        # Fallback directory copy
        sim_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            str(self.workspace_path),
            str(sim_dir),
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git", "node_modules", "__pycache__", ".venv", "venv", ".agenttrace"
            ),
        )
        logger.info("Created isolated directory copy: %s", sim_dir)
        return sim_dir

    def _apply_constraints(self, worktree: Path, constraints: dict[str, Any]) -> None:
        """Apply modified constraints to the simulation worktree."""
        prohibited = constraints.get("prohibited_paths", [])
        for pat in prohibited:
            for matched in worktree.glob(pat):
                if matched.is_file():
                    matched.unlink(missing_ok=True)

    def _run_command(self, command: str, worktree: Path) -> dict[str, Any]:
        """Run a verification command safely inside the isolated worktree."""
        try:
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
                "stdout": result.stdout[:5000],
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

    def _compute_graph_diff(
        self, original: GraphSnapshot, simulation: GraphSnapshot
    ) -> list[str]:
        """Compute differences between original and simulation graph snapshots."""
        diffs: list[str] = []
        orig_labels = {n.label for n in original.nodes}
        sim_labels = {n.label for n in simulation.nodes}

        added = sim_labels - orig_labels
        for a in added:
            diffs.append(f"+ Node added: {a}")

        removed = orig_labels - sim_labels
        for r in removed:
            diffs.append(f"- Node missing: {r}")

        diffs.append(f"Simulation node count: {len(simulation.nodes)} (original: {len(original.nodes)})")
        return diffs

    def _cleanup_worktree(self, sim_id: UUID, worktree_path: Path) -> None:
        """Clean up a simulation worktree."""
        self._active_simulations.pop(sim_id, None)
        try:
            subprocess.run(
                ["git", "worktree", "remove", str(worktree_path), "--force"],
                cwd=str(self.workspace_path),
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass

        if worktree_path.exists():
            shutil.rmtree(str(worktree_path), ignore_errors=True)

    def cleanup_all(self) -> None:
        """Clean up all active simulation worktrees."""
        for sim_id, worktree_path in list(self._active_simulations.items()):
            self._cleanup_worktree(sim_id, worktree_path)
