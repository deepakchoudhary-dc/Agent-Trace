"""Branch-and-replay simulation engine.

Allows selecting a graph checkpoint, cloning the workspace into an
isolated worktree, applying modified constraints, running allowlisted verification
steps, and comparing the resulting graph with the original.

Critical safety invariant: NEVER modifies the user's live workspace.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid4

from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.events import ConfidenceLevel
from agenttrace.models.graph import GraphNode, GraphSnapshot, NodeType

logger = logging.getLogger(__name__)


def _venv_bin_dir() -> str:
    """PATH prefix for the active environment's executables (Scripts on Windows)."""
    scripts = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
    return str(scripts) + os.pathsep + os.environ.get("PATH", "")


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
    """Manages branch-and-replay simulations in isolated disposable environments.

    Verification commands are restricted to a server-side allowlist — arbitrary
    API-supplied command text is never executed (P1-7 hardening).
    """

    # Test runners allowed inside simulations, with their permitted subcommands
    _PYTHON_MODULES = {"pytest", "unittest", "py_compile"}
    _JS_PACKAGE_MANAGERS = {"npm", "yarn", "pnpm"}
    # Read-only linters/type checkers: safe to run in a workspace
    _STATIC_TOOLS = {"pytest", "ruff", "mypy"}

    # Dangerous interpreter-hook, library-preload, and injection environment variables
    _DANGEROUS_ENV_VARS = frozenset({
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSAFEPATH",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PERLLIB",
        "PERL5LIB",
        "RUBYOPT",
        "CLASSPATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
    })

    def __init__(self, workspace_path: str, container_isolation: bool = False) -> None:
        self.workspace_path = Path(workspace_path)
        self._active_simulations: dict[UUID, Path] = {}
        self.container_isolation = container_isolation
        self._container_engine = self._find_container_engine()

    @staticmethod
    def _find_container_engine() -> str | None:
        """Find an available container runner (docker or podman)."""
        for engine in ("docker", "podman"):
            if shutil.which(engine):
                return engine
        return None

    @staticmethod
    def verify_command_allowed(command: str) -> tuple[bool, str]:
        """Check a verification command against the server-side allowlist.

        Allows only well-known, non-destructive test runners and rejects shell
        metacharacters and arbitrary executables. Returns (allowed, reason).
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Backticks are stripped as quote chars by shlex, so reject them on the
        # raw string before parsing (command substitution: `id`, `cat x`)
        if "`" in command:
            return False, "Command substitution (backticks) is not allowed"

        try:
            parts = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return False, "Unparseable command"
        if not parts:
            return False, "Empty command"

        # Reject shell control operators / redirection outright
        if any(tok in parts for tok in ("&&", "||", ";", "|", ">", "<")):
            return False, "Shell control operators and redirection are not allowed"
        if any("$(" in tok or "${ " in tok for tok in parts):
            return False, "Command substitution is not allowed"

        # Reject interactive/debug hooks: `pytest --pdb` spawns a debugger
        # on the child's stdin, `go test -exec` / `-execx` runs arbitrary
        # binaries, and `-s` on pytest keeps stdout (harmless alone but a
        # common first step of interactive rigging). Anything interactive
        # must fail closed inside a replay.
        if any(tok.startswith(("--pdb", "--pdbcls")) for tok in parts):
            return False, "Interactive debugger flags (--pdb) are not allowed in replays"
        if any(tok in ("-exec", "-execx") for tok in parts):
            return False, "`-exec` is not allowed in replays (arbitrary binary execution)"
        if any(tok in ("--capture=no", "-s", "--showlocals") for tok in parts):
            return False, "Interactive test flags are not allowed in replays"

        base = Path(parts[0]).name.lower().removesuffix(".exe")

        # python -m pytest | python -m unittest | python -m py_compile
        if base in ("python", "python3", "py"):
            if (
                len(parts) >= 3
                and parts[1] == "-m"
                and Path(parts[2]).name.lower().removesuffix(".exe")
                in ReplayEngine._PYTHON_MODULES
            ):
                return True, ""
            return False, "Only pytest / unittest / py_compile via `python -m` are allowed"

        # pytest ... | ruff ... | mypy ...
        if base in ReplayEngine._STATIC_TOOLS:
            return True, ""

        # npm test | npm run test | yarn test | pnpm test
        if base in ReplayEngine._JS_PACKAGE_MANAGERS:
            sub = parts[1].lower() if len(parts) > 1 else ""
            if sub == "test":
                return True, ""
            if sub == "run" and len(parts) > 2 and parts[2].lower() == "test":
                return True, ""
            return False, f"Only `{base} test` is allowed"

        # cargo test | go test | make test
        if base == "cargo" and len(parts) > 1 and parts[1] == "test":
            return True, ""
        if base == "go" and len(parts) > 1 and parts[1] == "test":
            return True, ""
        if base == "make" and len(parts) > 1 and parts[1] == "test":
            return True, ""

        return False, f"`{command}` is not on the verification allowlist"

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

            # Step 3: Run verification commands (allowlist-enforced)
            for cmd in config.verification_commands:
                allowed, reason = self.verify_command_allowed(cmd)
                if not allowed:
                    result.verification_results.append({
                        "command": cmd,
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": f"Rejected by server-side allowlist: {reason}",
                        "success": False,
                    })
                    continue
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
            # Only a full 40-hex commit hash is accepted as a target ref;
            # anything else falls back to HEAD so git never parses API input.
            target_ref = config.commit_hash or "HEAD"
            if not re.fullmatch(r"[0-9a-fA-F]{40}", target_ref):
                target_ref = "HEAD"
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
        """Apply modified constraints to the simulation worktree.

        Patterns must stay inside the worktree: absolute patterns and `..`
        traversal are rejected, so a simulation can never delete files in the
        live workspace or anywhere else on disk (fail closed).
        """
        prohibited = constraints.get("prohibited_paths", [])
        for pat in prohibited:
            if not self._is_safe_pattern(pat):
                raise ValueError(
                    f"Constraint pattern `{pat}` escapes the simulation worktree"
                )
            for matched in worktree.glob(pat):
                if not self._is_within_worktree(matched, worktree):
                    logger.warning(
                        "Skipping match outside worktree: %s", matched
                    )
                    continue
                if matched.is_file():
                    matched.unlink(missing_ok=True)

    @staticmethod
    def _is_safe_pattern(pattern: str) -> bool:
        """Reject absolute patterns or patterns that traverse out of the worktree."""
        if not pattern:
            return False
        normalized = pattern.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            return False
        return ".." not in PurePosixPath(normalized).parts

    @staticmethod
    def _is_within_worktree(path: Path, worktree: Path) -> bool:
        """True if the resolved path stays inside the worktree directory."""
        try:
            return path.resolve().is_relative_to(worktree.resolve())
        except (OSError, ValueError):
            return False

    def _resolve_command(self, command: str) -> tuple[list[str] | None, str]:
        """Resolve an allowlisted command to an absolute-executable argv list.

        The raw command text is never passed to a shell; executables are
        resolved to absolute paths (python -> sys.executable, tools -> PATH)
        so a worktree-local impostor executable can never be picked up.
        Returns (argv, "") on success or (None, reason) on failure.
        """
        try:
            parts = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return None, "Unparseable command"
        if not parts:
            return None, "Empty command"

        # Defense in depth: shell control operators and substitution must never
        # survive into argv, even if the allowlist check is bypassed by a caller.
        if any(tok in parts for tok in ("&&", "||", ";", "|", ">", "<")):
            return None, "Shell control operators and redirection are not allowed"
        if any("$(" in tok or "${ " in tok or "`" in tok for tok in parts):
            return None, "Command substitution is not allowed"

        base = Path(parts[0]).name.lower().removesuffix(".exe")

        if base in ("python", "python3", "py"):
            return [sys.executable, *parts[1:]], ""

        resolvable = (
            ReplayEngine._STATIC_TOOLS
            | ReplayEngine._JS_PACKAGE_MANAGERS
            | {"cargo", "go", "make"}
        )
        if base in resolvable:
            exe = shutil.which(parts[0], path=_venv_bin_dir())
            if not exe:
                return None, f"`{base}` not found on PATH"
            return [exe, *parts[1:]], ""

        return None, f"`{command}` is not on the verification allowlist"

    def _run_command(self, command: str, worktree: Path) -> dict[str, Any]:
        """Run a verification command safely inside the isolated worktree.

        Hardened: stdin is detached (a ``pytest --pdb``-style interactive
        debugger must never get a live terminal), and the environment is
        scrubbed of interpreter-hook variables that could smuggle arbitrary
        code into the child (PYTHONSTARTUP, PYTHONINSPECT, BASH_ENV).
        """
        argv, error = self._resolve_command(command)
        if argv is None:
            return {
                "command": command,
                "exit_code": -1,
                "stdout": "",
                "stderr": error,
                "success": False,
            }
        # Containerized isolation execution
        if self.container_isolation and self._container_engine:
            container_argv = [
                self._container_engine,
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{worktree.resolve()}:/workspace",
                "-w",
                "/workspace",
                "--memory",
                "1g",
                "--cpus",
                "2",
                "python:3.11-slim",
                *argv,
            ]
            try:
                c_result = subprocess.run(
                    container_argv,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    stdin=subprocess.DEVNULL,
                )
                return {
                    "command": command,
                    "exit_code": c_result.returncode,
                    "stdout": c_result.stdout[:5000],
                    "stderr": c_result.stderr[:5000],
                    "success": c_result.returncode == 0,
                    "isolated_container": True,
                }
            except Exception as e:
                logger.debug(
                    "Container replay failed, falling back to scrubbed host runner: %s", e
                )

        scrubbed_env = dict(os.environ)
        for var in self._DANGEROUS_ENV_VARS:
            scrubbed_env.pop(var, None)
        try:
            result = subprocess.run(
                argv,
                shell=False,
                cwd=str(worktree),
                capture_output=True,
                text=True,
                timeout=120,
                stdin=subprocess.DEVNULL,
                env=scrubbed_env,
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

        diffs.append(
            f"Simulation node count: {len(simulation.nodes)} "
            f"(original: {len(original.nodes)})"
        )
        return diffs

    def _cleanup_worktree(self, sim_id: UUID, worktree_path: Path) -> None:
        """Clean up a simulation worktree."""
        self._active_simulations.pop(sim_id, None)
        with contextlib.suppress(Exception):
            subprocess.run(
                ["git", "worktree", "remove", str(worktree_path), "--force"],
                cwd=str(self.workspace_path),
                capture_output=True,
                timeout=10,
            )

        if worktree_path.exists():
            shutil.rmtree(str(worktree_path), ignore_errors=True)

    def cleanup_all(self) -> None:
        """Clean up all active simulation worktrees."""
        for sim_id, worktree_path in list(self._active_simulations.items()):
            self._cleanup_worktree(sim_id, worktree_path)
