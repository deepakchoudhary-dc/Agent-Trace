"""Real verification command execution for the review loop.

Commands are restricted to the server-side allowlist (ReplayEngine) and run
against the audited workspace with a bounded timeout and output size. The
review loop never executes arbitrary command text — rejected commands are
reported as such and never reach a subprocess.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from agenttrace.graph.replay import ReplayEngine

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 120
_MAX_OUTPUT_CHARS = 8000

# Console scripts the runner resolves inside the same virtualenv as the daemon
_VENV_SCRIPTS = {"pytest", "ruff", "mypy"}
# Interpreters mapped to the running process's interpreter
_PYTHON_ALIASES = {"python", "python3", "py"}


@dataclass
class VerificationResult:
    """Outcome of running one allowlisted verification command."""

    command: str = ""
    allowed: bool = False
    rejection_reason: str = ""
    exit_code: int | None = None
    output: str = ""
    duration_ms: int = 0
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.allowed and self.exit_code == 0


class VerificationRunner:
    """Runs allowlisted verification commands against a workspace."""

    def __init__(
        self,
        workspace_path: str | Path,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = _MAX_OUTPUT_CHARS,
    ) -> None:
        self.workspace_path = Path(workspace_path)
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def run(self, command: str) -> VerificationResult:
        """Run one command, returning its real outcome (never raises)."""
        result = VerificationResult(command=command)
        allowed, reason = ReplayEngine.verify_command_allowed(command)
        result.allowed = allowed
        result.rejection_reason = "" if allowed else reason
        if not allowed:
            logger.warning("Verification command rejected by allowlist: %s (%s)", command, reason)
            return result

        try:
            parts = shlex.split(command, posix=os.name != "nt")
            parts = self._resolve_executable(parts)
            start = time.monotonic()
            proc = subprocess.run(
                parts,
                cwd=str(self.workspace_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                env=self._build_env(),
                check=False,
            )
            result.duration_ms = int((time.monotonic() - start) * 1000)
            result.exit_code = proc.returncode
            result.output = self._truncate(proc.stdout + proc.stderr)
        except FileNotFoundError as e:
            result.error = f"Executable not found: {e.filename}"
        except subprocess.TimeoutExpired:
            result.error = f"Timed out after {self.timeout_seconds}s"
        except OSError as e:
            result.error = str(e)
        return result

    @staticmethod
    def _resolve_executable(parts: list[str]) -> list[str]:
        """Pin interpreters and venv console scripts to the daemon's environment.

        `python`/`py` map to the interpreter running the daemon; pytest/ruff/mypy
        resolve to the same virtualenv's scripts so verification reflects the
        environment the workspace is audited under.
        """
        base = Path(parts[0]).name.lower().removesuffix(".exe")
        if base in _PYTHON_ALIASES:
            return [sys.executable, *parts[1:]]
        if base in _VENV_SCRIPTS:
            resolved = shutil.which(parts[0], path=_venv_path())
            if resolved:
                return [resolved, *parts[1:]]
        return parts

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = _venv_path() + os.pathsep + env.get("PATH", "")
        return env

    def _truncate(self, text: str) -> str:
        if len(text) <= self.max_output_chars:
            return text
        return (
            text[: self.max_output_chars]
            + f"\n... [truncated, {len(text)} chars total]"
        )


def _venv_path() -> str:
    """Path to the virtualenv/prefix containing the running interpreter."""
    return str(Path(sys.executable).parent)
