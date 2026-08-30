"""Fail-closed isolated execution for replay and review (plan2.md P0.1).

One ``IsolationRunner`` is the only sanctioned way to execute untrusted
verification commands (allowlisted replay commands, review-loop checks).
It preflights a container runtime, mounts the audited worktree read-only
plus a separate writable scratch volume, disables network and host IPC,
drops capabilities, sets no-new-privileges, and enforces PID, CPU, memory,
output, and wall-clock limits.

There is deliberately **no host fallback**: if no container runtime or the
pinned image is unavailable, execution fails with ``isolation_unavailable``
and the command never runs. Host project configuration (pytest plugins,
hooks, make, compilers) is arbitrary code execution, not a harmless default.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_ALLOWED_ENGINES = ("docker", "podman")
_TMPFS_SIZE_BYTES = 64 * 1024 * 1024


class IsolationError(RuntimeError):
    """Isolated execution cannot proceed; the command must NOT run on host."""


@dataclass(frozen=True)
class IsolationMetadata:
    """Provenance of one isolated execution."""

    engine: str
    image: str
    image_digest: str
    memory_limit_mb: int
    cpu_limit: float
    pids_limit: int
    timeout_seconds: int
    network_disabled: bool = True
    read_only_rootfs: bool = True
    no_new_privileges: bool = True


@dataclass(frozen=True)
class IsolationResult:
    """Outcome of one isolated execution (never raises for command failure)."""

    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    metadata: IsolationMetadata | None = None
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.error == "" and self.exit_code == 0


class IsolationRunner:
    """Executes argv inside a hardened, network-less container. Fail closed."""

    def __init__(
        self,
        image: str = "python:3.11-slim",
        memory_limit_mb: int = 512,
        cpu_limit: float = 1.0,
        pids_limit: int = 128,
        timeout_seconds: int = 120,
        max_output_chars: int = 8000,
    ) -> None:
        self.image = image
        self.memory_limit_mb = memory_limit_mb
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        # Resolved once; a runtime disappearing mid-session is treated the
        # same as never having one (fail closed).
        self._engine: str | None = _find_engine_name() or None

    def _truncate(self, text: str) -> str:
        if len(text) <= self.max_output_chars:
            return text
        return text[: self.max_output_chars] + f"\n... [truncated, {len(text)} chars total]"


    # -- Preflight ---------------------------------------------------------

    def preflight(self) -> IsolationMetadata:
        """Verify engine and image availability; return execution provenance.

        Raises ``IsolationError`` (``isolation_unavailable``) instead of ever
        allowing a host fallback.
        """
        if not self._engine:
            raise IsolationError(
                "isolation_unavailable: no container runtime found among "
                f"{', '.join(_ALLOWED_ENGINES)}"
            )
        digest = self._image_digest()
        if not digest:
            raise IsolationError(
                f"isolation_unavailable: image '{self.image}' is not present "
                f"in the {self._engine} image store; pull it explicitly"
            )
        return IsolationMetadata(
            engine=self._engine,
            image=self.image,
            image_digest=digest,
            memory_limit_mb=self.memory_limit_mb,
            cpu_limit=self.cpu_limit,
            pids_limit=self.pids_limit,
            timeout_seconds=self.timeout_seconds,
        )

    def _image_digest(self) -> str:
        assert self._engine is not None
        proc = subprocess.run(
            [self._engine, "image", "inspect", "--format", "{{.Id}}", self.image],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    # -- Execution ---------------------------------------------------------

    def run(
        self,
        argv: list[str],
        *,
        workspace_path: Path,
        scratch_dir: Path | None = None,
        env: dict[str, str] | None = None,
        workdir: str = "/workspace",
    ) -> IsolationResult:
        """Run argv in the hardened container. Fails closed, never on host."""
        for arg in argv:
            if not isinstance(arg, str) or not arg or "\x00" in arg:
                raise IsolationError("invalid argv: empty or non-string element")
        meta = self.preflight()
        assert self._engine is not None

        cmd = [
            self._engine,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            f"{self.memory_limit_mb}m",
            "--cpus",
            str(self.cpu_limit),
            "--pids-limit",
            str(self.pids_limit),
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={_TMPFS_SIZE_BYTES}",
            "-v",
            f"{workspace_path.resolve()}:/workspace:ro",
        ]
        if scratch_dir is not None:
            scratch_dir.mkdir(parents=True, exist_ok=True)
            cmd += ["-v", f"{scratch_dir.resolve()}:/scratch:rw"]
        for key, value in (env or {}).items():
            cmd += ["-e", f"{key}={value}"]
        cmd += ["-w", workdir, self.image, *argv]

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return IsolationResult(
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=int((time.monotonic() - start) * 1000),
                metadata=meta,
                error=f"isolation_timeout: exceeded {self.timeout_seconds}s",
            )
        except OSError as exc:
            # Engine vanished between preflight and run: still fail closed.
            return IsolationResult(
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=int((time.monotonic() - start) * 1000),
                metadata=meta,
                error=f"isolation_unavailable: {exc}",
            )
        return IsolationResult(
            exit_code=proc.returncode,
            stdout=self._truncate(proc.stdout),
            stderr=self._truncate(proc.stderr),
            duration_ms=int((time.monotonic() - start) * 1000),
            metadata=meta,
        )


def _find_engine_name() -> str:
    """First available container engine name, or '' (caller fails closed)."""
    for engine in _ALLOWED_ENGINES:
        if shutil.which(engine):
            return engine
    return ""

