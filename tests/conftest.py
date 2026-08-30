"""Pytest configuration and path setup."""

import subprocess
import sys
from pathlib import Path

# Ensure src/ is on sys.path
src_dir = str(Path(__file__).resolve().parent.parent / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from agenttrace.security.isolation import IsolationResult  # noqa: E402

_PYTHON_ALIASES = {"python", "python3", "py"}


class HostIsolationStub:
    """Test double standing in for an available isolation runtime.

    Executes allowlisted argv on the host the way the pre-P0.1 runner did —
    interpreter pinned to the running venv, stdin detached, bounded timeout —
    so tests can exercise replay/review end-to-end on machines without a
    container runtime. The production default remains fail-closed.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.last_env: dict[str, str] | None = None

    def run(
        self,
        argv: list[str],
        *,
        workspace_path: Path,
        scratch_dir: Path | None = None,
        env: dict[str, str] | None = None,
        workdir: str = "/workspace",
    ) -> IsolationResult:
        self.calls.append(list(argv))
        self.last_env = env
        base = Path(argv[0]).name.lower().removesuffix(".exe")
        resolved = [sys.executable, *argv[1:]] if base in _PYTHON_ALIASES else list(argv)
        proc = subprocess.run(  # noqa: S603
            resolved,
            cwd=str(workspace_path),
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
            env=env,
            shell=False,
            check=False,
        )
        return IsolationResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=1,
        )

