"""Pytest configuration and path setup."""

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

# Ensure src/ is on sys.path
src_dir = str(Path(__file__).resolve().parent.parent / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from agenttrace.security.isolation import IsolationResult  # noqa: E402

_PYTHON_ALIASES = {"python", "python3", "py"}


def _console_script_path(name: str) -> str | None:
    """Resolve a bare console-script name against the ACTIVE environment.

    ``Path(sys.executable).parent`` only holds the scripts when the
    interpreter is a venv interpreter (``<env>/Scripts/python.exe``). CI
    installs into the system interpreter, whose executable sits in the
    install root while the scripts sit in ``<prefix>/Scripts`` — so the
    old lookup returned ``None`` on every runner and silently degraded to
    a bare name, which only works while the child inherits a PATH that
    contains the scripts directory. Same rule as
    ``graph.replay._venv_bin_dir``.
    """
    candidates = [
        sysconfig.get_path("scripts"),
        str(Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")),
    ]
    for directory in candidates:
        if not directory:
            continue
        found = shutil.which(name, path=directory)
        if found:
            return found
    return None


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
        if base in _PYTHON_ALIASES:
            resolved = [sys.executable, *argv[1:]]
        else:
            # Bare console-script names (e.g. "pytest") resolve via PATH on
            # POSIX but CreateProcess on Windows needs the ".exe" suffix;
            # resolve explicitly so tests behave identically on both.
            resolved = list(argv)
            if os.name == "nt" and not Path(argv[0]).suffix:
                which = _console_script_path(argv[0])
                if which:
                    resolved = [which, *argv[1:]]
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

