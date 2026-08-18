"""Daemon entry point — run the local API server as its own process.

The CLI talks to AgentTrace exclusively over the local HTTP API. The daemon
process is spawned detached by ``agenttrace start`` (or run in the foreground
with ``agenttrace daemon``), writes a ``runtime.json`` describing where it
listens, and authenticates every request via the data-dir API token.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import uvicorn

from agenttrace.security.token import ApiTokenManager

DEFAULT_PORT = 8765
RUNTIME_FILENAME = "runtime.json"
_HEALTH_PATH = "/health"

logger = logging.getLogger(__name__)


def default_data_dir() -> Path:
    return Path(os.environ.get("AGENTTRACE_DATA_DIR") or Path.home() / ".agenttrace")


def runtime_path(data_dir: Path) -> Path:
    return data_dir / RUNTIME_FILENAME


def read_runtime(data_dir: Path) -> dict[str, Any] | None:
    """Read the runtime file; returns None when missing or unparseable."""
    path = runtime_path(data_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("port"), int):
        return None
    return raw


def is_running(data_dir: Path, timeout: float = 1.0) -> bool:
    """True when the daemon's health endpoint answers on the recorded port."""
    import urllib.request

    runtime = read_runtime(data_dir)
    if not runtime:
        return False
    url = f"http://127.0.0.1:{runtime['port']}{_HEALTH_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (localhost only)
            return bool(resp.status == 200)
    except OSError:
        return False


def wait_until_running(data_dir: Path, port: int, timeout: float = 10.0) -> bool:
    """Poll the health endpoint until the daemon answers or the timeout elapses."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _health_ok(port, timeout=0.5):
            return True
        time.sleep(0.2)
    return False


def _health_ok(port: int, timeout: float) -> bool:
    import urllib.request

    url = f"http://127.0.0.1:{port}{_HEALTH_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (localhost only)
            return bool(resp.status == 200)
    except OSError:
        return False


def spawn_daemon(data_dir: Path, port: int) -> None:
    """Launch a detached daemon process for this data directory."""
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = data_dir / "daemon.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        creationflags = 0
        if os.name == "nt":
            # Windows-only process flags; mypy's POSIX typeshed does not define
            # them, so resolve defensively (getattr) instead of direct access.
            creationflags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "DETACHED_PROCESS", 0)
            )
        subprocess.Popen(  # noqa: S603 (explicit, trusted invocation of ourselves)
            [
                sys.executable,
                "-m",
                "agenttrace.daemon_entry",
                "--data-dir",
                str(data_dir),
                "--port",
                str(port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            creationflags=creationflags,
            close_fds=True,
        )
    finally:
        log_handle.close()


def write_runtime(data_dir: Path, port: int) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    runtime = {
        "pid": os.getpid(),
        "port": port,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    tmp = runtime_path(data_dir).with_suffix(".tmp")
    tmp.write_text(json.dumps(runtime, indent=2), encoding="utf-8")
    os.replace(tmp, runtime_path(data_dir))


def clear_runtime(data_dir: Path) -> None:
    try:
        runtime_path(data_dir).unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove runtime file %s", runtime_path(data_dir))


def run_server(data_dir: Path, port: int) -> None:
    """Run the API server in-process until interrupted."""
    os.environ["AGENTTRACE_DATA_DIR"] = str(data_dir)
    # Ensure the token exists before uvicorn binds so the API can verify clients.
    ApiTokenManager(data_dir).token()

    from agenttrace.api import app  # noqa: PLC0415 (import after env is set)

    write_runtime(data_dir, port)
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info", access_log=False)
    finally:
        clear_runtime(data_dir)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="agenttrace-daemon", description="Run the AgentTrace local API daemon."
    )
    parser.add_argument(
        "--data-dir", type=Path, default=None, help="Data directory (default: ~/.agenttrace)."
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="Local API port (default: 8765)."
    )
    args = parser.parse_args(argv)

    data_dir = args.data_dir or default_data_dir()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    run_server(data_dir, args.port)


if __name__ == "__main__":
    main()
