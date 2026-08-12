"""Process tree observer using psutil.

Monitors child processes of agent sessions, auto-detects known agent
processes, and tracks process lifecycle events.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID

import psutil

from agenttrace.models.events import ConfidenceLevel, ProcessEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

# Process names that indicate known AI agent tools
KNOWN_AGENT_NAMES = {
    "codex": "codex",
    "claude": "claude",
    "copilot": "copilot",
    "node": "generic",  # Many agents run as Node.js processes
    "python": "generic",
    "python3": "generic",
}

# Polling interval in seconds
_POLL_INTERVAL = 2.0


class ProcessTreeObserver(BaseObserver):
    """Watches for agent-related processes in the system.

    Uses psutil to poll the process tree at regular intervals.
    Tracks new processes, terminated processes, and their relationships.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
        poll_interval: float = _POLL_INTERVAL,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._poll_interval = poll_interval
        self._tracked_pids: dict[int, dict[str, str | int | None]] = {}

    async def _run(self) -> None:
        """Poll process tree at regular intervals."""
        logger.info("Watching process tree for workspace: %s", self.workspace_path)

        try:
            while self._running:
                await self._scan_processes()
                await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            logger.debug("ProcessTreeObserver cancelled")
        except Exception:
            logger.exception("ProcessTreeObserver error")

    async def _scan_processes(self) -> None:
        """Scan running processes for agent-related activity."""
        current_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "cwd"]):
            try:
                info = proc.info  # type: ignore[attr-defined]
                pid = info["pid"]
                current_pids.add(pid)

                if pid in self._tracked_pids:
                    continue

                # Check if this process is relevant
                name = (info.get("name") or "").lower()
                cmdline = info.get("cmdline") or []
                cwd = info.get("cwd") or ""

                if not self._is_relevant(name, cmdline, cwd):
                    continue

                # New relevant process found
                proc_info: dict[str, str | int | None] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": name,
                    "cmdline": " ".join(cmdline) if cmdline else name,
                    "cwd": cwd,
                }
                self._tracked_pids[pid] = proc_info

                event = ProcessEvent(
                    session_id=self.session_id,
                    actor_id=f"process:{pid}",
                    source_adapter="process_tree_observer",
                    confidence=ConfidenceLevel.MEDIUM,
                    pid=pid,
                    ppid=info.get("ppid") or 0,
                    command_line=proc_info["cmdline"] or "",  # type: ignore[arg-type]
                    working_dir=cwd,
                    started_at=datetime.now(timezone.utc),
                    payload={"process_name": name},
                )
                await self.emit(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for terminated processes
        terminated = set(self._tracked_pids.keys()) - current_pids
        for pid in terminated:
            proc_info = self._tracked_pids.pop(pid)
            event = ProcessEvent(
                session_id=self.session_id,
                actor_id=f"process:{pid}",
                source_adapter="process_tree_observer",
                confidence=ConfidenceLevel.MEDIUM,
                pid=pid,
                ppid=proc_info.get("ppid") or 0,  # type: ignore[arg-type]
                command_line=proc_info.get("cmdline") or "",  # type: ignore[arg-type]
                working_dir=proc_info.get("cwd") or "",  # type: ignore[arg-type]
                ended_at=datetime.now(timezone.utc),
                payload={"terminated": True},
            )
            await self.emit(event)

    def _is_relevant(self, name: str, cmdline: list[str], cwd: str) -> bool:
        """Determine if a process is relevant to track.

        A process is relevant if:
        - Its name matches a known agent tool
        - Its working directory is within the watched workspace
        - Its command line references the workspace
        """
        # Check known agent names
        if name in KNOWN_AGENT_NAMES:
            return True

        # Check if CWD is within workspace
        if cwd and self.workspace_path:
            try:
                from pathlib import Path

                if Path(cwd).is_relative_to(Path(self.workspace_path)):
                    return True
            except (ValueError, TypeError):
                pass

        # Check command line for workspace references
        cmdline_str = " ".join(cmdline).lower()
        if self.workspace_path.lower() in cmdline_str:
            return True

        return False

    def get_tracked_processes(self) -> dict[int, dict[str, str | int | None]]:
        """Return currently tracked processes."""
        return dict(self._tracked_pids)
