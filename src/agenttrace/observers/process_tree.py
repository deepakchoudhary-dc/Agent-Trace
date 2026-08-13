"""Process tree observer using psutil.

Monitors child processes of agent sessions, auto-detects known agent
processes, and tracks process lifecycle events with strict workspace scoping.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import psutil

from agenttrace.models.events import ConfidenceLevel, ProcessEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

# Process names that indicate known AI agent tools
KNOWN_AGENT_NAMES = {
    "codex",
    "claude",
    "copilot",
}

_POLL_INTERVAL = 2.0


class ProcessTreeObserver(BaseObserver):
    """Watches for agent-related processes strictly within the workspace.

    Uses psutil to poll the process tree. Tracks new processes, terminated processes,
    and updates active workspace PIDs.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
        poll_interval: float = _POLL_INTERVAL,
        on_pids_updated: Callable[[set[int]], None] | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._poll_interval = poll_interval
        self._on_pids_updated = on_pids_updated
        self._tracked_pids: dict[int, dict[str, str | int | None]] = {}
        self._workspace_resolved = Path(workspace_path).resolve()

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
        """Scan running processes for workspace-scoped activity."""
        current_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "cwd"]):
            try:
                info = proc.info  # type: ignore[attr-defined]
                pid = info["pid"]
                if not pid:
                    continue

                name = (info.get("name") or "").lower()
                cmdline = info.get("cmdline") or []
                cwd = info.get("cwd") or ""

                if not self._is_relevant(name, cmdline, cwd):
                    continue

                current_pids.add(pid)
                if pid in self._tracked_pids:
                    continue

                # New relevant workspace process found
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
                    confidence=ConfidenceLevel.HIGH,
                    pid=pid,
                    ppid=info.get("ppid") or 0,
                    command_line=str(proc_info["cmdline"]),
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
                confidence=ConfidenceLevel.HIGH,
                pid=pid,
                ppid=int(proc_info.get("ppid") or 0),
                command_line=str(proc_info.get("cmdline") or ""),
                working_dir=str(proc_info.get("cwd") or ""),
                ended_at=datetime.now(timezone.utc),
                payload={"terminated": True},
            )
            await self.emit(event)

        # Notify network observer of current active PIDs
        if self._on_pids_updated:
            self._on_pids_updated(set(self._tracked_pids.keys()))

    def _is_relevant(self, name: str, cmdline: list[str], cwd: str) -> bool:
        """Determine if a process is relevant to track strictly within the workspace."""
        # 1. Check if CWD is within workspace
        if cwd:
            try:
                proc_cwd = Path(cwd).resolve()
                if proc_cwd == self._workspace_resolved or self._workspace_resolved in proc_cwd.parents:
                    return True
            except (ValueError, TypeError, OSError):
                pass

        # 2. Check if command line contains workspace path explicitly
        if cmdline and self.workspace_path:
            cmdline_str = " ".join(cmdline).lower()
            if str(self._workspace_resolved).lower() in cmdline_str or self.workspace_path.lower() in cmdline_str:
                return True

        # 3. Known agent tool executing within or pointing to workspace
        if any(agent_name in name for agent_name in KNOWN_AGENT_NAMES):
            cmdline_str = " ".join(cmdline).lower()
            if self.workspace_path.lower() in cmdline_str:
                return True

        return False

    def get_tracked_pids(self) -> set[int]:
        """Return currently tracked workspace PIDs."""
        return set(self._tracked_pids.keys())
