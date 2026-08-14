"""Git state monitor.

Polls the Git repository at regular intervals to detect commits,
branch changes, staging operations, and other Git state transitions.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.models.events import ConfidenceLevel, GitEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 3.0


class GitMonitor(BaseObserver):
    """Watches Git repository state for changes.

    Polls HEAD, index, and working tree status. Emits GitEvents on
    commits, branch switches, staging, and resets. Uses subprocess
    calls to the git CLI for maximum compatibility.
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
        self._last_head: str = ""
        self._last_branch: str = ""
        self._last_index_hash: str = ""

    def _git_cmd(self, *args: str) -> str:
        """Run a git command and return stdout."""
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=self.workspace_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _get_head(self) -> str:
        """Get current HEAD commit hash."""
        return self._git_cmd("rev-parse", "HEAD")

    def _get_branch(self) -> str:
        """Get current branch name."""
        return self._git_cmd("rev-parse", "--abbrev-ref", "HEAD")

    def _get_index_hash(self) -> str:
        """Get a hash representing the current index state."""
        return self._git_cmd("write-tree")

    def _get_commit_info(self, commit_hash: str) -> dict[str, str]:
        """Get commit metadata."""
        msg = self._git_cmd("log", "-1", "--format=%s", commit_hash)
        parent = self._git_cmd("log", "-1", "--format=%P", commit_hash)
        return {"message": msg, "parent": parent}

    def _get_diff_stat(self, from_ref: str, to_ref: str) -> dict[str, Any]:
        """Get diff statistics between two refs."""
        files_raw = self._git_cmd("diff", "--name-only", from_ref, to_ref)
        files = [f for f in files_raw.split("\n") if f.strip()] if files_raw else []

        stat = self._git_cmd("diff", "--shortstat", from_ref, to_ref)
        insertions = 0
        deletions = 0
        if stat:
            parts = stat.split(",")
            for part in parts:
                part = part.strip()
                if "insertion" in part:
                    insertions = int(part.split()[0])
                elif "deletion" in part:
                    deletions = int(part.split()[0])

        return {
            "files": files,
            "insertions": insertions,
            "deletions": deletions,
        }

    async def _run(self) -> None:
        """Poll git state at regular intervals."""
        # Check if this is a git repo
        git_dir = Path(self.workspace_path) / ".git"
        if not git_dir.exists():
            logger.info("No .git directory in %s, GitMonitor inactive", self.workspace_path)
            return

        # Initialize state
        self._last_head = self._get_head()
        self._last_branch = self._get_branch()
        self._last_index_hash = self._get_index_hash()
        logger.info("GitMonitor started: HEAD=%s branch=%s", self._last_head[:8], self._last_branch)

        try:
            while self._running:
                await asyncio.sleep(self._poll_interval)
                await self._check_state()
        except asyncio.CancelledError:
            logger.debug("GitMonitor cancelled")
        except Exception:
            logger.exception("GitMonitor error")

    async def _check_state(self) -> None:
        """Check for git state changes and emit events."""
        current_head = self._get_head()
        current_branch = self._get_branch()
        current_index = self._get_index_hash()

        # Detect new commit
        if current_head and current_head != self._last_head:
            info = self._get_commit_info(current_head)
            diff_stat = self._get_diff_stat(self._last_head, current_head) if self._last_head else {
                "files": [], "insertions": 0, "deletions": 0
            }

            event = GitEvent(
                session_id=self.session_id,
                actor_id="git",
                source_adapter="git_monitor",
                confidence=ConfidenceLevel.HIGH,
                git_action="commit",
                branch=current_branch,
                commit_hash=current_head,
                parent_hash=info["parent"],
                message=info["message"],
                files_changed=diff_stat["files"],
                insertions=diff_stat["insertions"],
                deletions=diff_stat["deletions"],
            )
            await self.emit(event)
            self._last_head = current_head

        # Detect branch change
        if current_branch and current_branch != self._last_branch:
            event = GitEvent(
                session_id=self.session_id,
                actor_id="git",
                source_adapter="git_monitor",
                confidence=ConfidenceLevel.HIGH,
                git_action="checkout",
                branch=current_branch,
                commit_hash=current_head,
                payload={"previous_branch": self._last_branch},
            )
            await self.emit(event)
            self._last_branch = current_branch

        # Detect staging changes
        if current_index and current_index != self._last_index_hash:
            event = GitEvent(
                session_id=self.session_id,
                actor_id="git",
                source_adapter="git_monitor",
                confidence=ConfidenceLevel.HIGH,
                git_action="stage",
                branch=current_branch,
                commit_hash=current_head,
            )
            await self.emit(event)
            self._last_index_hash = current_index
