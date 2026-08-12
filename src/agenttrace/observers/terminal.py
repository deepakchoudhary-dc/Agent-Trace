"""Terminal/shell output capture.

Captures command execution results by monitoring shell history and
output. On Windows, uses ConPTY-compatible approaches where available,
with log-file tailing as fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from agenttrace.models.events import CommandEvent, ConfidenceLevel
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

# Common shell history file locations
_HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".local/share/fish/fish_history",
]

# Regex patterns for known dangerous commands
_RISKY_COMMAND_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b", re.IGNORECASE),
    re.compile(r"\bwget\b.*\|\s*(ba)?sh\b", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\brunas\b", re.IGNORECASE),
    re.compile(r"\bpowershell\b.*-enc", re.IGNORECASE),
    re.compile(r"\breg\b.*\badd\b", re.IGNORECASE),
]

_POLL_INTERVAL = 2.0


class TerminalObserver(BaseObserver):
    """Captures terminal command execution within the workspace.

    Uses shell history monitoring as the primary capture method.
    Each detected command is emitted as a CommandEvent. Risky
    commands are flagged with metadata.
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
        self._history_positions: dict[str, int] = {}
        self._seen_commands: set[str] = set()

    def _find_history_files(self) -> list[Path]:
        """Find readable shell history files."""
        home = Path.home()
        found: list[Path] = []
        for rel_path in _HISTORY_FILES:
            hist_path = home / rel_path
            if hist_path.exists() and hist_path.is_file():
                found.append(hist_path)

        # Windows PowerShell history
        ps_hist = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        if ps_hist.exists():
            found.append(ps_hist)

        return found

    @staticmethod
    def _is_risky(command: str) -> bool:
        """Check if a command matches risky patterns."""
        return any(pat.search(command) for pat in _RISKY_COMMAND_PATTERNS)

    async def _run(self) -> None:
        """Monitor shell history files for new commands."""
        history_files = self._find_history_files()
        if not history_files:
            logger.info("No shell history files found, TerminalObserver limited")

        # Initialize positions to end of file
        for hist_file in history_files:
            try:
                self._history_positions[str(hist_file)] = hist_file.stat().st_size
            except OSError:
                self._history_positions[str(hist_file)] = 0

        try:
            while self._running:
                await asyncio.sleep(self._poll_interval)

                for hist_file in history_files:
                    await self._check_history(hist_file)

        except asyncio.CancelledError:
            logger.debug("TerminalObserver cancelled")
        except Exception:
            logger.exception("TerminalObserver error")

    async def _check_history(self, hist_file: Path) -> None:
        """Check a history file for new commands."""
        path_key = str(hist_file)
        try:
            current_size = hist_file.stat().st_size
            last_pos = self._history_positions.get(path_key, 0)

            if current_size <= last_pos:
                return

            with open(hist_file, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_content = f.read()

            self._history_positions[path_key] = current_size

            for line in new_content.strip().split("\n"):
                command = line.strip()
                if not command or command in self._seen_commands:
                    continue

                self._seen_commands.add(command)

                # Create a dedup key based on timestamp + command
                event = CommandEvent(
                    session_id=self.session_id,
                    actor_id="terminal",
                    source_adapter="terminal_observer",
                    confidence=ConfidenceLevel.MEDIUM,
                    command=command,
                    working_dir=self.workspace_path,
                    payload={
                        "source_file": path_key,
                        "is_risky": self._is_risky(command),
                    },
                )
                await self.emit(event)

        except (OSError, PermissionError):
            logger.debug("Cannot read history file: %s", hist_file)
