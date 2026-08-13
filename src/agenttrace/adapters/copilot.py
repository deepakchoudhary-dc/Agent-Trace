"""GitHub Copilot Chat & Extension Adapter.

Monitors Copilot Chat interactions, language server requests, and tool executions
within VS Code / Antigravity IDE / JetBrains.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import (
    ConfidenceLevel,
    ContextBoundaryEvent,
    EventBase,
    EventType,
    InvocationEvent,
    ToolRequestEvent,
    ToolResultEvent,
)

logger = logging.getLogger(__name__)


class CopilotAdapter(AdapterBase):
    """Adapter for GitHub Copilot & Copilot Chat.

    Tracks Copilot Chat prompts, workspace contextual references, and
    emitted terminal/file tools.
    """

    @property
    def adapter_name(self) -> str:
        return "copilot_chat"

    @property
    def adapter_version(self) -> str:
        return "0.1.0"

    @property
    def sdk_version(self) -> str:
        return SDK_VERSION

    @property
    def supported_event_types(self) -> list[EventType]:
        return [
            EventType.INVOCATION,
            EventType.TOOL_REQUEST,
            EventType.TOOL_RESULT,
            EventType.CONTEXT_BOUNDARY,
        ]

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
    ) -> None:
        super().__init__(session_id, workspace_path)
        self._log_paths = self._find_copilot_logs()
        self._positions: dict[str, int] = {}
        self._seen_prompts: set[str] = set()

    @staticmethod
    def _find_copilot_logs() -> list[Path]:
        """Locate Copilot log files across VS Code, Antigravity IDE, and user dirs."""
        candidates: list[Path] = []
        home = Path.home()
        appdata = os.environ.get("APPDATA", "")

        search_dirs = [
            home / ".copilot" / "logs",
            home / ".config" / "github-copilot",
            Path(appdata) / "Code" / "logs" if appdata else None,
            Path(appdata) / "Antigravity IDE" / "logs" if appdata else None,
        ]

        for s_dir in search_dirs:
            if s_dir and s_dir.exists():
                try:
                    for f in s_dir.rglob("*.log"):
                        if "copilot" in f.name.lower():
                            candidates.append(f)
                except Exception:
                    pass

        return candidates

    async def start(self) -> None:
        self._running = True
        for p in self._log_paths:
            try:
                self._positions[str(p)] = p.stat().st_size
            except OSError:
                self._positions[str(p)] = 0
        logger.info("CopilotAdapter started with %d log files", len(self._log_paths))

    async def stop(self) -> None:
        self._running = False
        logger.info("CopilotAdapter stopped")

    async def poll(self) -> list[EventBase]:
        """Poll for new Copilot Chat invocations and tool actions."""
        events: list[EventBase] = []
        if not self._running:
            return events

        for log_path in self._log_paths:
            try:
                if not log_path.exists():
                    continue
                size = log_path.stat().st_size
                last_pos = self._positions.get(str(log_path), 0)
                if size <= last_pos:
                    continue

                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    self._positions[str(log_path)] = f.tell()

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    # Parse potential JSON or Copilot log lines
                    if "conversation" in line.lower() or "prompt" in line.lower() or "chat" in line.lower():
                        if line not in self._seen_prompts:
                            self._seen_prompts.add(line)
                            events.append(
                                InvocationEvent(
                                    session_id=self.session_id,
                                    actor_id="copilot_chat",
                                    source_adapter=self.adapter_name,
                                    confidence=ConfidenceLevel.HIGH,
                                    user_intent=line[:200],
                                    prompt=line[:500],
                                )
                            )
            except Exception as e:
                logger.debug("Error reading Copilot log %s: %s", log_path, e)

        return events
