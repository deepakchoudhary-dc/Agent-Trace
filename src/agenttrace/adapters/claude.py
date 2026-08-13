"""Claude Code CLI Adapter.

Monitors Claude Code sessions, tool executions, and file operations.
"""

from __future__ import annotations

import asyncio
import json
import logging
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


class ClaudeAdapter(AdapterBase):
    """Adapter for Anthropic Claude Code CLI."""

    @property
    def adapter_name(self) -> str:
        return "claude_code"

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
        self._history_dirs = self._find_claude_dirs()
        self._positions: dict[str, int] = {}

    @staticmethod
    def _find_claude_dirs() -> list[Path]:
        candidates: list[Path] = []
        home = Path.home()
        for p in [home / ".claude", home / ".config" / "claude"]:
            if p.exists() and p.is_dir():
                candidates.append(p)
        return candidates

    async def start(self) -> None:
        self._running = True
        logger.info("ClaudeAdapter started")

    async def stop(self) -> None:
        self._running = False
        logger.info("ClaudeAdapter stopped")

    async def poll(self) -> list[EventBase]:
        events: list[EventBase] = []
        # Query Claude session files if present
        return events
