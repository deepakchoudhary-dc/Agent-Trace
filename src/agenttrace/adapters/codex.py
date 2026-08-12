"""Codex CLI adapter — reference deep integration.

The Codex CLI adapter reads Codex CLI's output and state to emit
rich canonical events: invocations, user intent, context boundaries,
tool requests/results, and approvals.
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


class CodexAdapter(AdapterBase):
    """Reference adapter for OpenAI Codex CLI.

    Monitors Codex CLI's log output and process state to emit
    canonical events. This is a deep integration — it provides
    context boundary visibility that generic observers cannot.
    """

    @property
    def adapter_name(self) -> str:
        return "codex_cli"

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
            EventType.SESSION_START,
            EventType.SESSION_END,
        ]

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
    ) -> None:
        super().__init__(session_id, workspace_path)
        self._log_dir = self._find_codex_log_dir()
        self._last_log_position: int = 0
        self._poll_interval: float = 1.0

    @staticmethod
    def _find_codex_log_dir() -> Path | None:
        """Find the Codex CLI log directory."""
        # Codex CLI typically logs to ~/.codex/logs or similar
        candidates = [
            Path.home() / ".codex" / "logs",
            Path.home() / ".openai" / "codex" / "logs",
            Path(os.environ.get("APPDATA", "")) / "codex" / "logs",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    async def start(self) -> None:
        """Start monitoring Codex CLI output."""
        self._running = True
        logger.info("CodexAdapter started, log_dir=%s", self._log_dir)

    async def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.info("CodexAdapter stopped")

    async def poll(self) -> list[EventBase]:
        """Poll for new Codex CLI events.

        Reads new lines from the Codex log file and translates them
        into canonical events.
        """
        events: list[EventBase] = []

        if not self._log_dir:
            return events

        # Find the latest log file
        log_files = sorted(
            self._log_dir.glob("*.jsonl"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if not log_files:
            return events

        latest_log = log_files[0]
        try:
            with open(latest_log, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._last_log_position)
                new_lines = f.readlines()
                self._last_log_position = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    event = self._translate_log_entry(entry)
                    if event:
                        events.append(event)
                except json.JSONDecodeError:
                    continue

        except OSError:
            logger.debug("Cannot read Codex log file: %s", latest_log)

        return events

    def _translate_log_entry(self, entry: dict[str, Any]) -> EventBase | None:
        """Translate a Codex CLI log entry into a canonical event."""
        entry_type = entry.get("type", "")

        if entry_type == "invocation":
            return InvocationEvent(
                session_id=self.session_id,
                actor_id=f"codex:{entry.get('session_id', 'unknown')}",
                source_adapter=self.adapter_name,
                confidence=ConfidenceLevel.HIGH,
                user_intent=entry.get("prompt", ""),
                agent_name="codex",
                agent_version=entry.get("version", ""),
                payload=entry,
            )

        elif entry_type == "tool_call":
            return ToolRequestEvent(
                session_id=self.session_id,
                actor_id=f"codex:{entry.get('session_id', 'unknown')}",
                source_adapter=self.adapter_name,
                confidence=ConfidenceLevel.HIGH,
                tool_name=entry.get("tool", ""),
                tool_args=entry.get("args", {}),
                requires_approval=entry.get("requires_approval", False),
                payload=entry,
            )

        elif entry_type == "tool_result":
            return ToolResultEvent(
                session_id=self.session_id,
                actor_id=f"codex:{entry.get('session_id', 'unknown')}",
                source_adapter=self.adapter_name,
                confidence=ConfidenceLevel.HIGH,
                tool_name=entry.get("tool", ""),
                exit_code=entry.get("exit_code"),
                output_summary=entry.get("output", "")[:500],
                payload=entry,
            )

        elif entry_type == "context":
            return ContextBoundaryEvent(
                session_id=self.session_id,
                actor_id=f"codex:{entry.get('session_id', 'unknown')}",
                source_adapter=self.adapter_name,
                confidence=ConfidenceLevel.HIGH,
                files_visible=entry.get("files", []),
                context_window_tokens=entry.get("token_count", 0),
                payload=entry,
            )

        return None
