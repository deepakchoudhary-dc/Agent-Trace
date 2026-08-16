"""GitHub Copilot Chat & Extension Adapter.

Copilot (VS Code / Antigravity / JetBrains) does not expose a stable
structured transcript format: its logs are free-text with occasional JSON
records. Per the anti-fabrication invariant we therefore emit an
InvocationEvent ONLY when a log line parses as JSON and carries a genuine
prompt/message field. Everything else is left to the process-tree observer
and the universal adapter's honest "session file detected" events.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    EventType,
    InvocationEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_MAX_SEEN_PROMPTS = 10_000


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

    def cursor_state(self) -> dict[str, Any]:
        return {
            "positions": dict(self._positions),
            "seen_prompts": sorted(self._seen_prompts),
        }

    def restore_cursor(self, state: dict[str, Any]) -> None:
        positions = state.get("positions", {})
        if isinstance(positions, dict):
            self._positions = {
                str(k): int(v) for k, v in positions.items()
            }
        self._seen_prompts = set(state.get("seen_prompts", []))

    async def start(self) -> None:
        self._running = True
        # Position at EOF only for logs with no restored cursor — a resumed
        # session keeps its persisted offsets instead of skipping or
        # replaying history.
        for p in self._log_paths:
            if str(p) in self._positions:
                continue
            try:
                self._positions[str(p)] = p.stat().st_size
            except OSError:
                self._positions[str(p)] = 0
        logger.info("CopilotAdapter started with %d log files", len(self._log_paths))

    async def stop(self) -> None:
        self._running = False
        logger.info("CopilotAdapter stopped")

    async def poll(self) -> list[EventBase]:
        """Poll for new Copilot Chat invocations.

        Only JSON records carrying a real prompt/message field are emitted;
        keyword-sniffing text logs would fabricate user intents.
        """
        events: list[EventBase] = []
        if not self._running:
            return events

        for log_path in self._log_paths:
            try:
                if not log_path.exists():
                    continue
                size = log_path.stat().st_size
                last_pos = self._positions.get(str(log_path), 0)
                if size < last_pos:
                    # Log rotated/truncated while not watched — restart the
                    # cursor from the top so the new file is not skipped.
                    last_pos = 0
                    self._positions[str(log_path)] = 0
                if size <= last_pos:
                    continue

                with open(log_path, "rb") as f:
                    f.seek(last_pos)
                    raw_lines = f.readlines()
                    new_position = f.tell()
                self._positions[str(log_path)] = new_position

                lines: list[str] = []
                for raw in raw_lines:
                    if not raw.endswith(b"\n"):
                        line = raw.decode("utf-8", errors="replace").strip()
                        if not line:
                            self._positions[str(log_path)] = new_position - len(raw)
                            break
                        try:
                            json.loads(line)
                        except json.JSONDecodeError:
                            self._positions[str(log_path)] = new_position - len(raw)
                            break
                        lines.append(line)
                    else:
                        lines.append(raw.decode("utf-8", errors="replace"))

                for line in lines:
                    entry: Any = None
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # free-text log line — not an invocation
                    if not isinstance(entry, dict):
                        continue
                    prompt = self._extract_prompt(entry)
                    if not prompt:
                        continue
                    if line in self._seen_prompts:
                        continue
                    self._seen_prompts.add(line)
                    if len(self._seen_prompts) > _MAX_SEEN_PROMPTS:
                        self._seen_prompts.clear()
                    events.append(InvocationEvent(
                        session_id=self.session_id,
                        actor_id="copilot_chat",
                        source_adapter=self.adapter_name,
                        confidence=ConfidenceLevel.HIGH,
                        user_intent=prompt[:500],
                        agent_name="copilot",
                        agent_version="",
                        payload={"log": str(log_path), "format": "json"},
                    ))
            except Exception as e:
                logger.debug("Error reading Copilot log %s: %s", log_path, e)

        return events

    @staticmethod
    def _extract_prompt(entry: dict[str, Any]) -> str:
        """Extract a genuine user prompt from a JSON record, if present."""
        for key in ("prompt", "user_message", "message", "userPrompt"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                text = value.get("content") or value.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
        return ""
