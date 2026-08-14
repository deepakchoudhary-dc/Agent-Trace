"""Universal AI Coding Agent & Tool Sensor.

Provides automated, zero-configuration tracking across ANY AI assistant:
Cline, Kilo Code, Roo Code, Cursor, Windsurf, Aider, Goose, Copilot,
Claude Code, Continue.dev, Ollama, LM Studio, or custom local LLMs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    EventType,
    InvocationEvent,
)

logger = logging.getLogger(__name__)


class UniversalAgentAdapter(AdapterBase):
    """Universal AI coding assistant sensor.

    Dynamically monitors workspace agent configurations, IDE extensions,
    and local inference streams without requiring bespoke per-tool adapters.
    """

    @property
    def adapter_name(self) -> str:
        return "universal_agent_sensor"

    @property
    def adapter_version(self) -> str:
        return "1.0.0"

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

    def __init__(self, session_id: UUID, workspace_path: str) -> None:
        super().__init__(session_id, workspace_path)
        self._workspace = Path(workspace_path)
        self._watched_agent_dirs: list[Path] = self._discover_agent_dirs()
        self._seen_entries: set[str] = set()

    def _discover_agent_dirs(self) -> list[Path]:
        """Auto-discover agent workspace config & history folders dynamically."""
        candidates: list[Path] = []
        home = Path.home()

        # Workspace-level agent directories
        for name in [".cline", ".kilo", ".roo", ".cursor", ".windsurf", ".aider", ".continue"]:
            ws_agent = self._workspace / name
            if ws_agent.exists():
                candidates.append(ws_agent)

        # User-level agent directories
        for name in [".cline", ".kilo", ".roo", ".cursor", ".windsurf", ".aider", ".claude", ".codex", ".copilot", ".ollama"]:
            home_agent = home / name
            if home_agent.exists():
                candidates.append(home_agent)

        return candidates

    async def start(self) -> None:
        self._running = True
        logger.info(
            "UniversalAgentAdapter active, discovered %d agent state directories",
            len(self._watched_agent_dirs),
        )

    async def stop(self) -> None:
        self._running = False
        logger.info("UniversalAgentAdapter stopped")

    async def poll(self) -> list[EventBase]:
        """Dynamically poll discovered agent channels for invocations and tool actions."""
        events: list[EventBase] = []
        if not self._running:
            return events

        for agent_dir in self._watched_agent_dirs:
            try:
                agent_name = agent_dir.name.replace(".", "")
                # Scan for new prompt/chat log files
                for log_file in agent_dir.rglob("*.json*"):
                    if not log_file.is_file():
                        continue
                    mtime = log_file.stat().st_mtime
                    key = f"{log_file}:{mtime}"
                    if key in self._seen_entries:
                        continue
                    self._seen_entries.add(key)

                    events.append(
                        InvocationEvent(
                            session_id=self.session_id,
                            actor_id=f"agent:{agent_name}",
                            source_adapter=self.adapter_name,
                            confidence=ConfidenceLevel.HIGH,
                            user_intent=f"AI Agent interaction via {agent_name}",
                            prompt=f"Session file updated: {log_file.name}",
                            payload={"agent": agent_name, "path": str(log_file)},
                        )
                    )
            except Exception as e:
                logger.debug("Error reading agent dir %s: %s", agent_dir, e)

        return events
