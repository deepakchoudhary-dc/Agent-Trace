"""Universal AI Coding Agent & Tool Sensor.

Provides zero-configuration coverage across AI assistants that have no
dedicated adapter (Cline, Kilo Code, Roo Code, Cursor, Windsurf, Aider,
Goose, Continue.dev, ...).

Per the anti-fabrication invariant this adapter NEVER invents user intents:
it only reports the honest fact that an agent state file changed inside a
watched directory, marked as an unparsed CONTEXT_BOUNDARY event at LOW
confidence. Domains with dedicated adapters (claude, codex, copilot) are
excluded to avoid double-reporting. The file content itself is not read.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import (
    ConfidenceLevel,
    ContextBoundaryEvent,
    EventBase,
    EventType,
)

if TYPE_CHECKING:
    from uuid import UUID


logger = logging.getLogger(__name__)

_MAX_SEEN_ENTRIES = 10_000
# Files at or below this size get a content-hash change fingerprint; larger
# files fall back to (mtime, size) to keep polling cheap.
_HASH_MAX_BYTES = 1_000_000


class UniversalAgentAdapter(AdapterBase):
    """Universal AI coding assistant sensor.

    Emits low-confidence "agent session file changed" context events for
    assistants without a dedicated adapter. The observability gap (what the
    agent actually did) is declared, not fabricated.
    """

    @property
    def adapter_name(self) -> str:
        return "universal_agent_sensor"

    @property
    def adapter_version(self) -> str:
        return "1.1.0"

    @property
    def sdk_version(self) -> str:
        return SDK_VERSION

    @property
    def supported_event_types(self) -> list[EventType]:
        return [EventType.CONTEXT_BOUNDARY]

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        watch_dirs: list[Path] | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path)
        self._workspace = Path(workspace_path)
        self._watched_agent_dirs: list[Path] = (
            watch_dirs if watch_dirs is not None else self._discover_agent_dirs()
        )
        self._seen_entries: set[str] = set()

    def _discover_agent_dirs(self) -> list[Path]:
        """Discover agent state dirs for tools WITHOUT a dedicated adapter.

        ``.claude``, ``.codex``, ``.copilot`` are excluded — those domains
        have dedicated adapters and must not be double-reported.
        """
        candidates: list[Path] = []
        home = Path.home()
        names = [".cline", ".kilo", ".roo", ".cursor", ".windsurf", ".aider", ".continue"]

        # Workspace-level agent directories
        for name in names:
            ws_agent = self._workspace / name
            if ws_agent.exists():
                candidates.append(ws_agent)

        # User-level agent directories (same tool set only)
        for name in names:
            home_agent = home / name
            if home_agent.exists():
                candidates.append(home_agent)

        return candidates

    def cursor_state(self) -> dict[str, Any]:
        return {"seen_entries": sorted(self._seen_entries)}

    def restore_cursor(self, state: dict[str, Any]) -> None:
        self._seen_entries = set(state.get("seen_entries", []))

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
        """Report newly-changed agent session files as unparsed context.

        The emitted event says exactly what is known — a session file for
        agent X changed at path P — and nothing more. Confidence is LOW
        because the content was not parsed.
        """
        events: list[EventBase] = []
        if not self._running:
            return events

        for agent_dir in self._watched_agent_dirs:
            try:
                agent_name = agent_dir.name.lstrip(".")
                for log_file in agent_dir.rglob("*.json*"):
                    if not log_file.is_file():
                        continue
                    mtime = log_file.stat().st_mtime
                    size = log_file.stat().st_size
                    # Content hash is the change fingerprint: mtime alone can
                    # collide for two writes in the same timestamp tick, which
                    # would silently drop a real change. Hash small files;
                    # fall back to (mtime, size) for large ones.
                    if size <= _HASH_MAX_BYTES:
                        digest = hashlib.sha256(
                            log_file.read_bytes()
                        ).hexdigest()
                        key = f"{log_file}:sha256:{digest}"
                    else:
                        key = f"{log_file}:{mtime}:{size}"
                    if key in self._seen_entries:
                        continue
                    self._seen_entries.add(key)
                    if len(self._seen_entries) > _MAX_SEEN_ENTRIES:
                        self._seen_entries.clear()

                    events.append(ContextBoundaryEvent(
                        session_id=self.session_id,
                        actor_id=f"agent:{agent_name}",
                        source_adapter=self.adapter_name,
                        confidence=ConfidenceLevel.LOW,
                        payload={
                            "agent": agent_name,
                            "path": str(log_file),
                            "size_bytes": log_file.stat().st_size,
                            "note": "session file detected, content not parsed",
                        },
                    ))
            except Exception as e:
                logger.debug("Error reading agent dir %s: %s", agent_dir, e)

        return events
