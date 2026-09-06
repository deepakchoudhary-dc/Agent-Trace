"""Composite AI Assistant Adapter.

Polls Codex CLI, Copilot Chat, Claude Code, and generic workspace adapters
simultaneously to ensure seamless coverage across all developer tools.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from agenttrace.adapters.claude import ClaudeAdapter
from agenttrace.adapters.codex import CodexAdapter
from agenttrace.adapters.copilot import CopilotAdapter
from agenttrace.adapters.generic import GenericAdapter
from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.events import EventBase, EventType

logger = logging.getLogger(__name__)


class CompositeAdapter(AdapterBase):
    """Aggregates multiple AI coding assistant adapters simultaneously."""

    def __init__(self, session_id: UUID, workspace_path: str) -> None:
        self._supported_types_cache: list[EventType] | None = None
        super().__init__(session_id, workspace_path)
        self._sub_adapters: list[AdapterBase] = [
            CodexAdapter(session_id, workspace_path),
            CopilotAdapter(session_id, workspace_path),
            ClaudeAdapter(session_id, workspace_path),
            GenericAdapter(session_id, workspace_path),
        ]

    @property
    def supported_event_types(self) -> list[EventType]:
        """Union of every event type any sub-adapter can emit.

        The daemon validates events against *this* adapter's supported types
        (the composite has no per-sub-adapter validation), so a type present
        in a sub-adapter but missing here is silently dropped at ingest —
        that is exactly how shell commands from agent transcripts were being
        lost in the default ``auto`` configuration.
        """
        if self._supported_types_cache is None:
            union: set[EventType] = set()
            for adapter in self._sub_adapters:
                union.update(adapter.supported_event_types)
            self._supported_types_cache = sorted(union, key=lambda t: t.value)
        return list(self._supported_types_cache)

    @property
    def adapter_name(self) -> str:
        return "multi_agent_composite"

    @property
    def adapter_version(self) -> str:
        return "0.1.0"

    @property
    def sdk_version(self) -> str:
        return SDK_VERSION

    async def start(self) -> None:
        self._running = True
        for adapter in self._sub_adapters:
            try:
                await adapter.start()
            except Exception as e:
                logger.debug("Failed starting sub-adapter %s: %s", adapter.adapter_name, e)
        logger.info("CompositeAdapter started with %d sub-adapters", len(self._sub_adapters))

    async def stop(self) -> None:
        self._running = False
        for adapter in self._sub_adapters:
            with contextlib.suppress(Exception):
                await adapter.stop()
        logger.info("CompositeAdapter stopped")

    async def poll(self) -> list[EventBase]:
        all_events: list[EventBase] = []
        if not self._running:
            return all_events

        for adapter in self._sub_adapters:
            try:
                events = await adapter.poll()
                all_events.extend(events)
            except Exception as e:
                logger.debug("Error polling sub-adapter %s: %s", adapter.adapter_name, e)

        return all_events

    def commit_cursor(self) -> None:
        for adapter in self._sub_adapters:
            with contextlib.suppress(Exception):
                adapter.commit_cursor()

    def rollback_cursor(self) -> None:
        for adapter in self._sub_adapters:
            with contextlib.suppress(Exception):
                adapter.rollback_cursor()
