"""Base observer interface for all AgentTrace sensors.

Every observer follows the same lifecycle: start watching, emit events
via callback, stop watching. Subclasses implement the platform-specific
sensing logic.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any
from uuid import UUID

from agenttrace.models.events import EventBase

logger = logging.getLogger(__name__)

# Callback type: receives an event and optional raw payload bytes
EventCallback = Callable[[EventBase, bytes | None], Any]


class BaseObserver(ABC):
    """Abstract base class for workspace observers.

    Observers are started per-session and emit canonical events via
    the registered callback. They must be safe to start/stop multiple
    times and must clean up their own resources.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
    ) -> None:
        self.session_id = session_id
        self.workspace_path = workspace_path
        self._callback = callback
        self._running = False
        self._task: asyncio.Task[None] | None = None

    @property
    def name(self) -> str:
        """Human-readable observer name."""
        return self.__class__.__name__

    @property
    def running(self) -> bool:
        """Whether the observer is currently active."""
        return self._running

    async def start(self) -> None:
        """Start the observer. Safe to call multiple times."""
        if self._running:
            logger.warning("%s already running", self.name)
            return
        self._running = True
        self._task = asyncio.create_task(self._run(), name=f"observer-{self.name}")
        logger.info("%s started for session %s", self.name, self.session_id)

    async def stop(self) -> None:
        """Stop the observer and clean up resources."""
        if not self._running:
            return
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("%s stopped for session %s", self.name, self.session_id)

    async def emit(self, event: EventBase, payload: bytes | None = None) -> None:
        """Emit an event through the registered callback."""
        try:
            result = self._callback(event, payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            logger.exception("Error in event callback for %s", self.name)

    @abstractmethod
    async def _run(self) -> None:
        """Main observer loop. Subclasses implement platform-specific logic.

        This coroutine runs until self._running becomes False or the
        task is cancelled. It should emit events via self.emit().
        """
        ...
