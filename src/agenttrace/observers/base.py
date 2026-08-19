"""Base observer interface for all AgentTrace sensors.

Every observer follows the same lifecycle: start watching, emit events
via callback, stop watching. Subclasses implement the platform-specific
sensing logic.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import EventBase

if TYPE_CHECKING:
    from uuid import UUID

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
        # Observability gaps: reasons this sensor cannot see parts of the
        # environment (privilege denials, unsupported platform features).
        # Surfaced in session responses so "we don't know" is explicit.
        self.observability_gaps: list[str] = []
        self._dropped_events = 0
        self._last_callback_error: Exception | None = None

    @property
    def name(self) -> str:
        """Human-readable observer name."""
        return self.__class__.__name__

    @property
    def running(self) -> bool:
        """Whether the observer is currently active."""
        return self._running

    @property
    def dropped_events(self) -> int:
        """Number of events lost because the callback rejected them."""
        return self._dropped_events

    def _record_gap(self, message: str) -> None:
        """Record an observability gap (deduplicated) for surfacing."""
        if message not in self.observability_gaps:
            self.observability_gaps.append(message)

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
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self._task = None
        logger.info("%s stopped for session %s", self.name, self.session_id)

    async def emit(self, event: EventBase, payload: bytes | None = None) -> None:
        """Emit an event through the registered callback.

        Callback failures are counted and recorded as a gap instead of being
        swallowed silently: a dropping callback creates a blind spot that must
        be visible in the session's observability report.
        """
        try:
            result = self._callback(event, payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            self._dropped_events += 1
            self._last_callback_error = exc
            self._record_gap(
                f"{self.name}: {self._dropped_events} event(s) dropped by callback "
                f"({type(exc).__name__}: {exc})"
            )
            logger.exception("Error in event callback for %s", self.name)

    @abstractmethod
    async def _run(self) -> None:
        """Main observer loop. Subclasses implement platform-specific logic.

        This coroutine runs until self._running becomes False or the
        task is cancelled. It should emit events via self.emit().
        """
        ...
