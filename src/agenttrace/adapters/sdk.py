"""Adapter SDK — versioned event contract for agent integrations.

New integrations implement AdapterBase to map vendor-specific events
into the canonical AgentTrace schema. The SDK enforces the contract:
actor/session identity, timestamps, payload classification, provenance,
evidence locators, and confidence levels.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import EventBase, EventType

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# SDK version — adapters must declare compatibility
SDK_VERSION = "0.1.0"


class AdapterError(Exception):
    """Raised when adapter operations fail."""


class AdapterBase(ABC):
    """Base class for all AgentTrace adapters.

    Adapters translate vendor-specific telemetry into canonical events.
    They must declare their capabilities and the types of events they
    can emit. The daemon will only accept events matching declared types.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
    ) -> None:
        self.session_id = session_id
        self.workspace_path = workspace_path
        self._running = False

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Unique identifier for this adapter."""
        ...

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Version of this adapter."""
        ...

    @property
    @abstractmethod
    def sdk_version(self) -> str:
        """SDK version this adapter is compatible with."""
        ...

    @property
    @abstractmethod
    def supported_event_types(self) -> list[EventType]:
        """Event types this adapter can emit."""
        ...

    @property
    def capabilities(self) -> dict[str, bool]:
        """What this adapter can observe.

        Returns a dict of capability → available. Used by the UI
        to show what's observable vs. what's a gap.
        """
        return {
            "invocation": EventType.INVOCATION in self.supported_event_types,
            "user_intent": EventType.INVOCATION in self.supported_event_types,
            "context_boundary": EventType.CONTEXT_BOUNDARY in self.supported_event_types,
            "tool_requests": EventType.TOOL_REQUEST in self.supported_event_types,
            "tool_results": EventType.TOOL_RESULT in self.supported_event_types,
            "approvals": EventType.APPROVAL in self.supported_event_types,
            "session_identity": True,  # All adapters must provide this
        }

    @property
    def observability_gaps(self) -> list[str]:
        """Explicitly list what this adapter CANNOT observe.

        This is critical for trust: we never fabricate explanations
        for things we can't see.
        """
        gaps = []
        if EventType.CONTEXT_BOUNDARY not in self.supported_event_types:
            gaps.append("Agent's internal context window contents")
        if EventType.INVOCATION not in self.supported_event_types:
            gaps.append("Agent's reasoning chain and decision process")
        if EventType.TOOL_REQUEST not in self.supported_event_types:
            gaps.append("Tool request details (args, rationale)")
        return gaps

    @abstractmethod
    async def start(self) -> None:
        """Start the adapter."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop the adapter and clean up."""
        ...

    @abstractmethod
    async def poll(self) -> list[EventBase]:
        """Poll for new events from the vendor source.

        Returns a list of canonical events translated from vendor format.
        """
        ...

    def cursor_state(self) -> dict[str, Any]:
        """Serializable position state for resuming after a restart.

        Subclasses tracking file offsets / seen records override this so the
        daemon can persist the cursor and restore it on the next start —
        otherwise a restarted session would either replay its whole source
        (duplicate events) or skip events that happened while it was down.
        """
        return {}

    def restore_cursor(self, state: dict[str, Any]) -> None:
        """Restore position state persisted by :meth:`cursor_state`."""
        return None

    def validate_event(self, event: EventBase) -> bool:
        """Validate that an event meets the SDK contract."""
        if not event.event_id:
            logger.error("Event missing event_id")
            return False
        if not event.session_id:
            logger.error("Event missing session_id")
            return False
        if not event.actor_id:
            logger.error("Event missing actor_id")
            return False
        if not event.timestamp:
            logger.error("Event missing timestamp")
            return False
        if not event.source_adapter:
            logger.error("Event missing source_adapter")
            return False
        if event.event_type not in self.supported_event_types:
            logger.error(
                "Event type %s not in adapter's supported types",
                event.event_type,
            )
            return False
        return True
