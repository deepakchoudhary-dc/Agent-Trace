"""Generic host-observer adapter — fallback for any AI tool.

When no deep adapter is available, the generic adapter provides
host-level evidence: file changes, git state, process trees, shell
commands, test/build output, package changes, and network metadata.

It clearly marks unavailable agent-internal context as gaps.
"""

from __future__ import annotations

import logging

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import EventBase, EventType

logger = logging.getLogger(__name__)


class GenericAdapter(AdapterBase):
    """Generic host-level observer adapter.

    This adapter doesn't integrate with any specific agent's internals.
    Instead, it relies on the observers (filesystem, process, git,
    terminal, network) to capture host-level evidence.

    Its observability gaps are explicitly declared so the UI shows
    what's unknown rather than fabricating explanations.
    """

    @property
    def adapter_name(self) -> str:
        return "generic"

    @property
    def adapter_version(self) -> str:
        return "0.1.0"

    @property
    def sdk_version(self) -> str:
        return SDK_VERSION

    @property
    def supported_event_types(self) -> list[EventType]:
        return [
            EventType.FILE_MUTATION,
            EventType.PROCESS,
            EventType.COMMAND,
            EventType.NETWORK,
            EventType.GIT,
            EventType.TEST_RESULT,
            EventType.BUILD_RESULT,
            EventType.SESSION_START,
            EventType.SESSION_END,
        ]

    @property
    def observability_gaps(self) -> list[str]:
        """What the generic adapter explicitly cannot observe."""
        return [
            "Agent's internal reasoning and decision process",
            "Agent's context window contents and token usage",
            "Tool request rationale and selection logic",
            "Agent's system prompt and configuration",
            "Communication between agent and model API",
            "Approval decisions made within the agent's UI",
        ]

    async def start(self) -> None:
        """Start the generic adapter (no-op — observers do the work)."""
        self._running = True
        logger.info("GenericAdapter started (host-level observation only)")

    async def stop(self) -> None:
        """Stop the generic adapter."""
        self._running = False
        logger.info("GenericAdapter stopped")

    async def poll(self) -> list[EventBase]:
        """Generic adapter doesn't poll — events come from observers.

        The observers (filesystem, process, git, etc.) emit events
        directly into the daemon's event pipeline. The generic adapter
        exists mainly to declare capabilities and gaps.
        """
        return []
