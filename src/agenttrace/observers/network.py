"""Network destination metadata observer using psutil.

Captures connection metadata (destination IP, port, protocol) for
processes within the watched workspace. HTTP method/status capture
is opt-in per workspace policy.
"""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import psutil

from agenttrace.models.events import ConfidenceLevel, NetworkEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 5.0

# Common local addresses to filter out
_LOCAL_ADDRS = {"127.0.0.1", "::1", "0.0.0.0", "::", ""}


class NetworkObserver(BaseObserver):
    """Monitors network connections from workspace-related processes.

    Uses psutil to poll active connections. By default captures only
    destination metadata (IP, port, protocol). Does not intercept
    or proxy traffic — that's an opt-in future enhancement.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
        poll_interval: float = _POLL_INTERVAL,
        tracked_pids: set[int] | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._poll_interval = poll_interval
        self._tracked_pids = tracked_pids or set()
        # Track connections we've already reported to avoid duplicates
        self._seen_connections: set[tuple[int, str, int, str]] = set()

    def update_tracked_pids(self, pids: set[int]) -> None:
        """Update the set of PIDs to monitor for network activity."""
        self._tracked_pids = pids

    async def _run(self) -> None:
        """Poll network connections at regular intervals."""
        logger.info("NetworkObserver started")

        try:
            while self._running:
                await asyncio.sleep(self._poll_interval)
                await self._scan_connections()
        except asyncio.CancelledError:
            logger.debug("NetworkObserver cancelled")
        except Exception:
            logger.exception("NetworkObserver error")

    async def _scan_connections(self) -> None:
        """Scan active network connections for tracked processes."""
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            logger.debug("Cannot access network connections (requires elevation)")
            return

        for conn in connections:
            # Skip if no remote address or not a tracked process
            if not conn.raddr:
                continue

            pid = conn.pid
            if pid is None:
                continue

            # If we have tracked PIDs, filter. Otherwise capture all.
            if self._tracked_pids and pid not in self._tracked_pids:
                continue

            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            # Skip local-only connections
            if remote_ip in _LOCAL_ADDRS:
                continue

            # Dedup key
            conn_key = (pid, remote_ip, remote_port, conn.type.name if hasattr(conn.type, 'name') else str(conn.type))
            if conn_key in self._seen_connections:
                continue
            self._seen_connections.add(conn_key)

            protocol = "tcp" if conn.type == 1 else "udp"  # SOCK_STREAM=1, SOCK_DGRAM=2
            direction = "outbound" if conn.status == "ESTABLISHED" else "unknown"

            event = NetworkEvent(
                session_id=self.session_id,
                actor_id=f"process:{pid}",
                source_adapter="network_observer",
                confidence=ConfidenceLevel.MEDIUM,
                destination_ip=remote_ip,
                destination_port=remote_port,
                protocol=protocol,
                direction=direction,
                process_pid=pid,
            )
            await self.emit(event)
