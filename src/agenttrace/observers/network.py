"""Network destination metadata observer using psutil.

Captures connection metadata (destination IP, port, protocol) for
processes strictly within the watched workspace.
"""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID

import psutil  # type: ignore[import-untyped]

from agenttrace.models.events import ConfidenceLevel, NetworkEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 4.0

# Common local addresses to filter out
_LOCAL_ADDRS = {"127.0.0.1", "::1", "0.0.0.0", "::", "localhost", ""}

# Connection states that prove an *outbound* connection to the destination.
# TIME_WAIT/CLOSE_WAIT/FIN_WAIT linger after completion (~60s), so a
# short-lived connection (a curl POST, a gym-cancellation DELETE) that is
# gone by the next poll still leaves evidence of having happened.
_OUTBOUND_STATUSES = {
    "ESTABLISHED", "SYN_SENT", "SYN-RECEIVED", "CLOSE_WAIT", "LAST_ACK",
    "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSING",
}


class NetworkObserver(BaseObserver):
    """Monitors network connections from workspace-related processes.

    Captures only destination metadata for verified workspace processes.
    Never collects arbitrary system-wide connection telemetry.
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
        self._tracked_pids = tracked_pids if tracked_pids is not None else set()
        # Track connections we've already reported to avoid duplicates
        self._seen_connections: set[tuple[int, str, int, str]] = set()

    def update_tracked_pids(self, pids: set[int]) -> None:
        """Update the set of PIDs to monitor for network activity."""
        self._tracked_pids = set(pids)

    async def _run(self) -> None:
        """Poll network connections at regular intervals."""
        logger.info("NetworkObserver started (strict workspace process tracking)")

        try:
            while self._running:
                await asyncio.sleep(self._poll_interval)
                await self._scan_connections()
        except asyncio.CancelledError:
            logger.debug("NetworkObserver cancelled")
        except Exception:
            logger.exception("NetworkObserver error")

    async def _scan_connections(self) -> None:
        """Scan active network connections strictly for workspace-scoped processes."""
        # If no workspace processes are active, do NOT collect system-wide connections
        if not self._tracked_pids:
            return

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            logger.debug("Cannot access network connections (requires elevation)")
            return

        for conn in connections:
            if not conn.raddr:
                continue

            pid = conn.pid
            if pid is None or pid not in self._tracked_pids:
                continue

            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            # Skip local-only connections
            if remote_ip in _LOCAL_ADDRS:
                continue

            # Dedup key
            conn_key = (pid, remote_ip, remote_port, str(conn.type))
            if conn_key in self._seen_connections:
                continue
            self._seen_connections.add(conn_key)

            protocol = "tcp" if conn.type == 1 else "udp"
            direction = (
                "outbound"
                if (conn.status or "").upper() in _OUTBOUND_STATUSES
                else "unknown"
            )
            # Capture the state so downstream engines can weight short-lived
            # completed connections (TIME_WAIT) as completed egress
            conn_state = (conn.status or "").upper()

            event = NetworkEvent(
                session_id=self.session_id,
                actor_id=f"process:{pid}",
                source_adapter="network_observer",
                confidence=ConfidenceLevel.HIGH,
                destination_ip=remote_ip,
                destination_port=remote_port,
                protocol=protocol,
                direction=direction,
                process_pid=pid,
                payload={"conn_state": conn_state, "connection_status": conn.status or ""},
            )
            await self.emit(event)
