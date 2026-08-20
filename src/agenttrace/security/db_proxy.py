"""Database Wire-Protocol Interception Mediator for AgentTrace.

Inspects PostgreSQL (port 5432) and MySQL (port 3306) raw binary wire protocol
frames in real-time, decoding SQL statements directly from TCP byte streams to
detect and block database destruction (DROP, TRUNCATE) before reaching the server.
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

logger = logging.getLogger(__name__)

# Destructive SQL statement patterns
_DESTRUCTIVE_SQL_PATTERN = re.compile(
    r"\b(DROP\s+DATABASE|DROP\s+SCHEMA|DROP\s+TABLE|TRUNCATE\s+TABLE|TRUNCATE|ALTER\s+TABLE\s+.*DROP\s+COLUMN)\b",
    re.IGNORECASE,
)


class DatabaseWireParser:
    """Decodes SQL query statements from raw database wire protocol packets."""

    @staticmethod
    def parse_postgres(data: bytes) -> list[str]:
        """Extract SQL queries from PostgreSQL frontend wire protocol bytes.

        Postgres Message Format:
          [1 byte type] [4 bytes Int32 length] [payload]
          - 'Q' (0x51): Simple query string (null-terminated)
          - 'P' (0x50): Parse statement string
        """
        queries: list[str] = []
        offset = 0
        total_len = len(data)

        while offset + 5 <= total_len:
            msg_type = chr(data[offset])
            try:
                msg_len = struct.unpack("!I", data[offset + 1 : offset + 5])[0]
            except Exception:
                break

            if msg_len < 4 or offset + 1 + msg_len > total_len:
                break

            payload = data[offset + 5 : offset + 1 + msg_len]

            if msg_type == "Q":
                # Null-terminated query string
                query = payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                if query.strip():
                    queries.append(query.strip())
            elif msg_type == "P":
                # Statement name (null-terminated) followed by query string (null-terminated)
                parts = payload.split(b"\x00")
                if len(parts) >= 2:
                    query = parts[1].decode("utf-8", errors="replace")
                    if query.strip():
                        queries.append(query.strip())

            offset += 1 + msg_len

        return queries

    @staticmethod
    def parse_mysql(data: bytes) -> list[str]:
        """Extract SQL queries from MySQL client wire protocol bytes.

        MySQL Packet Format:
          [3 bytes length] [1 byte sequence id] [1 byte command] [payload]
          - 0x03 (COM_QUERY): query string
          - 0x16 (COM_STMT_PREPARE): prepare string
        """
        queries: list[str] = []
        if len(data) < 5:
            return queries

        try:
            # 3-byte little endian packet length
            pkt_len = data[0] | (data[1] << 8) | (data[2] << 16)
            cmd = data[4]

            if cmd in (0x03, 0x16):  # COM_QUERY or COM_STMT_PREPARE
                query_bytes = data[5 : 4 + pkt_len]
                query = query_bytes.decode("utf-8", errors="replace").strip()
                if query:
                    queries.append(query)
        except Exception as e:
            logger.debug("MySQL packet parse error: %s", e)

        return queries

    @classmethod
    def is_destructive(cls, query: str) -> tuple[bool, str]:
        """Check if an extracted SQL statement is destructive."""
        match = _DESTRUCTIVE_SQL_PATTERN.search(query)
        if match:
            return True, match.group(0).upper()
        return False, ""


class DatabaseProtocolMediator:
    """Local proxy mediator that intercepts and filters database connections."""

    def __init__(
        self,
        session_id: UUID,
        listen_host: str = "127.0.0.1",
        listen_port: int = 15432,
        target_host: str = "127.0.0.1",
        target_port: int = 5432,
        db_type: str = "postgres",
        on_destructive_query: Callable[[str, str], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.db_type = db_type.lower()
        self.on_destructive_query = on_destructive_query
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        """Start the database proxy server."""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        logger.info(
            "Database mediator listening on %s:%d (proxying to %s:%d, type=%s)",
            self.listen_host,
            self.listen_port,
            self.target_host,
            self.target_port,
            self.db_type,
        )

    async def stop(self) -> None:
        """Stop the database proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """Proxy client traffic to upstream database with real-time query filtering."""
        target_reader, target_writer = None, None
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except Exception as e:
            logger.warning("Database mediator could not connect to target DB: %s", e)
            client_writer.close()
            return

        async def forward_upstream() -> None:
            try:
                while self._running:
                    data = await client_reader.read(4096)
                    if not data:
                        break

                    # Inspect queries
                    if self.db_type == "postgres":
                        queries = DatabaseWireParser.parse_postgres(data)
                    elif self.db_type == "mysql":
                        queries = DatabaseWireParser.parse_mysql(data)
                    else:
                        queries = []

                    for query in queries:
                        destructive, matched_term = DatabaseWireParser.is_destructive(query)
                        if destructive:
                            logger.critical(
                                "Database mediator BLOCKED destructive query: %s (matched: %s)",
                                query,
                                matched_term,
                            )
                            if self.on_destructive_query:
                                self.on_destructive_query(query, matched_term)

                            # Return error response to client and drop connection
                            if self.db_type == "postgres":
                                err_msg = (
                                    b"SERROR\x00C42501\x00M"
                                    b"AgentTrace: Destructive SQL query blocked by policy\x00\x00"
                                )
                                pkt = b"E" + struct.pack("!I", len(err_msg) + 4) + err_msg
                                client_writer.write(pkt)
                                await client_writer.drain()
                            client_writer.close()
                            return

                    target_writer.write(data)
                    await target_writer.drain()
            except Exception:
                pass
            finally:
                if target_writer:
                    target_writer.close()

        async def forward_downstream() -> None:
            try:
                while self._running:
                    data = await target_reader.read(4096)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception:
                pass
            finally:
                client_writer.close()

        await asyncio.gather(forward_upstream(), forward_downstream(), return_exceptions=True)
