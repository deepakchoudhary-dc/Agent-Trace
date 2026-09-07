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

# Fail-closed sanity cap: a single wire message claiming more than this is a
# protocol violation (no legitimate agent SQL needs a 1 MB statement), not a
# buffer to wait on — unbounded retention would be its own DoS.
_MAX_MESSAGE_BYTES = 1_000_000


class WireProtocolViolationError(Exception):
    """The byte stream violates the database wire protocol.

    Raised by the parsers instead of silently discarding state: once a
    stream is uninspectable, the mediator must close the connection rather
    than forward bytes it can no longer vouch for.
    """


def _postgres_query_from_message(msg_type: str, payload: bytes) -> str:
    """Extract the SQL text from one complete Postgres message payload."""
    if msg_type == "Q":
        # Null-terminated query string
        query = payload.rstrip(b"\x00").decode("utf-8", errors="replace")
        return query.strip()
    if msg_type == "P":
        # Statement name (null-terminated) followed by query string (null-terminated)
        parts = payload.split(b"\x00")
        if len(parts) >= 2:
            return parts[1].decode("utf-8", errors="replace").strip()
    return ""


class DatabaseWireParser:
    """Decodes SQL query statements from database wire protocol byte streams.

    Both parsers are **streaming and buffer-carrying**: they consume any
    chunk of a TCP stream and return the extracted queries plus the
    unparsed remainder, so a message straddling a TCP boundary is held
    back and inspected once complete — never forwarded uninspected.
    """

    @staticmethod
    def parse_postgres(data: bytes, buffer: bytes = b"") -> tuple[list[str], bytes]:
        """Extract SQL queries from a PostgreSQL frontend byte stream.

        Postgres Message Format:
          [1 byte type] [4 bytes Int32 length] [payload]
          - 'Q' (0x51): Simple query string (null-terminated)
          - 'P' (0x50): Parse statement string

        Returns ``(queries, remainder)``; ``remainder`` holds an incomplete
        trailing message for the next call. A message whose declared length
        exceeds the fail-closed sanity cap is treated as a protocol
        violation: the connection buffer is discarded (fail-closed — the
        stream becomes uninspectable, so it must not pass through).
        """
        buf = buffer + data
        queries: list[str] = []
        while len(buf) >= 5:
            msg_type = chr(buf[0])
            msg_len = struct.unpack("!I", buf[1:5])[0]
            if msg_len < 4 or msg_len - 4 > _MAX_MESSAGE_BYTES:
                raise WireProtocolViolationError(
                    f"postgres message length {msg_len} violates protocol bounds"
                )
            if 1 + msg_len > len(buf):
                break  # incomplete message — hold it in the remainder
            payload = buf[5 : 1 + msg_len]
            query = _postgres_query_from_message(msg_type, payload)
            if query:
                queries.append(query)
            buf = buf[1 + msg_len :]
        return queries, buf

    @staticmethod
    def parse_mysql(data: bytes, buffer: bytes = b"") -> tuple[list[str], bytes]:
        """Extract SQL queries from a MySQL client byte stream.

        MySQL Packet Format:
          [3 bytes length] [1 byte sequence id] [1 byte command] [payload]
          - 0x03 (COM_QUERY): query string
          - 0x16 (COM_STMT_PREPARE): prepare string

        Streams every packet in the chunk (the previous implementation
        inspected only the first), returning ``(queries, remainder)`` for
        the incomplete trailing packet. Header/packet-length violations
        discard the buffer: fail-closed.
        """
        buf = buffer + data
        queries: list[str] = []
        while True:
            if len(buf) < 5:
                break  # incomplete header — hold it
            # 3-byte little endian packet length (+1 for the command byte)
            pkt_len = buf[0] | (buf[1] << 8) | (buf[2] << 16)
            if pkt_len < 1 or pkt_len - 1 > _MAX_MESSAGE_BYTES:
                raise WireProtocolViolationError(
                    f"mysql packet length {pkt_len} violates protocol bounds"
                )
            if 4 + pkt_len > len(buf):
                break  # incomplete packet — hold it
            cmd = buf[4]
            if cmd in (0x03, 0x16):  # COM_QUERY or COM_STMT_PREPARE
                query_bytes = buf[5 : 4 + pkt_len]
                query = query_bytes.decode("utf-8", errors="replace").strip()
                if query:
                    queries.append(query)
            buf = buf[4 + pkt_len :]
        return queries, buf

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
        on_protocol_violation: Callable[[str, str], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.db_type = db_type.lower()
        self.on_destructive_query = on_destructive_query
        self.on_protocol_violation = on_protocol_violation
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

        # Per-connection parser buffer: a message straddling a TCP chunk is
        # held here and inspected once complete — never forwarded uninspected.
        upstream_buf = b""

        async def forward_upstream() -> None:
            nonlocal upstream_buf
            try:
                while self._running:
                    data = await client_reader.read(4096)
                    if not data:
                        break

                    # Inspect queries (streaming, buffer-carrying, fail-closed)
                    if self.db_type == "postgres":
                        queries, upstream_buf = DatabaseWireParser.parse_postgres(
                            data, upstream_buf
                        )
                    elif self.db_type == "mysql":
                        queries, upstream_buf = DatabaseWireParser.parse_mysql(
                            data, upstream_buf
                        )
                    else:
                        # No parser for this protocol: we cannot vouch for the
                        # bytes, so they must not pass through (fail-closed).
                        logger.error(
                            "Database mediator has no parser for db_type %r; "
                            "closing connection (fail-closed)",
                            self.db_type,
                        )
                        if self.on_protocol_violation:
                            self.on_protocol_violation(
                                "unknown_protocol", f"db_type={self.db_type}"
                            )
                        client_writer.close()
                        return

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
            except WireProtocolViolationError as e:
                logger.error(
                    "Database mediator wire-protocol violation (%s): %s — closing "
                    "connection (fail-closed)",
                    self.db_type,
                    e,
                )
                if self.on_protocol_violation:
                    self.on_protocol_violation("wire_violation", str(e))
                client_writer.close()
            except Exception:
                logger.debug("Database mediator upstream stream ended", exc_info=True)
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
