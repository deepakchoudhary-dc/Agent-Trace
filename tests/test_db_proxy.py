"""Tests for Database Wire Protocol Interception Mediator."""

from __future__ import annotations

import struct

from agenttrace.security.db_proxy import (
    DatabaseWireParser,
    WireProtocolViolationError,
)


def _pg_packet(query: str) -> bytes:
    payload = (query + "\x00").encode("utf-8")
    return b"Q" + struct.pack("!I", len(payload) + 4) + payload


def _mysql_packet(query: str) -> bytes:
    query_bytes = query.encode("utf-8")
    pkt_len = len(query_bytes) + 1
    header = bytes([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF, (pkt_len >> 16) & 0xFF, 0, 0x03])
    return header + query_bytes


def _pg_startup_packet(protocol: int = 196608, params: bytes = b"user\x00db\x00\x00") -> bytes:
    """A Postgres StartupMessage: [Int32 length][Int32 protocol][params] — NO type byte."""
    payload = struct.pack("!I", protocol) + params
    return struct.pack("!I", len(payload) + 4) + payload


def test_postgres_wire_parser_extracts_simple_query() -> None:
    """DatabaseWireParser decodes PostgreSQL simple query messages."""
    queries, remainder = DatabaseWireParser.parse_postgres(_pg_packet("SELECT * FROM users;"))
    assert queries == ["SELECT * FROM users;"]
    assert remainder == b""


def test_postgres_wire_parser_detects_destructive_drop() -> None:
    """DatabaseWireParser flags DROP TABLE in PostgreSQL wire bytes."""
    queries, _ = DatabaseWireParser.parse_postgres(_pg_packet("DROP TABLE users CASCADE;"))
    assert len(queries) == 1
    is_destructive, matched = DatabaseWireParser.is_destructive(queries[0])
    assert is_destructive is True
    assert "DROP TABLE" in matched


def test_postgres_startup_packet_is_skipped_then_queries_parsed() -> None:
    """The startup message has NO type byte. Reading its length's high byte
    as the message type desynced the parser for the entire connection: no
    query was ever inspected (DROP TABLE passed through) and the buffer
    grew without bound."""
    stream = _pg_startup_packet() + _pg_packet("SELECT 1") + _pg_packet("DROP TABLE users")
    queries, remainder = DatabaseWireParser.parse_postgres(stream)
    assert queries == ["SELECT 1", "DROP TABLE users"]
    assert remainder == b""


def test_postgres_ssl_and_cancel_requests_carry_no_sql() -> None:
    """SSLRequest (8 bytes) and CancelRequest (16 bytes) are also untagged."""
    ssl_request = struct.pack("!II", 8, 80877103)
    cancel = struct.pack("!IIII", 16, 80877102, 1234, 5678)
    queries, remainder = DatabaseWireParser.parse_postgres(
        ssl_request + cancel + _pg_packet("SELECT 1")
    )
    assert queries == ["SELECT 1"]
    assert remainder == b""


def test_postgres_straddled_startup_packet_is_held_then_skipped() -> None:
    """A startup packet split across TCP chunks is buffered, then skipped."""
    packet = _pg_startup_packet() + _pg_packet("SELECT 1")
    cut = 3  # inside the startup packet's own length field
    q1, rem1 = DatabaseWireParser.parse_postgres(packet[:cut])
    assert q1 == []
    assert rem1 == packet[:cut]

    q2, rem2 = DatabaseWireParser.parse_postgres(packet[cut:], rem1)
    assert q2 == ["SELECT 1"]
    assert rem2 == b""


def test_postgres_truncated_startup_length_is_a_violation_not_a_hang() -> None:
    """A NUL-led packet whose declared length is absurd fails closed."""
    import pytest

    with pytest.raises(WireProtocolViolationError):
        DatabaseWireParser.parse_postgres(struct.pack("!I", 4))  # length < 8


def test_mysql_wire_parser_extracts_com_query() -> None:
    """DatabaseWireParser decodes MySQL COM_QUERY packets."""
    queries, remainder = DatabaseWireParser.parse_mysql(_mysql_packet("TRUNCATE TABLE logs"))
    assert queries == ["TRUNCATE TABLE logs"]
    assert remainder == b""

    is_destructive, matched = DatabaseWireParser.is_destructive(queries[0])
    assert is_destructive is True
    assert "TRUNCATE TABLE" in matched


def test_mysql_parses_every_packet_in_chunk() -> None:
    """A chunk holding several COM_QUERY packets yields every query (the old
    implementation inspected only the first packet per chunk)."""
    chunk = (
        _mysql_packet("SELECT 1")
        + _mysql_packet("DROP TABLE users")
        + _mysql_packet("SELECT 2")
    )
    queries, remainder = DatabaseWireParser.parse_mysql(chunk)
    assert queries == ["SELECT 1", "DROP TABLE users", "SELECT 2"]
    assert remainder == b""


def test_postgres_straddled_message_is_held_then_parsed() -> None:
    """A message split across TCP chunks is buffered, never forwarded
    uninspected, and parsed once complete."""
    packet = _pg_packet("DROP TABLE secrets")
    cut = 4  # inside the 5-byte header
    q1, rem1 = DatabaseWireParser.parse_postgres(packet[:cut])
    assert q1 == []
    assert rem1 == packet[:cut]

    q2, rem2 = DatabaseWireParser.parse_postgres(packet[cut:], rem1)
    assert q2 == ["DROP TABLE secrets"]
    assert rem2 == b""


def test_mysql_straddled_destructive_query_is_caught() -> None:
    """A destructive MySQL packet straddling a chunk boundary is still
    inspected — the exact DseWiki-adjacent hole this closes."""
    packet = _mysql_packet("DROP DATABASE prod")
    cut = 3  # header only; command + payload straddle
    q1, rem1 = DatabaseWireParser.parse_mysql(packet[:cut])
    assert q1 == []

    q2, _ = DatabaseWireParser.parse_mysql(packet[cut:], rem1)
    assert q2 == ["DROP DATABASE prod"]
    is_destructive, matched = DatabaseWireParser.is_destructive(q2[0])
    assert is_destructive is True
    assert "DROP DATABASE" in matched


def test_postgres_oversize_length_is_protocol_violation() -> None:
    """A declared length beyond the sanity cap raises instead of waiting
    forever on an unbounded buffer (fail-closed)."""
    hostile = b"Q" + struct.pack("!I", 2_000_000_000) + b"partial"
    try:
        DatabaseWireParser.parse_postgres(hostile)
    except WireProtocolViolationError:
        pass
    else:
        raise AssertionError("oversize postgres length must raise WireProtocolViolationError")


def test_mysql_zero_length_packet_is_protocol_violation() -> None:
    hostile = bytes([0, 0, 0, 0, 0x03]) + b"x"
    try:
        DatabaseWireParser.parse_mysql(hostile)
    except WireProtocolViolationError:
        pass
    else:
        raise AssertionError("zero-length mysql packet must raise WireProtocolViolationError")

