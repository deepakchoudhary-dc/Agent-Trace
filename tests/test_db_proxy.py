"""Tests for Database Wire Protocol Interception Mediator."""

from __future__ import annotations

import struct
from uuid import uuid4

from agenttrace.security.db_proxy import DatabaseProtocolMediator, DatabaseWireParser


def test_postgres_wire_parser_extracts_simple_query() -> None:
    """DatabaseWireParser decodes PostgreSQL simple query messages."""
    query_str = "SELECT * FROM users WHERE active = true;\x00"
    payload = query_str.encode("utf-8")
    msg_len = len(payload) + 4
    packet = b"Q" + struct.pack("!I", msg_len) + payload

    queries = DatabaseWireParser.parse_postgres(packet)
    assert queries == ["SELECT * FROM users WHERE active = true;"]


def test_postgres_wire_parser_detects_destructive_drop() -> None:
    """DatabaseWireParser flags DROP TABLE in PostgreSQL wire bytes."""
    query_str = "DROP TABLE users CASCADE;\x00"
    payload = query_str.encode("utf-8")
    msg_len = len(payload) + 4
    packet = b"Q" + struct.pack("!I", msg_len) + payload

    queries = DatabaseWireParser.parse_postgres(packet)
    assert len(queries) == 1

    is_destructive, matched = DatabaseWireParser.is_destructive(queries[0])
    assert is_destructive is True
    assert "DROP TABLE" in matched


def test_mysql_wire_parser_extracts_com_query() -> None:
    """DatabaseWireParser decodes MySQL COM_QUERY packets."""
    query_str = "TRUNCATE TABLE logs"
    query_bytes = query_str.encode("utf-8")
    pkt_len = len(query_bytes) + 1
    # 3-byte len (little endian) + 1-byte seq (0) + 1-byte cmd (0x03) + payload
    header = bytes([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF, (pkt_len >> 16) & 0xFF, 0, 0x03])
    packet = header + query_bytes

    queries = DatabaseWireParser.parse_mysql(packet)
    assert queries == ["TRUNCATE TABLE logs"]

    is_destructive, matched = DatabaseWireParser.is_destructive(queries[0])
    assert is_destructive is True
    assert "TRUNCATE TABLE" in matched


def test_database_mediator_initialization() -> None:
    """DatabaseProtocolMediator initializes cleanly with target config."""
    sid = uuid4()
    mediator = DatabaseProtocolMediator(
        session_id=sid,
        listen_port=15432,
        target_port=5432,
        db_type="postgres",
    )
    assert mediator.session_id == sid
    assert mediator.listen_port == 15432
    assert mediator.db_type == "postgres"
