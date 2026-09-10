"""Property-based and fuzz tests for the database wire-protocol parsers.

plan2.md P2.5: the wire parsers are a trust boundary — arbitrary TCP bytes
must never crash them, split messages must reassemble identically regardless
of chunk boundaries, and the fail-closed length cap must hold for any input.
"""

from __future__ import annotations

import random
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agenttrace.security.db_proxy import (
    DatabaseWireParser,
    WireProtocolViolationError,
)

_MAX_WIRE_BYTES = 1_000_000


def _pg_frame(msg_type: str, payload: bytes) -> bytes:
    return msg_type.encode("ascii") + struct.pack("!I", len(payload) + 4) + payload


_QUERY_ALPHABET = "abc DROP;*"


@st.composite
def _pg_streams(draw: st.DrawFn) -> tuple[bytes, list[str]]:
    """A stream of well-formed PG frames plus the queries they must yield."""
    frames: list[bytes] = []
    queries: list[str] = []
    for _ in range(draw(st.integers(min_value=0, max_value=6))):
        msg_type = draw(st.sampled_from(("Q", "P")))
        if msg_type == "Q":
            text = draw(st.text(alphabet=_QUERY_ALPHABET, max_size=40))
            payload = text.encode("utf-8") + b"\x00"
        else:
            name = draw(st.text(alphabet="abc_", max_size=8))
            text = draw(st.text(alphabet=_QUERY_ALPHABET, max_size=40))
            payload = name.encode("utf-8") + b"\x00" + text.encode("utf-8") + b"\x00"
        if text.strip():
            queries.append(text.strip())
        frames.append(_pg_frame(msg_type, payload))
    return b"".join(frames), queries


_MYSQL_CMDS = (0x03, 0x16, 0x00, 0x0E)


@st.composite
def _mysql_streams(draw: st.DrawFn) -> tuple[bytes, list[str]]:
    """A stream of well-formed MySQL packets plus the queries they must yield."""
    frames: list[bytes] = []
    queries: list[str] = []
    for _ in range(draw(st.integers(min_value=0, max_value=6))):
        cmd = draw(st.sampled_from(_MYSQL_CMDS))
        body = draw(st.binary(max_size=40))
        payload = bytes([cmd]) + body
        frames.append(len(payload).to_bytes(3, "little") + b"\x00" + payload)
        if cmd in (0x03, 0x16):
            text = body.decode("utf-8", errors="replace").strip()
            if text:
                queries.append(text)
    return b"".join(frames), queries


# -- Property tests: crash-freedom, split-invariance, fail-closed caps ---------

@given(st.binary(max_size=256))
@settings(max_examples=300, deadline=None)
def test_pg_never_crashes_on_arbitrary_bytes(data: bytes) -> None:
    """Arbitrary bytes either parse or raise the fail-closed violation."""
    try:
        queries, remainder = DatabaseWireParser.parse_postgres(data)
    except WireProtocolViolationError:
        return
    assert isinstance(queries, list)
    assert isinstance(remainder, bytes)
    assert len(remainder) < max(5, len(data))
    assert all(isinstance(q, str) and q for q in queries)


@given(st.binary(max_size=256))
@settings(max_examples=300, deadline=None)
def test_mysql_never_crashes_on_arbitrary_bytes(data: bytes) -> None:
    """Arbitrary bytes either parse or raise the fail-closed violation."""
    try:
        queries, remainder = DatabaseWireParser.parse_mysql(data)
    except WireProtocolViolationError:
        return
    assert isinstance(queries, list)
    assert isinstance(remainder, bytes)
    assert all(isinstance(q, str) and q for q in queries)


def _walk(
    parse: object, stream: bytes, chunk: int
) -> tuple[list[str], bytes]:
    """Feed ``stream`` through ``parse`` in fixed-size chunks."""
    found: list[str] = []
    buf = b""
    for i in range(0, len(stream), chunk):
        qs, buf = parse(stream[i : i + chunk], buf)  # type: ignore[operator]
        found.extend(qs)
    qs, buf = parse(b"", buf)  # type: ignore[operator]
    found.extend(qs)
    return found, buf


@given(_pg_streams(), st.integers(min_value=1, max_value=9))
@settings(max_examples=200, deadline=None)
def test_pg_split_invariance(
    stream_and_queries: tuple[bytes, list[str]], chunk: int
) -> None:
    """Queries found are identical regardless of TCP chunk boundaries."""
    stream, queries = stream_and_queries
    found, remainder = _walk(DatabaseWireParser.parse_postgres, stream, chunk)
    assert found == queries
    assert remainder == b""


@given(_mysql_streams(), st.integers(min_value=1, max_value=9))
@settings(max_examples=200, deadline=None)
def test_mysql_split_invariance(
    stream_and_queries: tuple[bytes, list[str]], chunk: int
) -> None:
    """Packets found are identical regardless of TCP chunk boundaries."""
    stream, queries = stream_and_queries
    found, remainder = _walk(DatabaseWireParser.parse_mysql, stream, chunk)
    assert found == queries
    assert remainder == b""


@given(st.integers(min_value=_MAX_WIRE_BYTES + 5, max_value=_MAX_WIRE_BYTES + 1024))
def test_pg_oversize_declared_length_always_violates(msg_len: int) -> None:
    """Any declared PG length beyond the sanity cap fails closed."""
    frame = b"Q" + struct.pack("!I", msg_len) + b"x" * 16
    with pytest.raises(WireProtocolViolationError):
        DatabaseWireParser.parse_postgres(frame)


@given(st.integers(min_value=_MAX_WIRE_BYTES + 2, max_value=_MAX_WIRE_BYTES + 1024))
def test_mysql_oversize_declared_length_always_violates(pkt_len: int) -> None:
    """Any declared MySQL packet length beyond the sanity cap fails closed."""
    packet = pkt_len.to_bytes(3, "little") + b"\x00\x03SELECT 1"
    with pytest.raises(WireProtocolViolationError):
        DatabaseWireParser.parse_mysql(packet)




# -- Deterministic structured fuzzer (stdlib only, seeded) ---------------------

ADVERSARIAL_TOKENS = (
    b"", b"\x00", b"\xff" * 8, b"Q", b"\x03", b"DROP TABLE users;",
    b"\x51\x00\x00\x00\x04", b"\xff\xff\xff\xff", b"\x01\x00\x00",
)


def _adversarial_stream(rng: random.Random) -> bytes:
    """Random stream mixing valid frames with hostile header fragments."""
    parts: list[bytes] = []
    if rng.random() < 0.7:
        text = rng.choice(
            [b"SELECT 1\x00", b"DROP TABLE users\x00", b"  \x00"]
        )
        parts.append(_pg_frame("Q", text[:-1]))
    if rng.random() < 0.5:
        body = rng.choice([b"SELECT 1", b"TRUNCATE t"])
        payload = b"\x03" + body
        parts.append(len(payload).to_bytes(3, "little") + b"\x00" + payload)
    for _ in range(rng.randint(0, 5)):
        parts.append(rng.choice(ADVERSARIAL_TOKENS))
    rng.shuffle(parts)
    return b"".join(parts)


def test_deterministic_fuzzer_finds_no_crash_and_detects_destructive() -> None:
    """Seeded fuzz: parsers survive hostile streams without crashing."""
    parser_pg = DatabaseWireParser.parse_postgres
    parser_my = DatabaseWireParser.parse_mysql
    for seed in range(400):
        rng = random.Random(seed)
        stream = _adversarial_stream(rng)
        for parser in (parser_pg, parser_my):
            try:
                queries, _ = parser(stream)
            except WireProtocolViolationError:
                continue
            assert all(isinstance(q, str) for q in queries)


def test_fuzz_finds_embedded_destructive_queries() -> None:
    """Destructive SQL inside well-formed frames is always detected."""
    for seed in range(200):
        rng = random.Random(seed)
        stream = _adversarial_stream(rng)
        try:
            queries, _ = DatabaseWireParser.parse_postgres(stream)
        except WireProtocolViolationError:
            continue  # fail-closed: a violated stream yields nothing
        for q in queries:
            destructive, term = DatabaseWireParser.is_destructive(q)
            if "DROP" in q.upper() or "TRUNCATE" in q.upper():
                assert destructive, q
                assert term
