"""Tests for the network observer — short-lived connection capture.

TIME_WAIT/CLOSE_WAIT/SYN_SENT connections are evidence of *completed or
attempted* outbound traffic even when the connection itself is gone by the
next poll — the fix that makes sub-second requests (a gym-cancellation
DELETE, a PyPI upload) visible instead of missed.
"""

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agenttrace.observers.network import NetworkObserver


@pytest.mark.asyncio
async def test_captures_time_wait_as_outbound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    seen = []

    async def cb(event, payload=None) -> None:
        seen.append(event)

    observer = NetworkObserver(uuid4(), str(workspace), cb)
    observer.update_tracked_pids({42})

    fake_conn = SimpleNamespace(
        raddr=SimpleNamespace(ip="8.8.8.8", port=443),
        pid=42,
        type=1,  # SOCK_STREAM → tcp
        status="TIME_WAIT",
    )
    monkeypatch.setattr(
        "agenttrace.observers.network.psutil.net_connections",
        lambda kind="inet": [fake_conn],
    )

    await observer._scan_connections()

    assert len(seen) == 1
    ev = seen[0]
    assert ev.destination_ip == "8.8.8.8"
    assert ev.destination_port == 443
    assert ev.direction == "outbound"
    assert ev.payload.get("conn_state") == "TIME_WAIT"


@pytest.mark.asyncio
async def test_captures_syn_sent_as_outbound_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    seen = []

    async def cb(event, payload=None) -> None:
        seen.append(event)

    observer = NetworkObserver(uuid4(), str(workspace), cb)
    observer.update_tracked_pids({7})

    fake_conn = SimpleNamespace(
        raddr=SimpleNamespace(ip="203.0.113.9", port=80),
        pid=7,
        type=1,
        status="SYN_SENT",
    )
    monkeypatch.setattr(
        "agenttrace.observers.network.psutil.net_connections",
        lambda kind="inet": [fake_conn],
    )

    await observer._scan_connections()

    assert len(seen) == 1
    assert seen[0].direction == "outbound"


@pytest.mark.asyncio
async def test_untracked_pids_not_collected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    seen = []

    async def cb(event, payload=None) -> None:
        seen.append(event)

    observer = NetworkObserver(uuid4(), str(workspace), cb)
    observer.update_tracked_pids({1})  # only pid 1 tracked

    fake_conn = SimpleNamespace(
        raddr=SimpleNamespace(ip="8.8.8.8", port=443),
        pid=999,  # not tracked
        type=1,
        status="ESTABLISHED",
    )
    monkeypatch.setattr(
        "agenttrace.observers.network.psutil.net_connections",
        lambda kind="inet": [fake_conn],
    )

    await observer._scan_connections()
    assert seen == []


@pytest.mark.asyncio
async def test_no_scan_without_tracked_pids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    seen = []

    async def cb(event, payload=None) -> None:
        seen.append(event)

    observer = NetworkObserver(uuid4(), str(workspace), cb)
    # no update_tracked_pids → empty set → no system-wide collection

    def boom(kind="inet"):
        raise AssertionError("must not scan when no workspace processes are tracked")

    monkeypatch.setattr(
        "agenttrace.observers.network.psutil.net_connections", boom
    )

    await observer._scan_connections()
    assert seen == []
