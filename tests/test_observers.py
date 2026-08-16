"""Tests for observer hygiene fixes (P1-5):

- GitMonitor: read-only index check (never ``git write-tree``)
- TerminalObserver: post-rotation history capture, bounded seen-set
- FilesystemObserver: bounded content cache, baseline hash seeding
- NetworkObserver: time-windowed dedup, protocol labels, IPv4-mapped IPv6
"""

from __future__ import annotations

import asyncio
import subprocess
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import psutil  # type: ignore[import-untyped]

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    GitEvent,
    NetworkEvent,
)
from agenttrace.observers.filesystem import FilesystemObserver
from agenttrace.observers.git_monitor import GitMonitor
from agenttrace.observers.network import NetworkObserver
from agenttrace.observers.terminal import TerminalObserver

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path


def _collector() -> tuple[list[Any], Callable[[Any, bytes | None], Any]]:
    events: list[Any] = []

    async def callback(event: Any, payload: bytes | None = None) -> None:
        events.append(event)

    return events, callback


def _run(coro: Coroutine[Any, Any, Any]) -> Any:
    return asyncio.run(coro)


class TestGitMonitor:
    def _repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"], cwd=repo, check=True
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "a.txt").write_text("hello", encoding="utf-8")
        subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return repo

    def test_index_dirty_reflects_staged_changes(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        events, callback = _collector()
        monitor = GitMonitor(uuid4(), str(repo), callback, poll_interval=0.01)
        assert monitor._get_index_dirty() is False

        (repo / "b.txt").write_text("new", encoding="utf-8")
        subprocess.run(["git", "add", "b.txt"], cwd=repo, check=True)
        assert monitor._get_index_dirty() is True

        subprocess.run(["git", "reset", "-q"], cwd=repo, check=True)
        assert monitor._get_index_dirty() is False

    def test_stage_event_on_dirty_transition(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        events, callback = _collector()
        monitor = GitMonitor(uuid4(), str(repo), callback, poll_interval=0.01)
        monitor._last_head = monitor._get_head()
        monitor._last_branch = monitor._get_branch()
        monitor._last_index_dirty = False

        (repo / "b.txt").write_text("new", encoding="utf-8")
        subprocess.run(["git", "add", "b.txt"], cwd=repo, check=True)
        _run(monitor._check_state())

        stages = [e for e in events if isinstance(e, GitEvent) and e.git_action == "stage"]
        assert len(stages) == 1

        # No re-emission while the index stays dirty
        _run(monitor._check_state())
        stages = [e for e in events if isinstance(e, GitEvent) and e.git_action == "stage"]
        assert len(stages) == 1


class TestTerminalObserver:
    def test_captures_history_after_rotation(self, tmp_path: Path) -> None:
        hist = tmp_path / ".bash_history"
        hist.write_text("first command\n", encoding="utf-8")
        events, callback = _collector()
        observer = TerminalObserver(
            uuid4(), str(tmp_path), callback, track_global_history=True
        )
        observer._history_positions[str(hist)] = hist.stat().st_size

        # Rotation: file truncated to a SHORTER size, then a new command written
        hist.write_text("new cmd\n", encoding="utf-8")
        _run(observer._check_history(hist))

        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["new cmd"]

        # Post-rotation appends are captured; already-seen commands are not
        # re-emitted (seen-set dedup survives rotation)
        hist.write_text("new cmd\nother cmd\n", encoding="utf-8")
        _run(observer._check_history(hist))
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["new cmd", "other cmd"]

    def test_workspace_correlated_commands_are_medium_confidence(
        self, tmp_path: Path
    ) -> None:
        hist = tmp_path / ".bash_history"
        workspace_name = tmp_path.name.lower()
        hist.write_text(f"cd {workspace_name}\n", encoding="utf-8")
        events, callback = _collector()
        observer = TerminalObserver(
            uuid4(), str(tmp_path), callback, track_global_history=True
        )
        observer._history_positions[str(hist)] = 0
        _run(observer._check_history(hist))
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert commands and commands[0].confidence == ConfidenceLevel.MEDIUM


class TestFilesystemObserver:
    def test_content_cache_is_bounded(self, tmp_path: Path) -> None:
        events, callback = _collector()
        observer = FilesystemObserver(uuid4(), str(tmp_path), callback)
        for i in range(3000):
            observer._cache_content(f"/fake/{i}.txt", f"content {i}")
        assert len(observer._content_cache) == 2048
        assert "/fake/0.txt" not in observer._content_cache
        assert "/fake/2999.txt" in observer._content_cache

    def test_seed_hashes_does_not_overwrite(self, tmp_path: Path) -> None:
        events, callback = _collector()
        observer = FilesystemObserver(uuid4(), str(tmp_path), callback)
        observer._hash_cache["/ws/a.py"] = "existing"
        observer.seed_hashes({
            "/ws/a.py": "baseline-a",
            "/ws/b.py": "baseline-b",
            "": "skipped",
            "/ws/c.py": "",
        })
        assert observer._hash_cache["/ws/a.py"] == "existing"
        assert observer._hash_cache["/ws/b.py"] == "baseline-b"
        assert "/ws/c.py" not in observer._hash_cache


class TestNetworkObserver:
    class _FakeConn:
        def __init__(
            self,
            pid: int | None,
            ip: str,
            port: int,
            conn_type: int,
            status: str = "ESTABLISHED",
        ) -> None:
            self.pid = pid
            self.raddr = type("R", (), {"ip": ip, "port": port})()
            self.type = conn_type
            self.status = status

    def _observer(
        self, tmp_path: Path, tracked: set[int]
    ) -> tuple[NetworkObserver, list[Any]]:
        events, callback = _collector()
        observer = NetworkObserver(uuid4(), str(tmp_path), callback)
        observer.update_tracked_pids(tracked)
        return observer, events

    def _patch_connections(self, connections: list[Any]) -> Any:
        import agenttrace.observers.network as net_mod

        fake_psutil = type(
            "_FakePSUtil",
            (),
            {
                "net_connections": staticmethod(
                    lambda kind="inet": connections
                ),
                "AccessDenied": type("AccessDenied", (Exception,), {}),
            },
        )()
        net_mod.psutil = fake_psutil  # type: ignore[attr-defined]
        return net_mod

    def test_ipv4_mapped_ipv6_local_is_filtered(self, tmp_path: Path) -> None:
        observer, events = self._observer(tmp_path, {42})
        net_mod = self._patch_connections([
            self._FakeConn(42, "::ffff:127.0.0.1", 8080, 1),
        ])
        try:
            _run(observer._scan_connections())
        finally:
            net_mod.psutil = psutil
        assert events == []

    def test_raw_socket_protocol_labeled(self, tmp_path: Path) -> None:
        observer, events = self._observer(tmp_path, {42})
        net_mod = self._patch_connections([
            self._FakeConn(42, "8.8.8.8", 0, 3),
        ])
        try:
            _run(observer._scan_connections())
        finally:
            net_mod.psutil = psutil
        nets = [e for e in events if isinstance(e, NetworkEvent)]
        assert nets and nets[0].protocol == "raw"

    def test_dedup_expires_after_window(self, tmp_path: Path) -> None:
        import time as _time

        import agenttrace.observers.network as net_mod

        observer, events = self._observer(tmp_path, {42})
        conn = self._FakeConn(42, "8.8.8.8", 443, 1)
        patched = self._patch_connections([conn])
        try:
            _run(observer._scan_connections())
            # Same connection still alive â†’ suppressed
            _run(observer._scan_connections())
            assert len([e for e in events if isinstance(e, NetworkEvent)]) == 1

            # Window expires â†’ a fresh connection to the same destination is
            # a NEW egress
            patched.time = type(
                "_FakeTime",
                (),
                {
                    "monotonic": staticmethod(
                        lambda: _time.monotonic() + net_mod._DEDUP_WINDOW + 1
                    ),
                },
            )()
            _run(observer._scan_connections())
            assert len([e for e in events if isinstance(e, NetworkEvent)]) == 2
        finally:
            patched.psutil = psutil
