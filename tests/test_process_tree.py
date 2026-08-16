"""Tests for the process tree observer — canonical process identity (pid + start time)."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import psutil  # type: ignore[import-untyped]

from agenttrace.models.events import CommandEvent, EventBase, ProcessEvent
from agenttrace.observers.process_tree import ProcessTreeObserver


class _FakeProc:
    def __init__(
        self,
        pid: int,
        name: str,
        cmdline: list[str],
        cwd: str,
        create_time: float,
    ) -> None:
        self.info: dict[str, Any] = {
            "pid": pid,
            "ppid": 1,
            "name": name,
            "cmdline": cmdline,
            "cwd": cwd,
            "create_time": create_time,
        }

    def cwd(self) -> str:
        return str(self.info["cwd"])


def _make_observer(workspace: str) -> tuple[ProcessTreeObserver, list[Any]]:
    events: list[Any] = []

    async def callback(event: EventBase, payload: bytes | None = None) -> None:
        events.append(event)

    observer = ProcessTreeObserver(
        session_id=uuid4(),
        workspace_path=workspace,
        callback=callback,
    )
    return observer, events


async def _starts(events: list[Any]) -> list[ProcessEvent]:
    return [
        e for e in events
        if isinstance(e, ProcessEvent)
        and not e.payload.get("terminated")
    ]


async def _scan(observer: ProcessTreeObserver, procs: list[_FakeProc]) -> None:
    import agenttrace.observers.process_tree as pt_mod

    def fake_iter(_attrs: list[str]) -> list[_FakeProc]:
        return procs

    fake_psutil = type(
        "_FakePSUtil", (), {"process_iter": staticmethod(fake_iter)}
    )()
    pt_mod.psutil = fake_psutil  # type: ignore[attr-defined]
    try:
        await observer._scan_processes()
    finally:
        pt_mod.psutil = psutil  # type: ignore[attr-defined]


class TestProcessIdentity:
    async def test_new_process_emits_start_event(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        await _scan(observer, [
            _FakeProc(1001, "python.exe", ["python", "-c", "x"], str(tmp_path), 1111.0),
        ])
        starts = await _starts(events)
        assert len(starts) == 1
        assert starts[0].pid == 1001
        assert observer.get_tracked_pids() == {1001}

    async def test_pid_reuse_emits_termination_then_new_start(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        await _scan(observer, [
            _FakeProc(1001, "python.exe", ["python", "-c", "x"], str(tmp_path), 1111.0),
        ])
        assert observer.get_tracked_pids() == {1001}

        # Same pid, different start time: the old identity exited and the pid
        # was recycled. The observer must emit a termination AND re-track.
        await _scan(observer, [
            _FakeProc(1001, "python.exe", ["python", "-c", "y"], str(tmp_path), 2222.0),
        ])

        terminated = [e for e in events if e.payload.get("terminated")]
        starts = await _starts(events)
        assert len(terminated) == 1
        assert terminated[0].pid == 1001
        assert len(starts) == 2, "recycled pid must be tracked as a new identity"
        assert observer.get_tracked_pids() == {1001}

    async def test_same_identity_is_not_duplicated(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        proc = _FakeProc(1001, "python.exe", ["python", "-c", "x"], str(tmp_path), 1111.0)
        await _scan(observer, [proc])
        await _scan(observer, [proc])

        starts = await _starts(events)
        assert len(starts) == 1, "stable identity must not be re-emitted"

    async def test_termination_emitted_when_process_exits(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        await _scan(observer, [
            _FakeProc(1001, "python.exe", ["python", "-c", "x"], str(tmp_path), 1111.0),
        ])
        await _scan(observer, [])

        terminated = [e for e in events if e.payload.get("terminated")]
        assert len(terminated) == 1
        assert terminated[0].pid == 1001
        assert observer.get_tracked_pids() == set()

    def test_is_pid_reused_matches_start_time(self, tmp_path: Path) -> None:
        prev: dict[str, Any] = {"pid": 1001, "started_at": 1111.0}
        assert ProcessTreeObserver._is_pid_reused(prev, {"create_time": 2222.0})
        assert not ProcessTreeObserver._is_pid_reused(prev, {"create_time": 1111.0})

    def test_is_pid_reused_without_timestamps_is_safe(self, tmp_path: Path) -> None:
        assert not ProcessTreeObserver._is_pid_reused({"pid": 1001}, {"create_time": 2222.0})
        assert not ProcessTreeObserver._is_pid_reused({"pid": 1001, "started_at": 1.0}, {})

    def test_extract_shell_payload(self) -> None:
        assert ProcessTreeObserver._extract_shell_payload(
            "bash", ["bash", "-c", "rm -rf /tmp/x"]
        ) == "rm -rf /tmp/x"
        assert ProcessTreeObserver._extract_shell_payload("bash", ["bash", "-c"]) == ""
        assert ProcessTreeObserver._extract_shell_payload("bash", ["bash"]) == ""

    def test_extract_windows_shell_payloads(self) -> None:
        assert ProcessTreeObserver._extract_shell_payload(
            "cmd.exe", ["cmd.exe", "/c", "rmdir /s /q C:\\tmp\\x"]
        ) == "rmdir /s /q C:\\tmp\\x"
        assert ProcessTreeObserver._extract_shell_payload(
            "powershell.exe",
            ["powershell.exe", "-Command", "Remove-Item -Recurse C:\\tmp\\x"],
        ) == "Remove-Item -Recurse C:\\tmp\\x"
        assert ProcessTreeObserver._extract_shell_payload(
            "pwsh.exe", ["pwsh.exe", "/c", "Get-ChildItem"]
        ) == "Get-ChildItem"

    async def test_cmd_exe_payload_surfaces_as_command(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        await _scan(observer, [
            _FakeProc(
                2001,
                "cmd.exe",
                ["cmd.exe", "/c", "del /f /q secrets.txt"],
                str(tmp_path),
                1111.0,
            ),
        ])
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert commands and commands[0].command == "del /f /q secrets.txt"

    async def test_started_at_uses_create_time(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        create_time = 1_700_000_000.0
        await _scan(observer, [
            _FakeProc(3001, "python.exe", ["python", "-c", "x"], str(tmp_path), create_time),
        ])
        starts = await _starts(events)
        assert len(starts) == 1
        assert starts[0].started_at == datetime.fromtimestamp(
            create_time, tz=timezone.utc
        )

    async def test_irrelevant_process_skips_cwd_lookup(self, tmp_path: Path) -> None:
        observer, events = _make_observer(str(tmp_path))
        looked_up: list[int] = []

        def recording_cwd(proc: Any) -> str:
            looked_up.append(proc.info["pid"])
            return str(proc.info["cwd"])

        observer._safe_cwd = recording_cwd  # type: ignore[method-assign]
        await _scan(observer, [
            _FakeProc(4001, "svchost.exe", ["svchost.exe", "-k", "netsvcs"], "", 1111.0),
            _FakeProc(4002, "python.exe", ["python", "tool.py"], "", 1111.0),
        ])
        # Only the hint-matching process gets the expensive cwd syscall
        assert looked_up == [4002]
        assert observer.get_tracked_pids() == set()

        # Second scan: the irrelevant identity is cached and skipped entirely
        looked_up.clear()
        await _scan(observer, [
            _FakeProc(4001, "svchost.exe", ["svchost.exe", "-k", "netsvcs"], "", 1111.0),
        ])
        assert looked_up == []
