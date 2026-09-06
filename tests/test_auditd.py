"""Tests for the Linux auditd process-execution observer (plan2 P1.2).

The kernel writes an execve record for EVERY process creation — including
processes whose whole lifetime fits inside a poll interval. These tests pin
the translation of real audit-log records into ProcessEvents, and the
honesty properties: exit_code stays None (a syscall exit is not a process
exit), failed execs are attempts not executions, and undecodable input is
never guessed into a command line.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.models.events import EventBase, ProcessEvent
from agenttrace.observers.auditd import AuditdObserver, _decode_proctitle

_T0 = 1725300000.123

# A real-shape record: bash spawned from a shell, with proctitle.
_RECORD = [
    'type=SYSCALL msg=audit(1725300000.123:456): arch=c000003e syscall=execve '
    'success=yes exit=0 a0=7ffd1 a1=7ffd2 a2=7ffd3 a3=0 items=2 ppid=400 '
    'pid=4242 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 '
    'fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=5 '
    'comm="pytest" exe="/usr/bin/pytest" key=(null)',
    'type=EXECVE msg=audit(1725300000.123:456): argc=2 a0="pytest" a1="tests/"',
    'type=PROCTITLE msg=audit(1725300000.123:456): proctitle=707974686F6E002D6D00707974657374',
    'type=PATH msg=audit(1725300000.123:456): item=0 name="/usr/bin/pytest" '
    'inode=2490368 dev=ca mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL',
    'type=EOE msg=audit(1725300000.123:456):',
]


def _observer(log: Path, workspace: str = "/ws") -> AuditdObserver:
    return AuditdObserver(
        uuid4(), workspace, callback=lambda event, payload=None: None,
        log_path=log, from_start=True,
    )


def _write(log: Path, lines: list[str]) -> None:
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")


# -- Proctitle decoding -----------------------------------------------------------


def test_proctitle_hex_decodes_to_argv() -> None:
    # "python\x00-m\x00pytest" hex-encoded
    assert _decode_proctitle("707974686F6E002D6D00707974657374") == "python -m pytest"


def test_proctitle_quoted_form_passes_through() -> None:
    """auditd's quoted single-argument form is not hex; it must pass through
    verbatim rather than being hex-decoded into garbage."""
    assert _decode_proctitle("bash") == "bash"
    assert _decode_proctitle("(null)") == "(null)"


def test_proctitle_garbage_not_guessed() -> None:
    """Odd-length or non-hex input is returned verbatim, never decoded into
    something that only looks like a command."""
    assert _decode_proctitle("zznotihex") == "zznotihex"


# -- Record translation -----------------------------------------------------------


def test_complete_record_becomes_process_event(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, _RECORD)
    observer = _observer(log)
    events = observer.read_new_records()

    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ProcessEvent)
    assert event.pid == 4242
    assert event.ppid == 400
    assert event.source_adapter == "auditd"
    assert event.exit_code is None  # syscall exit is NOT a process exit
    assert event.payload["exec_success"] is True
    assert event.payload["audit_serial"] == "456"
    # Timestamp comes from the audit record itself, not the read time.
    assert event.started_at == datetime.fromtimestamp(_T0, tz=timezone.utc)


def test_workspace_correlated_exec_gets_high_confidence(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    lines = [
        line.replace('exe="/usr/bin/pytest"', 'exe="/ws/venv/bin/pytest"')
        for line in _RECORD
    ]
    _write(log, lines)
    events = _observer(log).read_new_records()

    assert events[0].confidence.value == "high"
    assert events[0].actor_id == "auditd:4242"


def test_uncorrelated_exec_is_unattributed_low_confidence(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, _RECORD)
    events = _observer(log).read_new_records()

    assert events[0].confidence.value == "low"
    assert events[0].actor_id == "unattributed_auditd:4242"


def test_record_without_proctitle_uses_exe_and_comm(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, [_RECORD[0], _RECORD[-1]])  # SYSCALL + EOE only
    events = _observer(log).read_new_records()

    assert len(events) == 1
    assert "/usr/bin/pytest" in events[0].command_line


def test_failed_exec_is_attempt_not_execution(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    failed = [_RECORD[0].replace("success=yes exit=0", "success=no exit=-13"), _RECORD[-1]]
    _write(log, failed)
    events = _observer(log).read_new_records()

    assert len(events) == 1
    assert events[0].payload["exec_success"] is False
    assert events[0].exit_code is None


def test_non_exec_syscalls_ignored(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    other = [_RECORD[0].replace("syscall=execve", "syscall=openat"), _RECORD[-1]]
    _write(log, other)
    assert _observer(log).read_new_records() == []


def test_malformed_line_skipped_silently(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, ["this is not an audit record", *_RECORD])
    events = _observer(log).read_new_records()
    assert len(events) == 1


def test_partial_line_held_back_until_complete(tmp_path: Path) -> None:
    """The log is read as a byte stream: a record split across reads must
    never be parsed from half a line."""
    log = tmp_path / "audit.log"
    observer = _observer(log)
    log.write_text(_RECORD[0][:40], encoding="utf-8")
    assert observer.read_new_records() == []

    with open(log, "a", encoding="utf-8") as f:
        f.write(_RECORD[0][40:] + "\n" + _RECORD[-1] + "\n")
    events = observer.read_new_records()
    assert len(events) == 1


def test_cursor_does_not_reemit(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, _RECORD)
    observer = _observer(log)
    assert len(observer.read_new_records()) == 1
    assert observer.read_new_records() == []


def test_pending_records_capped(tmp_path: Path) -> None:
    """Records whose EOE never arrives cannot grow the buffer unbounded."""
    log = tmp_path / "audit.log"
    observer = _observer(log)
    unclosed = [
        f"type=SYSCALL msg=audit(1725300000.123:{i}): syscall=execve success=yes "
        f'pid={i} ppid=1 comm="x" exe="/bin/x" key=(null)'
        for i in range(5000)
    ]
    _write(log, unclosed)
    observer.read_new_records()
    assert len(observer._pending) <= 4096


# -- Lifecycle ----------------------------------------------------------------------


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="auditd is Linux-only")
@pytest.mark.asyncio
async def test_start_seeks_to_eof_by_default(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    _write(log, _RECORD)
    received: list[EventBase] = []

    observer = AuditdObserver(
        uuid4(), "/ws", callback=lambda e, p=None: received.append(e), log_path=log
    )
    await observer.start()
    assert observer.read_new_records() == []  # pre-existing history not replayed
    await observer.stop()


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="gap path is non-Linux")
@pytest.mark.asyncio
async def test_non_linux_start_records_honest_gap() -> None:
    observer = _observer(Path("/var/log/audit/audit.log"))
    await observer.start()
    assert observer.observability_gaps
    assert observer.running is False


# -- Reviewer findings: rotation survival and numeric syscall IDs -----------------


def test_log_rotation_resets_cursor_and_discloses(tmp_path: Path) -> None:
    """logrotate makes the file smaller than the cursor; without a size
    check the observer would return b"" forever and the process plane would
    be silently blind until the new log grew past the old offset."""
    log = tmp_path / "audit.log"
    observer = _observer(log)
    _write(log, _RECORD)
    assert len(observer.read_new_records()) == 1

    # copytruncate: file shrinks, then new activity arrives.
    _write(log, [_RECORD[0].replace(":456)", ":789)") + "", _RECORD[-1].replace(":456)", ":789)")])
    events = observer.read_new_records()
    assert len(events) == 1
    assert events[0].payload["audit_serial"] == "789"
    assert any("rotated" in gap for gap in observer.observability_gaps)


def test_numeric_execve_syscall_ids_recognized(tmp_path: Path) -> None:
    """When auditd cannot resolve the arch table, syscalls appear as numbers
    (x86_64 execve=59); they must not be silently dropped."""
    log = tmp_path / "audit.log"
    numeric = [
        _RECORD[0].replace("syscall=execve", "syscall=59").replace(":456)", ":460)"),
        _RECORD[-1].replace(":456)", ":460)"),
    ]
    _write(log, numeric)
    events = _observer(log).read_new_records()
    assert len(events) == 1
    assert events[0].pid == 4242


def test_node_prefixed_records_parsed(tmp_path: Path) -> None:
    """auditd --node configurations prefix every line with node=<host>."""
    log = tmp_path / "audit.log"
    node_lines = [line.replace("type=", "node=host01 type=", 1) for line in _RECORD]
    _write(log, node_lines)
    events = _observer(log).read_new_records()
    assert len(events) == 1
