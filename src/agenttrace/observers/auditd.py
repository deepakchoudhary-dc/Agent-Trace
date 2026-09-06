"""Kernel-grade process-execution watcher via the Linux audit subsystem.

Polling observers (psutil) structurally miss any process whose full lifetime
fits inside one poll interval. auditd does not: the kernel writes an execve
record for EVERY process creation to the audit log — whether the process
lives for a minute or a millisecond — and the log persists, so a cursor-based
tail catches up on everything that happened while we were not reading.
Polling an OS event log is not lossy; polling a process list is.

This is the Linux counterpart of the Windows Security-log observer
(events 4688/4689) and closes the same polling blind spot (plan2 P1.2,
architectural debt #2). Model-agnostic by construction: auditd records every
execve on the machine — Claude, Codex, a shell loop, a compiled dropper —
with no adapter cooperation.

Honesty notes:
- The audit ``exit=`` field of an execve syscall is the syscall result, NOT
  the process exit status; fabricating it into ``exit_code`` would poison
  outcome reconciliation. Process-exit evidence stays with the platforms
  that genuinely observe it (Windows 4689).
- ``success=no`` execve attempts are recorded as attempts (payload flag),
  never as executions.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import ConfidenceLevel, EventBase, ProcessEvent
from agenttrace.observers.base import BaseObserver

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_AUDIT_LOG = Path("/var/log/audit/audit.log")
_POLL_INTERVAL = 1.0
# Audit records that never terminate (dropped EOE) are evicted oldest-first.
_MAX_PENDING = 4096

_EXECVE_SYSCALLS = {"execve", "execveat"}
# Numeric syscall IDs seen when auditd cannot resolve the arch table.
# x86_64: execve=59, execveat=322; aarch64: execve=221, execveat=281.
# Symbolic names remain the primary signal; the numbers are the fallback so
# "records every execve" does not silently fail on those systems.
_EXECVE_SYSCALL_IDS = {"59", "322", "221", "281"}
_EXECVE_ALL = _EXECVE_SYSCALLS | _EXECVE_SYSCALL_IDS

# Optional "node=<host>" prefix, emitted by auditd --node configurations.
_AUDIT_MSG_RE = re.compile(
    r"(?:node=\S+\s+)?type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)"
)
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')
_HEX_ONLY_RE = re.compile(r"(?:[0-9A-Fa-f]{2})+")


def _parse_kv(text: str) -> dict[str, str]:
    """Parse audit key=value pairs, stripping one level of quoting."""
    return {k: v[1:-1] if v.startswith('"') else v for k, v in _KV_RE.findall(text)}


def _decode_proctitle(value: str) -> str:
    """Decode a PROCTITLE value into the process command line.

    auditd hex-encodes the argv (NUL-separated); some kernels emit a quoted
    single-argument form instead. Undecodable input is returned verbatim —
    never guessed into something that looks like a command.
    """
    if _HEX_ONLY_RE.fullmatch(value):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return value
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
        return " ".join(parts) if parts else ""
    return value


class AuditdObserver(BaseObserver):
    """Tail the Linux audit log for kernel-recorded process executions.

    Emits ``ProcessEvent`` (source_adapter ``auditd``) for every execve the
    kernel recorded, with the record's true timestamp — the ground-truth
    process plane for Linux, including processes too short-lived for any
    poll to see.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: Any,
        log_path: str | Path | None = None,
        from_start: bool = False,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._log_path = Path(log_path) if log_path else _AUDIT_LOG
        # None = start at EOF (only new activity); 0 = replay from the top
        # (tests, or an operator who explicitly wants history).
        self._offset: int | None = 0 if from_start else None
        self._partial: bytes = b""
        self._pending: dict[str, dict[str, Any]] = {}

    async def start(self) -> None:
        if sys.platform != "linux":
            self._record_gap("auditd observer requires Linux")
            return
        if not self._log_path.exists():
            self._record_gap(
                f"auditd log not found at {self._log_path} — short-lived "
                "processes are invisible to this session (is auditd installed?)"
            )
            return
        try:
            with open(self._log_path, "rb") as f:
                f.seek(0, 2)
                if self._offset is None:
                    self._offset = f.tell()
        except OSError as exc:
            self._record_gap(f"auditd log unreadable ({exc}) — process plane degraded")
            return
        await super().start()

    async def _run(self) -> None:
        while self._running:
            try:
                events = await asyncio.to_thread(self.read_new_records)
            except OSError as exc:
                self._record_gap(f"auditd log read failed ({exc})")
                events = []
            for event in events:
                await self.emit(event)
            await asyncio.sleep(_POLL_INTERVAL)

    # -- Parsing (synchronous; platform-independent and directly testable) ----

    def read_new_records(self) -> list[EventBase]:
        """Read newly appended audit lines and translate complete records."""
        try:
            with open(self._log_path, "rb") as f:
                if self._offset is None:
                    f.seek(0, 2)
                    self._offset = f.tell()
                    return []
                # logrotate (copytruncate or rename+create) makes the file
                # smaller than the cursor; without this check seek() would
                # return b"" forever and the process plane would be silently
                # blind until the new log grew past the old offset.
                size = f.seek(0, 2)
                if size < self._offset:
                    logger.warning(
                        "audit log shrank from %d to %d bytes (logrotate?) — "
                        "resetting cursor to 0",
                        self._offset,
                        size,
                    )
                    self._record_gap("audit log rotated/truncated; records "
                                     "written before the rotation are lost")
                    self._offset = 0
                    self._partial = b""
                f.seek(self._offset)
                new_bytes = f.read()
        except OSError:
            raise
        if not new_bytes:
            return []

        data = self._partial + new_bytes
        *lines, last = data.split(b"\n")
        # A trailing chunk without a newline is an incomplete write; hold it
        # back so a record is never parsed from half a line. The offset
        # always advances by the full byte count — the partial lives in
        # memory, so advancing by less would duplicate it on the next read.
        self._partial = last
        self._offset += len(new_bytes)

        events: list[EventBase] = []
        for line in lines:
            text = line.decode("utf-8", "replace").strip()
            if text:
                event = self._process_line(text)
                if event is not None:
                    events.append(event)
        return events

    def _process_line(self, line: str) -> EventBase | None:
        match = _AUDIT_MSG_RE.match(line)
        if not match:
            return None
        rtype, _epoch, serial, body = match.groups()
        fields = _parse_kv(body)

        if rtype == "SYSCALL":
            if fields.get("syscall") not in _EXECVE_ALL:
                return None
            if len(self._pending) >= _MAX_PENDING and serial not in self._pending:
                oldest = next(iter(self._pending))
                del self._pending[oldest]
            self._pending[serial] = {
                "epoch": _epoch_of(match),
                "pid": _int_or_none(fields.get("pid")),
                "ppid": _int_or_none(fields.get("ppid")),
                "exe": fields.get("exe", ""),
                "comm": fields.get("comm", ""),
                "success": fields.get("success", ""),
                "cwd": fields.get("cwd", ""),
            }
            return None

        if rtype == "PROCTITLE" and serial in self._pending:
            self._pending[serial]["proctitle"] = fields.get("proctitle", "")
            return None

        if rtype == "EOE":
            record = self._pending.pop(serial, None)
            if record is not None:
                return self._translate(record, serial)
        return None

    def _translate(self, record: dict[str, Any], serial: str) -> ProcessEvent | None:
        pid = record.get("pid")
        if pid is None:
            return None
        command_line = _decode_proctitle(record.get("proctitle", "")) or " ".join(
            part for part in (record.get("exe", ""), record.get("comm", "")) if part
        )
        exe = record.get("exe", "")
        ws = self.workspace_path.lower().replace("\\", "/")
        # Same convention as the ETW observer: workspace correlation via the
        # command line OR the executable image.
        correlated = bool(ws) and (
            ws in command_line.lower().replace("\\", "/")
            or ws in exe.lower().replace("\\", "/")
        )

        return ProcessEvent(
            session_id=self.session_id,
            actor_id=(f"auditd:{pid}" if correlated else f"unattributed_auditd:{pid}"),
            source_adapter="auditd",
            confidence=ConfidenceLevel.HIGH if correlated else ConfidenceLevel.LOW,
            pid=pid,
            ppid=record.get("ppid") or 0,
            command_line=command_line,
            working_dir=record.get("cwd", ""),
            started_at=record.get("epoch"),
            # execve's syscall exit is not the process exit status; inventing
            # one here would feed fabricated outcome evidence to the #4
            # reconciler. Real exit codes remain with platforms that observe
            # them (Windows 4689).
            exit_code=None,
            payload={
                "exe": exe,
                "exec_success": record.get("success", "") == "yes",
                "audit_serial": serial,
                "workspace_correlated": correlated,
            },
        )


def _epoch_of(match: re.Match[str]) -> datetime:
    try:
        return datetime.fromtimestamp(float(match.group(2)), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return datetime.now(timezone.utc)


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None
