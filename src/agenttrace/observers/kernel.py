"""Kernel-tier observer — ETW process audit, Job-Object containment, MXC.

This observer attempts the deepest host integration available in pure
Python and, when the platform or privilege level does not provide it,
declares the blind spot instead of fabricating coverage (anti-fabrication
invariant):

- **ETW process audit** (Windows, ``wevtutil``): Event ID 4688 (process
  created, with command line) and 4689 (process exited) from the Security
  log — direct kernel-sourced process lifecycle evidence.
- **Job-Object containment** (Windows): true descendant containment needs
  the win32 Job API; without it this is an honest gap.
- **MXC memory-execution control**: image-load callbacks need a signed
  kernel driver; from userspace this is an honest gap, always.

On any platform where a tier is unavailable, ``observability_gaps`` lists
the reason and the observer emits nothing rather than guesses.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import ConfidenceLevel, ProcessEvent
from agenttrace.observers.base import BaseObserver, EventCallback

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 4.0
_WEVTUTIL_TIMEOUT = 15

# ETW Security-log events for process lifecycle
_EVENT_PROCESS_CREATED = "4688"
_EVENT_PROCESS_EXITED = "4689"
_WEVTUTIL_ARGS = [
    "wevtutil", "qe", "Security", "/f:xml", "/rd:true", "/c:200",
    f"/q:*[System[(EventID={_EVENT_PROCESS_CREATED} "
    f"or EventID={_EVENT_PROCESS_EXITED})]]",
]

_XMLNS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_TIME_RE = re.compile(
    r"<TimeCreated SystemTime=\"([^\"]+)\"\s*/>"
)

# ETW 4688/4689 data fields → ProcessEvent mapping
_FIELD_MAP = {
    "ProcessId": "pid",
    "ParentProcessId": "ppid",
    "NewProcessName": "image",
    "CommandLine": "command_line",
    "ExitCode": "exit_code",
}


class KernelObserver(BaseObserver):
    """Kernel-sourced process lifecycle observer with honest tier gaps.

    ``poll``-style loop is replaced by the BaseObserver ``_run`` task; the
    ETW tail is read with ``wevtutil`` and translated into ProcessEvents
    at HIGH confidence (direct kernel observation). On platforms or
    privilege levels where a tier is unavailable, the gap is recorded in
    ``observability_gaps`` and no events are emitted for it.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._etw_available = False
        self._cursor: str | None = None  # last processed SystemTime (ISO)
        self._last_poll = 0.0
        self._gap_diagnostics: list[str] = []

    # -- Capability reporting ------------------------------------------------

    @property
    def capabilities(self) -> dict[str, bool]:
        return {
            "etw_process_audit": self._etw_available,
            "job_object_containment": False,
            "mxc_memory_execution_control": False,
        }

    def cursor_state(self) -> dict[str, Any]:
        return {"cursor": self._cursor, "etw_available": self._etw_available}

    def restore_cursor(self, state: dict[str, Any]) -> None:
        cursor = state.get("cursor")
        if isinstance(cursor, str) and cursor:
            self._cursor = cursor

    # -- Lifecycle ------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._etw_available = self._probe_etw()
        if not self._etw_available:
            self._record_gap(
                "ETW process audit unavailable: " + self._etw_reason()
            )
        if os.name != "nt":
            self._record_gap(
                "Job-Object descendant containment requires the Windows "
                "Job API; not available on this platform"
            )
        self._record_gap(
            "MXC memory-execution control requires a signed kernel driver; "
            "not observable from userspace"
        )
        self._task = asyncio.create_task(self._run(), name=f"observer-{self.name}")
        logger.info(
            "%s started for session %s (etw=%s)",
            self.name,
            self.session_id,
            self._etw_available,
        )

    def _etw_reason(self) -> str:
        if os.name != "nt":
            return "requires Windows Security log"
        if self._gap_diagnostics:
            return "; ".join(self._gap_diagnostics)
        return "wevtutil probe returned no data"

    # -- ETW probe ------------------------------------------------------------

    def _probe_etw(self) -> bool:
        """Check wevtutil can read the Security log (needs Audit enabled)."""
        if os.name != "nt":
            return False
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:xml"],
                capture_output=True,
                text=True,
                timeout=_WEVTUTIL_TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._gap_diagnostics.append(f"wevtutil failed: {exc}")
            return False
        if proc.returncode != 0:
            self._gap_diagnostics.append(
                proc.stderr.strip().splitlines()[0]
                if proc.stderr.strip()
                else f"wevtutil exit {proc.returncode}"
            )
            return False
        return bool(proc.stdout.strip())

    # -- Main loop ------------------------------------------------------------

    async def _run(self) -> None:
        while self._running:
            if self._etw_available:
                await self._poll_etw()
            await asyncio.sleep(_POLL_INTERVAL)

    async def _poll_etw(self) -> None:
        try:
            proc = await asyncio.to_thread(self._query_wevtutil)
        except (OSError, subprocess.SubprocessError) as exc:
            self._record_gap(f"ETW query failed: {exc}")
            self._etw_available = False
            return
        events = self._translate(proc)
        for event in events:
            await self.emit(event)

    def _query_wevtutil(self) -> str:
        proc = subprocess.run(
            _WEVTUTIL_ARGS,
            capture_output=True,
            text=True,
            timeout=_WEVTUTIL_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0:
            raise OSError(
                proc.stderr.strip() or f"wevtutil exit {proc.returncode}"
            )
        return proc.stdout

    # -- Translation -----------------------------------------------------------

    def _translate(self, xml_text: str) -> list[ProcessEvent]:
        """Translate wevtutil XML into ProcessEvents, honoring the cursor.

        Only events newer than the cursor are emitted; the cursor advances
        to the newest event seen so restarts resume without duplicates.
        """
        events: list[ProcessEvent] = []
        latest: str | None = None
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            self._record_gap(f"ETW output unparseable: {exc}")
            return events

        for element in root.iter(f"{_XMLNS}Event"):
            time_el = element.find(f"{_XMLNS}System/{_XMLNS}TimeCreated")
            time_text = time_el.get("SystemTime") if time_el is not None else None
            if not time_text:
                continue
            if latest is None or time_text > latest:
                latest = time_text
            if self._cursor and time_text <= self._cursor:
                continue

            event_id = element.findtext(f"{_XMLNS}System/{_XMLNS}EventID")
            fields: dict[str, str] = {}
            for data in element.iter(f"{_XMLNS}Data"):
                name = data.get("Name", "")
                if name in _FIELD_MAP and data.text:
                    fields[_FIELD_MAP[name]] = data.text.strip()

            translated = self._translate_event(event_id, fields, time_text)
            if translated is not None:
                events.append(translated)

        if latest is not None:
            self._cursor = latest
        return events

    def _translate_event(
        self, event_id: str | None, fields: dict[str, str], time_text: str
    ) -> ProcessEvent | None:
        from datetime import datetime, timezone

        try:
            timestamp = datetime.fromisoformat(
                time_text.replace("Z", "+00:00")
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        pid_text = fields.get("pid", "")
        if not pid_text.isdigit():
            return None
        try:
            pid = int(pid_text)
        except ValueError:
            pid = 0

        if event_id == _EVENT_PROCESS_CREATED:
            return ProcessEvent(
                session_id=self.session_id,
                actor_id=f"etw:{pid}",
                source_adapter="kernel_etw",
                confidence=ConfidenceLevel.HIGH,
                pid=pid,
                ppid=int(fields["ppid"]) if fields.get("ppid", "").isdigit() else 0,
                command_line=fields.get("command_line", ""),
                started_at=timestamp,
                payload={"image": fields.get("image", "")},
            )
        if event_id == _EVENT_PROCESS_EXITED:
            return ProcessEvent(
                session_id=self.session_id,
                actor_id=f"etw:{pid}",
                source_adapter="kernel_etw",
                confidence=ConfidenceLevel.HIGH,
                pid=pid,
                command_line=fields.get("command_line", ""),
                ended_at=timestamp,
                exit_code=(
                    int(fields["exit_code"])
                    if fields.get("exit_code", "").lstrip("-").isdigit()
                    else None
                ),
                payload={"image": fields.get("image", "")},
            )
        return None
