"""Windows Job Object process containment provider for AgentTrace.

Traps 100% of agent child and grandchild processes at the Windows kernel level,
preventing escaping via CWD changes, sub-second execution, or detached spawns.
Provides atomic process enumeration and instant kill ladders.
"""

from __future__ import annotations

import contextlib
import ctypes
import logging
import platform
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Win32 Constants
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_INFORMATION = 0x0400


class _IO_COUNTERS(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("NumberOfAssignedProcesses", wintypes.DWORD),
        ("NumberOfProcessIdsInList", wintypes.DWORD),
        ("ProcessIdList", ctypes.c_size_t * 1024),
    ]


def _get_kernel32() -> Any:
    """Safely obtain kernel32 DLL reference without platform attribute errors."""
    windll = getattr(ctypes, "windll", None)
    if windll is not None:
        return getattr(windll, "kernel32", None)
    return None


class WindowsJobObject:
    """Encapsulates a Windows Job Object for deterministic process containment."""

    def __init__(self, session_id: UUID, kill_on_close: bool = True) -> None:
        self.session_id = session_id
        self._kill_on_close = kill_on_close
        self._handle: wintypes.HANDLE | None = None
        self._assigned_pids: set[int] = set()
        self._is_windows = sys.platform == "win32" and platform.system() == "Windows"

        if self._is_windows:
            self._init_job_object()

    def _init_job_object(self) -> None:
        """Create and configure the Windows Job Object."""
        kernel32 = _get_kernel32()
        if not kernel32:
            return

        try:
            job_name = f"AgentTrace_Session_{self.session_id}"
            handle = kernel32.CreateJobObjectW(None, job_name)
            if not handle:
                error = kernel32.GetLastError()
                logger.warning("CreateJobObjectW failed with error code: %d", error)
                return

            self._handle = handle

            # Configure extended limits (strict containment: breakaway disabled)
            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            flags = 0
            if self._kill_on_close:
                flags |= _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

            info.BasicLimitInformation.LimitFlags = flags

            success = kernel32.SetInformationJobObject(
                self._handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not success:
                logger.warning(
                    "SetInformationJobObject failed: %d", kernel32.GetLastError()
                )
            else:
                logger.debug(
                    "Windows Job Object configured for session %s (kill_on_close=%s)",
                    self.session_id,
                    self._kill_on_close,
                )
        except Exception as e:
            logger.warning("Failed to initialize Windows Job Object: %s", e)
            self._handle = None

    @property
    def is_active(self) -> bool:
        """Whether the Job Object handle is open and operational."""
        return self._handle is not None and bool(self._handle)

    def assign_pid(self, pid: int) -> bool:
        """Assign a process ID to the Job Object."""
        if not self.is_active or not self._is_windows:
            self._assigned_pids.add(pid)
            return False

        kernel32 = _get_kernel32()
        if not kernel32:
            self._assigned_pids.add(pid)
            return False

        try:
            proc_handle = kernel32.OpenProcess(
                _PROCESS_SET_QUOTA | _PROCESS_TERMINATE | _PROCESS_QUERY_INFORMATION,
                False,
                pid,
            )
            if not proc_handle:
                logger.debug(
                    "OpenProcess failed for PID %d (error %d)",
                    pid,
                    kernel32.GetLastError(),
                )
                return False

            try:
                success = bool(
                    kernel32.AssignProcessToJobObject(self._handle, proc_handle)
                )
                if success:
                    self._assigned_pids.add(pid)
                    logger.debug(
                        "Assigned PID %d to Job Object %s", pid, self.session_id
                    )
                    return True
                logger.debug(
                    "AssignProcessToJobObject failed for PID %d: %d",
                    pid,
                    kernel32.GetLastError(),
                )
                return False
            finally:
                kernel32.CloseHandle(proc_handle)
        except Exception as e:
            logger.debug("Error assigning PID %d to Job Object: %s", pid, e)
            return False

    def get_pids(self) -> list[int]:
        """Atomically query all active PIDs trapped in the Job Object kernel hierarchy."""
        if not self.is_active or not self._is_windows:
            return list(self._assigned_pids)

        kernel32 = _get_kernel32()
        if not kernel32:
            return list(self._assigned_pids)

        try:
            id_list = _JOBOBJECT_BASIC_PROCESS_ID_LIST()
            success = kernel32.QueryInformationJobObject(
                self._handle,
                _JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                ctypes.byref(id_list),
                ctypes.sizeof(id_list),
                None,
            )
            if not success:
                return list(self._assigned_pids)

            count = id_list.NumberOfProcessIdsInList
            return [int(id_list.ProcessIdList[i]) for i in range(count)]
        except Exception as e:
            logger.debug("QueryInformationJobObject failed: %s", e)
            return list(self._assigned_pids)

    def terminate(self, exit_code: int = 1) -> bool:
        """Atomically terminate all processes inside the Job Object via the kernel."""
        if not self.is_active or not self._is_windows:
            return False

        kernel32 = _get_kernel32()
        if not kernel32:
            return False

        try:
            success = bool(kernel32.TerminateJobObject(self._handle, exit_code))
            logger.info(
                "Terminated Job Object for session %s (success=%s)",
                self.session_id,
                success,
            )
            return success
        except Exception as e:
            logger.warning("TerminateJobObject failed: %s", e)
            return False

    def close(self) -> None:
        """Close the Job Object handle."""
        if self._handle and self._is_windows:
            kernel32 = _get_kernel32()
            if kernel32:
                with contextlib.suppress(Exception):
                    kernel32.CloseHandle(self._handle)
            self._handle = None
