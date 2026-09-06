"""Daemon-owned containment lifecycle (plan2.md P0.3, METR shortcoming #2).

Before this module the containment providers existed but were never owned by
the daemon lifecycle: Windows PIDs were assigned **post-attach** by the
process-tree observer (a child that spawned and forked before the poll loop
noticed was never in the job -- the exact escape race P0.3 names), Linux
cgroups were constructed by nobody, and ``register_session_pid`` had no
callers. Observation was a stronger guarantee than containment.

The :class:`ContainmentManager` closes that with three properties:

- **Race-free spawn** -- the sanctioned path. On Windows the child is created
  via ``CreateProcessW(CREATE_SUSPENDED)``: it has executed **zero
  instructions** when ``AssignProcessToJobObject`` runs, and only then is its
  primary thread resumed. On Linux the child writes its own pid into
  ``cgroup.procs`` in the pre-exec hook (after fork, before exec), so the
  kernel locks it and every future descendant before the first instruction.
  If assignment fails, the suspended process is terminated and the spawn
  fails closed -- there is no host fallback, matching the P0.1 precedent.
- **Fail-honest lifecycle** -- ``ensure`` creates the provider at session
  start / daemon resume, ``release`` terminates kernel-verified members and
  closes the provider at session stop. The daemon's own pid tree is a
  protected set: if it ever appears inside the containment unit, termination
  is refused rather than armed.
- **Resource limits** -- Windows: per-process and job memory caps plus an
  active-process cap, and *both* breakaway flags deliberately unset (no
  child may leave the job, silently or otherwise). Linux: ``pids.max`` and
  ``memory.max`` written at cgroup creation (best-effort, logged).

Honest ceiling, unchanged and documented: on a same-user host an agent that
never leaves the job can still do everything its user can -- containment
constrains *process lifetime*, not permissions. That is the same-user trust
boundary plan2 records as unsolved; this module does not pretend otherwise.
"""
from __future__ import annotations

import ctypes
import logging
import os
import signal
import subprocess
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenttrace.observers.cgroup_process import CgroupV2Controller
from agenttrace.observers.job_object_process import WindowsJobObject

if TYPE_CHECKING:
    from uuid import UUID

# Both providers expose the same kernel-unit surface (is_active, assign_pid,
# get_pids, terminate, close); both import cleanly on every platform, so the
# union is a real runtime alias.
ContainmentProvider = WindowsJobObject | CgroupV2Controller

logger = logging.getLogger(__name__)

# Windows creation flag: start the primary thread suspended so containment
# assignment happens before the first instruction executes.
_CREATE_SUSPENDED = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002

_DEFAULT_MEMORY_LIMIT_MB = 2048
_DEFAULT_MAX_ACTIVE_PROCESSES = 256

# Exit code used by the Linux pre-exec hook when self-assignment fails: the
# child dies before exec, so no uncontained instruction ever runs.
_PREEXEC_FAIL_EXIT = 126

# Thread-local carrying the cgroup provider across the fork boundary. Set
# only in the pre-exec context; read by _linux_preexec.
_preexec_state = threading.local()


def _apply_windows_limits(
    provider: WindowsJobObject,
    memory_limit_mb: int,
    max_active_processes: int,
) -> None:
    """Job-wide memory + active-process caps (JobObjectExtendedLimitInformation).

    Written through explicit ctypes structures so LimitFlags starts at 0 for
    the *limit* call only -- this does not disturb the KILL_ON_JOB_CLOSE flag
    the provider set at creation (that lives in the job's own state, not in
    this request structure).
    """
    ext = _EXTENDED()
    ext.BasicLimitInformation.LimitFlags = (
        _JOB_LIMIT_JOB_MEMORY | _JOB_LIMIT_ACTIVE_PROCESS
    )
    ext.BasicLimitInformation.ActiveProcessLimit = max_active_processes
    ext.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
    ext.JobMemoryLimit = memory_limit_mb * 1024 * 1024

    kernel32 = getattr(ctypes, "windll", None)
    if kernel32 is None:
        raise ContainmentError("kernel32 unavailable")
    k32 = kernel32.kernel32
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    ok = k32.SetInformationJobObject(
        provider.handle,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(ext),
        ctypes.sizeof(ext),
    )
    if not ok:
        raise ContainmentError(
            f"SetInformationJobObject failed (error {k32.GetLastError()})"
        )


def _apply_cgroup_limits(
    provider: CgroupV2Controller,
    memory_limit_mb: int,
    max_active_processes: int,
) -> None:
    """pids.max + memory.max, best-effort writes with logged failures."""
    limits = {
        "pids.max": str(max_active_processes),
        "memory.max": f"{memory_limit_mb * 1024 * 1024}",
    }
    for name, value in limits.items():
        try:
            (provider.cgroup_path / name).write_text(value, encoding="ascii")
        except OSError as e:
            logger.warning("Could not write %s: %s", name, e)


class ContainmentError(RuntimeError):
    """Containment refused or failed; the process was NOT left on the host."""


@dataclass
class ContainedProcess:
    """A spawned process that was contained before its first instruction."""

    pid: int
    provider: WindowsJobObject | CgroupV2Controller
    contained: bool
    _proc: subprocess.Popen[Any] | None = field(default=None, repr=False)
    _win: dict[str, Any] = field(default_factory=dict, repr=False)

    def pids(self) -> list[int]:
        """Dynamic enumeration of every live pid in the containment unit."""
        return self.provider.get_pids()

    def terminate(self) -> bool:
        """Kill every process in the containment unit (kernel-verified)."""
        return self.provider.terminate()

    def wait(self, timeout: float | None = None) -> int | None:
        """Wait for the spawned root; returns its exit code if known."""
        if self._proc is not None:
            try:
                return self._proc.wait(timeout)
            except subprocess.TimeoutExpired:
                return None
        handle = self._win.get("process_handle")
        if handle is not None and sys.platform == "win32":
            kernel32 = _kernel32()
            kernel32.WaitForSingleObject(handle, int((timeout or 60) * 1000))
            code = ctypes.c_ulong(0)
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return int(code.value)
        return None

    def close(self) -> None:
        """Release the caller-side handles (does not affect containment)."""
        handle = self._win.pop("process_handle", None)
        if handle is not None and sys.platform == "win32":
            import contextlib

            with contextlib.suppress(Exception):
                _kernel32().CloseHandle(handle)


# -- Win32 spawn structures (exact layout, ctypes struct) -------------------

class _STARTUPINFOW(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):  # noqa: N801 - Win32 name alignment
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _EXTENDED(ctypes.Structure):  # noqa: N801 - Win32 name alignment
    """JobObjectExtendedLimitInformation layout (8-byte packing)."""

    _pack_ = 8
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_JOB_LIMIT_JOB_MEMORY = 0x00000200
_JOB_LIMIT_ACTIVE_PROCESS = 0x00000008



def _kernel32() -> Any:
    """kernel32 with exact 64-bit-safe prototypes for the spawn path.

    Without explicit restype, ctypes returns handles as 32-bit ints and
    every HANDLE above 2^31 would be truncated -- the same corruption class
    job_object_process.py documents for AssignProcessToJobObject.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None

    kernel32 = windll.kernel32
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    return kernel32


def _spawn_contained_windows(
    cmdline: list[str],
    provider: WindowsJobObject,
    cwd: str | None,
) -> tuple[int, dict[str, Any]]:
    """CreateProcessW(CREATE_SUSPENDED) -> assign -> resume. Zero instructions
    execute before the process is inside the job object."""
    kernel32 = _kernel32()
    if kernel32 is None:
        raise ContainmentError("kernel32 unavailable on this platform")

    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(_STARTUPINFOW)
    pi = _PROCESS_INFORMATION()
    command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmdline))

    ok = kernel32.CreateProcessW(
        None,
        command_line,
        None,
        None,
        False,
        _CREATE_SUSPENDED,  # breakaway flags deliberately absent: no escape
        None,
        cwd,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        raise ContainmentError(
            f"CreateProcessW failed (error {kernel32.GetLastError()})"
        )

    assigned = False
    try:
        assigned = provider.assign_pid(int(pi.dwProcessId))
        if not assigned:
            raise ContainmentError(
                f"AssignProcessToJobObject failed for PID {pi.dwProcessId}"
            )
        kernel32.ResumeThread(pi.hThread)
    finally:
        if not assigned:
            # Fail closed: kill the still-suspended process, release handles.
            kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hThread)

    return int(pi.dwProcessId), {"process_handle": pi.hProcess}


def _linux_preexec() -> None:
    provider = getattr(_preexec_state, "provider", None)
    if provider is not None and not provider.assign_pid(0):
        os._exit(_PREEXEC_FAIL_EXIT)
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)


class ContainmentManager:
    """Owns one kernel containment provider per session for the daemon.

    - ``ensure``: create the provider (and resource limits) at session start
      or daemon resume.
    - ``spawn``: the sanctioned contained-spawn path (race-free by construct).
    - ``release``: terminate kernel-verified members and close the provider
      at session stop.
    """

    def __init__(
        self,
        session_id: UUID,
        *,
        memory_limit_mb: int = _DEFAULT_MEMORY_LIMIT_MB,
        max_active_processes: int = _DEFAULT_MAX_ACTIVE_PROCESSES,
        cgroup_root: Path | None = None,
    ) -> None:
        self.session_id = session_id
        self._memory_limit_mb = memory_limit_mb
        self._max_active = max_active_processes
        self._cgroup_root = cgroup_root
        self._provider: WindowsJobObject | CgroupV2Controller | None = None
        self._is_windows = sys.platform == "win32"
        self._is_linux = sys.platform.startswith("linux")
        self._daemon_pid = os.getpid()

    # -- Lifecycle -----------------------------------------------------------

    def ensure(self) -> WindowsJobObject | CgroupV2Controller:
        """Create the provider and apply resource limits. Raises on failure --
        a session must never run with implied containment."""
        if self._provider is not None:
            return self._provider
        if self._is_windows:
            provider: ContainmentProvider = WindowsJobObject(
                self.session_id, kill_on_close=True
            )
            assert isinstance(provider, WindowsJobObject)
            _apply_windows_limits(provider, self._memory_limit_mb, self._max_active)
        elif self._is_linux:
            root = self._cgroup_root or Path("/sys/fs/cgroup")
            provider = CgroupV2Controller(self.session_id, cgroup_root=root)
            if not provider.is_active:
                raise ContainmentError(
                    "cgroup v2 slice could not be created (unprivileged host?)"
                )
            _apply_cgroup_limits(provider, self._memory_limit_mb, self._max_active)
        else:
            raise ContainmentError(
                f"no containment provider on {sys.platform}; refusing to run"
            )
        self._provider = provider
        logger.info("Containment provider ready for session %s", self.session_id)
        return provider

    # -- Spawn -------------------------------------------------------------------

    def spawn(
        self,
        cmdline: list[str],
        *,
        cwd: str | None = None,
    ) -> ContainedProcess:
        """Race-free contained spawn: inside the kernel unit before the first
        instruction executes. Raises ContainmentError rather than leaving a
        process on the host uncontained (no host fallback)."""
        if not self._is_windows and not self._is_linux:
            raise ContainmentError(f"no contained spawn path on {sys.platform}")
        provider = self.ensure()
        if self._is_windows:
            assert isinstance(provider, WindowsJobObject)
            pid, win_state = _spawn_contained_windows(cmdline, provider, cwd)
            return ContainedProcess(
                pid=pid, provider=provider, contained=True, _win=win_state
            )
        if self._is_linux:
            _preexec_state.provider = provider
            try:
                proc: subprocess.Popen[Any] = subprocess.Popen(
                    cmdline,
                    cwd=cwd,
                    preexec_fn=_linux_preexec,
                )
            finally:
                _preexec_state.provider = None
            return ContainedProcess(
                pid=proc.pid, provider=provider, contained=True, _proc=proc
            )
        raise ContainmentError(f"no contained spawn path on {sys.platform}")

    # -- Release -------------------------------------------------------------------

    def release(self, *, kill: bool = True) -> bool:
        """Terminate kernel-verified members and close the provider.

        The daemon's own pid tree is a protected set: if it is ever observed
        inside the containment unit, termination is refused AND the provider
        is left open -- closing it would arm KILL_ON_JOB_CLOSE and commit the
        very kill this method just refused.
        """
        provider = self._provider
        if provider is None:
            return False
        if kill:
            members = set(provider.get_pids())
            protected = self._protected_pids()
            if members & protected:
                logger.error(
                    "Refusing to terminate containment for session %s: "
                    "daemon pid tree detected inside the unit; provider "
                    "left open (closing it would arm KILL_ON_JOB_CLOSE)",
                    self.session_id,
                )
                return False
            if not provider.terminate():
                # Kernel refused the kill; closing the unit still ends every
                # member via KILL_ON_JOB_CLOSE, so the release stands.
                logger.warning(
                    "terminate() failed for session %s; closing the unit "
                    "instead (KILL_ON_JOB_CLOSE ends remaining members)",
                    self.session_id,
                )
        provider.close()
        self._provider = None
        return True

    def member_pids(self) -> list[int]:
        """Every live pid currently inside the containment unit."""
        provider = self._provider
        return provider.get_pids() if provider is not None else []

    def assign_pid(self, pid: int) -> bool:
        """Post-attach assignment (best-effort; spawn is the race-free path)."""
        provider = self._provider
        return provider.assign_pid(pid) if provider is not None else False

    def provider(self) -> WindowsJobObject | CgroupV2Controller | None:
        """The live kernel provider, for observers that sweep pids into it."""
        return self._provider

    def _protected_pids(self) -> set[int]:
        """Daemon pid plus descendants (best-effort: psutil when available)."""
        protected = {self._daemon_pid}
        try:
            import psutil  # type: ignore[import-untyped]

            parent = psutil.Process(self._daemon_pid)
            protected |= {c.pid for c in parent.children(recursive=True)}
        except ImportError:
            logger.debug("psutil unavailable; protecting daemon pid only")
        except psutil.Error:
            logger.debug("daemon pid tree enumeration failed; protecting pid only")
        return protected
