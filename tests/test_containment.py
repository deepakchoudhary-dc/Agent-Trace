"""Tests for the daemon-owned containment lifecycle (plan2.md P0.3).

The scripted provider stands in for the kernel unit; the win32 smoke tests
exercise the real CreateProcessW(CREATE_SUSPENDED) -> assign -> resume path.
"""

from __future__ import annotations

import ctypes
import os
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from agenttrace.observers.job_object_process import (
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
)
from agenttrace.security import containment
from agenttrace.security.containment import (
    _JOB_LIMIT_ACTIVE_PROCESS,
    _JOB_LIMIT_JOB_MEMORY,
    ContainmentError,
    ContainmentManager,
    _apply_windows_limits,
)


class _FakeProvider:
    """Scripted kernel unit: records assignments, membership, termination."""

    def __init__(self, pids: set[int] | None = None, assign_ok: bool = True) -> None:
        self.pids: set[int] = set(pids or set())
        self.assign_ok = assign_ok
        self.assignments: list[int] = []
        self.terminated = False
        self.closed = False

    @property
    def is_active(self) -> bool:
        return not self.closed

    def assign_pid(self, pid: int) -> bool:
        self.assignments.append(pid)
        if not self.assign_ok:
            return False
        self.pids.add(pid)
        return True

    def get_pids(self) -> list[int]:
        return sorted(self.pids)

    def terminate(self, exit_code: int = 1) -> bool:
        self.terminated = True
        self.pids.clear()
        return True

    def close(self) -> None:
        self.closed = True


def _manager(fake: _FakeProvider) -> ContainmentManager:
    """A real manager wrapping the scripted provider (platform-neutral)."""
    manager = ContainmentManager(uuid4())
    manager._provider = fake  # type: ignore[assignment]
    manager._is_windows = False
    manager._is_linux = False
    return manager


class TestFailClosedLifecycle:
    def test_ensure_raises_on_unsupported_platform(self) -> None:
        """No provider on the host => error; containment is never implied."""
        manager = ContainmentManager(uuid4())
        manager._is_windows = False
        manager._is_linux = False
        with pytest.raises(ContainmentError, match="no containment provider"):
            manager.ensure()

    def test_spawn_fails_closed_without_provider(self) -> None:
        """No contained-spawn path => ContainmentError, never a host process."""
        manager = ContainmentManager(uuid4())
        manager._is_windows = False
        manager._is_linux = False
        with pytest.raises(ContainmentError, match="no contained spawn path"):
            manager.spawn(["cmd", "/c", "echo hi"])

    def test_release_without_provider_is_false(self) -> None:
        manager = ContainmentManager(uuid4())
        assert manager.release(kill=True) is False

    def test_member_pids_without_provider_is_empty(self) -> None:
        manager = ContainmentManager(uuid4())
        assert manager.member_pids() == []

    def test_assign_pid_without_provider_is_false(self) -> None:
        manager = ContainmentManager(uuid4())
        assert manager.assign_pid(4242) is False


class TestProtectedSet:
    def test_release_refuses_and_leaves_provider_open(self) -> None:
        """Daemon pid inside the unit: refuse kill AND keep the provider.

        Closing the provider would arm KILL_ON_JOB_CLOSE and commit the
        very kill that was just refused — so release must leave it open.
        """
        fake = _FakeProvider(pids={os.getpid(), 4242})
        manager = _manager(fake)
        assert manager.release(kill=True) is False
        assert fake.terminated is False
        assert fake.closed is False
        assert manager.provider() is fake

    def test_release_kills_verified_members_and_closes(self) -> None:
        fake = _FakeProvider(pids={1001, 1002})
        manager = _manager(fake)
        assert manager.release(kill=True) is True
        assert fake.terminated is True
        assert fake.closed is True
        assert manager.provider() is None

    def test_release_without_kill_closes_without_terminating(self) -> None:
        fake = _FakeProvider(pids=set())
        manager = _manager(fake)
        assert manager.release(kill=False) is True
        assert fake.terminated is False
        assert fake.closed is True
        assert manager.provider() is None


class TestAssignmentSweep:
    def test_assign_pid_delegates_to_provider(self) -> None:
        fake = _FakeProvider()
        manager = _manager(fake)
        assert manager.assign_pid(4242) is True
        assert fake.assignments == [4242]
        assert manager.member_pids() == [4242]

    def test_assign_pid_failure_is_reported_not_swallowed(self) -> None:
        fake = _FakeProvider(assign_ok=False)
        manager = _manager(fake)
        assert manager.assign_pid(4242) is False

    def test_provider_accessor_round_trip(self) -> None:
        fake = _FakeProvider()
        manager = _manager(fake)
        assert manager.provider() is fake
        manager.release(kill=False)
        assert manager.provider() is None


class TestSpawnPathSelection:
    def test_spawn_on_unsupported_platform_fails_closed(self) -> None:
        manager = ContainmentManager(uuid4())
        manager._is_windows = False
        manager._is_linux = False
        with pytest.raises(ContainmentError):
            manager.spawn(["whatever"])

    def test_linux_spawn_uses_preexec_self_assignment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On Linux the child writes its own pid in the pre-exec hook.

        The pre-exec hook is the whole race-freedom contract: at the moment
        Popen forks, the hook must already carry the provider, and Popen
        must be invoked with it. Asserted with a scripted Popen so the
        test runs on every platform.
        """
        from agenttrace.security.containment import _linux_preexec, _preexec_state

        fake = _FakeProvider()
        manager = _manager(fake)
        manager._is_linux = True
        manager._provider = fake
        captured: dict[str, object] = {}
        state_at_popen: list[object] = []

        class _FakePopen:
            pid = 4321

            def __init__(self, args: object, **kwargs: object) -> None:
                captured.update(kwargs)
                state_at_popen.append(_preexec_state.provider)

        monkeypatch.setattr(
            "agenttrace.security.containment.subprocess.Popen", _FakePopen
        )
        returned = manager.spawn(["run"])
        assert returned.pid == 4321
        assert returned.contained is True
        assert returned.provider is fake
        assert captured["preexec_fn"] is _linux_preexec
        # The hook could see the provider: self-assignment was possible.
        assert state_at_popen == [fake]

    def test_protected_set_includes_daemon_descendants(self) -> None:
        manager = ContainmentManager(uuid4())
        protected = manager._protected_pids()
        assert os.getpid() in protected


# -- Sprint-1 fix: limit writes must merge flags, not clear KILL_ON_JOB_CLOSE ----


def _make_fake_kernel32(current_flags: int) -> tuple[Any, dict[str, Any]]:
    """Plain-function kernel32 stand-in: _apply_windows_limits assigns
    argtypes/restype onto the functions, so they must not be bound methods."""
    state: dict[str, Any] = {"set_flags": 0}

    def QueryInformationJobObject(handle: int, cls: int, ptr: Any, size: int, ret: Any) -> int:  # noqa: N802
        ext = ctypes.cast(ptr, ctypes.POINTER(containment._EXTENDED)).contents
        ext.BasicLimitInformation.LimitFlags = current_flags
        return 1

    def SetInformationJobObject(handle: int, cls: int, ptr: Any, size: int) -> int:  # noqa: N802
        ext = ctypes.cast(ptr, ctypes.POINTER(containment._EXTENDED)).contents
        state["set_flags"] = ext.BasicLimitInformation.LimitFlags
        return 1

    def GetLastError() -> int:  # noqa: N802
        return 0

    fake = SimpleNamespace(
        QueryInformationJobObject=QueryInformationJobObject,
        SetInformationJobObject=SetInformationJobObject,
        GetLastError=GetLastError,
    )
    return fake, state


def test_windows_limits_merge_preserves_kill_on_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SetInformationJobObject REPLACES LimitFlags, so writing memory/process
    caps without querying first silently disarmed KILL_ON_JOB_CLOSE — daemon
    crash no longer killed contained children, and release() logged false
    success. The write must OR-merge into the queried flags."""
    fake, state = _make_fake_kernel32(_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=fake), raising=False)
    _apply_windows_limits(
        SimpleNamespace(handle=1234),  # type: ignore[arg-type]
        memory_limit_mb=1024,
        max_active_processes=64,
    )
    set_flags = int(state["set_flags"])
    assert set_flags & _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert set_flags & _JOB_LIMIT_JOB_MEMORY
    assert set_flags & _JOB_LIMIT_ACTIVE_PROCESS


def test_windows_limits_fail_closed_when_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the current flag set a merge is impossible, and an unmerged
    write disarms kill-on-close: the failure must be raised, never silent."""
    fake, _state = _make_fake_kernel32(0)
    fake.QueryInformationJobObject = lambda *a: 0  # type: ignore[method-assign]
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=fake), raising=False)
    with pytest.raises(ContainmentError, match="QueryInformationJobObject"):
        _apply_windows_limits(
            SimpleNamespace(handle=1234),  # type: ignore[arg-type]
            memory_limit_mb=1024,
            max_active_processes=64,
        )
