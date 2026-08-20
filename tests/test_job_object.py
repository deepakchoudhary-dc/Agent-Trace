"""Tests for Windows Job Object deterministic process containment."""

from __future__ import annotations

import os
import sys
from uuid import uuid4

from agenttrace.observers.job_object_process import WindowsJobObject


def test_job_object_initialization() -> None:
    """WindowsJobObject initializes cleanly on any platform."""
    sid = uuid4()
    job = WindowsJobObject(sid, kill_on_close=False)
    assert job.session_id == sid

    if sys.platform == "win32":
        assert job.is_active is True
        pids = job.get_pids()
        assert isinstance(pids, list)
    else:
        assert job.is_active is False
    job.close()


def test_job_object_pid_assignment_and_query() -> None:
    """Current process can be assigned to the Job Object."""
    sid = uuid4()
    job = WindowsJobObject(sid, kill_on_close=False)
    current_pid = os.getpid()

    # Assign current process
    assigned = job.assign_pid(current_pid)
    pids = job.get_pids()

    if sys.platform == "win32" and job.is_active:
        assert assigned is True
        assert current_pid in pids
    else:
        assert current_pid in pids
    job.close()


def test_job_object_fallback_on_mock() -> None:
    """Job Object behaves safely when inactive."""
    sid = uuid4()
    job = WindowsJobObject(sid)
    job._is_windows = False
    job._handle = None

    assert job.is_active is False
    assert job.assign_pid(12345) is False
    assert 12345 in job.get_pids()
    assert job.terminate() is False
    job.close()
