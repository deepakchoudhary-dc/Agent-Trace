"""Tests for Windows Job Object deterministic process containment."""

from __future__ import annotations

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
    """A target child process can be assigned to the Job Object."""
    import subprocess

    sid = uuid4()
    job = WindowsJobObject(sid, kill_on_close=False)

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        target_pid = proc.pid
        assigned = job.assign_pid(target_pid)
        pids = job.get_pids()

        if sys.platform == "win32" and job.is_active:
            assert assigned is True
            assert target_pid in pids
        else:
            assert target_pid in pids
    finally:
        job.close()
        proc.kill()
        proc.wait()


def test_job_object_fallback_on_mock() -> None:
    """Job Object behaves safely when inactive."""
    sid = uuid4()
    job = WindowsJobObject(sid, kill_on_close=False)
    job._is_windows = False
    job._handle = None

    assert job.is_active is False
    assert job.assign_pid(12345) is False
    assert 12345 in job.get_pids()
    assert job.terminate() is False
    job.close()
