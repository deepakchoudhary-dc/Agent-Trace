"""Tests for Linux cgroups v2 Process Containment Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from agenttrace.observers.cgroup_process import CgroupV2Controller

if TYPE_CHECKING:
    from pathlib import Path


def test_cgroup_controller_initialization(tmp_path: Path) -> None:
    """CgroupV2Controller initializes cleanly on any host with custom or default root."""
    sid = uuid4()
    controller = CgroupV2Controller(sid, cgroup_root=tmp_path)
    assert controller.session_id == sid

    # Assign PID
    controller.assign_pid(12345)
    pids = controller.get_pids()
    assert 12345 in pids

    # Termination
    controller.terminate()
    controller.close()


def test_cgroup_controller_reads_procs_file(tmp_path: Path) -> None:
    """CgroupV2Controller parses integer lines from cgroup.procs correctly."""
    sid = uuid4()
    cgroup_dir = tmp_path / "agenttrace" / str(sid)
    cgroup_dir.mkdir(parents=True, exist_ok=True)
    procs_file = cgroup_dir / "cgroup.procs"
    procs_file.write_text("1001\n1002\n1003\n", encoding="utf-8")

    controller = CgroupV2Controller(sid, cgroup_root=tmp_path)
    controller._active = True
    pids = controller.get_pids()

    assert 1001 in pids
    assert 1002 in pids
    assert 1003 in pids
    controller.close()
