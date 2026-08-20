"""Linux cgroups v2 Process Containment Controller for AgentTrace.

Traps 100% of agent child and grandchild processes at the Linux kernel level
via unified cgroups v2 hierarchy (/sys/fs/cgroup), providing atomic PID tracking
and instant kill-switch termination via cgroup.kill.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_DEFAULT_CGROUP_ROOT = Path("/sys/fs/cgroup")


class CgroupV2Controller:
    """Controls a dedicated cgroups v2 slice for an agent audit session."""

    def __init__(
        self,
        session_id: UUID,
        cgroup_root: Path = _DEFAULT_CGROUP_ROOT,
    ) -> None:
        self.session_id = session_id
        self.cgroup_root = cgroup_root
        self.cgroup_path = cgroup_root / "agenttrace" / str(session_id)
        self._is_linux = sys.platform.startswith("linux")
        self._active = False
        self._fallback_pids: set[int] = set()

        if self._is_linux:
            self._init_cgroup()

    def _init_cgroup(self) -> None:
        """Create the cgroup directory if permissions allow."""
        try:
            if not self.cgroup_root.exists():
                return

            self.cgroup_path.mkdir(parents=True, exist_ok=True)
            self._active = True
            logger.debug(
                "Created Linux cgroups v2 slice for session %s at %s",
                self.session_id,
                self.cgroup_path,
            )
        except Exception as e:
            logger.debug(
                "Could not initialize cgroups v2 (unprivileged or non-systemd host): %s", e
            )
            self._active = False

    @property
    def is_active(self) -> bool:
        """Whether the cgroup directory exists and is active."""
        return self._active and self.cgroup_path.exists()

    def assign_pid(self, pid: int) -> bool:
        """Move a process into the cgroup slice.

        The Linux kernel automatically locks all future forks/clones of this PID
        into the same cgroup slice.
        """
        self._fallback_pids.add(pid)
        if not self.is_active:
            return False

        try:
            procs_file = self.cgroup_path / "cgroup.procs"
            with open(procs_file, "a", encoding="utf-8") as f:
                f.write(f"{pid}\n")
            logger.debug("Assigned PID %d to cgroup %s", pid, self.session_id)
            return True
        except Exception as e:
            logger.debug("Failed to write PID %d to cgroup.procs: %s", pid, e)
            return False

    def get_pids(self) -> list[int]:
        """Atomically query all active PIDs trapped in the cgroup slice."""
        if not self.is_active:
            return list(self._fallback_pids)

        try:
            procs_file = self.cgroup_path / "cgroup.procs"
            if not procs_file.exists():
                return list(self._fallback_pids)

            pids: list[int] = []
            for line in procs_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
            return pids if pids else list(self._fallback_pids)
        except Exception as e:
            logger.debug("Failed to read cgroup.procs: %s", e)
            return list(self._fallback_pids)

    def terminate(self) -> bool:
        """Atomically terminate all processes inside the cgroup slice."""
        pids = self.get_pids()
        success = True

        # 1. Try atomic cgroup.kill (Linux 5.14+)
        if self.is_active:
            kill_file = self.cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1\n", encoding="utf-8")
                    logger.info("Triggered cgroup.kill for session %s", self.session_id)
                    return True
                except Exception as e:
                    logger.debug("cgroup.kill write failed, falling back to SIGKILL: %s", e)

        # 2. Fallback: SIGKILL each PID directly
        sig = getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 9))
        for pid in pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.debug("Failed to signal PID %d: %s", pid, e)
                success = False

        return success

    def close(self) -> None:
        """Clean up the cgroup directory."""
        if self.is_active:
            try:
                self.terminate()
                self.cgroup_path.rmdir()
            except Exception:
                pass
            self._active = False
