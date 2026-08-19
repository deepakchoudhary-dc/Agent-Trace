"""Host-level file permission hardening.

Best-effort restrictive permissions for data-dir artifacts: 0600 on POSIX,
and a Windows DACL granting only the current user plus SYSTEM (icacls with
inheritance removed). Failures are logged, never fatal — constrained hosts
must still be able to run.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def apply_restrictive_perms(path: Path) -> None:
    """Restrict a file (or directory) to the current user on the host.

    Files get 0600; directories get 0700 (owner read/write/search). A 0600
    directory drops the execute/search bit, which makes the owner unable to
    traverse into it — so every child ``stat``/``open`` then fails with
    PermissionError. The execute bit is required on directories, not just
    allowed: it is what permits walking and listing the directory.
    """
    if os.name == "posix":
        mode = (
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            if path.is_dir()
            else stat.S_IRUSR | stat.S_IWUSR
        )
        path.chmod(mode)
    elif os.name == "nt":
        _apply_windows_dacl(path)


def _apply_windows_dacl(path: Path) -> None:
    try:
        user = os.environ.get("USERNAME", "")
        if not user:
            return
        proc = subprocess.run(
            [
                "icacls", str(path),
                "/inheritance:r",
                "/grant:r", f"{user}:F",
                "/grant:r", "SYSTEM:F",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0:
            logger.warning(
                "icacls failed for %s: %s", path, proc.stderr.strip()
            )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Cannot apply restrictive DACL to %s: %s", path, exc)
