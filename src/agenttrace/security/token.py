"""Local API token management for CLI↔daemon IPC.

The token is generated once per data directory, stored unencrypted at
``<data_dir>/api_token`` (permission 0600) because the daemon itself must be
able to read it without prompting. Every HTTP request to the local API must
carry it in the ``X-AgentTrace-Token`` header; verification uses a
constant-time comparison.
"""

from __future__ import annotations

import hmac
import os
import secrets
import stat
from pathlib import Path

_TOKEN_FILENAME = "api_token"
_TOKEN_BYTES = 32


class ApiTokenError(Exception):
    """Raised when the API token cannot be created or read."""


class ApiTokenManager:
    """Create, read, and verify the data-dir-scoped API token."""

    def __init__(self, data_dir: str | Path) -> None:
        self._path = Path(data_dir) / _TOKEN_FILENAME

    @property
    def token_path(self) -> Path:
        return self._path

    def token(self) -> str:
        """Return the current token, creating it on first use."""
        if not self._path.exists():
            self._create()
        return self._path.read_text(encoding="utf-8").strip()

    def _create(self) -> None:
        token = secrets.token_hex(_TOKEN_BYTES)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(token + "\n", encoding="utf-8")
        self._apply_restrictive_perms(tmp)
        os.replace(tmp, self._path)
        self._apply_restrictive_perms(self._path)

    @staticmethod
    def _apply_restrictive_perms(path: Path) -> None:
        if os.name == "posix":
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def verify(self, presented: str) -> bool:
        """Constant-time check of a presented token against the stored one."""
        try:
            stored = self.token()
        except OSError:
            return False
        if not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), stored.encode("utf-8"))

    def rotate(self) -> str:
        """Regenerate the token (invalidates all in-flight clients)."""
        self._path.unlink(missing_ok=True)
        return self.token()
