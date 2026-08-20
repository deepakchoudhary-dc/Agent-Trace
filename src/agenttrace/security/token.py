"""Local API token management for CLI↔daemon IPC.

The token is generated once per data directory, stored unencrypted at
``<data_dir>/api_token`` (permission 0600 / Windows DACL restricted to the
current user) because the daemon itself must be able to read it without
prompting. Every HTTP request to the local API must carry it in the
``X-AgentTrace-Token`` header; verification uses a constant-time comparison.

Tokens expire: a new token is minted on first use after ``token_ttl_days``.
``verify`` fails closed once expired, so a stale token cannot be used to
replay a hijacked file.
"""

from __future__ import annotations

import datetime
import hmac
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

_TOKEN_FILENAME = "api_token"
_TOKEN_EXPIRY_FILENAME = "api_token_expiry"
_TOKEN_BYTES = 32
_TOKEN_TTL_DAYS = 90


class ApiTokenError(Exception):
    """Raised when the API token cannot be created or read."""


class ApiTokenManager:
    """Create, read, verify, and rotate the data-dir-scoped API token."""

    def __init__(self, data_dir: str | Path) -> None:
        self._path = Path(data_dir) / _TOKEN_FILENAME
        self._expiry_path = Path(data_dir) / _TOKEN_EXPIRY_FILENAME

    @property
    def token_path(self) -> Path:
        return self._path

    @property
    def expiry_path(self) -> Path:
        return self._expiry_path

    def token(self) -> str:
        """Return the current token, creating it on first use."""
        if not self._path.exists():
            self._create()
        return self._path.read_text(encoding="utf-8").strip()

    def token_expiry(self) -> datetime.datetime | None:
        """ISO-8601 expiry timestamp of the current token, if known."""
        try:
            raw = self._expiry_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        try:
            return datetime.datetime.fromisoformat(raw)
        except ValueError:
            return None

    def is_expired(self) -> bool:
        """Whether the stored token has passed its expiry (fail closed)."""
        if not self._path.exists():
            return False
        expiry = self.token_expiry()
        if expiry is None:
            # Missing or corrupt companion expiry file fails closed (P1.3)
            return True
        return datetime.datetime.now(datetime.timezone.utc) >= expiry

    def _create(self) -> None:
        token = secrets.token_hex(_TOKEN_BYTES)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(token + "\n", encoding="utf-8")
        self._apply_restrictive_perms(tmp)
        os.replace(tmp, self._path)
        self._apply_restrictive_perms(self._path)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=_TOKEN_TTL_DAYS
        )
        tmp_expiry = self._expiry_path.with_suffix(".tmp")
        tmp_expiry.write_text(expiry.isoformat() + "\n", encoding="utf-8")
        self._apply_restrictive_perms(tmp_expiry)
        os.replace(tmp_expiry, self._expiry_path)
        self._apply_restrictive_perms(self._expiry_path)

    @classmethod
    def _apply_restrictive_perms(cls, path: Path) -> None:
        """Restrict a token file to the current user (best-effort)."""
        from agenttrace.security.permissions import apply_restrictive_perms

        apply_restrictive_perms(path)

    def verify(self, presented: str) -> bool:
        """Constant-time check of a presented token against the stored one."""
        try:
            if not presented or self.is_expired():
                return False
            stored = self.token()
        except OSError:
            return False
        if not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), stored.encode("utf-8"))

    def rotate(self) -> str:
        """Regenerate the token (invalidates all in-flight clients)."""
        self._path.unlink(missing_ok=True)
        self._expiry_path.unlink(missing_ok=True)
        return self.token()
