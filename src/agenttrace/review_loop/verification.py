from __future__ import annotations

import logging
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from agenttrace.graph.replay import ReplayEngine
from agenttrace.security.isolation import IsolationError, IsolationRunner

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 120
_MAX_OUTPUT_CHARS = 8000


@dataclass
class VerificationResult:
    """Outcome of running one allowlisted verification command."""

    command: str = ""
    allowed: bool = False
    rejection_reason: str = ""
    exit_code: int | None = None
    output: str = ""
    duration_ms: int = 0
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.allowed and self.exit_code == 0 and not self.error


class VerificationRunner:
    """Runs allowlisted verification commands inside isolated containment.

    Per plan2.md P0.1 the runner is fail-closed: with no ``IsolationRunner``
    configured (or when the container runtime/image is unavailable) the
    command is never executed — not on the host, not with a scrubbed
    environment. Host project configuration (pytest plugins, hooks, make,
    native extensions) is arbitrary code execution, not a harmless default.
    """

    def __init__(
        self,
        workspace_path: str | Path,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = _MAX_OUTPUT_CHARS,
        isolation: IsolationRunner | None = None,
    ) -> None:
        self.workspace_path = Path(workspace_path)
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self._isolation = isolation

    def run(self, command: str) -> VerificationResult:
        """Run one command, returning its real outcome (never raises)."""
        result = VerificationResult(command=command)
        allowed, reason = ReplayEngine.verify_command_allowed(command)
        result.allowed = allowed
        result.rejection_reason = "" if allowed else reason
        if not allowed:
            logger.warning("Verification command rejected by allowlist: %s (%s)", command, reason)
            return result

        if self._isolation is None:
            result.error = (
                "isolation_unavailable: no IsolationRunner configured; "
                "verification commands are never executed directly on the host"
            )
            logger.error("Verification blocked: %s", result.error)
            return result

        try:
            parts = shlex.split(command, posix=os.name != "nt")
        except ValueError as exc:
            result.error = f"Unparseable command: {exc}"
            return result
        if not parts or any(not part for part in parts):
            result.error = "invalid argv: empty element in command"
            return result

        try:
            iso = self._isolation.run(parts, workspace_path=self.workspace_path)
        except IsolationError as exc:
            result.error = str(exc)
            return result

        result.exit_code = iso.exit_code
        result.duration_ms = iso.duration_ms
        if iso.error:
            result.error = iso.error
        result.output = self._truncate(iso.stdout + iso.stderr)
        return result

    def _truncate(self, text: str) -> str:
        if len(text) <= self.max_output_chars:
            return text
        return (
            text[: self.max_output_chars]
            + f"\n... [truncated, {len(text)} chars total]"
        )

