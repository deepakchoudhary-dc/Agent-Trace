"""Execution broker — the only sanctioned path from approval to process (P0.2).

A hostile or confused agent cannot be allowed to translate a voluntary
PATH-wrapper gate into real execution: an absolute path or an unwrapped tool
bypasses it. The broker receives **structured argv** (never a rejoined shell
string), requires a daemon-issued single-use challenge bound to the exact
session, finding, path, and argv, consults the durable approval decision,
records the decision as a hash-chained event, and only then spawns the child
inside the verified containment unit (``IsolationRunner``). Unsupported
platforms fail closed with ``isolation_unavailable`` — never a host fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from agenttrace.models.events import CommandEvent, ConfidenceLevel
from agenttrace.security.isolation import IsolationError, IsolationResult, IsolationRunner

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.security.approval import ApprovalManager
    from agenttrace.storage.ledger import EventLedger

logger = logging.getLogger(__name__)

_CHALLENGE_TTL_SECONDS = 120


class BrokerError(RuntimeError):
    """The broker refused to execute; message carries the machine-readable code."""


@dataclass(frozen=True)
class BrokerChallenge:
    """A single-use, tightly bound pre-execution challenge."""

    nonce: str
    finding_id: str
    argv_hash: str
    path: str
    expires_at: datetime


class ExecutionBroker:
    """Mediates every agent-initiated execution: challenge → approval → spawn."""

    def __init__(
        self,
        session_id: UUID,
        ledger: EventLedger,
        approvals: ApprovalManager,
        isolation: IsolationRunner,
        workspace_path: str | Path,
    ) -> None:
        self.session_id = session_id
        self._ledger = ledger
        self._approvals = approvals
        self._isolation = isolation
        self._workspace = Path(workspace_path).resolve()
        self._challenges: dict[str, BrokerChallenge] = {}

    # -- Challenges --------------------------------------------------------

    @staticmethod
    def _argv_hash(argv: list[str]) -> str:
        canonical = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def issue_challenge(self, finding_id: str, argv: list[str], path: str = "") -> str:
        """Issue a nonce bound to finding, argv, and path (short TTL)."""
        self._validate_argv(argv)
        nonce = secrets.token_urlsafe(24)
        self._challenges[nonce] = BrokerChallenge(
            nonce=nonce,
            finding_id=finding_id,
            argv_hash=self._argv_hash(argv),
            path=path,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=_CHALLENGE_TTL_SECONDS),
        )
        return nonce

    # -- Execution ---------------------------------------------------------

    def execute(
        self,
        argv: list[str],
        *,
        finding_id: str,
        nonce: str,
        path: str = "",
        env: dict[str, str] | None = None,
        scratch_dir: Path | None = None,
    ) -> IsolationResult:
        """Validate challenge + approval, then run inside containment."""
        self._validate_argv(argv)

        challenge = self._challenges.get(nonce)
        if (
            challenge is None
            or challenge.expires_at < datetime.now(timezone.utc)
            or challenge.finding_id != finding_id
            or challenge.argv_hash != self._argv_hash(argv)
            or challenge.path != path
        ):
            raise BrokerError("challenge_invalid")

        self._challenges.pop(nonce, None)  # single use, even on later failure

        if not self._approvals.check_approval(finding_id=finding_id):
            raise BrokerError(
                f"approval_required: no active approval for finding '{finding_id}'"
            )

        if path:
            target = (self._workspace / path).resolve()
            if self._workspace not in target.parents and target != self._workspace:
                raise BrokerError(f"path_outside_scope: {path}")

        try:
            result = self._isolation.run(
                argv,
                workspace_path=self._workspace,
                scratch_dir=scratch_dir,
                env=env,
            )
        except IsolationError as exc:
            raise BrokerError(str(exc)) from exc

        self._record_decision(argv, finding_id, path, result)
        return result

    # -- Internals ---------------------------------------------------------

    @staticmethod
    def _validate_argv(argv: list[str]) -> None:
        if not argv or not all(isinstance(a, str) and a for a in argv):
            raise BrokerError("invalid_argv: argv must be a non-empty list of strings")

    def _record_decision(
        self,
        argv: list[str],
        finding_id: str,
        path: str,
        result: IsolationResult,
    ) -> None:
        event = CommandEvent(
            session_id=self.session_id,
            actor_id="execution_broker",
            source_adapter="execution_broker",
            confidence=ConfidenceLevel.HIGH,
            command=json.dumps(argv, ensure_ascii=False),
            working_dir=path,
            exit_code=result.exit_code,
            output=(result.stdout + result.stderr)[:2000],
        )
        self._ledger.append_event(event)
        logger.info(
            "Broker executed finding=%s argv0=%s exit=%s error=%s",
            finding_id,
            argv[0],
            result.exit_code,
            result.error,
        )
