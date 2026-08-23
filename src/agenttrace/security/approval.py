"""Approval manager — creates signed graph events for user approvals.

Every approval is a graph event with the user's stated reason, scope,
expiry, and affected commands/paths/destinations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from agenttrace.models.events import ApprovalEvent, ConfidenceLevel

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.storage.ledger import EventLedger

logger = logging.getLogger(__name__)

# Server-side ceiling on approval lifetime: a client may request any
# expiry_minutes, but grants never outlive this window.
MAX_EXPIRY_MINUTES = 24 * 60


class ApprovalManager:
    """Manages approval lifecycle for policy-gated actions.

    Approvals are time-limited and scoped to specific paths, commands,
    or network destinations. Each approval is stored as both a ledger
    event (for the hash chain) and a queryable approval record.
    """

    def __init__(self, session_id: UUID, ledger: EventLedger) -> None:
        self.session_id = session_id
        self._ledger = ledger
        # In-memory cache of active approvals for fast lookup
        self._active_approvals: dict[str, ApprovalEvent] = {}

    def request_approval(
        self,
        finding_id: str,
        description: str,
        affected_paths: list[str] | None = None,
        affected_commands: list[str] | None = None,
    ) -> str:
        """Create an approval request. Returns the finding ID.

        The request is persisted as a hash-chained ledger event plus a
        status='requested' approval record, so pending requests survive
        daemon restarts and can be resolved later.
        """
        event = ApprovalEvent(
            session_id=self.session_id,
            actor_id="policy_engine",
            source_adapter="approval_manager",
            confidence=ConfidenceLevel.HIGH,
            finding_id=finding_id,
            approved=False,
            reason=description,
            scope="",
            expiry=None,
            affected_paths=affected_paths or [],
            affected_commands=affected_commands or [],
        )
        event_hash = self._ledger.append_event(event)
        self._ledger.store_approval(
            approval_id=event.event_id,
            session_id=self.session_id,
            finding_id=finding_id,
            approved=False,
            reason=description,
            scope="",
            expiry=None,
            affected_paths=affected_paths or [],
            affected_commands=affected_commands or [],
            created_at=event.timestamp.isoformat(),
            event_hash=event_hash,
            status="requested",
        )
        logger.info("Approval requested: %s — %s", finding_id, description)
        return finding_id

    def record_approval(
        self,
        finding_id: str,
        approved: bool,
        reason: str,
        scope: str = "",
        expiry_minutes: int = 60,
        affected_paths: list[str] | None = None,
        affected_commands: list[str] | None = None,
    ) -> ApprovalEvent:
        """Record a user's approval or denial.

        The approval is stored as a ledger event (hash-chained) and
        as a queryable approval record — resolving any pending request
        for the same finding in place.
        """
        # Cap only the upper bound: negative/past expiries stay in the past
        # (an already-expired grant is never active).
        expiry = datetime.now(timezone.utc) + timedelta(
            minutes=min(expiry_minutes, MAX_EXPIRY_MINUTES)
        )

        event = ApprovalEvent(
            session_id=self.session_id,
            actor_id="user",
            source_adapter="approval_manager",
            confidence=ConfidenceLevel.HIGH,
            finding_id=finding_id,
            approved=approved,
            reason=reason,
            scope=scope,
            expiry=expiry,
            affected_paths=affected_paths or [],
            affected_commands=affected_commands or [],
        )

        # Append to the hash-chained ledger
        event_hash = self._ledger.append_event(event)

        # Store queryable approval record (paths AND commands encrypted)
        self._ledger.store_approval(
            approval_id=event.event_id,
            session_id=self.session_id,
            finding_id=finding_id,
            approved=approved,
            reason=reason,
            scope=scope,
            expiry=expiry.isoformat(),
            affected_paths=affected_paths or [],
            affected_commands=affected_commands or [],
            created_at=event.timestamp.isoformat(),
            event_hash=event_hash,
            status="granted" if approved else "denied",
        )

        if approved:
            self._active_approvals[finding_id] = event

        logger.info(
            "Approval %s for %s: %s (expires %s)",
            "granted" if approved else "denied",
            finding_id,
            reason,
            expiry.isoformat(),
        )

        return event

    def check_approval(
        self,
        finding_id: str | None = None,
        path: str | None = None,
        command: str | None = None,
    ) -> bool:
        """Check if an action is covered by an active approval.

        Returns True if a valid, non-expired approval matches either:
        - the exact finding ID, or
        - the action's path / command scope (so a user who approved a finding
          covering `/workspace/.env` is not re-prompted for the same file).

        Path scopes match segment-exactly (approving `/a/.env` never covers
        `/a/.env.bak`); command scopes match as a whitespace token prefix
        (`git commit` covers `git commit -m x`, never `git commit-evil`).
        Typed scope strings ("path:...", "command:...", "network:...") are
        honored alongside the structured affected lists.

        Expired approvals are pruned from the active cache on access.
        """
        now = datetime.now(timezone.utc)

        for fid, approval in list(self._active_approvals.items()):
            if not approval.approved:
                continue

            # Prune expired approvals
            if approval.expiry and now > approval.expiry:
                del self._active_approvals[fid]
                continue

            # Exact finding match
            if finding_id and (fid == finding_id or approval.finding_id == finding_id):
                return True

            scoped_paths, scoped_commands = self._approval_scopes(approval)

            # Scope match on path
            if path and scoped_paths and any(self._path_in_scope(p, path) for p in scoped_paths):
                return True

            # Scope match on command
            if (
                command
                and scoped_commands
                and any(self._command_in_scope(c, command) for c in scoped_commands)
            ):
                return True

        return False

    @staticmethod
    def _approval_scopes(approval: ApprovalEvent) -> tuple[list[str], list[str]]:
        """Extract typed path/command scopes from an approval event.

        Honors both the structured affected lists and typed scope strings
        ("path:/a/b", "command:git commit", "network:host:443"). Network
        scopes are not matched here — they are enforced by the network
        policy layer.
        """
        paths: list[str] = []
        commands: list[str] = []
        for p in approval.affected_paths or []:
            if isinstance(p, str) and p:
                paths.append(p)
        for c in approval.affected_commands or []:
            if isinstance(c, str) and c:
                commands.append(c)
        for item in approval.scope.split(","):
            item = item.strip()
            if item.startswith("path:"):
                paths.append(item[len("path:"):].strip())
            elif item.startswith("command:"):
                commands.append(item[len("command:"):].strip())
        return paths, commands

    @staticmethod
    def _normalize_path(p: str) -> str:
        """Normalize separators for cross-platform matching without touching disk."""
        return p.replace("\\", "/").rstrip("/")

    @classmethod
    def _path_in_scope(cls, approved_path: str, action_path: str) -> bool:
        """Segment-exact path scope match.

        `approved_path` covers `action_path` only when the action is the
        approved path itself or a descendant at a separator boundary —
        `/a/.env` never covers `/a/.env.bak` or `/a/.env-2`.
        """
        approved = cls._normalize_path(approved_path)
        action = cls._normalize_path(action_path)
        if not approved or not action:
            return False
        if action == approved:
            return True
        return action.startswith(approved + "/")

    @staticmethod
    def _command_in_scope(approved_command: str, action_command: str) -> bool:
        """Whitespace token-prefix command scope match.

        `git commit` covers `git commit -m "x"` and `git commit --amend`,
        but never `git commit-evil` or `git commit; rm -rf .`.
        """
        approved_tokens = approved_command.split()
        action_tokens = action_command.split()
        if not approved_tokens or not action_tokens:
            return False
        if len(approved_tokens) > len(action_tokens):
            return False
        return action_tokens[: len(approved_tokens)] == approved_tokens

    # Backwards-compatible alias: earlier daemon code referenced is_approved()
    is_approved = check_approval

    def reload_from_storage(self) -> int:
        """Repopulate the active approval cache from the persisted ledger.

        Called on daemon restart so previously granted approvals keep working
        without requiring the user to re-approve the same action.

        Every grant must anchor to a hash that exists in the session's
        tamper-evident event chain; rows whose ``event_hash`` is missing or
        absent from the ledger were inserted/mutated out-of-band and are
        refused (they never reach the active cache).

        Returns the number of active approvals restored.
        """
        records = self._ledger.get_approvals(self.session_id)
        now = datetime.now(timezone.utc)
        restored = 0

        for rec in records:
            if rec.get("status") != "granted":
                continue

            if not self._ledger.event_hash_exists(
                self.session_id, rec.get("event_hash", "")
            ):
                logger.warning(
                    "Refusing approval %s for session %s: anchor hash not in "
                    "event chain (tampered or forged record)",
                    rec.get("finding_id"),
                    self.session_id,
                )
                continue

            try:
                expiry = datetime.fromisoformat(rec["expiry"]) if rec.get("expiry") else None
            except (ValueError, TypeError):
                expiry = None

            if expiry and now > expiry:
                continue

            event = ApprovalEvent(
                session_id=self.session_id,
                actor_id="user",
                source_adapter="approval_manager",
                confidence=ConfidenceLevel.HIGH,
                finding_id=rec.get("finding_id", ""),
                approved=True,
                reason=rec.get("reason", ""),
                scope=rec.get("scope", ""),
                expiry=expiry,
                affected_paths=rec.get("affected_paths", []) or [],
                affected_commands=rec.get("affected_commands", []) or [],
            )
            self._active_approvals[event.finding_id] = event
            restored += 1

        if restored:
            logger.info(
                "Restored %d active approval(s) for session %s from ledger",
                restored,
                self.session_id,
            )
        return restored

    def get_active_approvals(self) -> list[ApprovalEvent]:
        """Get all active (non-expired) approvals."""
        now = datetime.now(timezone.utc)
        expired = [
            fid for fid, a in self._active_approvals.items()
            if a.expiry and now > a.expiry
        ]
        for fid in expired:
            del self._active_approvals[fid]

        return list(self._active_approvals.values())

    def revoke_approval(self, finding_id: str) -> bool:
        """Revoke an existing approval and persist revocation to ledger."""
        revoked = False
        if finding_id in self._active_approvals:
            del self._active_approvals[finding_id]
            revoked = True

        if hasattr(self._ledger, "revoke_approval"):
            self._ledger.revoke_approval(self.session_id, finding_id)

        if revoked:
            logger.info("Approval revoked: %s", finding_id)
        return revoked
