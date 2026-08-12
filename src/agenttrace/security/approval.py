"""Approval manager — creates signed graph events for user approvals.

Every approval is a graph event with the user's stated reason, scope,
expiry, and affected commands/paths/destinations.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from agenttrace.models.events import ApprovalEvent, ConfidenceLevel
from agenttrace.storage.ledger import EventLedger

logger = logging.getLogger(__name__)


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
        """Create an approval request. Returns the finding ID."""
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
        as a queryable approval record.
        """
        expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

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

        # Store queryable approval record
        self._ledger.store_approval(
            approval_id=event.event_id,
            session_id=self.session_id,
            finding_id=finding_id,
            approved=approved,
            reason=reason,
            scope=scope,
            expiry=expiry.isoformat(),
            affected_json=json.dumps(
                {"paths": affected_paths or [], "commands": affected_commands or []}
            ),
            created_at=event.timestamp.isoformat(),
            event_hash=event_hash,
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
        finding_id: str,
        path: str | None = None,
        command: str | None = None,
    ) -> bool:
        """Check if an action is covered by an active approval.

        Returns True if a valid, non-expired approval covers the action.
        """
        approval = self._active_approvals.get(finding_id)
        if not approval:
            return False

        # Check expiry
        if approval.expiry and datetime.now(timezone.utc) > approval.expiry:
            del self._active_approvals[finding_id]
            return False

        if not approval.approved:
            return False

        # Check scope
        if path and approval.affected_paths:
            if not any(p in path for p in approval.affected_paths):
                return False

        if command and approval.affected_commands:
            if not any(c in command for c in approval.affected_commands):
                return False

        return True

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
        """Revoke an existing approval."""
        if finding_id in self._active_approvals:
            del self._active_approvals[finding_id]
            logger.info("Approval revoked: %s", finding_id)
            return True
        return False
