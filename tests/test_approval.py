"""Tests for ApprovalManager — recording, scope matching, expiry, restart restore."""

from pathlib import Path
from uuid import uuid4

from agenttrace.security.approval import ApprovalManager
from agenttrace.storage.ledger import EventLedger


def _make_manager(tmp_path: Path) -> tuple[EventLedger, ApprovalManager, object]:
    ledger = EventLedger(tmp_path / "approvals.db")
    sid = uuid4()
    ledger.create_session(sid, "{}", "approval test", "2024-01-01T00:00:00Z")
    return ledger, ApprovalManager(sid, ledger), sid


class TestApprovalManager:
    """Tests for ApprovalManager lifecycle and scope matching."""

    def test_record_and_check_by_finding(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "trusted", scope="workspace")
        assert mgr.check_approval(finding_id="finding-1") is True
        assert mgr.check_approval(finding_id="other") is False

    def test_scope_match_by_path(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_paths=["/workspace/.env"])
        # A later gate on the same path is pre-approved
        assert mgr.check_approval(path="/workspace/.env") is True
        assert mgr.check_approval(path="/workspace/src/main.py") is False

    def test_scope_match_by_command(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_commands=["rm -rf /tmp/scratch"])
        assert mgr.check_approval(command="rm -rf /tmp/scratch") is True
        assert mgr.check_approval(command="rm -rf /") is False

    def test_expired_approval_is_ignored(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", expiry_minutes=-1)
        assert mgr.check_approval(finding_id="finding-1") is False

    def test_denied_approval_never_grants(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", False, "not allowed")
        assert mgr.check_approval(finding_id="finding-1") is False

    def test_is_approved_alias(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok")
        assert mgr.is_approved(finding_id="finding-1") is True

    def test_reload_from_storage_restores_cache(self, tmp_path: Path) -> None:
        ledger, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_paths=["/workspace/.env"])
        mgr.record_approval("finding-2", True, "ok", affected_commands=["npm install"])

        # Simulate a restart: a fresh manager over the same ledger starts empty
        fresh = ApprovalManager(mgr.session_id, ledger)
        assert fresh.check_approval(finding_id="finding-1") is False

        restored = fresh.reload_from_storage()
        assert restored == 2
        assert fresh.check_approval(finding_id="finding-1") is True
        assert fresh.check_approval(path="/workspace/.env") is True
        assert fresh.check_approval(command="npm install") is True

    def test_reload_skips_denied_and_expired(self, tmp_path: Path) -> None:
        ledger, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("denied-1", False, "no")
        mgr.record_approval("expired-1", True, "old", expiry_minutes=-1)
        mgr.record_approval("good-1", True, "yes")

        fresh = ApprovalManager(mgr.session_id, ledger)
        restored = fresh.reload_from_storage()
        assert restored == 1
        assert fresh.check_approval(finding_id="good-1") is True
        assert fresh.check_approval(finding_id="denied-1") is False
