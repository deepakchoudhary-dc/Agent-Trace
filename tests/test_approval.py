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

    def test_path_scope_is_segment_exact(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_paths=["/workspace/.env"])
        # Same file and a descendant at a separator boundary match...
        assert mgr.check_approval(path="/workspace/.env") is True
        assert mgr.check_approval(path="/workspace/src") is False
        # ...but lookalike names sharing the prefix must NOT match
        assert mgr.check_approval(path="/workspace/.env.bak") is False
        assert mgr.check_approval(path="/workspace/.env-2") is False
        assert mgr.check_approval(path="/workspace/env") is False

    def test_path_scope_covers_descendants_only(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_paths=["/workspace/src"])
        assert mgr.check_approval(path="/workspace/src/main.py") is True
        assert mgr.check_approval(path="/workspace/src2/main.py") is False

    def test_path_scope_windows_separators(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_paths=["C:\\work\\src"])
        assert mgr.check_approval(path="C:/work/src/main.py") is True
        assert mgr.check_approval(path="C:/work/src2/main.py") is False

    def test_command_scope_is_token_prefix(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval("finding-1", True, "ok", affected_commands=["git commit"])
        assert mgr.check_approval(command="git commit -m 'fix'") is True
        assert mgr.check_approval(command="git commit") is True
        # The approved command is a true prefix of tokens — not of characters
        assert mgr.check_approval(command="git commit-evil") is False
        assert mgr.check_approval(command="git commit; rm -rf .") is False
        assert mgr.check_approval(command="git push") is False

    def test_typed_scope_strings(self, tmp_path: Path) -> None:
        _, mgr, _ = _make_manager(tmp_path)
        mgr.record_approval(
            "finding-1", True, "ok", scope="path:/data/x, command:npm run build"
        )
        assert mgr.check_approval(path="/data/x/config.json") is True
        assert mgr.check_approval(command="npm run build --prod") is True
        assert mgr.check_approval(path="/data/y/config.json") is False
        assert mgr.check_approval(command="npm install") is False

    def test_request_then_verdict_is_one_record(self, tmp_path: Path) -> None:
        """A request persisted, then resolved by record_approval, must not
        leave duplicate records — the verdict updates the pending row."""
        ledger, mgr, sid = _make_manager(tmp_path)

        mgr.request_approval(
            "finding-1",
            "agent wants to touch .env",
            affected_paths=["/workspace/.env"],
        )
        records = ledger.get_approvals(sid)
        assert len(records) == 1
        assert records[0]["status"] == "requested"
        assert records[0]["approved"] == 0
        # A request alone must never gate as approved
        assert mgr.check_approval(path="/workspace/.env") is False

        mgr.record_approval(
            "finding-1", True, "fine", affected_paths=["/workspace/.env"]
        )
        records = ledger.get_approvals(sid)
        assert len(records) == 1
        assert records[0]["status"] == "granted"
        assert records[0]["approved"] == 1
        assert mgr.check_approval(path="/workspace/.env") is True

    def test_request_denied_does_not_gate(self, tmp_path: Path) -> None:
        ledger, mgr, sid = _make_manager(tmp_path)
        mgr.request_approval("finding-1", "needs approval")
        mgr.record_approval("finding-1", False, "no")
        records = ledger.get_approvals(sid)
        assert len(records) == 1
        assert records[0]["status"] == "denied"
        assert mgr.check_approval(finding_id="finding-1") is False

    def test_request_restored_after_restart(self, tmp_path: Path) -> None:
        """Pending requests survive restart and stay non-granting."""
        ledger, mgr, _ = _make_manager(tmp_path)
        mgr.request_approval("finding-1", "pending thing")

        fresh = ApprovalManager(mgr.session_id, ledger)
        restored = fresh.reload_from_storage()
        assert restored == 0  # requests are not grants
        assert fresh.check_approval(finding_id="finding-1") is False
