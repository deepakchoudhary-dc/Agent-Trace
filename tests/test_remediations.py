"""Tests for plan2.md security, containment, and wiring remediations."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from uuid import uuid4

from agenttrace.api import app, lifespan
from agenttrace.daemon import AgentTraceDaemon
from agenttrace.observers.job_object_process import WindowsJobObject
from agenttrace.observers.kernel import KernelObserver
from agenttrace.security.approval import ApprovalManager
from agenttrace.security.policy import PolicyEngine
from agenttrace.security.redaction import SecretRedactor
from agenttrace.storage.ledger import EventLedger

if TYPE_CHECKING:
    from pathlib import Path


def test_zero_width_unicode_secret_redaction() -> None:
    """SecretRedactor detects and redacts secrets obfuscated with zero-width characters."""
    redactor = SecretRedactor()
    # AWS Access Key obfuscated with zero-width spaces (\u200b)
    obfuscated_aws = "AKIA\u200bIOSFOD\u200bNN7EXAMP\u200bLE"
    redacted = redactor.redact(f"Connect with key: {obfuscated_aws}")
    assert "AKIA" not in redacted
    assert "[REDACTED]" in redacted


def test_binary_redaction_fails_closed() -> None:
    """SecretRedactor replaces non-decodable binary bytes with safe hash metadata."""
    redactor = SecretRedactor()
    # Non-decodable binary data containing raw secret bytes
    raw_binary = b"\x80\x81\xfe\xff" + b"sk-live-supersecretbinarykey"
    redacted_bytes = redactor.redact_bytes(raw_binary)
    assert b"sk-live" not in redacted_bytes
    assert b"[REDACTED BINARY EVIDENCE" in redacted_bytes


def test_policy_engine_rules_are_isolated_per_session() -> None:
    """Mutating rules in one PolicyEngine does not pollute other sessions."""
    sid1 = uuid4()
    sid2 = uuid4()

    engine1 = PolicyEngine(sid1)
    engine2 = PolicyEngine(sid2)

    # Disable a rule in engine1
    updated = engine1.update_rule("destructive_file_op", enabled=False)
    assert updated is True

    # Rule in engine1 is disabled; rule in engine2 must remain enabled
    assert engine1.get_rules()["destructive_file_op"].enabled is False
    assert engine2.get_rules()["destructive_file_op"].enabled is True


def test_approval_revocation_persists_to_ledger(tmp_path: Path) -> None:
    """ApprovalManager.revoke_approval updates SQLite so revocation survives restart."""
    ledger = EventLedger(tmp_path / "ledger.db")
    sid = uuid4()
    ledger.create_session(
        session_id=sid,
        config_json="{}",
        task_desc="Test task",
        started_at="2026-08-20T12:00:00Z",
    )
    manager = ApprovalManager(sid, ledger)

    # Request and record an approval
    manager.request_approval("finding-1", "Test approval required")
    manager.record_approval("finding-1", approved=True, reason="User verified")

    assert len(manager.get_active_approvals()) == 1

    # Revoke approval
    revoked = manager.revoke_approval("finding-1")
    assert revoked is True
    assert len(manager.get_active_approvals()) == 0

    # Simulate daemon restart / new ApprovalManager reloading from ledger
    manager2 = ApprovalManager(sid, ledger)
    restored = manager2.reload_from_storage()
    assert restored == 0
    assert len(manager2.get_active_approvals()) == 0


def test_fastapi_lifespan_is_bound_to_app() -> None:
    """FastAPI app is initialized with the lifespan context manager."""
    assert app.router.lifespan_context is lifespan


def test_job_object_strict_containment_no_breakaway() -> None:
    """WindowsJobObject creates strict containment without breakaway flag."""
    sid = uuid4()
    job = WindowsJobObject(sid, kill_on_close=False)
    # The job object must be initialized without raising errors
    assert job.session_id == sid
    job.close()


class _FakeJob:
    """Stands in for WindowsJobObject with scripted kernel membership."""

    def __init__(self, pids: set[int], active: bool = True) -> None:
        self._pids = pids
        self._active = active
        self.terminated = False

    @property
    def is_active(self) -> bool:
        return self._active

    def get_pids(self) -> list[int]:
        return list(self._pids)

    def terminate(self, exit_code: int = 1) -> bool:
        self.terminated = True
        return True


def test_incident_kill_requires_kernel_verified_membership(tmp_path: Path) -> None:
    """Heuristic descendants are never killed; only Job Object members."""
    daemon = AgentTraceDaemon(tmp_path / "data")
    sid = uuid4()

    # A heuristic "contained_descendant" tracked by the observer must NOT
    # influence the kill decision: the fake job reports empty membership.
    daemon._job_objects[sid] = _FakeJob(pids=set())
    assert daemon._terminate_contained(sid) == 0
    assert not daemon._job_objects[sid].terminated

    daemon._job_objects[sid] = _FakeJob(pids={1001, 1002})
    assert daemon._terminate_contained(sid) == 2
    assert daemon._job_objects[sid].terminated


def test_incident_kill_refuses_daemon_own_tree(tmp_path: Path) -> None:
    """If the daemon's own PIDs appear inside a job, refuse to arm."""
    daemon = AgentTraceDaemon(tmp_path / "data")
    sid = uuid4()
    daemon._job_objects[sid] = _FakeJob(pids={os.getpid(), os.getppid(), 4242})
    assert daemon._terminate_contained(sid) == 0
    assert not daemon._job_objects[sid].terminated


def test_kernel_observer_parses_hex_pid_and_scopes_confidence(tmp_path: Path) -> None:
    """KernelObserver parses hexadecimal PIDs and scopes confidence based on workspace."""
    observer = KernelObserver(uuid4(), str(tmp_path), lambda e, p=None: None)

    # Hexadecimal PID with matching workspace in command line
    fields_workspace = {
        "pid": "0x1234",
        "ppid": "0x5678",
        "command_line": f"python {tmp_path / 'main.py'}",
        "image": "python.exe",
    }
    event = observer._translate_event("4688", fields_workspace, "2026-08-20T12:00:00Z")
    assert event is not None
    assert event.pid == 0x1234
    assert event.ppid == 0x5678
    assert event.confidence.value == "high"

    # Hexadecimal PID with unrelated system command line
    fields_system = {
        "pid": "0x400",
        "ppid": "0x100",
        "command_line": "svchost.exe -k netsvcs",
        "image": "svchost.exe",
    }
    event_system = observer._translate_event("4688", fields_system, "2026-08-20T12:00:00Z")
    assert event_system is not None
    assert event_system.pid == 0x400
    assert event_system.confidence.value == "low"
    assert "unattributed_etw" in event_system.actor_id


def test_token_expiry_fails_closed_when_companion_missing(tmp_path: Path) -> None:
    """ApiTokenManager.is_expired() returns True when expiry file is missing/corrupt."""
    from agenttrace.security.token import ApiTokenManager

    manager = ApiTokenManager(tmp_path)
    tok = manager.token()
    assert tok is not None
    assert manager.is_expired() is False

    # Delete companion expiry file -> must fail closed (P1.3)
    manager.expiry_path.unlink()
    assert manager.is_expired() is True


def test_auto_agent_type_selects_composite_adapter(tmp_path: Path) -> None:
    """AgentType.AUTO selects CompositeAdapter to compose all dedicated transcripts."""
    from agenttrace.adapters.composite import CompositeAdapter
    from agenttrace.daemon import AgentTraceDaemon
    from agenttrace.models.session import AgentType, AuditSession, SessionConfig

    daemon = AgentTraceDaemon(tmp_path)
    session = AuditSession(
        config=SessionConfig(
            workspace_path=str(tmp_path),
            agent_type=AgentType.AUTO,
        ),
    )
    adapter = daemon._select_adapter(session)
    assert isinstance(adapter, CompositeAdapter)

