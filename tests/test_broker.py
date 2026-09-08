"""Tests for the ExecutionBroker (plan2.md P0.2)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from agenttrace.security.approval import ApprovalManager
from agenttrace.security.broker import BrokerError, ExecutionBroker
from agenttrace.security.isolation import IsolationResult
from agenttrace.storage.ledger import EventLedger

if TYPE_CHECKING:
    from pathlib import Path


class StubRunner:
    """Records argv; stands in for the container IsolationRunner."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        workspace_path: Path,
        scratch_dir: Path | None = None,
        env: dict[str, str] | None = None,
        workdir: str = "/workspace",
    ) -> IsolationResult:
        self.calls.append(list(argv))
        return IsolationResult(exit_code=0, stdout="ok", stderr="", duration_ms=1)


class StubContained:
    """Scripted ContainedProcess: returns a fixed exit code."""

    def __init__(self, exit_code: int) -> None:
        self._exit_code = exit_code
        self.terminated = False
        self.closed = False

    def wait(self, timeout: float | None = None) -> int | None:
        return self._exit_code

    def terminate(self) -> bool:
        self.terminated = True
        return True

    def close(self) -> None:
        self.closed = True


class StubContainment:
    """Records spawn calls; stands in for the kernel containment unit."""

    def __init__(self, exit_code: int = 0) -> None:
        self.spawned: list[list[str]] = []
        self._exit_code = exit_code

    def spawn(self, cmdline: list[str], *, cwd: str | None = None) -> StubContained:
        self.spawned.append(list(cmdline))
        return StubContained(self._exit_code)


class ContainedStubRunner(StubRunner):
    """Stub runner that serves the contained spawn path."""

    def __init__(self) -> None:
        super().__init__()
        self.contained_calls: list[list[str]] = []

    def run_contained(
        self,
        argv: list[str],
        *,
        containment: Any,
        workspace_path: Path,
        env: dict[str, str] | None = None,
    ) -> IsolationResult:
        self.contained_calls.append(list(argv))
        proc = containment.spawn(argv, cwd=str(workspace_path))
        code = proc.wait(timeout=5)
        proc.close()
        return IsolationResult(exit_code=code, stdout="ok", stderr="", duration_ms=1)


@pytest.fixture()
def contained_env(
    tmp_path: Path,
) -> tuple[ExecutionBroker, ContainedStubRunner, StubContainment]:
    ledger = EventLedger(tmp_path / "ledger.db")
    sid = uuid4()
    ledger.create_session(sid, "{}", "broker-contained", "2026-01-01T00:00:00Z")
    approvals = ApprovalManager(sid, ledger)
    runner = ContainedStubRunner()
    broker = ExecutionBroker(
        sid, ledger, approvals, runner,  # type: ignore[arg-type]
        tmp_path / "ws",
    )
    return broker, runner, StubContainment()


def test_contained_spawn_verified_at_creation(
    contained_env: tuple,
) -> None:
    """P1 residual closed: on the contained path the child enters the
    kernel unit at spawn — membership is verified by construction, not
    attached post-hoc. The container path is never touched."""
    broker, runner, containment = contained_env
    nonce = broker.issue_challenge("f-1", ["python", "-V"])
    broker._approvals.record_approval("f-1", True, "pre-approved")
    result = broker.execute(
        ["python", "-V"], finding_id="f-1", nonce=nonce, containment=containment
    )
    assert result.exit_code == 0
    assert containment.spawned == [["python", "-V"]]
    assert runner.calls == []  # container path untouched


def test_without_containment_falls_back_to_container(env: tuple) -> None:
    """No containment unit -> the container path is used, same challenge
    and approval discipline."""
    broker, ledger, runner = env
    nonce = broker.issue_challenge("f-1", ["python", "-V"])
    broker._approvals.record_approval("f-1", True, "pre-approved")
    result = broker.execute(["python", "-V"], finding_id="f-1", nonce=nonce)
    assert result.exit_code == 0
    assert runner.calls == [["python", "-V"]]


def test_contained_timeout_reports_error(tmp_path: Path) -> None:
    """A hung contained child is terminated at the wall clock and the
    result carries the isolation_timeout error, not a silent hang."""
    from agenttrace.security.approval import ApprovalManager

    ledger = EventLedger(tmp_path / "ledger.db")
    sid = uuid4()
    ledger.create_session(sid, "{}", "broker-timeout", "2026-01-01T00:00:00Z")
    approvals = ApprovalManager(sid, ledger)

    class HungRunner:
        timeout_seconds = 0.2

        def preflight(self) -> None:
            return None

        def run_contained(
            self,
            argv: list[str],
            *,
            containment: Any,
            workspace_path: Path,
            env: dict[str, str] | None = None,
        ) -> IsolationResult:
            import time as _t

            start = _t.monotonic()
            proc = containment.spawn(argv, cwd=str(workspace_path))
            while _t.monotonic() - start < self.timeout_seconds:
                code = proc.wait(timeout=0.05)
                if code is not None:
                    proc.close()
                    return IsolationResult(
                        exit_code=code, stdout="", stderr="", duration_ms=1
                    )
            proc.terminate()
            return IsolationResult(
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=int((_t.monotonic() - start) * 1000),
                error="isolation_timeout: exceeded 0.2s",
            )

    class HungProcess:
        def wait(self, timeout: float | None = None) -> int | None:
            return None

        def terminate(self) -> bool:
            return True

        def close(self) -> None:
            return None

    class HungContainment:
        def __init__(self) -> None:
            self.spawned: list[list[str]] = []

        def spawn(
            self, cmdline: list[str], *, cwd: str | None = None
        ) -> HungProcess:
            self.spawned.append(list(cmdline))
            return HungProcess()

    broker = ExecutionBroker(
        sid, ledger, approvals, HungRunner(),  # type: ignore[arg-type]
        tmp_path / "ws",
    )
    argv = ["python", "-c", "sleep"]
    nonce = broker.issue_challenge("f-1", argv)
    broker._approvals.record_approval("f-1", True, "pre-approved")
    result = broker.execute(
        argv, finding_id="f-1", nonce=nonce, containment=HungContainment()
    )
    assert result.exit_code is None
    assert result.error is not None
    assert "isolation_timeout" in result.error


@pytest.fixture()
def env(tmp_path: Path) -> tuple[ExecutionBroker, EventLedger, StubRunner]:
    ledger = EventLedger(tmp_path / "ledger.db")
    sid = uuid4()
    ledger.create_session(sid, "{}", "broker-test", "2026-01-01T00:00:00Z")
    approvals = ApprovalManager(sid, ledger)
    runner = StubRunner()
    broker = ExecutionBroker(
        sid, ledger, approvals, runner,  # type: ignore[arg-type]
        tmp_path / "ws",
    )
    return broker, ledger, runner


def test_execute_without_challenge_rejected(env: tuple) -> None:
    broker, _ledger, _runner = env
    with pytest.raises(BrokerError, match="challenge_invalid"):
        broker.execute(["pytest", "-q"], finding_id="f1", nonce="nope")


def test_execute_without_approval_rejected(env: tuple) -> None:
    broker, _ledger, _runner = env
    nonce = broker.issue_challenge("f1", ["pytest", "-q"])
    with pytest.raises(BrokerError, match="approval_required"):
        broker.execute(["pytest", "-q"], finding_id="f1", nonce=nonce)


def test_challenge_is_bound_to_argv(env: tuple) -> None:
    broker, _ledger, _runner = env
    nonce = broker.issue_challenge("f1", ["pytest", "-q"])
    broker._approvals.record_approval("f1", True, "ok")  # noqa: SLF001
    with pytest.raises(BrokerError, match="challenge_invalid"):
        broker.execute(["pytest", "--evil"], finding_id="f1", nonce=nonce)


def test_challenge_is_single_use(env: tuple) -> None:
    broker, _ledger, _runner = env
    broker._approvals.record_approval("f1", True, "ok")  # noqa: SLF001
    nonce = broker.issue_challenge("f1", ["pytest", "-q"])
    broker.execute(["pytest", "-q"], finding_id="f1", nonce=nonce)
    with pytest.raises(BrokerError, match="challenge_invalid"):
        broker.execute(["pytest", "-q"], finding_id="f1", nonce=nonce)


def test_happy_path_runs_isolated_and_records_decision(env: tuple) -> None:
    broker, ledger, runner = env
    sid = broker.session_id
    broker._approvals.record_approval("f1", True, "ok")  # noqa: SLF001
    nonce = broker.issue_challenge("f1", ["pytest", "-q"])

    result = broker.execute(["pytest", "-q"], finding_id="f1", nonce=nonce)

    assert result.succeeded
    assert runner.calls == [["pytest", "-q"]]
    events = ledger.query_events(sid, limit=50)
    broker_events = [
        e for e in events if getattr(e, "actor_id", "") == "execution_broker"
    ]
    assert broker_events, "broker decision must be recorded in the ledger"
    assert json.loads(broker_events[-1].command) == ["pytest", "-q"]


def test_path_outside_scope_rejected(env: tuple, tmp_path: Path) -> None:
    broker, _ledger, _runner = env
    broker._approvals.record_approval("f1", True, "ok")  # noqa: SLF001
    nonce = broker.issue_challenge("f1", ["pytest", "-q"], path="../outside")
    with pytest.raises(BrokerError, match="path_outside_scope"):
        broker.execute(
            ["pytest", "-q"], finding_id="f1", nonce=nonce, path="../outside"
        )
