"""Tests for the ExecutionBroker (plan2.md P0.2)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
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
