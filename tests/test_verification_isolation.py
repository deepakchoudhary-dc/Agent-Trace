"""Tests for fail-closed VerificationRunner (plan2.md P0.1, review loop)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agenttrace.review_loop.verification import VerificationRunner
from agenttrace.security.isolation import IsolationResult

if TYPE_CHECKING:
    from pathlib import Path


def test_no_isolation_never_executes(tmp_path: Path) -> None:
    """Without an IsolationRunner the allowlisted command does not run."""
    runner = VerificationRunner(tmp_path)
    result = runner.run("pytest --version")
    assert result.allowed  # it IS on the allowlist...
    assert result.exit_code is None
    assert result.error.startswith("isolation_unavailable")
    assert not result.succeeded


def test_non_allowlisted_command_rejected(tmp_path: Path) -> None:
    runner = VerificationRunner(tmp_path)
    result = runner.run("curl http://evil.example")
    assert not result.allowed
    assert result.rejection_reason


def test_isolated_execution_roundtrip(tmp_path: Path) -> None:
    """With a runner, the allowlisted argv is passed to isolation verbatim."""
    seen: dict[str, list[str]] = {}

    class StubRunner:
        def run(
            self, argv: list[str], *, workspace_path: Path, **kwargs: object
        ) -> IsolationResult:
            seen["argv"] = list(argv)
            return IsolationResult(
                exit_code=0, stdout="ok", stderr="", duration_ms=2
            )

    runner = VerificationRunner(tmp_path, isolation=StubRunner())  # type: ignore[arg-type]
    result = runner.run("pytest -q")
    assert result.succeeded
    assert seen["argv"] == ["pytest", "-q"]
