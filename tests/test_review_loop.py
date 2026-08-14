"""Tests for the self-improving review loop."""

from agenttrace.review_loop.loop import ReviewLoop
from agenttrace.review_loop.planner import Planner
from agenttrace.review_loop.reviewer import (
    ConventionReviewer,
    SecurityReviewer,
    SpecComplianceReviewer,
)
from agenttrace.review_loop.synthesizer import Synthesizer
from agenttrace.review_loop.worker import Worker


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
        assert any("satisfy" in c.lower() or "changes" in c.lower() for c in plan.acceptance_criteria)

    def test_amend_plan(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Refactor module")
        original_count = len(plan.subtasks)

        plan = planner.amend_plan(plan, "Need more tests", ["Tests missing"])
        assert len(plan.subtasks) > original_count


class TestWorker:
    """Tests for the Worker component."""

    def test_execute_iteration(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Write a function")

        worker = Worker()
        result = worker.execute(plan)
        assert result.iteration == 1
        assert len(result.artifacts) > 0

    def test_feedback_incorporation(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Add validation")

        worker = Worker()
        worker.execute(plan)

        feedback = {
            "failed_criteria": ["Missing edge case tests"],
            "suggestions": ["Use pytest parametrize"],
        }
        result = worker.execute(plan, feedback)
        assert result.iteration == 2
        assert len(result.feedback_applied) > 0

    def test_convergence_metrics(self) -> None:
        worker = Worker()
        metrics = worker.get_convergence_metrics()
        assert metrics["iteration"] == 0


class TestReviewers:
    """Tests for the reviewer components."""

    def test_spec_compliance_review(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Add feature")
        worker = Worker()
        worker_result = worker.execute(plan)

        reviewer = SpecComplianceReviewer()
        review = reviewer.review(plan, worker_result)
        assert review.reviewer_name == "spec_compliance"
        assert len(review.results) > 0

    def test_security_review(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Add feature")
        worker = Worker()
        worker_result = worker.execute(plan)

        reviewer = SecurityReviewer()
        review = reviewer.review(plan, worker_result)
        assert review.reviewer_name == "security"

    def test_convention_review(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Add feature")
        worker = Worker()
        worker_result = worker.execute(plan)

        reviewer = ConventionReviewer()
        review = reviewer.review(plan, worker_result)
        assert review.reviewer_name == "convention"


class TestSynthesizer:
    """Tests for the Synthesizer component."""

    def test_synthesize_passing(self) -> None:
        planner = Planner()
        plan = planner.create_plan("Simple task")
        worker = Worker()
        worker_result = worker.execute(plan)

        reviews = [
            SpecComplianceReviewer().review(plan, worker_result),
            SecurityReviewer().review(plan, worker_result),
            ConventionReviewer().review(plan, worker_result),
        ]

        synthesizer = Synthesizer()
        result = synthesizer.synthesize(reviews)
        # Should pass since worker produces artifacts
        assert result.passed
        assert result.overall_confidence > 0


class TestReviewLoop:
    """Tests for the ReviewLoop orchestrator."""

    def test_loop_runs(self) -> None:
        loop = ReviewLoop(max_iterations=2)
        result = loop.run("Add a hello world function")
        assert result.total_iterations >= 1
        assert result.completed_at is not None

    def test_loop_max_iterations(self) -> None:
        loop = ReviewLoop(max_iterations=1)
        result = loop.run("Complex task")
        assert result.total_iterations <= 1

    def test_loop_tracks_convergence(self) -> None:
        loop = ReviewLoop(max_iterations=2)
        result = loop.run("Simple task")
        assert "iteration" in result.convergence_metrics
