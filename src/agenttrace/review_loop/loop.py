"""Review Loop orchestrator — manages the full self-improving cycle.

Coordinates the complete flow: Task → Planner → Worker → Reviewers →
Synthesise → Pass/Fail → feedback loop. Tracks iterations, convergence,
and logs lessons to gotchas.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agenttrace.review_loop.planner import Planner
from agenttrace.review_loop.plan_reviewer import PlanReviewer, PlanReviewResult
from agenttrace.review_loop.reviewer import (
    BaseReviewer,
    ConventionReviewer,
    ReviewResult,
    SecurityReviewer,
    SpecComplianceReviewer,
)
from agenttrace.review_loop.synthesizer import Synthesizer, SynthesisResult
from agenttrace.review_loop.worker import Worker, WorkerResult

logger = logging.getLogger(__name__)

_MAX_ITERATIONS = 3


@dataclass
class LoopIteration:
    """Record of a single iteration through the review loop."""

    iteration: int = 0
    worker_result: WorkerResult | None = None
    review_results: list[ReviewResult] = field(default_factory=list)
    synthesis: SynthesisResult | None = None
    plan_review: PlanReviewResult | None = None
    passed: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class LoopResult:
    """Final result of the entire review loop."""

    loop_id: UUID = field(default_factory=uuid4)
    task_description: str = ""
    iterations: list[LoopIteration] = field(default_factory=list)
    final_passed: bool = False
    total_iterations: int = 0
    convergence_metrics: dict[str, Any] = field(default_factory=dict)
    lessons_learned: list[str] = field(default_factory=list)
    deliverable_summary: str = ""
    escalation_reason: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


class ReviewLoop:
    """Orchestrates the self-improving review loop.

    The loop runs until either:
    - All acceptance criteria pass (success)
    - Maximum iterations reached (escalation)
    - Convergence stalls (rethink)

    Each iteration's results are logged, and lessons are written
    to gotchas.md for future sessions.
    """

    def __init__(
        self,
        workspace_path: str = "",
        max_iterations: int = _MAX_ITERATIONS,
        gotchas_path: str | None = None,
    ) -> None:
        self.workspace_path = workspace_path
        self.max_iterations = max_iterations
        self._gotchas_path = gotchas_path or str(
            Path(workspace_path) / "gotchas.md"
        )

        # Components
        self._planner = Planner(workspace_path)
        self._worker = Worker(workspace_path)
        self._reviewers: list[BaseReviewer] = [
            SpecComplianceReviewer(),
            SecurityReviewer(),
            ConventionReviewer(),
        ]
        self._synthesizer = Synthesizer()
        self._plan_reviewer = PlanReviewer()

    def run(self, task_description: str) -> LoopResult:
        """Execute the full review loop for a task.

        Flow per the architecture diagram:
        Task → Planner → [Worker → Reviewers → Synthesise → Pass?] loop
        """
        result = LoopResult(task_description=task_description)

        # Step 1: Plan
        plan = self._planner.create_plan(task_description)
        logger.info("Plan created: %d subtasks", len(plan.subtasks))

        feedback: dict[str, Any] | None = None

        # Step 2: Loop
        for iteration_num in range(1, self.max_iterations + 1):
            logger.info("=== Iteration %d/%d ===", iteration_num, self.max_iterations)
            iter_record = LoopIteration(iteration=iteration_num)

            # Worker executes (with feedback from previous iteration)
            worker_result = self._worker.execute(plan, feedback)
            iter_record.worker_result = worker_result

            # All reviewers evaluate independently
            review_results: list[ReviewResult] = []
            for reviewer in self._reviewers:
                review = reviewer.review(plan, worker_result)
                review_results.append(review)
            iter_record.review_results = review_results

            # Synthesize
            synthesis = self._synthesizer.synthesize(review_results)
            iter_record.synthesis = synthesis
            iter_record.passed = synthesis.passed

            # Plan review
            plan_review = self._plan_reviewer.review_plan(
                plan, synthesis, iteration_num
            )
            iter_record.plan_review = plan_review

            result.iterations.append(iter_record)

            # Check if we passed
            if synthesis.passed:
                result.final_passed = True
                result.deliverable_summary = synthesis.deliverable_summary
                logger.info("✓ Review loop PASSED on iteration %d", iteration_num)
                break

            # Prepare feedback for next iteration
            feedback = synthesis.feedback_for_worker

            # Amend plan if needed
            if plan_review.proposed_amendments:
                plan = self._planner.amend_plan(
                    plan,
                    "; ".join(plan_review.proposed_amendments),
                    synthesis.failed_criteria,
                )

            # Check convergence
            metrics = self._worker.get_convergence_metrics()
            if metrics.get("feedback_trend") == "stalled" and iteration_num >= 2:
                logger.warning("Convergence stalled at iteration %d", iteration_num)
                result.escalation_reason = (
                    f"Convergence stalled after {iteration_num} iterations. "
                    "Consider fundamentally different approach."
                )
                break

        # Finalize
        result.total_iterations = len(result.iterations)
        result.convergence_metrics = self._worker.get_convergence_metrics()
        result.completed_at = datetime.now(timezone.utc)

        # Collect all lessons
        for iteration in result.iterations:
            if iteration.plan_review:
                result.lessons_learned.extend(iteration.plan_review.lessons_learned)

        # Log lessons to gotchas.md
        if result.lessons_learned:
            self._log_lessons(result)

        if not result.final_passed:
            result.escalation_reason = result.escalation_reason or (
                f"Max iterations ({self.max_iterations}) reached without convergence"
            )
            logger.warning("Review loop FAILED: %s", result.escalation_reason)

        return result

    def _log_lessons(self, result: LoopResult) -> None:
        """Append lessons learned to gotchas.md."""
        try:
            gotchas_path = Path(self._gotchas_path)
            if not gotchas_path.exists():
                return

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            entry_lines = [
                f"\n### {now} — Review Loop: {result.task_description[:60]}",
                f"**Iterations**: {result.total_iterations}",
                f"**Passed**: {result.final_passed}",
            ]

            for lesson in result.lessons_learned:
                entry_lines.append(f"- {lesson}")

            if result.escalation_reason:
                entry_lines.append(f"**Escalation**: {result.escalation_reason}")

            entry = "\n".join(entry_lines) + "\n"

            with open(gotchas_path, "a", encoding="utf-8") as f:
                f.write(entry)

            logger.info("Logged %d lessons to %s", len(result.lessons_learned), gotchas_path)

        except OSError:
            logger.warning("Could not write to gotchas.md: %s", self._gotchas_path)

    def add_reviewer(self, reviewer: BaseReviewer) -> None:
        """Add a custom reviewer to the loop."""
        self._reviewers.append(reviewer)

    def set_max_iterations(self, max_iter: int) -> None:
        """Update the maximum iteration count."""
        self.max_iterations = max_iter
