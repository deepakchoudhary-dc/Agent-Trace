"""Plan Reviewer — validates plans against actual outcomes.

The Plan Reviewer receives synthesis results and compares them
against the original plan to propose amendments for the next iteration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from agenttrace.review_loop.planner import ReviewPlan
    from agenttrace.review_loop.synthesizer import SynthesisResult

logger = logging.getLogger(__name__)


@dataclass
class PlanReviewResult:
    """Result of reviewing the plan against outcomes."""

    review_id: UUID = field(default_factory=uuid4)
    plan_adequate: bool = True
    scope_issues: list[str] = field(default_factory=list)
    missing_criteria: list[str] = field(default_factory=list)
    unnecessary_criteria: list[str] = field(default_factory=list)
    proposed_amendments: list[str] = field(default_factory=list)
    lessons_learned: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PlanReviewer:
    """Validates the plan against synthesis outcomes.

    After the synthesis step, the Plan Reviewer checks whether:
    - The plan's scope was appropriate
    - The acceptance criteria were sufficient
    - The subtask decomposition was effective
    - Any lessons should be logged to gotchas.md
    """

    def review_plan(
        self,
        plan: ReviewPlan,
        synthesis: SynthesisResult,
        iteration: int,
    ) -> PlanReviewResult:
        """Review the plan's effectiveness based on synthesis results."""
        result = PlanReviewResult()

        # Check scope
        result.scope_issues = self._check_scope(plan, synthesis)

        # Check criteria completeness
        result.missing_criteria = self._find_missing_criteria(plan, synthesis)
        result.unnecessary_criteria = self._find_unnecessary_criteria(plan, synthesis)

        # Propose amendments
        result.proposed_amendments = self._propose_amendments(
            plan, synthesis, result, iteration
        )

        # Extract lessons
        result.lessons_learned = self._extract_lessons(plan, synthesis, iteration)

        # Overall assessment
        result.plan_adequate = (
            not result.scope_issues
            and not result.missing_criteria
            and synthesis.passed
        )

        logger.info(
            "Plan review (iteration %d): adequate=%s, %d amendments proposed",
            iteration,
            result.plan_adequate,
            len(result.proposed_amendments),
        )

        return result

    def _check_scope(
        self, plan: ReviewPlan, synthesis: SynthesisResult
    ) -> list[str]:
        """Check if the plan's scope was appropriate."""
        issues: list[str] = []

        # If there were many failures, scope might be too broad
        if len(synthesis.failed_criteria) > len(plan.acceptance_criteria) / 2:
            issues.append("Plan scope may be too broad — many criteria failed")

        # If slop was found, scope might be too loose
        if synthesis.slop_findings:
            issues.append(
                f"Slop detected ({len(synthesis.slop_findings)} findings) — "
                "tighten scope or add explicit constraints"
            )

        return issues

    def _find_missing_criteria(
        self, plan: ReviewPlan, synthesis: SynthesisResult
    ) -> list[str]:
        """Find criteria that should have been in the plan."""
        missing: list[str] = []

        # Security issues that weren't in the plan
        for finding in synthesis.slop_findings:
            flagged = "security" in finding.lower() or "injection" in finding.lower()
            if flagged and not any(
                "security" in c.lower() for c in plan.acceptance_criteria
            ):
                missing.append("Security checks should be explicit criteria")

        # Convention issues that weren't covered
        for finding in synthesis.slop_findings:
            flagged = "convention" in finding.lower() or "naming" in finding.lower()
            if flagged and not any(
                "convention" in c.lower() for c in plan.acceptance_criteria
            ):
                missing.append("Convention compliance should be an explicit criterion")

        return missing

    def _find_unnecessary_criteria(
        self, plan: ReviewPlan, synthesis: SynthesisResult
    ) -> list[str]:
        """Find criteria that were always passing and might be unnecessary."""
        # Criteria that passed on first iteration are candidates
        always_passed = [
            c for c in synthesis.passed_criteria
            if c not in synthesis.failed_criteria and c not in synthesis.partial_criteria
        ]

        unnecessary: list[str] = []
        for criterion in always_passed:
            if "trivial" in criterion.lower() or "basic" in criterion.lower():
                unnecessary.append(f"Consider removing trivial criterion: {criterion}")

        return unnecessary

    def _propose_amendments(
        self,
        plan: ReviewPlan,
        synthesis: SynthesisResult,
        review: PlanReviewResult,
        iteration: int,
    ) -> list[str]:
        """Propose plan amendments for the next iteration."""
        amendments: list[str] = []

        for issue in review.scope_issues:
            amendments.append(f"Scope adjustment: {issue}")

        for missing in review.missing_criteria:
            amendments.append(f"Add criterion: {missing}")

        # If we're on iteration 3+, suggest fundamental rethinking
        if iteration >= 3 and not synthesis.passed:
            amendments.append(
                "CRITICAL: 3+ iterations without convergence. "
                "Consider fundamentally different approach."
            )

        return amendments

    def _extract_lessons(
        self,
        plan: ReviewPlan,
        synthesis: SynthesisResult,
        iteration: int,
    ) -> list[str]:
        """Extract lessons to log in gotchas.md."""
        lessons: list[str] = []

        if synthesis.slop_findings:
            for finding in synthesis.slop_findings:
                lessons.append(f"Anti-slop: {finding}")

        if not synthesis.passed and iteration > 1:
            lessons.append(
                f"Iteration {iteration} still failing — "
                f"root causes: {', '.join(synthesis.failed_criteria[:3])}"
            )

        return lessons
