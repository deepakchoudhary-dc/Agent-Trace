"""Synthesiser — aggregates reviewer results to determine Pass/Fail.

The Synthesiser is an ephemeral worker that combines all reviewer
outputs, applies weighted criteria, and either packages the deliverable
(on pass) or generates structured feedback for the Worker (on fail).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from agenttrace.review_loop.reviewer import ReviewResult, ReviewVerdict

logger = logging.getLogger(__name__)


@dataclass
class SynthesisResult:
    """Aggregated result from the synthesis step."""

    synthesis_id: UUID = field(default_factory=uuid4)
    passed: bool = False
    overall_confidence: float = 0.0
    review_results: list[ReviewResult] = field(default_factory=list)
    passed_criteria: list[str] = field(default_factory=list)
    failed_criteria: list[str] = field(default_factory=list)
    partial_criteria: list[str] = field(default_factory=list)
    slop_findings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    feedback_for_worker: dict[str, Any] = field(default_factory=dict)
    deliverable_summary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Default weights for reviewer types
_REVIEWER_WEIGHTS: dict[str, float] = {
    "spec_compliance": 1.0,  # Must pass
    "security": 1.0,  # Must pass
    "convention": 0.5,  # Advisory
}


class Synthesizer:
    """Aggregates multiple reviewer outputs into a single verdict.

    The Synthesizer:
    1. Collects all ReviewResults
    2. Applies weighted criteria (security/spec are mandatory)
    3. Determines overall Pass/Fail
    4. On fail: generates structured feedback for Worker
    5. On pass: packages the deliverable summary
    """

    def __init__(
        self,
        reviewer_weights: dict[str, float] | None = None,
    ) -> None:
        self._weights = reviewer_weights or _REVIEWER_WEIGHTS

    def synthesize(
        self,
        review_results: list[ReviewResult],
    ) -> SynthesisResult:
        """Synthesize all reviewer outputs into a final verdict."""
        result = SynthesisResult(review_results=review_results)

        # Aggregate criteria across all reviewers
        for review in review_results:
            weight = self._weights.get(review.reviewer_name, 0.5)

            for cr in review.results:
                if cr.verdict == ReviewVerdict.PASSED:
                    result.passed_criteria.append(cr.criterion)
                elif cr.verdict == ReviewVerdict.FAILED:
                    result.failed_criteria.append(cr.criterion)
                elif cr.verdict == ReviewVerdict.PARTIAL:
                    result.partial_criteria.append(cr.criterion)

            result.slop_findings.extend(review.slop_findings)
            result.suggestions.extend(review.suggestions)

        # Determine pass/fail
        # Mandatory reviewers must pass
        mandatory_pass = True
        for review in review_results:
            weight = self._weights.get(review.reviewer_name, 0.5)
            if weight >= 1.0 and review.overall_verdict == ReviewVerdict.FAILED:
                mandatory_pass = False
                break

        # No critical slop findings
        has_critical_slop = any(
            "security" in s.lower() or "injection" in s.lower()
            for s in result.slop_findings
        )

        result.passed = mandatory_pass and not has_critical_slop

        # Calculate confidence
        if review_results:
            weighted_sum = sum(
                r.confidence * self._weights.get(r.reviewer_name, 0.5)
                for r in review_results
            )
            total_weight = sum(
                self._weights.get(r.reviewer_name, 0.5)
                for r in review_results
            )
            result.overall_confidence = round(
                weighted_sum / total_weight if total_weight > 0 else 0.0,
                3,
            )

        # Generate feedback or deliverable
        if result.passed:
            result.deliverable_summary = self._package_deliverable(review_results)
            logger.info("Synthesis PASSED (confidence=%.2f)", result.overall_confidence)
        else:
            result.feedback_for_worker = self._generate_feedback(result)
            logger.info(
                "Synthesis FAILED: %d criteria failed, %d slop findings",
                len(result.failed_criteria),
                len(result.slop_findings),
            )

        return result

    def _generate_feedback(self, result: SynthesisResult) -> dict[str, Any]:
        """Generate structured feedback for the Worker to iterate on."""
        return {
            "failed_criteria": result.failed_criteria,
            "partial_criteria": result.partial_criteria,
            "slop_findings": result.slop_findings,
            "suggestions": result.suggestions,
            "priority_actions": self._prioritize_actions(result),
        }

    @staticmethod
    def _prioritize_actions(result: SynthesisResult) -> list[str]:
        """Prioritize actions for the Worker's next iteration."""
        actions: list[str] = []

        # Security failures are highest priority
        for criterion in result.failed_criteria:
            if "security" in criterion.lower():
                actions.insert(0, f"FIX (critical): {criterion}")
            else:
                actions.append(f"FIX: {criterion}")

        # Slop findings next
        for finding in result.slop_findings:
            actions.append(f"RESOLVE: {finding}")

        # Partial criteria last
        for criterion in result.partial_criteria:
            actions.append(f"IMPROVE: {criterion}")

        return actions

    @staticmethod
    def _package_deliverable(review_results: list[ReviewResult]) -> str:
        """Create a deliverable summary from passing review results."""
        total_criteria = sum(len(r.results) for r in review_results)
        passed = sum(r.passed_count for r in review_results)
        reviewers = ", ".join(r.reviewer_name for r in review_results)

        return (
            f"All acceptance criteria satisfied ({passed}/{total_criteria}). "
            f"Reviewed by: {reviewers}. "
            f"No critical findings."
        )
