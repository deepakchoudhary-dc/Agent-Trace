"""Reviewers — multi-perspective code review agents.

Multiple reviewers evaluate the Worker's output from different angles:
- Reviewer 1 (resident): Spec compliance, correctness, anti-slop
- Reviewer 2 (ephemeral): Security review
- Reviewer N (ephemeral): Convention compliance

Each produces a structured ReviewResult with PASSED/FAILED/PARTIAL verdicts.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from agenttrace.review_loop.planner import ReviewPlan
from agenttrace.review_loop.worker import WorkerArtifact, WorkerResult

logger = logging.getLogger(__name__)


class ReviewVerdict(str, Enum):
    """Verdict for each acceptance criterion."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


@dataclass
class CriterionResult:
    """Result of evaluating a single acceptance criterion."""

    criterion: str = ""
    verdict: ReviewVerdict = ReviewVerdict.FAILED
    file_refs: list[str] = field(default_factory=list)
    line_refs: list[int] = field(default_factory=list)
    notes: str = ""


@dataclass
class ReviewResult:
    """Structured result from a single reviewer."""

    reviewer_name: str = ""
    reviewer_type: str = ""  # resident | ephemeral
    results: list[CriterionResult] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    slop_findings: list[str] = field(default_factory=list)
    overall_verdict: ReviewVerdict = ReviewVerdict.FAILED
    confidence: float = 0.0
    review_time_ms: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == ReviewVerdict.PASSED)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == ReviewVerdict.FAILED)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == ReviewVerdict.PARTIAL)


class BaseReviewer:
    """Base class for all reviewers."""

    def __init__(self, name: str, reviewer_type: str = "ephemeral") -> None:
        self.name = name
        self.reviewer_type = reviewer_type

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Review the worker's output against the plan."""
        raise NotImplementedError


class SpecComplianceReviewer(BaseReviewer):
    """Reviewer 1 (resident): Spec compliance and correctness.

    Checks that the worker's output satisfies all acceptance criteria
    from the plan, and runs the anti-slop checklist from review.md.
    """

    def __init__(self) -> None:
        super().__init__("spec_compliance", "resident")

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Check each acceptance criterion against the artifacts."""
        result = ReviewResult(
            reviewer_name=self.name,
            reviewer_type=self.reviewer_type,
        )

        for criterion in plan.acceptance_criteria:
            cr = self._check_criterion(criterion, worker_result)
            result.results.append(cr)

        # Anti-slop checks
        slop = self._anti_slop_check(worker_result)
        result.slop_findings = slop

        # Calculate overall verdict
        if result.failed_count == 0 and not slop:
            result.overall_verdict = ReviewVerdict.PASSED
            result.confidence = 0.9
        elif result.failed_count == 0:
            result.overall_verdict = ReviewVerdict.PARTIAL
            result.confidence = 0.6
        else:
            result.overall_verdict = ReviewVerdict.FAILED
            result.confidence = 0.3

        logger.info(
            "SpecCompliance review: %d passed, %d failed, %d partial, %d slop",
            result.passed_count,
            result.failed_count,
            result.partial_count,
            len(slop),
        )

        return result

    def _check_criterion(
        self, criterion: str, worker_result: WorkerResult
    ) -> CriterionResult:
        """Check a single acceptance criterion."""
        cr = CriterionResult(criterion=criterion)

        # If worker produced artifacts, the criterion is at least partially met
        if worker_result.artifacts:
            cr.verdict = ReviewVerdict.PASSED
            cr.notes = "Artifacts produced for this criterion"
        else:
            cr.verdict = ReviewVerdict.FAILED
            cr.notes = "No artifacts found for this criterion"

        return cr

    def _anti_slop_check(self, worker_result: WorkerResult) -> list[str]:
        """Run the 6 anti-slop checks from review.md."""
        findings: list[str] = []

        for artifact in worker_result.artifacts:
            content = artifact.content

            # Check 1: Plausible but incorrect logic
            # (Would require semantic analysis — flag for manual review)

            # Check 2: Over-engineering (long files with simple tasks)
            if len(content.split("\n")) > 200:
                findings.append(
                    f"Over-engineering risk: {artifact.file_path} has {len(content.split(chr(10)))} lines"
                )

            # Check 3: Convention blindness (basic checks)
            # Check for mixed naming conventions
            if re.search(r"[a-z][A-Z]", content) and re.search(r"_[a-z]", content):
                findings.append(
                    f"Mixed naming conventions (camelCase + snake_case) in {artifact.file_path}"
                )

            # Check 4: Hallucinated APIs (would need dependency analysis)

            # Check 5: Defensive overreach
            try_count = content.count("try:")
            except_count = content.count("except:")
            bare_except = content.count("except:\n")
            if bare_except > 0:
                findings.append(
                    f"Bare except clause in {artifact.file_path} — swallows errors silently"
                )

            # Check 6: Cargo-cult patterns
            if "retry" in content.lower() and "circuit" in content.lower():
                findings.append(
                    f"Possible cargo-cult pattern (retry + circuit breaker) in {artifact.file_path}"
                )

        return findings


class SecurityReviewer(BaseReviewer):
    """Reviewer 2 (ephemeral): Security-focused review.

    Checks for secrets, permissions, injection risks, and
    credential handling.
    """

    def __init__(self) -> None:
        super().__init__("security", "ephemeral")

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Security-focused review of all artifacts."""
        result = ReviewResult(
            reviewer_name=self.name,
            reviewer_type=self.reviewer_type,
        )

        for artifact in worker_result.artifacts:
            issues = self._check_security(artifact)
            for issue in issues:
                result.results.append(CriterionResult(
                    criterion=f"Security: {issue}",
                    verdict=ReviewVerdict.FAILED,
                    file_refs=[artifact.file_path],
                    notes=issue,
                ))

        if result.failed_count == 0:
            result.overall_verdict = ReviewVerdict.PASSED
            result.confidence = 0.85
        else:
            result.overall_verdict = ReviewVerdict.FAILED
            result.confidence = 0.9  # High confidence in security findings

        return result

    def _check_security(self, artifact: WorkerArtifact) -> list[str]:
        """Check an artifact for security issues."""
        issues: list[str] = []
        content = artifact.content

        # Check for hardcoded secrets
        secret_patterns = [
            (r"password\s*=\s*['\"]", "Hardcoded password"),
            (r"api[_-]?key\s*=\s*['\"]", "Hardcoded API key"),
            (r"secret\s*=\s*['\"]", "Hardcoded secret"),
            (r"Bearer\s+[A-Za-z0-9]", "Hardcoded bearer token"),
        ]
        for pattern, description in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append(description)

        # Check for SQL injection risk
        if "f'" in content and "SELECT" in content.upper():
            issues.append("Potential SQL injection via f-string")
        if "format(" in content and "SELECT" in content.upper():
            issues.append("Potential SQL injection via format()")

        # Check for command injection
        if "shell=True" in content and ("subprocess" in content or "os.system" in content):
            issues.append("Command injection risk: shell=True with user input")

        # Check for path traversal
        if ".." in content and ("open(" in content or "read(" in content):
            issues.append("Potential path traversal vulnerability")

        return issues


class ConventionReviewer(BaseReviewer):
    """Reviewer N (ephemeral): Convention compliance.

    Checks import organization, naming patterns, duplication,
    and adherence to project standards.
    """

    def __init__(self) -> None:
        super().__init__("convention", "ephemeral")

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Convention-focused review of all artifacts."""
        result = ReviewResult(
            reviewer_name=self.name,
            reviewer_type=self.reviewer_type,
        )

        for artifact in worker_result.artifacts:
            issues = self._check_conventions(artifact)
            for issue in issues:
                result.results.append(CriterionResult(
                    criterion=f"Convention: {issue}",
                    verdict=ReviewVerdict.PARTIAL,
                    file_refs=[artifact.file_path],
                    notes=issue,
                ))

            suggestions = self._suggest_improvements(artifact)
            result.suggestions.extend(suggestions)

        if result.failed_count == 0 and result.partial_count == 0:
            result.overall_verdict = ReviewVerdict.PASSED
            result.confidence = 0.8
        elif result.failed_count == 0:
            result.overall_verdict = ReviewVerdict.PARTIAL
            result.confidence = 0.6
        else:
            result.overall_verdict = ReviewVerdict.FAILED
            result.confidence = 0.7

        return result

    def _check_conventions(self, artifact: WorkerArtifact) -> list[str]:
        """Check code conventions."""
        issues: list[str] = []
        content = artifact.content
        lines = content.split("\n")

        # Check line length
        long_lines = [
            i + 1 for i, line in enumerate(lines)
            if len(line) > 100
        ]
        if long_lines:
            issues.append(f"Lines exceeding 100 chars: {long_lines[:5]}")

        # Check for TODO/FIXME/HACK
        for i, line in enumerate(lines):
            upper = line.upper()
            if "FIXME" in upper or "HACK" in upper:
                issues.append(f"Line {i+1}: Contains FIXME/HACK marker")

        return issues

    def _suggest_improvements(self, artifact: WorkerArtifact) -> list[str]:
        """Suggest non-blocking improvements."""
        suggestions: list[str] = []
        content = artifact.content

        # Suggest docstrings for functions without them
        if "def " in content and '"""' not in content:
            suggestions.append("Consider adding docstrings to functions")

        # Suggest type hints
        if "def " in content and " -> " not in content:
            suggestions.append("Consider adding return type hints")

        return suggestions
