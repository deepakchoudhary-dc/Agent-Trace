"""Reviewers — multi-perspective code review agents.

Multiple reviewers evaluate the Worker's evidence from different angles:
- Reviewer 1 (resident): Spec compliance, correctness, anti-slop
- Reviewer 2 (ephemeral): Security review
- Reviewer N (ephemeral): Convention compliance

Each produces a structured ReviewResult with PASSED/FAILED/PARTIAL verdicts.
Verdicts are derived from REAL evidence: verification command outcomes
(exit codes) and actual artifact content — never from assumed completion.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from math import log2
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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

    Checks each acceptance criterion against REAL verification outcomes and
    artifact content, and runs the anti-slop checklist from review.md.
    """

    def __init__(self) -> None:
        super().__init__("spec_compliance", "resident")

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Check each acceptance criterion against the evidence."""
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

        # Calculate overall verdict — PARTIAL criteria mean incomplete work
        if result.failed_count == 0 and result.partial_count == 0 and not slop:
            result.overall_verdict = ReviewVerdict.PASSED
            result.confidence = 0.9
        elif result.failed_count == 0 and result.partial_count == 0:
            result.overall_verdict = ReviewVerdict.PARTIAL
            result.confidence = 0.6
        elif result.failed_count == 0:
            result.overall_verdict = ReviewVerdict.PARTIAL
            result.confidence = 0.5
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

    # Criterion keyword → (verification command hints, label)
    _VERIFICATION_HINTS: dict[str, tuple[tuple[str, ...], str]] = {
        "test": (("pytest", "unittest"), "test"),
        "edge case": (("pytest", "unittest"), "test"),
        "lint": (("ruff",), "lint"),
        "type": (("mypy",), "type"),
        "compil": (("py_compile",), "compile"),
        "pars": (("py_compile",), "compile"),
    }

    def _check_criterion(
        self, criterion: str, worker_result: WorkerResult
    ) -> CriterionResult:
        """Check a single acceptance criterion against real evidence."""
        cr = CriterionResult(criterion=criterion)
        low = criterion.lower()
        verifications = [
            a for a in worker_result.artifacts if a.artifact_type == "verification"
        ]
        code_artifacts = [
            a for a in worker_result.artifacts if a.artifact_type == "code"
        ]

        for keyword, (hints, label) in self._VERIFICATION_HINTS.items():
            if keyword in low:
                matches = [
                    v for v in verifications if any(h in v.command for h in hints)
                ]
                return self._verify_based(cr, matches, label)

        # "Secrets are properly handled" — light scan on real content
        if "secret" in low:
            issues: list[str] = []
            for artifact in code_artifacts:
                issues.extend(SecurityReviewer._find_security_issues(artifact))
            if issues:
                cr.verdict = ReviewVerdict.FAILED
                cr.notes = "; ".join(issues[:3])
                cr.file_refs = list(dict.fromkeys(a.file_path for a in code_artifacts))
            elif code_artifacts or verifications:
                cr.verdict = ReviewVerdict.PASSED
                cr.notes = "No secrets found in reviewed content"
            else:
                cr.verdict = ReviewVerdict.FAILED
                cr.notes = "Nothing to review"
            return cr

        # Generic criteria: require real evidence of work
        if code_artifacts or any(v.succeeded for v in verifications):
            cr.verdict = ReviewVerdict.PASSED
            cr.notes = "Real artifacts reviewed against this criterion"
            cr.file_refs = list(dict.fromkeys(
                [a.file_path for a in code_artifacts]
                + [v.command for v in verifications if v.succeeded]
            ))
        elif verifications:
            cr.verdict = ReviewVerdict.PARTIAL
            cr.notes = "Verification ran but did not pass"
        else:
            cr.verdict = ReviewVerdict.FAILED
            cr.notes = "No artifacts or verification evidence found"

        return cr

    @staticmethod
    def _verify_based(
        cr: CriterionResult,
        matches: list[WorkerArtifact],
        label: str,
    ) -> CriterionResult:
        """Verdict from real verification outcomes for a label."""
        cr.file_refs = [m.command for m in matches]
        if not matches:
            cr.verdict = ReviewVerdict.FAILED
            cr.notes = f"No {label} verification ran"
        elif all(m.exit_code == 0 for m in matches):
            cr.verdict = ReviewVerdict.PASSED
            cr.notes = f"{label} verification passed (exit 0)"
        elif all(not m.evidence.get("allowed", True) for m in matches):
            cr.verdict = ReviewVerdict.FAILED
            cr.notes = (
                f"{label} verification rejected by allowlist: "
                + "; ".join(
                    m.evidence.get("rejection_reason", "") for m in matches
                )
            )
        else:
            codes = [m.exit_code for m in matches]
            cr.verdict = ReviewVerdict.PARTIAL
            cr.notes = f"{label} verification failed (exit codes {codes})"
        return cr

    def _anti_slop_check(self, worker_result: WorkerResult) -> list[str]:
        """Run the anti-slop checks from review.md against real content."""
        findings: list[str] = []

        for artifact in worker_result.artifacts:
            if artifact.artifact_type != "code":
                continue
            content = artifact.content

            # Check 0: placeholder / fabricated content
            if (
                not content.strip()
                or "# Implementation for:" in content
                or "# The actual work would be done here" in content
            ):
                findings.append(
                    f"Placeholder or fabricated artifact: {artifact.file_path}"
                )

            # Check 2: Over-engineering (long files with simple tasks)
            if len(content.split("\n")) > 200:
                findings.append(
                    f"Over-engineering risk: {artifact.file_path} has "
                    f"{len(content.split(chr(10)))} lines"
                )

            # Check 3: Convention blindness (basic checks)
            if re.search(r"[a-z][A-Z]", content) and re.search(r"_[a-z]", content):
                findings.append(
                    f"Mixed naming conventions (camelCase + snake_case) in "
                    f"{artifact.file_path}"
                )

            # Check 5: Defensive overreach
            if "except:\n" in content:
                findings.append(
                    f"Bare except clause in {artifact.file_path} — swallows "
                    f"errors silently"
                )

            # Check 6: Cargo-cult patterns
            if "retry" in content.lower() and "circuit" in content.lower():
                findings.append(
                    f"Possible cargo-cult pattern (retry + circuit breaker) "
                    f"in {artifact.file_path}"
                )

        return findings


class SecurityReviewer(BaseReviewer):
    """Reviewer 2 (ephemeral): Security-focused review.

    Checks real artifact content (code files and verification output) for
    secrets, permissions, injection risks, and credential handling.
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
            issues = self._find_security_issues(artifact)
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

    @staticmethod
    def _find_security_issues(artifact: WorkerArtifact) -> list[str]:
        """Check one artifact's content for security issues."""
        issues: list[str] = []
        content = artifact.content
        file_label = artifact.file_path or artifact.command

        # Check for hardcoded secrets
        secret_patterns = [
            (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
            (r"passwd\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
            (r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
            (r"client[_-]?secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded client secret"),
            (r"token\s*=\s*['\"][A-Za-z0-9._~+/=-]{16,}['\"]", "Hardcoded token"),
            (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret"),
            (r"Bearer\s+[A-Za-z0-9]", "Hardcoded bearer token"),
            (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS access key"),
            (r"ghp_[A-Za-z0-9]{20,}", "Hardcoded GitHub token"),
            (r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----", "Embedded private key"),
        ]
        for pattern, description in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append(f"{description} in {file_label}")

        # High-entropy credential assignments (hex/base64-ish values)
        for line in content.split("\n"):
            m = re.search(
                r"(?:=\s*['\"])([A-Za-z0-9+/_=-]{20,})(?:['\"])",
                line,
            )
            if m and SecurityReviewer._is_high_entropy(m.group(1)):
                issues.append(f"High-entropy credential assigned in {file_label}")

        # Check for SQL injection risk
        if "f'" in content and "SELECT" in content.upper():
            issues.append(f"Potential SQL injection via f-string in {file_label}")
        if "format(" in content and "SELECT" in content.upper():
            issues.append(f"Potential SQL injection via format() in {file_label}")

        # Check for command injection
        if "shell=True" in content and ("subprocess" in content or "os.system" in content):
            issues.append(f"Command injection risk: shell=True in {file_label}")

        # Check for path traversal
        if ".." in content and ("open(" in content or "read(" in content):
            issues.append(f"Potential path traversal vulnerability in {file_label}")

        return issues

    @staticmethod
    def _is_high_entropy(token: str) -> bool:
        """Heuristic entropy check for credential-shaped tokens."""
        if len(set(token)) < 6:
            return False

        counts = Counter(token)
        length = len(token)
        entropy = -sum(
            (count / length) * log2(count / length) for count in counts.values()
        )
        return entropy > 3.5


class ConventionReviewer(BaseReviewer):
    """Reviewer N (ephemeral): Convention compliance.

    Checks real code artifact content for line length, markers, import
    organization, and duplication.
    """

    def __init__(self) -> None:
        super().__init__("convention", "ephemeral")

    def review(
        self,
        plan: ReviewPlan,
        worker_result: WorkerResult,
    ) -> ReviewResult:
        """Convention-focused review of all code artifacts."""
        result = ReviewResult(
            reviewer_name=self.name,
            reviewer_type=self.reviewer_type,
        )

        for artifact in worker_result.artifacts:
            if artifact.artifact_type != "code":
                continue
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
                issues.append(f"Line {i + 1}: Contains FIXME/HACK marker")

        # Check for duplicated blocks (>5 identical consecutive lines)
        seen: set[str] = set()
        for i in range(len(lines) - 5):
            block = "\n".join(lines[i:i + 5])
            if block in seen:
                issues.append(f"Likely duplicated block near line {i + 1}")
                break
            seen.add(block)

        return issues

    def _suggest_improvements(self, artifact: WorkerArtifact) -> list[str]:
        """Suggest non-blocking improvements."""
        suggestions: list[str] = []
        content = artifact.content

        # Suggest docstrings for functions without them
        if "def " in content and '"""' not in content:
            suggestions.append(
                f"Consider adding docstrings to functions in {artifact.file_path}"
            )

        # Suggest type hints
        if "def " in content and " -> " not in content:
            suggestions.append(
                f"Consider adding return type hints in {artifact.file_path}"
            )

        return suggestions
