"""Planner — decomposes tasks into structured plans.

The Planner is an ephemeral worker that takes a raw task description
and produces a structured ReviewPlan with subtasks, acceptance criteria,
verification steps, and scope boundaries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


@dataclass
class Subtask:
    """A single unit of work within a plan."""

    subtask_id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    acceptance_criteria: list[str] = field(default_factory=list)
    verification_commands: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    estimated_files: int = 0
    priority: int = 0


@dataclass
class ReviewPlan:
    """Structured plan produced by the Planner."""

    plan_id: UUID = field(default_factory=uuid4)
    task_description: str = ""
    subtasks: list[Subtask] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    risk_assessment: str = ""
    estimated_iteration_count: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Planner:
    """Decomposes tasks into structured review plans.

    The Planner analyzes the task description and workspace context
    to produce a plan with clear acceptance criteria, scope boundaries,
    and verification steps. This guides the Worker and Reviewers.
    """

    def __init__(self, workspace_path: str = "") -> None:
        self.workspace_path = workspace_path

    def create_plan(
        self,
        task_description: str,
        context: dict[str, object] | None = None,
    ) -> ReviewPlan:
        """Create a structured plan from a task description.

        Analyzes the task to determine:
        - What subtasks are needed
        - What acceptance criteria apply
        - What's in scope vs. out of scope
        - What verification steps to run

        `context` may carry real scope files (e.g. the files an audited agent
        actually mutated) so the plan's scope reflects the real change set.
        """
        plan = ReviewPlan(task_description=task_description)

        scope_files: list[str] = []
        if context:
            raw = context.get("scope_files", [])
            if isinstance(raw, list):
                scope_files = [str(f) for f in raw]

        # Decompose into subtasks
        plan.subtasks = self._decompose_task(task_description, scope_files)

        # Set acceptance criteria
        plan.acceptance_criteria = self._derive_criteria(task_description, plan.subtasks)

        # Define scope
        plan.scope = self._define_scope(task_description, scope_files)
        plan.out_of_scope = self._define_exclusions(task_description)

        # Assess risk
        plan.risk_assessment = self._assess_risk(task_description, plan.subtasks)

        # Estimate iterations
        plan.estimated_iteration_count = max(1, len(plan.subtasks) // 3)

        logger.info(
            "Plan created: %d subtasks, %d criteria",
            len(plan.subtasks),
            len(plan.acceptance_criteria),
        )

        return plan

    def _decompose_task(
        self, description: str, scope_files: list[str] | None = None
    ) -> list[Subtask]:
        """Decompose a task into ordered subtasks."""
        scope_files = scope_files or []
        # Subtasks
        subtasks: list[Subtask] = []

        # Every task needs implementation
        # py_compile requires file arguments; verify the real change set.
        compile_command = (
            ["python -m py_compile " + " ".join(scope_files)] if scope_files else []
        )
        subtasks.append(Subtask(
            title="Implementation",
            description=f"Implement: {description}",
            acceptance_criteria=["Code compiles/parses without errors"],
            verification_commands=compile_command,
            priority=1,
        ))

        # Every non-trivial task needs tests
        subtasks.append(Subtask(
            title="Testing",
            description="Write and run tests for the implementation",
            acceptance_criteria=["All tests pass", "Edge cases covered"],
            verification_commands=["pytest -v"],
            priority=2,
        ))

        # Quality check
        subtasks.append(Subtask(
            title="Quality Review",
            description="Lint, type-check, and review code quality",
            acceptance_criteria=["No lint errors", "Types check"],
            verification_commands=["ruff check .", "mypy --strict ."],
            priority=3,
        ))

        return subtasks

    def _derive_criteria(
        self, description: str, subtasks: list[Subtask]
    ) -> list[str]:
        """Derive overall acceptance criteria from task and subtasks."""
        criteria = [
            "All code changes satisfy the stated requirements",
            "No regressions introduced",
            "Code follows project conventions",
            "Secrets are properly handled",
        ]

        # Aggregate subtask criteria
        for subtask in subtasks:
            criteria.extend(subtask.acceptance_criteria)

        return list(dict.fromkeys(criteria))  # Deduplicate, preserve order

    def _define_scope(self, description: str, scope_files: list[str] | None = None) -> list[str]:
        """Define what's in scope for this task."""
        scope = [
            f"Changes directly related to: {description}",
            "Supporting test files",
            "Documentation updates for changed code",
        ]
        if scope_files:
            scope.extend(f"Changed file: {file_path}" for file_path in scope_files[:50])
        return scope

    def _define_exclusions(self, description: str) -> list[str]:
        """Define what's out of scope."""
        return [
            "Unrelated refactoring",
            "Style changes to unmodified code",
            "Dependency upgrades not required by the task",
        ]

    def _assess_risk(self, description: str, subtasks: list[Subtask]) -> str:
        """Simple risk assessment."""
        total_files = sum(s.estimated_files for s in subtasks)
        if total_files > 20:
            return "HIGH — large scope, consider decomposing further"
        if total_files > 10:
            return "MEDIUM — moderate scope, review carefully"
        return "LOW — focused scope"

    def amend_plan(
        self,
        plan: ReviewPlan,
        feedback: str,
        failed_criteria: list[str] | None = None,
    ) -> ReviewPlan:
        """Amend a plan based on review feedback.

        Adds corrective subtasks for failed criteria and incorporates
        reviewer feedback.
        """
        if failed_criteria:
            correction = Subtask(
                title="Corrections",
                description=f"Fix: {', '.join(failed_criteria)}",
                acceptance_criteria=failed_criteria,
                priority=0,  # Highest priority
            )
            plan.subtasks.insert(0, correction)

        # Log the amendment
        logger.info(
            "Plan amended: %d subtasks (added corrections for %d failures)",
            len(plan.subtasks),
            len(failed_criteria or []),
        )

        return plan
