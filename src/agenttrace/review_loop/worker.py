"""Worker — resident agent that executes plans and accepts feedback.

The Worker is a persistent agent that implements the plan's subtasks,
produces artifacts, and iterates based on reviewer feedback until
all acceptance criteria are met.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from agenttrace.review_loop.planner import ReviewPlan, Subtask

logger = logging.getLogger(__name__)


@dataclass
class WorkerArtifact:
    """An artifact produced by the Worker."""

    artifact_id: UUID = field(default_factory=uuid4)
    artifact_type: str = ""  # code | test | doc | config
    file_path: str = ""
    content: str = ""
    subtask_id: UUID | None = None
    iteration: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class WorkerResult:
    """Result of a Worker execution cycle."""

    iteration: int = 0
    artifacts: list[WorkerArtifact] = field(default_factory=list)
    completed_subtasks: list[UUID] = field(default_factory=list)
    pending_subtasks: list[UUID] = field(default_factory=list)
    feedback_applied: list[str] = field(default_factory=list)
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Worker:
    """Resident agent that implements the review plan.

    The Worker:
    1. Receives a plan with subtasks and acceptance criteria
    2. Executes subtasks in priority order
    3. Produces artifacts (code, tests, docs)
    4. Accepts feedback from reviewers
    5. Iterates until convergence

    The Worker tracks its iteration count and the feedback it has
    incorporated, enabling convergence detection.
    """

    def __init__(self, workspace_path: str = "") -> None:
        self.workspace_path = workspace_path
        self._iteration = 0
        self._feedback_history: list[dict[str, Any]] = []
        self._artifacts: list[WorkerArtifact] = []

    @property
    def iteration(self) -> int:
        return self._iteration

    @property
    def feedback_history(self) -> list[dict[str, Any]]:
        return list(self._feedback_history)

    def execute(
        self,
        plan: ReviewPlan,
        feedback: dict[str, Any] | None = None,
    ) -> WorkerResult:
        """Execute one iteration of the plan.

        If feedback is provided (from a previous review cycle),
        incorporate it before working on subtasks.
        """
        self._iteration += 1
        result = WorkerResult(iteration=self._iteration)

        # Apply feedback if provided
        if feedback:
            self._feedback_history.append(feedback)
            applied = self._apply_feedback(feedback)
            result.feedback_applied = applied

        # Execute subtasks in priority order
        sorted_subtasks = sorted(plan.subtasks, key=lambda s: s.priority)
        for subtask in sorted_subtasks:
            artifact = self._execute_subtask(subtask)
            if artifact:
                result.artifacts.append(artifact)
                self._artifacts.append(artifact)
                result.completed_subtasks.append(subtask.subtask_id)
            else:
                result.pending_subtasks.append(subtask.subtask_id)

        logger.info(
            "Worker iteration %d: %d artifacts, %d completed, %d pending",
            self._iteration,
            len(result.artifacts),
            len(result.completed_subtasks),
            len(result.pending_subtasks),
        )

        return result

    def _apply_feedback(self, feedback: dict[str, Any]) -> list[str]:
        """Incorporate reviewer feedback into the work."""
        applied: list[str] = []

        failed_criteria = feedback.get("failed_criteria", [])
        for criterion in failed_criteria:
            applied.append(f"Addressing: {criterion}")

        suggestions = feedback.get("suggestions", [])
        for suggestion in suggestions:
            applied.append(f"Applying suggestion: {suggestion}")

        logger.info("Applied %d feedback items", len(applied))
        return applied

    def _execute_subtask(self, subtask: Subtask) -> WorkerArtifact | None:
        """Execute a single subtask and produce an artifact.

        In a real AI-powered system, this would invoke an LLM to
        generate code. In the framework, it records the subtask
        execution and produces a structured artifact.
        """
        artifact = WorkerArtifact(
            artifact_type="code",
            subtask_id=subtask.subtask_id,
            iteration=self._iteration,
        )

        # The actual work would be done here by an AI agent or developer
        artifact.content = f"# Implementation for: {subtask.title}\n# {subtask.description}"

        return artifact

    def get_artifacts(self) -> list[WorkerArtifact]:
        """Get all artifacts produced across all iterations."""
        return list(self._artifacts)

    def get_convergence_metrics(self) -> dict[str, Any]:
        """Calculate convergence metrics for the review loop.

        Higher convergence means fewer changes between iterations,
        indicating the work is stabilizing.
        """
        if self._iteration <= 1:
            return {
                "iteration": self._iteration,
                "convergence_score": 0.0,
                "feedback_trend": "initial",
            }

        # Calculate feedback trend
        if len(self._feedback_history) >= 2:
            recent_failures = len(
                self._feedback_history[-1].get("failed_criteria", [])
            )
            previous_failures = len(
                self._feedback_history[-2].get("failed_criteria", [])
            )

            if recent_failures < previous_failures:
                trend = "improving"
                score = 1.0 - (recent_failures / max(previous_failures, 1))
            elif recent_failures == 0:
                trend = "converged"
                score = 1.0
            else:
                trend = "stalled"
                score = 0.0
        else:
            trend = "insufficient_data"
            score = 0.5

        return {
            "iteration": self._iteration,
            "convergence_score": round(score, 2),
            "feedback_trend": trend,
            "total_artifacts": len(self._artifacts),
            "feedback_rounds": len(self._feedback_history),
        }
