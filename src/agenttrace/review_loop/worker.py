"""Worker — resident agent that executes plans and accepts feedback.

The Worker gathers REAL evidence for the review loop:
- code artifacts: the actual content of files in scope (from the session's
  recorded FILE_MUTATION events), bounded in size
- verification artifacts: real output of allowlisted verification commands
  (`pytest`, `ruff`, `mypy`, `py_compile`, ...) run against the audited
  workspace

On feedback iterations, only commands that previously failed, errored, or
were rejected by the allowlist are re-run — the loop converges on real
verification outcomes instead of fabricating artifacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from agenttrace.review_loop.planner import ReviewPlan, Subtask
    from agenttrace.review_loop.verification import VerificationResult

from agenttrace.review_loop.verification import VerificationRunner
from agenttrace.security.isolation import IsolationRunner

logger = logging.getLogger(__name__)

_MAX_FILE_CHARS = 65536


@dataclass
class WorkerArtifact:
    """An artifact produced by the Worker."""

    artifact_id: UUID = field(default_factory=uuid4)
    artifact_type: str = ""  # code | verification
    file_path: str = ""
    content: str = ""
    command: str = ""
    exit_code: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    subtask_id: UUID | None = None
    iteration: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def succeeded(self) -> bool:
        """Whether this verification artifact reflects a passing run."""
        return (
            self.artifact_type == "verification"
            and self.evidence.get("allowed", True)
            and self.exit_code == 0
        )


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
    """Resident agent that gathers real evidence for the review plan.

    The Worker:
    1. Reads the plan's subtasks and scope (real changed files)
    2. Produces code artifacts from actual file content
    3. Runs allowlisted verification commands against the workspace
    4. Accepts feedback from reviewers
    5. Iterates until convergence (re-running only failed verification)
    """

    def __init__(self, workspace_path: str = "", max_file_chars: int = _MAX_FILE_CHARS) -> None:
        self.workspace_path = workspace_path
        self.max_file_chars = max_file_chars
        self._iteration = 0
        self._feedback_history: list[dict[str, Any]] = []
        self._artifacts: list[WorkerArtifact] = []
        self._scope_files: list[str] = []
        self._diff_summaries: dict[str, str] = {}
        self._verification: dict[str, VerificationResult] = {}
        self._runner: VerificationRunner | None = None

    @property
    def iteration(self) -> int:
        return self._iteration

    @property
    def feedback_history(self) -> list[dict[str, Any]]:
        return list(self._feedback_history)

    def set_review_context(
        self,
        scope_files: list[str] | None = None,
        diff_summaries: dict[str, str] | None = None,
    ) -> None:
        """Set the real scope of the review (files changed by the audited agent)."""
        self._scope_files = list(scope_files or [])
        self._diff_summaries = dict(diff_summaries or {})

    def _runner_for(self) -> VerificationRunner:
        if self._runner is None:
            self._runner = VerificationRunner(self.workspace_path, isolation=IsolationRunner())
        return self._runner

    def execute(
        self,
        plan: ReviewPlan,
        feedback: dict[str, Any] | None = None,
    ) -> WorkerResult:
        """Execute one iteration of the plan."""
        self._iteration += 1
        result = WorkerResult(iteration=self._iteration)

        # Apply feedback if provided
        if feedback:
            self._feedback_history.append(feedback)
            result.feedback_applied = self._apply_feedback(feedback)

        # Which verification commands to run this iteration: on the first
        # iteration all plan commands; afterwards only the ones that failed
        # or were rejected previously, plus commands from newly added subtasks.
        run_set = self._commands_to_run(plan)

        # Execute subtasks in priority order
        sorted_subtasks = sorted(plan.subtasks, key=lambda s: s.priority)
        for subtask in sorted_subtasks:
            artifacts, complete, note = self._execute_subtask(subtask, run_set)
            for artifact in artifacts:
                result.artifacts.append(artifact)
                self._artifacts.append(artifact)
            if complete:
                result.completed_subtasks.append(subtask.subtask_id)
            else:
                result.pending_subtasks.append(subtask.subtask_id)
            if note:
                result.notes = (result.notes + "; " + note) if result.notes else note

        logger.info(
            "Worker iteration %d: %d artifacts, %d completed, %d pending",
            self._iteration,
            len(result.artifacts),
            len(result.completed_subtasks),
            len(result.pending_subtasks),
        )

        return result

    def _commands_to_run(self, plan: ReviewPlan) -> set[str]:
        """Collect verification commands for this iteration."""
        all_commands = {
            cmd
            for subtask in plan.subtasks
            for cmd in subtask.verification_commands
        }
        if self._iteration <= 1:
            return all_commands

        retry = {
            cmd for cmd, r in self._verification.items()
            if not r.succeeded
        }
        never_run = all_commands - set(self._verification)
        return retry | never_run

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

    def _execute_subtask(
        self,
        subtask: Subtask,
        run_set: set[str],
    ) -> tuple[list[WorkerArtifact], bool, str]:
        """Execute one subtask, producing real code and verification artifacts.

        Returns (artifacts, completed, note).
        """
        artifacts: list[WorkerArtifact] = []
        note = ""

        # Real file content for the subtask in scope
        if subtask.title == "Implementation":
            for file_path in self._scope_files:
                content = self._read_scope_file(file_path)
                if content is None:
                    continue
                artifacts.append(
                    WorkerArtifact(
                        artifact_type="code",
                        file_path=file_path,
                        content=content,
                        evidence={"diff_summary": self._diff_summaries.get(file_path, "")},
                        subtask_id=subtask.subtask_id,
                        iteration=self._iteration,
                    )
                )

        # Real verification evidence
        for command in subtask.verification_commands:
            if command not in run_set:
                continue
            verification = self._run_verification(command, subtask.subtask_id)
            artifacts.append(
                WorkerArtifact(
                    artifact_type="verification",
                    file_path=command,
                    content=verification.output,
                    command=command,
                    exit_code=verification.exit_code,
                    evidence={
                        "allowed": verification.allowed,
                        "rejection_reason": verification.rejection_reason,
                        "duration_ms": verification.duration_ms,
                        "error": verification.error,
                    },
                    subtask_id=subtask.subtask_id,
                    iteration=self._iteration,
                )
            )

        # Completion: all its verification commands succeeded (or none were
        # expected), and implementation subtasks also need scope files.
        verification_results = [
            self._verification[cmd] for cmd in subtask.verification_commands
        ]
        if subtask.verification_commands and not verification_results:
            return artifacts, False, f"No verification ran for: {subtask.title}"

        all_passed = all(r.succeeded for r in verification_results)
        implementation_has_files = (
            subtask.title != "Implementation" or bool(self._scope_files)
        )
        complete = all_passed and implementation_has_files

        if not all_passed and verification_results:
            failed = [
                r.command for r in verification_results
                if not r.succeeded
            ]
            note = f"Failed verification for {subtask.title}: {', '.join(failed)}"
        elif subtask.title == "Implementation" and not self._scope_files:
            note = f"No changed files in scope for: {subtask.title}"

        return artifacts, complete, note

    def _run_verification(self, command: str, subtask_id: UUID | None) -> VerificationResult:
        """Run one verification command, updating the per-iteration cache."""
        verification = self._runner_for().run(command)
        self._verification[command] = verification
        return verification

    def _read_scope_file(self, file_path: str) -> str | None:
        """Read real file content, bounded; None if unreadable or out of scope."""
        try:
            path = Path(file_path)
            if not path.is_absolute():
                path = Path(self.workspace_path) / path
            if not path.exists():
                return None
            content = path.read_text(encoding="utf-8", errors="replace")
            if len(content) > self.max_file_chars:
                content = (
                    content[: self.max_file_chars]
                    + f"\n... [truncated, {len(content)} chars total]"
                )
            return content
        except OSError:
            return None

    def get_artifacts(self) -> list[WorkerArtifact]:
        """Get all artifacts produced across all iterations."""
        return list(self._artifacts)

    def get_convergence_metrics(self) -> dict[str, Any]:
        """Calculate convergence metrics for the review loop.

        Higher convergence means fewer failures between iterations,
        indicating the work is stabilizing.
        """
        total_artifacts = len(self._artifacts)
        feedback_rounds = len(self._feedback_history)
        verification_runs = len(self._verification)
        failed_verification = sum(
            1 for r in self._verification.values() if not r.succeeded
        )

        if self._iteration <= 1:
            return {
                "iteration": self._iteration,
                "convergence_score": 0.0,
                "feedback_trend": "initial",
                "total_artifacts": total_artifacts,
                "feedback_rounds": feedback_rounds,
                "verification_runs": verification_runs,
                "failed_verification": failed_verification,
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
            "total_artifacts": total_artifacts,
            "feedback_rounds": feedback_rounds,
            "verification_runs": verification_runs,
            "failed_verification": failed_verification,
        }
