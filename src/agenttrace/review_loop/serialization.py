"""JSON-safe serialization for review loop results.

Converts LoopResult and all nested records (iterations, worker artifacts,
reviewer verdicts, synthesis, plan review) into plain dicts so they can be
stored encrypted in the ledger and served to the dashboard. UUIDs, datetimes,
and enums are normalized to JSON-native representations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agenttrace.review_loop.loop import LoopIteration, LoopResult
    from agenttrace.review_loop.plan_reviewer import PlanReviewResult
    from agenttrace.review_loop.reviewer import CriterionResult, ReviewResult
    from agenttrace.review_loop.synthesizer import SynthesisResult
    from agenttrace.review_loop.worker import WorkerArtifact, WorkerResult


def loop_result_to_dict(result: LoopResult) -> dict[str, Any]:
    """Serialize a LoopResult into a JSON-safe dict."""
    return {
        "loop_id": str(result.loop_id),
        "task_description": result.task_description,
        "workspace_path": result.workspace_path,
        "scope_files": list(result.scope_files),
        "iterations": [iteration_to_dict(i) for i in result.iterations],
        "final_passed": result.final_passed,
        "total_iterations": result.total_iterations,
        "convergence_metrics": result.convergence_metrics,
        "lessons_learned": list(result.lessons_learned),
        "deliverable_summary": result.deliverable_summary,
        "escalation_reason": result.escalation_reason,
        "started_at": _iso(result.started_at),
        "completed_at": _iso(result.completed_at) if result.completed_at else None,
    }


def iteration_to_dict(iteration: LoopIteration) -> dict[str, Any]:
    """Serialize a single loop iteration."""
    return {
        "iteration": iteration.iteration,
        "worker_result": (
            worker_result_to_dict(iteration.worker_result)
            if iteration.worker_result
            else None
        ),
        "review_results": [
            review_result_to_dict(r) for r in iteration.review_results
        ],
        "synthesis": (
            synthesis_to_dict(iteration.synthesis)
            if iteration.synthesis
            else None
        ),
        "plan_review": (
            plan_review_to_dict(iteration.plan_review)
            if iteration.plan_review
            else None
        ),
        "passed": iteration.passed,
        "timestamp": _iso(iteration.timestamp),
    }


def worker_result_to_dict(result: WorkerResult) -> dict[str, Any]:
    """Serialize a worker result."""
    return {
        "iteration": result.iteration,
        "artifacts": [artifact_to_dict(a) for a in result.artifacts],
        "completed_subtasks": [str(s) for s in result.completed_subtasks],
        "pending_subtasks": [str(s) for s in result.pending_subtasks],
        "feedback_applied": list(result.feedback_applied),
        "notes": result.notes,
        "created_at": _iso(result.created_at),
    }


def artifact_to_dict(artifact: WorkerArtifact) -> dict[str, Any]:
    """Serialize a worker artifact."""
    return {
        "artifact_id": str(artifact.artifact_id),
        "artifact_type": artifact.artifact_type,
        "file_path": artifact.file_path,
        "content": artifact.content,
        "command": artifact.command,
        "exit_code": artifact.exit_code,
        "evidence": artifact.evidence,
        "subtask_id": str(artifact.subtask_id) if artifact.subtask_id else None,
        "iteration": artifact.iteration,
        "created_at": _iso(artifact.created_at),
    }


def review_result_to_dict(result: ReviewResult) -> dict[str, Any]:
    """Serialize a reviewer result."""
    return {
        "reviewer_name": result.reviewer_name,
        "reviewer_type": result.reviewer_type,
        "results": [criterion_to_dict(c) for c in result.results],
        "suggestions": list(result.suggestions),
        "slop_findings": list(result.slop_findings),
        "overall_verdict": result.overall_verdict.value,
        "confidence": result.confidence,
        "review_time_ms": result.review_time_ms,
        "created_at": _iso(result.created_at),
    }


def criterion_to_dict(criterion: CriterionResult) -> dict[str, Any]:
    """Serialize a single criterion verdict."""
    return {
        "criterion": criterion.criterion,
        "verdict": criterion.verdict.value,
        "file_refs": list(criterion.file_refs),
        "line_refs": list(criterion.line_refs),
        "notes": criterion.notes,
    }


def synthesis_to_dict(synthesis: SynthesisResult) -> dict[str, Any]:
    """Serialize a synthesis result."""
    return {
        "synthesis_id": str(synthesis.synthesis_id),
        "passed": synthesis.passed,
        "overall_confidence": synthesis.overall_confidence,
        "passed_criteria": list(synthesis.passed_criteria),
        "failed_criteria": list(synthesis.failed_criteria),
        "partial_criteria": list(synthesis.partial_criteria),
        "slop_findings": list(synthesis.slop_findings),
        "suggestions": list(synthesis.suggestions),
        "feedback_for_worker": synthesis.feedback_for_worker,
        "deliverable_summary": synthesis.deliverable_summary,
        "created_at": _iso(synthesis.created_at),
    }


def plan_review_to_dict(review: PlanReviewResult) -> dict[str, Any]:
    """Serialize a plan review result."""
    return {
        "review_id": str(review.review_id),
        "plan_adequate": review.plan_adequate,
        "scope_issues": list(review.scope_issues),
        "missing_criteria": list(review.missing_criteria),
        "unnecessary_criteria": list(review.unnecessary_criteria),
        "proposed_amendments": list(review.proposed_amendments),
        "lessons_learned": list(review.lessons_learned),
        "created_at": _iso(review.created_at),
    }


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
