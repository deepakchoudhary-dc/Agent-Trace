"""Tests for evidence-boundary classification and tool-claim reconciliation
(plan2.md shortcoming #4 — chain of custody starts at the wrong boundary)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.evidence_boundary import (
    EvidenceClass,
    ToolClaimReconciler,
    classify_evidence,
    event_evidence_class,
)
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    IncidentEvent,
    ProcessEvent,
    ToolResultEvent,
)

_SID = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _claim(
    exit_code: int | None = 0,
    summary: str = "",
    at: datetime | None = None,
) -> ToolResultEvent:
    return ToolResultEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        tool_name="bash",
        exit_code=exit_code,
        output_summary=summary,
        timestamp=at or _T0,
    )


def _os_process(
    exit_code: int = 0,
    at: datetime | None = None,
) -> ProcessEvent:
    return ProcessEvent(
        session_id=_SID,
        actor_id="system",
        source_adapter="process_tree_observer",
        confidence=ConfidenceLevel.HIGH,
        pid=4242,
        ppid=400,
        command_line="pytest tests/",
        exit_code=exit_code,
        timestamp=at or _T0 - timedelta(seconds=10),
    )


# -- Classification ------------------------------------------------------------


def test_adapter_strings_classify_os_observed() -> None:
    for adapter in (
        "filesystem_observer",
        "process_tree_observer",
        "network_observer",
        "kernel_etw",
        "git_monitor",
    ):
        assert classify_evidence(adapter) is EvidenceClass.OS_OBSERVED


def test_adapter_strings_classify_agent_claimed() -> None:
    for adapter in (
        "claude_code",
        "codex_cli",
        "copilot_chat",
        "generic",
        "universal_agent_sensor",
        "multi_agent_composite",
        "terminal",
    ):
        assert classify_evidence(adapter) is EvidenceClass.AGENT_CLAIMED


def test_adapter_strings_classify_derived() -> None:
    for adapter in (
        "daemon",
        "user_cli",
        "task_boundary",
        "execution_broker",
        "detector_engine",
        "covert_channel_detector",
    ):
        assert classify_evidence(adapter) is EvidenceClass.DERIVED


def test_unknown_adapter_fails_toward_distrust() -> None:
    """Unclassified adapters are agent claims, never OS observations."""
    assert classify_evidence("mystery_adapter") is EvidenceClass.AGENT_CLAIMED


def test_classification_is_pure_function_of_committed_adapter() -> None:
    event = _claim()
    event.source_adapter = "filesystem_observer"
    assert event_evidence_class(event) is EvidenceClass.OS_OBSERVED


# -- Reconciliation: unverified claims ------------------------------------------


def test_unverified_claim_no_os_signal() -> None:
    reconciler = ToolClaimReconciler(_SID)
    incidents = reconciler.observe(_claim(exit_code=0))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "unverified_tool_claim"
    assert incidents[0].severity == "medium"
    assert incidents[0].confidence is ConfidenceLevel.MEDIUM


def test_verified_claim_produces_no_incident() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_os_process(exit_code=0))
    assert reconciler.observe(_claim(exit_code=0)) == []


def test_verified_failure_claim_produces_no_incident() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_os_process(exit_code=1))
    assert reconciler.observe(_claim(exit_code=1)) == []


def test_neutral_claim_produces_no_incident() -> None:
    """No exit code and no outcome wording: nothing to verify."""
    reconciler = ToolClaimReconciler(_SID)
    assert reconciler.observe(_claim(exit_code=None, summary="done")) == []


# -- Reconciliation: substitution (contradiction) --------------------------------


def test_substitution_success_claimed_process_failed() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_os_process(exit_code=1))
    incidents = reconciler.observe(_claim(exit_code=0))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "tool_claim_substitution"
    assert incidents[0].severity == "high"


def test_substitution_failure_claimed_process_succeeded() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_os_process(exit_code=0))
    incidents = reconciler.observe(_claim(exit_code=1))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "tool_claim_substitution"


def test_substitution_detected_from_summary_wording() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_os_process(exit_code=1))
    incidents = reconciler.observe(_claim(exit_code=None, summary="All tests passed"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "tool_claim_substitution"


# -- Window and cooldown behavior -------------------------------------------------


def test_stale_os_signal_outside_window_is_ignored() -> None:
    reconciler = ToolClaimReconciler(_SID, window_seconds=90)
    reconciler.observe(_os_process(exit_code=0, at=_T0 - timedelta(seconds=120)))
    incidents = reconciler.observe(_claim(exit_code=0))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "unverified_tool_claim"


def test_cooldown_prevents_spam() -> None:
    reconciler = ToolClaimReconciler(_SID)
    assert len(reconciler.observe(_claim(exit_code=0))) == 1
    second = _claim(exit_code=0, at=_T0 + timedelta(minutes=5))
    assert reconciler.observe(second) == []


def test_cooldown_expires_after_ten_minutes() -> None:
    reconciler = ToolClaimReconciler(_SID)
    assert len(reconciler.observe(_claim(exit_code=0))) == 1
    later = _claim(exit_code=0, at=_T0 + timedelta(minutes=11))
    incidents = reconciler.observe(later)
    assert len(incidents) == 1
    assert incidents[0].incident_type == "unverified_tool_claim"


def test_os_signal_after_claim_is_recorded_for_next_claim() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(_claim(exit_code=0))  # unverified: cooldown armed
    reconciler.observe(_os_process(exit_code=0, at=_T0 + timedelta(seconds=1)))
    later = _claim(exit_code=0, at=_T0 + timedelta(seconds=2))
    assert reconciler.observe(later) == []


# -- Boundary conditions ------------------------------------------------------------


def test_incident_events_are_ignored() -> None:
    reconciler = ToolClaimReconciler(_SID)
    incident = IncidentEvent(
        session_id=_SID,
        actor_id="covert_channel_detector",
        source_adapter="covert_channel_detector",
        incident_type="message_board_structure",
        severity="medium",
        title="t",
        description="d",
    )
    assert reconciler.observe(incident) == []


def test_terminal_and_command_events_do_not_pollute_os_window() -> None:
    """Terminal output is a claim, not OS ground truth (the whole point)."""
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(
        CommandEvent(
            session_id=_SID,
            actor_id="agent",
            source_adapter="terminal",
            command="pytest tests/",
            exit_code=0,
            timestamp=_T0 - timedelta(seconds=5),
        )
    )
    incidents = reconciler.observe(_claim(exit_code=0))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "unverified_tool_claim"


def test_filesystem_events_count_as_os_presence() -> None:
    reconciler = ToolClaimReconciler(_SID)
    reconciler.observe(
        FileMutationEvent(
            session_id=_SID,
            actor_id="system",
            source_adapter="filesystem_observer",
            file_path="/ws/src/main.py",
            mutation_type="modify",
            timestamp=_T0 - timedelta(seconds=5),
        )
    )
    assert reconciler.observe(_claim(exit_code=0)) == []
