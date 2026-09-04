"""Tests for credential discovery -> sharing -> lateral movement loops
(plan2.md shortcoming #7 — the Hugging Face shared-currency pattern)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.credential_loops import (
    CredentialLoopTracker,
    _fingerprint,
    extract_secret_candidates,
)
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    IncidentEvent,
)

_SID_A = uuid4()
_SID_B = uuid4()
_SID_C = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)

_HF = "hf_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"  # 34 alnum chars


def _cmd(
    command: str,
    sid: object = None,
    at: datetime | None = None,
) -> CommandEvent:
    return CommandEvent(
        session_id=_SID_A if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        timestamp=at or _T0,
    )


# -- Extraction -----------------------------------------------------------------


def test_hf_token_extracted_once_under_single_identity() -> None:
    found = extract_secret_candidates(f"export HF_TOKEN={_HF}")
    assert found == [("hf", _HF)]


def test_provider_grammars_are_recognized() -> None:
    tokens = {
        "sk-" + "Ab1" * 13 + "A": "openai",
        "sk-ant-" + "Zy9" * 13 + "Z": "anthropic",
        "ghp_" + "G" * 36: "github",
        "github_pat_" + "P" * 60: "github",
        "AIza" + "G" * 35: "google",
        "AKIA" + "IOSFODNN7EXAMPLE"[:16]: "aws",
        "xoxb-" + "1234567890abcdef": "slack",
    }
    for token, provider in tokens.items():
        found = extract_secret_candidates(f"using {token}")
        assert found and found[0][0] == provider, token


def test_generic_secret_structurally_detected() -> None:
    secret = "Kx9-mQ2vLp7_Rw4nZ8aJc3fT5yH6bD"  # 30 chars, digits+symbols
    assert extract_secret_candidates(f"apikey={secret}") == [("generic", secret)]


def test_low_entropy_run_not_flagged() -> None:
    assert extract_secret_candidates("key=" + "a" * 28 + "1-") == []


# -- Loop lifecycle ----------------------------------------------------------------


def test_first_discovery_is_silent() -> None:
    tracker = CredentialLoopTracker()
    assert tracker.observe(_cmd(f"cat .env  # {_HF}")) == []


def test_single_session_reuse_is_silent() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"use {_HF}"))
    assert tracker.observe(_cmd(f"use {_HF} again")) == []


def test_shared_between_sessions_fires() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    incidents = tracker.observe(_cmd(f"post {_HF}", sid=_SID_B, at=_T0 + _min(2)))
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.incident_type == "credential_shared_between_sessions"
    assert inc.severity == "high"
    fp = inc.payload["fingerprint_sha256"]
    assert fp == _fingerprint("hf", _HF)
    assert len(fp) == 64


def test_raw_secret_never_reaches_incident_text() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    inc = tracker.observe(_cmd(f"post {_HF}", sid=_SID_B))[0]
    assert _HF not in inc.description
    assert _HF not in inc.title


def test_lateral_movement_on_third_session() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    shared = tracker.observe(_cmd(f"use {_HF}", sid=_SID_B, at=_T0 + _min(1)))
    assert shared[0].incident_type == "credential_shared_between_sessions"
    lateral = tracker.observe(_cmd(f"use {_HF}", sid=_SID_C, at=_T0 + _min(2)))
    assert len(lateral) == 1
    assert lateral[0].incident_type == "credential_lateral_movement"
    assert lateral[0].severity == "critical"


def test_fourth_session_after_lateral_is_silent() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    tracker.observe(_cmd(f"use {_HF}", sid=_SID_B, at=_T0 + _min(1)))
    tracker.observe(_cmd(f"use {_HF}", sid=_SID_C, at=_T0 + _min(2)))
    assert tracker.observe(_cmd(f"use {_HF}", sid=_SID_C, at=_T0 + _min(3))) == []


def _min(minutes: int) -> timedelta:
    return timedelta(minutes=minutes)


# -- Escalation and close coupling ------------------------------------------------


def test_closed_session_holding_secret_escalates_to_critical() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    tracker.mark_session_closed(_SID_A)
    inc = tracker.observe(_cmd(f"use {_HF}", sid=_SID_B))[0]
    assert inc.incident_type == "credential_shared_between_sessions"
    assert inc.severity == "critical"
    assert "outlived its session" in inc.description


def test_escalation_to_lateral_bypasses_cooldown() -> None:
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    tracker.observe(_cmd(f"use {_HF}", sid=_SID_B, at=_T0 + _min(1)))
    # Within the 10-minute cooldown of the shared emission:
    lateral = tracker.observe(_cmd(f"use {_HF}", sid=_SID_C, at=_T0 + _min(2)))
    assert lateral[0].incident_type == "credential_lateral_movement"


def test_file_diff_summary_scanned() -> None:
    tracker = CredentialLoopTracker()
    from agenttrace.models.events import FileMutationEvent

    tracker.observe(
        FileMutationEvent(
            session_id=_SID_A,
            actor_id="agent",
            source_adapter="filesystem_observer",
            file_path="/ws/.env",
            mutation_type="create",
            diff_summary=f"TOKEN={_HF}",
            timestamp=_T0,
        )
    )
    inc = tracker.observe(_cmd(f"curl -H 'Authorization: Bearer {_HF}'", sid=_SID_B))[0]
    assert inc.incident_type == "credential_shared_between_sessions"


def test_incident_events_ignored() -> None:
    tracker = CredentialLoopTracker()
    incident = IncidentEvent(
        session_id=_SID_A,
        actor_id="credential_loop_tracker",
        source_adapter="credential_loop_tracker",
        incident_type="credential_shared_between_sessions",
        severity="high",
        title="t",
        description="d",
    )
    assert tracker.observe(incident) == []


def test_two_distinct_secrets_tracked_independently() -> None:
    other = "hf_" + "f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3"
    tracker = CredentialLoopTracker()
    tracker.observe(_cmd(f"find {_HF}", sid=_SID_A))
    tracker.observe(_cmd(f"find {other}", sid=_SID_A))
    assert tracker.observe(_cmd(f"use {_HF}", sid=_SID_B))[0].severity == "high"
    assert len(tracker.observe(_cmd(f"use {other}", sid=_SID_B))) == 1


def test_observability_event_not_scanned() -> None:
    """Network/process events carry no narrative text to scan."""
    from agenttrace.models.events import NetworkEvent

    tracker = CredentialLoopTracker()
    tracker.observe(
        NetworkEvent(
            session_id=_SID_A,
            actor_id="agent",
            source_adapter="network_observer",
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="tcp",
            direction="outbound",
            url_path=f"/dl/{_HF}",
            timestamp=_T0,
        )
    )
    assert tracker.observe(_cmd(f"use {_HF}", sid=_SID_B)) == []
