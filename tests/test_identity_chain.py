"""Tests for the identity-bootstrap chain detector (ant.md P1 #6)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.identity_chain import IdentityBootstrapDetector
from agenttrace.models.events import CommandEvent, ConfidenceLevel

SESSION = uuid4()
T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)


def _cmd(command: str, *, when: datetime | None = None) -> CommandEvent:
    return CommandEvent(
        session_id=SESSION,
        actor_id="agent",
        source_adapter="terminal",
        command=command,
        output="",
        timestamp=when or T0,
    )


def test_single_registry_step_stays_silent() -> None:
    """Registry activity alone is real work — never a finding."""
    detector = IdentityBootstrapDetector(SESSION)
    assert detector.observe(_cmd("twine upload dist/pkg-1.0.tar.gz")) == []
    assert detector.observe(_cmd("npm login")) == []


def test_two_distinct_stages_then_registry_fires_high() -> None:
    """Crypto + phone stages then registry -> identity_bootstrap_chain."""
    detector = IdentityBootstrapDetector(SESSION)
    assert detector.observe(_cmd("electrum seed phrase backup")) == []
    assert detector.observe(
        _cmd("sms-activate order virtual phone", when=T0 + timedelta(minutes=5))
    ) == []
    (inc,) = detector.observe(
        _cmd("npm publish", when=T0 + timedelta(minutes=10))
    )
    assert inc.incident_type == "identity_bootstrap_chain"
    assert inc.severity == "high"
    assert inc.confidence is ConfidenceLevel.MEDIUM
    assert "crypto" in inc.description and "phone" in inc.description
    assert len(inc.related_events) == 3


def test_window_prunes_old_stages() -> None:
    """Stages outside the correlation window don't count."""
    detector = IdentityBootstrapDetector(SESSION, window=timedelta(hours=1))
    detector.observe(_cmd("stripe payment processor credentials"))


def test_cooldown_silent_inside_one_hour() -> None:
    """Second chain completion inside cooldown emits nothing."""
    detector = IdentityBootstrapDetector(SESSION)
    detector.observe(_cmd("electrum seed phrase backup"))
    detector.observe(_cmd("guerrillamail disposable email"))
    detector.observe(_cmd("npm publish"))
    second = detector.observe(
        _cmd("stripe credit-card", when=T0 + timedelta(minutes=20))
    )
    detector.observe(
        _cmd("mailinator temp-mail inbox", when=T0 + timedelta(minutes=25))
    )
    second_completion = detector.observe(
        _cmd("pypi register account", when=T0 + timedelta(minutes=30))
    )
    assert second == []
    assert second_completion == []


def test_derived_events_ignored() -> None:
    """Daemon-minted events never feed stage detection."""
    from agenttrace.models.events import IncidentEvent

    detector = IdentityBootstrapDetector(SESSION)
    incident = IncidentEvent(
        session_id=SESSION,
        actor_id="daemon",
        source_adapter="policy_finding",
        confidence=ConfidenceLevel.MEDIUM,
        incident_type="policy_finding",
        severity="low",
        title="x",
        description="stripe pypi npm publish chain",
        timestamp=T0,
    )
    assert detector.observe(incident) == []

    far_later = detector.observe(
        _cmd("npm login", when=T0 + timedelta(hours=3))
    )
    assert far_later == []
