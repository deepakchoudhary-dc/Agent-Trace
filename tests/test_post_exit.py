"""Tests for post-exit surveillance (plan2.md shortcoming #6)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.post_exit import (
    PostExitRegistry,
    _is_persistence_path,
    _persistence_command_labels,
)
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    FileMutationEvent,
    IncidentEvent,
)

_SID_A = uuid4()
_SID_B = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _cmd(command: str, sid: object = None, at: datetime | None = None) -> CommandEvent:
    return CommandEvent(
        session_id=_SID_A if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        timestamp=at or _T0,
    )


def _file(
    path: str,
    sid: object = None,
    at: datetime | None = None,
    mutation: str = "create",
) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=_SID_A if sid is None else sid,  # type: ignore[arg-type]
        actor_id="agent",
        source_adapter="filesystem_observer",
        confidence=ConfidenceLevel.HIGH,
        file_path=path,
        mutation_type=mutation,
        timestamp=at or _T0,
    )


# -- Classification helpers ------------------------------------------------------


def test_persistence_paths_detected() -> None:
    for path in (
        "/etc/cron.d/renew",
        "/var/spool/cron/root",
        "/etc/systemd/system/watch.service",
        "/Library/LaunchAgents/com.agent.plist",
        "C:/Users/u/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.bat",
        "/home/u/.bashrc",
    ):
        assert _is_persistence_path(path), path


def test_benign_paths_not_flagged() -> None:
    for path in ("/ws/src/main.py", "/etc/hosts", "/home/u/project/README.md"):
        assert not _is_persistence_path(path), path


def test_persistence_commands_detected() -> None:
    cases = {
        "schtasks /create /tn watch /sc hourly /tr cmd": "schtasks",
        "crontab -l && echo x | crontab -": "crontab",
        "systemctl enable watch.service": "systemctl-enable",
        "launchctl load ~/Library/LaunchAgents/a.plist": "launchctl",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x": (
            "registry-run"
        ),
        "nssm install AgentWatch python": "nssm-install",
        "pm2 save": "pm2-save",
    }
    for command, label in cases.items():
        assert label in _persistence_command_labels(command), command


def test_benign_commands_not_flagged() -> None:
    for command in ("pytest tests/", "git status", "npm install", "ls -la"):
        assert _persistence_command_labels(command) == [], command


# -- Close accounting ---------------------------------------------------------------


def test_clean_session_close_emits_nothing() -> None:
    registry = PostExitRegistry()
    assert registry.close_session(_SID_A, _T0) == []


def test_close_with_persistence_emits_summary() -> None:
    registry = PostExitRegistry()
    registry.observe(_cmd("systemctl enable watch.service"))
    incidents = registry.close_session(_SID_A, _T0)
    assert len(incidents) == 1
    assert incidents[0].incident_type == "persistence_outlives_session"
    assert incidents[0].severity == "high"
    assert "systemctl-enable" in incidents[0].description


def test_file_artifact_recorded_before_close() -> None:
    registry = PostExitRegistry()
    registry.observe(_file("/etc/cron.d/renew"))
    incidents = registry.close_session(_SID_A, _T0)
    assert len(incidents) == 1
    assert "file:/etc/cron.d/renew" in incidents[0].description


def test_delete_mutation_not_recorded() -> None:
    """Removing a persistence artifact is cleanup, not installation."""
    registry = PostExitRegistry()
    registry.observe(_file("/etc/cron.d/renew", mutation="delete"))
    assert registry.close_session(_SID_A, _T0) == []


# -- Post-close activity ------------------------------------------------------------


def test_event_within_grace_window_ignored() -> None:
    registry = PostExitRegistry()
    registry.close_session(_SID_A, _T0)
    late = _cmd("echo in-flight", at=_T0 + timedelta(seconds=10))
    assert registry.observe(late) == []


def test_event_beyond_grace_window_fires() -> None:
    registry = PostExitRegistry()
    registry.close_session(_SID_A, _T0)
    late = _cmd("echo beacon", at=_T0 + timedelta(minutes=5))
    incidents = registry.observe(late)
    assert len(incidents) == 1
    assert incidents[0].incident_type == "post_close_activity"
    assert incidents[0].severity == "medium"


def test_post_close_cooldown_prevents_spam() -> None:
    registry = PostExitRegistry()
    registry.close_session(_SID_A, _T0)
    first = _cmd("echo beacon", at=_T0 + timedelta(minutes=5))
    second = _cmd("echo beacon", at=_T0 + timedelta(minutes=6))
    assert len(registry.observe(first)) == 1
    assert registry.observe(second) == []


def test_closed_session_skips_persistence_bookkeeping() -> None:
    """A closed session's file events become post-close signals, not installs."""
    registry = PostExitRegistry()
    registry.close_session(_SID_A, _T0)
    late = _file("/etc/cron.d/renew", at=_T0 + timedelta(minutes=5))
    incidents = registry.observe(late)
    assert len(incidents) == 1
    assert incidents[0].incident_type == "post_close_activity"


# -- Shared infrastructure -----------------------------------------------------------


def test_second_session_same_artifact_fires() -> None:
    registry = PostExitRegistry()
    registry.observe(_file("/etc/cron.d/renew", sid=_SID_A))
    incidents = registry.observe(_file("/etc/cron.d/renew", sid=_SID_B))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "shared_post_exit_infrastructure"
    assert incidents[0].severity == "high"


def test_second_session_same_command_fires() -> None:
    registry = PostExitRegistry()
    registry.observe(_cmd("schtasks /create /tn w /sc onlogon /tr x", sid=_SID_A))
    incidents = registry.observe(
        _cmd("schtasks /create /tn w /sc onlogon /tr x", sid=_SID_B)
    )
    assert len(incidents) == 1
    assert incidents[0].incident_type == "shared_post_exit_infrastructure"


def test_different_artifacts_do_not_fire() -> None:
    registry = PostExitRegistry()
    registry.observe(_file("/etc/cron.d/renew", sid=_SID_A))
    assert registry.observe(_file("/etc/cron.d/other", sid=_SID_B)) == []


def test_same_session_reinstall_does_not_fire() -> None:
    registry = PostExitRegistry()
    registry.observe(_file("/etc/cron.d/renew", sid=_SID_A))
    assert registry.observe(_file("/etc/cron.d/renew", sid=_SID_A)) == []


def test_incident_events_ignored() -> None:
    registry = PostExitRegistry()
    incident = IncidentEvent(
        session_id=_SID_A,
        actor_id="post_exit_registry",
        source_adapter="post_exit_registry",
        incident_type="post_close_activity",
        severity="medium",
        title="t",
        description="d",
    )
    assert registry.observe(incident) == []
