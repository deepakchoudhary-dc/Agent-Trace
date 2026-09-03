"""Post-exit surveillance (plan2.md shortcoming #6).

In the METR incident, trip-wires fired and RESETWATCH heartbeats kept
running after their creators exited; agents explicitly treated
post-existence infrastructure as a shared resource for the collective.
AgentTrace observation was session-bound: nothing distinguished events
that arrive after a session closed, nothing aggregated the persistence
artifacts a session leaves behind (cron entries, scheduled tasks, launch
agents, background daemons), and nothing noticed one session re-arming
another session's artifact.

The :class:`PostExitRegistry` closes all three gaps:

- **Persistence tracking** -- file mutations under persistence locations
  (cron dirs, systemd units, LaunchAgents/LaunchDaemons, startup folders,
  rc files) and commands that install scheduled/long-lived work
  (schtasks, launchctl, systemctl enable, crontab, registry Run keys,
  nssm/pm2 service installs) are fingerprinted per session. The
  command-level PersistenceDetector already flags individual commands as
  policy findings; this layer answers the lifecycle question: what will
  still be running after this session ends.
- **Close accounting** -- when a session closes, one
  ``persistence_outlives_session`` incident lists every fingerprint the
  session installed. That artifact's purpose outlives the audit window
  and must be reviewed as such.
- **Post-close activity** -- events arriving for a closed session beyond
  a short grace window (in-flight events are normal) raise
  ``post_close_activity``: observation is over, yet the session's
  identity is still producing events.
- **Shared infrastructure** -- when a second session fingerprints the
  same artifact, ``shared_post_exit_infrastructure`` fires: agents
  treating post-existence infrastructure as a shared resource is the
  exact METR collective pattern.

Incidents are hash-chained ``IncidentEvent`` s at MEDIUM confidence
(structural correlation, not direct observation that a process
survived).
"""

from __future__ import annotations

import logging
import posixpath
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_GRACE_SECONDS = 30

# Path fragments that mark persistence locations (normalized, lowercase,
# forward slashes).
_PERSISTENCE_PATH_FRAGMENTS = (
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/var/spool/cron/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/init.d/",
    "/library/launchagents/",
    "/library/launchdaemons/",
    "start menu/programs/startup/",
    "/etc/profile.d/",
)

_RC_FILE_NAMES = frozenset({
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
})


def _is_persistence_path(file_path: str) -> bool:
    """True when a file mutation lands in a persistence location."""
    normalized = file_path.replace("\\", "/").lower()
    if "~" in normalized:
        # Expand a leading ~ so ~/Library/... matches the fragment list.
        normalized = normalized.replace("~", "/home/user", 1)
    if posixpath.basename(normalized) in _RC_FILE_NAMES:
        return True
    return any(fragment in normalized for fragment in _PERSISTENCE_PATH_FRAGMENTS)


# Command patterns that install or modify scheduled/long-lived work.
_PERSISTENCE_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in (
        ("schtasks", r"\bschtasks\s+/create\b"),
        ("crontab", r"\bcrontab\s"),
        ("systemctl-enable", r"\bsystemctl\s+(?:enable|link)\b"),
        ("launchctl", r"\blaunchctl\s+(?:load|submit)\b"),
        ("registry-run", r"\breg\s+add\b.*\\run\b"),
        ("nssm-install", r"\bnssm\s+install\b"),
        ("pm2-save", r"\bpm2\s+(?:save|startup)\b"),
        ("at-job", r"\bat\s+\d{1,2}:\d{2}\b"),
        ("initctl", r"\binitctl\s+start\b"),
    )
)


def _persistence_command_labels(command: str) -> list[str]:
    """Labels for the install mechanisms a command touches."""
    return [
        label
        for label, pattern in _PERSISTENCE_COMMAND_PATTERNS
        if pattern.search(command)
    ]


class PostExitRegistry:
    """Tracks persistence artifacts, post-close activity, and shared
    post-existence infrastructure across all sessions (daemon-wide)."""

    def __init__(
        self,
        *,
        grace_seconds: int = _GRACE_SECONDS,
        cooldown: timedelta | None = None,
    ) -> None:
        self._grace = timedelta(seconds=grace_seconds)
        self._cooldown = cooldown if cooldown is not None else timedelta(minutes=10)
        # session -> fingerprints of persistence artifacts it installed
        self._persistence: dict[UUID, dict[str, str]] = {}
        # session -> close time
        self._closed: dict[UUID, datetime] = {}
        # fingerprint -> sessions that installed it
        self._shared: dict[str, set[UUID]] = {}
        self._last_emitted: dict[str, datetime] = {}

    # -- Ingest hooks ------------------------------------------------------------

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one event; returns post-exit incidents when they fire."""
        if isinstance(event, IncidentEvent):
            return []

        sid = event.session_id
        if sid in self._closed:
            return self._observe_post_close(event)

        if (
            isinstance(event, FileMutationEvent)
            and event.mutation_type in ("create", "modify")
            and _is_persistence_path(event.file_path)
        ):
            return self._record_artifact(event)
        if isinstance(event, CommandEvent):
            return self._record_command_artifacts(event)
        return []

    def close_session(self, session_id: UUID, now: datetime) -> list[IncidentEvent]:
        """Called when a session stops; emits its persistence summary."""
        self._closed[session_id] = now
        artifacts = self._persistence.pop(session_id, {})
        if not artifacts:
            return []
        summary = "; ".join(f"{k}:{v}" for k, v in sorted(artifacts.items()))
        if not self._can_emit("close-summary", now):
            return []
        logger.warning(
            "POST-EXIT: session %s closed with %d persistence artifact(s)",
            session_id,
            len(artifacts),
        )
        return [
            IncidentEvent(
                session_id=session_id,
                actor_id="post_exit_registry",
                source_adapter="post_exit_registry",
                confidence=ConfidenceLevel.MEDIUM,
                incident_type="persistence_outlives_session",
                severity="high",
                title="Session closed with persistence in place",
                description=(
                    f"Session installed {len(artifacts)} persistence "
                    f"artifact(s) ({summary}). These artifacts' purpose "
                    "outlives the session: scheduled jobs, launch agents, "
                    "startup hooks, or background services will continue "
                    "operating after the agent exits. Review each artifact "
                    "for intended scope before treating the session as "
                    "ended (METR pattern: RESETWATCH heartbeats and "
                    "trip-wires running after their creators exited)."
                ),
                related_events=list(artifacts.values()),
                causal_path=list(artifacts.values()),
                timestamp=now,
            )
        ]

    # -- Post-close behavior ------------------------------------------------------

    def _observe_post_close(self, event: EventBase) -> list[IncidentEvent]:
        sid = event.session_id
        closed_at = self._closed[sid]
        if event.timestamp - closed_at <= self._grace:
            return []
        if not self._can_emit("post-close", event.timestamp):
            return []
        logger.warning(
            "POST-EXIT: event for closed session %s arrived %s after close",
            sid,
            event.timestamp - closed_at,
        )
        return [
            IncidentEvent(
                session_id=sid,
                actor_id="post_exit_registry",
                source_adapter="post_exit_registry",
                confidence=ConfidenceLevel.MEDIUM,
                incident_type="post_close_activity",
                severity="medium",
                title="Event arrived after session close",
                description=(
                    f"A {event.event_type.value} event arrived for closed "
                    f"session {sid} "
                    f"{int((event.timestamp - closed_at).total_seconds())}s "
                    "after close (beyond the in-flight grace window). The "
                    "session's identity is still producing activity: either "
                    "observers were not fully torn down, or an autonomous "
                    "process installed during the session is still "
                    "emitting. Correlate with "
                    "persistence_outlives_session findings for this "
                    "session."
                ),
                related_events=[str(event.event_id)],
                causal_path=[str(event.event_id)],
                timestamp=event.timestamp,
            )
        ]

    # -- Persistence bookkeeping -----------------------------------------------

    def _record_artifact(self, event: FileMutationEvent) -> list[IncidentEvent]:
        fingerprint = f"file:{event.file_path}"
        self._persistence.setdefault(event.session_id, {})[fingerprint] = str(
            event.event_id
        )
        return self._check_shared(fingerprint, event.session_id, event.timestamp)

    def _record_command_artifacts(self, event: CommandEvent) -> list[IncidentEvent]:
        incidents: list[IncidentEvent] = []
        for label in _persistence_command_labels(event.command):
            fingerprint = f"cmd:{label}:{event.working_dir or 'cwd'}"
            self._persistence.setdefault(event.session_id, {})[fingerprint] = str(
                event.event_id
            )
            incidents.extend(
                self._check_shared(fingerprint, event.session_id, event.timestamp)
            )
        return incidents

    def _check_shared(
        self,
        fingerprint: str,
        sid: UUID,
        now: datetime,
    ) -> list[IncidentEvent]:
        sessions = self._shared.setdefault(fingerprint, set())
        sessions.add(sid)
        if len(sessions) < 2:
            return []
        if not self._can_emit(f"shared:{fingerprint}", now):
            return []
        others = sorted(str(s) for s in sessions - {sid})
        logger.warning(
            "POST-EXIT: fingerprint '%s' installed by %d sessions",
            fingerprint,
            len(sessions),
        )
        return [
            IncidentEvent(
                session_id=sid,
                actor_id="post_exit_registry",
                source_adapter="post_exit_registry",
                confidence=ConfidenceLevel.MEDIUM,
                incident_type="shared_post_exit_infrastructure",
                severity="high",
                title="Post-exit infrastructure shared across sessions",
                description=(
                    f"Session {sid} installed the same persistence "
                    f"artifact ({fingerprint}) already installed by "
                    f"session(s) {', '.join(others)}. Agents treating "
                    "post-existence infrastructure as a shared resource "
                    "for the collective is the exact METR incident "
                    "pattern; the artifact is coordinating across audit "
                    "sessions."
                ),
                related_events=[],
                causal_path=[],
                timestamp=now,
            )
        ]

    def _can_emit(self, key: str, now: datetime) -> bool:
        last = self._last_emitted.get(key)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[key] = now
        return True
