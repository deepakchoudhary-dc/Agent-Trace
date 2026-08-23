"""Audit session models.

A session represents one audit run across a workspace. Multiple agents
can operate within a single session, each tracked as a separate actor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    """Lifecycle states of an audit session."""

    STARTING = "starting"
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class AgentType(str, Enum):
    """Known agent types for auto-detection."""

    AUTO = "auto"
    CODEX = "codex"
    CLAUDE = "claude"
    COPILOT = "copilot"
    GENERIC = "generic"


class SessionConfig(BaseModel):
    """Per-workspace configuration for an audit session.

    Deliberately contains NO toggles for redaction, encryption, or network
    capture depth: those are always-on integrity/privacy guarantees, not
    options. A config knob that is never read by the daemon is a false
    promise, so none exist here.
    """

    workspace_path: str
    agent_type: AgentType = AgentType.AUTO
    watch_patterns: list[str] = Field(default_factory=lambda: ["**/*"])
    ignore_patterns: list[str] = Field(
        default_factory=lambda: [
            ".git/**",
            "node_modules/**",
            "__pycache__/**",
            "*.pyc",
            ".venv/**",
            "venv/**",
        ]
    )
    # Privacy: global shell-history files (~/.bash_history, PSReadLine history)
    # are NEVER read unless the user explicitly opts in per session
    track_global_shell_history: bool = False
    # Declared network boundary for the audited environment. When
    # internet_access_allowed is False (a *sealed* eval/air-gapped
    # workspace), ANY egress to a public host is a violation — this turns
    # the "eval said no internet but had internet" misconfiguration behind
    # the Anthropic CTF incidents into a detectable finding at runtime.
    # allowed_destinations, when set, is an allowlist of destination IPs
    # the environment may reach; anything else is a violation.
    internet_access_allowed: bool | None = None
    allowed_destinations: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class AuditSession(BaseModel):
    """A single audit session tracking agent activity in a workspace."""

    session_id: UUID = Field(default_factory=uuid4)
    config: SessionConfig
    task_description: str = ""
    status: SessionStatus = SessionStatus.STARTING
    agents: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stopped_at: datetime | None = None
    event_count: int = 0
    last_event_hash: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
