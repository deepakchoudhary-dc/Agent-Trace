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


class NetworkCapturePolicy(str, Enum):
    """Network capture depth per workspace."""

    METADATA_ONLY = "metadata_only"  # Destination IP/port/protocol
    HEADERS = "headers"  # + HTTP method/status/headers
    FULL = "full"  # + redacted bodies (opt-in)


class SessionConfig(BaseModel):
    """Per-workspace configuration for an audit session."""

    workspace_path: str
    agent_type: AgentType = AgentType.AUTO
    network_capture: NetworkCapturePolicy = NetworkCapturePolicy.METADATA_ONLY
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
    redaction_enabled: bool = True
    encryption_enabled: bool = True
    max_blob_size_mb: int = 50
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
