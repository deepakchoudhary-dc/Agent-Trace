"""Canonical event models for the AgentTrace event ledger.

Every event in the system flows through these models. Each event is:
- Immutable once stored
- Cryptographically hash-chained to its predecessor across ALL typed fields
- Classified by confidence level
- Tagged with source adapter provenance
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """How much trust to place in this event's accuracy."""

    HIGH = "high"  # Direct telemetry observation
    MEDIUM = "medium"  # Filesystem/process correlation
    LOW = "low"  # Semantic or temporal inference


class EventType(str, Enum):
    """Canonical event types emitted by observers and adapters."""

    INVOCATION = "invocation"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    APPROVAL = "approval"
    FILE_MUTATION = "file_mutation"
    PROCESS = "process"
    COMMAND = "command"
    NETWORK = "network"
    GIT = "git"
    TEST_RESULT = "test_result"
    BUILD_RESULT = "build_result"
    POLICY_FINDING = "policy_finding"
    INCIDENT = "incident"
    CONTEXT_BOUNDARY = "context_boundary"
    SESSION_START = "session_start"
    SESSION_END = "session_end"


class EventBase(BaseModel):
    """Base for all events in the hash-chained ledger.

    Every event carries provenance metadata and complete typed attributes.
    The cryptographic hash commits to ALL typed subclass fields deterministically.
    """

    version: str = "1.0"
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str
    session_id: UUID
    source_adapter: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence_refs: list[str] = Field(default_factory=list)
    prev_hash: str = ""
    event_hash: str = ""
    seq: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)

    def canonical_dict(self) -> dict[str, Any]:
        """Produce the canonical, deterministic dictionary for hashing and storage."""
        data = self.model_dump(mode="json")
        # Exclude event_hash itself from the preimage to avoid recursion
        data.pop("event_hash", None)
        return data

    def canonical_bytes(self) -> bytes:
        """Produce deterministic canonical UTF-8 bytes."""
        canonical_str = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return canonical_str.encode("utf-8")

    def compute_hash(self) -> str:
        """Compute SHA-256 hash over the event's complete canonical envelope."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def seal(self, prev_hash: str = "", seq: int = 0) -> None:
        """Set the hash chain link, sequence number, and compute this event's hash."""
        self.prev_hash = prev_hash
        self.seq = seq
        self.event_hash = self.compute_hash()


class InvocationEvent(EventBase):
    """An AI agent was invoked with a user request."""

    event_type: EventType = EventType.INVOCATION
    user_intent: str = ""
    agent_name: str = ""
    agent_version: str = ""


class ToolRequestEvent(EventBase):
    """An agent requested a tool execution."""

    event_type: EventType = EventType.TOOL_REQUEST
    tool_name: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False


class ToolResultEvent(EventBase):
    """A tool execution completed."""

    event_type: EventType = EventType.TOOL_RESULT
    tool_name: str = ""
    exit_code: int | None = None
    output_summary: str = ""
    duration_ms: int = 0


class ApprovalEvent(EventBase):
    """A user approved or denied a gated action."""

    event_type: EventType = EventType.APPROVAL
    finding_id: str = ""
    approved: bool = False
    reason: str = ""
    scope: str = ""
    expiry: datetime | None = None
    affected_paths: list[str] = Field(default_factory=list)
    affected_commands: list[str] = Field(default_factory=list)


class FileMutationEvent(EventBase):
    """A file was created, modified, or deleted."""

    event_type: EventType = EventType.FILE_MUTATION
    file_path: str = ""
    mutation_type: str = ""  # create | modify | delete
    before_hash: str = ""
    after_hash: str = ""
    diff_summary: str = ""
    size_delta: int = 0


class ProcessEvent(EventBase):
    """A process was started, observed, or terminated."""

    event_type: EventType = EventType.PROCESS
    pid: int = 0
    ppid: int = 0
    command_line: str = ""
    working_dir: str = ""
    started_at: datetime | None = None
    ended_at: datetime | None = None
    exit_code: int | None = None


class CommandEvent(EventBase):
    """A shell command was executed."""

    event_type: EventType = EventType.COMMAND
    command: str = ""
    output: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    working_dir: str = ""


class NetworkEvent(EventBase):
    """A network connection was observed."""

    event_type: EventType = EventType.NETWORK
    destination_ip: str = ""
    destination_port: int = 0
    protocol: str = ""
    direction: str = ""  # outbound | inbound
    process_pid: int | None = None
    http_method: str | None = None
    http_status: int | None = None
    url_path: str | None = None


class GitEvent(EventBase):
    """A Git state change was observed."""

    event_type: EventType = EventType.GIT
    git_action: str = ""  # commit | checkout | merge | stage | reset
    branch: str = ""
    commit_hash: str = ""
    parent_hash: str = ""
    message: str = ""
    files_changed: list[str] = Field(default_factory=list)
    insertions: int = 0
    deletions: int = 0


class TestResultEvent(EventBase):
    """A test run completed."""

    __test__ = False

    event_type: EventType = EventType.TEST_RESULT
    test_suite: str = ""
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_ms: int = 0
    failures: list[dict[str, str]] = Field(default_factory=list)


class BuildResultEvent(EventBase):
    """A build process completed."""

    event_type: EventType = EventType.BUILD_RESULT
    build_tool: str = ""
    success: bool = False
    output_summary: str = ""
    duration_ms: int = 0
    errors: list[str] = Field(default_factory=list)


class PolicyFindingEvent(EventBase):
    """A policy violation or risk was detected."""

    event_type: EventType = EventType.POLICY_FINDING
    finding_type: str = ""
    severity: str = ""  # critical | high | medium | low | info
    description: str = ""
    affected_path: str = ""
    affected_command: str = ""
    requires_approval: bool = True
    auto_resolved: bool = False


class IncidentEvent(EventBase):
    """An incident was flagged for investigation."""

    event_type: EventType = EventType.INCIDENT
    incident_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    related_events: list[str] = Field(default_factory=list)
    causal_path: list[str] = Field(default_factory=list)


class ContextBoundaryEvent(EventBase):
    """Records the visible context boundary of an agent session."""

    event_type: EventType = EventType.CONTEXT_BOUNDARY
    files_visible: list[str] = Field(default_factory=list)
    context_window_tokens: int = 0
    system_prompt_hash: str = ""
    external_sources: list[str] = Field(default_factory=list)


_EVENT_TYPE_MAP: dict[EventType, type[EventBase]] = {
    EventType.INVOCATION: InvocationEvent,
    EventType.TOOL_REQUEST: ToolRequestEvent,
    EventType.TOOL_RESULT: ToolResultEvent,
    EventType.APPROVAL: ApprovalEvent,
    EventType.FILE_MUTATION: FileMutationEvent,
    EventType.PROCESS: ProcessEvent,
    EventType.COMMAND: CommandEvent,
    EventType.NETWORK: NetworkEvent,
    EventType.GIT: GitEvent,
    EventType.TEST_RESULT: TestResultEvent,
    EventType.BUILD_RESULT: BuildResultEvent,
    EventType.POLICY_FINDING: PolicyFindingEvent,
    EventType.INCIDENT: IncidentEvent,
    EventType.CONTEXT_BOUNDARY: ContextBoundaryEvent,
    EventType.SESSION_START: EventBase,
    EventType.SESSION_END: EventBase,
}


def event_from_dict(data: dict[str, Any]) -> EventBase:
    """Deserialize a canonical event dictionary into its concrete Event model subclass."""
    event_type_str = data.get("event_type", "")
    try:
        event_type = EventType(event_type_str)
        model_cls = _EVENT_TYPE_MAP.get(event_type, EventBase)
        return model_cls.model_validate(data)
    except Exception:
        return EventBase.model_validate(data)
