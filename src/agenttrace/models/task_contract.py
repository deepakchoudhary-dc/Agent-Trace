"""Task contract and scope drift detection models.

A task contract is the structured representation of a user's request,
including allowed paths, expected tests, and risk level. The scope
drift detector compares ongoing actions against this contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk classification for a task."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DriftType(str, Enum):
    """Categories of scope drift."""

    FILE_OUTSIDE_SCOPE = "file_outside_scope"
    UNEXPECTED_DEPENDENCY = "unexpected_dependency"
    NETWORK_EGRESS = "network_egress"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESTRUCTIVE_OPERATION = "destructive_operation"
    CREDENTIAL_ACCESS = "credential_access"
    SEMANTIC_DRIFT = "semantic_drift"
    UNTESTED_CHANGE = "untested_change"
    SANDBOX_EVASION = "sandbox_evasion"
    PAYLOAD_STAGING = "payload_staging"


class TaskContract(BaseModel):
    """Structured representation of a user's task request.

    Editable by the user — this is the ground truth for scope checking.
    """

    contract_id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    goal: str
    allowed_paths: list[str] = Field(default_factory=list)
    prohibited_paths: list[str] = Field(default_factory=list)
    expected_tests: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""


class ScopeDriftResult(BaseModel):
    """Result of checking an action against the task contract."""

    drift_id: UUID = Field(default_factory=uuid4)
    contract_id: UUID
    drift_type: DriftType
    severity: str = "medium"
    description: str = ""
    affected_path: str = ""
    affected_command: str = ""
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
