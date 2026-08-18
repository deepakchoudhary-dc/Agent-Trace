"""Detector protocol and shared result types for the threat-detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.events import ConfidenceLevel, EventBase


@dataclass
class DetectionContext:
    """Immutable session-level inputs passed to every detector evaluation."""

    session_id: UUID
    # Paths the task contract declares as in-scope. When empty the detector
    # cannot reason about "outside the workspace" and must skip those checks.
    workspace_paths: list[str] = field(default_factory=list)
    # Declared network boundary; ``None`` means unknown (no sealing declared).
    internet_allowed: bool | None = None


@dataclass
class DetectorFinding:
    """A single detection result ready to be converted into a policy finding."""

    detector_id: str
    name: str
    severity: str  # critical | high | medium | low | info
    confidence: ConfidenceLevel
    description: str
    evidence_refs: list[str] = field(default_factory=list)
    affected_path: str = ""
    affected_command: str = ""
    requires_approval: bool = False


@runtime_checkable
class Detector(Protocol):
    """Interface every rule in the detection engine must implement."""

    detector_id: str
    name: str

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        """Return findings for a single observed event (empty list = no match)."""
        ...
