"""Orchestrator for the threat-detection rule engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agenttrace.security.detectors.base import DetectionContext
from agenttrace.security.detectors.rules import DEFAULT_DETECTORS

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.events import EventBase
    from agenttrace.security.detectors.base import Detector, DetectorFinding


class DetectionEngine:
    """Runs all active detectors over each observed event.

    Every detector sees every event; detectors filter by event type
    themselves. Findings are aggregated in rule definition order and each
    carries an evidence reference to the triggering event id.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_paths: list[str] | None = None,
        internet_allowed: bool | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self._context = DetectionContext(
            session_id=session_id,
            workspace_paths=list(workspace_paths or []),
            internet_allowed=internet_allowed,
        )
        self._detectors: list[Detector] = list(detectors or DEFAULT_DETECTORS)

    def evaluate(self, event: EventBase) -> list[DetectorFinding]:
        """Evaluate one event against all active detectors."""
        findings: list[DetectorFinding] = []
        for detector in self._detectors:
            try:
                for finding in detector.evaluate(event, self._context):
                    # Every finding is anchored to the triggering event so the
                    # graph/ledger can trace evidence end-to-end.
                    if str(event.event_id) not in finding.evidence_refs:
                        finding.evidence_refs.insert(0, str(event.event_id))
                    findings.append(finding)
            except Exception:
                # A detector bug must never break event ingestion.
                continue
        return findings

    def get_detectors(self) -> list[tuple[str, str]]:
        """Registered detectors as (id, name) pairs."""
        return [(d.detector_id, d.name) for d in self._detectors]
