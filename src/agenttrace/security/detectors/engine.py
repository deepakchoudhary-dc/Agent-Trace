"""Orchestrator for the threat-detection rule engine."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agenttrace.models.events import ConfidenceLevel
from agenttrace.security.detectors.base import DetectionContext, DetectorFinding
from agenttrace.security.detectors.rules import DEFAULT_DETECTORS

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.events import EventBase
    from agenttrace.security.detectors.base import Detector

logger = logging.getLogger(__name__)


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
        self._error_findings: list[DetectorFinding] = []

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
            except Exception as exc:  # noqa: BLE001 — surface, never break ingestion
                # A detector bug must never break event ingestion, but it must
                # also never vanish silently (N5). Surface a degraded-coverage
                # finding so the operator can see the blind spot.
                logger.warning(
                    "Detector %s raised during evaluation of event %s: %s",
                    getattr(detector, "detector_id", "?"),
                    event.event_id,
                    exc,
                    exc_info=True,
                )
                error_finding = DetectorFinding(
                    detector_id="detector_engine_error",
                    name=(
                        f"Detector {getattr(detector, 'name', '?')} failed"
                    ),
                    severity="low",
                    confidence=ConfidenceLevel.HIGH,
                    description=(
                        f"Detector {getattr(detector, 'detector_id', '?')} raised "
                        f"{type(exc).__name__}: {exc}. Coverage is degraded for this event."
                    ),
                    evidence_refs=[str(event.event_id)],
                )
                self._error_findings.append(error_finding)
                findings.append(error_finding)
        return findings

    def get_detectors(self) -> list[tuple[str, str]]:
        """Registered detectors as (id, name) pairs."""
        return [(d.detector_id, d.name) for d in self._detectors]

    @property
    def error_findings(self) -> list[DetectorFinding]:
        """Detector failures surfaced during this engine's lifetime."""
        return list(self._error_findings)
