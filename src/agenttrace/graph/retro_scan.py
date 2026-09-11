"""Historical retro-scan — the "wide net" over stored history (ant.md P1 #4).

Anthropic's own detection pipeline is the failure mode to design
against: an agentic search over ~141,000 transcripts MISSED a fourth
incident, found only by accident months later. The corrected
methodology is a two-stage wide-net re-scan of everything already
stored — cheap exhaustive pattern triage first, focused review second —
not a single agentic pass.

``RetroScan`` re-runs the **current** detector arsenal (rules engine +
graph detectors) over stored sessions, so a detector shipped after a
session closed can still retro-flag it. Findings become new
hash-chained ``IncidentEvent``s anchored to the historical events,
clearly marked ``retro_scan`` provenance with the detector set that
produced them.

Stage 1 (wide net): deterministic regex triage over every stored
command/network/tool narrative — public IPs, URLs, registry publishes,
credential material. Every session is screened; nothing is skipped.

Stage 2 (focused): the session's events are replayed through
DetectionEngine so full structural detectors (not just regexes) apply.
Sessions that stage 1 flags — or ALL sessions when the caller opts for
exhaustive mode — get stage 2.

Honest limits: the scan reads the ledger as stored (tampered rows raise
LedgerError and abort the scan — fail closed); detectors are structural
screens so retro-findings carry MEDIUM confidence regardless of the
live detector's severity; and the scan cannot recover events that were
never recorded (coverage gaps stay honest via ``evidence_incomplete``).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from agenttrace.graph.evidence_boundary import EvidenceClass, event_evidence_class
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    IncidentEvent,
    NetworkEvent,
    ToolResultEvent,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

# Stage-1 wide-net patterns. Deliberately broad: stage 1 only nominates
# sessions for stage 2, so false positives cost focused review, not verdicts.
_STAGE1_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        (
            "public_ip",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        ),
        ("url", r"https?://[^\s\"'<>]+"),
        (
            "registry_publish",
            r"\b(?:twine\s+upload|npm\s+publish|dotnet\s+nuget\s+push)\b",
        ),
        (
            "credential_material",
            r"\b(?:api[_-]?key|secret[_-]?key|private[_-]?key|"
            r"aws_secret_access_key|xox[baprs]-|ghp_[A-Za-z0-9]{20,})\b"
        ),
        (
            "reverse_shell",
            r"(?:\bnc\s+-e|\bncat\s+-e|/dev/tcp/|\bsocat\s+TCP:|\bmkfifo.*nc)",
        ),
    )
)


@dataclass(frozen=True)
class Stage1Hit:
    """One wide-net pattern hit inside one stored event."""

    session_id: UUID
    event_id: str
    pattern_name: str
    excerpt: str
    timestamp: datetime


@dataclass(frozen=True)
class RetroScanReport:
    """Result of one retro-scan run over the ledger."""

    started_at: datetime
    finished_at: datetime
    sessions_scanned: int
    events_scanned: int
    stage1_hits: tuple[Stage1Hit, ...] = field(default_factory=tuple)
    sessions_stage2: tuple[UUID, ...] = field(default_factory=tuple)
    retro_incidents: tuple[IncidentEvent, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        lines = [
            f"Retro-scan {self.started_at.isoformat()} → {self.finished_at.isoformat()}: "
            f"{self.sessions_scanned} sessions, {self.events_scanned} events scanned.",
            f"Stage 1 (wide net): {len(self.stage1_hits)} hits across "
            f"{len({h.session_id for h in self.stage1_hits})} sessions.",
            f"Stage 2 (focused detector replay): {len(self.sessions_stage2)} sessions "
            f"→ {len(self.retro_incidents)} retro incidents.",
        ]
        if self.errors:
            lines.append(f"Errors ({len(self.errors)}): " + "; ".join(self.errors[:5]))
        return "\n".join(lines)


def stage1_screen(events: Iterable[EventBase], session_id: UUID) -> list[Stage1Hit]:
    """Stage 1: cheap deterministic triage over agent narratives."""
    hits: list[Stage1Hit] = []
    for event in events:
        if event_evidence_class(event) is not EvidenceClass.AGENT_CLAIMED:
            continue
        text = _narrative_text(event)
        if not text:
            continue
        for name, pattern in _STAGE1_PATTERNS:
            m = pattern.search(text)
            if m:
                start = max(0, m.start() - 40)
                hits.append(Stage1Hit(
                    session_id=session_id,
                    event_id=str(event.event_id),
                    pattern_name=name,
                    excerpt=" ".join(text[start:m.end() + 40].split()),
                    timestamp=event.timestamp,
                ))
    return hits


def _narrative_text(event: EventBase) -> str:
    if isinstance(event, CommandEvent):
        return f"{event.command}\n{event.output}"
    if isinstance(event, NetworkEvent):
        return f"{event.protocol} {event.destination_ip}:{event.destination_port}"
    if isinstance(event, ToolResultEvent):
        return event.output_summary
    payload_text = event.payload.get("reasoning", "")
    return str(payload_text) if payload_text else ""


class RetroScan:
    """Two-stage re-scan of stored sessions with the current detector arsenal."""

    def __init__(
        self,
        ledger: Any,
        *,
        stage2_batch_size: int = 2000,
    ) -> None:
        self._ledger = ledger
        self._stage2_batch_size = stage2_batch_size

    # -- Public API -----------------------------------------------------------

    def scan(
        self,
        *,
        session_ids: list[UUID] | None = None,
        exhaustive: bool = False,
        engine_factory: Callable[[UUID], Any] | None = None,
    ) -> RetroScanReport:
        """Scan stored sessions. session_ids=None scans every stored session.

        ``engine_factory`` builds a DetectionEngine for stage 2; when it is
        None, stage 2 replays through the same DEFAULT_DETECTORS rules
        engine the live pipeline uses.
        """
        started = datetime.now(timezone.utc)
        from agenttrace.security.detectors import DetectionEngine

        factory = engine_factory or (
            lambda sid: DetectionEngine(sid, workspace_paths=[])
        )
        errors: list[str] = []
        all_hits: list[Stage1Hit] = []
        stage2_ids: list[UUID] = []
        retro_incidents: list[IncidentEvent] = []

        targets = self._resolve_targets(session_ids)
        events_scanned = 0
        for sid in targets:
            try:
                events = self._read_all_events(sid)
            except Exception as exc:  # noqa: BLE001 — fail-closed per session
                errors.append(f"{sid}: {type(exc).__name__}: {exc}")
                continue
            events_scanned += len(events)
            hits = stage1_screen(events, sid)
            all_hits.extend(hits)
            if hits or exhaustive:
                stage2_ids.append(sid)
                engine = factory(sid)
                for event in events:
                    try:
                        for finding in engine.evaluate(event):
                            retro_incidents.append(
                                self._finding_to_incident(sid, event, finding)
                            )
                    except Exception as exc:  # noqa: BLE001 — one bad event
                        errors.append(
                            f"{sid}/{event.event_id}: {type(exc).__name__}: {exc}"
                        )

        return RetroScanReport(
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            sessions_scanned=len(targets),
            events_scanned=events_scanned,
            stage1_hits=tuple(all_hits),
            sessions_stage2=tuple(stage2_ids),
            retro_incidents=tuple(retro_incidents),
            errors=tuple(errors),
        )

    # -- Internals -------------------------------------------------------------

    def _resolve_targets(self, session_ids: list[UUID] | None) -> list[UUID]:
        if session_ids is not None:
            return list(session_ids)
        rows = self._ledger.list_sessions()
        return [UUID(r["session_id"]) for r in rows]

    def _read_all_events(self, sid: UUID) -> list[EventBase]:
        """Read a session's full event stream; tampered rows abort (fail closed)."""
        events: list[EventBase] = []
        offset_marker: str | None = None
        while True:
            batch = self._ledger.query_events(
                sid,
                after=offset_marker,
                limit=self._stage2_batch_size,
            )
            if not batch:
                break
            events.extend(batch)
            last = batch[-1]
            offset_marker = last.timestamp.isoformat()
            if len(batch) < self._stage2_batch_size:
                break
        return events

    def _finding_to_incident(
        self, sid: UUID, event: EventBase, finding: Any
    ) -> IncidentEvent:
        detector_id = getattr(finding, "detector_id", "unknown")
        description = getattr(finding, "description", "") or str(finding)
        severity = getattr(finding, "severity", "medium")
        return IncidentEvent(
            session_id=sid,
            actor_id="retro_scan",
            source_adapter="retro_scan",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=f"retro_{detector_id}",
            severity=severity if severity in {"critical", "high", "medium", "low"} else "medium",
            title=f"Retro-scan: {detector_id} on historical event",
            description=(
                f"[retro_scan] Detector '{detector_id}' (shipped after this "
                "session was recorded) flagged a stored event: "
                f"{description}. Two-stage wide-net re-scan per the "
                "Anthropic assessment methodology — pattern triage first, "
                "full detector replay second. Provenance: derived from the "
                "hash-chained ledger, not live observation."
            ),
            related_events=[str(event.event_id)],
            causal_path=[str(event.event_id)],
            timestamp=event.timestamp,
        )

