"""Convention-free meta-detection and detector-decay monitoring (plan2.md
shortcoming #10).

Within four days of the METR incident, agents invented file-chunk protocols,
mailboxes, HOLD/VETO governance, automated reset telemetry, and message
signing — coordination technology evolves faster than any static detection
corpus. AgentTrace's detectors are regex/behavioral and point-in-time; they
detect the conventions that were written down. This module adds the layer
that does not need to know any convention:

- :class:`MetaAnomalyDetector` scores communication-shaped artifacts on pure
  structure — name-shape uniformity, size periodicity, cross-session
  directory sharing — instead of matching patterns. A mailbox protocol with
  names nobody has seen before still looks like eight same-shaped siblings
  in one directory with periodic sizes. Findings carry MEDIUM confidence
  and describe the statistics, never a guessed purpose (invariant #3: no
  fabricated explanations — the gap between "structurally anomalous" and
  "covert channel" stays visible).
- :class:`DetectorStalenessMonitor` is the detector-decay process: a
  rolling per-detector fire-rate census that, at session close, flags
  detectors that have never fired across many sessions (stale — the
  corpus no longer matches current behavior) and detectors that fire on
  most events (over-firing — threshold decay), as low-severity findings
  for corpus maintenance.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
    PolicyFindingEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Structural candidates must clear this bar; tuned above the scores benign
# workspaces produce in tests (see tests/test_meta_detection.py).
_ANOMALY_THRESHOLD = 5.0
_MIN_SIBLINGS = 8


def _name_shape(name: str) -> str:
    """Character-class template of a filename: the convention-free shape."""
    shape: list[str] = []
    for ch in name:
        if ch.isalpha():
            shape.append("A" if ch.isupper() else "a")
        elif ch.isdigit():
            shape.append("9")
        elif ch in "-_.":
            shape.append(ch)
        else:
            shape.append("*")
    return "".join(shape)


class MetaAnomalyDetector:
    """Convention-free structural anomaly scoring over communication-shaped
    artifacts, with a cross-session sharing view (daemon-wide)."""

    def __init__(
        self,
        *,
        threshold: float = _ANOMALY_THRESHOLD,
        min_siblings: int = _MIN_SIBLINGS,
        cooldown: timedelta | None = None,
    ) -> None:
        self._threshold = threshold
        self._min_siblings = min_siblings
        self._cooldown = cooldown if cooldown is not None else timedelta(minutes=15)
        # parent dir -> deque of (stem, size, session, event_id)
        self._dirs: dict[str, deque[tuple[str, int, UUID, str]]] = defaultdict(
            lambda: deque(maxlen=64)
        )
        self._last_emitted: dict[str, datetime] = {}

    def observe(self, event: EventBase) -> list[PolicyFindingEvent]:
        """Feed one event; returns structural-anomaly findings when they fire."""
        if isinstance(event, (IncidentEvent, PolicyFindingEvent)):
            return []
        if not isinstance(event, FileMutationEvent):
            return []
        if event.mutation_type not in ("create", "modify"):
            return []

        path = event.file_path.replace("\\", "/")
        parent = path.rsplit("/", 1)[0] if "/" in path else path
        stem = path.rsplit("/", 1)[1] if "/" in path else path
        self._dirs[parent].append(
            (stem, max(event.size_delta, 0), event.session_id, str(event.event_id))
        )
        if len(self._dirs[parent]) < self._min_siblings:
            return []
        return self._score_directory(parent, event)

    def _score_directory(self, parent: str, trigger: FileMutationEvent) -> list[PolicyFindingEvent]:
        siblings = list(self._dirs[parent])
        names = [s for s, _, _, _ in siblings]
        sizes = [sz for _, sz, _, _ in siblings]
        shape_uniformity = self._shape_uniformity(names)
        size_periodicity = self._size_periodicity(sizes)
        cross_session = self._cross_session_share(siblings)
        score = shape_uniformity + size_periodicity + cross_session
        if score < self._threshold:
            return []
        key = f"meta:{parent}"
        now = trigger.timestamp
        last = self._last_emitted.get(key)
        if last is not None and now - last < self._cooldown:
            return []
        self._last_emitted[key] = now
        detail = (
            f"parent_dir={parent} siblings={len(siblings)} "
            f"shape_uniformity={shape_uniformity:.2f} "
            f"size_periodicity={size_periodicity:.2f} "
            f"cross_session={cross_session:.2f} score={score:.2f}"
        )
        logger.warning("META-DETECTION: structural anomaly — %s", detail)
        return [
            PolicyFindingEvent(
                session_id=trigger.session_id,
                actor_id="meta_anomaly_detector",
                source_adapter="meta_anomaly_detector",
                confidence=ConfidenceLevel.MEDIUM,
                finding_type="structural_anomaly",
                severity="medium",
                description=(
                    "Convention-free structural anomaly in "
                    f"communication-shaped artifacts: {detail}. The score is "
                    "pure statistics (name-shape uniformity, size "
                    "periodicity, cross-session sharing) — it does not "
                    "identify a protocol, purpose, or content. Manual "
                    "review required; the gap between 'structurally "
                    "anomalous' and 'covert channel' is deliberately not "
                    "closed by this finding."
                ),
                affected_path=parent,
                evidence_refs=[e for _, _, _, e in siblings[-8:]],
                requires_approval=False,
            )
        ]

    @staticmethod
    def _shape_uniformity(names: list[str]) -> float:
        shapes = Counter(_name_shape(n) for n in names)
        dominant = max(shapes.values())
        base = 4.0 * (dominant / len(names))
        if dominant >= 8:
            base += 1.0
        return base

    @staticmethod
    def _size_periodicity(sizes: list[int]) -> float:
        """Score repeated equal sizes — the chunk-protocol signature.

        A transfer split into fixed-size chunks shows one dominant size;
        organic file activity produces varied sizes. Deliberately crude:
        this is a review pointer, not a protocol decoder.
        """
        nonzero = [sz for sz in sizes if sz > 0]
        if len(nonzero) < 4:
            return 0.0
        mode_count = Counter(nonzero).most_common(1)[0][1]
        if mode_count / len(sizes) < 0.6:
            return 0.0
        return 2.5

    @staticmethod
    def _cross_session_share(
        siblings: list[tuple[str, int, UUID, str]],
    ) -> float:
        sessions = {sid for _, _, sid, _ in siblings}
        return 2.0 if len(sessions) >= 2 else 0.0


class DetectorStalenessMonitor:
    """Detector-decay census: rolling per-detector fire rates across sessions.

    A static corpus decays in two directions: conventions move on and
    detectors go silent (stale), or thresholds drift and detectors fire
    on everything (over-firing). Neither is visible in a single session —
    they only show in aggregate — so the census is daemon-wide and
    findings are emitted when a session close tips the census past its
    session minimum. Findings are maintenance signals about the detector
    corpus, never claims about the audited agent.
    """

    def __init__(
        self,
        *,
        detector_ids: list[str],
        min_sessions: int = 5,
        stale_session_ratio: float = 0.2,
        overfire_event_ratio: float = 0.5,
        cooldown: timedelta | None = None,
    ) -> None:
        self._detector_ids = list(detector_ids)
        self._min_sessions = min_sessions
        self._stale_ratio = stale_session_ratio
        self._overfire_ratio = overfire_event_ratio
        self._cooldown = cooldown if cooldown is not None else timedelta(hours=6)
        self._events_seen: dict[UUID, int] = {}
        self._fires: dict[UUID, Counter[str]] = defaultdict(Counter)
        self._closed: set[UUID] = set()
        self._last_emitted: dict[str, datetime] = {}

    def record_event(self, session_id: UUID) -> None:
        """Census one evaluated event (every event reaches every detector)."""
        self._events_seen[session_id] = self._events_seen.get(session_id, 0) + 1

    def record_fire(self, session_id: UUID, detector_id: str) -> None:
        """Census one detector firing."""
        self._fires[session_id][detector_id] += 1

    def close_session(
        self, session_id: UUID, now: datetime
    ) -> list[PolicyFindingEvent]:
        """Fold a closing session into the census; emit decay findings once
        enough sessions have accumulated (cooldown-throttled)."""
        self._closed.add(session_id)
        if len(self._closed) < self._min_sessions:
            return []
        last = self._last_emitted.get("detector_decay_census")
        if last is not None and now - last < self._cooldown:
            return []
        self._last_emitted["detector_decay_census"] = now
        return self._census_findings(session_id, now)

    def _census_findings(
        self, closing_session: UUID, now: datetime
    ) -> list[PolicyFindingEvent]:
        sessions = len(self._closed)
        total_events = sum(self._events_seen.values())
        findings: list[PolicyFindingEvent] = []
        for detector_id in self._detector_ids:
            firing_sessions = sum(
                1 for counts in self._fires.values() if counts[detector_id] > 0
            )
            total_fires = sum(counts[detector_id] for counts in self._fires.values())
            detail = (
                f"detector={detector_id} fired in {firing_sessions}/{sessions} "
                f"completed sessions ({total_fires} findings over "
                f"{total_events} evaluated events)"
            )
            if firing_sessions <= self._stale_ratio * sessions and total_fires == 0:
                findings.append(self._decay_finding(
                    closing_session,
                    "detector_staleness",
                    (
                        f"Stale detector: {detail}. The corpus may no longer "
                        "match current agent behavior — review for staleness. "
                        "This is a maintenance signal about the detector, not "
                        "a finding about the audited agent."
                    ),
                    now,
                ))
            elif (
                total_events > 0
                and total_fires / total_events > self._overfire_ratio
                and firing_sessions >= sessions // 2
            ):
                findings.append(self._decay_finding(
                    closing_session,
                    "detector_overfire",
                    (
                        f"Over-firing detector: {detail} — above the "
                        f"{self._overfire_ratio:.0%} fire-rate bar, which "
                        "decays signal value. Review thresholds. Maintenance "
                        "signal, not an agent finding."
                    ),
                    now,
                ))
            if len(findings) >= 4:
                break
        return findings

    def _decay_finding(
        self,
        session_id: UUID,
        finding_type: str,
        description: str,
        now: datetime,
    ) -> PolicyFindingEvent:
        return PolicyFindingEvent(
            session_id=session_id,
            actor_id="staleness_monitor",
            source_adapter="staleness_monitor",
            confidence=ConfidenceLevel.HIGH,
            finding_type=finding_type,
            severity="low",
            description=description,
            requires_approval=False,
            timestamp=now,
        )
