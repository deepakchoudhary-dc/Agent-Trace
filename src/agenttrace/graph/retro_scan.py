"""Historical retro-scan — the "wide net" over stored history (ant.md P1 #4).

Anthropic's own detection pipeline is the failure mode to design
against: an agentic search over ~141,000 transcripts MISSED a fourth
incident, found only by accident months later. The corrected
methodology is a two-stage wide-net re-scan of everything already
stored — cheap exhaustive pattern triage first, focused review second —
not a single agentic pass.

``RetroScan`` re-runs the **current** detector arsenal over stored
sessions, so a detector shipped after a session closed can still
retro-flag it. Findings become new hash-chained ``IncidentEvent``s
anchored to the historical events, clearly marked ``retro_scan``
provenance with the detector set that produced them.

Stage 1 (wide net): deterministic regex triage over every stored
command/network/tool narrative — public IPs, URLs, registry publishes,
credential material. Every session is screened; nothing is skipped. A
filesystem-volume nominator promotes sessions with heavy write activity
to stage 2 even without a regex hit: structural detectors (covert
channels, message boards) are invisible to narrative regexes by
construction.

Stage 2 (focused): the session's events are replayed through the
DetectionEngine rules engine AND the graph detector corpus — the same
per-session engines the live ingest pipeline constructs, built fresh
per session (covert-channel, tool-claim reconciler, hesitation,
eval-integrity, cot-realism, identity-chain, continuation-risk,
containment-escape) — plus the daemon-wide engines (post-exit,
credential-loops, meta-anomaly, actor-identity) rebuilt once and fed
the full timestamp-merged stream across ALL scanned sessions, with
session-close hooks replayed at each session's last event. The
daemon-wide engines must see every session's events to rebuild
cross-session state: an artifact shared between two sessions is
detectable only if the first install is known when the second is
replayed, even if the first session itself was not nominated.

Honest limits: the scan reads the ledger as stored (tampered rows raise
LedgerError and abort the scan — fail closed); detectors are structural
screens so retro-findings carry MEDIUM confidence regardless of the
live detector's severity; replay constructs FRESH engines, so
daemon-wide state is rebuilt from the scanned sessions only (sessions
outside the scan scope contribute nothing); the merged stream is held
in memory for the duration of the scan (single-host scale); internal
detector cooldowns suppress repeat firings exactly as they do live;
the scan cannot recover events that were never recorded (coverage gaps
stay honest via ``evidence_incomplete``); and containment-escape replay
is skipped for sessions whose configuration (workspace root) cannot be
reconstructed — the boundary is never guessed.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

from agenttrace.graph.actor_identity import ActorIdentityGraph
from agenttrace.graph.containment_escape import ContainmentEscapeDetector
from agenttrace.graph.continuation_risk import ContinuationRiskTracker
from agenttrace.graph.cot_realism import CoTRealismDivergenceDetector
from agenttrace.graph.covert_channel import CovertChannelDetector
from agenttrace.graph.credential_loops import CredentialLoopTracker
from agenttrace.graph.eval_integrity import SandbaggingDetector, task_is_safety_flavored
from agenttrace.graph.evidence_boundary import (
    EvidenceClass,
    ToolClaimReconciler,
    event_evidence_class,
)
from agenttrace.graph.hesitation import HesitationDetector
from agenttrace.graph.identity_chain import IdentityBootstrapDetector
from agenttrace.graph.meta_detection import MetaAnomalyDetector
from agenttrace.graph.post_exit import PostExitRegistry
from agenttrace.graph.severity import (
    DEFAULT_THRESHOLD,
    SeverityCalibration,
    calibrate,
    negative_result_statement,
)
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
    NetworkEvent,
    PolicyFindingEvent,
    ToolResultEvent,
)
from agenttrace.models.session import SessionConfig
from agenttrace.models.task_contract import RiskLevel, TaskContract

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

# A session with at least this many file mutations is nominated to stage 2
# regardless of narrative regex hits: structural detectors work on the
# filesystem event stream, which stage-1 regexes never see.
_FILE_VOLUME_NOMINATION = 32

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
    graph_detectors_applied: tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        lines = [
            f"Retro-scan {self.started_at.isoformat()} → {self.finished_at.isoformat()}: "
            f"{self.sessions_scanned} sessions, {self.events_scanned} events scanned.",
            f"Stage 1 (wide net): {len(self.stage1_hits)} hits across "
            f"{len({h.session_id for h in self.stage1_hits})} sessions.",
            f"Stage 2 (focused detector replay): {len(self.sessions_stage2)} sessions "
            f"→ {len(self.retro_incidents)} retro incidents.",
        ]
        if self.graph_detectors_applied:
            lines.append(
                f"Graph-detector replay: {len(self.graph_detectors_applied)} engines "
                f"({', '.join(self.graph_detectors_applied)})."
            )
        if self.errors:
            lines.append(f"Errors ({len(self.errors)}): " + "; ".join(self.errors[:5]))
        return "\n".join(lines)

    def calibration(self) -> SeverityCalibration:
        """Severity distribution of the incidents this scan surfaced (P2 #10).

        Calibrating the scan's own output is what makes its conclusion
        comparable with an earlier sweep's: "nothing of similar or worse
        severity" is only checkable against one ordered scale.
        """
        return calibrate(self.retro_incidents)

    def negative_result(
        self,
        *,
        threshold: str = DEFAULT_THRESHOLD,
        detectors_applied: int | None = None,
    ) -> str:
        """The sweep's result — positive or negative — with its coverage gap."""
        if detectors_applied is None and self.graph_detectors_applied:
            # Rules engine (1) + every graph engine actually replayed.
            detectors_applied = len(self.graph_detectors_applied) + 1
        return negative_result_statement(
            self.calibration(),
            threshold=threshold,
            sessions_scanned=self.sessions_scanned,
            events_scanned=self.events_scanned,
            errors=self.errors,
            detectors_applied=detectors_applied,
        )


def stage1_screen(events: Iterable[EventBase], session_id: UUID) -> list[Stage1Hit]:
    """Stage 1: cheap deterministic triage over agent narratives.

    The filesystem-volume nominator runs regardless of evidence class:
    OS-observed write volume is exactly what structural detectors need,
    and no narrative regex can nominate for them.
    """
    hits: list[Stage1Hit] = []
    file_writes = 0
    last_file: FileMutationEvent | None = None
    for event in events:
        if isinstance(event, FileMutationEvent):
            file_writes += 1
            last_file = event
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
    if last_file is not None and file_writes >= _FILE_VOLUME_NOMINATION:
        hits.append(Stage1Hit(
            session_id=session_id,
            event_id=str(last_file.event_id),
            pattern_name="filesystem_volume",
            excerpt=(
                f"{file_writes} file mutations observed "
                "(structural-detector nominator)"
            ),
            timestamp=last_file.timestamp,
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


class _Observer(Protocol):
    """Anything the live pipeline feeds events through one at a time."""

    def observe(self, event: EventBase) -> list[Any]: ...


def _contract_boundary(contract: TaskContract | None) -> list[str] | None:
    """Containment-escape boundary for replay.

    Mirrors the daemon's ``_escape_boundary_paths``: the tighter declared
    scope when the contract supplies one, otherwise None (the detector
    falls back to the session's workspace root).
    """
    if contract is not None and contract.allowed_paths and contract.allowed_paths != ["*"]:
        return list(contract.allowed_paths)
    return None


def _load_replay_context(
    ledger: Any, sid: UUID
) -> tuple[SessionConfig | None, TaskContract | None]:
    """Reconstruct a session's config and task contract from the ledger.

    Both are best-effort: a session whose config or contract cannot be
    read replays with default engine configuration and, for
    containment-escape, is skipped entirely rather than scanned against
    a guessed boundary. Stub ledgers in tests simply lack the methods.
    """
    config: SessionConfig | None = None
    get_session = getattr(ledger, "get_session", None)
    if callable(get_session):
        try:
            row = get_session(sid)
            if row and row.get("config_json"):
                config = SessionConfig.model_validate_json(row["config_json"])
        except Exception:  # noqa: BLE001 — degrade honestly, never guess
            config = None

    contract: TaskContract | None = None
    get_contract = getattr(ledger, "get_task_contract", None)
    if callable(get_contract):
        try:
            cd = get_contract(sid)
        except Exception:  # noqa: BLE001
            cd = None
        if cd:
            try:
                contract = TaskContract(
                    contract_id=UUID(str(cd.get("contract_id") or uuid4())),
                    session_id=sid,
                    goal=cd.get("goal", ""),
                    allowed_paths=cd.get("allowed_paths", []),
                    prohibited_paths=cd.get("prohibited_paths", []),
                    expected_tests=cd.get("expected_tests", []),
                    allowed_tools=cd.get("allowed_tools", []),
                    risk_level=RiskLevel(cd.get("risk_level", "medium")),
                )
            except Exception:  # noqa: BLE001
                contract = None
    return config, contract


class _GraphReplay:
    """Fresh graph detectors replaying stored events.

    Per-session engines mirror the live pipeline's ``create_session``
    construction argument-for-argument. Daemon-wide engines are built
    once per scan and observe the full merged stream, so cross-session
    patterns (shared persistence artifacts, credential loops, dossier
    handoffs) re-emerge exactly as they did live.
    """

    def __init__(self, ledger: Any, stage2_sessions: set[UUID]) -> None:
        self.post_exit = PostExitRegistry()
        self.credential = CredentialLoopTracker()
        self.meta = MetaAnomalyDetector()
        self.actor = ActorIdentityGraph()
        self._shared: list[_Observer] = [
            self.post_exit,
            self.credential,
            self.meta,
            self.actor,
        ]
        self._boundary_reconstructable = False
        self._per_session: dict[UUID, list[_Observer]] = {}
        for sid in stage2_sessions:
            config, contract = _load_replay_context(ledger, sid)
            engines: list[_Observer] = [
                CovertChannelDetector(sid),
                ToolClaimReconciler(sid),
                HesitationDetector(sid),
                SandbaggingDetector(
                    sid,
                    safety_flavored=task_is_safety_flavored(
                        contract.goal if contract else "",
                        contract.risk_level.value if contract else "medium",
                    ),
                    task_goal=contract.goal if contract else "",
                ),
                CoTRealismDivergenceDetector(sid),
                IdentityBootstrapDetector(sid),
                ContinuationRiskTracker(sid),
            ]
            if config is not None:
                engines.append(ContainmentEscapeDetector(
                    sid,
                    workspace_root=config.workspace_path,
                    allowed_paths=_contract_boundary(contract),
                ))
                self._boundary_reconstructable = True
            self._per_session[sid] = engines

    @property
    def engine_names(self) -> tuple[str, ...]:
        names = [
            "post_exit",
            "credential_loops",
            "meta_anomaly",
            "actor_identity",
            "covert_channel",
            "tool_claim_reconciler",
            "hesitation",
            "eval_integrity",
            "cot_realism",
            "identity_chain",
            "continuation_risk",
        ]
        if self._boundary_reconstructable:
            names.append("containment_escape")
        return tuple(names)

    def feed(self, event: EventBase, sid: UUID) -> list[Any]:
        """Fold one stored event into every replayed engine."""
        out: list[Any] = []
        for engine in self._shared:
            out.extend(engine.observe(event))
        for engine in self._per_session.get(sid, ()):
            out.extend(engine.observe(event))
        return out


_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def retro_incident_from_graph(obj: Any) -> IncidentEvent | None:
    """Map a replayed engine's output to a retro-provenance incident.

    Accepts both output types the corpus produces: ``IncidentEvent``
    (graph detectors) and ``PolicyFindingEvent`` (meta-anomaly). The
    original type, severity, related events and timestamp are preserved;
    provenance is restated as derived-from-ledger so a retro incident is
    never mistaken for a live observation.
    """
    if isinstance(obj, IncidentEvent):
        return IncidentEvent(
            session_id=obj.session_id,
            actor_id="retro_scan",
            source_adapter="retro_scan",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=obj.incident_type,
            severity=obj.severity if obj.severity in _VALID_SEVERITIES else "medium",
            title=f"Retro-scan: {obj.incident_type}",
            description=(
                f"{obj.description} [retro-scan replay over the sealed "
                "ledger; derived from stored events, not live observation]"
            ),
            related_events=list(obj.related_events),
            causal_path=list(obj.causal_path),
            timestamp=obj.timestamp,
        )
    if isinstance(obj, PolicyFindingEvent):
        return IncidentEvent(
            session_id=obj.session_id,
            actor_id="retro_scan",
            source_adapter="retro_scan",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=obj.finding_type,
            severity=obj.severity if obj.severity in _VALID_SEVERITIES else "medium",
            title=f"Retro-scan: {obj.finding_type}",
            description=(
                f"{obj.description} [retro-scan replay over the sealed "
                "ledger; derived from stored events, not live observation]"
            ),
            related_events=[str(r) for r in obj.evidence_refs],
            causal_path=[str(r) for r in obj.evidence_refs],
            timestamp=obj.timestamp,
        )
    return None


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

        ``engine_factory`` builds the rules engine for stage 2; when it is
        None, stage 2 replays through the same DEFAULT_DETECTORS rules
        engine the live pipeline uses. The graph corpus is always replayed
        alongside it, constructed exactly as the live pipeline constructs
        it (see ``_GraphReplay``).
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
        per_session: dict[UUID, list[EventBase]] = {}
        events_scanned = 0
        for sid in targets:
            try:
                events = self._read_all_events(sid)
            except Exception as exc:  # noqa: BLE001 — fail-closed per session
                errors.append(f"{sid}: {type(exc).__name__}: {exc}")
                continue
            events_scanned += len(events)
            per_session[sid] = events

        graph_names: tuple[str, ...] = ()
        if per_session:
            # Stage 1: nominate sessions for the focused replay.
            stage2_set: set[UUID] = set()
            for sid, events in per_session.items():
                hits = stage1_screen(events, sid)
                all_hits.extend(hits)
                if hits or exhaustive:
                    stage2_set.add(sid)
                    stage2_ids.append(sid)

            # Stage 2: rules engine per nominated session + the graph corpus.
            # Shared engines see the FULL merged stream (cross-session state
            # requires every session's events); per-session engines only run
            # for nominated sessions, mirroring live per-session construction.
            graph = _GraphReplay(self._ledger, stage2_set)
            graph_names = graph.engine_names
            rules_engines: dict[UUID, Any] = {
                sid: factory(sid) for sid in stage2_set
            }

            merged: list[tuple[datetime, UUID, EventBase]] = sorted(
                (
                    (event.timestamp, sid, event)
                    for sid, events in per_session.items()
                    for event in events
                ),
                key=lambda t: (t[0], str(t[1])),
            )
            closes: list[tuple[datetime, UUID]] = sorted(
                (
                    (max(event.timestamp for event in events), sid)
                    for sid, events in per_session.items()
                    if events
                ),
                key=lambda t: (t[0], str(t[1])),
            )
            close_idx = 0
            for ts, sid, event in merged:
                # Replay each session's close hooks at its last event time,
                # in stream order — persistence summaries, credential
                # escalations and dossier candidates fire exactly where the
                # live daemon fires them.
                while close_idx < len(closes) and closes[close_idx][0] < ts:
                    close_ts, close_sid = closes[close_idx]
                    close_idx += 1
                    for incident in graph.post_exit.close_session(close_sid, close_ts):
                        mapped = retro_incident_from_graph(incident)
                        if mapped is not None:
                            retro_incidents.append(mapped)
                    graph.credential.mark_session_closed(close_sid)
                    # Live stop_session ignores the actor graph's close return;
                    # replay mirrors it.
                    graph.actor.close_session(close_sid, close_ts)
                try:
                    if sid in stage2_set:
                        for finding in rules_engines[sid].evaluate(event):
                            retro_incidents.append(
                                self._finding_to_incident(sid, event, finding)
                            )
                    outputs = graph.feed(event, sid)
                except Exception as exc:  # noqa: BLE001 — one bad event
                    errors.append(
                        f"{sid}/{event.event_id}: {type(exc).__name__}: {exc}"
                    )
                    continue
                for obj in outputs:
                    mapped = retro_incident_from_graph(obj)
                    if mapped is not None:
                        retro_incidents.append(mapped)
            while close_idx < len(closes):
                close_ts, close_sid = closes[close_idx]
                close_idx += 1
                for incident in graph.post_exit.close_session(close_sid, close_ts):
                    mapped = retro_incident_from_graph(incident)
                    if mapped is not None:
                        retro_incidents.append(mapped)
                graph.credential.mark_session_closed(close_sid)
                graph.actor.close_session(close_sid, close_ts)

        return RetroScanReport(
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            sessions_scanned=len(targets),
            events_scanned=events_scanned,
            stage1_hits=tuple(all_hits),
            sessions_stage2=tuple(stage2_ids),
            retro_incidents=tuple(retro_incidents),
            errors=tuple(errors),
            graph_detectors_applied=graph_names,
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
            severity=severity if severity in _VALID_SEVERITIES else "medium",
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
