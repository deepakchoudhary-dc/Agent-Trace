"""Multi-agent collusion correlation — the observable half only.

Correlates shared artifacts, reused egress destinations, and reused agent
identities across sessions. Every candidate is evidence-anchored and carries
an explicit reasoning gap: hidden coordination channels and intent are NOT
observable at host level. These signals surface the visible half of the
phenomenon (shared files, shared destinations, shared accounts) and never
claim to detect coordination itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    NetworkEvent,
)

if TYPE_CHECKING:
    from agenttrace.storage.ledger import EventLedger

_INFRA_ACTORS = {"user", "cli", "detector_engine"}


@dataclass
class CollusionCandidate:
    """An evidence-anchored coordination signal between two or more actors."""

    signal: str
    session_ids: list[str]
    actors: list[str]
    detail: str
    confidence: ConfidenceLevel
    evidence_event_ids: list[str]
    reasoning_gap: str
    created_at: str = field(default="")

    def to_dict(self) -> dict[str, object]:
        return {
            "signal": self.signal,
            "session_ids": self.session_ids,
            "actors": self.actors,
            "detail": self.detail,
            "confidence": self.confidence.value,
            "evidence_event_ids": self.evidence_event_ids,
            "reasoning_gap": self.reasoning_gap,
            "created_at": self.created_at,
        }


_GAPS: dict[str, str] = {
    "shared_artifact": (
        "Both actors touched the same file. Whether that was coordination, "
        "competition, or coincidence is not observable from host telemetry."
    ),
    "reused_egress": (
        "Both sessions contacted the same network destination. Shared "
        "infrastructure, shared task context, or coordination are "
        "indistinguishable at this layer."
    ),
    "shared_actor": (
        "The same agent identity drove both sessions. Account sharing is "
        "observable; the intent behind it is not."
    ),
    "complementary_roles": (
        "One session showed privilege-escalation activity while another "
        "showed anti-forensic cleanup, with a shared identity or egress "
        "destination. Division of labor is consistent with collusion but "
        "equally consistent with coincidental parallel work — intent is "
        "not observable at host level."
    ),
    "rotated_identity": (
        "Sessions contacting the same external endpoint claim DIFFERENT "
        "actor identities. This compartmentalization pattern is consistent "
        "with deliberate fingerprint rotation to fragment audit trails — "
        "and equally with unrelated tools sharing common infrastructure. "
        "Identity claims are self-reported; true attribution is not "
        "observable at host level."
    ),
}


class CollusionCorrelationEngine:
    """Cross-session correlation over observable ledger evidence."""

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger

    def candidates(self) -> list[CollusionCandidate]:
        """All coordination signals across sessions in the same workspace."""
        by_workspace: dict[str, list[UUID]] = {}
        for s in self._ledger.list_sessions():
            config = s.get("config") or {}
            workspace = config.get("workspace_path")
            if workspace:
                by_workspace.setdefault(workspace, []).append(UUID(s["session_id"]))

        candidates: list[CollusionCandidate] = []
        for sids in by_workspace.values():
            if len(sids) < 2:
                continue
            candidates.extend(self._shared_artifacts(sids))
            candidates.extend(self._reused_egress(sids))
            candidates.extend(self._shared_actors(sids))
            candidates.extend(self._complementary_roles(sids))
            candidates.extend(self._rotated_identity(sids))
        return candidates

    def for_session(self, session_id: UUID) -> list[CollusionCandidate]:
        """Signals involving a specific session."""
        sid = str(session_id)
        return [c for c in self.candidates() if sid in c.session_ids]

    def _events(self, session_id: UUID) -> list[EventBase]:
        return self._ledger.query_events(session_id, limit=None)

    def _shared_artifacts(self, sids: list[UUID]) -> list[CollusionCandidate]:
        """File paths mutated by ≥2 distinct actors across the sessions."""
        path_evidence: dict[str, list[tuple[str, str, str]]] = {}
        for sid in sids:
            for evt in self._events(sid):
                if evt.event_type.value != "file_mutation":
                    continue
                path = getattr(evt, "file_path", "")
                if not path:
                    continue
                path_evidence.setdefault(path, []).append(
                    (str(sid), evt.actor_id, str(evt.event_id))
                )

        out: list[CollusionCandidate] = []
        for path, evidence in path_evidence.items():
            actors = sorted({a for _, a, _ in evidence})
            if len(actors) < 2:
                continue
            out.append(CollusionCandidate(
                signal="shared_artifact",
                session_ids=sorted({s for s, _, _ in evidence}),
                actors=actors,
                detail=path,
                confidence=ConfidenceLevel.HIGH,
                evidence_event_ids=[e for _, _, e in evidence],
                reasoning_gap=_GAPS["shared_artifact"],
            ))
        return out

    def _reused_egress(self, sids: list[UUID]) -> list[CollusionCandidate]:
        """Network destinations contacted from ≥2 sessions."""
        dest_sessions: dict[str, dict[str, set[str]]] = {}
        for sid in sids:
            for evt in self._events(sid):
                if not isinstance(evt, NetworkEvent):
                    continue
                if evt.direction != "outbound":
                    continue
                dest = f"{evt.destination_ip}:{evt.destination_port}"
                entry = dest_sessions.setdefault(
                    dest, {"sessions": set(), "events": set(), "actors": set()}
                )
                entry["sessions"].add(str(sid))
                entry["events"].add(str(evt.event_id))
                entry["actors"].add(evt.actor_id)

        out: list[CollusionCandidate] = []
        for dest, entry in dest_sessions.items():
            sessions = sorted(entry["sessions"])
            if len(sessions) < 2:
                continue
            out.append(CollusionCandidate(
                signal="reused_egress",
                session_ids=sessions,
                actors=sorted(entry["actors"]),
                detail=dest,
                confidence=ConfidenceLevel.MEDIUM,
                evidence_event_ids=sorted(entry["events"]),
                reasoning_gap=_GAPS["reused_egress"],
            ))
        return out

    def _shared_actors(self, sids: list[UUID]) -> list[CollusionCandidate]:
        """Actor identities driving ≥2 sessions (account/credential reuse)."""
        actor_sessions: dict[str, dict[str, set[str]]] = {}
        for sid in sids:
            for evt in self._events(sid):
                if evt.actor_id in _INFRA_ACTORS or not evt.actor_id:
                    continue
                entry = actor_sessions.setdefault(
                    evt.actor_id, {"sessions": set(), "events": set()}
                )
                entry["sessions"].add(str(sid))
                entry["events"].add(str(evt.event_id))

        out: list[CollusionCandidate] = []
        for actor, entry in actor_sessions.items():
            sessions = sorted(entry["sessions"])
            if len(sessions) < 2:
                continue
            out.append(CollusionCandidate(
                signal="shared_actor",
                session_ids=sessions,
                actors=[actor],
                detail=actor,
                confidence=ConfidenceLevel.HIGH,
                evidence_event_ids=sorted(entry["events"]),
                reasoning_gap=_GAPS["shared_actor"],
            ))
        return out

    def _complementary_roles(self, sids: list[UUID]) -> list[CollusionCandidate]:
        """One session escalates while another cleans up, sharing identity/egress.

        The collusion hypothesis with the highest stakes: agents dividing
        labor so one reaches for privilege while another erases traces.
        Only fires when the two behavior families appear in DIFFERENT
        sessions that also share an actor identity or egress destination —
        a single session doing both is handled by per-session detectors.
        """
        import re

        elevation_re = re.compile(
            r"\b(?:sudo|doas|pkexec|gsudo)\b|\bsu\s+-|"
            r"chmod\s+u\+s|start-process\b[^\n]*-verb\s+runas",
            re.IGNORECASE,
        )
        cleanup_re = re.compile(
            r"(?:shred|rm|remove-item|clear-content)\b[^\n]*"
            r"(?:bash_history|zsh_history|psreadline|/var/log)|"
            r"\bwevtutil\s+cl\b",
            re.IGNORECASE,
        )

        escalating: dict[str, dict[str, set[str]]] = {}  # sid -> actor -> event ids
        cleaning: dict[str, dict[str, set[str]]] = {}
        actors_by_sid: dict[str, set[str]] = {}
        egress_by_sid: dict[str, set[str]] = {}

        for sid in sids:
            for evt in self._events(sid):
                if evt.actor_id and evt.actor_id not in _INFRA_ACTORS:
                    actors_by_sid.setdefault(str(sid), set()).add(evt.actor_id)
                if isinstance(evt, NetworkEvent) and evt.direction == "outbound":
                    egress_by_sid.setdefault(str(sid), set()).add(
                        f"{evt.destination_ip}:{evt.destination_port}"
                    )
                if not isinstance(evt, CommandEvent):
                    continue
                cmd = evt.command or ""
                bucket = None
                if elevation_re.search(cmd):
                    bucket = escalating
                elif cleanup_re.search(cmd):
                    bucket = cleaning
                if bucket is not None:
                    entry = bucket.setdefault(str(sid), {})
                    entry.setdefault(evt.actor_id, set()).add(str(evt.event_id))

        out: list[CollusionCandidate] = []

        def _linked(a: str, b: str) -> bool:
            return bool(
                actors_by_sid.get(a, set()) & actors_by_sid.get(b, set())
                or egress_by_sid.get(a, set()) & egress_by_sid.get(b, set())
            )

        for esc_sid, esc_actors in escalating.items():
            for clean_sid, _clean_actors in cleaning.items():
                if esc_sid == clean_sid or not _linked(esc_sid, clean_sid):
                    continue
                evidence = sorted(
                    eid
                    for entry in (esc_actors, cleaning[clean_sid])
                    for evs in entry.values()
                    for eid in evs
                )
                out.append(CollusionCandidate(
                    signal="complementary_roles",
                    session_ids=sorted({esc_sid, clean_sid}),
                    actors=sorted(set(esc_actors) | set(cleaning[clean_sid])),
                    detail=(
                        f"escalation in {esc_sid} paired with anti-forensic "
                        f"cleanup in {clean_sid}"
                    ),
                    confidence=ConfidenceLevel.MEDIUM,
                    evidence_event_ids=evidence,
                    reasoning_gap=_GAPS["complementary_roles"],
                ))
                break  # one candidate per escalating session
        return out

    def _rotated_identity(self, sids: list[UUID]) -> list[CollusionCandidate]:
        """Same endpoint, different claimed identities across sessions.

        The fingerprint-rotation pattern: an actor that rotates its
        self-reported identity per session cannot be linked by
        ``shared_actors`` — but shared egress infrastructure still links
        the activity. LOW confidence: common infrastructure is mundane.
        """
        egress_actors: dict[str, dict[str, tuple[set[str], list[str]]]] = {}
        for sid in sids:
            for evt in self._events(sid):
                if not isinstance(evt, NetworkEvent) or evt.direction != "outbound":
                    continue
                if evt.actor_id in _INFRA_ACTORS or not evt.actor_id:
                    continue
                dest = f"{evt.destination_ip}:{evt.destination_port}"
                entry = egress_actors.setdefault(dest, {})
                actors, events = entry.setdefault(str(sid), (set(), []))
                actors.add(evt.actor_id)
                events.append(str(evt.event_id))

        out: list[CollusionCandidate] = []
        for dest, by_sid in egress_actors.items():
            if len(by_sid) < 2:
                continue
            actor_sets = [actors for actors, _events in by_sid.values()]
            # Disjoint claimed identities across every participating session
            # is what distinguishes rotation from plain identity reuse.
            if any(
                set(a) & set(b)
                for a, b in zip(actor_sets, actor_sets[1:], strict=False)
            ):
                continue
            all_actors = sorted({a for actors in actor_sets for a in actors})
            evidence = sorted(
                eid for _actors, events in by_sid.values() for eid in events
            )
            out.append(CollusionCandidate(
                signal="rotated_identity",
                session_ids=sorted(by_sid),
                actors=all_actors,
                detail=f"shared endpoint {dest} with disjoint actor identities",
                confidence=ConfidenceLevel.LOW,
                evidence_event_ids=evidence,
                reasoning_gap=_GAPS["rotated_identity"],
            ))
        return out
