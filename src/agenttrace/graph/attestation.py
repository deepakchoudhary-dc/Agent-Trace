"""Process attestation — kernel-bound attribution vs the narrative's claims
(plan2 P1.2 residual, architectural debt #2, METR #2's attribution half).

Every honest assessment of this product has flagged the same weakest link:
"which agent did it" rests on harness-provided actor_id strings — claim-class
evidence. A sophisticated agent can invent handles, veto itself as a second
agent, or attribute its egress to a peer. The kernel does not have to trust
anyone's story:

- Containment membership is kernel truth. When a pid is assigned into a
  session's Job Object / cgroup (``register_session_pid`` and the observer
  sweep), that pid BELONGS to that session — no claim can change it.
- Process Events from the process-tree, auditd, and ETW sensors give the
  pid -> ppid chains: the real lineage of who spawned what.

This engine joins the two and emits incidents when the narrative contradicts
the kernel:

- ``process_attestation_conflict`` (high) — a session narrates a process the
  kernel has bound to a DIFFERENT session's containment unit.
- ``egress_attribution_contradiction`` (high) — a session's ledger records
  network egress from a pid whose lineage roots in another session's
  kernel-bound process tree: one agent's traffic wearing another audit
  session's identity.

Honest boundaries (invariant #2): the kernel binding is observed; the
*contradiction* is derived correlation, so incidents carry MEDIUM confidence
with the lineage chain in the payload. Where no kernel binding exists the
engine stays silent — an unknown lineage is an honest gap, never a guess.
Attribution coverage is therefore proportional to containment coverage, and
both are disclosed by the #9 accounting rather than implied.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    ConfidenceLevel,
    EventBase,
    IncidentEvent,
    NetworkEvent,
    ProcessEvent,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

logger = logging.getLogger(__name__)

# Lineage walk and state bounds: a pid chain deeper than this is treated as
# unattestable (cycles and recycled-pid chains terminate here).
_MAX_LINEAGE_HOPS = 8
_MAX_LINEAGE_ENTRIES = 8192
# Kernel membership is re-synced at most this often per session: the binding
# itself is a kernel query, and ProcessEvents can be chatty.
_SYNC_THROTTLE_SECONDS = 5.0

_CONFLICT_COOLDOWN = timedelta(minutes=10)
_MAX_COOLDOWN_KEYS = 4096


class ProcessAttestationEngine:
    """Daemon-wide kernel-bound pid ownership vs narrative attribution.

    Kernel bindings come from real containment assignments; lineage comes
    from observed ProcessEvents; incidents fire only on contradictions
    between the two. State rebuilds silently from ledger history
    (:meth:`seed_event`) except kernel bindings, which are not restorable —
    containment is re-armed fresh after a restart, and the old binding of a
    dead unit must not outlive it.
    """

    def __init__(self) -> None:
        # pid -> (session_id, bound_at): kernel-verified ownership
        self._kernel_bound: dict[int, tuple[UUID, datetime]] = {}
        # pids bound via bind_kernel_root (kernel-verified assignment, not
        # sweep-absorbed). Sync sweeps may prune members they absorbed, never
        # these: an assigned root's lifecycle ends with its unit's release
        # (drop_session), not with any single sweep's best-effort snapshot.
        self._explicit_pins: set[int] = set()
        # pid -> (ppid, session_id, first_seen): observed lineage
        self._lineage: OrderedDict[int, tuple[int, UUID, datetime]] = OrderedDict()
        self._sync_at: dict[UUID, float] = {}
        self._last_emitted: dict[str, datetime] = {}

    # -- Kernel bindings ---------------------------------------------------------

    def bind_kernel_root(self, session_id: UUID, pid: int, now: datetime | None = None) -> None:
        """Record a kernel-verified containment assignment (P1.7-grade truth)."""
        if pid <= 0:
            # pid 0 is the cgroup pre-exec self-assign convention, never a
            # real process: binding it would make os.kill(0) semantics leak
            # into attribution.
            return
        self._kernel_bound[pid] = (session_id, now or datetime.now(timezone.utc))
        self._explicit_pins.add(pid)

    def drop_session(self, session_id: UUID) -> None:
        """Forget bindings when a session's containment unit is released."""
        dead = [pid for pid, (sid, _) in self._kernel_bound.items() if sid == session_id]
        for pid in dead:
            del self._kernel_bound[pid]
            self._explicit_pins.discard(pid)

    def sync_kernel_bindings(
        self, session_id: UUID, get_member_pids: Callable[[], list[int]]
    ) -> None:
        """Absorb current kernel membership (throttled per session).

        The containment sweep assigns pids directly through the provider, so
        membership grows without register_session_pid seeing it; syncing the
        live member list keeps the binding set equal to kernel truth. The
        fetcher is invoked ONLY inside the throttle window: it is a real
        kernel query (Job Object / cgroup read), and events can be chatty.
        Members absent from the live set are dropped — a pid the kernel no
        longer reports must not keep manufacturing contradictions — EXCEPT
        pids bound through :meth:`bind_kernel_root`: those are
        kernel-verified assignments (not sweep observations) whose lifecycle
        ends with the unit's release, so a sweep snapshot that transiently
        does not report them must never drop them.
        """
        now = time.monotonic()
        last = self._sync_at.get(session_id)
        if last is not None and now - last < _SYNC_THROTTLE_SECONDS:
            return
        self._sync_at[session_id] = now
        stamp = datetime.now(timezone.utc)
        live: set[int] = set()
        for pid in get_member_pids():
            if pid <= 0:
                continue
            live.add(pid)
            if pid not in self._kernel_bound:
                self._kernel_bound[pid] = (session_id, stamp)
        dead = [
            pid
            for pid, (sid, _) in self._kernel_bound.items()
            if (
                sid == session_id
                and pid not in live
                and pid not in self._explicit_pins
            )
        ]
        for pid in dead:
            del self._kernel_bound[pid]

    # -- Ingest -------------------------------------------------------------------

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one live event; return attribution-contradiction incidents."""
        if isinstance(event, IncidentEvent):
            return []
        incidents: list[IncidentEvent] = []
        if isinstance(event, ProcessEvent):
            incidents.extend(self._absorb_process(event))
        if isinstance(event, NetworkEvent):
            incidents.extend(self._attest_egress(event))
        return incidents

    def seed_event(self, event: EventBase) -> None:
        """Silent lineage rebuild from ledger history.

        Kernel bindings are intentionally NOT seeded: after a restart the
        containment units are new. Post-restart kernel truth therefore wins
        over pre-restart lineage — a fresh binding against old lineage is a
        live contradiction, while pre-restart bindings are simply absent
        (honest silence) until the new units sync.
        """
        if isinstance(event, ProcessEvent) and event.pid > 0:
            self._record_lineage(event)

    # -- Internals -----------------------------------------------------------------

    def _record_lineage(self, event: ProcessEvent) -> None:
        self._lineage[event.pid] = (event.ppid, event.session_id, event.timestamp)
        while len(self._lineage) > _MAX_LINEAGE_ENTRIES:
            self._lineage.popitem(last=False)

    def _absorb_process(self, event: ProcessEvent) -> list[IncidentEvent]:
        if event.pid <= 0:
            return []
        self._record_lineage(event)
        bound = self._kernel_bound.get(event.pid)
        if bound is not None and bound[0] != event.session_id:
            if not self._can_emit(f"conflict:{event.session_id}:{event.pid}", event.timestamp):
                return []
            logger.warning(
                "ATTESTATION: session %s narrates pid %d, kernel-bound to session %s",
                event.session_id,
                event.pid,
                bound[0],
            )
            return [self._incident(
                event,
                "process_attestation_conflict",
                "Process ownership contradicts the narrative",
                (
                    f"Session {event.session_id} narrates process {event.pid} "
                    f"({event.command_line[:80]}), but the kernel has that pid "
                    f"inside session {bound[0]}'s containment unit. Two audit "
                    "sessions claiming one process is the attribution forgery "
                    "pattern: one agent's activity wearing another audit "
                    "session's identity (the fake-veto / fake-peer shape). "
                    "Kernel binding is observed truth; the contradiction is "
                    "correlation and carries MEDIUM confidence."
                ),
                lineage=[event.pid],
                bound_session=str(bound[0]),
            )]
        return []

    def _attest_egress(self, event: NetworkEvent) -> list[IncidentEvent]:
        pid = event.process_pid
        if not pid or pid <= 0:
            return []
        owner_session = self._attest_lineage_owner(pid, event.timestamp)
        if owner_session is None or owner_session == event.session_id:
            # Unattestable lineage is an honest gap; own-session lineage is
            # the normal case and produces nothing.
            return []
        if not self._can_emit(f"egress:{event.session_id}:{pid}", event.timestamp):
            return []
        chain = self._lineage_chain(pid)
        logger.warning(
            "ATTESTATION: session %s records egress from pid %d whose lineage "
            "roots in session %s's kernel-bound tree",
            event.session_id,
            pid,
            owner_session,
        )
        return [self._incident(
            event,
            "egress_attribution_contradiction",
            "Egress lineage belongs to another session",
            (
                f"Session {event.session_id} records network egress from pid "
                f"{pid}, but that pid's process lineage (chain: {chain}) roots "
                f"in a process the kernel bound to session {owner_session}. "
                "One session's ledger claiming another session's process "
                "traffic is the cross-identity attribution forgery pattern — "
                "the same process reality the credential-loop engine sees as "
                "content reuse, seen here as kernel lineage. MEDIUM "
                "confidence: the binding is kernel-observed, the "
                "contradiction is correlation."
            ),
            lineage=chain,
            bound_session=str(owner_session),
        )]

    def _attest_lineage_owner(self, pid: int, now: datetime) -> UUID | None:
        """Walk the pid->ppid chain; return the session owning a kernel-bound
        ancestor, or None when the chain reaches no kernel binding."""
        current: int | None = pid
        for _ in range(_MAX_LINEAGE_HOPS):
            if current is None or current <= 0:
                return None
            bound = self._kernel_bound.get(current)
            if bound is not None:
                return bound[0]
            record = self._lineage.get(current)
            if record is None:
                return None
            current = record[0]
        return None

    def _lineage_chain(self, pid: int) -> list[int]:
        """The observed chain from pid toward its root (bounded, cycle-safe)."""
        chain: list[int] = []
        current: int | None = pid
        seen: set[int] = set()
        for _ in range(_MAX_LINEAGE_HOPS):
            if current is None or current <= 0 or current in seen:
                break
            seen.add(current)
            chain.append(current)
            record = self._lineage.get(current)
            if record is None:
                break
            current = record[0]
        return chain

    def _can_emit(self, key: str, now: datetime) -> bool:
        if len(self._last_emitted) >= _MAX_COOLDOWN_KEYS:
            # The map is a cooldown memory, not a history: evict the oldest
            # entry when the bound is hit.
            oldest = min(self._last_emitted, key=lambda k: self._last_emitted[k])
            del self._last_emitted[oldest]
        last = self._last_emitted.get(key)
        if last is not None and now - last < _CONFLICT_COOLDOWN:
            return False
        self._last_emitted[key] = now
        return True

    def _incident(
        self,
        event: EventBase,
        incident_type: str,
        title: str,
        description: str,
        *,
        lineage: list[int],
        bound_session: str,
    ) -> IncidentEvent:
        return IncidentEvent(
            session_id=event.session_id,
            actor_id="process_attestation",
            source_adapter="process_attestation",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=incident_type,
            severity="high",
            title=title,
            description=description,
            related_events=[str(event.event_id)],
            causal_path=[str(event.event_id)],
            timestamp=event.timestamp,
            payload={
                "lineage_pids": lineage,
                "kernel_bound_session": bound_session,
                "kernel_evidence": True,
            },
        )

