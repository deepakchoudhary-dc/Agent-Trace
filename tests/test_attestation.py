"""Tests for kernel-bound process attestation (plan2 P1.2 residual).

The kernel knows which pid belongs to which session's containment unit;
the narrative claims whatever it wants. These tests pin the two
contradiction incidents, the honest silence when no binding exists, and
the state discipline (bounds, drops, silent seeding).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agenttrace.graph.attestation import (
    _MAX_LINEAGE_ENTRIES,
    ProcessAttestationEngine,
)
from agenttrace.models.events import ConfidenceLevel, NetworkEvent, ProcessEvent

_T0 = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
_SID_A = uuid4()
_SID_B = uuid4()


def _proc(sid: object, pid: int, ppid: int, at: datetime | None = None) -> ProcessEvent:
    return ProcessEvent(
        session_id=sid,  # type: ignore[arg-type]
        actor_id="agent:claude_code",
        source_adapter="process_tree_observer",
        confidence=ConfidenceLevel.HIGH,
        pid=pid,
        ppid=ppid,
        command_line="python worker.py",
        timestamp=at or _T0,
    )


def _egress(sid: object, pid: int, at: datetime | None = None) -> NetworkEvent:
    return NetworkEvent(
        session_id=sid,  # type: ignore[arg-type]
        actor_id=f"process:{pid}",
        source_adapter="network_observer",
        confidence=ConfidenceLevel.HIGH,
        destination_ip="93.184.216.34",
        destination_port=443,
        protocol="tcp",
        direction="outbound",
        process_pid=pid,
        timestamp=at or _T0,
    )


# -- Same-session lineage: the normal case, always silent -------------------------


def test_own_session_lineage_is_silent() -> None:
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 100, _T0)
    assert engine.observe(_proc(_SID_A, 200, 100)) == []
    assert engine.observe(_egress(_SID_A, 200)) == []


def test_unbound_lineage_is_an_honest_gap() -> None:
    """No kernel binding: no verdict, no guess (invariant #2)."""
    engine = ProcessAttestationEngine()
    engine.observe(_proc(_SID_B, 200, 100))
    assert engine.observe(_egress(_SID_B, 200)) == []


# -- Direct conflicts --------------------------------------------------------------


def test_process_conflict_when_pid_bound_to_other_session() -> None:
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 4242, _T0)
    incidents = engine.observe(_proc(_SID_B, 4242, 1))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "process_attestation_conflict"
    assert incidents[0].severity == "high"
    assert incidents[0].confidence is ConfidenceLevel.MEDIUM
    assert incidents[0].payload["kernel_evidence"] is True
    assert incidents[0].payload["kernel_bound_session"] == str(_SID_A)


def test_conflict_cooldown_per_session_and_pid() -> None:
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 4242, _T0)
    assert len(engine.observe(_proc(_SID_B, 4242, 1))) == 1
    # Same claim inside the cooldown: silent.
    assert engine.observe(
        _proc(_SID_B, 4242, 1, at=_T0 + timedelta(minutes=1))
    ) == []
    # After the cooldown: fires again.
    later = engine.observe(_proc(_SID_B, 4242, 1, at=_T0 + timedelta(minutes=11)))
    assert len(later) == 1


# -- Lineage-rooted egress contradictions ------------------------------------------


def test_egress_from_foreign_tree_fires() -> None:
    """B's ledger records egress from a pid whose lineage roots in a pid the
    kernel bound to A: one agent's traffic wearing another session's identity."""
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 100, _T0)
    # B observes the child process (ppid 100 = A's kernel-bound root).
    engine.observe(_proc(_SID_B, 200, 100))
    incidents = engine.observe(_egress(_SID_B, 200))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "egress_attribution_contradiction"
    assert incidents[0].payload["lineage_pids"] == [200, 100]
    assert incidents[0].payload["kernel_bound_session"] == str(_SID_A)


def test_deep_lineage_walk_finds_root() -> None:
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 1, _T0)
    # 300 -> 200 -> 1(A's root), all observed in B.
    engine.observe(_proc(_SID_B, 200, 1))
    engine.observe(_proc(_SID_B, 300, 200))
    incidents = engine.observe(_egress(_SID_B, 300))
    assert len(incidents) == 1
    assert incidents[0].payload["lineage_pids"] == [300, 200, 1]


def test_lineage_deeper_than_hop_budget_is_unattestable() -> None:
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 1, _T0)
    pid = 1
    for i in range(2, 16):
        engine.observe(_proc(_SID_B, i * 10, pid))
        pid = i * 10
    assert engine.observe(_egress(_SID_B, pid)) == []


def test_cycle_in_lineage_terminates() -> None:
    """Recycled-pid data can form a cycle; the walk must terminate."""
    engine = ProcessAttestationEngine()
    engine.observe(_proc(_SID_B, 200, 300))
    engine.observe(_proc(_SID_B, 300, 200))
    assert engine.observe(_egress(_SID_B, 200)) == []


# -- State discipline ----------------------------------------------------------------


def test_drop_session_removes_bindings() -> None:
    """When a session's containment unit is released, its bindings must not
    outlive it and manufacture contradictions against a recycled pid."""
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 4242, _T0)
    engine.drop_session(_SID_A)
    assert engine.observe(_proc(_SID_B, 4242, 1)) == []


def test_seed_is_silent_and_bindings_are_not_seeded() -> None:
    """Lineage history rebuilds silently; kernel bindings do NOT survive a
    restart (the units are new) — an old binding must never manufacture a
    contradiction against a fresh world."""
    engine = ProcessAttestationEngine()
    engine.seed_event(_proc(_SID_A, 200, 100))
    engine.seed_event(_proc(_SID_B, 200, 100))
    engine.bind_kernel_root(_SID_B, 100, _T0)
    # A's egress from pid 200: lineage roots at 100, bound to B — a REAL
    # contradiction against the fresh binding, and lineage was seeded.
    incidents = engine.observe(_egress(_SID_A, 200))
    assert len(incidents) == 1


def test_pid_zero_never_bound() -> None:
    """pid 0 is the cgroup self-assign convention, never a process."""
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 0, _T0)
    assert engine.observe(_proc(_SID_B, 0, 1)) == []
    assert engine._kernel_bound == {}


def test_lineage_state_bounded() -> None:
    engine = ProcessAttestationEngine()
    pid = 0
    for i in range(1, _MAX_LINEAGE_ENTRIES + 50):
        engine.observe(_proc(_SID_B, i, pid))
        pid = i
    assert len(engine._lineage) <= _MAX_LINEAGE_ENTRIES


# -- Reviewer findings: sync discipline, bindings-not-seeded pin, exercised cycle --


def test_sync_absorbs_prunes_and_throttles_the_kernel_fetch() -> None:
    """The fetcher is a real kernel query: it must run inside the throttle
    window only, absorbed members must appear, and members the kernel no
    longer reports must be dropped (a dead binding manufactures
    contradictions against a recycled pid)."""
    engine = ProcessAttestationEngine()
    calls: list[int] = []

    def fetch() -> list[int]:
        calls.append(1)
        return [100, 200]

    engine.sync_kernel_bindings(_SID_A, fetch)
    assert sorted(engine._kernel_bound) == [100, 200]
    n_calls = len(calls)
    # Inside the throttle window: the fetcher must not even run.
    engine.sync_kernel_bindings(_SID_A, fetch)
    assert len(calls) == n_calls
    # Prune: the kernel no longer reports 200.
    def fetch_pruned() -> list[int]:
        calls.append(1)
        return [100]

    import time as _time

    engine._sync_at[_SID_A] = _time.monotonic() - 10.0
    engine.sync_kernel_bindings(_SID_A, fetch_pruned)
    assert 200 not in engine._kernel_bound
    assert 100 in engine._kernel_bound


def test_seed_does_not_seed_bindings() -> None:
    """The 'bindings are not seeded' half, actually pinned: with lineage
    seeded but NO binding, a fresh session narrating that pid stays silent
    (honest gap) — if seed_event bound pids, it would fire."""
    engine = ProcessAttestationEngine()
    engine.seed_event(_proc(_SID_A, 200, 100))
    assert engine.observe(_proc(_SID_B, 200, 100)) == []
    assert engine.observe(_egress(_SID_B, 200)) == []


def test_cycle_with_bound_node_exercises_walk_and_chain() -> None:
    """Binding one node of a pid cycle forces the walk to traverse the cycle
    (terminated by the hop budget) and the chain builder to truncate."""
    engine = ProcessAttestationEngine()
    engine.bind_kernel_root(_SID_A, 300, _T0)
    engine.observe(_proc(_SID_B, 200, 300))
    engine.observe(_proc(_SID_B, 300, 200))
    incidents = engine.observe(_egress(_SID_B, 200))
    assert len(incidents) == 1
    chain = incidents[0].payload["lineage_pids"]
    assert chain[0] == 200
    assert len(chain) <= 8
