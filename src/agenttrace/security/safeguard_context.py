"""Safeguard-context metadata (ant.md P2 #11).

The Anthropic incident report notes its models ran WITHOUT the cyber
safeguards that ship with released models — and that honest post-hoc
analysis requires knowing which safeguards were in force. Until now an
AgentTrace session header recorded *what* was configured (workspace,
network contract) but not *which detectors and response engines were
actually enabled* — so a reviewer reconstructing an incident could not
distinguish "the detector saw nothing" from "the detector was not
running".

This module records the safeguard context once per session, close to
session start, as a hash-chained ``PolicyFindingEvent`` anchored to the
session's early chain (the event's ``evidence_refs`` names the session
start event id, so the context statement is provably attached to that
session's chain and time). What is recorded:

- the enabled detector/monitor inventory, derived from the daemon's
  live registries (not from a static list that can drift);
- the declared network contract (isolated / allowlist / open);
- the declared observation limits (single-host, no witness), so the
  context statement itself carries the honest boundary.

A session that never produced this record is a visible gap, not a
silent one: reports can distinguish "record missing" from "recorded
empty", mirroring the coverage-account discipline (never mistake
silence for health, never fabricate a pass).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import ConfidenceLevel, PolicyFindingEvent

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.models.session import SessionConfig

logger = logging.getLogger(__name__)

FINDING_TYPE = "safeguard_context"


def build_safeguard_context_payload(
    *,
    config: SessionConfig,
    per_session_detectors: dict[str, bool],
    daemon_wide_engines: dict[str, bool],
    containment_active: bool,
    kernel_observer_active: bool,
    auditd_observer_active: bool,
) -> dict[str, Any]:
    """Assemble the safeguard-context payload from live daemon state.

    Args:
        config: the session's declared configuration.
        per_session_detectors: per-session detector name -> present.
        daemon_wide_engines: daemon-wide engine name -> present.
        containment_active: whether a containment unit is owned.
        kernel_observer_active: whether the kernel-tier observer started.
        auditd_observer_active: whether the auditd observer started (Linux).
    """
    if config.internet_access_allowed is False:
        network_contract = "sealed (no internet declared)"
    elif config.internet_access_allowed is None:
        network_contract = "undeclared"
    else:
        network_contract = "open (internet declared allowed)"

    return {
        "network_contract": network_contract,
        "allowed_destinations_count": len(config.allowed_destinations),
        "per_session_detectors": dict(sorted(per_session_detectors.items())),
        "daemon_wide_engines": dict(sorted(daemon_wide_engines.items())),
        "response_engines": {
            "containment_active": containment_active,
        },
        "observation_planes": {
            "kernel_observer": kernel_observer_active,
            "auditd_observer": auditd_observer_active,
            "platform": "linux-auditd" if auditd_observer_active else "polling+etw",
        },
        "declared_limits": [
            "single-host visibility (actions on other machines are invisible)",
            "no out-of-band witness (host compromise can forge local telemetry)",
            "same-user trust boundary (a same-account process can read local state)",
        ],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


def emit_safeguard_context(
    *,
    session_id: UUID,
    chain_anchor: str | None,
    payload: dict[str, Any],
) -> PolicyFindingEvent:
    """Build the chain-anchored safeguard-context finding event.

    The caller appends this to the ledger. ``chain_anchor`` is the
    session's head event hash at recording time — the record is provably
    attached to that chain position. ``severity`` is ``info``: the record
    is context, not a violation, and must never gate or alarm on its own.
    """
    evidence = [chain_anchor] if chain_anchor else []
    if not evidence:
        # Expected for a fresh session: the chain is empty and this record
        # becomes one of its first sealed events — itself the anchor.
        logger.info(
            "Safeguard context for session %s recorded at chain start",
            session_id,
        )
    return PolicyFindingEvent(
        session_id=session_id,
        actor_id="daemon",
        source_adapter="safeguard_context",
        confidence=ConfidenceLevel.HIGH,
        finding_type=FINDING_TYPE,
        severity="info",
        description=(
            "Safeguard context recorded: which detectors, monitors and "
            "response engines were enabled for this session, with the "
            "declared network contract and observation limits. Required "
            "for honest post-hoc analysis (ant.md P2 #11)."
        ),
        evidence_refs=evidence,
        payload=payload,
    )
