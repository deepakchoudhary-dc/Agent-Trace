"""Actor scoping: separating the agent's conduct from its host machine.

The exported report that motivated this module attributed 274 of 500 events to
`codex:unknown` and presented `process:tasklist` and `process:conhost` as
audit-worthy activity about the agent. These tests pin the boundaries.
"""

from __future__ import annotations

from agenttrace.graph.actor_scope import (
    AGENT_SCOPED,
    ActorClass,
    classify_actor,
    classify_event,
    is_agent_scoped,
    summarize_scope,
)


def test_agent_identities_are_agent_scoped() -> None:
    for actor in ("codex:abc123", "claude:xyz", "copilot_chat", "agent:cline"):
        assert classify_actor(actor) is ActorClass.AGENT
        assert is_agent_scoped(classify_actor(actor))


def test_containment_verdict_outranks_the_process_name() -> None:
    """Kernel containment is the one signal a process cannot spoof by naming
    itself after an agent, and it is the one that proves the opposite: a
    process inside the unit is the agent's whatever it is called."""
    assert classify_actor("process:conhost", contained=True) is ActorClass.AGENT_TOOL
    assert classify_actor("process:conhost", contained=False) is ActorClass.SYSTEM


def test_os_and_other_applications_are_system_not_agent() -> None:
    for actor in (
        "process:tasklist",
        "process:svchost",
        "process:explorer",
        "process:dwm",
        "process:runtimebroker",
    ):
        assert classify_actor(actor) is ActorClass.SYSTEM


def test_kernel_telemetry_is_kernel_including_unattributed() -> None:
    for actor in ("etw:1234", "auditd:99", "unattributed_etw:12", "unattributed_auditd:99"):
        assert classify_actor(actor) is ActorClass.KERNEL


def test_agenttraces_own_engines_are_never_agent_activity() -> None:
    """Our own analysis must not inflate the agent's event count."""
    for actor in ("detector_engine", "collusion_engine", "policy_engine", "daemon"):
        assert classify_actor(actor) is ActorClass.DETECTOR


def test_operator_and_tooling_are_distinguished() -> None:
    assert classify_actor("terminal:developer") is ActorClass.OPERATOR
    assert classify_actor("tool:python") is ActorClass.AGENT_TOOL


def test_workspace_observers_are_unattributed_not_guessed() -> None:
    """A file changed; the event alone does not say who changed it. Claiming
    the agent did would be a fabricated explanation (invariant #3)."""
    assert classify_actor("filesystem") is ActorClass.UNATTRIBUTED
    assert classify_actor("git") is ActorClass.UNATTRIBUTED


def test_classify_event_reads_containment_from_the_payload() -> None:
    contained = {
        "actor_id": "process:conhost",
        "source_adapter": "process_tree_observer",
        "event_type": "process",
        "payload": {"contained_descendant": True},
    }
    ambient = {**contained, "payload": {"contained_descendant": False}}
    assert classify_event(contained) is ActorClass.AGENT_TOOL
    assert classify_event(ambient) is ActorClass.SYSTEM


def test_classify_event_accepts_objects_and_enum_event_types() -> None:
    class FakeEvent:
        actor_id = "codex:abc"
        source_adapter = "codex_cli"
        payload: dict[str, object] = {}

        class _Type:
            value = "tool_request"

        event_type = _Type()

    assert classify_event(FakeEvent()) is ActorClass.AGENT


def test_summary_counts_every_event_exactly_once() -> None:
    events = [
        {"actor_id": "codex:a", "source_adapter": "codex_cli", "event_type": "tool_request"},
        {"actor_id": "process:tasklist", "source_adapter": "process_tree_observer",
         "event_type": "process"},
        {"actor_id": "detector_engine", "source_adapter": "detector_engine",
         "event_type": "policy_finding"},
    ]
    summary = summarize_scope(events)
    assert summary.total == 3
    assert sum(summary.counts.values()) == 3
    assert summary.agent_scoped == 1
    assert summary.ambient == 1
    assert summary.to_payload()["agent_scoped_classes"] == sorted(
        c.value for c in AGENT_SCOPED
    )
