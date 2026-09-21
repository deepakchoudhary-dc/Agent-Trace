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


# -- Classification must not over-claim the agent ------------------------------


def test_explicit_identity_beats_the_adapter_guess() -> None:
    """A workspace observer must not become the agent just because it arrived
    through an agent-facing adapter — that is how 274 events were attributed to
    `codex:unknown` in the first place."""
    assert classify_actor("filesystem", "sdk") is ActorClass.UNATTRIBUTED
    assert classify_actor("git", "universal") is ActorClass.UNATTRIBUTED
    assert classify_actor("process:tasklist", "sdk") is ActorClass.SYSTEM


def test_a_process_named_after_an_assistant_is_the_assistant() -> None:
    assert classify_actor("process:codex") is ActorClass.AGENT
    assert classify_actor("process:claude") is ActorClass.AGENT
    assert classify_actor("process:notepad") is ActorClass.SYSTEM


def test_agent_only_event_types_are_the_agent() -> None:
    """A tool request IS the agent acting, whatever the adapter called it."""
    assert classify_actor("mystery", "mystery", "tool_request") is ActorClass.AGENT
    assert classify_actor("mystery", "mystery", "process") is ActorClass.UNATTRIBUTED


def test_a_different_assistant_is_not_the_audited_agent() -> None:
    """The `agent:` prefix is overloaded: the process observer emits it for a
    known assistant AND for any VS Code extension directory, so the editor's
    language server was being counted as the agent's own conduct."""
    assert (
        classify_actor("agent:json-language-features", "process_tree_observer",
                       "process", declared_agent="codex")
        is ActorClass.OTHER_AGENT
    )
    assert (
        classify_actor("agent:codex_cli", "process_tree_observer", "process",
                       declared_agent="codex")
        is ActorClass.AGENT
    )
    assert (
        classify_actor("claude:abc", "claude_code", "tool_request",
                       declared_agent="codex")
        is ActorClass.OTHER_AGENT
    )


def test_an_undeclared_agent_type_cannot_split_so_it_does_not() -> None:
    """`auto` / `generic` name no specific assistant; guessing would be worse
    than not splitting."""
    for declared in ("auto", "generic", "", None):
        assert (
            classify_actor("agent:whatever", "process_tree_observer", "process",
                           declared_agent=declared)
            is ActorClass.AGENT
        )


def test_other_agent_is_neither_agent_scope_nor_ambient() -> None:
    events = [
        {"actor_id": "codex:a", "source_adapter": "codex_cli", "event_type": "tool_request"},
        {"actor_id": "agent:json-language-features", "source_adapter": "process_tree_observer",
         "event_type": "process"},
        {"actor_id": "process:tasklist", "source_adapter": "process_tree_observer",
         "event_type": "process"},
    ]
    summary = summarize_scope(events, declared_agent="codex")
    assert summary.counts["other_agent"] == 1
    assert summary.agent_scoped == 1
    assert summary.ambient == 1
    assert sum(summary.counts.values()) == summary.total == 3
