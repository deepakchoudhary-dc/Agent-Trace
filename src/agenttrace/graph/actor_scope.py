"""Actor scoping: is an event about the AGENT, or about the machine?

AgentTrace audits an AI coding agent's causal behaviour. The raw ledger also
contains the ambient noise of the host it ran on — the console host, the
antivirus's `tasklist`, the IDE's language server, `svchost`, kernel audit
records. A report that presents all of that with equal weight buries the agent
under its own machine, which is what made the first exported manifest
unreadable as evidence about the agent.

This module answers one question per event: *whose action is this?* It is a pure
function of already-persisted fields, so the answer is recomputable and never
has to be sealed into the chain — a derived label must not become part of the
evidence it describes.

The strongest signal is used first: ``payload["contained_descendant"]``, which
the process-tree observer sets from the kernel containment unit (Windows Job
Object / cgroup v2). A process inside the containment unit is the agent's by
kernel verdict, whatever it is named, so it outranks every name heuristic.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable


class ActorClass(str, Enum):
    """Whose action an event records."""

    AGENT = "agent"  # the audited agent itself
    AGENT_TOOL = "agent_tool"  # a process/tool inside the agent's containment unit
    OPERATOR = "operator"  # the human developer
    DETECTOR = "detector"  # AgentTrace's own analysis engines
    SYSTEM = "system"  # OS, userland, other applications
    KERNEL = "kernel"  # kernel-level telemetry sources
    UNATTRIBUTED = "unattributed"  # observed, but the actor cannot be established


#: Classes that describe the agent's own conduct. Everything else is either the
#: machine, the operator, or our own instrumentation.
AGENT_SCOPED: frozenset[ActorClass] = frozenset({ActorClass.AGENT, ActorClass.AGENT_TOOL})

#: Agent identifiers as the adapters emit them.
_AGENT_PREFIXES = ("codex:", "claude:", "copilot", "agent:")

#: AgentTrace's own engines. These are analysis OF the session, not conduct IN
#: it, and must never be counted as agent activity.
_DETECTOR_ACTORS = frozenset(
    {
        "daemon",
        "detector_engine",
        "policy_engine",
        "incident_engine",
        "actor_identity",
        "collusion_engine",
        "continuation_risk",
        "task_boundary_engine",
        "eval_integrity",
        "safeguard_context",
        "shield_gate",
        "gate",
        "user",
    }
)

#: Kernel / OS telemetry planes. The observers emit an `unattributed_` variant
#: when a kernel record cannot be tied to a process; it is still kernel
#: telemetry, just without a named subject.
_KERNEL_PREFIXES = (
    "etw:",
    "auditd:",
    "unattributed_etw:",
    "unattributed_auditd:",
)
_KERNEL_ADAPTERS = frozenset({"kernel_observer", "auditd"})

#: Operating-system and other-application processes. An agent may legitimately
#: spawn some of these; the containment signal decides that, not this list.
_OS_PROCESS_NAMES = frozenset(
    {
        "system",
        "idle",
        "registry",
        "memory compression",
        "secure system",
        "smss",
        "csrss",
        "wininit",
        "winlogon",
        "services",
        "lsass",
        "svchost",
        "fontdrvhost",
        "dwm",
        "explorer",
        "sihost",
        "ctfmon",
        "taskhostw",
        "runtimebroker",
        "searchindexer",
        "searchhost",
        "startmenuexperiencehost",
        "shellexperiencehost",
        "textinputhost",
        "conhost",
        "conhost.exe",
        "tasklist",
        "taskmgr",
        "wmiprvse",
        "wudfhost",
        "spoolsv",
        "audiodg",
        "widgets",
        "widgetservice",
        "msmpeng",
        "nissrv",
        "securityhealthservice",
        "crashpad_handler",
        "gitbash",
        "msedge",
        "chrome",
        "firefox",
        "code",
        "devenv",
    }
)

#: Observers that watch the workspace itself. A file or git change is a real
#: consequence but is not attributable to a person or process from the event
#: alone — claiming otherwise would be a fabricated explanation (invariant #3).
_WORKSPACE_ACTORS = frozenset({"filesystem", "git", "workspace", "blob_store"})

#: Adapters that carry the agent's own transcript.
_AGENT_ADAPTERS = frozenset({"codex_cli", "claude_code", "copilot_chat", "sdk", "universal"})


def classify_actor(
    actor_id: str,
    source_adapter: str = "",
    event_type: str = "",
    *,
    contained: bool = False,
) -> ActorClass:
    """Classify one event's actor.

    ``contained`` is the kernel's answer to "is this process inside the agent's
    containment unit" and wins over every name-based heuristic.
    """
    actor = (actor_id or "").strip()
    lowered = actor.lower()
    adapter = (source_adapter or "").strip().lower()

    # 1. Kernel containment verdict — the only signal that cannot be spoofed by
    #    a process naming itself after an agent.
    if contained:
        return ActorClass.AGENT_TOOL

    # 2. Our own analysis engines, by actor or by provenance.
    if lowered in _DETECTOR_ACTORS or adapter in _DETECTOR_ACTORS:
        return ActorClass.DETECTOR

    # 3. Kernel telemetry planes.
    if lowered.startswith(_KERNEL_PREFIXES) or adapter in _KERNEL_ADAPTERS:
        return ActorClass.KERNEL

    # 4. The agent, by its adapter-assigned identity.
    if lowered.startswith(_AGENT_PREFIXES):
        return ActorClass.AGENT
    if adapter in _AGENT_ADAPTERS and not lowered.startswith("tool:"):
        return ActorClass.AGENT

    # 5. Operator tooling and shells.
    if lowered.startswith("tool:"):
        return ActorClass.AGENT_TOOL
    if lowered.startswith("terminal:"):
        return ActorClass.OPERATOR

    # 6. Workspace observers — consequences without an attributable actor.
    if lowered in _WORKSPACE_ACTORS:
        return ActorClass.UNATTRIBUTED

    # 7. Ambient OS / other-application processes.
    if lowered.startswith("process:"):
        name = lowered.split(":", 1)[1]
        if name in _OS_PROCESS_NAMES:
            return ActorClass.SYSTEM
        # A process we cannot place is still a process on this host.
        return ActorClass.SYSTEM

    return ActorClass.UNATTRIBUTED


def is_agent_scoped(actor_class: ActorClass) -> bool:
    """Whether a class counts as the agent's own conduct."""
    return actor_class in AGENT_SCOPED


def classify_event(event: Any) -> ActorClass:
    """Classify an event object or a serialized event mapping."""
    if isinstance(event, dict):
        actor_id = event.get("actor_id", "")
        source_adapter = event.get("source_adapter", "")
        event_type = event.get("event_type", "")
        payload = event.get("payload") or {}
    else:
        actor_id = getattr(event, "actor_id", "")
        source_adapter = getattr(event, "source_adapter", "")
        event_type = getattr(event, "event_type", "")
        payload = getattr(event, "payload", None) or {}

    if not isinstance(event_type, str):
        event_type = str(getattr(event_type, "value", event_type))

    contained = isinstance(payload, dict) and bool(
        payload.get("contained_descendant", False)
    )
    return classify_actor(
        str(actor_id),
        str(source_adapter),
        str(event_type),
        contained=contained,
    )


@dataclass(frozen=True)
class ActorScopeSummary:
    """How a session's events divide between the agent and its machine.

    Every event lands in exactly one class, so the counts always sum to the
    number of events considered — an auditor can see that nothing was dropped
    to make the agent look busier or cleaner than it was.
    """

    counts: dict[str, int] = field(default_factory=dict)
    total: int = 0

    @property
    def agent_scoped(self) -> int:
        return sum(self.counts.get(c.value, 0) for c in AGENT_SCOPED)

    @property
    def ambient(self) -> int:
        return self.counts.get(ActorClass.SYSTEM.value, 0) + self.counts.get(
            ActorClass.KERNEL.value, 0
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "counts": dict(sorted(self.counts.items())),
            "total": self.total,
            "agent_scoped": self.agent_scoped,
            "ambient": self.ambient,
            "agent_scoped_classes": sorted(c.value for c in AGENT_SCOPED),
        }


def summarize_scope(events: Iterable[Any]) -> ActorScopeSummary:
    """Classify every event and count the result per class."""
    counts = Counter(classify_event(event).value for event in events)
    return ActorScopeSummary(counts=dict(counts), total=sum(counts.values()))
