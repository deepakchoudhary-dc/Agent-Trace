"""Assistant layer — recommendations, narratives, and briefings.

Turns machine-shaped evidence (findings, causal paths, counters) into
operator-facing guidance. Every recommendation is an imperative for the
HUMAN, never an autonomous action; every narrative carries its confidence
and names what is NOT known.
"""

from __future__ import annotations

from typing import Any

# One imperative per finding/rule/detector/incident id. Keys are matched
# against PolicyFindingEvent.finding_type, policy rule_ids, and detector_ids
# interchangeably — they share one namespace at the gate and in the UI.
RECOMMENDED_ACTIONS: dict[str, str] = {
    # -- Policy rules --
    "destructive_file_op":
        "Inspect the diff before approving; prefer a scoped approval "
        "limited to the exact file.",
    "write_outside_scope":
        "Confirm the target path belongs to the task; widen scope only if "
        "it is genuinely required.",
    "credential_access":
        "Treat as secret exposure: rotate the credential, then approve "
        "only if the read was justified.",
    "privilege_escalation":
        "Deny unless elevation is explicitly required by the task; verify "
        "the exact command line first.",
    "dependency_change":
        "Review the manifest diff for typosquats and new install sources "
        "before allowing installs.",
    "network_egress":
        "Check the destination against your allowlist; deny unknown endpoints.",
    "external_state_change":
        "Verify the remote side effect (issue/PR/deploy) was intended "
        "before allowing a repeat.",
    "high_impact_git":
        "Inspect the git operation (force-push/reset) against branch "
        "protection expectations.",
    "script_execution":
        "Read the downloaded script end-to-end; piped execution cannot be "
        "un-executed.",
    "seal_violation":
        "The environment declared no internet but reached out — treat the "
        "seal as broken and investigate.",
    "destination_allowlist":
        "Endpoint outside the declared allowlist; add only after verifying "
        "ownership.",
    # -- Detectors --
    "prompt_injection_markers":
        "Trace where this content entered the session; treat it as hostile "
        "until proven otherwise.",
    "config_tamper":
        "Diff the agent config/instruction file; revert unauthorized "
        "changes and re-approve the tool.",
    "credential_read_heuristic":
        "Identify which secret was read and rotate it; check subsequent "
        "egress for the value.",
    "obfuscation_tool":
        "Decode the payload out-of-band and review it; obfuscation in a "
        "coding task is rarely legitimate.",
    "egress_anomaly":
        "Compare the destination with known baselines; block while "
        "unidentified.",
    "git_history_rewriting":
        "Verify no collaborator work is lost; restore from reflog or "
        "remote before continuing.",
    "path_trick":
        "Resolve the real path being accessed; traversal tricks indicate "
        "boundary probing.",
    "privilege_change":
        "Audit capability/setuid changes immediately; these persist past "
        "the session.",
    "sandbox_escape":
        "Assume containment is compromised; freeze the session and inspect "
        "spawned processes.",
    "database_destruction":
        "Stop writes, verify backups exist, and require explicit operator "
        "sign-off for any DDL.",
    "multi_agent_sabotage":
        "Isolate the implicated sessions and compare their task contracts; "
        "one agent is attacking another.",
    "persistence_malware":
        "Remove the cron/systemd/task/Run-key entry and re-scan for "
        "siblings; this outlives the session.",
    "test_integrity":
        "Revert the test change and rerun; rigged tests invalidate the "
        "review loop's verdicts.",
    "powershell_cradle":
        "Decode the cradle payload; download-and-execute via PowerShell is "
        "malware-grade behavior.",
    "git_author_spoof":
        "Verify commit authorship against credentials; spoofed authorship "
        "breaks attribution.",
    "orphaned_commit":
        "Locate the unobserved parent work; commits appearing from nowhere "
        "hide their preparation.",
    "network_tunnel":
        "Block the destination and inspect the traffic; tunneling "
        "indicates covert channeling.",
    "subagent_privilege_escalation":
        "Freeze the sub-agent's session; a descendant escalated beyond its "
        "parent context.",
    "benign_tool_chain":
        "Review each step individually — the composition is suspicious "
        "even though no step is.",
    "recursive_agent_spawn":
        "Terminate spawned agents and audit what they were instructed to do.",
    "log_tampering":
        "Preserve copies of the targeted logs immediately; deletion "
        "mid-session is anti-forensics.",
    "inference_proxy_abuse":
        "Treat the sandbox boundary as breached: rotate the interception/"
        "API key, audit what was fetched via file_url, and block the "
        "proxy endpoint from agent reach.",
    # -- Incidents / daemon findings --
    "approval_fatigue":
        "Slow down: re-read pending gates individually instead of "
        "batch-approving.",
    "event_flood":
        "Expect projection lag during the flood; the ledger stays intact — "
        "wait for rate to drop.",
    "clock_anomaly":
        "Cross-check host clock sync; skewed timestamps distort causality "
        "ordering.",
    "session_frozen":
        "Session paused by critical incident — review the incident chain "
        "before resuming anything.",
    "over_broad_scope":
        "Narrow allowed_paths to real workspace subtrees; current scope "
        "disables boundary checks.",
}

_FALLBACK_ACTION = (
    "Review the evidence chain and decide manually; no playbook exists "
    "for this finding type yet."
)


def recommended_action(kind_id: str | None) -> str:
    """Operator guidance for a finding/rule/detector id (never auto-executed)."""
    if not kind_id:
        return _FALLBACK_ACTION
    return RECOMMENDED_ACTIONS.get(kind_id.lower(), _FALLBACK_ACTION)


_EDGE_VERBS = {
    "CAUSES": "caused",
    "EXECUTES": "executed",
    "SPAWNS": "spawned",
    "MODIFIES": "modified",
    "REQUESTS": "requested",
    "PROVIDES_CONTEXT_TO": "provided context to",
    "INTRODUCES": "introduced",
}


def narrate_paths(
    paths: list[Any],
    target_label: str,
    node_lookup: Any,
    edge_lookup: Any,
) -> dict[str, Any]:
    """Turn ranked EvidencePaths into a human-readable causal narrative.

    Honest by construction: when no path exists we say the action has no
    observed antecedents rather than inventing a story; every step keeps
    its own confidence label; alternatives are counted, not hidden.
    """
    if not paths:
        return {
            "summary": (
                f"No prior causal chain observed for '{target_label}' within "
                "the traversal budget. Treat it as an unexplained origin."
            ),
            "steps": [],
            "overall_confidence": None,
            "unknowns": [
                "No antecedent edges were found — either this is genuinely "
                "first-in-session or the linking event was never observed."
            ],
        }

    best = paths[0]
    steps: list[dict[str, str]] = []
    for edge_id in best.edges:
        edge = edge_lookup(edge_id)
        if edge is None:
            continue
        src = node_lookup(edge.source_node_id)
        dst = node_lookup(edge.target_node_id)
        if src is None or dst is None:
            continue
        verb = _EDGE_VERBS.get(edge.edge_type.value, edge.edge_type.value.lower())
        steps.append({
            "text": (
                f"{src.label or src.node_type.value} {verb} "
                f"{dst.label or dst.node_type.value}"
            ),
            "edge_type": edge.edge_type.value,
            "actor": src.actor_id,
            "confidence": edge.confidence.value,
        })

    alt = (
        f" {len(paths) - 1} lower-confidence alternative path(s) also exist."
        if len(paths) > 1
        else ""
    )
    return {
        "summary": (
            f"'{target_label}' is explained by a {len(best.edges)}-step "
            f"chain at overall confidence {best.overall_confidence:.2f}."
            + alt
        ),
        "steps": steps,
        "overall_confidence": best.overall_confidence,
        "unknowns": [
            "Adjacent-in-time events are not necessarily causal; only "
            "recorded edges are asserted here.",
        ],
    }
