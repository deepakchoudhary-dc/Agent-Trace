"""AgentTrace CLI — Click-based command-line interface.

Commands:
  agenttrace start --workspace <path> --task "<request>" [--agent auto|codex|claude|copilot]
  agenttrace approve <finding-id> --scope <scoped-policy> [--session-id <id>]
  agenttrace verify <session-id>
  agenttrace report <session-id> [--output <file>]
  agenttrace status
  agenttrace stop [session-id]
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
import sys

# Ensure src directory is on sys.path for direct invocation
_SRC_DIR = str(Path(__file__).resolve().parent.parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from typing import Any
from uuid import UUID

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.session import AgentType

console = Console()
logger = logging.getLogger(__name__)
_DEFAULT_API_URL = "http://127.0.0.1:8000"


def _call_api(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any] | list[Any] | None:
    """Attempt to query local daemon REST API."""
    url = f"{_DEFAULT_API_URL}{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    body = json.dumps(data).encode("utf-8") if data else None

    try:
        with urllib.request.urlopen(req, data=body, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return payload if isinstance(payload, (dict, list)) else None
    except urllib.error.HTTPError as e:
        # Daemon reachable but returned an error — do NOT treat as success
        logger.debug("API %s %s -> HTTP %s", method, endpoint, e.code)
        return None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _get_daemon() -> AgentTraceDaemon:
    """Create a daemon instance initialized with persistent storage."""
    d = AgentTraceDaemon()
    d._restore_from_storage()
    return d


@click.group()
@click.version_option(version="0.2.0", prog_name="agenttrace")
def main() -> None:
    """AgentTrace — Local causal auditor for AI coding agents."""
    pass


@main.command()
@click.option(
    "--workspace", "-w",
    type=click.Path(exists=True, file_okay=False),
    required=True,
    help="Path to the workspace to audit.",
)
@click.option(
    "--task", "-t",
    type=str,
    default="",
    help="Description of the task/request being audited.",
)
@click.option(
    "--agent", "-a",
    type=click.Choice(["auto", "codex", "claude", "copilot", "generic"]),
    default="auto",
    help="Agent type to monitor.",
)
def start(workspace: str, task: str, agent: str) -> None:
    """Start an audit session for a workspace."""
    workspace_path = str(Path(workspace).resolve())

    console.print(Panel(
        f"[bold green]Starting AgentTrace Audit Session[/bold green]\n"
        f"Workspace: {workspace_path}\n"
        f"Task: {task or '(general development audit)'}\n"
        f"Agent: {agent}",
        title="🔍 AgentTrace",
        border_style="green",
    ))

    async def _start() -> None:
        daemon = _get_daemon()
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=workspace_path,
            task_description=task,
            agent_type=AgentType(agent),
        )

        console.print(f"\n[green]✓[/green] Session active: [bold cyan]{session.session_id}[/bold cyan]")
        console.print(f"  Status: {session.status}")
        adapter = daemon._adapters.get(session.session_id)
        if adapter:
            console.print(f"  Adapter: {adapter.adapter_name}")
            if adapter.observability_gaps:
                console.print("\n[yellow]⚠ Observability gaps (unobservable agent internals):[/yellow]")
                for gap in adapter.observability_gaps:
                    console.print(f"  • {gap}")

        console.print("\n[dim]Audit active. Press Ctrl+C to stop session and seal ledger...[/dim]")

        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print("\n[yellow]Stopping audit session & sealing cryptographic hash chain...[/yellow]")
            await daemon.stop_session(session.session_id)
            await daemon.stop()
            console.print("[green]✓ Session stopped and cryptographically sealed.[/green]")

    try:
        asyncio.run(_start())
    except KeyboardInterrupt:
        pass


@main.command()
@click.argument("finding_id")
@click.option(
    "--scope", "-s",
    type=str,
    required=True,
    help="Scope of the approval (e.g., file path, command pattern).",
)
@click.option(
    "--reason", "-r",
    type=str,
    default="",
    help="Reason for the approval.",
)
@click.option(
    "--session-id",
    type=str,
    default=None,
    help="Target session ID (optional if only one session exists).",
)
@click.option(
    "--expiry", "-e",
    type=int,
    default=60,
    help="Approval expiry in minutes.",
)
def approve(finding_id: str, scope: str, reason: str, session_id: str | None, expiry: int) -> None:
    """Approve a gated policy finding."""
    # Try API first
    daemon = _get_daemon()
    sessions = daemon.list_sessions()
    if not sessions:
        console.print("[red]No sessions found in local ledger[/red]")
        return

    target_sid = UUID(session_id) if session_id else sessions[0].session_id

    # Interpret --scope as a path or command pattern so the enforcement gate
    # can honor the approval for the same path/command later
    affected_paths: list[str] = []
    affected_commands: list[str] = []
    if scope and any(ch in scope for ch in ("/", "\\", ".")):
        affected_paths.append(scope)
    elif scope:
        affected_commands.append(scope)

    # Record approval
    api_res = _call_api(f"/sessions/{target_sid}/approvals", method="POST", data={
        "finding_id": finding_id,
        "approved": True,
        "reason": reason,
        "scope": scope,
        "expiry_minutes": expiry,
        "affected_paths": affected_paths,
        "affected_commands": affected_commands,
    })

    if not api_res:
        # Fallback to direct ledger record
        approvals = daemon.get_approval_manager(target_sid)
        if approvals:
            approvals.record_approval(
                finding_id=finding_id,
                approved=True,
                reason=reason,
                scope=scope,
                expiry_minutes=expiry,
                affected_paths=affected_paths,
                affected_commands=affected_commands,
            )

    console.print(Panel(
        f"[green]✓ Approval granted & signed in ledger[/green]\n"
        f"Session: {target_sid}\n"
        f"Finding: {finding_id}\n"
        f"Scope: {scope}\n"
        f"Reason: {reason or '(unspecified)'}\n"
        f"Expires: {expiry} minutes",
        title="🔐 Approval Gate",
        border_style="green",
    ))


@main.command()
@click.argument("action_type", type=click.Choice(["file_mutation", "command", "network", "git"]))
@click.argument("target")
@click.option(
    "--session-id",
    type=str,
    default=None,
    help="Target session ID (optional if only one session exists).",
)
@click.option(
    "--details", "-d",
    type=str,
    default=None,
    help="Optional JSON details, e.g. '{\"mutation_type\": \"delete\"}'.",
)
def gate(action_type: str, target: str, session_id: str | None, details: str | None) -> None:
    """Evaluate a proposed action against the policy gate BEFORE running it.

    Returns ALLOWED, APPROVAL REQUIRED (pause), or BLOCKED.
    """
    details_dict: dict[str, Any] = {}
    if details:
        try:
            details_dict = json.loads(details)
        except json.JSONDecodeError:
            console.print("[red]--details must be valid JSON[/red]")
            return

    daemon = _get_daemon()
    sessions = daemon.list_sessions()
    if not sessions:
        console.print("[red]No sessions found in local ledger[/red]")
        return

    target_sid = UUID(session_id) if session_id else sessions[0].session_id

    api_res = _call_api(f"/sessions/{target_sid}/evaluate", method="POST", data={
        "action_type": action_type,
        "target": target,
        "details": details_dict,
    })

    if isinstance(api_res, dict):
        action = api_res["action"]
        reason = api_res["reason"]
        req_id = api_res.get("required_approval_id", "")
    else:
        _, reason, req_id = daemon.evaluate_proposed_action(
            target_sid, action_type, target, details_dict
        )
        action = "block" if reason.startswith("BLOCKED:") else ("pause" if req_id else "allow")

    if action == "block":
        title = "⛔ GATE: BLOCKED"
        style = "red"
    elif action == "pause":
        title = "🛑 GATE: APPROVAL REQUIRED"
        style = "yellow"
    else:
        title = "✅ GATE: ALLOWED"
        style = "green"

    lines = [
        f"Session: {target_sid}",
        f"Action:  {action_type} → {target}",
        f"Decision: {reason}",
    ]
    if req_id:
        lines.append(f"Required approval ID: {req_id}")
        lines.append("Grant it with: agenttrace approve <finding-id> --scope ...")
    console.print(Panel(
        "\n".join(lines),
        title=title,
        border_style=style,
    ))


# ---------------------------------------------------------------------------
# Shield — mediated execution gate. Enforcement: the gate is evaluated BEFORE
# the command runs. BLOCKED commands are refused outright; APPROVAL REQUIRED
# commands pause for a scoped approval; ALLOWED commands execute. `install`
# writes PATH wrappers so agent-launched tools route through this gate.
# ---------------------------------------------------------------------------


@main.group()
def shield() -> None:
    """Mediated execution gate — enforce policy BEFORE commands run."""


def _shield_verdict(sid: UUID, command: str) -> tuple[str, str, str]:
    """Evaluate a command against the gate. Returns (action, reason, approval_id)."""
    api_res = _call_api(f"/sessions/{sid}/evaluate", method="POST", data={
        "action_type": "command",
        "target": command,
        "details": {},
    })
    if isinstance(api_res, dict):
        return (
            api_res.get("action", "allow"),
            api_res.get("reason", ""),
            api_res.get("required_approval_id", ""),
        )
    daemon = _get_daemon()
    _, reason, req_id = daemon.evaluate_proposed_action(sid, "command", command, {})
    action = "block" if reason.startswith("BLOCKED:") else ("pause" if req_id else "allow")
    return action, reason, req_id


def _record_shield_approval(sid: UUID, command: str, reason: str, req_id: str) -> None:
    """Record a scoped approval for the exact command the gate paused on."""
    api_res = _call_api(f"/sessions/{sid}/approvals", method="POST", data={
        "finding_id": req_id or "gate",
        "approved": True,
        "reason": reason,
        "scope": "command",
        "expiry_minutes": 60,
        "affected_paths": [],
        "affected_commands": [command],
    })
    if api_res:
        return
    daemon = _get_daemon()
    mgr = daemon.get_approval_manager(sid)
    if mgr:
        mgr.record_approval(
            finding_id=req_id or "gate",
            approved=True,
            reason=reason,
            scope="command",
            expiry_minutes=60,
            affected_paths=[],
            affected_commands=[command],
        )


@shield.command("check", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("session_id")
@click.argument("command", nargs=-1, required=True)
def shield_check(session_id: str, command: tuple[str, ...]) -> None:
    """Evaluate a command against the gate and print the verdict WITHOUT running it."""
    sid = UUID(session_id)
    cmdline = " ".join(command)
    action, reason, req_id = _shield_verdict(sid, cmdline)
    style = {"block": "red", "pause": "yellow", "allow": "green"}[action]
    lines = [f"Command: {cmdline}", f"Decision: {reason}"]
    if req_id:
        lines.append(f"Approval ID: {req_id}")
    console.print(Panel(
        "\n".join(lines),
        title={"block": "⛔ SHIELD: BLOCKED", "pause": "🛑 SHIELD: APPROVAL REQUIRED", "allow": "✅ SHIELD: ALLOWED"}[action],
        border_style=style,
    ))
    raise SystemExit(2 if action == "block" else 0)


@shield.command("run", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("session_id")
@click.argument("command", nargs=-1, required=True)
@click.option("--approve-all", is_flag=True, help="Auto-approve pause verdicts (non-interactive).")
def shield_run(session_id: str, command: tuple[str, ...], approve_all: bool) -> None:
    """Evaluate then execute: BLOCK → refuse, APPROVAL REQUIRED → prompt (or
    auto-approve with --approve-all), ALLOWED → run."""
    sid = UUID(session_id)
    cmdline = " ".join(command)

    action, reason, req_id = _shield_verdict(sid, cmdline)

    if action == "block":
        console.print(f"[bold red]⛔ BLOCKED — not executing:[/bold red] {cmdline}")
        console.print(f"[red]  {reason}[/red]")
        raise SystemExit(2)

    if action == "pause":
        console.print(f"[yellow]🛑 APPROVAL REQUIRED:[/yellow] {cmdline}")
        console.print(f"[yellow]  {reason}[/yellow]")
        if not approve_all:
            if not click.confirm("Approve and execute?", default=False):
                console.print("[red]Denied — not executing.[/red]")
                raise SystemExit(1)
        _record_shield_approval(sid, cmdline, "granted via shield run", req_id)
        console.print("[green]✓ Approval recorded for this exact command.[/green]")

    import subprocess
    proc = subprocess.call(list(command))
    raise SystemExit(proc)


@shield.command("install")
@click.argument("session_id")
@click.option("--workspace", type=click.Path(file_okay=False), default=None,
              help="Workspace to install wrappers into (defaults to the session's workspace).")
def shield_install(session_id: str, workspace: str | None) -> None:
    """Write PATH wrapper scripts that route agent-launched tools through the gate.

    Prepend the printed directory to the agent's PATH so every wrapped tool
    (git, npm, python, curl, ...) is evaluated by the shield before running.
    """
    sid = UUID(session_id)

    if workspace:
        workspace_path = str(Path(workspace).resolve())
    else:
        daemon = _get_daemon()
        session = daemon.get_session(sid)
        if not session:
            console.print("[red]Session not found. Pass --workspace explicitly.[/red]")
            return
        workspace_path = session.config.workspace_path

    bin_dir = Path(workspace_path) / ".agenttrace" / "shield" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    tools = [
        "git", "npm", "npx", "yarn", "pnpm", "python", "python3", "pip",
        "pip3", "curl", "wget", "node", "bash", "sh", "docker", "kubectl",
        "cargo", "go", "gem", "twine", "make", "tsc", "vite", "ssh", "scp",
    ]
    written: list[str] = []
    for tool in tools:
        bash_wrapper = bin_dir / tool
        bash_wrapper.write_text(
            f"#!/usr/bin/env bash\nexec agenttrace shield run {sid} -- \"$@\"\n",
            encoding="utf-8",
        )
        cmd_wrapper = bin_dir / f"{tool}.cmd"
        cmd_wrapper.write_text(
            f"@echo off\r\nagenttrace shield run {sid} -- %*\r\n",
            encoding="utf-8",
        )
        written.extend([str(bash_wrapper), str(cmd_wrapper)])

    console.print(Panel(
        f"[green]✓ {len(written)} shield wrappers installed[/green]\n\n"
        f"Directory: {bin_dir}\n\n"
        f"Prepend to the agent's PATH so its tools route through the gate:\n"
        f"  [bold]export PATH={bin_dir}:$PATH[/bold]\n\n"
        f"Wrapped tools: {', '.join(tools)}\n\n"
        f"[dim]Each wrapper evaluates the command via the shield gate; BLOCKED \n"
        f"commands are refused, APPROVAL REQUIRED commands pause for consent.[/dim]",
        title="🛡 Shield — mediated execution",
        border_style="green",
    ))


@main.command()
@click.argument("session_id")
def incidents(session_id: str) -> None:
    """List correlated multi-stage incidents for a session."""
    sid = UUID(session_id)

    api_res = _call_api(f"/sessions/{sid}/incidents")
    if isinstance(api_res, list):
        incs = api_res
    else:
        daemon = _get_daemon()
        incs = [
            e.model_dump(mode="json")
            for e in daemon.get_incidents(sid)
        ]

    if not incs:
        console.print("[dim]No incidents correlated for this session.[/dim]")
        return

    for inc in incs:
        severity = inc.get("severity", "medium")
        style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(severity, "white")
        console.print(Panel(
            f"Type: {inc.get('incident_type', '?')}\n"
            f"Severity: {severity}\n"
            f"Title: {inc.get('title', '')}\n"
            f"Description: {inc.get('description', '')}\n"
            f"Evidence events: {', '.join(inc.get('related_events', [])) or '(none)'}",
            title=f"🚨 Incident ({severity})",
            border_style=style,
        ))


@main.command()
@click.argument("session_id")
def verify(session_id: str) -> None:
    """Verify cryptographic hash chain integrity for a session."""
    sid = UUID(session_id)
    daemon = _get_daemon()

    is_valid, error = daemon._ledger.verify_chain(sid)
    last_hash = daemon._ledger.get_last_hash(sid)
    events = daemon._ledger.query_events(sid)

    if is_valid:
        console.print(Panel(
            f"[bold green]✓ CRYPTOGRAPHIC HASH CHAIN VERIFIED[/bold green]\n\n"
            f"Session ID:       {sid}\n"
            f"Total Events:     {len(events)}\n"
            f"Head Event Hash:  {last_hash}\n"
            f"Tamper Status:    UNBROKEN & UNMODIFIED",
            title="🛡 Forensic Integrity Verification",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ TAMPER DETECTED IN EVENT CHAIN[/bold red]\n\n"
            f"Session ID:       {sid}\n"
            f"Error Detail:     {error}",
            title="🛡 Forensic Integrity Alert",
            border_style="red",
        ))


@main.command()
@click.argument("session_id")
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file for the signed forensic report JSON.",
)
def report(session_id: str, output: str | None) -> None:
    """Generate a verified, cryptographically signed forensic audit report."""
    sid = UUID(session_id)
    daemon = _get_daemon()

    # Query API or generate locally
    rep = _call_api(f"/sessions/{sid}/report")
    if not rep:
        is_valid, error = daemon._ledger.verify_chain(sid)
        events = daemon._ledger.query_events(sid)
        findings = daemon.get_findings(sid)
        last_hash = daemon._ledger.get_last_hash(sid)
        rep = {
            "session_id": str(sid),
            "integrity_status": "TAMPER_VERIFIED" if is_valid else "TAMPER_DETECTED",
            "integrity_error": error,
            "head_event_hash": last_hash,
            "event_count": len(events),
            "findings_count": len(findings),
        }

    report_json = json.dumps(rep, indent=2)
    if output:
        Path(output).write_text(report_json, encoding="utf-8")
        console.print(f"[green]✓ Forensic report written to {output}[/green]")
    else:
        console.print(Panel(report_json, title="📋 Signed Forensic Report", border_style="blue"))


@main.command()
def status() -> None:
    """List sessions and audit ledger health."""
    daemon = _get_daemon()
    sessions = daemon.list_sessions()

    if not sessions:
        console.print("[dim]No audit sessions in local ledger.[/dim]")
        return

    table = Table(title="AgentTrace Audit Ledger")
    table.add_column("Session ID", style="cyan")
    table.add_column("Workspace", style="white")
    table.add_column("Status", style="green")
    table.add_column("Events", justify="right")
    table.add_column("Integrity", style="bold")

    for s in sessions:
        is_valid, _ = daemon._ledger.verify_chain(s.session_id)
        integrity_label = "[green]VERIFIED[/green]" if is_valid else "[red]TAMPERED[/red]"
        table.add_row(
            str(s.session_id)[:8] + "...",
            s.config.workspace_path,
            s.status.value if hasattr(s.status, "value") else str(s.status),
            str(s.event_count),
            integrity_label,
        )

    console.print(table)


@main.command(name="stop")
@click.argument("session_id", required=False)
def stop_cmd(session_id: str | None) -> None:
    """Stop an active session."""
    daemon = _get_daemon()

    async def _stop() -> None:
        if session_id:
            sid = UUID(session_id)
            await daemon.stop_session(sid)
            console.print(f"[green]✓ Session {session_id[:8]}... stopped[/green]")
        else:
            for s in daemon.list_sessions():
                await daemon.stop_session(s.session_id)
            console.print("[green]✓ All active sessions stopped[/green]")
        await daemon.stop()

    asyncio.run(_stop())


if __name__ == "__main__":
    main()
