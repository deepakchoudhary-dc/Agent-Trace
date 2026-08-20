"""AgentTrace CLI — Click-based command-line interface.

The CLI is a thin client over the local daemon API. All state lives in the
daemon process (data_dir); commands fail loudly — never silently fall back to
direct ledger access — when the daemon is not running.

Commands:
  agenttrace start --workspace <path> --task "<request>" [--agent auto|codex|claude|copilot]
  agenttrace daemon [--port N]                # run daemon in the foreground
  agenttrace daemon stop                      # stop daemon + all sessions
  agenttrace stop [session-id]
  agenttrace status
  agenttrace approve <finding-id> --scope <scoped-policy> [--session-id <id>]
  agenttrace gate <action-type> <target> [--session-id <id>]
  agenttrace verify <session-id>
  agenttrace report <session-id> [--output <file>]
  agenttrace incidents <session-id>
  agenttrace shield check|run|install <session-id> <command...>
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from uuid import UUID

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agenttrace.daemon_entry import DEFAULT_PORT, is_running, spawn_daemon, wait_until_running

console = Console()
logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Raised when the daemon API rejects or cannot be reached."""


def _data_dir() -> Path:
    return Path(os.environ.get("AGENTTRACE_DATA_DIR") or Path.home() / ".agenttrace")


def _api_url() -> str:
    port = os.environ.get("AGENTTRACE_PORT", str(DEFAULT_PORT))
    return f"http://127.0.0.1:{port}"


def _read_token() -> str:
    try:
        return (_data_dir() / "api_token").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _call_api(
    endpoint: str, method: str = "GET", data: dict[str, Any] | None = None
) -> dict[str, Any] | list[Any]:
    """Call the local daemon API; raise ApiError on any failure.

    The daemon is the single writer of the ledger: there is intentionally no
    direct-storage fallback, so a failed call can never masquerade as success.
    """
    url = f"{_api_url()}{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    token = _read_token()
    if token:
        req.add_header("X-AgentTrace-Token", token)
    body = json.dumps(data).encode("utf-8") if data else None

    try:
        with urllib.request.urlopen(req, data=body, timeout=5.0) as resp:  # noqa: S310 (loopback only)
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        with contextlib.suppress(ValueError, OSError):
            detail = json.loads(e.read().decode("utf-8")).get("detail", "")
        if e.code == 401:
            raise ApiError(
                "Invalid or missing API token. Restart the daemon to regenerate it."
            ) from e
        raise ApiError(f"API returned HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ApiError(
            f"Daemon not reachable at {_api_url()} ({e}). "
            "Start it with `agenttrace start` or `agenttrace daemon`."
        ) from e
    if not isinstance(payload, (dict, list)):
        raise ApiError("API returned an unexpected payload")
    return payload


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
    """Start an audit session for a workspace (spawns the daemon if needed)."""
    workspace_path = str(Path(workspace).resolve())
    data_dir = _data_dir()
    port = int(os.environ.get("AGENTTRACE_PORT", str(DEFAULT_PORT)))

    if not is_running(data_dir):
        console.print("[yellow]Starting AgentTrace daemon...[/yellow]")
        spawn_daemon(data_dir, port)
        if not wait_until_running(data_dir, port):
            console.print(
                f"[red]Daemon failed to start. Check the log: {data_dir / 'daemon.log'}[/red]"
            )
            return
        console.print("[green]✓ Daemon started[/green]")

    try:
        res = _call_api("/sessions", method="POST", data={
            "workspace_path": workspace_path,
            "task_description": task,
            "agent_type": agent,
        })
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return

    if not isinstance(res, dict):
        console.print("[red]Unexpected API response[/red]")
        return

    session_id = res["session_id"]
    console.print(Panel(
        f"[bold green]Starting AgentTrace Audit Session[/bold green]\n"
        f"Workspace: {workspace_path}\n"
        f"Task: {task or '(general development audit)'}\n"
        f"Agent: {agent}\n\n"
        f"[green]✓[/green] Session active: [bold cyan]{session_id}[/bold cyan]\n"
        f"  Status: {res.get('status')}\n"
        f"  Adapter: {res.get('adapter')}",
        title="🔍 AgentTrace",
        border_style="green",
    ))

    gaps = res.get("observability_gaps") or []
    if gaps:
        console.print("[yellow]⚠ Observability gaps (unobservable agent internals):[/yellow]")
        for gap in gaps:
            console.print(f"  • {gap}")

    console.print(
        f"\n[dim]Daemon running detached. Stop the session with "
        f"`agenttrace stop {session_id}` (all: `agenttrace stop`).[/dim]"
    )


@main.group()
def daemon() -> None:
    """Manage the local daemon process."""


@daemon.command("run")
@click.option(
    "--port", type=int, default=None,
    help=f"API port (default: {DEFAULT_PORT}, env AGENTTRACE_PORT).",
)
@click.option("--data-dir", type=click.Path(file_okay=False), default=None, help="Data directory.")
def daemon_run(port: int | None, data_dir: str | None) -> None:
    """Run the daemon in the foreground (Ctrl+C to stop)."""
    from agenttrace.daemon_entry import run_server

    target_dir = Path(data_dir) if data_dir else _data_dir()
    run_server(
        target_dir, port or int(os.environ.get("AGENTTRACE_PORT", str(DEFAULT_PORT)))
    )


@daemon.command("stop")
def daemon_stop() -> None:
    """Stop the daemon and all active sessions."""
    try:
        _call_api("/shutdown", method="POST")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    console.print("[green]✓ Daemon stopped[/green]")


@daemon.command("rotate-token")
def daemon_rotate_token() -> None:
    """Regenerate the API token (invalidates all in-flight clients).

    The daemon reads the token file on every verification, so a rotation
    takes effect immediately; any running dashboard session must re-read
    the token.
    """
    from agenttrace.security.token import ApiTokenManager

    manager = ApiTokenManager(_data_dir())
    if is_running(_data_dir()):
        console.print(
            "[yellow]Daemon is running — rotating the token will reject all "
            "in-flight clients until they pick up the new token.[/yellow]"
        )
    old = manager.token()
    new = manager.rotate()
    if old == new:
        console.print("[red]Token rotation failed (token unchanged).[/red]")
        return
    console.print(
        f"[green]✓ API token rotated[/green]\n"
        f"  New token: [bold cyan]{new}[/bold cyan]\n"
        f"  File: {manager.token_path}\n"
        f"  Expires: {manager.token_expiry() or 'unknown'}"
    )


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
    try:
        sessions = _call_api("/sessions")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(sessions, list) or not sessions:
        console.print("[red]No sessions found in local ledger[/red]")
        return

    target_sid = session_id or str(sessions[0]["session_id"])

    # Interpret --scope as a path or command pattern so the enforcement gate
    # can honor the approval for the same path/command later
    affected_paths: list[str] = []
    affected_commands: list[str] = []
    if scope and any(ch in scope for ch in ("/", "\\", ".")):
        affected_paths.append(scope)
    elif scope:
        affected_commands.append(scope)

    try:
        _call_api(f"/sessions/{target_sid}/approvals", method="POST", data={
            "finding_id": finding_id,
            "approved": True,
            "reason": reason,
            "scope": scope,
            "expiry_minutes": expiry,
            "affected_paths": affected_paths,
            "affected_commands": affected_commands,
        })
    except ApiError as e:
        console.print(f"[red]Approval NOT recorded: {e}[/red]")
        return

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

    try:
        sessions = _call_api("/sessions")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(sessions, list) or not sessions:
        console.print("[red]No sessions found in local ledger[/red]")
        return

    target_sid = session_id or str(sessions[0]["session_id"])

    try:
        res = _call_api(f"/sessions/{target_sid}/evaluate", method="POST", data={
            "action_type": action_type,
            "target": target,
            "details": details_dict,
        })
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(res, dict):
        console.print("[red]Unexpected API response[/red]")
        return

    action = res["action"]
    reason = res["reason"]
    req_id = res.get("required_approval_id", "")

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
    res = _call_api(f"/sessions/{sid}/evaluate", method="POST", data={
        "action_type": "command",
        "target": command,
        "details": {},
    })
    if not isinstance(res, dict):
        raise ApiError("Unexpected API response")
    return (
        str(res.get("action", "allow")),
        str(res.get("reason", "")),
        str(res.get("required_approval_id", "")),
    )


def _record_shield_approval(sid: UUID, command: str, reason: str, req_id: str) -> None:
    """Record a scoped approval for the exact command the gate paused on."""
    _call_api(f"/sessions/{sid}/approvals", method="POST", data={
        "finding_id": req_id or "gate",
        "approved": True,
        "reason": reason,
        "scope": "command",
        "expiry_minutes": 60,
        "affected_paths": [],
        "affected_commands": [command],
    })


@shield.command("check", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("session_id")
@click.argument("command", nargs=-1, required=True)
def shield_check(session_id: str, command: tuple[str, ...]) -> None:
    """Evaluate a command against the gate and print the verdict WITHOUT running it."""
    sid = UUID(session_id)
    cmdline = " ".join(command)
    try:
        action, reason, req_id = _shield_verdict(sid, cmdline)
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(3) from e
    style = {"block": "red", "pause": "yellow", "allow": "green"}[action]
    lines = [f"Command: {cmdline}", f"Decision: {reason}"]
    if req_id:
        lines.append(f"Approval ID: {req_id}")
    verdict_title = {
        "block": "⛔ SHIELD: BLOCKED",
        "pause": "🛑 SHIELD: APPROVAL REQUIRED",
        "allow": "✅ SHIELD: ALLOWED",
    }[action]
    console.print(Panel(
        "\n".join(lines),
        title=verdict_title,
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

    try:
        action, reason, req_id = _shield_verdict(sid, cmdline)
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(3) from e

    if action == "block":
        console.print(f"[bold red]⛔ BLOCKED — not executing:[/bold red] {cmdline}")
        console.print(f"[red]  {reason}[/red]")
        raise SystemExit(2)

    if action == "pause":
        console.print(f"[yellow]🛑 APPROVAL REQUIRED:[/yellow] {cmdline}")
        console.print(f"[yellow]  {reason}[/yellow]")
        if not approve_all and not click.confirm("Approve and execute?", default=False):
            console.print("[red]Denied — not executing.[/red]")
            raise SystemExit(1)
        try:
            _record_shield_approval(sid, cmdline, "granted via shield run", req_id)
        except ApiError as e:
            console.print(f"[red]Approval NOT recorded: {e}[/red]")
            raise SystemExit(3) from e
        console.print("[green]✓ Approval recorded for this exact command.[/green]")

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
        try:
            session = _call_api(f"/sessions/{sid}")
        except ApiError as e:
            console.print(f"[red]{e}[/red]")
            return
        if not isinstance(session, dict):
            console.print("[red]Session not found. Pass --workspace explicitly.[/red]")
            return
        workspace_path = session["workspace_path"]

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
        ps1_wrapper = bin_dir / f"{tool}.ps1"
        ps1_wrapper.write_text(
            f"agenttrace shield run {sid} -- $args\n",
            encoding="utf-8",
        )
        written.extend([str(bash_wrapper), str(cmd_wrapper), str(ps1_wrapper)])

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
    try:
        incs = _call_api(f"/sessions/{sid}/incidents")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(incs, list) or not incs:
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
    try:
        res = _call_api(f"/sessions/{sid}/verify")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(res, dict):
        console.print("[red]Unexpected API response[/red]")
        return

    if res["verified"]:
        console.print(Panel(
            f"[bold green]✓ CRYPTOGRAPHIC HASH CHAIN VERIFIED[/bold green]\n\n"
            f"Session ID:       {sid}\n"
            f"Total Events:     {res['event_count']}\n"
            f"Head Event Hash:  {res['last_event_hash']}\n"
            f"Tamper Status:    UNBROKEN & UNMODIFIED",
            title="🛡 Forensic Integrity Verification",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ TAMPER DETECTED IN EVENT CHAIN[/bold red]\n\n"
            f"Session ID:       {sid}\n"
            f"Error Detail:     {res.get('error', '')}",
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
    try:
        rep = _call_api(f"/sessions/{sid}/report")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(rep, dict):
        console.print("[red]Unexpected API response[/red]")
        return

    report_json = json.dumps(rep, indent=2)
    if output:
        Path(output).write_text(report_json, encoding="utf-8")
        console.print(f"[green]✓ Forensic report written to {output}[/green]")
    else:
        console.print(Panel(report_json, title="📋 Signed Forensic Report", border_style="blue"))


@main.command()
def status() -> None:
    """List sessions and audit ledger health."""
    try:
        sessions = _call_api("/sessions")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")
        return
    if not isinstance(sessions, list) or not sessions:
        console.print("[dim]No audit sessions in local ledger.[/dim]")
        return

    table = Table(title="AgentTrace Audit Ledger")
    table.add_column("Session ID", style="cyan")
    table.add_column("Workspace", style="white")
    table.add_column("Status", style="green")
    table.add_column("Events", justify="right")
    table.add_column("Integrity", style="bold")

    for s in sessions:
        sid = s["session_id"]
        try:
            v = _call_api(f"/sessions/{sid}/verify")
            verified = bool(v["verified"]) if isinstance(v, dict) else False
        except ApiError:
            verified = False
        integrity_label = "[green]VERIFIED[/green]" if verified else "[red]TAMPERED[/red]"
        table.add_row(
            sid[:8] + "...",
            s.get("workspace_path", ""),
            s.get("status", "?"),
            str(s.get("event_count", 0)),
            integrity_label,
        )

    console.print(table)


@main.command(name="stop")
@click.argument("session_id", required=False)
def stop_cmd(session_id: str | None) -> None:
    """Stop an active session (all sessions when no ID is given)."""
    try:
        if session_id:
            sid = UUID(session_id)
            _call_api(f"/sessions/{sid}/stop", method="POST")
            console.print(f"[green]✓ Session {session_id[:8]}... stopped[/green]")
        else:
            sessions = _call_api("/sessions")
            if not isinstance(sessions, list):
                console.print("[red]Unexpected API response[/red]")
                return
            active = [s for s in sessions if s.get("status") not in ("stopped", "completed")]
            for s in active:
                _call_api(f"/sessions/{s['session_id']}/stop", method="POST")
            if not active:
                console.print("[dim]No active sessions.[/dim]")
            else:
                console.print("[green]✓ All active sessions stopped[/green]")
    except ApiError as e:
        console.print(f"[red]{e}[/red]")


if __name__ == "__main__":
    main()
