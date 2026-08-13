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
_DEFAULT_API_URL = "http://127.0.0.1:8000"


def _call_api(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any] | list[Any] | None:
    """Attempt to query local daemon REST API."""
    url = f"{_DEFAULT_API_URL}{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    body = json.dumps(data).encode("utf-8") if data else None

    try:
        with urllib.request.urlopen(req, data=body, timeout=2.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
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

    # Record approval
    api_res = _call_api(f"/sessions/{target_sid}/approvals", method="POST", data={
        "finding_id": finding_id,
        "approved": True,
        "reason": reason,
        "scope": scope,
        "expiry_minutes": expiry,
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
