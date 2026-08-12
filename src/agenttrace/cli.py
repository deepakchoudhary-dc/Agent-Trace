"""AgentTrace CLI — Click-based command-line interface.

Commands:
  agenttrace start --workspace <path> --task "<request>" [--agent auto|codex|claude|copilot]
  agenttrace approve <finding-id> --scope <scoped-policy>
  agenttrace report <session-id>
  agenttrace status
  agenttrace stop [session-id]
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from uuid import UUID

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from agenttrace.daemon import AgentTraceDaemon
from agenttrace.models.session import AgentType

console = Console()

# Global daemon instance (created on start)
_daemon: AgentTraceDaemon | None = None


def _get_daemon() -> AgentTraceDaemon:
    """Get or create the daemon instance."""
    global _daemon
    if _daemon is None:
        _daemon = AgentTraceDaemon()
    return _daemon


@click.group()
@click.version_option(version="0.1.0", prog_name="agenttrace")
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
    daemon = _get_daemon()
    workspace_path = str(Path(workspace).resolve())

    console.print(Panel(
        f"[bold green]Starting AgentTrace[/bold green]\n"
        f"Workspace: {workspace_path}\n"
        f"Task: {task or '(not specified)'}\n"
        f"Agent: {agent}",
        title="🔍 AgentTrace",
        border_style="green",
    ))

    async def _start() -> None:
        await daemon.start()
        session = await daemon.create_session(
            workspace_path=workspace_path,
            task_description=task,
            agent_type=AgentType(agent),
        )

        console.print(f"\n[green]✓[/green] Session started: [bold]{session.session_id}[/bold]")
        console.print(f"  Status: {session.status}")
        console.print(f"  Adapter: {daemon._adapters[session.session_id].adapter_name}")

        # Show observability gaps
        adapter = daemon._adapters[session.session_id]
        gaps = adapter.observability_gaps
        if gaps:
            console.print("\n[yellow]⚠ Observability gaps:[/yellow]")
            for gap in gaps:
                console.print(f"  • {gap}")

        console.print("\n[dim]Press Ctrl+C to stop the session[/dim]")

        # Run until interrupted
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping session...[/yellow]")
            await daemon.stop_session(session.session_id)
            await daemon.stop()
            console.print("[green]✓ Session stopped[/green]")

    asyncio.run(_start())


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
    "--expiry", "-e",
    type=int,
    default=60,
    help="Approval expiry in minutes.",
)
def approve(finding_id: str, scope: str, reason: str, expiry: int) -> None:
    """Approve a policy finding."""
    daemon = _get_daemon()

    # Find the session with this finding
    sessions = daemon.list_sessions()
    if not sessions:
        console.print("[red]No active sessions[/red]")
        return

    session = sessions[0]  # Use first active session
    approval_mgr = daemon.get_approval_manager(session.session_id)
    if not approval_mgr:
        console.print("[red]No approval manager for session[/red]")
        return

    approval = approval_mgr.record_approval(
        finding_id=finding_id,
        approved=True,
        reason=reason,
        scope=scope,
        expiry_minutes=expiry,
    )

    console.print(Panel(
        f"[green]✓ Approval granted[/green]\n"
        f"Finding: {finding_id}\n"
        f"Scope: {scope}\n"
        f"Reason: {reason or '(not specified)'}\n"
        f"Expires in: {expiry} minutes",
        title="🔐 Approval",
        border_style="green",
    ))


@main.command()
@click.argument("session_id")
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file for the report.",
)
def report(session_id: str, output: str | None) -> None:
    """Generate a forensic report for a session."""
    daemon = _get_daemon()
    sid = UUID(session_id)

    session = daemon.get_session(sid)
    graph = daemon.get_graph(sid)
    contract = daemon.get_contract(sid)

    if not session:
        console.print(f"[red]Session {session_id} not found[/red]")
        return

    # Build report
    report_data = {
        "session_id": str(sid),
        "workspace": session.config.workspace_path,
        "task": session.task_description,
        "status": session.status,
        "started_at": session.started_at.isoformat(),
        "stopped_at": session.stopped_at.isoformat() if session.stopped_at else None,
        "event_count": session.event_count,
    }

    if contract:
        report_data["task_contract"] = {
            "goal": contract.goal,
            "allowed_paths": contract.allowed_paths,
            "prohibited_paths": contract.prohibited_paths,
            "risk_level": contract.risk_level,
        }

    if graph:
        report_data["graph_summary"] = {
            "nodes": graph.node_count,
            "edges": graph.edge_count,
        }

    # Get timeline and findings
    timeline = daemon.get_timeline(sid)
    findings = daemon.get_findings(sid)
    report_data["timeline_events"] = len(timeline)
    report_data["policy_findings"] = len(findings)

    # Output
    report_json = json.dumps(report_data, indent=2, default=str)

    if output:
        Path(output).write_text(report_json, encoding="utf-8")
        console.print(f"[green]✓ Report saved to {output}[/green]")
    else:
        console.print(Panel(report_json, title="📋 Forensic Report", border_style="blue"))


@main.command()
def status() -> None:
    """Show status of active sessions."""
    daemon = _get_daemon()
    sessions = daemon.list_sessions()

    if not sessions:
        console.print("[dim]No active sessions[/dim]")
        return

    table = Table(title="Active Sessions")
    table.add_column("Session ID", style="cyan")
    table.add_column("Workspace", style="white")
    table.add_column("Status", style="green")
    table.add_column("Events", justify="right")
    table.add_column("Started", style="dim")

    for session in sessions:
        table.add_row(
            str(session.session_id)[:8] + "...",
            session.config.workspace_path,
            session.status,
            str(session.event_count),
            session.started_at.strftime("%H:%M:%S"),
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
            sessions = daemon.list_sessions()
            for session in sessions:
                await daemon.stop_session(session.session_id)
            console.print(f"[green]✓ All sessions stopped[/green]")
        await daemon.stop()

    asyncio.run(_stop())


if __name__ == "__main__":
    main()
