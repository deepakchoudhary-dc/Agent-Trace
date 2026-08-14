"""Process tree observer using psutil with Universal AI Agent Classification.

Monitors child processes of agent sessions, auto-detects ANY AI coding tool
(Cline, Kilo Code, Roo Code, Copilot, Claude, Cursor, Aider, Windsurf, Ollama, etc.),
and tracks process lifecycle events with strict workspace scoping.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import psutil  # type: ignore[import-untyped]

from agenttrace.models.events import CommandEvent, ConfidenceLevel, ProcessEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

# Core agent keyword signatures
_UNIVERSAL_AGENT_SIGNATURES = [
    "kilo",
    "cline",
    "roo",
    "copilot",
    "claude",
    "codex",
    "cursor",
    "windsurf",
    "aider",
    "goose",
    "continue",
    "devika",
    "ollama",
    "open-interpreter",
    "antigravity",
    "code.exe",
]

_POLL_INTERVAL = 1.5

# Tools whose invocation is itself evidence worth recording as a CommandEvent.
# Note: this is a *prefix* match on the process name, so short-lived tools
# (curl, wget, git fetch) are captured whenever they survive a poll; the
# shell interpreters (bash/sh/zsh/fish) carry their -c payload in argv.
_COMMAND_TOOL_PREFIXES = [
    "git", "npm", "npx", "yarn", "pnpm", "python", "python3", "pip", "pip3",
    "node", "deno", "bun", "tsc", "vite", "esbuild", "webpack", "rollup",
    "pytest", "curl", "wget", "ssh", "scp", "rsync", "cargo", "go", "rustc",
    "gcc", "clang", "make", "cmake", "gem", "twine", "ruby", "perl", "php",
    "java", "mvn", "gradle", "docker", "docker-compose", "kubectl", "helm",
    "terraform", "aws", "gcloud", "az", "bash", "sh", "zsh", "fish", "cmd.exe",
]

# Shell interpreters whose argv carries the actual command (-c payload)
_SHELL_NAMES = {"bash", "sh", "zsh", "fish"}


class ProcessTreeObserver(BaseObserver):
    """Universal process watcher for AI coding agents and developer toolchains.

    Automatically identifies and attributes actions across Cline, Kilo Code,
    Roo Code, Copilot, Claude Code, Cursor, Aider, manual terminals, and local LLMs.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
        poll_interval: float = _POLL_INTERVAL,
        on_pids_updated: Callable[[set[int]], None] | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._poll_interval = poll_interval
        self._on_pids_updated = on_pids_updated
        self._tracked_pids: dict[int, dict[str, str | int | None]] = {}
        self._workspace_resolved = Path(workspace_path).resolve()

    async def _run(self) -> None:
        """Poll process tree at regular intervals."""
        logger.info("Universal ProcessTreeObserver watching workspace: %s", self.workspace_path)

        try:
            while self._running:
                await self._scan_processes()
                await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            logger.debug("ProcessTreeObserver cancelled")
        except Exception:
            logger.exception("ProcessTreeObserver error")

    async def _scan_processes(self) -> None:
        """Scan running processes for workspace-scoped activity."""
        current_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "cwd"]):
            try:
                info = proc.info
                pid = info["pid"]
                if not pid:
                    continue

                name = (info.get("name") or "").lower()
                cmdline = info.get("cmdline") or []
                cwd = info.get("cwd") or ""

                if not self._is_relevant(name, cmdline, cwd):
                    continue

                current_pids.add(pid)
                if pid in self._tracked_pids:
                    continue

                # New relevant workspace process found
                proc_info: dict[str, str | int | None] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": name,
                    "cmdline": " ".join(cmdline) if cmdline else name,
                    "cwd": cwd,
                }
                self._tracked_pids[pid] = proc_info

                actor_id = self._classify_actor(name, str(proc_info["cmdline"]))
                event = ProcessEvent(
                    session_id=self.session_id,
                    actor_id=actor_id,
                    source_adapter="process_tree_observer",
                    confidence=ConfidenceLevel.HIGH,
                    pid=pid,
                    ppid=info.get("ppid") or 0,
                    command_line=str(proc_info["cmdline"]),
                    working_dir=cwd,
                    started_at=datetime.now(timezone.utc),
                    payload={"process_name": name, "actor": actor_id},
                )
                await self.emit(event)

                # If process is a discrete command, also emit CommandEvent for
                # graph correlation. Shell interpreters with a -c payload carry
                # the *actual* command the agent ran in argv — extract it so the
                # boundary/policy engines see the real string, not just "bash".
                clean_cmd = str(proc_info["cmdline"])
                if any(tool_prefix in name for tool_prefix in _COMMAND_TOOL_PREFIXES):
                    command = clean_cmd[:300]
                    if name in _SHELL_NAMES:
                        extracted = self._extract_shell_payload(cmdline)
                        if extracted:
                            command = extracted[:300]
                    cmd_event = CommandEvent(
                        session_id=self.session_id,
                        actor_id=actor_id,
                        source_adapter="process_tree_observer",
                        confidence=ConfidenceLevel.HIGH,
                        command=command,
                        working_dir=cwd,
                        payload={"pid": pid, "tool": name, "raw_cmdline": clean_cmd[:300]},
                    )
                    await self.emit(cmd_event)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for terminated processes
        terminated = set(self._tracked_pids.keys()) - current_pids
        for pid in terminated:
            proc_info = self._tracked_pids.pop(pid)
            name = str(proc_info.get("name") or "")
            actor_id = self._classify_actor(name, str(proc_info.get("cmdline") or ""))
            event = ProcessEvent(
                session_id=self.session_id,
                actor_id=actor_id,
                source_adapter="process_tree_observer",
                confidence=ConfidenceLevel.HIGH,
                pid=pid,
                ppid=int(proc_info.get("ppid") or 0),
                command_line=str(proc_info.get("cmdline") or ""),
                working_dir=str(proc_info.get("cwd") or ""),
                ended_at=datetime.now(timezone.utc),
                payload={"terminated": True, "actor": actor_id},
            )
            await self.emit(event)

        # Notify network observer of current active PIDs
        if self._on_pids_updated:
            self._on_pids_updated(set(self._tracked_pids.keys()))

    @staticmethod
    def _extract_shell_payload(cmdline: list[str]) -> str:
        """Extract the actual command from `bash -c '<cmd>' ...` argv.

        psutil returns argv as a list, so the `-c` payload is a single element
        (e.g. ``["bash", "-c", "rm -rf /tmp/x"]``). We return that element
        verbatim — the boundary/policy engines see the real command string.
        """
        try:
            idx = cmdline.index("-c")
        except ValueError:
            return ""
        if idx + 1 < len(cmdline):
            return cmdline[idx + 1].strip()
        return ""

    def _is_relevant(self, name: str, cmdline: list[str], cwd: str) -> bool:
        """Determine if a process is relevant to track strictly within the workspace."""
        # 1. Check if CWD is within workspace
        if cwd:
            try:
                proc_cwd = Path(cwd).resolve()
                if proc_cwd == self._workspace_resolved or self._workspace_resolved in proc_cwd.parents:
                    return True
            except (ValueError, TypeError, OSError):
                pass

        # 2. Check if command line contains workspace path explicitly
        if cmdline and self.workspace_path:
            cmdline_str = " ".join(cmdline).lower()
            if str(self._workspace_resolved).lower() in cmdline_str or self.workspace_path.lower() in cmdline_str:
                return True

        # 3. Known or detected AI agent tool executing within or pointing to workspace
        if any(agent_sig in name for agent_sig in _UNIVERSAL_AGENT_SIGNATURES):
            cmdline_str = " ".join(cmdline).lower()
            if self.workspace_path.lower() in cmdline_str:
                return True

        return False

    @staticmethod
    def _classify_actor(name: str, cmdline_str: str) -> str:
        """Dynamically and universally classify any AI agent, extension, CLI, or tool."""
        combined = (name + " " + cmdline_str).lower()

        # 1. Match known AI coding assistants and CLI tools
        known_agents = [
            ("kilo", "agent:kilo_code"),
            ("cline", "agent:cline"),
            ("roo-cline", "agent:roo_code"),
            ("roo", "agent:roo_code"),
            ("copilot", "agent:copilot_chat"),
            ("claude", "agent:claude_code"),
            ("codex", "agent:codex_cli"),
            ("cursor", "agent:cursor_ai"),
            ("windsurf", "agent:windsurf_ai"),
            ("aider", "agent:aider"),
            ("goose", "agent:goose_ai"),
            ("continue", "agent:continue_dev"),
            ("devika", "agent:devika"),
            ("ollama", "agent:ollama_local"),
            ("open-interpreter", "agent:open_interpreter"),
            ("antigravity", "agent:antigravity_ide"),
        ]
        for key, agent_id in known_agents:
            if key in combined:
                return agent_id

        # 2. Extract VS Code / IDE extension name dynamically
        # e.g., "extensions\publisher.extension-name\..."
        ext_match = re.search(r"extensions[\\/]([a-zA-Z0-9_\-\.]+)[\\/]", cmdline_str, re.IGNORECASE)
        if ext_match:
            ext_full = ext_match.group(1).lower()
            ext_short = ext_full.split(".")[-1]
            return f"agent:{ext_short}"

        # 3. Interactive Developer Terminals
        if any(k in name.lower() for k in ["powershell", "cmd.exe", "bash", "zsh", "fish"]):
            return "terminal:developer"

        # 4. Standard developer build tools, compilers, and runtimes
        if any(k in name.lower() for k in ["git", "npm", "node", "python", "pytest", "tsc", "vite", "esbuild", "pip", "cargo", "go", "docker", "make"]):
            clean_name = name.lower().replace(".exe", "")
            return f"tool:{clean_name}"

        return f"process:{name.lower().replace('.exe', '')}"

    def get_tracked_pids(self) -> set[int]:
        """Return currently tracked workspace PIDs."""
        return set(self._tracked_pids.keys())
