"""Process tree observer using psutil with Universal AI Agent Classification.

Monitors child processes of agent sessions, auto-detects ANY AI coding tool
(Cline, Kilo Code, Roo Code, Copilot, Claude, Cursor, Aider, Windsurf, Ollama, etc.),
and tracks process lifecycle events with strict workspace scoping.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil  # type: ignore[import-untyped]

from agenttrace.models.events import CommandEvent, ConfidenceLevel, ProcessEvent
from agenttrace.observers.base import BaseObserver, EventCallback

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from agenttrace.observers.job_object_process import WindowsJobObject

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
# shell interpreters (bash/sh/zsh/fish, cmd.exe, powershell) carry their
# -c/-Command payload in argv.
_COMMAND_TOOL_PREFIXES = [
    "git", "npm", "npx", "yarn", "pnpm", "python", "python3", "pip", "pip3",
    "node", "deno", "bun", "tsc", "vite", "esbuild", "webpack", "rollup",
    "pytest", "curl", "wget", "ssh", "scp", "rsync", "cargo", "go", "rustc",
    "gcc", "clang", "make", "cmake", "gem", "twine", "ruby", "perl", "php",
    "java", "mvn", "gradle", "docker", "docker-compose", "kubectl", "helm",
    "terraform", "aws", "gcloud", "az", "bash", "sh", "zsh", "fish",
    "cmd.exe", "powershell", "pwsh",
]

# Shell interpreters whose argv carries the actual command (-c payload)
_SHELL_NAMES = {"bash", "sh", "zsh", "fish", "cmd.exe", "powershell", "pwsh"}

# Max entries in the irrelevant-process cache (pid → create_time). A pid
# whose identity was already deemed irrelevant is skipped without the
# expensive cwd lookup on Windows. Identities are immutable per create_time,
# so a cached verdict is final; a recycled pid gets a fresh create_time and
# is re-evaluated.
_MAX_IRRELEVANT = 8192


def _is_shell(name: str) -> bool:
    """True for shell interpreters whose argv carries the real command."""
    return (
        name in _SHELL_NAMES
        or name.startswith("cmd")
        or name.startswith("powershell")
        or name.startswith("pwsh")
    )


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
        job_object: WindowsJobObject | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._poll_interval = poll_interval
        self._on_pids_updated = on_pids_updated
        self._job_object = job_object
        self._tracked_pids: dict[int, dict[str, str | int | float | None]] = {}
        self._irrelevant: dict[int, float] = {}
        self._workspace_resolved = Path(workspace_path).resolve()
        self._boost_until: float = 0.0

    def boost_polling(self, duration: float = 2.0) -> None:
        """Temporarily boost polling frequency during high-velocity command execution."""
        import time
        self._boost_until = max(self._boost_until, time.monotonic() + duration)

    async def _run(self) -> None:
        """Poll process tree at regular or adaptive intervals."""
        import time
        logger.info("Universal ProcessTreeObserver watching workspace: %s", self.workspace_path)

        try:
            while self._running:
                await self._scan_processes()
                is_boosted = time.monotonic() < self._boost_until
                current_interval = 0.25 if is_boosted else self._poll_interval
                await asyncio.sleep(current_interval)
        except asyncio.CancelledError:
            logger.debug("ProcessTreeObserver cancelled")
        except Exception:
            logger.exception("ProcessTreeObserver error")

    async def _scan_processes(self) -> None:
        """Scan running processes for workspace-scoped activity.

        Two-phase scan: cheap attributes (pid/ppid/name/cmdline/create_time)
        are fetched for every process; the expensive cwd lookup is only done
        for candidates that could plausibly relate to the workspace, and a
        cached "irrelevant" verdict (keyed by pid identity = create_time)
        skips even that.
        """
        current_pids: set[int] = set()
        workspace_l = str(self._workspace_resolved).lower()
        ws_raw_l = self.workspace_path.lower()
        job_pids: set[int] = set(self._job_object.get_pids()) if self._job_object else set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                if not pid:
                    continue

                name = (info.get("name") or "").lower()
                cmdline = info.get("cmdline") or []
                create_time = info.get("create_time")

                # Descendants of already-tracked session processes or Job Object members
                # are always relevant (VULN-04: prevents out-of-workspace CWD escape)
                ppid = info.get("ppid")
                is_descendant = bool(
                    (ppid is not None and ppid in self._tracked_pids)
                    or (pid in job_pids)
                )

                if not is_descendant:
                    # Skip identities already judged irrelevant (no cwd lookup)
                    if create_time is not None and self._irrelevant.get(pid) == create_time:
                        continue

                    # Cheap pre-filter before the expensive cwd syscall:
                    # name hints, shell/terminal interpreters, or the workspace
                    # path appearing in the command line.
                    cmdline_str = " ".join(cmdline).lower()
                    hints_cmdline = (
                        workspace_l in cmdline_str or ws_raw_l in cmdline_str
                    )
                    hints_name = (
                        any(sig in name for sig in _UNIVERSAL_AGENT_SIGNATURES)
                        or any(prefix in name for prefix in _COMMAND_TOOL_PREFIXES)
                        or _is_shell(name)
                    )
                    if not hints_cmdline and not hints_name:
                        if create_time is not None:
                            self._cache_irrelevant(pid, create_time)
                        continue

                    cwd = self._safe_cwd(proc)

                    if not self._is_relevant(name, cmdline, cwd):
                        if create_time is not None:
                            self._cache_irrelevant(pid, create_time)
                        continue
                else:
                    cwd = self._safe_cwd(proc)

                current_pids.add(pid)
                if self._job_object and pid not in job_pids:
                    self._job_object.assign_pid(pid)

                if pid in self._tracked_pids:
                    # Canonical process identity = (pid, start time). A pid
                    # reused by a NEW process (the old one exited between
                    # polls) must not be merged with the old record — emit
                    # the termination for the previous identity first.
                    if self._is_pid_reused(self._tracked_pids[pid], info):
                        await self._emit_terminated(pid, self._tracked_pids[pid])
                        self._tracked_pids.pop(pid)
                    else:
                        continue

                # New relevant workspace process found
                proc_info: dict[str, str | int | float | None] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": name,
                    "cmdline": " ".join(cmdline) if cmdline else name,
                    "cwd": cwd,
                    "started_at": create_time,
                }
                self._tracked_pids[pid] = proc_info

                actor_id = self._classify_actor(name, str(proc_info["cmdline"]))
                started_at = datetime.now(timezone.utc)
                if isinstance(create_time, (int, float)) and create_time > 0:
                    started_at = datetime.fromtimestamp(create_time, tz=timezone.utc)

                proc_confidence = (
                    ConfidenceLevel.HIGH if is_descendant else ConfidenceLevel.MEDIUM
                )

                event = ProcessEvent(
                    session_id=self.session_id,
                    actor_id=actor_id,
                    source_adapter="process_tree_observer",
                    confidence=proc_confidence,
                    pid=pid,
                    ppid=info.get("ppid") or 0,
                    command_line=str(proc_info["cmdline"]),
                    working_dir=cwd,
                    started_at=started_at,
                    payload={
                        "process_name": name,
                        "actor": actor_id,
                        "contained_descendant": is_descendant,
                    },
                )
                await self.emit(event)

                # If process is a discrete command, also emit CommandEvent for
                # graph correlation. Shell interpreters with a -c/-Command
                # payload carry the *actual* command the agent ran in argv —
                # extract it so the boundary/policy engines see the real
                # string, not just "bash" / "cmd.exe" / "powershell".
                clean_cmd = str(proc_info["cmdline"])
                if any(tool_prefix in name for tool_prefix in _COMMAND_TOOL_PREFIXES):
                    command = clean_cmd[:300]
                    if _is_shell(name):
                        extracted = self._extract_shell_payload(name, cmdline)
                        if extracted:
                            command = extracted[:300]
                    cmd_event = CommandEvent(
                        session_id=self.session_id,
                        actor_id=actor_id,
                        source_adapter="process_tree_observer",
                        confidence=proc_confidence,
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
            await self._emit_terminated(pid, proc_info)

        # Notify network observer of current active PIDs
        if self._on_pids_updated:
            self._on_pids_updated(set(self._tracked_pids.keys()))

    def _cache_irrelevant(self, pid: int, create_time: float) -> None:
        """Cache an irrelevant-process verdict, bounding the cache size."""
        if len(self._irrelevant) >= _MAX_IRRELEVANT:
            self._irrelevant.clear()
        self._irrelevant[pid] = create_time

    @staticmethod
    def _safe_cwd(proc: Any) -> str:
        """Fetch a process cwd, tolerating races and access denials."""
        try:
            return str(proc.cwd() or "")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return ""

    @staticmethod
    def _is_pid_reused(
        prev_info: dict[str, str | int | float | None],
        current_info: dict[str, Any],
    ) -> bool:
        """True when a tracked pid now belongs to a different process identity.

        A pid is canonical only together with its start time (create_time).
        When the tracked start time differs from the live process, the old
        identity has exited and the pid was recycled.
        """
        prev_started = prev_info.get("started_at")
        cur_started = current_info.get("create_time")
        if prev_started is None or cur_started is None:
            return False
        return bool(prev_started != cur_started)

    async def _emit_terminated(
        self,
        pid: int,
        proc_info: dict[str, str | int | float | None],
    ) -> None:
        """Emit a ProcessEvent marking the end of a tracked process identity."""
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

    @staticmethod
    def _extract_shell_payload(name: str, cmdline: list[str]) -> str:
        """Extract the actual command from shell argv.

        psutil returns argv as a list, so the payload is a single element:

        - POSIX shells: ``["bash", "-c", "rm -rf /tmp/x"]``
        - cmd.exe:     ``["cmd.exe", "/c", "rmdir /s /q C:\\tmp\\x"]``
        - PowerShell:  ``["powershell.exe", "-Command", "Remove-Item -Recurse ..."]``

        The payload is returned verbatim — the boundary/policy engines see
        the real command string, not just the interpreter name.
        """
        flags: tuple[str, ...]
        if name.startswith("cmd") or name.startswith("powershell") or name.startswith("pwsh"):
            flags = ("/c", "-c", "-command", "/command")
        else:
            flags = ("-c",)
        lowered = [arg.lower() for arg in cmdline]
        try:
            idx = next(i for i, arg in enumerate(lowered) if arg in flags)
        except StopIteration:
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
                within = (
                    proc_cwd == self._workspace_resolved
                    or self._workspace_resolved in proc_cwd.parents
                )
                if within:
                    return True
            except (ValueError, TypeError, OSError):
                pass

        # 2. Check if command line contains workspace path explicitly
        if cmdline and self.workspace_path:
            cmdline_str = " ".join(cmdline).lower()
            resolved_l = str(self._workspace_resolved).lower()
            if resolved_l in cmdline_str or self.workspace_path.lower() in cmdline_str:
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
        ext_match = re.search(
            r"extensions[\\/]([a-zA-Z0-9_\-\.]+)[\\/]", cmdline_str, re.IGNORECASE
        )
        if ext_match:
            ext_full = ext_match.group(1).lower()
            ext_short = ext_full.split(".")[-1]
            return f"agent:{ext_short}"

        # 3. Interactive Developer Terminals
        if any(k in name.lower() for k in ["powershell", "cmd.exe", "bash", "zsh", "fish"]):
            return "terminal:developer"

        # 4. Standard developer build tools, compilers, and runtimes
        tool_keys = [
            "git", "npm", "node", "python", "pytest", "tsc", "vite",
            "esbuild", "pip", "cargo", "go", "docker", "make",
        ]
        if any(k in name.lower() for k in tool_keys):
            clean_name = name.lower().replace(".exe", "")
            return f"tool:{clean_name}"

        return f"process:{name.lower().replace('.exe', '')}"

    def get_tracked_pids(self) -> set[int]:
        """Return currently tracked workspace PIDs."""
        return set(self._tracked_pids.keys())
