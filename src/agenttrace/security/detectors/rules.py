"""Rule implementations for the threat-detection engine.

Each rule inspects a single observed event and returns zero or more
:class:`~agenttrace.security.detectors.base.DetectorFinding` results. Rules
only use host-observable fields — commands, file paths, diff content,
network destinations, git actions, process metadata — and never claim to
observe model intent.
"""

from __future__ import annotations

import json
import re
from collections import deque
from typing import Any

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    GitEvent,
    NetworkEvent,
    ProcessEvent,
    ToolRequestEvent,
    ToolResultEvent,
)
from agenttrace.security.detectors.base import DetectionContext, DetectorFinding


def _collect_texts(event: EventBase) -> list[str]:
    """Free-text surfaces of an event for marker scanning."""
    texts: list[str] = []
    if isinstance(event, CommandEvent):
        if event.command:
            texts.append(event.command)
        if event.output:
            texts.append(event.output)
    elif isinstance(event, FileMutationEvent):
        if event.diff_summary:
            texts.append(event.diff_summary)
    elif isinstance(event, ProcessEvent):
        if event.command_line:
            texts.append(event.command_line)
    elif isinstance(event, ToolRequestEvent):
        texts.append(json.dumps(event.tool_args, sort_keys=True))
    elif isinstance(event, ToolResultEvent):
        if event.output_summary:
            texts.append(event.output_summary)
    return texts


def _command(event: EventBase) -> str:
    """Shell command text of an event, or empty string."""
    if isinstance(event, CommandEvent):
        return event.command
    if isinstance(event, ProcessEvent):
        return event.command_line
    return ""


# ---------------------------------------------------------------------------
# 1. Prompt-injection markers — marker TEXT observed in artifacts.
#    Confidence is LOW by design: this is a content signal, never intent.
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_MARKERS: tuple[str, ...] = (
    r"ignore\s+(all\s+|any\s+)?(previous|prior)\s+(instructions?|directions?|messages)",
    r"disregard\s+(your\s+|all\s+|previous\s+)?instructions?",
    r"override\s+(your\s+|the\s+|all\s+)?(instructions?|system prompt)",
    r"system\s+prompt\s*[:;]?\s*(override|replace|update|change)",
    r"new\s+(system\s+)?instructions?",
    r"you\s+are\s+now\s+",
    r"act\s+as\s+(an\s+)?unrestricted",
    r"act\s+as\s+if\s+(you|this)",
    r"jailbreak",
    r"developer\s+mode",
    r"DAN\s+mode",
    r"remove\s+(your\s+)?guardrails",
    r"bypass\s+(your\s+)?(safety|security|guardrails)",
    r"do\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules)",
    r"pretend\s+you\s+(are|have)",
    r"follow\s+these\s+instructions\s+above\s+all",
)


class PromptInjectionDetector:
    """Flags marker phrasing consistent with prompt injection observed in artifacts."""

    detector_id = "prompt_injection_markers"
    name = "Prompt-Injection Marker Text"
    _patterns = [re.compile(p, re.IGNORECASE) for p in _PROMPT_INJECTION_MARKERS]

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if isinstance(event, (GitEvent, NetworkEvent)):
            return []
        for text in _collect_texts(event):
            for pattern in self._patterns:
                match = pattern.search(text)
                if match:
                    return [
                        DetectorFinding(
                            detector_id=self.detector_id,
                            name=self.name,
                            severity="medium",
                            confidence=ConfidenceLevel.LOW,
                            description=(
                                "Marker text consistent with prompt injection observed in "
                                f"artifact ({match.group(0)!r}). Content signal only — the "
                                "model's response or intent is NOT asserted."
                            ),
                            evidence_refs=[str(event.event_id)],
                            affected_command=(
                                text[:100]
                                if isinstance(event, (CommandEvent, ProcessEvent))
                                else ""
                            ),
                            requires_approval=False,
                        )
                    ]
        return []


# ---------------------------------------------------------------------------
# 2. Config-file tampering — writes to agent/tool configuration that can
#    redirect model behavior, exfiltrate tokens, or disable guards.
# ---------------------------------------------------------------------------

_TAMPER_PATTERNS: tuple[str, ...] = (
    r"\.claude[/\\]settings(\.local)?\.json$",
    r"\.claude\.json$",
    r"\.claude[/\\]agents[/\\]",
    r"\.claude[/\\]commands[/\\]",
    r"CLAUDE\.md$",
    r"AGENTS\.md$",
    r"\.cursorrules$",
    r"\.cursor[/\\](rules[/\\]|mcp\.json$|settings\.json$)",
    r"\.mcp\.json$",
    r"\.vscode[/\\]settings\.json$",
    r"\.vscode[/\\]tasks\.json$",
    r"\.copilot[/\\]config\.json$",
    r"\.copilot[/\\]instructions\.md$",
    r"\.codex[/\\](config\.toml$|policy\.json$)",
    r"\.npmrc$",
    r"\.netrc$",
    r"\.docker[/\\]config\.json$",
    r"\.wslconfig$",
    r"\.git-credentials$",
)
_TAMPER_COMPILED = [re.compile(p, re.IGNORECASE) for p in _TAMPER_PATTERNS]


class ConfigTamperDetector:
    """Flags mutations to agent/tool configuration and instruction files."""

    detector_id = "config_tamper"
    name = "Agent Configuration Tampering"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if not isinstance(event, FileMutationEvent):
            return []
        path = event.file_path
        for pattern in _TAMPER_COMPILED:
            if pattern.search(path):
                return [
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=self.severity,
                        confidence=ConfidenceLevel.HIGH,
                        description=(
                            f"{event.mutation_type} of agent/tool config or instruction "
                            f"file: {path}"
                        ),
                        evidence_refs=[str(event.event_id)],
                        affected_path=path,
                        requires_approval=False,
                    )
                ]
        return []


# ---------------------------------------------------------------------------
# 3. Credential-read heuristics — commands reading secret material.
# ---------------------------------------------------------------------------

_CRED_READER_VERBS = (
    r"cat",
    r"less",
    r"more",
    r"head",
    r"tail",
    r"type",
    r"Get-Content",
    r"vim",
    r"nano",
    r"vi",
    r"strings",
    r"xxd",
    r"od",
    r"cp",
    r"sed",
    r"awk",
)
_CRED_TARGETS = (
    r"\.env\b",
    r"\.env\.[A-Za-z0-9_]+",
    r"MEMORY\.md",
    r"id_rsa\b",
    r"id_ed25519\b",
    r"\.ssh[/\\]",
    r"\.aws[/\\]",
    r"credentials",
    r"kubeconfig",
    r"\.netrc",
    r"\.pgpass",
    r"\.pypirc",
    r"\.npmrc",
    r"\.git-credentials",
    r"tokens?\.(json|txt)",
    r"secrets?\.(json|txt|yaml)",
)
_CRED_READER_RE = re.compile(r"(?:" + "|".join(_CRED_READER_VERBS) + r")\s+", re.IGNORECASE)
_CRED_TARGET_RE = re.compile(r"(?:" + "|".join(_CRED_TARGETS) + r")", re.IGNORECASE)
_TOKEN_QUERY_RE = re.compile(
    r"gh\s+auth\s+token|aws\s+configure\s+get\s+aws_secret_access_key|"
    r"az\s+account\s+get-access-token|gcloud\s+auth\s+print-access-token|"
    r"kubectl\s+get\s+secrets|vault\s+kv\s+get",
    re.IGNORECASE,
)


class CredentialReadDetector:
    """Flags commands that read credential files or dump access tokens."""

    detector_id = "credential_read_heuristic"
    name = "Credential Material Read"
    severity = "critical"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd:
            return []
        reason = ""
        if _TOKEN_QUERY_RE.search(cmd):
            reason = "access-token retrieval command"
        elif _CRED_READER_RE.search(cmd) and _CRED_TARGET_RE.search(cmd):
            reason = "credential file read"
        if not reason:
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description=f"Credential material {reason}: {cmd[:120]}",
                evidence_refs=[str(event.event_id)],
                affected_command=cmd[:200],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 4. Obfuscation-tool invocations.
# ---------------------------------------------------------------------------

_OBFUSCATION_RE = re.compile(
    r"base64\b(?:\s+-[a-zA-Z]*[dD]|\s+--decode)|"
    r"python[23]?\s+-c\s+.*\b(base64|rot13|zlib)\b|"
    r"perl\s+-e\s+.*\b(MIME::Base64|pack\s*\(|unpack\s*\()|"
    r"ruby\s+-e\s+.*\b(base64|Zlib)\b|"
    r"\bxxd\s+-r\b|"
    r"\bgzip\s+-d\b|\bgunzip\b|\bunxz\b|\bbunzip2\b|"
    r"openssl\s+enc\s+-d|"
    r"\brot13\b|rot\s+13|"
    r"tr\s+['\"][A-Za-z]{20,}['\"][A-Za-z]{20,}|"
    r"echo\s+[^|\n;]*\|\s*(base64|xxd|openssl|gzip|gunzip)\b|"
    r"eval\s*\(?\s*\$?\(?\s*echo|"
    r"printf\s+['\"]?(\\x[0-9a-fA-F]{2}){3,}",
    re.IGNORECASE,
)


class ObfuscationDetector:
    """Flags commands invoking decoding/encoding tools on payload material."""

    detector_id = "obfuscation_tool"
    name = "Payload Obfuscation Tool"
    severity = "medium"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd or not _OBFUSCATION_RE.search(cmd):
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.HIGH,
                description=f"Obfuscation/decoding tool invoked: {cmd[:120]}",
                evidence_refs=[str(event.event_id)],
                affected_command=cmd[:200],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 5. Egress anomalies — anonymity channels and paste-style exfil services.
# ---------------------------------------------------------------------------

_TOR_PORTS = {9001, 9030, 9040, 9041, 9050, 9051, 9150}
_PASTE_PATH_RE = re.compile(
    r"paste|dpaste|hastebin|clbin|transfer\.sh|0x0\.st|tmpfiles|file\.io|termbin|ix\.io|sprunge|ugy\.de",
    re.IGNORECASE,
)


class EgressAnomalyDetector:
    """Flags outbound connections to anonymity or paste-style destinations."""

    detector_id = "egress_anomaly"
    name = "Egress Anomaly (Tor / Paste Service)"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if not isinstance(event, NetworkEvent):
            return []
        if event.direction and event.direction.lower() != "outbound":
            return []
        reason = ""
        if event.destination_port in _TOR_PORTS:
            reason = f"Tor/anon network port {event.destination_port}"
        elif event.url_path and _PASTE_PATH_RE.search(event.url_path):
            reason = f"paste-style service path {event.url_path!r}"
        if not reason:
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description=(
                    f"Outbound connection to {event.destination_ip}:{event.destination_port} "
                    f"— {reason}"
                ),
                evidence_refs=[str(event.event_id)],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 6. Git history rewriting.
# ---------------------------------------------------------------------------

_GIT_REWRITE_RE = re.compile(
    r"git\s+filter-branch|git\s+filter-repo|"
    r"git\s+reflog\s+expire|"
    r"git\s+gc\b[^|;]*--prune|"
    r"git\s+update-ref\s+-d\b|"
    r"git\s+commit\s+--amend\b[^|;]*(--force|-f\b)|"
    r"git\s+branch\s+-[dD]\s",
    re.IGNORECASE,
)


class GitHistoryRewritingDetector:
    """Flags commands that rewrite or destroy git history."""

    detector_id = "git_history_rewriting"
    name = "Git History Rewriting"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd or not _GIT_REWRITE_RE.search(cmd):
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.HIGH,
                description=f"Git history rewriting/destruction: {cmd[:120]}",
                evidence_refs=[str(event.event_id)],
                affected_command=cmd[:200],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 7. Path tricks — proc-root escapes and traversal beyond one level.
# ---------------------------------------------------------------------------

_PATH_TRICK_RE = re.compile(
    r"/proc/self/root|/proc/1/root|/proc/\d+/root|/proc/self/(cwd|fd|exe)|"
    r"/dev/fd/\d+|"
    r"%2e%2e|%252e|\.\.%2f|%2e%2e%2f|"
    r"(\.\./){2,}|(\.\.\\){2,}|"
    r"\.\./\.\.\s",
    re.IGNORECASE,
)


class PathTrickDetector:
    """Flags proc-root tricks and multi-level traversal in paths and commands."""

    detector_id = "path_trick"
    name = "Path Traversal / Proc-Root Trick"
    severity = "medium"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if isinstance(event, GitEvent):
            return []
        sources: list[tuple[str, str]] = []
        if isinstance(event, FileMutationEvent):
            sources.append(("path", event.file_path))
        cmd = _command(event)
        if cmd:
            sources.append(("command", cmd))
        for kind, text in sources:
            if _PATH_TRICK_RE.search(text):
                return [
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=self.severity,
                        confidence=ConfidenceLevel.HIGH,
                        description=f"Path traversal or proc-root trick in {kind}: {text[:120]}",
                        evidence_refs=[str(event.event_id)],
                        affected_path=(
                            event.file_path if isinstance(event, FileMutationEvent) else ""
                        ),
                        affected_command=cmd[:200] if cmd else "",
                        requires_approval=False,
                    )
                ]
        return []


# ---------------------------------------------------------------------------
# 8. Privilege changes — namespaces, capabilities, setuid.
# ---------------------------------------------------------------------------

_PRIV_CMDS = {
    "unshare",
    "chroot",
    "nsenter",
    "pivot_root",
    "capsh",
    "setpriv",
    "setuidgid",
    "setcap",
    "setfcap",
    "mknod",
    "setuid",
    "doas",
    "pkexec",
    "gsudo",
}
_PRIV_RE = re.compile(
    r"\bCAP_(NET_ADMIN|SYS_ADMIN|SYS_PTRACE|SETUID|DAC_OVERRIDE)\b|"
    r"\bip\s+netns\s+add|"
    r"chmod\s+u\+s|chmod\s+[ug]\+s\b|chmod\s+\d*[4-7]\d\d[0127]?\s|"
    r"\bsudo\b|\bsu\s+-|start-process\b[^\n]*-verb\s+runas",
    re.IGNORECASE,
)


class PrivilegeChangeDetector:
    """Flags namespace/capability/setuid operations that change privilege."""

    detector_id = "privilege_change"
    name = "Privilege Escalation Tooling"
    severity = "critical"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event).strip()
        if not cmd:
            return []
        base = cmd.split()[0].split("/")[-1].lower() if cmd.split() else ""
        if base in _PRIV_CMDS or _PRIV_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Privilege-affecting tool invoked: {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 9. Sandbox-escape awareness — boundary routing patterns.
# ---------------------------------------------------------------------------

_LINKER_EXEC_RE = re.compile(r"\bld-linux[^\s]*\.so\b|\bld\.so(\.\d+)?\b|\bld-musl[^\s]*\.so\b")
_MEM_STATE_RE = re.compile(r"--state=mem:?/?|--state\s+mem:?/", re.IGNORECASE)
# Trampolines that bypass sandbox exec wrappers or scrub the environment:
# direct procfs pivots and env-clearing execution.
_ESCAPE_TRAMPOLINES = re.compile(
    r"/proc/self/(root|fd|mem)\b|"
    r"(?:\benv\s+-i\b|\bunset\s+(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH)\b)",
    re.IGNORECASE,
)
_SYSTEM_PATHS = (
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/boot/",
    "/var/run/docker.sock",
    "/proc/sys/",
    "/sys/",
    "/dev/",
)
_WRITE_OPS_RE = re.compile(
    r">\s*[^|]|>>\s*|touch\s+|mkdir\s+|cp\s+|mv\s+|rm\s+|git\s+clone|pip\s+install|npm\s+(i|install)",
    re.IGNORECASE,
)


def _is_outside_workspace(path: str, workspace_paths: list[str]) -> bool:
    """True when a path is not under any declared workspace path."""
    normalized = path.replace("\\", "/")
    return not any(
        normalized.startswith(wp.rstrip("/\\").replace("\\", "/") + "/")
        or normalized == wp.rstrip("/\\")
        for wp in workspace_paths
    )


class SandboxEscapeDetector:
    """Flags boundary-routing patterns: linker exec, sandbox config writes,
    ephemeral state invocations, and work outside the declared workspace."""

    detector_id = "sandbox_escape"
    name = "Sandbox-Escape Boundary Routing"
    severity = "critical"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        reasons: list[str] = []

        if isinstance(event, FileMutationEvent):
            path = event.file_path
            if any(path.startswith(prefix) for prefix in _SYSTEM_PATHS):
                reasons.append(f"write to system path {path}")
            elif path.endswith(".wslconfig"):
                reasons.append(f"write to WSL sandbox config {path}")

        cmd = _command(event)
        if cmd:
            if _LINKER_EXEC_RE.search(cmd):
                reasons.append("direct linker/loader execution")
            if _MEM_STATE_RE.search(cmd):
                reasons.append("ephemeral in-memory state invocation")
            if _ESCAPE_TRAMPOLINES.search(cmd):
                reasons.append("sandbox-escape trampoline (procfs/env scrub)")

        if isinstance(event, CommandEvent) and ctx.workspace_paths:
            wd = event.working_dir
            if wd and _WRITE_OPS_RE.search(cmd) and _is_outside_workspace(wd, ctx.workspace_paths):
                reasons.append(f"mutating work outside declared workspace ({wd})")

        if isinstance(event, ProcessEvent) and ctx.workspace_paths:
            wd = event.working_dir
            if wd and _is_outside_workspace(wd, ctx.workspace_paths):
                reasons.append(f"process working directory outside workspace ({wd})")

        if not reasons:
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description="Sandbox boundary routing observed: " + "; ".join(reasons),
                evidence_refs=[str(event.event_id)],
                affected_path=event.file_path if isinstance(event, FileMutationEvent) else "",
                affected_command=cmd[:200] if cmd else "",
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 10. Destructive database operations — data-loss primitives.
# ---------------------------------------------------------------------------

_DESTRUCTIVE_SQL_RE = re.compile(
    r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b|\bTRUNCATE\b|"
    r"\bDELETE\s+FROM\b(?!\s+\w+\s+WHERE)|"
    r"\bALTER\s+\w+\s+DROP\b|\brm\s+-[rf]+\s+[^\s]*\.(?:db|sqlite|sqlite3)\b",
    re.IGNORECASE,
)


class DatabaseDestructionDetector:
    """Flags destructive SQL and database-file deletion (data-loss events).

    Covers the sabotage pattern of erasing evaluation/agent state stored in
    databases (results, checkpoints, test fixtures).
    """

    detector_id = "database_destruction"
    name = "Destructive Database Operations"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        for text in _collect_texts(event):
            match = _DESTRUCTIVE_SQL_RE.search(text)
            if match:
                return [
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=self.severity,
                        confidence=ConfidenceLevel.HIGH,
                        description=f"Destructive database operation: {text[:120]}",
                        evidence_refs=[str(event.event_id)],
                        affected_command=(
                            text[:200]
                            if isinstance(event, (CommandEvent, ProcessEvent))
                            else ""
                        ),
                        requires_approval=False,
                    )
                ]
        return []


# ---------------------------------------------------------------------------
# 11. Multi-agent sabotage — hostile actions against other agents' state.
# ---------------------------------------------------------------------------

_SABOTAGE_RE = re.compile(
    r"\bkill\s+(?:-\d+|-[A-Za-z]+)\b|\bpkill\b|\bkillall\b|\btaskkill\b|\bStop-Process\b|"
    r"\bchmod\s+(?:000|a-w|-R\s+000)\b|\bicacls\s+.*\/deny\b|"
    r"\brm\s+-f\s+[^\s]*\.git[/\\]index\.lock\b|"
    r"\brm\s+-rf\s+[^\s]*(?:[/\\](?:node_modules|__pycache__|\.venv|target|dist)(?:[/\\]|$)|\.git\b)",
    re.IGNORECASE,
)


class MultiAgentSabotageDetector:
    """Flags process kills, permission locks, and deletion of shared state.

    The turf-war failure mode: an agent destroying another agent's
    environment (killing processes, locking permissions, wiping caches,
    deleting git locks) to sabotage a concurrent run.
    """

    detector_id = "multi_agent_sabotage"
    name = "Multi-Agent Sabotage Signals"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd:
            return []
        if _SABOTAGE_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=f"Sabotage signal (kill/lock/state deletion): {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 12. Persistence — outliving the session via cron/services/registry.
# ---------------------------------------------------------------------------

_PERSISTENCE_RE = re.compile(
    r"\bcrontab\b|/etc/cron\.|/etc/systemd/|\bsystemctl\s+enable\b|"
    r"\bupdate-rc\.d\b|\bchkconfig\b|\bschtasks\s+/create\b|"
    r"HKCU\\[^ \"]*\\Run\b|HKEY_CURRENT_USER\\[^ \"]*\\Run\b|"
    r"\.config/autostart|/etc/init\.d/|\breg\s+add\b.*\\Run\b|"
    r"(?:\.bashrc|\.zshrc|\.profile)\b|"
    # Time-delayed re-execution triggers (activates after audits/session):
    r"\bat\s+\d{1,2}:\d{2}\b"
    r"|\b(?:systemctl|systemd-run)[^\n]*\.timer\b|on-calendar="
    r"|new-scheduledtasktrigger[^\n]*\s-at\b"
    r"|\bsleep\s+\d{2,}\s*(?:&&|;)"
    r"|start-sleep\s+-seconds\s+\d{2,}[^\n]*(?:&&|;)",
    re.IGNORECASE,
)


class PersistenceDetector:
    """Flags attempts to establish persistence outside the session lifetime.

    Covers the "lay down infrastructure for later" pattern — cron entries,
    systemd units, scheduled tasks, registry Run keys, and shell rc files
    being modified for later re-execution.
    """

    detector_id = "persistence_malware"
    name = "Persistence Establishment"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if isinstance(event, FileMutationEvent):
            path = event.file_path.replace("\\", "/")
            if any(k in path for k in ("/cron.", "systemd/", "/init.d/", "autostart")):
                return [
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=self.severity,
                        confidence=ConfidenceLevel.MEDIUM,
                        description=f"Persistence-path mutation: {path}",
                        evidence_refs=[str(event.event_id)],
                        affected_path=event.file_path,
                        requires_approval=False,
                    )
                ]
        cmd = _command(event)
        if cmd and _PERSISTENCE_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=f"Persistence-establishment command: {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 13. Test integrity — evaluation-rigging primitives.
# ---------------------------------------------------------------------------

_TEST_RIGGING_RE = re.compile(
    r"--ignore(?:-glob)?(?:=[^\s]+)?(?=\s|['\"]|$)|--deselect\b|"
    r"-k\s+['\"]?not\b|\b@(?:pytest\.mark\.)?skip\b|"
    r"\bskipif\s+True\b|\bunittest\.skip\b|"
    r"\bpython\s+-c\b.*\b(?:r|w)\s*\([^)]*test",
    re.IGNORECASE,
)

_TEST_PATH_RE = re.compile(
    r"(?:^|[/\\\s'\"])(?:tests?|specs?|e2e|__tests__)[/\\]"
    r"|[._-](?:test|spec)(?:[/\\_\s'\"]|$)",
    re.IGNORECASE,
)


class TestIntegrityDetector:
    """Flags evaluation-rigging: test deselection, forced skips, test deletion.

    The METR o3 rigging pattern (14/20 evals gamed): tests deleted or
    deselected, failures forced green, evaluation scope silently narrowed.
    """

    detector_id = "test_integrity"
    name = "Test / Evaluation Rigging"
    severity = "medium"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        reasons: list[str] = []
        if isinstance(event, FileMutationEvent) and _TEST_PATH_RE.search(event.file_path):
            mutation = getattr(event, "mutation_type", "") or ""
            if mutation.lower() in {"delete", "remove", "rename"}:
                reasons.append(f"test file removed ({event.file_path})")
        cmd = _command(event)
        if cmd:
            if _TEST_RIGGING_RE.search(cmd):
                reasons.append(f"test selection rigging ({cmd[:120]})")
            sed_cmd = cmd.strip().startswith("sed")
            if isinstance(event, CommandEvent) and sed_cmd and _TEST_PATH_RE.search(cmd):
                reasons.append("in-place mutation of test file via sed")
        if not reasons:
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description="Test/evaluation rigging: " + "; ".join(reasons),
                evidence_refs=[str(event.event_id)],
                affected_path=event.file_path if isinstance(event, FileMutationEvent) else "",
                affected_command=cmd[:200] if cmd else "",
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 14. PowerShell cradles — encoded/obfuscated remote execution.
# ---------------------------------------------------------------------------

_PS_CRADLE_RE = re.compile(
    r"-encod(?:ed)?\s*command\b|-enc\s+[A-Za-z0-9+/=]{20,}|"
    r"\bIEX\s*\(|\bInvoke-Expression\b|\bDownloadString\b|"
    r"-ExecutionPolicy\s+Bypass\b|(?:^|\s)-nop\b(?:.*)(?:^|\s)-w\s+hidden\b|"
    r"powershell(?:\.exe)?\s+.*\bhidden\b.*\b-enc\b|"
    r"\bwsl(?:\.exe)?\s+.*\bpowershell",
    re.IGNORECASE,
)


class PowerShellCradleDetector:
    """Flags encoded or download-and-execute PowerShell invocation.

    Covers the classic Windows payload delivery chain — base64-encoded
    command lines, ExecutionPolicy bypass, hidden windows — and the WSL
    bridging variant that executes PowerShell from inside a Linux sandbox.
    """

    detector_id = "powershell_cradle"
    name = "PowerShell Payload Cradles"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd:
            return []
        if _PS_CRADLE_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"PowerShell payload cradle: {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 15. Git author/committer spoofing — identity laundering.
# ---------------------------------------------------------------------------

_GIT_SPOOF_RE = re.compile(
    r"\bgit\b[^\n;]*(?:^|\s)-c\s+user\.(?:name|email)\s*=\s*[^\s]+|"
    r"\bGIT_(?:AUTHOR|COMMITTER)_(?:NAME|EMAIL|DATE)\s*=\s*[^\s]+|"
    r"\bgit\s+commit\b[^\n;]*--author\s*=\s*[^\s]+",
    re.IGNORECASE,
)


class GitAuthorSpoofDetector:
    """Flags identity laundering: forged git authorship/committer identity.

    Rewriting attribution hides which agent actually performed a commit —
    the prerequisite for blaming another agent or evading per-agent
    accountability.
    """

    detector_id = "git_author_spoof"
    name = "Git Identity Spoofing"
    severity = "medium"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd:
            return []
        if _GIT_SPOOF_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=f"Git identity override: {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 16. Orphaned commits — parents outside the observed history.
# ---------------------------------------------------------------------------

_EMPTY_SHA_RE = re.compile(r"^0+$")


class OrphanedCommitDetector:
    """Flags commits whose parent chain is absent from the observed session.

    A commit whose parent was never observed is either the first commit of a
    freshly cloned/initialized repository or evidence of history rewriting /
    out-of-band commits (a rebase, filter-branch, or a commit made by a
    different agent outside this session's observation window). The finding
    states exactly that — it never asserts intent.
    """

    detector_id = "orphaned_commit"
    name = "Unobserved Parent Commit Chain"
    severity = "medium"

    def __init__(self) -> None:
        self._seen_hashes: dict[str, set[str]] = {}
        self._flagged: dict[str, set[tuple[str, str]]] = {}

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if not isinstance(event, GitEvent):
            return []
        if event.git_action not in {"commit", "merge"} or not event.commit_hash:
            return []
        if _EMPTY_SHA_RE.match(event.commit_hash) or _EMPTY_SHA_RE.match(event.parent_hash):
            return []

        session_key = str(ctx.session_id)
        seen = self._seen_hashes.setdefault(session_key, set())
        seen.add(event.commit_hash)
        if not event.parent_hash:
            return []

        flagged = self._flagged.setdefault(session_key, set())
        if (event.commit_hash, event.parent_hash) in flagged:
            return []
        if event.parent_hash in seen:
            return []
        flagged.add((event.commit_hash, event.parent_hash))

        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description=(
                    f"Commit {event.commit_hash[:12]} on {event.branch or '?'} has a "
                    f"parent ({event.parent_hash[:12]}) never observed in this session — "
                    "consistent with history rewriting or an out-of-band commit"
                ),
                evidence_refs=[str(event.event_id)],
                affected_command=event.message[:100],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 17. DNS/ICMP tunneling signals — covert-channel primitives.
# ---------------------------------------------------------------------------

_TUNNEL_TOOLS_RE = re.compile(
    r"\b(?:iodine|dnscat2?|dnscat|ptunnel|icmptunnel|icmpsh|dns2tcp)\b",
    re.IGNORECASE,
)
# ICMP payloads large enough to carry tunneled data (classic ``ping -s``
# data-channel usage; default ICMP payload is 32-56 bytes).
_ICMP_DATA_PING_RE = re.compile(r"\bping\b[^\n;]*\s-s\s+\d{4,}")
# DNS query labels long/entropy-dense enough to carry chunked payloads
# (base64-ish blob as a subdomain label).
_DNS_BLOB_LABEL_RE = re.compile(
    r"\b(?:dig|nslookup|host)\s+([a-z0-9+/=_-]{50,})", re.IGNORECASE
)

_DNS_TUNNEL_WINDOW_SECONDS = 60.0
_DNS_TUNNEL_VOLUME = 15
_ICMP_TUNNEL_VOLUME = 15
# Beaconing must be reachable GIVEN the observer pipeline: NetworkObserver
# dedups per (pid, dest) for 120s, so emissions arrive at most ~1/120s. A
# 60s window could therefore NEVER accumulate enough events (dead signal).
# The beacon horizon spans that reality: repeated contact with one endpoint
# across minutes - the C2/inference-proxy polling cadence.
_BEACON_CONTACT_VOLUME = 6
_BEACON_WINDOW_SECONDS = 900.0
# Low-and-slow exfiltration: enough contacts, spread far enough apart,
# to be pacing rather than a burst. Never window-pruned (session horizon).
_TRICKLE_CONTACTS = 6
_TRICKLE_MIN_SPAN_SECONDS = 300.0


class NetworkTunnelSignalsDetector:
    """Flags DNS/ICMP covert-channel primitives from host-observable signals.

    Two signal classes, both honestly low-confidence:
    - Command primitives: tunnel-tool invocations (iodine, dnscat2, ...),
      oversized ICMP payloads (``ping -s``), and base64-blob DNS labels.
    - Volume: a single destination receiving a dense burst of UDP/53 or
      ICMP traffic within a short window is consistent with chunked
      tunneled data, but never asserted as intent.
    """

    detector_id = "network_tunnel"
    name = "DNS/ICMP Tunneling Signals"
    severity = "medium"

    def __init__(self) -> None:
        self._recent: dict[str, dict[tuple[str, str], list[float]]] = {}
        self._volume_flagged: dict[str, set[tuple[str, str]]] = {}
        # Beacon horizon (own window, NOT the 60s burst bucket - see
        # _BEACON_WINDOW_SECONDS for why it must be longer than dedup TTL).
        self._beacon: dict[str, dict[str, list[float]]] = {}
        # Long-horizon contact tracking (never window-pruned): catches the
        # LOW-AND-SLOW exfiltration pattern that deliberately stays under
        # burst thresholds by spacing small transfers minutes apart.
        self._horizon: dict[str, dict[str, list[float]]] = {}
        self._trickle_flagged: dict[str, set[str]] = {}

    def _volume_finding(
        self, event: EventBase, ctx: DetectionContext, kind: str, destination: str
    ) -> DetectorFinding | None:
        session_key = str(ctx.session_id)
        key = (kind, destination)
        flagged = self._volume_flagged.setdefault(session_key, set())
        if key in flagged:
            return None
        flagged.add(key)
        return DetectorFinding(
            detector_id=self.detector_id,
            name=self.name,
            severity=self.severity,
            confidence=ConfidenceLevel.LOW,
            description=(
                f"Dense {kind} traffic to a single destination "
                f"({destination}) within {int(_DNS_TUNNEL_WINDOW_SECONDS)}s "
                "— consistent with a chunked covert channel"
            ),
            evidence_refs=[str(event.event_id)],
            requires_approval=False,
        )

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        cmd = _command(event)
        if cmd:
            if _TUNNEL_TOOLS_RE.search(cmd):
                findings.append(DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=f"Covert-channel tunnel tool invoked: {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                ))
            if _ICMP_DATA_PING_RE.search(cmd):
                findings.append(DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=f"Oversized ICMP payload ping (data channel): {cmd[:120]}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                ))
            blob = _DNS_BLOB_LABEL_RE.search(cmd)
            if blob and len(blob.group(1)) >= 50:
                findings.append(DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    description=(
                        "DNS query carrying a payload-sized label "
                        f"({len(blob.group(1))} chars)"
                    ),
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                    requires_approval=False,
                ))

        if isinstance(event, NetworkEvent) and event.direction == "outbound":
            now = event.timestamp.timestamp()
            window = now - _DNS_TUNNEL_WINDOW_SECONDS
            destination = f"{event.destination_ip}:{event.destination_port}"
            session_key = str(ctx.session_id)
            bucket = self._recent.setdefault(session_key, {})

            proto = (event.protocol or "").lower()
            if proto == "udp" and event.destination_port == 53:
                key = ("dns", destination)
                queue = bucket.setdefault(key, [])
                queue.append(now)
                if len(queue) >= _DNS_TUNNEL_VOLUME:
                    finding = self._volume_finding(event, ctx, "DNS", destination)
                    if finding is not None:
                        findings.append(finding)
            elif proto == "icmp":
                key = ("icmp", destination)
                queue = bucket.setdefault(key, [])
                queue.append(now)
                if len(queue) >= _ICMP_TUNNEL_VOLUME:
                    finding = self._volume_finding(event, ctx, "ICMP", destination)
                    if finding is not None:
                        findings.append(finding)

            # Beaconing: repeated contact with a single endpoint on ANY port
            # across the beacon horizon - the C2/inference-proxy polling
            # pattern used to fetch instructions or exfiltrate via an
            # authorized tunnel. Correlation-level signal.
            hkey_beacon = str(ctx.session_id)
            beacon_map = self._beacon.setdefault(hkey_beacon, {})
            beacon_queue = beacon_map.setdefault(destination, [])
            beacon_queue.append(now)
            beacon_queue[:] = [
                t for t in beacon_queue if t >= now - _BEACON_WINDOW_SECONDS
            ]
            if (
                len(beacon_queue) >= _BEACON_CONTACT_VOLUME
                and ("beacon", destination)
                not in self._volume_flagged.get(hkey_beacon, set())
            ):
                self._volume_flagged.setdefault(hkey_beacon, set()).add(
                    ("beacon", destination)
                )
                findings.append(DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity="medium",
                    confidence=ConfidenceLevel.LOW,
                    description=(
                        f"Repeated outbound contact to {destination} "
                        f"({len(beacon_queue)}x in "
                        f"{int(_BEACON_WINDOW_SECONDS)}s) — consistent "
                        "with external coordination/beaconing"
                    ),
                    evidence_refs=[str(event.event_id)],
                    requires_approval=False,
                ))

            # Prune entries outside the window so the volume signal decays.
            for key, queue in bucket.items():
                bucket[key] = [t for t in queue if t >= window]

            # Low-and-slow: repeated small contact with one destination
            # spread over a long horizon. Deliberately below every burst
            # threshold — the pattern is pacing, not volume.
            hkey = str(ctx.session_id)
            horizon = self._horizon.setdefault(hkey, {})
            span_queue = horizon.setdefault(destination, [])
            span_queue.append(now)
            count = len(span_queue)
            duration = (span_queue[-1] - span_queue[0]) if count >= 2 else 0.0
            if (
                count >= _TRICKLE_CONTACTS
                and duration >= _TRICKLE_MIN_SPAN_SECONDS
                and destination not in self._trickle_flagged.get(hkey, set())
            ):
                self._trickle_flagged.setdefault(hkey, set()).add(destination)
                findings.append(DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity="medium",
                    confidence=ConfidenceLevel.LOW,
                    description=(
                        f"Slow-drip contact with {destination}: "
                        f"{count} transfers over {int(duration)}s — pacing "
                        "consistent with low-frequency exfiltration"
                    ),
                    evidence_refs=[str(event.event_id)],
                    requires_approval=False,
                ))

        return findings


# ---------------------------------------------------------------------------
# 18. Sub-agent privilege escalation — a spawned descendant running with
#     more privilege than its parent context (elevation tooling observed
#     inside the tracked process subtree).
# ---------------------------------------------------------------------------

class SubagentPrivilegeDetector:
    """Flags elevation tooling executed by a *descendant* of the session.

    The process-tree observer marks processes whose parent chain traces
    back into the session subtree (``payload["contained_descendant"]``).
    Elevation tooling inside that subtree means a sub-agent escalated
    beyond what the parent session context implies.
    """

    detector_id = "subagent_privilege_escalation"
    name = "Sub-agent Privilege Escalation"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        if not isinstance(event, ProcessEvent):
            return []
        payload = event.payload or {}
        # Only descendants attributed to this session's subtree qualify;
        # unattributed kernel/process events are never claimed.
        if not payload.get("contained_descendant", False):
            return []
        if str(event.actor_id).startswith("unattributed_"):
            return []

        cmd = event.command_line or ""
        base = cmd.split()[0].split("/")[-1].lower() if cmd.split() else ""
        if base in _PRIV_CMDS or _PRIV_RE.search(cmd):
            return [
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.HIGH,
                    description=(
                        f"Descendant process ran elevation tooling: {cmd[:120]}"
                    ),
                    evidence_refs=[str(event.event_id)],
                    affected_command=cmd[:200],
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 19. Benign tool-chain composition — individually harmless calls that
#     compose into harm (fetch→execute, credential read→egress,
#     escalate→anti-forensic cleanup). Correlation-level signal: MEDIUM
#     confidence by design.
# ---------------------------------------------------------------------------

_ELEVATION_TOOLING_RE = re.compile(
    r"\b(?:sudo|doas|pkexec|gsudo)\b|\bsu\s+-|start-process\b[^\n]*-verb\s+runas",
    re.IGNORECASE,
)
_FETCH_URL_RE = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod|fetch)\b[^\n]*https?://",
    re.IGNORECASE,
)
_SECRET_READ_RE = re.compile(
    r"\.aws[/\\]credentials|\.ssh[/\\]|id_rsa|id_ed25519|\.env\b|"
    r"credentials\b|\.npmrc|\.pypirc|\.netrc|"
    r"(?:password|api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]",
    re.IGNORECASE,
)
_CLEANUP_RE = re.compile(
    r"(?:shred|rm|remove-item|clear-content|del|unlink)\b[^\n]*"
    r"(?:bash_history|zsh_history|psreadline|/var/log|%systemroot%|wevtutil)|"
    r"\bwevtutil\s+cl\b|\bclear-history\b",
    re.IGNORECASE,
)
_INTERPRETER_EXEC_RE = re.compile(
    r"(?:^|[\s/])(?:bash|sh|zsh|dash|ksh|pwsh|powershell|python3?|node|perl|ruby)\b",
    re.IGNORECASE,
)
_ASSEMBLE_RE = re.compile(
    r"\b(?:cat|type|get-content)\b|copy\s+/b\b",
    re.IGNORECASE,
)
_SCRIPT_TARGET_RE = re.compile(r">\s*\S+\.(?:sh|bat|ps1|py|js|rb|pl)\b", re.IGNORECASE)


class ToolChainDetector:
    """Correlates recent benign-looking steps into harmful compositions.

    State is keyed per session (detector instances are shared across
    engines). Window is a bounded command count, not wall-clock — an
    attacker cannot outwait it and a slow machine cannot trip it.
    Findings are correlation-level (MEDIUM confidence): each step alone
    is legitimate; the composition is the risk.
    """

    detector_id = "benign_tool_chain"
    name = "Suspicious Tool-Chain Composition"

    _WINDOW = 30

    # (recipe id, earlier step kind, later step kind, severity, description)
    _RECIPES = (
        (
            "fetch_then_execute",
            "fetch",
            "exec",
            "high",
            "Downloaded content followed by interpreter execution "
            "(split across separate benign-looking calls)",
        ),
        (
            "secret_then_egress",
            "secret_read",
            "egress",
            "high",
            "Credential material accessed shortly before network egress",
        ),
        (
            "escalate_then_cleanup",
            "elevate",
            "cleanup",
            "medium",
            "Anti-forensic cleanup shortly after privilege escalation",
        ),
        (
            "fragment_assembly",
            "write",
            "assemble",
            "high",
            "Multiple recent file fragments concatenated into an executable "
            "artifact — payload splitting to evade per-file pattern detection",
        ),
    )

    def __init__(self) -> None:
        self._history: dict[str, deque[tuple[str, str]]] = {}
        self._fired: dict[str, set[str]] = {}

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        key = str(ctx.session_id)
        history = self._history.setdefault(key, deque(maxlen=self._WINDOW))
        fired = self._fired.setdefault(key, set())

        kind, value = self._classify(event)
        if not kind:
            return []

        findings: list[DetectorFinding] = []
        for recipe_id, first_kind, second_kind, severity, description in self._RECIPES:
            if recipe_id in fired or kind != second_kind:
                continue
            if recipe_id == "fragment_assembly":
                # Stronger condition: the command must reference >=2 file
                # basenames written recently in this session.
                written = {v for k, v in history if k == "write"}
                referenced = sum(1 for name in written if name and name in value)
                if referenced < 2:
                    continue
                fired.add(recipe_id)
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=severity,
                        confidence=ConfidenceLevel.MEDIUM,
                        description=f"{description}: {value[:120]}",
                        evidence_refs=[str(event.event_id)],
                        affected_command=value[:200],
                    )
                )
                break
            if any(k == first_kind for k, _v in history):
                fired.add(recipe_id)
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        name=self.name,
                        severity=severity,
                        confidence=ConfidenceLevel.MEDIUM,
                        description=f"{description}: {value[:120]}",
                        evidence_refs=[str(event.event_id)],
                        affected_command=value[:200],
                    )
                )
                break

        history.append((kind, value))
        return findings

    def _classify(self, event: EventBase) -> tuple[str, str]:
        """Map one event to a chain-relevant (kind, value) pair."""
        if isinstance(event, CommandEvent):
            cmd = (event.command or "").strip()
            if not cmd:
                return "", ""
            if _ELEVATION_TOOLING_RE.search(cmd):
                return "elevate", cmd
            if _FETCH_URL_RE.search(cmd):
                return "fetch", cmd
            if _CLEANUP_RE.search(cmd):
                return "cleanup", cmd
            if _SECRET_READ_RE.search(cmd):
                return "secret_read", cmd
            if _ASSEMBLE_RE.search(cmd) and (
                _SCRIPT_TARGET_RE.search(cmd) or _INTERPRETER_EXEC_RE.search(cmd)
            ):
                return "assemble", cmd
            if _INTERPRETER_EXEC_RE.search(cmd):
                return "exec", cmd
            return "", ""
        if isinstance(event, NetworkEvent):
            dest = event.destination_ip or ""
            port = event.destination_port or 0
            return "egress", f"{dest}:{port}"
        if isinstance(event, FileMutationEvent) and event.mutation_type in {
            "create", "modify", "append"
        }:
            from pathlib import Path  # noqa: PLC0415 (basename only)

            return "write", Path(event.file_path).name
        return "", ""


# ---------------------------------------------------------------------------
# 20. Recursive agent spawning — an agent writing/spawning another agent.
#     Out-of-spec by definition: the audited session was approved to act,
#     not to mint new unapproved actors.
# ---------------------------------------------------------------------------

_AGENT_SPAWN_RE = re.compile(
    r"(?:^|[\s/])claude\s+(?:-p\b|--print\b|--dangerously)"
    r"|(?:^|[\s/])codex\s+(?:exec\b|e\b|--full-auto|--dangerously-bypass)"
    r"|\bnpx\b[^\n]*(?:@anthropic-ai/)?claude"
    r"|\bpip\s+install\b[^\n]*-e?\s*git\+https?://[^\n]*(?:agent|bot)",
    re.IGNORECASE,
)


class RecursiveAgentSpawnDetector:
    """Flags an agent creating or invoking additional agents.

    Covers both directions of "recursive agent": command-line spawning of
    agent CLIs from inside a session, and writing files whose content
    registers/defines new agent behavior (subagent definitions, MCP server
    registrations). Path-based registration is additionally caught by
    ConfigTamperDetector; this rule adds the invocation/content signal.
    """

    detector_id = "recursive_agent_spawn"
    name = "Recursive Agent Spawning"
    severity = "high"

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        surfaces: list[tuple[str, str]] = []
        cmd = _command(event)
        if cmd and _AGENT_SPAWN_RE.search(cmd):
            surfaces.append((cmd[:200], "invoked an agent CLI recursively"))
        if isinstance(event, FileMutationEvent) and event.diff_summary:
            if _AGENT_SPAWN_RE.search(event.diff_summary):
                surfaces.append(
                    (event.diff_summary[:200], "wrote content that spawns an agent")
                )
            path = event.file_path.replace("\\", "/").lower()
            if ".claude/agents/" in path or path.endswith(".mcp.json"):
                surfaces.append(
                    (event.file_path, f"{event.mutation_type} of spawnable agent surface")
                )
        findings: list[DetectorFinding] = []
        for detail, what in surfaces:
            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    name=self.name,
                    severity=self.severity,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Agent {what}: {detail}",
                    evidence_refs=[str(event.event_id)],
                    affected_command=detail,
                    requires_approval=False,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# 21. Log tampering — wiping or rewriting audit/log/history artifacts.
#     The ledger itself is cryptographically tamper-evident; this covers the
#     host-level half: OS logs, shell history, and AgentTrace's own files.
# ---------------------------------------------------------------------------

_LOG_TAMPER_RE = re.compile(
    r"(?:shred|rm|mv|truncate|remove-item|clear-content)\b[^\n]*"
    r"(?:\.log\b|/var/log|%systemroot%[^\n]*logs?|wevtutil)"
    r"|\bwevtutil\s+cl\b"
    r"|(?:rm|mv|shred|truncate)\b[^\n]*\.agenttrace[/\\]"
    r"|(?:history\s+-c\b)|\bclear-history\b"
    r"|(?:set-content|add-content|out-file|echo\s*>)[^\n]*\.agenttrace[/\\]",
    re.IGNORECASE,
)


class LogTamperDetector:
    """Flags attempts to wipe or rewrite logs, history, or AgentTrace files.

    Standalone rule on purpose: until now, log wipes only mattered as the
    second half of an escalation chain — a bare ``rm /var/log/syslog``
    produced nothing. Ledger entries are separately protected by the hash
    chain; this covers every tamper surface that is just a file.
    """

    detector_id = "log_tampering"
    name = "Log / Audit Trail Tampering"
    severity = "high"

    def __init__(self) -> None:
        self._flagged: dict[str, set[str]] = {}

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd:
            return []
        match = _LOG_TAMPER_RE.search(cmd)
        if not match:
            return []

        key = str(ctx.session_id)
        # Dedupe per matched target family so one wipe sweep yields one
        # finding, but distinct targets (OS logs vs history vs ledger dir)
        # each stay visible.
        family = match.group(0).lower()[:24]
        flagged = self._flagged.setdefault(key, set())
        if family in flagged:
            return []
        flagged.add(family)

        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=self.severity,
                confidence=ConfidenceLevel.MEDIUM,
                description=f"Log/audit artifact tampering attempt: {cmd[:120]}",
                evidence_refs=[str(event.event_id)],
                affected_command=cmd[:200],
                requires_approval=False,
            )
        ]


# ---------------------------------------------------------------------------
# 22. Inference-proxy abuse / SSRF-as-a-feature (Prime Intellect
#     universal-offline-sandbox-escape, Aug 2026): an agent inside an
#     "offline" sandbox calling the model API directly - reusing the
#     interception proxy's bearer key and abusing server-side remote-fetch
#     parameters (file_url/input_file) as an SSRF primitive, and invoking
#     other model instances as sub-agents.
# ---------------------------------------------------------------------------

_LLM_API_ENDPOINT_RE = re.compile(
    r"/v1/(?:responses|chat/completions|completions)\b"
    r"|chat/completions\b"
    r"|/v1/responses\b",
    re.IGNORECASE,
)
_REMOTE_FETCH_PARAM_RE = re.compile(
    r"(?:\"|')?(?:file_url|input_file|input_image)(?:\"|')?\s*:"
    r"|input_file\b.*https?://",
    re.IGNORECASE,
)
_BEARER_HEADER_RE = re.compile(r"authorization[\"':=\s]+bearer\b", re.IGNORECASE)
_PRIVATE_HOST_RE = re.compile(
    r"https?://"
    r"(?!localhost|127\.0\.0\.1)"
    r"(?:[a-z0-9.-]*\.internal|host\.docker\.internal|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.IGNORECASE,
)


class InferenceProxyAbuseDetector:
    """Flags direct invocation of LLM inference endpoints from a session.

    Two tiers, honestly separated:
    - HIGH: the request carries server-side remote-fetch parameters
      (``file_url`` / ``input_file``) — the model API is being used as an
      SSRF fetch primitive, the universal offline-sandbox escape.
    - MEDIUM: raw completions/responses endpoint invoked with an explicit
      bearer header or against a private/internal host. Local inference
      stacks (ollama/vLLM) call these endpoints too, so bare loopback calls
      WITHOUT credentials or fetch params stay silent here.
    This detector also OWNS the "model-as-sub-agent" signal: spawning other
    LLM instances via raw API calls is recursive agent use (deliberately
    not duplicated in recursive_agent_spawn to avoid double findings).
    """

    detector_id = "inference_proxy_abuse"
    name = "Inference Endpoint Abuse / SSRF Fetch"

    def __init__(self) -> None:
        self._flagged: dict[str, set[str]] = {}

    def evaluate(self, event: EventBase, ctx: DetectionContext) -> list[DetectorFinding]:
        cmd = _command(event)
        if not cmd or not _LLM_API_ENDPOINT_RE.search(cmd):
            return []

        session_key = str(ctx.session_id)

        if _REMOTE_FETCH_PARAM_RE.search(cmd):
            family = "ssrf_fetch"
        elif (
            _BEARER_HEADER_RE.search(cmd) or _PRIVATE_HOST_RE.search(cmd)
        ):
            # Loopback inference (ollama/vLLM on 127.0.0.1) without
            # credentials is normal developer tooling - stay silent.
            family = "raw_invocation"
        else:
            return []

        flagged = self._flagged.setdefault(session_key, set())
        if family in flagged:
            return []
        flagged.add(family)

        if family == "ssrf_fetch":
            description = (
                "Server-side remote fetch via inference API "
                "(file_url/input_file) — offline-sandbox SSRF escape pattern"
            )
            confidence = ConfidenceLevel.HIGH
            severity = "critical"
        else:
            description = (
                "Direct LLM-endpoint invocation with credential or internal "
                "host — possible proxy-key reuse / model-as-sub-agent"
            )
            confidence = ConfidenceLevel.MEDIUM
            severity = "high"

        return [
            DetectorFinding(
                detector_id=self.detector_id,
                name=self.name,
                severity=severity,
                confidence=confidence,
                description=f"{description}: {cmd[:100]}",
                evidence_refs=[str(event.event_id)],
                affected_command=cmd[:200],
                requires_approval=False,
            )
        ]


DEFAULT_DETECTORS: list[Any] = [
    PromptInjectionDetector(),
    ConfigTamperDetector(),
    CredentialReadDetector(),
    ObfuscationDetector(),
    EgressAnomalyDetector(),
    GitHistoryRewritingDetector(),
    PathTrickDetector(),
    PrivilegeChangeDetector(),
    SandboxEscapeDetector(),
    DatabaseDestructionDetector(),
    MultiAgentSabotageDetector(),
    PersistenceDetector(),
    TestIntegrityDetector(),
    PowerShellCradleDetector(),
    GitAuthorSpoofDetector(),
    OrphanedCommitDetector(),
    NetworkTunnelSignalsDetector(),
    SubagentPrivilegeDetector(),
    ToolChainDetector(),
    RecursiveAgentSpawnDetector(),
    LogTamperDetector(),
    InferenceProxyAbuseDetector(),
]
