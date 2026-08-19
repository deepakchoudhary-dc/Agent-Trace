"""Claude Code adapter — reads Claude Code JSONL session transcripts.

Claude Code stores every session as an append-only JSONL transcript under
``~/.claude/projects/<encoded-project-path>/<session-id>.jsonl`` (and
``%USERPROFILE%\\.claude\\projects\\...`` on Windows). Each line is one
event with a ``type`` discriminator (``user`` / ``assistant`` / ``system``)
plus ``uuid``, ``parentUuid``, ``timestamp``, ``sessionId``, ``cwd``,
``gitBranch`` and ``version``. Assistant entries carry ``message.content``
as an array of blocks:

- ``text``      — assistant prose
- ``thinking``  — the model's extended reasoning (the *why* evidence the
  case-study incidents hinge on: Opus 4.7 rationalizing a real target as
  part of the exercise, Mythos 5 convincing itself it was still in a
  simulation)
- ``tool_use``  — ``{id, name, input}``, one per tool invocation

User entries carry ``tool_result`` blocks (referencing the ``tool_use_id``
they answer) and ``message.usage`` token accounting.

This adapter translates transcripts into canonical AgentTrace events so the
analysis layers (task boundary, policy, incident correlation) see what the
agent *decided* to do — not just the host-level effects observers see.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenttrace.adapters.sdk import SDK_VERSION, AdapterBase
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    ContextBoundaryEvent,
    EventBase,
    EventType,
    InvocationEvent,
    ToolRequestEvent,
    ToolResultEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)


def _parse_iso(value: Any) -> datetime | None:
    """Parse a vendor ISO-8601 timestamp into an aware datetime.

    Naive vendor timestamps are clamped to UTC — the vendor's local clock
    offset is unobservable, and assuming the host's current local offset
    would silently skew replay ordering.
    """
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


class ClaudeAdapter(AdapterBase):
    """Adapter for Anthropic Claude Code CLI session transcripts."""

    @property
    def adapter_name(self) -> str:
        return "claude_code"

    @property
    def adapter_version(self) -> str:
        return "0.2.0"

    @property
    def sdk_version(self) -> str:
        return SDK_VERSION

    @property
    def supported_event_types(self) -> list[EventType]:
        return [
            EventType.INVOCATION,
            EventType.TOOL_REQUEST,
            EventType.TOOL_RESULT,
            EventType.CONTEXT_BOUNDARY,
            EventType.COMMAND,
        ]

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        projects_dir: Path | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path)
        self._projects_dir = projects_dir or self._default_projects_dir()
        self._positions: dict[str, int] = {}
        # Transcripts whose session cwd is outside the audited workspace are
        # excluded once (a session's cwd does not change).
        self._excluded: set[str] = set()
        # tool_use id -> (tool_name, tool_use_uuid) for resolving tool_results
        self._tool_ids: dict[str, dict[str, str]] = {}
        self._invoked: set[str] = set()

    @staticmethod
    def _default_projects_dir() -> Path:
        home = Path.home()
        candidates = [
            home / ".claude" / "projects",
            Path(os.environ.get("USERPROFILE", "")) / ".claude" / "projects",
        ]
        for c in candidates:
            if c.is_dir():
                return c
        return candidates[0]

    # -- Transcript discovery --

    def _transcripts(self) -> list[Path]:
        """All JSONL transcripts under the projects dir, newest first."""
        if not self._projects_dir.is_dir():
            return []
        try:
            files = sorted(
                self._projects_dir.rglob("*.jsonl"),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return []
        return [f for f in files if str(f) not in self._excluded]

    def _belongs_to_workspace(self, transcript: Path) -> bool:
        """A transcript belongs to this session if its session cwd is the
        audited workspace (or a subdirectory of it).

        Matching is segment-exact: workspace ``C:\\proj`` must NOT ingest a
        transcript whose cwd is ``C:\\proj2``.
        """
        try:
            with open(transcript, encoding="utf-8", errors="replace") as f:
                first = f.readline()
            entry = json.loads(first)
            cwd = entry.get("cwd", "")
            if not cwd:
                return False
            try:
                cwd_path = Path(cwd).resolve()
                ws_path = Path(self.workspace_path).resolve()
            except (OSError, ValueError):
                return False
            return cwd_path == ws_path or cwd_path.is_relative_to(ws_path)
        except (OSError, json.JSONDecodeError, ValueError):
            return False

    # -- Lifecycle --

    def cursor_state(self) -> dict[str, Any]:
        return {
            "positions": dict(self._positions),
            "excluded": sorted(self._excluded),
            "invoked": sorted(self._invoked),
            "tool_ids": {k: dict(v) for k, v in self._tool_ids.items()},
        }

    def restore_cursor(self, state: dict[str, Any]) -> None:
        positions = state.get("positions", {})
        if isinstance(positions, dict):
            self._positions = {
                str(k): int(v) for k, v in positions.items()
            }
        self._excluded = set(state.get("excluded", []))
        self._invoked = set(state.get("invoked", []))
        tool_ids = state.get("tool_ids", {})
        if isinstance(tool_ids, dict):
            self._tool_ids = {
                str(k): {"name": str(v.get("name", "")), "uuid": str(v.get("uuid", ""))}
                for k, v in tool_ids.items()
                if isinstance(v, dict)
            }

    async def start(self) -> None:
        self._running = True
        logger.info(
            "ClaudeAdapter started, projects_dir=%s", self._projects_dir
        )

    async def stop(self) -> None:
        self._running = False
        logger.info("ClaudeAdapter stopped")

    # -- Polling --

    async def poll(self) -> list[EventBase]:
        events: list[EventBase] = []
        if not self._running:
            return events

        for transcript in self._transcripts():
            try:
                if str(transcript) not in self._positions:
                    if not self._belongs_to_workspace(transcript):
                        self._excluded.add(str(transcript))
                        continue
                    self._positions[str(transcript)] = 0
            except OSError:
                continue

            for raw_line in self._read_new_lines(transcript):
                if raw_line is None:
                    break  # tail line was truncated mid-write — retry next poll
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                translated = self._translate_entry(transcript, entry)
                timestamp = _parse_iso(entry.get("timestamp"))
                if timestamp is not None:
                    for ev in translated:
                        ev.timestamp = timestamp
                events.extend(translated)

        return events

    def _read_new_lines(self, transcript: Path) -> list[str | None]:
        """Read new transcript lines as text, in binary mode so byte-offset
        cursors stay exact on Windows.

        A trailing line without a newline that fails to parse is a tail line
        truncated mid-write: the cursor is rewound to its start so the same
        line is retried on the next poll instead of being permanently lost.
        """
        position = self._positions[str(transcript)]
        try:
            with open(transcript, "rb") as f:
                size = f.seek(0, 2)
                if size < position:
                    # File rotated/truncated while not watched (e.g. during a
                    # daemon restart) — restart the cursor from the top.
                    position = 0
                f.seek(position)
                raw_lines = f.readlines()
                new_position = f.tell()
        except OSError:
            return []
        self._positions[str(transcript)] = new_position

        lines: list[str | None] = []
        for raw in raw_lines:
            if not raw.endswith(b"\n"):
                truncated = raw.decode("utf-8", errors="replace").strip()
                if truncated:
                    try:
                        json.loads(truncated)
                    except json.JSONDecodeError:
                        self._positions[str(transcript)] = (
                            new_position - len(raw)
                        )
                        return [*lines, None]
                lines.append(truncated)
            else:
                lines.append(raw.decode("utf-8", errors="replace"))
        return lines

    # -- Translation --

    def _translate_entry(self, transcript: Path, entry: dict[str, Any]) -> list[EventBase]:
        """Translate one transcript line into canonical events."""
        events: list[EventBase] = []
        entry_type = entry.get("type", "")
        path_key = str(transcript)
        cwd = entry.get("cwd", "") or self.workspace_path
        common_payload: dict[str, Any] = {
            "transcript": path_key,
            "cwd": cwd,
            "git_branch": entry.get("gitBranch", ""),
            "claude_version": entry.get("version", ""),
            "line_uuid": entry.get("uuid", ""),
        }

        if entry_type == "user":
            msg = entry.get("message")
            content = msg.get("content") if isinstance(msg, dict) else msg

            # Plain-text prompt → invocation (once per transcript)
            if (
                isinstance(content, str)
                and content.strip()
                and path_key not in self._invoked
            ):
                self._invoked.add(path_key)
                events.append(InvocationEvent(
                    session_id=self.session_id,
                    actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    user_intent=content[:500],
                    agent_name="claude_code",
                    agent_version=entry.get("version", ""),
                    payload=common_payload,
                ))

            # Tool result blocks → ToolResultEvent
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        tool_use_id = str(block.get("tool_use_id", ""))
                        result_content = block.get("content", "")
                        if isinstance(result_content, list):
                            result_content = json.dumps(result_content, ensure_ascii=False)
                        name = self._tool_ids.get(tool_use_id, {}).get("name", "")
                        events.append(ToolResultEvent(
                            session_id=self.session_id,
                            actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                            source_adapter=self.adapter_name,
                            confidence=ConfidenceLevel.HIGH,
                            tool_name=name or "unknown",
                            output_summary=str(result_content)[:500],
                            payload={
                                **common_payload,
                                "tool_use_id": tool_use_id,
                            },
                        ))

            usage = entry.get("message", {}).get("usage")
            if isinstance(usage, dict) and usage:
                events.append(ContextBoundaryEvent(
                    session_id=self.session_id,
                    actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    context_window_tokens=int(
                        usage.get("input_tokens", 0) or 0
                    ) + int(usage.get("output_tokens", 0) or 0),
                    payload={**common_payload, "usage": usage},
                ))

        elif entry_type == "assistant":
            msg = entry.get("message")
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                return events

            pending_reasoning: list[str] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                block_type = block.get("type")

                if block_type == "thinking":
                    text = str(block.get("thinking", ""))
                    if text.strip():
                        pending_reasoning.append(text)
                        events.append(ContextBoundaryEvent(
                            session_id=self.session_id,
                            actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                            source_adapter=self.adapter_name,
                            confidence=ConfidenceLevel.HIGH,
                            payload={
                                **common_payload,
                                "reasoning": text[:2000],
                                "reasoning_kind": "thinking",
                            },
                        ))

                elif block_type == "tool_use":
                    tool_id = str(block.get("id", ""))
                    tool_name = str(block.get("name", ""))
                    tool_input = block.get("input") or {}
                    if not isinstance(tool_input, dict):
                        try:
                            tool_input = json.loads(str(tool_input))
                        except json.JSONDecodeError:
                            tool_input = {"value": str(tool_input)}
                    self._tool_ids[tool_id] = {
                        "name": tool_name,
                        "uuid": str(block.get("uuid", "")),
                    }

                    events.append(ToolRequestEvent(
                        session_id=self.session_id,
                        actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                        source_adapter=self.adapter_name,
                        confidence=ConfidenceLevel.HIGH,
                        tool_name=tool_name,
                        tool_args=tool_input,
                        payload={
                            **common_payload,
                            "tool_use_id": tool_id,
                            "reasoning": " ".join(pending_reasoning)[:2000],
                        },
                    ))

                    # Bash tool input → CommandEvent so the task boundary and
                    # policy engines see the exact shell command
                    if tool_name == "Bash" and tool_input.get("command"):
                        events.append(CommandEvent(
                            session_id=self.session_id,
                            actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                            source_adapter=self.adapter_name,
                            confidence=ConfidenceLevel.HIGH,
                            command=str(tool_input["command"])[:1000],
                            working_dir=cwd,
                            payload={**common_payload, "tool_use_id": tool_id},
                        ))
                    pending_reasoning = []

            usage = entry.get("message", {}).get("usage")
            if isinstance(usage, dict) and usage:
                events.append(ContextBoundaryEvent(
                    session_id=self.session_id,
                    actor_id=f"claude:{entry.get('sessionId', 'unknown')}",
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    context_window_tokens=int(
                        usage.get("input_tokens", 0) or 0
                    ) + int(usage.get("output_tokens", 0) or 0),
                    payload={**common_payload, "usage": usage},
                ))

        return events
