"""Codex CLI adapter — reads Codex CLI rollout JSONL transcripts.

Codex CLI stores every session as an append-only JSONL rollout under
``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``. Each line is an envelope
whose ``payload`` object carries a ``type`` discriminator:

- ``user_message``    — the user's prompt (invocation / user intent)
- ``response_item``   — model output; the nested ``payload.type`` is one of
  ``message``, ``reasoning``, ``function_call``, ``custom_tool_call``,
  ``local_shell_call``, ``file_edit_call``, ...
- ``custom_tool_call``— a tool invocation with ``{toolName, args}``
- ``event_msg``       — runtime events (tool results, exec results)

The adapter translates these into canonical AgentTrace events, capturing the
model's reasoning summaries and tool calls so the analysis layers see the
agent's decisions — not just host-level effects.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from uuid import UUID

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

logger = logging.getLogger(__name__)

# Tool names whose input is a shell command string
_SHELL_TOOLS = {"shell", "shell_command", "bash", "local_shell_call"}


class CodexAdapter(AdapterBase):
    """Adapter for OpenAI Codex CLI rollout transcripts."""

    @property
    def adapter_name(self) -> str:
        return "codex_cli"

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
        sessions_dir: Path | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path)
        self._sessions_dir = sessions_dir or Path.home() / ".codex" / "sessions"
        self._positions: dict[str, int] = {}
        self._invoked: set[str] = set()

    @staticmethod
    def _is_shell_tool(name: str) -> bool:
        return name.lower() in _SHELL_TOOLS

    # -- Lifecycle --

    async def start(self) -> None:
        self._running = True
        logger.info(
            "CodexAdapter started, sessions_dir=%s", self._sessions_dir
        )

    async def stop(self) -> None:
        self._running = False
        logger.info("CodexAdapter stopped")

    # -- Polling --

    def _rollouts(self) -> list[Path]:
        """All rollout JSONL files, newest first."""
        if not self._sessions_dir.is_dir():
            return []
        try:
            return sorted(
                self._sessions_dir.rglob("rollout-*.jsonl"),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return []

    async def poll(self) -> list[EventBase]:
        events: list[EventBase] = []
        if not self._running:
            return events

        for rollout in self._rollouts():
            path_key = str(rollout)
            if path_key not in self._positions:
                self._positions[path_key] = 0
            try:
                with open(rollout, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._positions[path_key])
                    new_lines = f.readlines()
                    self._positions[path_key] = f.tell()
            except OSError:
                continue

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.extend(self._translate_envelope(rollout, envelope))

        return events

    # -- Translation --

    def _translate_envelope(self, rollout: Path, envelope: dict[str, Any]) -> list[EventBase]:
        """Translate one rollout line into canonical events."""
        events: list[EventBase] = []
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return events

        ptype = payload.get("type", "")
        actor = f"codex:{payload.get('session_id') or payload.get('thread_id') or 'unknown'}"
        common: dict[str, Any] = {
            "rollout": str(rollout),
            "ts": envelope.get("timestamp", ""),
            "codex_version": envelope.get("version", ""),
        }

        if ptype == "user_message":
            message = payload.get("message", "")
            if isinstance(message, dict):
                message = message.get("content", "")
            if str(message).strip() and str(rollout) not in self._invoked:
                self._invoked.add(str(rollout))
                events.append(InvocationEvent(
                    session_id=self.session_id,
                    actor_id=actor,
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    user_intent=str(message)[:500],
                    agent_name="codex",
                    agent_version=envelope.get("version", ""),
                    payload=common,
                ))
            return events

        if ptype == "response_item":
            inner = payload.get("payload")
            if isinstance(inner, dict):
                events.extend(self._translate_response_item(actor, inner, common))
            return events

        if ptype == "custom_tool_call":
            tool_name = str(payload.get("name") or payload.get("toolName") or "unknown")
            args = payload.get("args") or payload.get("arguments") or {}
            events.extend(self._tool_request(actor, tool_name, args, common))
            return events

        if ptype == "event_msg":
            event = payload.get("event")
            if isinstance(event, dict):
                ep = event.get("payload")
                if isinstance(ep, dict):
                    events.extend(self._translate_event_msg(actor, ep, common))
            return events

        return events

    def _translate_response_item(
        self, actor: str, inner: dict[str, Any], common: dict[str, Any]
    ) -> list[EventBase]:
        events: list[EventBase] = []
        itype = inner.get("type", "")

        if itype == "reasoning":
            summary = inner.get("summary") or inner.get("content") or ""
            if isinstance(summary, list):
                summary = " ".join(str(s) for s in summary)
            if str(summary).strip():
                events.append(ContextBoundaryEvent(
                    session_id=self.session_id,
                    actor_id=actor,
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    payload={**common, "reasoning": str(summary)[:2000], "reasoning_kind": "summary"},
                ))
            return events

        if itype == "message":
            content = inner.get("content", [])
            text = ""
            if isinstance(content, list):
                text = " ".join(
                    str(block.get("text", ""))
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "output_text"
                )
            elif isinstance(content, str):
                text = content
            if text.strip():
                events.append(ContextBoundaryEvent(
                    session_id=self.session_id,
                    actor_id=actor,
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    payload={**common, "response_text": text[:1000]},
                ))
            return events

        if itype in ("function_call", "custom_tool_call", "local_shell_call", "file_edit_call"):
            tool_name = str(inner.get("name") or inner.get("toolName") or itype)
            args = inner.get("arguments") or inner.get("args") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"value": args}
            if not isinstance(args, dict):
                args = {"value": str(args)}
            events.extend(self._tool_request(actor, tool_name, args, common))
            return events

        return events

    def _translate_event_msg(
        self, actor: str, ep: dict[str, Any], common: dict[str, Any]
    ) -> list[EventBase]:
        events: list[EventBase] = []
        etype = ep.get("type", "")

        if etype in ("exec_result", "function_call_output", "custom_tool_call_result"):
            output = ep.get("output", "") or ep.get("value", "") or ""
            if isinstance(output, (dict, list)):
                output = json.dumps(output, ensure_ascii=False)
            exit_code = ep.get("exit_code")
            if isinstance(exit_code, str):
                try:
                    exit_code = int(exit_code)
                except ValueError:
                    exit_code = None
            events.append(ToolResultEvent(
                session_id=self.session_id,
                actor_id=actor,
                source_adapter=self.adapter_name,
                confidence=ConfidenceLevel.HIGH,
                tool_name=str(ep.get("tool_name") or ep.get("name") or "unknown"),
                exit_code=exit_code,
                output_summary=str(output)[:500],
                payload={**common, "exec_type": etype},
            ))
            return events

        if etype == "agent_message":
            text = ep.get("text") or ep.get("message") or ""
            if str(text).strip():
                events.append(ContextBoundaryEvent(
                    session_id=self.session_id,
                    actor_id=actor,
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    payload={**common, "response_text": str(text)[:1000]},
                ))
            return events

        return events

    def _tool_request(
        self,
        actor: str,
        tool_name: str,
        args: dict[str, Any],
        common: dict[str, Any],
    ) -> list[EventBase]:
        events: list[EventBase] = []
        events.append(ToolRequestEvent(
            session_id=self.session_id,
            actor_id=actor,
            source_adapter=self.adapter_name,
            confidence=ConfidenceLevel.HIGH,
            tool_name=tool_name,
            tool_args=args,
            payload=common,
        ))
        # Shell tools carry the exact command — surface it to the boundary and
        # policy engines as a CommandEvent
        if self._is_shell_tool(tool_name):
            command = (
                args.get("command")
                or args.get("cmd")
                or args.get("value")
                or ""
            )
            if command:
                events.append(CommandEvent(
                    session_id=self.session_id,
                    actor_id=actor,
                    source_adapter=self.adapter_name,
                    confidence=ConfidenceLevel.HIGH,
                    command=str(command)[:1000],
                    working_dir=self.workspace_path,
                    payload=common,
                ))
        return events
