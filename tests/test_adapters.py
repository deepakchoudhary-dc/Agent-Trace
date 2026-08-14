"""Tests for the transcript-based adapters (Claude Code, Codex CLI).

These adapters turn real on-disk agent transcripts into canonical events,
including the model's *reasoning* — the evidence the case-study incidents
show is essential to understanding why an agent acted.
"""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.adapters.claude import ClaudeAdapter
from agenttrace.adapters.codex import CodexAdapter
from agenttrace.models.events import (
    CommandEvent,
    ContextBoundaryEvent,
    EventType,
    InvocationEvent,
    ToolRequestEvent,
    ToolResultEvent,
)


class TestClaudeAdapter:
    """Claude Code ~/.claude/projects/**/*.jsonl transcripts."""

    @pytest.mark.asyncio
    async def test_parses_transcript_with_reasoning(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        projects = tmp_path / "projects" / "-Users-me-app"
        projects.mkdir(parents=True)
        transcript = projects / "session-1.jsonl"

        lines = [
            {
                "type": "user", "uuid": "u1", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {"role": "user", "content": "deploy the service"},
            },
            {
                "type": "assistant", "uuid": "a1", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "I should check the database credentials first"},
                        {"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": "cat ~/.ssh/id_rsa"}},
                    ],
                    "usage": {"input_tokens": 100, "output_tokens": 50},
                },
            },
            {
                "type": "user", "uuid": "u2", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "BEGIN RSA PRIVATE KEY"}],
                },
            },
        ]
        transcript.write_text(
            "\n".join(json.dumps(line) for line in lines), encoding="utf-8"
        )

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()

        # Invocation from the user prompt
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].user_intent == "deploy the service"

        # Tool request + surfaced shell command
        tool_reqs = [e for e in events if isinstance(e, ToolRequestEvent)]
        assert len(tool_reqs) == 1
        assert tool_reqs[0].tool_name == "Bash"

        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert len(commands) == 1
        assert commands[0].command == "cat ~/.ssh/id_rsa"

        # Reasoning captured from the thinking block
        reasoning = [
            e for e in events
            if isinstance(e, ContextBoundaryEvent) and e.payload.get("reasoning")
        ]
        assert reasoning, "reasoning should be captured from thinking blocks"
        assert "database credentials" in reasoning[0].payload["reasoning"]

        # Token accounting
        usage = [
            e for e in events
            if isinstance(e, ContextBoundaryEvent) and e.payload.get("usage")
        ]
        assert usage and usage[0].context_window_tokens == 150

        # Tool result resolved back to the request
        results = [e for e in events if isinstance(e, ToolResultEvent)]
        assert len(results) == 1
        assert results[0].tool_name == "Bash"
        assert "BEGIN RSA PRIVATE KEY" in results[0].output_summary

        # Second poll must not duplicate
        assert await adapter.poll() == []

    @pytest.mark.asyncio
    async def test_ignores_transcripts_outside_workspace(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        projects = tmp_path / "projects"
        projects.mkdir()
        transcript = projects / "other-project.jsonl"
        transcript.write_text(
            json.dumps({
                "type": "user", "uuid": "u1", "cwd": str(other),
                "sessionId": "s2",
                "message": {"role": "user", "content": "something else"},
            }),
            encoding="utf-8",
        )

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()
        assert events == []


class TestCodexAdapter:
    """Codex CLI ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl transcripts."""

    @pytest.mark.asyncio
    async def test_parses_rollout(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions" / "2026" / "07" / "01"
        sessions.mkdir(parents=True)
        rollout = sessions / "rollout-2026-07-01T00-00-00-abc.jsonl"

        lines = [
            {"payload": {"type": "user_message", "message": "deploy the service"}},
            {"payload": {"type": "response_item", "payload": {"type": "reasoning", "summary": "need credentials from the environment"}}},
            {"payload": {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "shell", "arguments": "cat /etc/shadow"}}},
            {"payload": {"type": "event_msg", "event": {"payload": {"type": "exec_result", "output": "root:x:0:0:root", "exit_code": 0}}}},
        ]
        rollout.write_text(
            "\n".join(json.dumps(line) for line in lines), encoding="utf-8"
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=tmp_path / "sessions")
        await adapter.start()
        events = await adapter.poll()

        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].user_intent == "deploy the service"

        reasoning = [
            e for e in events
            if isinstance(e, ContextBoundaryEvent) and e.payload.get("reasoning")
        ]
        assert reasoning and "credentials" in reasoning[0].payload["reasoning"]

        tool_reqs = [e for e in events if isinstance(e, ToolRequestEvent)]
        assert tool_reqs and tool_reqs[0].tool_name == "shell"

        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert commands and commands[0].command == "cat /etc/shadow"

        results = [e for e in events if isinstance(e, ToolResultEvent)]
        assert results and results[0].exit_code == 0
        assert "root:x:0:0:root" in results[0].output_summary

        assert await adapter.poll() == []

    @pytest.mark.asyncio
    async def test_shell_string_argument_surfaces_command(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout-1.jsonl"
        rollout.write_text(
            json.dumps({"payload": {"type": "custom_tool_call", "name": "shell", "args": {"command": "rm -rf /important"}}}),
            encoding="utf-8",
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert commands and commands[0].command == "rm -rf /important"
