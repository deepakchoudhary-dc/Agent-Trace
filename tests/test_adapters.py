"""Tests for the transcript-based adapters (Claude Code, Codex CLI).

These adapters turn real on-disk agent transcripts into canonical events,
including the model's *reasoning* â€” the evidence the case-study incidents
show is essential to understanding why an agent acted.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from agenttrace.adapters.claude import ClaudeAdapter
from agenttrace.adapters.codex import CodexAdapter
from agenttrace.adapters.composite import CompositeAdapter
from agenttrace.adapters.copilot import CopilotAdapter
from agenttrace.adapters.universal import UniversalAgentAdapter
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
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
                        {
                        "type": "thinking",
                        "thinking": "I should check the database credentials first",
                    },
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
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t1",
                            "content": "BEGIN RSA PRIVATE KEY",
                        }
                    ],
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

    @pytest.mark.asyncio
    async def test_cursor_restore_skips_old_lines_and_reads_new(
        self, tmp_path: Path
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        projects = tmp_path / "projects" / "-Users-me-app"
        projects.mkdir(parents=True)
        transcript = projects / "session-1.jsonl"

        first_lines = [
            json.dumps({
                "type": "user", "uuid": "u1", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {"role": "user", "content": "first prompt"},
            }),
            json.dumps({
                "type": "assistant", "uuid": "a1", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": "ls -la"}},
                    ],
                },
            }),
        ]
        transcript.write_text("\n".join(first_lines) + "\n", encoding="utf-8")

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()
        assert len(events) == 3  # invocation + tool request + command

        cursor = adapter.cursor_state()
        assert cursor["positions"][str(transcript)] > 0
        assert cursor["invoked"] == [str(transcript)]

        # A fresh adapter (as after a daemon restart) resumes from the cursor:
        # nothing already seen is re-emitted.
        resumed = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        resumed.restore_cursor(cursor)
        await resumed.start()
        assert await resumed.poll() == []

        # Activity while the daemon was down is picked up exactly once.
        transcript.write_text(
            json.dumps({
                "type": "assistant", "uuid": "a2", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t2", "name": "Bash",
                         "input": {"command": "git status"}},
                    ],
                },
            })
            + "\n",
            encoding="utf-8",
        )
        events = await resumed.poll()
        assert len(events) == 2  # tool request + command
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert len(commands) == 1
        assert commands[0].command == "git status"
        assert await resumed.poll() == []

    @pytest.mark.asyncio
    async def test_uses_vendor_timestamp_when_present(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        projects = tmp_path / "projects" / "-Users-me-app"
        projects.mkdir(parents=True)
        transcript = projects / "session-1.jsonl"
        vendor_ts = "2026-08-16T10:30:00+00:00"
        transcript.write_text(json.dumps({
            "type": "user", "uuid": "u1", "cwd": str(workspace),
            "sessionId": "s1", "version": "2.1.0",
            "timestamp": vendor_ts,
            "message": {"role": "user", "content": "deploy now"},
        }) + "\n", encoding="utf-8")

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].timestamp == datetime.fromisoformat(vendor_ts)

    @pytest.mark.asyncio
    async def test_naive_vendor_timestamp_clamped_to_utc(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        projects = tmp_path / "projects" / "-Users-me-app"
        projects.mkdir(parents=True)
        transcript = projects / "session-1.jsonl"
        transcript.write_text(json.dumps({
            "type": "user", "uuid": "u1", "cwd": str(workspace),
            "sessionId": "s1", "version": "2.1.0",
            "timestamp": "2026-08-16T10:30:00",
            "message": {"role": "user", "content": "deploy now"},
        }) + "\n", encoding="utf-8")

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].timestamp.utcoffset() == timedelta(0)

    @pytest.mark.asyncio
    async def test_rewind_reparses_truncated_tail_line(self, tmp_path: Path) -> None:
        """A tail line cut mid-write is rewound and parsed once it completes."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        projects = tmp_path / "projects" / "-Users-me-app"
        projects.mkdir(parents=True)
        transcript = projects / "session-1.jsonl"

        def make_line(cmd: str) -> str:
            return json.dumps({
                "type": "assistant", "uuid": "a1", "cwd": str(workspace),
                "sessionId": "s1", "version": "2.1.0",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": cmd}},
                    ],
                },
            })

        complete = make_line("git add .")
        pending = make_line("git commit -m part")
        cut = len(pending) - 20
        partial = pending[:cut]
        transcript.write_text(complete + "\n" + partial, encoding="utf-8")

        adapter = ClaudeAdapter(uuid4(), str(workspace), projects_dir=projects)
        await adapter.start()
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["git add ."]

        # Cursor was rewound to the start of the truncated tail line (the
        # byte just after the first complete line), not left at EOF.
        first_line_end = transcript.read_bytes().find(b"\n") + 1
        assert adapter._positions[str(transcript)] == first_line_end

        # The rest of the line arrives â€” it is parsed exactly once
        with open(transcript, "a", encoding="utf-8") as f:
            f.write(pending[cut:] + "\n")
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["git commit -m part"]
        assert await adapter.poll() == []


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
            {
                "payload": {
                    "type": "response_item",
                    "payload": {
                        "type": "reasoning",
                        "summary": "need credentials from the environment",
                    },
                }
            },
            {
                "payload": {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "shell",
                        "arguments": "cat /etc/shadow",
                    },
                }
            },
            {
                "payload": {
                    "type": "event_msg",
                    "event": {
                        "payload": {
                            "type": "exec_result",
                            "output": "root:x:0:0:root",
                            "exit_code": 0,
                        }
                    }
                }
            },
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
            json.dumps({
                "payload": {
                    "type": "custom_tool_call",
                    "name": "shell",
                    "args": {"command": "rm -rf /important"},
                }
            }),
            encoding="utf-8",
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()

        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert commands and commands[0].command == "rm -rf /important"

    @pytest.mark.asyncio
    async def test_uses_vendor_timestamp_when_present(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout-1.jsonl"
        vendor_ts = "2026-08-16T10:30:00+00:00"
        rollout.write_text(
            json.dumps({
                "timestamp": vendor_ts,
                "payload": {"type": "user_message", "message": "deploy now"},
            }),
            encoding="utf-8",
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].timestamp == datetime.fromisoformat(vendor_ts)

    @pytest.mark.asyncio
    async def test_rewind_reparses_truncated_tail_line(self, tmp_path: Path) -> None:
        """A rollout line cut mid-write is rewound and parsed once complete."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout-1.jsonl"

        def make_line(cmd: str) -> str:
            return json.dumps({
                "payload": {
                    "type": "response_item",
                    "payload": {
                        "type": "local_shell_call",
                        "name": "shell",
                        "arguments": {"command": cmd},
                    },
                }
            })

        complete = make_line("git add .")
        pending = make_line("git commit -m part")
        cut = len(pending) - 20
        partial = pending[:cut]
        rollout.write_text(complete + "\n" + partial, encoding="utf-8")

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["git add ."]

        # Cursor was rewound to the start of the truncated tail line
        first_line_end = rollout.read_bytes().find(b"\n") + 1
        assert adapter._positions[str(rollout)] == first_line_end

        # The rest of the line arrives â€” it is parsed exactly once
        with open(rollout, "a", encoding="utf-8") as f:
            f.write(pending[cut:] + "\n")
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert [c.command for c in commands] == ["git commit -m part"]
        assert await adapter.poll() == []

    @pytest.mark.asyncio
    async def test_rollback_rewinds_positions(self, tmp_path: Path) -> None:
        """A failed ingest batch rewinds offsets so lines are re-reported."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout-1.jsonl"
        rollout.write_text(
            json.dumps({
                "payload": {"type": "user_message", "message": "do it"},
            }),
            encoding="utf-8",
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        pre_poll = adapter.cursor_state()
        assert len(await adapter.poll()) == 1

        adapter.rollback_cursor()
        assert adapter.cursor_state() == pre_poll
        assert len(await adapter.poll()) == 1

        adapter.commit_cursor()
        assert await adapter.poll() == []

    @pytest.mark.asyncio
    async def test_naive_vendor_timestamp_clamped_to_utc(self, tmp_path: Path) -> None:
        """Naive vendor timestamps are UTC, never the host's local offset."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout-1.jsonl"
        rollout.write_text(
            json.dumps({
                "timestamp": "2026-08-16T10:30:00",
                "payload": {"type": "user_message", "message": "deploy now"},
            }),
            encoding="utf-8",
        )

        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].timestamp.utcoffset() == timedelta(0)


class TestCopilotAdapter:
    """Copilot logs: only strict JSON records with a real prompt are emitted."""

    def _adapter(
        self, log_path: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> CopilotAdapter:
        monkeypatch.setattr(
            CopilotAdapter, "_find_copilot_logs", staticmethod(lambda: [log_path])
        )
        return CopilotAdapter(uuid4(), str(workspace))

    @pytest.mark.asyncio
    async def test_emits_invocation_for_json_prompt_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        log_path = tmp_path / "copilot.log"
        log_path.write_text("", encoding="utf-8")

        adapter = self._adapter(log_path, workspace, monkeypatch)
        await adapter.start()
        log_path.write_text(
            json.dumps({
                "timestamp": "2026-08-16T11:00:00Z",
                "prompt": "fix the failing test",
            })
            + "\n",
            encoding="utf-8",
        )
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].user_intent == "fix the failing test"

    @pytest.mark.asyncio
    async def test_ignores_free_text_log_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        log_path = tmp_path / "copilot.log"
        log_path.write_text("", encoding="utf-8")

        adapter = self._adapter(log_path, workspace, monkeypatch)
        await adapter.start()
        log_path.write_text(
            "[info] conversation request: 2026-08-16 11:00:00 [debug] prompt tokens=42\n"
            "session started for workspace /Users/me/app\n",
            encoding="utf-8",
        )
        events = await adapter.poll()
        assert events == []

    @pytest.mark.asyncio
    async def test_cursor_restore_skips_old_lines_and_reads_new(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        log_path = tmp_path / "copilot.log"
        log_path.write_text("", encoding="utf-8")

        adapter = self._adapter(log_path, workspace, monkeypatch)
        await adapter.start()
        log_path.write_text(
            json.dumps({"prompt": "old prompt"}) + "\n",
            encoding="utf-8",
        )
        events = await adapter.poll()
        assert len([e for e in events if isinstance(e, InvocationEvent)]) == 1

        cursor = adapter.cursor_state()
        assert cursor["positions"][str(log_path)] > 0
        assert cursor["seen_prompts"]

        # Resumed adapter keeps the persisted offsets â€” start() must not
        # clobber them with the current EOF.
        resumed = self._adapter(log_path, workspace, monkeypatch)
        resumed.restore_cursor(cursor)
        await resumed.start()
        assert await resumed.poll() == []

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"prompt": "new prompt"}) + "\n")
        events = await resumed.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].user_intent == "new prompt"

    @pytest.mark.asyncio
    async def test_resumes_after_log_rotation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        log_path = tmp_path / "copilot.log"
        log_path.write_text("", encoding="utf-8")

        adapter = self._adapter(log_path, workspace, monkeypatch)
        await adapter.start()
        log_path.write_text(
            json.dumps({"prompt": "pre-rotation"}) + "\n",
            encoding="utf-8",
        )
        assert len(await adapter.poll()) == 1

        # The log rotates (truncated to a smaller file) while unwatched — the
        # cursor must reset to the top instead of skipping the new file.
        log_path.write_text(
            json.dumps({"prompt": "rotated"}) + "\n",
            encoding="utf-8",
        )
        events = await adapter.poll()
        invocations = [e for e in events if isinstance(e, InvocationEvent)]
        assert len(invocations) == 1
        assert invocations[0].user_intent == "rotated"


class TestUniversalAgentAdapter:
    """Universal sensor emits honest low-confidence context events only."""

    @pytest.mark.asyncio
    async def test_emits_honest_context_events_only(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        cline = workspace / ".cline"
        cline.mkdir()
        session_file = cline / "session-1.json"
        session_file.write_text('{"messages": []}', encoding="utf-8")

        adapter = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        await adapter.start()
        events = await adapter.poll()

        assert all(isinstance(e, ContextBoundaryEvent) for e in events)
        assert events, "expected a context boundary event"
        assert events[0].confidence == ConfidenceLevel.LOW
        assert events[0].payload.get("note") == "session file detected, content not parsed"
        assert events[0].event_type == EventType.CONTEXT_BOUNDARY
        assert not any(isinstance(e, InvocationEvent) for e in events)

    @pytest.mark.asyncio
    async def test_no_duplicates_across_polls(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        cline = workspace / ".cline"
        cline.mkdir()
        session_file = cline / "session-1.json"
        session_file.write_text('{"messages": []}', encoding="utf-8")

        adapter = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        await adapter.start()
        assert len(await adapter.poll()) == 1
        assert await adapter.poll() == []

    @pytest.mark.asyncio
    async def test_cursor_restore_suppresses_old_entries(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        cline = workspace / ".cline"
        cline.mkdir()
        session_file = cline / "session-1.json"
        session_file.write_text('{"messages": []}', encoding="utf-8")

        adapter = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        await adapter.start()
        assert len(await adapter.poll()) == 1
        adapter.commit_cursor()

        cursor = adapter.cursor_state()
        assert cursor["seen_entries"]

        # A resumed adapter does not re-report files it already flagged...
        resumed = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        resumed.restore_cursor(cursor)
        await resumed.start()
        assert await resumed.poll() == []

        # ...but a file changed while the daemon was down is a NEW change.
        session_file.write_text('{"messages": [1]}', encoding="utf-8")
        events = await resumed.poll()
        assert len(events) == 1
        assert events[0].payload.get("path") == str(session_file)

    @pytest.mark.asyncio
    async def test_rollback_reports_changes_again(self, tmp_path: Path) -> None:
        """A failed ingest batch (no commit) must not lose the change."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        cline = workspace / ".cline"
        cline.mkdir()
        session_file = cline / "session-1.json"
        session_file.write_text('{"messages": []}', encoding="utf-8")

        adapter = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        await adapter.start()
        assert len(await adapter.poll()) == 1

        # Daemon failed to ingest → rollback → next poll re-reports the change.
        adapter.rollback_cursor()
        assert len(await adapter.poll()) == 1
        # Committing persists the fingerprint and stops re-reporting.
        adapter.commit_cursor()
        assert await adapter.poll() == []
        assert adapter.cursor_state()["seen_entries"]

    @pytest.mark.asyncio
    async def test_pending_entries_not_persisted_in_cursor(self, tmp_path: Path) -> None:
        """Uncommitted staged fingerprints must not leak into the cursor."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        cline = workspace / ".cline"
        cline.mkdir()
        session_file = cline / "session-1.json"
        session_file.write_text('{"messages": []}', encoding="utf-8")

        adapter = UniversalAgentAdapter(uuid4(), str(workspace), watch_dirs=[cline])
        await adapter.start()
        assert len(await adapter.poll()) == 1
        assert adapter.cursor_state()["seen_entries"] == []

        adapter.commit_cursor()
        assert len(adapter.cursor_state()["seen_entries"]) == 1


# -- Sprint-1 fixes: composite command drop + codex cross-project isolation ------


class TestCompositeSupportedTypes:
    """The composite validates events against its own supported types, so a
    type any sub-adapter emits must be included or the daemon drops it
    silently (shell commands were lost in the default auto config)."""

    def test_union_includes_every_sub_adapter_type(self) -> None:
        adapter = CompositeAdapter(uuid4(), "/ws")
        union: set[EventType] = set()
        for sub in adapter._sub_adapters:
            union.update(sub.supported_event_types)
        assert set(adapter.supported_event_types) == union

    def test_command_events_pass_validation(self) -> None:
        adapter = CompositeAdapter(uuid4(), "/ws")
        event = CommandEvent(
            session_id=adapter.session_id,
            actor_id="agent",
            source_adapter="claude_code",
            command="pytest tests/",
        )
        assert adapter.validate_event(event)


class TestCodexCrossProjectFilter:
    """Codex stores every project's rollouts under one home directory; this
    adapter must not ingest other projects' transcripts under this
    workspace's provenance."""

    def _write_rollout(
        self, sessions: Path, name: str, cwd: str, command: str
    ) -> Path:
        rollout = sessions / name
        lines = [
            {"payload": {"type": "session_meta", "cwd": cwd}},
            {"payload": {"type": "user_message", "message": "go"}},
            {
                "payload": {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "shell",
                        "arguments": json.dumps({"command": command}),
                    },
                }
            },
        ]
        rollout.write_text(
            "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8"
        )
        return rollout

    @pytest.mark.asyncio
    async def test_foreign_project_rollout_skipped(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        other = tmp_path / "other-project"
        other.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        self._write_rollout(
            sessions, "rollout-1.jsonl", str(other), "cat secrets.txt"
        )
        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        assert events == []

    @pytest.mark.asyncio
    async def test_workspace_rollout_ingested_with_real_cwd(
        self, tmp_path: Path
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        self._write_rollout(
            sessions, "rollout-2.jsonl", str(workspace), "pytest tests/"
        )
        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        events = await adapter.poll()
        commands = [e for e in events if isinstance(e, CommandEvent)]
        assert len(commands) == 1
        assert commands[0].working_dir == str(workspace)

    @pytest.mark.asyncio
    async def test_cwd_survives_cursor_roundtrip(self, tmp_path: Path) -> None:
        """The restart case: positions are past session_meta, so the cwd map
        must persist in the cursor state or a NEW adapter (post-restart)
        resumes translating a foreign rollout with no cwd to filter by."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        rollout = self._write_rollout(
            sessions, "rollout-3.jsonl", str(other), "cat secrets.txt"
        )
        adapter = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await adapter.start()
        await adapter.poll()  # consume through session_meta
        cursor = adapter.cursor_state()

        fresh = CodexAdapter(uuid4(), str(workspace), sessions_dir=sessions)
        await fresh.start()
        fresh.restore_cursor(cursor)
        # A foreign command arriving after the restart must still be filtered
        # by the persisted cwd — without rollout_cwd in the cursor it would
        # be ingested under this workspace's provenance.
        with open(rollout, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "payload": {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "shell",
                        "arguments": json.dumps({"command": "cat /etc/shadow"}),
                    },
                }
            }) + "\n")
        assert await fresh.poll() == []
