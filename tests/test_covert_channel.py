"""Tests for the covert-channel structural detector (plan.md shortcoming #1)."""

from __future__ import annotations

from uuid import uuid4

from agenttrace.graph.covert_channel import CovertChannelDetector
from agenttrace.models.events import CommandEvent, ConfidenceLevel, FileMutationEvent


def _fme(path: str) -> FileMutationEvent:
    return FileMutationEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="filesystem",
        file_path=path,
        mutation_type="create",
    )


def _cmd(command: str) -> CommandEvent:
    return CommandEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="terminal",
        confidence=ConfidenceLevel.HIGH,
        command=command,
    )


def test_benign_files_produce_no_incident() -> None:
    detector = CovertChannelDetector(uuid4())
    for name in ("main.py", "utils.py", "README.md"):
        assert detector.observe(_fme(f"/ws/src/{name}")) == []


def test_encoded_artifact_name_detected() -> None:
    detector = CovertChannelDetector(uuid4())
    # Long, high-entropy stem: the zzFILE_<b64> cache-entry pattern.
    incidents = detector.observe(
        _fme("/ws/cache/zzFILE_d7shc-dF5g5622LVtEIW2yareqM2Nw_F9yRZB8rjn2Z7fSB")
    )
    assert len(incidents) == 1
    assert incidents[0].incident_type == "encoded_artifact_names"
    assert incidents[0].severity == "high"


def test_chunked_encoded_transfer_detected() -> None:
    detector = CovertChannelDetector(uuid4())
    incidents: list = []
    for i in range(1, 9):
        incidents = detector.observe(_fme(f"/ws/board/zzBUNDLE_{i:04d}"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "chunked_encoded_transfer"


def test_message_board_structure_detected() -> None:
    detector = CovertChannelDetector(uuid4(), min_board_siblings=6)
    incidents: list = []
    for name in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"):
        incidents = detector.observe(_fme(f"/ws/zzMAILBOX_AIC71C/{name}"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "message_board_structure"


def test_short_prefix_board_detected_at_double_volume() -> None:
    """The literal METR convention: a 2-char 'zz' prefix at high volume."""
    detector = CovertChannelDetector(uuid4(), min_board_siblings=6)
    names = (
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
        "golf", "hotel", "india", "juliet", "kilo", "lima",
    )
    incidents: list = []
    for name in names:  # 12 = 2x min_board_siblings
        incidents = detector.observe(_fme(f"/ws/board/zz{name}"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "message_board_structure"


def test_short_prefix_below_double_volume_not_flagged() -> None:
    """A short prefix needs 2x volume — a few same-prefixed files are normal."""
    detector = CovertChannelDetector(uuid4(), min_board_siblings=6)
    incidents: list = []
    for name in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"):
        incidents = detector.observe(_fme(f"/ws/board/zz{name}"))
    assert incidents == []


def test_cooldown_prevents_spam() -> None:
    detector = CovertChannelDetector(uuid4())
    first = detector.observe(
        _fme("/ws/cache/zzFILE_d7shc-dF5g5622LVtEIW2yareqM2Nw_F9yRZB8rjn2Z7fSB")
    )
    second = detector.observe(
        _fme("/ws/cache/zzFILE_aaaa-dF5g5622LVtEIW2yareqM2Nw_F9yRZB8rjn2Z7fSB")
    )
    assert len(first) == 1
    assert second == []


def test_non_file_events_ignored() -> None:
    from agenttrace.models.events import CommandEvent, ConfidenceLevel

    detector = CovertChannelDetector(uuid4())
    event = CommandEvent(
        session_id=uuid4(),
        actor_id="agent",
        source_adapter="terminal",
        confidence=ConfidenceLevel.HIGH,
        command="ls",
    )
    assert detector.observe(event) == []


def test_delete_events_ignored() -> None:
    detector = CovertChannelDetector(uuid4())
    event = _fme("/ws/cache/zzFILE_d7shc-dF5g5622LVtEIW2yareqM2Nw_F9yRZB8rjn2Z7fSB")
    event.mutation_type = "delete"
    assert detector.observe(event) == []


# -- High-entropy blob carriage (steganography-shaped, structural only) --


def test_base64_blob_in_echo_context_detected() -> None:
    detector = CovertChannelDetector(uuid4())
    blob = "eW91bWrDn7p8q9s0t1u2v3w4x5y6zA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5"
    incidents = detector.observe(
        _cmd(f'echo "{blob}" | base64 -d > /tmp/payload.bin')
    )
    assert len(incidents) == 1
    assert incidents[0].incident_type == "high_entropy_blob_command"
    assert incidents[0].severity == "low"
    assert "not a finding of intent" in incidents[0].description


def test_hex_blob_in_sh_c_context_detected() -> None:
    detector = CovertChannelDetector(uuid4())
    hexblob = "4a6f686e2d4f6d2068652c6e54686f7261626c65337165342e426c7468"
    incidents = detector.observe(_cmd(f"sh -c 'xxd -r -p <<< {hexblob} > note.bin'"))
    assert len(incidents) == 1
    assert incidents[0].incident_type == "high_entropy_blob_command"


def test_blob_without_placement_context_is_silent() -> None:
    detector = CovertChannelDetector(uuid4())
    blob = "eW91bWrDn7p8q9s0t1u2v3w4x5y6zA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5"
    # Same blob, but passed to a program as a plain argument (no decode/
    # write/eval shape) — ordinary opaque token, indistinguishable.
    assert detector.observe(_cmd(f"curl -H 'X-Custom: {blob}' https://api.x/")) == []


def test_short_tokens_do_not_fire() -> None:
    detector = CovertChannelDetector(uuid4())
    assert detector.observe(_cmd("echo 'aGVsb28cWq4=' > tmp.txt")) == []
    assert detector.observe(_cmd('echo "dGVz" > tmp.txt')) == []


def test_checksum_context_is_benign() -> None:
    detector = CovertChannelDetector(uuid4())
    sha = "9" * 64
    assert detector.observe(_cmd(f"echo {sha} > /tmp/checksum.txt")) == []
