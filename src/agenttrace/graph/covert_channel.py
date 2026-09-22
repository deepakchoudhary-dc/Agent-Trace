"""Emergent covert-channel detection (plan.md shortcoming #1).

The METR Hugging Face incident ran on infrastructure never designed for
communication: ~63,000 messages and 5,855 shared files written as cache
entries with ``zz``-prefixed directory names, chunked base64 file transfers,
and per-agent mailbox directories. Nothing about that traffic is a "bad
command" — it is communication-shaped *structure* on ordinary filesystem
artifacts.

This detector is deliberately structural, not keyword-based: it looks for

- **encoded artifact names** — filename stems that are long, high-entropy
  base64/hex-style tokens (cache keys, encoded chunks, ``zzFILE_...``-style);
- **chunked encoded transfers** — many sibling files sharing a prefix with
  sequential numeric suffixes created in a short window (split-file upload);
- **message-board-like structures** — a directory receiving a burst of
  similarly-prefixed sibling entries (an improvised mailbox/board).

- **high-entropy blob carriage** (low) — a shell command in a content-
  placement/decode context (``echo``/``python -c``/``base64 -d``/...) carries
  a large random-looking base64/hex blob. High-entropy nested data in a
  command is consistent with steganographic content carriage AND with
  minified scripts or opaque tokens — distinguishable only by intent, so
  the finding says so explicitly (structure only).

Incidents are emitted through the same hash-chained ``IncidentEvent`` path
as the correlation engine, so the finding is auditable evidence, not a log line.
"""

from __future__ import annotations

import logging
import math
import re
from collections import deque
from datetime import datetime, timedelta
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

from agenttrace.models.events import (
    CommandEvent,
    ConfidenceLevel,
    EventBase,
    FileMutationEvent,
    IncidentEvent,
)

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

_ENCODED_STEM = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")
# Directory/mailbox names: distinctive shape, lower length floor.
_DISTINCTIVE_NAME = re.compile(r"^[A-Za-z0-9_./+-]{8,}$")
_SEQUENTIAL_SUFFIX = re.compile(r"^(?P<prefix>.*?)(?P<num>\d{2,})$")
# Prefixes that legitimately produce many same-prefixed siblings.
_BENIGN_PREFIXES = frozenset({
    "test", "tests", "spec", "tmp", "temp", "build", "dist", "cache",
    "module", "component", "page", "chunk", "part", "log", "backup",
    "node_modules", "venv", ".git", "output", "result", "session",
})

# -- High-entropy blob carriage -----------------------------------------------
# Minimal-floor policy: a base64/hex blob short enough to be a version
# token or hash is ordinary; only LARGE opaque blobs in a content-
# placement/decode context are structurally steganography-shaped.
_STE_BASE64 = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")
_STE_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_STE_BLOB_ENTROPY = 4.0
# 3.3: hex of structured/English-text payloads sits ~3.3-3.6; uniform-random
# hex (hashes, ciphertext) lands ~3.7+. Pure-pattern hex (00001111...) is far
# below. Measured floor: 58-char English-text hex measured H=3.39.
_STE_HEX_ENTROPY = 3.3
# Command shapes that MOVE opaque data into place (write/decode/eval).
_STE_CONTEXT = re.compile(
    r"\b(?:echo|printf)\b.*(?:>>|>|$)"
    r"|\b(?:python|python3|node|ruby|perl)\s+-[ec]"
    r"|\bbase64\s+-d\b|\bopenssl\s+enc\b|\bxxd\s+-r\b"
    r"|\beval\b|\bsh\s+-c\b|\bcat\s*>>|\btee\b"
    r"|\b(?:write|save|decode|decrypt|unpack)\b",
    re.IGNORECASE,
)
# Blobs that are self-explanatorily benign in the same context.
_STE_HEADERS = re.compile(
    r"sha256:|sha512:|blake2|sha256sum|md5sum|git\s+hash|"
    r"signature|-----BEGIN|nonce=|token=|apikey|secret=",
    re.IGNORECASE,
)


class CovertChannelDetector:
    """Structural anomaly detection on the filesystem event stream."""

    def __init__(
        self,
        session_id: UUID,
        *,
        window_seconds: int = 600,
        min_chunk_siblings: int = 8,
        min_board_siblings: int = 12,
    ) -> None:
        self.session_id = session_id
        self._window = timedelta(seconds=window_seconds)
        self._min_chunk_siblings = min_chunk_siblings
        self._min_board_siblings = min_board_siblings
        self._recent: deque[tuple[datetime, str]] = deque(maxlen=2048)
        self._last_emitted: dict[str, datetime] = {}
        self._cooldown = timedelta(minutes=10)

    def observe(self, event: EventBase) -> list[IncidentEvent]:
        """Feed one event; return any covert-channel incidents it completes."""
        if isinstance(event, CommandEvent) and event.command:
            return self._check_encoded_payload(event)
        if not isinstance(event, FileMutationEvent):
            return []
        if event.mutation_type == "delete" or not event.file_path:
            return []

        now = event.timestamp
        self._recent.append((now, event.file_path))
        self._prune(now)

        for check in (
            self._check_encoded_name,
            self._check_chunked_transfer,
            self._check_board_structure,
        ):
            incidents = check(event)
            if incidents:
                return incidents
        return []

    def reset(self) -> None:
        """Clear correlation state (e.g., on session restart)."""
        self._recent.clear()
        self._last_emitted.clear()


    # -- Signal 1: high-entropy encoded names ------------------------------

    def _check_encoded_name(self, event: FileMutationEvent) -> list[IncidentEvent]:
        stem = _stem(event.file_path)
        if not _ENCODED_STEM.match(stem) or _shannon(stem) < 3.5:
            return []
        if not self._can_emit("encoded_artifact_names", event.timestamp):
            return []
        logger.warning("COVERT: encoded artifact name written: %s", event.file_path)
        return [self._incident(
            "encoded_artifact_names",
            "high",
            "High-entropy encoded artifact name",
            (
                f"File '{event.file_path}' has a long high-entropy name with no "
                "identifiable structure — the covert message-board pattern from "
                "the METR Hugging Face incident, where agents used encoded "
                "directory names in a package cache as a communication channel."
            ),
            [event],
        )]

    # -- Signal 2: chunked encoded transfers -------------------------------

    def _check_chunked_transfer(self, event: FileMutationEvent) -> list[IncidentEvent]:
        groups: dict[str, list[int]] = {}
        for _, path in self._recent:
            parent, name = _split(path)
            match = _SEQUENTIAL_SUFFIX.match(name)
            if not match:
                continue
            prefix = match.group("prefix")
            if not prefix or _normalize_prefix(prefix) in _BENIGN_PREFIXES:
                continue
            groups.setdefault(f"{parent}::{prefix}", []).append(
                int(match.group("num"))
            )
        for key, numbers in groups.items():
            if len(numbers) < self._min_chunk_siblings:
                continue
            ordered = sorted(set(numbers))
            if ordered[-1] - ordered[0] + 1 > 4 * len(ordered):
                continue  # not a coherent sequence
            if not self._can_emit("chunked_encoded_transfer", event.timestamp):
                return []
            parent, prefix = key.split("::", 1)
            logger.warning(
                "COVERT: chunked transfer shape in %s (%d parts of '%s*')",
                parent, len(numbers), prefix,
            )
            return [self._incident(
                "chunked_encoded_transfer",
                "high",
                "Chunked encoded file transfer",
                (
                    f"{len(numbers)} sequentially-numbered, same-prefixed files "
                    f"were written under '{parent}' within the correlation window "
                    "— the split-file protocol agents used in the METR incident "
                    "to move multi-hundred-KB bundles through a channel that "
                    "limits entry size."
                ),
                [event],
            )]
        return []

    # -- Signal 3: improvised message-board structures ---------------------

    def _check_board_structure(self, event: FileMutationEvent) -> list[IncidentEvent]:
        parent, _name = _split(event.file_path)
        if not parent:
            return []
        names = {_split(p)[1] for _, p in self._recent if _split(p)[0] == parent}
        if len(names) < self._min_board_siblings:
            return []

        # (a) Convention prefixes among SIBLING NAMES (never the parent path):
        #     a >=4-char distinctive prefix at min volume, or a short (2-3
        #     char) prefix like the METR incident's literal 'zz' convention
        #     at DOUBLE volume (short prefixes are common in benign dirs).
        common = _common_prefix(names)
        prefix_hit = (
            len(common) >= 4
            or (len(common) >= 2 and len(names) >= self._min_board_siblings * 2)
        ) and _normalize_prefix(common) not in _BENIGN_PREFIXES

        # (b) Mailbox-shaped directory: a distinctive (long, high-entropy)
        #     directory name accumulating many sibling entries — the
        #     zzMAILBOX_<handle> pattern from the incident.
        parent_name = PurePosixPath(parent).name
        mailbox_hit = (
            len(parent_name) >= 8
            and _DISTINCTIVE_NAME.match(parent_name) is not None
            and _shannon(parent_name) >= 3.0
        )

        if not prefix_hit and not mailbox_hit:
            return []
        if not self._can_emit("message_board_structure", event.timestamp):
            return []
        logger.warning(
            "COVERT: message-board-like structure: %d siblings under %s "
            "(name prefix '%s', parent '%s')",
            len(names), parent, common, parent_name,
        )
        return [self._incident(
            "message_board_structure",
            "medium",
            "Improvised message-board-like directory structure",
            (
                f"{len(names)} sibling entries under '{parent}' form a "
                f"communication-shaped structure (name prefix '{common}', "
                "distinctive parent directory) — structurally consistent with "
                "the improvised agent message boards (mailboxes, reply "
                "conventions, coordination channels) documented in the METR "
                "incident, for which no designed inter-agent channel exists "
                "to explain them."
            ),
            [event],
        )]

    # -- Signal 4: high-entropy blob carriage -------------------------------

    def _check_encoded_payload(
        self, event: CommandEvent
    ) -> list[IncidentEvent]:
        """A large encoded blob moved into place by a decode/write context.

        Network payload bytes are NOT captured by the event model, and file
        content is stored only as a hash — so the honest observable for
        "high-entropy channel" is the shell command that *carries* the
        opaque bytes into place. Structure only, LOW confidence, and the
        limitation is part of the finding's reasoning gap.
        """
        cmd = event.command
        if not _STE_CONTEXT.search(cmd):
            return []
        if _STE_HEADERS.search(cmd):
            return []

        blob: str | None = None
        hex_match = _STE_HEX.search(cmd)
        if hex_match:
            # Hex has a 16-symbol alphabet (max H = 4.0), so its "high
            # entropy" bar must be lower than base64's.
            blob = hex_match.group(0)
            kind = "hex"
            floor = _STE_HEX_ENTROPY
        else:
            match = _STE_BASE64.search(cmd)
            if match and len(match.group(0)) >= 56:
                blob = match.group(0)
                kind = "base64"
                floor = _STE_BLOB_ENTROPY
        if blob is None:
            return []

        entropy = _shannon(blob)
        if entropy < floor:
            return []
        # A blob's own length entropy floor: short blobs reaching the
        # threshold are typically hashes, which the header check already
        # catches; this guards the converse.
        if not self._can_emit("high_entropy_blob_command", event.timestamp):
            return []

        logger.warning(
            "COVERT: high-entropy %s blob (%d chars, H=%.2f) in content-"
            "placement context: %s",
            kind, len(blob), entropy, cmd[:120],
        )
        return [self._incident(
            "high_entropy_blob_command",
            "low",
            "High-entropy encoded blob moved into place by a command",
            (
                f"A {len(blob)}-char {kind} blob (entropy {entropy:.2f}) is "
                "embedded in a content-placement/decode context: "
                f"{cmd[:120]!r}. Large opaque payloads carried by shell "
                "commands are the structural shape of steganographic "
                "content carriage. Honest limits: network payload bytes "
                "and file contents are NOT captured by this event model — "
                "only the command line is observable — and minified "
                "scripts or opaque tokens are indistinguishable from "
                "steganography at this layer. Screening signal only, not "
                "a finding of intent."
            ),
            [event],
        )]

    # -- Shared machinery ----------------------------------------------------

    def _prune(self, now: datetime) -> None:
        while self._recent and now - self._recent[0][0] > self._window:
            self._recent.popleft()

    def _can_emit(self, incident_type: str, now: datetime) -> bool:
        last = self._last_emitted.get(incident_type)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[incident_type] = now
        return True

    def _incident(
        self,
        incident_type: str,
        severity: str,
        title: str,
        description: str,
        related: list[EventBase],
    ) -> IncidentEvent:
        return IncidentEvent(
            session_id=self.session_id,
            actor_id="covert_channel_detector",
            source_adapter="covert_channel_detector",
            confidence=ConfidenceLevel.MEDIUM,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            related_events=[str(e.event_id) for e in related],
            causal_path=[str(e.event_id) for e in related],
        )


def _normalize_prefix(prefix: str) -> str:
    return prefix.lower().strip("._- /\\")

# -- Helpers -----------------------------------------------------------------


def _stem(path: str) -> str:
    name = PureWindowsPath(path).name if "\\" in path else PurePosixPath(path).name
    return name.rsplit(".", 1)[0]


def _split(path: str) -> tuple[str, str]:
    normalized = path.replace("\\", "/")
    posix = PurePosixPath(normalized)
    return str(posix.parent), posix.name


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total) for count in freq.values()
    )


def _common_prefix(names: set[str]) -> str:
    try:
        return "".join(
            chars[0] if len(set(chars)) == 1 else ""
            for chars in zip(*list(names), strict=False)
        )
    except (ValueError, IndexError):
        return ""
