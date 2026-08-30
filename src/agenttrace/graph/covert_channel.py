"""Emergent covert-channel detection (plan2.md shortcoming #1).

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
