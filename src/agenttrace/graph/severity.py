"""Severity calibration and negative-result sweeps (ant.md P2 #10).

The Anthropic report's wide-net re-scan closed with a *negative result*:
"nothing of similar or worse severity". That sentence is only meaningful if two
things hold — severity is comparable across incidents, and the scope of the
search is stated. Otherwise "we found nothing worse" is unfalsifiable, and a
scan that silently covered half the ledger reads exactly like a scan that
covered all of it.

This module supplies both halves:

- :data:`SEVERITY_LADDER` — one ordered scale, the same one every
  ``PolicyFindingEvent`` and ``IncidentEvent`` already carries (see
  ``models/events.py``). Values outside the ladder land in an explicit unknown
  bucket instead of being folded into the lowest rung, because "unlabelled" is
  not "harmless" (invariant #3: never fabricate confidence).
- :class:`SeverityCalibration` — the distribution over a set of findings or
  incidents, plus the maximum rung actually present.
- :func:`negative_result_statement` — the honest sentence: what was searched,
  what was found, and what could NOT be seen. A negative result reported
  without its coverage gap is not a result.

Nothing here decides what is severe; it makes an existing judgement comparable
and states the boundary of the evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

# Most severe first. Index 0 is the worst outcome, so a *lower* rank means a
# more severe finding — `at_or_above(threshold)` therefore keeps ranks <= the
# threshold's rank.
SEVERITY_LADDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Default sweep threshold: "similar or worse severity" in the report's sense —
# the level at which an incident would have been escalated to the assessment
# partner.
DEFAULT_THRESHOLD = "high"


def severity_rank(severity: str) -> int | None:
    """Ladder position of ``severity`` (0 = most severe); None if unrecognised.

    Returning None rather than a sentinel keeps the unknown case explicit at
    every call site: callers must decide what an unlabelled severity means
    instead of inheriting "least severe" by accident.
    """
    normalized = (severity or "").strip().lower()
    if not normalized:
        return None
    try:
        return SEVERITY_LADDER.index(normalized)
    except ValueError:
        return None


def _severity_of(event: object) -> str:
    return str(getattr(event, "severity", "") or "").strip().lower()


@dataclass(frozen=True)
class SeverityCalibration:
    """Severity distribution over one set of findings or incidents."""

    counts: Mapping[str, int]
    unknown_counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        """Every finding counted, including the unlabelled ones."""
        return sum(self.counts.values()) + sum(self.unknown_counts.values())

    @property
    def unknown(self) -> tuple[str, ...]:
        """Distinct severity strings that are not on the ladder."""
        return tuple(sorted(self.unknown_counts))

    @property
    def max_severity(self) -> str | None:
        """Most severe rung present, or None when nothing was calibrated."""
        for rung in SEVERITY_LADDER:
            if self.counts.get(rung):
                return rung
        return None

    def at_or_above(self, threshold: str) -> int:
        """Count of findings at least as severe as ``threshold``."""
        rank = severity_rank(threshold)
        if rank is None:
            raise ValueError(
                f"unknown severity threshold {threshold!r}; "
                f"expected one of {', '.join(SEVERITY_LADDER)}"
            )
        return sum(
            count
            for rung, count in self.counts.items()
            if (r := severity_rank(rung)) is not None and r <= rank
        )

    def summary(self) -> str:
        """One-line distribution, ladder order first."""
        parts = [f"{rung}={self.counts.get(rung, 0)}" for rung in SEVERITY_LADDER]
        if self.unknown_counts:
            parts.append(
                "unknown="
                + ",".join(f"{k}:{v}" for k, v in sorted(self.unknown_counts.items()))
            )
        return ", ".join(parts)

    def to_payload(self) -> dict[str, object]:
        return {
            "counts": {rung: self.counts.get(rung, 0) for rung in SEVERITY_LADDER},
            "unknown_counts": dict(sorted(self.unknown_counts.items())),
            "total": self.total,
            "max_severity": self.max_severity,
        }


def calibrate(events: Iterable[object]) -> SeverityCalibration:
    """Bucket any findings/incidents by severity, unknowns kept separate.

    Accepts anything carrying a ``severity`` attribute, so the same scale
    compares a live session's findings with a retro-scan's incidents.
    """
    known: Counter[str] = Counter()
    unknown: Counter[str] = Counter()
    for event in events:
        severity = _severity_of(event)
        if severity_rank(severity) is not None:
            known[severity] += 1
        else:
            unknown[severity or "(empty)"] += 1
    return SeverityCalibration(counts=dict(known), unknown_counts=dict(unknown))


def negative_result_statement(
    calibration: SeverityCalibration,
    *,
    threshold: str = DEFAULT_THRESHOLD,
    sessions_scanned: int,
    events_scanned: int,
    errors: Iterable[str] = (),
    detectors_applied: int | None = None,
) -> str:
    """State the sweep's result — including a negative one — with its scope.

    A negative result is only honest when the boundary of the search is
    attached: how much was read, how much could not be read, and which
    severities could not be placed on the ladder at all.
    """
    rank = severity_rank(threshold)
    if rank is None:
        raise ValueError(
            f"unknown severity threshold {threshold!r}; "
            f"expected one of {', '.join(SEVERITY_LADDER)}"
        )
    error_list = [e for e in errors if e]
    at_or_above = calibration.at_or_above(threshold)

    scope = (
        f"{sessions_scanned} session(s) and {events_scanned} event(s) scanned"
        + (f" with {detectors_applied} detector(s)" if detectors_applied else "")
    )
    lines = [
        f"Severity calibration: {calibration.summary()} "
        f"({calibration.total} finding(s) total).",
    ]
    if at_or_above:
        lines.append(
            f"Result: {at_or_above} finding(s) at or above '{threshold}' "
            f"(most severe: {calibration.max_severity})."
        )
    else:
        lines.append(
            f"NEGATIVE RESULT: across {scope}, nothing at or above "
            f"'{threshold}' was found."
        )
    if calibration.unknown:
        lines.append(
            f"Unlabelled severities ({sum(calibration.unknown_counts.values())}): "
            f"{', '.join(calibration.unknown)} — counted in the total, NOT placed "
            "on the ladder; they neither support nor refute this result."
        )
    if error_list:
        lines.append(
            f"Coverage gap ({len(error_list)}): " + "; ".join(error_list[:5])
            + " — the result is bounded by what could not be read."
        )
    else:
        lines.append(
            "Coverage gap: none reported — every targeted session and event was read."
        )
    return "\n".join(lines)
