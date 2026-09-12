"""Tests for severity calibration and negative-result sweeps (ant.md P2 #10).

The point of this module is honesty about a *negative* result: "nothing of
similar or worse severity" is only meaningful against one ordered scale, and
only if the boundary of what was read is attached. These tests pin both — the
ladder's ordering, the explicit unknown bucket, and the coverage caveats.
"""

from __future__ import annotations

import pytest

from agenttrace.graph.severity import (
    DEFAULT_THRESHOLD,
    SEVERITY_LADDER,
    SeverityCalibration,
    calibrate,
    negative_result_statement,
    severity_rank,
)


class _Finding:
    """Anything carrying a severity attribute — a finding or an incident."""

    def __init__(self, severity: str) -> None:
        self.severity = severity


def test_ladder_is_ordered_most_severe_first() -> None:
    assert SEVERITY_LADDER[0] == "critical"
    ranks = [severity_rank(rung) for rung in SEVERITY_LADDER]
    assert ranks == list(range(len(SEVERITY_LADDER)))
    # A lower rank must mean a more severe finding.
    assert severity_rank("critical") < severity_rank("info")


def test_unknown_severity_is_not_silently_treated_as_low() -> None:
    assert severity_rank("sev2") is None
    assert severity_rank("") is None
    calibration = calibrate([_Finding("sev2"), _Finding("high")])
    assert calibration.unknown == ("sev2",)
    assert calibration.total == 2  # counted in the total ...
    assert calibration.counts == {"high": 1}  # ... but not placed on the ladder
    assert calibration.max_severity == "high"


def test_calibration_normalises_case_and_whitespace() -> None:
    calibration = calibrate([_Finding(" HIGH "), _Finding("High")])
    assert calibration.counts == {"high": 2}
    assert calibration.unknown == ()


def test_at_or_above_counts_the_threshold_and_everything_worse() -> None:
    calibration = calibrate(
        [_Finding(s) for s in ("critical", "high", "medium", "low", "info")]
    )
    assert calibration.at_or_above("critical") == 1
    assert calibration.at_or_above("high") == 2
    assert calibration.at_or_above("low") == 4
    assert calibration.at_or_above("info") == 5


def test_at_or_above_rejects_an_off_ladder_threshold() -> None:
    with pytest.raises(ValueError, match="unknown severity threshold"):
        SeverityCalibration(counts={}).at_or_above("sev2")


def test_empty_calibration_has_no_maximum() -> None:
    calibration = calibrate([])
    assert calibration.total == 0
    assert calibration.max_severity is None


def test_negative_result_states_scope_and_coverage_gap() -> None:
    text = negative_result_statement(
        calibrate([_Finding("low")]),
        threshold="high",
        sessions_scanned=12,
        events_scanned=4812,
        errors=["s1: LedgerError"],
        detectors_applied=29,
    )
    assert "NEGATIVE RESULT" in text
    assert "12 session(s) and 4812 event(s)" in text
    assert "29 detector(s)" in text
    assert "Coverage gap (1)" in text
    assert "bounded by what could not be read" in text


def test_negative_result_is_never_claimed_when_findings_clear_the_threshold() -> None:
    text = negative_result_statement(
        calibrate([_Finding("critical")]),
        threshold="high",
        sessions_scanned=1,
        events_scanned=10,
    )
    assert "NEGATIVE RESULT" not in text
    assert "1 finding(s) at or above 'high'" in text
    assert "most severe: critical" in text


def test_clean_sweep_says_the_coverage_gap_is_empty() -> None:
    text = negative_result_statement(
        calibrate([]), sessions_scanned=3, events_scanned=30
    )
    assert "Coverage gap: none reported" in text
    assert DEFAULT_THRESHOLD == "high"


def test_unlabelled_severities_are_disclosed_in_the_verdict() -> None:
    text = negative_result_statement(
        calibrate([_Finding("sev2")]), sessions_scanned=1, events_scanned=1
    )
    assert "Unlabelled severities (1)" in text
    assert "sev2" in text
    assert "neither support nor refute" in text


def test_payload_keeps_ladder_order_and_totals() -> None:
    payload = calibrate([_Finding("low"), _Finding("sev2")]).to_payload()
    assert list(payload["counts"]) == list(SEVERITY_LADDER)
    assert payload["counts"]["low"] == 1
    assert payload["unknown_counts"] == {"sev2": 1}
    assert payload["total"] == 2
    assert payload["max_severity"] == "low"


def test_off_ladder_threshold_is_rejected_by_the_verdict_builder() -> None:
    with pytest.raises(ValueError, match="unknown severity threshold"):
        negative_result_statement(
            calibrate([]), threshold="sev2", sessions_scanned=0, events_scanned=0
        )
