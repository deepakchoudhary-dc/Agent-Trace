"""Evaluation harness over replayable session corpora.

Regression-test policies and detectors in CI on recorded session corpora
(Opik/DeepEval pattern): every scenario replays a fixed event stream through
the PolicyEngine and DetectionEngine and compares the emitted findings to
the scenario's expectations. When a scenario declares ``task_goal``, the
stream is additionally replayed through the eval-integrity detector —
scope-pivot goal divergence needs the contracted goal as its baseline.
A regression in detection surfaces as a failed
scenario, and the harness writes a machine-readable report that the review
loop can consume as real evidence artifacts.

Scenarios never claim ground truth about agent behavior — they assert that
the *product* responds to a replayed observation in the specified way.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from agenttrace.graph.eval_integrity import SandbaggingDetector
from agenttrace.models.events import event_from_dict
from agenttrace.security.detectors import DetectionEngine
from agenttrace.security.policy import PolicyEngine

if TYPE_CHECKING:
    from pathlib import Path



@dataclass
class ScenarioResult:
    name: str
    policy_findings: list[str] = field(default_factory=list)
    detector_findings: list[str] = field(default_factory=list)
    eval_incidents: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    passed: bool = False


def load_scenario(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    return data


def run_scenario(data: dict[str, Any], name: str) -> ScenarioResult:
    """Replay one scenario through policy + detector engines."""
    session_id = uuid4()
    events = [
        event_from_dict({**e, "session_id": str(session_id)})
        for e in data.get("events", [])
    ]
    expected = sorted(set(data.get("expected_findings", [])))

    policy = PolicyEngine(
        session_id,
        internet_allowed=data.get("internet_allowed"),
        allowed_destinations=data.get("allowed_destinations", []),
        baseline_destinations=set(data.get("baseline_destinations", [])),
    )
    detectors = DetectionEngine(
        session_id,
        workspace_paths=data.get("workspace_paths", []),
        internet_allowed=data.get("internet_allowed"),
    )

    policy_findings: set[str] = set()
    detector_findings: set[str] = set()
    for event in events:
        policy_findings.update(
            f.finding_type for f in policy.evaluate(event).findings
        )
        for finding in detectors.evaluate(event):
            detector_findings.add(finding.detector_id)

    # DseWiki #1: replay through the eval-integrity detector when the
    # scenario declares a contracted goal (scope-pivot divergence is
    # undefined without one — the detector stays silent, by design).
    eval_incidents: set[str] = set()
    task_goal = data.get("task_goal")
    if task_goal:
        eval_detector = SandbaggingDetector(
            session_id,
            task_goal=str(task_goal),
        )
        for offset, event in enumerate(events):
            # Replay constructs every event from static JSON, so all
            # timestamps are identical; stagger them to give the detector
            # the monotonic stream its time-based machinery assumes.
            event.timestamp = event.timestamp + timedelta(seconds=offset)
            for incident in eval_detector.observe(event):
                eval_incidents.add(incident.incident_type)

    actual = policy_findings | detector_findings | eval_incidents
    result = ScenarioResult(
        name=name,
        policy_findings=sorted(policy_findings),
        detector_findings=sorted(detector_findings),
        eval_incidents=sorted(eval_incidents),
    )
    result.missing = [e for e in expected if e not in actual]
    result.unexpected = [a for a in actual if a not in expected]
    result.passed = not result.missing and not result.unexpected
    return result


def run_corpus(corpus_dir: Path) -> list[ScenarioResult]:
    """Run every *.json scenario under corpus_dir, sorted by name."""
    results: list[ScenarioResult] = []
    for scenario_path in sorted(corpus_dir.glob("*.json")):
        data = load_scenario(scenario_path)
        results.append(
            run_scenario(data, data.get("name", scenario_path.stem))
        )
    return results


def report(results: list[ScenarioResult]) -> dict[str, Any]:
    """Machine-readable report for CI and the review loop."""
    return {
        "harness": "agenttrace-eval",
        "scenarios_total": len(results),
        "scenarios_passed": sum(1 for r in results if r.passed),
        "scenarios": [
            {
                "name": r.name,
                "passed": r.passed,
                "policy_findings": r.policy_findings,
                "detector_findings": r.detector_findings,
                "eval_incidents": r.eval_incidents,
                "missing": r.missing,
                "unexpected": r.unexpected,
            }
            for r in results
        ],
    }
