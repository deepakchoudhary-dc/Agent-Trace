"""S5-8: evaluation harness over replayable session corpora."""

from pathlib import Path

from agenttrace.eval.runner import (
    load_scenario,
    report,
    run_corpus,
    run_scenario,
)

CORPUS = Path(__file__).parent / "corpus"


def test_corpus_scenarios_all_pass() -> None:
    results = run_corpus(CORPUS)
    assert len(results) >= 16
    failures = [r for r in results if not r.passed]
    assert failures == [], [
        (f.name, f.missing, f.unexpected) for f in failures
    ]


def test_report_is_machine_readable() -> None:
    results = run_corpus(CORPUS)
    rep = report(results)
    assert rep["harness"] == "agenttrace-eval"
    assert rep["scenarios_total"] == rep["scenarios_passed"]
    for scenario in rep["scenarios"]:
        assert "missing" in scenario and "unexpected" in scenario
        assert scenario["passed"]


def test_harness_detects_regressions() -> None:
    """A wrong expectation must fail the scenario — the harness must be able
    to catch detection regressions, or it cannot guard against them."""
    data = {
        "name": "regression probe",
        "workspace_paths": ["/workspace/app"],
        "events": [
            {
                "event_type": "command",
                "actor_id": "agent",
                "source_adapter": "shell_observer",
                "command": "cat ~/.env",
                "working_dir": "/workspace/app",
            }
        ],
        "expected_findings": ["prompt_injection_markers"],
    }
    result = run_scenario(data, "regression probe")
    assert not result.passed
    assert result.missing == ["prompt_injection_markers"]
    assert "credential_read_heuristic" in result.unexpected


def test_scenario_surfaces_actual_findings() -> None:
    data = {
        "name": "finder probe",
        "workspace_paths": ["/workspace/app"],
        "events": [
            {
                "event_type": "command",
                "actor_id": "agent",
                "source_adapter": "shell_observer",
                "command": "git filter-branch --force",
                "working_dir": "/workspace/app",
            }
        ],
        "expected_findings": ["git_history_rewriting"],
    }
    result = run_scenario(data, "finder probe")
    assert result.passed
    assert result.detector_findings == ["git_history_rewriting"]


def test_scope_pivot_scenario_replays_through_eval_detector() -> None:
    """DseWiki #1: a scenario with a contracted goal replays through the
    eval-integrity detector, and the pivot fires with nothing else."""
    data = load_scenario(CORPUS / "scope_pivot_benchmark.json")
    result = run_scenario(data, data["name"])
    assert result.passed
    assert result.eval_incidents == ["scope_pivot_suspected"]


def test_scope_pivot_stays_silent_without_declared_goal() -> None:
    """Same pivot stream without task_goal: divergence is undefined, so
    the eval detector must stay silent and the expectation must fail —
    proving the goal context, not the command alone, drives the signal."""
    data = load_scenario(CORPUS / "scope_pivot_benchmark.json")
    del data["task_goal"]
    data["expected_findings"] = []
    result = run_scenario(data, "no-goal pivot probe")
    assert result.eval_incidents == []
