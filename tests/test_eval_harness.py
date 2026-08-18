"""S5-8: evaluation harness over replayable session corpora."""

from pathlib import Path

from agenttrace.eval.runner import report, run_corpus, run_scenario

CORPUS = Path(__file__).parent / "corpus"


def test_corpus_scenarios_all_pass() -> None:
    results = run_corpus(CORPUS)
    assert len(results) >= 4
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
