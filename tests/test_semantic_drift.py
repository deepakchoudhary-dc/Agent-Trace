"""Tests for AST and Semantic Intent-Drift Engine."""

from __future__ import annotations

from uuid import uuid4

from agenttrace.graph.semantic_drift import ASTDiffAnalyzer, SemanticDriftEngine
from agenttrace.models.task_contract import TaskContract


def test_ast_diff_analyzer_detects_symbol_mutations() -> None:
    """ASTDiffAnalyzer accurately identifies added, modified, and removed functions."""
    old_code = """
def calculate_tax(amount: float) -> float:
    return amount * 0.15

def get_user_profile(user_id: int) -> dict:
    return {"id": user_id}
"""
    new_code = """
def calculate_tax(amount: float, rate: float = 0.15) -> float:
    return amount * rate

def authenticate_user(token: str) -> bool:
    import os
    os.system("echo authenticated")
    return True
"""
    analyzer = ASTDiffAnalyzer()
    summary = analyzer.diff_code(old_code, new_code, file_path="src/utils.py")

    added_names = [s.name for s in summary.added_symbols]
    removed_names = [s.name for s in summary.removed_symbols]
    modified_names = [s.name for s in summary.modified_symbols]

    assert "authenticate_user" in added_names
    assert "get_user_profile" in removed_names
    assert "calculate_tax" in modified_names
    assert "system" in summary.sensitive_calls_added


def test_semantic_drift_engine_flags_auth_rewrite_in_ui_task() -> None:
    """SemanticDriftEngine flags critical auth file mutation under a frontend UI task."""
    contract = TaskContract(
        session_id=uuid4(),
        goal="Update header CSS colors and button padding",
        allowed_paths=["src/components/*", "src/styles/*"],
    )
    engine = SemanticDriftEngine(contract)

    old_code = """
def login(username, password):
    return check_password(password)
"""
    new_code = """
def login(username, password):
    import eval
    return True
"""
    result = engine.evaluate_mutation(
        file_path="src/auth/login.py",
        old_code=old_code,
        new_code=new_code,
    )

    assert result.drift_detected is True
    assert result.drift_score >= 0.7
    assert result.severity in ("high", "critical")
    assert "auth" in result.reason.lower() or "ui" in result.reason.lower()


def test_semantic_drift_engine_allows_aligned_modifications() -> None:
    """SemanticDriftEngine permits mutations that match the task contract."""
    contract = TaskContract(
        session_id=uuid4(),
        goal="Update header CSS colors and button layout",
        allowed_paths=["src/components/*"],
    )
    engine = SemanticDriftEngine(contract)

    old_code = """
def render_button(label: str) -> str:
    return f"<button>{label}</button>"
"""
    new_code = """
def render_button(label: str, color: str = "blue") -> str:
    return f"<button class='{color}'>{label}</button>"
"""
    result = engine.evaluate_mutation(
        file_path="src/components/button.py",
        old_code=old_code,
        new_code=new_code,
    )

    assert result.drift_detected is False
    assert result.drift_score < 0.5
    assert result.severity == "low"
