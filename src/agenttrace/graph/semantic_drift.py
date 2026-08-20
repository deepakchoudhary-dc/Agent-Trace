"""AST and Semantic Intent-Drift Engine for AgentTrace.

Analyzes AST symbol modifications across file mutations and compares them
against the approved TaskContract intent to detect silent scope divergence,
unauthorized security surface modifications, and malicious logic alterations.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agenttrace.models.task_contract import TaskContract

logger = logging.getLogger(__name__)

# Security-sensitive function/call names that warrant immediate inspection
_SENSITIVE_CALLS = {
    "eval",
    "exec",
    "system",
    "popen",
    "subprocess",
    "call",
    "check_output",
    "run",
    "rmtree",
    "unlink",
    "remove",
    "chmod",
    "chown",
    "connect",
    "execute",
    "executemany",
    "loads",
    "unpickle",
    "b64decode",
    "decode",
}

# Domain keyword clusters for task-drift classification
_SECURITY_AUTH_KEYWORDS = {
    "auth",
    "authentication",
    "login",
    "password",
    "jwt",
    "token",
    "hash",
    "crypto",
    "encrypt",
    "decrypt",
    "secret",
    "credential",
    "permission",
    "role",
    "rbac",
    "oauth",
    "session",
}

_DATABASE_KEYWORDS = {
    "database",
    "db",
    "sql",
    "query",
    "table",
    "migration",
    "drop",
    "truncate",
    "insert",
    "schema",
}

_FRONTEND_UI_KEYWORDS = {
    "css",
    "style",
    "styling",
    "ui",
    "frontend",
    "layout",
    "button",
    "color",
    "html",
    "component",
    "theme",
    "animation",
    "font",
    "margin",
    "padding",
}


@dataclass
class SymbolSignature:
    """Represents an extracted AST symbol definition."""

    name: str
    symbol_type: str  # function, class, async_function, import
    docstring: str = ""
    args: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class ASTDiffSummary:
    """Summary of structural AST changes between two versions of code."""

    file_path: str
    added_symbols: list[SymbolSignature] = field(default_factory=list)
    removed_symbols: list[SymbolSignature] = field(default_factory=list)
    modified_symbols: list[SymbolSignature] = field(default_factory=list)
    sensitive_calls_added: list[str] = field(default_factory=list)
    parse_error: bool = False
    error_message: str = ""


@dataclass
class SemanticDriftResult:
    """Evaluation of whether AST mutations drift from the declared TaskContract."""

    file_path: str
    drift_detected: bool
    drift_score: float  # 0.0 to 1.0
    severity: str  # low, medium, high, critical
    reason: str
    affected_symbols: list[str] = field(default_factory=list)
    sensitive_calls: list[str] = field(default_factory=list)


class ASTDiffAnalyzer:
    """Performs deep AST parsing and symbol extraction across Python code."""

    @staticmethod
    def extract_symbols(source_code: str) -> dict[str, SymbolSignature]:
        """Extract function, class, and call signatures from Python source code."""
        symbols: dict[str, SymbolSignature] = {}
        if not source_code.strip():
            return symbols

        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return symbols

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls: list[str] = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            calls.append(child.func.id)
                        elif isinstance(child.func, ast.Attribute):
                            calls.append(child.func.attr)

                args = [a.arg for a in node.args.args]
                decorators: list[str] = []
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(dec.attr)

                is_async = isinstance(node, ast.AsyncFunctionDef)
                sym_type = "async_function" if is_async else "function"
                symbols[node.name] = SymbolSignature(
                    name=node.name,
                    symbol_type=sym_type,
                    docstring=ast.get_docstring(node) or "",
                    args=args,
                    calls=calls,
                    decorators=decorators,
                    line_number=node.lineno,
                )
            elif isinstance(node, ast.ClassDef):
                calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            calls.append(child.func.id)
                        elif isinstance(child.func, ast.Attribute):
                            calls.append(child.func.attr)

                symbols[node.name] = SymbolSignature(
                    name=node.name,
                    symbol_type="class",
                    docstring=ast.get_docstring(node) or "",
                    calls=calls,
                    line_number=node.lineno,
                )

        return symbols

    def diff_code(self, old_code: str, new_code: str, file_path: str = "") -> ASTDiffSummary:
        """Diff two versions of Python code at the AST symbol level."""
        old_symbols = self.extract_symbols(old_code)
        new_symbols = self.extract_symbols(new_code)

        added: list[SymbolSignature] = []
        removed: list[SymbolSignature] = []
        modified: list[SymbolSignature] = []
        sensitive_calls: list[str] = []

        # Find added or modified symbols
        for name, new_sym in new_symbols.items():
            if name not in old_symbols:
                added.append(new_sym)
                for call in new_sym.calls:
                    if call in _SENSITIVE_CALLS:
                        sensitive_calls.append(call)
            else:
                old_sym = old_symbols[name]
                if (
                    old_sym.args != new_sym.args
                    or old_sym.calls != new_sym.calls
                    or old_sym.decorators != new_sym.decorators
                ):
                    modified.append(new_sym)
                    for call in new_sym.calls:
                        if call in _SENSITIVE_CALLS and call not in old_sym.calls:
                            sensitive_calls.append(call)

        # Find removed symbols
        for name, old_sym in old_symbols.items():
            if name not in new_symbols:
                removed.append(old_sym)

        return ASTDiffSummary(
            file_path=file_path,
            added_symbols=added,
            removed_symbols=removed,
            modified_symbols=modified,
            sensitive_calls_added=list(set(sensitive_calls)),
        )


class SemanticDriftEngine:
    """Evaluates AST diffs against TaskContract intent to detect scope divergence."""

    def __init__(self, contract: TaskContract | None = None) -> None:
        self.contract = contract
        self.analyzer = ASTDiffAnalyzer()

    def evaluate_mutation(
        self,
        file_path: str,
        old_code: str,
        new_code: str,
    ) -> SemanticDriftResult:
        """Evaluate a file mutation for semantic drift from the declared task goal."""
        summary = self.analyzer.diff_code(old_code, new_code, file_path)

        if not self.contract:
            return SemanticDriftResult(
                file_path=file_path,
                drift_detected=False,
                drift_score=0.0,
                severity="low",
                reason="No active task contract to evaluate against",
            )

        goal_lower = self.contract.goal.lower()
        path_lower = file_path.lower()

        # Extract keywords from the goal
        is_frontend_task = any(kw in goal_lower for kw in _FRONTEND_UI_KEYWORDS)
        is_security_task = any(kw in goal_lower for kw in _SECURITY_AUTH_KEYWORDS)
        is_db_task = any(kw in goal_lower for kw in _DATABASE_KEYWORDS)

        # Check if modified file is a security/auth/db critical surface
        is_auth_file = any(
            sec in path_lower
            for sec in ("auth", "security", "jwt", "crypto", "password", "token", "credentials")
        )
        is_db_file = any(
            db in path_lower
            for db in ("migration", "database", "models/user", "schema", "sqlite", "postgres")
        )

        all_mutated_symbols = [s.name for s in summary.added_symbols + summary.modified_symbols]
        mutated_syms_lower = " ".join(all_mutated_symbols).lower()

        drift_score = 0.0
        reasons: list[str] = []
        severity = "low"

        # Case 1: Frontend/UI task modifying Auth or Crypto logic
        if is_frontend_task and not is_security_task:
            if is_auth_file:
                drift_score += 0.8
                reasons.append(
                    f"UI task ('{self.contract.goal}') modified critical auth path: {file_path}"
                )
            if any(sec in mutated_syms_lower for sec in _SECURITY_AUTH_KEYWORDS):
                drift_score += 0.7
                reasons.append(
                    f"Frontend task modified security/auth symbols: {all_mutated_symbols}"
                )

        # Case 2: Non-DB task dropping/altering database schemas
        has_db_mutations = is_db_file or any(db in mutated_syms_lower for db in _DATABASE_KEYWORDS)
        if not is_db_task and has_db_mutations:
            drift_score += 0.6
            reasons.append(
                f"Task ('{self.contract.goal}') modified DB symbols without DB scope: {file_path}"
            )

        # Case 3: Sensitive system/exec calls injected
        if summary.sensitive_calls_added:
            drift_score += 0.5
            reasons.append(
                f"Injected sensitive system/exec calls: {summary.sensitive_calls_added}"
            )

        drift_score = min(drift_score, 1.0)
        drift_detected = drift_score >= 0.5

        if drift_score >= 0.8:
            severity = "critical"
        elif drift_score >= 0.6:
            severity = "high"
        elif drift_score >= 0.4:
            severity = "medium"

        reason_str = " | ".join(reasons) if reasons else "Mutations align with task contract"

        return SemanticDriftResult(
            file_path=file_path,
            drift_detected=drift_detected,
            drift_score=drift_score,
            severity=severity,
            reason=reason_str,
            affected_symbols=all_mutated_symbols,
            sensitive_calls=summary.sensitive_calls_added,
        )
