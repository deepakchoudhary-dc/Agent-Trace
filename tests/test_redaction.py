"""Tests for secret redaction engine."""

from agenttrace.security.redaction import SecretRedactor


class TestSecretRedactor:
    """Tests for the SecretRedactor."""

    def test_redact_aws_access_key(self) -> None:
        redactor = SecretRedactor()
        sample_key = "AKIA" + "TESTACCESSKEY12345"
        text = f"config: {sample_key}"
        result = redactor.redact(text)
        assert sample_key not in result
        assert "[REDACTED]" in result

    def test_redact_github_token(self) -> None:
        redactor = SecretRedactor()
        sample_token = "ghp_" + "TEST" * 10
        text = f"token: {sample_token}"
        result = redactor.redact(text)
        assert "ghp_" not in result
        assert "[REDACTED]" in result

    def test_redact_password(self) -> None:
        redactor = SecretRedactor()
        text = 'password = "my_super_secret_123"'
        result = redactor.redact(text)
        assert "my_super_secret_123" not in result
        assert "[REDACTED]" in result

    def test_redact_bearer_token(self) -> None:
        redactor = SecretRedactor()
        text = "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9.abcdef"
        result = redactor.redact(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_redact_private_key(self) -> None:
        redactor = SecretRedactor()
        text = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = redactor.redact(text)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "[REDACTED]" in result

    def test_redact_connection_string(self) -> None:
        redactor = SecretRedactor()
        text = "db_url = 'postgres://user:pass@host:5432/db'"
        result = redactor.redact(text)
        assert "postgres://user:pass" not in result

    def test_redact_stripe_key(self) -> None:
        redactor = SecretRedactor()
        sample_stripe = "sk_" + "test_" + "1234567890abcdefghijkl"
        text = f"stripe_key = {sample_stripe}"
        result = redactor.redact(text)
        assert "sk_test_" not in result

    def test_no_false_positive_on_normal_text(self) -> None:
        redactor = SecretRedactor()
        text = "This is a normal log message with no secrets"
        result = redactor.redact(text)
        assert result == text

    def test_contains_secrets_detection(self) -> None:
        redactor = SecretRedactor()
        test_key = "sk_" + "test_" + "abc123def456ghi789jkl0"
        assert redactor.contains_secrets(f"api_key = '{test_key}'")
        assert not redactor.contains_secrets("Hello world")

    def test_redact_dict(self) -> None:
        redactor = SecretRedactor()
        data = {
            "command": "curl -H 'Authorization: Bearer eyJhbG123456789abcdefghijklmn'",
            "output": "Success",
            "nested": {
                "secret": "password = hunter2",
            },
        }
        result = redactor.redact_dict(data)
        assert "[REDACTED]" in result["command"]  # type: ignore[operator]
        assert result["output"] == "Success"

    def test_redaction_audit_log(self) -> None:
        redactor = SecretRedactor()
        sample_tok = "ghp_" + "TESTAUDITTOKEN" * 2
        redactor.redact(f"token: {sample_tok}")
        log = redactor.redaction_log
        assert len(log) >= 1
        # Verify the log doesn't contain the secret
        for record in log:
            assert "TESTAUDITTOKEN" not in record.context_preview

    def test_shannon_entropy(self) -> None:
        """High-entropy strings should be flagged."""
        redactor = SecretRedactor()
        # Low entropy
        assert redactor._shannon_entropy("aaaaaaaaaa") < 1.0
        # High entropy (random-looking)
        assert redactor._shannon_entropy("aB3$cD5!eF7@gH9#") > 3.0
