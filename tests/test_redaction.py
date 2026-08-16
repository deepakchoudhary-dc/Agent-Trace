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

    def test_recursive_nested_structures(self) -> None:
        """Verify deeply nested dictionaries inside lists and tuples are sanitized."""
        redactor = SecretRedactor()
        complex_data = {
            "root_key": "normal",
            "sensitive_token": "raw_token_value_9999",
            "items": [
                {"description": "clean", "password": "nested_password_123"},
                ["inner_list", "Authorization: Bearer " + "tok_1234567890"],
            ],
            "nested_obj": {
                "auth": "secret_auth_header",
            },
        }

        sanitized = redactor.redact_any(complex_data)
        assert sanitized["sensitive_token"] == "[REDACTED]"
        assert sanitized["items"][0]["password"] == "[REDACTED]"
        assert "[REDACTED]" in sanitized["items"][1][1]
        assert sanitized["nested_obj"]["auth"] == "[REDACTED]"
        assert sanitized["root_key"] == "normal"

    def test_redaction_audit_log(self) -> None:
        redactor = SecretRedactor()
        sample_tok = "ghp_" + "TESTAUDITTOKEN" * 2
        redactor.redact(f"token: {sample_tok}")
        log = redactor.redaction_log
        assert len(log) >= 1
        for record in log:
            assert "TESTAUDITTOKEN" not in record.context_preview

    def test_shannon_entropy(self) -> None:
        redactor = SecretRedactor()
        assert redactor._shannon_entropy("aaaaaaaaaa") < 1.0
        assert redactor._shannon_entropy("aB3$cD5!eF7@gH9#") > 3.0

    def test_high_entropy_token_redacted_in_write_path(self) -> None:
        """A high-entropy token that matches no known pattern must still be
        redacted when stored — the entropy test runs on the write path."""
        redactor = SecretRedactor()
        token = "8xK9vT2mQ4pLz8wR5nJc3hY7uB1eF6aS0dG4iC7"  # no pattern match, high entropy
        result = redactor.redact(f"handed to the agent: {token}")
        assert token not in result
        assert "[REDACTED]" in result
        assert redactor.contains_secrets(f"value {token}")

    def test_no_entropy_false_positive_on_prose(self) -> None:
        redactor = SecretRedactor()
        samples = [
            "The quick brown fox jumps over the lazy dog today",
            "documentation was updated and committed to main",
            "abcdefghijklmnopqrstuvwxyz",  # long but lowercase: fails digit/symbol/mixed-case
            "0123456789abcdef0123456789abcdef",  # hex: entropy below threshold
        ]
        for text in samples:
            assert redactor.redact(text) == text, f"false positive on: {text}"
            assert not redactor.contains_secrets(text), f"false positive on: {text}"

    def test_sensitive_key_non_string_values_redacted(self) -> None:
        """Sensitive keys must redact the value regardless of its type."""
        redactor = SecretRedactor()
        data = {
            "password": 1234567890,
            "token": ["a", "b", "c"],
            "secret": {"nested": "deep"},
            "normal": {"author": "Jane", "tokens_used": 42},
        }
        result = redactor.redact_any(data)
        assert result["password"] == "[REDACTED]"
        assert result["token"] == "[REDACTED]"
        assert result["secret"] == "[REDACTED]"
        # Precision: "author" and "tokens_used" are NOT secrets
        assert result["normal"] == {"author": "Jane", "tokens_used": 42}

    def test_sensitive_key_component_matching(self) -> None:
        """snake_case/camelCase credential keys match; lookalikes do not."""
        redactor = SecretRedactor()
        data = {
            "clientSecret": "s3cr3t",
            "api_key": "k" * 20,
            "Authorization": "Bearer xyz",
            "privateKey": "p" * 8,
            "author": "Jane",
            "tokens": "not a secret list",
            "tokenizers": "bert",
            "client_id": "public-id",
            "password_hash": "abc123",
        }
        result = redactor.redact_any(data)
        assert result["clientSecret"] == "[REDACTED]"
        assert result["api_key"] == "[REDACTED]"
        assert result["Authorization"] == "[REDACTED]"
        assert result["privateKey"] == "[REDACTED]"
        assert result["author"] == "Jane"
        assert result["tokens"] == "not a secret list"
        assert result["tokenizers"] == "bert"
        assert result["client_id"] == "public-id"
        assert result["password_hash"] == "abc123"

    def test_audit_log_positions_reference_original_text(self) -> None:
        """Log positions must reference the original text — multiple redactions
        in one string must not skew later entries."""
        redactor = SecretRedactor()
        tok1 = "ghp_" + "A" * 40
        tok2 = "sk_test_" + "1234567890abcdefghijkl"
        text = f"first {tok1} second {tok2} end"
        result = redactor.redact(text)
        assert tok1 not in result and tok2 not in result

        positions = sorted(r.position for r in redactor.redaction_log)
        assert len(positions) >= 2
        # Positions are distinct and in original-text order
        assert all(positions[i] < positions[i + 1] for i in range(len(positions) - 1))
        assert text[positions[0]:positions[0] + 4] == "ghp_"

    def test_redact_is_idempotent(self) -> None:
        redactor = SecretRedactor()
        text = "token = 'ghp_" + "B" * 40 + "'"
        once = redactor.redact(text)
        twice = redactor.redact(once)
        assert once == twice
