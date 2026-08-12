"""Secret redaction engine.

Detects and redacts secrets (API keys, tokens, passwords, private keys,
connection strings) before any data reaches persistent storage. Maintains
an audit log of what was redacted (without the secret itself).
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_REDACTED = "[REDACTED]"

# Patterns for known secret formats
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # API keys and tokens
    ("aws_access_key", re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}")),
    ("aws_secret_key", re.compile(r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("github_token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,255}")),
    ("github_fine_token", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    ("generic_api_key", re.compile(r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,100})['\"]?", re.IGNORECASE)),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*", re.IGNORECASE)),

    # Passwords and secrets
    ("password_assignment", re.compile(r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?([^\s'\"]{4,100})['\"]?", re.IGNORECASE)),
    ("secret_assignment", re.compile(r"(?:secret|token|credential)\s*[:=]\s*['\"]?([^\s'\"]{8,200})['\"]?", re.IGNORECASE)),

    # Private keys
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----")),

    # Connection strings
    ("connection_string", re.compile(r"(?:mongodb|postgres|mysql|redis|amqp|mssql)://[^\s'\"]{10,500}", re.IGNORECASE)),
    ("jdbc_url", re.compile(r"jdbc:[a-z]+://[^\s'\"]{10,500}", re.IGNORECASE)),

    # Cloud provider secrets
    ("azure_key", re.compile(r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,100}")),
    ("gcp_key", re.compile(r"AIza[A-Za-z0-9\-_]{35}")),
    ("slack_token", re.compile(r"xox[bpsorta]-[A-Za-z0-9\-]{10,250}")),
    ("stripe_key", re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,100}")),

    # Generic high-entropy strings in sensitive contexts
    ("env_secret", re.compile(r"(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[_A-Z]*\s*=\s*['\"]?([A-Za-z0-9\-_.+/=]{16,200})['\"]?", re.IGNORECASE)),
]


@dataclass
class RedactionRecord:
    """Audit record of a redaction event (does NOT contain the secret)."""

    pattern_name: str
    position: int
    length: int
    context_preview: str  # Surrounding non-secret text for identification
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SecretRedactor:
    """Detects and redacts secrets before storage.

    Uses both regex pattern matching and entropy analysis. Maintains
    an audit log of what was redacted for incident review.
    """

    def __init__(self, entropy_threshold: float = 4.5) -> None:
        self._entropy_threshold = entropy_threshold
        self._redaction_log: list[RedactionRecord] = []

    @property
    def redaction_log(self) -> list[RedactionRecord]:
        """Read-only access to the redaction audit log."""
        return list(self._redaction_log)

    def redact(self, text: str) -> str:
        """Redact all detected secrets from text.

        Returns the redacted text. Logs each redaction.
        """
        if not text:
            return text

        result = text
        for pattern_name, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(result):
                # Log the redaction (without the secret)
                start = max(0, match.start() - 10)
                end = min(len(result), match.end() + 10)
                context = result[start:match.start()] + _REDACTED + result[match.end():end]

                record = RedactionRecord(
                    pattern_name=pattern_name,
                    position=match.start(),
                    length=match.end() - match.start(),
                    context_preview=context[:100],
                )
                self._redaction_log.append(record)

            # Replace matches
            result = pattern.sub(_REDACTED, result)

        return result

    def redact_dict(self, data: dict[str, object]) -> dict[str, object]:
        """Recursively redact secrets in a dictionary."""
        redacted: dict[str, object] = {}
        for key, value in data.items():
            if isinstance(value, str):
                redacted[key] = self.redact(value)
            elif isinstance(value, dict):
                redacted[key] = self.redact_dict(value)  # type: ignore[arg-type]
            elif isinstance(value, list):
                redacted[key] = [
                    self.redact(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted

    def contains_secrets(self, text: str) -> bool:
        """Check if text contains any detectable secrets."""
        for _, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return True

        # Also check for high-entropy strings
        words = text.split()
        for word in words:
            if len(word) >= 20 and self._shannon_entropy(word) > self._entropy_threshold:
                return True

        return False

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def clear_log(self) -> None:
        """Clear the redaction audit log."""
        self._redaction_log.clear()
