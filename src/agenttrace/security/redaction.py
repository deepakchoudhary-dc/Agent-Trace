"""Secret redaction engine.

Detects and redacts secrets (API keys, tokens, passwords, private keys,
connection strings, high-entropy credentials) before any data reaches
persistent storage. Maintains an audit log of what was redacted (without the secret itself).
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_REDACTED = "[REDACTED]"

# Patterns for known secret formats
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # API keys and tokens
    ("aws_access_key", re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}")),
    ("aws_secret_key", re.compile(
        r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    )),
    ("github_token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,255}")),
    ("github_fine_token", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    ("generic_api_key", re.compile(
        r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,100})['\"]?",
        re.IGNORECASE,
    )),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*", re.IGNORECASE)),

    # Passwords and secrets
    ("password_assignment", re.compile(
        r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?([^\s'\"]{4,100})['\"]?",
        re.IGNORECASE,
    )),
    ("secret_assignment", re.compile(
        r"(?:secret|token|credential)\s*[:=]\s*['\"]?([^\s'\"]{8,200})['\"]?",
        re.IGNORECASE,
    )),

    # Private keys
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----")),

    # Connection strings
    ("connection_string", re.compile(
        r"(?:mongodb|postgres|mysql|redis|amqp|mssql)://[^\s'\"]{10,500}",
        re.IGNORECASE,
    )),
    ("jdbc_url", re.compile(r"jdbc:[a-z]+://[^\s'\"]{10,500}", re.IGNORECASE)),

    # Cloud provider secrets
    ("azure_key", re.compile(r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,100}")),
    ("gcp_key", re.compile(r"AIza[A-Za-z0-9\-_]{35}")),
    ("slack_token", re.compile(r"xox[bpsorta]-[A-Za-z0-9\-]{10,250}")),
    ("stripe_key", re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,100}")),

    # Generic high-entropy strings in sensitive contexts
    ("env_secret", re.compile(
        r"(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[_A-Z]*\s*=\s*['\"]?"
        r"([A-Za-z0-9\-_.+/=]{16,200})['\"]?",
        re.IGNORECASE,
    )),
]

# Sensitive dictionary keys, matched component-exactly after normalization
# (lowercase + strip non-alphanumeric). "author" and "tokens" never match;
# "clientSecret" and "api_key" both normalize to set members.
_SENSITIVE_KEY_NAMES = frozenset({
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "sensitivetoken",
    "apikey",
    "apisecret",
    "credential",
    "privatekey",
    "clientsecret",
    "accesskey",
    "accesssecret",
    "auth",
    "authorization",
    "authentication",
    "bearer",
    "passphrase",
    "oauth",
    "oauthtoken",
    "accesstoken",
    "refreshtoken",
    "sessiontoken",
})

_ZERO_WIDTH_CHARS = frozenset({
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad",
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
})


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

    Uses regex pattern matching, sensitive dictionary key inspection,
    and Shannon entropy analysis.
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

        Every match is collected against the ORIGINAL text and applied
        end-to-start, so the audit log always references original positions
        and no match is skewed by earlier replacements.
        """
        if not text or not isinstance(text, str):
            return text

        spans: list[tuple[int, int, str]] = []

        # 1. Known secret formats
        for pattern_name, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                spans.append((match.start(), match.end(), pattern_name))

        # 1b. Defeat zero-width Unicode obfuscation (P1.14)
        clean_chars: list[str] = []
        orig_indices: list[int] = []
        for i, ch in enumerate(text):
            if ch not in _ZERO_WIDTH_CHARS:
                clean_chars.append(ch)
                orig_indices.append(i)
        clean_text = "".join(clean_chars)

        if len(clean_text) != len(text):
            for pattern_name, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(clean_text):
                    c_start, c_end = match.start(), match.end()
                    if c_start < len(orig_indices) and c_end <= len(orig_indices):
                        spans.append(
                            (orig_indices[c_start], orig_indices[c_end - 1] + 1, pattern_name)
                        )

        # 2. High-entropy credential tokens (entropy test on the write path)
        for token_match in re.finditer(r"\S+", text):
            full_tok = token_match.group(0)
            if self._is_high_entropy_credential(full_tok):
                spans.append(
                    (token_match.start(), token_match.end(), "high_entropy_credential")
                )
            elif any(sep in full_tok for sep in ("/", "\\", "?", "&", "=")):
                # Evaluate sub-segments (e.g. query parameters, API keys in URLs/paths)
                for seg in re.finditer(r"[^/\\?&=:\s]+", full_tok):
                    if self._is_high_entropy_credential(seg.group(0)):
                        spans.append(
                            (
                                token_match.start() + seg.start(),
                                token_match.start() + seg.end(),
                                "high_entropy_credential",
                            )
                        )

        # Merge overlapping spans, keeping the wider one
        merged: list[tuple[int, int, str]] = []
        for start, end, name in sorted(spans, key=lambda s: (s[0], -(s[1] - s[0]))):
            if merged and start < merged[-1][1]:
                if end > merged[-1][1]:
                    merged[-1] = (merged[-1][0], end, merged[-1][2])
                continue
            merged.append((start, end, name))

        result = text
        for start, end, pattern_name in reversed(merged):
            if start >= end:
                continue
            context = (
                text[max(0, start - 10):start]
                + _REDACTED
                + text[end:min(len(text), end + 10)]
            )
            self._redaction_log.append(
                RedactionRecord(
                    pattern_name=pattern_name,
                    position=start,
                    length=end - start,
                    context_preview=context[:100],
                )
            )
            result = result[:start] + _REDACTED + result[end:]

        return result

    def redact_bytes(self, data: bytes) -> bytes:
        """Redact secrets from a byte payload before at-rest encryption.

        Text payloads (UTF-8) are scrubbed in place. Binary payloads that do
        not decode as text are returned unchanged: re-encoding arbitrary
        binary through a text codec would corrupt the blob, and binary bytes
        cannot be tokenized as text. Callers that capture binary secrets must
        scrub at capture time.
        """
        try:
            text = data.decode("utf-8")
            return self.redact(text).encode("utf-8")
        except UnicodeDecodeError:
            # Fail closed (P0.11): replace non-decodable binary payload with safe digest metadata
            import hashlib
            digest = hashlib.sha256(data).hexdigest()
            meta = f"[REDACTED BINARY EVIDENCE: SHA256={digest}, size={len(data)}B]"
            return meta.encode("utf-8")

    def redact_any(self, value: Any) -> Any:
        """Recursively redact secrets across arbitrary nested Python data structures."""
        if isinstance(value, str):
            return self.redact(value)
        elif isinstance(value, dict):
            redacted_dict: dict[str, Any] = {}
            for k, v in value.items():
                k_str = str(k)
                # A sensitive key name makes the whole value a credential —
                # redact regardless of its type (strings, numbers, nested
                # structures all carry the secret).
                if self._is_sensitive_key(k_str) and self._has_content(v):
                    redacted_dict[k] = _REDACTED
                    self._redaction_log.append(
                        RedactionRecord(
                            pattern_name=f"sensitive_key:{k_str}",
                            position=0,
                            length=len(str(v)),
                            context_preview=f"{k_str}={_REDACTED}",
                        )
                    )
                else:
                    redacted_dict[k] = self.redact_any(v)
            return redacted_dict
        elif isinstance(value, list):
            return [self.redact_any(item) for item in value]
        elif isinstance(value, tuple):
            return tuple(self.redact_any(item) for item in value)
        elif isinstance(value, set):
            return {self.redact_any(item) for item in value}
        return value

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact secrets in a dictionary."""
        return self.redact_any(data)  # type: ignore[no-any-return]

    def contains_secrets(self, text: str) -> bool:
        """Check if text contains any detectable secrets."""
        if not isinstance(text, str):
            return False

        for _, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return True

        for token_match in re.finditer(r"\S+", text):
            if self._is_high_entropy_credential(token_match.group(0)):
                return True

        return False

    @staticmethod
    def _normalize_key(key: str) -> str:
        """Normalize a dictionary key for sensitive-name matching.

        Lowercases and strips non-alphanumeric characters so snake_case,
        camelCase, and spaced forms of the same credential name all match.
        """
        return re.sub(r"[^a-z0-9]", "", key.lower())

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        """Component-exact sensitive key test.

        Substring matching misclassified benign keys ("author", "tokens",
        "tokenizers"). Normalizing then testing exact membership keeps the
        precision without losing snake_case/camelCase coverage.
        """
        return cls._normalize_key(key) in _SENSITIVE_KEY_NAMES

    @staticmethod
    def _has_content(value: Any) -> bool:
        """Whether a value could carry a secret (empty values cannot)."""
        if value is None:
            return False
        if isinstance(value, (str, list, tuple, set, dict)):
            return len(value) > 0
        return True

    def _is_high_entropy_credential(self, token: str) -> bool:
        """Full-value-domain entropy test for standalone credential tokens.

        A token must be long (>=16), high-entropy (>4.5 bits/char), and contain
        at least one digit or symbol — or be mixed-case and very long (>=24).
        Plain prose, hex hashes, and short identifiers never trip it.
        Standard paths with common file extensions or root path prefixes are
        exempted from whole-string matching (their sub-segments are checked separately).
        """
        clean = token.strip("\"'()[]{}:;,")
        if len(clean) < 16:
            return False
        _exempt = (
            "/", "\\", "./", ".\\", "../", "..\\", "~",
            "http://", "https://", "ws://", "wss://",
        )
        if ("/" in clean or "\\" in clean) and (
            clean.startswith(_exempt)
            or re.search(r"\.[a-zA-Z0-9]{1,6}$", clean)
        ):
            return False
        if self._shannon_entropy(clean) <= self._entropy_threshold:
            return False
        has_digit = any(c.isdigit() for c in clean)
        has_symbol = any(not c.isalnum() for c in clean)
        has_mixed_case = any(c.islower() for c in clean) and any(c.isupper() for c in clean)
        if has_digit or has_symbol:
            return True
        return has_mixed_case and len(clean) >= 24

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
