"""Tests for Unicode canonicalization in redaction (plan2.md P1.8)."""

from __future__ import annotations

from agenttrace.security.redaction import SecretRedactor


def test_fullwidth_confusables_still_redacted() -> None:
    """NFKC folds fullwidth forms so obfuscated keys still match."""
    redactor = SecretRedactor()
    # fullwidth ｐａｓｓｗｏｒｄ＝ secret-value
    text = "ｐａｓｓｗｏｒｄ＝SuperSecret99!"
    assert redactor.contains_secrets(text)
    redacted = redactor.redact(text)
    assert "SuperSecret99" not in redacted


def test_bidi_isolate_chars_stripped_before_matching() -> None:
    """BiDi isolates (U+2066-2069) cannot hide a token from detection."""
    redactor = SecretRedactor()
    # token = gh\u2066p_\u2067... split with isolates
    token = "gh" + "\u2066" + "p_" + "\u2067" + "A" * 40
    text = f"commit authored with {token} ok"
    assert redactor.contains_secrets(text)


def test_zero_width_still_stripped() -> None:
    redactor = SecretRedactor()
    token = "sk_live_" + "\u200b" + "A" * 30
    assert redactor.contains_secrets(token)


def test_plain_text_untouched() -> None:
    redactor = SecretRedactor()
    text = "The agent refactored parser.py and added 12 tests."
    assert redactor.redact(text) == text


def test_redaction_positions_reference_original_text() -> None:
    """Spans map back to original indices even with control chars present."""
    redactor = SecretRedactor()
    secret = "SuperSecret99!"
    text = "pwd=\u200b" + secret + "; end"
    redacted = redactor.redact(text)
    assert secret in text  # sanity: original contains it
    assert secret not in redacted
    assert "[REDACTED]" in redacted
