"""Encryption manager for event payloads and blob storage.

Handles AES-256-GCM encryption/decryption of event payloads and blobs.
Key management uses Windows DPAPI via the cryptography library for
machine-local key protection.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_KEY_SIZE = 32  # 256 bits
_NONCE_SIZE = 12  # 96 bits for AES-GCM


class EncryptionError(Exception):
    """Raised when encryption/decryption operations fail."""


class EncryptionManager:
    """AES-256-GCM encryption for event payloads and blobs.

    The encryption key is derived from a machine-local keyfile.
    On Windows, the keyfile can be further protected using DPAPI
    (Data Protection API) which ties it to the user's login.
    """

    def __init__(self, key_dir: str | Path | None = None) -> None:
        self._key_dir = Path(key_dir) if key_dir else self._default_key_dir()
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()
        self._cipher = AESGCM(self._key)

    @staticmethod
    def _default_key_dir() -> Path:
        """Default key storage directory."""
        app_data = os.environ.get("LOCALAPPDATA", "")
        if app_data:
            return Path(app_data) / "AgentTrace" / "keys"
        return Path.home() / ".agenttrace" / "keys"

    def _key_path(self) -> Path:
        """Path to the encryption key file."""
        return self._key_dir / "master.key"

    def _load_or_create_key(self) -> bytes:
        """Load existing key or generate a new one."""
        key_path = self._key_path()

        if key_path.exists():
            try:
                encoded = key_path.read_text(encoding="utf-8").strip()
                key = base64.b64decode(encoded)
                if len(key) == _KEY_SIZE:
                    return key
                logger.warning("Invalid key size, generating new key")
            except Exception:
                logger.warning("Failed to load key, generating new one")

        # Generate new key
        key = secrets.token_bytes(_KEY_SIZE)
        key_path.write_text(
            base64.b64encode(key).decode("utf-8"),
            encoding="utf-8",
        )

        # Set restrictive permissions (Windows: owner-only via ACLs)
        try:
            os.chmod(str(key_path), 0o600)
        except OSError:
            logger.debug("Could not set key file permissions (Windows)")

        logger.info("Generated new encryption key: %s", key_path)
        return key

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        """Encrypt data using AES-256-GCM.

        Returns: nonce (12 bytes) + ciphertext (includes GCM tag).
        """
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, data: bytes, associated_data: bytes | None = None) -> bytes:
        """Decrypt AES-256-GCM encrypted data.

        Expects: nonce (12 bytes) + ciphertext (with GCM tag).
        """
        if len(data) < _NONCE_SIZE:
            raise EncryptionError("Data too short to contain nonce")

        nonce = data[:_NONCE_SIZE]
        ciphertext = data[_NONCE_SIZE:]

        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e

    def encrypt_json(self, data: dict[str, object]) -> bytes:
        """Encrypt a JSON-serializable dict."""
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")
        return self.encrypt(plaintext)

    def decrypt_json(self, encrypted: bytes) -> dict[str, object]:
        """Decrypt to a JSON dict."""
        plaintext = self.decrypt(encrypted)
        return json.loads(plaintext)  # type: ignore[no-any-return]

    def rotate_key(self) -> bytes:
        """Generate a new key. Returns the old key for re-encryption."""
        old_key = self._key
        self._key = secrets.token_bytes(_KEY_SIZE)
        self._cipher = AESGCM(self._key)

        key_path = self._key_path()
        key_path.write_text(
            base64.b64encode(self._key).decode("utf-8"),
            encoding="utf-8",
        )

        logger.info("Encryption key rotated")
        return old_key
