"""Encryption manager for event payloads, sensitive columns, and blob storage.

Handles AES-256-GCM encryption/decryption. The machine-local keyfile is protected
at rest using Windows DPAPI (CryptProtectData / CryptUnprotectData via ctypes) on Windows,
and strict OS permissions on non-Windows platforms.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_KEY_SIZE = 32  # 256 bits
_NONCE_SIZE = 12  # 96 bits for AES-GCM


class EncryptionError(Exception):
    """Raised when encryption/decryption operations fail."""


# --- Windows DPAPI Helper Structures & Functions ---

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _win32_dpapi_protect(data: bytes, description: str = "AgentTrace Master Key") -> bytes:
    """Encrypts bytes using Windows DPAPI (tied to current user login).

    FAILS CLOSED: if DPAPI protection fails, an EncryptionError is raised
    rather than silently persisting the master key in plaintext.
    """
    if sys.platform != "win32":
        return data

    try:
        crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        data_in = _DATA_BLOB(
            cbData=len(data),
            pbData=ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte)),
        )
        data_out = _DATA_BLOB()

        desc_p = ctypes.c_wchar_p(description)
        ret = crypt32.CryptProtectData(
            ctypes.byref(data_in),
            desc_p,
            None,
            None,
            None,
            0,  # CRYPTPROTECT_UI_FORBIDDEN
            ctypes.byref(data_out),
        )
        if not ret:
            raise EncryptionError(
                "CryptProtectData failed; refusing to store the master key in plaintext"
            )

        raw_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)
        kernel32.LocalFree(data_out.pbData)
        return raw_bytes
    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"DPAPI Protect error: {e}") from e


def _win32_dpapi_unprotect(data: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI.

    FAILS CLOSED: if the data is not a valid DPAPI blob, an EncryptionError
    is raised. Callers may treat the failure as a legacy-plaintext migration
    case, but the bytes are never silently trusted.
    """
    if sys.platform != "win32":
        return data

    try:
        crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        data_in = _DATA_BLOB(
            cbData=len(data),
            pbData=ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte)),
        )
        data_out = _DATA_BLOB()

        ret = crypt32.CryptUnprotectData(
            ctypes.byref(data_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(data_out),
        )
        if not ret:
            raise EncryptionError("CryptUnprotectData failed: data is not a DPAPI-protected blob")

        raw_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)
        kernel32.LocalFree(data_out.pbData)
        return raw_bytes
    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"DPAPI Unprotect error: {e}") from e


class EncryptionManager:
    """AES-256-GCM encryption for event payloads, sensitive columns, and blobs.

    The master key on disk is DPAPI-protected on Windows.
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
        """Load existing key or generate a new one with OS protection.

        Fail-closed behavior: a present-but-unreadable/corrupt key file raises
        rather than being silently replaced (replacement would orphan all
        previously encrypted data). Legacy plaintext keys written by older
        versions are migrated to DPAPI protection in place.
        """
        key_path = self._key_path()

        if key_path.exists():
            raw_disk_bytes = key_path.read_bytes()
            key = self._try_load_key(key_path, raw_disk_bytes)
            if key is not None:
                return key
            raise EncryptionError(
                f"Master key file {key_path} is present but unreadable/corrupt. "
                "Refusing to overwrite it (existing encrypted data would be lost). "
                "Restore a valid key or remove the file deliberately to start fresh."
            )

        return self._create_key(key_path)

    def _try_load_key(self, key_path: Path, raw: bytes) -> bytes | None:
        """Attempt to load a key from disk, handling current and legacy formats."""
        # 1) Current format: DPAPI-protected (Windows) or raw base64 (POSIX, file-perms protected)
        try:
            unprotected = _win32_dpapi_unprotect(raw)
            try:
                key = base64.b64decode(unprotected)
            except Exception:
                key = unprotected
            if len(key) == _KEY_SIZE:
                return key
        except EncryptionError:
            pass

        # 2) Legacy format: plaintext base64 key written by versions that failed open.
        #    Migrate it to DPAPI protection in place (one-time), then return it.
        try:
            legacy_key = base64.b64decode(raw)
        except Exception:
            legacy_key = b""
        if len(legacy_key) == _KEY_SIZE:
            logger.warning(
                "Legacy plaintext master key detected at %s; migrating to OS-protected storage",
                key_path,
            )
            protected_bytes = _win32_dpapi_protect(legacy_key)
            key_path.write_bytes(protected_bytes)
            self._restrict_permissions(key_path)
            return legacy_key

        return None

    def _create_key(self, key_path: Path) -> bytes:
        """Generate a fresh 256-bit cryptographically secure key with OS protection."""
        key = secrets.token_bytes(_KEY_SIZE)
        encoded_key = base64.b64encode(key)
        protected_bytes = _win32_dpapi_protect(encoded_key)

        key_path.write_bytes(protected_bytes)
        self._restrict_permissions(key_path)

        logger.info("Generated new protected encryption key at: %s", key_path)
        return key

    @staticmethod
    def _restrict_permissions(key_path: Path) -> None:
        """Enforce restrictive file permissions on the key file."""
        try:
            os.chmod(str(key_path), 0o600)
        except OSError:
            pass

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        """Encrypt data using AES-256-GCM.

        Returns: nonce (12 bytes) + ciphertext (including 16-byte authentication tag).
        """
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, data: bytes, associated_data: bytes | None = None) -> bytes:
        """Decrypt AES-256-GCM encrypted data.

        Expects: nonce (12 bytes) + ciphertext + tag.
        """
        if len(data) < _NONCE_SIZE:
            raise EncryptionError("Data too short to contain nonce")

        nonce = data[:_NONCE_SIZE]
        ciphertext = data[_NONCE_SIZE:]

        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise EncryptionError(f"Decryption failed or data tampered: {e}") from e

    def encrypt_str(self, text: str, associated_data: bytes | None = None) -> bytes:
        """Encrypt a UTF-8 string."""
        return self.encrypt(text.encode("utf-8"), associated_data)

    def decrypt_str(self, encrypted: bytes, associated_data: bytes | None = None) -> str:
        """Decrypt to a UTF-8 string."""
        return self.decrypt(encrypted, associated_data).decode("utf-8")

    def encrypt_json(self, data: Any, associated_data: bytes | None = None) -> bytes:
        """Encrypt a JSON-serializable structure."""
        plaintext = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.encrypt(plaintext, associated_data)

    def decrypt_json(self, encrypted: bytes, associated_data: bytes | None = None) -> Any:
        """Decrypt to a JSON structure."""
        plaintext = self.decrypt(encrypted, associated_data)
        return json.loads(plaintext)

    def rotate_key(self) -> bytes:
        """Generate a new key. Returns the old key for data re-encryption."""
        old_key = self._key
        new_key = secrets.token_bytes(_KEY_SIZE)
        encoded_key = base64.b64encode(new_key)
        protected_bytes = _win32_dpapi_protect(encoded_key)

        key_path = self._key_path()
        key_path.write_bytes(protected_bytes)

        self._key = new_key
        self._cipher = AESGCM(self._key)
        logger.info("Master encryption key rotated")
        return old_key
