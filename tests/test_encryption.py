"""Tests for AES-256-GCM encryption and DPAPI key management."""

from pathlib import Path

import pytest

from agenttrace.security.encryption import EncryptionError, EncryptionManager


@pytest.fixture
def enc_mgr(tmp_path: Path) -> EncryptionManager:
    return EncryptionManager(tmp_path / "keys")


class TestEncryptionManager:
    """Tests for EncryptionManager."""

    def test_encrypt_decrypt_str(self, enc_mgr: EncryptionManager) -> None:
        plaintext = "Hello, AgentTrace forensic audit!"
        ciphertext = enc_mgr.encrypt_str(plaintext)
        assert ciphertext != plaintext.encode()

        decrypted = enc_mgr.decrypt_str(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_json(self, enc_mgr: EncryptionManager) -> None:
        data = {
            "session_id": "12345",
            "actor": "claude",
            "nested": {"allowed": True, "count": 42},
        }
        ciphertext = enc_mgr.encrypt_json(data)
        assert isinstance(ciphertext, bytes)

        decrypted = enc_mgr.decrypt_json(ciphertext)
        assert decrypted == data

    def test_tamper_detection(self, enc_mgr: EncryptionManager) -> None:
        """Modifying ciphertext bytes causes AES-GCM tag verification failure."""
        ciphertext = bytearray(enc_mgr.encrypt_str("Secret data"))
        # Flip a bit in ciphertext
        ciphertext[-1] ^= 0xFF

        with pytest.raises(EncryptionError):
            enc_mgr.decrypt_str(bytes(ciphertext))

    def test_key_rotation(self, enc_mgr: EncryptionManager) -> None:
        old_key = enc_mgr._key
        ciphertext = enc_mgr.encrypt_str("Payload before rotation")

        new_key = enc_mgr.prepare_rotation()
        assert new_key != old_key
        # prepare_rotation() must have no side effects
        assert enc_mgr._key == old_key

        enc_mgr.commit_rotation(new_key)
        assert enc_mgr._key == new_key
        # Data encrypted under the old key still decrypts (retired-key chain)
        assert enc_mgr.decrypt_str(ciphertext) == "Payload before rotation"

        # Re-initialize manager with same key dir to verify persistence
        new_mgr = EncryptionManager(enc_mgr._key_dir)
        assert new_mgr._key == new_key
        # Retired key survives restarts via master.key.old
        assert new_mgr.decrypt_str(ciphertext) == "Payload before rotation"

    def test_retired_key_survives_reload(self, enc_mgr: EncryptionManager) -> None:
        """After a crash mid-rotation, data written pre-rotation still decrypts."""
        ciphertext = enc_mgr.encrypt_str("pre-rotation secret")
        new_key = enc_mgr.prepare_rotation()
        enc_mgr.commit_rotation(new_key)

        fresh = EncryptionManager(enc_mgr._key_dir)
        assert fresh.decrypt_str(ciphertext) == "pre-rotation secret"

    def test_blob_store_encryption_at_rest(
        self, enc_mgr: EncryptionManager, tmp_path: Path
    ) -> None:
        """Large payload blobs are AES-256-GCM encrypted on disk, not plaintext."""
        from agenttrace.storage.blob_store import BlobStore

        store = BlobStore(tmp_path / "blobs", encryption_mgr=enc_mgr)
        secret = b"terminal output containing DB_PASSWORD_xyz payload"

        blob_hash = store.store_blob(secret)
        blob_file = tmp_path / "blobs" / blob_hash[:2] / blob_hash

        raw = blob_file.read_bytes()
        assert secret not in raw
        assert store.retrieve_blob(blob_hash) == secret

    def test_blob_store_plaintext_fallback(self, tmp_path: Path) -> None:
        """Legacy callers without an EncryptionManager keep plaintext behavior."""
        from agenttrace.storage.blob_store import BlobStore

        store = BlobStore(tmp_path / "blobs")
        blob_hash = store.store_blob(b"legacy-payload")
        assert store.retrieve_blob(blob_hash) == b"legacy-payload"
