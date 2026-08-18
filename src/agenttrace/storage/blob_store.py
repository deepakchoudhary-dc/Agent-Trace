"""Content-addressed encrypted blob store for large captures.

Blobs are stored as individual AES-256-GCM encrypted files addressed by the
SHA-256 hash of their *plaintext* content (for deduplication). This handles
file snapshots, terminal output dumps, and other large payloads that don't
belong in the SQLite ledger.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agenttrace.security.encryption import EncryptionManager


class BlobStoreError(Exception):
    """Raised when blob operations fail."""


class BlobStore:
    """Content-addressed file store with at-rest encryption.

    Files are stored in a flat directory named by their plaintext content
    hash. The bytes written to disk are AES-256-GCM ciphertext; retrieval
    transparently decrypts. If no EncryptionManager is supplied (legacy
    callers), blobs fall back to plaintext.
    """

    def __init__(
        self,
        store_dir: str | Path,
        encryption_mgr: EncryptionManager | None = None,
    ) -> None:
        self._store_dir = Path(store_dir)
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._encryption = encryption_mgr

    @staticmethod
    def compute_hash(data: bytes) -> str:
        """Compute SHA-256 hash of raw data."""
        return hashlib.sha256(data).hexdigest()

    def _blob_path(self, content_hash: str) -> Path:
        """Get the filesystem path for a blob.

        Uses two-level directory sharding to avoid filesystem limits:
        ab/cdef1234... → store_dir/ab/cdef1234...
        """
        prefix = content_hash[:2]
        shard_dir = self._store_dir / prefix
        shard_dir.mkdir(exist_ok=True)
        return shard_dir / content_hash

    def path_for(self, content_hash: str) -> Path:
        """Public canonical path for a content hash.

        Callers that index blob locations (e.g. the ledger blob index) must
        use this method so the indexed path matches the on-disk layout
        (``<store_dir>/<2-char shard>/<full hash>``).
        """
        return self._blob_path(content_hash)

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt blob bytes for at-rest storage (no-op without a manager)."""
        if self._encryption is None:
            return data
        return self._encryption.encrypt(data)

    def _decrypt(self, payload: bytes) -> bytes:
        """Decrypt blob bytes read from disk."""
        if self._encryption is None:
            return payload
        return self._encryption.decrypt(payload)

    def store_blob(self, data: bytes) -> str:
        """Store a blob, returning its plaintext content hash.

        If the blob already exists (same hash), this is a no-op.
        """
        content_hash = self.compute_hash(data)
        blob_path = self._blob_path(content_hash)

        if blob_path.exists():
            return content_hash

        # Write atomically: temp file then rename
        tmp_path = blob_path.with_suffix(".tmp")
        try:
            tmp_path.write_bytes(self._encrypt(data))
            tmp_path.rename(blob_path)
        except OSError:
            # On Windows, rename can fail if target exists (race condition)
            if blob_path.exists():
                tmp_path.unlink(missing_ok=True)
            else:
                raise

        return content_hash

    def retrieve_blob(self, content_hash: str) -> bytes:
        """Retrieve and decrypt a blob by its content hash."""
        blob_path = self._blob_path(content_hash)
        if not blob_path.exists():
            raise BlobStoreError(f"Blob not found: {content_hash}")
        return self._decrypt(blob_path.read_bytes())

    def exists(self, content_hash: str) -> bool:
        """Check if a blob exists."""
        return self._blob_path(content_hash).exists()

    def delete_blob(self, content_hash: str) -> bool:
        """Delete a blob. Returns True if it existed."""
        blob_path = self._blob_path(content_hash)
        if blob_path.exists():
            blob_path.unlink()
            return True
        return False

    def list_blobs(self) -> list[str]:
        """List all blob content hashes in the store."""
        hashes: list[str] = []
        for shard_dir in self._store_dir.iterdir():
            if shard_dir.is_dir() and len(shard_dir.name) == 2:
                for blob_file in shard_dir.iterdir():
                    if blob_file.is_file() and not blob_file.suffix:
                        hashes.append(blob_file.name)
        return hashes

    def total_size_bytes(self) -> int:
        """Calculate total size of all stored blobs."""
        total = 0
        for shard_dir in self._store_dir.iterdir():
            if shard_dir.is_dir() and len(shard_dir.name) == 2:
                for blob_file in shard_dir.iterdir():
                    if blob_file.is_file() and not blob_file.suffix:
                        total += blob_file.stat().st_size
        return total

    def gc_orphans(self, referenced_hashes: set[str]) -> int:
        """Remove blobs not in the referenced set.

        Returns the number of blobs removed.
        """
        removed = 0
        for content_hash in self.list_blobs():
            if content_hash not in referenced_hashes:
                self.delete_blob(content_hash)
                removed += 1
        return removed

    def reencrypt_all(self, new_key: bytes) -> None:
        """Re-encrypt every blob with a new master key.

        Part of key rotation: decrypts with the current key and re-encrypts
        in place (temp file + atomic rename per blob, as in store_blob).
        No-ops without an EncryptionManager.
        """
        if self._encryption is None:
            return
        for content_hash in self.list_blobs():
            blob_path = self._blob_path(content_hash)
            plaintext = self._encryption.decrypt(blob_path.read_bytes())
            new_cipher = self._encryption.encrypt_with(new_key, plaintext)
            tmp_path = blob_path.with_suffix(".tmp")
            tmp_path.write_bytes(new_cipher)
            os.replace(tmp_path, blob_path)
