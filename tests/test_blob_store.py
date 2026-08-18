"""Tests for the encrypted blob store — round-trip, dedup, rotation."""

from pathlib import Path

import pytest

from agenttrace.security.encryption import EncryptionManager
from agenttrace.storage.blob_store import BlobStore, BlobStoreError


class TestBlobStore:
    def test_store_and_retrieve_round_trip(self, tmp_path: Path) -> None:
        store = BlobStore(tmp_path / "blobs", EncryptionManager(tmp_path / "keys"))
        data = b"terminal capture payload \x00\x01\x02 binary"
        blob_hash = store.store_blob(data)
        assert store.retrieve_blob(blob_hash) == data

    def test_path_for_matches_on_disk_layout(self, tmp_path: Path) -> None:
        """Indexed paths must resolve to the actual file (shard/full-hash)."""
        store = BlobStore(tmp_path / "blobs", EncryptionManager(tmp_path / "keys"))
        data = b"indexed blob content"
        blob_hash = store.store_blob(data)
        indexed_path = store.path_for(blob_hash)
        assert indexed_path.exists()
        assert indexed_path.parent.name == blob_hash[:2]
        assert indexed_path.name == blob_hash
        assert store.retrieve_blob(blob_hash) == data

    def test_dedup_by_plaintext_hash(self, tmp_path: Path) -> None:
        store = BlobStore(tmp_path / "blobs", EncryptionManager(tmp_path / "keys"))
        h1 = store.store_blob(b"same content")
        h2 = store.store_blob(b"same content")
        assert h1 == h2
        assert len(store.list_blobs()) == 1

    def test_missing_blob_raises(self, tmp_path: Path) -> None:
        store = BlobStore(tmp_path / "blobs", EncryptionManager(tmp_path / "keys"))
        with pytest.raises(BlobStoreError):
            store.retrieve_blob("a" * 64)

    def test_reencrypt_all_preserves_content(self, tmp_path: Path) -> None:
        mgr = EncryptionManager(tmp_path / "keys")
        store = BlobStore(tmp_path / "blobs", mgr)
        data = b"captured file snapshot"
        blob_hash = store.store_blob(data)

        new_key = mgr.prepare_rotation()
        store.reencrypt_all(new_key)
        mgr.commit_rotation(new_key)

        assert store.retrieve_blob(blob_hash) == data

    def test_gc_orphans(self, tmp_path: Path) -> None:
        store = BlobStore(tmp_path / "blobs", EncryptionManager(tmp_path / "keys"))
        h1 = store.store_blob(b"keep")
        h2 = store.store_blob(b"drop")
        removed = store.gc_orphans({h1})
        assert removed == 1
        assert store.exists(h1)
        assert not store.exists(h2)
