"""Filesystem observer using watchfiles (Rust-backed, cross-platform).

Watches the workspace for file creates, modifications, and deletions.
Computes content hashes before/after and captures unified diffs.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import logging
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

from watchfiles import Change, awatch

from agenttrace.models.events import ConfidenceLevel, FileMutationEvent
from agenttrace.observers.base import BaseObserver, EventCallback

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Map watchfiles Change enum to our mutation types
_CHANGE_MAP = {
    Change.added: "create",
    Change.modified: "modify",
    Change.deleted: "delete",
}

# Cap on the in-memory text cache used for before/after diffs. Entries are
# ≤100 KB each; without a cap a 10k-file repo can pin ~1 GB of RAM.
_MAX_CONTENT_CACHE = 2048


class FilesystemObserver(BaseObserver):
    """Watches workspace files for mutations.

    Uses watchfiles (Rust-backed) for efficient cross-platform file
    watching. Builds an initial cache before monitoring starts.
    """

    def __init__(
        self,
        session_id: UUID,
        workspace_path: str,
        callback: EventCallback,
        ignore_patterns: list[str] | None = None,
    ) -> None:
        super().__init__(session_id, workspace_path, callback)
        self._ignore_patterns = ignore_patterns or [
            ".git/objects/**",
            ".git/index",
            ".git/logs/**",
            ".git/refs/**",
            "node_modules/**",
            "__pycache__/**",
            "*.pyc",
            ".venv/**",
            "venv/**",
        ]
        self._stop_event = asyncio.Event()
        # Cache of file content hashes for before/after comparison
        self._hash_cache: dict[str, str] = {}
        # In-memory text cache for bounded diff generation
        self._content_cache: dict[str, str] = {}

    def _should_ignore(self, path: str) -> bool:
        """Check if a file path matches any ignore pattern."""
        try:
            rel_path = str(Path(path).relative_to(self.workspace_path)).replace("\\", "/")
            return any(
                fnmatch(rel_path, pat) or fnmatch(Path(path).name, pat)
                for pat in self._ignore_patterns
            )
        except Exception:
            return False

    def _cache_content(self, path: str, content: str) -> None:
        """Store a file text in the bounded diff cache, evicting oldest."""
        if len(self._content_cache) >= _MAX_CONTENT_CACHE:
            self._content_cache.pop(next(iter(self._content_cache)))
        self._content_cache[path] = content

    @staticmethod
    def _compute_file_hash(path: str) -> str:
        """Compute SHA-256 hash of file contents."""
        try:
            data = Path(path).read_bytes()
            return hashlib.sha256(data).hexdigest()
        except (OSError, PermissionError):
            return ""

    def _read_file_text(self, path: str) -> str:
        """Safely read text file for diff generation (max 100KB)."""
        try:
            p = Path(path)
            if p.is_file() and p.stat().st_size < 100_000:
                return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return ""

    async def build_initial_cache(self) -> None:
        """Build initial hash cache by scanning the workspace."""
        workspace = Path(self.workspace_path)
        count = 0
        try:
            for file_path in workspace.rglob("*"):
                if file_path.is_file():
                    path_str = str(file_path)
                    if not self._should_ignore(path_str):
                        file_hash = self._compute_file_hash(path_str)
                        if file_hash:
                            self._hash_cache[path_str] = file_hash
                            self._cache_content(path_str, self._read_file_text(path_str))
                            count += 1
        except Exception as e:
            logger.warning("Error building initial filesystem cache: %s", e)
        logger.info("Initial filesystem cache built: %d files hashed", count)

    async def _run(self) -> None:
        """Watch the workspace for file changes."""
        logger.info("Watching filesystem: %s", self.workspace_path)

        # Build initial cache first so the very first edit has a valid before_hash
        await self.build_initial_cache()

        try:
            async for changes in awatch(
                self.workspace_path,
                stop_event=self._stop_event,
            ):
                if not self._running:
                    break

                for change_type, path_str in changes:
                    if self._should_ignore(path_str):
                        continue

                    mutation_type = _CHANGE_MAP.get(change_type, "modify")
                    before_hash = self._hash_cache.get(path_str, "")
                    before_content = self._content_cache.get(path_str, "")
                    after_hash = ""
                    after_content = ""
                    diff_summary = ""

                    if mutation_type != "delete":
                        after_hash = self._compute_file_hash(path_str)
                        after_content = self._read_file_text(path_str)
                        self._hash_cache[path_str] = after_hash
                        self._cache_content(path_str, after_content)

                        if before_content and after_content:
                            diff_lines = list(
                                difflib.unified_diff(
                                    before_content.splitlines(),
                                    after_content.splitlines(),
                                    fromfile="before",
                                    tofile="after",
                                    lineterm="",
                                )
                            )
                            diff_summary = "\n".join(diff_lines[:30])
                    else:
                        self._hash_cache.pop(path_str, None)
                        self._content_cache.pop(path_str, None)

                    # Skip if file content didn't actually change
                    if mutation_type == "modify" and before_hash and before_hash == after_hash:
                        continue

                    event = FileMutationEvent(
                        session_id=self.session_id,
                        actor_id="filesystem",
                        source_adapter="filesystem_observer",
                        confidence=ConfidenceLevel.HIGH,
                        file_path=path_str,
                        mutation_type=mutation_type,
                        before_hash=before_hash,
                        after_hash=after_hash,
                        diff_summary=diff_summary,
                    )
                    await self.emit(event)

        except asyncio.CancelledError:
            logger.debug("FilesystemObserver cancelled")
        except Exception:
            logger.exception("FilesystemObserver error")

    def snapshot_hashes(self) -> dict[str, str]:
        """Return current file hash cache for baseline generation."""
        return dict(self._hash_cache)

    def seed_hashes(self, hashes: dict[str, str]) -> None:
        """Seed the hash cache from the baseline graph's SOURCE_FILE nodes.

        Reconciles the two independently-computed hash sources (baseline
        generator and this observer) so the first watchfiles mutation has a
        real ``before_hash`` instead of an empty string. Existing entries are
        never overwritten.
        """
        for path, content_hash in hashes.items():
            if path and content_hash and path not in self._hash_cache:
                self._hash_cache[path] = content_hash

    async def stop(self) -> None:
        """Stop the filesystem watcher gracefully."""
        self._stop_event.set()
        await super().stop()
