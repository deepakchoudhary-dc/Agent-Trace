"""Filesystem observer using watchfiles (Rust-backed, cross-platform).

Watches the workspace for file creates, modifications, and deletions.
Computes content hashes before/after for diff tracking.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from fnmatch import fnmatch
from pathlib import Path
from uuid import UUID

from watchfiles import Change, awatch

from agenttrace.models.events import ConfidenceLevel, FileMutationEvent
from agenttrace.observers.base import BaseObserver, EventCallback

logger = logging.getLogger(__name__)

# Map watchfiles Change enum to our mutation types
_CHANGE_MAP = {
    Change.added: "create",
    Change.modified: "modify",
    Change.deleted: "delete",
}


class FilesystemObserver(BaseObserver):
    """Watches workspace files for mutations.

    Uses watchfiles (Rust-backed) for efficient cross-platform file
    watching. Filters out ignored patterns (e.g., .git, node_modules).
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
            ".git/**",
            "node_modules/**",
            "__pycache__/**",
            "*.pyc",
            ".venv/**",
            "venv/**",
        ]
        # Cache of file content hashes for before/after comparison
        self._hash_cache: dict[str, str] = {}

    def _should_ignore(self, path: str) -> bool:
        """Check if a file path matches any ignore pattern."""
        rel_path = str(Path(path).relative_to(self.workspace_path))
        return any(fnmatch(rel_path, pat) for pat in self._ignore_patterns)

    @staticmethod
    def _compute_file_hash(path: str) -> str:
        """Compute SHA-256 hash of file contents."""
        try:
            data = Path(path).read_bytes()
            return hashlib.sha256(data).hexdigest()
        except (OSError, PermissionError):
            return ""

    async def _run(self) -> None:
        """Watch the workspace for file changes."""
        logger.info("Watching filesystem: %s", self.workspace_path)

        try:
            async for changes in awatch(
                self.workspace_path,
                stop_event=asyncio.Event(),  # We control via self._running
            ):
                if not self._running:
                    break

                for change_type, path_str in changes:
                    if self._should_ignore(path_str):
                        continue

                    mutation_type = _CHANGE_MAP.get(change_type, "modify")
                    before_hash = self._hash_cache.get(path_str, "")
                    after_hash = ""

                    if mutation_type != "delete":
                        after_hash = self._compute_file_hash(path_str)
                        self._hash_cache[path_str] = after_hash
                    else:
                        self._hash_cache.pop(path_str, None)

                    # Skip if file content didn't actually change
                    if mutation_type == "modify" and before_hash == after_hash:
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
                    )
                    await self.emit(event)

        except asyncio.CancelledError:
            logger.debug("FilesystemObserver cancelled")
        except Exception:
            logger.exception("FilesystemObserver error")

    def snapshot_hashes(self) -> dict[str, str]:
        """Return current file hash cache for baseline generation."""
        return dict(self._hash_cache)

    async def build_initial_cache(self) -> None:
        """Build initial hash cache by scanning the workspace."""
        workspace = Path(self.workspace_path)
        for file_path in workspace.rglob("*"):
            if file_path.is_file():
                path_str = str(file_path)
                if not self._should_ignore(path_str):
                    file_hash = self._compute_file_hash(path_str)
                    if file_hash:
                        self._hash_cache[path_str] = file_hash
        logger.info("Initial cache built: %d files", len(self._hash_cache))
