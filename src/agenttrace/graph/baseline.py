"""Baseline generator — creates the initial Context Graph snapshot.

When a session opens, this module scans the workspace to build the
starting graph: repo structure, git status, dependency manifests,
build config, import relationships, and content-hash snapshots.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.events import ConfidenceLevel
from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

# Files that indicate project structure
_MANIFEST_FILES = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
]

_BUILD_CONFIG_FILES = [
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".github/workflows/*.yml",
    "Jenkinsfile",
    "tsconfig.json",
    "webpack.config.js",
    "vite.config.ts",
    "vite.config.js",
    "next.config.js",
    "next.config.mjs",
    ".eslintrc.json",
    "ruff.toml",
    "mypy.ini",
    "pytest.ini",
]

# Extensions to include in import scanning
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
    ".java", ".kt", ".cs", ".rb", ".php",
}


class BaselineGenerator:
    """Creates the initial Context Graph when a session starts.

    Scans the workspace to establish the baseline state — everything
    that existed before agents started working.
    """

    def __init__(self, session_id: UUID, workspace_path: str) -> None:
        self.session_id = session_id
        self.workspace_path = Path(workspace_path)

    def generate(self) -> ContextGraph:
        """Build the full baseline Context Graph."""
        graph = ContextGraph(self.session_id)

        # Create workspace snapshot root node
        ws_node = GraphNode(
            node_type=NodeType.WORKSPACE_SNAPSHOT,
            label=str(self.workspace_path),
            actor_id="baseline",
            source_adapter="baseline_generator",
            confidence=ConfidenceLevel.HIGH,
            session_id=self.session_id,
            data={"path": str(self.workspace_path)},
        )
        graph.add_node(ws_node)

        # Scan repository structure
        self._add_repo_tree(graph, ws_node.node_id)

        # Scan git status
        self._add_git_status(graph, ws_node.node_id)

        # Scan dependency manifests
        self._add_manifests(graph, ws_node.node_id)

        # Scan build/test config
        self._add_build_config(graph, ws_node.node_id)

        # Scan code import relationships
        self._add_import_graph(graph, ws_node.node_id)

        logger.info(
            "Baseline generated: %d nodes, %d edges",
            graph.node_count,
            graph.edge_count,
        )
        return graph

    def _add_repo_tree(self, graph: ContextGraph, parent_id: UUID) -> None:
        """Add source file nodes for the repository tree."""
        ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}

        for file_path in self.workspace_path.rglob("*"):
            # Skip ignored directories
            if any(part in ignore_dirs for part in file_path.parts):
                continue
            if not file_path.is_file():
                continue

            # Compute content hash
            try:
                content_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            except (OSError, PermissionError):
                content_hash = ""

            rel_path = str(file_path.relative_to(self.workspace_path))
            file_node = GraphNode(
                node_type=NodeType.SOURCE_FILE,
                label=rel_path,
                actor_id="baseline",
                source_adapter="baseline_generator",
                confidence=ConfidenceLevel.HIGH,
                content_hash=content_hash,
                session_id=self.session_id,
                data={
                    "path": str(file_path),
                    "relative_path": rel_path,
                    "extension": file_path.suffix,
                    "size_bytes": file_path.stat().st_size,
                },
            )
            graph.add_node(file_node)

            # Connect to workspace
            edge = GraphEdge(
                source_node_id=parent_id,
                target_node_id=file_node.node_id,
                edge_type=EdgeType.READS,
                actor_id="baseline",
                source_adapter="baseline_generator",
                confidence=ConfidenceLevel.HIGH,
            )
            graph.add_edge(edge)

    def _add_git_status(self, graph: ContextGraph, parent_id: UUID) -> None:
        """Add Git status information to the graph."""
        try:
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.workspace_path),
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()

            branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(self.workspace_path),
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()

            if head:
                git_node = GraphNode(
                    node_type=NodeType.GIT_COMMIT_DIFF,
                    label=f"HEAD: {branch} ({head[:8]})",
                    actor_id="baseline",
                    source_adapter="baseline_generator",
                    confidence=ConfidenceLevel.HIGH,
                    content_hash=head,
                    session_id=self.session_id,
                    data={"branch": branch, "commit": head},
                )
                graph.add_node(git_node)
                graph.add_edge(GraphEdge(
                    source_node_id=parent_id,
                    target_node_id=git_node.node_id,
                    edge_type=EdgeType.READS,
                    actor_id="baseline",
                    source_adapter="baseline_generator",
                ))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("Git not available for baseline")

    def _add_manifests(self, graph: ContextGraph, parent_id: UUID) -> None:
        """Add dependency manifest nodes."""
        for manifest_name in _MANIFEST_FILES:
            manifest_path = self.workspace_path / manifest_name
            if manifest_path.exists():
                try:
                    content_hash = hashlib.sha256(
                        manifest_path.read_bytes()
                    ).hexdigest()
                except OSError:
                    content_hash = ""

                node = GraphNode(
                    node_type=NodeType.CONTEXTUAL_DOCUMENT,
                    label=manifest_name,
                    actor_id="baseline",
                    source_adapter="baseline_generator",
                    confidence=ConfidenceLevel.HIGH,
                    content_hash=content_hash,
                    session_id=self.session_id,
                    data={
                        "path": str(manifest_path),
                        "type": "dependency_manifest",
                    },
                )
                graph.add_node(node)
                graph.add_edge(GraphEdge(
                    source_node_id=parent_id,
                    target_node_id=node.node_id,
                    edge_type=EdgeType.READS,
                    actor_id="baseline",
                    source_adapter="baseline_generator",
                ))

    def _add_build_config(self, graph: ContextGraph, parent_id: UUID) -> None:
        """Add build/test configuration nodes."""
        for config_name in _BUILD_CONFIG_FILES:
            if "*" in config_name:
                # Glob pattern
                for match in self.workspace_path.glob(config_name):
                    self._add_config_node(graph, parent_id, match)
            else:
                config_path = self.workspace_path / config_name
                if config_path.exists():
                    self._add_config_node(graph, parent_id, config_path)

    def _add_config_node(
        self, graph: ContextGraph, parent_id: UUID, config_path: Path
    ) -> None:
        """Add a single config file node."""
        rel_path = str(config_path.relative_to(self.workspace_path))
        node = GraphNode(
            node_type=NodeType.CONTEXTUAL_DOCUMENT,
            label=rel_path,
            actor_id="baseline",
            source_adapter="baseline_generator",
            confidence=ConfidenceLevel.HIGH,
            session_id=self.session_id,
            data={
                "path": str(config_path),
                "type": "build_config",
            },
        )
        graph.add_node(node)
        graph.add_edge(GraphEdge(
            source_node_id=parent_id,
            target_node_id=node.node_id,
            edge_type=EdgeType.READS,
            actor_id="baseline",
            source_adapter="baseline_generator",
        ))

    def _add_import_graph(self, graph: ContextGraph, parent_id: UUID) -> None:
        """Add import/dependency relationships between source files.

        This is a lightweight scan — it parses import statements without
        full AST analysis to keep baseline generation fast.
        """
        source_files = [
            n for n in graph.get_nodes_by_type(NodeType.SOURCE_FILE)
            if n.data.get("extension") in _CODE_EXTENSIONS
        ]

        # Build a lookup from relative path to node
        path_to_node: dict[str, GraphNode] = {}
        for node in source_files:
            rel = node.data.get("relative_path", "")
            if rel:
                path_to_node[rel] = node
                # Also add without extension for import resolution
                stem = str(Path(rel).with_suffix(""))
                path_to_node[stem] = node

        for node in source_files:
            file_path = Path(node.data.get("path", ""))
            if not file_path.exists():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            ext = node.data.get("extension", "")
            imports = self._extract_imports(content, ext)

            for imp in imports:
                # Try to resolve import to a file in the project
                target = path_to_node.get(imp) or path_to_node.get(
                    imp.replace(".", "/")
                )
                if target and target.node_id != node.node_id:
                    graph.add_edge(GraphEdge(
                        source_node_id=node.node_id,
                        target_node_id=target.node_id,
                        edge_type=EdgeType.READS,
                        actor_id="baseline",
                        source_adapter="baseline_generator",
                        confidence=ConfidenceLevel.LOW,
                        data={"import_path": imp},
                    ))

    @staticmethod
    def _extract_imports(content: str, extension: str) -> list[str]:
        """Extract import paths from source code (lightweight parsing)."""
        imports: list[str] = []

        for line in content.split("\n"):
            line = line.strip()

            if extension == ".py":
                if line.startswith("import "):
                    module = line[7:].split(" as ")[0].split(",")[0].strip()
                    imports.append(module)
                elif line.startswith("from "):
                    parts = line.split(" import ")
                    if parts:
                        module = parts[0][5:].strip()
                        imports.append(module)

            elif extension in (".js", ".ts", ".tsx", ".jsx"):
                if "import " in line and " from " in line:
                    # import X from 'path'
                    parts = line.split(" from ")
                    if len(parts) > 1:
                        path = parts[-1].strip().strip("'\"`;")
                        if path.startswith("."):
                            imports.append(path)
                elif line.startswith("require("):
                    # require('path')
                    start = line.find("(") + 1
                    end = line.find(")")
                    if start > 0 and end > start:
                        path = line[start:end].strip("'\"")
                        if path.startswith("."):
                            imports.append(path)

        return imports
