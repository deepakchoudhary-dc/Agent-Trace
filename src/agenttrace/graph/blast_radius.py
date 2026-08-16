"""Blast radius analysis — forward impact from a code change.

Traces a code change through import/API/dependency relationships
to find all potentially affected downstream components: tests,
builds, configs, and runtime dependencies.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agenttrace.models.graph import BlastRadiusResult, EdgeType, GraphNode, NodeType

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.graph.context_graph import ContextGraph

logger = logging.getLogger(__name__)

# Edge types that propagate impact forward
_IMPACT_EDGES = {
    EdgeType.MODIFIES,
    EdgeType.CAUSES,
    EdgeType.INTRODUCES,
    EdgeType.READS,
    EdgeType.VALIDATES,
    EdgeType.VIOLATES,
}


class BlastRadiusAnalyzer:
    """Analyzes the forward impact of a code change.

    Starting from a filesystem mutation or code change node, traverses
    the graph forward to find all affected components.
    """

    def __init__(self, graph: ContextGraph) -> None:
        self.graph = graph

    def analyze(
        self,
        origin_node_id: UUID,
        max_depth: int = 8,
    ) -> BlastRadiusResult:
        """Compute blast radius from a given change node."""
        result = BlastRadiusResult(origin_node_id=origin_node_id)

        # Get all descendants through impact edges
        affected = self._forward_traverse(origin_node_id, max_depth)

        for node_id in affected:
            result.affected_nodes.append(node_id)
            node = self.graph.get_node(node_id)
            if not node:
                continue

            # Categorize by node type
            if node.node_type == NodeType.SOURCE_FILE:
                path = node.data.get("relative_path", node.label)
                if path not in result.affected_files:
                    result.affected_files.append(path)

            elif node.node_type == NodeType.TEST_RESULT:
                test_name = node.label or node.data.get("test_suite", "unknown")
                if node.data.get("failed", False):
                    result.failed_tests.append(test_name)

            elif node.node_type in (NodeType.PACKAGE_CHANGE, NodeType.CONFIG_CHANGE):
                name = node.label or "unknown"
                result.config_changes.append(name)

        # Files that import the changed file are broken when it is deleted
        file_node = self._origin_file_node(origin_node_id)
        if file_node:
            for edge in self.graph.get_edges_to(file_node.node_id):
                if edge.edge_type != EdgeType.READS:
                    continue
                importer = self.graph.get_node(edge.source_node_id)
                if importer and importer.node_type == NodeType.SOURCE_FILE:
                    path = (
                        importer.data.get("relative_path")
                        or importer.data.get("path")
                        or importer.label
                    )
                    if path not in result.broken_imports:
                        result.broken_imports.append(path)

        # Calculate risk score based on breadth and depth of impact
        result.risk_score = self._calculate_risk(result)
        return result

    def _origin_file_node(self, origin_node_id: UUID) -> GraphNode | None:
        """Resolve the origin to a SOURCE_FILE node (directly or via MODIFIES)."""
        origin = self.graph.get_node(origin_node_id)
        if not origin:
            return None
        if origin.node_type == NodeType.SOURCE_FILE:
            return origin
        for edge in self.graph.get_edges_from(origin_node_id):
            if edge.edge_type == EdgeType.MODIFIES:
                target = self.graph.get_node(edge.target_node_id)
                if target and target.node_type == NodeType.SOURCE_FILE:
                    return target
        return None

    def _forward_traverse(
        self,
        start_id: UUID,
        max_depth: int,
    ) -> set[UUID]:
        """BFS forward traversal through impact edges."""
        visited: set[UUID] = set()
        frontier = {start_id}

        for _depth in range(max_depth):
            next_frontier: set[UUID] = set()
            for node_id in frontier:
                if node_id in visited:
                    continue
                visited.add(node_id)

                # Follow outgoing impact edges
                for edge in self.graph.get_edges_from(node_id):
                    if edge.edge_type in _IMPACT_EDGES:
                        next_frontier.add(edge.target_node_id)

                # Also follow reverse READS edges (files that import this one)
                for edge in self.graph.get_edges_to(node_id):
                    if edge.edge_type == EdgeType.READS:
                        next_frontier.add(edge.source_node_id)

            frontier = next_frontier - visited
            if not frontier:
                break

        # Nodes discovered at the final depth were never expanded — include them
        visited.update(frontier)

        visited.discard(start_id)
        return visited

    @staticmethod
    def _calculate_risk(result: BlastRadiusResult) -> float:
        """Calculate a 0-1 risk score for the blast radius."""
        score = 0.0

        # Number of affected files contributes to risk
        file_count = len(result.affected_files)
        score += min(file_count * 0.05, 0.3)

        # Failed tests significantly increase risk
        failed_count = len(result.failed_tests)
        score += min(failed_count * 0.15, 0.4)

        # Config changes add moderate risk
        config_count = len(result.config_changes)
        score += min(config_count * 0.1, 0.2)

        # Broken imports
        import_count = len(result.broken_imports)
        score += min(import_count * 0.1, 0.1)

        return min(score, 1.0)

    def find_affected_tests(self, file_node_id: UUID) -> list[GraphNode]:
        """Find test nodes that validate the given file."""
        affected: list[GraphNode] = []

        # Look for VALIDATES edges pointing to this file
        for edge in self.graph.get_edges_to(file_node_id):
            if edge.edge_type == EdgeType.VALIDATES:
                node = self.graph.get_node(edge.source_node_id)
                if node and node.node_type == NodeType.TEST_RESULT:
                    affected.append(node)

        # Also check impact-edge descendants for test results (bounded BFS,
        # never the full transitive closure over every edge type)
        for desc_id in self._forward_traverse(file_node_id, max_depth=8):
            node = self.graph.get_node(desc_id)
            if node and node.node_type == NodeType.TEST_RESULT:
                affected.append(node)

        return affected
