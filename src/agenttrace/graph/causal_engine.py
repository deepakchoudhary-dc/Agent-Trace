"""Causal explanation engine — backward graph traversal for root-cause analysis.

Given a suspicious action or incident, traverses backward through the
Context Graph to build ranked evidence paths explaining what led to it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from agenttrace.models.events import ConfidenceLevel
from agenttrace.models.graph import EdgeType, EvidencePath, GraphNode, NodeType

if TYPE_CHECKING:
    from uuid import UUID

    from agenttrace.graph.context_graph import ContextGraph

logger = logging.getLogger(__name__)

# Hard budget on total node expansions per explain() call — protects against
# path explosion in dense graphs (a naive DFS can enumerate 10^N paths).
_MAX_EXPLORED_NODES = 2000

# Edge types that indicate causal flow (backward traversal follows these)
_CAUSAL_EDGES = {
    EdgeType.CAUSES,
    EdgeType.EXECUTES,
    EdgeType.SPAWNS,
    EdgeType.MODIFIES,
    EdgeType.REQUESTS,
    EdgeType.PROVIDES_CONTEXT_TO,
    EdgeType.INTRODUCES,
}

# Node types that are potential root causes
_ROOT_CAUSE_TYPES = {
    NodeType.TASK_INTENT,
    NodeType.UNTRUSTED_CONTENT,
    NodeType.CONTEXTUAL_DOCUMENT,
    NodeType.AGENT_SESSION,
}

# Confidence weights for edge types
_EDGE_CONFIDENCE_WEIGHT: dict[EdgeType, float] = {
    EdgeType.CAUSES: 0.95,
    EdgeType.EXECUTES: 0.9,
    EdgeType.MODIFIES: 0.85,
    EdgeType.SPAWNS: 0.8,
    EdgeType.REQUESTS: 0.75,
    EdgeType.PROVIDES_CONTEXT_TO: 0.6,
    EdgeType.INTRODUCES: 0.7,
    EdgeType.INFERRED_FROM: 0.4,
    EdgeType.READS: 0.3,
    EdgeType.VALIDATES: 0.5,
    EdgeType.VIOLATES: 0.9,
    EdgeType.APPROVED_BY: 0.5,
}


class CausalExplanationEngine:
    """Performs backward traversal from suspicious actions to root causes.

    Returns ranked evidence paths — each path is a chain of nodes and
    edges from the suspicious action back to an origin. Paths are
    ranked by overall confidence (product of edge confidences along
    the path).
    """

    def __init__(self, graph: ContextGraph) -> None:
        self.graph = graph

    def explain(
        self,
        target_node_id: UUID,
        max_depth: int = 10,
        max_paths: int = 5,
    ) -> list[EvidencePath]:
        """Find and rank causal evidence paths to a target node.

        Performs backward BFS/DFS from the target, collecting all paths
        that reach a root-cause node type or the maximum depth. The search
        is bounded by a node-expansion budget and by `max_paths` so dense
        graphs cannot trigger exponential path enumeration.
        """
        target = self.graph.get_node(target_node_id)
        if not target:
            logger.warning("Target node %s not found", target_node_id)
            return []

        state: dict[str, Any] = {
            "paths": [],
            "budget": _MAX_EXPLORED_NODES,
            "max_paths": max_paths,
        }
        self._traverse_backward(
            current_id=target_node_id,
            visited=set(),
            current_path=[target_node_id],
            current_edges=[],
            current_confidence=1.0,
            depth=0,
            max_depth=max_depth,
            max_paths=max_paths,
            state=state,
        )

        paths: list[EvidencePath] = state["paths"]
        paths.sort(key=lambda p: p.overall_confidence, reverse=True)
        return paths[:max_paths]

    def _traverse_backward(
        self,
        current_id: UUID,
        visited: set[UUID],
        current_path: list[UUID],
        current_edges: list[UUID],
        current_confidence: float,
        depth: int,
        max_depth: int,
        max_paths: int,
        state: dict[str, Any],
    ) -> None:
        """Recursive backward traversal with hard budgets."""
        if depth >= max_depth:
            self._emit_path(current_path, current_edges, current_confidence, state)
            return
        if state["budget"] <= 0 or len(state["paths"]) >= max_paths:
            return

        state["budget"] -= 1
        visited.add(current_id)
        incoming_edges = self.graph.get_edges_to(current_id)

        # If we reached a root cause type, emit the path
        current_node = self.graph.get_node(current_id)
        if current_node and current_node.node_type in _ROOT_CAUSE_TYPES and depth > 0:
            self._emit_path(current_path, current_edges, current_confidence, state)
            # Don't return — continue exploring for longer paths

        # If no incoming edges, this is a natural root
        if not incoming_edges:
            emitted_as_root = bool(
                current_node and current_node.node_type in _ROOT_CAUSE_TYPES
            )
            if depth > 0 and not emitted_as_root:
                self._emit_path(current_path, current_edges, current_confidence, state)
            return

        for edge in incoming_edges:
            if len(state["paths"]) >= max_paths or state["budget"] <= 0:
                return
            if edge.source_node_id in visited:
                continue

            # Calculate confidence through this edge
            edge_weight = _EDGE_CONFIDENCE_WEIGHT.get(edge.edge_type, 0.5)
            # Factor in the edge's own confidence
            confidence_map = {
                ConfidenceLevel.HIGH: 1.0,
                ConfidenceLevel.MEDIUM: 0.7,
                ConfidenceLevel.LOW: 0.4,
            }
            edge_conf = confidence_map.get(edge.confidence, 0.5)
            path_confidence = current_confidence * edge_weight * edge_conf

            # Prune paths with very low confidence
            if path_confidence < 0.01:
                continue

            self._traverse_backward(
                current_id=edge.source_node_id,
                visited=set(visited),  # Copy to allow branching
                current_path=[edge.source_node_id] + current_path,
                current_edges=[edge.edge_id] + current_edges,
                current_confidence=path_confidence,
                depth=depth + 1,
                max_depth=max_depth,
                max_paths=max_paths,
                state=state,
            )

    def _emit_path(
        self,
        node_ids: list[UUID],
        edge_ids: list[UUID],
        confidence: float,
        state: dict[str, Any],
    ) -> None:
        """Create an EvidencePath from the traversal."""
        paths = state["paths"]
        if len(paths) >= state["max_paths"]:
            return
        # Build description from node labels
        descriptions: list[str] = []
        for nid in node_ids:
            node = self.graph.get_node(nid)
            if node:
                descriptions.append(f"{node.node_type}({node.label})")

        path = EvidencePath(
            nodes=list(node_ids),
            edges=list(edge_ids),
            overall_confidence=round(confidence, 4),
            description=" → ".join(descriptions),
            evidence_summary=f"Path with {len(node_ids)} nodes, confidence={confidence:.2%}",
        )
        paths.append(path)

    def what_changed_after(
        self, node_id: UUID, max_depth: int = 8
    ) -> list[GraphNode]:
        """Get nodes causally impacted by a given node.

        Forward traversal through CAUSAL edges only (never the full
        transitive closure over every edge type), bounded by max_depth.
        """
        visited: set[UUID] = set()
        frontier = {node_id}

        for _ in range(max_depth):
            next_frontier: set[UUID] = set()
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                for edge in self.graph.get_edges_from(nid):
                    if edge.edge_type in _CAUSAL_EDGES:
                        next_frontier.add(edge.target_node_id)
            frontier = next_frontier - visited
            if not frontier:
                break

        # Nodes discovered at the final depth were never expanded — include them
        visited.update(frontier)

        visited.discard(node_id)
        nodes: list[GraphNode] = []
        for desc_id in visited:
            node = self.graph.get_node(desc_id)
            if node:
                nodes.append(node)

        # Sort by timestamp
        return sorted(nodes, key=lambda n: n.timestamp)
