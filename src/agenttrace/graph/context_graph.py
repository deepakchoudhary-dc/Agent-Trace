"""Context Graph — the central data structure for causal audit.

Backed by networkx DiGraph, the Context Graph connects all observable
entities (files, processes, agents, commands) through typed, confidence-
labeled edges. Every node and edge carries provenance metadata.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

import networkx as nx  # type: ignore[import-untyped]

from agenttrace.models.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    NodeType,
)

logger = logging.getLogger(__name__)


class ContextGraph:
    """Directed graph of causal/contextual relationships.

    The graph is the primary data structure for audit analysis.
    All traversal, subgraph extraction, and serialization happens here.
    """

    def __init__(self, session_id: UUID) -> None:
        self.session_id = session_id
        self._graph = nx.DiGraph()
        self._nodes: dict[UUID, GraphNode] = {}
        self._edges: dict[UUID, GraphEdge] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # -- Node operations --

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        self._nodes[node.node_id] = node
        self._graph.add_node(
            str(node.node_id),
            node_type=node.node_type,
            label=node.label,
            timestamp=node.timestamp.isoformat(),
            confidence=node.confidence,
            actor_id=node.actor_id,
        )

    def get_node(self, node_id: UUID) -> GraphNode | None:
        """Retrieve a node by ID."""
        return self._nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a specific type."""
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def remove_node(self, node_id: UUID) -> bool:
        """Remove a node and its connected edges."""
        if node_id not in self._nodes:
            return False

        node_id_str = str(node_id)
        # Remove connected edges from our tracking
        edges_to_remove = [
            eid for eid, e in self._edges.items()
            if e.source_node_id == node_id or e.target_node_id == node_id
        ]
        for eid in edges_to_remove:
            del self._edges[eid]

        self._graph.remove_node(node_id_str)
        del self._nodes[node_id]
        return True

    # -- Edge operations --

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge between two nodes."""
        if edge.source_node_id not in self._nodes:
            logger.warning("Source node %s not found for edge", edge.source_node_id)
            return
        if edge.target_node_id not in self._nodes:
            logger.warning("Target node %s not found for edge", edge.target_node_id)
            return

        self._edges[edge.edge_id] = edge
        self._graph.add_edge(
            str(edge.source_node_id),
            str(edge.target_node_id),
            edge_id=str(edge.edge_id),
            edge_type=edge.edge_type,
            confidence=edge.confidence,
            timestamp=edge.timestamp.isoformat(),
        )

    def get_edge(self, edge_id: UUID) -> GraphEdge | None:
        """Retrieve an edge by ID."""
        return self._edges.get(edge_id)

    def get_edges_from(self, node_id: UUID) -> list[GraphEdge]:
        """Get all outgoing edges from a node."""
        return [
            e for e in self._edges.values()
            if e.source_node_id == node_id
        ]

    def get_edges_to(self, node_id: UUID) -> list[GraphEdge]:
        """Get all incoming edges to a node."""
        return [
            e for e in self._edges.values()
            if e.target_node_id == node_id
        ]

    def get_edges_by_type(self, edge_type: EdgeType) -> list[GraphEdge]:
        """Get all edges of a specific type."""
        return [e for e in self._edges.values() if e.edge_type == edge_type]

    # -- Traversal --

    def predecessors(self, node_id: UUID) -> list[GraphNode]:
        """Get all direct predecessor nodes."""
        node_id_str = str(node_id)
        if node_id_str not in self._graph:
            return []
        pred_ids = list(self._graph.predecessors(node_id_str))
        return [self._nodes[UUID(pid)] for pid in pred_ids if UUID(pid) in self._nodes]

    def successors(self, node_id: UUID) -> list[GraphNode]:
        """Get all direct successor nodes."""
        node_id_str = str(node_id)
        if node_id_str not in self._graph:
            return []
        succ_ids = list(self._graph.successors(node_id_str))
        return [self._nodes[UUID(sid)] for sid in succ_ids if UUID(sid) in self._nodes]

    def ancestors(self, node_id: UUID) -> set[UUID]:
        """Get all ancestor nodes (transitive predecessors)."""
        node_id_str = str(node_id)
        if node_id_str not in self._graph:
            return set()
        anc = nx.ancestors(self._graph, node_id_str)
        return {UUID(a) for a in anc}

    def descendants(self, node_id: UUID) -> set[UUID]:
        """Get all descendant nodes (transitive successors)."""
        node_id_str = str(node_id)
        if node_id_str not in self._graph:
            return set()
        desc = nx.descendants(self._graph, node_id_str)
        return {UUID(d) for d in desc}

    def shortest_path(self, source_id: UUID, target_id: UUID) -> list[UUID] | None:
        """Find shortest path between two nodes."""
        try:
            path = nx.shortest_path(
                self._graph, str(source_id), str(target_id)
            )
            return [UUID(p) for p in path]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def all_paths(
        self, source_id: UUID, target_id: UUID, max_depth: int = 10
    ) -> list[list[UUID]]:
        """Find all simple paths between two nodes up to max_depth."""
        try:
            paths = nx.all_simple_paths(
                self._graph, str(source_id), str(target_id),
                cutoff=max_depth,
            )
            return [[UUID(p) for p in path] for path in paths]
        except nx.NodeNotFound:
            return []

    # -- Subgraph extraction --

    def get_subgraph(
        self,
        center_id: UUID,
        depth: int = 2,
        direction: str = "both",
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Extract a subgraph around a center node.

        Args:
            center_id: The center node to expand from
            depth: How many hops to include
            direction: "forward", "backward", or "both"
        """
        node_ids: set[UUID] = {center_id}

        frontier = {center_id}
        for _ in range(depth):
            next_frontier: set[UUID] = set()
            for nid in frontier:
                if direction in ("forward", "both"):
                    next_frontier |= {UUID(s) for s in self._graph.successors(str(nid))}
                if direction in ("backward", "both"):
                    next_frontier |= {UUID(p) for p in self._graph.predecessors(str(nid))}
            node_ids |= next_frontier
            frontier = next_frontier

        nodes = [self._nodes[nid] for nid in node_ids if nid in self._nodes]
        edges = [
            e for e in self._edges.values()
            if e.source_node_id in node_ids and e.target_node_id in node_ids
        ]
        return nodes, edges

    # -- Serialization --

    def to_snapshot(self) -> GraphSnapshot:
        """Create a serializable snapshot of the entire graph."""
        return GraphSnapshot(
            session_id=self.session_id,
            nodes=list(self._nodes.values()),
            edges=list(self._edges.values()),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to a JSON-compatible dict."""
        snapshot = self.to_snapshot()
        return snapshot.model_dump(mode="json")

    @classmethod
    def from_snapshot(cls, snapshot: GraphSnapshot) -> ContextGraph:
        """Reconstruct a graph from a snapshot."""
        graph = cls(snapshot.session_id)
        for node in snapshot.nodes:
            graph.add_node(node)
        for edge in snapshot.edges:
            graph.add_edge(edge)
        return graph

    # -- Timeline --

    def get_timeline(
        self,
        after: datetime | None = None,
        before: datetime | None = None,
        actor_id: str | None = None,
        node_types: list[NodeType] | None = None,
    ) -> list[GraphNode]:
        """Get nodes ordered by timestamp, with optional filters."""
        nodes = list(self._nodes.values())

        if after:
            nodes = [n for n in nodes if n.timestamp > after]
        if before:
            nodes = [n for n in nodes if n.timestamp < before]
        if actor_id:
            nodes = [n for n in nodes if n.actor_id == actor_id]
        if node_types:
            nodes = [n for n in nodes if n.node_type in node_types]

        return sorted(nodes, key=lambda n: n.timestamp)
