"""Tests for Context Graph operations."""

from uuid import uuid4

from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.graph import EdgeType, GraphEdge, GraphNode, NodeType


class TestContextGraph:
    """Tests for the ContextGraph class."""

    def test_add_and_get_node(self) -> None:
        graph = ContextGraph(uuid4())
        node = GraphNode(
            node_type=NodeType.SOURCE_FILE,
            label="main.py",
            actor_id="baseline",
        )
        graph.add_node(node)
        assert graph.node_count == 1
        assert graph.get_node(node.node_id) == node

    def test_add_and_get_edge(self) -> None:
        graph = ContextGraph(uuid4())
        node1 = GraphNode(node_type=NodeType.SOURCE_FILE, label="a.py")
        node2 = GraphNode(node_type=NodeType.SOURCE_FILE, label="b.py")
        graph.add_node(node1)
        graph.add_node(node2)

        edge = GraphEdge(
            source_node_id=node1.node_id,
            target_node_id=node2.node_id,
            edge_type=EdgeType.READS,
        )
        graph.add_edge(edge)

        assert graph.edge_count == 1
        assert graph.get_edge(edge.edge_id) == edge

    def test_get_nodes_by_type(self) -> None:
        graph = ContextGraph(uuid4())
        graph.add_node(GraphNode(node_type=NodeType.SOURCE_FILE, label="a.py"))
        graph.add_node(GraphNode(node_type=NodeType.SOURCE_FILE, label="b.py"))
        graph.add_node(GraphNode(node_type=NodeType.PROCESS, label="proc1"))

        files = graph.get_nodes_by_type(NodeType.SOURCE_FILE)
        assert len(files) == 2

    def test_predecessors_and_successors(self) -> None:
        graph = ContextGraph(uuid4())
        n1 = GraphNode(node_type=NodeType.AGENT_SESSION, label="session")
        n2 = GraphNode(node_type=NodeType.TOOL_REQUEST, label="tool")
        n3 = GraphNode(node_type=NodeType.FILESYSTEM_MUTATION, label="file_change")

        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_node(n3)

        graph.add_edge(GraphEdge(
            source_node_id=n1.node_id, target_node_id=n2.node_id,
            edge_type=EdgeType.REQUESTS,
        ))
        graph.add_edge(GraphEdge(
            source_node_id=n2.node_id, target_node_id=n3.node_id,
            edge_type=EdgeType.MODIFIES,
        ))

        assert len(graph.successors(n1.node_id)) == 1
        assert graph.successors(n1.node_id)[0].node_id == n2.node_id
        assert len(graph.predecessors(n3.node_id)) == 1
        assert graph.predecessors(n3.node_id)[0].node_id == n2.node_id

    def test_ancestors_and_descendants(self) -> None:
        graph = ContextGraph(uuid4())
        nodes = [
            GraphNode(node_type=NodeType.TASK_INTENT, label=f"n{i}")
            for i in range(4)
        ]
        for n in nodes:
            graph.add_node(n)

        # Chain: n0 → n1 → n2 → n3
        for i in range(3):
            graph.add_edge(GraphEdge(
                source_node_id=nodes[i].node_id,
                target_node_id=nodes[i+1].node_id,
                edge_type=EdgeType.CAUSES,
            ))

        anc = graph.ancestors(nodes[3].node_id)
        assert len(anc) == 3  # n0, n1, n2

        desc = graph.descendants(nodes[0].node_id)
        assert len(desc) == 3  # n1, n2, n3

    def test_shortest_path(self) -> None:
        graph = ContextGraph(uuid4())
        nodes = [GraphNode(node_type=NodeType.SOURCE_FILE, label=f"n{i}") for i in range(3)]
        for n in nodes:
            graph.add_node(n)

        graph.add_edge(GraphEdge(
            source_node_id=nodes[0].node_id, target_node_id=nodes[1].node_id,
            edge_type=EdgeType.READS,
        ))
        graph.add_edge(GraphEdge(
            source_node_id=nodes[1].node_id, target_node_id=nodes[2].node_id,
            edge_type=EdgeType.READS,
        ))

        path = graph.shortest_path(nodes[0].node_id, nodes[2].node_id)
        assert path is not None
        assert len(path) == 3

    def test_subgraph_extraction(self) -> None:
        graph = ContextGraph(uuid4())
        center = GraphNode(node_type=NodeType.COMMAND, label="center")
        neighbor = GraphNode(node_type=NodeType.PROCESS, label="neighbor")
        far = GraphNode(node_type=NodeType.SOURCE_FILE, label="far")

        graph.add_node(center)
        graph.add_node(neighbor)
        graph.add_node(far)

        graph.add_edge(GraphEdge(
            source_node_id=center.node_id, target_node_id=neighbor.node_id,
            edge_type=EdgeType.EXECUTES,
        ))
        graph.add_edge(GraphEdge(
            source_node_id=neighbor.node_id, target_node_id=far.node_id,
            edge_type=EdgeType.MODIFIES,
        ))

        # Depth 1: center + neighbor
        nodes, edges = graph.get_subgraph(center.node_id, depth=1)
        assert len(nodes) == 2

        # Depth 2: all three
        nodes, edges = graph.get_subgraph(center.node_id, depth=2)
        assert len(nodes) == 3

    def test_snapshot_and_restore(self) -> None:
        session_id = uuid4()
        graph = ContextGraph(session_id)
        node = GraphNode(node_type=NodeType.SOURCE_FILE, label="test.py")
        graph.add_node(node)

        snapshot = graph.to_snapshot()
        assert len(snapshot.nodes) == 1

        restored = ContextGraph.from_snapshot(snapshot)
        assert restored.node_count == 1
        assert restored.get_node(node.node_id) is not None

    def test_remove_node(self) -> None:
        graph = ContextGraph(uuid4())
        node = GraphNode(node_type=NodeType.SOURCE_FILE, label="temp.py")
        graph.add_node(node)
        assert graph.node_count == 1

        graph.remove_node(node.node_id)
        assert graph.node_count == 0

    def test_timeline_filtering(self) -> None:
        from datetime import datetime, timedelta, timezone

        graph = ContextGraph(uuid4())
        base_time = datetime(2024, 1, 1, tzinfo=timezone.utc)

        for i in range(5):
            node = GraphNode(
                node_type=NodeType.COMMAND,
                label=f"cmd{i}",
                timestamp=base_time + timedelta(hours=i),
                actor_id="actor-a" if i % 2 == 0 else "actor-b",
            )
            graph.add_node(node)

        # Filter by actor
        actor_a = graph.get_timeline(actor_id="actor-a")
        assert len(actor_a) == 3

        # Filter by time
        after_2hrs = graph.get_timeline(after=base_time + timedelta(hours=1, minutes=30))
        assert len(after_2hrs) == 3
