"""Tests for causal explanation (bounded traversal) and blast radius analysis."""

from uuid import uuid4

from agenttrace.graph.blast_radius import BlastRadiusAnalyzer
from agenttrace.graph.causal_engine import CausalExplanationEngine
from agenttrace.graph.context_graph import ContextGraph
from agenttrace.models.events import ConfidenceLevel
from agenttrace.models.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


def _node(
    graph: ContextGraph,
    node_type: NodeType,
    label: str,
    data: dict | None = None,
) -> GraphNode:
    node = GraphNode(
        node_type=node_type,
        label=label,
        actor_id="test",
        source_adapter="test",
        confidence=ConfidenceLevel.HIGH,
        session_id=graph.session_id,
        data=data or {},
    )
    graph.add_node(node)
    return node


def _edge(
    graph: ContextGraph,
    source: GraphNode,
    target: GraphNode,
    edge_type: EdgeType,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> None:
    graph.add_edge(GraphEdge(
        source_node_id=source.node_id,
        target_node_id=target.node_id,
        edge_type=edge_type,
        actor_id="test",
        source_adapter="test",
        confidence=confidence,
    ))


class TestCausalExplanationEngine:
    def test_explain_finds_root_cause_path(self) -> None:
        graph = ContextGraph(uuid4())
        intent = _node(graph, NodeType.TASK_INTENT, "install package x")
        cmd = _node(graph, NodeType.COMMAND, "pip install x")
        target = _node(graph, NodeType.POLICY_FINDING, "dependency change")
        _edge(graph, intent, cmd, EdgeType.CAUSES)
        _edge(graph, cmd, target, EdgeType.EXECUTES)

        engine = CausalExplanationEngine(graph)
        paths = engine.explain(target.node_id, max_depth=5, max_paths=5)

        assert len(paths) == 1
        assert paths[0].nodes[-1] == target.node_id
        assert paths[0].nodes[0] == intent.node_id
        assert "task_intent" in paths[0].description
        assert paths[0].overall_confidence > 0

    def test_explain_respects_max_paths(self) -> None:
        graph = ContextGraph(uuid4())
        # Binary tree of depth 8 -> 256 leaf-to-root paths (exponential blowup
        # without caps). The engine must stop at max_paths during traversal.
        leaves: list[GraphNode] = []
        current: list[GraphNode] = []
        for level in range(8):
            if not current:
                current = [_node(graph, NodeType.AGENT_SESSION, f"n{level}_{i}") for i in range(2)]
            else:
                nxt: list[GraphNode] = []
                for parent in current:
                    a = _node(graph, NodeType.AGENT_SESSION, f"n{level}_{parent.label}_a")
                    b = _node(graph, NodeType.AGENT_SESSION, f"n{level}_{parent.label}_b")
                    _edge(graph, parent, a, EdgeType.CAUSES)
                    _edge(graph, parent, b, EdgeType.CAUSES)
                    nxt.extend([a, b])
                current = nxt
                if level == 7:
                    leaves = current

        target = _node(graph, NodeType.POLICY_FINDING, "target")
        for leaf in leaves:
            _edge(graph, leaf, target, EdgeType.CAUSES)

        engine = CausalExplanationEngine(graph)
        paths = engine.explain(target.node_id, max_depth=20, max_paths=5)

        assert len(paths) <= 5, "traversal must stop at max_paths"

    def test_explain_unknown_target_returns_empty(self) -> None:
        graph = ContextGraph(uuid4())
        engine = CausalExplanationEngine(graph)
        assert engine.explain(uuid4()) == []

    def test_what_changed_after_follows_only_causal_edges(self) -> None:
        graph = ContextGraph(uuid4())
        origin = _node(graph, NodeType.COMMAND, "origin")
        caused = _node(graph, NodeType.FILESYSTEM_MUTATION, "caused")
        read = _node(graph, NodeType.SOURCE_FILE, "merely read")
        _edge(graph, origin, caused, EdgeType.CAUSES)
        _edge(graph, origin, read, EdgeType.READS)

        engine = CausalExplanationEngine(graph)
        changed = engine.what_changed_after(origin.node_id)

        ids = {n.node_id for n in changed}
        assert caused.node_id in ids
        assert read.node_id not in ids, "READS-only links are not causal impact"

    def test_what_changed_after_respects_max_depth(self) -> None:
        graph = ContextGraph(uuid4())
        origin = _node(graph, NodeType.COMMAND, "origin")
        prev = origin
        for i in range(10):
            nxt = _node(graph, NodeType.FILESYSTEM_MUTATION, f"hop{i}")
            _edge(graph, prev, nxt, EdgeType.CAUSES)
            prev = nxt

        engine = CausalExplanationEngine(graph)
        changed = engine.what_changed_after(origin.node_id, max_depth=3)

        assert len(changed) == 3


class TestBlastRadiusAnalyzer:
    def test_broken_imports_detected_for_deleted_file(self) -> None:
        graph = ContextGraph(uuid4())
        lib = _node(
            graph,
            NodeType.SOURCE_FILE,
            "lib.py",
            data={"path": "C:/ws/lib.py", "relative_path": "lib.py"},
        )
        app = _node(
            graph,
            NodeType.SOURCE_FILE,
            "app.py",
            data={"path": "C:/ws/app.py", "relative_path": "app.py"},
        )
        _edge(graph, app, lib, EdgeType.READS, ConfidenceLevel.LOW)

        analyzer = BlastRadiusAnalyzer(graph)
        result = analyzer.analyze(lib.node_id)

        assert "app.py" in result.broken_imports
        assert result.risk_score >= 0.1, "broken imports must raise risk score"

    def test_mutation_node_resolves_to_source_file(self) -> None:
        graph = ContextGraph(uuid4())
        lib = _node(
            graph,
            NodeType.SOURCE_FILE,
            "lib.py",
            data={"path": "C:/ws/lib.py", "relative_path": "lib.py"},
        )
        app = _node(
            graph,
            NodeType.SOURCE_FILE,
            "app.py",
            data={"path": "C:/ws/app.py", "relative_path": "app.py"},
        )
        mutation = _node(graph, NodeType.FILESYSTEM_MUTATION, "delete: lib.py")
        _edge(graph, mutation, lib, EdgeType.MODIFIES)
        _edge(graph, app, lib, EdgeType.READS, ConfidenceLevel.LOW)

        analyzer = BlastRadiusAnalyzer(graph)
        result = analyzer.analyze(mutation.node_id)

        assert "app.py" in result.broken_imports

    def test_failed_tests_raise_risk(self) -> None:
        graph = ContextGraph(uuid4())
        change = _node(graph, NodeType.FILESYSTEM_MUTATION, "modify: lib.py")
        test = _node(
            graph,
            NodeType.TEST_RESULT,
            "test_math.py::test_add",
            data={"failed": True, "test_suite": "test_math.py"},
        )
        _edge(graph, change, test, EdgeType.VALIDATES)

        analyzer = BlastRadiusAnalyzer(graph)
        result = analyzer.analyze(change.node_id)

        assert "test_math.py::test_add" in result.failed_tests
        assert result.risk_score >= 0.15
        assert result.risk_score <= 1.0

    def test_analyze_bounded_and_includes_files(self) -> None:
        graph = ContextGraph(uuid4())
        change = _node(graph, NodeType.FILESYSTEM_MUTATION, "modify: a.py")
        a = _node(
            graph,
            NodeType.SOURCE_FILE,
            "a.py",
            data={"path": "C:/ws/a.py", "relative_path": "a.py"},
        )
        b = _node(
            graph,
            NodeType.SOURCE_FILE,
            "b.py",
            data={"path": "C:/ws/b.py", "relative_path": "b.py"},
        )
        _edge(graph, change, a, EdgeType.MODIFIES)
        _edge(graph, b, a, EdgeType.READS, ConfidenceLevel.LOW)

        analyzer = BlastRadiusAnalyzer(graph)
        result = analyzer.analyze(change.node_id)

        assert "a.py" in result.affected_files or "b.py" in result.affected_files
        assert result.affected_nodes
