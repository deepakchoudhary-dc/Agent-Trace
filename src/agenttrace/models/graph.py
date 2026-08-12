"""Context Graph data models — nodes, edges, and traversal primitives.

The Context Graph is the central data structure: a directed graph where
nodes represent observable entities (files, processes, agents, commands)
and edges represent causal/contextual relationships between them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from agenttrace.models.events import ConfidenceLevel


class NodeType(str, Enum):
    """Types of nodes in the Context Graph."""

    TASK_INTENT = "task_intent"
    TASK_CONSTRAINTS = "task_constraints"
    WORKSPACE_SNAPSHOT = "workspace_snapshot"
    GIT_COMMIT_DIFF = "git_commit_diff"
    SOURCE_FILE = "source_file"
    SOURCE_SYMBOL = "source_symbol"
    CONTEXTUAL_DOCUMENT = "contextual_document"
    UNTRUSTED_CONTENT = "untrusted_content"
    AGENT_SESSION = "agent_session"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    PROCESS = "process"
    COMMAND = "command"
    NETWORK_REQUEST = "network_request"
    FILESYSTEM_MUTATION = "filesystem_mutation"
    PACKAGE_CHANGE = "package_change"
    CONFIG_CHANGE = "config_change"
    TEST_RESULT = "test_result"
    BUILD_RESULT = "build_result"
    APPROVAL = "approval"
    POLICY_FINDING = "policy_finding"
    INCIDENT = "incident"


class EdgeType(str, Enum):
    """Types of directed edges in the Context Graph."""

    READS = "READS"
    PROVIDES_CONTEXT_TO = "PROVIDES_CONTEXT_TO"
    REQUESTS = "REQUESTS"
    EXECUTES = "EXECUTES"
    SPAWNS = "SPAWNS"
    MODIFIES = "MODIFIES"
    INTRODUCES = "INTRODUCES"
    CAUSES = "CAUSES"
    VALIDATES = "VALIDATES"
    VIOLATES = "VIOLATES"
    APPROVED_BY = "APPROVED_BY"
    INFERRED_FROM = "INFERRED_FROM"


class GraphNode(BaseModel):
    """A node in the Context Graph.

    Every node has provenance: who created it, when, from what source,
    and with what confidence. This lets the UI distinguish directly
    observed facts from inferred relationships.
    """

    node_id: UUID = Field(default_factory=uuid4)
    node_type: NodeType
    label: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str = ""
    source_adapter: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    content_hash: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    session_id: UUID | None = None


class GraphEdge(BaseModel):
    """A directed edge in the Context Graph.

    Edges carry the same provenance as nodes. Inferred edges
    (e.g., temporal correlation) are explicitly marked LOW confidence.
    """

    edge_id: UUID = Field(default_factory=uuid4)
    source_node_id: UUID
    target_node_id: UUID
    edge_type: EdgeType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str = ""
    source_adapter: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence_refs: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class EvidencePath(BaseModel):
    """A ranked causal path through the graph.

    Used by the causal explanation engine to present backward
    traversals from suspicious actions to root causes.
    """

    path_id: UUID = Field(default_factory=uuid4)
    nodes: list[UUID] = Field(default_factory=list)
    edges: list[UUID] = Field(default_factory=list)
    overall_confidence: float = 0.0
    description: str = ""
    evidence_summary: str = ""


class BlastRadiusResult(BaseModel):
    """Forward impact analysis result from a code change."""

    origin_node_id: UUID
    affected_nodes: list[UUID] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    failed_tests: list[str] = Field(default_factory=list)
    broken_imports: list[str] = Field(default_factory=list)
    config_changes: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class GraphSnapshot(BaseModel):
    """A serializable snapshot of the entire Context Graph at a point in time."""

    snapshot_id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
