export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type NodeType =
  | 'task_intent'
  | 'task_constraints'
  | 'workspace_snapshot'
  | 'git_commit_diff'
  | 'source_file'
  | 'source_symbol'
  | 'contextual_document'
  | 'untrusted_content'
  | 'agent_session'
  | 'tool_request'
  | 'tool_result'
  | 'process'
  | 'command'
  | 'network_request'
  | 'filesystem_mutation'
  | 'package_change'
  | 'config_change'
  | 'test_result'
  | 'build_result'
  | 'approval'
  | 'policy_finding'
  | 'incident';

export type EdgeType =
  | 'READS'
  | 'PROVIDES_CONTEXT_TO'
  | 'REQUESTS'
  | 'EXECUTES'
  | 'SPAWNS'
  | 'MODIFIES'
  | 'INTRODUCES'
  | 'CAUSES'
  | 'VALIDATES'
  | 'VIOLATES'
  | 'APPROVED_BY'
  | 'INFERRED_FROM';

export interface GraphNode {
  node_id: string;
  node_type: NodeType;
  label: string;
  timestamp: string;
  actor_id: string;
  source_adapter: string;
  confidence: ConfidenceLevel;
  content_hash: string;
  evidence_refs: string[];
  data: Record<string, any>;
  session_id?: string;
}

export interface GraphEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: EdgeType;
  timestamp: string;
  actor_id: string;
  source_adapter: string;
  confidence: ConfidenceLevel;
  evidence_refs: string[];
  data: Record<string, any>;
}

export interface ContextGraphData {
  session_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelineEvent {
  event_id: string;
  session_id: string;
  event_type: string;
  timestamp: string;
  actor_id: string;
  source_adapter: string;
  confidence: ConfidenceLevel;
  payload_enc?: string;
  event_hash: string;
  prev_hash: string;
  evidence_json: string;
  seq: number;
}

export interface PolicyFinding {
  event_id: string;
  session_id: string;
  finding_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  affected_path: string;
  affected_command: string;
  requires_approval: boolean;
  timestamp: string;
  actor_id: string;
}

export interface Approval {
  approval_id: string;
  session_id: string;
  finding_id: string;
  approved: boolean;
  reason: string;
  scope: string;
  expiry?: string;
  affected_paths: string[];
  affected_commands: string[];
  created_at: string;
}

export interface EvidencePath {
  path_id: string;
  nodes: string[];
  edges: string[];
  overall_confidence: number;
  description: string;
  evidence_summary: string;
}

export interface BlastRadiusResult {
  origin_node_id: string;
  affected_nodes: string[];
  affected_files: string[];
  failed_tests: string[];
  broken_imports: string[];
  config_changes: string[];
  risk_score: number;
}

export interface SessionInfo {
  session_id: string;
  workspace_path: string;
  status: string;
  task_description: string;
  event_count: number;
  started_at: string;
  adapter?: string;
  capabilities?: Record<string, boolean>;
  observability_gaps?: string[];
}
