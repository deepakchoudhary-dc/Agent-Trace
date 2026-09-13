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
  | 'incident'
  | 'cluster';

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
  content_hash?: string;
  evidence_refs?: string[];
  data?: Record<string, unknown>;
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
  evidence_refs?: string[];
  data?: Record<string, unknown>;
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
  payload?: Record<string, unknown>;
  event_hash: string;
  prev_hash: string;
  seq: number;
}

export interface PolicyFinding {
  finding_id: string;
  session_id: string;
  finding_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  affected_path: string;
  affected_command: string;
  requires_approval: boolean;
  auto_resolved?: boolean;
  timestamp: string;
}

export interface DiffItem {
  file_path: string;
  mutation_type: string;
  before_hash: string;
  after_hash: string;
  diff_summary: string;
  timestamp: string;
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

export interface VerificationResult {
  session_id: string;
  verified: boolean;
  error: string;
  event_count: number;
  last_event_hash: string;
}

export interface ForensicReport {
  report_id: string;
  session_id: string;
  generated_at: string;
  integrity_status: string;
  integrity_error: string;
  head_event_hash: string;
  event_count: number;
  findings_count: number;
  approvals_count: number;
  report_signature_sha256: string;
  findings_summary?: Array<{
    finding_id: string;
    type: string;
    severity: string;
    description: string;
  }>;
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
  stopped_at?: string;
  last_event_hash?: string;
  adapter?: string;
  observability_gaps?: string[];
}

// -- Review loop (P0-7): real artifacts & verdicts --

export type ReviewVerdict = 'PASSED' | 'FAILED' | 'PARTIAL';

export interface CriterionVerdict {
  criterion: string;
  verdict: ReviewVerdict;
  file_refs: string[];
  line_refs: number[];
  notes: string;
}

export interface WorkerArtifactData {
  artifact_id: string;
  artifact_type: 'code' | 'verification' | '';
  file_path: string;
  content: string;
  command: string;
  exit_code: number | null;
  evidence: Record<string, unknown>;
  subtask_id: string | null;
  iteration: number;
  created_at: string;
}

export interface ReviewResultData {
  reviewer_name: string;
  reviewer_type: string;
  results: CriterionVerdict[];
  suggestions: string[];
  slop_findings: string[];
  overall_verdict: ReviewVerdict;
  confidence: number;
  review_time_ms: number;
  created_at: string;
}

export interface SynthesisData {
  passed: boolean;
  overall_confidence: number;
  passed_criteria: string[];
  failed_criteria: string[];
  partial_criteria: string[];
  slop_findings: string[];
  suggestions: string[];
  feedback_for_worker: Record<string, unknown>;
  deliverable_summary: string;
}

export interface PlanReviewData {
  plan_adequate: boolean;
  scope_issues: string[];
  missing_criteria: string[];
  unnecessary_criteria: string[];
  proposed_amendments: string[];
  lessons_learned: string[];
}

export interface ReviewIterationData {
  iteration: number;
  worker_result: {
    iteration: number;
    artifacts: WorkerArtifactData[];
    completed_subtasks: string[];
    pending_subtasks: string[];
    feedback_applied: string[];
    notes: string;
  } | null;
  review_results: ReviewResultData[];
  synthesis: SynthesisData | null;
  plan_review: PlanReviewData | null;
  passed: boolean;
  timestamp: string;
}

export interface ReviewRunData {
  loop_id: string;
  task_description: string;
  workspace_path: string;
  scope_files: string[];
  iterations: ReviewIterationData[];
  final_passed: boolean;
  total_iterations: number;
  convergence_metrics: Record<string, unknown>;
  lessons_learned: string[];
  deliverable_summary: string;
  escalation_reason: string;
  started_at: string;
  completed_at: string | null;
}

export interface ReviewRunRecord {
  loop_id: string;
  session_id: string;
  passed: boolean;
  iterations: number;
  created_at: string;
  payload: ReviewRunData;
}

// -- ant.md P2 #8: compliance evidence manifest (EU AI Act / ISO 42001 / SOC 2) --

export interface ComplianceBundle {
  bundle_id: string;
  session_id: string;
  workspace_path: string;
  generated_at: string;
  event_count: number;
  findings_count: number;
  incidents_count: number;
  approvals_count: number;
  integrity: {
    chain_verified: boolean;
    chain_error: string;
    head_event_hash: string;
  };
  frameworks: Record<string, unknown>;
  report_signature_sha256: string;
}

// -- ant.md P1 #4: retro-scan report (two-stage wide-net re-scan) --

export interface RetroScanResponse {
  sessions_scanned: number;
  events_scanned: number;
  stage1_hits: number;
  sessions_stage2: string[];
  retro_incidents: number;
  errors: string[];
  summary: string;
  threshold: string;
  calibration: Record<string, unknown>;
  negative_result: Record<string, unknown>;
}

// -- Correlated multi-stage incidents --

export interface IncidentSummary {
  incident_id: string;
  session_id: string;
  incident_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence_event_ids: string[];
  timestamp: string;
}

// -- Operator briefing (real GET /sessions/{id}/brief payload) --

export interface BriefAttentionItem {
  finding_type: string;
  severity: string;
  description: string;
  recommended_action: string;
}

export interface OpenApprovalSummary {
  finding_id: string;
  scope: string;
  expiry: string;
}

export interface SessionBrief {
  session_id: string;
  status: string;
  total_findings: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  attention: BriefAttentionItem[];
  open_approvals: OpenApprovalSummary[];
  integrity_failures: number;
  last_activity: string | null;
}

// -- Coordination signals (real GET /sessions/{id}/collusion payload) --
// Observable half only: every candidate carries an explicit reasoning gap and
// never claims coordination itself.

export interface CollusionCandidate {
  signal: string;
  session_ids: string[];
  actors: string[];
  detail: string;
  confidence: string;
  evidence_event_ids: string[];
  reasoning_gap: string;
  created_at: string;
}

// -- Projection MAC verdict (real GET /sessions/{id}/projection/verify) --
// checked: false means no MAC was ever committed - it is not checked,
// never a pass.

export interface ProjectionVerdict {
  checked: boolean;
  authenticated: boolean;
  stored_digest: string | null;
}

// -- Retro-scan (real POST /rescan payload) --
// Single source of truth: RetroScanResponse above; RetroScanResult kept as a
// strict alias so both the api-object signature and the standalone helper agree.

export type RetroScanResult = RetroScanResponse;

export type CalibrationPayload = RetroScanResponse['calibration'];
export type NegativeResultPayload = RetroScanResponse['negative_result'];

// -- Sealed forensic report envelope (real GET /sessions/{id}/report) --
// The signed manifest also carries the reasoning trail and incidents summary;
// both are surfaced in the dashboard instead of being dropped.

export interface ReasoningTrailEntry {
  event_id: string;
  timestamp: string;
  kind: string;
  excerpt: string;
}

export interface IncidentSummaryEntry {
  incident_id: string;
  incident_type: string;
  severity: string;
  title: string;
  related_events: string[];
}

export interface SignedForensicReport extends ForensicReport {
  incidents_count: number;
  reasoning_trail: ReasoningTrailEntry[];
  incidents_summary: IncidentSummaryEntry[];
  chain_binding: {
    chain_tip: string;
    chain_length: number;
  };
  report_signature: string;
}
