import {
  BlastRadiusResult,
  ContextGraphData,
  EvidencePath,
  PolicyFinding,
  SessionInfo,
  TimelineEvent,
} from '../types';

const API_BASE = 'http://localhost:8000';

export class ApiClient {
  private static async request<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });
    if (!res.ok) {
      throw new Error(`API error ${res.status}: ${await res.text()}`);
    }
    return res.json();
  }

  static async getSessions(): Promise<SessionInfo[]> {
    try {
      return await this.request<SessionInfo[]>('/sessions');
    } catch {
      return this.getMockSessions();
    }
  }

  static async getSession(sessionId: string): Promise<SessionInfo> {
    try {
      return await this.request<SessionInfo>(`/sessions/${sessionId}`);
    } catch {
      return this.getMockSessions()[0];
    }
  }

  static async getGraph(sessionId: string): Promise<ContextGraphData> {
    try {
      return await this.request<ContextGraphData>(`/sessions/${sessionId}/graph`);
    } catch {
      return this.getMockGraph(sessionId);
    }
  }

  static async getTimeline(sessionId: string): Promise<TimelineEvent[]> {
    try {
      return await this.request<TimelineEvent[]>(`/sessions/${sessionId}/timeline`);
    } catch {
      return this.getMockTimeline(sessionId);
    }
  }

  static async getFindings(sessionId: string): Promise<PolicyFinding[]> {
    try {
      return await this.request<PolicyFinding[]>(`/sessions/${sessionId}/findings`);
    } catch {
      return this.getMockFindings(sessionId);
    }
  }

  static async getCausalExplanation(sessionId: string, nodeId: string): Promise<EvidencePath[]> {
    try {
      return await this.request<EvidencePath[]>(`/sessions/${sessionId}/causal/${nodeId}`);
    } catch {
      return [
        {
          path_id: 'p-1',
          nodes: ['n-prompt', 'n-session-codex', 'n-cmd-1', 'n-file-1', 'n-test-fail'],
          edges: ['e-1', 'e-2', 'e-3', 'e-4'],
          overall_confidence: 0.88,
          description: 'untrusted_content (PR Description) → agent_session (Codex) → command (npm install) → filesystem_mutation (auth.ts) → test_result (FAILED)',
          evidence_summary: '5 nodes traversed, high confidence causal path',
        },
      ];
    }
  }

  static async getBlastRadius(sessionId: string, nodeId: string): Promise<BlastRadiusResult> {
    try {
      return await this.request<BlastRadiusResult>(`/sessions/${sessionId}/blast-radius/${nodeId}`);
    } catch {
      return {
        origin_node_id: nodeId,
        affected_nodes: ['n-file-1', 'n-file-2', 'n-test-1'],
        affected_files: ['src/auth/jwt.ts', 'src/server.ts', 'src/routes/login.ts'],
        failed_tests: ['test_auth_header_validation', 'test_jwt_expiration'],
        broken_imports: ['jsonwebtoken'],
        config_changes: ['package.json'],
        risk_score: 0.72,
      };
    }
  }

  static async recordApproval(
    sessionId: string,
    findingId: string,
    approved: boolean,
    reason: string,
    scope: string,
    affectedPaths: string[] = []
  ): Promise<{ status: string }> {
    try {
      return await this.request<{ status: string }>(`/sessions/${sessionId}/approvals`, {
        method: 'POST',
        body: JSON.stringify({
          finding_id: findingId,
          approved,
          reason,
          scope,
          affected_paths: affectedPaths,
        }),
      });
    } catch {
      return { status: approved ? 'approved' : 'denied' };
    }
  }

  // --- Mock Data Fallbacks for standalone dashboard exploration ---

  private static getMockSessions(): SessionInfo[] {
    return [
      {
        session_id: '36472cad-9ae9-4a9f-af7b-deb729cfea9e',
        workspace_path: 'e:/Blackbox',
        status: 'active',
        task_description: 'Audit AI coding assistant changes across auth & network layer',
        event_count: 24,
        started_at: new Date(Date.now() - 3600000).toISOString(),
        adapter: 'codex_cli',
        capabilities: {
          invocation: true,
          tool_requests: true,
          tool_results: true,
          approvals: true,
          context_boundary: true,
        },
        observability_gaps: [
          "Agent's private model chain-of-thought weights",
          'Encrypted TLS payload plaintext (metadata only)',
        ],
      },
    ];
  }

  private static getMockGraph(sessionId: string): ContextGraphData {
    return {
      session_id: sessionId,
      nodes: [
        {
          node_id: 'n-prompt',
          node_type: 'task_intent',
          label: 'Task: Refactor JWT token authentication',
          timestamp: new Date(Date.now() - 3000000).toISOString(),
          actor_id: 'user',
          source_adapter: 'user_cli',
          confidence: 'high',
          content_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          evidence_refs: ['CLI argv'],
          data: { goal: 'Refactor JWT token auth' },
        },
        {
          node_id: 'n-session-codex',
          node_type: 'agent_session',
          label: 'Codex CLI Session #1',
          timestamp: new Date(Date.now() - 2800000).toISOString(),
          actor_id: 'codex:sess_84a9',
          source_adapter: 'codex_cli',
          confidence: 'high',
          content_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          evidence_refs: ['codex_log.jsonl:L12'],
          data: { version: '0.1.0' },
        },
        {
          node_id: 'n-cmd-1',
          node_type: 'command',
          label: 'cmd: npm install jsonwebtoken@9.0.2',
          timestamp: new Date(Date.now() - 2500000).toISOString(),
          actor_id: 'codex:sess_84a9',
          source_adapter: 'terminal_observer',
          confidence: 'high',
          content_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
          evidence_refs: ['bash_history'],
          data: { exit_code: 0 },
        },
        {
          node_id: 'n-file-1',
          node_type: 'filesystem_mutation',
          label: 'modify: src/auth/jwt.ts',
          timestamp: new Date(Date.now() - 2000000).toISOString(),
          actor_id: 'codex:sess_84a9',
          source_adapter: 'filesystem_observer',
          confidence: 'high',
          content_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
          evidence_refs: ['fs_watch:diff_01'],
          data: { lines_added: 42, lines_removed: 18 },
        },
        {
          node_id: 'n-net-1',
          node_type: 'network_request',
          label: 'net: 142.250.190.46:443 (api.github.com)',
          timestamp: new Date(Date.now() - 1700000).toISOString(),
          actor_id: 'process:1420',
          source_adapter: 'network_observer',
          confidence: 'medium',
          content_hash: 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f',
          evidence_refs: ['psutil:inet_sock'],
          data: { protocol: 'tcp', direction: 'outbound' },
        },
        {
          node_id: 'n-policy-1',
          node_type: 'policy_finding',
          label: 'Finding: Network Egress to External IP',
          timestamp: new Date(Date.now() - 1500000).toISOString(),
          actor_id: 'policy_engine',
          source_adapter: 'policy_engine',
          confidence: 'high',
          content_hash: 'cb24a8726dd7ef03b9b47e5b53e80eb0b3687be69d51152a28185bb8b2f90a9a',
          evidence_refs: ['policy:network_egress'],
          data: { severity: 'medium', destination: '142.250.190.46:443' },
        },
        {
          node_id: 'n-test-fail',
          node_type: 'test_result',
          label: 'test: pytest tests/test_auth.py (FAILED 1/4)',
          timestamp: new Date(Date.now() - 1000000).toISOString(),
          actor_id: 'terminal',
          source_adapter: 'terminal_observer',
          confidence: 'high',
          content_hash: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4',
          evidence_refs: ['pytest_stdout'],
          data: { passed: 3, failed: 1, duration_ms: 450 },
        },
      ],
      edges: [
        {
          edge_id: 'e-1',
          source_node_id: 'n-prompt',
          target_node_id: 'n-session-codex',
          edge_type: 'PROVIDES_CONTEXT_TO',
          timestamp: new Date(Date.now() - 2800000).toISOString(),
          actor_id: 'user',
          source_adapter: 'user_cli',
          confidence: 'high',
          evidence_refs: [],
          data: {},
        },
        {
          edge_id: 'e-2',
          source_node_id: 'n-session-codex',
          target_node_id: 'n-cmd-1',
          edge_type: 'EXECUTES',
          timestamp: new Date(Date.now() - 2500000).toISOString(),
          actor_id: 'codex:sess_84a9',
          source_adapter: 'codex_cli',
          confidence: 'high',
          evidence_refs: [],
          data: {},
        },
        {
          edge_id: 'e-3',
          source_node_id: 'n-session-codex',
          target_node_id: 'n-file-1',
          edge_type: 'MODIFIES',
          timestamp: new Date(Date.now() - 2000000).toISOString(),
          actor_id: 'codex:sess_84a9',
          source_adapter: 'filesystem_observer',
          confidence: 'high',
          evidence_refs: [],
          data: {},
        },
        {
          edge_id: 'e-4',
          source_node_id: 'n-cmd-1',
          target_node_id: 'n-net-1',
          edge_type: 'SPAWNS',
          timestamp: new Date(Date.now() - 1700000).toISOString(),
          actor_id: 'process:1420',
          source_adapter: 'network_observer',
          confidence: 'medium',
          evidence_refs: [],
          data: {},
        },
        {
          edge_id: 'e-5',
          source_node_id: 'n-net-1',
          target_node_id: 'n-policy-1',
          edge_type: 'VIOLATES',
          timestamp: new Date(Date.now() - 1500000).toISOString(),
          actor_id: 'policy_engine',
          source_adapter: 'policy_engine',
          confidence: 'high',
          evidence_refs: [],
          data: {},
        },
        {
          edge_id: 'e-6',
          source_node_id: 'n-file-1',
          target_node_id: 'n-test-fail',
          edge_type: 'CAUSES',
          timestamp: new Date(Date.now() - 1000000).toISOString(),
          actor_id: 'terminal',
          source_adapter: 'terminal_observer',
          confidence: 'high',
          evidence_refs: [],
          data: {},
        },
      ],
    };
  }

  private static getMockTimeline(sessionId: string): TimelineEvent[] {
    return [
      {
        event_id: 'evt-01',
        session_id: sessionId,
        event_type: 'session_start',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        actor_id: 'daemon',
        source_adapter: 'daemon',
        confidence: 'high',
        event_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        prev_hash: '',
        evidence_json: '[]',
        seq: 1,
      },
      {
        event_id: 'evt-02',
        session_id: sessionId,
        event_type: 'invocation',
        timestamp: new Date(Date.now() - 3000000).toISOString(),
        actor_id: 'user',
        source_adapter: 'user_cli',
        confidence: 'high',
        event_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        prev_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        evidence_json: '["prompt_text"]',
        seq: 2,
      },
      {
        event_id: 'evt-03',
        session_id: sessionId,
        event_type: 'command',
        timestamp: new Date(Date.now() - 2500000).toISOString(),
        actor_id: 'codex:sess_84a9',
        source_adapter: 'terminal_observer',
        confidence: 'high',
        event_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        prev_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        evidence_json: '["ps_history"]',
        seq: 3,
      },
      {
        event_id: 'evt-04',
        session_id: sessionId,
        event_type: 'file_mutation',
        timestamp: new Date(Date.now() - 2000000).toISOString(),
        actor_id: 'codex:sess_84a9',
        source_adapter: 'filesystem_observer',
        confidence: 'high',
        event_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
        prev_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        evidence_json: '["diff_hash_a1"]',
        seq: 4,
      },
      {
        event_id: 'evt-05',
        session_id: sessionId,
        event_type: 'policy_finding',
        timestamp: new Date(Date.now() - 1500000).toISOString(),
        actor_id: 'policy_engine',
        source_adapter: 'policy_engine',
        confidence: 'high',
        event_hash: 'cb24a8726dd7ef03b9b47e5b53e80eb0b3687be69d51152a28185bb8b2f90a9a',
        prev_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
        evidence_json: '["policy_rule_03"]',
        seq: 5,
      },
    ];
  }

  private static getMockFindings(sessionId: string): PolicyFinding[] {
    return [
      {
        event_id: 'f-01',
        session_id: sessionId,
        finding_type: 'network_egress',
        severity: 'medium',
        description: 'New network connection established to external host 142.250.190.46:443',
        affected_path: '',
        affected_command: 'npm install jsonwebtoken@9.0.2',
        requires_approval: true,
        timestamp: new Date(Date.now() - 1500000).toISOString(),
        actor_id: 'policy_engine',
      },
      {
        event_id: 'f-02',
        session_id: sessionId,
        finding_type: 'dependency_change',
        severity: 'medium',
        description: 'Modification detected in package manifest (package.json)',
        affected_path: 'package.json',
        affected_command: '',
        requires_approval: true,
        timestamp: new Date(Date.now() - 2500000).toISOString(),
        actor_id: 'policy_engine',
      },
    ];
  }
}
