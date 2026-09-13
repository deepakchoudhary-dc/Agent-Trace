/**
 * AgentTrace API Client — Direct typed communication with local daemon.
 * Zero synthetic mock data or false verification fallbacks.
 */

import {
  BlastRadiusResult,
  CollusionCandidate,
  ComplianceBundle,
  ContextGraphData,
  DiffItem,
  EvidencePath,
  ForensicReport,
  IncidentSummary,
  PolicyFinding,
  ProjectionVerdict,
  RetroScanResponse,
  ReviewRunData,
  ReviewRunRecord,
  SessionBrief,
  SessionInfo,
  SignedForensicReport,
  TimelineEvent,
  VerificationResult,
} from '../types';

const DEFAULT_API_BASE = 'http://127.0.0.1:8765';

export function getApiBase(): string {
  if (typeof window !== 'undefined') {
    const custom = (window as unknown as { __AGENTTRACE_API_URL__?: string }).__AGENTTRACE_API_URL__;
    if (custom) return custom;
    const stored = localStorage.getItem('agenttrace_api_url');
    if (stored) return stored;
  }
  return DEFAULT_API_BASE;
}

export function setApiBase(url: string): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('agenttrace_api_url', url);
  }
}

export function getApiToken(): string | null {
  if (typeof window !== 'undefined') {
    const custom = (window as unknown as { __AGENTTRACE_TOKEN__?: string }).__AGENTTRACE_TOKEN__;
    if (custom) return custom;
    const stored = sessionStorage.getItem('agenttrace_token') || localStorage.getItem('agenttrace_token');
    if (stored) return stored;
  }
  return null;
}

export function setApiToken(token: string): void {
  if (typeof window !== 'undefined') {
    // Session-scoped only. A daemon token must not outlive the tab it was
    // issued for; localStorage persistence would leave a live credential
    // readable by any same-origin script after the operator walks away.
    sessionStorage.setItem('agenttrace_token', token);
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const apiBase = getApiBase();
  const token = getApiToken();
  const url = `${apiBase}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { 'X-AgentTrace-Token': token } : {}),
    ...(options?.headers as Record<string, string>),
  };

  try {
    const res = await fetch(url, {
      ...options,
      headers,
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: res.statusText }));
      throw new ApiError(res.status, errBody.detail || `Request failed with status ${res.status}`);
    }

    return (await res.json()) as T;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new Error(
      `AgentTrace daemon unreachable at ${apiBase}. Ensure daemon is running.`,
      { cause: err }
    );
  }
}

async function requestWithCount<T>(endpoint: string): Promise<{ items: T; total: number }> {
  const apiBase = getApiBase();
  const token = getApiToken();
  const url = `${apiBase}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { 'X-AgentTrace-Token': token } : {}),
  };

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: res.statusText }));
      throw new ApiError(res.status, errBody.detail || `Request failed with status ${res.status}`);
    }
    const items = (await res.json()) as T;
    // Prefer the server's total count header; fall back to page length only
    // when the header is absent. (The old one-liner's precedence silently
    // discarded the header — the pagination total lied.)
    const totalHeader = res.headers.get('X-Total-Count');
    const total =
      totalHeader !== null
        ? Number(totalHeader)
        : Array.isArray(items)
          ? (items as unknown[]).length
          : 0;
    return { items, total: Number.isFinite(total) ? total : (items as unknown[]).length };
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new Error(
      `AgentTrace daemon unreachable at ${apiBase}. Ensure daemon is running.`,
      { cause: err }
    );
  }
}

export const api = {
  // Session management
  async getSessions(): Promise<SessionInfo[]> {
    return request<SessionInfo[]>('/sessions');
  },

  async getSession(sessionId: string): Promise<SessionInfo> {
    return request<SessionInfo>(`/sessions/${sessionId}`);
  },

  async createSession(workspacePath: string, taskDescription?: string, agentType = 'auto'): Promise<SessionInfo> {
    return request<SessionInfo>('/sessions', {
      method: 'POST',
      body: JSON.stringify({
        workspace_path: workspacePath,
        task_description: taskDescription || '',
        agent_type: agentType,
      }),
    });
  },

  async stopSession(sessionId: string): Promise<{ status: string }> {
    return request<{ status: string }>(`/sessions/${sessionId}/stop`, {
      method: 'POST',
    });
  },

  // Context Graph
  async getGraph(sessionId: string): Promise<ContextGraphData> {
    return request<ContextGraphData>(`/sessions/${sessionId}/graph`);
  },

  // Timeline & Diffs
  async getTimeline(sessionId: string): Promise<TimelineEvent[]> {
    return request<TimelineEvent[]>(`/sessions/${sessionId}/timeline`);
  },

  async getDiffs(sessionId: string): Promise<DiffItem[]> {
    return request<DiffItem[]>(`/sessions/${sessionId}/diffs`);
  },

  // Policy Findings & Approvals
  async getFindings(sessionId: string): Promise<PolicyFinding[]> {
    return request<PolicyFinding[]>(`/sessions/${sessionId}/findings`);
  },

  async recordApproval(
    sessionId: string,
    findingId: string,
    approved: boolean,
    reason: string,
    scope: string,
    affectedPaths: string[] = [],
    affectedCommands: string[] = [],
    operatorChallenge: string = ''
  ): Promise<{ status: string; approval_id: string; event_hash: string; approved: boolean; effective_expiry_minutes?: number }> {
    return request(`/sessions/${sessionId}/approvals`, {
      method: 'POST',
      body: JSON.stringify({
        finding_id: findingId,
        approved,
        reason,
        scope,
        affected_paths: affectedPaths,
        affected_commands: affectedCommands,
        operator_challenge: operatorChallenge,
      }),
    });
  },

  async issueApprovalChallenge(
    sessionId: string,
    findingId: string,
    decision: 'approved' | 'denied'
  ): Promise<{ operator_challenge: string; ttl_seconds: number }> {
    return request(`/sessions/${sessionId}/approvals/challenge`, {
      method: 'POST',
      body: JSON.stringify({
        finding_id: findingId,
        decision,
      }),
    });
  },

  // Cryptographic Verification & Signed Forensic Reports
  async verifyChain(sessionId: string): Promise<VerificationResult> {
    return request<VerificationResult>(`/sessions/${sessionId}/verify`);
  },

  async getForensicReport(sessionId: string): Promise<ForensicReport> {
    return request<ForensicReport>(`/sessions/${sessionId}/report`);
  },

  // Causal analysis
  async explainNode(sessionId: string, nodeId: string): Promise<EvidencePath> {
    return request<EvidencePath>(`/sessions/${sessionId}/causal/${nodeId}`);
  },

  async analyzeBlastRadius(sessionId: string, nodeId: string): Promise<BlastRadiusResult> {
    return request<BlastRadiusResult>(`/sessions/${sessionId}/blast_radius/${nodeId}`);
  },

  // Review loop (P0-7): real artifacts & verdicts
  async runReview(sessionId: string, maxIterations = 3): Promise<ReviewRunData> {
    return request<ReviewRunData>(`/sessions/${sessionId}/review`, {
      method: 'POST',
      body: JSON.stringify({ max_iterations: maxIterations }),
    });
  },

  async getReviewRun(sessionId: string): Promise<ReviewRunRecord> {
    return request<ReviewRunRecord>(`/sessions/${sessionId}/review`);
  },

  // -- ant.md P2 #8: verifiable compliance evidence manifest (EU AI Act / ISO 42001 / SOC 2) --
  async getComplianceBundle(sessionId: string): Promise<ComplianceBundle> {
    return request<ComplianceBundle>(`/sessions/${sessionId}/compliance`);
  },

  // -- ant.md P1 #4: two-stage wide-net retro-scan over stored history --
  async runRetroScan(sessionIds?: string[], exhaustive = false): Promise<RetroScanResponse> {
    return request<RetroScanResponse>('/rescan', {
      method: 'POST',
      body: JSON.stringify({ session_ids: sessionIds, exhaustive }),
    });
  },

  // -- Collusion correlation: observable coordination half only --
  async getCollusion(sessionId: string): Promise<CollusionCandidate[]> {
    const { items } = await requestWithCount<CollusionCandidate[]>(`/sessions/${sessionId}/collusion`);
    return items;
  },

  // -- Multi-stage correlated incidents (evidence-backed) --
  async getIncidents(sessionId: string): Promise<IncidentSummary[]> {
    const { items } = await requestWithCount<IncidentSummary[]>(`/sessions/${sessionId}/incidents`);
    return items;
  },

  // -- Operator briefing: what happened, what needs attention --
  async getSessionBrief(sessionId: string): Promise<SessionBrief> {
    return request<SessionBrief>(`/sessions/${sessionId}/brief`);
  },

  // -- Projection MAC verdict: checked:false means never committed, not a pass --
  async getProjectionVerdict(sessionId: string): Promise<ProjectionVerdict> {
    return request<ProjectionVerdict>(`/sessions/${sessionId}/projection/verify`);
  },

  // -- Sealed, chain-bound forensic report (incl. reasoning trail + incidents) --
  async getSignedForensicReport(sessionId: string): Promise<SignedForensicReport> {
    return request<SignedForensicReport>(`/sessions/${sessionId}/report`);
  },
};
