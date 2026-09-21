import React, { useState, useEffect, useRef, useCallback } from 'react';
import { api, ApiError, setApiTokenOverride, setApiToken, TIMELINE_TAIL_EVENTS } from './api/client';
import {
  SessionInfo,
  ContextGraphData,
  TimelineEvent,
  PolicyFinding,
  GraphNode,
  EvidencePath,
  BlastRadiusResult,
  ComplianceBundle,
  CollusionCandidate,
  IncidentSummary,
  ProjectionVerdict,
  RetroScanResponse,
  SessionBrief,
} from './types';
import { Navbar } from './components/Navbar';
import { GraphView } from './components/GraphView';
import { Timeline } from './components/Timeline';
import { IncidentPanel } from './components/IncidentPanel';
import { DiffPanel } from './components/DiffPanel';
import { ReviewLoopView } from './components/ReviewLoopView';
import { ApprovalGateModal } from './components/ApprovalGateModal';
import { ForensicReportModal } from './components/ForensicReportModal';
import { ObservabilityGapsBanner } from './components/ObservabilityGapsBanner';
import { AuditPanel } from './components/AuditPanel';
import { AlertCircle, RefreshCw, X } from 'lucide-react';

const LoadingShell: React.FC = () => (
  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', margin: '0 16px 16px 16px' }}>
    <div className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="skeleton" style={{ width: '45%', height: '14px' }} />
      <div className="skeleton" style={{ width: '100%', height: '120px' }} />
      <div className="skeleton" style={{ width: '80%', height: '120px' }} />
      <div className="skeleton" style={{ width: '60%', height: '120px' }} />
    </div>
    <div className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="skeleton" style={{ width: '35%', height: '14px' }} />
      <div className="skeleton" style={{ width: '100%', height: '200px' }} />
      <div className="skeleton" style={{ width: '70%', height: '80px' }} />
    </div>
  </div>
);

export const App: React.FC = () => {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [currentSession, setCurrentSession] = useState<SessionInfo | null>(null);
  const [graphData, setGraphData] = useState<ContextGraphData | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [findings, setFindings] = useState<PolicyFinding[]>([]);
  const [causalPaths, setCausalPaths] = useState<EvidencePath[]>([]);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusResult | null>(null);
  // Audit plane (brief / incidents / collusion / retro-scan / compliance manifest)
  const [brief, setBrief] = useState<SessionBrief | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [collusion, setCollusion] = useState<CollusionCandidate[]>([]);
  const [retroScan, setRetroScan] = useState<RetroScanResponse | null>(null);
  const [retroScanning, setRetroScanning] = useState<boolean>(false);
  const [compliance, setCompliance] = useState<ComplianceBundle | null>(null);
  const [projection, setProjection] = useState<ProjectionVerdict | null>(null);

  const [activeTab, setActiveTab] = useState<string>('graph');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [approvalFinding, setApprovalFinding] = useState<PolicyFinding | null>(null);
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [livePolling, setLivePolling] = useState<boolean>(true);
  const [connectionError, setConnectionError] = useState<string>('');
  const [tokenDraft, setTokenDraft] = useState('');

  // The daemon rejects unauthenticated requests; the token lives in
  // ~/.agenttrace/api_token and is held for this tab session. Persisting to
  // sessionStorage matters: keeping it only in a window variable meant every
  // refresh silently dropped the token and each 2.5s live poll re-errored
  // with 401s. sessionStorage survives refresh but dies with the tab, so the
  // credential still never outlives the operator's session.
  const handleSaveToken = useCallback(() => {
    const trimmed = tokenDraft.trim();
    if (!trimmed) return;
    setApiTokenOverride(trimmed);
    setApiToken(trimmed);
    setTokenDraft('');
    setConnectionError('');
    loadSessions();
  }, [tokenDraft]);
  // False when the daemon could not be reached for session data — views must
  // render "UNVERIFIED" instead of treating missing data as compliance.
  const [dataVerified, setDataVerified] = useState<boolean>(true);

  const requestIdRef = useRef<number>(0);
  const pollInFlightRef = useRef<boolean>(false);
  const currentSessionIdRef = useRef<string | null>(null);
  currentSessionIdRef.current = currentSession?.session_id || null;

  // Surface the live session first: an operator opening the dashboard while an
  // agent works should land on the active recording, not the newest sealed one.
  const pickInitialSession = (list: SessionInfo[]): SessionInfo =>
    list.find((s) => s.status === 'active') ?? list[0];

  // Load Sessions on Mount
  useEffect(() => {
    loadSessions();
  }, []);

  // Load Session Data when Current Session Changes
  useEffect(() => {
    if (currentSession) {
      loadSessionData(currentSession.session_id, true);
    }
  }, [currentSession]);

  const loadSessions = async () => {
    setLoading(true);
    setConnectionError('');
    try {
      const list = await api.getSessions();
      setSessions(list);
      if (list.length > 0 && !currentSessionIdRef.current) {
        setCurrentSession(pickInitialSession(list));
      }
    } catch (err: unknown) {
      setConnectionError(
        err instanceof Error ? err.message : 'Unable to connect to local AgentTrace daemon.'
      );
    } finally {
      setLoading(false);
    }
  };

  const loadSessionData = useCallback(
    async (sessionId: string, showSpinner: boolean = false, isLightPoll: boolean = false) => {
    const currentRequestId = ++requestIdRef.current;
    if (showSpinner) {
      setLoading(true);
    }
    setConnectionError('');

    try {
      // Load-shedding for long sessions: the heavy payloads (graph, collusion)
      // and the O(n) analysis enrichment only refresh on initial load or the
      // slow 30s cadence; the fast 2.5s live poll refreshes only the cheap
      // tail endpoints. Refetching the whole graph + blast radius every 2.5s
      // is what made the dashboard lag and the tab's memory balloon.
      const heavy = !isLightPoll;
      const [graph, time, fnd, briefData, incData, colData, projData] = await Promise.all([
        heavy ? api.getGraph(sessionId) : Promise.resolve(null),
        // The most recent window, not the daemon's default FIRST page: an
        // unparameterized fetch leaves a multi-thousand-event live session
        // pinned to its oldest (days-old) events, which read as "live".
        api.getTimelineTail(sessionId, TIMELINE_TAIL_EVENTS),
        api.getFindings(sessionId),
        api.getSessionBrief(sessionId),
        api.getIncidents(sessionId),
        heavy ? api.getCollusion(sessionId) : Promise.resolve(null),
        api.getProjectionVerdict(sessionId),
      ]);

      // Guard against stale asynchronous response
      if (currentRequestId !== requestIdRef.current) return;

      setDataVerified(true);
      if (graph) setGraphData(graph);
      setTimeline(time);
      setFindings(fnd);
      setBrief(briefData);
      setIncidents(incData);
      if (colData) setCollusion(colData);
      setProjection(projData);

      // Causal & blast radius for selected or first node — O(n) analysis, so
      // it belongs to the heavy cadence only, never the 2.5s live poll.
      if (heavy) {
        const targetNodeId =
          selectedNode?.node_id ||
          (graph && graph.nodes.length > 0 ? graph.nodes[0].node_id : null);
        if (targetNodeId) {
          try {
            const path = await api.explainNode(sessionId, targetNodeId);
            const br = await api.analyzeBlastRadius(sessionId, targetNodeId);
            if (currentRequestId === requestIdRef.current) {
              setCausalPaths(path ? [path] : []);
              setBlastRadius(br);
            }
          } catch {
            // Optional causal enrichment
          }
        }
      }
    } catch (err: unknown) {
      if (currentRequestId === requestIdRef.current) {
        if (err instanceof ApiError && err.status === 401) {
          setConnectionError(err.message);
          setLoading(false);
          return;
        }
        // The daemon is unreachable: do NOT substitute empty data — an empty
        // timeline/findings view would be read as a clean audit.
        setDataVerified(false);
        setGraphData(null);
        setTimeline([]);
        setFindings([]);
        setCausalPaths([]);
        setBlastRadius(null);
        setBrief(null);
        setIncidents([]);
        setCollusion([]);
        setRetroScan(null);
        setCompliance(null);
        setProjection(null);
        setConnectionError(err instanceof Error ? err.message : 'UNVERIFIED — daemon unreachable');
      }
    } finally {
      if (currentRequestId === requestIdRef.current && showSpinner) {
        setLoading(false);
      }
    }
    },
    [selectedNode]
  );

  // Live Auto-Polling Loop (Polls every 2.5 seconds when active). The in-flight
  // guard matters: when the daemon is slow or unreachable, a 2.5s interval
  // stacks overlapping request storms (every pending fetch re-throws the same
  // CSP/network error) and floods the console with duplicated failures.
  useEffect(() => {
    if (!livePolling) return;

    const interval = setInterval(async () => {
      if (pollInFlightRef.current) return;
      pollInFlightRef.current = true;
      try {
        // 1. Refresh sessions list in background
        try {
          const list = await api.getSessions();
          setSessions(list);
          if (list.length > 0 && !currentSessionIdRef.current) {
            setCurrentSession(pickInitialSession(list));
          }
        } catch {
          // Daemon offline
        }

        // 2. Refresh active session data — light cadence: only the cheap tail
        // endpoints, so a long session stays responsive without ballooning.
        if (currentSessionIdRef.current) {
          loadSessionData(currentSessionIdRef.current, false, true);
        }
      } finally {
        pollInFlightRef.current = false;
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [livePolling, loadSessionData]);

  const handleInspectNode = async (node: GraphNode) => {
    if (selectedNode?.node_id === node.node_id) {
      setSelectedNode(null);
    } else {
      const currentRequestId = ++requestIdRef.current;
      setSelectedNode(node);
      if (currentSession) {
        try {
          const path = await api.explainNode(currentSession.session_id, node.node_id);
          const br = await api.analyzeBlastRadius(currentSession.session_id, node.node_id);
          // Guard against stale responses (user inspected another node or
          // switched sessions while this request was in flight).
          if (currentRequestId === requestIdRef.current) {
            setCausalPaths(path ? [path] : []);
            setBlastRadius(br);
          }
        } catch {
          // Graceful fallback
        }
      }
    }
  };

  const handleConfirmApproval = async (
    findingId: string,
    approved: boolean,
    reason: string,
    scope: string
  ) => {
    if (!currentSession) return;
    try {
      // Operator-channel authentication (item 4): fetch a fresh single-use
      // challenge bound to this finding+decision and present it with the
      // grant — a bearer token alone only yields a short-lived approval.
      const challenge = await api.issueApprovalChallenge(
        currentSession.session_id,
        findingId,
        approved ? 'approved' : 'denied'
      );
      const res = await api.recordApproval(
        currentSession.session_id,
        findingId,
        approved,
        reason,
        scope,
        [],
        [],
        challenge.operator_challenge
      );
      if (res && res.event_hash) {
        setFindings((prev) => prev.filter((f) => f.finding_id !== findingId));
        loadSessionData(currentSession.session_id, true);
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to record approval in ledger');
    }
  };

  // Stop recording: POST /sessions/{id}/stop seals the ledger, then the
  // session record is refetched so the LIVE badge flips to SEALED without
  // a manual refresh.
  const handleStopSession = async (sessionId: string): Promise<void> => {
    try {
      await api.stopSession(sessionId);
      const fresh = await api.getSession(sessionId).catch(() => null);
      if (fresh) setCurrentSession(fresh);
      await loadSessions();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to stop session');
    }
  };

  // Retro-scan (ant.md P1 #4): re-run the two-stage wide-net detector sweep
  // over stored history. Real POST /rescan — never client-side synthesis.
  const handleRunRetroScan = useCallback(async () => {
    if (!currentSession || retroScanning) return;
    setRetroScanning(true);
    try {
      const res = await api.runRetroScan([currentSession.session_id], false);
      setRetroScan(res);
    } catch {
      setRetroScan(null);
    } finally {
      setRetroScanning(false);
    }
  }, [currentSession, retroScanning]);

  // Start recording a new session (Navbar "New Audit"). The daemon boots its
  // observer stack in POST /sessions; on success the directory is re-fetched
  // and the fresh live session is selected so the operator lands on it.
  // Every piece of state below belongs to ONE session. Leaving any of it in
  // place across a session change is how one session's 500-event timeline was
  // rendered — and exported — as another session's audit trail. Both entry
  // points that change the current session (select and create) must clear the
  // same set, so it lives here instead of being repeated in each and drifting.
  const resetSessionState = useCallback(() => {
    setGraphData(null);
    setTimeline([]);
    setFindings([]);
    setBrief(null);
    setIncidents([]);
    setCollusion([]);
    setProjection(null);
    setCausalPaths([]);
    setBlastRadius(null);
    setCompliance(null);
    setRetroScan(null);
    setSelectedNode(null);
  }, []);

  const handleCreateSession = useCallback(
    async (workspacePath: string, taskDescription: string) => {
      const created = await api.createSession(workspacePath, taskDescription);
      const list = await api.getSessions();
      setSessions(list);
      setCurrentSession(created);
      resetSessionState();
    },
    [resetSessionState]
  );

  // ant.md P2 #8: fetch the compliance evidence manifest from the real
  // GET /sessions/{id}/compliance route. Failure surfaces as "null" (panel
  // shows the honest "not generated" state), never synthetic data.
  useEffect(() => {
    let active = true;
    const sid = currentSession?.session_id;
    if (!sid) return;
    api
      .getComplianceBundle(sid)
      .then((bundle) => {
        if (active) setCompliance(bundle);
      })
      .catch(() => {
        if (active) setCompliance(null);
      });
    return () => {
      active = false;
    };
  }, [currentSession?.session_id]);

  // Skeleton when there is nothing to show yet OR a fresh heavy load is still
  // in flight: after saving the token the graph/collusion/brief bundle can
  // take seconds (server-side), and without this the operator stares at a
  // blank shell — which read as "the app did nothing". Light polls never set
  // `loading`, so the skeleton cannot flash during normal live updates.
  const showInitialSkeleton = loading && !connectionError && !graphData;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: '#000000' }}>
      {/* Top Navigation */}
      <Navbar
        sessions={sessions}
        currentSession={currentSession}
        onSelectSession={(s) => {
          setCurrentSession(s);
          // Everything the previous session left behind is cleared here; see
          // resetSessionState for why leaving any of it is not cosmetic.
          resetSessionState();
        }}
        onCreateSession={handleCreateSession}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onOpenReport={() => setShowReportModal(true)}
        onRefresh={() => currentSession && loadSessionData(currentSession.session_id, true)}
        loading={loading}
        livePolling={livePolling}
        onToggleLivePolling={() => setLivePolling((prev) => !prev)}
        onStopSession={handleStopSession}
      />

      {/* Offline / Auth Alert Banner */}
      {connectionError && (
        <div
          role="alert"
          className="glass-panel"
          style={{
            margin: '0 16px 10px 16px',
            padding: '10px 14px',
            borderColor: '#ffffff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            animation: 'none',
          }}
        >
          <div className="flex" style={{ gap: '9px', minWidth: 0 }}>
            <AlertCircle size={15} color="#ffffff" style={{ flexShrink: 0 }} />
            <span style={{ fontSize: '12px', color: '#ffffff' }}>{connectionError}</span>
          </div>
          <div className="flex" style={{ gap: '6px', flexShrink: 0 }}>
            <input
              type="password"
              value={tokenDraft}
              onChange={(e) => setTokenDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSaveToken();
              }}
              placeholder="paste ~/.agenttrace/api_token"
              aria-label="Daemon API token"
              spellCheck={false}
              autoComplete="off"
              style={{
                width: '230px',
                padding: '4px 8px',
                fontSize: '11px',
                borderRadius: '6px',
                border: '1px solid rgba(255,255,255,0.25)',
                background: 'rgba(0,0,0,0.35)',
                color: '#fff',
              }}
            />
            <button onClick={handleSaveToken} className="btn btn-secondary btn-sm">
              Save token
            </button>
            <button onClick={loadSessions} className="btn btn-secondary btn-sm">
              <RefreshCw size={11} /> Retry
            </button>
            <button onClick={() => setConnectionError('')} className="btn btn-ghost btn-icon" aria-label="Dismiss alert">
              <X size={13} />
            </button>
          </div>
        </div>
      )}

      {/* Observability gaps: what the adapter could not see — surfaced as a
          feature, never hidden or fabricated around. */}
      {currentSession && !showInitialSkeleton && (
        <ObservabilityGapsBanner session={currentSession} />
      )}

      {/* Main Content Area by Tab */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {showInitialSkeleton ? (
          <LoadingShell />
        ) : (
          <>
            {activeTab === 'graph' && (
              <GraphView
                graphData={graphData || { session_id: currentSession?.session_id || '', nodes: [], edges: [] }}
                onInspectNode={handleInspectNode}
                selectedNode={selectedNode}
                currentSession={currentSession}
                livePolling={livePolling}
              />
            )}

            {activeTab === 'timeline' && (
              <Timeline
                events={timeline}
                onSelectEvent={(e) => {
                  // Find corresponding graph node if available
                  const matchingNode = graphData?.nodes.find(
                    (n) => n.data?.event_id === e.event_id || n.label.includes(e.event_type)
                  );
                  if (matchingNode) {
                    setSelectedNode(matchingNode);
                    setActiveTab('graph');
                  }
                }}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentPanel
                findings={findings}
                causalPaths={causalPaths}
                unverified={!dataVerified}
                onRequestApproval={(f) => setApprovalFinding(f)}
              />
            )}

            {activeTab === 'review_loop' && (
              <ReviewLoopView sessionId={currentSession?.session_id || null} />
            )}

            {activeTab === 'diff' && (
              <DiffPanel sessionId={currentSession?.session_id} blastRadius={blastRadius} />
            )}

            {activeTab === 'audit' && (
              <AuditPanel
                brief={brief}
                incidents={incidents}
                collusion={collusion}
                retroScan={retroScan}
                retroScanning={retroScanning}
                compliance={compliance}
                findings={findings}
                projection={projection}
                unverified={!dataVerified}
                onRunRetroScan={() => void handleRunRetroScan()}
              />
            )}
          </>
        )}
      </main>

      {/* Modals */}
      <ApprovalGateModal
        finding={approvalFinding}
        onClose={() => setApprovalFinding(null)}
        onConfirm={handleConfirmApproval}
      />

      {showReportModal && (
        <ForensicReportModal
          session={currentSession}
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
};
