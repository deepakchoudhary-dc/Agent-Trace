import React, { useState, useEffect, useRef, useCallback } from 'react';
import { api } from './api/client';
import {
  SessionInfo,
  ContextGraphData,
  TimelineEvent,
  PolicyFinding,
  GraphNode,
  EvidencePath,
  BlastRadiusResult,
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

  const [activeTab, setActiveTab] = useState<string>('graph');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [approvalFinding, setApprovalFinding] = useState<PolicyFinding | null>(null);
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [livePolling, setLivePolling] = useState<boolean>(true);
  const [connectionError, setConnectionError] = useState<string>('');
  // False when the daemon could not be reached for session data — views must
  // render "UNVERIFIED" instead of treating missing data as compliance.
  const [dataVerified, setDataVerified] = useState<boolean>(true);

  const requestIdRef = useRef<number>(0);
  const currentSessionIdRef = useRef<string | null>(null);
  currentSessionIdRef.current = currentSession?.session_id || null;

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
        setCurrentSession(list[0]);
      }
    } catch (err: unknown) {
      setConnectionError(
        err instanceof Error ? err.message : 'Unable to connect to local AgentTrace daemon.'
      );
    } finally {
      setLoading(false);
    }
  };

  const loadSessionData = useCallback(async (sessionId: string, showSpinner: boolean = false) => {
    const currentRequestId = ++requestIdRef.current;
    if (showSpinner) {
      setLoading(true);
    }
    setConnectionError('');

    try {
      const [graph, time, fnd] = await Promise.all([
        api.getGraph(sessionId),
        api.getTimeline(sessionId),
        api.getFindings(sessionId),
      ]);

      // Guard against stale asynchronous response
      if (currentRequestId !== requestIdRef.current) return;

      setDataVerified(true);
      setGraphData(graph);
      setTimeline(time);
      setFindings(fnd);

      // Causal & blast radius for selected or first node
      const targetNodeId = selectedNode?.node_id || (graph.nodes.length > 0 ? graph.nodes[0].node_id : null);
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
    } catch (err: unknown) {
      if (currentRequestId === requestIdRef.current) {
        // The daemon is unreachable: do NOT substitute empty data — an empty
        // timeline/findings view would be read as a clean audit.
        setDataVerified(false);
        setGraphData(null);
        setTimeline([]);
        setFindings([]);
        setCausalPaths([]);
        setBlastRadius(null);
        setConnectionError(err instanceof Error ? err.message : 'UNVERIFIED — daemon unreachable');
      }
    } finally {
      if (currentRequestId === requestIdRef.current && showSpinner) {
        setLoading(false);
      }
    }
  }, [selectedNode]);

  // Live Auto-Polling Loop (Polls every 2.5 seconds when active)
  useEffect(() => {
    if (!livePolling) return;

    const interval = setInterval(async () => {
      // 1. Refresh sessions list in background
      try {
        const list = await api.getSessions();
        setSessions(list);
        if (list.length > 0 && !currentSessionIdRef.current) {
          setCurrentSession(list[0]);
        }
      } catch {
        // Daemon offline
      }

      // 2. Refresh active session data
      if (currentSessionIdRef.current) {
        loadSessionData(currentSessionIdRef.current, false);
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
      const res = await api.recordApproval(currentSession.session_id, findingId, approved, reason, scope);
      if (res && res.event_hash) {
        setFindings((prev) => prev.filter((f) => f.finding_id !== findingId));
        loadSessionData(currentSession.session_id, true);
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to record approval in ledger');
    }
  };

  const showInitialSkeleton = loading && sessions.length === 0 && !connectionError;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: '#000000' }}>
      {/* Top Navigation */}
      <Navbar
        sessions={sessions}
        currentSession={currentSession}
        onSelectSession={(s) => {
          setCurrentSession(s);
          setSelectedNode(null);
          // The previous session's causal analysis must not leak into the
          // newly selected session's views.
          setCausalPaths([]);
          setBlastRadius(null);
        }}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onOpenReport={() => setShowReportModal(true)}
        onRefresh={() => currentSession && loadSessionData(currentSession.session_id, true)}
        loading={loading}
        livePolling={livePolling}
        onToggleLivePolling={() => setLivePolling((prev) => !prev)}
      />

      {/* Offline Alert Banner */}
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
          graphData={graphData}
          timeline={timeline}
          findings={findings}
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
};
