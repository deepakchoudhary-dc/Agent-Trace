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
import { AlertCircle, RefreshCw } from 'lucide-react';

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
        api.getGraph(sessionId).catch(() => ({ session_id: sessionId, nodes: [], edges: [] })),
        api.getTimeline(sessionId).catch(() => []),
        api.getFindings(sessionId).catch(() => []),
      ]);

      // Guard against stale asynchronous response
      if (currentRequestId !== requestIdRef.current) return;

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
        setConnectionError(err instanceof Error ? err.message : 'Failed loading session data');
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
      setSelectedNode(node);
      if (currentSession) {
        try {
          const path = await api.explainNode(currentSession.session_id, node.node_id);
          const br = await api.analyzeBlastRadius(currentSession.session_id, node.node_id);
          setCausalPaths(path ? [path] : []);
          setBlastRadius(br);
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: '#000000' }}>
      {/* Top Navigation */}
      <Navbar
        sessions={sessions}
        currentSession={currentSession}
        onSelectSession={(s) => {
          setCurrentSession(s);
          setSelectedNode(null);
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
          style={{
            margin: '0 16px 10px 16px',
            padding: '8px 14px',
            background: '#18181b',
            border: '1px solid #ffffff',
            borderRadius: '6px',
            color: '#ffffff',
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle size={14} color="#ffffff" />
            <span>{connectionError}</span>
          </div>
          <button
            onClick={loadSessions}
            className="btn btn-secondary"
            style={{ fontSize: '10.5px', padding: '3px 8px' }}
          >
            <RefreshCw size={11} /> Retry
          </button>
        </div>
      )}

      {/* Main Content Area by Tab */}
      <main style={{ flex: 1 }}>
        {activeTab === 'graph' && (
          <GraphView
            graphData={graphData || { session_id: currentSession?.session_id || '', nodes: [], edges: [] }}
            onInspectNode={handleInspectNode}
            selectedNode={selectedNode}
          />
        )}

        {activeTab === 'timeline' && (
          <Timeline events={timeline} onSelectEvent={(e) => {
            // Find corresponding graph node if available
            const matchingNode = graphData?.nodes.find((n) => n.data?.event_id === e.event_id || n.label.includes(e.event_type));
            if (matchingNode) {
              setSelectedNode(matchingNode);
              setActiveTab('graph');
            }
          }} />
        )}

        {activeTab === 'incidents' && (
          <IncidentPanel
            findings={findings}
            causalPaths={causalPaths}
            onRequestApproval={(f) => setApprovalFinding(f)}
          />
        )}

        {activeTab === 'review_loop' && (
          <ReviewLoopView />
        )}

        {activeTab === 'diff' && (
          <DiffPanel sessionId={currentSession?.session_id} blastRadius={blastRadius} />
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
