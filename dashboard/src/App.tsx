import React, { useState, useEffect } from 'react';
import { ApiClient } from './api/client';
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

  // Load Sessions on Mount
  useEffect(() => {
    loadSessions();
  }, []);

  // Load Session Data when Current Session Changes
  useEffect(() => {
    if (currentSession) {
      loadSessionData(currentSession.session_id);
    }
  }, [currentSession]);

  const loadSessions = async () => {
    const list = await ApiClient.getSessions();
    setSessions(list);
    if (list.length > 0 && !currentSession) {
      setCurrentSession(list[0]);
    }
  };

  const loadSessionData = async (sessionId: string) => {
    const [graph, time, fnd] = await Promise.all([
      ApiClient.getGraph(sessionId),
      ApiClient.getTimeline(sessionId),
      ApiClient.getFindings(sessionId),
    ]);
    setGraphData(graph);
    setTimeline(time);
    setFindings(fnd);

    // Initial causal & blast radius for demo/first node
    if (graph.nodes.length > 0) {
      const paths = await ApiClient.getCausalExplanation(sessionId, graph.nodes[0].node_id);
      const br = await ApiClient.getBlastRadius(sessionId, graph.nodes[0].node_id);
      setCausalPaths(paths);
      setBlastRadius(br);
    }
  };

  const handleInspectNode = async (node: GraphNode) => {
    if (selectedNode?.node_id === node.node_id) {
      setSelectedNode(null);
    } else {
      setSelectedNode(node);
      if (currentSession) {
        const paths = await ApiClient.getCausalExplanation(currentSession.session_id, node.node_id);
        const br = await ApiClient.getBlastRadius(currentSession.session_id, node.node_id);
        setCausalPaths(paths);
        setBlastRadius(br);
      }
    }
  };

  const handleConfirmApproval = async (
    findingId: string,
    approved: boolean,
    reason: string,
    scope: string
  ) => {
    if (currentSession) {
      await ApiClient.recordApproval(currentSession.session_id, findingId, approved, reason, scope);
      // Remove or mark approved in local state
      setFindings((prev) => prev.filter((f) => f.event_id !== findingId));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
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
        onRefresh={() => currentSession && loadSessionData(currentSession.session_id)}
      />

      {/* Main Content Area by Tab */}
      <main style={{ flex: 1 }}>
        {activeTab === 'graph' && graphData && (
          <GraphView
            graphData={graphData}
            onInspectNode={handleInspectNode}
            selectedNode={selectedNode}
          />
        )}

        {activeTab === 'timeline' && (
          <Timeline events={timeline} />
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
          <DiffPanel blastRadius={blastRadius} />
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
