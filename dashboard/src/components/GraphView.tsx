import React, { useState, useMemo } from 'react';
import {
  ContextGraphData,
  GraphNode,
  ConfidenceLevel,
} from '../types';
import {
  Search,
  Filter,
  Eye,
  Terminal,
  FileCode,
  Globe,
  AlertTriangle,
  CheckCircle2,
  GitBranch,
  Layers,
  ArrowRight,
  Info,
} from 'lucide-react';

interface GraphViewProps {
  graphData: ContextGraphData;
  onInspectNode: (node: GraphNode) => void;
  selectedNode: GraphNode | null;
}

export const GraphView: React.FC<GraphViewProps> = ({
  graphData,
  onInspectNode,
  selectedNode,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterConfidence, setFilterConfidence] = useState<string>('all');

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter((node) => {
      const matchSearch =
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.node_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.actor_id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchType = filterType === 'all' || node.node_type === filterType;
      const matchConfidence =
        filterConfidence === 'all' || node.confidence === filterConfidence;
      return matchSearch && matchType && matchConfidence;
    });
  }, [graphData.nodes, searchQuery, filterType, filterConfidence]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'task_intent':
        return <Layers size={14} color="#06b6d4" />;
      case 'agent_session':
        return <Eye size={14} color="#a855f7" />;
      case 'command':
        return <Terminal size={14} color="#3b82f6" />;
      case 'filesystem_mutation':
      case 'source_file':
        return <FileCode size={14} color="#10b981" />;
      case 'network_request':
        return <Globe size={14} color="#f59e0b" />;
      case 'policy_finding':
      case 'incident':
        return <AlertTriangle size={14} color="#f43f5e" />;
      case 'test_result':
        return <CheckCircle2 size={14} color="#10b981" />;
      default:
        return <GitBranch size={14} color="#94a3b8" />;
    }
  };

  const getConfidenceBadge = (confidence: ConfidenceLevel) => {
    switch (confidence) {
      case 'high':
        return <span className="badge badge-high">High Telemetry</span>;
      case 'medium':
        return <span className="badge badge-medium">Medium Correlation</span>;
      case 'low':
        return <span className="badge badge-low">Low Inferred</span>;
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 380px' : '1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* Main Graph Viewport */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Controls Toolbar */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '220px' }}>
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search nodes by label, actor, type, or file path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-dim)',
                borderRadius: '8px',
                padding: '6px 12px',
                color: 'var(--text-main)',
                fontSize: '13px',
                width: '100%',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '6px',
                  padding: '4px 8px',
                  color: 'var(--text-main)',
                  fontSize: '12px',
                  outline: 'none',
                }}
              >
                <option value="all">All Node Types</option>
                <option value="task_intent">Task Intent</option>
                <option value="agent_session">Agent Session</option>
                <option value="command">Command</option>
                <option value="filesystem_mutation">File Mutation</option>
                <option value="network_request">Network Request</option>
                <option value="policy_finding">Policy Finding</option>
                <option value="test_result">Test Result</option>
              </select>
            </div>

            <select
              value={filterConfidence}
              onChange={(e) => setFilterConfidence(e.target.value)}
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-dim)',
                borderRadius: '6px',
                padding: '4px 8px',
                color: 'var(--text-main)',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="all">All Confidence</option>
              <option value="high">High (Direct Telemetry)</option>
              <option value="medium">Medium (Correlated)</option>
              <option value="low">Low (Inferred)</option>
            </select>

            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Showing <strong style={{ color: 'var(--accent-cyan)' }}>{filteredNodes.length}</strong> / {graphData.nodes.length} Nodes
            </div>
          </div>
        </div>

        {/* Node Grid & Graph Canvas */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '12px', alignContent: 'start' }}>
          {filteredNodes.map((node) => {
            const isSelected = selectedNode?.node_id === node.node_id;
            const connectedEdges = graphData.edges.filter(
              (e) => e.source_node_id === node.node_id || e.target_node_id === node.node_id
            );

            return (
              <div
                key={node.node_id}
                onClick={() => onInspectNode(node)}
                className="glass-panel"
                style={{
                  padding: '14px',
                  cursor: 'pointer',
                  border: isSelected ? '1px solid var(--accent-cyan)' : '1px solid var(--border-dim)',
                  boxShadow: isSelected ? '0 0 20px var(--accent-cyan-glow)' : 'none',
                  background: isSelected ? 'rgba(6, 182, 212, 0.08)' : 'var(--bg-card)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {getNodeIcon(node.node_type)}
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      {node.node_type.replace('_', ' ')}
                    </span>
                  </div>
                  {getConfidenceBadge(node.confidence)}
                </div>

                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)', lineHeight: 1.4 }}>
                  {node.label}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-dim)', paddingTop: '4px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                  <span className="font-mono">Actor: {node.actor_id}</span>
                  <span>{connectedEdges.length} links</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Slide-out Inspector Drawer */}
      {selectedNode && (
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', overflowY: 'auto', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Info size={16} color="var(--accent-cyan)" />
              <h2 className="font-heading" style={{ fontSize: '15px', fontWeight: 600 }}>
                Node Provenance
              </h2>
            </div>
            <button
              onClick={() => onInspectNode(selectedNode)}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}
            >
              &times;
            </button>
          </div>

          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Type & Confidence
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontWeight: 600, fontSize: '14px' }}>{selectedNode.node_type}</span>
              {getConfidenceBadge(selectedNode.confidence)}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Canonical Label
            </span>
            <p style={{ fontSize: '13px', marginTop: '4px', color: 'var(--text-main)', background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
              {selectedNode.label}
            </p>
          </div>

          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Cryptographic Content Hash
            </span>
            <div className="font-mono" style={{ fontSize: '10px', marginTop: '4px', wordBreak: 'break-all', background: 'rgba(0,0,0,0.4)', padding: '6px 8px', borderRadius: '6px', color: 'var(--accent-cyan)' }}>
              {selectedNode.content_hash || 'SHA-256 verified in event ledger'}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Causal Relationships
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' }}>
              {graphData.edges
                .filter((e) => e.source_node_id === selectedNode.node_id || e.target_node_id === selectedNode.node_id)
                .map((edge) => {
                  const isOutgoing = edge.source_node_id === selectedNode.node_id;
                  const targetId = isOutgoing ? edge.target_node_id : edge.source_node_id;
                  const otherNode = graphData.nodes.find((n) => n.node_id === targetId);

                  return (
                    <div
                      key={edge.edge_id}
                      style={{
                        padding: '8px',
                        background: 'rgba(255,255,255,0.03)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-dim)',
                        fontSize: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '11px' }}>
                        {isOutgoing ? <span>OUTGOING:</span> : <span>INCOMING:</span>}
                        <span className="font-mono" style={{ color: 'var(--accent-amber)' }}>{edge.edge_type}</span>
                        <ArrowRight size={10} />
                      </div>
                      <div style={{ marginTop: '2px', color: 'var(--text-main)', fontSize: '12px' }}>
                        {otherNode?.label || targetId}
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
