import React, { useState, useMemo, useRef } from 'react';
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
  ZoomIn,
  ZoomOut,
  Maximize2,
  Grid,
  Share2,
  EyeOff,
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
  const [hideBaselineFiles, setHideBaselineFiles] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'visual' | 'cards'>('visual');
  const [zoom, setZoom] = useState(0.85);
  const [pan, setPan] = useState({ x: 50, y: 30 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef({ x: 0, y: 0 });

  // Custom dragged node positions override
  const [customPositions, setCustomPositions] = useState<Record<string, { x: number; y: number }>>({});
  const draggedNodeIdRef = useRef<string | null>(null);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter((node) => {
      if (hideBaselineFiles && node.node_type === 'source_file') {
        return false;
      }
      const matchSearch =
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.node_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.actor_id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchType = filterType === 'all' || node.node_type === filterType;
      const matchConfidence =
        filterConfidence === 'all' || node.confidence === filterConfidence;
      return matchSearch && matchType && matchConfidence;
    });
  }, [graphData.nodes, searchQuery, filterType, filterConfidence, hideBaselineFiles]);

  // High-fidelity wrapping tiered grid layout engine (Guarantees zero overlapping)
  const nodePositions = useMemo(() => {
    const posMap = new Map<string, { x: number; y: number }>();
    if (filteredNodes.length === 0) return posMap;

    // Define tiers
    const tierDefs: Array<{ types: string[]; label: string }> = [
      { types: ['task_intent', 'task_constraints'], label: 'Task Intent' },
      { types: ['agent_session', 'invocation'], label: 'Agent Session' },
      { types: ['tool_request', 'tool_result'], label: 'Tool Invocations' },
      { types: ['command', 'process'], label: 'Commands & Processes' },
      { types: ['filesystem_mutation', 'package_change', 'config_change'], label: 'Mutations' },
      { types: ['policy_finding', 'incident', 'approval'], label: 'Policy Findings & Approvals' },
      { types: ['network_request', 'test_result', 'build_result'], label: 'Network & Verification' },
      { types: ['source_file', 'workspace_snapshot', 'git_commit_diff', 'contextual_document', 'untrusted_content'], label: 'Baseline & Context' },
    ];

    const typeToTier = new Map<string, number>();
    tierDefs.forEach((td, idx) => {
      td.types.forEach((t) => typeToTier.set(t, idx));
    });

    // Group nodes into tiers
    const tierBuckets: GraphNode[][] = tierDefs.map(() => []);
    const unclassified: GraphNode[] = [];

    filteredNodes.forEach((node) => {
      const tIdx = typeToTier.get(node.node_type);
      if (tIdx !== undefined) {
        tierBuckets[tIdx].push(node);
      } else {
        unclassified.push(node);
      }
    });

    let currentY = 70;
    const centerX = 500;
    const colSpacing = 170;
    const rowSpacing = 95;
    const maxColsPerRow = 5;

    tierBuckets.forEach((bucket) => {
      if (bucket.length === 0) return;

      const totalInTier = bucket.length;
      const numRows = Math.ceil(totalInTier / maxColsPerRow);

      for (let r = 0; r < numRows; r++) {
        const rowStartIdx = r * maxColsPerRow;
        const rowNodes = bucket.slice(rowStartIdx, rowStartIdx + maxColsPerRow);
        const countInRow = rowNodes.length;
        const startX = centerX - ((countInRow - 1) * colSpacing) / 2;

        rowNodes.forEach((node, c) => {
          posMap.set(node.node_id, {
            x: startX + c * colSpacing,
            y: currentY,
          });
        });

        currentY += rowSpacing;
      }

      currentY += 30; // Extra spacing between distinct tiers
    });

    if (unclassified.length > 0) {
      const count = unclassified.length;
      const cols = Math.min(maxColsPerRow, count);
      const startX = centerX - ((cols - 1) * colSpacing) / 2;
      unclassified.forEach((node, idx) => {
        const r = Math.floor(idx / cols);
        const c = idx % cols;
        posMap.set(node.node_id, {
          x: startX + c * colSpacing,
          y: currentY + r * rowSpacing,
        });
      });
    }

    // Apply any manually dragged node positions
    Object.entries(customPositions).forEach(([id, pos]) => {
      posMap.set(id, pos);
    });

    return posMap;
  }, [filteredNodes, customPositions]);

  // Connected nodes & edges for selected node
  const { connectedNodeIds, connectedEdgeIds } = useMemo(() => {
    if (!selectedNode) {
      return { connectedNodeIds: new Set<string>(), connectedEdgeIds: new Set<string>() };
    }
    const nIds = new Set<string>([selectedNode.node_id]);
    const eIds = new Set<string>();

    graphData.edges.forEach((edge) => {
      if (edge.source_node_id === selectedNode.node_id) {
        nIds.add(edge.target_node_id);
        eIds.add(edge.edge_id);
      }
      if (edge.target_node_id === selectedNode.node_id) {
        nIds.add(edge.source_node_id);
        eIds.add(edge.edge_id);
      }
    });

    return { connectedNodeIds: nIds, connectedEdgeIds: eIds };
  }, [selectedNode, graphData.edges]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'task_intent':
        return <Layers size={14} color="#ffffff" />;
      case 'agent_session':
        return <Eye size={14} color="#ffffff" />;
      case 'command':
        return <Terminal size={14} color="#ffffff" />;
      case 'filesystem_mutation':
      case 'source_file':
        return <FileCode size={14} color="#ffffff" />;
      case 'network_request':
        return <Globe size={14} color="#ffffff" />;
      case 'policy_finding':
      case 'incident':
        return <AlertTriangle size={14} color="#ffffff" />;
      case 'test_result':
        return <CheckCircle2 size={14} color="#ffffff" />;
      default:
        return <GitBranch size={14} color="#a1a1aa" />;
    }
  };

  const getConfidenceBadge = (confidence: ConfidenceLevel) => {
    switch (confidence) {
      case 'high':
        return <span className="badge badge-high">Direct Telemetry</span>;
      case 'medium':
        return <span className="badge badge-medium">Correlated</span>;
      case 'low':
        return <span className="badge badge-low">Inferred</span>;
    }
  };

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (draggedNodeIdRef.current) return;
    setIsDragging(true);
    dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNodeIdRef.current) {
      // Dragging a specific node
      const currentPos = nodePositions.get(draggedNodeIdRef.current) || { x: 500, y: 300 };
      setCustomPositions((prev) => ({
        ...prev,
        [draggedNodeIdRef.current!]: {
          x: currentPos.x + e.movementX / zoom,
          y: currentPos.y + e.movementY / zoom,
        },
      }));
    } else if (isDragging) {
      setPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    draggedNodeIdRef.current = null;
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 390px' : '1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* Main Graph Canvas */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Controls Toolbar */}
        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '220px' }}>
            <Search size={15} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search graph nodes by label, actor, type, or path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search graph nodes"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-dim)',
                borderRadius: '6px',
                padding: '6px 12px',
                color: 'var(--text-main)',
                fontSize: '12px',
                width: '100%',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {/* Collapse Baseline Filter */}
            <button
              onClick={() => setHideBaselineFiles((prev) => !prev)}
              className="btn btn-secondary"
              style={{
                padding: '5px 9px',
                fontSize: '11px',
                background: hideBaselineFiles ? '#ffffff' : 'var(--bg-input)',
                color: hideBaselineFiles ? '#000000' : 'var(--text-muted)',
              }}
              title="Toggle passive baseline source files"
            >
              {hideBaselineFiles ? <Eye size={12} /> : <EyeOff size={12} />}
              {hideBaselineFiles ? 'Show All Files' : 'Hide Baseline Files'}
            </button>

            {/* View Mode Toggle */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '2px', background: 'var(--bg-input)', padding: '2px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
              <button
                onClick={() => setViewMode('visual')}
                className="btn"
                style={{
                  padding: '4px 8px',
                  fontSize: '11px',
                  background: viewMode === 'visual' ? '#ffffff' : 'transparent',
                  color: viewMode === 'visual' ? '#000000' : 'var(--text-muted)',
                  fontWeight: 600,
                }}
                aria-label="Visual Graph Mode"
              >
                <Share2 size={12} /> Graph
              </button>
              <button
                onClick={() => setViewMode('cards')}
                className="btn"
                style={{
                  padding: '4px 8px',
                  fontSize: '11px',
                  background: viewMode === 'cards' ? '#ffffff' : 'transparent',
                  color: viewMode === 'cards' ? '#000000' : 'var(--text-muted)',
                  fontWeight: 600,
                }}
                aria-label="Card Grid Mode"
              >
                <Grid size={12} /> Cards
              </button>
            </div>

            {/* Node Type Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Filter size={13} color="var(--text-muted)" />
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                aria-label="Filter by node type"
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '6px',
                  padding: '5px 8px',
                  color: 'var(--text-main)',
                  fontSize: '11px',
                  outline: 'none',
                }}
              >
                <option value="all">All Node Types</option>
                <option value="task_intent">Task Intent</option>
                <option value="agent_session">Agent Session</option>
                <option value="command">Commands</option>
                <option value="filesystem_mutation">File Mutations</option>
                <option value="network_request">Network Requests</option>
                <option value="policy_finding">Policy Findings</option>
                <option value="test_result">Test Results</option>
                <option value="source_file">Source Files</option>
              </select>
            </div>

            {/* Zoom Controls */}
            {viewMode === 'visual' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
                <button
                  onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
                  className="btn btn-secondary"
                  style={{ padding: '4px 7px' }}
                  aria-label="Zoom in"
                >
                  <ZoomIn size={13} />
                </button>
                <button
                  onClick={() => setZoom((z) => Math.max(0.2, z - 0.15))}
                  className="btn btn-secondary"
                  style={{ padding: '4px 7px' }}
                  aria-label="Zoom out"
                >
                  <ZoomOut size={13} />
                </button>
                <button
                  onClick={() => { setZoom(0.85); setPan({ x: 50, y: 30 }); setCustomPositions({}); }}
                  className="btn btn-secondary"
                  style={{ padding: '4px 7px' }}
                  aria-label="Reset layout"
                  title="Reset zoom & center"
                >
                  <Maximize2 size={13} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Visual Graph Viewport */}
        {viewMode === 'visual' ? (
          <div
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            style={{
              flex: 1,
              position: 'relative',
              overflow: 'hidden',
              cursor: isDragging ? 'grabbing' : 'grab',
              background: 'radial-gradient(circle at 50% 50%, rgba(255, 255, 255, 0.02) 0%, transparent 80%)',
            }}
          >
            <svg
              style={{ width: '100%', height: '100%' }}
              viewBox="0 0 1100 800"
            >
              <defs>
                <marker
                  id="arrow-solid"
                  viewBox="0 0 10 10"
                  refX="21"
                  refY="5"
                  markerWidth="5"
                  markerHeight="5"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ffffff" />
                </marker>
                <marker
                  id="arrow-dim"
                  viewBox="0 0 10 10"
                  refX="21"
                  refY="5"
                  markerWidth="5"
                  markerHeight="5"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#71717a" />
                </marker>
                <marker
                  id="arrow-selected"
                  viewBox="0 0 10 10"
                  refX="21"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ffffff" />
                </marker>
              </defs>

              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Directed Edges */}
                {graphData.edges.map((edge) => {
                  const src = nodePositions.get(edge.source_node_id);
                  const tgt = nodePositions.get(edge.target_node_id);
                  if (!src || !tgt) return null;

                  const isConnectedToSelected = connectedEdgeIds.has(edge.edge_id);
                  const hasSelection = Boolean(selectedNode);

                  const strokeColor = isConnectedToSelected ? '#ffffff' : hasSelection ? 'rgba(255, 255, 255, 0.15)' : 'rgba(255, 255, 255, 0.45)';
                  const strokeWidth = isConnectedToSelected ? '2' : '1.2';
                  const strokeDash = edge.confidence === 'low' ? '4 4' : 'none';
                  const marker = isConnectedToSelected ? 'url(#arrow-selected)' : hasSelection ? 'url(#arrow-dim)' : 'url(#arrow-solid)';

                  return (
                    <g key={edge.edge_id}>
                      <line
                        x1={src.x}
                        y1={src.y}
                        x2={tgt.x}
                        y2={tgt.y}
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        strokeDasharray={strokeDash}
                        markerEnd={marker}
                        style={{ transition: 'stroke 0.2s ease' }}
                      />
                      <text
                        x={(src.x + tgt.x) / 2}
                        y={(src.y + tgt.y) / 2 - 4}
                        fill={isConnectedToSelected ? '#ffffff' : '#71717a'}
                        fontSize="9px"
                        fontFamily="var(--font-mono)"
                        textAnchor="middle"
                        style={{ userSelect: 'none', pointerEvents: 'none' }}
                      >
                        {edge.edge_type}
                      </text>
                    </g>
                  );
                })}

                {/* Nodes */}
                {filteredNodes.map((node) => {
                  const pos = nodePositions.get(node.node_id) || { x: 500, y: 300 };
                  const isSelected = selectedNode?.node_id === node.node_id;
                  const isConnected = connectedNodeIds.has(node.node_id);
                  const hasSelection = Boolean(selectedNode);

                  const opacity = hasSelection ? (isSelected || isConnected ? 1 : 0.35) : 1;

                  return (
                    <g
                      key={node.node_id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => onInspectNode(node)}
                      onMouseDown={(e) => {
                        e.stopPropagation();
                        draggedNodeIdRef.current = node.node_id;
                      }}
                      style={{ cursor: 'pointer', opacity, transition: 'opacity 0.2s ease' }}
                      tabIndex={0}
                      role="button"
                      aria-label={`Node: ${node.label} (${node.node_type})`}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          onInspectNode(node);
                        }
                      }}
                    >
                      {/* Outer selection halo */}
                      {isSelected && (
                        <circle
                          r={24}
                          fill="none"
                          stroke="#ffffff"
                          strokeWidth={1.5}
                          strokeDasharray="4 2"
                          style={{
                            filter: 'drop-shadow(0 0 8px rgba(255, 255, 255, 0.8))',
                          }}
                        />
                      )}

                      {/* Main Node Body */}
                      <circle
                        r={isSelected ? 18 : 14}
                        fill="#09090b"
                        stroke={isSelected ? '#ffffff' : isConnected ? '#e4e4e7' : 'rgba(255, 255, 255, 0.4)'}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                      />

                      {/* Center Pin */}
                      <circle
                        r={4}
                        fill={isSelected ? '#ffffff' : '#d4d4d8'}
                      />

                      {/* Node Label Text */}
                      <text
                        y={26}
                        fill="#ffffff"
                        fontSize="11px"
                        fontWeight={isSelected ? '700' : '500'}
                        textAnchor="middle"
                        style={{ pointerEvents: 'none', userSelect: 'none' }}
                      >
                        {node.label.length > 22 ? `${node.label.slice(0, 20)}...` : node.label}
                      </text>

                      {/* Type subtitle */}
                      <text
                        y={37}
                        fill="#a1a1aa"
                        fontSize="8.5px"
                        fontFamily="var(--font-mono)"
                        textAnchor="middle"
                        style={{ pointerEvents: 'none', userSelect: 'none' }}
                      >
                        {node.node_type}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        ) : (
          /* Cards Grid Mode */
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '10px', alignContent: 'start' }}>
            {filteredNodes.map((node) => {
              const isSelected = selectedNode?.node_id === node.node_id;
              const connectedEdges = graphData.edges.filter(
                (e) => e.source_node_id === node.node_id || e.target_node_id === node.node_id
              );

              return (
                <div
                  key={node.node_id}
                  onClick={() => onInspectNode(node)}
                  tabIndex={0}
                  role="button"
                  aria-label={`Inspect node ${node.label}`}
                  className="glass-panel"
                  style={{
                    padding: '12px',
                    cursor: 'pointer',
                    border: isSelected ? '1px solid #ffffff' : '1px solid var(--border-dim)',
                    boxShadow: isSelected ? '0 0 15px rgba(255, 255, 255, 0.25)' : 'none',
                    background: isSelected ? '#18181b' : 'var(--bg-card)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {getNodeIcon(node.node_type)}
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                        {node.node_type.replace('_', ' ')}
                      </span>
                    </div>
                    {getConfidenceBadge(node.confidence)}
                  </div>

                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>
                    {node.label}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-dim)', paddingTop: '4px', borderTop: '1px solid var(--border-dim)' }}>
                    <span className="font-mono">Actor: {node.actor_id}</span>
                    <span>{connectedEdges.length} links</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Slide-out Inspector Drawer */}
      {selectedNode && (
        <aside className="glass-panel" aria-label="Node Provenance Drawer" style={{ display: 'flex', flexDirection: 'column', padding: '16px', overflowY: 'auto', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-dim)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Info size={15} color="#ffffff" />
              <h2 className="font-heading" style={{ fontSize: '14px', fontWeight: 600 }}>
                Node Metadata & Provenance
              </h2>
            </div>
            <button
              onClick={() => onInspectNode(selectedNode)}
              aria-label="Close inspector drawer"
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}
            >
              &times;
            </button>
          </div>

          <div>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Type & Confidence
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontWeight: 600, fontSize: '13px' }}>{selectedNode.node_type}</span>
              {getConfidenceBadge(selectedNode.confidence)}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Canonical Label
            </span>
            <p style={{ fontSize: '12px', marginTop: '4px', color: 'var(--text-main)', background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
              {selectedNode.label}
            </p>
          </div>

          <div>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Origin Provenance
            </span>
            <div className="font-mono" style={{ fontSize: '10px', marginTop: '4px', background: '#09090b', padding: '8px', borderRadius: '6px', border: '1px solid var(--border-dim)', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Actor: <span style={{ color: '#ffffff' }}>{selectedNode.actor_id}</span></div>
              <div>Adapter: <span style={{ color: '#ffffff' }}>{selectedNode.source_adapter}</span></div>
              <div>Recorded At: <span style={{ color: '#ffffff' }}>{new Date(selectedNode.timestamp).toLocaleTimeString()}</span></div>
              {selectedNode.content_hash && (
                <div style={{ wordBreak: 'break-all' }}>SHA: <span style={{ color: '#ffffff' }}>{selectedNode.content_hash}</span></div>
              )}
            </div>
          </div>

          {selectedNode.data && Object.keys(selectedNode.data).length > 0 && (
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                Payload Attributes
              </span>
              <pre className="font-mono" style={{ fontSize: '10px', marginTop: '4px', background: '#09090b', padding: '8px', borderRadius: '6px', border: '1px solid var(--border-dim)', color: '#d4d4d8', overflowX: 'auto', maxHeight: '140px' }}>
                {JSON.stringify(selectedNode.data, null, 2)}
              </pre>
            </div>
          )}

          <div>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
              Causal Relationships ({connectedEdgeIds.size})
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '6px' }}>
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
                        padding: '8px 10px',
                        background: 'rgba(255,255,255,0.03)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-dim)',
                        fontSize: '11px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#ffffff', fontWeight: 600, fontSize: '10px' }}>
                        <span>{isOutgoing ? 'OUTGOING:' : 'INCOMING:'}</span>
                        <span className="font-mono" style={{ color: '#a1a1aa' }}>{edge.edge_type}</span>
                        <ArrowRight size={10} />
                      </div>
                      <div style={{ marginTop: '2px', color: 'var(--text-main)', fontSize: '11px' }}>
                        {otherNode?.label || targetId}
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </aside>
      )}
    </div>
  );
};
