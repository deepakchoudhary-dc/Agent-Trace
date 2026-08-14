import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import dagre from '@dagrejs/dagre';
import {
  ContextGraphData,
  GraphNode,
  GraphEdge,
  ConfidenceLevel,
  SessionInfo,
} from '../types';
import {
  Search,
  Filter,
  Eye,
  EyeOff,
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
  Activity,
  X,
  FolderTree,
  Crosshair,
} from 'lucide-react';

interface GraphViewProps {
  graphData: ContextGraphData;
  onInspectNode: (node: GraphNode) => void;
  selectedNode: GraphNode | null;
  currentSession?: SessionInfo | null;
  livePolling?: boolean;
}

const NODE_TYPES = [
  { value: 'all', label: 'All Types' },
  { value: 'task_intent', label: 'Task Intent' },
  { value: 'agent_session', label: 'Agent Session' },
  { value: 'tool_request', label: 'Tool Requests' },
  { value: 'command', label: 'Commands' },
  { value: 'filesystem_mutation', label: 'File Mutations' },
  { value: 'network_request', label: 'Network Requests' },
  { value: 'policy_finding', label: 'Policy Findings' },
  { value: 'test_result', label: 'Test Results' },
  { value: 'source_file', label: 'Source Files' },
  { value: 'process', label: 'Processes' },
  { value: 'approval', label: 'Approvals' },
];

const CONFIDENCE_FILTERS = [
  { value: 'all', label: 'All Confidence' },
  { value: 'high', label: 'Direct' },
  { value: 'medium', label: 'Correlated' },
  { value: 'low', label: 'Inferred' },
];

// Node types treated as passive "baseline & context" — collapsible at scale
const BASELINE_TYPES = new Set([
  'source_file',
  'contextual_document',
  'workspace_snapshot',
  'git_commit_diff',
  'untrusted_content',
]);

// Dagre layout constants
const NODE_W = 132;
const NODE_H = 56;
const CLUSTER_ID = 'cluster:baseline';

// Causal edges pull nodes vertically; context edges are weaker horizontal glue
const STRONG_EDGES = new Set(['CAUSES', 'EXECUTES', 'MODIFIES', 'REQUESTS', 'SPAWNS', 'VIOLATES', 'VALIDATES']);
const edgeWeight = (type: string) => (STRONG_EDGES.has(type) ? 10 : 2);

type BaselineMode = 'show' | 'collapse' | 'hide';

/**
 * Sugiyama layered layout (dagre): cycle-breaking → rank assignment from real
 * edges → crossing minimization → placement. Produces a true causal "context
 * tree" instead of a hardcoded type grid.
 */
function computeLayeredLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  viewWidth: number
): Map<string, { x: number; y: number }> {
  const posMap = new Map<string, { x: number; y: number }>();
  if (nodes.length === 0) return posMap;

  const g = new dagre.graphlib.Graph();
  g.setGraph({
    rankdir: 'TB',
    nodesep: 44,
    ranksep: 72,
    edgesep: 14,
    marginx: 60,
    marginy: 40,
  });
  g.setDefaultEdgeLabel(() => ({}));

  nodes.forEach((n) => g.setNode(n.node_id, { width: NODE_W, height: NODE_H }));

  const nodeIds = new Set(nodes.map((n) => n.node_id));
  const seen = new Set<string>();
  edges.forEach((e) => {
    if (!nodeIds.has(e.source_node_id) || !nodeIds.has(e.target_node_id)) return;
    if (e.source_node_id === e.target_node_id) return; // skip self-loops
    const key = `${e.source_node_id}\u0000${e.target_node_id}`;
    if (seen.has(key)) return; // dedupe parallel edges
    seen.add(key);
    g.setEdge(e.source_node_id, e.target_node_id, { weight: edgeWeight(e.edge_type) });
  });

  dagre.layout(g);

  // dagre returns node centers; convert to top-left and normalize horizontally
  let minX = Infinity;
  let maxX = -Infinity;
  nodes.forEach((n) => {
    const p = g.node(n.node_id);
    if (!p) return;
    const x = p.x - NODE_W / 2;
    const y = p.y - NODE_H / 2;
    posMap.set(n.node_id, { x, y });
    if (x < minX) minX = x;
    if (x + NODE_W > maxX) maxX = x + NODE_W;
  });

  // Center the whole layout on the viewport
  if (posMap.size > 0 && isFinite(minX) && isFinite(maxX)) {
    const offset = viewWidth / 2 - (minX + maxX) / 2;
    if (Math.abs(offset) > 0.5) {
      posMap.forEach((p) => {
        p.x += offset;
      });
    }
  }

  return posMap;
}

export const GraphView: React.FC<GraphViewProps> = ({
  graphData,
  onInspectNode,
  selectedNode,
  currentSession,
  livePolling = true,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterConfidence, setFilterConfidence] = useState<string>('all');
  const [baselineMode, setBaselineMode] = useState<BaselineMode>('show');
  const [viewMode, setViewMode] = useState<'visual' | 'cards'>('visual');
  const [zoom, setZoom] = useState(0.85);
  const [pan, setPan] = useState({ x: 40, y: 30 });
  const [isDragging, setIsDragging] = useState(false);
  const [viewSize, setViewSize] = useState({ width: 1100, height: 800 });
  const [followLatest, setFollowLatest] = useState(true);
  const [recentNodeIds, setRecentNodeIds] = useState<Record<string, number>>({});
  const containerRef = useRef<HTMLDivElement | null>(null);
  const dragStartRef = useRef({ x: 0, y: 0 });

  // Custom dragged node positions override
  const [customPositions, setCustomPositions] = useState<Record<string, { x: number; y: number }>>({});
  const draggedNodeIdRef = useRef<string | null>(null);
  const prevNodeIdsRef = useRef<Set<string>>(new Set());

  // Responsive canvas: track container size
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      if (width > 0 && height > 0) {
        setViewSize({ width, height });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Prune "recently added" highlights after a few seconds
  useEffect(() => {
    const t = setInterval(() => {
      setRecentNodeIds((prev) => {
        const cutoff = Date.now() - 6000;
        const next: Record<string, number> = {};
        let changed = false;
        Object.entries(prev).forEach(([id, ts]) => {
          if (ts >= cutoff) next[id] = ts;
          else changed = true;
        });
        return changed ? next : prev;
      });
    }, 1500);
    return () => clearInterval(t);
  }, []);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter((node) => {
      if (baselineMode === 'hide' && BASELINE_TYPES.has(node.node_type)) {
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
  }, [graphData.nodes, searchQuery, filterType, filterConfidence, baselineMode]);

  const baselineCount = useMemo(
    () => filteredNodes.filter((n) => BASELINE_TYPES.has(n.node_type)).length,
    [filteredNodes]
  );

  // Auto-collapse baseline files at scale (enterprise aggregation pattern)
  useEffect(() => {
    if (baselineMode === 'show' && baselineCount > 24) {
      setBaselineMode('collapse');
    }
  }, [baselineCount, baselineMode]);

  // Build display nodes + edges, collapsing baseline files into a cluster node
  const { displayNodes, displayEdges } = useMemo(() => {
    const collapse = baselineMode === 'collapse' && baselineCount > 0;
    if (!collapse) {
      return { displayNodes: filteredNodes, displayEdges: graphData.edges };
    }

    const active = filteredNodes.filter((n) => !BASELINE_TYPES.has(n.node_type));
    const clusterNode: GraphNode = {
      node_id: CLUSTER_ID,
      node_type: 'cluster',
      label: `${baselineCount} baseline files`,
      timestamp: new Date().toISOString(),
      actor_id: 'baseline',
      source_adapter: 'graph',
      confidence: 'low',
      data: { count: baselineCount },
    };

    // Re-point edges touching collapsed nodes at the cluster
    const edgeMap = new Map<string, GraphEdge>();
    graphData.edges.forEach((e) => {
      const srcCollapsed = BASELINE_TYPES.has(
        graphData.nodes.find((n) => n.node_id === e.source_node_id)?.node_type || ''
      );
      const tgtCollapsed = BASELINE_TYPES.has(
        graphData.nodes.find((n) => n.node_id === e.target_node_id)?.node_type || ''
      );
      const source = srcCollapsed ? CLUSTER_ID : e.source_node_id;
      const target = tgtCollapsed ? CLUSTER_ID : e.target_node_id;
      if (source === target) return;
      edgeMap.set(`${source}\u0000${target}`, { ...e, source_node_id: source, target_node_id: target });
    });

    return { displayNodes: [...active, clusterNode], displayEdges: Array.from(edgeMap.values()) };
  }, [filteredNodes, graphData.edges, graphData.nodes, baselineMode, baselineCount]);

  // Dagre layered layout derived from the real edge structure
  const nodePositions = useMemo(() => {
    const base = computeLayeredLayout(displayNodes, displayEdges, viewSize.width);
    Object.entries(customPositions).forEach(([id, pos]) => {
      base.set(id, pos);
    });
    return base;
  }, [displayNodes, displayEdges, viewSize.width, customPositions]);

  // Detect newly-arrived nodes/edges (live build-up) and follow the newest
  useEffect(() => {
    const ids = new Set(displayNodes.map((n) => n.node_id));
    const added: string[] = [];
    ids.forEach((id) => {
      if (!prevNodeIdsRef.current.has(id)) added.push(id);
    });
    if (added.length > 0) {
      const now = Date.now();
      setRecentNodeIds((prev) => {
        const next = { ...prev };
        added.forEach((id) => {
          next[id] = now;
        });
        return next;
      });

      // Follow the newest node into view when live streaming
      if (followLatest && livePolling) {
        const newest = added[added.length - 1];
        const pos = nodePositions.get(newest);
        if (pos) {
          const screenX = pos.x * zoom + pan.x;
          const screenY = pos.y * zoom + pan.y;
          const margin = 160;
          if (
            screenX < margin ||
            screenX > viewSize.width - margin ||
            screenY < margin ||
            screenY > viewSize.height - margin
          ) {
            setPan({
              x: viewSize.width / 2 - pos.x * zoom,
              y: viewSize.height / 2 - pos.y * zoom,
            });
          }
        }
      }
    }
    prevNodeIdsRef.current = ids;
  }, [displayNodes, nodePositions, followLatest, livePolling, zoom, pan, viewSize]);

  // Connected nodes & edges for selected node
  const { connectedNodeIds, connectedEdgeIds } = useMemo(() => {
    if (!selectedNode) {
      return { connectedNodeIds: new Set<string>(), connectedEdgeIds: new Set<string>() };
    }
    const nIds = new Set<string>([selectedNode.node_id]);
    const eIds = new Set<string>();
    displayEdges.forEach((edge) => {
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
  }, [selectedNode, displayEdges]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'task_intent':
      case 'task_constraints':
        return <Layers size={14} color="#ffffff" />;
      case 'agent_session':
        return <Activity size={14} color="#ffffff" />;
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
      case 'build_result':
        return <CheckCircle2 size={14} color="#ffffff" />;
      case 'cluster':
        return <FolderTree size={14} color="#ffffff" />;
      default:
        return <GitBranch size={14} color="#a1a1aa" />;
    }
  };

  const getConfidenceBadge = (confidence: ConfidenceLevel) => {
    switch (confidence) {
      case 'high':
        return <span className="badge badge-high">Direct</span>;
      case 'medium':
        return <span className="badge badge-medium">Correlated</span>;
      case 'low':
        return <span className="badge badge-low">Inferred</span>;
    }
  };

  const resetView = useCallback(() => {
    setZoom(0.85);
    setPan({ x: 40, y: 30 });
    setCustomPositions({});
  }, []);

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (draggedNodeIdRef.current) return;
    if (e.button !== 0) return;
    setIsDragging(true);
    dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNodeIdRef.current) {
      const currentPos = nodePositions.get(draggedNodeIdRef.current) || { x: viewSize.width / 2, y: 300 };
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

  // Quadratic bezier control point with perpendicular bow for a modern curve
  const edgePath = (x1: number, y1: number, x2: number, y2: number) => {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.max(1, Math.hypot(dx, dy));
    const bow = Math.min(42, len * 0.16);
    const cx = (x1 + x2) / 2 - (dy / len) * bow;
    const cy = (y1 + y2) / 2 + (dx / len) * bow;
    return { path: `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`, cx, cy };
  };

  const isRecent = (id: string) => Boolean(recentNodeIds[id]);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: selectedNode ? '1fr 390px' : '1fr',
        gap: '16px',
        margin: '0 16px 16px 16px',
        height: 'calc(100vh - 120px)',
        transition: 'grid-template-columns 0.25s var(--ease-out)',
      }}
    >
      {/* Main Graph Canvas */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        {/* Session Info & Stream Status Strip */}
        <div className="panel-header" style={{ flexWrap: 'wrap' }}>
          <div className="flex" style={{ gap: '10px', minWidth: 0, flexWrap: 'wrap' }}>
            <span className="flex" style={{ gap: '6px' }}>
              <span className="dim" style={{ fontSize: '10.5px', letterSpacing: '0.06em' }}>SESSION</span>
              <span className="font-mono ellipsis" style={{ color: '#ffffff', fontWeight: 650, fontSize: '11px' }} title={currentSession?.session_id}>
                {currentSession ? currentSession.session_id : 'No session selected'}
              </span>
            </span>
            {currentSession?.task_description && (
              <span className="ellipsis" style={{ color: 'var(--text-muted)', fontSize: '11.5px', maxWidth: '340px' }} title={currentSession.task_description}>
                — “{currentSession.task_description}”
              </span>
            )}
          </div>

          <div className="flex" style={{ gap: '8px' }}>
            <span className="chip">{filteredNodes.length} nodes</span>
            <span className="chip">{graphData.edges.length} links</span>
            {Object.keys(recentNodeIds).length > 0 && (
              <span className="badge badge-high" style={{ fontSize: '9px' }}>
                +{Object.keys(recentNodeIds).length} new
              </span>
            )}
            {currentSession?.status === 'active' && livePolling && (
              <span className="flex" style={{ gap: '6px', color: '#ffffff', fontSize: '10.5px', fontWeight: 650 }}>
                <span className="live-dot" /> LIVE STREAM
              </span>
            )}
          </div>
        </div>

        {/* Controls Toolbar */}
        <div className="toolbar">
          <div className="flex grow" style={{ minWidth: '200px', position: 'relative' }}>
            <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '8px', pointerEvents: 'none' }} />
            <input
              type="text"
              placeholder="Filter nodes by label, actor, or type…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search graph nodes"
              className="input"
              style={{ width: '100%', paddingLeft: '30px' }}
            />
          </div>

          <div className="toolbar-group">
            {/* Baseline Aggregation */}
            <div className="seg" title="Aggregate passive baseline files at scale">
              <button
                onClick={() => setBaselineMode('show')}
                className={`seg-btn ${baselineMode === 'show' ? 'seg-btn--active' : ''}`}
                aria-label="Show all baseline files"
              >
                <Eye size={12} /> All
              </button>
              <button
                onClick={() => setBaselineMode('collapse')}
                className={`seg-btn ${baselineMode === 'collapse' ? 'seg-btn--active' : ''}`}
                aria-label="Collapse baseline files into a cluster"
              >
                <FolderTree size={12} /> Collapse{baselineMode === 'collapse' && baselineCount > 0 ? ` (${baselineCount})` : ''}
              </button>
              <button
                onClick={() => setBaselineMode('hide')}
                className={`seg-btn ${baselineMode === 'hide' ? 'seg-btn--active' : ''}`}
                aria-label="Hide baseline files"
              >
                <EyeOff size={12} /> Hide
              </button>
            </div>

            {/* View Mode Toggle */}
            <div className="seg">
              <button
                onClick={() => setViewMode('visual')}
                className={`seg-btn ${viewMode === 'visual' ? 'seg-btn--active' : ''}`}
                aria-label="Visual Graph Mode"
              >
                <Share2 size={12} /> Graph
              </button>
              <button
                onClick={() => setViewMode('cards')}
                className={`seg-btn ${viewMode === 'cards' ? 'seg-btn--active' : ''}`}
                aria-label="Card Grid Mode"
              >
                <Grid size={12} /> Cards
              </button>
            </div>

            {/* Node Type Filter */}
            <div className="flex" style={{ gap: '4px' }}>
              <Filter size={12} color="var(--text-muted)" />
              <select value={filterType} onChange={(e) => setFilterType(e.target.value)} aria-label="Filter by node type" className="select" style={{ fontSize: '10.5px', padding: '4px 24px 4px 8px' }}>
                {NODE_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>

            {/* Confidence Filter */}
            <select
              value={filterConfidence}
              onChange={(e) => setFilterConfidence(e.target.value)}
              aria-label="Filter by evidence confidence"
              className="select"
              style={{ fontSize: '10.5px', padding: '4px 24px 4px 8px' }}
            >
              {CONFIDENCE_FILTERS.map((c) => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>

            {/* Follow latest live activity */}
            <button
              onClick={() => setFollowLatest((v) => !v)}
              className={`btn btn-sm ${followLatest && livePolling ? 'btn-primary' : 'btn-secondary'}`}
              title="Keep the newest live activity in view"
              aria-pressed={followLatest && livePolling}
            >
              <Crosshair size={12} />
              Follow
            </button>

            {/* Zoom Controls */}
            {viewMode === 'visual' && (
              <div className="seg">
                <button onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))} className="seg-btn" aria-label="Zoom in">
                  <ZoomIn size={12} />
                </button>
                <button onClick={() => setZoom((z) => Math.max(0.2, z - 0.15))} className="seg-btn" aria-label="Zoom out">
                  <ZoomOut size={12} />
                </button>
                <button onClick={resetView} className="seg-btn" aria-label="Reset layout" title="Reset zoom & center">
                  <Maximize2 size={12} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Visual Graph Viewport */}
        {displayNodes.length === 0 ? (
          <div className="empty-state" style={{ flex: 1 }}>
            <Activity size={36} color="var(--border-medium)" />
            <h3 className="font-heading" style={{ fontSize: '15px', color: 'var(--text-muted)' }}>
              No Graph Nodes Match
            </h3>
            <p style={{ fontSize: '12px', maxWidth: '380px' }}>
              {filteredNodes.length === 0
                ? 'Start an audit session via terminal or select a different recorded session.'
                : 'Adjust the search query, filters, or baseline aggregation to reveal matching context nodes.'}
            </p>
          </div>
        ) : viewMode === 'visual' ? (
          <div
            ref={containerRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            className="graph-canvas"
          >
            <svg width={viewSize.width} height={viewSize.height} viewBox={`0 0 ${viewSize.width} ${viewSize.height}`} style={{ display: 'block' }}>
              <defs>
                <marker id="arrow-solid" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ffffff" />
                </marker>
                <marker id="arrow-dim" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#71717a" />
                </marker>
                <marker id="arrow-selected" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ffffff" />
                </marker>
              </defs>

              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Directed Edges (curved, live draw-in) */}
                {displayEdges.map((edge) => {
                  const src = nodePositions.get(edge.source_node_id);
                  const tgt = nodePositions.get(edge.target_node_id);
                  if (!src || !tgt) return null;

                  const isConnectedToSelected = connectedEdgeIds.has(edge.edge_id);
                  const hasSelection = Boolean(selectedNode);
                  const { path, cx, cy } = edgePath(
                    src.x + NODE_W / 2,
                    src.y + NODE_H / 2,
                    tgt.x + NODE_W / 2,
                    tgt.y + NODE_H / 2
                  );
                  const isNew = isRecent(edge.target_node_id) || isRecent(edge.source_node_id);

                  const strokeColor = isConnectedToSelected ? '#ffffff' : hasSelection ? 'rgba(255, 255, 255, 0.15)' : 'rgba(255, 255, 255, 0.38)';
                  const strokeWidth = isConnectedToSelected ? 2 : 1.3;
                  const strokeDash = edge.confidence === 'low' ? '5 5' : 'none';
                  const marker = isConnectedToSelected ? 'url(#arrow-selected)' : hasSelection ? 'url(#arrow-dim)' : 'url(#arrow-solid)';
                  const opacity = hasSelection ? (isConnectedToSelected ? 1 : 0.25) : 1;

                  return (
                    <g key={edge.edge_id} className="g-edge" style={{ opacity }}>
                      <path
                        d={path}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        strokeDasharray={strokeDash}
                        markerEnd={marker}
                        className={isNew && !strokeDash ? 'edge-draw' : undefined}
                        style={{ transition: 'stroke 0.2s ease' }}
                      />
                      <text
                        x={cx}
                        y={cy - 6}
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
                {displayNodes.map((node) => {
                  const pos = nodePositions.get(node.node_id) || { x: viewSize.width / 2, y: 300 };
                  const isCluster = node.node_type === 'cluster';
                  const isSelected = selectedNode?.node_id === node.node_id;
                  const isConnected = connectedNodeIds.has(node.node_id);
                  const hasSelection = Boolean(selectedNode);
                  const opacity = hasSelection ? (isSelected || isConnected ? 1 : 0.3) : 1;
                  const newFlag = isRecent(node.node_id);

                  return (
                    <g
                      key={node.node_id}
                      className="g-node-pos"
                      style={{
                        transform: `translate(${pos.x}px, ${pos.y}px)`,
                        opacity,
                        cursor: 'pointer',
                      }}
                    >
                      <g
                        onClick={() => {
                          if (isCluster) {
                            setBaselineMode('show');
                            return;
                          }
                          onInspectNode(node);
                        }}
                        onMouseDown={(e) => {
                          e.stopPropagation();
                          if (!isCluster) draggedNodeIdRef.current = node.node_id;
                        }}
                        className={`g-node ${newFlag && !isCluster ? 'node-pop' : ''}`}
                        tabIndex={0}
                        role="button"
                        aria-label={`Node: ${node.label} (${node.node_type})`}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            if (isCluster) setBaselineMode('show');
                            else onInspectNode(node);
                          }
                        }}
                      >
                        {isCluster ? (
                          <>
                            <rect
                              className="cluster-body"
                              x={-NODE_W / 2 + 8}
                              y={-NODE_H / 2 + 8}
                              width={NODE_W - 16}
                              height={NODE_H - 16}
                              rx={12}
                              fill="#0a0a0b"
                              stroke="#ffffff"
                              strokeWidth={1.2}
                              strokeDasharray="5 4"
                            />
                            <FolderTree size={15} color="#ffffff" x={-NODE_W / 2 + 22} y={-8} />
                            <text
                              x={-NODE_W / 2 + 44}
                              y={-2}
                              fill="#ffffff"
                              fontSize="11px"
                              fontWeight={650}
                              style={{ pointerEvents: 'none', userSelect: 'none' }}
                            >
                              {node.label}
                            </text>
                            <text
                              x={-NODE_W / 2 + 44}
                              y={12}
                              fill="#a1a1aa"
                              fontSize="8.5px"
                              fontFamily="var(--font-mono)"
                              style={{ pointerEvents: 'none', userSelect: 'none' }}
                            >
                              click to expand
                            </text>
                          </>
                        ) : (
                          <>
                            {/* Selection halo */}
                            {isSelected && (
                              <circle r={26} fill="none" stroke="#ffffff" strokeWidth={1.5} strokeDasharray="4 2" style={{ filter: 'drop-shadow(0 0 8px rgba(255, 255, 255, 0.8))' }} />
                            )}

                            {/* New-activity pulse ring */}
                            {newFlag && <circle className="new-node-ring" r={20} fill="none" stroke="#ffffff" strokeWidth={1.4} />}

                            {/* Node body */}
                            <circle
                              className="node-body"
                              r={isSelected ? 19 : 14}
                              fill="#09090b"
                              stroke={isSelected ? '#ffffff' : isConnected ? '#e4e4e7' : 'rgba(255, 255, 255, 0.4)'}
                              strokeWidth={isSelected ? 2.5 : 1.5}
                            />

                            {/* Center pin */}
                            <circle r={4} fill={isSelected || newFlag ? '#ffffff' : '#d4d4d8'} />

                            {/* Label */}
                            <text
                              y={28}
                              fill="#ffffff"
                              fontSize="11px"
                              fontWeight={isSelected ? 700 : 500}
                              textAnchor="middle"
                              style={{ pointerEvents: 'none', userSelect: 'none' }}
                            >
                              {node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label}
                            </text>

                            {/* Type subtitle */}
                            <text
                              y={39}
                              fill="#a1a1aa"
                              fontSize="8.5px"
                              fontFamily="var(--font-mono)"
                              textAnchor="middle"
                              style={{ pointerEvents: 'none', userSelect: 'none' }}
                            >
                              {node.node_type}
                            </text>
                          </>
                        )}
                      </g>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        ) : (
          /* Cards Grid Mode */
          <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '10px', alignContent: 'start' }}>
            {filteredNodes.map((node) => {
              const isSelected = selectedNode?.node_id === node.node_id;
              const connectedEdges = graphData.edges.filter(
                (e) => e.source_node_id === node.node_id || e.target_node_id === node.node_id
              );
              const newFlag = isRecent(node.node_id);

              return (
                <div
                  key={node.node_id}
                  onClick={() => onInspectNode(node)}
                  tabIndex={0}
                  role="button"
                  aria-label={`Inspect node ${node.label}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') onInspectNode(node);
                  }}
                  className={`card card--clickable ${isSelected ? 'card--selected' : ''}`}
                  style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '7px', borderColor: newFlag ? 'var(--border-strong)' : undefined }}
                >
                  <div className="flex-between">
                    <div className="flex" style={{ gap: '6px' }}>
                      {getNodeIcon(node.node_type)}
                      <span style={{ fontSize: '9.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 650, letterSpacing: '0.04em' }}>
                        {node.node_type.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="flex" style={{ gap: '5px' }}>
                      {newFlag && <span className="badge badge-high" style={{ fontSize: '8px' }}>NEW</span>}
                      {getConfidenceBadge(node.confidence)}
                    </div>
                  </div>

                  <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-main)', lineHeight: 1.35 }} title={node.label}>
                    {node.label}
                  </div>

                  <div className="flex-between" style={{ fontSize: '10px', color: 'var(--text-dim)', paddingTop: '6px', borderTop: '1px solid var(--border-dim)' }}>
                    <span className="font-mono ellipsis" title={node.actor_id}>Actor: {node.actor_id}</span>
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
        <aside className="glass-panel" aria-label="Node Provenance Drawer" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflowY: 'auto', minWidth: 0 }}>
          <div className="panel-header" style={{ position: 'sticky', top: 0, zIndex: 2, backdropFilter: 'blur(12px)' }}>
            <div className="flex" style={{ gap: '8px' }}>
              <Info size={15} color="#ffffff" />
              <h2 className="panel-title">Node Metadata</h2>
            </div>
            <button onClick={() => onInspectNode(selectedNode)} aria-label="Close inspector drawer" className="btn btn-ghost btn-icon">
              <X size={16} />
            </button>
          </div>

          <div className="flex-col" style={{ padding: '16px', gap: '14px' }}>
            <div>
              <div className="stat-label" style={{ marginBottom: '5px' }}>Type & Confidence</div>
              <div className="flex" style={{ gap: '8px', flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 650, fontSize: '13px' }}>{selectedNode.node_type}</span>
                {getConfidenceBadge(selectedNode.confidence)}
              </div>
            </div>

            <div>
              <div className="stat-label" style={{ marginBottom: '5px' }}>Canonical Label</div>
              <div className="code-block">{selectedNode.label}</div>
            </div>

            <div>
              <div className="stat-label" style={{ marginBottom: '5px' }}>Origin Provenance</div>
              <div className="code-block" style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '10px', color: 'var(--text-muted)' }}>
                <div>Actor: <span style={{ color: '#ffffff' }}>{selectedNode.actor_id}</span></div>
                <div>Adapter: <span style={{ color: '#ffffff' }}>{selectedNode.source_adapter}</span></div>
                <div>Recorded: <span style={{ color: '#ffffff' }}>{new Date(selectedNode.timestamp).toLocaleString()}</span></div>
                {selectedNode.content_hash && (
                  <div style={{ wordBreak: 'break-all' }}>SHA: <span style={{ color: '#ffffff' }}>{selectedNode.content_hash}</span></div>
                )}
              </div>
            </div>

            {selectedNode.data && Object.keys(selectedNode.data).length > 0 && (
              <div>
                <div className="stat-label" style={{ marginBottom: '5px' }}>Payload Attributes</div>
                <pre className="code-block" style={{ maxHeight: '160px', color: '#d4d4d8', fontSize: '10px' }}>
                  {JSON.stringify(selectedNode.data, null, 2)}
                </pre>
              </div>
            )}

            <div>
              <div className="stat-label" style={{ marginBottom: '6px' }}>
                Causal Relationships ({connectedEdgeIds.size})
              </div>
              <div className="flex-col" style={{ gap: '6px' }}>
                {displayEdges
                  .filter((e) => e.source_node_id === selectedNode.node_id || e.target_node_id === selectedNode.node_id)
                  .map((edge) => {
                    const isOutgoing = edge.source_node_id === selectedNode.node_id;
                    const targetId = isOutgoing ? edge.target_node_id : edge.source_node_id;
                    const otherNode = displayNodes.find((n) => n.node_id === targetId);

                    return (
                      <div
                        key={edge.edge_id}
                        style={{
                          padding: '8px 10px',
                          background: 'var(--bg-subtle)',
                          borderRadius: '6px',
                          border: '1px solid var(--border-dim)',
                          fontSize: '11px',
                        }}
                      >
                        <div className="flex" style={{ gap: '4px', color: '#ffffff', fontWeight: 650, fontSize: '9.5px' }}>
                          <span>{isOutgoing ? 'OUTGOING' : 'INCOMING'}</span>
                          <span className="font-mono" style={{ color: '#a1a1aa' }}>{edge.edge_type}</span>
                          <ArrowRight size={10} />
                        </div>
                        <div style={{ marginTop: '3px', color: 'var(--text-main)', fontSize: '11px' }} title={targetId}>
                          {otherNode?.label || targetId}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
};
