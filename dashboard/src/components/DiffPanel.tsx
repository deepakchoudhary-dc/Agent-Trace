import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { DiffItem, BlastRadiusResult } from '../types';
import {
  FileDiff,
  FilePlus,
  FileMinus,
  FileEdit,
  Flame,
  Shield,
  Layers,
} from 'lucide-react';

interface DiffPanelProps {
  sessionId?: string;
  blastRadius?: BlastRadiusResult | null;
}

export const DiffPanel: React.FC<DiffPanelProps> = ({ sessionId, blastRadius }) => {
  const [diffs, setDiffs] = useState<DiffItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (sessionId) {
      loadDiffs(sessionId);
    }
  }, [sessionId]);

  const loadDiffs = async (sid: string) => {
    setLoading(true);
    try {
      const data = await api.getSessionDiffs(sid);
      setDiffs(data);
      if (data.length > 0) {
        setSelectedFile(data[0].path);
      }
    } catch {
      setDiffs([]);
    } finally {
      setLoading(false);
    }
  };

  const activeDiff = diffs.find((d) => d.path === selectedFile) || diffs[0];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'added':
        return <FilePlus size={14} color="#ffffff" />;
      case 'deleted':
        return <FileMinus size={14} color="#a1a1aa" />;
      default:
        return <FileEdit size={14} color="#ffffff" />;
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* File List & Blast Radius Sidebar */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%', overflow: 'hidden' }}>
        {/* Changed Files List */}
        <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '14px', gap: '10px', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileDiff size={15} color="#ffffff" />
              <h2 className="font-heading" style={{ fontSize: '13px', fontWeight: 600 }}>
                Mutated Files ({diffs.length})
              </h2>
            </div>
            {loading && <span className="badge badge-low">Syncing...</span>}
          </div>

          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {diffs.length === 0 ? (
              <div style={{ padding: '24px 8px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '11.5px' }}>
                No file mutations recorded yet.
              </div>
            ) : (
              diffs.map((diff) => (
                <div
                  key={diff.path}
                  onClick={() => setSelectedFile(diff.path)}
                  tabIndex={0}
                  role="button"
                  aria-label={`Diff for file: ${diff.path}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      setSelectedFile(diff.path);
                    }
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    background: selectedFile === diff.path ? '#18181b' : 'transparent',
                    border: selectedFile === diff.path ? '1px solid #ffffff' : '1px solid transparent',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                    {getStatusIcon(diff.status)}
                    <span className="font-mono" style={{ fontSize: '11.5px', color: '#ffffff', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                      {diff.path}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ fontSize: '10px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                      +{diff.additions}
                    </span>
                    <span style={{ fontSize: '10px', color: '#71717a', fontFamily: 'var(--font-mono)' }}>
                      -{diff.deletions}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Blast Radius Assessment */}
        {blastRadius && (
          <div className="glass-panel" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Flame size={14} color="#ffffff" />
                <h3 className="font-heading" style={{ fontSize: '12px', fontWeight: 600 }}>
                  Blast Radius
                </h3>
              </div>
              <span className="badge badge-high" style={{ fontSize: '9px' }}>
                {blastRadius.affected_nodes.length} Nodes
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', fontSize: '11px', marginTop: '2px' }}>
              <div style={{ background: '#09090b', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
                <div style={{ color: 'var(--text-dim)', fontSize: '9.5px' }}>IMPACT TIER</div>
                <div style={{ fontWeight: 600, color: '#ffffff' }}>
                  {blastRadius.impact_score > 0.6 ? 'HIGH' : 'ISOLATED'}
                </div>
              </div>

              <div style={{ background: '#09090b', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
                <div style={{ color: 'var(--text-dim)', fontSize: '9.5px' }}>CRITICAL PATHS</div>
                <div style={{ fontWeight: 600, color: '#ffffff' }}>
                  {blastRadius.critical_paths.length}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Unified Diff Viewer */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {activeDiff ? (
          <>
            {/* Diff Header */}
            <div style={{ padding: '10px 18px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="font-mono" style={{ fontSize: '12px', fontWeight: 600, color: '#ffffff' }}>
                  {activeDiff.path}
                </span>
                <span className="badge badge-medium">
                  {activeDiff.status.toUpperCase()}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px' }}>
                <span style={{ color: '#ffffff', fontFamily: 'var(--font-mono)' }}>+{activeDiff.additions} additions</span>
                <span style={{ color: '#71717a', fontFamily: 'var(--font-mono)' }}>-{activeDiff.deletions} deletions</span>
              </div>
            </div>

            {/* Diff Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '16px', background: '#050505', fontFamily: 'var(--font-mono)', fontSize: '11.5px', lineHeight: 1.6 }}>
              {activeDiff.diff ? (
                activeDiff.diff.split('\n').map((line, idx) => {
                  const isAdd = line.startsWith('+') && !line.startsWith('+++');
                  const isDel = line.startsWith('-') && !line.startsWith('---');
                  const isHunk = line.startsWith('@@');

                  let bg = 'transparent';
                  let color = '#d4d4d8';
                  if (isAdd) {
                    bg = 'rgba(255, 255, 255, 0.08)';
                    color = '#ffffff';
                  } else if (isDel) {
                    bg = 'rgba(255, 255, 255, 0.02)';
                    color = '#71717a';
                  } else if (isHunk) {
                    color = '#a1a1aa';
                  }

                  return (
                    <div
                      key={idx}
                      style={{
                        background: bg,
                        color,
                        padding: '1px 8px',
                        display: 'flex',
                        gap: '12px',
                        borderRadius: '2px',
                      }}
                    >
                      <span style={{ color: 'var(--text-dim)', userSelect: 'none', width: '32px', textAlign: 'right' }}>
                        {idx + 1}
                      </span>
                      <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {line}
                      </span>
                    </div>
                  );
                })
              ) : (
                <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px' }}>
                  No structural diff content available for this mutation.
                </div>
              )}
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--text-dim)', gap: '10px' }}>
            <FileDiff size={32} color="var(--border-dim)" />
            <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
              No Diff Selected
            </h3>
          </div>
        )}
      </div>
    </div>
  );
};
