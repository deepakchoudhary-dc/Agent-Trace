import React, { useState, useEffect, useMemo } from 'react';
import { api } from '../api/client';
import { DiffItem, BlastRadiusResult } from '../types';
import {
  FileDiff,
  FilePlus,
  FileMinus,
  FileEdit,
  Flame,
  Layers,
  GitCompareArrows,
  Hash,
} from 'lucide-react';

interface DiffPanelProps {
  sessionId?: string;
  blastRadius?: BlastRadiusResult | null;
}

const MUTATION_META: Record<string, { icon: typeof FilePlus; label: string }> = {
  create: { icon: FilePlus, label: 'ADDED' },
  modify: { icon: FileEdit, label: 'MODIFIED' },
  delete: { icon: FileMinus, label: 'DELETED' },
};

export const DiffPanel: React.FC<DiffPanelProps> = ({ sessionId, blastRadius }) => {
  const [diffs, setDiffs] = useState<DiffItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (sessionId) {
      loadDiffs(sessionId);
    }
    // Reset selection when switching sessions
    setSelectedFile(null);
    setDiffs([]);
  }, [sessionId]);

  const loadDiffs = async (sid: string) => {
    setLoading(true);
    try {
      const data = await api.getDiffs(sid);
      setDiffs(data);
      if (data.length > 0) {
        setSelectedFile(data[0].file_path);
      }
    } catch {
      setDiffs([]);
    } finally {
      setLoading(false);
    }
  };

  const activeDiff = diffs.find((d) => d.file_path === selectedFile) || diffs[0];

  // Derive add/delete line counts from the unified diff summary
  const diffStats = useMemo(() => {
    if (!activeDiff) return { additions: 0, deletions: 0 };
    const lines = activeDiff.diff_summary.split('\n');
    return {
      additions: lines.filter((l) => l.startsWith('+') && !l.startsWith('+++')).length,
      deletions: lines.filter((l) => l.startsWith('-') && !l.startsWith('---')).length,
    };
  }, [activeDiff]);

  if (!sessionId) {
    return (
      <div className="glass-panel" style={{ margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
        <div className="empty-state">
          <GitCompareArrows size={34} color="var(--border-medium)" />
          <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
            No Session Selected
          </h3>
          <p style={{ fontSize: '12px' }}>Select an audit session to inspect file mutations and blast radius.</p>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(280px, 340px) 1fr',
        gap: '16px',
        margin: '0 16px 16px 16px',
        height: 'calc(100vh - 120px)',
      }}
    >
      {/* File List & Blast Radius Sidebar */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%', overflow: 'hidden', minWidth: 0 }}>
        {/* Changed Files List */}
        <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div className="panel-header">
            <div className="flex" style={{ gap: '8px' }}>
              <FileDiff size={15} color="#ffffff" />
              <span className="panel-title">Mutated Files</span>
              <span className="chip">{diffs.length}</span>
            </div>
            {loading && <span className="badge badge-low">SYNCING</span>}
          </div>

          <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {diffs.length === 0 ? (
              <div className="empty-state" style={{ padding: '28px 8px' }}>
                <p style={{ fontSize: '11.5px' }}>
                  {loading ? 'Loading mutations…' : 'No file mutations recorded yet in this session.'}
                </p>
              </div>
            ) : (
              diffs.map((diff) => {
                const meta = MUTATION_META[diff.mutation_type] || { icon: FileEdit, label: diff.mutation_type.toUpperCase() };
                const Icon = meta.icon;
                const isSelected = selectedFile === diff.file_path;
                return (
                  <div
                    key={diff.file_path}
                    onClick={() => setSelectedFile(diff.file_path)}
                    tabIndex={0}
                    role="button"
                    aria-label={`Diff for file: ${diff.file_path}`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        setSelectedFile(diff.file_path);
                      }
                    }}
                    className={`card card--clickable ${isSelected ? 'card--selected' : ''}`}
                    style={{ padding: '9px 10px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}
                  >
                    <div className="flex" style={{ gap: '8px', minWidth: 0 }}>
                      <Icon size={14} color={diff.mutation_type === 'delete' ? '#a1a1aa' : '#ffffff'} style={{ flexShrink: 0 }} />
                      <span className="font-mono ellipsis" style={{ fontSize: '11px', color: '#ffffff' }} title={diff.file_path}>
                        {diff.file_path}
                      </span>
                    </div>
                    <span className="badge badge-low" style={{ fontSize: '8px', flexShrink: 0 }}>
                      {meta.label}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Blast Radius Assessment */}
        {blastRadius && (
          <div className="glass-panel" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px', flexShrink: 0 }}>
            <div className="flex-between">
              <div className="flex" style={{ gap: '6px' }}>
                <Flame size={14} color="#ffffff" />
                <h3 className="panel-title" style={{ fontSize: '12px' }}>Blast Radius</h3>
              </div>
              <span className="badge badge-high" style={{ fontSize: '9px' }}>
                {blastRadius.affected_nodes.length} Nodes
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
              <div className="stat" style={{ padding: '7px 9px' }}>
                <div className="stat-label">RISK SCORE</div>
                <div style={{ fontWeight: 650, color: '#ffffff', fontSize: '13px', marginTop: '1px' }}>
                  {Math.round(blastRadius.risk_score * 100)}%
                </div>
              </div>
              <div className="stat" style={{ padding: '7px 9px' }}>
                <div className="stat-label">FILES AFFECTED</div>
                <div style={{ fontWeight: 650, color: '#ffffff', fontSize: '13px', marginTop: '1px' }}>
                  {blastRadius.affected_files.length}
                </div>
              </div>
            </div>

            {(blastRadius.failed_tests.length > 0 || blastRadius.broken_imports.length > 0 || blastRadius.config_changes.length > 0) && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                {blastRadius.failed_tests.length > 0 && (
                  <div className="flex" style={{ gap: '6px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
                    <span className="badge badge-critical" style={{ fontSize: '8px' }}>TESTS</span>
                    <span className="ellipsis">{blastRadius.failed_tests.join(', ')}</span>
                  </div>
                )}
                {blastRadius.broken_imports.length > 0 && (
                  <div className="flex" style={{ gap: '6px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
                    <span className="badge badge-medium" style={{ fontSize: '8px' }}>IMPORTS</span>
                    <span className="ellipsis">{blastRadius.broken_imports.join(', ')}</span>
                  </div>
                )}
                {blastRadius.config_changes.length > 0 && (
                  <div className="flex" style={{ gap: '6px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
                    <span className="badge badge-low" style={{ fontSize: '8px' }}>CONFIG</span>
                    <span className="ellipsis">{blastRadius.config_changes.join(', ')}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Unified Diff Viewer */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        {activeDiff ? (
          <>
            {/* Diff Header */}
            <div className="panel-header">
              <div className="flex" style={{ gap: '10px', minWidth: 0 }}>
                <span className="font-mono ellipsis" style={{ fontSize: '12px', fontWeight: 600, color: '#ffffff' }} title={activeDiff.file_path}>
                  {activeDiff.file_path}
                </span>
                <span className="badge badge-medium">
                  {(MUTATION_META[activeDiff.mutation_type]?.label || activeDiff.mutation_type).toUpperCase()}
                </span>
              </div>
              <div className="flex" style={{ gap: '12px', fontSize: '11px', flexShrink: 0 }}>
                <span style={{ color: '#ffffff', fontFamily: 'var(--font-mono)' }}>+{diffStats.additions}</span>
                <span style={{ color: '#71717a', fontFamily: 'var(--font-mono)' }}>-{diffStats.deletions}</span>
              </div>
            </div>

            {/* Content hashes */}
            <div className="toolbar" style={{ justifyContent: 'flex-start', gap: '14px', fontSize: '10px' }}>
              <span className="flex" style={{ gap: '6px' }}>
                <Hash size={10} color="var(--text-dim)" />
                <span className="dim">BEFORE</span>
                <span className="font-mono" style={{ color: 'var(--text-muted)' }}>{activeDiff.before_hash.slice(0, 12) || '—'}</span>
              </span>
              <span className="flex" style={{ gap: '6px' }}>
                <Hash size={10} color="var(--text-dim)" />
                <span className="dim">AFTER</span>
                <span className="font-mono" style={{ color: 'var(--text-muted)' }}>{activeDiff.after_hash.slice(0, 12) || '—'}</span>
              </span>
            </div>

            {/* Diff Body */}
            <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', background: '#050505', fontFamily: 'var(--font-mono)', fontSize: '11.5px', lineHeight: 1.65 }}>
              {activeDiff.diff_summary ? (
                activeDiff.diff_summary.split('\n').map((line, idx) => {
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
                      <span style={{ color: 'var(--text-dim)', userSelect: 'none', width: '30px', textAlign: 'right', flexShrink: 0 }}>
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
                  No structural diff content captured for this mutation.
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="empty-state">
            <Layers size={32} color="var(--border-medium)" />
            <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
              No Diff Selected
            </h3>
            <p style={{ fontSize: '12px' }}>Select a mutated file from the list to view its content diff.</p>
          </div>
        )}
      </div>
    </div>
  );
};
