import React, { useState, useMemo } from 'react';
import { SessionInfo } from '../types';
import { FolderGit2, Search, Check, X } from 'lucide-react';

interface SessionPickerModalProps {
  sessions: SessionInfo[];
  currentSession: SessionInfo | null;
  onSelectSession: (session: SessionInfo) => void;
  onClose: () => void;
}

export const SessionPickerModal: React.FC<SessionPickerModalProps> = ({
  sessions,
  currentSession,
  onSelectSession,
  onClose,
}) => {
  const [search, setSearch] = useState('');

  const filtered = useMemo(
    () =>
      sessions.filter(
        (s) =>
          s.session_id.toLowerCase().includes(search.toLowerCase()) ||
          s.task_description.toLowerCase().includes(search.toLowerCase()) ||
          s.workspace_path.toLowerCase().includes(search.toLowerCase()) ||
          s.status.toLowerCase().includes(search.toLowerCase())
      ),
    [sessions, search]
  );

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="session-picker-title"
    >
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '82vh',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          overflow: 'hidden',
          boxShadow: 'var(--shadow-pop)',
        }}
      >
        {/* Header */}
        <div className="flex-between">
          <div className="flex" style={{ gap: '10px' }}>
            <div className="brand-mark brand-mark--sm">
              <FolderGit2 size={18} color="#000000" />
            </div>
            <div>
              <h2 id="session-picker-title" className="font-heading" style={{ fontSize: '16px', fontWeight: 650 }}>
                Audit Session Directory
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Select an isolated audit ledger to view its dedicated Context Graph and evidence
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close dialog" className="btn btn-ghost btn-icon">
            <X size={16} />
          </button>
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative' }}>
          <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '10px', pointerEvents: 'none' }} />
          <input
            type="text"
            placeholder="Search sessions by task description, workspace, or session ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input"
            style={{ width: '100%', paddingLeft: '34px' }}
          />
        </div>

        {/* Sessions List */}
        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {filtered.length === 0 ? (
            <div className="empty-state" style={{ padding: '40px 16px' }}>
              <p style={{ fontSize: '12px' }}>No audit sessions match your query.</p>
            </div>
          ) : (
            filtered.map((s) => {
              const isSelected = currentSession?.session_id === s.session_id;
              const isActive = s.status === 'active';

              return (
                <div
                  key={s.session_id}
                  onClick={() => {
                    onSelectSession(s);
                    onClose();
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`Select session ${s.session_id}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      onSelectSession(s);
                      onClose();
                    }
                  }}
                  className={`card card--clickable ${isSelected ? 'card--selected' : ''}`}
                  style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}
                >
                  <div className="flex-between">
                    <div className="flex" style={{ gap: '8px', minWidth: 0 }}>
                      <span className="font-mono ellipsis" style={{ fontSize: '12px', fontWeight: 650, color: '#ffffff' }} title={s.session_id}>
                        {s.session_id}
                      </span>
                      {isActive ? (
                        <span className="badge badge-high" style={{ fontSize: '8.5px', flexShrink: 0 }}>
                          ● LIVE
                        </span>
                      ) : (
                        <span className="badge badge-medium" style={{ fontSize: '8.5px', flexShrink: 0 }}>
                          SEALED
                        </span>
                      )}
                    </div>

                    <div className="flex" style={{ gap: '6px', flexShrink: 0 }}>
                      <span className="chip">{s.event_count} events</span>
                      {isSelected && <Check size={16} color="#ffffff" />}
                    </div>
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--text-main)', fontWeight: 500 }}>
                    {s.task_description || '(No task description provided)'}
                  </div>

                  <div
                    className="flex-between"
                    style={{ fontSize: '10.5px', color: 'var(--text-dim)', paddingTop: '8px', borderTop: '1px solid var(--border-dim)' }}
                  >
                    <span className="font-mono ellipsis" title={s.workspace_path}>
                      {s.workspace_path}
                    </span>
                    <span style={{ flexShrink: 0 }}>{new Date(s.started_at).toLocaleString()}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex" style={{ justifyContent: 'flex-end', paddingTop: '8px', borderTop: '1px solid var(--border-dim)' }}>
          <button onClick={onClose} className="btn btn-secondary btn-sm">
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
