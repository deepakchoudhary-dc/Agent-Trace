import React, { useState } from 'react';
import { SessionInfo } from '../types';
import { FolderGit2, Search, Check, Play, Clock, ShieldCheck, Activity } from 'lucide-react';

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

  const filtered = sessions.filter(
    (s) =>
      s.session_id.toLowerCase().includes(search.toLowerCase()) ||
      s.task_description.toLowerCase().includes(search.toLowerCase()) ||
      s.workspace_path.toLowerCase().includes(search.toLowerCase()) ||
      s.status.toLowerCase().includes(search.toLowerCase())
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
          maxHeight: '80vh',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '6px',
                background: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <FolderGit2 size={18} color="#000000" />
            </div>
            <div>
              <h2 id="session-picker-title" className="font-heading" style={{ fontSize: '16px', fontWeight: 600 }}>
                Audit Session Directory
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Select an isolated audit ledger to view its dedicated Context Graph and evidence
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              fontSize: '20px',
            }}
          >
            &times;
          </button>
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative' }}>
          <Search
            size={14}
            color="var(--text-muted)"
            style={{ position: 'absolute', left: '12px', top: '10px' }}
          />
          <input
            type="text"
            placeholder="Search sessions by task description, workspace, or session ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: '#09090b',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '8px 12px 8px 34px',
              color: '#ffffff',
              fontSize: '12px',
              outline: 'none',
            }}
          />
        </div>

        {/* Sessions List */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '40px 16px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No audit sessions match your query.
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
                  style={{
                    background: isSelected ? '#18181b' : '#09090b',
                    border: isSelected ? '1px solid #ffffff' : '1px solid var(--border-dim)',
                    borderRadius: '8px',
                    padding: '14px',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="font-mono" style={{ fontSize: '12px', fontWeight: 600, color: '#ffffff' }}>
                        {s.session_id}
                      </span>
                      {isActive ? (
                        <span className="badge badge-high" style={{ fontSize: '8.5px' }}>
                          ● LIVE RECORDING
                        </span>
                      ) : (
                        <span className="badge badge-medium" style={{ fontSize: '8.5px' }}>
                          SEALED
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="badge badge-low" style={{ fontSize: '9px' }}>
                        {s.event_count} Events
                      </span>
                      {isSelected && <Check size={16} color="#ffffff" />}
                    </div>
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--text-main)', fontWeight: 500 }}>
                    {s.task_description || '(No task description provided)'}
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '10.5px',
                      color: 'var(--text-dim)',
                      paddingTop: '6px',
                      borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                    }}
                  >
                    <span className="font-mono">Workspace: {s.workspace_path}</span>
                    <span>Started: {new Date(s.started_at).toLocaleString()}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '8px', borderTop: '1px solid var(--border-dim)' }}>
          <button onClick={onClose} className="btn btn-secondary" style={{ fontSize: '11px' }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
