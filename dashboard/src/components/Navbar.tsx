import React, { useState } from 'react';
import {
  ShieldAlert,
  FolderGit2,
  Lock,
  FileCheck,
  RefreshCw,
  GitGraph,
  Clock,
  AlertTriangle,
  FileCode,
  FileSearch,
  Repeat,
  Radio,
  ChevronDown,
  Play,
  Square,
} from 'lucide-react';
import { SessionInfo } from '../types';
import { SessionPickerModal } from './SessionPickerModal';

interface NavbarProps {
  sessions: SessionInfo[];
  currentSession: SessionInfo | null;
  onSelectSession: (session: SessionInfo) => void;
  onCreateSession: (workspacePath: string, taskDescription: string) => Promise<void>;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onOpenReport: () => void;
  onRefresh: () => void;
  loading?: boolean;
  livePolling?: boolean;
  onToggleLivePolling?: () => void;
  /** Stop recording the active session (seals the ledger). Omit to hide the control. */
  onStopSession?: (sessionId: string) => void;
}

const TABS = [
  { id: 'graph', label: 'Context Graph', icon: GitGraph },
  { id: 'timeline', label: 'Timeline & Actors', icon: Clock },
  { id: 'incidents', label: 'Incidents & Policy', icon: AlertTriangle },
  { id: 'audit', label: 'Audit & Verification', icon: FileSearch },
  { id: 'review_loop', label: 'Review Loop', icon: Repeat },
  { id: 'diff', label: 'Diff & Blast Radius', icon: FileCode },
];

// DPAPI key protection exists only on Windows; on other platforms the local
// key store differs. The chip must not claim platform features it does not
// use.
const IS_WINDOWS =
  typeof navigator !== 'undefined' &&
  /win/i.test(navigator.platform || navigator.userAgent || '');
const CRYPTO_LABEL = IS_WINDOWS ? 'DPAPI + AES-256' : 'OS keyring + AES-256';

export const Navbar: React.FC<NavbarProps> = ({
  sessions,
  currentSession,
  onSelectSession,
  onCreateSession,
  activeTab,
  onTabChange,
  onOpenReport,
  onRefresh,
  loading = false,
  livePolling = true,
  onToggleLivePolling,
  onStopSession,
}) => {
  const [showPicker, setShowPicker] = useState(false);
  const [showNewSession, setShowNewSession] = useState(false);
  const isSessionLive = currentSession?.status === 'active';

  return (
    <>
      <header
        className="glass-panel"
        style={{
          position: 'sticky',
          top: '10px',
          zIndex: 50,
          margin: '10px 16px',
          padding: '10px 16px',
          borderRadius: '12px',
          backdropFilter: 'blur(24px) saturate(1.2)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          {/* Brand & Session Directory */}
          <div className="flex" style={{ gap: '14px' }}>
            <div className="flex" style={{ gap: '10px' }}>
              <div className="brand-mark">
                <ShieldAlert size={18} color="#000000" />
              </div>
              <div>
                <div className="flex" style={{ gap: '6px' }}>
                  <h1 className="font-heading" style={{ fontSize: '15px', fontWeight: 750, letterSpacing: '-0.02em', color: '#ffffff' }}>
                    AGENTTRACE
                  </h1>
                  <span className="badge badge-high" style={{ fontSize: '8.5px', padding: '1px 6px' }}>
                    FORENSIC AUDITOR
                  </span>
                </div>
                <p style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                  Zero-Telemetry Causal Evidence Ledger
                </p>
              </div>
            </div>

            <div className="divider-v" />

            {/* Session Selector Button */}
            <div className="flex" style={{ gap: '8px' }}>
              <button
                onClick={() => setShowPicker(true)}
                className="btn btn-secondary"
                style={{
                  padding: '5px 10px',
                  fontSize: '11.5px',
                  background: '#09090b',
                }}
                title="Browse all recorded audit sessions"
              >
                <FolderGit2 size={13} color="#ffffff" />
                <span className="font-mono" style={{ color: '#ffffff' }}>
                  {currentSession ? `${currentSession.session_id.slice(0, 8)}…` : 'Select Session'}
                </span>
                {isSessionLive ? (
                  <span className="badge badge-high" style={{ fontSize: '8px', padding: '1px 4px' }}>
                    LIVE
                  </span>
                ) : (
                  <span className="badge badge-low" style={{ fontSize: '8px', padding: '1px 4px' }}>
                    SEALED
                  </span>
                )}
                <ChevronDown size={12} color="var(--text-muted)" />
              </button>

              {/* Live Streaming Toggle */}
              {onToggleLivePolling && (
                <button
                  onClick={onToggleLivePolling}
                  className="btn btn-sm"
                  style={{
                    background: livePolling ? 'rgba(255,255,255,0.1)' : 'transparent',
                    color: livePolling ? '#ffffff' : 'var(--text-dim)',
                    border: livePolling ? '1px solid var(--border-medium)' : '1px solid var(--border-dim)',
                  }}
                  title="Toggle real-time live event streaming"
                >
                  <Radio size={11} className={livePolling ? 'live-dot' : ''} />
                  {livePolling ? 'LIVE (2.5s)' : 'PAUSED'}
                </button>
              )}
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="tabs" aria-label="Primary">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => onTabChange(id)}
                className={`tab ${activeTab === id ? 'tab--active' : ''}`}
                aria-current={activeTab === id ? 'page' : undefined}
              >
                <Icon size={13} />
                <span style={{ whiteSpace: 'nowrap' }}>{label}</span>
              </button>
            ))}
          </nav>

          {/* Actions & Cryptography Status */}
          <div className="flex" style={{ gap: '8px' }}>
            <div className="chip" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <Lock size={11} color="#ffffff" />
              <span style={{ color: '#ffffff' }}>{CRYPTO_LABEL}</span>
            </div>

            <button
              onClick={onRefresh}
              className="btn btn-secondary btn-icon"
              title="Refresh Live State"
              aria-label="Refresh session state"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>

            <button
              onClick={() => setShowNewSession(true)}
              className="btn btn-secondary btn-sm"
              title="Start recording a new audit session (must start before the agent works)"
            >
              <Play size={13} />
              Start Session
            </button>

            {isSessionLive && onStopSession && currentSession && (
              <button
                onClick={() => onStopSession(currentSession.session_id)}
                className="btn btn-secondary btn-sm"
                title="Stop recording the live session (seals the ledger)"
              >
                <Square size={13} />
                End Session
              </button>
            )}

            <button onClick={onOpenReport} className="btn btn-primary btn-sm">
              <FileCheck size={13} />
              Forensic Report
            </button>
          </div>
        </div>
      </header>

      {showNewSession && (
        <NewSessionModal
          onCreate={onCreateSession}
          onClose={() => setShowNewSession(false)}
        />
      )}

      {showPicker && (
        <SessionPickerModal
          sessions={sessions}
          currentSession={currentSession}
          onSelectSession={onSelectSession}
          onClose={() => setShowPicker(false)}
        />
      )}
    </>
  );
};


// -- Inline start-recording flow: agents cannot be traced retroactively --
// a session must be recording BEFORE the agent starts working. POST /sessions
// boots the observer stack, so a stray record without a live workspace is a
// real state (policy engine flags the gap) -- the UI does not block it, the
// operator just sees zero events until something writes to the watched path.

interface NewSessionModalProps {
  onCreate: (workspacePath: string, taskDescription: string) => Promise<void>;
  onClose: () => void;
}

export const NewSessionModal: React.FC<NewSessionModalProps> = ({ onCreate, onClose }) => {
  const [workspacePath, setWorkspacePath] = useState('');
  const [taskDescription, setTaskDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!workspacePath.trim() || submitting) {
      setError('A workspace path is required -- the daemon observes files, not intentions.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onCreate(workspacePath.trim(), taskDescription.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create session');
      setSubmitting(false);
      return;
    }
    // Success: the App re-selected the new live session; dismiss the form.
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="new-session-title">
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '560px',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          boxShadow: 'var(--shadow-pop)',
        }}
      >
        <div>
          <h2 id="new-session-title" className="font-heading" style={{ fontSize: '16px', fontWeight: 650 }}>
            Start New Audit Session
          </h2>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            POST /sessions boots the observer stack. Recording must start BEFORE the agent works.
          </p>
        </div>

        <div className="flex-col" style={{ gap: '10px' }}>
          <div className="flex-col" style={{ gap: '4px' }}>
            <label htmlFor="ns-workspace" className="stat-label">Workspace path (required)</label>
            <input
              id="ns-workspace"
              value={workspacePath}
              onChange={(e) => setWorkspacePath(e.target.value)}
              placeholder="E:\projects\my-app"
              spellCheck={false}
              autoComplete="off"
              className="code-block"
              style={{ padding: '8px 10px', fontSize: '12px', background: 'rgba(0,0,0,0.35)' }}
            />
          </div>
          <div className="flex-col" style={{ gap: '4px' }}>
            <label htmlFor="ns-task" className="stat-label">Task description (optional)</label>
            <input
              id="ns-task"
              value={taskDescription}
              onChange={(e) => setTaskDescription(e.target.value)}
              placeholder="What is the agent about to do?"
              spellCheck={false}
              autoComplete="off"
              className="code-block"
              style={{ padding: '8px 10px', fontSize: '12px', background: 'rgba(0,0,0,0.35)' }}
            />
          </div>
          {error && <div style={{ fontSize: '11px', color: '#dc2626' }}>{error}</div>}
        </div>

        <div className="flex" style={{ justifyContent: 'flex-end', gap: '8px', paddingTop: '4px' }}>
          <button onClick={onClose} className="btn btn-secondary btn-sm" disabled={submitting}>
            Cancel
          </button>
          <button onClick={submit} className="btn btn-primary btn-sm" disabled={submitting}>
            {submitting ? 'Starting…' : 'Start Recording'}
          </button>
        </div>
      </div>
    </div>
  );
};
