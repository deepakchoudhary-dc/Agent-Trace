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
  Repeat,
  Radio,
  ChevronDown,
} from 'lucide-react';
import { SessionInfo } from '../types';
import { SessionPickerModal } from './SessionPickerModal';

interface NavbarProps {
  sessions: SessionInfo[];
  currentSession: SessionInfo | null;
  onSelectSession: (session: SessionInfo) => void;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onOpenReport: () => void;
  onRefresh: () => void;
  loading?: boolean;
  livePolling?: boolean;
  onToggleLivePolling?: () => void;
}

const TABS = [
  { id: 'graph', label: 'Context Graph', icon: GitGraph },
  { id: 'timeline', label: 'Timeline & Actors', icon: Clock },
  { id: 'incidents', label: 'Incidents & Policy', icon: AlertTriangle },
  { id: 'review_loop', label: 'Review Loop', icon: Repeat },
  { id: 'diff', label: 'Diff & Blast Radius', icon: FileCode },
];

export const Navbar: React.FC<NavbarProps> = ({
  sessions,
  currentSession,
  onSelectSession,
  activeTab,
  onTabChange,
  onOpenReport,
  onRefresh,
  loading = false,
  livePolling = true,
  onToggleLivePolling,
}) => {
  const [showPicker, setShowPicker] = useState(false);
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
              <span style={{ color: '#ffffff' }}>DPAPI + AES-256</span>
            </div>

            <button
              onClick={onRefresh}
              className="btn btn-secondary btn-icon"
              title="Refresh Live State"
              aria-label="Refresh session state"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>

            <button onClick={onOpenReport} className="btn btn-primary btn-sm">
              <FileCheck size={13} />
              Forensic Report
            </button>
          </div>
        </div>
      </header>

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
