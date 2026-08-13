import React from 'react';
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
} from 'lucide-react';
import { SessionInfo } from '../types';

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
  return (
    <header className="glass-panel" style={{ margin: '14px 16px 12px 16px', padding: '10px 18px', borderRadius: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        {/* Brand & Workspace */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '6px',
              background: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 10px rgba(255, 255, 255, 0.4)',
            }}>
              <ShieldAlert size={18} color="#000000" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <h1 className="font-heading" style={{ fontSize: '15px', fontWeight: 700, letterSpacing: '-0.02em', color: '#ffffff' }}>
                  AGENTTRACE
                </h1>
                <span className="badge badge-high" style={{ fontSize: '9px', padding: '1px 5px' }}>
                  FORENSIC AUDITOR
                </span>
              </div>
              <p style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                Zero-Telemetry Causal Evidence Ledger
              </p>
            </div>
          </div>

          <div style={{ height: '22px', width: '1px', background: 'var(--border-dim)' }} />

          {/* Session Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderGit2 size={14} color="#ffffff" />
            <select
              style={{
                background: 'var(--bg-input)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-dim)',
                borderRadius: '6px',
                padding: '5px 10px',
                fontSize: '11.5px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                cursor: 'pointer',
                maxWidth: '240px',
              }}
              aria-label="Select audit session"
              value={currentSession?.session_id || ''}
              onChange={(e) => {
                const s = sessions.find((item) => item.session_id === e.target.value);
                if (s) onSelectSession(s);
              }}
            >
              {sessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.session_id.slice(0, 8)}... ({s.status})
                </option>
              ))}
            </select>

            {/* Live Feed Toggle */}
            {onToggleLivePolling && (
              <button
                onClick={onToggleLivePolling}
                className="btn"
                style={{
                  padding: '4px 8px',
                  fontSize: '10.5px',
                  background: livePolling ? 'rgba(255,255,255,0.1)' : 'transparent',
                  color: livePolling ? '#ffffff' : 'var(--text-dim)',
                  border: livePolling ? '1px solid rgba(255,255,255,0.3)' : '1px solid var(--border-dim)',
                }}
                title="Toggle real-time live event streaming"
              >
                <Radio size={11} className={livePolling ? "animate-pulse" : ""} />
                {livePolling ? 'LIVE FEED (2.5s)' : 'PAUSED'}
              </button>
            )}
          </div>
        </div>

        {/* Navigation Tabs — Stark Monochrome */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#09090b', padding: '3px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
          <button
            onClick={() => onTabChange('graph')}
            className={`btn ${activeTab === 'graph' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            <GitGraph size={13} />
            Context Graph
          </button>
          <button
            onClick={() => onTabChange('timeline')}
            className={`btn ${activeTab === 'timeline' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            <Clock size={13} />
            Timeline & Actors
          </button>
          <button
            onClick={() => onTabChange('incidents')}
            className={`btn ${activeTab === 'incidents' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            <AlertTriangle size={13} />
            Incidents & Policy
          </button>
          <button
            onClick={() => onTabChange('review_loop')}
            className={`btn ${activeTab === 'review_loop' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            <Repeat size={13} />
            Review Loop
          </button>
          <button
            onClick={() => onTabChange('diff')}
            className={`btn ${activeTab === 'diff' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '11px', padding: '5px 10px' }}
          >
            <FileCode size={13} />
            Diff & Blast Radius
          </button>
        </nav>

        {/* Actions & Cryptography Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '4px 8px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
            <Lock size={11} color="#ffffff" />
            <span style={{ fontSize: '10px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>DPAPI + AES-256</span>
          </div>

          <button onClick={onRefresh} className="btn btn-secondary" title="Refresh Live State" style={{ padding: '5px 8px' }} aria-label="Refresh session state">
            <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          </button>

          <button onClick={onOpenReport} className="btn btn-primary" style={{ padding: '5px 12px', fontSize: '11px' }}>
            <FileCheck size={13} />
            Forensic Report
          </button>
        </div>
      </div>
    </header>
  );
};
