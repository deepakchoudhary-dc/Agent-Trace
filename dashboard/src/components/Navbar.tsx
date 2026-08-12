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
}

export const Navbar: React.FC<NavbarProps> = ({
  sessions,
  currentSession,
  onSelectSession,
  activeTab,
  onTabChange,
  onOpenReport,
  onRefresh,
}) => {
  return (
    <header className="glass-panel" style={{ margin: '16px', padding: '12px 20px', borderRadius: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        {/* Brand & Workspace */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)',
            }}>
              <ShieldAlert size={20} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h1 className="font-heading" style={{ fontSize: '18px', fontWeight: 700, letterSpacing: '-0.02em' }}>
                  AgentTrace
                </h1>
                <span className="badge badge-high" style={{ fontSize: '9px', padding: '1px 6px' }}>
                  Local Auditor
                </span>
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Zero-Telemetry Causal Evidence Ledger
              </p>
            </div>
          </div>

          <div style={{ height: '24px', width: '1px', background: 'var(--border-dim)' }} />

          {/* Session Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderGit2 size={16} color="var(--accent-cyan)" />
            <select
              style={{
                background: 'var(--bg-input)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-dim)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                cursor: 'pointer',
              }}
              value={currentSession?.session_id || ''}
              onChange={(e) => {
                const s = sessions.find((item) => item.session_id === e.target.value);
                if (s) onSelectSession(s);
              }}
            >
              {sessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.workspace_path} ({s.status})
                </option>
              ))}
            </select>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginLeft: '4px' }}>
              <div className="live-dot" />
              <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 500 }}>
                {currentSession?.status || 'Active'}
              </span>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(0,0,0,0.3)', padding: '4px', borderRadius: '10px' }}>
          <button
            onClick={() => onTabChange('graph')}
            className={`btn ${activeTab === 'graph' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <GitGraph size={14} />
            Context Graph
          </button>
          <button
            onClick={() => onTabChange('timeline')}
            className={`btn ${activeTab === 'timeline' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <Clock size={14} />
            Timeline & Actors
          </button>
          <button
            onClick={() => onTabChange('incidents')}
            className={`btn ${activeTab === 'incidents' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <AlertTriangle size={14} />
            Incidents & Policy
          </button>
          <button
            onClick={() => onTabChange('review_loop')}
            className={`btn ${activeTab === 'review_loop' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <Repeat size={14} />
            Review Loop
          </button>
          <button
            onClick={() => onTabChange('diff')}
            className={`btn ${activeTab === 'diff' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <FileCode size={14} />
            Diff & Blast Radius
          </button>
        </nav>

        {/* Actions & Encryption Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 10px', background: 'rgba(16, 185, 129, 0.08)', borderRadius: '6px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
            <Lock size={12} color="#10b981" />
            <span style={{ fontSize: '11px', color: '#10b981', fontFamily: 'var(--font-mono)' }}>AES-256 GCM</span>
          </div>

          <button onClick={onRefresh} className="btn btn-secondary" title="Refresh Live State" style={{ padding: '6px 10px' }}>
            <RefreshCw size={14} />
          </button>

          <button onClick={onOpenReport} className="btn btn-primary" style={{ padding: '6px 14px' }}>
            <FileCheck size={14} />
            Forensic Report
          </button>
        </div>
      </div>
    </header>
  );
};
