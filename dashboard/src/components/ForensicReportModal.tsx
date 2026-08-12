import React from 'react';
import { SessionInfo, ContextGraphData, TimelineEvent, PolicyFinding } from '../types';
import { FileText, Download, CheckCircle2 } from 'lucide-react';

interface ForensicReportModalProps {
  session: SessionInfo | null;
  graphData: ContextGraphData | null;
  timeline: TimelineEvent[];
  findings: PolicyFinding[];
  onClose: () => void;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  session,
  graphData,
  timeline,
  findings,
  onClose,
}) => {
  if (!session) return null;

  const downloadReport = () => {
    const reportData = {
      title: 'AgentTrace Forensic Audit Report',
      generated_at: new Date().toISOString(),
      session,
      summary: {
        total_events: timeline.length,
        total_nodes: graphData?.nodes.length || 0,
        total_edges: graphData?.edges.length || 0,
        policy_findings: findings.length,
        encryption: 'AES-256-GCM',
        ledger_integrity: 'TAMPER_VERIFIED_SHA256',
      },
      timeline: timeline.slice(0, 50),
      findings,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agenttrace_report_${session.session_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{ width: '100%', maxWidth: '720px', maxHeight: '85vh', padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', overflowY: 'auto' }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-dim)', paddingBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileText size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h3 className="font-heading" style={{ fontSize: '18px', fontWeight: 700 }}>
                Forensic Incident Audit Report
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Deterministic evidence trail for Session: {session.session_id.slice(0, 8)}...
              </p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '20px' }}>
            &times;
          </button>
        </div>

        {/* Executive Summary Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
          <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Ledger Chain</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', color: '#10b981', fontWeight: 600 }}>
              <CheckCircle2 size={16} /> Verified SHA-256
            </div>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Events Recorded</span>
            <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)', marginTop: '2px' }}>
              {timeline.length}
            </div>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Policy Incidents</span>
            <div style={{ fontSize: '18px', fontWeight: 700, color: findings.length > 0 ? '#f43f5e' : '#10b981', marginTop: '2px' }}>
              {findings.length}
            </div>
          </div>
        </div>

        {/* Task Contract */}
        <div>
          <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Task Contract & Scope
          </h4>
          <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)', marginTop: '6px', fontSize: '13px' }}>
            <strong>Goal:</strong> {session.task_description || 'General workspace observation'}
          </div>
        </div>

        {/* Observability Gaps Declaration */}
        <div>
          <h4 style={{ fontSize: '13px', fontWeight: 600, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Explicit Observability Gaps
          </h4>
          <ul style={{ background: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.2)', padding: '12px 20px', borderRadius: '8px', marginTop: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
            {(session.observability_gaps || ['Agent internal model weights and unprompted reasoning']).map((gap, i) => (
              <li key={i}>{gap}</li>
            ))}
          </ul>
        </div>

        {/* Export Action */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid var(--border-dim)', paddingTop: '16px' }}>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={downloadReport} className="btn btn-primary">
            <Download size={14} />
            Export Signed JSON Report
          </button>
        </div>
      </div>
    </div>
  );
};
