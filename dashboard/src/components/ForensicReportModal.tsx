import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import {
  SessionInfo,
  ContextGraphData,
  TimelineEvent,
  PolicyFinding,
  VerificationResult,
} from '../types';
import {
  ShieldCheck,
  ShieldAlert,
  Download,
  Check,
  FileCheck,
} from 'lucide-react';

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
  const [downloading, setDownloading] = useState(false);
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [verifying, setVerifying] = useState(true);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  useEffect(() => {
    let active = true;
    if (session?.session_id) {
      setVerifying(true);
      api
        .verifySession(session.session_id)
        .then((res) => {
          if (active) setVerification(res);
        })
        .catch(() => {
          if (active) {
            setVerification({
              session_id: session.session_id,
              is_valid: false,
              error: 'Daemon verification endpoint unreachable',
              head_event_hash: '',
              event_count: timeline.length,
            });
          }
        })
        .finally(() => {
          if (active) setVerifying(false);
        });
    }
    return () => {
      active = false;
    };
  }, [session?.session_id, timeline.length]);

  if (!session) return null;

  const isChainValid = verification ? verification.is_valid : false;
  const lastEventHash = verification?.head_event_hash || (timeline.length > 0 ? timeline[timeline.length - 1].event_hash : '0'.repeat(64));

  const handleExportJSON = () => {
    setDownloading(true);
    const reportData = {
      manifest_version: '1.0.0',
      generated_at: new Date().toISOString(),
      session: {
        session_id: session.session_id,
        task_description: session.task_description,
        workspace_path: session.workspace_path,
        status: session.status,
      },
      cryptographic_verification: {
        status: isChainValid ? 'VERIFIED' : 'UNVERIFIED',
        head_event_hash: lastEventHash,
        total_chained_events: timeline.length,
        error_detail: verification?.error || null,
      },
      audit_statistics: {
        total_events: timeline.length,
        context_nodes: graphData?.nodes.length || 0,
        context_edges: graphData?.edges.length || 0,
        policy_findings: findings.length,
      },
      tamper_evident_timeline: timeline.map((e) => ({
        seq: e.seq,
        event_id: e.event_id,
        event_type: e.event_type,
        actor_id: e.actor_id,
        source_adapter: e.source_adapter,
        timestamp: e.timestamp,
        event_hash: e.event_hash,
        prev_hash: e.prev_hash,
      })),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agenttrace-audit-${session.session_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => setDownloading(false), 800);
  };

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="report-modal-title">
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{ width: '100%', maxWidth: '640px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileCheck size={18} color="#000000" />
            </div>
            <div>
              <h2 id="report-modal-title" className="font-heading" style={{ fontSize: '16px', fontWeight: 600 }}>
                Forensic Audit Export Manifest
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Session: {session.session_id}
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close dialog" style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '20px' }}>
            &times;
          </button>
        </div>

        {/* Verification Status Banner */}
        <div style={{
          background: '#09090b',
          border: isChainValid ? '1px solid #ffffff' : '1px solid var(--border-dim)',
          borderRadius: '8px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}>
          {verifying ? (
            <span className="badge badge-low">Checking cryptographic integrity...</span>
          ) : isChainValid ? (
            <>
              <ShieldCheck size={24} color="#ffffff" />
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                  Cryptographic Hash Chain: VERIFIED
                </h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  All {timeline.length} event hashes recomputed from canonical JSON preimages and validated unbroken.
                </p>
              </div>
            </>
          ) : (
            <>
              <ShieldAlert size={24} color="#71717a" />
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                  Cryptographic Status: UNVERIFIED
                </h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {verification?.error || 'Hash chain integrity could not be confirmed.'}
                </p>
              </div>
            </>
          )}
        </div>

        {/* Audit Metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
          <div style={{ background: '#09090b', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>SEALED EVENTS</div>
            <div style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', marginTop: '2px' }}>
              {timeline.length}
            </div>
          </div>
          <div style={{ background: '#09090b', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>CONTEXT NODES</div>
            <div style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', marginTop: '2px' }}>
              {graphData?.nodes.length || 0}
            </div>
          </div>
          <div style={{ background: '#09090b', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>POLICY GATES</div>
            <div style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', marginTop: '2px' }}>
              {findings.length}
            </div>
          </div>
        </div>

        {/* Cryptographic Head Hash */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <label style={{ fontSize: '11px', fontWeight: 500, color: 'var(--text-muted)' }}>
            Head Event Hash (Merkle Chain Root)
          </label>
          <div className="font-mono" style={{ background: '#09090b', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)', fontSize: '11px', color: '#d4d4d8', wordBreak: 'break-all' }}>
            {lastEventHash}
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '6px' }}>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={handleExportJSON} className="btn btn-primary" disabled={downloading}>
            {downloading ? <Check size={14} /> : <Download size={14} />}
            {downloading ? 'Exported!' : 'Export Verified Report (JSON)'}
          </button>
        </div>
      </div>
    </div>
  );
};
