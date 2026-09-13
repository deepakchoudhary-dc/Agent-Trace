import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api/client';
import {
  SessionInfo,
  ContextGraphData,
  TimelineEvent,
  PolicyFinding,
  SignedForensicReport,
  VerificationResult,
} from '../types';
import {
  ShieldCheck,
  ShieldAlert,
  Download,
  Check,
  FileCheck,
  X,
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
  const [signedReport, setSignedReport] = useState<SignedForensicReport | null>(null);
  const [verifying, setVerifying] = useState(true);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeRef.current();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    let active = true;
    if (session?.session_id) {
      setVerifying(true);
      setSignedReport(null);
      api
        .verifyChain(session.session_id)
        .then((res) => {
          if (active) setVerification(res);
        })
        .catch(() => {
          if (active) {
            setVerification({
              session_id: session.session_id,
              verified: false,
              error: 'Daemon verification endpoint unreachable',
              event_count: timeline.length,
              last_event_hash: timeline.length > 0 ? timeline[timeline.length - 1].event_hash : '',
            });
          }
        })
        // The signed envelope (reasoning trail + incidents) is part of the
        // report contract; fetch it alongside the chain verdict. Failure leaves
        // the state null — the modal renders the honest "unavailable" gap
        // instead of a synthetic placeholder.
        .then(async () => {
          try {
            const report = await api.getSignedForensicReport(session.session_id);
            if (active) setSignedReport(report);
          } catch {
            if (active) setSignedReport(null);
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

  const isChainValid = verification ? verification.verified : false;
  // Never fabricate a chain root: without a verified head hash the report
  // shows an explicit gap instead of a fake all-zeros digest.
  const lastEventHash =
    verification?.last_event_hash ||
    (timeline.length > 0 ? timeline[timeline.length - 1].event_hash : '');

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
      // Server-generated signed envelope: HMAC chain-anchored fields straight
      // from GET /sessions/{id}/report. Null when the envelope could not be
      // fetched — the export then honestly lacks the signature instead of
      // carrying a fabricated one.
      signed_report: signedReport
        ? {
            report_id: signedReport.report_id,
            generated_at: signedReport.generated_at,
            integrity_status: signedReport.integrity_status,
            integrity_error: signedReport.integrity_error || null,
            head_event_hash: signedReport.head_event_hash,
            event_count: signedReport.event_count,
            findings_count: signedReport.findings_count,
            approvals_count: signedReport.approvals_count,
            incidents_count: signedReport.incidents_count,
            report_signature_sha256: signedReport.report_signature_sha256,
            chain_binding: signedReport.chain_binding,
            incidents_summary: signedReport.incidents_summary,
            reasoning_trail: signedReport.reasoning_trail,
          }
        : null,
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
        style={{ width: '100%', maxWidth: '640px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', maxHeight: '90vh', overflowY: 'auto' }}
      >
        {/* Header */}
        <div className="flex-between">
          <div className="flex" style={{ gap: '10px' }}>
            <div className="brand-mark brand-mark--sm">
              <FileCheck size={18} color="#000000" />
            </div>
            <div>
              <h2 id="report-modal-title" className="font-heading" style={{ fontSize: '16px', fontWeight: 650 }}>
                Forensic Audit Export Manifest
              </h2>
              <p className="font-mono" style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                {session.session_id}
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close dialog" className="btn btn-ghost btn-icon">
            <X size={16} />
          </button>
        </div>

        {/* Verification Status Banner */}
        <div
          style={{
            background: 'var(--bg-card-solid)',
            border: isChainValid ? '1px solid #ffffff' : '1px solid var(--border-dim)',
            borderRadius: '10px',
            padding: '14px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            boxShadow: isChainValid ? '0 0 18px rgba(255,255,255,0.12)' : 'none',
          }}
        >
          {verifying ? (
            <div className="flex" style={{ gap: '10px' }}>
              <div className="live-dot" />
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Recomputing cryptographic hash chain…</span>
            </div>
          ) : isChainValid ? (
            <>
              <ShieldCheck size={26} color="#ffffff" style={{ flexShrink: 0 }} />
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 650, color: '#ffffff' }}>Hash Chain: VERIFIED</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  All {verification?.event_count ?? timeline.length} event hashes recomputed from canonical JSON preimages — chain unbroken.
                </p>
              </div>
            </>
          ) : (
            <>
              <ShieldAlert size={26} color="#71717a" style={{ flexShrink: 0 }} />
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 650, color: '#ffffff' }}>Hash Chain: UNVERIFIED</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {verification?.error || 'Integrity could not be confirmed.'}
                </p>
              </div>
            </>
          )}
        </div>

        {/* Audit Metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
          <div className="stat">
            <div className="stat-label">SEALED EVENTS</div>
            <div className="stat-value">{timeline.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">CONTEXT NODES</div>
            <div className="stat-value">{graphData?.nodes.length || 0}</div>
          </div>
          <div className="stat">
            <div className="stat-label">POLICY GATES</div>
            <div className="stat-value">{findings.length}</div>
          </div>
        </div>

        {/* Cryptographic Head Hash */}
        <div className="flex-col" style={{ gap: '5px' }}>
          <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
            Head Event Hash (Chain Root)
          </label>
          <div className="code-block" style={{ fontSize: '11px', color: '#d4d4d8', wordBreak: 'break-all' }}>
            {lastEventHash || '—'}
          </div>
          {!lastEventHash && (
            <p style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
              No chain root — no events have been sealed and verified for this session.
            </p>
          )}
        </div>

        {/* Incidents summary — from the server's signed report, not client-side */}
        {signedReport && signedReport.incidents_summary.length > 0 && (
          <div className="flex-col" style={{ gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
              Incidents ({signedReport.incidents_count})
            </label>
            {signedReport.incidents_summary.map((inc) => (
              <div key={inc.incident_id} className="card" style={{ padding: '8px 10px', fontSize: '11px' }}>
                <div className="flex-between">
                  <span className={`badge badge-${inc.severity === 'critical' ? 'critical' : inc.severity === 'high' ? 'high' : inc.severity === 'low' ? 'low' : 'medium'}`}>
                    {inc.incident_type}
                  </span>
                  <span className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)' }}>
                    {inc.related_events.length} linked event(s)
                  </span>
                </div>
                <div style={{ marginTop: '4px', color: '#e4e4e7' }}>{inc.title}</div>
              </div>
            ))}
          </div>
        )}

        {/* Reasoning trail — the model's own captured thinking around risky
            actions. Rendered verbatim from the signed envelope; the server
            already redacts excerpts through the write-boundary redactor. */}
        {signedReport && signedReport.reasoning_trail.length > 0 && (
          <div className="flex-col" style={{ gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
              Reasoning Trail ({signedReport.reasoning_trail.length})
            </label>
            {signedReport.reasoning_trail.map((r) => (
              <div key={r.event_id} className="card" style={{ padding: '8px 10px' }}>
                <div className="flex-between" style={{ marginBottom: '3px' }}>
                  <span className="badge badge-medium">{r.kind}</span>
                  <span className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)' }}>
                    {new Date(r.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="font-mono" style={{ fontSize: '10px', color: '#d4d4d8', whiteSpace: 'pre-wrap' }}>
                  {r.excerpt}
                </div>
              </div>
            ))}
          </div>
        )}

        {signedReport && signedReport.reasoning_trail.length === 0 && (
          <p style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
            No context-boundary reasoning was captured for this session — the gap is stated, not filled.
          </p>
        )}

        {signedReport && (
          <p className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)', wordBreak: 'break-all' }}>
            signature: {signedReport.report_signature_sha256}
            <br />
            chain binding: tip {signedReport.chain_binding.chain_tip.slice(0, 24)}… · len {signedReport.chain_binding.chain_length}
          </p>
        )}

        {/* Action Buttons */}
        <div className="flex" style={{ justifyContent: 'flex-end', gap: '10px', marginTop: '6px' }}>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={handleExportJSON} className="btn btn-primary" disabled={downloading}>
            {downloading ? <Check size={14} /> : <Download size={14} />}
            {downloading ? 'Exported!' : 'Export Report (JSON)'}
          </button>
        </div>
      </div>
    </div>
  );
};
