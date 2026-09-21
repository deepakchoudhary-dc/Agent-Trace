import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api/client';
import { SessionInfo, ForensicManifest, VerificationResult } from '../types';
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
  onClose: () => void;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  session,
  onClose,
}) => {
  const [downloading, setDownloading] = useState(false);
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [manifest, setManifest] = useState<ForensicManifest | null>(null);
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
      setManifest(null);
      setVerification(null);
      void (async () => {
        // The signed manifest is the single source of truth for this modal, so
        // it is fetched first: the chain banner below then falls back to the
        // manifest's own signed verdict rather than numbers read from client
        // state. Failure leaves the state null — the modal renders the honest
        // "unavailable" gap instead of a synthetic placeholder.
        const loaded: ForensicManifest | null = await api
          .getSignedForensicReport(session.session_id)
          .catch(() => null);
        if (active) setManifest(loaded);

        try {
          const res = await api.verifyChain(session.session_id);
          if (active) setVerification(res);
        } catch {
          if (active) {
            // Live re-verification is unreachable. Never synthesise a head hash
            // from client state — state the signed manifest's own verdict when
            // it exists, otherwise leave the verdict absent so the banner shows
            // the gap.
            setVerification(
              loaded
                ? {
                    session_id: session.session_id,
                    verified: loaded.chain.integrity_status === 'TAMPER_VERIFIED',
                    error:
                      loaded.chain.integrity_error ??
                      'Live chain re-verification unavailable',
                    event_count: loaded.chain.chain_length,
                    last_event_hash: loaded.chain.head_event_hash,
                  }
                : null
            );
          }
        }
        if (active) setVerifying(false);
      })();
    }
    return () => {
      active = false;
    };
  }, [session?.session_id]);

  if (!session) return null;

  // The manifest is fetched per session, so one loaded for a previously
  // selected session must never be rendered or exported under the current
  // session's name. Requiring the ids to match is what keeps the export safe
  // when the operator switches sessions with this modal still open — the
  // browser no longer assembles a report, so there is no other guard between
  // stale session state and the exported file.
  const currentManifest =
    manifest && manifest.session.session_id === session.session_id ? manifest : null;

  const isChainValid = verification ? verification.verified : false;
  // Never fabricate a chain root: the live verification result first, then the
  // signed manifest's own head hash, otherwise an explicit gap.
  const lastEventHash =
    verification?.last_event_hash || currentManifest?.chain.head_event_hash || '';

  const handleExportJSON = () => {
    // Nothing signed means nothing to export: emitting a file the server did
    // not sign would hand the operator an unauthenticated document.
    if (!currentManifest) return;
    setDownloading(true);
    // The daemon builds, self-checks and HMAC-signs this document in one place.
    // Download it verbatim — re-assembling it here is what produced a report
    // whose own numbers contradicted each other and that carried no signature.
    const blob = new Blob([JSON.stringify(currentManifest, null, 2)], {
      type: 'application/json',
    });
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
          ) : isChainValid && verification ? (
            <>
              <ShieldCheck size={26} color="#ffffff" style={{ flexShrink: 0 }} />
              <div>
                <h4 style={{ fontSize: '13px', fontWeight: 650, color: '#ffffff' }}>Hash Chain: VERIFIED</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  All {verification.event_count} event hashes recomputed from canonical JSON preimages — chain unbroken.
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

        {/* Audit Metrics — read from the signed manifest, never from client
            state: those two sources were never reconciled. */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
          <div className="stat">
            <div className="stat-label">SEALED EVENTS</div>
            <div className="stat-value">{currentManifest ? currentManifest.audit_statistics.total_events : '—'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">CONTEXT NODES</div>
            <div className="stat-value">{currentManifest ? currentManifest.audit_statistics.context_nodes : '—'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">POLICY GATES</div>
            <div className="stat-value">{currentManifest ? currentManifest.audit_statistics.findings : '—'}</div>
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

        {/* Signed manifest verdicts — the facts an operator needs and the old
            browser-assembled export dropped entirely. */}
        {currentManifest && (
          <div className="flex-col" style={{ gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
              Signed Manifest Facts
            </label>
            <div className="flex" style={{ gap: '6px', flexWrap: 'wrap' }}>
              <span
                className={`badge ${
                  currentManifest.chain.integrity_status === 'TAMPER_VERIFIED'
                    ? 'badge-low'
                    : 'badge-critical'
                }`}
              >
                {currentManifest.chain.integrity_status}
              </span>
              <span className="badge badge-medium">
                chain length {currentManifest.chain.chain_length}
              </span>
              <span
                className={`badge ${
                  currentManifest.chain.binding.operator_anchored ? 'badge-low' : 'badge-high'
                }`}
              >
                operator anchor {currentManifest.chain.binding.operator_anchored ? 'present' : 'absent'}
              </span>
              <span
                className={`badge ${currentManifest.task_contract.usable ? 'badge-low' : 'badge-high'}`}
              >
                task contract {currentManifest.task_contract.usable ? 'usable' : 'unusable'}
              </span>
              <span
                className={`badge ${
                  currentManifest.temporal_integrity.events_outside_session_window > 0
                    ? 'badge-high'
                    : 'badge-low'
                }`}
              >
                {currentManifest.temporal_integrity.events_outside_session_window} event(s) outside
                session window
              </span>
              <span className="badge badge-medium">
                agent-scoped {currentManifest.agent_scope.agent_scoped} /{' '}
                {currentManifest.agent_scope.total}
              </span>
            </div>
            <div className="flex" style={{ gap: '6px', flexWrap: 'wrap' }}>
              <span className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)' }}>
                severity (findings + incidents, {currentManifest.audit_statistics.by_severity.total}):
              </span>
              {Object.entries(currentManifest.audit_statistics.by_severity.counts).map(([sev, n]) => (
                <span key={sev} className={`badge badge-${sev === 'info' ? 'low' : sev}`}>
                  {sev}: {n}
                </span>
              ))}
              {Object.entries(currentManifest.audit_statistics.by_severity.unknown_counts).map(
                ([sev, n]) => (
                  <span key={`unknown-${sev}`} className="badge badge-info">
                    {sev}: {n}
                  </span>
                )
              )}
              {currentManifest.audit_statistics.by_severity.max_severity && (
                <span
                  className={`badge badge-${
                    currentManifest.audit_statistics.by_severity.max_severity === 'info'
                      ? 'low'
                      : currentManifest.audit_statistics.by_severity.max_severity
                  }`}
                >
                  max: {currentManifest.audit_statistics.by_severity.max_severity}
                </span>
              )}
            </div>
            {!currentManifest.task_contract.usable && (
              <p style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                {currentManifest.task_contract.note}
              </p>
            )}
          </div>
        )}

        {/* Incidents summary — from the server's signed report, not client-side */}
        {currentManifest && currentManifest.incidents_summary.length > 0 && (
          <div className="flex-col" style={{ gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
              Incidents ({currentManifest.audit_statistics.incidents})
            </label>
            {currentManifest.incidents_summary.map((inc) => (
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
        {currentManifest && currentManifest.reasoning_trail.length > 0 && (
          <div className="flex-col" style={{ gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
              Reasoning Trail ({currentManifest.reasoning_trail.length})
            </label>
            {currentManifest.reasoning_trail.map((r) => (
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

        {currentManifest && currentManifest.reasoning_trail.length === 0 && (
          <p style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
            No context-boundary reasoning was captured for this session — the gap is stated, not filled.
          </p>
        )}

        {currentManifest && (
          <p className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)', wordBreak: 'break-all' }}>
            signature: {currentManifest.report_signature.signature}
            <br />
            chain binding: {currentManifest.chain.integrity_status} · tip{' '}
            {currentManifest.chain.binding.chain_tip.slice(0, 24)}… · len{' '}
            {currentManifest.chain.binding.chain_length} · operator-anchored{' '}
            {currentManifest.chain.binding.operator_anchored ? 'yes' : 'no'}
          </p>
        )}

        {!verifying && !currentManifest && (
          <p style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
            The signed manifest could not be loaded for this session, so there is nothing to export.
            An unsigned or partly assembled file would not be evidence — the daemon must be
            reachable to issue one.
          </p>
        )}

        {/* Action Buttons */}
        <div className="flex" style={{ justifyContent: 'flex-end', gap: '10px', marginTop: '6px' }}>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button
            onClick={handleExportJSON}
            className="btn btn-primary"
            disabled={downloading || !currentManifest}
          >
            {downloading ? <Check size={14} /> : <Download size={14} />}
            {downloading ? 'Exported!' : 'Export Report (JSON)'}
          </button>
        </div>
      </div>
    </div>
  );
};
