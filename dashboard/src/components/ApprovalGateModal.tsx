import React, { useState, useEffect } from 'react';
import { PolicyFinding } from '../types';
import { Check, X, ShieldAlert } from 'lucide-react';

interface ApprovalGateModalProps {
  finding: PolicyFinding | null;
  onClose: () => void;
  onConfirm: (findingId: string, approved: boolean, reason: string, scope: string) => Promise<void> | void;
}

export const ApprovalGateModal: React.FC<ApprovalGateModalProps> = ({
  finding,
  onClose,
  onConfirm,
}) => {
  const [reason, setReason] = useState('Authorized for workspace development');
  const [scope, setScope] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (finding) {
      setScope(finding.affected_path || finding.affected_command || 'workspace_scoped');
    }
  }, [finding]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose, submitting]);

  if (!finding) return null;

  const handleSubmit = async (approved: boolean) => {
    setSubmitting(true);
    try {
      await onConfirm(finding.finding_id, approved, reason, scope);
      onClose();
    } catch {
      // Handled by caller
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-gate-title"
    >
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{ width: '100%', maxWidth: '520px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert size={18} color="#000000" />
            </div>
            <div>
              <h2 id="approval-gate-title" className="font-heading" style={{ fontSize: '15px', fontWeight: 600 }}>
                Risk-Tiered Approval Gate
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Authenticated event will be appended to the cryptographic ledger
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close approval dialog"
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '20px' }}
          >
            &times;
          </button>
        </div>

        <div style={{ background: '#09090b', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-dim)', fontSize: '12px' }}>
          <div style={{ color: '#ffffff', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase' }}>
            {finding.finding_type}
          </div>
          <div style={{ color: 'var(--text-muted)', marginTop: '4px' }}>
            {finding.description}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
          <label htmlFor="approval-reason" style={{ fontSize: '11px', fontWeight: 500, color: 'var(--text-muted)' }}>
            Approval Reason (Signed Record)
          </label>
          <input
            id="approval-reason"
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={submitting}
            style={{
              background: '#09090b',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '7px 12px',
              color: 'var(--text-main)',
              fontSize: '12px',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
          <label htmlFor="approval-scope" style={{ fontSize: '11px', fontWeight: 500, color: 'var(--text-muted)' }}>
            Scoped Path or Command Filter
          </label>
          <input
            id="approval-scope"
            type="text"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            disabled={submitting}
            style={{
              background: '#09090b',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '7px 12px',
              color: 'var(--text-main)',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
          <button
            onClick={() => handleSubmit(false)}
            disabled={submitting}
            className="btn btn-secondary"
          >
            <X size={13} />
            Deny & Block Action
          </button>

          <button
            onClick={() => handleSubmit(true)}
            disabled={submitting}
            className="btn btn-primary"
          >
            <Check size={13} />
            {submitting ? 'Signing in Ledger...' : 'Sign & Approve'}
          </button>
        </div>
      </div>
    </div>
  );
};
