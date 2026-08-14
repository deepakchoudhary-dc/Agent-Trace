import React, { useState, useEffect, useRef } from 'react';
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
  const reasonRef = useRef<HTMLInputElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (finding) {
      setScope(finding.affected_path || finding.affected_command || 'workspace_scoped');
      // Focus the reason field when the modal opens
      const t = setTimeout(() => reasonRef.current?.focus(), 50);
      return () => clearTimeout(t);
    }
  }, [finding]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting) {
        closeRef.current();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [submitting]);

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
        style={{ width: '100%', maxWidth: '520px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', boxShadow: 'var(--shadow-pop)' }}
      >
        <div className="flex-between">
          <div className="flex" style={{ gap: '10px' }}>
            <div className="brand-mark brand-mark--sm">
              <ShieldAlert size={18} color="#000000" />
            </div>
            <div>
              <h2 id="approval-gate-title" className="font-heading" style={{ fontSize: '15px', fontWeight: 650 }}>
                Risk-Tiered Approval Gate
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Authenticated event will be appended to the cryptographic ledger
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close approval dialog" className="btn btn-ghost btn-icon">
            <X size={16} />
          </button>
        </div>

        <div className="code-block" style={{ fontSize: '12px' }}>
          <div style={{ color: '#ffffff', fontWeight: 650, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            {finding.finding_type.replace(/_/g, ' ')}
          </div>
          <div style={{ color: 'var(--text-muted)', marginTop: '5px', fontWeight: 400, fontFamily: 'var(--font-sans)' }}>
            {finding.description}
          </div>
        </div>

        <div className="flex-col" style={{ gap: '5px' }}>
          <label htmlFor="approval-reason" style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
            Approval Reason (Signed Record)
          </label>
          <input
            id="approval-reason"
            ref={reasonRef}
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={submitting}
            className="input"
          />
        </div>

        <div className="flex-col" style={{ gap: '5px' }}>
          <label htmlFor="approval-scope" style={{ fontSize: '11px', fontWeight: 550, color: 'var(--text-muted)' }}>
            Scoped Path or Command Filter
          </label>
          <input
            id="approval-scope"
            type="text"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            disabled={submitting}
            className="input input--mono"
          />
        </div>

        <div className="flex" style={{ justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
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
            {submitting ? 'Signing in Ledger…' : 'Sign & Approve'}
          </button>
        </div>
      </div>
    </div>
  );
};
