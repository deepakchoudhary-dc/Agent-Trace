import React, { useState } from 'react';
import { PolicyFinding } from '../types';
import { Check, X, ShieldAlert } from 'lucide-react';

interface ApprovalGateModalProps {
  finding: PolicyFinding | null;
  onClose: () => void;
  onConfirm: (findingId: string, approved: boolean, reason: string, scope: string) => void;
}

export const ApprovalGateModal: React.FC<ApprovalGateModalProps> = ({
  finding,
  onClose,
  onConfirm,
}) => {
  if (!finding) return null;

  const [reason, setReason] = useState('Authorized for workspace development');
  const [scope, setScope] = useState(finding.affected_path || 'workspace_scoped');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{ width: '100%', maxWidth: '520px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'rgba(244, 63, 94, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldAlert size={20} color="#f43f5e" />
          </div>
          <div>
            <h3 className="font-heading" style={{ fontSize: '16px', fontWeight: 600 }}>
              Risk-Tiered Approval Gate
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Signed cryptographic event will be appended to the ledger
            </p>
          </div>
        </div>

        <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)', fontSize: '13px' }}>
          <div style={{ color: '#f43f5e', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase' }}>
            {finding.finding_type}
          </div>
          <div style={{ color: 'var(--text-main)', marginTop: '4px' }}>
            {finding.description}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)' }}>
            Approval Reason (Signed Record)
          </label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '8px 12px',
              color: 'var(--text-main)',
              fontSize: '13px',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)' }}>
            Scoped Path or Command Filter
          </label>
          <input
            type="text"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '8px 12px',
              color: 'var(--text-main)',
              fontSize: '13px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
          <button
            onClick={() => {
              onConfirm(finding.event_id, false, reason, scope);
              onClose();
            }}
            className="btn btn-danger"
          >
            <X size={14} />
            Deny & Block Action
          </button>

          <button
            onClick={() => {
              onConfirm(finding.event_id, true, reason, scope);
              onClose();
            }}
            className="btn btn-success"
          >
            <Check size={14} />
            Sign & Approve
          </button>
        </div>
      </div>
    </div>
  );
};
