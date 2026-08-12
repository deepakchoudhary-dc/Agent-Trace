import React from 'react';
import { PolicyFinding, EvidencePath } from '../types';
import {
  AlertTriangle,
  ShieldAlert,
  Lock,
} from 'lucide-react';

interface IncidentPanelProps {
  findings: PolicyFinding[];
  causalPaths: EvidencePath[];
  onRequestApproval: (finding: PolicyFinding) => void;
}

export const IncidentPanel: React.FC<IncidentPanelProps> = ({
  findings,
  causalPaths,
  onRequestApproval,
}) => {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* Policy Findings & Gated Incidents */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', gap: '16px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} color="#f43f5e" />
            <h2 className="font-heading" style={{ fontSize: '16px', fontWeight: 600 }}>
              Active Policy Incidents ({findings.length})
            </h2>
          </div>
          <span className="badge badge-critical">Gated By Policy</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {findings.map((finding) => (
            <div
              key={finding.event_id}
              style={{
                background: 'rgba(244, 63, 94, 0.05)',
                border: '1px solid rgba(244, 63, 94, 0.2)',
                borderRadius: '10px',
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className="badge badge-critical">{finding.severity}</span>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                  {new Date(finding.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)' }}>
                  {finding.finding_type.replace('_', ' ').toUpperCase()}
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  {finding.description}
                </p>
              </div>

              {finding.affected_command && (
                <div style={{ background: 'var(--bg-input)', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>COMMAND:</span>
                  <div className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)' }}>
                    {finding.affected_command}
                  </div>
                </div>
              )}

              {finding.affected_path && (
                <div style={{ background: 'var(--bg-input)', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>PATH:</span>
                  <div className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)' }}>
                    {finding.affected_path}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '4px' }}>
                <button
                  onClick={() => onRequestApproval(finding)}
                  className="btn btn-primary"
                  style={{ fontSize: '12px', padding: '6px 14px' }}
                >
                  <Lock size={12} />
                  Authorize / Grant Approval
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Backward Causal Root-Cause Analysis */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', gap: '16px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={18} color="var(--accent-cyan)" />
          <h2 className="font-heading" style={{ fontSize: '16px', fontWeight: 600 }}>
            Backward Causal Root-Cause Path
          </h2>
        </div>

        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Traversing backward from suspicious incident to originating prompt, untrusted repository context, and tool invocations:
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {causalPaths.map((path) => (
            <div
              key={path.path_id}
              style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-dim)',
                borderRadius: '10px',
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className="badge badge-high">
                  Confidence: {(path.overall_confidence * 100).toFixed(0)}%
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                  {path.nodes.length} Causal Nodes
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {path.description.split(' → ').map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '8px 12px',
                      background: idx === 0 ? 'rgba(6, 182, 212, 0.1)' : idx === path.description.split(' → ').length - 1 ? 'rgba(244, 63, 94, 0.1)' : 'var(--bg-input)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: '6px',
                    }}
                  >
                    <span className="font-mono" style={{ fontSize: '10px', color: 'var(--text-dim)', width: '20px' }}>
                      #{idx + 1}
                    </span>
                    <span style={{ fontSize: '12px', fontWeight: 500, color: idx === 0 ? 'var(--accent-cyan)' : idx === path.description.split(' → ').length - 1 ? '#f43f5e' : 'var(--text-main)' }}>
                      {step}
                    </span>
                  </div>
                ))}
              </div>

              <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                {path.evidence_summary}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
