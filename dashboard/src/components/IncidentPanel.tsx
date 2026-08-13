import React from 'react';
import { PolicyFinding, EvidencePath } from '../types';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
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
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', gap: '14px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={16} color="#ffffff" />
            <h2 className="font-heading" style={{ fontSize: '15px', fontWeight: 600 }}>
              Active Policy Findings ({findings.length})
            </h2>
          </div>
          {findings.length > 0 ? (
            <span className="badge badge-critical">Gated By Policy</span>
          ) : (
            <span className="badge badge-high">Clean & Compliant</span>
          )}
        </div>

        {findings.length === 0 ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--text-dim)', gap: '10px' }}>
            <ShieldCheck size={32} color="#ffffff" />
            <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
              No Security Incidents or Violations
            </h3>
            <p style={{ fontSize: '11.5px' }}>
              All observed actions comply with workspace constraints and security policies.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {findings.map((finding) => (
              <div
                key={finding.finding_id}
                style={{
                  background: '#09090b',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="badge badge-critical">{finding.severity}</span>
                  <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    {new Date(finding.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div>
                  <h3 style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                    {finding.finding_type.replace('_', ' ').toUpperCase()}
                  </h3>
                  <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '3px' }}>
                    {finding.description}
                  </p>
                </div>

                {finding.affected_command && (
                  <div style={{ background: '#000000', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
                    <span style={{ fontSize: '9px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>COMMAND:</span>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#ffffff' }}>
                      {finding.affected_command}
                    </div>
                  </div>
                )}

                {finding.affected_path && (
                  <div style={{ background: '#000000', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border-dim)' }}>
                    <span style={{ fontSize: '9px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>PATH:</span>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#ffffff' }}>
                      {finding.affected_path}
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '2px' }}>
                  <button
                    onClick={() => onRequestApproval(finding)}
                    className="btn btn-primary"
                    style={{ fontSize: '11px', padding: '5px 12px' }}
                  >
                    <Lock size={12} />
                    Authorize & Sign Approval
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Backward Causal Root-Cause Analysis */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', gap: '14px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={16} color="#ffffff" />
          <h2 className="font-heading" style={{ fontSize: '15px', fontWeight: 600 }}>
            Backward Causal Root-Cause Path
          </h2>
        </div>

        <p style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
          Traversing backward from suspicious incident to originating prompt and tool invocations:
        </p>

        {causalPaths.length === 0 ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--text-dim)', gap: '8px' }}>
            <p style={{ fontSize: '11.5px' }}>
              Select a node in Context Graph to inspect backward causal antecedents.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {causalPaths.map((path) => (
              <div
                key={path.path_id}
                style={{
                  background: '#09090b',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '8px',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="badge badge-high">
                    Confidence: {(path.overall_confidence * 100).toFixed(0)}%
                  </span>
                  <span style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                    {path.nodes.length} Causal Nodes
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {path.description.split(' → ').map((step, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '6px 10px',
                        background: idx === 0 ? '#18181b' : '#0f0f10',
                        border: '1px solid var(--border-dim)',
                        borderRadius: '4px',
                      }}
                    >
                      <span className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)', width: '18px' }}>
                        #{idx + 1}
                      </span>
                      <span style={{ fontSize: '11.5px', fontWeight: 500, color: '#ffffff' }}>
                        {step}
                      </span>
                    </div>
                  ))}
                </div>

                <div style={{ fontSize: '10.5px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                  {path.evidence_summary}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
