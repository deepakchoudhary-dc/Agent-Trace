import React from 'react';
import { PolicyFinding, EvidencePath } from '../types';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Lock,
  ChevronRight,
} from 'lucide-react';

interface IncidentPanelProps {
  findings: PolicyFinding[];
  causalPaths: EvidencePath[];
  onRequestApproval: (finding: PolicyFinding) => void;
}

const severityBadge = (severity: string) => {
  switch (severity) {
    case 'critical':
      return <span className="badge badge-critical">{severity}</span>;
    case 'high':
      return <span className="badge badge-high">{severity}</span>;
    case 'medium':
      return <span className="badge badge-medium">{severity}</span>;
    default:
      return <span className="badge badge-low">{severity}</span>;
  }
};

export const IncidentPanel: React.FC<IncidentPanelProps> = ({
  findings,
  causalPaths,
  onRequestApproval,
}) => {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
        gap: '16px',
        margin: '0 16px 16px 16px',
        height: 'calc(100vh - 120px)',
      }}
    >
      {/* Policy Findings & Gated Incidents */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <AlertTriangle size={16} color="#ffffff" />
            <span className="panel-title">Active Policy Findings</span>
            <span className="chip">{findings.length}</span>
          </div>
          {findings.length > 0 ? (
            <span className="badge badge-critical">GATED BY POLICY</span>
          ) : (
            <span className="badge badge-high">CLEAN & COMPLIANT</span>
          )}
        </div>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          {findings.length === 0 ? (
            <div className="empty-state">
              <ShieldCheck size={34} color="#ffffff" />
              <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
                No Security Incidents or Violations
              </h3>
              <p style={{ fontSize: '11.5px' }}>
                All observed actions comply with workspace constraints and security policies.
              </p>
            </div>
          ) : (
            <div className="flex-col" style={{ gap: '10px' }}>
              {findings.map((finding) => (
                <div
                  key={finding.finding_id}
                  className="card"
                  style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '9px' }}
                >
                  <div className="flex-between">
                    {severityBadge(finding.severity)}
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontVariantNumeric: 'tabular-nums' }}>
                      {new Date(finding.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <div>
                    <h3 style={{ fontSize: '13px', fontWeight: 650, color: '#ffffff' }}>
                      {finding.finding_type.replace(/_/g, ' ').toUpperCase()}
                    </h3>
                    <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '3px' }}>
                      {finding.description}
                    </p>
                  </div>

                  {finding.affected_command && (
                    <div>
                      <div className="stat-label" style={{ marginBottom: '3px' }}>COMMAND</div>
                      <div className="code-block" style={{ fontSize: '10.5px' }}>
                        {finding.affected_command}
                      </div>
                    </div>
                  )}

                  {finding.affected_path && (
                    <div>
                      <div className="stat-label" style={{ marginBottom: '3px' }}>PATH</div>
                      <div className="code-block" style={{ fontSize: '10.5px' }}>
                        {finding.affected_path}
                      </div>
                    </div>
                  )}

                  <div className="flex" style={{ justifyContent: 'flex-end', marginTop: '2px' }}>
                    <button
                      onClick={() => onRequestApproval(finding)}
                      className="btn btn-primary btn-sm"
                    >
                      <Lock size={12} />
                      Authorize & Sign
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Backward Causal Root-Cause Analysis */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <ShieldAlert size={16} color="#ffffff" />
            <span className="panel-title">Backward Causal Root-Cause Path</span>
          </div>
        </div>

        <p style={{ padding: '12px 16px 0 16px', fontSize: '11.5px', color: 'var(--text-muted)' }}>
          Traversing backward from suspicious incident to originating prompt and tool invocations:
        </p>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          {causalPaths.length === 0 ? (
            <div className="empty-state">
              <p style={{ fontSize: '11.5px' }}>
                Select a node in the Context Graph to inspect backward causal antecedents.
              </p>
            </div>
          ) : (
            <div className="flex-col" style={{ gap: '10px' }}>
              {causalPaths.map((path) => (
                <div
                  key={path.path_id}
                  className="card"
                  style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}
                >
                  <div className="flex-between">
                    <span className="badge badge-high">
                      Confidence: {(path.overall_confidence * 100).toFixed(0)}%
                    </span>
                    <span style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                      {path.nodes.length} causal nodes
                    </span>
                  </div>

                  <div className="flex-col" style={{ gap: '6px' }}>
                    {path.description.split(' → ').map((step, idx) => (
                      <div
                        key={idx}
                        className="flex"
                        style={{
                          gap: '8px',
                          padding: '7px 10px',
                          background: idx === 0 ? '#18181b' : '#0c0c0d',
                          border: '1px solid var(--border-dim)',
                          borderRadius: '6px',
                        }}
                      >
                        <span className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)', width: '18px', flexShrink: 0 }}>
                          #{idx + 1}
                        </span>
                        <span style={{ fontSize: '11.5px', fontWeight: 500, color: '#ffffff' }}>
                          {step}
                        </span>
                        {idx < path.description.split(' → ').length - 1 && (
                          <ChevronRight size={12} color="var(--text-dim)" style={{ marginLeft: 'auto', flexShrink: 0 }} />
                        )}
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
    </div>
  );
};
