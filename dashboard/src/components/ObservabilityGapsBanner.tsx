import React from 'react';
import { EyeOff } from 'lucide-react';
import { SessionInfo } from '../types';

interface ObservabilityGapsBannerProps {
  session: SessionInfo;
}

/**
 * Renders the adapter's declared observability gaps prominently.
 *
 * What AgentTrace could not see is a first-class feature, not a caveat:
 * the ledger never fabricates explanations for unobserved activity. Showing
 * the gap is the honest alternative to pretending the picture is complete.
 */
export const ObservabilityGapsBanner: React.FC<ObservabilityGapsBannerProps> = ({
  session,
}) => {
  const gaps = session.observability_gaps ?? [];
  if (gaps.length === 0) {
    return null;
  }

  return (
    <div
      className="glass-panel"
      role="note"
      aria-label="Observability gaps"
      style={{
        margin: '0 16px 10px',
        padding: '10px 14px',
        borderRadius: '10px',
        border: '1px solid var(--border-medium)',
        background: 'rgba(180, 150, 20, 0.06)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: gaps.length > 1 ? '6px' : 0 }}>
        <EyeOff size={13} color="var(--text-muted)" />
        <span className="font-heading" style={{ fontSize: '11px', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
          WHAT WE COULD NOT SEE
        </span>
        <span
          className="badge badge-low"
          style={{ fontSize: '8.5px', padding: '1px 6px' }}
          title="Declared by the session adapter"
        >
          ADAPTER DECLARED
        </span>
      </div>
      {gaps.map((gap) => (
        <p key={gap} style={{ fontSize: '11.5px', color: 'var(--text-dim)', marginTop: '4px' }}>
          {gap}
        </p>
      ))}
      <p
        style={{
          fontSize: '10px',
          color: 'var(--text-dim)',
          marginTop: '6px',
          opacity: 0.8,
        }}
      >
        Activity inside these gaps is not observed — the ledger says nothing about it rather
        than inventing an explanation.
      </p>
    </div>
  );
};