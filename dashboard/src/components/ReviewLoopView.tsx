import React, { useState } from 'react';
import {
  GitPullRequest,
  CheckCircle2,
  XCircle,
  AlertCircle,
  FileCheck,
  Cpu,
  RefreshCw,
  Sparkles,
  ArrowRight,
} from 'lucide-react';

export const ReviewLoopView: React.FC = () => {
  const [activeIteration, setActiveIteration] = useState<number>(1);

  // Structural review iteration data
  const iterations = [
    {
      number: 1,
      timestamp: '2026-08-13T10:14:00Z',
      verdict: 'FAILED',
      convergence_score: 0.65,
      planner_intent: 'Refactor canonical envelope serialization & hash chaining',
      worker_patch: 'src/agenttrace/models/events.py',
      reviews: [
        { role: 'Spec Compliance', status: 'PASSED', comment: 'All typed subclass attributes serialized in canonical JSON' },
        { role: 'Security & Redaction', status: 'FAILED', comment: 'Secret redaction must run before sealing hash' },
        { role: 'Convention & Style', status: 'PASSED', comment: 'Strict type annotations and zero lint errors' },
      ],
    },
    {
      number: 2,
      timestamp: '2026-08-13T10:18:00Z',
      verdict: 'PASSED',
      convergence_score: 1.0,
      planner_intent: 'Incorporate recursive secret sanitizer before ledger seal',
      worker_patch: 'src/agenttrace/storage/ledger.py',
      reviews: [
        { role: 'Spec Compliance', status: 'PASSED', comment: 'Verified deterministic SHA-256 pre-image matching' },
        { role: 'Security & Redaction', status: 'PASSED', comment: 'Entropy check & recursive dict sanitizer validated' },
        { role: 'Convention & Style', status: 'PASSED', comment: 'Standard schema compliance met' },
      ],
    },
  ];

  const current = iterations.find((i) => i.number === activeIteration) || iterations[0];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* Iterations Sidebar */}
      <div className="glass-panel" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <RefreshCw size={14} color="#ffffff" />
          <h2 className="font-heading" style={{ fontSize: '13px', fontWeight: 600 }}>
            Review Iterations ({iterations.length})
          </h2>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {iterations.map((iter) => (
            <div
              key={iter.number}
              onClick={() => setActiveIteration(iter.number)}
              tabIndex={0}
              role="button"
              aria-label={`Iteration ${iter.number}`}
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                cursor: 'pointer',
                background: activeIteration === iter.number ? '#18181b' : 'transparent',
                border: activeIteration === iter.number ? '1px solid #ffffff' : '1px solid var(--border-dim)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '12px', color: '#ffffff' }}>
                  Iteration #{iter.number}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                  {new Date(iter.timestamp).toLocaleTimeString()}
                </div>
              </div>
              <span className={`badge ${iter.verdict === 'PASSED' ? 'badge-high' : 'badge-low'}`} style={{ fontSize: '9px' }}>
                {iter.verdict}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Main Review Loop Trace */}
      <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px', overflowY: 'auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 className="font-heading" style={{ fontSize: '16px', fontWeight: 700 }}>
                Review Loop Convergence Trace — Iteration #{current.number}
              </h2>
              <span className={`badge ${current.verdict === 'PASSED' ? 'badge-high' : 'badge-critical'}`}>
                {current.verdict}
              </span>
            </div>
            <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Autonomous multi-agent synthesis loop (Planner → Worker → Independent Reviewers → Synthesizer)
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Convergence:</span>
            <span className="badge badge-high" style={{ fontSize: '10px' }}>
              {(current.convergence_score * 100).toFixed(0)}%
            </span>
          </div>
        </div>

        {/* Roles Flow Chart */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
          {/* Planner */}
          <div style={{ background: '#09090b', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
              <Sparkles size={13} color="#ffffff" />
              <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>PLANNER</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              {current.planner_intent}
            </p>
          </div>

          {/* Worker */}
          <div style={{ background: '#09090b', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
              <Cpu size={13} color="#ffffff" />
              <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>WORKER</span>
            </div>
            <p className="font-mono" style={{ fontSize: '11px', color: '#ffffff' }}>
              {current.worker_patch}
            </p>
          </div>

          {/* Synthesizer */}
          <div style={{ background: '#09090b', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
              <FileCheck size={13} color="#ffffff" />
              <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>SYNTHESIZER</span>
            </div>
            <p style={{ fontSize: '11px', color: current.verdict === 'PASSED' ? '#ffffff' : 'var(--text-muted)' }}>
              {current.verdict === 'PASSED' ? 'All criteria satisfied. Approved for merge.' : 'Failed criteria detected. Iteration loop resumed.'}
            </p>
          </div>
        </div>

        {/* Independent Reviewers Section */}
        <div>
          <h3 className="font-heading" style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>
            Independent Reviewer Verdicts
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {current.reviews.map((rev, idx) => (
              <div
                key={idx}
                style={{
                  background: '#09090b',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '6px',
                  padding: '10px 14px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {rev.status === 'PASSED' ? (
                    <CheckCircle2 size={15} color="#ffffff" />
                  ) : (
                    <XCircle size={15} color="#71717a" />
                  )}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#ffffff' }}>
                      {rev.role}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {rev.comment}
                    </div>
                  </div>
                </div>

                <span className={`badge ${rev.status === 'PASSED' ? 'badge-high' : 'badge-low'}`}>
                  {rev.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
