import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
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
  const convergencePct = Math.round(current.convergence_score * 100);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 260px) 1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* Iterations Sidebar */}
      <div className="glass-panel" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px', minHeight: 0 }}>
        <div className="panel-header" style={{ padding: 0, border: 'none', background: 'transparent' }}>
          <div className="flex" style={{ gap: '8px' }}>
            <RefreshCw size={14} color="#ffffff" />
            <span className="panel-title">Iterations</span>
            <span className="chip">{iterations.length}</span>
          </div>
        </div>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {iterations.map((iter) => (
            <div
              key={iter.number}
              onClick={() => setActiveIteration(iter.number)}
              tabIndex={0}
              role="button"
              aria-label={`Iteration ${iter.number}`}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') setActiveIteration(iter.number);
              }}
              className={`card card--clickable ${activeIteration === iter.number ? 'card--selected' : ''}`}
              style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
            >
              <div>
                <div style={{ fontWeight: 650, fontSize: '12px', color: '#ffffff' }}>
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
        <div className="flex-between" style={{ borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div className="flex" style={{ gap: '8px' }}>
              <h2 className="font-heading" style={{ fontSize: '16px', fontWeight: 700 }}>
                Review Loop Convergence — Iteration #{current.number}
              </h2>
              <span className={`badge ${current.verdict === 'PASSED' ? 'badge-high' : 'badge-critical'}`}>
                {current.verdict}
              </span>
            </div>
            <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Autonomous multi-agent synthesis loop (Planner → Worker → Independent Reviewers → Synthesizer)
            </p>
          </div>

          <div className="flex" style={{ gap: '10px' }}>
            <div className="flex" style={{ gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Convergence</span>
              <span className="badge badge-high">{convergencePct}%</span>
            </div>
            <div
              style={{
                width: '110px',
                height: '6px',
                background: 'rgba(255,255,255,0.1)',
                borderRadius: '999px',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${convergencePct}%`,
                  height: '100%',
                  background: '#ffffff',
                  borderRadius: '999px',
                  boxShadow: '0 0 8px rgba(255,255,255,0.6)',
                  transition: 'width 0.4s var(--ease-out)',
                }}
              />
            </div>
          </div>
        </div>

        {/* Roles Flow Chart */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '10px' }}>
          {[
            { icon: Sparkles, title: 'PLANNER', body: current.planner_intent, mono: false },
            { icon: Cpu, title: 'WORKER', body: current.worker_patch, mono: true },
            {
              icon: FileCheck,
              title: 'SYNTHESIZER',
              body: current.verdict === 'PASSED' ? 'All criteria satisfied. Approved for merge.' : 'Failed criteria detected. Iteration loop resumed.',
              mono: false,
            },
          ].map(({ icon: Icon, title, body, mono }) => (
            <div key={title} className="card" style={{ padding: '12px' }}>
              <div className="flex" style={{ gap: '6px', marginBottom: '7px' }}>
                <Icon size={13} color="#ffffff" />
                <span style={{ fontSize: '10.5px', fontWeight: 650, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {title}
                </span>
              </div>
              <p className={mono ? 'font-mono' : ''} style={{ fontSize: '11px', color: mono ? '#ffffff' : 'var(--text-muted)', wordBreak: 'break-word' }}>
                {body}
              </p>
            </div>
          ))}
        </div>

        {/* Flow connector */}
        <div className="flex" style={{ justifyContent: 'center', color: 'var(--text-dim)' }}>
          <ArrowRight size={14} />
        </div>

        {/* Independent Reviewers Section */}
        <div>
          <h3 className="font-heading" style={{ fontSize: '13px', fontWeight: 650, marginBottom: '8px' }}>
            Independent Reviewer Verdicts
          </h3>
          <div className="flex-col" style={{ gap: '8px' }}>
            {current.reviews.map((rev, idx) => (
              <div
                key={idx}
                className="card"
                style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}
              >
                <div className="flex" style={{ gap: '10px', minWidth: 0 }}>
                  {rev.status === 'PASSED' ? (
                    <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0 }} />
                  ) : (
                    <XCircle size={15} color="#71717a" style={{ flexShrink: 0 }} />
                  )}
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: '12px', fontWeight: 650, color: '#ffffff' }}>
                      {rev.role}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {rev.comment}
                    </div>
                  </div>
                </div>

                <span className={`badge ${rev.status === 'PASSED' ? 'badge-high' : 'badge-low'}`} style={{ flexShrink: 0 }}>
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
