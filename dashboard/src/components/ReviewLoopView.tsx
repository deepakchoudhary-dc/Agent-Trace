import React from 'react';
import {
  Repeat,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';

export const ReviewLoopView: React.FC = () => {
  return (
    <div className="glass-panel" style={{ margin: '0 16px 16px 16px', padding: '24px', height: 'calc(100vh - 120px)', overflowY: 'auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Repeat size={20} color="var(--accent-cyan)" />
            <h2 className="font-heading" style={{ fontSize: '18px', fontWeight: 700 }}>
              AgentTrace Self-Improving Review Loop
            </h2>
            <span className="badge badge-high">Active Protocol</span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Multi-agent self-verification cycle based on AGENTS.md, mind.md & review.md standards
          </p>
        </div>
      </div>

      {/* Visual Flow Architecture */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', alignItems: 'center', marginBottom: '32px' }}>
        {/* Step 1: Task */}
        <div style={{ background: 'rgba(6, 182, 212, 0.08)', border: '1px solid rgba(6, 182, 212, 0.3)', borderRadius: '12px', padding: '16px', textAlign: 'center' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--accent-cyan)', color: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px auto', fontWeight: 700 }}>
            1
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--accent-cyan)' }}>Task Contract</h4>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            User intent, allowed paths & risk constraints
          </p>
        </div>

        {/* Step 2: Planner */}
        <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-dim)', borderRadius: '12px', padding: '16px', textAlign: 'center' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'rgba(255,255,255,0.1)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px auto', fontWeight: 700 }}>
            2
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600 }}>Planner (Ephemeral)</h4>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Subtask decomposition & acceptance criteria
          </p>
        </div>

        {/* Step 3: Worker */}
        <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '12px', padding: '16px', textAlign: 'center' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: '#10b981', color: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px auto', fontWeight: 700 }}>
            3
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: '#10b981' }}>Worker (Resident)</h4>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Executes code & incorporates reviewer feedback
          </p>
        </div>

        {/* Step 4: Multi Reviewers */}
        <div style={{ background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.3)', borderRadius: '12px', padding: '16px', textAlign: 'center' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: '#a855f7', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px auto', fontWeight: 700 }}>
            4
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: '#a855f7' }}>Reviewers 1..N</h4>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Spec, Anti-Slop, Security & Conventions
          </p>
        </div>

        {/* Step 5: Synthesiser */}
        <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-dim)', borderRadius: '12px', padding: '16px', textAlign: 'center' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'rgba(255,255,255,0.1)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 8px auto', fontWeight: 700 }}>
            5
          </div>
          <h4 style={{ fontSize: '14px', fontWeight: 600 }}>Synthesiser</h4>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Pass / Fail verdict & structured feedback loop
          </p>
        </div>
      </div>

      {/* Convergence & Anti-Slop Checklist */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Anti-Slop 6 Critical Gates */}
        <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '12px', padding: '16px', border: '1px solid var(--border-dim)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <ShieldCheck size={16} color="#10b981" />
            <h3 className="font-heading" style={{ fontSize: '14px', fontWeight: 600 }}>
              6 Anti-Slop Verification Gates (review.md)
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[
              { title: 'Plausible but Incorrect Logic', status: 'Passed', desc: 'Syntax strictly satisfies business intent' },
              { title: 'Over-Engineering', status: 'Passed', desc: 'No enterprise generic abstractions for simple tasks' },
              { title: 'Convention Blindness', status: 'Passed', desc: 'Adheres to existing repo naming & error patterns' },
              { title: 'Hallucinated / Deprecated APIs', status: 'Passed', desc: 'Every endpoint & library verified in Python 3.10' },
              { title: 'Defensive Overreach', status: 'Passed', desc: 'No bare excepts or error swallowing' },
              { title: 'Cargo-Cult Patterns', status: 'Passed', desc: 'No redundant circuit breakers or sync retry loops' },
            ].map((gate, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', padding: '8px', background: 'var(--bg-input)', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>{gate.title}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{gate.desc}</div>
                </div>
                <span className="badge badge-high" style={{ fontSize: '9px' }}>{gate.status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Convergence Metrics & gotchas.md logger */}
        <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '12px', padding: '16px', border: '1px solid var(--border-dim)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Sparkles size={16} color="var(--accent-cyan)" />
            <h3 className="font-heading" style={{ fontSize: '14px', fontWeight: 600 }}>
              Self-Improvement & Gotchas Log
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                Convergence Metric
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
                <span className="font-mono" style={{ fontSize: '24px', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                  100%
                </span>
                <span style={{ fontSize: '12px', color: '#10b981' }}>Converged (Iteration 1)</span>
              </div>
            </div>

            <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                Living Gotchas Register (gotchas.md)
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                • Python 3.10 StrEnum compatibility: Standardized to (str, Enum) across all canonical models.<br/>
                • Local storage: WAL mode sqlite3 provides full durability without native C-compiler prerequisites.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
