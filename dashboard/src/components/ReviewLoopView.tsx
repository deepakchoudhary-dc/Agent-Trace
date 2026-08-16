import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  MinusCircle,
  FileCheck,
  Cpu,
  RefreshCw,
  Play,
  Terminal,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';
import { ReviewRunData, ReviewVerdict } from '../types';

interface ReviewLoopViewProps {
  sessionId: string | null;
}

const VERDICT_ICON: Record<ReviewVerdict, React.ReactNode> = {
  PASSED: <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0 }} />,
  FAILED: <XCircle size={15} color="#ffffff" style={{ flexShrink: 0 }} />,
  PARTIAL: <MinusCircle size={15} color="#fbbf24" style={{ flexShrink: 0 }} />,
};

export const ReviewLoopView: React.FC<ReviewLoopViewProps> = ({ sessionId }) => {
  const [data, setData] = useState<ReviewRunData | null>(null);
  const [activeIteration, setActiveIteration] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(false);
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const load = useCallback(async (sid: string) => {
    setLoading(true);
    setError('');
    try {
      const run = await api.getReviewRun(sid);
      setData(run.payload);
      setActiveIteration(run.payload.total_iterations || 1);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : '';
      if (message.includes('404')) {
        setData(null);
      } else {
        setError(message || 'Failed to load review run');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setData(null);
    if (sessionId) {
      load(sessionId);
    }
  }, [sessionId, load]);

  const handleRunReview = async () => {
    if (!sessionId) return;
    setRunning(true);
    setError('');
    try {
      const run = await api.runReview(sessionId);
      setData(run);
      setActiveIteration(run.total_iterations || 1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Review run failed');
    } finally {
      setRunning(false);
    }
  };

  const iterations = data?.iterations || [];
  const current = iterations.find((i) => i.iteration === activeIteration) || iterations[iterations.length - 1];
  const convergenceScore =
    typeof data?.convergence_metrics?.convergence_score === 'number'
      ? (data.convergence_metrics.convergence_score as number)
      : 0;
  const convergencePct = Math.round(convergenceScore * 100);

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

        {iterations.length > 0 ? (
          <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {iterations.map((iter) => (
              <div
                key={iter.iteration}
                onClick={() => setActiveIteration(iter.iteration)}
                tabIndex={0}
                role="button"
                aria-label={`Iteration ${iter.iteration}`}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') setActiveIteration(iter.iteration);
                }}
                className={`card card--clickable ${activeIteration === iter.iteration ? 'card--selected' : ''}`}
                style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
              >
                <div>
                  <div style={{ fontWeight: 650, fontSize: '12px', color: '#ffffff' }}>
                    Iteration #{iter.iteration}
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    {new Date(iter.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <span className={`badge ${iter.passed ? 'badge-high' : 'badge-critical'}`} style={{ fontSize: '9px' }}>
                  {iter.passed ? 'PASSED' : 'FAILED'}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)', fontSize: '11.5px', textAlign: 'center', padding: '12px' }}>
            <AlertTriangle size={16} />
            <span>
              No review run recorded yet.
              <br />
              Run one to review the session's real artifacts.
            </span>
            <button className="btn btn-primary btn-sm" onClick={handleRunReview} disabled={running || !sessionId}>
              <Play size={11} /> {running ? 'Running…' : 'Run review'}
            </button>
          </div>
        )}
      </div>

      {/* Main Review Loop Trace */}
      <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px', overflowY: 'auto' }}>
        {/* Header */}
        <div className="flex-between" style={{ borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div className="flex" style={{ gap: '8px' }}>
              <h2 className="font-heading" style={{ fontSize: '16px', fontWeight: 700 }}>
                Review Loop {data ? `— ${data.total_iterations} iteration${data.total_iterations === 1 ? '' : 's'}` : ''}
              </h2>
              {data && (
                <span className={`badge ${data.final_passed ? 'badge-high' : 'badge-critical'}`}>
                  {data.final_passed ? 'PASSED' : 'FAILED'}
                </span>
              )}
            </div>
            <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {data
                ? `${data.task_description} — ${data.scope_files.length} changed file${data.scope_files.length === 1 ? '' : 's'} in scope`
                : 'Autonomous multi-agent synthesis loop (Planner → Worker → Independent Reviewers → Synthesizer)'}
            </p>
          </div>

          <div className="flex" style={{ gap: '10px', alignItems: 'center' }}>
            <button className="btn btn-primary btn-sm" onClick={handleRunReview} disabled={running || !sessionId} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <RefreshCw size={11} className={running ? 'animate-spin' : ''} /> {running ? 'Running…' : 'Run review'}
            </button>
            <div className="flex" style={{ gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Convergence</span>
              <span className="badge badge-high">{convergencePct}%</span>
            </div>
          </div>
        </div>

        {loading && (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '12px' }}>
            Loading review run…
          </div>
        )}

        {error && (
          <div role="alert" style={{ padding: '10px 14px', border: '1px solid var(--border-dim)', borderRadius: '8px', color: '#ffffff', fontSize: '12px' }}>
            {error}
          </div>
        )}

        {!loading && !error && !data && (
          <div style={{ padding: '30px 20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '12.5px' }}>
            {sessionId
              ? 'This session has no review run yet. Use "Run review" to execute the loop against the session\'s real artifacts — verification commands run under the server-side allowlist.'
              : 'Select a session to review its real artifacts.'}
          </div>
        )}

        {!loading && !error && data && current && (
          <>
            {/* Roles Flow Chart */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '10px' }}>
              <div className="card" style={{ padding: '12px' }}>
                <div className="flex" style={{ gap: '6px', marginBottom: '7px' }}>
                  <RefreshCw size={13} color="#ffffff" />
                  <span style={{ fontSize: '10.5px', fontWeight: 650, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    PLANNER
                  </span>
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)', wordBreak: 'break-word' }}>
                  Iteration #{current.iteration} of {data.total_iterations}
                  {current.synthesis?.failed_criteria?.length
                    ? ` — ${current.synthesis.failed_criteria.length} failed, ${current.synthesis.partial_criteria.length} partial`
                    : ''}
                </p>
              </div>
              <div className="card" style={{ padding: '12px' }}>
                <div className="flex" style={{ gap: '6px', marginBottom: '7px' }}>
                  <Cpu size={13} color="#ffffff" />
                  <span style={{ fontSize: '10.5px', fontWeight: 650, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    WORKER
                  </span>
                </div>
                <p className="font-mono" style={{ fontSize: '11px', color: '#ffffff', wordBreak: 'break-word' }}>
                  {current.worker_result?.artifacts
                    ?.filter((a) => a.artifact_type === 'verification')
                    .map((a) => `${a.command}${a.exit_code === 0 ? ' ✓' : ` ✗${a.exit_code !== null ? ` (${a.exit_code})` : ''}`}`)
                    .join(' · ') || 'No verification commands ran'}
                </p>
              </div>
              <div className="card" style={{ padding: '12px' }}>
                <div className="flex" style={{ gap: '6px', marginBottom: '7px' }}>
                  <FileCheck size={13} color="#ffffff" />
                  <span style={{ fontSize: '10.5px', fontWeight: 650, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    SYNTHESIZER
                  </span>
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)', wordBreak: 'break-word' }}>
                  {current.synthesis?.passed
                    ? 'All criteria satisfied. Approved.'
                    : current.synthesis?.deliverable_summary || 'Criteria unmet — iteration loop resumed.'}
                </p>
              </div>
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
                {current.review_results.map((rev, idx) => (
                  <div
                    key={idx}
                    className="card"
                    style={{ padding: '10px 14px', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '10px' }}
                  >
                    <div className="flex" style={{ gap: '10px', minWidth: 0, flex: 1 }}>
                      {VERDICT_ICON[rev.overall_verdict] || VERDICT_ICON.FAILED}
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: '12px', fontWeight: 650, color: '#ffffff' }}>
                          {rev.reviewer_name.replace('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                          <span style={{ fontSize: '10px', color: 'var(--text-dim)', marginLeft: '8px' }}>
                            confidence {Math.round(rev.confidence * 100)}%
                          </span>
                        </div>
                        {rev.results.length > 0 ? (
                          <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            {rev.results.map((cr, crIdx) => (
                              <div key={crIdx} style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
                                <span style={{ flexShrink: 0, color: cr.verdict === 'PASSED' ? '#ffffff' : cr.verdict === 'PARTIAL' ? '#fbbf24' : '#71717a' }}>
                                  {cr.verdict}
                                </span>
                                <span style={{ minWidth: 0, wordBreak: 'break-word' }}>
                                  {cr.criterion} — {cr.notes}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                            {rev.slop_findings.length > 0
                              ? rev.slop_findings.join('; ')
                              : 'No findings'}
                          </div>
                        )}
                        {rev.slop_findings.length > 0 && (
                          <div style={{ fontSize: '11px', color: '#fbbf24', marginTop: '4px' }}>
                            Slop: {rev.slop_findings.join('; ')}
                          </div>
                        )}
                      </div>
                    </div>

                    <span className={`badge ${rev.overall_verdict === 'PASSED' ? 'badge-high' : rev.overall_verdict === 'PARTIAL' ? '' : 'badge-low'}`} style={{ flexShrink: 0 }}>
                      {rev.overall_verdict}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Verification evidence */}
            <div>
              <h3 className="font-heading" style={{ fontSize: '13px', fontWeight: 650, marginBottom: '8px' }}>
                Verification Evidence
              </h3>
              <div className="flex-col" style={{ gap: '6px' }}>
                {current.worker_result?.artifacts
                  ?.filter((a) => a.artifact_type === 'verification')
                  .map((a) => (
                    <div key={a.artifact_id} className="card" style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Terminal size={12} color="var(--text-dim)" style={{ flexShrink: 0 }} />
                      <code className="font-mono" style={{ fontSize: '11px', color: '#ffffff', flex: 1, wordBreak: 'break-all' }}>
                        {a.command}
                      </code>
                      {a.evidence?.allowed === false ? (
                        <span className="badge badge-low" style={{ flexShrink: 0 }}>REJECTED</span>
                      ) : a.exit_code === 0 ? (
                        <span className="badge badge-high" style={{ flexShrink: 0 }}>exit 0</span>
                      ) : (
                        <span className="badge badge-critical" style={{ flexShrink: 0 }}>
                          {a.exit_code !== null ? `exit ${a.exit_code}` : 'ERROR'}
                        </span>
                      )}
                    </div>
                  ))}
                {!current.worker_result?.artifacts?.some((a) => a.artifact_type === 'verification') && (
                  <div style={{ fontSize: '11.5px', color: 'var(--text-dim)' }}>
                    No verification commands were executed in this iteration.
                  </div>
                )}
              </div>
            </div>

            {/* Scope files */}
            {data.scope_files.length > 0 && (
              <div>
                <h3 className="font-heading" style={{ fontSize: '13px', fontWeight: 650, marginBottom: '8px' }}>
                  Files in Review Scope
                </h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {data.scope_files.map((f) => (
                    <code key={f} className="font-mono" style={{ fontSize: '10.5px', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.06)', padding: '3px 8px', borderRadius: '6px' }}>
                      {f}
                    </code>
                  ))}
                </div>
              </div>
            )}

            {data.escalation_reason && (
              <div role="alert" style={{ padding: '10px 14px', border: '1px solid var(--border-dim)', borderRadius: '8px', color: '#ffffff', fontSize: '11.5px' }}>
                {data.escalation_reason}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};