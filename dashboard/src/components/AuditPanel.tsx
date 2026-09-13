import React from 'react';
import {
  ComplianceBundle,
  CollusionCandidate,
  IncidentSummary,
  PolicyFinding,
  ProjectionVerdict,
  RetroScanResponse,
  SessionBrief,
} from '../types';
import {
  BadgeCheck,
  ChevronDown,
  ChevronRight,
  FileSearch,
  Gavel,
  Globe,
  Info,
  ScanLine,
  ShieldAlert,
  Users,
} from 'lucide-react';

interface AuditPanelProps {
  brief: SessionBrief | null;
  incidents: IncidentSummary[];
  collusion: CollusionCandidate[];
  retroScan: RetroScanResponse | null;
  retroScanning: boolean;
  compliance: ComplianceBundle | null;
  findings: PolicyFinding[];
  projection: ProjectionVerdict | null;
  unverified: boolean;
  onRunRetroScan: () => void;
}

const card: React.CSSProperties = {
  padding: '12px',
  display: 'flex',
  flexDirection: 'column',
  gap: '8px',
};

const panelShell: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  minHeight: 0,
};

export const AuditPanel: React.FC<AuditPanelProps> = ({
  brief,
  incidents,
  collusion,
  retroScan,
  retroScanning,
  compliance,
  findings,
  projection,
  unverified,
  onRunRetroScan,
}) => {
  const [collusionOpen, setCollusionOpen] = React.useState<boolean>(false);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
        gridTemplateRows: 'minmax(0, 1fr) minmax(0, 1fr)',
        gap: '16px',
        margin: '0 16px 16px 16px',
        height: 'calc(100vh - 120px)',
      }}
    >
      {/* Operator Briefing (GET /brief) */}
      <div className="glass-panel" style={panelShell}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <Gavel size={16} color="#ffffff" />
            <span className="panel-title">Operator Briefing</span>
          </div>
          {brief && <span className="chip">{brief.total_findings} findings</span>}
        </div>

        {/* Projection integrity strip (P0.4 residual): the keyed-MAC verdict
            for the live projection. Fail-closed display — if the daemon was
            never asked (checked=false) we show it as unknown, never as OK. */}
        {projection && (
          <div
            className="flex"
            style={{
              gap: '8px',
              alignItems: 'center',
              padding: '8px 14px',
              borderBottom: '1px solid var(--border-dim)',
              fontSize: '10.5px',
              fontFamily: 'var(--font-mono, monospace)',
            }}
          >
            <ShieldAlert
              size={13}
              color={projection.checked ? (projection.authenticated ? '#16a34a' : '#dc2626') : '#a1a1aa'}
            />
            {projection.checked ? (
              projection.authenticated ? (
                <>
                  <span style={{ color: '#16a34a' }}>projection MAC authenticated</span>
                  {projection.stored_digest && (
                    <span style={{ color: 'var(--text-dim)' }}>digest {projection.stored_digest.slice(0, 12)}…</span>
                  )}
                </>
              ) : (
                <span style={{ color: '#dc2626', fontWeight: 600 }}>
                  PROJECTION TAMPERED — live state failed keyed-MAC verification
                </span>
              )
            ) : (
              <span style={{ color: '#a1a1aa' }}>projection verification not yet performed</span>
            )}
          </div>
        )}

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          {unverified ? (
            <div className="empty-state">
              <ShieldAlert size={34} color="#71717a" />
              <h3 className="font-heading" style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
                Briefing Unavailable — Daemon Unreachable
              </h3>
              <p style={{ fontSize: '11.5px' }}>
                Nothing observed means nothing verified. Reconnect to confirm state.
              </p>
            </div>
          ) : !brief ? (
            <div className="empty-state">
              <p style={{ fontSize: '11.5px' }}>No briefing loaded for this session.</p>
            </div>
          ) : (
            <div className="flex-col" style={{ gap: '10px' }}>
              <div className="flex" style={{ gap: '8px', flexWrap: 'wrap' }}>
                {Object.entries(brief.by_severity).map(([sev, n]) => (
                  <span key={sev} className={`badge badge-${sev === 'info' ? 'low' : sev}`}>
                    {sev}: {n}
                  </span>
                ))}
                {brief.integrity_failures > 0 && (
                  <span className="badge badge-critical">
                    integrity failures: {brief.integrity_failures}
                  </span>
                )}
              </div>

              {brief.attention.length > 0 ? (
                brief.attention.map((a, idx) => (
                  <div key={idx} style={card} className="card">
                    <div className="flex-between">
                      <span className={`badge badge-${a.severity === 'critical' ? 'critical' : 'high'}`}>
                        {a.finding_type}
                      </span>
                      <span className="badge badge-medium">{a.severity}</span>
                    </div>
                    <div style={{ fontSize: '11.5px' }}>{a.description}</div>
                    <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                      <Info size={11} color="var(--text-dim)" /> {a.recommended_action}
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty-state">
                  <BadgeCheck size={30} color="#ffffff" />
                  <h3 className="font-heading" style={{ fontSize: '13.5px', color: 'var(--text-muted)' }}>
                    Nothing Needs Attention
                  </h3>
                  <p style={{ fontSize: '11px' }}>No critical or high severity findings await review.</p>
                </div>
              )}

              {brief.open_approvals.length > 0 && (
                <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                  {brief.open_approvals.length} open approval(s) currently in scope.
                </div>
              )}
              {brief.last_activity && (
                <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                  Last activity: {new Date(brief.last_activity).toLocaleString()}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Correlated Incidents (GET /incidents) */}
      <div className="glass-panel" style={panelShell}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <ShieldAlert size={16} color="#ffffff" />
            <span className="panel-title">Correlated Incidents</span>
            <span className="chip">{incidents.length}</span>
          </div>
        </div>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          {unverified ? (
            <div className="empty-state">
              <p style={{ fontSize: '11.5px' }}>
                Incident correlation cannot be verified while the daemon is unreachable.
              </p>
            </div>
          ) : incidents.length === 0 ? (
            <div className="empty-state">
              <p style={{ fontSize: '11.5px' }}>
                No multi-stage incidents. Correlation requires at least two evidence-backed stages.
              </p>
            </div>
          ) : (
            <div className="flex-col" style={{ gap: '10px' }}>
              {incidents.map((inc) => (
                <div key={inc.incident_id} style={card} className="card">
                  <div className="flex-between">
                    <span className={`badge badge-${inc.severity === 'info' ? 'low' : inc.severity}`}>
                      {inc.incident_type}
                    </span>
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                      {new Date(inc.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '11.5px' }}>{inc.description}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    evidence: {inc.evidence_event_ids.length} sealed event(s)
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Collusion / Coordination Candidates (GET /collusion) */}
      <div className="glass-panel" style={panelShell}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <Users size={16} color="#ffffff" />
            <span className="panel-title">Coordination Signals</span>
            <span className="chip">{collusion.length}</span>
          </div>
          {collusion.length > 0 && (
            <button
              className="btn btn-ghost"
              onClick={() => setCollusionOpen((o) => !o)}
              aria-expanded={collusionOpen}
              style={{ fontSize: '10.5px' }}
            >
              {collusionOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              {collusionOpen ? 'hide' : 'show'}
            </button>
          )}
        </div>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          {collusion.length === 0 ? (
            <div className="empty-state">
              <p style={{ fontSize: '11.5px' }}>
                No cross-session coordination signals involving this session. Coordination itself
                is never claimed — only the observable half is shown.
              </p>
            </div>
          ) : !collusionOpen ? (
            <div className="empty-state">
              <Globe size={30} color="#71717a" />
              <p style={{ fontSize: '11.5px' }}>
                {collusion.length} candidate signal(s) found — expand to review; each carries an
                explicit reasoning gap.
              </p>
            </div>
          ) : (
            <div className="flex-col" style={{ gap: '10px' }}>
              {collusion.map((c, idx) => (
                <div key={idx} style={card} className="card">
                  <div className="flex-between">
                    <span className="badge badge-medium">{c.signal}</span>
                    <span className="badge badge-low">confidence: {c.confidence}</span>
                  </div>
                  <div style={{ fontSize: '11.5px' }}>{c.detail}</div>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    reasoning gap: {c.reasoning_gap}
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    actors: {c.actors.join(', ')} · sessions:{' '}
                    {c.session_ids.map((s) => s.slice(0, 8)).join(', ')}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Retro-Scan + Compliance Bundle (POST /rescan, GET /compliance) */}
      <div className="glass-panel" style={panelShell}>
        <div className="panel-header">
          <div className="flex" style={{ gap: '8px' }}>
            <ScanLine size={16} color="#ffffff" />
            <span className="panel-title">Retro-Scan &amp; Compliance</span>
          </div>
          <button
            className="btn btn-ghost"
            onClick={onRunRetroScan}
            disabled={retroScanning || unverified}
            style={{ fontSize: '10.5px' }}
          >
            <FileSearch size={12} />
            {retroScanning ? 'scanning…' : 'run retro-scan'}
          </button>
        </div>

        <div className="scroll-thin" style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
          <div className="flex-col" style={{ gap: '10px' }}>
            {retroScan ? (
              <div style={card} className="card">
                <div className="flex" style={{ gap: '8px', flexWrap: 'wrap' }}>
                  <span className="badge badge-low">{retroScan.events_scanned} events scanned</span>
                  <span
                    className={`badge ${retroScan.retro_incidents > 0 ? 'badge-critical' : 'badge-low'}`}
                  >
                    {retroScan.retro_incidents} retro incident(s)
                  </span>
                  <span className="badge badge-low">{retroScan.stage1_hits} stage-1 hits</span>
                </div>
                <div style={{ fontSize: '11px' }}>{retroScan.summary}</div>
                {retroScan.errors.length > 0 && (
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    errors: {retroScan.errors.join('; ')}
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-state">
                <p style={{ fontSize: '11.5px' }}>
                  The transcript search can miss incidents. Run the two-stage wide-net retro-scan
                  to re-check stored history offline — read-only, repeatable.
                </p>
              </div>
            )}

            {compliance ? (
              <div style={card} className="card">
                <div className="flex-between">
                  <span className="panel-title" style={{ fontSize: '11px' }}>
                    Compliance Manifest (EU AI Act / ISO 42001 / SOC 2)
                  </span>
                  <span
                    className={`badge ${compliance.integrity.chain_verified ? 'badge-low' : 'badge-critical'}`}
                  >
                    {compliance.integrity.chain_verified ? 'chain verified' : 'CHAIN FAILED'}
                  </span>
                </div>
                <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                  {compliance.event_count} events · {compliance.findings_count} findings ·{' '}
                  {compliance.incidents_count} incidents · {compliance.approvals_count} approvals
                </div>
                <div className="font-mono" style={{ fontSize: '9.5px', color: 'var(--text-dim)' }}>
                  head: {compliance.integrity.head_event_hash.slice(0, 24)}… · sig:{' '}
                  {compliance.report_signature_sha256.slice(0, 24)}…
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p style={{ fontSize: '11.5px' }}>
                  The verifiable compliance manifest is generated with the session report. Use the
                  Forensic Report modal to verify the chain and export.
                </p>
              </div>
            )}

            {findings.length === 0 && !retroScan && !compliance && !unverified && (
              <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                Nothing found is not a verdict — verify the chain and run the retro-scan before
                treating this session as clean.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};