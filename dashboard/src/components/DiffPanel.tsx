import React, { useState } from 'react';
import { BlastRadiusResult } from '../types';
import { FileCode, AlertOctagon } from 'lucide-react';

interface DiffPanelProps {
  blastRadius?: BlastRadiusResult | null;
}

export const DiffPanel: React.FC<DiffPanelProps> = ({ blastRadius }) => {
  const [selectedFile, setSelectedFile] = useState('src/auth/jwt.ts');

  const sampleDiffs: Record<string, { before: string[]; after: string[] }> = {
    'src/auth/jwt.ts': {
      before: [
        'import jwt from "jsonwebtoken";',
        '',
        'export function verifyToken(token: string): boolean {',
        '  try {',
        '    const decoded = jwt.verify(token, process.env.JWT_SECRET!);',
        '    return Boolean(decoded);',
        '  } catch {',
        '    return false;',
        '  }',
        '}',
      ],
      after: [
        'import jwt from "jsonwebtoken";',
        'import { auditLog } from "../utils/audit";',
        '',
        'export function verifyToken(token: string): boolean {',
        '  try {',
        '    const decoded = jwt.verify(token, process.env.JWT_SECRET!, {',
        '      algorithms: ["HS256", "RS256"],',
        '      maxAge: "2h"',
        '    });',
        '    auditLog("token_verified", { subject: (decoded as any).sub });',
        '    return true;',
        '  } catch (err: any) {',
        '    auditLog("token_verification_failed", { error: err.message });',
        '    return false;',
        '  }',
        '}',
      ],
    },
    'package.json': {
      before: [
        '  "dependencies": {',
        '    "fastapi": "^0.111.0",',
        '    "pydantic": "^2.10.0"',
        '  }',
      ],
      after: [
        '  "dependencies": {',
        '    "fastapi": "^0.111.0",',
        '    "jsonwebtoken": "^9.0.2",',
        '    "pydantic": "^2.10.0"',
        '  }',
      ],
    },
  };

  const currentDiff = sampleDiffs[selectedFile] || sampleDiffs['src/auth/jwt.ts'];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '16px', margin: '0 16px 16px 16px', height: 'calc(100vh - 120px)' }}>
      {/* File List & Blast Radius Overview */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', gap: '16px', overflowY: 'auto' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <FileCode size={16} color="var(--accent-cyan)" />
            <h2 className="font-heading" style={{ fontSize: '15px', fontWeight: 600 }}>
              Mutated Workspace Files
            </h2>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {Object.keys(sampleDiffs).map((filePath) => (
              <button
                key={filePath}
                onClick={() => setSelectedFile(filePath)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: selectedFile === filePath ? '1px solid var(--accent-cyan)' : '1px solid var(--border-dim)',
                  background: selectedFile === filePath ? 'rgba(6, 182, 212, 0.1)' : 'var(--bg-input)',
                  color: selectedFile === filePath ? 'var(--accent-cyan)' : 'var(--text-main)',
                  textAlign: 'left',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                }}
              >
                {filePath}
              </button>
            ))}
          </div>
        </div>

        {/* Blast Radius Section */}
        <div style={{ borderTop: '1px solid var(--border-dim)', paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <AlertOctagon size={16} color="#f59e0b" />
              <h3 className="font-heading" style={{ fontSize: '14px', fontWeight: 600 }}>
                Blast Radius
              </h3>
            </div>
            <span className="badge badge-medium">
              Risk: {((blastRadius?.risk_score || 0.72) * 100).toFixed(0)}%
            </span>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                Downstream Impacted Files ({blastRadius?.affected_files.length || 3})
              </span>
              <ul style={{ listStyle: 'none', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {(blastRadius?.affected_files || ['src/auth/jwt.ts', 'src/server.ts', 'src/routes/login.ts']).map((f) => (
                  <li key={f} className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    • {f}
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                Test Regressions ({blastRadius?.failed_tests.length || 2})
              </span>
              <ul style={{ listStyle: 'none', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {(blastRadius?.failed_tests || ['test_auth_header_validation', 'test_jwt_expiration']).map((t) => (
                  <li key={t} style={{ fontSize: '11px', color: '#f43f5e' }}>
                    ✕ {t}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Side-by-Side Diff Display */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent-cyan)' }}>
            Diff: {selectedFile}
          </span>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
            Before (Recorded Baseline) ⟷ After (Agent Mutation)
          </span>
        </div>

        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', overflow: 'hidden' }}>
          {/* Before */}
          <div style={{ padding: '12px', overflowY: 'auto', borderRight: '1px solid var(--border-dim)', background: 'rgba(0,0,0,0.2)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '8px', fontWeight: 600 }}>BEFORE</div>
            <pre className="font-mono" style={{ fontSize: '12px', lineHeight: 1.6, color: '#94a3b8' }}>
              {currentDiff.before.map((line, idx) => (
                <div key={idx} style={{ padding: '0 4px' }}>
                  <span style={{ color: 'var(--text-dim)', marginRight: '12px', userSelect: 'none' }}>{idx + 1}</span>
                  {line}
                </div>
              ))}
            </pre>
          </div>

          {/* After */}
          <div style={{ padding: '12px', overflowY: 'auto', background: 'rgba(6, 182, 212, 0.02)' }}>
            <div style={{ fontSize: '11px', color: '#10b981', marginBottom: '8px', fontWeight: 600 }}>AFTER</div>
            <pre className="font-mono" style={{ fontSize: '12px', lineHeight: 1.6, color: 'var(--text-main)' }}>
              {currentDiff.after.map((line, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '0 4px',
                    background: line.includes('auditLog') || line.includes('algorithms') ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
                    borderLeft: line.includes('auditLog') || line.includes('algorithms') ? '2px solid #10b981' : 'none',
                  }}
                >
                  <span style={{ color: 'var(--text-dim)', marginRight: '12px', userSelect: 'none' }}>{idx + 1}</span>
                  {line}
                </div>
              ))}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
