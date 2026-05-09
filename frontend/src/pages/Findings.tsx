// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

const riskColor = (level: string) => ({
  critical: 'var(--risk-critical)', high: 'var(--risk-high)',
  medium: 'var(--risk-medium)', low: 'var(--risk-low)',
}[level] || 'var(--text-muted)');

export default function Findings() {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    api.getFindings().then(setFindings).catch(console.error);
  }, []);

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Security Findings</h1>
          <p>All vulnerabilities and weaknesses identified by both AI agents</p>
        </div>
        <span className="badge badge-critical">{findings.filter(f => f.status === 'open').length} Open</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {findings.map(f => (
          <div key={f.id} className="card" style={{
            borderLeft: `3px solid ${riskColor(f.risk_level)}`
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <span className={`badge badge-${f.risk_level}`}>{f.risk_level.toUpperCase()}</span>
                  <span className="badge badge-open">{f.source}</span>
                </div>
                <h3 style={{ color: 'var(--text-primary)', marginBottom: 6 }}>{f.title}</h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.7 }}>
                  {f.description}
                </p>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div style={{ fontSize: '2rem', fontWeight: 700, color: riskColor(f.risk_level),
                  fontFamily: 'var(--font-mono)' }}>{f.risk_score}</div>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Score</div>
              </div>
            </div>

            <div className="divider" />

            <div className="grid-2">
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6,
                  textTransform: 'uppercase', letterSpacing: '0.08em' }}>Evidence</div>
                {f.evidence.map((e, i) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: 'var(--text-secondary)',
                    marginBottom: 3, display: 'flex', gap: 6 }}>
                    <span style={{ color: 'var(--accent-cyan)' }}>▸</span> {e}
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6,
                  textTransform: 'uppercase', letterSpacing: '0.08em' }}>Recommended Fix</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                  {f.recommended_fix}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
