// @ts-nocheck
import { useState } from 'react';
import { Play, CheckCircle, Clock } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function OffensiveMissions() {
  const [mission, setMission] = useState<any>(null);
  useEffect(() => { api.getMissions().then(m => setMission(m[0])).catch(console.error); }, []);

  const [showReport, setShowReport] = useState(false);
  const [running, setRunning] = useState(false);

  const handleRun = () => {
    setRunning(true);
    setTimeout(() => { setRunning(false); setShowReport(true); }, 2000);
  };

  if (!mission) return <div style={{padding:40}}>Loading...</div>;

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Offensive Red-Team Missions</h1>
          <p>AI-generated attack path analysis — safe validation only, no exploitation</p>
        </div>
      </div>

      <div className="alert alert-warning" style={{ marginBottom: 24 }}>
        ⚠️ All offensive actions are policy-controlled. Exploit execution, credential abuse,
        persistence, C2, lateral movement, and data exfiltration are permanently blocked.
      </div>

      {/* Mission Card */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span className="badge badge-completed">Completed</span>
              <span className="badge badge-critical">CRITICAL</span>
            </div>
            <h3 style={{ color: 'var(--text-primary)', marginBottom: 4 }}>{mission.name}</h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Engagement: Q2 2024 Red Team Assessment
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--risk-critical)',
              fontFamily: 'var(--font-mono)' }}>{mission.risk_score}</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>RISK SCORE</div>
          </div>
        </div>

        {!showReport ? (
          <button className="btn btn-primary" onClick={handleRun} style={{ marginTop: 16 }}
            disabled={running}>
            {running ? (
              <><Clock size={14} /> Running Mission...</>
            ) : (
              <><Play size={14} /> Replay Mission Analysis</>
            )}
          </button>
        ) : null}
      </div>

      {/* Report */}
      {(showReport || mission.status === 'completed') && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Attack Path Report</span>
            <CheckCircle size={16} style={{ color: 'var(--accent-green)' }} />
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6 }}>HYPOTHESIS</div>
            <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.7,
              padding: '12px 16px', background: 'var(--bg-secondary)', borderRadius: 8,
              borderLeft: '3px solid var(--accent-cyan)' }}>
              {mission.report.hypothesis}
            </div>
          </div>

          <div className="grid-2" style={{ marginBottom: 20 }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 8 }}>BUSINESS IMPACT</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                {mission.report.business_impact}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 8 }}>RECOMMENDED FIX</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                {mission.report.recommended_fix}
              </div>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 8 }}>
              BLOCKED UNSAFE STEPS (POLICY ENFORCED)
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {mission.report.blocked_unsafe_steps.map(s => (
                <span key={s} className="badge badge-critical" style={{ textTransform: 'none', letterSpacing: 0 }}>
                  ⛔ {s}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
