// @ts-nocheck
import { useEffect, useState } from 'react';
import { AlertTriangle, Shield, Crosshair, Radar, Zap, FileCode, Wrench, TrendingUp } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { api } from '../api/client';

const riskColor = (level: string) => ({
  critical: 'var(--risk-critical)',
  high: 'var(--risk-high)',
  medium: 'var(--risk-medium)',
  low: 'var(--risk-low)',
  informational: 'var(--risk-info)',
}[level] || 'var(--text-muted)');

const telemetryData = [
  { time: '14:00', waf: 3, edr: 1 },
  { time: '14:05', waf: 5, edr: 2 },
  { time: '14:10', waf: 8, edr: 3 },
  { time: '14:15', waf: 12, edr: 4 },
  { time: '14:20', waf: 7, edr: 6 },
  { time: '14:25', waf: 4, edr: 8 }, // honeytoken triggered
  { time: '14:30', waf: 2, edr: 3 },
];

const riskPieData = [
  { name: 'Critical', value: 1, color: 'var(--risk-critical)' },
  { name: 'High', value: 1, color: 'var(--risk-high)' },
  { name: 'Medium', value: 1, color: 'var(--risk-medium)' },
];

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    api.getDashboard().then(setStats).catch(console.error);
    api.getFindings().then(setFindings).catch(console.error);
  }, []);

  if (!stats) {
    return <div style={{ padding: 40, color: 'var(--text-muted)' }}>Loading live telemetry...</div>;
  }

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Security Operations Center</h1>
          <p>Acme Fintech — Real-time offensive and defensive intelligence</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <span className="badge badge-critical">⚠ Critical Risk Posture</span>
        </div>
      </div>

      {/* Critical Alert */}
      <div className="alert alert-danger" style={{ marginBottom: 24 }}>
        <Zap size={16} />
        <div>
          <strong>DECEPTION ITEM TRIGGERED</strong> — Honeytoken "FAKE-AWS-API-KEY" accessed from
          IP <code style={{ fontFamily: 'var(--font-mono)' }}>45.155.204.127</code> at 14:22 UTC.
          Actor cluster CLUSTER-A3F7B291 created. Immediate action required.
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card" style={{ '--accent-color': 'var(--risk-critical)' } as any}>
          <div className="stat-value" style={{ color: 'var(--risk-critical)' }}>
            {stats.findings.critical}
          </div>
          <div className="stat-label">Critical Findings</div>
          <div className="stat-trend" style={{ color: 'var(--risk-critical)' }}>
            ↑ Requires immediate action
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--risk-high)' } as any}>
          <div className="stat-value" style={{ color: 'var(--risk-high)' }}>
            {stats.findings.high}
          </div>
          <div className="stat-label">High Risk Findings</div>
          <div className="stat-trend" style={{ color: 'var(--text-muted)' }}>
            3 total findings open
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--accent-cyan)' } as any}>
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>
            {stats.offensive_missions}
          </div>
          <div className="stat-label">Active Missions</div>
          <div className="stat-trend" style={{ color: 'var(--accent-cyan)' }}>
            Staging → Data attack path mapped
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--accent-purple)' } as any}>
          <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>
            {stats.actor_clusters}
          </div>
          <div className="stat-label">Actor Clusters</div>
          <div className="stat-trend" style={{ color: 'var(--accent-purple)' }}>
            Confidence: 91%
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--accent-orange)' } as any}>
          <div className="stat-value" style={{ color: 'var(--accent-orange)' }}>
            {stats.telemetry_events}
          </div>
          <div className="stat-label">Telemetry Events</div>
          <div className="stat-trend" style={{ color: 'var(--text-muted)' }}>
            Last 1h window
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--accent-yellow)' } as any}>
          <div className="stat-value" style={{ color: 'var(--accent-yellow)' }}>
            {stats.deception_events}
          </div>
          <div className="stat-label">Deception Triggers</div>
          <div className="stat-trend" style={{ color: 'var(--accent-yellow)' }}>
            ↑ Honeytoken accessed
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--accent-green)' } as any}>
          <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
            {stats.detection_drafts}
          </div>
          <div className="stat-label">Detection Drafts</div>
          <div className="stat-trend" style={{ color: 'var(--text-muted)' }}>
            Awaiting review
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--text-muted)' } as any}>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>
            {stats.assets}
          </div>
          <div className="stat-label">Assets Monitored</div>
          <div className="stat-trend" style={{ color: 'var(--text-muted)' }}>
            All in scope
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Telemetry timeline */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Telemetry Activity Timeline</span>
            <span className="badge badge-high">Suspicious</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={telemetryData}>
              <defs>
                <linearGradient id="colorWaf" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorEdr" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-red)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--accent-red)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="time" stroke="var(--text-muted)" tick={{ fontSize: 11 }} />
              <YAxis stroke="var(--text-muted)" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
                labelStyle={{ color: 'var(--text-primary)' }}
              />
              <Area type="monotone" dataKey="waf" stroke="var(--accent-cyan)" fill="url(#colorWaf)" strokeWidth={2} name="WAF" />
              <Area type="monotone" dataKey="edr" stroke="var(--accent-red)" fill="url(#colorEdr)" strokeWidth={2} name="EDR" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Risk distribution */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Risk Distribution</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24, height: 200 }}>
            <ResponsiveContainer width="50%" height="100%">
              <PieChart>
                <Pie data={riskPieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                  paddingAngle={3} dataKey="value">
                  {riskPieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ flex: 1 }}>
              {riskPieData.map((item) => (
                <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: item.color }} />
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {item.name}
                  </span>
                  <span style={{ marginLeft: 'auto', fontSize: '0.82rem', color: item.color, fontWeight: 600 }}>
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Findings</span>
          <a href="/findings" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>View all →</a>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 5).map(f => (
                <tr key={f.id}>
                  <td style={{ color: 'var(--text-primary)', maxWidth: 320 }}>
                    <div style={{ fontWeight: 500, fontSize: '0.875rem', whiteSpace: 'nowrap',
                      overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.title}</div>
                  </td>
                  <td>
                    <span className={`badge badge-${f.risk_level}`}>
                      {f.risk_level.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div className="risk-bar-container" style={{ width: 60 }}>
                        <div className="risk-bar-fill"
                          style={{ width: `${f.risk_score}%`, background: riskColor(f.risk_level) }} />
                      </div>
                      <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)',
                        color: riskColor(f.risk_level) }}>{f.risk_score}</span>
                    </div>
                  </td>
                  <td><span className="badge badge-open">{f.source}</span></td>
                  <td><span className="badge badge-open">{f.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
