// @ts-nocheck
import { useState } from 'react';
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function DefensiveHunter() {
  const [activeTab, setActiveTab] = useState('telemetry');
  const [events, setEvents] = useState<any[]>([]);
  const [cluster, setCluster] = useState<any>(null);
  useEffect(() => {
    api.getTelemetry().then(setEvents).catch(console.error);
    api.getClusters().then(c => setCluster(c[0])).catch(console.error);
  }, []);

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Defensive Hunter AI</h1>
          <p>Telemetry ingestion, behavioral analysis, and actor clustering</p>
        </div>
        <span className="badge badge-critical">🔴 Active Threat</span>
      </div>

      {/* Cluster Alert */}
      <div className="alert alert-danger" style={{ marginBottom: 20 }}>
        ⚠️ <strong>Actor Cluster Detected:</strong> CLUSTER-A3F7B291 — Confidence 91% —
        High automation, Honeytoken triggered at 14:22 UTC
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-secondary)',
        padding: 4, borderRadius: 8, width: 'fit-content' }}>
        {(['events', 'analysis'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} className="btn"
            style={{ background: activeTab === tab ? 'var(--bg-card)' : 'transparent',
              color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-muted)',
              textTransform: 'capitalize', border: 'none' }}>
            {tab === 'events' ? `Telemetry Events (${mockTelemetryEvents.length})` : 'Cluster Analysis'}
          </button>
        ))}
      </div>

      {activeTab === 'events' && (
        <div className="card">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Actor IP</th>
                  <th>ASN</th>
                  <th>Action</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={e.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem',
                      color: 'var(--text-muted)' }}>{i + 1}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                      {e.event_timestamp.split('T')[1].split('Z')[0]}
                    </td>
                    <td><span className="badge badge-open">{e.source.toUpperCase()}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                      {e.actor_ip}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {e.actor_asn}
                    </td>
                    <td>
                      {e.action === 'honeytoken_access' ? (
                        <span className="badge badge-critical">🍯 HONEYTOKEN</span>
                      ) : (
                        <span style={{ fontSize: '0.8rem' }}>{e.action}</span>
                      )}
                    </td>
                    <td>
                      {e.is_suspicious ? (
                        <span className="badge badge-high">Suspicious</span>
                      ) : (
                        <span className="badge badge-low">Normal</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'analysis' && (
        <div className="grid-2">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Cluster Summary</span>
              <span className="badge badge-critical">{Math.round(cluster.confidence * 100)}% Confidence</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
              {[
                { label: 'Automation', value: cluster.likely_automation },
                { label: 'AI-Assisted', value: cluster.likely_ai_assisted },
                { label: 'Events', value: String(cluster.event_count) },
              ].map(m => (
                <div key={m.label} style={{ textAlign: 'center', padding: '12px',
                  background: 'var(--bg-secondary)', borderRadius: 8 }}>
                  <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--accent-cyan)',
                    textTransform: 'capitalize' }}>{m.value}</div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase',
                    letterSpacing: '0.08em' }}>{m.label}</div>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 8,
                textTransform: 'uppercase', letterSpacing: '0.08em' }}>Evidence</div>
              {cluster.evidence.map((e, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: '0.82rem',
                  color: 'var(--text-secondary)' }}>
                  <span style={{ color: 'var(--accent-orange)', flexShrink: 0 }}>▸</span>
                  {e}
                </div>
              ))}
            </div>

            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 8,
                textTransform: 'uppercase', letterSpacing: '0.08em' }}>Recommended Actions</div>
              {cluster.recommended_actions.map((a, i) => (
                <div key={i} style={{ padding: '8px 12px', marginBottom: 6, background: 'var(--bg-secondary)',
                  borderRadius: 6, fontSize: '0.82rem', color: 'var(--text-secondary)',
                  borderLeft: i === 0 ? '3px solid var(--risk-critical)' : '3px solid var(--border)' }}>
                  {a}
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title">Actor Fingerprint</span></div>
            <div className="fingerprint-grid">
              <div className="fingerprint-item">
                <div className="fingerprint-key">Source ASNs</div>
                <div className="fingerprint-value">{cluster.fingerprint.asn_pattern.join(', ')}</div>
              </div>
              <div className="fingerprint-item">
                <div className="fingerprint-key">Source IPs</div>
                <div className="fingerprint-value">{cluster.fingerprint.source_ips.join('\n')}</div>
              </div>
              <div className="fingerprint-item">
                <div className="fingerprint-key">JA3 Fingerprint</div>
                <div className="fingerprint-value">{cluster.fingerprint.ja3_fingerprints[0]}</div>
              </div>
              <div className="fingerprint-item">
                <div className="fingerprint-key">User Agents</div>
                <div className="fingerprint-value">{cluster.fingerprint.user_agents.join('\n')}</div>
              </div>
              <div className="fingerprint-item">
                <div className="fingerprint-key">Timing Regular</div>
                <div className="fingerprint-value" style={{ color: 'var(--risk-high)' }}>
                  {cluster.fingerprint.timing_regular ? 'Yes — Automated' : 'No'}
                </div>
              </div>
              <div className="fingerprint-item">
                <div className="fingerprint-key">Honeytoken Hit</div>
                <div className="fingerprint-value" style={{ color: 'var(--risk-critical)' }}>
                  {cluster.fingerprint.honeytoken_interaction ? '🍯 YES — CONFIRMED' : 'No'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
