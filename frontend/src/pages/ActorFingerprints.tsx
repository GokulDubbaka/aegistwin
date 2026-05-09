// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function ActorFingerprints() {
  const [cluster, setCluster] = useState<any>(null);
  useEffect(() => { api.getClusters().then(c => setCluster(c[0])).catch(console.error); }, []);
  if (!cluster) return <div style={{padding:40}}>Loading...</div>;
  const fp = cluster.fingerprint;

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Actor Fingerprints</h1>
          <p>Multi-dimensional behavioral fingerprinting of observed threat actors</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div style={{ padding: '8px 16px', background: 'var(--accent-red-dim)',
            border: '1px solid rgba(255,59,92,0.3)', borderRadius: 8,
            fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--accent-red)', fontWeight: 700 }}>
            {cluster.cluster_label}
          </div>
          <span className="badge badge-critical">Confidence {Math.round(cluster.confidence * 100)}%</span>
          <span className="badge badge-high">Automation: {cluster.likely_automation}</span>
          <span className="badge badge-medium">AI-Assisted: {cluster.likely_ai_assisted}</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          {[
            { label: 'Source ASNs', value: fp.asn_pattern.join(', '), color: 'var(--accent-cyan)' },
            { label: 'Source IPs', value: fp.source_ips.join(' · '), color: 'var(--accent-orange)' },
            { label: 'JA3 Hash', value: fp.ja3_fingerprints[0] || 'N/A', color: 'var(--accent-purple)' },
            { label: 'User Agents', value: fp.user_agents.join(' · '), color: 'var(--text-secondary)' },
            { label: 'Timing Pattern', value: fp.timing_regular ? 'Regular (Automated)' : 'Irregular', color: 'var(--risk-high)' },
            { label: 'Honeytoken', value: fp.honeytoken_interaction ? '🍯 TRIGGERED — HIGH CONFIDENCE' : 'Not triggered', color: fp.honeytoken_interaction ? 'var(--risk-critical)' : 'var(--risk-low)' },
          ].map(item => (
            <div key={item.label} style={{ padding: '16px', background: 'var(--bg-secondary)',
              borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: '0.1em', marginBottom: 8 }}>{item.label}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: item.color, wordBreak: 'break-all' }}>
                {item.value}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-header"><span className="card-title">Evidence Chain</span></div>
        {cluster.evidence.map((e, i) => (
          <div key={i} style={{ display: 'flex', gap: 12, padding: '10px 0',
            borderBottom: i < cluster.evidence.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)', flexShrink: 0, paddingTop: 1 }}>#{i + 1}</span>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{e}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
