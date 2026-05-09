// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function DeceptionEvents() {
  const [items, setItems] = useState<any[]>([]);
  useEffect(() => { api.getDeceptionItems().then(setItems).catch(console.error); }, []);
  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Deception Events</h1>
          <p>Honeytoken, honey credential, canary doc and decoy asset interactions</p>
        </div>
      </div>

      <div className="alert alert-danger" style={{ marginBottom: 20 }}>
        🍯 <strong>HONEYTOKEN TRIGGERED</strong> — "Fake AWS API Key" accessed from
        IP 45.155.204.127 at 14:22 UTC. Actor cluster CLUSTER-A3F7B291 created automatically.
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header"><span className="card-title">Active Deception Items</span></div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Type</th><th>Label</th><th>Fake Value (Marked)</th><th>Triggered</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id}>
                  <td><span className="badge badge-open">{item.item_type.replace('_', ' ')}</span></td>
                  <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{item.label}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
                    color: 'var(--text-muted)', maxWidth: 260, wordBreak: 'break-all' }}>
                    {item.fake_value.substring(0, 60)}...
                  </td>
                  <td>
                    {item.triggered_count > 0 ? (
                      <span className="badge badge-critical">🍯 {item.triggered_count}x</span>
                    ) : (
                      <span className="badge badge-low">Not triggered</span>
                    )}
                  </td>
                  <td>
                    {item.is_active ? (
                      <span className="badge badge-low">Active</span>
                    ) : (
                      <span className="badge badge-info">Inactive</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-header"><span className="card-title">Event Log</span></div>
        <div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: 8,
          border: '1px solid rgba(255,59,92,0.3)' }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ fontSize: '1.5rem' }}>🍯</span>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--risk-critical)', marginBottom: 4 }}>
                HONEYTOKEN ACCESS DETECTED
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
                Deception item "Fake AWS API Key — Acme Prod" was accessed by attacker.
                This is definitive evidence of malicious reconnaissance activity.
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: '0.75rem', color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)' }}>
                <span>IP: 45.155.204.127</span>
                <span>Time: 2024-03-15 14:22 UTC</span>
                <span>ASN: AS209605</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
