// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

const typeIcon: Record<string, string> = {
  web_app: '🌐', api: '🔌', repository: '📦', cloud_account: '☁️',
  identity_provider: '🔑', database: '🗄️', network_device: '📡',
};

const typeBadge: Record<string, string> = {
  web_app: 'Web App', api: 'API', repository: 'Repository',
  cloud_account: 'Cloud Account', identity_provider: 'Identity Provider',
  database: 'Database', network_device: 'Network Device',
};

export default function DigitalTwin() {
  const [assets, setAssets] = useState<any[]>([]);

  useEffect(() => {
    api.getAssets().then(setAssets).catch(console.error);
  }, []);

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Company Digital Twin</h1>
          <p>Acme Fintech asset inventory — the shared context for both AI agents</p>
        </div>
        <span className="badge badge-open">{assets.length} Assets</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
        {assets.map(asset => (
          <div key={asset.id} className="card" style={{ cursor: 'pointer' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 14 }}>
              <div style={{ fontSize: '1.6rem' }}>{typeIcon[asset.asset_type] || '🖥️'}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {asset.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                  {asset.url || asset.hostname || 'Internal'}
                </div>
              </div>
              <span className="badge badge-open">{typeBadge[asset.asset_type]}</span>
            </div>

            <div style={{ display: 'flex', gap: 12, marginBottom: 14 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.08em', marginBottom: 4 }}>Criticality</div>
                <div className="risk-bar-container">
                  <div className="risk-bar-fill" style={{
                    width: `${asset.criticality * 10}%`,
                    background: asset.criticality >= 9 ? 'var(--risk-critical)' :
                                asset.criticality >= 7 ? 'var(--risk-high)' : 'var(--risk-medium)'
                  }} />
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                  {asset.criticality}/10
                </div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.08em', marginBottom: 4 }}>Data Sensitivity</div>
                <div className="risk-bar-container">
                  <div className="risk-bar-fill" style={{
                    width: `${asset.data_sensitivity * 10}%`,
                    background: asset.data_sensitivity >= 9 ? 'var(--accent-purple)' :
                                asset.data_sensitivity >= 7 ? 'var(--accent-cyan)' : 'var(--risk-low)'
                  }} />
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                  {asset.data_sensitivity}/10
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {asset.tags?.map(tag => (
                <span key={tag} style={{ fontSize: '0.65rem', padding: '2px 6px', borderRadius: 4,
                  background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>
                  {tag}
                </span>
              ))}
            </div>

            <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)',
              fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Owner: <span style={{ color: 'var(--text-secondary)' }}>{asset.owner}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
