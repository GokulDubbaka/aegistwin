// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function EvidenceVault() {
  const [mission, setMission] = useState<any>(null);
  const [cluster, setCluster] = useState<any>(null);
  useEffect(() => {
    api.getMissions().then(m => setMission(m[0])).catch(console.error);
    api.getClusters().then(c => setCluster(c[0])).catch(console.error);
  }, []);
  if (!mission || !cluster) return <div style={{padding:40}}>Loading...</div>;
  const evidence = [
    ...mission.report.attack_path.nodes.map(n => ({
      id: n.id, type: 'Attack Node', source: 'Offensive Agent',
      title: n.label, detail: n.description, severity: n.node_type === 'BusinessImpact' ? 'critical' : 'high'
    })),
    ...cluster.evidence.map((e, i) => ({
      id: `cl-${i}`, type: 'Behavioral Signal', source: 'Defensive Hunter',
      title: e, detail: `Cluster: ${cluster.cluster_label}`, severity: 'high'
    })),
  ];

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Evidence Vault</h1>
          <p>All collected evidence from offensive and defensive operations</p>
        </div>
        <span className="badge badge-open">{evidence.length} items</span>
      </div>

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Type</th><th>Source</th><th>Evidence</th><th>Detail</th><th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {evidence.map(e => (
              <tr key={e.id}>
                <td><span className="badge badge-open">{e.type}</span></td>
                <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{e.source}</td>
                <td style={{ color: 'var(--text-primary)', maxWidth: 300, fontWeight: 500 }}>{e.title}</td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: 200 }}>{e.detail}</td>
                <td><span className={`badge badge-${e.severity}`}>{e.severity.toUpperCase()}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
