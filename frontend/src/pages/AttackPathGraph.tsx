// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

const nodeColors: Record<string, string> = {
  EntryPoint: 'var(--accent-cyan)',
  Weakness: 'var(--risk-high)',
  Application: 'var(--accent-purple)',
  BusinessImpact: 'var(--risk-critical)',
  CloudPermission: 'var(--accent-orange)',
  DataStore: 'var(--risk-medium)',
  DetectionGap: 'var(--text-muted)',
};

const nodeIcons: Record<string, string> = {
  EntryPoint: '🚪', Weakness: '⚠️', Application: '🖥️',
  BusinessImpact: '💥', CloudPermission: '☁️', DataStore: '🗄️',
};

export default function AttackPathGraph() {
  const [mission, setMission] = useState<any>(null);
  useEffect(() => { api.getMissions().then(m => setMission(m[0])).catch(console.error); }, []);
  const { nodes, edges } = mission.report.attack_path;

  if (!mission) return <div style={{padding:40}}>Loading...</div>;

  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Attack Path Graph</h1>
          <p>Visual kill chain from entry point to business impact</p>
        </div>
        <span className="badge badge-critical">CRITICAL PATH</span>
      </div>

      <div className="grid-2" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header">
            <span className="card-title">Attack Chain Visualization</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {nodes.length} nodes · {edges.length} edges
            </span>
          </div>

          <div className="attack-path">
            {nodes.map((node, i) => (
              <div key={node.id} className="attack-node">
                <div className="attack-node-connector">
                  <div className="attack-node-dot"
                    style={{ background: `${nodeColors[node.node_type] || 'var(--text-muted)'}22`,
                      color: nodeColors[node.node_type] || 'var(--text-muted)',
                      border: `2px solid ${nodeColors[node.node_type] || 'var(--border)'}` }}>
                    {nodeIcons[node.node_type] || '●'}
                  </div>
                  {i < nodes.length - 1 && <div className="attack-node-line" />}
                </div>
                <div className="attack-node-content">
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                    <div>
                      <div style={{ fontSize: '0.6rem', fontWeight: 600, textTransform: 'uppercase',
                        letterSpacing: '0.1em', color: nodeColors[node.node_type] || 'var(--text-muted)',
                        marginBottom: 3 }}>{node.node_type}</div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                        {node.label}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
                        {node.description}
                      </div>
                    </div>
                    {!node.detection_coverage && (
                      <span className="badge badge-critical">No Detection</span>
                    )}
                    {node.detection_coverage && (
                      <span className="badge badge-low">Detected</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          {/* Risk metrics */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Path Risk Metrics</span>
            </div>
            <div style={{ display: 'flex', gap: 20 }}>
              <div style={{ flex: 1, textAlign: 'center' }}>
                <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--risk-critical)',
                  fontFamily: 'var(--font-mono)' }}>
                  {mission.report.risk_score}
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Risk Score
                </div>
              </div>
              <div style={{ flex: 1, textAlign: 'center' }}>
                <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--accent-cyan)',
                  fontFamily: 'var(--font-mono)' }}>
                  {Math.round((mission.report.confidence || 0.75) * 100)}%
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Confidence
                </div>
              </div>
            </div>
          </div>

          {/* Legend */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header"><span className="card-title">Node Types</span></div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {Object.entries(nodeColors).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: color }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{type}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Retest Plan */}
          <div className="card">
            <div className="card-header"><span className="card-title">Retest Plan</span></div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              {mission.report.retest_plan}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
