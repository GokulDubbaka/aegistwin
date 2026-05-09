// @ts-nocheck
import { useEffect, useState } from 'react';
import { api } from '../api/client';

const priorityColor = (p: string) => ({
  critical: 'var(--risk-critical)', high: 'var(--risk-high)',
  medium: 'var(--risk-medium)', low: 'var(--risk-low)',
}[p] || 'var(--text-muted)');

export default function RemediationQueue() {
  const [tickets, setTickets] = useState<any[]>([]);
  useEffect(() => { api.getRemediationTickets().then(setTickets).catch(console.error); }, []);
  return (
    <div>
      <div className="page-header">
        <div className="page-header-info">
          <h1>Remediation Queue</h1>
          <p>Structured tickets, owner assignments, and retest plans</p>
        </div>
        <span className="badge badge-high">{tickets.length} Open Tickets</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {tickets.map((ticket, i) => (
          <div key={ticket.id} className="card"
            style={{ borderLeft: `3px solid ${priorityColor(ticket.priority)}` }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 16 }}>
              <div>
                <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <span className={`badge badge-${ticket.priority}`}>{ticket.priority.toUpperCase()}</span>
                  <span className="badge badge-info">{ticket.ticket_type.toUpperCase()}</span>
                  <span className="badge badge-open">{ticket.status}</span>
                </div>
                <h3 style={{ color: 'var(--text-primary)' }}>{ticket.title}</h3>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Suggested Owner</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 500 }}>
                  {ticket.suggested_owner}
                </div>
              </div>
            </div>

            <div style={{ padding: '12px 16px', background: 'var(--bg-secondary)',
              borderRadius: 8, marginBottom: 12 }}>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: '0.08em', marginBottom: 6 }}>Retest Plan</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {ticket.retest_plan}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-secondary" style={{ fontSize: '0.75rem' }}>
                Export to {ticket.ticket_type === 'jira' ? 'Jira' : 'GitHub'}
              </button>
              <button className="btn btn-secondary" style={{ fontSize: '0.75rem' }}>
                Mark In-Progress
              </button>
              <button className="btn btn-secondary" style={{ fontSize: '0.75rem', color: 'var(--risk-low)' }}>
                Mark Remediated
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
