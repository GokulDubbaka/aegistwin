import { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Shield, Crosshair, GitBranch, Radar, Fingerprint,
  AlertTriangle, Archive, Zap, FileCode, Wrench, Activity, ChevronRight
} from 'lucide-react';

import Dashboard from './pages/Dashboard';
import DigitalTwin from './pages/DigitalTwin';
import OffensiveMissions from './pages/OffensiveMissions';
import AttackPathGraph from './pages/AttackPathGraph';
import DefensiveHunter from './pages/DefensiveHunter';
import ActorFingerprints from './pages/ActorFingerprints';
import Findings from './pages/Findings';
import EvidenceVault from './pages/EvidenceVault';
import DeceptionEvents from './pages/DeceptionEvents';
import DetectionDrafts from './pages/DetectionDrafts';
import RemediationQueue from './pages/RemediationQueue';

const navSections = [
  {
    label: 'Overview',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
      { to: '/digital-twin', icon: Shield, label: 'Company Twin' },
    ],
  },
  {
    label: 'Offensive',
    items: [
      { to: '/missions', icon: Crosshair, label: 'Red Team Missions' },
      { to: '/attack-paths', icon: GitBranch, label: 'Attack Paths' },
    ],
  },
  {
    label: 'Defensive',
    items: [
      { to: '/defensive-hunter', icon: Radar, label: 'Hunter' },
      { to: '/actor-fingerprints', icon: Fingerprint, label: 'Actor Fingerprints' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/findings', icon: AlertTriangle, label: 'Findings' },
      { to: '/evidence-vault', icon: Archive, label: 'Evidence Vault' },
      { to: '/deception', icon: Zap, label: 'Deception Events' },
    ],
  },
  {
    label: 'Engineering',
    items: [
      { to: '/detections', icon: FileCode, label: 'Detection Drafts' },
      { to: '/remediation', icon: Wrench, label: 'Remediation Queue' },
    ],
  },
];

function Sidebar() {
  const location = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-text">AegisTwin</div>
        <div className="sidebar-subtitle">Dual-Agent Security Platform</div>
      </div>

      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div key={section.label} className="sidebar-section">
            <div className="sidebar-section-label">{section.label}</div>
            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = item.exact
                ? location.pathname === item.to
                : location.pathname.startsWith(item.to);
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={`nav-item ${isActive ? 'active' : ''}`}
                >
                  <Icon className="nav-icon" size={16} />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Status indicator */}
      <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="pulse-dot" />
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Acme Fintech — Live
          </span>
        </div>
      </div>
    </aside>
  );
}

function Header() {
  const location = useLocation();
  const labels: Record<string, string> = {
    '/': 'Dashboard',
    '/digital-twin': 'Company Digital Twin',
    '/missions': 'Offensive Red-Team Missions',
    '/attack-paths': 'Attack Path Graph',
    '/defensive-hunter': 'Defensive Hunter AI',
    '/actor-fingerprints': 'Actor Fingerprints',
    '/findings': 'Security Findings',
    '/evidence-vault': 'Evidence Vault',
    '/deception': 'Deception Events',
    '/detections': 'Detection Engineering Drafts',
    '/remediation': 'Remediation Queue',
  };

  const title = labels[location.pathname] || 'AegisTwin';

  return (
    <header className="header">
      <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
      <span className="header-title">{title}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Tenant: Acme Fintech
        </span>
        <span className="badge badge-open">Demo</span>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <Sidebar />
        <div className="main-content">
          <Header />
          <div className="page-container">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/digital-twin" element={<DigitalTwin />} />
              <Route path="/missions" element={<OffensiveMissions />} />
              <Route path="/attack-paths" element={<AttackPathGraph />} />
              <Route path="/defensive-hunter" element={<DefensiveHunter />} />
              <Route path="/actor-fingerprints" element={<ActorFingerprints />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/evidence-vault" element={<EvidenceVault />} />
              <Route path="/deception" element={<DeceptionEvents />} />
              <Route path="/detections" element={<DetectionDrafts />} />
              <Route path="/remediation" element={<RemediationQueue />} />
            </Routes>
          </div>
        </div>
      </div>
    </BrowserRouter>
  );
}
