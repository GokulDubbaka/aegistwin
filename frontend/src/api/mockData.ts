// AegisTwin Mock Data — Acme Fintech Demo Scenario
// Used for frontend when backend is not available

export const DEMO_TENANT_ID = 'acme-fintech-demo';

export const mockStats = {
  tenant_id: DEMO_TENANT_ID,
  findings: { total: 3, open: 3, critical: 1, high: 1 },
  offensive_missions: 1,
  actor_clusters: 1,
  telemetry_events: 22,
  deception_events: 1,
  detection_drafts: 2,
  remediation_tickets: 2,
  assets: 7,
  risk_posture: 'critical',
};

export const mockAssets = [
  { id: '1', name: 'Acme Public API', asset_type: 'api', url: 'https://api.acmefintech.com',
    criticality: 8, data_sensitivity: 7, is_in_scope: true, owner: 'Platform Engineering',
    tags: ['public', 'production'], status: 'active' },
  { id: '2', name: 'Staging Web App', asset_type: 'web_app', url: 'https://staging.acmefintech.com',
    criticality: 5, data_sensitivity: 4, is_in_scope: true, owner: 'Engineering',
    tags: ['staging', 'internet-facing'], status: 'active' },
  { id: '3', name: 'GitHub Monorepo', asset_type: 'repository', url: 'https://github.com/acmefintech/monorepo',
    criticality: 7, data_sensitivity: 8, is_in_scope: true, owner: 'DevSecOps',
    tags: ['source-code'], status: 'active' },
  { id: '4', name: 'AWS Production Account', asset_type: 'cloud_account', criticality: 9,
    data_sensitivity: 9, is_in_scope: true, owner: 'Cloud Infrastructure',
    tags: ['aws', 'production'], status: 'active' },
  { id: '5', name: 'Okta Identity Provider', asset_type: 'identity_provider',
    hostname: 'acmefintech.okta.com', criticality: 9, data_sensitivity: 8, is_in_scope: true,
    owner: 'IAM Team', tags: ['idp', 'sso'], status: 'active' },
  { id: '6', name: 'Support Admin Portal', asset_type: 'web_app',
    url: 'https://admin.acmefintech.com', criticality: 10, data_sensitivity: 10, is_in_scope: true,
    owner: 'Operations', tags: ['admin', 'internal'], status: 'active' },
  { id: '7', name: 'Customer Data Store', asset_type: 'database',
    hostname: 'customer-db.internal.acmefintech.com', criticality: 10, data_sensitivity: 10,
    is_in_scope: true, owner: 'Data Engineering', tags: ['pii', 'financial-data'], status: 'active' },
];

export const mockFindings = [
  {
    id: 'f1', tenant_id: DEMO_TENANT_ID, title: 'Staging Environment Publicly Accessible',
    description: 'staging.acmefintech.com is directly accessible from the public internet without VPN.',
    risk_level: 'critical', risk_score: 87.5, status: 'open', source: 'offensive',
    asset_id: '2', created_at: '2024-03-15T12:00:00Z',
    evidence: ['HTTP 200 from external IP', 'robots.txt discloses /admin path'],
    recommended_fix: 'Place behind VPN or IP allowlist',
  },
  {
    id: 'f2', tenant_id: DEMO_TENANT_ID, title: 'Conditional MFA Gaps in Okta Admin Portal',
    description: 'MFA bypass via trusted device exception not reviewed in 18 months.',
    risk_level: 'high', risk_score: 72.3, status: 'open', source: 'offensive',
    asset_id: '5', created_at: '2024-03-15T12:05:00Z',
    evidence: ['Trusted device exception active in Okta policy', 'Admin portal no step-up MFA'],
    recommended_fix: 'Remove trusted device exception, enforce step-up MFA',
  },
  {
    id: 'f3', tenant_id: DEMO_TENANT_ID, title: 'AWS S3 Bucket with Public Read ACL',
    description: 'acme-backups bucket has public-read ACL — potential data exposure.',
    risk_level: 'medium', risk_score: 48.1, status: 'open', source: 'offensive',
    asset_id: '4', created_at: '2024-03-15T12:10:00Z',
    evidence: ['S3 ACL: public-read confirmed', 'backup-role has s3:* permissions'],
    recommended_fix: 'Remove public ACL, restrict IAM role to specific buckets',
  },
];

export const mockMission = {
  id: 'm1', tenant_id: DEMO_TENANT_ID, engagement_id: 'eng-acme-2024',
  name: 'Staging-to-Data-Store Attack Path', status: 'completed',
  risk_score: 87.5, risk_level: 'critical',
  created_at: '2024-03-15T11:00:00Z',
  report: {
    hypothesis: 'Attacker accesses staging app, exploits weak MFA to pivot to admin portal, reaches customer data.',
    risk_score: 87.5, risk_level: 'critical', confidence: 0.75,
    business_impact: 'Customer financial data exposure, PCI-DSS/GDPR penalties, reputational damage.',
    recommended_fix: '1. Enforce MFA for ALL users. 2. VPN for staging. 3. Rotate exposed secrets. 4. Enable cloud audit logging.',
    retest_plan: 'After fix: re-run fingerprint scan, re-check IdP MFA policy, verify bucket ACL.',
    attack_path: {
      nodes: [
        { id: 'n1', node_type: 'EntryPoint', label: 'Staging App — Public Exposure',
          description: 'Staging environment accessible without VPN', detection_coverage: false },
        { id: 'n2', node_type: 'Weakness', label: 'Weak MFA Policy',
          description: 'MFA enforcement gaps allow account takeover', detection_coverage: true },
        { id: 'n3', node_type: 'Application', label: 'Admin Portal',
          description: 'Internal admin portal reached via stolen session', detection_coverage: true },
        { id: 'n4', node_type: 'BusinessImpact', label: 'Customer Data Exposure',
          description: 'Attacker reaches PII financial data store — regulatory exposure', detection_coverage: false },
      ],
      edges: [
        { from: 'n1', to: 'n2', relationship: 'ENABLES' },
        { from: 'n2', to: 'n3', relationship: 'ENABLES' },
        { from: 'n3', to: 'n4', relationship: 'LEADS_TO' },
      ],
    },
    blocked_unsafe_steps: [
      'exploit execution against production',
      'credential use or abuse',
      'persistence installation',
      'lateral movement automation',
      'data exfiltration',
    ],
  },
};

export const mockCluster = {
  id: 'c1', tenant_id: DEMO_TENANT_ID,
  cluster_label: 'CLUSTER-A3F7B291',
  confidence: 0.91,
  likely_automation: 'high',
  likely_ai_assisted: 'medium',
  event_count: 22,
  created_at: '2024-03-15T14:30:00Z',
  evidence: [
    'IP 185.220.101.5 sent 22 requests in window',
    'User-agent matches known scanner: Nuclei',
    'ASN AS209605 in threat intel bad-ASN list',
    'Honeytoken triggered — definitive attacker evidence',
  ],
  recommended_actions: [
    'IMMEDIATE: Block source IPs — honeytoken triggered',
    'Escalate to incident response team',
    'Enable enhanced logging on all cluster-scope assets',
    'Deploy detection rule draft to SIEM in monitor-only mode',
  ],
  fingerprint: {
    asn_pattern: ['AS209605'],
    ja3_fingerprints: ['t13d1512h2_8daaf6152771'],
    source_ips: ['185.220.101.5', '45.155.204.127'],
    user_agents: ['Nuclei/2.9.6', 'curl/7.88'],
    honeytoken_interaction: true,
    timing_regular: true,
  },
};

export const mockDetectionDrafts = [
  {
    id: 'd1', tenant_id: DEMO_TENANT_ID,
    title: '[DRAFT] Staging Environment Publicly Accessible',
    rule_type: 'sigma', status: 'draft',
    description: 'Sigma rule for detecting staging app probing',
    created_at: '2024-03-15T14:00:00Z',
    content: `title: 'Staging App Public Exposure Probe'
id: a1b2c3d4-...
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/admin'
      - '/.env'
  condition: selection
level: high`,
  },
  {
    id: 'd2', tenant_id: DEMO_TENANT_ID,
    title: '[DRAFT] Behavioral Cluster CLUSTER-A3F7B291',
    rule_type: 'sigma', status: 'draft',
    description: 'Sigma rule for actor cluster pattern',
    created_at: '2024-03-15T14:05:00Z',
    content: `title: 'Actor Cluster CLUSTER-A3F7B291 Activity'
id: e5f6g7h8-...
status: experimental
logsource:
  category: proxy
detection:
  selection_asn:
    src_asn:
      - AS209605
  condition: selection_asn
level: critical`,
  },
];

export const mockTickets = [
  {
    id: 't1', tenant_id: DEMO_TENANT_ID, finding_id: 'f1',
    title: '[SECURITY] Staging Environment Publicly Accessible',
    priority: 'critical', ticket_type: 'jira', status: 'open',
    suggested_owner: 'Application Security Team',
    created_at: '2024-03-15T14:00:00Z',
    retest_plan: 'Verify staging returns 403 from external IP after VPN implementation.',
  },
  {
    id: 't2', tenant_id: DEMO_TENANT_ID, finding_id: 'f2',
    title: '[SECURITY] MFA Bypass in Okta Admin Portal',
    priority: 'high', ticket_type: 'jira', status: 'open',
    suggested_owner: 'Identity & Access Management Team',
    created_at: '2024-03-15T14:05:00Z',
    retest_plan: 'Verify admin portal requires MFA step-up for all sessions.',
  },
];

export const mockDeceptionItems = [
  {
    id: 'di1', tenant_id: DEMO_TENANT_ID, item_type: 'honey_token',
    label: 'Fake AWS API Key — Acme Prod',
    fake_value: 'FAKE_AKIAIOSFODNN7EXAMPLE_AEGISTWIN_FAKE_DO_NOT_USE',
    internal_marker: 'AEGISTWIN_FAKE_DO_NOT_USE',
    is_active: true, triggered_count: 1,
    created_at: '2024-03-10T09:00:00Z',
  },
  {
    id: 'di2', tenant_id: DEMO_TENANT_ID, item_type: 'honey_credential',
    label: 'Fake Admin Portal Credential',
    fake_value: 'username=admin.fake@acmefintech.com password=FAKE_PASSWORD_AEGISTWIN_FAKE_DO_NOT_USE',
    internal_marker: 'AEGISTWIN_FAKE_DO_NOT_USE',
    is_active: true, triggered_count: 0,
    created_at: '2024-03-10T09:05:00Z',
  },
];

export const mockTelemetryEvents = Array.from({ length: 22 }, (_, i) => ({
  id: `te${i}`, tenant_id: DEMO_TENANT_ID,
  source: i % 3 === 0 ? 'waf' : 'edr',
  event_timestamp: `2024-03-15T14:${String(i).padStart(2, '0')}:00Z`,
  actor_ip: i < 15 ? '185.220.101.5' : '45.155.204.127',
  actor_asn: 'AS209605',
  action: i === 21 ? 'honeytoken_access' : 'GET',
  is_suspicious: true,
  cluster_id: 'CLUSTER-A3F7B291',
  created_at: `2024-03-15T14:${String(i).padStart(2, '0')}:00Z`,
}));
