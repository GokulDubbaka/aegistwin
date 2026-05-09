// AegisTwin API Client
const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';
const TENANT_ID = 'acme-fintech-demo';

async function apiRequest<T = any>(path: string, options?: RequestInit): Promise<T> {
  const sep = path.includes('?') ? '&' : '?';
  const url = `${BASE_URL}${path}${sep}tenant_id=${TENANT_ID}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json();
}

export const api = {
  getDashboard: () => apiRequest('/reports/dashboard'),
  getAssets: () => apiRequest('/assets/'),
  getFindings: () => apiRequest('/findings/'),
  getMissions: () => apiRequest('/missions/'),
  runMission: (id: string) => apiRequest(`/missions/${id}/run`, { method: 'POST' }),
  getClusters: () => apiRequest('/clusters/'),
  getTelemetry: () => apiRequest('/telemetry/'),
  getDeceptionItems: () => apiRequest('/deception/items'),
  getDeceptionEvents: () => apiRequest('/deception/events'),
  getDetectionDrafts: () => apiRequest('/detections/'),
  getRemediationTickets: () => apiRequest('/remediation/'),
  getAuditLog: () => apiRequest('/audit/'),
  checkPolicy: (actionType: string) =>
    apiRequest(`/missions/policy-check?action_type=${actionType}`),
};
