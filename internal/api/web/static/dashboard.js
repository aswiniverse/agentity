/* Agentity Admin — dashboard summary */

async function loadDashboard() {
  // Agent count
  try {
    const r = await apiFetch('/api/v1/agents');
    if (r.ok) {
      const data = await r.json();
      const el = document.getElementById('stat-agents');
      if (el) el.textContent = data.count ?? (data.agents ? data.agents.length : '—');
    }
  } catch { /* ignore */ }

  // Policy count via admin/policies
  try {
    const r = await apiFetch('/api/v1/admin/policies');
    if (r.ok) {
      const data = await r.json();
      const el = document.getElementById('stat-policies');
      if (el) el.textContent = data.count ?? (Array.isArray(data.policies) ? data.policies.length : '—');
    }
  } catch { /* ignore */ }

  // Recent audit events
  try {
    const r = await apiFetch('/api/v1/audit?limit=5');
    if (r.ok) {
      const data = await r.json();
      renderRecentAudit(data.entries || []);
    }
  } catch { /* ignore */ }
}

function renderRecentAudit(entries) {
  const tbody = document.getElementById('recent-audit-body');
  if (!tbody) return;
  if (!entries.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No recent events</td></tr>';
    return;
  }
  tbody.innerHTML = entries.map(e => `
    <tr>
      <td>${escHtml(e.type || e.event_type || '')}</td>
      <td class="mono">${escHtml(e.actor || '')}</td>
      <td class="mono">${escHtml(e.target || '')}</td>
      <td>${e.outcome ? `<span class="badge badge-${e.outcome === 'allow' ? 'allow' : 'deny'}">${escHtml(e.outcome)}</span>` : '—'}</td>
      <td>${formatDate(e.timestamp || e.created_at)}</td>
    </tr>
  `).join('');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', loadDashboard);
