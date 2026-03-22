/* Agentity Admin — audit log viewer */

let autoRefreshTimer = null;

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function loadAudit() {
  const tbody = document.getElementById('audit-body');
  if (!tbody) return;
  try {
    const r = await apiFetch('/api/v1/audit?limit=50');
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      showToast(`Failed to load audit log: ${err.detail || r.status}`, 'error');
      return;
    }
    const data = await r.json();
    const entries = data.entries || [];
    if (!entries.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No audit events</td></tr>';
      return;
    }
    tbody.innerHTML = entries.map(e => {
      const outcome = (e.outcome || '').toLowerCase();
      const badgeClass = outcome === 'allow' ? 'badge-allow' : outcome === 'deny' ? 'badge-deny' : 'badge-info';
      return `
        <tr>
          <td>${escHtml(e.type || e.event_type || '—')}</td>
          <td class="mono">${escHtml(e.actor || '—')}</td>
          <td class="mono">${escHtml(e.target || '—')}</td>
          <td>${escHtml(e.action || '—')}</td>
          <td>${outcome ? `<span class="badge ${badgeClass}">${escHtml(outcome)}</span>` : '—'}</td>
          <td>${formatDate(e.timestamp || e.created_at)}</td>
        </tr>
      `;
    }).join('');
  } catch {
    showToast('Network error loading audit log', 'error');
  }
}

function setAutoRefresh(enabled) {
  if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
  if (enabled) { autoRefreshTimer = setInterval(loadAudit, 10000); }
}

document.addEventListener('DOMContentLoaded', () => {
  loadAudit();

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadAudit);

  const toggle = document.getElementById('auto-refresh-toggle');
  if (toggle) {
    toggle.addEventListener('change', () => setAutoRefresh(toggle.checked));
  }
});
