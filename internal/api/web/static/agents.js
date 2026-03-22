/* Agentity Admin — agents table */

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function loadAgents() {
  const tbody = document.getElementById('agents-body');
  if (!tbody) return;
  tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Loading…</td></tr>';
  try {
    const r = await apiFetch('/api/v1/agents');
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      showToast(`Failed to load agents: ${err.detail || r.status}`, 'error');
      tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Error loading agents</td></tr>';
      return;
    }
    const data = await r.json();
    const agents = data.agents || [];
    if (!agents.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No agents registered</td></tr>';
      return;
    }
    tbody.innerHTML = agents.map(a => `
      <tr data-id="${escHtml(a.id)}" onclick="showDetail(${escHtml(JSON.stringify(a))})">
        <td class="mono">${escHtml(a.id)}</td>
        <td>${escHtml(a.name || '—')}</td>
        <td>${escHtml(a.model || '—')}</td>
        <td><span class="badge badge-${(a.status || '').toLowerCase()}">${escHtml(a.status || '—')}</span></td>
        <td>${formatDate(a.created_at)}</td>
      </tr>
    `).join('');
  } catch (err) {
    showToast('Network error loading agents', 'error');
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Network error</td></tr>';
  }
}

function showDetail(agent) {
  const overlay = document.getElementById('detail-overlay');
  const body    = document.getElementById('detail-body');
  if (!overlay || !body) return;
  body.innerHTML = `
    <div class="form-group"><label>ID</label><div class="token-field-value">${escHtml(agent.id)}</div></div>
    <div class="form-group"><label>Name</label><div>${escHtml(agent.name || '—')}</div></div>
    <div class="form-group"><label>Model</label><div>${escHtml(agent.model || '—')}</div></div>
    <div class="form-group"><label>Status</label><div><span class="badge badge-${(agent.status||'').toLowerCase()}">${escHtml(agent.status||'—')}</span></div></div>
    <div class="form-group"><label>Key ID</label><div class="mono">${escHtml(agent.key_id || agent.keyID || '—')}</div></div>
    <div class="form-group"><label>Parent ID</label><div class="mono">${escHtml(agent.parent_id || '—')}</div></div>
    <div class="form-group"><label>Created</label><div>${formatDate(agent.created_at)}</div></div>
    <div class="form-group"><label>Updated</label><div>${formatDate(agent.updated_at)}</div></div>
  `;
  overlay.classList.remove('hidden');
}

function closeDetail() {
  const overlay = document.getElementById('detail-overlay');
  if (overlay) overlay.classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  loadAgents();
  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadAgents);
  const closeBtn = document.getElementById('detail-close');
  if (closeBtn) closeBtn.addEventListener('click', closeDetail);
  const overlay = document.getElementById('detail-overlay');
  if (overlay) overlay.addEventListener('click', (e) => { if (e.target === overlay) closeDetail(); });
});
