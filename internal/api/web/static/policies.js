/* Agentity Admin — policy management */

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function loadPolicies() {
  const tbody = document.getElementById('policies-body');
  if (!tbody) return;
  tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Loading…</td></tr>';
  try {
    const r = await apiFetch('/api/v1/admin/policies');
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      showToast(`Failed to load policies: ${err.detail || r.status}`, 'error');
      tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Error loading policies</td></tr>';
      return;
    }
    const data = await r.json();
    const policies = data.policies || [];
    if (!policies.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No policies defined</td></tr>';
      return;
    }
    tbody.innerHTML = policies.map(p => `
      <tr>
        <td>${escHtml(p.name || '—')}</td>
        <td class="mono" style="max-width:260px;word-break:break-all">${escHtml(p.expression || p.rule || '—')}</td>
        <td><span class="badge badge-${p.action === 'allow' ? 'allow' : 'deny'}">${escHtml(p.action || '—')}</span></td>
        <td>${escHtml(p.priority ?? '—')}</td>
        <td>
          <button class="btn btn-danger" onclick="deletePolicy('${escHtml(p.id)}', '${escHtml(p.name || p.id)}')">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast('Network error loading policies', 'error');
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Network error</td></tr>';
  }
}

async function deletePolicy(id, name) {
  if (!confirm(`Delete policy "${name}"? This cannot be undone.`)) return;
  try {
    const r = await apiFetch(`/api/v1/admin/policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      showToast(`Delete failed: ${err.detail || r.status}`, 'error');
      return;
    }
    showToast('Policy deleted', 'success');
    loadPolicies();
  } catch {
    showToast('Network error deleting policy', 'error');
  }
}

function openAddModal() {
  const overlay = document.getElementById('add-modal');
  if (overlay) overlay.classList.remove('hidden');
}

function closeAddModal() {
  const overlay = document.getElementById('add-modal');
  if (overlay) overlay.classList.add('hidden');
  const form = document.getElementById('policy-form');
  if (form) form.reset();
}

async function submitPolicy(e) {
  e.preventDefault();
  const name       = document.getElementById('p-name').value.trim();
  const expression = document.getElementById('p-expression').value.trim();
  const action     = document.getElementById('p-action').value;
  const priority   = parseInt(document.getElementById('p-priority').value, 10);

  if (!name || !expression) {
    showToast('Name and expression are required', 'error');
    return;
  }

  try {
    const r = await apiFetch('/api/v1/admin/policies', {
      method: 'POST',
      body: JSON.stringify({ name, expression, action, priority: isNaN(priority) ? 0 : priority }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      showToast(`Create failed: ${err.detail || r.status}`, 'error');
      return;
    }
    showToast('Policy created', 'success');
    closeAddModal();
    loadPolicies();
  } catch {
    showToast('Network error creating policy', 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadPolicies();

  const addBtn = document.getElementById('add-policy-btn');
  if (addBtn) addBtn.addEventListener('click', openAddModal);

  const cancelBtn = document.getElementById('cancel-policy-btn');
  if (cancelBtn) cancelBtn.addEventListener('click', closeAddModal);

  const form = document.getElementById('policy-form');
  if (form) form.addEventListener('submit', submitPolicy);

  const overlay = document.getElementById('add-modal');
  if (overlay) overlay.addEventListener('click', (e) => { if (e.target === overlay) closeAddModal(); });

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadPolicies);
});
