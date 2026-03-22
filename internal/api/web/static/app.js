/* Agentity Admin — shared utilities */

// ── API key management ────────────────────────────────
const getApiKey = () => localStorage.getItem('agentity-api-key') || '';
const saveApiKey = (key) => localStorage.setItem('agentity-api-key', key);

// ── Fetch wrapper with auth header ────────────────────
async function apiFetch(path, options = {}) {
  const key = getApiKey();
  const resp = await fetch(path, {
    ...options,
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  return resp;
}

// ── Toast notification ────────────────────────────────
(function () {
  const container = document.createElement('div');
  container.className = 'toast-container';
  document.body.appendChild(container);
  window._toastContainer = container;
})();

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  window._toastContainer.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// ── Format timestamp ──────────────────────────────────
function formatDate(isoStr) {
  if (!isoStr) return '—';
  try { return new Date(isoStr).toLocaleString(); } catch { return isoStr; }
}

// ── API key input wiring (shared header) ──────────────
function initApiKeyInput() {
  const input = document.getElementById('api-key-input');
  const btn   = document.getElementById('api-key-save');
  if (!input) return;
  input.value = getApiKey();
  if (btn) {
    btn.addEventListener('click', () => {
      saveApiKey(input.value.trim());
      showToast('API key saved', 'success');
    });
  }
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      saveApiKey(input.value.trim());
      showToast('API key saved', 'success');
    }
  });
}

// ── Mark active nav link ──────────────────────────────
function markActiveNav() {
  const page = location.pathname.replace(/\/$/, '').split('/').pop() || 'index.html';
  document.querySelectorAll('.sidebar nav a').forEach(a => {
    const href = a.getAttribute('href').split('/').pop();
    if (href === page || (page === '' && href === 'index.html')) {
      a.classList.add('active');
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initApiKeyInput();
  markActiveNav();
});
