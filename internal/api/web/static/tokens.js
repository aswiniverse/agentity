/* Agentity Admin — token inspector (pure client-side) */

function base64urlToBase64(str) {
  // Replace URL-safe chars and add padding
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4;
  if (pad === 2) str += '==';
  else if (pad === 3) str += '=';
  return str;
}

function decodeACT(raw) {
  raw = raw.trim();
  // Agentity ACT: base64url(JSON) — a single segment (not JWT)
  // Also handle dot-separated format if present
  let segment = raw;
  if (raw.includes('.')) {
    // If it looks like a dotted format, take the payload (middle or first)
    const parts = raw.split('.');
    // Try each part, use the first that parses to an object with 'blocks'
    for (const p of parts) {
      try {
        const decoded = JSON.parse(atob(base64urlToBase64(p)));
        if (decoded && (decoded.blocks || decoded.agent_id || decoded.capabilities)) {
          return decoded;
        }
      } catch { /* continue */ }
    }
    // Fallback: try first segment
    segment = parts[0];
  }
  const decoded = JSON.parse(atob(base64urlToBase64(segment)));
  return decoded;
}

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderBlock(block, index, total) {
  const caps = Array.isArray(block.capabilities) ? block.capabilities : [];
  const capsHtml = caps.length
    ? caps.map(c => `<span class="cap-pill">${escHtml(c)}</span>`).join('')
    : '<em style="color:var(--text-muted)">none</em>';

  return `
    <div class="token-block">
      <div class="token-block-title">Block ${index + 1} of ${total}${index === 0 ? ' — Root' : ' — Delegated'}</div>
      <div class="token-field">
        <span class="token-field-label">Agent ID</span>
        <span class="token-field-value">${escHtml(block.agent_id || '—')}</span>
      </div>
      ${block.user_id ? `
      <div class="token-field">
        <span class="token-field-label">User ID</span>
        <span class="token-field-value">${escHtml(block.user_id)}</span>
      </div>` : ''}
      <div class="token-field">
        <span class="token-field-label">Capabilities</span>
        <span class="token-field-value">${capsHtml}</span>
      </div>
      <div class="token-field">
        <span class="token-field-label">Expires At</span>
        <span class="token-field-value">${formatDate(block.expires_at)}</span>
      </div>
      <div class="token-field">
        <span class="token-field-label">Parent Key ID</span>
        <span class="token-field-value mono">${escHtml(block.parent_key_id || '—')}</span>
      </div>
      ${block.issued_at ? `
      <div class="token-field">
        <span class="token-field-label">Issued At</span>
        <span class="token-field-value">${formatDate(block.issued_at)}</span>
      </div>` : ''}
    </div>
  `;
}

function renderChain(act) {
  const chainEl = document.getElementById('token-chain');
  if (!chainEl) return;

  // Normalize: ACT might be {blocks:[...]} or a single block
  let blocks = [];
  if (Array.isArray(act.blocks)) {
    blocks = act.blocks;
  } else if (act.agent_id || act.capabilities) {
    blocks = [act];
  } else {
    chainEl.innerHTML = '<p style="color:var(--deny)">Decoded but unrecognised structure. Check raw JSON below.</p>';
    return;
  }

  let html = '';
  blocks.forEach((block, i) => {
    html += renderBlock(block, i, blocks.length);
    if (i < blocks.length - 1) {
      html += '<div class="token-arrow">&#8595;</div>';
    }
  });
  chainEl.innerHTML = html;
}

function decode() {
  const input  = document.getElementById('token-input');
  const rawOut = document.getElementById('raw-output');
  const chainEl = document.getElementById('token-chain');
  const errEl  = document.getElementById('decode-error');

  if (!input) return;
  const raw = input.value.trim();
  if (!raw) {
    showToast('Paste a token first', 'info');
    return;
  }

  if (errEl)  errEl.textContent = '';
  if (chainEl) chainEl.innerHTML = '';
  if (rawOut) rawOut.textContent = '';

  try {
    const act = decodeACT(raw);

    renderChain(act);

    if (rawOut) {
      rawOut.textContent = JSON.stringify(act, null, 2);
    }
    showToast('Token decoded', 'success');
  } catch (err) {
    const msg = `Failed to decode: ${err.message}`;
    if (errEl) errEl.textContent = msg;
    showToast(msg, 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('decode-btn');
  if (btn) btn.addEventListener('click', decode);
  const input = document.getElementById('token-input');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'Enter') decode();
    });
  }
  const clearBtn = document.getElementById('clear-btn');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    const inp = document.getElementById('token-input');
    const chain = document.getElementById('token-chain');
    const raw = document.getElementById('raw-output');
    const err = document.getElementById('decode-error');
    if (inp) inp.value = '';
    if (chain) chain.innerHTML = '';
    if (raw) raw.textContent = '';
    if (err) err.textContent = '';
  });
});
