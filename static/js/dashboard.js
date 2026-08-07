const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

function apiPost(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken,
    },
    body: JSON.stringify(body || {}),
  }).then(r => r.json());
}

function apiGet(url) {
  return fetch(url).then(r => r.json());
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

// ---------- stats ----------

function refreshStats() {
  apiGet('/api/stats').then(s => {
    document.getElementById('statTotal').textContent = s.total_devices;
    document.getElementById('statConnected').textContent = s.connected;
    document.getElementById('statRules').textContent = s.blocked_rules;
    document.getElementById('statBlockedVisits').textContent = s.blocked_visits;
  });
}

// ---------- devices ----------

function renderDevices(devices) {
  const tbody = document.getElementById('deviceTableBody');
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">No devices yet…</td></tr>';
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const statusClass = d.status === 'connected' ? 'status-connected' : 'status-disconnected';
    const blockLabel = d.is_blocked ? 'Blocked' : 'Allowed';
    const blockClass = d.is_blocked ? 'toggle-btn blocked' : 'toggle-btn';
    return `
      <tr>
        <td><span class="status-pill ${statusClass}"><span class="dot"></span>${d.status}</span></td>
        <td>${escapeHtml(d.hostname)}</td>
        <td class="mono">${escapeHtml(d.ip || '-')}</td>
        <td class="mono">${escapeHtml(d.mac)}</td>
        <td>${escapeHtml(d.last_seen || '-')}</td>
        <td><button class="${blockClass}" data-toggle-device="${d.id}" data-blocked="${d.is_blocked}">${blockLabel}</button></td>
        <td><button class="link-btn" data-history="${d.id}" data-name="${escapeHtml(d.hostname)}">View history</button></td>
      </tr>`;
  }).join('');

  tbody.querySelectorAll('[data-toggle-device]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-toggle-device');
      const currentlyBlocked = btn.getAttribute('data-blocked') === 'true';
      const url = currentlyBlocked ? '/api/unblock-device' : '/api/block-device';
      apiPost(url, { device_id: Number(id) }).then(() => { refreshDevices(); refreshStats(); refreshAudit(); });
    });
  });

  tbody.querySelectorAll('[data-history]').forEach(btn => {
    btn.addEventListener('click', () => openHistoryModal(btn.getAttribute('data-history'), btn.getAttribute('data-name')));
  });
}

function refreshDevices() {
  apiGet('/api/devices').then(renderDevices);
}

// ---------- block rules ----------

function renderRules(rules) {
  const list = document.getElementById('ruleList');
  const domainRules = rules.filter(r => r.type === 'domain');
  if (!domainRules.length) {
    list.innerHTML = '<li class="muted">No rules yet</li>';
    return;
  }
  list.innerHTML = domainRules.map(r => `
    <li>
      <span class="rule-target">${escapeHtml(r.target)}</span>
      <button class="rule-remove" data-unblock="${escapeHtml(r.target)}">Remove</button>
    </li>`).join('');

  list.querySelectorAll('[data-unblock]').forEach(btn => {
    btn.addEventListener('click', () => {
      apiPost('/api/unblock-domain', { domain: btn.getAttribute('data-unblock') })
        .then(() => { refreshRules(); refreshStats(); refreshAudit(); });
    });
  });
}

function refreshRules() {
  apiGet('/api/blocklist').then(renderRules);
}

document.getElementById('blockDomainForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('domainInput');
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;
  apiPost('/api/block-domain', { domain }).then(res => {
    if (res.error) { alert(res.error); return; }
    input.value = '';
    refreshRules();
    refreshStats();
    refreshAudit();
  });
});

// ---------- audit log ----------

function refreshAudit() {
  apiGet('/api/audit-log').then(logs => {
    const list = document.getElementById('auditList');
    if (!logs.length) {
      list.innerHTML = '<li class="muted">No activity yet</li>';
      return;
    }
    list.innerHTML = logs.map(l => `
      <li>
        <span class="audit-action">${escapeHtml(l.actor)} — ${escapeHtml(l.action)}</span>
        <span class="audit-time">${escapeHtml(l.timestamp)}</span>
      </li>`).join('');
  });
}

// ---------- history modal ----------

const modalBackdrop = document.getElementById('modalBackdrop');
document.getElementById('modalClose').addEventListener('click', () => modalBackdrop.classList.remove('open'));
modalBackdrop.addEventListener('click', (e) => { if (e.target === modalBackdrop) modalBackdrop.classList.remove('open'); });

function openHistoryModal(deviceId, name) {
  document.getElementById('modalTitle').textContent = `${name} — Recent Activity`;
  const body = document.getElementById('modalBody');
  body.innerHTML = '<p class="muted">Loading…</p>';
  modalBackdrop.classList.add('open');

  apiGet(`/api/devices/${deviceId}/history`).then(data => {
    if (!data.history.length) {
      body.innerHTML = '<p class="muted">No visits logged yet.</p>';
      return;
    }
    body.innerHTML = data.history.map(v => `
      <div class="history-row">
        <span class="history-domain ${v.blocked ? 'blocked' : 'allowed'}">${escapeHtml(v.domain)}</span>
        <span>${v.blocked ? 'Blocked (simulation)' : 'Allowed'}</span>
        <span class="audit-time">${escapeHtml(v.timestamp)}</span>
      </div>`).join('');
  });
}

// ---------- polling loop ----------

function refreshAll() {
  refreshDevices();
  refreshRules();
  refreshStats();
  refreshAudit();
}

refreshAll();
setInterval(refreshAll, 3000);
