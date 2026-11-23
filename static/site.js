const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function formatTimestamp(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '—';
  const normalized = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return raw;
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short'
  }).format(date);
}
let dashboardUsers = [];
let dashboardRole = 'employee';
let osMetricsTimer = null;
let osMetricHistory = [];
let loginLockTimer = null;
let loginLockUntil = 0;

function applyThemeMode(isDark) {
  document.body.classList.toggle('theme-dark', isDark);
  const button = $('#theme-toggle');
  button.textContent = isDark ? 'Light' : 'Dark';
  button.title = `Switch to ${isDark ? 'light' : 'dark'} mode`;
  button.setAttribute('aria-label', button.title);
  button.setAttribute('aria-pressed', String(isDark));
}

let darkTheme = false;
try { darkTheme = localStorage.getItem('aegis-theme') === 'dark'; } catch { /* Use the light theme if browser storage is unavailable. */ }
applyThemeMode(darkTheme);
$('#theme-toggle').addEventListener('click', () => {
  darkTheme = !darkTheme;
  try { localStorage.setItem('aegis-theme', darkTheme ? 'dark' : 'light'); } catch { /* The selected theme still applies for this page. */ }
  applyThemeMode(darkTheme);
});


async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  const response = await fetch(path, { credentials: 'same-origin', ...options,
    headers });
  const body = await response.text();
  let result = {};
  try { result = body ? JSON.parse(body) : {}; } catch { /* Keep the HTTP status for non-JSON server errors. */ }
  if (!response.ok) {
    const error = new Error(result.error || `The security service returned HTTP ${response.status}. Check the server terminal for details.`);
    error.status = response.status;
    error.data = result;
    throw error;
  }
  return result;
}
function message(selector, text, success = false) {
  const target = $(selector);
  target.textContent = text;
  target.hidden = false;
  target.classList.toggle('success', success);
  target.classList.toggle('error', !success);
}
function clearLoginLockTimer() {
  if (loginLockTimer) clearInterval(loginLockTimer);
  loginLockTimer = null;
  loginLockUntil = 0;
}
function startLoginLockCountdown(text) {
  const button = $('#login-form button[type="submit"]');
  const match = text.match(/(\d+)\s*second/i);
  const seconds = Math.max(1, Number(match?.[1] || 30));
  clearLoginLockTimer();
  loginLockUntil = Date.now() + seconds * 1000;
  const update = () => {
    const remaining = Math.max(0, Math.ceil((loginLockUntil - Date.now()) / 1000));
    if (remaining === 0) {
      clearLoginLockTimer();
      button.disabled = false;
      button.firstChild.textContent = 'Sign in ';
      message('#login-message', 'The temporary lock has ended. You can try signing in again.');
      return;
    }
    button.disabled = true;
    button.firstChild.textContent = `Wait ${remaining}s `;
    message('#login-message', `Your account is temporarily locked after repeated incorrect passwords. You can try again in ${remaining} second${remaining === 1 ? '' : 's'}.`);
  };
  update();
  loginLockTimer = setInterval(update, 1000);
}
function showDashboard() {
  $('#login-view').hidden = true;
  $('#dashboard-view').hidden = false;
  $('#today').textContent = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date());
  document.querySelectorAll('.admin-only').forEach((element) => { element.hidden = dashboardRole !== 'admin'; });
  updateRoleSidebar();
  switchDashboardTab(location.hash.slice(1) || 'repository', false);
  loadDashboard().catch((error) => message('#access-message', error.message));
}

const dashboardTabs = {
  repository: { label: 'File Repository', targets: ['.welcome-row', '.stat-grid', '#files', '#access-check'] },
  users: { label: 'User Management', targets: [] },
  permissions: { label: 'Access Permissions', targets: [] },
  audit: { label: 'Audit Logs', targets: ['#activity'] },
  transactions: { label: 'Transactions', targets: [] },
  diagnostics: { label: 'OS Diagnostics', targets: ['#os-panel'] },
  vault: { label: 'AES-256 RAM Vault', targets: ['#vault-panel'] },
  recovery: { label: 'ARIES Recovery', targets: ['#recovery-panel'] },
  soc: { label: 'SOC Cockpit', targets: ['#soc-panel'] },
  fim: { label: 'FIM & Ransomware Guard', targets: ['#integrity-panel'] },
  'threat-intel': { label: 'IP Firewall Rules', targets: [] },
  announcements: { label: 'Announcements', targets: ['#announcements-board'] },
  scanner: { label: 'Vulnerability Scanner', targets: ['#scanner-panel'] },
  sessions: { label: 'Active Sessions', targets: [] }
};

const accessCardsByTab = {
  repository: ['#protected-upload-card', '#protected-edit-card', '#protected-remove-card'],
  users: ['#email-card', '#unlock-card', '#employee-create-card', '#employee-remove-card'],
  permissions: ['#permission-card']
};
const operationCardsByTab = {
  announcements: ['#announcement-card'],
  sessions: ['#sessions-card'],
  transactions: ['#transactions-card'],
  'threat-intel': ['#network-card']
};

const roleTabs = {
  EMPLOYEE: ['repository', 'announcements'],
  HR: ['repository', 'audit', 'transactions', 'announcements', 'sessions'],
  DIRECTOR: ['repository', 'audit', 'transactions', 'announcements', 'sessions'],
  PROJECT_MANAGER: ['repository', 'audit', 'transactions', 'diagnostics', 'vault', 'announcements', 'sessions'],
  ADMIN: ['repository', 'users', 'permissions', 'audit', 'transactions', 'diagnostics', 'vault', 'recovery', 'soc', 'fim', 'threat-intel', 'announcements', 'scanner', 'sessions']
};

function currentRoleType() {
  return dashboardRole.toUpperCase();
}

function updateRoleSidebar() {
  const allowed = roleTabs[currentRoleType()] || roleTabs.EMPLOYEE;
  document.querySelectorAll('#dashboard-nav [data-tab]').forEach((link) => {
    link.hidden = !allowed.includes(link.dataset.tab);
  });
  const publisher = true;
  document.querySelectorAll('[data-publisher-only]').forEach((el) => { el.hidden = !publisher; });
}

function switchDashboardTab(tab, updateAddress = true) {
  const link = document.querySelector(`#dashboard-nav [data-tab="${tab}"]`);
  if (!dashboardTabs[tab] || !link || link.hidden) tab = 'repository';
  displayDashboardTab(tab);
  document.querySelectorAll('#dashboard-nav .nav-item').forEach((item) => {
    const active = item.dataset.tab === tab;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  const crumb = document.querySelector('.crumb strong');
  if (crumb) crumb.textContent = dashboardTabs[tab].label;
  if (updateAddress) history.replaceState(null, '', `#${tab}`);
  if (osMetricsTimer) { clearInterval(osMetricsTimer); osMetricsTimer = null; }
  if (tab === 'diagnostics') {
    loadOsPanel();
    osMetricsTimer = setInterval(() => loadOsPanel(), 5000);
  }
  if (tab === 'soc') loadSocPanel().catch((error) => { $('#soc-threat').textContent = error.message; });
  if (tab === 'fim') loadIntegrityPanel().catch((error) => { $('#integrity-summary').textContent = error.message; });
  if (tab === 'recovery') loadRecoveryPanel().catch((error) => { $('#recovery-status').textContent = error.message; });
  if (tab === 'vault') loadVaultPanel().catch((error) => { $('#vault-list').textContent = error.message; });
  if (tab === 'audit') loadAuditPanel().catch((error) => { $('#audit-table').innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`; });
  if (tab === 'transactions') loadTransactionsPanel().catch((error) => { $('#transactions-table').innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`; });
  if (tab === 'sessions') loadSessionsPanel().catch((error) => { $('#sessions-table').innerHTML = `<tr><td colspan="4">${escapeHtml(error.message)}</td></tr>`; });
  if (tab === 'scanner') loadScannerPanel().catch((error) => { $('#health-results').textContent = error.message; });
  if (tab === 'announcements') loadAnnouncementList().catch((error) => { $('#employee-announcements').textContent = error.message; });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function displayDashboardTab(tab) {
  const visibleTargets = new Set(dashboardTabs[tab].targets);
  const roleType = currentRoleType();
  if (dashboardRole === 'admin' && ['repository', 'users', 'permissions'].includes(tab)) visibleTargets.add('#access');
  if (['sessions', 'transactions', 'diagnostics', 'threat-intel'].includes(tab) || tab === 'announcements') visibleTargets.add('#operations');
  const allTargets = [...Object.values(dashboardTabs).flatMap((item) => item.targets), '#access', '#operations', '#system'];
  allTargets.forEach((selector) => {
    document.querySelectorAll(selector).forEach((element) => { element.hidden = !visibleTargets.has(selector); });
  });
  document.querySelectorAll('#access [id$="-card"]').forEach((card) => {
    card.hidden = !(dashboardRole === 'admin' && (accessCardsByTab[tab] || []).includes(`#${card.id}`));
  });
  document.querySelectorAll('#operations [id$="-card"]').forEach((card) => {
    const isAllowed = (operationCardsByTab[tab] || []).includes(`#${card.id}`) &&
      (card.id !== 'network-card' || dashboardRole === 'admin');
    card.hidden = !isAllowed;
  });
}

$('#dashboard-nav').addEventListener('click', (event) => {
  const link = event.target.closest('[data-tab]');
  if (!link) return;
  event.preventDefault();
  switchDashboardTab(link.dataset.tab);
});

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $('#login-message').hidden = true;
  try {
    const loginResult = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: $('#username').value.trim(), password: $('#password').value }) });
    dashboardRole = loginResult.role;
    $('#username').value = '';
    $('#password').value = '';
    showDashboard();
  } catch (error) {
    if (error.data?.locked && !error.data?.permanent) startLoginLockCountdown(error.message);
    else message('#login-message', error.message);
  } finally { if (!loginLockTimer) button.disabled = false; }
});

$('#show-reset').addEventListener('click', () => {
  const requestForm = $('#reset-request-form');
  requestForm.hidden = !requestForm.hidden;
  if (!requestForm.hidden) {
    $('#reset-username').value = $('#username').value.trim();
    requestForm.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});
$('#reset-request-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $('#reset-request-message').hidden = true;
  try {
    const username = $('#reset-username').value.trim();
    const result = await api('/api/password-reset/request', { method: 'POST', body: JSON.stringify({
      username, email: $('#reset-email').value.trim()
    }) });
    $('#reset-username').value = username;
    message('#reset-request-message', result.message, true);
    $('#reset-complete-form').hidden = false;
    $('#reset-code').focus();
  } catch (error) { message('#reset-request-message', error.message); }
  finally { button.disabled = false; }
});
$('#reset-complete-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $('#reset-complete-message').hidden = true;
  try {
    const result = await api('/api/password-reset/complete', { method: 'POST', body: JSON.stringify({
      username: $('#reset-username').value.trim(), code: $('#reset-code').value.trim(), new_password: $('#reset-new-password').value
    }) });
    message('#reset-complete-message', result.message, true);
    $('#password').value = '';
    $('#username').value = $('#reset-username').value.trim();
    $('#reset-code').value = '';
    $('#reset-new-password').value = '';
  } catch (error) { message('#reset-complete-message', error.message); }
  finally { button.disabled = false; }
});

async function loadDashboard() {
  const [me, data, announcementData] = await Promise.all([api('/api/me'), api('/api/dashboard'), api('/api/announcements')]);
  const admin = me.role === 'admin';
  dashboardRole = me.role;
  document.querySelectorAll('.admin-only').forEach((el) => { el.hidden = !admin; });
  updateRoleSidebar();
  $('#sidebar-user').textContent = me.username;
  $('#sidebar-role').textContent = dashboardRole.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
  $('#user-avatar').textContent = me.username.slice(0, 1).toUpperCase();
  $('#welcome-user').textContent = me.username;
  $('#stat-files').textContent = data.file_count;
  $('#files-count').textContent = `${data.files.length} file${data.files.length === 1 ? '' : 's'}`;
  $('#files-table').innerHTML = data.files.length ? data.files.map((file) => `<tr><td><strong>${escapeHtml(file.filename)}</strong></td><td>${Number(file.size_kb).toLocaleString(undefined, { maximumFractionDigits: 2 })} KB</td><td><code>${escapeHtml(file.hash)}</code></td><td><button class="text-button verify-file" data-file="${escapeHtml(file.filename)}">Verify access</button>${admin ? ` <button class="transaction-button apply-file-transaction" data-file="${escapeHtml(file.filename)}">Apply Txn</button>` : ''}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No files available.</td></tr>';
  $('#employee-announcements').innerHTML = announcementData.announcements.length ? announcementData.announcements.map((a) => `<div class="operation-row"><span><strong>${escapeHtml(a.sender)}</strong> · ${escapeHtml(a.timestamp)}<br>${escapeHtml(a.message)}</span></div>`).join('') : '<p class="muted">No announcements yet.</p>';
  fillSelect($('#access-file'), data.files, 'Select an available file', 'filename');
  try { $('#nosql-data').textContent = JSON.stringify(JSON.parse(data.nosql), null, 2); } catch { $('#nosql-data').textContent = data.nosql || 'No security documents.'; }
  const activeTab = $('#dashboard-nav .nav-item.active')?.dataset.tab || 'repository';
  displayDashboardTab(dashboardTabs[activeTab] ? activeTab : 'repository');
  if (!admin) return;
  $('#stat-users').textContent = data.user_count;
  $('#stat-audit').textContent = data.audit_count;
  dashboardUsers = data.users;
  const selectedAuditName = $('#audit-name-filter').value;
  fillSelect($('#audit-name-filter'), data.users, 'All names', 'username');
  if (data.users.some((user) => user.username === selectedAuditName)) $('#audit-name-filter').value = selectedAuditName;
  const employees = data.users.filter((user) => user.role !== 'admin');
  fillSelect($('#permission-user'), employees, 'Select an employee', 'username');
  fillSelect($('#remove-employee'), employees, 'Select an employee', 'username');
  fillSelect($('#unlock-user'), employees.filter((u) => u.permanently_locked), 'Select a permanently locked employee', 'username');
  fillSelect($('#email-account'), data.users, 'Select an account', 'username');
  $('#email-account').onchange = updateEmailField;
  updateEmailField();
  fillSelect($('#permission-file'), data.files, 'Select a file', 'filename');
  fillSelect($('#edit-protected-file'), data.files.filter((file) => !file.canary), 'Select a protected file', 'filename');
  fillSelect($('#unprotect-file'), data.files, 'Select a protected file', 'filename');
  renderAuditRows(data.audit);
  await loadOperations();
  if (activeTab === 'audit') await loadAuditPanel();
}
function updateEmailField() {
  const selected = dashboardUsers.find((user) => user.username === $('#email-account').value);
  $('#account-email').value = selected?.email || '';
}
function fillSelect(select, items, placeholder, key) {
  select.innerHTML = `<option value="">${escapeHtml(placeholder)}</option>` + items.map((item) => {
    const label = key === 'username' && item.role ? `${item[key]} — ${item.role.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())}` : item[key];
    return `<option value="${escapeHtml(item[key])}">${escapeHtml(label)}</option>`;
  }).join('');
}

async function loadOperations() {
  const data = await api('/api/operations');
  $('#sessions-table').innerHTML = data.sessions.length ? data.sessions.map((s) => `<tr><td>${escapeHtml(s.username)}</td><td>${escapeHtml(s.ip)}</td><td>${escapeHtml(s.login_time)}</td><td><button class="text-button terminate-session" data-id="${s.id}">End</button></td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No active sessions.</td></tr>';
  $('#transactions-table').innerHTML = data.transactions.length ? data.transactions.map((t) => `<tr><td>${escapeHtml(formatTimestamp(t.timestamp))}</td><td>${escapeHtml(t.username)}</td><td>${escapeHtml(t.action)}</td><td>${escapeHtml(t.target)}</td><td>${escapeHtml(t.status)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-cell">No transactions yet.</td></tr>';
  $('#firewall-list').innerHTML = data.firewall.length ? data.firewall.map((r) => `<div class="operation-row"><span>${escapeHtml(r.ip)} · ${escapeHtml(r.reason)}</span><button class="text-button unblock-address" data-ip="${escapeHtml(r.ip)}">Unblock</button></div>`).join('') : '<p class="muted">No blocked addresses.</p>';
  $('#lockdown-button').textContent = data.lockdown ? 'Disable emergency lockdown' : 'Enable emergency lockdown';
  $('#lockdown-button').dataset.enabled = data.lockdown ? '0' : '1';
  $('#geofence-list').innerHTML = data.geofence.length ? data.geofence.map((r) => `<div class="operation-row"><span>${escapeHtml(r.cidr)}</span><button class="text-button remove-geofence" data-cidr="${escapeHtml(r.cidr)}">Remove</button></div>`).join('') : '<p class="muted">No allowed network range is set. Network range checks are off.</p>';
}

async function loadAnnouncementList() {
  const data = await api('/api/announcements');
  $('#employee-announcements').innerHTML = data.announcements.length ? data.announcements.map((a) => `<div class="operation-row"><span><strong>${escapeHtml(a.sender)}</strong> · ${escapeHtml(a.timestamp)}<br>${escapeHtml(a.message)}</span></div>`).join('') : '<p class="muted">No announcements yet.</p>';
}

function renderAuditRows(rows) {
  const statusClass = (status) => /denied|failed|blocked|invalid|rejected|error|locked/i.test(status || '') ? 'audit-bad' : /success|passed|posted|allowed|sent|verified/i.test(status || '') ? 'audit-good' : 'audit-neutral';
  $('#audit-table').innerHTML = rows.length ? rows.map((item) => `<tr><td class="audit-id">${escapeHtml(item.audit_id)}</td><td>${escapeHtml(formatTimestamp(item.timestamp))}</td><td class="audit-name">${escapeHtml(item.username)}</td><td><span class="audit-pill audit-role">${escapeHtml(item.role_type || 'Account removed')}</span></td><td>${escapeHtml(item.action)}</td><td><span class="audit-pill ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.filename)}</td><td><code>${escapeHtml(item.prev_hash || '—')}</code></td><td><code>${escapeHtml(item.block_hash || '—')}</code></td></tr>`).join('') : '<tr><td colspan="9" class="empty-cell">No audit events match these filters.</td></tr>';
}

async function loadAuditPanel() {
  const params = new URLSearchParams();
  if ($('#audit-role-filter').value) params.set('role', $('#audit-role-filter').value);
  if ($('#audit-name-filter').value) params.set('name', $('#audit-name-filter').value);
  const query = params.toString();
  const data = await api(`/api/audit${query ? `?${query}` : ''}`);
  renderAuditRows(data.audit);
}

async function loadTransactionsPanel() {
  const data = await api('/api/transactions');
  $('#transactions-table').innerHTML = data.transactions.length ? data.transactions.map((item) => `<tr><td>${escapeHtml(formatTimestamp(item.timestamp))}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.target)}</td><td>${escapeHtml(item.status)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-cell">No transactions yet.</td></tr>';
}

async function loadSessionsPanel() {
  const data = await api('/api/sessions');
  const admin = dashboardRole === 'admin';
  const actionHeading = document.querySelector('#sessions-card thead th:last-child');
  if (actionHeading) actionHeading.hidden = !admin;
  $('#sessions-table').innerHTML = data.sessions.length ? data.sessions.map((item) => `<tr><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.ip)}</td><td>${escapeHtml(item.login_time)}</td>${admin ? `<td><button class="text-button terminate-session" data-id="${item.id}">End</button></td>` : ''}</tr>`).join('') : `<tr><td colspan="${admin ? 4 : 3}" class="empty-cell">No active sessions.</td></tr>`;
}

async function loadScannerPanel() {
  const data = await api('/api/security/scan');
  $('#health-results').textContent = JSON.stringify(data.checks, null, 2);
}

async function loadSocPanel() {
  const data = await api('/api/soc/metrics');
  $('#soc-threat').textContent = data.threat_level;
  $('#soc-threat').dataset.level = data.threat_level.toLowerCase();
  $('#soc-failed').textContent = data.failed_logins_24h;
  $('#soc-blocked').textContent = data.blocked_addresses;
  $('#soc-sessions').textContent = data.active_sessions;
  $('#soc-locked').textContent = data.locked_accounts;
  $('#soc-canary').textContent = data.canary_alerts_7d;
  const peak = Math.max(1, ...data.events_by_day.map((day) => day.count));
  $('#soc-chart').innerHTML = data.events_by_day.map((day) => `<div class="zip-bar-column"><div class="zip-bar-value">${day.count}</div><div class="zip-bar" style="height:${Math.max(3, Math.round(day.count / peak * 100))}%"></div><span>${escapeHtml(day.date.slice(5))}</span></div>`).join('');
}

async function loadIntegrityPanel() {
  const data = await api('/api/security/scan');
  const summary = data.summary;
  $('#integrity-summary').textContent = `${summary.passed} checks passed, ${summary.warnings} need attention, ${summary.failed} failed.`;
  $('#integrity-table').innerHTML = data.files.length ? data.files.map((file) => `<tr><td>${escapeHtml(file.filename)}</td><td>${file.encrypted ? (file.encrypted_valid ? 'Verified' : 'Failed') : 'Missing'}</td><td>${file.disk_matches ? 'Matches saved copy' : 'Does not match'}</td><td><span class="zip-check ${escapeHtml(file.status)}">${escapeHtml(file.status)}</span></td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No protected files are registered.</td></tr>';
}

async function loadRecoveryPanel() {
  const data = await api('/api/db/recovery-check', { method: 'POST', body: '{}' });
  $('#recovery-status').innerHTML = `<article><span>Database check</span><strong>${escapeHtml(data.integrity)}</strong></article><article><span>Automatic backup</span><strong>${data.backup.exists ? 'Available' : 'Not created'}</strong></article><article><span>Backup check</span><strong>${escapeHtml(data.backup.integrity || 'Not available')}</strong></article><article><span>Backup updated</span><strong>${escapeHtml(data.backup.updated || '—')}</strong></article><article><span>Backup size</span><strong>${Number(data.backup.size_bytes).toLocaleString()} bytes</strong></article>`;
}

async function loadVaultPanel() {
  const data = await api('/api/security/vault');
  $('#vault-list').innerHTML = data.files.length ? data.files.map((file) => `<div class="zip-vault-row"><strong>${escapeHtml(file.filename)}</strong><span>${file.encrypted_copy ? (file.encrypted_valid ? 'Encrypted copy verified' : 'Encrypted copy check failed') : 'No encrypted copy'}</span><span>${file.disk_matches ? 'Disk matches' : 'Disk differs or baseline missing'}</span></div>`).join('') : '<p>No protected files are registered.</p>';
}

async function loadOsPanel() {
  try {
    const data = await api('/api/os/metrics');
    if (data.message) { $('#os-chart-status').textContent = data.message; return; }
    const sample = { cpu: Number(data.cpu_percent), memory: Number(data.memory_percent), memoryUsed: Number(data.memory_used_mb), memoryTotal: Number(data.memory_total_mb) };
    osMetricHistory.push(sample);
    if (osMetricHistory.length > 24) osMetricHistory.shift();
    $('#os-cpu-value').textContent = `${sample.cpu.toFixed(1)}%`;
    $('#os-memory-value').textContent = `${sample.memoryUsed.toLocaleString()} MB / ${sample.memoryTotal.toLocaleString()} MB`;
    const cpuPointCoordinates = (value, index) => {
      const x = 60 + (osMetricHistory.length === 1 ? 0 : index * 520 / (osMetricHistory.length - 1));
      const y = 210 - Math.min(100, Math.max(0, value)) * 1.8;
      return { x, y };
    };
    const memoryPointCoordinates = (value, index) => {
      const x = 78 + (osMetricHistory.length === 1 ? 0 : index * 500 / (osMetricHistory.length - 1));
      const y = 210 - Math.min(100, Math.max(0, value)) * 1.8;
      return { x, y };
    };
    const linePoints = (key, coordinates) => osMetricHistory.map((item, index) => {
      const point = coordinates(item[key], index);
      return `${point.x.toFixed(1)},${point.y.toFixed(1)}`;
    }).join(' ');
    $('#cpu-line').setAttribute('points', linePoints('cpu', cpuPointCoordinates));
    $('#memory-line').setAttribute('points', linePoints('memory', memoryPointCoordinates));
    const cpuPoint = cpuPointCoordinates(sample.cpu, osMetricHistory.length - 1);
    $('#cpu-point').setAttribute('cx', cpuPoint.x.toFixed(1));
    $('#cpu-point').setAttribute('cy', cpuPoint.y.toFixed(1));
    const memoryPoint = memoryPointCoordinates(sample.memory, osMetricHistory.length - 1);
    $('#memory-point').setAttribute('cx', memoryPoint.x.toFixed(1));
    $('#memory-point').setAttribute('cy', memoryPoint.y.toFixed(1));
    const labels = $('#os-memory-labels');
    labels.replaceChildren();
    for (const pct of [100, 75, 50, 25, 0]) {
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', '4');
      label.setAttribute('y', String(34 + (100 - pct) * 1.8));
      label.textContent = `${Math.round(sample.memoryTotal * pct / 100).toLocaleString()} MB`;
      labels.append(label);
    }
    $('#os-chart-status').textContent = `${data.process_count} processes · graph refreshes every 5 seconds`;
  } catch (error) { $('#os-chart-status').textContent = error.message; }
}

$('#soc-refresh').addEventListener('click', () => loadSocPanel().catch((error) => { $('#soc-threat').textContent = error.message; }));
$('#integrity-scan').addEventListener('click', () => loadIntegrityPanel().catch((error) => { $('#integrity-summary').textContent = error.message; }));
$('#vault-refresh').addEventListener('click', () => loadVaultPanel().catch((error) => { $('#vault-list').textContent = error.message; }));
$('#announcement-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { const r = await api('/api/announcements', { method: 'POST', body: JSON.stringify({ message: $('#announcement-message').value }) }); $('#announcement-message').value = ''; message('#announcement-status', r.message, true); await loadAnnouncementList(); }
  catch (error) { message('#announcement-status', error.message); }
});
$('#firewall-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { const r = await api('/api/firewall', { method: 'POST', body: JSON.stringify({ ip: $('#firewall-ip').value, reason: $('#firewall-reason').value }) }); message('#firewall-status', r.message, true); event.currentTarget.reset(); await loadOperations(); }
  catch (error) { message('#firewall-status', error.message); }
});
$('#geofence-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { const r = await api('/api/security/geofence', { method: 'POST', body: JSON.stringify({ cidr: $('#geofence-cidr').value.trim() }) }); message('#security-action-status', r.message, true); event.currentTarget.reset(); await loadOperations(); }
  catch (error) { message('#security-action-status', error.message); }
});
$('#operations').addEventListener('click', async (event) => {
  const terminate = event.target.closest('.terminate-session');
  const unblock = event.target.closest('.unblock-address');
  const removeGeofence = event.target.closest('.remove-geofence');
  try {
    if (terminate) await api(`/api/sessions/${terminate.dataset.id}/terminate`, { method: 'POST', body: '{}' });
    if (unblock) await api(`/api/firewall/${encodeURIComponent(unblock.dataset.ip)}`, { method: 'DELETE' });
    if (removeGeofence) await api(`/api/security/geofence/${encodeURIComponent(removeGeofence.dataset.cidr)}`, { method: 'DELETE' });
    if (terminate || unblock || removeGeofence) await loadOperations();
  } catch (error) { message('#security-action-status', error.message); }
});
$('#lockdown-button').addEventListener('click', async () => {
  try { const r = await api('/api/security/lockdown', { method: 'POST', body: JSON.stringify({ enabled: $('#lockdown-button').dataset.enabled === '1' }) }); message('#security-action-status', r.message, true); await loadOperations(); }
  catch (error) { message('#security-action-status', error.message); }
});
$('#fim-button').addEventListener('click', async () => {
  try { const r = await api('/api/security/fim-simulate', { method: 'POST', body: '{}' }); message('#fim-action-status', r.message, true); }
  catch (error) { message('#fim-action-status', error.message); }
});
$('#canary-button').addEventListener('click', async () => {
  try { const r = await api('/api/security/canary', { method: 'POST', body: '{}' }); message('#fim-action-status', r.message, true); await loadDashboard(); }
  catch (error) { message('#fim-action-status', error.message); }
});
$('#security-scan-button').addEventListener('click', async () => {
  try { $('#health-results').textContent = JSON.stringify((await api('/api/security/scan')).checks, null, 2); }
  catch (error) { $('#health-results').textContent = error.message; }
});
$('#audit-verify-button').addEventListener('click', async () => {
  try { const r = await api('/api/security/audit/verify', { method: 'POST', body: '{}' }); message('#audit-verify-status', r.message, true); await loadDashboard(); }
  catch (error) { message('#audit-verify-status', error.message); }
});
$('#audit-filter-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { await loadAuditPanel(); }
  catch (error) { $('#audit-table').innerHTML = `<tr><td colspan="9" class="empty-cell">${escapeHtml(error.message)}</td></tr>`; }
});
$('#audit-filter-clear').addEventListener('click', async () => {
  $('#audit-filter-form').reset();
  try { await loadAuditPanel(); }
  catch (error) { $('#audit-table').innerHTML = `<tr><td colspan="9" class="empty-cell">${escapeHtml(error.message)}</td></tr>`; }
});
$('#recovery-check-button').addEventListener('click', async () => {
  try { await loadRecoveryPanel(); }
  catch (error) { $('#recovery-status').textContent = error.message; }
});
document.querySelectorAll('.os-demo-button').forEach((button) => button.addEventListener('click', async () => {
  const kind = button.dataset.demo;
  const output = $(`#${kind}-result`);
  button.disabled = true;
  output.textContent = 'Running…';
  try {
    const result = await api(`/api/os/demo/${kind}`, { method: 'POST', body: JSON.stringify({}) });
    if (kind === 'bankers') {
      output.textContent = result.safe
        ? `System is in a SAFE state.\nSafe process order: ${result.safe_sequence.map((index) => `P${index}`).join(' → ')}`
        : 'System is NOT in a safe state. No safe process order was found.';
    } else if (kind === 'page-replacement') {
      output.textContent = `${result.algorithm} simulation complete.\nPage faults: ${result.page_faults}\nFrames used: ${result.frames}`;
    } else {
      output.textContent = `${result.algorithm} complete.\nTotal head movement: ${result.head_movement} cylinders\nService order: ${result.service_order.join(' → ')}`;
    }
  } catch (error) { output.textContent = error.message; }
  finally { button.disabled = false; }
}));

$('#logout-button').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST', body: '{}' }); } catch { /* The view still returns to sign-in. */ }
  $('#username').value = '';
  $('#password').value = '';
  $('#reset-username').value = '';
  $('#reset-email').value = '';
  $('#reset-code').value = '';
  $('#reset-new-password').value = '';
  $('#reset-request-form').reset();
  $('#reset-complete-form').reset();
  $('#reset-request-form').hidden = true;
  $('#reset-complete-form').hidden = true;
  $('#reset-request-message').textContent = '';
  $('#reset-request-message').hidden = true;
  $('#reset-complete-message').textContent = '';
  $('#reset-complete-message').hidden = true;
  $('#login-message').textContent = '';
  $('#login-message').hidden = true;
  $('#access-password').value = '';
  if (osMetricsTimer) { clearInterval(osMetricsTimer); osMetricsTimer = null; }
  dashboardRole = 'employee';
  $('#dashboard-view').hidden = true;
  $('#login-view').hidden = false;
});
$('#files-table').addEventListener('click', (event) => {
  const button = event.target.closest('.verify-file');
  if (button) { $('#access-file').value = button.dataset.file; $('#access-check').scrollIntoView({ behavior: 'smooth' }); }
});
$('#files-table').addEventListener('click', async (event) => {
  const button = event.target.closest('.apply-file-transaction');
  if (!button) return;
  button.disabled = true;
  try {
    const result = await api('/api/transactions/apply', { method: 'POST', body: JSON.stringify({ filename: button.dataset.file }) });
    message('#access-message', result.message, true);
    await loadDashboard();
  } catch (error) { message('#access-message', error.message); }
  finally { button.disabled = false; }
});
$('#access-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const readTab = window.open('about:blank', '_blank');
  if (readTab) {
    readTab.opener = null;
    readTab.document.title = 'Checking file access';
    readTab.document.body.textContent = 'Checking file access…';
  }
  try {
    const result = await api('/api/access', { method: 'POST', body: JSON.stringify({ filename: $('#access-file').value, password: $('#access-password').value }) });
    message('#access-message', result.message, true);
    if (readTab) readTab.location.replace(result.read_url);
    else message('#access-message', 'Your browser blocked the new tab. Allow pop-ups for this site, then verify access again.');
  } catch (error) {
    if (readTab) readTab.close();
    message('#access-message', error.message);
  }
  finally { $('#access-password').value = ''; }
});
$('#permission-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/permissions', { method: 'POST', body: JSON.stringify({ username: $('#permission-user').value, filename: $('#permission-file').value, can_read: $('#permission-value').value }) });
    message('#permission-message', result.message, true); await loadDashboard();
  } catch (error) { message('#permission-message', error.message); }
});
$('#unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/unlock', { method: 'POST', body: JSON.stringify({ username: $('#unlock-user').value }) });
    message('#unlock-message', result.message, true); await loadDashboard();
  } catch (error) { message('#unlock-message', error.message); }
});
$('#employee-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const result = await api('/api/users', { method: 'POST', body: JSON.stringify({
      username: $('#employee-username').value.trim(),
      email: $('#employee-email').value.trim(),
      password: $('#employee-password').value,
      role: $('#employee-role').value
    }) });
    message('#employee-message', result.message || 'Employee account created.', true);
    form.reset();
    await loadDashboard();
  } catch (error) { message('#employee-message', error.message); }
  finally { button.disabled = false; }
});
$('#remove-employee-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = $('#remove-employee').value;
  if (!username || !window.confirm(`Remove employee account '${username}' and revoke its file permissions?`)) return;
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const result = await api('/api/users/remove', { method: 'POST', body: JSON.stringify({ username }) });
    message('#remove-employee-message', result.message, true);
    await loadDashboard();
  } catch (error) { message('#remove-employee-message', error.message); }
  finally { button.disabled = false; }
});
$('#account-email-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/users/email', { method: 'POST', body: JSON.stringify({
      username: $('#email-account').value, email: $('#account-email').value.trim()
    }) });
    message('#account-email-message', result.message, true);
    await loadDashboard();
  } catch (error) { message('#account-email-message', error.message); }
});
$('#file-upload-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const selectedFile = $('#protected-file').files[0];
  const supportedExtensions = new Set(['doc', 'docx', 'ppt', 'pptx', 'csv', 'xls', 'xlsx', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tif', 'tiff']);
  const extension = selectedFile?.name.split('.').pop()?.toLowerCase();
  if (!selectedFile || !supportedExtensions.has(extension)) {
    message('#file-upload-message', 'Unsupported file type. Choose a Word, PowerPoint, CSV, Excel, PDF, or image file.');
    return;
  }
  const upload = new FormData();
  upload.append('file', selectedFile);
  button.disabled = true;
  try {
    const result = await api('/api/files', { method: 'POST', body: upload });
    form.reset();
    await loadDashboard();
    message('#file-upload-message', result.message, true);
  } catch (error) { message('#file-upload-message', error.message); }
  finally { button.disabled = false; }
});
$('#file-revision-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const selectedFile = $('#edited-protected-copy').files[0];
  if (!selectedFile) {
    message('#file-revision-message', 'Choose the edited file version to upload.');
    return;
  }
  const revision = new FormData();
  revision.append('filename', $('#edit-protected-file').value);
  revision.append('file', selectedFile);
  button.disabled = true;
  try {
    const result = await api('/api/files/replace', { method: 'POST', body: revision });
    form.reset();
    await loadDashboard();
    message('#file-revision-message', result.message, true);
  } catch (error) { message('#file-revision-message', error.message); }
  finally { button.disabled = false; }
});
$('#unprotect-file-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const filename = $('#unprotect-file').value;
  if (!filename || !window.confirm(`Remove '${filename}' from protected storage and revoke all employee access? The file will remain on disk.`)) return;
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const result = await api('/api/files/unprotect', { method: 'POST', body: JSON.stringify({ filename }) });
    message('#unprotect-file-message', result.message, true);
    await loadDashboard();
  } catch (error) { message('#unprotect-file-message', error.message); }
  finally { button.disabled = false; }
});
api('/api/me').then((me) => { dashboardRole = me.role; showDashboard(); }).catch(() => {});
window.setInterval(() => {
  if (!$('#dashboard-view').hidden && !document.hidden) {
    loadDashboard().catch(() => {});
  }
}, 30000);
window.setInterval(() => {
  if (!$('#dashboard-view').hidden && !document.hidden) {
    loadAnnouncementList().catch(() => {});
  }
}, 8000);
