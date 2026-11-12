'use strict';
let csrf = '';
let isBusy = false;
const $ = id => document.getElementById(id);
const safeText = (tag, text, className = '') => {
  const el = document.createElement(tag);
  el.textContent = String(text);
  if (className) el.className = className;
  return el;
};
async function api(path, method = 'GET', payload) {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(method !== 'GET' ? {'X-Lab-CSRF': csrf} : {}) },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function toast(message) {
  $('toast').textContent = message;
  $('toast').hidden = false;
  setTimeout(() => $('toast').hidden = true, 5000);
}
function showApp(authorized) {
  $('auth').hidden = authorized;
  $('app').hidden = !authorized;
}
function renderHistory(runs) {
  const list = $('history-list');
  list.replaceChildren();
  if (!runs.length) {
    list.append(safeText('p', 'No simulations yet. Select a scenario above to generate Kali-side evidence.', 'empty'));
    return;
  }
  for (const run of runs) {
    const item = document.createElement('article'); item.className = 'run-entry';
    const left = document.createElement('div');
    left.append(safeText('strong', run.label));
    const details = (run.results || []).map(x => `${x.action}: ${x.ok ? 'request completed' : 'failed'}`).join(' · ');
    left.append(safeText('p', `${new Date(run.started).toLocaleString()} · ${details || run.error || 'In progress…'}`));
    item.append(left, safeText('span', run.state, `run-state ${run.state}`));
    list.append(item);
  }
}
async function refresh() {
  if (isBusy) return;
  isBusy = true;
  try {
    const data = await api('/api/status');
    $('kali-status').textContent = data.target_online ? 'Online' : 'Unreachable';
    $('kali-status').className = data.target_online ? 'positive' : 'negative';
    $('kali-address').textContent = data.target;
    $('engine-status').textContent = data.running ? 'Running…' : 'Idle';
    $('engine-status').className = data.running ? 'positive' : '';
    $('stop').disabled = !data.running;
    $('run-count').textContent = data.runs.filter(x => x.state === 'COMPLETE' || x.state === 'PARTIAL').length;
    document.querySelectorAll('[data-scenario]').forEach(b => { b.disabled = data.running || !data.target_online; });
    renderHistory(data.runs);
  } catch (error) {
    if (/Sign in/.test(error.message)) { showApp(false); return; }
    toast(error.message);
  } finally { isBusy = false; }
}
async function initial() {
  try {
    const session = await api('/api/session');
    if (session.authenticated) {
      csrf = session.csrf;
      showApp(true);
      await refresh();
    } else showApp(false);
  } catch { showApp(false); }
}
$('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('login-error').textContent = '';
  try {
    const result = await api('/api/login', 'POST', {password: $('password').value});
    csrf = result.csrf;
    $('password').value = '';
    showApp(true);
    await refresh();
  } catch (error) { $('login-error').textContent = error.message; }
});
document.querySelectorAll('[data-scenario]').forEach(button => {
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await api('/api/run', 'POST', {scenario: button.dataset.scenario});
      toast('Test traffic started. The Kali VM will record received requests.');
      await refresh();
    } catch (error) { toast(error.message); }
  });
});
$('stop').addEventListener('click', async () => {
  try { await api('/api/stop', 'POST', {}); toast('Stopping after the current request finishes (up to four seconds).'); await refresh(); }
  catch (error) { toast(error.message); }
});
$('refresh').addEventListener('click', refresh);
$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', 'POST'); } finally { csrf = ''; showApp(false); }
});
setInterval(() => { if (!$('app').hidden && !document.hidden) refresh(); }, 2500);
initial();
