'use strict';
// Argus dashboard screen. Read-only in phase 1. All text from the server is
// written with textContent, never as HTML.

const $ = (id) => document.getElementById(id);
const REFRESH_MS = 30000;
let timer = null;

// ---------- theme ----------
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
function savedTheme() {
  try { return localStorage.getItem('argus-theme') || 'system'; } catch { return 'system'; }
}
function applyTheme() {
  const t = savedTheme();
  const dark = t === 'dark' || (t === 'system' && darkQuery.matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  $('theme').value = t;
}
$('theme').addEventListener('change', (e) => {
  try { localStorage.setItem('argus-theme', e.target.value); } catch { /* still applies for this run */ }
  applyTheme();
});
darkQuery.addEventListener('change', applyTheme);
applyTheme();

// ---------- sign-in ----------
function show(id) {
  $('signin').hidden = id !== 'signin';
  $('dash').hidden = id !== 'dash';
}
function signinStep(step, message = '') {
  show('signin');
  $('pass-form').hidden = step !== 'pass';
  $('code-form').hidden = step !== 'code';
  $('signin-msg').textContent = message;
  $('pass').value = '';
  $('code').value = '';
  (step === 'pass' ? $('pass') : $('code')).focus();
}
function busy(form, on) {
  for (const el of form.querySelectorAll('input, button')) el.disabled = on;
}

$('pass-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const pass = $('pass').value;
  $('pass').value = '';
  $('signin-msg').textContent = 'Checking the server and your key…';
  busy(form, true);
  try {
    await window.argus.signInStart(pass);
    signinStep('code');
  } catch (err) {
    signinStep('pass', clean(err));
  } finally {
    busy(form, false);
  }
});

$('code-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const code = $('code').value.trim();
  $('code').value = '';
  busy(form, true);
  try {
    await window.argus.signInFinish(code);
    await enterDashboard();
  } catch (err) {
    signinStep('pass', clean(err) + ' Start again with your passphrase.');
  } finally {
    busy(form, false);
  }
});

$('disconnect').addEventListener('click', async () => {
  stop();
  closeTerminal();
  lastStatus = null;
  showView('dashboard');
  await window.argus.disconnect();
  signinStep('pass', '');
});
$('refresh').addEventListener('click', () => refresh());

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

function clean(err) {
  // Electron prefixes IPC errors with "Error invoking remote method '...': Error: ".
  return String(err && err.message ? err.message : err).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
}

// ---------- dashboard ----------
let refreshMsgShown = false;
async function refresh() {
  $('refresh').disabled = true;
  try {
    const s = await window.argus.status();
    lastStatus = s && typeof s === 'object' ? s : {};
    render(lastStatus);
    if (refreshMsgShown) { $('dash-msg').textContent = ''; refreshMsgShown = false; }
    $('conn').className = 'pill ok';
    $('conn').textContent = 'Connected';
  } catch (err) {
    const m = clean(err);
    if (m.startsWith('HELPER:')) {
      // Still connected; only this report failed. Keep refreshing.
      $('dash-msg').textContent = 'The server could not produce its status report: ' + m.slice(7).trim() + ' Trying again in 30 seconds.';
      refreshMsgShown = true;
    } else {
      stop();
      $('conn').className = 'pill bad';
      $('conn').textContent = 'Not connected';
      $('dash-msg').textContent = 'Lost the connection: ' + m.replace(/^NOT_CONNECTED:\s*/, '') + '. Disconnect and sign in again (a fresh code is needed).';
      refreshMsgShown = true;
    }
  } finally {
    $('refresh').disabled = false;
  }
}

const UNKNOWN = 'unknown';
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : null);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const str = (v) => (typeof v === 'string' && v ? v : null);
const gb = (b) => (num(b) == null ? null : (b / 1e9).toFixed(1));
const list = (a) => (a == null ? null : a.length ? a.map(String).join(', ') : 'none');
function ago(hours) {
  if (num(hours) == null) return null;
  if (hours < 1) return Math.round(hours * 60) + ' min ago';
  if (hours < 48) return Math.round(hours) + ' h ago';
  return Math.round(hours / 24) + ' days ago';
}
function uptime(s) {
  if (num(s) == null) return null;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return `${d} days ${h} h`;
}
const UNK_PILL = ['unknown', 'Unknown'];
// "Sun 2026-11-01 02:30:44 EST" -> "today 02:30", "31 Oct 02:30"
function shortTime(t) {
  const m = t && t.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/);
  if (!m) return UNKNOWN;
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const day = `${m[1]}-${m[2]}-${m[3]}`;
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return (day === today ? 'today' : `${Number(m[3])} ${months[Number(m[2]) - 1]}`) + ` ${m[4]}:${m[5]}`;
}

function tile(title, pill, rows) {
  const t = document.createElement('div');
  t.className = 'tile';
  const h = document.createElement('h2');
  h.append(title);
  const p = document.createElement('span');
  p.className = 'pill ' + pill[0];
  p.textContent = pill[1];
  h.append(p);
  t.append(h);
  for (const [k, v] of rows) {
    const r = document.createElement('div');
    r.className = 'row';
    const a = document.createElement('span'); a.textContent = k;
    const b = document.createElement('span'); b.className = 'mono'; b.textContent = v == null ? UNKNOWN : String(v);
    r.append(a, b);
    t.append(r);
  }
  return t;
}
const unknownTile = (title) => tile(title, UNK_PILL, [['Status', 'could not be read']]);

const TILES = [
  ['Server', (s, issues) => {
    const sv = obj(s.server); if (!sv) return null;
    const cpus = num(sv.cpus), load = num(sv.load_1m);
    const mu = num(sv.mem_used_b), mt = num(sv.mem_total_b), du = num(sv.disk_used_b), dt = num(sv.disk_total_b);
    const memPct = mu != null && mt ? mu / mt : null, diskPct = du != null && dt ? du / dt : null;
    const reboot = typeof sv.reboot_needed === 'boolean' ? sv.reboot_needed : null;
    if (diskPct != null && diskPct > 0.85) issues.push([`Disk is ${Math.round(diskPct * 100)}% full. Old backups and files are the usual cause.`, 'files', 'Open Files']);
    if (reboot) issues.push(['The server needs a restart to finish an update.', 'server', 'Go to Restart', 'reboot']);
    const known = memPct != null && diskPct != null && load != null && cpus != null;
    const busy = known && (memPct > 0.9 || diskPct > 0.85 || load > cpus * 1.5);
    return tile('Server', !known ? UNK_PILL : busy ? ['warn', 'Busy'] : ['ok', 'Healthy'], [
      ['Up for', uptime(sv.uptime_s)],
      [`Load (${cpus ?? '?'} CPUs)`, load == null ? null : load.toFixed(2)],
      ['Memory', mu == null || mt == null ? null : `${gb(mu)} of ${gb(mt)} GB`],
      ['Disk', diskPct == null ? null : `${gb(du)} of ${gb(dt)} GB · ${Math.round(diskPct * 100)}%`],
      ['Reboot needed', reboot == null ? null : reboot ? 'Yes' : 'No'],
    ]);
  }],
  ['Services', (s, issues) => {
    const se = obj(s.services); if (!se) return null;
    const stopped = arr(se.stopped), unhealthy = arr(se.unhealthy), finished = arr(se.finished_one_shot);
    for (const n of stopped || []) issues.push([`Service stopped: ${n}.`, 'server', 'Go to Services', 'svc-rows']);
    for (const n of unhealthy || []) issues.push([`Service unhealthy: ${n}.`, 'server', 'Go to Services', 'svc-rows']);
    const bad = (stopped || []).length + (unhealthy || []).length;
    const pill = bad ? ['bad', `${bad} need attention`] : stopped && unhealthy ? ['ok', 'All running'] : UNK_PILL;
    return tile('Services', pill, [
      ['Running', num(se.running)],
      ['Unhealthy', list(unhealthy)],
      ['Stopped', list(stopped)],
      ['Finished one-off jobs', list(finished)],
    ]);
  }],
  ['Websites', (s, issues) => {
    const ws = arr(s.websites); if (!ws) return null;
    const sites = ws.map(obj).filter(Boolean);
    const unread = sites.filter((w) => num(w.cert_days) == null);
    const soon = sites.filter((w) => num(w.cert_days) != null && w.cert_days < 21);
    for (const w of soon) issues.push([`Certificate for ${str(w.name) || 'a site'} expires in ${w.cert_days} days.`, 'web', 'Go to Websites', 'ws-rows']);
    const known = sites.map((w) => num(w.cert_days)).filter((d) => d != null);
    const pill = soon.length ? ['warn', `${soon.length} expiring`] : unread.length ? ['unknown', `${unread.length} unreadable`] : ['ok', `${sites.length} with certificates`];
    return tile('Websites', pill, [
      ['Names served', sites.length],
      ['Certificates', known.length ? `${Math.min(...known)}–${Math.max(...known)} days left` : null],
      ['Could not check', unread.length ? unread.map((w) => str(w.name) || '?').join(', ') : 'none'],
    ]);
  }],
  ['Mail', (s, issues) => {
    const m = obj(s.mail); if (!m) return null;
    if (m.web_ok === false) issues.push(["mailcow's web side (webmail, admin, Argus's mail page) is not answering. Mail delivery may still be fine.", 'server', 'Go to Services', 'svc-rows']);
    const q = num(m.queue);
    if (q && q > 20) issues.push([`${q} messages are waiting in the mail queue.`, 'mail', 'Go to Mail Queue', 'mq-rows']);
    return tile('Mail', m.web_ok === true ? ['ok', 'Answering'] : m.web_ok === false ? ['bad', 'Web side down'] : UNK_PILL, [
      ['Webmail and admin', m.web_ok === true ? 'answering' : m.web_ok === false ? (str(m.problem) || 'not answering') : null],
      ['Queue', q == null ? null : q === 0 ? 'empty' : `${q} waiting`],
    ]);
  }],
  ['Hephaestus', (s, issues) => {
    const he = obj(s.hephaestus); if (!he) return null;
    const health = str(he.app_health);
    if (health && health !== 'healthy') issues.push([`Hephaestus reports ${health}.`, 'hephaestus', 'Go to Hephaestus']);
    return tile('Hephaestus', health == null ? UNK_PILL : health === 'healthy' ? ['ok', 'Live'] : ['bad', health], [
      ['Version', str(he.version)],
      ['App health', health],
    ]);
  }],
  ['Backups', (s, issues) => {
    const bk = obj(s.backups); if (!bk) return null;
    const rows = [], late = [];
    for (const [name, label] of [['mail', 'Mail'], ['hephaestus', 'Hephaestus Database']]) {
      const b = obj(bk[name]);
      const age = b ? num(b.newest_age_h) : null, count = b ? num(b.count) : null;
      rows.push([label, age == null ? null : `${ago(age)} · ${count ?? '?'} kept`]);
      if (age == null || age > 26) late.push(label);
    }
    for (const l of late) issues.push([`${l} backup is missing, unreadable, or more than a day old.`, 'backups', 'Go to Backups']);
    return tile('Backups', late.length ? ['warn', `${late.length} late or unknown`] : ['ok', 'Up to date'], rows);
  }],
  ['Scheduled jobs', (s, issues) => {
    const jb = arr(s.jobs); if (!jb) return null;
    const jobs = jb.map((j) => obj(j) || {});
    const failed = jobs.filter((j) => str(j.result) && j.result !== 'success');
    const unread = jobs.filter((j) => !str(j.result));
    for (const j of failed) issues.push([`Scheduled job ${str(j.name) || '?'}: ${j.result}. In the Terminal, "systemctl status ${str(j.name) || '?'}" shows why.`, 'terminal', 'Open Terminal']);
    const pill = failed.length ? ['bad', `${failed.length} not ok`] : unread.length ? ['unknown', `${unread.length} unknown`] : ['ok', 'All ok'];
    return tile('Scheduled Jobs', pill,
      jobs.map((j) => [str(j.name) || '?', j.result === 'success' ? `ok · ${shortTime(str(j.last_run))}` : str(j.result)]));
  }],
  ['Updates', (s, issues) => {
    const up = obj(s.updates); if (!up) return null;
    const sec = num(up.security), waiting = num(up.waiting);
    if (sec) issues.push([`${sec} security ${sec === 1 ? 'update is' : 'updates are'} waiting.`, 'server', 'Go to Updates', 'upd-apply']);
    return tile('Updates', sec == null ? UNK_PILL : sec ? ['warn', `${sec} security`] : ['ok', 'No security updates'], [
      ['Waiting', waiting],
      ['Security', sec],
    ]);
  }],
  ['Sign-ins', (s) => {
    const si = obj(s.signins); if (!si) return null;
    const acc = num(si.accepted_24h), ref = num(si.refused_24h);
    return tile('Sign-Ins', ref == null ? UNK_PILL : ref > 0 ? ['warn', 'Bots knocking'] : ['ok', 'Quiet'], [
      ['Accepted, 24 h', acc],
      ['Refused, 24 h', ref],
    ]);
  }],
];

function render(s) {
  const issues = [];
  const tiles = TILES.map(([title, build]) => {
    try {
      return build(s, issues) || unknownTile(title);
    } catch {
      return unknownTile(title);
    }
  });
  $('tiles').replaceChildren(...tiles);

  $('attention').hidden = issues.length === 0 || currentView !== 'dashboard';
  $('attention-title').textContent = issues.length === 1 ? 'One thing needs a look' : `${issues.length} things need a look`;
  $('attention-list').replaceChildren(...issues.map(([text, view, label, focusId]) => {
    const li = el('li', null, 'att-item');
    li.append(el('span', text));
    if (view) li.append(button(label, '', () => goTo(view, focusId)));
    return li;
  }));

  const when = new Date(str(s.generated) || NaN);
  $('refreshed').textContent = `Refreshed every 30 seconds · last at ${isNaN(when) ? UNKNOWN : when.toLocaleTimeString()}`;
}

// ---------- views (phase 2) ----------
let lastStatus = null;
let currentView = 'dashboard';
const VIEWS = ['dashboard', 'server', 'backups', 'hephaestus', 'activity', 'terminal', 'files', 'mail', 'web', 'accounts'];

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function row(cells) {
  const tr = document.createElement('tr');
  for (const c of cells) {
    const td = document.createElement('td');
    if (c instanceof Node) td.append(c); else td.textContent = c == null ? UNKNOWN : String(c);
    tr.append(td);
  }
  return tr;
}
function button(text, cls, onClick) {
  const b = el('button', text, 'btn small ' + (cls || ''));
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}
function say(message) {
  $('dash-msg').textContent = message;
}
function errText(err) {
  return clean(err).replace(/^(HELPER|NOT_CONNECTED):\s*/, '');
}
async function call(action, args = []) {
  try {
    return await window.argus.helper(action, args);
  } catch (err) {
    const m = clean(err);
    if (m.startsWith('NOT_CONNECTED:')) {
      stop();
      $('conn').className = 'pill bad';
      $('conn').textContent = 'Not connected';
    }
    throw err;
  }
}

// Confirmation dialog. `word`, when given, must be typed to enable the button.
function confirmAction({ title, text, ok, word, extra, wide }) {
  return new Promise((resolve) => {
    const d = $('confirm');
    $('confirm-title').textContent = title;
    $('confirm-text').textContent = text;
    $('confirm-extra').replaceChildren(...(extra ? [extra] : []));
    d.classList.toggle('wide', !!wide);
    $('confirm-ok').textContent = ok;
    $('confirm-ok').hidden = false;
    $('confirm-type-label').hidden = !word;
    $('confirm-word').textContent = word || '';
    $('confirm-type').value = '';
    $('confirm-ok').disabled = !!word;
    $('confirm-type').oninput = () => { $('confirm-ok').disabled = $('confirm-type').value.trim() !== word; };
    // A close event left over from the dialog's previous use arrives after it
    // has reopened; only a real close (dialog no longer open) counts.
    d.onclose = () => { if (!d.open) resolve(d.returnValue === 'ok'); };
    d.returnValue = 'cancel';
    d.showModal();
    (word ? $('confirm-type') : d.querySelector('button[value="cancel"]')).focus();
  });
}

function showView(v) {
  currentView = v;
  $('page-title').textContent = { dashboard: 'Everything at a Glance', server: 'Server', backups: 'Backups', hephaestus: 'Hephaestus', activity: 'Activity Log', terminal: 'Terminal', files: 'Files', mail: 'Mail', web: 'Websites', accounts: 'Accounts' }[v];
  $('refreshed').hidden = v !== 'dashboard';
  for (const name of VIEWS) $('view-' + name).hidden = name !== v;
  for (const b of document.querySelectorAll('button.nav')) {
    const on = b.dataset.view === v;
    b.classList.toggle('current', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  }
  $('attention').hidden = v !== 'dashboard' || $('attention-list').children.length === 0;
  say('');
  return loadView(v);
}
for (const b of document.querySelectorAll('button.nav')) b.addEventListener('click', () => showView(b.dataset.view));

// From a dashboard warning: open the page that deals with it and bring the
// right part into view once the page has loaded.
async function goTo(view, focusId) {
  const loaded = showView(view);
  if (!focusId) return;
  // A minimised section is opened through its own Show button, so its label
  // and the remembered choice stay right.
  $(focusId)?.closest('.collapsed')?.querySelector('[data-toggle]')?.click();
  await loaded;      // scroll after the page's data is in, so nothing pushes it down
  const t = $(focusId);
  if (!t || t.offsetParent === null) { say('Look further down this page.'); return; }
  const box = t.closest('section, .card') || t;
  const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  box.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'start' });
  box.classList.add('flash');
  setTimeout(() => box.classList.remove('flash'), 1600);
}

async function loadView(v) {
  try {
    if (v === 'server') await loadServer();
    else if (v === 'backups') await loadBackups();
    else if (v === 'hephaestus') await loadHephaestus();
    else if (v === 'activity') await loadActivity();
    else if (v === 'terminal') await openTerminal(false);
    else if (v === 'files') await openFiles();
    else if (v === 'mail') await loadMail();
    else if (v === 'web') await loadWeb();
    else if (v === 'accounts') await loadAccounts();
  } catch (err) {
    say('Could not load this page: ' + errText(err));
  }
}

// --- server
async function loadServer() {
  const st = lastStatus || {};
  const names = arr(obj(st.services)?.names) || [];
  $('svc-rows').replaceChildren(...(names.length ? names.map((n) => row([el('span', n, 'mono'), el('span', '…', 'muted'), el('span', 'Checking…', 'muted'),
    button('Restart', '', () => restartService(n))])) : [row(['No running services were reported.', '', '', ''])]));
  loadServiceUpdates(false);
  const reboot = obj(st.server)?.reboot_scheduled === true;
  $('reboot-state').textContent = reboot ? 'A restart is scheduled within the next minute.' : '';
  $('reboot-cancel').hidden = !reboot;
  $('reboot').disabled = reboot;
  $('upd-list').replaceChildren(el('p', 'Checking what is waiting…', 'muted'));
  const pkgs = await call('updates-list');
  const list = $('upd-list');
  updatesIncludeDocker = pkgs.some((p) => /^(docker|containerd)/.test(p.name));
  if (!pkgs.length) {
    list.replaceChildren(el('p', 'Nothing waiting. The server is up to date.', 'muted'));
    $('upd-apply').disabled = true;
  } else {
    const count = (lv) => pkgs.filter((p) => p.level === lv).length;
    const high = count('high'), medium = count('medium'), low = count('low');
    const other = pkgs.length - high - medium - low;
    const summary = [high && `${high} high`, medium && `${medium} medium`, low && `${low} low`, other && `${other} not rated`].filter(Boolean).join(', ');
    const advice = high ? 'Apply soon: at least one fixes a security problem or is marked urgent.'
      : medium ? 'Time-sensitive fixes. Apply when convenient, within a few days.'
      : 'Routine. These can wait for your next update round.';
    const items = pkgs.map((p) => {
      const item = el('div', null, 'upd-item');
      const head = el('div', null, 'upd-head');
      head.append(el('strong', p.name, 'mono'), levelPill(p));
      item.append(head);
      if (p.description) item.append(el('p', p.description));
      item.append(el('p', `${p.from || '?'} → ${p.to}${p.source ? ' · ' + p.source : ''}`, 'mono muted small'));
      if (p.changes && p.changes.length) {
        const d = document.createElement('details');
        d.append(el('summary', 'What this update changes'), el('pre', p.changes.join('\n'), 'changes'));
        item.append(d);
      } else {
        item.append(el('p', 'Change details are not available.', 'muted small'));
      }
      return item;
    });
    list.replaceChildren(el('p', `${pkgs.length} waiting: ${summary}.`), el('p', advice, high ? 'warn-text' : 'muted'), ...items);
    if (updatesIncludeDocker) {
      list.append(el('p', 'This includes Docker. Installing it restarts every service on the server, mail included, for a minute or two.', 'warn-text'));
    }
    $('upd-apply').disabled = false;
  }
  watchJob('updates', $('upd-job'), true);
}

// --- service versions and updates
const SU_PILL = { current: ['ok', 'Up to Date'], update: ['warn', 'Update Available'], newer: ['warn', 'Newer Version (Manual)'], own: ['unknown', 'Your Code'], unknown: ['unknown', "Can't Check"] };
let suData = null;
async function loadServiceUpdates(refresh) {
  $('su-list').replaceChildren(el('p', refresh ? 'Checking every service with its publisher…' : 'Reading service versions…', 'muted'));
  $('su-check').disabled = true;
  try { suData = await call('service-updates', refresh ? ['refresh'] : []); }
  catch (err) { $('su-list').replaceChildren(el('p', 'Could not check: ' + errText(err), 'muted')); $('su-check').disabled = false; return; }
  $('su-check').disabled = false;
  const byName = new Map((suData.services || []).map((x) => [x.name, x]));
  const running = arr(obj(lastStatus?.services)?.names) || [];
  $('svc-rows').replaceChildren(...running.map((n) => {
    const x = byName.get(n);
    const p = SU_PILL[x?.status] || SU_PILL.unknown;
    const pill = el('span', p[1], 'pill ' + p[0]);
    pill.title = x?.detail || '';
    const cell = el('div', null, 'su-cell');
    cell.append(pill);
    if (x?.status === 'update' && x.newer) cell.append(el('span', `also ${x.newer.version} (manual)`, 'muted small'));
    return row([el('span', n, 'mono'), el('span', x?.version || 'unknown', 'mono'), cell, button('Restart', '', () => restartService(n))]);
  }));
  $('svc-checked').textContent = suData.checked ? `Checked with each publisher ${new Date(suData.checked).toLocaleString()}; checked again every 6 hours or with Check Now.` : '';
  renderServiceUpdates();
  watchJob('svc-update', $('su-job'), true);
}

function renderServiceUpdates() {
  const items = [], seen = new Set();
  for (const x of suData.services || []) {
    if (x.name === 'hephaestus-prod-migrate-1') continue;                 // one-off migration job (postgres image); the next Hephaestus deploy recreates it
    if (x.can_update) {
      // mailcow updates as one; a hand-built image rebuilds once for all its
      // containers; anything else is updated container by container (two
      // containers on the same image can belong to different projects).
      const key = x.action === 'mailcow' ? 'mailcow' : x.action === 'rebuild-image' ? 'img:' + x.image : x.name;
      if (!seen.has(key)) {
        seen.add(key);
        const names = key === 'mailcow' ? ['mail'] : key.startsWith('img:')
          ? (suData.services || []).filter((y) => y.image === x.image && y.action === x.action).map((y) => y.name) : [x.name];
        items.push({ title: key === 'mailcow' ? 'Mail System (mailcow)' : names.join(', '), detail: x.detail, how: x.how, target: key === 'mailcow' ? 'mailcow' : x.name, manual: false, count: names.length });
      }
    }
    if (x.status === 'update' && !x.can_update && !seen.has('manual:' + x.name)) {
      seen.add('manual:' + x.name);
      items.push({ title: x.name, detail: x.detail, how: x.how, manual: true });
    }
    if (x.newer) {
      const key = 'newer:' + x.image;
      if (!seen.has(key)) {
        seen.add(key);
        const names = (suData.services || []).filter((y) => y.image === x.image && y.name !== 'hephaestus-prod-migrate-1').map((y) => y.name);
        items.push({ title: names.join(', '), detail: `${x.newer.major ? 'New major version' : 'Newer version'} ${x.newer.version} (you have ${x.version}). Argus doesn't change versions by itself${x.newer.major ? ': a major version can change how data is stored' : ''}.`, how: x.newer.how, manual: true });
      }
    }
  }
  const list = $('su-list');
  if (!items.length) { list.replaceChildren(el('p', 'Every service is up to date.', 'muted')); return; }
  const auto = items.filter((i) => !i.manual).length, manual = items.length - auto;
  list.replaceChildren(el('p', [auto && `${auto} Argus can apply`, manual && `${manual} to do by hand (steps included)`].filter(Boolean).join('; ') + '.'),
    ...items.map((i) => {
      const box = el('div', null, 'upd-item');
      const head = el('div', null, 'upd-head');
      head.append(el('strong', i.title, 'mono'), el('span', i.manual ? 'Manual' : 'Update Available', 'pill ' + (i.manual ? 'unknown' : 'warn')));
      box.append(head, el('p', i.detail));
      if (i.how && i.how.length) {
        const d = document.createElement('details');
        d.append(el('summary', 'How to Update'), ...i.how.map((t) => el('p', t, /^(By hand|docker|cd |\d\. )/.test(t) || t.includes(' && ') ? 'mono small' : 'small')));
        box.append(d);
      }
      if (!i.manual) box.append(button(i.target === 'mailcow' ? 'Update Mail System' : 'Update', 'primary', () => applyServiceUpdate(i)));
      return box;
    }));
}

async function applyServiceUpdate(i) {
  const mail = i.target === 'mailcow';
  const ok = await confirmAction({ title: mail ? 'Update the Mail System?' : `Update ${i.title}?`,
    text: mail ? 'Argus takes a mail backup first, then runs mailcow\'s updater. Mail and webmail are unavailable for a few minutes. If the backup fails, nothing is updated.'
      : `${i.detail}. ${i.count > 1 ? 'Each of these restarts' : 'It restarts'} for a few seconds; anything using ${i.count > 1 ? 'them' : 'it'} sees an error meanwhile.`,
    ok: mail ? 'Update Mail System' : 'Update' });
  if (!ok) return;
  try { await call('service-update', [i.target]); watchJob('svc-update', $('su-job')); }
  catch (err) { say('The update did not start: ' + errText(err)); }
}
$('su-check').addEventListener('click', () => loadServiceUpdates(true));

async function restartService(name) {
  const ok = await confirmAction({ title: `Restart ${name}?`,
    text: `${name} stops for a few seconds and starts again. Anything it serves shows an error meanwhile.`, ok: 'Restart' });
  if (!ok) return;
  say(`Restarting ${name}…`);
  try {
    await call('service-restart', [name]);
    say(`${name} restarted.`);
    await refresh();
  } catch (err) { say(`Could not restart ${name}: ` + errText(err)); }
}

let updatesIncludeDocker = false;
function levelPill(p) {
  const map = {
    high: ['bad', p.why === 'urgent' ? 'High · marked urgent' : 'High · security fix'],
    medium: ['warn', 'Medium · time-sensitive fix'],
    low: ['ok', 'Low · routine'],
  };
  const [cls, text] = map[p.level] || ['unknown', 'Not rated'];
  const pill = el('span', text, 'pill ' + cls);
  pill.title = p.why === 'security' ? 'Published in Debian security updates: it fixes a security problem.'
    : p.why === 'urgent' ? `Its maintainer marked it "${p.urgency}".`
    : p.why === 'stable-updates' ? 'Published in Debian stable-updates, kept for fixes that cannot wait for the next routine release.'
    : p.why === 'routine' ? 'An ordinary Debian point-release update.' : 'Could not be read.';
  return pill;
}
$('upd-apply').addEventListener('click', async () => {
  const docker = updatesIncludeDocker
    ? ' This includes Docker: every service on the server, mail included, restarts for a minute or two.' : '';
  const ok = await confirmAction({ title: 'Apply Updates?',
    text: 'The waiting updates are installed now. Services they touch may restart briefly.' + docker + ' If an update needs the server restarted, Argus says so and you choose when.', ok: 'Apply Updates' });
  if (!ok) return;
  try {
    await call('updates-apply');
    watchJob('updates', $('upd-job'));
  } catch (err) { say('Could not start the updates: ' + errText(err)); }
});

$('reboot').addEventListener('click', async () => {
  const ok = await confirmAction({ title: 'Restart the Server?',
    text: 'In one minute the server restarts. Websites, mail and Hephaestus are offline for about two minutes. You can cancel during that minute.',
    ok: 'Restart in One Minute', word: 'restart' });
  if (!ok) return;
  try {
    await call('reboot');
    $('reboot-state').textContent = 'The server restarts in one minute. Argus will lose its connection; sign in again in about three minutes.';
    $('reboot-cancel').hidden = false;
    $('reboot').disabled = true;
  } catch (err) { say('Could not schedule the restart: ' + errText(err)); }
});
$('reboot-cancel').addEventListener('click', async () => {
  const ok = await confirmAction({ title: 'Cancel the Restart?', text: 'The scheduled restart is called off and the server keeps running.', ok: 'Cancel the Restart' });
  if (!ok) return;
  try {
    await call('reboot-cancel');
    $('reboot-state').textContent = 'Restart cancelled.';
    $('reboot-cancel').hidden = true;
    $('reboot').disabled = false;
  } catch (err) { say('Could not cancel the restart: ' + errText(err)); }
});

// --- background jobs
const jobTimers = {};
async function watchJob(job, box, quietIfNone) {
  clearTimeout(jobTimers[job]);
  let st;
  try { st = await call('job-status', [job]); } catch (err) { box.hidden = false; box.replaceChildren(el('p', 'Could not read progress: ' + errText(err))); return; }
  if (!st.log.length && quietIfNone) { box.hidden = true; return; }
  box.hidden = false;
  const label = st.running ? ['warn', 'Running'] : st.result === 'ok' ? ['ok', 'Finished'] : st.result === 'failed' ? ['bad', 'Failed'] : ['warn', 'Interrupted'];
  const pill = el('span', label[1], 'pill ' + label[0]);
  const head = el('p', { updates: 'Last update run: ', 'heph-rollback': 'Last rollback: ', 'heph-deploy': 'Last deploy: ', web: 'Last web server change: ', 'svc-update': 'Last service update: ' }[job]);
  head.append(pill);
  const lines = st.log.filter((l) => !l.startsWith('ARGUS-RESULT'));
  // A plain last line, so the end of the log says how it ended.
  if (!st.running) lines.push('', st.result === 'ok' ? '■ Done: finished without errors.' : st.result === 'failed' ? '■ Stopped: it failed. The lines above say where.' : '■ Stopped before it finished (interrupted).');
  const pre = el('pre', lines.join('\n'));
  box.replaceChildren(head, pre);
  // Always show the end of the log (after layout, so the height is known).
  requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
  if (st.running) jobTimers[job] = setTimeout(() => watchJob(job, box), 3000);
  else if (!quietIfNone) { refresh(); if (job === 'svc-update') loadServiceUpdates(false); }
}

// --- backups
async function loadBackups() {
  const bk = await call('backup-list');
  const cards = [];
  for (const [key, label] of [['mail', 'Mail'], ['hephaestus', 'Hephaestus Database']]) {
    const c = el('section', null, 'card');
    c.append(el('h3', label));
    const items = arr(bk[key]);
    if (!items) c.append(el('p', 'Could not read this folder.', 'muted'));
    else if (!items.length) c.append(el('p', 'None kept yet.', 'muted'));
    else {
      const t = el('table');
      const tb = el('tbody');
      for (const i of items) tb.append(row([el('span', i.time, 'mono'), el('span', (i.size_b / 1e6).toFixed(1) + ' MB', 'mono')]));
      t.append(tb);
      c.append(el('p', `${items.length} kept. Older copies are removed automatically.`, 'muted'), t);
    }
    c.append(button('Back Up Now', '', async () => {
      const ok = await confirmAction({ title: `Back Up ${label} Now?`,
        text: key === 'mail'
          ? 'A copy of all mail, plus the websites\' files, is made now. It takes a few minutes; mail and the websites keep working meanwhile. Copies past the kept number of days are removed.'
          : 'A copy of the Hephaestus database is made now. It takes a few seconds; Hephaestus keeps working. Copies older than 14 days are removed.',
        ok: 'Back Up Now' });
      if (!ok) return;
      try { await call('backup-run', [key]); say(`${label} backup started. It appears here when it finishes; refresh this page in a minute or two.`); }
      catch (err) { say(`Could not start the ${label} backup: ` + errText(err)); }
    }));
    cards.push(c);
  }
  $('bk-cards').replaceChildren(...cards);
}

// --- hephaestus
async function loadHephaestus() {
  const rl = await call('rollback-list');
  $('hp-live').textContent = rl.live_version || UNKNOWN;
  const choices = arr(rl.choices) || [];
  $('hp-rows').replaceChildren(...(choices.length ? choices.map((c) => row([el('span', c.tag.replace(/^pre-/, ''), 'mono'),
    el('span', c.created, 'mono'), button('Roll Back to This', 'danger', () => rollback(c.tag))]))
    : [row(['No earlier versions are kept.', '', ''])]));
  watchJob('heph-rollback', $('hp-job'), true);
  await loadDeploySource();
  watchJob('heph-deploy', $('dp-job'), true);
}

async function rollback(tag) {
  const name = tag.replace(/^pre-/, '');
  const ok = await confirmAction({ title: `Roll Hephaestus Back to ${name}?`,
    text: `Hephaestus restarts on the earlier version ${name}. It is offline for a minute or two, a few minutes at most. The database is not changed. The version live now is kept so you can switch back, and if ${name} does not start, Argus puts the current version back on its own.`,
    ok: 'Roll Back', word: name });
  if (!ok) return;
  try {
    await call('heph-rollback', [tag]);
    watchJob('heph-rollback', $('hp-job'));
  } catch (err) { say('Could not start the rollback: ' + errText(err)); }
}

// --- activity
async function loadActivity() {
  const entries = await call('activity');
  $('act-rows').replaceChildren(...entries.map((e) => {
    const ok = e.result === 'ok';
    return row([el('span', e.time, 'mono'), e.action, (arr(e.args) || []).join(' ') || '—',
      el('span', e.result, 'pill ' + (ok ? 'ok' : String(e.result).startsWith('refused') ? 'warn' : 'bad')), el('span', e.session, 'mono')]);
  }));
}

// ---------- deploy ----------
let dpSource = null;
async function loadDeploySource() {
  const box = $('dp-source');
  try {
    const src = await window.argus.deploySource();
    dpSource = src;
    const dl = el('dl', null, 'plan');
    const add = (k, v) => dl.append(el('dt', k), el('dd', v));
    add('Source', `${src.repo} (${src.branch})`);
    add('Latest commit', `${src.commit} · ${src.subject}`);
    add('Committed', new Date(src.date).toLocaleString());
    const parts = [dl];
    if (src.uncommitted) parts.push(el('p', `${src.uncommitted} file(s) have changes that are not committed. They are not included; commit them first if they should go live.`, 'warn-text'));
    parts.push(el('p', 'Only committed work is deployed, and only the usual set: Cargo files, crates, migrations, deploy (never .env) and the RLS test. "Prepare" sends it to the server and shows what would change. Nothing goes live until you confirm.', 'muted small'));
    box.replaceChildren(...parts);
    $('dp-prepare').disabled = false;
  } catch (err) {
    dpSource = null;
    box.replaceChildren(el('p', 'Could not read the Hephaestus source on this PC: ' + errText(err), 'muted'));
    $('dp-prepare').disabled = true;
  }
}

$('dp-prepare').addEventListener('click', async () => {
  if (!dpSource) return;
  const commit = dpSource.commit;
  $('dp-prepare').disabled = true;
  const out = $('dp-staged');
  out.hidden = false;
  out.replaceChildren(el('p', `Packing ${commit}, sending it to the server and checking it…`, 'muted'));
  try {
    const st = await window.argus.deployPrepare(commit);
    showStaged(st);
  } catch (err) {
    out.replaceChildren(el('p', 'Could not prepare it: ' + errText(err), 'warn-text'));
  } finally {
    $('dp-prepare').disabled = false;
  }
});

function showStaged(st) {
  const out = $('dp-staged');
  const parts = [el('h3', `Ready: ${st.commit} (live now: ${st.live_version || 'unknown'})`)];
  if (!st.change_count) {
    parts.push(el('p', 'Nothing would change: this is the same source as the live version.', 'muted'));
    out.replaceChildren(...parts);
    return;
  }
  const counts = { added: 0, changed: 0, removed: 0 };
  for (const c of st.changes) counts[c.change]++;
  parts.push(el('p', `${st.change_count} file(s): ${counts.changed} changed, ${counts.added} added, ${counts.removed} removed.`));
  if (st.new_migrations.length) {
    parts.push(el('p', `New database migrations: ${st.new_migrations.join(', ')}. These change the database and are not undone by a rollback (the extra columns stay, which does no harm).`, 'warn-text'));
  }
  const files = document.createElement('details');
  files.append(el('summary', 'Files that change'), el('pre', st.changes.map((c) => `${c.change.padEnd(8)} ${c.path}`).join('\n'), 'changes'));
  const full = document.createElement('details');
  full.append(el('summary', 'Show every change, line by line'));
  full.addEventListener('toggle', async () => {
    if (!full.open || full.dataset.loaded) return;
    full.dataset.loaded = '1';
    try {
      const d = await call('heph-diff', [st.commit]);
      full.append(el('pre', d.diff + (d.cut ? '\n… (cut at 512 KB)' : ''), 'changes'));
    } catch (err) { full.append(el('p', 'Could not load the changes: ' + errText(err), 'muted')); }
  });
  parts.push(files, full);
  parts.push(el('p', 'Board rule: a change that touches security gets a Sentinel review of these changes before it goes live. Argus cannot do that review.', 'muted small'));
  parts.push(button(`Deploy ${st.commit}`, 'primary', () => deploy(st)));
  out.replaceChildren(...parts);
}

async function deploy(st) {
  const ok = await confirmAction({
    title: `Deploy ${st.commit}?`,
    text: `What happens: the current source is backed up, the database is saved, and ${st.live_version || 'the live version'} is kept for rollback. The new version is built while the old one keeps running (several minutes). ${st.new_migrations.length ? 'Its database migrations are applied, then it' : 'Then it'} starts; Hephaestus is offline for a minute or two. If the build, the migrations or the start fail, or it is not healthy within two minutes, the previous version is put back automatically${st.new_migrations.length ? ' (database columns the migrations added stay; they do no harm)' : ''}. Last, the server checks run: if any fail, the new version stays live and Argus says so, so you can roll back from this page.`,
    ok: 'Deploy', word: st.commit,
  });
  if (!ok) return;
  try {
    await call('heph-deploy', [st.commit]);
    $('dp-staged').hidden = true;
    watchJob('heph-deploy', $('dp-job'));
  } catch (err) { say('Could not start the deploy: ' + errText(err)); }
}

// ---------- accounts ----------
// A menu of actions in the shared dialog (as the mailbox Manage menu).
function menuDialog(title, subtitle, items) {
  const list = el('div', null, 'menu');
  for (const [label, help, fn, cls] of items) {
    const r = el('div', null, 'menu-item');
    r.append(button(label, cls || '', () => { $('confirm').close('cancel'); fn(); }), el('span', help, 'muted small'));
    list.append(r);
  }
  const d = $('confirm');
  $('confirm-title').textContent = title;
  $('confirm-text').textContent = subtitle || '';
  $('confirm-extra').replaceChildren(list);
  $('confirm-type-label').hidden = true;
  $('confirm-ok').hidden = true;
  d.classList.remove('wide');
  d.onclose = () => { if (!d.open) $('confirm-ok').hidden = false; };
  d.showModal();
}

// Pick one option from a list; resolves to its value, or null.
async function choose({ title, text, label, options, ok }) {
  const sel = el('select', null, 'wide-select');
  for (const [value, name] of options) { const o = el('option', name); o.value = value; sel.append(o); }
  const wrap = el('label');
  wrap.append(el('span', label), sel);
  const go = await confirmAction({ title, text, ok, extra: wrap });
  return go ? sel.value : null;
}

const kbText = (kb) => (kb == null ? 'unknown' : gbText(kb * 1024));

function showCode(title, text, r) {
  return new Promise((resolve) => {
    const d = $('qr');
    $('qr-title').textContent = title;
    $('qr-text').textContent = text;
    try {
      const q = qrcode(0, 'M');
      q.addData(r.otpauth);
      q.make();
      $('qr-img').src = q.createDataURL(5, 2);
      $('qr-img').hidden = false;
    } catch { $('qr-img').hidden = true; }
    $('qr-secret').textContent = r.secret;
    $('qr-codes').replaceChildren(...(r.emergency_codes || []).map((c) => el('span', c)));
    $('qr-copy').onclick = () => window.argus.copy(`Authenticator key: ${r.secret}\nEmergency codes: ${(r.emergency_codes || []).join(' ')}`, true);
    d.onclose = () => { if (d.open) return; $('qr-img').removeAttribute('src'); $('qr-secret').textContent = ''; $('qr-codes').replaceChildren(); resolve(); };
    d.showModal();
  });
}

let acctData = null;
async function loadAccounts() {
  const loading = (n) => row([el('span', 'Loading…', 'muted'), ...Array(n - 1).fill('')]);
  $('ac-rows').replaceChildren(loading(5));
  $('ak-rows').replaceChildren(el('p', 'Loading…', 'muted'));
  $('hu-rows').replaceChildren(loading(5));
  $('hc-rows').replaceChildren(loading(2));
  const [a, h] = await Promise.allSettled([call('acct-list'), call('heph-people')]);
  if (a.status === 'fulfilled') renderAccounts(a.value);
  else {
    const msg = 'Could not read the accounts: ' + errText(a.reason);
    $('ac-rows').replaceChildren(row([el('span', msg, 'muted'), '', '', '', '']));
    $('ak-rows').replaceChildren(el('p', msg, 'muted'));
  }
  if (h.status === 'fulfilled') renderHeph(h.value);
  else {
    const msg = 'Could not read Hephaestus: ' + errText(h.reason);
    $('hu-rows').replaceChildren(row([el('span', msg, 'muted'), '', '', '', '']));
    $('hc-rows').replaceChildren(row([el('span', msg, 'muted'), '']));
  }
}

const READY_TEXT = { quotas: 'Disk size limits (quotas) are not switched on.', authenticator_folder: 'Authenticator codes are not yet kept in the shared, root-only folder.', ssh_settings: "SSH's settings for upload accounts are not in place.", boot_mounts: 'Shared folders are not yet reconnected automatically when the server starts.' };

function renderAccounts(d) {
  acctData = d;
  const missing = Object.entries(d.ready || {}).filter(([, v]) => !v).map(([k]) => k);
  $('ac-setup').hidden = !missing.length;
  $('ac-setup-list').replaceChildren(...missing.map((k) => el('li', READY_TEXT[k] || k)));
  $('ac-new').disabled = missing.length > 0;
  const accts = d.accounts || [];
  $('ac-rows').replaceChildren(...accts.map((x) => {
    const who = el('div');
    who.append(el('span', x.name, 'mono'));
    if (x.label && x.label !== x.name) who.append(el('div', x.label, 'muted small'));
    if (x.disabled) who.append(el('span', 'Disabled', 'pill bad'));
    const folder = el('div');
    folder.append(el('span', x.folder || 'Its Own Folder', x.folder ? 'mono' : ''));
    if (x.folder && x.mounted === false) folder.append(el('span', 'Not Connected', 'pill warn'));
    const pct = x.limit_kb ? Math.round((x.used_kb / x.limit_kb) * 100) : null;
    const used = el('span', `${kbText(x.used_kb)} of ${x.limit_kb ? kbText(x.limit_kb) : 'no limit'}${pct != null ? ' · ' + pct + '%' : ''}`, 'mono');
    const keys = (x.keys || []).length;
    const sign = keys ? el('span', `${keys} ${keys === 1 ? 'Key' : 'Keys'} + Code`, 'pill ok') : el('span', 'No Key Yet', 'pill warn');
    return row([who, folder, used, sign, button('Manage', '', () => acManage(x))]);
  }));
  if (!accts.length) $('ac-rows').replaceChildren(row([el('span', 'No upload accounts yet.', 'muted'), '', '', '', '']));
  renderKeys($('ak-rows'), d.admin.name, d.admin.keys || []);
}

function renderKeys(box, account, keys) {
  if (!keys.length) { box.replaceChildren(el('p', 'No keys.', 'muted')); return; }
  box.replaceChildren(...keys.map((k) => {
    const r = el('div', null, 'key-line');
    const t = el('div');
    t.append(el('div', k.comment || '(no comment)'), el('div', `${k.type}${k.bits ? ' ' + k.bits : ''} · ${k.fingerprint || 'unreadable'}`, 'mono small muted'));
    r.append(t, k.fingerprint ? button('Remove', 'danger', () => keyRemove(account, k)) : el('span'));
    return r;
  }));
}

async function acctChange(action, args, done) {
  try { await call(action, args); say(done); }
  catch (err) { say('That did not work: ' + errText(err)); }
  try { await loadAccounts(); } catch { /* shown in the tables */ }
}

async function keyAdd(account) {
  const line = await ask({ title: `Add a Key for ${account}`, label: 'Paste the whole public key line (it starts with ssh-ed25519; never the private key)', ok: 'Add Key' });
  if (!line) return;
  if (/PRIVATE KEY/.test(line)) { say('That is a private key. Nothing was sent; use the .pub file instead.'); return; }
  await acctChange('key-add', [account, hex(line.trim())], `Key added for ${account}.`);
}

async function keyRemove(account, k) {
  const last = account === acctData?.admin?.name && (acctData.admin.keys || []).length <= 1;
  if (last) { say('That is your last key; add another one first, or you could not sign in.'); return; }
  if (!await confirmAction({ title: `Remove This Key from ${account}?`, text: `"${k.comment || k.fingerprint}" can no longer sign in as ${account}.${account === acctData?.admin?.name ? ' If it is the key Argus is using now, you stay signed in until you disconnect, then cannot sign in with it again.' : ''}`, ok: 'Remove Key' })) return;
  await acctChange('key-remove', [account, hex(k.fingerprint)], `Key removed from ${account}.`);
}

function acManage(x) {
  menuDialog(x.name, x.label && x.label !== x.name ? x.label : '', [
    ['Keys', `${(x.keys || []).length} now; add or remove`, () => acKeys(x)],
    ['Size Limit', `now ${x.limit_kb ? kbText(x.limit_kb) : 'no limit'}`, () => acSize(x)],
    ['Description', x.label || 'none', () => acLabel(x)],
    ['New Authenticator Code', 'for a lost phone; the old code stops working', () => acNewCode(x)],
    [x.disabled ? 'Enable' : 'Disable', x.disabled ? 'lets it sign in again' : 'stops sign-in now; keeps everything', () => acActive(x)],
    ['Delete Account', 'removes the account; its files are kept', () => acDelete(x), 'danger'],
  ]);
}

async function acKeys(x) {
  const box = el('div');
  renderKeys(box, x.name, x.keys || []);
  for (const b of box.querySelectorAll('button')) b.addEventListener('click', () => $('confirm').close('cancel'), { capture: true });
  if (await confirmAction({ title: `Keys for ${x.name}`, text: 'The keys that may sign in to this account. Each sign-in also needs the account\'s authenticator code.', ok: 'Add Key', extra: box })) await keyAdd(x.name);
}

async function acSize(x) {
  const v = await ask({ title: `Size Limit for ${x.name}`, label: `In GB (now ${x.limit_kb ? kbText(x.limit_kb) : 'no limit'}, using ${kbText(x.used_kb)})`, ok: 'Set Limit' });
  if (v == null) return;
  const gb = Number(v);
  if (!(gb > 0 && gb <= 100)) { say('Give the size in GB, from 0.001 to 100.'); return; }
  const mb = Math.max(1, Math.round(gb * 1024));
  if (x.used_kb != null && mb * 1024 < x.used_kb) { say(`That is smaller than what ${x.name} already uses.`); return; }
  await acctChange('acct-set', [x.name, 'quota', String(mb)], `Size limit for ${x.name} set to ${gb} GB.`);
}

async function acLabel(x) {
  const v = await ask({ title: `Description for ${x.name}`, label: 'Who or what it is for (letters, numbers and spaces)', ok: 'Save' });
  if (v == null) return;
  await acctChange('acct-set', [x.name, 'label', v.trim() ? hex(v.trim()) : 'none'], `Description for ${x.name} saved.`);
}

async function acNewCode(x) {
  if (!await confirmAction({ title: `New Authenticator Code for ${x.name}?`, text: 'A new code is made and shown once. The old one stops working straight away, and anyone signed in as this account is signed out.', ok: 'Make New Code' })) return;
  try {
    const r = await call('acct-set', [x.name, 'new-code']);
    await showCode(`New Code for ${x.name}`, 'Scan this with the authenticator app on the new phone, or type in the key.', r);
  } catch (err) { say('No new code was made: ' + errText(err)); }
}

async function acActive(x) {
  const off = !x.disabled;
  if (!await confirmAction({ title: `${off ? 'Disable' : 'Enable'} ${x.name}?`, text: off ? 'It can no longer sign in, and anyone signed in as it now is cut off. Its files, keys and code are kept.' : 'It can sign in again with its key and code.', ok: off ? 'Disable' : 'Enable' })) return;
  await acctChange('acct-set', [x.name, off ? 'disable' : 'enable'], `${x.name} ${off ? 'disabled' : 'enabled'}.`);
}

async function acDelete(x) {
  const text = x.folder
    ? `The account, its keys and its code are removed. Files it uploaded to ${x.folder} stay there, handed to root.`
    : 'The account, its keys and its code are removed. Its folder is moved to /var/backups/argus and kept for 30 days.';
  if (!await confirmAction({ title: `Delete ${x.name}?`, text, ok: 'Delete Account', word: x.name })) return;
  try {
    const r = await call('acct-delete', [x.name]);
    say(`${x.name} deleted.${r.kept ? ' Its files are in ' + r.kept + ' for 30 days.' : ''}`);
  } catch (err) { say('The account was not deleted: ' + errText(err)); }
  try { await loadAccounts(); } catch { /* shown in the tables */ }
}

$('ac-new').addEventListener('click', async () => {
  const name = await ask({ title: 'New Upload Account', label: 'Account name: 3 to 31 lowercase letters, digits or hyphens, starting with a letter', ok: 'Next' });
  if (!name) return;
  const n = name.trim();
  if (!/^[a-z][a-z0-9-]{2,30}$/.test(n)) { say('Use 3 to 31 lowercase letters, digits or hyphens, starting with a letter.'); return; }
  const label = await ask({ title: `Description for ${n}`, label: 'Who or what it is for (optional)', ok: 'Next' });
  if (label == null) return;
  let folders = [], listNote = '';
  try { folders = (await call('acct-folders')).folders || []; } catch (err) { listNote = ` (The shared folders could not be listed: ${errText(err)}.)`; }
  const where = await choose({ title: `Folder for ${n}`,
    text: 'The account sees this folder and nothing else. It can read what is already there and add its own files and folders, but it cannot change or delete anyone else\'s files. Folders a website serves (such as a site\'s public folder) can\'t be shared, so uploads never go live by themselves; to share a folder beside a site, make it first in Files with New Folder.' + listNote,
    label: 'Folder', options: [['own', 'Its Own New Folder (Private)'], ...folders.map((f) => [f, f])], ok: 'Next' });
  if (where == null) return;
  const gbAnswer = await ask({ title: `Size Limit for ${n}`, label: 'In GB, for example 5', ok: 'Next' });
  if (gbAnswer == null) return;
  const gb = Number(gbAnswer);
  if (!(gb > 0 && gb <= 100)) { say('Give the size in GB, from 0.001 to 100.'); return; }
  const mb = Math.max(1, Math.round(gb * 1024));
  if (!await confirmAction({ title: `Create ${n}?`, text: `${n} can upload up to ${gb} GB to ${where === 'own' ? 'its own new folder' : where}. Next you'll see its authenticator code once, then add its key.`, ok: 'Create Account' })) return;
  let r;
  try {
    r = await call('acct-add', [n, label.trim() ? hex(label.trim()) : 'none', String(mb), where === 'own' ? 'own' : hex(where)]);
  } catch (err) { say('The account was not created: ' + errText(err)); try { await loadAccounts(); } catch {} return; }
  await showCode(`Authenticator Code for ${n}`, `Give this to the person who will use ${n}: they scan it with an authenticator app (or type in the key). They'll need it together with their key every time they sign in.`, r);
  say(`${n} created. Add their public key next so they can sign in.`);
  await keyAdd(n);
  try { await loadAccounts(); } catch { /* shown in the tables */ }
});
$('ak-add').addEventListener('click', () => keyAdd(acctData?.admin?.name || 'mattridge'));

// --- Hephaestus users
let hephData = null;
const ROLE_TEXT = { platform_admin: 'Platform Admin', technician: 'Technician' };
function renderHeph(d) {
  hephData = d;
  $('hu-rows').replaceChildren(...(d.staff || []).map((s) => row([
    el('span', s.email, 'mono'), ROLE_TEXT[s.role] || s.role,
    s.active ? el('span', 'Active', 'pill ok') : el('span', 'Inactive', 'pill bad'),
    s.two_factor ? el('span', 'On', 'pill ok') : el('span', 'Not Set Up', 'pill warn'),
    button('Manage', '', () => huManage(s.email))])));
  if (!(d.staff || []).length) $('hu-rows').replaceChildren(row([el('span', 'No staff accounts.', 'muted'), '', '', '', '']));
  $('hc-rows').replaceChildren(...(d.companies || []).map((c) => row([el('span', c.slug, 'mono'), c.name])));
}

const huAfter = async (msg) => { say(msg); try { await loadAccounts(); } catch { /* shown in the tables */ } };

function huManage(email) {
  menuDialog(email, 'Hephaestus account', [
    ['Set Password', 'type one, or have one generated; signs them out everywhere', () => huPassword(email)],
    ['Reset Link', 'a one-time link to hand over; works for 4 hours', () => huLink(email)],
    ['Reset Two-Factor', 'for a lost phone; they set it up again at next sign-in', () => huTfa(email)],
    ['Sign Out Everywhere', 'ends all their sessions now', () => huSignOut(email)],
  ]);
}

async function huPassword(email) {
  const pw = await askPassword(`New Password for ${email}`);
  if (pw == null) return;
  try {
    const r = await window.argus.helperSecret('heph-user', [hex(email), 'set-password'], pw);
    if (r.password) await showOnce('New Hephaestus Password', `The new password for ${email}. They have been signed out everywhere.`, r.password);
    else say(`Password for ${email} set; they have been signed out everywhere.`);
  } catch (err) { say('The password was not changed: ' + errText(err)); }
}
async function huLink(email) {
  if (!await confirmAction({ title: `Reset Link for ${email}?`, text: 'Hephaestus makes a one-time link that lets them choose a new password. It works for 4 hours, and any earlier link stops working. Hand it over directly, not by email.', ok: 'Make Link' })) return;
  try {
    const r = await call('heph-user', [hex(email), 'reset-link']);
    await showOnce('Reset Link', `For ${email}. It works once, for ${r.hours} hours.`, r.link);
  } catch (err) { say('No link was made: ' + errText(err)); }
}
async function huTfa(email) {
  if (!await confirmAction({ title: `Reset Two-Factor for ${email}?`, text: 'Their authenticator code is cleared and they are signed out. They set up a new one the next time they sign in.', ok: 'Reset Two-Factor' })) return;
  try { await call('heph-user', [hex(email), 'reset-totp']); await huAfter(`Two-factor reset for ${email}.`); }
  catch (err) { say('That did not work: ' + errText(err)); }
}
async function huSignOut(email) {
  if (!await confirmAction({ title: `Sign ${email} Out Everywhere?`, text: 'Every session they have open ends now. Their password and two-factor are unchanged.', ok: 'Sign Out' })) return;
  try { const r = await call('heph-user', [hex(email), 'sign-out']); say(r.message || `${email} signed out everywhere.`); }
  catch (err) { say('That did not work: ' + errText(err)); }
}

async function askNames(title) {
  const first = await ask({ title, label: 'First name', ok: 'Next' });
  if (!first) return null;
  const last = await ask({ title, label: 'Last name', ok: 'Next' });
  if (!last) return null;
  return [first.trim(), last.trim()];
}
const EMAIL_OK = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/;

$('hu-staff').addEventListener('click', async () => {
  const email = (await ask({ title: 'New Staff Account', label: 'Email address they sign in with', ok: 'Next' }) || '').trim();
  if (!email) return;
  if (!EMAIL_OK.test(email)) { say('That is not an email address.'); return; }
  const names = await askNames(`Name for ${email}`);
  if (!names) return;
  const role = await choose({ title: `Role for ${email}`, text: 'A platform admin sees every company. A technician sees none until granted one.', label: 'Role', options: [['technician', 'Technician'], ['admin', 'Platform Admin']], ok: 'Next' });
  if (!role) return;
  const pw = await askPassword(`Password for ${email}`);
  if (pw == null) return;
  try {
    const r = await window.argus.helperSecret('heph-staff-add', [hex(email), hex(names.join('\t')), role], pw);
    if (r.password) await showOnce('Hephaestus Password', `For ${email}. They set up two-factor at their first sign-in.`, r.password);
    await huAfter(`Staff account ${email} created.`);
  } catch (err) { say('The account was not created: ' + errText(err)); }
});

$('hu-company').addEventListener('click', async () => {
  const name = await ask({ title: 'New Company', label: 'Company name', ok: 'Next' });
  if (!name) return;
  const suggest = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  const slug = (await ask({ title: `Short Name for ${name.trim()}`, label: `Goes in every page address; can't be changed later (for example ${suggest || 'acme'})`, ok: 'Next' }) || '').trim();
  if (!slug) return;
  if (!/^[a-z0-9][a-z0-9-]{1,39}$/.test(slug)) { say('The short name is 2 to 40 lowercase letters, digits or hyphens.'); return; }
  if (!await confirmAction({ title: `Create ${name.trim()}?`, text: `A new, empty company with the short name ${slug}. Add its first administrator with New Company User.`, ok: 'Create Company' })) return;
  try { await call('heph-company-add', [slug, hex(name.trim())]); await huAfter(`Company ${name.trim()} created.`); }
  catch (err) { say('The company was not created: ' + errText(err)); }
});

$('hu-user').addEventListener('click', async () => {
  const cos = (hephData?.companies || []);
  if (!cos.length) { say('There are no companies yet.'); return; }
  const slug = await choose({ title: 'New Company User', text: 'Which company are they in?', label: 'Company', options: cos.map((c) => [c.slug, `${c.name} (${c.slug})`]), ok: 'Next' });
  if (!slug) return;
  const email = (await ask({ title: 'New Company User', label: 'Email address they sign in with', ok: 'Next' }) || '').trim();
  if (!email) return;
  if (!EMAIL_OK.test(email)) { say('That is not an email address.'); return; }
  const names = await askNames(`Name for ${email}`);
  if (!names) return;
  const role = await choose({ title: `Role for ${email}`, text: 'If this address is already in that company, its name, role and password are replaced.', label: 'Role', options: [['tenant_user', 'User'], ['tenant_tech', 'Technician'], ['tenant_admin', 'Company Admin']], ok: 'Next' });
  if (!role) return;
  const pw = await askPassword(`Password for ${email}`);
  if (pw == null) return;
  try {
    const r = await window.argus.helperSecret('heph-user-add', [slug, hex(email), hex(names.join('\t')), role], pw);
    if (r.password) await showOnce('Hephaestus Password', `For ${email} in ${slug}.`, r.password);
    await huAfter(`${email} added to ${slug}.`);
  } catch (err) { say('The user was not added: ' + errText(err)); }
});

$('hu-find').addEventListener('click', async () => {
  const email = (await ask({ title: 'Manage a Hephaestus User', label: 'Their email address (staff or company user)', ok: 'Next' }) || '').trim();
  if (!email) return;
  if (!EMAIL_OK.test(email)) { say('That is not an email address.'); return; }
  huManage(email);
});

// ---------- collapsible sections (remembered on this PC) ----------
for (const sec of document.querySelectorAll('[data-collapse]')) {
  const key = 'argus-collapse-' + sec.dataset.collapse;
  const btn = sec.querySelector('[data-toggle]');
  if (!btn) continue;
  const set = (hidden) => {
    sec.classList.toggle('collapsed', hidden);
    btn.textContent = hidden ? 'Show' : 'Hide';
    btn.setAttribute('aria-expanded', String(!hidden));
    try { localStorage.setItem(key, hidden ? '1' : '0'); } catch { /* still works for this run */ }
  };
  let start = false;
  try { start = localStorage.getItem(key) === '1'; } catch { /* default open */ }
  set(start);
  btn.addEventListener('click', () => set(!sec.classList.contains('collapsed')));
}

// ---------- websites ----------
const KIND_TEXT = { site: 'Website', app: 'App on the server', redirect: 'Redirect', other: 'Other' };
async function loadWeb() {
  $('ws-rows').replaceChildren(row(['Checking every site…', '', '', '', '']));
  const r = await call('sites-list');
  $('ws-rows').replaceChildren(...r.sites.map((x) => {
    const ans = !x.http ? ['bad', 'Not answering'] : x.http >= 500 ? ['bad', `Error ${x.http}`] : ['ok', String(x.http)];
    const cert = x.cert_days == null ? ['unknown', 'Unknown'] : x.cert_days < 14 ? ['bad', `${x.cert_days} days`] : x.cert_days < 30 ? ['warn', `${x.cert_days} days`] : ['ok', `${x.cert_days} days`];
    const what = el('div');
    what.append(el('span', KIND_TEXT[x.kind] || x.kind));
    if (x.target) what.append(el('div', x.target, 'mono muted small'));
    return row([el('span', x.name, 'mono'), what, el('span', ans[1], 'pill ' + ans[0]), el('span', cert[1], 'pill ' + cert[0]),
      button('Renew', '', () => renewCert(x.name))]);
  }));
  $('wc-state').textContent = r.changed_since_apply == null ? 'Nothing has been applied through Argus yet. The first Apply keeps the configuration the web server is running now as the first good copy (only if the files have not been edited since it started).'
    : r.changed_since_apply ? `The files have changed since the last apply (${r.last_applied}). Check, then Apply.` : `The files match what was last applied (${r.last_applied}).`;
  $('wc-apply').disabled = r.changed_since_apply === false;
  watchJob('web', $('wc-job'), true);
}

async function renewCert(name) {
  if (!await confirmAction({ title: `Get a New Certificate for ${name}?`, text: `The current certificate is set aside (kept in /root/config-backups-argus) and the web server restarts; every site blips for a second or two. Caddy then asks Let's Encrypt for a new one, which takes up to a minute. Only needed if the certificate is wrong; Caddy renews on its own 30 days before expiry. Let's Encrypt allows about five new certificates per name per week, so do not repeat this many times. If no new certificate arrives within 90 seconds, the old one is put back.`, ok: 'Get a New Certificate' })) return;
  try { await call('cert-renew', [hex(name)]); watchJob('web', $('wc-job')); } catch (err) { say('Could not start: ' + errText(err)); }
}

$('wc-open').addEventListener('click', async () => { showView('files'); await navigate(srv, '/opt/web'); });
$('wc-check').addEventListener('click', async () => {
  $('wc-check-out').replaceChildren(el('p', 'Checking…', 'muted small'));
  try {
    const r = await call('caddy-check');
    const p = el('div');
    p.append(el('span', r.valid ? 'Valid' : 'Not valid', 'pill ' + (r.valid ? 'ok' : 'bad')));
    if (r.message) p.append(el('pre', r.message, 'changes'));
    $('wc-check-out').replaceChildren(p);
  } catch (err) { $('wc-check-out').replaceChildren(el('p', 'Could not check: ' + errText(err), 'muted')); }
});
$('wc-apply').addEventListener('click', async () => {
  if (!await confirmAction({ title: 'Apply the Web Server Changes?', text: 'The configuration is checked first; if it does not pass, nothing is restarted and your edits stay as they are. Then the web server restarts (every site blips for a second or two) and every site is tested. If a site that worked before stops working, the last good configuration is put back by itself, and your edited files are kept in /var/lib/argus/caddy-history/failed-<time> so nothing is lost.', ok: 'Apply' })) return;
  try { await call('caddy-apply'); watchJob('web', $('wc-job')); } catch (err) { say('Could not apply: ' + errText(err)); }
});
$('wc-files').addEventListener('toggle', async () => {
  if (!$('wc-files').open) return;
  try {
    const files = await call('caddy-show');
    $('wc-files-out').replaceChildren(...files.map((f) => { const d = document.createElement('details'); d.append(el('summary', f.file), el('pre', f.text, 'changes')); return d; }));
  } catch (err) { $('wc-files-out').replaceChildren(el('p', errText(err), 'muted')); }
});
$('wc-hist').addEventListener('toggle', async () => {
  if (!$('wc-hist').open) return;
  try {
    const h = await call('caddy-history');
    $('wc-hist-out').replaceChildren(...(h.length ? h.map((x, i) => { const r = el('div', null, 'card-head'); r.append(el('span', x.stamp.replace(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/, '$1-$2-$3 $4:$5') + (i === 0 ? ' (last applied)' : ''), 'mono'),
      i === 0 ? el('span', '') : button('Roll Back to This', '', async () => {
        if (!await confirmAction({ title: 'Roll the Web Server Configuration Back?', text: `The configuration kept on ${x.stamp} is put back, checked, and the web server restarts (every site blips). If a site that works in both would stop working, the current configuration is put back. Names added since then stop being served (their folders and files stay); the job lists them.`, ok: 'Roll Back' })) return;
        try { await call('caddy-rollback', [x.stamp]); watchJob('web', $('wc-job')); } catch (err) { say('Could not roll back: ' + errText(err)); }
      })); return r; }) : [el('p', 'None kept yet: the first Apply keeps one.', 'muted small')]));
  } catch (err) { $('wc-hist-out').replaceChildren(el('p', errText(err), 'muted')); }
});
for (const r of document.querySelectorAll('input[name="sk"]')) r.addEventListener('change', () => {
  const k = document.querySelector('input[name="sk"]:checked').value;
  $('sa-target-l').hidden = k === 'static';
  $('sa-target-label').textContent = k === 'redirect' ? 'Send visitors to (an https:// address)' : 'Local port the app listens on (for example 8090)';
});
$('sa-go').addEventListener('click', async () => {
  const kind = document.querySelector('input[name="sk"]:checked').value;
  const domain = $('sa-domain').value.trim().toLowerCase().replace(/^www\./, '');
  const target = $('sa-target').value.trim();
  if (!/^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) { say('Give a domain like example.com.'); return; }
  const what = kind === 'static' ? `a website served from /srv/${domain}/public (a "Coming soon" page is put there; upload the real pages on the Files page)`
    : kind === 'redirect' ? `a redirect to ${target}` : `the app on local port ${target}`;
  if (!await confirmAction({ title: `Add ${domain}?`, text: `${domain} and www.${domain} become ${what}. The web server restarts (every site blips). Nothing changes in DNS: Argus shows the records to add at your registrar, and the certificate arrives once they point here.`, ok: 'Add Site' })) return;
  try {
    const r = await call('site-add', kind === 'static' ? [kind, hex(domain)] : [kind, hex(domain), hex(target)]);
    const t = el('table'); const tb = el('tbody');
    for (const d of r.dns) tb.append(row([el('span', d.type, 'mono'), el('span', d.name, 'mono'), el('span', d.value, 'mono')]));
    t.append(tb);
    const box = el('div');
    box.append(el('p', 'Add these records where the domain is registered (or in its DNS host):'), t, el('p', 'No AAAA (IPv6) record: the server has no IPv6 address.', 'muted small'));
    $('sa-dns').replaceChildren(box);
    watchJob('web', $('wc-job'));
  } catch (err) { say('The site was not added: ' + errText(err)); }
});

// ---------- mail ----------
const hex = (s) => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, '0')).join('');
const GiB = 1024 ** 3;
const gbText = (b) => (b >= GiB ? (b / GiB).toFixed(1) + ' GB' : (b / 1024 ** 2).toFixed(0) + ' MB');

function askPassword(title, extra) {
  return new Promise((resolve) => {
    const d = $('pwd');
    $('pwd-title').textContent = title;
    $('pwd-extra').replaceChildren(...(extra ? [extra] : []));
    $('pwd-ok').textContent = 'Continue';
    d.querySelector('input[value="generate"]').checked = true;
    $('pwd-typed').hidden = true;
    $('pwd-input').value = '';
    $('pwd-input2').value = '';
    for (const r of d.querySelectorAll('input[name="pwmode"]')) r.onchange = () => { $('pwd-typed').hidden = r.value !== 'type' || !r.checked; if (!$('pwd-typed').hidden) $('pwd-input').focus(); };
    d.onclose = () => {
      if (d.open) return;
      const typed = $('pwd-input').value, again = $('pwd-input2').value;
      $('pwd-input').value = ''; $('pwd-input2').value = '';
      if (d.returnValue !== 'ok') return resolve(null);
      const gen = d.querySelector('input[value="generate"]').checked;
      if (!gen && typed.length < 12) { say('The password must be 12 characters or more.'); return resolve(null); }
      if (!gen && typed !== again) { say('The two passwords were not the same; nothing was changed.'); return resolve(null); }
      resolve(gen ? 'generate' : typed);
    };
    d.returnValue = 'cancel';
    d.showModal();
  });
}

function showOnce(title, text, secret) {
  return new Promise((resolve) => {
    const d = $('once');
    $('once-title').textContent = title;
    $('once-text').textContent = text;
    $('once-secret').textContent = secret;
    $('once-copy').onclick = () => window.argus.copy(secret, true);
    d.onclose = () => { if (d.open) return; $('once-secret').textContent = ''; resolve(); };
    d.showModal();
  });
}

let mailData = null;
async function loadMail() {
  const loading = () => row([el('span', 'Loading…', 'muted')]);
  $('mb-rows').replaceChildren(loading());
  $('al-rows').replaceChildren(loading());
  $('dm-rows').replaceChildren(el('p', 'Loading…', 'muted'));
  $('mq-rows').replaceChildren(el('p', 'Loading…', 'muted'));
  $('qt-rows').replaceChildren(loading());
  try {
    mailData = await call('mail-overview');
  } catch (err) {
    const msg = 'Could not read the mail server: ' + errText(err);
    for (const id of ['mb-rows', 'al-rows', 'qt-rows']) $(id).replaceChildren(row([el('span', msg, 'muted')]));
    qtHeld = []; qtPicked.clear(); qtUpdate();
    for (const id of ['dm-rows', 'mq-rows']) $(id).replaceChildren(el('p', msg, 'muted'));
    throw err;
  }
  const m = mailData;
  // mailboxes
  $('mb-rows').replaceChildren(...(m.mailboxes || []).map((b) => {
    const pct = b.quota_b ? Math.round((b.used_b / b.quota_b) * 100) : 0;
    const tfa = !m.tfa_known ? el('span', 'Unknown', 'pill unknown') : b.tfa && b.tfa.length ? el('span', 'On', 'pill ok') : el('span', 'Off', 'pill warn');
    const addr = el('div');
    addr.append(el('span', b.username, 'mono'));
    if (b.name) addr.append(el('div', b.name, 'muted small'));
    if (!b.active) addr.append(el('span', 'Disabled', 'pill bad'));
    const btns = button('Manage', '', () => mbManage(b));
    return row([addr, el('span', `${gbText(b.used_b)} of ${b.quota_b ? gbText(b.quota_b) : 'no limit'}${b.quota_b ? ' · ' + pct + '%' : ''}`, 'mono'),
      tfa, el('span', b.app_passwords ? String(b.app_passwords.length) : '?', 'mono'),
      el('span', b.last_login ? new Date(b.last_login * 1000).toLocaleDateString() : 'never', 'mono'), btns]);
  }));
  if (!m.mailboxes) $('mb-rows').replaceChildren(row(['Could not read the mailboxes.', '', '', '', '', '']));
  // aliases
  $('al-rows').replaceChildren(...(m.aliases || []).map((a) => row([
    el('span', a.address, 'mono'),
    (() => { const g = el('div', null, 'goto-list'); for (const t of String(a.goto).split(',').filter(Boolean)) g.append(el('span', t, 'mono')); if (!a.active) g.append(el('span', 'Disabled', 'pill bad')); return g; })(),
    button('Delete', '', async () => {
      if (!await confirmAction({ title: `Delete the Alias ${a.address}?`, text: `Mail to ${a.address} will no longer be forwarded to ${a.goto}; it will bounce unless another alias or mailbox takes it.`, ok: 'Delete Alias' })) return;
      await mailChange('alias-delete', [String(a.id)], `Alias ${a.address} deleted.`);
    })])));
  // domains
  $('dm-rows').replaceChildren(...(m.domains || []).map((d) => {
    const box = el('div', null, 'dns');
    const head = el('div', null, 'card-head');
    head.append(el('strong', d.domain, 'mono'), el('span', `${d.mailboxes} mailboxes · ${d.aliases} aliases`, 'muted small'));
    const out = el('div');
    box.append(head, button('Check Mail Records (SPF, DKIM, DMARC)', '', () => checkDns(d.domain, out)), out);
    return box;
  }));
  // queue
  const q = m.queue;
  $('mq-rows').replaceChildren(q == null ? el('p', 'Could not read the queue.', 'muted')
    : !q.length ? el('p', 'Nothing waiting: all mail has gone out.', 'muted')
    : (() => { const t = el('table'); const tb = el('tbody'); for (const i of q) tb.append(row([el('span', i.sender || '', 'mono'), el('span', (i.recipients || []).join(', '), 'mono'), el('span', i.queue, 'muted'),
        button('Retry Now', '', async () => {
          if (!await confirmAction({ title: 'Retry This Message Now?', text: `The message from ${i.sender} is tried again straight away. Nothing is deleted.`, ok: 'Retry' })) return;
          await mailChange('mailq-deliver', [i.id], 'Message retried.');
        }),
        button('Delete', 'danger', async () => {
          if (!await confirmAction({ title: 'Delete This Message from the Queue?', text: `The message from ${i.sender} will not be delivered. This cannot be undone.`, ok: 'Delete Message' })) return;
          await mailChange('mailq-delete', [i.id], 'Message deleted from the queue.');
        })])); t.append(tb); return t; })());
  $('mq-flush').disabled = !q || !q.length;
  // quarantine: tick several, then release or delete them together
  qtPicked.clear();
  const held = m.quarantine || [];
  $('qt-rows').replaceChildren(...held.map((i) => {
    const pick = el('input');
    pick.type = 'checkbox';
    pick.setAttribute('aria-label', `Select "${i.subject || '(no subject)'}" from ${i.sender}`);
    pick.addEventListener('change', () => { if (pick.checked) qtPicked.add(i.id); else qtPicked.delete(i.id); qtUpdate(); });
    const r = row([pick, el('span', i.sender, 'mono'), el('span', i.rcpt, 'mono'), i.subject || '(no subject)', el('span', String(i.score), 'mono'),
      (() => { const b = el('div', null, 'row-btns'); b.append(
        button('Release', '', () => qtAct('release', [i])),
        button('Delete', '', () => qtAct('delete', [i]))); return b; })()]);
    r.firstChild.className = 'pick';
    return r;
  }));
  qtHeld = held;
  if (m.quarantine && !held.length) $('qt-rows').replaceChildren(row(['', 'Nothing held.', '', '', '', '']));
  qtUpdate();
}

let qtHeld = [];
let qtBusy = false;
const qtPicked = new Set();
function qtUpdate() {
  const n = qtPicked.size;
  $('qt-count').textContent = n ? `${n} selected` : '';
  $('qt-release').disabled = !n || qtBusy;
  $('qt-delete').disabled = !n || qtBusy;
  $('qt-all').checked = n > 0 && n === qtHeld.length;
  $('qt-all').indeterminate = n > 0 && n < qtHeld.length;
  $('qt-all').disabled = !qtHeld.length;
}
$('qt-all').addEventListener('change', () => {
  const on = $('qt-all').checked;
  qtPicked.clear();
  if (on) for (const i of qtHeld) qtPicked.add(i.id);
  for (const c of $('qt-rows').querySelectorAll('input[type="checkbox"]')) c.checked = on;
  qtUpdate();
});
$('qt-release').addEventListener('click', () => qtAct('release', qtHeld.filter((i) => qtPicked.has(i.id))));
$('qt-delete').addEventListener('click', () => qtAct('delete', qtHeld.filter((i) => qtPicked.has(i.id))));

async function qtAct(op, items) {
  if (!items.length) return;
  const one = items.length === 1 ? items[0] : null;
  const what = one ? `"${one.subject || '(no subject)'}" from ${one.sender}` : `${items.length} held messages`;
  const list = el('ul', null, 'pick-list');
  if (!one) for (const i of items.slice(0, 12)) list.append(el('li', `${i.subject || '(no subject)'} — ${i.sender}`));
  if (items.length > 12) list.append(el('li', `and ${items.length - 12} more`, 'muted'));
  const ok = await confirmAction(op === 'release'
    ? { title: one ? 'Release This Message?' : `Release ${items.length} Messages?`, text: `${what} will be delivered to ${one ? one.rcpt : 'their recipients'}. Only release mail you trust: it was held as likely spam or harmful.`, ok: 'Release', extra: one ? null : list }
    : { title: one ? 'Delete This Held Message?' : `Delete ${items.length} Held Messages?`, text: `${what} will be removed for good.`, ok: 'Delete', extra: one ? null : list });
  if (!ok) return;
  let done = 0;
  const failed = [];
  qtBusy = true;
  qtUpdate();
  for (const i of items) {
    say(`${op === 'release' ? 'Releasing' : 'Deleting'} ${done + failed.length + 1} of ${items.length}…`);
    try { await call(op === 'release' ? 'quarantine-release' : 'quarantine-delete', [String(i.id)]); done++; }
    catch (err) { failed.push(`${i.subject || '(no subject)'}: ${errText(err)}`); }
  }
  qtBusy = false;
  try { await loadMail(); } catch { /* the page shows its own error */ }
  qtUpdate();
  const verb = op === 'release' ? 'released' : 'deleted';
  say(failed.length ? `${done} ${verb}; ${failed.length} not: ${failed.slice(0, 3).join('; ')}` : `${done} ${done === 1 ? 'message' : 'messages'} ${verb}.`);
}

// One menu per mailbox instead of a row of buttons.
function mbManage(b) {
  const list = el('div', null, 'menu');
  const item = (label, help, fn, cls) => {
    const x = button(label, cls || '', () => { $('confirm').close('cancel'); fn(b); });
    const r = el('div', null, 'menu-item');
    r.append(x, el('span', help, 'muted small'));
    list.append(r);
  };
  item('Change Password', 'type one, or have one generated and shown once', mbPassword);
  item('App Passwords', `${(b.app_passwords || []).length} now; one per device`, mbApps);
  item('Size Limit', `now ${b.quota_b ? gbText(b.quota_b) : 'no limit'}`, mbSize);
  item(b.active ? 'Disable' : 'Enable', b.active ? 'stops mail and sign-in; keeps everything' : 'lets it receive, send and sign in again', mbActive);
  item('Reset Two-Factor', "opens mailcow's admin pages", mbTfa);
  item('Delete Mailbox', 'removes it and all its mail', mbDelete, 'danger');
  const d = $('confirm');
  $('confirm-title').textContent = b.username;
  $('confirm-text').textContent = b.name || '';
  $('confirm-extra').replaceChildren(list);
  $('confirm-type-label').hidden = true;
  $('confirm-ok').hidden = true;
  d.classList.remove('wide');
  d.onclose = () => { if (!d.open) $('confirm-ok').hidden = false; };
  d.showModal();
}

async function mailChange(action, args, done) {
  try { await call(action, args); say(done); await loadMail(); }
  catch (err) { say('That did not work: ' + errText(err)); }
}

async function mbPassword(b) {
  const pw = await askPassword(`New password for ${b.username}`);
  if (pw == null) return;
  try {
    const r = await window.argus.helperSecret('mailbox-password', [hex(b.username)], pw);
    if (r.password) await showOnce('New password', `The new password for ${b.username}. Mail apps that used the old one stop working until they are given this (or an app password).`, r.password);
    else say(`Password for ${b.username} changed.`);
  } catch (err) { say('The password was not changed: ' + errText(err)); }
}

async function mbSize(b) {
  const v = await ask({ title: `Size Limit for ${b.username}`, label: `In GB (now ${b.quota_b ? gbText(b.quota_b) : 'no limit'}, using ${gbText(b.used_b)})`, ok: 'Set Limit' });
  if (v == null) return;
  const gb = Number(v);
  if (!(gb > 0 && gb <= 1000)) { say('Give the size in GB, for example 5.'); return; }
  if (gb * GiB < b.used_b) { say(`That is smaller than what ${b.username} already uses.`); return; }
  await mailChange('mailbox-set', [hex(b.username), 'quota', String(Math.round(gb * 1024))], `Size limit for ${b.username} set to ${gb} GB.`);
}

async function mbActive(b) {
  const off = b.active;
  if (!await confirmAction({ title: `${off ? 'Disable' : 'Enable'} ${b.username}?`,
    text: off ? 'It stops receiving and sending mail and cannot sign in. Its mail is kept, and enabling it again restores everything.' : 'It can receive, send and sign in again.',
    ok: off ? 'Disable' : 'Enable' })) return;
  await mailChange('mailbox-set', [hex(b.username), off ? 'inactive' : 'active'], `${b.username} ${off ? 'disabled' : 'enabled'}.`);
}

async function mbTfa(b) {
  if (!await confirmAction({ title: 'Reset Two-Factor in mailcow', text: `mailcow's API cannot reset two-factor, so this opens mailcow's admin pages in your browser. Sign in there, open the mailbox ${b.username} and remove its two-factor key; its owner then sets it up again in webmail.`, ok: 'Open mailcow Admin' })) return;
  window.argus.openMailAdmin();
}

async function mbDelete(b) {
  if (!await confirmAction({ title: `Delete ${b.username}?`,
    text: `The mailbox and all ${b.messages} of its messages (${gbText(b.used_b)}) are deleted. This cannot be undone except from a backup. Mail sent to it afterwards bounces.`,
    ok: 'Delete Mailbox', word: b.username })) return;
  await mailChange('mailbox-delete', [hex(b.username)], `${b.username} deleted.`);
}

async function mbApps(b) {
  const list = el('div');
  const apps = b.app_passwords || [];
  if (!apps.length) list.append(el('p', 'No app passwords yet.', 'muted'));
  for (const a of apps) {
    const r = el('div', null, 'card-head');
    r.append(el('span', `${a.name}${a.created ? ' · made ' + a.created : ''}`), button('Revoke', 'danger', async () => {
      $('confirm').close('cancel');
      if (!await confirmAction({ title: `Revoke "${a.name}"?`, text: `The device using it can no longer get or send mail for ${b.username}. Its owner's other devices are not affected.`, ok: 'Revoke' })) return;
      await mailChange('app-passwd-delete', [String(a.id)], `App password "${a.name}" revoked.`);
    }));
    list.append(r);
  }
  const ok = await confirmAction({ title: `App Passwords for ${b.username}`, text: 'One per device (phone, laptop, mail app). Make a new one for each device; revoke it if the device is lost.', ok: 'Make a New One', extra: list });
  if (!ok) return;
  const name = await ask({ title: 'New App Password', label: 'Which device is it for? (for example "Matt\'s phone")', ok: 'Make It' });
  if (!name) return;
  try {
    const r = await call('app-passwd-add', [hex(b.username), hex(name)]);
    await showOnce(`App password for ${name}`, `Use this, with ${b.username} as the user name, in the mail app on ${name}.`, r.password);
    await loadMail();
  } catch (err) { say('No app password was made: ' + errText(err)); }
}

$('mb-new').addEventListener('click', async () => {
  const domains = (mailData?.domains || []).map((d) => d.domain);
  const addr = await ask({ title: 'New Mailbox', label: `Full address (domains: ${domains.join(', ')})`, ok: 'Next' });
  if (!addr) return;
  const m = addr.trim().toLowerCase().match(/^([a-z0-9._%+-]{1,64})@([a-z0-9.-]+)$/);
  if (!m || !domains.includes(m[2])) { say('Use a full address on one of these domains: ' + domains.join(', ')); return; }
  const name = await ask({ title: `Name for ${addr}`, label: 'Person or purpose shown with the address (optional)', ok: 'Next' });
  if (name == null) return;
  const gb = Number(await ask({ title: `Size Limit for ${addr}`, label: 'In GB, for example 5', ok: 'Next' }));
  if (!(gb > 0 && gb <= 1000)) { say('Give the size in GB, for example 5.'); return; }
  const pw = await askPassword(`Password for ${addr}`);
  if (pw == null) return;
  try {
    const r = await window.argus.helperSecret('mailbox-add', [hex(m[1]), hex(m[2]), String(Math.round(gb * 1024)), name ? hex(name) : '00'], pw);
    if (r.password) await showOnce(`Password for ${r.mailbox}`, 'Give this to the mailbox owner. They should set up two-factor in webmail after their first sign-in.', r.password);
    else say(`${r.mailbox} created.`);
    await loadMail();
  } catch (err) { say('The mailbox was not created: ' + errText(err)); }
});

$('al-new').addEventListener('click', async () => {
  const addr = await ask({ title: 'New Alias', label: 'The address that receives mail (for example sales@blksheepltd.com, or @domain for a catch-all)', ok: 'Next' });
  if (!addr) return;
  const goto = await ask({ title: `Where Should ${addr} Go?`, label: 'One or more addresses, separated by commas', ok: 'Next' });
  if (!goto) return;
  if (!await confirmAction({ title: `Create ${addr}?`, text: `Mail to ${addr} will be delivered to ${goto}.`, ok: 'Create Alias' })) return;
  await mailChange('alias-add', [hex(addr.trim().toLowerCase()), hex(goto)], `Alias ${addr} created.`);
});

$('mq-flush').addEventListener('click', async () => {
  if (!await confirmAction({ title: 'Retry the Queue Now?', text: 'Every waiting message is tried again straight away. Nothing is deleted.', ok: 'Retry All' })) return;
  await mailChange('mailq-flush', [], 'Queue retried.');
});

async function checkDns(domain, out) {
  out.replaceChildren(el('p', 'Looking up the public records…', 'muted small'));
  try {
    const dk = await call('mail-dkim', [hex(domain)]);
    const r = await window.argus.dnsCheck(domain, dk.selector);
    const line = (ok, label, text) => { const d = el('div', null, 'dns-line'); d.append(el('span', ok === null ? 'Unknown' : ok ? 'OK' : 'Problem', 'pill ' + (ok === null ? 'unknown' : ok ? 'ok' : 'bad')), el('strong', label), el('span', text, 'mono')); return d; };
    const pubWanted = (dk.txt || '').replace(/\s/g, '').match(/p=([^;]+)/)?.[1];
    const dkimFound = (r.dkim || []).map((t) => t.replace(/\s/g, '').match(/p=([^;]+)/)?.[1]).filter(Boolean);
    const host = (mailData && mailData.hostname) || 'mail.blksheepltd.com';
    const mxOk = r.mx == null ? null : r.mx.some((x) => x.toLowerCase() === host || x.toLowerCase() === 'mail.' + domain);
    // SPF must exist once and must actually allow this server (mx, a:<host>, or an include).
    const spfAllows = (t) => /\s\+?(mx|a)(\s|:|\/|$)|\s(include:|ip4:|ip6:)/i.test(' ' + t);
    out.replaceChildren(
      line(mxOk, 'MX', r.mx == null ? 'could not look up' : (r.mx.join(', ') || 'none') + (mxOk === false ? ` (should be ${host})` : '')),
      line(r.spf == null ? null : r.spf.length === 1 && spfAllows(r.spf[0]), 'SPF', r.spf == null ? 'could not look up' : r.spf.length > 1 ? 'more than one SPF record: keep only one' : r.spf.length ? (spfAllows(r.spf[0]) ? r.spf[0] : r.spf[0] + ' (does not allow this server: add mx)') : 'missing: add a TXT record "v=spf1 mx -all"'),
      line(!pubWanted ? null : dkimFound.includes(pubWanted), 'DKIM', !pubWanted ? 'mailcow has no DKIM key for this domain' : dkimFound.includes(pubWanted) ? `${dk.selector}._domainkey matches mailcow's key` : `${dk.selector}._domainkey.${domain} should be: ${dk.txt}`),
      line(r.dmarc == null ? null : r.dmarc.length === 1, 'DMARC', r.dmarc == null ? 'could not look up' : r.dmarc.length ? r.dmarc.join(' | ') : `missing: add a TXT record at _dmarc.${domain}, for example "v=DMARC1; p=quarantine"`),
    );
  } catch (err) { out.replaceChildren(el('p', 'Could not check: ' + errText(err), 'muted small')); }
}

// ---------- terminal ----------
let term = null, fit = null, termLive = false, termGen = 0, termOpening = false;

function termState(text, cls) {
  $('term-state').textContent = text;
  $('term-state').className = 'pill ' + cls;
}

function ensureXterm() {
  if (term) return;
  term = new window.Terminal({
    cursorBlink: true,
    fontFamily: '"Cascadia Mono", Consolas, monospace',
    fontSize: 14,
    scrollback: 5000,
    theme: { background: '#0A131B', foreground: '#E4ECEF', cursor: '#3FB8AF', selectionBackground: '#1F4057' },
  });
  fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('term'));
  term.onData(sendToShell);
  let resizeTimer = null;
  term.onResize(({ cols, rows }) => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (termLive) window.argus.termResize(cols, rows).catch(() => {}); }, 150);
  });
  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== 'keydown' || !e.ctrlKey || !e.shiftKey) return true;
    if (e.code === 'KeyC') { if (term.hasSelection()) window.argus.copy(term.getSelection()); return false; }
    if (e.code === 'KeyV') return false; // the browser's own paste event delivers the text
    return true;
  });
  new ResizeObserver(() => { if (!$('view-terminal').hidden) fit.fit(); }).observe($('term'));
}

// Large pastes go in pieces small enough for the native side (64 KB).
// Keystrokes are queued so they always reach the server in the order typed.
let sendQueue = Promise.resolve();
function sendToShell(d) {
  if (!termLive) return;
  sendQueue = sendQueue.then(async () => {
    try {
      for (let i = 0; i < d.length;) {
        let end = Math.min(i + 8192, d.length);
        // Never split a character that takes two UTF-16 units (emoji etc.).
        if (end < d.length && /[\uD800-\uDBFF]/.test(d[end - 1])) end -= 1;
        await window.argus.termWrite(d.slice(i, end));
        i = end;
      }
    } catch (err) {
      term.write('\r\n[Argus: could not send that: ' + errText(err) + ']\r\n');
    }
  });
}

async function openTerminal(fresh) {
  if (termOpening) return;
  ensureXterm();
  fit.fit();
  term.focus();
  if (termLive && !fresh) return;
  const gen = ++termGen;
  termLive = false;
  if (fresh) term.reset();
  termState('Opening…', 'unknown');
  termOpening = true;
  try {
    await window.argus.termOpen(term.cols, term.rows);
  } catch (err) {
    if (gen === termGen) {
      termState('Not open', 'bad');
      term.write('\r\nCould not open a terminal: ' + errText(err) + '\r\n');
    }
    return;
  } finally {
    termOpening = false;
  }
  if (gen !== termGen) return;
  termLive = true;
  termState('Connected', 'ok');
  while (gen === termGen) {
    let chunk;
    try { chunk = await window.argus.termRead(); } catch { chunk = null; }
    if (gen !== termGen) return;
    if (chunk === null) {
      termLive = false;
      termState('Ended', 'unknown');
      term.write('\r\n[The session has ended. Press "New session" to open another.]\r\n');
      return;
    }
    if (chunk.length) await new Promise((resolve) => term.write(chunk, resolve));
  }
}
$('term-new').addEventListener('click', () => openTerminal(true));

function closeTerminal() {
  termGen++;
  termLive = false;
  if (term) term.reset();
  termState('Not open', 'unknown');
  window.argus.termClose().catch(() => {});
}

for (const b of document.querySelectorAll('dialog [data-cancel]')) {
  b.addEventListener('click', () => b.closest('dialog').close('cancel'));
}

// ---------- files ----------
const pc = { path: null, sel: null, entries: [] };
const srv = { path: '/srv', sel: null, entries: [] };

function ask({ title, label, ok }) {
  return new Promise((resolve) => {
    const d = $('ask');
    $('ask-title').textContent = title;
    $('ask-label').textContent = label;
    $('ask-ok').textContent = ok;
    $('ask-input').value = '';
    d.onclose = () => { if (!d.open) resolve(d.returnValue === 'ok' ? $('ask-input').value.trim() : null); };
    d.returnValue = 'cancel';
    d.showModal();
    $('ask-input').focus();
  });
}

function modeText(m) {
  const r = (b, c) => (m & b ? c : '-');
  let s = '';
  for (const shift of [6, 3, 0]) s += r(4 << shift, 'r') + r(2 << shift, 'w') + r(1 << shift, 'x');
  return '0' + (m & 0o7777).toString(8).padStart(3, '0') + ' ' + s;
}
function sizeText(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function when(t) {
  return t ? new Date(t * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : '';
}

// ---------- previews ----------
const IMAGE_TYPES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', ico: 'image/x-icon', svg: 'image/svg+xml', avif: 'image/avif' };
const PEEK_MAX = 5 * 1024 * 1024;
const isImage = (name) => !!IMAGE_TYPES[(name.split('.').pop() || '').toLowerCase()];

function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768));
  return btoa(s);
}

// What a file looks like: the picture, the first lines of text, or neither.
function previewNode(peek, name) {
  const box = el('div', null, 'pv');
  const bytes = peek.data instanceof Uint8Array ? peek.data : new Uint8Array(peek.data);
  const ext = (name.split('.').pop() || '').toLowerCase();
  box.append(el('span', `${sizeText(peek.size)} · modified ${when(peek.mtime) || 'unknown'}`, 'pv-info'));
  if (IMAGE_TYPES[ext]) {
    if (peek.size > PEEK_MAX) {
      box.append(el('span', 'Too large to preview.', 'muted small'));
    } else {
      const img = document.createElement('img');
      img.alt = 'Preview of ' + name;
      img.src = `data:${IMAGE_TYPES[ext]};base64,${toBase64(bytes)}`;
      img.onerror = () => img.replaceWith(el('span', 'This image could not be shown.', 'muted small'));
      img.onload = () => box.append(el('span', `${img.naturalWidth} × ${img.naturalHeight} pixels`, 'pv-info'));
      box.append(img);
    }
    return box;
  }
  const head = bytes.subarray(0, 8192);
  if (head.length && !head.includes(0)) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 16384));
    box.append(el('pre', text.split('\n').slice(0, 30).join('\n')));
  } else if (head.length) {
    box.append(el('span', 'No preview for this kind of file.', 'muted small'));
  } else {
    box.append(el('span', 'The file is empty.', 'muted small'));
  }
  return box;
}

const previewGen = { pc: 0, srv: 0 };
async function showPreview(side, e) {
  const key = side === pc ? 'pc' : 'srv';
  const box = $(key + '-preview');
  const gen = ++previewGen[key];
  if (!e || e.kind !== 'file') { box.hidden = true; return; }
  box.hidden = false;
  box.replaceChildren(el('span', 'Loading preview…', 'muted small'));
  try {
    const p = childPath(side, e.name);
    const peek = side === pc ? await window.argus.localPeek(p, isImage(e.name)) : await window.argus.filesPeek(p, isImage(e.name));
    if (gen === previewGen[key]) box.replaceChildren(previewNode(peek, e.name));
  } catch (err) {
    if (gen === previewGen[key]) box.replaceChildren(el('span', 'No preview: ' + errText(err), 'muted small'));
  }
}

function fileRow(e, side) {
  const r = el('div', null, 'frow');
  r.draggable = e.kind === 'file';
  const name = el('span', e.name, 'fname' + (e.kind === 'dir' ? ' dir' : ''));
  const meta = el('span', e.kind === 'file' ? sizeText(e.size) : e.kind === 'link' ? 'link' : '', 'meta');
  r.append(name, meta);
  if (side === srv) r.append(el('span', `${e.owner}:${e.group}  ${modeText(e.mode)}  ${when(e.mtime)}`, 'meta2'));
  else if (e.mtime) r.append(el('span', when(e.mtime), 'meta2'));
  r.addEventListener('click', () => select(side, e, r));
  r.addEventListener('dblclick', () => {
    if (e.kind === 'dir' || (side === srv && e.kind === 'link')) navigate(side, childPath(side, e.name));
  });
  r.addEventListener('dragstart', (ev) => {
    ev.dataTransfer.setData('application/x-argus', JSON.stringify({ from: side === pc ? 'pc' : 'srv', name: e.name, path: childPath(side, e.name) }));
    ev.dataTransfer.effectAllowed = 'copy';
  });
  return r;
}

function childPath(side, name) {
  if (side === srv) return (srv.path === '/' ? '' : srv.path) + '/' + name;
  return pc.path === '' ? name : pc.path.replace(/[\\/]+$/, '') + '\\' + name;
}

function select(side, e, row) {
  side.sel = e;
  const list = side === pc ? $('pc-list') : $('srv-list');
  for (const x of list.children) x.classList.toggle('sel', x === row);
  updateFileButtons();
  showPreview(side, e);
}
function updateFileButtons() {
  $('do-upload').disabled = !(pc.sel && pc.sel.kind === 'file');
  $('do-download').disabled = !(srv.sel && srv.sel.kind === 'file' && pc.path);
  $('pc-sel').textContent = pc.sel ? pc.sel.name : '';
  $('srv-sel').textContent = srv.sel ? srv.sel.name : '';
}

async function navigate(side, path) {
  try {
    if (side === pc) {
      const r = await window.argus.localList(path);
      pc.path = r.path; pc.parent = r.parent; pc.entries = r.entries; pc.sel = null;
      $('pc-path').value = r.path || 'This PC (drives)';
      $('pc-list').replaceChildren(...r.entries.map((e) => fileRow(e, pc)));
      showPreview(pc, null);
    } else {
      const r = await window.argus.filesList(path);
      srv.path = r.path; srv.entries = r.entries; srv.sel = null;
      $('srv-path').value = r.path;
      $('srv-web').hidden = !isPublicWeb(r.path);
      $('srv-list').replaceChildren(...r.entries.map((e) => fileRow(e, srv)));
      showPreview(srv, null);
    }
    updateFileButtons();
    say('');
  } catch (err) {
    say('Could not open that folder: ' + errText(err));
    if (side === pc) $('pc-path').value = pc.path ?? ''; else $('srv-path').value = srv.path;
  }
}
// Same rule as the server side (files.rs is_public_web).
function isPublicWeb(p) {
  const x = p + '/';
  return x.startsWith('/var/www/') || (x.startsWith('/srv/') && ['/public/', '/public_html/', '/htdocs/', '/html/', '/www/'].some((s) => x.includes(s)));
}

let filesStarted = false;
async function openFiles() {
  if (!filesStarted) {
    filesStarted = true;
    await navigate(pc, await window.argus.localHome());
    await navigate(srv, srv.path);
  } else {
    await navigate(srv, srv.path);
  }
}

$('pc-up').addEventListener('click', () => { if (pc.path) navigate(pc, pc.parent ?? ''); });
$('srv-up').addEventListener('click', () => { if (srv.path !== '/') navigate(srv, srv.path.replace(/\/[^/]+$/, '') || '/'); });
$('pc-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') navigate(pc, $('pc-path').value.trim()); });
$('srv-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') navigate(srv, $('srv-path').value.trim()); });

async function upload(localPath, name) {
  const dir = srv.path; // the folder on screen when the upload started
  let plan, local;
  try {
    local = await window.argus.localStat(localPath);
    if (local.kind !== 'file') { say(`${name} is a folder; only files can be uploaded for now.`); return; }
    plan = await window.argus.filesPlan(dir, name);
  } catch (err) { say('Cannot upload: ' + errText(err)); return; }

  const box = el('div');
  // Side by side: what is on the server now, and what will replace it.
  const compare = el('div', null, 'compare');
  const mine = el('div');
  mine.append(el('h3', 'From This PC'), el('span', 'Loading preview…', 'muted small'));
  const theirs = el('div');
  if (plan.exists) {
    theirs.append(el('h3', 'On the Server Now'), el('span', 'Loading preview…', 'muted small'));
    compare.append(theirs, mine);
  } else {
    compare.append(mine);
    compare.style.gridTemplateColumns = '1fr';
  }
  box.append(compare);
  window.argus.localPeek(localPath, isImage(name)).then((pk) => mine.lastChild.replaceWith(previewNode(pk, name)),
    (err) => mine.lastChild.replaceWith(el('span', 'No preview: ' + errText(err), 'muted small')));
  if (plan.exists) {
    window.argus.filesPeek(plan.target, isImage(name)).then((pk) => theirs.lastChild.replaceWith(previewNode(pk, name)),
      (err) => theirs.lastChild.replaceWith(el('span', 'No preview: ' + errText(err), 'muted small')));
  }

  const dl = el('dl', null, 'plan');
  const add = (k, v) => dl.append(el('dt', k), el('dd', v));
  add('To', plan.target);
  add('Owner', `${plan.owner}:${plan.group}`);
  add('Permissions', `${modeText(plan.mode)} (${plan.mode_from})`);
  if (plan.exists) add('Old file', `replaced; a copy is kept in ${plan.backup_to}`);
  box.append(dl);
  if (plan.public_web) box.append(el('p', 'This folder is served by a website: anyone will be able to see this file.', 'warn-text'));
  const ok = await confirmAction({
    title: plan.exists ? `Replace ${name} on the server?` : `Upload ${name}?`,
    text: plan.exists ? 'A file with this name is already there. Check the two previews before replacing it.' : 'The file is copied to the server.',
    ok: plan.exists ? 'Replace it' : 'Upload',
    extra: box,
    wide: true,
  });
  if (!ok) return;
  say(`Uploading ${name}…`);
  try {
    const r = await window.argus.filesUpload(localPath, { ...plan, name });
    say(`${name} uploaded${r.backup ? '; the old copy is in ' + r.backup : ''}.`);
    if (srv.path === dir) await navigate(srv, dir);
  } catch (err) { say(`Upload of ${name} failed: ` + errText(err)); }
}

async function download(remotePath, name) {
  if (!pc.path) { say('Choose a folder on this PC first.'); return; }
  say(`Downloading ${name}…`);
  try {
    let r;
    try {
      r = await window.argus.filesDownload(remotePath, pc.path, false);
    } catch (err) {
      if (!errText(err).startsWith('EXISTS')) throw err;
      const ok = await confirmAction({ title: `Replace ${name} on This PC?`, text: `${pc.path} already has a file called ${name}. It will be replaced.`, ok: 'Replace It' });
      if (!ok) { say(''); return; }
      r = await window.argus.filesDownload(remotePath, pc.path, true);
    }
    say(`${name} downloaded (${sizeText(r.bytes)}).${r.logged ? '' : ' (It could not be written to the Activity log.)'}`);
    await navigate(pc, pc.path);
  } catch (err) { say(`Download of ${name} failed: ` + errText(err)); }
}

$('do-upload').addEventListener('click', () => { if (pc.sel) upload(childPath(pc, pc.sel.name), pc.sel.name); });
$('do-download').addEventListener('click', () => { if (srv.sel) download(childPath(srv, srv.sel.name), srv.sel.name); });
$('srv-mkdir').addEventListener('click', async () => {
  const name = await ask({ title: 'New Folder', label: `Name of the new folder in ${srv.path}`, ok: 'Create' });
  if (!name) return;
  const dir = srv.path;
  try { await window.argus.filesMkdir(dir, name); if (srv.path === dir) await navigate(srv, dir); }
  catch (err) { say('Could not create the folder: ' + errText(err)); }
});

for (const [paneId, side] of [['pane-pc', pc], ['pane-srv', srv]]) {
  const pane = $(paneId);
  pane.addEventListener('dragover', (e) => { e.preventDefault(); pane.classList.add('drop'); });
  pane.addEventListener('dragleave', () => pane.classList.remove('drop'));
  pane.addEventListener('drop', async (e) => {
    e.preventDefault();
    pane.classList.remove('drop');
    const internal = e.dataTransfer.getData('application/x-argus');
    if (internal) {
      const d = JSON.parse(internal);
      if (side === srv && d.from === 'pc') await upload(d.path, d.name);
      if (side === pc && d.from === 'srv') await download(d.path, d.name);
      return;
    }
    if (side === srv) {
      for (const f of e.dataTransfer.files) {
        const p = window.argus.pathForFile(f);
        if (p) await upload(p, f.name);
      }
    }
  });
}

// ---------- reload / restart / exit ----------
$('app-reload').addEventListener('click', () => window.argus.appControl('reload'));
$('app-restart').addEventListener('click', async () => {
  const ok = await confirmAction({ title: 'Restart Argus?',
    text: 'Argus signs out, closes and opens again with any changes. Sign in again with your passphrase and a fresh code.', ok: 'Restart Argus' });
  if (ok) window.argus.appControl('restart');
});
$('app-exit').addEventListener('click', async () => {
  const ok = await confirmAction({ title: 'Exit Argus?', text: 'Argus signs out and closes.', ok: 'Exit' });
  if (ok) window.argus.appControl('exit');
});

async function enterDashboard() {
  stop();
  show('dash');
  $('conn-detail').textContent = (await window.argus.label()) + ' · key and code · server key matched';
  await refresh();
  timer = setInterval(refresh, REFRESH_MS);
}

// ---------- start ----------
window.argus.label().then((l) => { $('who').textContent = `Signing in as ${l}.`; });
// A shell left from before a Reload has no reader any more: close it.
window.argus.termClose().catch(() => {});
// After a Reload the connection is still up, so go straight back to the dashboard.
window.argus.connected().then((on) => (on ? enterDashboard() : signinStep('pass')), () => signinStep('pass'));
