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
  clearIdleLock();
  forgetHelperUpdate();
}

// ---------- idle lock ----------
// After 30 minutes with no user activity, lock: drop the connection and return to sign-in
// (a fresh passphrase + code is required). The SSH link itself no longer idles out - liveness
// is handled by keepalives - so this app-level lock is the only thing that ends an idle session,
// by design: it separates "user walked away" (this) from "network died" (keepalives).
const IDLE_MS = 30 * 60 * 1000;
let idleTimer = null;
function armIdleLock() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lockForIdle, IDLE_MS);
}
function clearIdleLock() {
  if (idleTimer !== null) clearTimeout(idleTimer);
  idleTimer = null;
}
async function teardownToSignIn(message) {
  // Real teardown (not a UI swap): kill timers, close the shell, drop the SSH session,
  // and return to the passphrase + code screen so a fresh sign-in is required.
  stop();
  closeTerminal();
  lastStatus = null;
  showView('dashboard');
  try { await window.argus.disconnect(); } catch { /* returning to sign-in regardless */ }
  signinStep('pass', message);
}
function lockForIdle() {
  return teardownToSignIn('Argus locked after 30 minutes of inactivity. Sign in again.');
}
// Real user activity rearms the timer, but only while signed in (i.e. while it is armed).
for (const ev of ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart']) {
  document.addEventListener(ev, () => { if (idleTimer !== null) armIdleLock(); }, { passive: true, capture: true });
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
    checkHelperUpdate();
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

// ---------- server helper update ----------
// Shown only while D:\Argus\helper-update\argus-helper.new exists and differs from the installed helper.
// The installed helper's hash is asked again when the PC file changes, every 5 minutes, and after an install;
// after a failed ask (an older helper without helper-hash), only every 10 minutes.
let helperServerSha = null;
let helperServerAt = 0;
let helperServerFailedAt = 0;
let helperUpdate = null;
let helperChecking = false;
let helperRecheck = false;
async function checkHelperUpdate(force) {
  if (helperChecking) { helperRecheck = helperRecheck || !!force; return; }
  helperChecking = true;
  try {
    const before = helperUpdate && helperUpdate.sha256;
    try { helperUpdate = await window.argus.helperUpdateLocal(); } catch { helperUpdate = null; }
    const now = Date.now();
    const changed = !!helperUpdate && helperUpdate.sha256 !== before;
    const due = force || changed || (!helperServerSha && now - helperServerFailedAt > 10 * 60 * 1000)
      || (helperServerSha && now - helperServerAt > 5 * 60 * 1000);
    if (helperUpdate && due) {
      try {
        const r = await window.argus.helper('helper-hash', []);
        helperServerSha = r && typeof r.sha256 === 'string' ? r.sha256 : null;
        helperServerAt = now;
      } catch {
        helperServerSha = null;
        helperServerFailedAt = now;
      }
    }
  } finally {
    helperChecking = false;
  }
  showHelperUpdate();
  if (helperRecheck) { helperRecheck = false; checkHelperUpdate(true); }
}
function showHelperUpdate() {
  const show = !!(helperUpdate && helperServerSha && helperUpdate.sha256 !== helperServerSha);
  $('helper-update').hidden = !show;
  if (show) {
    $('helper-update-text').textContent = `${helperUpdate.path} (${(helperUpdate.size / 1024).toFixed(0)} KB) differs from the helper on the server. `
      + `New ${helperUpdate.sha256.slice(0, 12)}…, installed ${helperServerSha.slice(0, 12)}….`;
  }
}
function forgetHelperUpdate() {
  helperServerSha = null;
  helperServerAt = 0;
  helperServerFailedAt = 0;
  $('helper-update').hidden = true;
}
$('helper-update-install').addEventListener('click', async () => {
  const u = helperUpdate;
  if (!u) return;
  // The confirmation is a Windows dialog from the main process, showing the full hash.
  $('helper-update-install').disabled = true;
  say('Waiting for you to confirm the helper install…');
  let cancelled = false;
  try {
    const r = await window.argus.helperInstall(u.sha256);
    if (r && r.cancelled) { cancelled = true; say(''); return; }
    helperServerSha = r.installed;
    helperServerAt = Date.now();
    showHelperUpdate();
    say(`The new helper is installed (${String(r.installed).slice(0, 12)}…). The previous one was kept as ${r.backup}.`);
  } catch (err) {
    const m = errText(err);
    say(/took too long/.test(m)
      ? 'The server did not say in time whether the helper was installed. Argus is checking the installed helper now.'
      : 'The helper was not installed: ' + m);
  } finally {
    $('helper-update-install').disabled = false;
    if (!cancelled) await checkHelperUpdate(true);
  }
});

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
    if (reboot) issues.push(['The server needs a restart to finish an update.', 'updates', 'Go to Restart', 'reboot']);
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
    if (health && health !== 'healthy') issues.push([`Hephaestus reports ${health}.`, 'deploy', 'Go to Hephaestus']);
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
    if (sec) issues.push([`${sec} security ${sec === 1 ? 'update is' : 'updates are'} waiting.`, 'updates', 'Go to Updates', 'upd-apply']);
    return tile('Updates', sec == null ? UNK_PILL : sec ? ['warn', `${sec} security`] : ['ok', 'No security updates'], [
      ['Waiting', waiting],
      ['Security', sec],
    ]);
  }],
  ['Sign-ins', (s) => {
    const si = obj(s.signins); if (!si) return null;
    const acc = num(si.accepted_24h), ref = num(si.refused_24h);
    const t = tile('Sign-Ins', ref == null ? UNK_PILL : ref > 0 ? ['warn', 'Bots knocking'] : ['ok', 'Quiet'], [
      ['Accepted, 24 h', acc],
      ['Refused, 24 h', ref],
    ]);
    t.append(button('See Where They Come From', '', () => goTo('signins')));
    return t;
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
// Sidebar areas and the pages (tabs) in each. The first page is what a click on the area opens.
const GROUPS = {
  overview: { tabs: [['dashboard', 'Dashboard']] },
  server: { tabs: [['server', 'Services'], ['updates', 'Updates'], ['databases', 'Databases'], ['backups', 'Backups'], ['signins', 'Sign-In Attempts']] },
  web: { tabs: [['web', 'Sites'], ['caddy', 'Caddy']] },
  mail: { tabs: [['mail', 'Mailboxes'], ['accounts', 'Accounts']] },
  hephaestus: { tabs: [['deploy', 'Deploy'], ['rollback', 'Roll Back']] },
  tools: { tabs: [['files', 'Files'], ['terminal', 'Terminal'], ['activity', 'Activity Log']] },
};
const VIEW_GROUP = {};
for (const [g, def] of Object.entries(GROUPS)) for (const [v] of def.tabs) VIEW_GROUP[v] = g;
const VIEWS = Object.keys(VIEW_GROUP);

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

// The name typed into the last confirmation that was accepted, with spaces at the ends removed. The helper
// checks it again on the server, so the typed name is sent with the action, not just the name shown.
let lastTyped = '';

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
    // Spaces at either end of a pasted name are ignored; the name itself must match exactly.
    $('confirm-type').oninput = () => { $('confirm-ok').disabled = $('confirm-type').value.trim() !== word; };
    // A close event left over from the dialog's previous use arrives after it
    // has reopened; only a real close (dialog no longer open) counts.
    d.onclose = () => {
      if (d.open) return;
      if (d.returnValue === 'ok') lastTyped = $('confirm-type').value.trim();
      resolve(d.returnValue === 'ok');
    };
    d.returnValue = 'cancel';
    d.showModal();
    (word ? $('confirm-type') : d.querySelector('button[value="cancel"]')).focus();
  });
}

function titleOf(v) {
  if (v === 'dashboard') return 'Everything at a Glance';
  const tab = GROUPS[VIEW_GROUP[v]].tabs.find(([view]) => view === v);
  return tab ? tab[1] : '';
}
// The top tabs for the area that holds this page.
function showTabs(group, v) {
  const tabs = GROUPS[group].tabs;
  const bar = $('subtabs');
  bar.hidden = tabs.length < 2;
  bar.replaceChildren(...tabs.map(([view, label]) => {
    const b = el('button', label, 'subtab');
    b.type = 'button';
    if (view === v) b.setAttribute('aria-current', 'page');
    b.addEventListener('click', () => showView(view));
    return b;
  }));
}
function showView(v) {
  currentView = v;
  const group = VIEW_GROUP[v];
  $('page-title').textContent = titleOf(v);
  $('refreshed').hidden = v !== 'dashboard';
  for (const name of VIEWS) $('view-' + name).hidden = name !== v;
  for (const b of document.querySelectorAll('button.nav')) {
    const on = b.dataset.group === group;
    b.classList.toggle('current', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  }
  showTabs(group, v);
  $('attention').hidden = v !== 'dashboard' || $('attention-list').children.length === 0;
  say('');
  return loadView(v);
}
// A sidebar click opens the area's first page.
for (const b of document.querySelectorAll('button.nav')) b.addEventListener('click', () => showView(GROUPS[b.dataset.group].tabs[0][0]));

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
    if (v === 'server' || v === 'updates') await loadServer();
    else if (v === 'backups') await loadBackups();
    else if (v === 'databases') await loadDatabases();
    else if (v === 'deploy' || v === 'rollback') await loadHephaestus();
    else if (v === 'activity') await loadActivity();
    else if (v === 'terminal') await openTerminal(false);
    else if (v === 'files') await openFiles();
    else if (v === 'mail') await loadMail();
    else if (v === 'web' || v === 'caddy') await loadWeb();
    else if (v === 'accounts') await loadAccounts();
    else if (v === 'signins') await loadSignins();
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
    const held = pkgs.filter((p) => p.why === 'held-back').length;
    const other = pkgs.length - high - medium - low - held;
    const summary = [high && `${high} high`, medium && `${medium} medium`, low && `${low} low`, other && `${other} not rated`, held && `${held} held back`].filter(Boolean).join(', ');
    const advice = high ? 'Apply soon: at least one fixes a security problem or is marked urgent.'
      : medium ? 'Time-sensitive fixes. Apply when convenient, within a few days.'
      : 'Routine. These can wait for your next update round.';
    const rows = pkgs.map((p) => {
      const nameCell = el('td');
      nameCell.append(el('strong', p.name, 'mono'));
      if (p.description) nameCell.append(el('div', p.description, 'muted small'));
      if (p.changes && p.changes.length) {
        const d = document.createElement('details');
        d.append(el('summary', 'What this update changes'), el('pre', p.changes.join('\n'), 'changes'));
        nameCell.append(d);
      }
      const version = p.why === 'held-back' ? 'Held back by apt' : `${p.from || '?'} → ${p.to}`;
      return row([nameCell, version, levelPill(p), p.source || '']);
    });
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const h of ['Package', 'Version', 'Priority', 'Source']) {
      const th = el('th', h);
      th.scope = 'col';
      headRow.append(th);
    }
    thead.append(headRow);
    const table = el('table');
    const tbody = el('tbody');
    tbody.append(...rows);
    table.append(thead, tbody);
    const tableWrap = el('div', null, 'table-wrap');
    tableWrap.append(table);
    list.replaceChildren(el('p', `${pkgs.length} waiting: ${summary}.`), el('p', advice, high ? 'warn-text' : 'muted'), tableWrap);
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
  // Updates first, then the rest; alphabetical inside each group.
  const rank = (x) => ({ update: 0, newer: 1, unknown: 2, own: 3, current: 4 })[x?.status] ?? 5;
  const ordered = [...running].sort((a, b) => rank(byName.get(a)) - rank(byName.get(b)) || a.localeCompare(b));
  $('svc-rows').replaceChildren(...ordered.map((n) => {
    const x = byName.get(n);
    const p = SU_PILL[x?.status] || SU_PILL.unknown;
    const pill = el('span', p[1], 'pill ' + p[0]);
    pill.title = x?.detail || '';
    const cell = el('div', null, 'su-cell');
    cell.append(pill);
    if (x?.status === 'update' && x.newer && !x.newer.ref) cell.append(el('span', `also ${x.newer.version} (manual)`, 'muted small'));
    if (x?.newer?.ref) cell.append(el('span', `newer: ${x.newer.version}`, 'muted small'));
    const actions = el('div', null, 'row-actions');
    if (x?.status === 'update' && x.can_update && x.action !== 'mailcow' && n !== 'hephaestus-prod-migrate-1') {
      actions.append(button('Update', 'primary', () => applyServiceUpdate({ title: n, target: n, detail: (x.detail || '') + (x.action === 'rebuild-image' ? '. Every container that uses this image restarts too' : ''), count: 2 })));
    }
    if (x?.newer?.ref && n !== 'hephaestus-prod-migrate-1') {
      actions.append(button('Update to ' + x.newer.version, 'primary', () => applyServiceUpdate({ title: n, target: n, newer: true, detail: 'Moves ' + n + ' from ' + x.version + ' to ' + x.newer.version + (x.image && /^(mysql|mariadb|postgres)[:@]/.test(x.image) ? '. The database is dumped, and the dump is test-restored into the new version first' : ''), count: 1 })));
    }
    actions.append(button('Restart', '', () => restartService(n)));
    return row([el('span', n, 'mono'), el('span', x?.version || 'unknown', 'mono'), cell, actions]);
  }));
  const anyUpdate = bulkUpdates().length > 0;
  $('svc-update-all').disabled = !anyUpdate;
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
    if (x.newer?.ref) {
      const key = 'newer:' + x.name;
      if (!seen.has(key) && x.name !== 'hephaestus-prod-migrate-1') {
        seen.add(key);
        const isDb = /^(mysql|mariadb|postgres)[:@]/.test(x.image || '');
        items.push({ title: x.name, detail: `Newer version ${x.newer.version} (you have ${x.version}). ` + (isDb ? 'The database is dumped, and the dump is test-restored into the new version before anything changes.' : 'It is applied in place, and the previous version is kept for rollback.'), how: x.newer.how, target: x.name, newer: true, manual: false, count: 1 });
      }
    } else if (x.newer) {
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
  // Show progress at once: the server checks the new image before it starts the job, which can take a minute.
  const box = $('su-job');
  box.hidden = false;
  box.replaceChildren(el('p', `Starting the update to ${i.newer ? 'the newer version' : 'the new build'}. Argus is checking the new image first; this can take a minute.`, 'muted'));
  try { await call(i.newer ? 'service-newer' : 'service-update', [i.target]); watchJob('svc-update', $('su-job')); }
  catch (err) { say('The update did not start: ' + errText(err)); }
}
$('su-check').addEventListener('click', () => loadServiceUpdates(true));
$('upd-check').addEventListener('click', () => loadServer());
// Container updates Update All runs: mail has its own button; the migration job is never updated here.
function bulkUpdates() {
  return (suData?.services || []).filter((x) => x.can_update && x.status === 'update'
    && x.action !== 'mailcow' && x.name !== 'hephaestus-prod-migrate-1');
}
$('svc-update-all').addEventListener('click', async () => {
  const names = bulkUpdates().map((x) => x.name);
  if (!names.length) return;
  const ok = await confirmAction({ title: 'Update All Services?',
    text: `Argus updates ${names.length} ${names.length === 1 ? 'service' : 'services'} one after another: ${names.join(', ')}. Each one restarts for a few seconds. If one fails, the rest are not started. Mail has its own update button and is not included.`,
    ok: 'Update All' });
  if (!ok) return;
  try { await call('service-update-all'); watchJob('svc-update', $('su-job')); }
  catch (err) { say('The updates did not start: ' + errText(err)); }
});

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
  if (p.why === 'held-back') {
    const held = el('span', 'Held back', 'pill unknown');
    held.title = 'apt keeps this package back, so a normal upgrade does not install it. It needs a decision by hand.';
    return held;
  }
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
  // A finished deploy or rollback changes what is live, so re-check Prepare.
  if (!st.running && (job === 'heph-deploy' || job === 'heph-rollback')) refreshDeployState();
  const label = st.running ? ['warn', 'Running'] : st.result === 'ok' ? ['ok', 'Finished'] : st.result === 'failed' ? ['bad', 'Failed'] : ['warn', 'Interrupted'];
  const pill = el('span', label[1], 'pill ' + label[0]);
  const head = el('p', { updates: 'Last update run: ', 'heph-rollback': 'Last rollback: ', 'heph-deploy': 'Last deploy: ', web: 'Last web server change: ', 'svc-update': 'Last service update: ', 'db-backup': 'Last database backup: ' }[job]);
  head.append(pill);
  const lines = st.log.filter((l) => !l.startsWith('ARGUS-RESULT'));
  // A plain last line, so the end of the log says how it ended.
  if (!st.running) lines.push('', st.result === 'ok' ? '■ Done: finished without errors.' : st.result === 'failed' ? '■ Stopped: it failed. The lines above say where.' : '■ Stopped before it finished (interrupted).');
  const pre = el('pre', lines.join('\n'));
  box.replaceChildren(head, pre);
  // Always show the end of the log (after layout, so the height is known).
  requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
  if (st.running) jobTimers[job] = setTimeout(() => watchJob(job, box), 3000);
  else if (!quietIfNone) { refresh(); if (job === 'svc-update') loadServiceUpdates(false); if (job === 'db-backup') loadDatabases(); }
}

// --- backups
async function loadBackups() {
  const bk = await call('backup-list');
  const cards = [];
  for (const [key, label] of [['mail', 'Mail'], ['hephaestus', 'Hephaestus Database']]) {
    const c = el('section', null, 'card');
    c.dataset.collapse = 'backups-' + key;
    const toggle = el('button', 'Hide', 'btn small');
    toggle.type = 'button';
    toggle.dataset.toggle = '';
    const head = el('div', null, 'card-head');
    const btns = el('div', null, 'btns');
    btns.append(toggle);
    head.append(el('h3', label), btns);
    const body = el('div', null, 'collapsible');
    c.append(head, body);
    const items = arr(bk[key]);
    if (!items) body.append(el('p', 'Could not read this folder.', 'muted'));
    else if (!items.length) body.append(el('p', 'None kept yet.', 'muted'));
    else {
      const t = el('table');
      const tb = el('tbody');
      for (const i of items) tb.append(row([el('span', i.time, 'mono'), el('span', (i.size_b / 1e6).toFixed(1) + ' MB', 'mono')]));
      t.append(tb);
      body.append(el('p', `${items.length} kept. Older copies are removed automatically.`, 'muted'), t);
    }
    body.append(button('Back Up Now', '', async () => {
      const ok = await confirmAction({ title: `Back Up ${label} Now?`,
        text: key === 'mail'
          ? 'A copy of all mail, plus the websites\' files, is made now. It takes a few minutes; mail and the websites keep working meanwhile. Copies past the kept number of days are removed.'
          : 'A copy of the Hephaestus database is made now. It takes a few seconds; Hephaestus keeps working. Copies older than 14 days are removed.',
        ok: 'Back Up Now' });
      if (!ok) return;
      try { await call('backup-run', [key]); say(`${label} backup started. It appears here when it finishes; refresh this page in a minute or two.`); }
      catch (err) { say(`Could not start the ${label} backup: ` + errText(err)); }
    }));
    setupCollapse(c);
    cards.push(c);
  }
  $('bk-cards').replaceChildren(...cards);
}

// Saves one database's scheduled backup (on or off, and its time HH:MM), then redraws the list.
async function saveSchedule(name, enabled, time) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(time);
  if (!m) { say('Enter the backup time as HH:MM.'); return; }
  try {
    await call('db-schedule-set', [name, String(enabled), m[1], m[2]]);
    say(enabled ? `Scheduled backup of ${name} is on, at ${time}.` : `Scheduled backup of ${name} is off.`);
  } catch (err) { say(`Could not save the schedule for ${name}: ` + errText(err)); }
  loadDatabases();
}

// The On/Off toggle and time field for one database. Turning it off asks first.
function scheduleCell(name, s) {
  const on = !!(s && s.enabled);
  const time = s && s.hour != null ? String(s.hour).padStart(2, '0') + ':' + String(s.minute).padStart(2, '0') : '03:00';
  const toggle = button(on ? 'On' : 'Off', on ? 'primary' : '', async () => {
    if (on) {
      const ok = await confirmAction({ title: `Turn Off the Scheduled Backup of ${name}?`,
        text: 'This database will no longer be backed up on its schedule. Copies already kept are not removed, and you can still back it up by hand.',
        ok: 'Turn Off' });
      if (!ok) return;
    }
    await saveSchedule(name, !on, input.value);
  });
  toggle.setAttribute('aria-pressed', String(on));
  const input = el('input');
  input.type = 'time';
  input.value = time;
  input.setAttribute('aria-label', `Scheduled backup time of ${name}`);
  input.addEventListener('change', () => saveSchedule(name, on, input.value));
  const next = on && s.next_run ? el('span', 'Next: ' + s.next_run.slice(0, 16).replace('T', ' '), 'muted') : el('span', 'Off', 'muted');
  const cell = el('span');
  cell.append(toggle, ' ', input, ' ', next);
  return cell;
}

// Lists the database containers, their scheduled backups, and lets each one be backed up now.
async function loadDatabases() {
  loadWarningsChoice();
  let dl, sl;
  try { dl = await call('db-list'); sl = await call('db-schedule-list'); }
  catch (err) { $('db-rows').replaceChildren(row(['Could not read databases: ' + errText(err), '', '', '', '', ''])); return; }
  $('db-keep').textContent = dl.keep;
  const dbs = arr(dl.databases) || [];
  const schedules = new Map((arr(sl.schedules) || []).map((s) => [s.name, s]));
  const kinds = { postgres: 'PostgreSQL', mysql: 'MySQL', mariadb: 'MariaDB', unsupported: 'Not supported' };
  $('db-rows').replaceChildren(...(dbs.length ? dbs.map((d) => {
    const can = d.kind !== 'unsupported';
    return row([
      el('span', d.name, 'mono'),
      el('span', (kinds[d.kind] || d.kind) + (d.running === false ? ' (stopped)' : '')),
      el('span', d.last_backup ? `${d.last_backup} (${d.backups} kept)` : 'None yet', 'mono'),
      el('span', d.last_size_b != null ? (d.last_size_b / 1e6).toFixed(1) + ' MB' : '', 'mono'),
      can ? scheduleCell(d.name, schedules.get(d.name)) : el('span'),
      actionsCell(can && d.running !== false ? button('Back Up Now', '', async () => {
        const ok = await confirmAction({ title: `Back Up ${d.name} Now?`,
          text: 'A full copy of this database is made now. The database keeps running. Older copies beyond the kept number are removed once this one succeeds.',
          ok: 'Back Up Now' });
        if (!ok) return;
        try { await call('db-backup', [d.name]); watchJob('db-backup', $('db-job')); }
        catch (err) { say(`Could not start the ${d.name} backup: ` + errText(err)); }
      }) : el('span', 'Not available', 'muted'),
      d.kind === 'postgres' && d.running !== false ? button('Grant Access', '', () => grantAccess(d.name)) : el('span')),
    ]);
  }) : [row(['No database containers found.', '', '', '', '', ''])]));
  dbPgNames = dbs.filter((d) => d.kind === 'postgres').map((d) => d.name);
  wireDatabaseTools();
  watchJob('db-backup', $('db-job'), true);
  loadDatabaseList();
  loadDatabaseUsers();
}

// Drops a login: takes its rights in every database on the container, then removes it. Two steps; the second
// needs the user's name typed in full. The first step is the picker itself, so it always shows.
async function dropUser() {
  if (!dbPgNames.length) return say('There is no PostgreSQL container to drop a user from.');
  const server = dbSelect(dbPgNames), user = dbSelect([]);
  const fillUsers = async () => {
    user.replaceChildren();
    try {
      const users = arr((await call('db-pg-roles', [server.value])).users) || [];
      if (!users.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No login users'; user.append(o); }
      for (const u of users) { const o = document.createElement('option'); o.value = u; o.textContent = u; user.append(o); }
    } catch (err) { say('Could not read the users: ' + errText(err)); }
  };
  server.addEventListener('change', fillUsers);
  await fillUsers();
  const extra = document.createElement('div');
  extra.append(dbField('Container', server), dbField('User to drop', user));
  const ok1 = await confirmAction({ title: 'Drop User', ok: 'Continue', extra,
    text: 'Takes away this user\'s rights in every database on the container, then removes the login. A user who still owns something cannot be dropped; Argus says why. Hephaestus\'s own roles are refused, and on the Hephaestus container a user with rights in the Hephaestus database is refused.' });
  if (!ok1) return;
  const who = user.value;
  if (!who) return say('Choose a user to drop.');
  const ok2 = await confirmAction({ title: `Drop ${who}?`, ok: 'Drop User', word: who,
    text: `Type ${who} to confirm. The login is removed from ${server.value}.` });
  if (!ok2) return;
  try {
    await call('db-user-drop', [server.value, who, lastTyped]);
    say(`Dropped ${who}.`);
    loadDatabases();
  } catch (err) { say('Could not drop the user: ' + errText(err)); }
}

// The row buttons for one database: take a user's access away, or drop the database.
// One Actions cell holding several buttons, so each row has exactly one cell per header.
function actionsCell(...buttons) {
  const cell = el('span');
  cell.style.display = 'inline-flex';
  cell.style.gap = '8px';
  cell.append(...buttons);
  return cell;
}

function dbRowActions(d) {
  const cell = el('span');
  cell.style.display = 'inline-flex';
  cell.style.gap = '8px';
  cell.append(button('Remove Access', '', () => revokeAccess(d.container, d.name)),
    ...publicButtons(d),
    button('Drop', 'danger', () => dropDatabase(d.container, d.name)));
  return cell;
}

// The postgres database can't be removed or emptied here, so its row only offers the public-connect buttons.
function postgresRowActions(d) {
  const cell = el('span');
  cell.style.display = 'inline-flex';
  cell.style.gap = '8px';
  cell.append(...publicButtons(d));
  return cell;
}

function publicButtons(d) {
  return [button('Block Public Connect', '', () => blockPublicConnect(d.container, d.name)),
    button('Allow Public Connect', '', () => allowPublicConnect(d.container, d.name))];
}

// Gives back the default CONNECT for PUBLIC on one database. Undoes Block Public Connect.
async function allowPublicConnect(container, name) {
  const ok = await confirmAction({ title: `Allow public connect to ${name}?`, ok: 'Allow Public Connect', word: name,
    text: `Type ${name} to confirm. Every login can connect to ${name} on ${container} again by default. Table access still needs a grant.` });
  if (!ok) return;
  try {
    await call('db-public-allow', [container, name, lastTyped]);
    say(`Public connect to ${name} is allowed again.`);
    loadDatabases();
  } catch (err) { say('Could not allow public connect: ' + errText(err)); }
}

// Takes away the default CONNECT that PUBLIC has on one database. Nothing changes until the admin does this for
// that database. Logins that were relying on the default can no longer connect; the owner still can.
async function blockPublicConnect(container, name) {
  const ok = await confirmAction({ title: `Block public connect to ${name}?`, ok: 'Block Public Connect', word: name,
    text: `Type ${name} to confirm. Logins that connect through the default (not through a grant) lose the ability to connect to ${name} on ${container}. Check that no application depends on it first. Grant Access puts a login back.` });
  if (!ok) return;
  try {
    await call('db-public-revoke', [container, name, lastTyped]);
    say(`Public connect to ${name} is blocked.`);
    loadDatabases();
  } catch (err) { say('Could not block public connect: ' + errText(err)); }
}

// Takes every right one user has in one database. Two confirmations; the second needs the user's name typed in full.
async function revokeAccess(container, name) {
  let users;
  try { users = arr((await call('db-pg-roles', [container])).users) || []; }
  catch (err) { say('Could not read the users: ' + errText(err)); return; }
  if (!users.length) { say(`No login users exist on ${container}.`); return; }
  const user = dbSelect(users);
  const extra = document.createElement('div');
  extra.append(dbField(`User to remove access to ${name}`, user));
  // The picker always shows: with warnings hidden, the user must still be chosen, not the first in the list.
  const ok1 = await confirmAction({ title: `Remove access to ${name}?`, ok: 'Continue', extra,
    text: 'Takes away every right this user has in this database, including rights for tables created later. The user keeps their login. The Hephaestus database and Hephaestus\'s own roles are refused.' });
  if (!ok1) return;
  const who = user.value;
  const ok2 = await confirmAction({ title: `Remove ${who}'s access?`, ok: 'Remove Access', word: who,
    text: `Type ${who} to confirm. ${who} loses access to ${name} on ${container}.` });
  if (!ok2) return;
  try {
    await call('db-revoke', [container, name, who, lastTyped]);
    say(`${who} no longer has access to ${name}.`);
    offerSkipWarnings();
  } catch (err) { say('Could not remove access: ' + errText(err)); }
}

// Every database inside each PostgreSQL container. Read-only.
async function loadDatabaseList() {
  let dl;
  try { dl = await call('db-pg-databases'); }
  catch (err) { $('db-pg-rows').replaceChildren(row(['Could not read databases: ' + errText(err), '', '', '', '', ''])); return; }
  const list = arr(dl.databases) || [];
  $('db-pg-rows').replaceChildren(...(list.length ? list.map((d) => d.error ? row([el('span', d.container, 'mono'), el('span', d.error, 'muted'), el('span'), el('span'), el('span'), el('span')]) : row([
    el('span', d.container, 'mono'),
    el('span', d.name, 'mono'),
    el('span', d.owner, 'mono'),
    el('span', (d.size_b / 1e6).toFixed(1) + ' MB', 'mono'),
    el('span', d.connectable ? 'Yes' : 'No'),
    d.name !== 'postgres' ? dbRowActions(d) : postgresRowActions(d),
  ])) : [row(['No databases found.', '', '', '', '', ''])]));
}

// Every login user in each PostgreSQL container, with the databases it can connect to. Read-only.
async function loadDatabaseUsers() {
  let du;
  try { du = await call('db-pg-users'); }
  catch (err) { $('db-user-rows').replaceChildren(row(['Could not read users: ' + errText(err), '', '', ''])); return; }
  const list = arr(du.users) || [];
  $('db-user-rows').replaceChildren(...(list.length ? list.map((u) => u.error ? row([el('span', u.container, 'mono'), el('span', u.error, 'muted'), el('span'), el('span')]) : row([
    el('span', u.container, 'mono'),
    el('span', u.name, 'mono'),
    el('span', u.owner ? 'Yes' : 'No'),
    el('span', u.databases.length ? u.databases.join(', ') : 'None', u.databases.length ? 'mono' : 'muted'),
  ])) : [row(['No users found.', '', '', ''])]));
}

// Two confirmations: the first says what happens, the second needs the database name typed in full.
// The helper takes a fresh backup first and refuses the drop if that backup fails.
async function dropDatabase(container, name) {
  const ok1 = skipWarnings || await confirmAction({ title: `Drop ${name}?`, ok: 'Continue',
    text: `This deletes ${name} on ${container}. A fresh backup is taken first. If that backup fails, nothing is dropped.` });
  if (!ok1) return;
  const ok2 = await confirmAction({ title: `Drop ${name} permanently?`, ok: 'Drop Database', word: name,
    text: `Type ${name} to confirm. Anyone connected to it is disconnected, and the database is removed from the server.` });
  if (!ok2) return;
  try {
    await call('db-drop', [container, name, lastTyped]);
    say(`Dropped ${name}. A backup was taken first.`);
    loadDatabases();
    offerSkipWarnings();
  } catch (err) { say('Could not drop the database: ' + errText(err)); }
}

// Restore one database from a whole-server backup. A live database is never overwritten: the copy gets a new name.
async function restoreDatabase() {
  if (!dbPgNames.length) return say('There is no PostgreSQL container to restore into.');
  const server = dbSelect(dbPgNames), backup = dbSelect([]);
  const fillBackups = async () => {
    backup.replaceChildren();
    try {
      const files = arr((await call('db-backup-files', [server.value])).files) || [];
      if (!files.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No backups yet'; backup.append(o); }
      for (const f of files) { const o = document.createElement('option'); o.value = f; o.textContent = f; backup.append(o); }
    } catch (err) { say('Could not read the backups: ' + errText(err)); }
  };
  const dbs = dbSelect([]);
  // The databases come from the chosen backup, so only databases that backup holds can be picked.
  const fillDatabases = async () => {
    dbs.replaceChildren();
    if (!backup.value) return;
    try {
      const names = arr((await call('db-backup-databases', [server.value, backup.value])).databases) || [];
      if (!names.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No databases in this backup'; dbs.append(o); }
      for (const n of names) { const o = document.createElement('option'); o.value = n; o.textContent = n; dbs.append(o); }
    } catch (err) { say('Could not read the backup: ' + errText(err)); }
  };
  const refresh = async () => { await fillBackups(); await fillDatabases(); };
  server.addEventListener('change', refresh);
  backup.addEventListener('change', fillDatabases);
  await refresh();
  const extra = document.createElement('div');
  extra.append(dbField('Container', server), dbField('Backup', backup), dbField('Database to restore', dbs));
  const ok = await confirmAction({ title: 'Restore Database', ok: 'Continue', extra,
    text: 'If the database still exists, a fresh backup of it is taken first, and the restore goes under a new name. The live database is not touched.' });
  if (!ok) return;
  const db = dbs.value, file = backup.value;
  if (!db) return say('Choose the database to restore.');
  if (!file) return say('There is no backup to restore from.');
  const ok2 = await confirmAction({ title: `Restore ${db}?`, ok: 'Restore', word: db,
    text: `Type ${db} to confirm the restore.` });
  if (!ok2) return;
  try {
    const r = await call('db-restore', [server.value, db, file, lastTyped]);
    say(`Restored to ${r.restored} from ${r.from}. ${r.tables} tables checked.`);
    loadDatabases();
  } catch (err) { say('Could not restore: ' + errText(err)); }
}

// --- database manager (PostgreSQL). Each action is one helper call; the helper does the checks and logs it.
let dbPgNames = [];
let dbToolsWired = false;
// true: the first warning for drop and remove access is hidden (the stored choice; the typed-name step stays)
let skipWarnings = false;

function setWarningsLabel() {
  $('db-warnings-toggle').textContent = skipWarnings ? 'Show Warnings' : 'Hide Warnings';
}

async function loadWarningsChoice() {
  try { skipWarnings = !!(await call('db-choice-get')).skip_warnings; setWarningsLabel(); }
  catch (err) { say('Could not read the warnings setting: ' + errText(err)); }
}

// Hiding or showing needs a fresh sign-in: the helper checks the SSH log for one in the last 5 minutes.
async function toggleWarnings() {
  const hide = !skipWarnings;
  const ok = await confirmAction({ title: hide ? 'Hide the first warning?' : 'Show the first warning again?',
    ok: hide ? 'Hide Warnings' : 'Show Warnings',
    text: 'This needs a fresh sign-in. Disconnect from Argus, connect again, then come back here. Argus refuses the change if you have not signed in within the last 5 minutes.' });
  if (!ok) return;
  try {
    await call('db-choice-set', [hide ? 'on' : 'off']);
    skipWarnings = hide;
    setWarningsLabel();
    say(hide ? 'The first warning is hidden for drop and remove access. The typed-name confirmation stays.'
             : 'The first warning is shown again.');
  } catch (err) { say('Could not change the warning: ' + errText(err)); }
}

// After a drop or remove-access finishes, offer to hide the first warning from now on.
async function offerSkipWarnings() {
  if (skipWarnings) return;
  const ok = await confirmAction({ title: 'Stop showing this warning?', ok: 'Yes, Hide It',
    text: 'Hide the first warning for drop and remove access? The typed-name confirmation stays. This needs a fresh sign-in: Disconnect, connect again, then answer Yes.' });
  if (!ok) return;
  try {
    await call('db-choice-set', ['on']);
    skipWarnings = true;
    setWarningsLabel();
    say('The first warning is hidden for drop and remove access.');
  } catch (err) { say('Could not hide the warning: ' + errText(err)); }
}

function dbInput(placeholder) {
  const i = document.createElement('input');
  i.type = 'text'; i.placeholder = placeholder; i.spellcheck = false; i.autocomplete = 'off';
  return i;
}

function dbSelect(names) {
  const s = document.createElement('select');
  for (const n of names) { const o = document.createElement('option'); o.value = n; o.textContent = n; s.append(o); }
  return s;
}

function dbField(label, input) {
  const p = document.createElement('p');
  const l = document.createElement('label');
  l.append(label + ' ', input);
  p.append(l);
  return p;
}

function wireDatabaseTools() {
  if (dbToolsWired) return;
  dbToolsWired = true;
  $('db-new-db').addEventListener('click', newDatabase);
  $('db-new-user').addEventListener('click', newDatabaseUser);
  $('db-restore-db').addEventListener('click', restoreDatabase);
  $('db-warnings-toggle').addEventListener('click', toggleWarnings);
  $('db-drop-user').addEventListener('click', dropUser);
}

async function newDatabase() {
  if (!dbPgNames.length) return say('There is no PostgreSQL database container to create a database in.');
  const server = dbSelect(dbPgNames), name = dbInput('new_database_name');
  const extra = document.createElement('div');
  extra.append(dbField('Container', server), dbField('Database name', name));
  const ok = await confirmAction({ title: 'New Database', ok: 'Create Database', extra,
    text: 'Creates an empty database. Nobody can connect to it until you grant access to it.' });
  if (!ok) return;
  try {
    await call('db-create', [server.value, name.value.trim()]);
    say(`Created ${name.value.trim()}.`);
    loadDatabases();
  } catch (err) { say('Could not create the database: ' + errText(err)); }
}

async function newDatabaseUser() {
  if (!dbPgNames.length) return say('There is no PostgreSQL database container to add a user to.');
  const server = dbSelect(dbPgNames), name = dbInput('new_user_name');
  const extra = document.createElement('div');
  extra.append(dbField('Container', server), dbField('User name', name));
  const ok = await confirmAction({ title: 'New Database User', ok: 'Create User', extra,
    text: 'Creates a login with no access yet, and a new password. The password is shown once and is not kept anywhere.' });
  if (!ok) return;
  try {
    const r = await call('db-user-create', [server.value, name.value.trim()]);
    await showOnce('New Database User Password', `For ${r.user}. Copy it now: it is not shown again. The user has no access to databases Argus made until you grant some. Databases Argus did not make, such as postgres, still let any login connect by default.`, r.password);
  } catch (err) { say('Could not create the user: ' + errText(err)); }
}

async function grantAccess(container) {
  let dbs, users;
  try {
    const dl = await call('db-pg-databases');
    dbs = (arr(dl.databases) || []).filter((d) => d.container === container && !d.error && d.name !== 'postgres').map((d) => d.name);
    users = arr((await call('db-pg-roles', [container])).users) || [];
  } catch (err) { say('Could not read the databases and users: ' + errText(err)); return; }
  if (!dbs.length) { say(`No database inside ${container} can be granted yet.`); return; }
  if (!users.length) { say(`No login users exist on ${container} yet. Create one first.`); return; }
  const db = dbSelect(dbs), user = dbSelect(users), level = dbSelect(['read', 'write']);
  const extra = document.createElement('div');
  extra.append(dbField('Database inside this server', db), dbField('User', user), dbField('Access', level));
  const ok = await confirmAction({ title: `Grant Access on ${container}`, ok: 'Grant Access', extra,
    text: 'Read lets the user see the data. Write also lets them change rows. Neither lets them create tables.' });
  if (!ok) return;
  try {
    const r = await call('db-grant', [container, db.value.trim(), user.value.trim(), level.value]);
    say(`${r.user} now has ${r.level} access to ${r.db}.`);
  } catch (err) { say('Could not grant access: ' + errText(err)); }
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
  await loadDeploySource(rl.live_version);
  watchJob('heph-deploy', $('dp-job'), true);
}

// Re-reads the live version and updates the Deploy panel. Does not call watchJob, so it cannot loop.
async function refreshDeployState() {
  try {
    const rl = await call('rollback-list');
    $('hp-live').textContent = rl.live_version || UNKNOWN;
    await loadDeploySource(rl.live_version);
  } catch (err) { say('Could not refresh the Deploy panel: ' + errText(err)); }
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
let dpLive = false;
let dpPreparing = false;
async function loadDeploySource(liveVersion) {
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
    // Prepare is only useful when the latest commit differs from the live one.
    const isLive = !!liveVersion && (src.commit.startsWith(liveVersion) || liveVersion.startsWith(src.commit));
    if (isLive) parts.push(el('p', `${src.commit} is already live. There is nothing new to prepare.`, 'muted'));
    box.replaceChildren(...parts);
    dpLive = isLive;
    $('dp-prepare').disabled = isLive || dpPreparing;
  } catch (err) {
    dpSource = null;
    dpLive = false;
    box.replaceChildren(el('p', 'Could not read the Hephaestus source on this PC: ' + errText(err), 'muted'));
    $('dp-prepare').disabled = true;
  }
}

$('dp-prepare').addEventListener('click', async () => {
  if (!dpSource) return;
  const commit = dpSource.commit;
  dpPreparing = true;
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
    dpPreparing = false;
    $('dp-prepare').disabled = dpLive;
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

// ---------- sign-in attempts: table, world map, traceroute ----------
const SVGNS = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v)); return e; };
const mapXY = (lon, lat) => [(lon + 180) / 360 * 1000, (90 - lat) / 180 * 500];
const placeText = (g) => [g.city, g.country].filter(Boolean).join(', ') || 'Unknown';
let siData = null, siSeq = 0, trSeq = 0, tracing = false;

function drawMap(rows, server, route) {
  const svg = $('si-map');
  const base = svgEl('path', { d: WORLD_MAP_PATH, class: 'land' });
  const dots = svgEl('g');
  for (const r of [...rows].sort((a, b) => (b.tries + b.probes) - (a.tries + a.probes))) {
    if (typeof r.lat !== 'number') continue;
    const [x, y] = mapXY(r.lon, r.lat);
    const n = r.tries || r.probes || 1;
    const c = svgEl('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: Math.min(16, 2.2 + Math.sqrt(n) / 2.2).toFixed(1), class: 'hit ' + (r.mail && !r.ssh ? 'mail' : 'ssh') });
    const t = svgEl('title'); t.textContent = `${r.ip} · ${placeText(r)} · ${n} ${n === 1 ? 'try' : 'tries'}`;
    c.append(t);
    dots.append(c);
  }
  const parts = [base, dots];
  if (route && route.length > 1) {
    // Split where a leg crosses the date line, so it isn't drawn the long way round.
    let seg = [route[0]];
    const segs = [seg];
    for (const p of route.slice(1)) { if (Math.abs(p[0] - seg[seg.length - 1][0]) > 500) { seg = [p]; segs.push(seg); } else seg.push(p); }
    for (const sg of segs) if (sg.length > 1) parts.push(svgEl('polyline', { points: sg.map(([x, y]) => x.toFixed(1) + ',' + y.toFixed(1)).join(' '), class: 'route' }));
    for (const [x, y] of route.slice(1)) parts.push(svgEl('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: 3, class: 'hop' }));
  }
  if (typeof server?.lat === 'number') {
    const [x, y] = mapXY(server.lon, server.lat);
    const h = svgEl('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: 5, class: 'here' });
    const t = svgEl('title'); t.textContent = 'This server' + (server.city ? ' (' + server.city + ')' : '');
    h.append(t);
    parts.push(h);
  }
  svg.replaceChildren(...parts);
}

// Severity: the helper ranks every address (Critical, High, Medium, Low) and
// gives the rule behind each rank. Shown above the Addresses list.
// Rank per address for the period on screen: null while ranking, a Map once done.
let siRank = null, siRankFailed = false;
const RANK_PILL = { Critical: 'bad', High: 'bad', Medium: 'warn', Low: 'unknown' };
const RANK_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };   // Rank sorts Critical first
async function loadSeverity(days, my) {
  siRank = null; siRankFailed = false;
  let d;
  try { d = await call('attack-groups', [days]); }
  catch (err) { if (my === siSeq) { siRank = new Map(); siRankFailed = true; renderSiRows(); } return; }
  if (my !== siSeq) return;
  siRank = new Map(d.rows.map((r) => [r.ip, r]));
  renderSiRows();
}

// resort: the same period again in a new order. Details, a route being traced
// and the block list stay as they are.
async function loadSignins({ resort = false } = {}) {
  const days = $('si-days').value;
  const my = ++siSeq;
  if (!resort) {
    siData = null;                           // nothing old to re-sort while this period loads
    trSeq++;                                 // a route still being traced belongs to the old view
    $('si-detail').hidden = true;
    loadBlocked();
  }
  $('si-summary').textContent = 'Reading the server logs…';
  $('si-rows').replaceChildren(row([el('span', 'Loading…', 'muted'), '', '', '', '', '', '', '', '']));
  let d;
  try { d = await call('attacks', siSort && siSort.key !== 'rank' ? [days, siSort.key, siSort.dir === 1 ? 'asc' : 'desc'] : [days]); }
  catch (err) { if (my === siSeq) { siData = null; $('si-summary').textContent = 'Could not read the sign-in logs: ' + errText(err); $('si-rows').replaceChildren(); } return; }
  if (my !== siSeq) return;                  // a newer request has been made since
  siData = d;
  const t = d.total;
  const span = { 1: 'the last 24 hours', 7: 'the last 7 days', 30: 'the last 30 days' }[d.days];
  $('si-summary').textContent = `In ${span}: ${t.addresses.toLocaleString()} addresses made ${t.ssh.toLocaleString()} SSH attempts`
    + (t.mail ? ` and ${t.mail.toLocaleString()} mail login failures` : '') + (t.probes ? `, plus ${t.probes.toLocaleString()} scans that never got as far as a sign-in` : '')
    + `. All refused.${t.key_ok ? ` ${t.key_ok} ${t.key_ok === 1 ? 'address' : 'addresses'} used your SSH key without the code: see Used Your SSH Key below.` : ''}${t.returning ? ` ${t.returning.toLocaleString()} of them came back on more than one day.` : ''}${t.bans ? ` mailcow banned ${t.bans} ${t.bans === 1 ? 'address' : 'addresses'} for repeated mail failures.` : ''}`;
  $('si-countries').textContent = d.countries.length ? 'Most attempts from: ' + d.countries.slice(0, 8).map(([c, n]) => `${c} (${n.toLocaleString()})`).join(', ') : '';
  $('si-credit').textContent = (d.geo?.credit || '') + (d.geo?.updated ? ` · updated ${d.geo.updated}` : ' · location data not downloaded yet') + ' · Map: Natural Earth.';
  const sortName = d.sort && document.querySelector(`#si-table th[data-sort="${d.sort.key}"] .th-sort`)?.textContent;
  $('si-count').textContent = d.rows.length >= t.addresses ? `${t.addresses.toLocaleString()} ${t.addresses === 1 ? 'address' : 'addresses'}`
    : d.sort ? `First ${d.rows.length} of ${t.addresses.toLocaleString()} by ${sortName} (${d.sort.dir === 'asc' ? 'ascending' : 'descending'})${t.key_ok ? ', plus any that used your key' : ''}, shown here and on the map`
    : `Top ${d.rows.length} of ${t.addresses.toLocaleString()} shown here and on the map (your key used and signed-in addresses first, then the busiest)`;
  drawMap(d.rows, d.server, null);
  loadSeverity(days, my);
  renderSiRows();
}

// Sorting the Addresses list. When every address fits on the page, sorting
// happens here; when the server had more than the 400 it sends, it is asked
// again for the first 400 in the chosen order, so sorting covers them all.
let siSort = null;                           // { key, dir: 1 | -1 } or null for the server's order
function ipKey(ip) {
  ip = String(ip).toLowerCase();
  if (!ip.includes(':')) return '4' + ip.split('.').map((p) => p.padStart(3, '0')).join('.');
  const [a, b = ''] = ip.split('::');
  const head = a ? a.split(':') : [], tail = b ? b.split(':') : [];
  const full = ip.includes('::') ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail] : head;
  return '6' + full.map((p) => p.padStart(4, '0')).join(':');
}
const SI_SORTS = {
  ip: { first: 1, val: (r) => ipKey(r.ip) },
  place: { first: 1, val: (r) => [r.city, r.country].filter(Boolean).join(', ').toLowerCase() },
  network: { first: 1, val: (r) => (r.network || '').toLowerCase() },
  tries: { first: -1, val: (r) => [r.tries || 0, r.probes || 0] },
  visits: { first: -1, val: (r) => [r.visits || 0, r.days || 0] },
  users: { first: 1, val: (r) => (r.users?.[0] || '').toLowerCase() },
  last: { first: -1, val: (r) => r.last || 0 },
  rank: { first: 1, val: (r) => RANK_ORDER[siRank?.get(r.ip)?.rank] ?? 4 },   // sorted here, never sent to the server
};
function cmp(a, b) {
  if (Array.isArray(a)) { for (let i = 0; i < a.length; i++) { const c = cmp(a[i], b[i]); if (c) return c; } return 0; }
  return a < b ? -1 : a > b ? 1 : 0;
}
function sortedSiRows() {
  const rows = siData?.rows || [];
  const rank = (r, i) => (Number.isInteger(r.rank) ? r.rank : i);   // the server's default order
  if (!siSort) return rows.map((r, i) => [rank(r, i), r]).sort((x, y) => x[0] - y[0]).map((x) => x[1]);
  const { val } = SI_SORTS[siSort.key];
  const empty = (v) => v === '';             // empty names and places go last either way
  return rows.map((r, i) => [val(r), rank(r, i), r]).sort((x, y) => {
    if (empty(x[0]) !== empty(y[0])) return empty(x[0]) ? 1 : -1;
    return cmp(x[0], y[0]) * siSort.dir || x[1] - y[1];
  }).map((x) => x[2]);
}
function setSiSort(key) {
  const first = SI_SORTS[key].first;
  if (!siSort || siSort.key !== key) siSort = { key, dir: first };
  else if (siSort.dir === first) siSort = { key, dir: -first };
  else siSort = null;                        // third click: back to the server's order
  sayHowSorted();
  showSortState();
  if (key !== 'rank' && (!siData || siData.rows.length < siData.total.addresses)) loadSignins({ resort: true });
  else renderSiRows();
}
function sayHowSorted() {
  const label = siSort && document.querySelector(`#si-table th[data-sort="${siSort.key}"] .th-sort`)?.textContent;
  $('si-sort-say').textContent = siSort ? `Sorted by ${label}, ${siSort.dir === 1 ? 'ascending' : 'descending'}` : 'Default order';
}
function showSortState() {
  document.querySelectorAll('#si-table th[data-sort]').forEach((th) => {
    th.setAttribute('aria-sort', siSort?.key === th.dataset.sort ? (siSort.dir === 1 ? 'ascending' : 'descending') : 'none');
  });
  $('si-sort-reset').hidden = !siSort;
}
document.querySelectorAll('#si-table th[data-sort] .th-sort').forEach((b) => {
  b.addEventListener('click', () => setSiSort(b.parentElement.dataset.sort));
});
$('si-sort-reset').addEventListener('click', () => {
  const refetch = !siData || siData.rows.length < siData.total.addresses;
  siSort = null; sayHowSorted();
  if (refetch) loadSignins({ resort: true }); else renderSiRows();
  showSortState();
  document.querySelector('#si-table .th-sort')?.focus();   // this button hides itself
});

function renderSiRows() {
  showSortState();
  const d = siData;
  if (!d) return;
  $('si-rows').replaceChildren(...sortedSiRows().map((r) => {
    const tries = el('div');
    tries.append(el('span', String(r.tries || 0), 'mono'));
    const bits = [r.ssh && `${r.ssh} SSH`, r.mail && `${r.mail} mail`, r.probes && `${r.probes} scans`, r.banned && 'banned'].filter(Boolean);
    if (bits.length) tries.append(el('div', bits.join(' · '), 'muted small'));
    const vis = el('div', null, 'su-cell');
    vis.append(el('span', `${r.visits} ${r.visits === 1 ? 'visit' : 'visits'} · ${r.days} ${r.days === 1 ? 'day' : 'days'}`, 'small'));
    if (r.days > 1) vis.append(el('span', 'Returning', 'pill warn'));
    if (r.blocked) vis.append(el('span', 'Blocked', 'pill bad'));
    if (r.signed_in) vis.append(el('span', 'Has Signed In', 'pill unknown'));
    if (r.key_ok) vis.append(el('span', 'Used Your SSH Key', 'pill bad'));
    const ranked = siRank && siRank.get(r.ip);
    const rank = ranked ? el('span', ranked.rank, 'pill ' + RANK_PILL[ranked.rank]) : el('span', siRankFailed ? 'Not ranked' : (siRank ? '—' : 'Ranking…'), 'muted small');
    if (ranked) rank.title = ranked.reason;                // the rule that set the rank
    return row([rank, el('span', r.ip, 'mono'), placeText(r), el('span', r.network || '', 'small'), tries, vis,
      el('span', (r.users || []).join(', '), 'mono small'), el('span', new Date(r.last * 1000).toLocaleString(), 'small'),
      button('Details', '', () => showAddress(r))]);
  }));
  if (!d.rows.length) $('si-rows').replaceChildren(row([el('span', 'No refused sign-ins in this period.', 'muted'), '', '', '', '', '', '', '', '']));
}

let detailSeq = 0, detailRow = null;
async function showAddress(r) {
  const my = ++detailSeq;
  trSeq++;
  detailRow = r;
  $('si-detail').hidden = false;
  $('si-route').hidden = true;
  $('si-detail-title').textContent = r.ip;
  $('si-detail-btns').replaceChildren();
  $('si-who').replaceChildren(el('dd', 'Looking it up…', 'muted'));
  $('si-visits').replaceChildren(row([el('span', 'Loading…', 'muted'), '', '', '', '']));
  $('si-timeline').replaceChildren();
  $('si-timeline-note').textContent = '';
  $('si-detail').scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  let info;
  try { info = await call('ip-info', [hex(r.ip)]); }
  catch (err) { if (my === detailSeq) $('si-who').replaceChildren(el('dd', 'Could not look it up: ' + errText(err), 'muted')); return; }
  if (my !== detailSeq) return;
  const reg = info.who?.registry || {};
  const facts = [
    ['Reverse Name', info.who?.ptr ? info.who.ptr + (info.who.ptr_confirmed ? ' (confirmed)' : ' (what it calls itself; not confirmed)') : 'none'],
    ['Owner', reg.org || reg.name || (info.who?.registry_error || 'unknown')],
    ['Registry Record', [reg.name, reg.handle].filter(Boolean).join(' · ')],
    ['Network', (reg.networks || []).join(', ') || reg.range || ''],
    ['Country', [reg.country, placeText(info.geo)].filter(Boolean).join(' · located in ')],
    ['Report Abuse To', reg.abuse || ''],
  ].filter(([, v]) => v);
  $('si-who').replaceChildren(...facts.flatMap(([k, v]) => {
    const dd = el('dd', null);
    dd.append(el('span', v, k === 'Report Abuse To' || k === 'Network' || k === 'Reverse Name' ? 'mono' : ''));
    if (k === 'Report Abuse To') dd.append(button('Copy', '', () => window.argus.copy(v, false)));
    return [el('dt', k), dd];
  }));
  drawTimeline(info.days);
  $('si-timeline-note').textContent = `${info.visit_count} separate ${info.visit_count === 1 ? 'visit' : 'visits'} in 30 days (a gap of more than 30 minutes starts a new one).`;
  $('si-visits').replaceChildren(...[...info.visits].reverse().slice(0, 30).map((v) => {
    const mins = Math.max(1, Math.round((v.end - v.start) / 60));
    return row([new Date(v.start * 1000).toLocaleString(), mins < 60 ? `${mins} min` : `${(mins / 60).toFixed(1)} h`, String(v.attempts),
      v.kinds.map((k) => ({ ssh: 'SSH', mail: 'mail', ban: 'mail ban', scan: 'scan' }[k] || k)).join(', '), el('span', v.users.join(', '), 'mono small')]);
  }));
  if (!info.visits.length) $('si-visits').replaceChildren(row([el('span', 'No attempts in the last 30 days.', 'muted'), '', '', '', '']));
  const net = (reg.networks || []).find((n) => { const len = Number(n.split('/')[1]); return n.includes(':') ? len >= 32 && len < 128 : len >= 16 && len < 32; });
  const btns = [button('Trace Route', 'trace-btn', () => traceTo(r))];
  if (info.blocked) btns.push(button(`Unblock ${info.blocked}`, '', () => unblock(info.blocked)));
  else {
    btns.push(button('Block Address', 'danger', () => blockIt(r.ip + (r.ip.includes(':') ? '/128' : '/32'), r, reg)));
    if (net) btns.push(button(`Block Network ${net}`, 'danger', () => blockIt(net, r, reg)));
  }
  btns.push(button('Close', '', () => { $('si-detail').hidden = true; drawMap(siData?.rows || [], siData?.server, null); }));
  for (const b of btns) if (b.classList.contains('trace-btn')) b.disabled = tracing;
  $('si-detail-btns').replaceChildren(...btns);
}

function drawTimeline(days) {
  const svg = $('si-timeline');
  const max = Math.max(1, ...days.map((d) => d.attempts));
  const w = 300 / days.length;
  const parts = [svgEl('line', { x1: 0, y1: 60, x2: 300, y2: 60, class: 'axis' })];
  days.forEach((d, i) => {
    const hgt = d.attempts ? Math.max(2, (d.attempts / max) * 56) : 0;
    const bar = svgEl('rect', { x: (i * w + 1).toFixed(1), y: (60 - hgt).toFixed(1), width: (w - 2).toFixed(1), height: hgt.toFixed(1), class: 'bar' });
    const t = svgEl('title'); t.textContent = `${d.day}: ${d.attempts} ${d.attempts === 1 ? 'attempt' : 'attempts'}`;
    bar.append(t);
    parts.push(bar);
  });
  const l = svgEl('text', { x: 0, y: 69, class: 'tick' }); l.textContent = days[0]?.day.slice(5) || '';
  const r = svgEl('text', { x: 300, y: 69, class: 'tick end' }); r.textContent = 'today';
  parts.push(l, r);
  svg.replaceChildren(...parts);
}

async function blockIt(network, r, reg, from = 'From Sign-In Attempts') {
  const owner = reg.org || reg.name || r.network || 'unknown owner';
  const bits = network.split('/')[1];
  const wide = network.includes(':') ? bits !== '128' : bits !== '32';   // an IPv6 /32 is a whole network
  if (!await confirmAction({ title: `Block ${network}?`,
    text: wide ? `Every address in ${network} (${owner}) is cut off from the whole server: SSH, mail and websites. Use this when one network keeps sending attackers; anyone legitimate on it is blocked too. The server can still reach out to it (sending mail, updates); only connections that network starts are dropped, so mail sent from it is refused too. Addresses you sign in from over SSH are never blocked, but if you later sign in from a new address inside this network you'd be locked out. The way back in is the Oracle Cloud console: run sudo nft destroy table inet argus && sudo systemctl disable argus-blocklist.service, unblock the network in Argus, then run sudo systemctl enable argus-blocklist.service.`
      : `${r.ip} (${owner}, ${placeText(r)}) is cut off from the whole server: SSH, mail and websites. You can unblock it at any time below.`,
    ok: 'Block', word: wide ? 'BLOCK' : undefined })) return;
  const note = hex(`${from}: ${owner}`.replace(/[^A-Za-z0-9 .,:;()'/@_+-]/g, '').slice(0, 120));
  try {
    let res;
    try { res = await call('block-add', [hex(network), note]); }
    catch (err) {
      const why = errText(err);
      if (!/signed in successfully here/.test(why)) throw err;
      // A mailbox or upload account signed in from here. That is either its
      // owner or someone with a stolen password; Matt decides.
      if (!await confirmAction({ title: `Block ${network} Anyway?`,
        text: `${why[0].toUpperCase()}${why.slice(1)}. If that sign-in was the mailbox or upload account's owner, blocking cuts them off too. If you believe the password was stolen, block it and change that password.`,
        ok: 'Block Anyway', word: 'BLOCK' })) return;
      res = await call('block-add', [hex(network), note, 'confirm-signed-in']);
    }
    const rep = res?.replaced?.length ? ` It replaces the narrower ${res.replaced.length === 1 ? 'block' : 'blocks'} on ${res.replaced.join(', ')}.` : '';
    say(`${res?.blocked || network} is blocked.${rep}`);
  } catch (err) { say('It was not blocked: ' + errText(err)); return; }
  await loadBlocked();
  if (from === 'From Sign-In Attempts') showAddress(r);    // back to the Details it came from
  else if (detailRow && !$('si-detail').hidden) showAddress(detailRow);
}

// Block an address or network typed in by hand (Blocked Addresses card).
async function blockByHand() {
  const v = await ask({ title: 'Block an Address', label: 'Address or Network (for example 203.0.113.7 or 203.0.113.0/24)', ok: 'Next' });
  if (!v) return;
  const m = /^([0-9A-Fa-f:.]{3,45})(?:\/(\d{1,3}))?$/.exec(v);
  if (!m || (!m[1].includes(':') && m[2] && +m[2] > 32) || (m[2] && +m[2] > 128)) { say('That is not an address or network.'); return; }
  const ip = m[1];
  let info = {};
  try { info = await call('ip-info', [hex(ip)]); }
  catch (err) {
    const why = errText(err);
    if (/not a public address|one of yours/.test(why)) { say(`It was not blocked: ${why}.`); return; }
    // otherwise (the registry didn't answer, say) carry on; block-add checks everything again
  }
  const single = !m[2] || (ip.includes(':') ? m[2] === '128' : m[2] === '32');
  let network = single ? ip + (ip.includes(':') ? '/128' : '/32') : v;
  if (!single && !ip.includes(':')) {        // show the network the server will block: 203.0.113.7/24 is 203.0.113.0/24
    const n = ip.split('.').reduce((a, p) => a * 256 + (+p & 255), 0), bits = +m[2];
    const base = bits === 0 ? 0 : (n - (n % 2 ** (32 - bits)));
    network = [24, 16, 8, 0].map((sh) => Math.floor(base / 2 ** sh) % 256).join('.') + '/' + bits;
  }
  const r = { ip, ...(info.geo || {}), network: info.geo?.network };
  await blockIt(network, r, info.who?.registry || {}, 'Added by hand');
}

async function unblock(network) {
  if (!await confirmAction({ title: `Unblock ${network}?`, text: 'It can reach the server again (and will be refused at sign-in as before).', ok: 'Unblock' })) return;
  try { await call('block-remove', [hex(network)]); say(`${network} is unblocked.`); }
  catch (err) { say('It was not unblocked: ' + errText(err)); return; }
  await loadBlocked();
  if (detailRow && !$('si-detail').hidden) showAddress(detailRow);
}

async function loadBlocked() {
  let d;
  try { d = await call('block-list'); }
  catch (err) { $('bl-rows').replaceChildren(row([el('span', 'Could not read the block list: ' + errText(err), 'muted'), '', '', '', '', ''])); return; }
  $('bl-state').textContent = d.blocked.length ? `${d.blocked.length} blocked` + (d.active ? '' : ' · not loaded on the server right now') : '';
  $('bl-rows').replaceChildren(...d.blocked.map((b) => row([el('span', b.network, 'mono'), [b.place, b.owner].filter(Boolean).join(' · '), el('span', b.note, 'small'),
    el('span', new Date(b.added * 1000).toLocaleString(), 'small'), el('span', b.dropped == null ? '' : `${b.dropped.toLocaleString()} packets`, 'mono small'),
    button('Unblock', '', () => unblock(b.network))])));
  if (!d.blocked.length) $('bl-rows').replaceChildren(row([el('span', 'Nothing is blocked. Open an address’s Details to block it, or use Block an Address.', 'muted'), '', '', '', '', '']));
}

async function traceTo(r) {
  if (tracing) return;
  const my = ++trSeq;
  tracing = true;
  for (const b of document.querySelectorAll('.trace-btn')) b.disabled = true;
  try { await traceRoute(r, my); }
  finally { tracing = false; for (const b of document.querySelectorAll('.trace-btn')) b.disabled = false; }
}

async function traceRoute(r, my) {
  $('si-route').hidden = false;
  $('si-route-title').textContent = `Route to ${r.ip}`;
  $('si-route-note').textContent = 'From this server outward, one line per network hop, three probes each. If the usual probes stop short, Argus tries ICMP, then TCP to port 22. Hops that don’t answer show as no reply.';
  $('si-hops').replaceChildren(row([el('span', 'Tracing (usually under a minute, up to two)…', 'muted'), '', '', '', '']));
  let t;
  try { t = await call('trace', [hex(r.ip)]); }
  catch (err) { if (my === trSeq) $('si-hops').replaceChildren(row([el('span', 'The route could not be traced: ' + errText(err), 'muted'), '', '', '', ''])); return; }
  if (my !== trSeq) return;
  $('si-route-note').textContent = (t.reached ? `Reached ${r.ip} using ${t.mode} probes.` : `Did not reach ${r.ip} itself: its network stops answering before the end, which is common. Best result shown (${t.mode}).`)
    + ` Tried: ${t.tried.join('; ')}.`;
  $('si-hops').replaceChildren(...t.hops.map((h) => row([String(h.hop), el('span', h.ip === 'private' ? 'private address' : h.ip || 'no reply', h.ip && h.ip !== 'private' ? 'mono' : 'muted'),
    h.ip && h.ip !== 'private' ? placeText(h) : '', el('span', h.network || '', 'small'), h.ms == null ? '' : h.ms.toFixed(1) + ' ms'])));
  const pts = [];
  if (typeof t.server?.lat === 'number') pts.push(mapXY(t.server.lon, t.server.lat));
  for (const h of t.hops) if (typeof h.lat === 'number') pts.push(mapXY(h.lon, h.lat));
  if (typeof t.target_geo?.lat === 'number') pts.push(mapXY(t.target_geo.lon, t.target_geo.lat));
  drawMap(siData?.rows || [], siData?.server, pts);
}
$('si-days').addEventListener('change', () => loadSignins());
$('si-refresh').addEventListener('click', () => loadSignins());
$('bl-add').addEventListener('click', () => blockByHand());

// ---------- collapsible sections (remembered on this PC) ----------
// A section marked data-collapse="name" gets a Hide/Show button (data-toggle).
// Sections built later (the Backups cards) call setupCollapse as they are made.
function setupCollapse(sec) {
  const key = 'argus-collapse-' + sec.dataset.collapse;
  const btn = sec.querySelector('[data-toggle]');
  if (!btn) return;
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
for (const sec of document.querySelectorAll('[data-collapse]')) setupCollapse(sec);

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
  // Files can always be dragged; on the server, folders can be dragged too (to move them).
  r.draggable = e.kind === 'file' || (side === srv && e.kind === 'dir');
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
    ev.dataTransfer.setData('application/x-argus', JSON.stringify({ from: side === pc ? 'pc' : 'srv', name: e.name, kind: e.kind, path: childPath(side, e.name) }));
    ev.dataTransfer.effectAllowed = side === srv ? 'copyMove' : 'copy';
  });
  if (side === srv) {
    // Right-click: move or rename this item.
    r.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      select(side, e, r);
      showContextMenu(ev.clientX, ev.clientY, [
        { label: 'Move to…', onClick: () => moveToDialog(e) },
        { label: 'Rename…', onClick: () => renameItem(e) },
      ]);
    });
    // A folder is a drop target: dropping a server item onto it moves it inside.
    if (e.kind === 'dir') {
      r.addEventListener('dragover', (ev) => {
        if (![...ev.dataTransfer.types].includes('application/x-argus')) return;
        ev.preventDefault(); ev.stopPropagation();
        ev.dataTransfer.dropEffect = 'move';
        r.classList.add('dropinto');
      });
      r.addEventListener('dragleave', () => r.classList.remove('dropinto'));
      r.addEventListener('drop', async (ev) => {
        r.classList.remove('dropinto');
        const raw = ev.dataTransfer.getData('application/x-argus');
        if (!raw) return;                               // external files: let the pane upload them
        let d; try { d = JSON.parse(raw); } catch { return; }
        if (d.from !== 'srv') return;                   // PC -> server: bubble to the pane's upload
        ev.preventDefault(); ev.stopPropagation();      // only now claim it for a server-side move
        const destDir = childPath(srv, e.name);
        if (d.path === destDir) return;                 // dropped onto itself: nothing to do
        await moveItem(srv.path, { name: d.name, kind: d.kind }, destDir, d.name);
      });
    }
  }
  return r;
}

// ---------- right-click menu ----------
let ctxMenuEl = null;
function closeContextMenu() {
  if (!ctxMenuEl) return;
  ctxMenuEl.remove();
  ctxMenuEl = null;
  document.removeEventListener('mousedown', onDocMenuDismiss, true);
  document.removeEventListener('keydown', onMenuKey, true);
  window.removeEventListener('blur', closeContextMenu);
}
function onDocMenuDismiss(ev) { if (ctxMenuEl && !ctxMenuEl.contains(ev.target)) closeContextMenu(); }
function onMenuKey(ev) { if (ev.key === 'Escape') closeContextMenu(); }
function showContextMenu(x, y, items) {
  closeContextMenu();
  const m = el('div', null, 'ctxmenu');
  for (const it of items) {
    const b = el('button', it.label, 'ctxitem');
    b.type = 'button';
    if (it.disabled) b.disabled = true;
    else b.addEventListener('click', () => { closeContextMenu(); it.onClick(); });
    m.append(b);
  }
  m.style.left = x + 'px';
  m.style.top = y + 'px';
  document.body.append(m);
  ctxMenuEl = m;
  // Keep it on screen.
  const box = m.getBoundingClientRect();
  if (box.right > window.innerWidth) m.style.left = Math.max(0, window.innerWidth - box.width - 4) + 'px';
  if (box.bottom > window.innerHeight) m.style.top = Math.max(0, window.innerHeight - box.height - 4) + 'px';
  // Added next tick so the opening click/right-click doesn't immediately dismiss it.
  setTimeout(() => {
    if (!ctxMenuEl) return;
    document.addEventListener('mousedown', onDocMenuDismiss, true);
    document.addEventListener('keydown', onMenuKey, true);
    window.addEventListener('blur', closeContextMenu);
  }, 0);
}

// ---------- move / rename ----------
// Move or rename a server item. destDir === srcDir with a new name is a rename.
async function moveItem(srcDir, entry, destDir, newName) {
  if (destDir === srcDir && newName === entry.name) return;
  // Warn if the item serves a web share: moving it changes what that share shows.
  let shares = [];
  try { shares = (await window.argus.filesShares(srcDir, entry.name)).shares || []; } catch { shares = []; }
  if (shares.length) {
    const renaming = destDir === srcDir;
    const ok = await confirmAction({ title: `${renaming ? 'Rename' : 'Move'} ${entry.name}?`,
      text: `${entry.name} serves: ${shares.join(', ')}. ${renaming ? 'Renaming' : 'Moving'} it changes what those show right away.`,
      ok: renaming ? 'Rename It' : 'Move It' });
    if (!ok) { say(''); return; }
  }
  const run = (replace) => window.argus.filesMove(srcDir, entry.name, destDir, newName, replace);
  try {
    await run(false);
  } catch (err) {
    const m = errText(err);
    if (/already there/i.test(m)) {
      if (entry.kind !== 'file') { say(`Could not move ${entry.name}: ${m}`); return; }
      const ok = await confirmAction({ title: `Replace ${newName}?`,
        text: `${destDir} already has a file called ${newName}. Its old copy is kept in the server backups first.`, ok: 'Replace' });
      if (!ok) { say(''); return; }
      try { await run(true); } catch (e2) { say(`Could not move ${entry.name}: ` + errText(e2)); return; }
    } else {
      say(`Could not move ${entry.name}: ` + m);
      return;
    }
  }
  say(destDir === srcDir ? `Renamed to ${newName}.` : `Moved ${entry.name}.`);
  await navigate(srv, srv.path);
}

async function moveToDialog(entry) {
  const dest = await pickFolder(srv.path, `Move ${entry.name} to…`);
  if (dest == null) return;
  await moveItem(srv.path, entry, dest, entry.name);
}

async function renameItem(entry) {
  const newName = await ask({ title: `Rename ${entry.name}`, label: 'New name', ok: 'Rename' });
  if (!newName || newName === entry.name) return;
  await moveItem(srv.path, entry, srv.path, newName);
}

// A navigable picker for a destination folder on the server. Resolves to the
// chosen folder path, or null if cancelled.
function pickFolder(startPath, title) {
  return new Promise((resolve) => {
    const dlg = document.createElement('dialog');
    dlg.className = 'pickfolder';
    let cur = startPath;
    const h = el('h3', title || 'Move to…');
    const pathLine = el('div', startPath, 'pickfolder-path mono');
    const list = el('div', null, 'pickfolder-list');
    const note = el('div', '', 'muted small');
    const upBtn = button('Up', '', () => load(parentOf(cur)));
    const okBtn = button('Move Here', 'primary', () => { dlg.returnValue = 'ok'; dlg.close(); });
    const cancelBtn = button('Cancel', '', () => { dlg.returnValue = 'cancel'; dlg.close(); });
    function parentOf(p) { return p === '/' ? '/' : (p.replace(/\/[^/]+$/, '') || '/'); }
    async function load(p) {
      note.textContent = 'Loading…';
      try {
        const r = await window.argus.filesList(p);
        cur = r.path;
        pathLine.textContent = r.path;
        note.textContent = '';
        const dirs = (r.entries || []).filter((x) => x.kind === 'dir');
        list.replaceChildren(...(dirs.length ? dirs.map((x) => {
          const b = el('div', x.name, 'pickfolder-row');
          b.addEventListener('click', () => load((r.path === '/' ? '' : r.path) + '/' + x.name));
          return b;
        }) : [el('div', '(no subfolders here)', 'muted small')]));
      } catch (e) { note.textContent = errText(e); }
    }
    dlg.onclose = () => { resolve(dlg.returnValue === 'ok' ? cur : null); dlg.remove(); };
    const bar = el('div', null, 'pickfolder-bar');
    bar.append(upBtn, okBtn, cancelBtn);
    const body = el('div', null, 'pickfolder-body');
    body.append(h, pathLine, list, note, bar);
    dlg.append(body);
    document.body.append(dlg);
    dlg.returnValue = 'cancel';
    dlg.showModal();
    load(startPath);
  });
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
  $('do-upload').disabled = !(pc.sel && (pc.sel.kind === 'file' || pc.sel.kind === 'dir'));
  $('do-download').disabled = !(srv.sel && srv.sel.kind === 'file' && pc.path);
  $('do-delete').disabled = !srv.sel;
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
$('pc-reload').addEventListener('click', () => navigate(pc, pc.path ?? ''));
$('srv-reload').addEventListener('click', () => navigate(srv, srv.path));

// Dropping a server item onto "Up" moves it to the parent folder.
(() => {
  const up = $('srv-up');
  up.addEventListener('dragover', (ev) => {
    if (srv.path === '/' || ![...ev.dataTransfer.types].includes('application/x-argus')) return;
    ev.preventDefault(); ev.stopPropagation();
    ev.dataTransfer.dropEffect = 'move';
    up.classList.add('dropinto');
  });
  up.addEventListener('dragleave', () => up.classList.remove('dropinto'));
  up.addEventListener('drop', async (ev) => {
    up.classList.remove('dropinto');
    const raw = ev.dataTransfer.getData('application/x-argus');
    if (!raw) return;                                   // external files: let the pane upload them
    let d; try { d = JSON.parse(raw); } catch { return; }
    if (d.from !== 'srv' || srv.path === '/') return;   // PC -> server: bubble to the pane's upload
    ev.preventDefault(); ev.stopPropagation();
    const parent = srv.path.replace(/\/[^/]+$/, '') || '/';
    if (parent === srv.path) return;
    await moveItem(srv.path, { name: d.name, kind: d.kind }, parent, d.name);
  });
})();

// ---------- delete (moves to the server's trash) and the trash ----------
$('do-delete').addEventListener('click', async () => {
  if (!srv.sel) return;
  const name = srv.sel.name;
  let shares = [];
  try { shares = (await window.argus.filesShares(srv.path, name)).shares || []; } catch (err) { shares = []; }
  const shareNote = shares.length
    ? ` Served from it: ${shares.join(', ')}. Those shares lose these files as soon as it moves.` : '';
  const ok = await confirmAction({ title: `Move ${name} to the Trash?`,
    text: `${name} is moved to the trash on the server. It stays there until you delete it for good. A folder goes with everything inside it.${shareNote}`,
    ok: 'Move to Trash' });
  if (!ok) return;
  try {
    await window.argus.filesDelete(srv.path, name);
    say(`${name} is in the trash.`);
    await navigate(srv, srv.path);
  } catch (err) { say(`Could not move ${name} to the trash: ` + errText(err)); }
});

async function loadTrashRows() {
  $('trash-rows').replaceChildren(row(['Loading…', '', '', '', '']));
  let items = [];
  try { items = (await window.argus.trashList()).items || []; }
  catch (err) { $('trash-rows').replaceChildren(row(['Could not read the trash: ' + errText(err), '', '', '', ''])); $('trash-empty').disabled = true; return; }
  $('trash-empty').disabled = items.length === 0;
  $('trash-rows').replaceChildren(...(items.length ? items.map((it) => row([
    el('span', it.name, 'mono'),
    el('span', it.original, 'mono muted small'),
    el('span', it.kind === 'folder' ? 'Folder' : 'File'),
    el('span', (it.size_b / 1e3).toFixed(1) + ' KB', 'mono'),
    trashActions(it),
  ])) : [row(['The trash is empty.', '', '', '', ''])]));
}

function trashDeleteButton(it) {
  return button('Delete for Good', 'danger', async () => {
    const ok = await confirmAction({ title: `Delete ${it.name} for Good?`,
      text: 'It is removed from the server and cannot be recovered.', ok: 'Delete for Good', word: 'delete' });
    if (!ok) return;
    try { await window.argus.trashDelete(it.id); say(`${it.name} was deleted for good.`); }
    catch (err) { say(`Could not delete ${it.name}: ` + errText(err)); }
    loadTrashRows();
  });
}

// Restore puts a trashed item back where it came from. If the spot is free it
// just moves back; if it's taken the server reports a conflict so we can ask,
// and only replaces a plain file after confirmation (keeping a backup first).
async function restoreItem(it) {
  let r;
  try { r = await window.argus.trashRestore(it.id, false); }
  catch (err) { say(`Could not restore ${it.name}: ` + errText(err)); return; }
  // The spot is taken: either refuse (a folder is in the way) or offer to replace.
  if (r && r.conflict) {
    if (!r.replaceable) {
      say(`Can't restore ${it.name}: ${r.dest} is already taken by a folder (or the trashed item is a folder). Move or rename what's there first.`);
      return;
    }
    const newer = r.newer ? ' The one there is newer than the copy in the trash.' : '';
    const ok = await confirmAction({ title: `Replace ${it.name}?`,
      text: `There is already something named ${it.name} at ${r.dest}.${newer} Replacing it keeps a backup of the current file first. Replace it?`,
      ok: 'Replace' });
    if (!ok) { say(''); return; }
    try { r = await window.argus.trashRestore(it.id, true); }
    catch (err) { say(`Could not restore ${it.name}: ` + errText(err)); return; }
  }
  say(`${it.name} restored to ${r.restored}.${r.backup ? ' The file that was there was backed up first.' : ''}`);
  loadTrashRows();
  try { if (srv.path) await navigate(srv, srv.path); } catch { /* the trash view is what matters */ }
}
function restoreButton(it) {
  return button('Restore', '', () => restoreItem(it));
}
function trashActions(it) {
  const wrap = el('span', null, 'trash-actions');
  wrap.append(restoreButton(it), trashDeleteButton(it));
  return wrap;
}

function openTrash() {
  $('trash-dlg').showModal();
  loadTrashRows();
}
$('srv-trash').addEventListener('click', openTrash);
$('trash-empty').addEventListener('click', async () => {
  const ok = await confirmAction({ title: 'Empty the Trash?',
    text: 'Everything in the trash is deleted for good and cannot be recovered.', ok: 'Empty Trash', word: 'empty' });
  if (!ok) return;
  let done = 0;
  try {
    const items = (await window.argus.trashList()).items || [];
    for (const it of items) { await window.argus.trashDelete(it.id); done++; }
    say(`The trash was emptied (${done} ${done === 1 ? 'item' : 'items'}).`);
  } catch (err) { say(`Removed ${done} before an error. Could not empty the trash: ` + errText(err)); }
  loadTrashRows();
});
$('pc-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') navigate(pc, $('pc-path').value.trim()); });
$('srv-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') navigate(srv, $('srv-path').value.trim()); });

async function upload(localPath, name) {
  const dir = srv.path; // the folder on screen when the upload started
  let plan, local;
  // Each step says so by name, so a refusal is not just 'cannot upload'.
  try { local = await window.argus.localStat(localPath); }
  catch (err) { say(`Cannot read ${name} on this PC: ` + errText(err)); return; }
  if (local.kind === 'dir') { await uploadMany([localPath]); return; }
  if (local.kind !== 'file') { say(`${name} is not an ordinary file.`); return; }
  try { plan = await window.argus.filesPlan(dir, name); }
  catch (err) { say(`Cannot upload ${name} to ${dir}: ` + errText(err)); return; }

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

// A folder, or several things at once. Everything inside is looked over
// first so one confirmation can describe the whole batch, and then it runs
// with a progress bar instead of a question per file.
async function uploadMany(localPaths) {
  const dir = srv.path; // the folder on screen when the upload started
  let scan;
  say('Looking over what is being uploaded…');
  try { scan = await window.argus.uploadScan(localPaths.slice(), dir); }
  catch (err) {
    const t = errText(err);
    // The window and the main process are updated separately; 'bad input' can
    // only come from a main process older than this window.
    say(t === 'bad input'
      ? 'Argus needs a full restart: the window has the new upload code and the rest of the app does not. Exit and open it again.'
      : `Cannot work out what to upload into ${dir || '(no folder open)'}: ` + t);
    return;
  }
  if (!scan.count) {
    say(scan.skippedCount ? `Nothing to upload: ${scan.skipped[0].name} ${scan.skipped[0].why}.` : 'There are no files to upload.');
    return;
  }

  const box = el('div');
  const dl = el('dl', null, 'plan up-summary');
  const add = (k, v) => dl.append(el('dt', k), el('dd', v));
  add('Files', `${scan.count} (${sizeText(scan.bytes)})`);
  if (scan.folders) add('New folders', String(scan.folders));
  add('Into', scan.dir);
  if (scan.owner) add('Owner', `${scan.owner}:${scan.group}`);
  add('Permissions', 'set for each file from the folder it goes into');
  if (scan.replacing) add('Already there', `${scan.replacing} of them; a copy of each is kept in /var/backups/argus first`);
  box.append(dl);

  // One choice for the whole batch, rather than a question per file.
  let mode = 'skip';
  if (scan.replacing) {
    const fs_ = el('fieldset', null, 'up-choice');
    fs_.append(el('legend', `The ${scan.replacing} already on the server`));
    for (const [value, label] of [['skip', 'Leave them alone and upload the rest'], ['replace', 'Replace them (the old copy is backed up)']]) {
      const lab = el('label');
      const r = el('input');
      r.type = 'radio'; r.name = 'up-mode'; r.value = value; r.checked = value === mode;
      r.addEventListener('change', () => { if (r.checked) mode = value; });
      lab.append(r, el('span', ' ' + label));
      fs_.append(lab);
    }
    box.append(fs_);
  }
  if (scan.capped) box.append(el('p', `Only the first ${scan.count} files are included; upload the rest separately.`, 'warn-text'));
  if (scan.skippedCount) {
    const d = el('details');
    d.append(el('summary', `${scan.skippedCount} left out`));
    const ul = el('ul');
    for (const sk of scan.skipped) ul.append(el('li', `${sk.name} — ${sk.why}`));
    if (scan.skippedCount > scan.skipped.length) ul.append(el('li', `…and ${scan.skippedCount - scan.skipped.length} more`));
    d.append(ul);
    box.append(d);
  }
  if (scan.publicWeb) box.append(el('p', 'This folder is served by a website: anyone will be able to see these files.', 'warn-text'));

  const ok = await confirmAction({
    title: `Upload ${scan.count} ${scan.count === 1 ? 'file' : 'files'}?`,
    text: scan.folders ? 'The folders are created on the server and the files copied into them.' : 'The files are copied to the server.',
    ok: 'Upload',
    extra: box,
    wide: true,
  });
  if (!ok) { say('Upload cancelled.'); return; }
  await runUpload(mode, dir, scan);
}

function showUploadProgress(p) {
  const total = p.total || 1;
  $('up-bar').value = Math.round((p.done / total) * 1000);
  $('up-prog-title').textContent = p.cancelled ? 'Stopping after this file…' : 'Uploading…';
  const bits = [`${p.done} of ${p.total}`, `${sizeText(p.bytesDone)} of ${sizeText(p.bytesTotal)}`];
  if (p.current) bits.push(p.current);
  if (p.failureCount) bits.push(`${p.failureCount} failed`);
  $('up-prog-text').textContent = bits.join(' · ');
}

async function runUpload(mode, dir, scan) {
  const panel = $('up-prog');
  const cancel = $('up-cancel');
  $('up-fail').replaceChildren();
  $('up-fail').hidden = true;
  cancel.textContent = 'Cancel';
  showUploadProgress({ total: scan.count, done: 0, bytesTotal: scan.bytes, bytesDone: 0, current: '', failureCount: 0 });
  panel.hidden = false;
  cancel.disabled = false;
  cancel.onclick = async () => { cancel.disabled = true; await window.argus.uploadCancel(); };
  say(`Uploading ${scan.count} files…`);
  // There is no push channel from the main process, so progress is polled,
  // the same way a running job is watched elsewhere in this window.
  const poll = setInterval(async () => {
    try { const p = await window.argus.uploadProgress(); if (p && !p.finished) showUploadProgress(p); } catch { /* the run itself reports */ }
  }, 400);
  let r;
  try { r = await window.argus.uploadRun(mode); }
  catch (err) { clearInterval(poll); panel.hidden = true; cancel.onclick = null; say('Upload failed: ' + errText(err)); return; }
  clearInterval(poll);
  panel.hidden = true;
  cancel.onclick = null;

  const parts = [];
  parts.push(`${r.uploaded} of ${r.total} uploaded`);
  if (r.replaced) parts.push(`${r.replaced} replaced (old copies in /var/backups/argus)`);
  if (r.left) parts.push(`${r.left} already there and left alone`);
  if (r.failureCount) parts.push(`${r.failureCount} failed`);
  if (r.cancelled) parts.push('stopped early');
  say(parts.join('; ') + '.');
  // What failed stays on screen until it is dismissed, rather than going by
  // in a message line.
  if (r.failureCount) {
    const ul = el('ul');
    for (const f of r.failures) ul.append(el('li', `${f.name} — ${f.why}`));
    if (r.failureCount > r.failures.length) ul.append(el('li', `…and ${r.failureCount - r.failures.length} more`));
    $('up-fail').replaceChildren(ul);
    $('up-fail').hidden = false;
    $('up-prog-title').textContent = `${r.failureCount} of ${r.total} did not upload`;
    $('up-prog-text').textContent = parts.join('; ') + '.';
    cancel.textContent = 'Close';
    cancel.disabled = false;
    cancel.onclick = () => { panel.hidden = true; cancel.textContent = 'Cancel'; cancel.onclick = null; };
    panel.hidden = false;
  }
  if (srv.path === dir) await navigate(srv, dir);
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
      // Read before anything is awaited: the drop's own data does not survive
      // the first await. `items` says which of them are folders, which
      // `files` alone does not, so a dropped folder stays one folder here
      // instead of arriving as everything inside it.
      const dropped = [];
      const items = e.dataTransfer.items ? [...e.dataTransfer.items] : [];
      const entries = items.map((it) => (it.kind === 'file' && it.webkitGetAsEntry ? it.webkitGetAsEntry() : null));
      if (entries.some(Boolean)) {
        items.forEach((it, i) => {
          if (it.kind !== 'file') return;
          const f = it.getAsFile();
          const p = f && window.argus.pathForFile(f);
          if (p) dropped.push([p, (entries[i] && entries[i].name) || f.name]);
        });
      } else {
        for (const f of e.dataTransfer.files) {
          const p = window.argus.pathForFile(f);
          if (p) dropped.push([p, f.name]);
        }
      }
      if (dropped.length === 1) await upload(dropped[0][0], dropped[0][1]);
      else if (dropped.length) await uploadMany(dropped.map(([p]) => p));
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
  // Arm polling and the 30-minute idle lock BEFORE any fallible await, so a session is never
  // left running with no idle bound if setup below throws.
  timer = setInterval(refresh, REFRESH_MS);
  armIdleLock();
  try {
    $('conn-detail').textContent = (await window.argus.label()) + ' · key and code · server key matched';
    await refresh();
  } catch (err) {
    // Session is up but the dashboard could not load: tear it down rather than orphan it.
    await teardownToSignIn('Could not load the dashboard: ' + clean(err) + ' Sign in again.');
  }
}

// ---------- start ----------
window.argus.label().then((l) => { $('who').textContent = `Signing in as ${l}.`; });
// A shell left from before a Reload has no reader any more: close it.
window.argus.termClose().catch(() => {});
// After a Reload the connection is still up, so go straight back to the dashboard.
window.argus.connected().then((on) => (on ? enterDashboard() : signinStep('pass')), () => signinStep('pass'));
