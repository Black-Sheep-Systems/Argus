// Argus main process. Holds the only link to the server (the Rust module);
// the window gets a short, fixed list of calls through preload.js.
const { app, BrowserWindow, clipboard, dialog, ipcMain, nativeTheme, session, shell } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');
const os = require('os');

// Development setup: load the newest build of the native module. Each build
// gets its own file name, because Windows keeps a loaded module locked (an
// overwrite during Restart would fail and leave the old one in use).
const fs = require('fs');
const NATIVE_DIR = path.join(__dirname, 'native');
const BUILT = path.join(__dirname, '..', 'native', 'target', 'release', 'argus_native.dll');
function pickNative() {
  fs.mkdirSync(NATIVE_DIR, { recursive: true });
  if (!app.isPackaged && fs.existsSync(BUILT)) {
    const stamp = Math.floor(fs.statSync(BUILT).mtimeMs);
    const target = path.join(NATIVE_DIR, `argus_native-${stamp}.node`);
    if (!fs.existsSync(target)) fs.copyFileSync(BUILT, target);
    // Clear older builds; any still locked by a closing copy of Argus stay until next time.
    for (const f of fs.readdirSync(NATIVE_DIR)) {
      if (/^argus_native(-\d+)?\.node$/.test(f) && f !== path.basename(target)) {
        try { fs.rmSync(path.join(NATIVE_DIR, f)); } catch { /* in use */ }
      }
    }
    return target;
  }
  return path.join(NATIVE_DIR, 'argus_native.node');
}
const native = require(pickNative());
const PAGE = pathToFileURL(path.join(__dirname, 'renderer', 'index.html')).href;
const RENDERER_DIR = pathToFileURL(path.join(__dirname, 'renderer')).href + '/';

let win = null;

function createWindow() {
	win = new BrowserWindow({
		width: 1360,
		height: 900,
		minWidth: 900,
		minHeight: 600,
		title: 'Argus',
		icon: path.join(__dirname, 'assets', 'argus.ico'),
		backgroundColor: nativeTheme.shouldUseDarkColors ? '#0F1A24' : '#EEF2F1',
		autoHideMenuBar: true,
		webPreferences: {
		preload: path.join(__dirname, 'preload.js'),
		contextIsolation: true,
		sandbox: true,
		nodeIntegration: false,
		webviewTag: false,
		spellcheck: false,
		devTools: !app.isPackaged,
    },
  });
  win.removeMenu();
  win.loadURL(PAGE);
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.on('closed', () => { win = null; });
}

// Only our own page, in our own window, may call in.
function fromOurPage(event) {
  return win !== null && event.sender === win.webContents && event.senderFrame?.url === PAGE;
}

function handle(channel, fn) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (!fromOurPage(event)) throw new Error('refused');
    return fn(...args);
  });
}

function text(v, max) {
  if (typeof v !== 'string' || v.length === 0 || v.length > max) throw new Error('bad input');
  return v;
}

handle('argus:signInStart', (passphrase) => native.signInStart(text(passphrase, 1024)));
handle('argus:signInFinish', (code) => {
  if (typeof code !== 'string' || !/^[0-9]{6,8}$/.test(code)) throw new Error('the code is 6 to 8 digits');
  return native.signInFinish(code);
});
handle('argus:status', async () => {
  const out = await native.status();
  try {
    return JSON.parse(out);
  } catch {
    throw new Error('HELPER: the status report could not be read');
  }
});
handle('argus:disconnect', () => native.disconnect());
handle('argus:helper', async (action, args) => {
  if (typeof action !== 'string' || !Array.isArray(args) || args.length > 4 || !args.every((x) => typeof x === 'string')) {
    throw new Error('HELPER: that request was not valid');
  }
  const out = await native.helper(action, args);
  try {
    return JSON.parse(out);
  } catch {
    throw new Error('HELPER: the server reply could not be read');
  }
});
handle('argus:label', () => native.connectionLabel());
handle('argus:connected', () => native.connected());
const size = (n) => (Number.isInteger(n) && n > 0 && n < 1000 ? n : 80);
handle('argus:termOpen', (cols, rows) => native.termOpen(size(cols), size(rows)));
handle('argus:termRead', () => native.termRead());
handle('argus:termWrite', (data) => {
  if (typeof data !== 'string' || data.length > 65536) throw new Error('bad input');
  return native.termWrite(Buffer.from(data, 'utf8'));
});
handle('argus:termResize', (cols, rows) => native.termResize(size(cols), size(rows)));
handle('argus:termClose', () => native.termClose());
// ---------- files ----------
const str = (v, max = 4096) => {
  if (typeof v !== 'string' || !v || v.length > max || v.includes('\0')) throw new Error('bad input');
  return v;
};
const localAbs = (p) => {
  str(p);
  if (!path.isAbsolute(p)) throw new Error('bad input');
  return path.resolve(p);
};

// The PC side of the file browser. '' lists the drives.
handle('argus:localList', async (dir) => {
  if (dir === '') {
    const drives = [];
    for (const l of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
      const d = `${l}:\\`;
      try { await fs.promises.access(d); drives.push({ name: d, kind: 'dir', size: 0, mtime: 0 }); } catch { /* not present */ }
    }
    return { path: '', parent: null, entries: drives };
  }
  const p = localAbs(dir);
  const ents = await fs.promises.readdir(p, { withFileTypes: true });
  const entries = [];
  for (const e of ents) {
    let st = null;
    try { st = await fs.promises.stat(path.join(p, e.name)); } catch { continue; }
    entries.push({ name: e.name, kind: st.isDirectory() ? 'dir' : st.isFile() ? 'file' : 'other', size: st.size, mtime: Math.floor(st.mtimeMs / 1000) });
  }
  entries.sort((a, b) => (a.kind !== 'dir') - (b.kind !== 'dir') || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  const parent = path.dirname(p) === p ? '' : path.dirname(p);
  return { path: p, parent, entries };
});
handle('argus:localHome', () => os.homedir());

handle('argus:filesList', async (p) => JSON.parse(await native.filesList(str(p))));
handle('argus:filesPlan', async (dir, name) => JSON.parse(await native.filesPlan(str(dir), str(name, 255))));
handle('argus:localStat', async (localPath) => {
  const st = await fs.promises.stat(localAbs(localPath));
  return { kind: st.isDirectory() ? 'dir' : st.isFile() ? 'file' : 'other', size: st.size, mtime: Math.floor(st.mtimeMs / 1000) };
});
// First part of a PC file, for previews.
handle('argus:localPeek', async (localPath, image) => {
  const p = localAbs(localPath);
  const st = await fs.promises.stat(p);
  if (!st.isFile()) throw new Error('only files can be previewed');
  const fh = await fs.promises.open(p, 'r');
  try {
    const buf = Buffer.alloc(Math.min(st.size, image === true ? 5 * 1024 * 1024 : 16 * 1024));
    await fh.read(buf, 0, buf.length, 0);
    return { size: st.size, mtime: Math.floor(st.mtimeMs / 1000), data: buf };
  } finally { await fh.close(); }
});
handle('argus:filesPeek', async (remotePath, image) => {
  const r = await native.filesPeek(str(remotePath), image === true);
  return { size: r.size, mtime: r.mtime, data: r.data };
});
handle('argus:filesUpload', async (localPath, plan) => {
  const p = localAbs(localPath);
  const st = await fs.promises.stat(p);
  if (!st.isFile()) throw new Error('only files can be uploaded (not folders, yet)');
  const ok = plan && typeof plan === 'object' && typeof plan.exists === 'boolean'
    && [plan.uid, plan.gid, plan.mode].every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff);
  if (!ok) throw new Error('bad input');
  if (plan.name !== path.basename(p)) throw new Error('the file confirmed is not the file being uploaded');
  return JSON.parse(await native.filesUpload(p, str(plan.dir), path.basename(p), plan.exists, plan.uid, plan.gid, plan.mode));
});
handle('argus:filesDownload', async (remotePath, localDir, overwrite) => {
  const dir = localAbs(localDir);
  const name = str(remotePath).split('/').pop();
  // Windows refuses these names or treats them as devices.
  const reserved = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;
  if (!name || name === '.' || name === '..' || /[<>:"\\|?*\x00-\x1f]/.test(name) || /[. ]$/.test(name) || reserved.test(name)) {
    throw new Error('that file name cannot be used on Windows');
  }
  const target = path.join(dir, name);
  if (path.dirname(target) !== dir) throw new Error('bad input');
  let claimed = false;
  if (!overwrite) {
    // Claim the name now so nothing can slip in between the check and the download.
    try { await (await fs.promises.open(target, 'wx')).close(); claimed = true; } catch (e) {
      if (e.code === 'EEXIST') throw new Error('EXISTS: ' + target);
      throw e;
    }
  }
  try {
    return JSON.parse(await native.filesDownload(remotePath, target));
  } catch (e) {
    if (claimed) await fs.promises.rm(target, { force: true });
    throw e;
  }
});
handle('argus:filesMkdir', async (dir, name) => JSON.parse(await native.filesMkdir(str(dir), str(name, 255))));

// ---------- folder and many-file uploads ----------
// A batch is looked over first, so one confirmation can describe the whole
// thing, and then run from that stored scan. The window never hands the file
// list back, so what goes up is what was scanned and confirmed.
const UPLOAD_MAX_FILES = 5000;
const UPLOAD_MAX_DEPTH = 32;
const UPLOAD_MAX_ROOTS = UPLOAD_MAX_FILES; // dropping a folder's contents is one item each
let uploadScan = null; // what the last scan found, waiting to be confirmed
let uploadBatch = null; // the run in progress, or the last one that finished

// The same rule the server side uses, applied here so a bad name is reported
// in the summary instead of failing halfway through the batch.
const okName = (n) => typeof n === 'string' && !!n && n !== '.' && n !== '..'
  && n.length <= 255 && !n.includes('/') && !n.includes('\\') && !n.includes('\0');
const joinRemote = (dir, rel) => (dir === '/' ? '' : dir.replace(/\/+$/, '')) + '/' + rel;
const splitRel = (rel) => {
  const i = rel.lastIndexOf('/');
  return i < 0 ? ['', rel] : [rel.slice(0, i), rel.slice(i + 1)];
};
const why = (err) => String((err && err.message) || err).slice(0, 300);

// Everything under one dropped folder. Breadth first, so a folder always
// comes out before the folders inside it and can be created in that order.
async function walkLocal(rootPath, rootRel, out) {
  const queue = [[rootPath, rootRel, 0]];
  while (queue.length) {
    const [dirPath, rel, depth] = queue.shift();
    out.dirs.push(rel);
    if (depth >= UPLOAD_MAX_DEPTH) { out.skipped.push({ name: rel, why: 'folders nested deeper than this are left alone' }); continue; }
    let ents;
    try { ents = await fs.promises.readdir(dirPath, { withFileTypes: true }); }
    catch (err) { out.skipped.push({ name: rel, why: why(err) }); continue; }
    for (const e of ents) {
      const childRel = rel + '/' + e.name;
      if (!okName(e.name)) { out.skipped.push({ name: childRel, why: 'this name cannot be used on the server' }); continue; }
      if (e.isSymbolicLink()) { out.skipped.push({ name: childRel, why: 'a shortcut, not a real file' }); continue; }
      const full = path.join(dirPath, e.name);
      if (e.isDirectory()) { queue.push([full, childRel, depth + 1]); continue; }
      if (!e.isFile()) { out.skipped.push({ name: childRel, why: 'not an ordinary file' }); continue; }
      if (out.files.length >= UPLOAD_MAX_FILES) { out.capped = true; continue; }
      let st;
      try { st = await fs.promises.stat(full); }
      catch (err) { out.skipped.push({ name: childRel, why: why(err) }); continue; }
      out.files.push({ local: full, rel: childRel, size: st.size });
      out.bytes += st.size;
    }
  }
}

// What is being uploaded and what is already there, for the one confirmation.
handle('argus:uploadScan', async (localPaths, remoteDir) => {
  // Crossing the bridge can turn the list into something array-like rather
  // than an array, so take it as it comes. Said plainly, so a refusal here
  // names what was wrong instead of 'bad input'.
  if (localPaths && typeof localPaths === 'object' && !Array.isArray(localPaths)) {
    try { localPaths = Array.from(localPaths); } catch { /* reported next */ }
  }
  if (!Array.isArray(localPaths)) throw new Error(`what was dropped did not arrive as a list (${typeof localPaths})`);
  if (!localPaths.length) throw new Error('nothing was dropped');
  if (localPaths.length > UPLOAD_MAX_ROOTS) throw new Error(`${localPaths.length} things at once is too many; ${UPLOAD_MAX_ROOTS} is the limit`);
  if (typeof remoteDir !== 'string' || !remoteDir) throw new Error('no folder is open on the server to upload into');
  if (remoteDir.length > 4096 || remoteDir.includes('\0')) throw new Error(`the server folder is not a usable path: ${JSON.stringify(remoteDir.slice(0, 120))}`);
  const dir = remoteDir;
  const out = { files: [], dirs: [], bytes: 0, skipped: [], capped: false };
  for (const given of localPaths) {
    if (typeof given !== 'string' || !given || given.includes('\0')) {
      out.skipped.push({ name: String(given).slice(0, 120), why: 'this is not a path on this PC' });
      continue;
    }
    if (!path.isAbsolute(given)) {
      out.skipped.push({ name: given.slice(0, 120), why: 'Windows did not give a full path for this' });
      continue;
    }
    const full = path.resolve(given);
    const name = path.basename(full);
    if (!okName(name)) { out.skipped.push({ name, why: 'this name cannot be used on the server' }); continue; }
    let st;
    try { st = await fs.promises.lstat(full); }
    catch (err) { out.skipped.push({ name, why: why(err) }); continue; }
    if (st.isSymbolicLink()) { out.skipped.push({ name, why: 'a shortcut, not a real file' }); continue; }
    if (st.isDirectory()) { await walkLocal(full, name, out); continue; }
    if (!st.isFile()) { out.skipped.push({ name, why: 'not an ordinary file' }); continue; }
    if (out.files.length >= UPLOAD_MAX_FILES) { out.capped = true; continue; }
    out.files.push({ local: full, rel: name, size: st.size });
    out.bytes += st.size;
  }

  // One listing per destination folder, rather than a question per file.
  const listed = new Map();
  const namesIn = async (relDir) => {
    if (listed.has(relDir)) return listed.get(relDir);
    let names = null;
    try {
      const l = JSON.parse(await native.filesList(relDir ? joinRemote(dir, relDir) : dir));
      names = new Set((l.entries || []).map((e) => e.name));
    } catch { names = null; } // not there yet, so nothing in it is being replaced
    listed.set(relDir, names);
    return names;
  };
  let replacing = 0;
  for (const f of out.files) {
    const [relDir, base] = splitRel(f.rel);
    const names = await namesIn(relDir);
    if (names && names.has(base)) replacing++;
  }
  const newDirs = [];
  for (const d of out.dirs) {
    const [relDir, base] = splitRel(d);
    const names = await namesIn(relDir);
    if (!names || !names.has(base)) newDirs.push(d);
  }

  // Owner and the public-website warning come from the folder itself. The
  // permissions of each file are worked out again as it goes up, so they are
  // described rather than promised here.
  let probe = {};
  try { probe = JSON.parse(await native.filesPlan(dir, '.argus-upload-check')); } catch { /* described as unknown */ }

  uploadScan = { dir, files: out.files, dirs: newDirs, bytes: out.bytes };
  return {
    dir,
    count: out.files.length,
    bytes: out.bytes,
    folders: newDirs.length,
    replacing,
    skipped: out.skipped.slice(0, 50),
    skippedCount: out.skipped.length,
    capped: out.capped,
    owner: probe.owner || null,
    group: probe.group || null,
    publicWeb: !!probe.public_web,
  };
});

// Run the batch that was just confirmed. `mode` says what to do with the
// files already on the server: replace them (old copy backed up, as for a
// single file) or leave them alone.
handle('argus:uploadRun', async (mode) => {
  if (mode !== 'replace' && mode !== 'skip') throw new Error('bad input');
  if (uploadBatch && !uploadBatch.finished) throw new Error('an upload is already running');
  if (!uploadScan) throw new Error('nothing has been looked over to upload');
  const s = uploadScan;
  uploadScan = null; // one run per confirmation
  const b = {
    total: s.files.length, bytesTotal: s.bytes, done: 0, bytesDone: 0, current: '',
    uploaded: 0, replaced: 0, left: 0, failures: [], cancelled: false, finished: false,
  };
  uploadBatch = b;
  try {
    for (const rel of s.dirs) {
      if (b.cancelled) break;
      const [relDir, base] = splitRel(rel);
      b.current = rel + '/';
      try { await native.filesMkdir(relDir ? joinRemote(s.dir, relDir) : s.dir, base); }
      catch (err) { b.failures.push({ name: rel, why: why(err) }); }
    }
    for (const f of s.files) {
      if (b.cancelled) break;
      b.current = f.rel;
      const [relDir, base] = splitRel(f.rel);
      const destDir = relDir ? joinRemote(s.dir, relDir) : s.dir;
      try {
        // Worked out again right before the file goes up, so the owner and
        // permissions are the folder's own and nothing stale is used.
        const plan = JSON.parse(await native.filesPlan(destDir, base));
        if (plan.exists && mode === 'skip') {
          b.left++;
        } else {
          await native.filesUpload(f.local, plan.dir, base, plan.exists, plan.uid, plan.gid, plan.mode);
          b.uploaded++;
          if (plan.exists) b.replaced++;
        }
      } catch (err) {
        // One bad file does not abandon the rest; they are all reported at the end.
        b.failures.push({ name: f.rel, why: why(err) });
      }
      b.done++;
      b.bytesDone += f.size;
    }
  } finally {
    b.current = '';
    b.finished = true;
  }
  return {
    total: b.total, done: b.done, uploaded: b.uploaded, replaced: b.replaced, left: b.left,
    bytesDone: b.bytesDone, cancelled: b.cancelled,
    failures: b.failures.slice(0, 50), failureCount: b.failures.length,
  };
});

handle('argus:uploadProgress', async () => (uploadBatch ? {
  total: uploadBatch.total, bytesTotal: uploadBatch.bytesTotal, done: uploadBatch.done,
  bytesDone: uploadBatch.bytesDone, current: uploadBatch.current, uploaded: uploadBatch.uploaded,
  replaced: uploadBatch.replaced, left: uploadBatch.left, failureCount: uploadBatch.failures.length,
  cancelled: uploadBatch.cancelled, finished: uploadBatch.finished,
} : null));

// Stops after the file being copied finishes, so nothing is left half written.
handle('argus:uploadCancel', async () => {
  if (uploadBatch && !uploadBatch.finished) uploadBatch.cancelled = true;
  return true;
});
// Deleted items go to the server's trash; only trashDelete removes them for good.
handle('argus:filesDelete', async (dir, name) => {
  name = str(name, 255);
  if (!name || name === '.' || name === '..' || /[\/\\\0]/.test(name)) throw new Error('bad name');
  return JSON.parse(await native.filesTrash(str(dir), name));
});
handle('argus:filesShares', async (dir, name) => JSON.parse(await native.filesShares(str(dir), str(name, 255))));
// Move or rename on the server. new name is where it lands in destDir (same as
// name for a plain move; destDir equals srcDir for a rename).
handle('argus:filesMove', async (srcDir, name, destDir, newName, replace) => {
  const badName = (n) => !n || n === '.' || n === '..' || /[\/\\\0]/.test(n);
  name = str(name, 255);
  newName = str(newName, 255);
  if (badName(name) || badName(newName)) throw new Error('bad name');
  return JSON.parse(await native.filesMove(str(srcDir), name, str(destDir), newName, replace === true));
});
handle('argus:trashList', async () => JSON.parse(await native.trashList()));
handle('argus:trashDelete', async (id) => {
  if (typeof id !== 'string' || !/^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$/.test(id)) throw new Error('bad input');
  return JSON.parse(await native.trashDelete(id));
});
handle('argus:trashRestore', async (id, replace) => {
  if (typeof id !== 'string' || !/^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$/.test(id)) throw new Error('bad input');
  return JSON.parse(await native.trashRestore(id, replace === true));
});

// ---------- Hephaestus deploy (source on this PC) ----------
const { execFile } = require('child_process');
// ---------- server helper update ----------
// A new helper is dropped here (by Matt or Claude). Argus offers to install it only
// while this file exists and differs from the helper on the server.
const HELPER_UPDATE = 'D:\\Argus\\helper-update\\argus-helper.new';
const HELPER_MAX = 4 * 1024 * 1024;
const crypto = require('crypto');
let helperFileCache = null;   // re-hashed only when its size or time changes
async function helperUpdateFile(fresh) {
  let st;
  try { st = await fs.promises.lstat(HELPER_UPDATE); } catch { helperFileCache = null; return null; }
  if (!st.isFile() || st.size === 0 || st.size > HELPER_MAX) { helperFileCache = null; return null; }
  const key = st.size + ':' + st.mtimeMs;
  if (!fresh && helperFileCache && helperFileCache.key === key) return helperFileCache.info;
  const data = await fs.promises.readFile(HELPER_UPDATE);
  if (data.length === 0 || data.length > HELPER_MAX) { helperFileCache = null; return null; }
  const info = { path: HELPER_UPDATE, size: data.length, mtime: Math.floor(st.mtimeMs / 1000),
                 sha256: crypto.createHash('sha256').update(data).digest('hex') };
  helperFileCache = { key, info };
  return info;
}
handle('argus:helperUpdateLocal', () => helperUpdateFile(false));
// Installing runs root code on the server, so the confirmation is a native dialog here,
// not something the window can answer for itself.
handle('argus:helperInstall', async (sha256) => {
  if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) throw new Error('bad input');
  const now = await helperUpdateFile(true);
  if (!now || now.sha256 !== sha256) throw new Error('the file in ' + HELPER_UPDATE + ' changed; look again');
  const { response } = await dialog.showMessageBox(win, {
    type: 'warning',
    title: 'Install the new server helper?',
    message: 'Replace the helper on the server with this file?',
    detail: `${HELPER_UPDATE}\n${now.size} bytes\n\nsha256:\n${sha256}\n\n`
      + 'Compare this hash with the one you were given before you install. The server checks the file against it '
      + 'and keeps the current helper as a backup.',
    buttons: ['Cancel', 'Install Helper'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
  });
  if (response !== 1) return { cancelled: true };
  return JSON.parse(await native.helperInstall(HELPER_UPDATE, sha256));
});

const HEPH_REPO = 'D:\\Github\\Hephaestus-MSP';
const PACKAGE_PATHS = ['Cargo.toml', 'Cargo.lock', 'crates', 'migrations', 'deploy', 'tools/test/rls_invariants.sql'];
function git(args) {
  return new Promise((resolve, reject) => {
    execFile('git', ['-C', HEPH_REPO, ...args], { windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (err, out, errout) => {
      if (err) reject(new Error((errout || err.message).trim().split('\n').pop()));
      else resolve(out);
    });
  });
}
// What would be deployed: the last commit (uncommitted work is not included).
handle('argus:deploySource', async () => {
  const commit = (await git(['rev-parse', '--short=7', 'HEAD'])).trim();
  const [subject, date] = (await git(['log', '-1', '--format=%s%x1f%cI'])).trim().split('\x1f');
  const branch = (await git(['rev-parse', '--abbrev-ref', 'HEAD'])).trim();
  const dirty = (await git(['status', '--porcelain', '--', ...PACKAGE_PATHS])).trim().split('\n').filter(Boolean).length;
  return { repo: HEPH_REPO, commit, subject, date, branch, uncommitted: dirty };
});
handle('argus:deployPrepare', async (commit) => {
  if (typeof commit !== 'string' || !/^[0-9a-f]{7,40}$/.test(commit)) throw new Error('bad input');
  const head = (await git(['rev-parse', '--short=7', 'HEAD'])).trim();
  if (head !== commit) throw new Error(`the latest commit is now ${head}, not ${commit}; look again`);
  // The full id, so a branch or tag that happens to share the short name cannot be picked instead.
  const full = (await git(['rev-parse', '--verify', `${commit}^{commit}`])).trim();
  if (!/^[0-9a-f]{40}$/.test(full) || !full.startsWith(commit)) throw new Error('could not resolve that commit');
  const tmp = path.join(os.tmpdir(), `argus-heph-${commit}-${process.pid}.tar.gz`);
  try {
    // Exactly as stored in the repository: no conversion to Windows line endings
    // (core.autocrlf on this PC would otherwise change every file).
    await git(['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar.gz', '-o', tmp, full, ...PACKAGE_PATHS]);
    return JSON.parse(await native.deployStage(tmp, commit));
  } finally {
    await fs.promises.rm(tmp, { force: true });
  }
});

// ---------- mail ----------
handle('argus:helperSecret', async (action, args, secret) => {
  if (typeof action !== 'string' || !Array.isArray(args) || args.length > 4 || !args.every((x) => typeof x === 'string')
      || typeof secret !== 'string' || secret.length > 1024) {
    throw new Error('HELPER: that request was not valid');
  }
  const out = await native.helperSecret(action, args, secret);
  try { return JSON.parse(out); } catch { throw new Error('HELPER: the server reply could not be read'); }
});
// DNS checks run from this PC: the server cannot look up outside DNS.
const dnsp = require('dns').promises;
handle('argus:dnsCheck', async (domain, selector) => {
  if (typeof domain !== 'string' || !/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) throw new Error('bad input');
  if (selector != null && (typeof selector !== 'string' || !/^[a-z0-9_-]{1,63}$/i.test(selector))) throw new Error('bad input');
  const txt = async (name) => {
    try { return (await dnsp.resolveTxt(name)).map((parts) => parts.join('')); } catch (e) { return e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? [] : null; }
  };
  let mx = null;
  try { mx = (await dnsp.resolveMx(domain)).sort((a, b) => a.priority - b.priority).map((m) => m.exchange); } catch (e) { mx = e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? [] : null; }
  return {
    mx,
    spf: (await txt(domain))?.filter((t) => /^v=spf1/i.test(t)) ?? null,
    dmarc: (await txt('_dmarc.' + domain))?.filter((t) => /^v=DMARC1/i.test(t)) ?? null,
    dkim: selector ? (await txt(`${selector}._domainkey.${domain}`)) : null,
  };
});
// Two-factor resets happen in mailcow's own admin pages (its API cannot do them).
handle('argus:openMailAdmin', () => shell.openExternal('https://mail.blksheepltd.com/admin'));

handle('argus:copy', (text, sensitive) => {
  if (typeof text !== 'string' || text.length > 262144) throw new Error('bad input');
  if (!win.isFocused()) throw new Error('refused');
  clipboard.writeText(text);
  // A password is cleared again after 30 seconds, unless something else
  // was copied meanwhile. (Windows clipboard history, if switched on, may
  // still keep a copy; Argus cannot reach that.)
  if (sensitive === true) {
    setTimeout(() => { if (clipboard.readText() === text) clipboard.clear(); }, 30000);
  }
});
handle('argus:app', async (op) => {
  if (op === 'reload') {
    win.webContents.reload();
  } else if (op === 'restart') {
    await native.disconnect();
    app.relaunch();
    app.exit(0);
  } else if (op === 'exit') {
    await native.disconnect();
    app.quit();
  } else {
    throw new Error('unknown option');
  }
});

// One Argus at a time: a second copy would have its own separate connection.
const firstCopy = app.requestSingleInstanceLock();
if (!firstCopy) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });
}

// No other web contents (webviews, popups) may load anything.
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', (e) => e.preventDefault());
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

app.whenReady().then(() => {
  if (!firstCopy) return;
  // No camera, microphone, notifications or anything else for the page.
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  // Nothing from the network, ever: only the app's own screen files load.
  session.defaultSession.webRequest.onBeforeRequest((details, cb) => {
    const ours = details.url.startsWith(RENDERER_DIR);
    const devtools = !app.isPackaged && details.url.startsWith('devtools://');
    cb({ cancel: !(ours || devtools) });
  });
  createWindow();
});

app.on('window-all-closed', async () => {
  try { await native.disconnect(); } finally { app.quit(); }
});
