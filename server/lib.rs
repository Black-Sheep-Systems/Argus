//! Node bindings for Argus. Loaded only by Electron's main process; the
//! screen never sees this module. One connection at a time.

use std::path::PathBuf;

use std::sync::Arc;

use argus_core::files::Files;
use argus_core::{start_sign_in, CommandFailed, PendingSignIn, Session, Target, Terminal};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const HOST: &str = "129.121.98.1";
const USER: &str = "mattridge";
const PINNED_HOST_KEY: &str = "SHA256:GnJpNrB2FnWjtqePDOeNaWHHfK1oHvESSfdz9q2EXwY";
const HELPER: &str = "sudo -n /usr/local/sbin/argus-helper";

enum State {
    None,
    Pending(PendingSignIn),
    Connected { session: Arc<Session>, id: String },
}

// The lock is only held to swap state in and out, never while waiting on the
// network, so Disconnect and quitting are never stuck behind a slow server.
static STATE: Mutex<State> = Mutex::const_new(State::None);

fn err(e: anyhow::Error) -> Error {
    Error::from_reason(e.to_string())
}

fn key_path() -> Result<PathBuf> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map_err(|_| Error::from_reason("could not find the home folder"))?;
    Ok(PathBuf::from(home).join(".ssh").join("mattridge_vps"))
}

fn session_id() -> Result<String> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

async fn take_state() -> State {
    std::mem::replace(&mut *STATE.lock().await, State::None)
}

async fn close_state(st: State) {
    if let State::Connected { session, .. } = st {
        let _ = session.close().await;
    }
}

/// Step 1: unlock the key and present it. Resolves when the server is
/// waiting for the authenticator code.
#[napi]
pub async fn sign_in_start(passphrase: String) -> Result<()> {
    let passphrase = Zeroizing::new(passphrase);
    FILES.lock().await.take();
    close_state(take_state().await).await;
    let target = Target {
        host: HOST.into(),
        port: 22,
        user: USER.into(),
        pinned_host_key: PINNED_HOST_KEY.into(),
    };
    let pending = start_sign_in(&target, &key_path()?, passphrase).await.map_err(err)?;
    *STATE.lock().await = State::Pending(pending);
    Ok(())
}

/// Step 2: send the authenticator code. A wrong code ends the attempt;
/// signing in starts again from the passphrase.
#[napi]
pub async fn sign_in_finish(code: String) -> Result<()> {
    let code = Zeroizing::new(code);
    let State::Pending(pending) = take_state().await else {
        return Err(Error::from_reason("enter the passphrase first"));
    };
    let session = pending.finish(code).await.map_err(err)?;
    *STATE.lock().await = State::Connected { session: Arc::new(session), id: session_id()? };
    Ok(())
}

/// The helper's read-only status report, as JSON text. Errors start with
/// "NOT_CONNECTED:" when the connection is gone, and "HELPER:" when the
/// connection is fine but the report failed.
#[napi]
pub async fn status() -> Result<String> {
    let (session, id) = match &*STATE.lock().await {
        State::Connected { session, id } => (session.clone(), id.clone()),
        _ => return Err(Error::from_reason("NOT_CONNECTED: not signed in")),
    };
    if session.is_closed() {
        return Err(Error::from_reason("NOT_CONNECTED: the connection closed"));
    }
    match session.run(&format!("{HELPER} --session {id} status")).await {
        Ok(out) => Ok(out),
        Err(e) if e.downcast_ref::<CommandFailed>().is_some() => {
            Err(Error::from_reason(format!("HELPER: {e}")))
        }
        Err(e) if session.is_closed() => Err(Error::from_reason(format!("NOT_CONNECTED: {e}"))),
        Err(e) => Err(Error::from_reason(format!("HELPER: {e}"))),
    }
}

/// Helper actions Argus may call, besides `status`. Anything else is refused
/// here, before it reaches the server.
const ACTIONS: &[&str] = &[
    "activity", "updates-list", "backup-list", "rollback-list", "job-status",
    "service-restart", "backup-run", "updates-apply", "reboot", "reboot-cancel", "heph-rollback",
    "heph-diff", "heph-deploy",
    "mail-overview", "mail-dkim", "mailbox-set", "mailbox-delete", "app-passwd-add", "app-passwd-delete",
    "alias-add", "alias-delete", "mailq-flush", "mailq-delete", "mailq-deliver",
    "sites-list", "caddy-show", "caddy-check", "caddy-apply", "caddy-history", "caddy-rollback", "cert-renew", "site-add", "quarantine-release", "quarantine-delete",
    "acct-list", "acct-folders", "acct-add", "acct-set", "acct-delete", "key-add", "key-remove",
    "heph-people", "heph-company-add", "heph-user", "service-updates", "service-update", "service-update-all", "attacks", "trace", "ip-info", "block-list", "block-add", "block-remove",
];

/// Arguments go onto the server's command line, so only plain names pass.
fn safe_arg(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 2048
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !a.starts_with('-')
}

/// Run one helper action and return its JSON text. Errors carry the same
/// NOT_CONNECTED: / HELPER: prefixes as `status`.
#[napi]
pub async fn helper(action: String, args: Vec<String>) -> Result<String> {
    if !ACTIONS.contains(&action.as_str()) {
        return Err(Error::from_reason("HELPER: that action is not available"));
    }
    if args.len() > 4 || !args.iter().all(|a| safe_arg(a)) {
        return Err(Error::from_reason("HELPER: that request was not valid"));
    }
    let (session, id) = match &*STATE.lock().await {
        State::Connected { session, id } => (session.clone(), id.clone()),
        _ => return Err(Error::from_reason("NOT_CONNECTED: not signed in")),
    };
    if session.is_closed() {
        return Err(Error::from_reason("NOT_CONNECTED: the connection closed"));
    }
    let mut cmd = format!("{HELPER} --session {id} {action}");
    for a in &args {
        cmd.push(' ');
        cmd.push_str(a);
    }
    match session.run(&cmd).await {
        Ok(out) => Ok(out),
        Err(e) if session.is_closed() && e.downcast_ref::<CommandFailed>().is_none() => {
            Err(Error::from_reason(format!("NOT_CONNECTED: {e}")))
        }
        Err(e) => Err(Error::from_reason(format!("HELPER: {e}"))),
    }
}

/// Helper actions that take a password, which goes to the server on stdin
/// (never on the command line). `secret` is the password Matt typed, or
/// "generate" for the server to make one and show it once.
const SECRET_ACTIONS: &[&str] = &["mailbox-add", "mailbox-password", "heph-staff-add", "heph-user-add", "heph-user"];

#[napi]
pub async fn helper_secret(action: String, args: Vec<String>, secret: String) -> Result<String> {
    let secret = Zeroizing::new(secret);
    if !SECRET_ACTIONS.contains(&action.as_str()) {
        return Err(Error::from_reason("HELPER: that action is not available"));
    }
    if args.len() > 4 || !args.iter().all(|a| safe_arg(a)) || secret.len() > 1024 {
        return Err(Error::from_reason("HELPER: that request was not valid"));
    }
    let (session, id) = connected_session().await?;
    let mut cmd = format!("{HELPER} --session {id} {action}");
    for a in &args {
        cmd.push(' ');
        cmd.push_str(a);
    }
    let input = Zeroizing::new(secret.as_bytes().to_vec());
    match session.run_with_input(&cmd, &input).await {
        Ok(out) => Ok(out),
        Err(e) if session.is_closed() && e.downcast_ref::<CommandFailed>().is_none() => {
            Err(Error::from_reason(format!("NOT_CONNECTED: {e}")))
        }
        Err(e) => Err(Error::from_reason(format!("HELPER: {e}"))),
    }
}

#[napi]
pub async fn disconnect() -> Result<()> {
    FILES.lock().await.take();
    TERM_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let t = TERM.lock().await.take();
    if let Some(t) = t {
        let _ = t.close().await;
    }
    close_state(take_state().await).await;
    Ok(())
}

/// True while signed in with a live connection (used when the screen reloads).
#[napi]
pub async fn connected() -> bool {
    match &*STATE.lock().await {
        State::Connected { session, .. } => !session.is_closed(),
        _ => false,
    }
}

// ---------- terminal ----------

static TERM: Mutex<Option<Arc<Terminal>>> = Mutex::const_new(None);
// Bumped by every open and close, so an open that finishes after a newer
// open or a close throws its shell away instead of keeping it.
static TERM_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn clamp_size(cols: u32, rows: u32) -> (u32, u32) {
    (cols.clamp(10, 500), rows.clamp(3, 300))
}

/// Open a shell on the server (one at a time; opening again replaces it).
#[napi]
pub async fn term_open(cols: u32, rows: u32) -> Result<()> {
    let session = match &*STATE.lock().await {
        State::Connected { session, .. } if !session.is_closed() => session.clone(),
        _ => return Err(Error::from_reason("NOT_CONNECTED: not signed in")),
    };
    let (c, r) = clamp_size(cols, rows);
    let gen = TERM_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let old = TERM.lock().await.take();
    if let Some(old) = old {
        let _ = old.close().await;
    }
    let term = Arc::new(session.open_shell(c, r).await.map_err(err)?);
    let mut slot = TERM.lock().await;
    if TERM_GEN.load(std::sync::atomic::Ordering::SeqCst) != gen {
        drop(slot);
        let _ = term.close().await;
        return Err(Error::from_reason("superseded by a newer terminal"));
    }
    if let Some(prev) = slot.replace(term) {
        drop(slot);
        let _ = prev.close().await;
    }
    Ok(())
}

async fn current_term() -> Result<Arc<Terminal>> {
    TERM.lock().await.clone().ok_or_else(|| Error::from_reason("the terminal is not open"))
}

/// Next output from the shell. Resolves within about 15 seconds; `null`
/// means the shell has ended.
#[napi]
pub async fn term_read() -> Result<Option<Buffer>> {
    let term = current_term().await?;
    match term.read(std::time::Duration::from_secs(15)).await {
        Some(bytes) => Ok(Some(bytes.into())),
        None => {
            // Make sure the server side is closed too (it may still be open
            // if Argus stopped reading, e.g. after too much output).
            let _ = term.close().await;
            let mut slot = TERM.lock().await;
            if slot.as_ref().is_some_and(|t| Arc::ptr_eq(t, &term)) {
                *slot = None;
            }
            Ok(None)
        }
    }
}

/// Keystrokes and pasted text for the shell.
#[napi]
pub async fn term_write(data: Buffer) -> Result<()> {
    if data.len() > 64 * 1024 {
        return Err(Error::from_reason("too much at once"));
    }
    let bytes = data.to_vec();
    current_term().await?.write(&bytes).await.map_err(err)
}

#[napi]
pub async fn term_resize(cols: u32, rows: u32) -> Result<()> {
    let (c, r) = clamp_size(cols, rows);
    current_term().await?.resize(c, r).await.map_err(err)
}

#[napi]
pub async fn term_close() -> Result<()> {
    TERM_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let t = TERM.lock().await.take();
    if let Some(t) = t {
        let _ = t.close().await;
    }
    Ok(())
}

// ---------- files ----------

static FILES: Mutex<Option<Arc<Files>>> = Mutex::const_new(None);

async fn connected_session() -> Result<(Arc<Session>, String)> {
    match &*STATE.lock().await {
        State::Connected { session, id } if !session.is_closed() => Ok((session.clone(), id.clone())),
        _ => Err(Error::from_reason("NOT_CONNECTED: not signed in")),
    }
}

async fn files() -> Result<Arc<Files>> {
    if let Some(f) = FILES.lock().await.as_ref() {
        return Ok(f.clone());
    }
    // Opened without holding the lock, so Disconnect is never kept waiting.
    let (session, _) = connected_session().await?;
    let f = Arc::new(session.open_files().await.map_err(err)?);
    let mut slot = FILES.lock().await;
    Ok(slot.get_or_insert(f).clone())
}

/// A failed file operation may mean the SFTP channel broke; drop it so the
/// next call opens a fresh one.
async fn files_failed(e: anyhow::Error) -> Error {
    FILES.lock().await.take();
    err(e)
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Run a helper action whose arguments Argus built itself (hex-encoded paths,
/// numbers, fixed words), returning its JSON or the helper's refusal.
async fn helper_internal(action: &str, args: &[String]) -> Result<String> {
    let (session, id) = connected_session().await?;
    let mut cmd = format!("{HELPER} --session {id} {action}");
    for a in args {
        if !a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
            return Err(Error::from_reason("internal: unsafe argument"));
        }
        cmd.push(' ');
        cmd.push_str(a);
    }
    session.run(&cmd).await.map_err(|e| Error::from_reason(e.to_string()))
}

/// Record a download in the server's Activity log (best effort).
async fn note(op: &str, path: &str) -> bool {
    // The helper takes at most 4096 bytes of path; cut on a character boundary.
    let mut end = path.len().min(4096);
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    let h = hex(&path[..end]);
    helper_internal("note-file", &[op.to_string(), h]).await.is_ok()
}

fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::from_reason(e.to_string()))
}

macro_rules! try_files {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(files_failed(e).await),
        }
    };
}

#[napi]
pub async fn files_list(path: String) -> Result<String> {
    json(&try_files!(files().await?.list(&path).await))
}

#[napi]
pub async fn files_plan(dir: String, name: String) -> Result<String> {
    json(&try_files!(files().await?.plan_upload(&dir, &name).await))
}

/// Upload exactly what Matt confirmed: the plan is worked out again and must
/// match the folder, owner, mode and replace-or-new he saw, or nothing happens.
#[napi]
pub async fn files_upload(
    local_path: String,
    dir: String,
    name: String,
    exists: bool,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<String> {
    let f = files().await?;
    let plan = try_files!(f.plan_upload(&dir, &name).await);
    if plan.dir != dir || plan.exists != exists || plan.uid != uid || plan.gid != gid || plan.mode != mode {
        return Err(Error::from_reason(format!("{} changed on the server since you confirmed; look again", plan.target)));
    }
    let tmp = try_files!(f.put_temp(std::path::Path::new(&local_path), &plan.dir).await);
    let args = vec![
        hex(&plan.dir),
        tmp.clone(),
        hex(&name),
        uid.to_string(),
        gid.to_string(),
        format!("{mode:o}"),
        if exists { "1" } else { "0" }.to_string(),
    ];
    match helper_internal("file-commit", &args).await {
        Ok(out) => Ok(out),
        Err(e) if e.reason.contains("took too long") => Err(Error::from_reason(format!(
            "the server did not say whether {} was replaced in time; refresh the folder to see what happened",
            plan.target
        ))),
        Err(e) => {
            if helper_internal("file-discard", &[hex(&plan.dir), tmp.clone()]).await.is_err() {
                f.remove_temp(&plan.dir, &tmp).await;
            }
            Err(e)
        }
    }
}

#[napi]
pub async fn files_download(remote: String, local_path: String) -> Result<String> {
    let n = try_files!(files().await?.download(&remote, std::path::Path::new(&local_path)).await);
    let logged = note("download", &remote).await;
    Ok(format!("{{\"bytes\":{n},\"logged\":{logged}}}"))
}

#[napi]
pub async fn files_mkdir(dir: String, name: String) -> Result<String> {
    let real = try_files!(files().await?.canonical(&dir).await);
    argus_core::files::check_name(&name).map_err(err)?;
    helper_internal("file-mkdir", &[hex(&real), hex(&name)]).await
}

/// Send a Hephaestus package built on this PC to the server and stage it
/// (checked and unpacked beside the live source; nothing live changes).
#[napi]
pub async fn deploy_stage(local_tar: String, commit: String) -> Result<String> {
    if commit.len() < 7 || commit.len() > 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(Error::from_reason("not a commit id"));
    }
    let f = files().await?;
    let tmp = try_files!(f.put_temp(std::path::Path::new(&local_tar), "/var/lib/argus/deploy").await);
    let r = helper_internal("heph-stage", &[tmp.clone(), commit]).await;
    if r.is_err() {
        // the helper removes the package itself once it starts; this covers
        // the cases where it never got that far
        f.remove_temp("/var/lib/argus/deploy", &tmp).await;
    }
    r
}

#[napi(object)]
pub struct PeekResult {
    pub size: f64,
    pub mtime: u32,
    pub data: Buffer,
}

/// The first part of a server file, for previews (5 MB at most).
#[napi]
pub async fn files_peek(path: String, image: bool) -> Result<PeekResult> {
    // Pictures need the whole file (up to 5 MB); text previews need only the start.
    let max = if image { 5 * 1024 * 1024 } else { 16 * 1024 };
    let p = try_files!(files().await?.peek(&path, max).await);
    Ok(PeekResult { size: p.size as f64, mtime: p.mtime, data: p.data.into() })
}

#[napi]
pub fn connection_label() -> String {
    format!("{USER}@{HOST}")
}
