//! Argus core: the SSH connection to the Black Sheep server.
//! Phase 1 holds only the sign-in. Everything else builds on `Session`.

pub mod updater;
pub mod files;

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::MethodKind;
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use zeroize::Zeroizing;

/// How long connecting, each sign-in step, and each command may take.
pub(crate) const NET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const RUN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) async fn within<T>(limit: std::time::Duration, what: &str, f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(limit, f).await.map_err(|_| anyhow!("{what} took too long; the server did not answer"))?
}

/// Where and as whom to connect, plus the server key we expect.
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// "SHA256:..." as shown by `ssh-keygen -lf`. The connection is refused
    /// if the server presents anything else.
    pub pinned_host_key: String,
}

struct Handler {
    pinned: String,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // Only a plain host key is accepted; it must match the pinned one.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let ok = fp == self.pinned;
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ok)
    }
}

pub struct Session {
    handle: client::Handle<Handler>,
}

/// First half of signing in: unlock the key, connect (checking the pinned
/// server key), and present the key. On success the server is waiting for
/// the authenticator code; finish with [`PendingSignIn::finish`].
pub async fn start_sign_in(
    target: &Target,
    key_path: &std::path::Path,
    passphrase: Zeroizing<String>,
) -> Result<PendingSignIn> {
    if !key_path.is_file() {
        bail!("no key file at {}", key_path.display());
    }
    let key = load_secret_key(key_path, Some(passphrase.as_str()))
        .context("could not unlock the key (wrong passphrase?)")?;
    drop(passphrase);

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(600)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });
    within(NET_TIMEOUT, "signing in", connect_and_present_key(target, key, config)).await
}

async fn connect_and_present_key(
    target: &Target,
    key: russh::keys::PrivateKey,
    config: Arc<client::Config>,
) -> Result<PendingSignIn> {
    let seen = Arc::new(Mutex::new(None));
    let handler = Handler { pinned: target.pinned_host_key.clone(), seen: seen.clone() };
    let mut handle = match client::connect(config, (target.host.as_str(), target.port), handler).await {
        Ok(h) => h,
        Err(e) => match seen.lock().unwrap().clone() {
            Some(fp) if fp != target.pinned_host_key => bail!(
                "server key did not match the pinned key: server showed {fp}, expected {}",
                target.pinned_host_key
            ),
            _ => bail!("could not connect: {e}"),
        },
    };

    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let first = handle
        .authenticate_publickey(&target.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await?;
    match first {
        AuthResult::Success => {
            bail!("the server let the key in without asking for the authenticator code; two-factor is not being enforced")
        }
        AuthResult::Failure { partial_success: true, remaining_methods, .. }
            if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {}
        AuthResult::Failure { partial_success: true, .. } => {
            bail!("key accepted, but the server is not offering the authenticator step")
        }
        AuthResult::Failure { .. } => bail!("the server did not accept the key"),
    }

    let resp = handle
        .authenticate_keyboard_interactive_start(&target.user, None::<String>)
        .await?;
    Ok(PendingSignIn { handle, resp: Some(resp) })
}

/// A connection whose key was accepted and which now needs the code.
pub struct PendingSignIn {
    handle: client::Handle<Handler>,
    resp: Option<KeyboardInteractiveAuthResponse>,
}

impl PendingSignIn {
    /// Second half of signing in: send the authenticator code.
    pub async fn finish(self, code: Zeroizing<String>) -> Result<Session> {
        within(NET_TIMEOUT, "checking the code", self.finish_inner(code)).await
    }

    async fn finish_inner(mut self, code: Zeroizing<String>) -> Result<Session> {
        let mut code = Some(code);
        let mut rounds = 0;
        let mut resp = self.resp.take().ok_or_else(|| anyhow!("sign-in already finished"))?;
        loop {
            rounds += 1;
            if rounds > 4 {
                bail!("the server kept asking questions; sign-in stopped");
            }
            match resp {
                KeyboardInteractiveAuthResponse::Success => return Ok(Session { handle: self.handle }),
                KeyboardInteractiveAuthResponse::Failure { .. } => {
                    bail!("the authenticator code was not accepted")
                }
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers: Vec<String> = match prompts.len() {
                        0 => Vec::new(),
                        1 => {
                            let c = code.take().ok_or_else(|| anyhow!("the server asked for a second code"))?;
                            // russh takes plain Strings, so this one copy cannot be wiped;
                            // a code is only valid for about 30 seconds.
                            let answer = vec![c.as_str().to_owned()];
                            drop(c);
                            answer
                        }
                        n => bail!("the server asked {n} questions at once; Argus expects only the authenticator code"),
                    };
                    resp = self.handle.authenticate_keyboard_interactive_respond(answers).await?;
                }
            }
        }
    }
}

/// Both halves in one call, for the command-line check. `ask_code` runs only
/// after the key has been accepted.
pub async fn sign_in(
    target: &Target,
    key_path: &std::path::Path,
    passphrase: Zeroizing<String>,
    ask_code: impl FnOnce() -> Result<Zeroizing<String>> + Send + 'static,
) -> Result<Session> {
    let pending = start_sign_in(target, key_path, passphrase).await?;
    let code = tokio::task::spawn_blocking(ask_code).await??;
    pending.finish(code).await
}

impl Session {
    /// Run one command and return its standard output. Phase 1 uses this only
    /// for `whoami` and the helper's `status`.
    pub async fn run(&self, command: &str) -> Result<String> {
        within(RUN_TIMEOUT, "the server command", self.run_inner(command, None)).await
    }

    /// Run a command and hand it `input` on its standard input (for secrets,
    /// which must never be on a command line). The caller wipes `input`.
    pub async fn run_with_input(&self, command: &str, input: &[u8]) -> Result<String> {
        within(RUN_TIMEOUT, "the server command", self.run_inner(command, Some(input))).await
    }

    async fn run_inner(&self, command: &str, input: Option<&[u8]>) -> Result<String> {
        let mut ch = self.handle.channel_open_session().await?;
        ch.exec(true, command).await?;
        if let Some(bytes) = input {
            ch.data(bytes).await?;
        }
        ch.eof().await?;
        let mut out = Vec::new();
        let mut errout = Vec::new();
        let mut status = None;
        while let Some(msg) = ch.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, ext: 1 } if errout.len() < 4096 => {
                    errout.extend_from_slice(&data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        if status != Some(0) {
            let msg = String::from_utf8_lossy(&errout).trim().chars().take(300).collect();
            return Err(anyhow::Error::new(CommandFailed(status, msg)));
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// True once the connection has dropped.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn close(&self) -> Result<()> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}

/// The connection worked but the command on the server failed.
#[derive(Debug)]
pub struct CommandFailed(pub Option<u32>, pub String);

impl std::fmt::Display for CommandFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.1.is_empty() {
            return write!(f, "{}", self.1);
        }
        match self.0 {
            Some(c) => write!(f, "the server command failed (exit code {c})"),
            None => write!(f, "the server command ended without an exit code"),
        }
    }
}

impl std::error::Error for CommandFailed {}

/// An interactive shell on the server, in a pseudo-terminal.
pub struct Terminal {
    write: russh::ChannelWriteHalf<client::Msg>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

/// Output waiting to be shown is capped. The reader task never blocks (a
/// blocked reader would stall the whole SSH connection, status included);
/// past the cap the terminal is closed instead.
const TERM_QUEUE_MAX: usize = 8 * 1024 * 1024;

impl Session {
    /// Open a shell in a terminal of the given size.
    pub async fn open_shell(&self, cols: u32, rows: u32) -> Result<Terminal> {
        let ch = within(NET_TIMEOUT, "opening the terminal", async {
            let ch = self.handle.channel_open_session().await?;
            ch.request_pty(true, "xterm-256color", cols, rows, 0, 0, &[]).await?;
            ch.request_shell(true).await?;
            Ok(ch)
        })
        .await?;
        let (mut read, write) = ch.split();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let q = queued.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            while let Some(msg) = read.wait().await {
                let bytes = match msg {
                    russh::ChannelMsg::Data { data } => data.to_vec(),
                    russh::ChannelMsg::ExtendedData { data, .. } => data.to_vec(),
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                    _ => continue,
                };
                if q.fetch_add(bytes.len(), Ordering::Relaxed) + bytes.len() > TERM_QUEUE_MAX {
                    let _ = tx.send(b"\r\n[Argus: output arrived faster than it could be shown; this session was closed.]\r\n".to_vec());
                    break;
                }
                if tx.send(bytes).is_err() {
                    break;
                }
            }
            // Dropping `tx` tells the reader the shell has ended.
        });
        Ok(Terminal { write, rx: tokio::sync::Mutex::new(rx), queued })
    }
}

impl Terminal {
    /// Wait up to `wait` for output. `None` means the shell has ended; an
    /// empty vector means nothing arrived in time.
    pub async fn read(&self, wait: std::time::Duration) -> Option<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        let first = match tokio::time::timeout(wait, rx.recv()).await {
            Err(_) => return Some(Vec::new()),
            Ok(None) => return None,
            Ok(Some(b)) => b,
        };
        let mut out = first;
        while out.len() < 256 * 1024 {
            match rx.try_recv() {
                Ok(b) => out.extend_from_slice(&b),
                Err(_) => break,
            }
        }
        self.queued.fetch_sub(out.len().min(self.queued.load(std::sync::atomic::Ordering::Relaxed)), std::sync::atomic::Ordering::Relaxed);
        Some(out)
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.write.data(data).await?;
        Ok(())
    }

    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.write.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.write.close().await?;
        Ok(())
    }
}
