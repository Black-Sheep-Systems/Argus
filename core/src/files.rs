//! Files on the server over SFTP, run as root through `sudo -n sftp-server`
//! (the same approach as WinSCP's "SFTP server" setting). Owners and modes
//! are set by Argus after every write so files never end up owned by root
//! by accident; overwritten files are copied to /var/backups/argus first.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Session;

pub const BACKUP_ROOT: &str = "/var/backups/argus";

#[derive(Debug, Clone, serde::Serialize)]
pub struct Entry {
    pub name: String,
    pub kind: &'static str, // "dir", "file", "link", "other"
    pub size: u64,
    pub mode: u32, // permission bits only
    pub owner: String,
    pub group: String,
    pub mtime: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
}

/// What an upload will do, shown to Matt before it happens.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadPlan {
    pub target: String,
    pub exists: bool,
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub group: String,
    pub mode: u32,
    pub mode_from: String,
    pub backup_to: Option<String>,
    pub public_web: bool,
    /// The folder the plan was made for, links resolved.
    pub dir: String,
}

pub struct Peek {
    pub size: u64,
    pub mtime: u32,
    pub data: Vec<u8>,
}

pub struct Files {
    sftp: SftpSession,
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl Session {
    /// Open an SFTP session that runs as root on the server.
    pub async fn open_files(&self) -> Result<Files> {
        let sftp = crate::within(crate::NET_TIMEOUT, "opening files", async {
            let ch = self.handle.channel_open_session().await?;
            ch.exec(true, "sudo -n /usr/lib/openssh/sftp-server").await?;
            Ok(SftpSession::new(ch.into_stream()).await?)
        })
        .await?;
        let users = id_map(&sftp, "/etc/passwd").await;
        let groups = id_map(&sftp, "/etc/group").await;
        Ok(Files { sftp, users, groups })
    }
}

async fn id_map(sftp: &SftpSession, file: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    if let Ok(bytes) = sftp.read(file).await {
        for line in String::from_utf8_lossy(&bytes).lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() > 2 {
                if let Ok(id) = f[2].parse() {
                    m.insert(id, f[0].to_string());
                }
            }
        }
    }
    m
}

/// A file or folder name typed or dropped by Matt: one path segment only.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.len() > 255
        || name.contains('/') || name.contains('\0') || name.contains('\\')
    {
        bail!("not a usable file name: {name:?}");
    }
    Ok(())
}

/// Absolute, normalised server path; refuses `..` so nothing climbs out.
pub fn check_path(path: &str) -> Result<String> {
    if !path.starts_with('/') || path.contains('\0') || path.len() > 4096 {
        bail!("not a server path");
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.iter().any(|p| *p == "..") {
        bail!("paths with .. are not accepted");
    }
    Ok(format!("/{}", parts.join("/")))
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

/// Folders whose contents a website serves to anyone.
pub fn is_public_web(path: &str) -> bool {
    let p = format!("{path}/");
    p.starts_with("/var/www/")
        || (p.starts_with("/srv/")
            && ["/public/", "/public_html/", "/htdocs/", "/html/", "/www/"].iter().any(|s| p.contains(s)))
}

fn kind(a: &FileAttributes) -> &'static str {
    if a.is_dir() { "dir" } else if a.is_symlink() { "link" } else if a.is_regular() { "file" } else { "other" }
}

impl Files {
    fn name_of(&self, map: &HashMap<u32, String>, id: Option<u32>) -> String {
        match id {
            Some(i) => map.get(&i).cloned().unwrap_or_else(|| i.to_string()),
            None => "?".into(),
        }
    }

    /// The real path of a folder (links resolved), for listing and planning.
    pub async fn canonical(&self, path: &str) -> Result<String> {
        let path = check_path(path)?;
        let real = self.sftp.canonicalize(path.clone()).await.with_context(|| format!("could not open {path}"))?;
        check_path(&real)
    }

    pub async fn list(&self, path: &str) -> Result<Listing> {
        let path = self.canonical(path).await?;
        let rd = self.sftp.read_dir(path.clone()).await.with_context(|| format!("could not open {path}"))?;
        let mut entries: Vec<Entry> = rd
            .map(|e| {
                let a = e.metadata();
                Entry {
                    name: e.file_name(),
                    kind: kind(&a),
                    size: a.size.unwrap_or(0),
                    mode: a.permissions.unwrap_or(0) & 0o7777,
                    owner: self.name_of(&self.users, a.uid),
                    group: self.name_of(&self.groups, a.gid),
                    mtime: a.mtime.unwrap_or(0),
                }
            })
            .filter(|e| e.name != "." && e.name != "..")
            .collect();
        entries.sort_by(|a, b| (a.kind != "dir").cmp(&(b.kind != "dir")).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(Listing { path, entries })
    }

    /// Work out owner, mode and backup for uploading `name` into `dir`.
    pub async fn plan_upload(&self, dir: &str, name: &str) -> Result<UploadPlan> {
        let dir = self.canonical(dir).await?;
        check_name(name)?;
        let target = join(&dir, name);
        let parent = self.sftp.metadata(dir.clone()).await.with_context(|| format!("could not read {dir}"))?;
        if !parent.is_dir() {
            bail!("{dir} is not a folder");
        }
        let (exists, uid, gid, mode, mode_from) = match self.sftp.symlink_metadata(target.clone()).await {
            Ok(a) if a.is_regular() => (
                true,
                a.uid.unwrap_or(0),
                a.gid.unwrap_or(0),
                a.permissions.unwrap_or(0o644) & 0o7777,
                "kept from the file it replaces".to_string(),
            ),
            Ok(a) if a.is_dir() => bail!("{target} is a folder"),
            Ok(_) => bail!("{target} is a link or special file; Argus does not overwrite those"),
            Err(_) => {
                let (mode, from) = self.neighbour_mode(&dir, name).await;
                (false, parent.uid.unwrap_or(0), parent.gid.unwrap_or(0), mode, from)
            }
        };
        let backup_to = exists.then(|| format!("{BACKUP_ROOT}/<date>/<time>{target}"));
        Ok(UploadPlan {
            owner: self.name_of(&self.users, Some(uid)),
            group: self.name_of(&self.groups, Some(gid)),
            target,
            exists,
            uid,
            gid,
            mode,
            mode_from,
            backup_to,
            public_web: is_public_web(&dir),
            dir,
        })
    }

    /// Mode of a neighbouring file with the same extension, without setuid
    /// or setgid; otherwise 0644. Never the folder's own mode.
    async fn neighbour_mode(&self, dir: &str, name: &str) -> (u32, String) {
        if let Some(ext) = Path::new(name).extension().and_then(|e| e.to_str()) {
            if let Ok(rd) = self.sftp.read_dir(dir.to_string()).await {
                let mut matches: Vec<(String, u32)> = rd
                    .filter(|e| e.metadata().is_regular())
                    .filter(|e| Path::new(&e.file_name()).extension().and_then(|x| x.to_str()) == Some(ext))
                    .map(|e| (e.file_name(), e.metadata().permissions.unwrap_or(0o644)))
                    .collect();
                matches.sort();
                if let Some((n, m)) = matches.first() {
                    // no setuid/setgid/sticky, never writable by everyone
                    return (m & 0o775, format!("matches {n} in the same folder"));
                }
            }
        }
        (0o644, "the standard for a new file".to_string())
    }

    /// Copy a PC file into a new, private temporary file in `dir` (which
    /// must be the plan's resolved folder). Created only if nothing of that
    /// name exists, so it cannot be redirected. Returns its name; the helper
    /// then puts it in place (see `file-commit`).
    pub async fn put_temp(&self, local: &Path, dir: &str) -> Result<String> {
        let dir = check_path(dir)?;
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|e| anyhow::anyhow!("{e}"))?;
        let name = format!(".argus-upload-{}", rnd.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let path = join(&dir, &name);
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0o600);
        let mut src = tokio::fs::File::open(local).await.with_context(|| format!("could not open {}", local.display()))?;
        let mut dst = self
            .sftp
            .open_with_flags_and_attributes(path.clone(), OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE, attrs)
            .await
            .with_context(|| format!("could not write in {dir}"))?;
        let copied = tokio::io::copy(&mut src, &mut dst).await;
        let closed = dst.shutdown().await;
        if let Err(e) = copied.map(|_| ()).map_err(anyhow::Error::from).and(closed.map_err(anyhow::Error::from)) {
            let _ = self.sftp.remove_file(path).await;
            return Err(e.context("the upload stopped part-way; nothing on the server was changed"));
        }
        Ok(name)
    }

    pub async fn remove_temp(&self, dir: &str, name: &str) {
        if name.starts_with(".argus-upload-") && !name.contains('/') {
            let _ = self.sftp.remove_file(join(dir, name)).await;
        }
    }

    /// The start of a server file, for a preview (at most `max` bytes).
    pub async fn peek(&self, path: &str, max: u64) -> Result<Peek> {
        let path = check_path(path)?;
        let a = self.sftp.symlink_metadata(path.clone()).await.with_context(|| format!("could not read {path}"))?;
        if !a.is_regular() {
            bail!("only plain files can be previewed");
        }
        let mut f = self.sftp.open(path).await?;
        if !f.metadata().await?.is_regular() {
            bail!("only plain files can be previewed");
        }
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::take(&mut f, max).read_to_end(&mut buf).await?;
        Ok(Peek { size: a.size.unwrap_or(0), mtime: a.mtime.unwrap_or(0), data: buf })
    }

    /// Download a server file to the PC.
    pub async fn download(&self, remote: &str, local: &Path) -> Result<u64> {
        let remote = check_path(remote)?;
        let a = self.sftp.symlink_metadata(remote.clone()).await.with_context(|| format!("could not read {remote}"))?;
        if !a.is_regular() {
            bail!("only plain files can be downloaded (not folders or links)");
        }
        let mut src = self.sftp.open(remote.clone()).await?;
        if !src.metadata().await?.is_regular() {
            bail!("only plain files can be downloaded (not folders or links)");
        }
        let mut dst = tokio::fs::File::create(local).await.with_context(|| format!("could not create {}", local.display()))?;
        let n = tokio::io::copy(&mut src, &mut dst).await.context("the download stopped part-way")?;
        dst.flush().await?;
        Ok(n)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths() {
        assert_eq!(check_path("/srv//a/./b/").unwrap(), "/srv/a/b");
        assert!(check_path("/srv/../etc").is_err());
        assert!(check_path("srv").is_err());
        assert!(check_name("..").is_err());
        assert!(check_name("a/b").is_err());
        assert!(is_public_web("/srv/blksheepltd.com/public/admin"));
        assert!(!is_public_web("/srv/backups"));
    }
}
