# Argus security audit, 2026-11-01

## Phase 4c: Accounts (upload accounts, SSH keys, Hephaestus users) - Sentinel

Scope: server/argus-helper (accounts section lines 1771-2366, ACTIONS 2382-2437, log() 2440-2446, main 2449-2480),
server/accounts-setup.sh, app/renderer/app.js (accounts block 692-1027), app/renderer/index.html (qr dialog, CSP),
app/main.js (argus:helper, argus:helperSecret, argus:copy), native/src/lib.rs (ACTIONS, SECRET_ACTIONS, safe_arg),
app/vendor.js and app/package.json (qrcode-generator 2.0.4).
Threat model: an upload-account holder is an attacker with a valid key and a valid authenticator code.
Not available to this audit: the live server files (/etc/ssh/sshd_config.d/50-mattridge.conf, 51_permit_root_login.conf,
97-ndspublish.conf, 99-backuppull.conf, /etc/pam.d/sshd, /opt/web/docker-compose.yml). Items depending on them are stated
as verification steps, not as findings.

Summary: 3 High, 4 Medium, 6 Low, 4 Informational. No Critical. No hardcoded credentials found in the changed code.

---

### H1. Upload accounts can create symlinks (and hard links); the web server follows them
- Severity: High
- Category: OWASP A01 Broken Access Control / CWE-59 (link following), CWE-61
- Location: server/accounts-setup.sh line 53 (`ForceCommand internal-sftp -d /files -u 0027`); consequence in any
  folder under /srv/<domain>/public shared via acct-add (argus-helper 2102-2111).
- Description: internal-sftp allows SSH_FXP_SYMLINK and the hardlink@openssh.com extension by default. The link target is
  stored verbatim; it is only confined by the chroot when the uploader follows it. Caddy runs in a container with
  /srv/<domain>/public mounted read only and `file_server` (SITE_TEMPLATE, argus-helper 1711-1723), and Caddy follows
  symlinks. An uploader with a website folder creates `x -> /data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.key`
  (or `/etc/caddy/Caddyfile`, `/etc/caddy/site-rules.caddy`, `/config/...`) and fetches https://<domain>/<path>/x: the
  TLS private keys of every domain, the ACME account key and the Caddy configuration are served to the internet. The
  `@forbidden` dot-file rule only checks the request path, not the link target. Hard links add nothing beyond this
  today (link(2) cannot cross the bind mount and the chroot), but there is no reason to allow them.
- Remediation: deny the two requests in the Match block (accounts-setup.sh line 53):
  ```
      ForceCommand internal-sftp -d /files -u 0027 -P symlink,hardlink
  ```
  and, because the setup script rewrites the file, make the helper's readiness check require it (argus-helper 1839):
  ```python
  def upload_conf_ok():
      try:
          t = open(SSHD_UPLOAD_CONF).read()
      except OSError:
          return False
      return bool(re.search(r"^\s*ForceCommand\s+internal-sftp\s+-d\s+/files\s+-u\s+0027\s+-P\s+symlink,hardlink\s*$", t, re.M))
  ...
          "ssh_settings": upload_conf_ok() and os.path.isfile(SSHD_DENY_CONF),
  ```
  Before the first account goes live, also run once: `find /srv -path /srv/sftp -prune -o -type l -print` and remove
  any link nobody put there on purpose.
- Verification: `/usr/lib/openssh/sftp-server -Q requests` lists `symlink` and `hardlink`;
  `sudo sshd -T -C user=<acct>,host=t,addr=127.0.0.1 | grep -i forcecommand` shows `-P symlink,hardlink`;
  as the upload account: `sftp> ln -s /etc/hostname t` and `sftp> ln /files/a /files/b` both fail with
  "Permission denied"; `journalctl -u ssh` shows the refused request.

### H2. fstab line injection through backslash-octal folder names (chroot escape)
- Severity: High
- Category: OWASP A03 Injection / CWE-74, CWE-22
- Location: argus-helper 1947-1957 (shareable_folder), 2048-2053 (fstab_add), 1859 (fstab_mounts decodes only \040),
  1960-1978 (acct_folders offers every folder three levels deep, including folders uploaders made).
- Description: fstab_add rejects only whitespace. libmount (mount and systemd-fstab-generator) decodes every `\ooo`
  octal escape in fstab fields. An uploader with a website folder runs `sftp> mkdir 'x\057..\057..\057..\057..\057..'`
  (legal: no slash, no whitespace). The folder is listed by acct-folders; when Matt shares it with a second account,
  the line reads `/srv/site/up/x\057..\057.. ... /srv/sftp/b/files none bind,nofail 0 0` and mount binds `/` (or
  `/etc`, `/home`, `/opt/hephaestus/...`) at the second account's /files. The ACL is granted on the literal folder,
  so the second account gets the "other" permissions on the whole tree: every world-readable file, and write on
  world-writable folders such as /var/tmp. The same applies to any folder name a web app or www-data can create.
- Remediation: allow only plain names in a shared path, everywhere the path is accepted or listed.
  argus-helper, after line 1805:
  ```python
  SHARE_RE = re.compile(r"^/srv(/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){1,8}$")
  ```
  shareable_folder, first line of the body (line 1950):
  ```python
      if not SHARE_RE.fullmatch(path):
          raise Refused("only folders whose names use letters, digits, '.', '_' or '-' can be shared")
  ```
  fstab_add (replace lines 2050-2051):
  ```python
      if not SHARE_RE.fullmatch(src) or not ACCT_RE.fullmatch(n):
          raise Refused("that folder can't be written to the mount table")
  ```
  acct_folders: append `p`, `q`, `r` only when `SHARE_RE.fullmatch(...)`.
- Verification: create `/srv/<site>/public/t\057..` as root, call `acct-folders` (not listed) and
  `acct-add t1 none 1 <hex of that path>` (refused, nothing written to /etc/fstab, `grep argus-upload /etc/fstab`
  unchanged); remove the test folder.

### H3. The bind source is re-resolved by path at every boot and can be swapped for a symlink
- Severity: High
- Category: OWASP A01 Broken Access Control / CWE-367 (TOCTOU), CWE-59
- Location: argus-helper 1955 (realpath check only at add time), 2048-2053 and 2110 (mount by fstab path), 2000
  (`mounted` only checks that something is mounted).
- Description: shareable_folder checks that the path has no links when the account is made. The fstab line is
  resolved again by mount at every boot (and on `mount -a`), following symlinks. Anyone who can write a parent of the
  shared folder can rename the folder away and put `folder -> /` in its place; at the next reboot the account's /files
  is whatever the link points at. Writers of a parent include: another upload account whose shared folder contains
  this one (acct_folders offers nested folders, and folders an uploader made), the account itself if Matt shares a
  folder it created, and any web app or user with write on a site folder.
- Remediation: (1) in shareable_folder, after the realpath check, require that every folder from /srv down to the
  parent of the chosen folder is owned by root, not group/other writable and carries no ACL write entry, and that the
  chosen folder is not owned by an upload account:
  ```python
      up_uids = set()
      for m in upload_members():
          try:
              up_uids.add(_pwd.getpwnam(m).pw_uid)
          except KeyError:
              pass
      cur = SITE_ROOT
      for comp in parts[:-1]:
          cur = os.path.join(cur, comp)
          st = os.lstat(cur)
          if st.st_uid != 0 or st.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH) or not _stat.S_ISDIR(st.st_mode):
              raise Refused(cur + " can be changed by someone other than root, so a folder inside it can't be shared")
          acl = run(["getfacl", "--omit-header", "--absolute-names", "--numeric", "--skip-base", cur]) or ""
          if re.search(r"^(user|group):[0-9]+:.w", acl, re.M) or re.search(r"^mask::.w", acl, re.M):
              raise Refused(cur + " gives write access to others, so a folder inside it can't be shared")
      if os.lstat(path).st_uid in up_uids:
          raise Refused("that folder was made by an upload account and can't be shared")
  ```
  (2) after `must(["mount", files])` (line 2110), confirm what was mounted, and roll back otherwise:
  ```python
                  got = (run(["findmnt", "-n", "-o", "FSROOT", "--mountpoint", files]) or "").strip()
                  if got != src:
                      raise Refused("the folder that was connected is not the one chosen")
  ```
  (3) in acct_list (line 2000) report `"mounted"` as True only when the same FSROOT equals `src`, so a swapped source
  shows "Not Connected" instead of looking healthy.
- Verification: as root make `/srv/<site>/public/up` owned by a test user and try to share `/srv/<site>/public/up/sub`
  (refused). For an existing account, `findmnt -n -o FSROOT --mountpoint /srv/sftp/<acct>/files` equals the folder in
  acct-list.

### M1. The default ACL grants the uploader rwx on every file anyone later creates in the folder
- Severity: Medium
- Category: OWASP A01 Broken Access Control / CWE-732; quota bypass (CWE-400)
- Location: argus-helper 2023-2025 (acl_grant).
- Description: `setfacl -d -m u:<n>:rwx` makes every file and folder later created in the shared folder by root
  (Argus file-commit), by Matt or by a web app writable by the uploader. Writes to files the uploader does not own are
  not counted against its quota, so it can grow any such root-owned file until the root filesystem is full, taking
  mail, Hephaestus and the web server down. It can also modify site files Matt places there later. Separately, rwx on
  the top folder lets it delete or rename every existing entry in that folder (including index.html if a site root is
  shared).
- Remediation: grant write on the folder itself, read only by inheritance; files and folders the uploader makes stay
  writable to it through ownership. Replace line 2025:
  ```python
      must(["setfacl", "-d", "-m", "u:" + n + ":rx,g:www-data:rx", folder])
  ```
  and add, so the uploader can only delete or rename its own entries in the top folder:
  ```python
      must(["chmod", "+t", folder])
  ```
  (acl_revoke is unchanged; on delete, `chmod -t` only if no other upload account shares the folder.)
- Verification: share a test folder; as root `touch <folder>/rootfile`; as the uploader `sftp> put big rootfile`
  fails with "Permission denied"; uploader cannot `rm` a root file in the top folder; `getfacl <folder>` shows
  `default:user:<n>:r-x`.

### M2. No inode limit: one account can exhaust the root filesystem's inodes
- Severity: Medium
- Category: CWE-400 Uncontrolled Resource Consumption
- Location: argus-helper 2060-2062 (set_quota_mb passes inode limits "0" "0" = unlimited).
- Description: the block limit holds, but millions of empty files cost no blocks. Inode exhaustion on / stops every
  service on the VPS (mail queue, Docker, logs).
- Remediation:
  ```python
  INODE_LIMIT = "200000"
  def set_quota_mb(n, mb):
      kb = str(mb * 1024)
      must(["setquota", "-u", n, kb, kb, INODE_LIMIT, INODE_LIMIT, "/"])
  ```
- Verification: `repquota -u /` shows file limits 200000 for the account; a loop of `sftp> put empty f$i` stops at the
  limit with "Disk quota exceeded".

### M3. uid/gid reuse after delete can hand a new account the old one's files and ACL rights
- Severity: Medium
- Category: OWASP A01 Broken Access Control / CWE-708, CWE-754 (unchecked return)
- Location: argus-helper 2203 (`find ... -exec chown -h root`), 2028-2032 (acl_revoke uses run(), failures ignored),
  2091 (useradd picks the next free uid, which is reused after userdel).
- Description: (a) only the owner is changed; files and setgid folders keep the deleted account's private gid, so a
  new account given the same gid (useradd --user-group reuses it) gets group access. (b) find (300 s timeout) and
  setfacl are run with run(): a timeout or error is ignored and userdel proceeds, leaving files owned by, and ACL
  entries for, a uid that the next account will receive. A replacement contractor given the same folder then owns the
  predecessor's files and holds its ACL rights.
- Remediation:
  ```python
  # acct_delete, replacing line 2203
  must(["find", src, "-xdev", "(", "-uid", str(pw.pw_uid), "-o", "-gid", str(pw.pw_gid), ")",
        "-exec", "chown", "-h", "root:root", "{}", "+"], timeout=600)
  # acl_revoke: use must() instead of run() for both setfacl calls, then before userdel:
  left = run(["getfacl", "-R", "-P", "--numeric", "--absolute-names", "--omit-header", src], timeout=300)
  if left is None or re.search(r"^(default:)?user:" + str(pw.pw_uid) + r":", left, re.M):
      raise Refused("the account's access could not be removed everywhere; it was disabled but not deleted")
  ```
  and stop uid reuse: keep a high-water mark (/var/lib/argus/upload-uid, root 0600) and pass `--uid` to useradd:
  ```python
  UID_HWM = "/var/lib/argus/upload-uid"
  def next_upload_uid():
      try:
          hwm = int(open(UID_HWM).read().strip())
      except (OSError, ValueError):
          hwm = 20000
      used = {p.pw_uid for p in _pwd.getpwall()} | {g.gr_gid for g in _grp.getgrall()}
      u = max(hwm, 20000) + 1
      while u in used:
          u += 1
      os.makedirs(os.path.dirname(UID_HWM), mode=0o700, exist_ok=True)
      with open(UID_HWM + ".new", "w") as f:
          f.write(str(u))
      os.chmod(UID_HWM + ".new", 0o600)
      os.rename(UID_HWM + ".new", UID_HWM)
      return u
  # acct_add useradd: add "--uid", str(uid) and pre-create the group with "groupadd --gid", str(uid), n
  # (replace --user-group with --gid n).
  ```
- Verification: create and delete account t1, create t2: `id t2` shows a uid/gid greater than t1's;
  `find <folder> -uid <t1 uid> -o -gid <t1 gid>` prints nothing; `getfacl -R -n <folder> | grep <t1 uid>` prints nothing.

### M4. Uploads into a website folder become active content on that site's origin
- Severity: Medium
- Category: OWASP A03 Injection (stored XSS, CWE-79) / CWE-434 Unrestricted Upload
- Location: argus-helper 2076 and 2102-2111 (any folder under /srv/<domain>/public can be shared); SITE_TEMPLATE 1710-1723.
- Description: an uploader can place .html/.svg/.js files that run with the site's origin (cookies scoped to the
  domain, same-origin requests to anything else on it), and can overwrite pages (M1 limits this to files it owns
  once fixed). If any site is ever served through php_fastcgi, a .php upload is code execution as the PHP user.
- Remediation: when an account is given a folder inside /srv/<domain>/public, add a Caddy rule for that path through
  the existing caddy-apply job, and refuse folders of sites that use php_fastcgi:
  ```
  @argus_upload_<acct> path /<folder relative to public>/*
  header @argus_upload_<acct> Content-Security-Policy "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'self'"
  header @argus_upload_<acct> X-Content-Type-Options nosniff
  ```
  In shareable_folder: `if "php_fastcgi" in open(f"/opt/web/sites/{domain}.caddy").read(): raise Refused(...)`.
  Until then, the UI text in app.js 893 should say plainly that what the account uploads runs as part of the site.
- Verification: upload `t.html` with `<script>alert(document.domain)</script>`; fetching it shows the CSP sandbox
  header and the script does not run.

### L1. sshd Match block: missing hardening, and its position lets an earlier Match win
- Severity: Low
- Category: OWASP A05 Security Misconfiguration
- Location: server/accounts-setup.sh 49-64.
- Description: for a keyword, sshd takes the first matching Match block's value. 60-argus-upload.conf comes after
  50-mattridge.conf and 51_permit_root_login.conf; any Match there that also matches upload users (Group, Address,
  `all`) would override ChrootDirectory/ForceCommand/AuthenticationMethods. `DisableForwarding`, `PermitListen`,
  `PermitUserRC` are not set; SFTP operations by third parties are not logged.
- Remediation: write the block as /etc/ssh/sshd_config.d/06-argus-upload.conf (update SSHD_UPLOAD_CONF, argus-helper
  1793, and remove the old 60- file in the setup script), and add:
  ```
      DisableForwarding yes
      PermitListen none
      PermitOpen none
      PermitUserRC no
      PermitUserEnvironment no
  ```
  and `-l INFO -f AUTHPRIV` on the ForceCommand (check the journal shows open/close lines; if not, the chroot needs
  /dev/log bind-mounted).
- Verification: `sudo sshd -T -C user=<acct>,host=t,addr=203.0.113.9` shows chrootdirectory /srv/sftp/<acct>,
  forcecommand internal-sftp ..., authenticationmethods publickey,keyboard-interactive, disableforwarding yes.

### L2. Removing an upload account's key does not end its open sessions
- Severity: Low
- Category: OWASP A07 Identification and Authentication Failures / CWE-613
- Location: argus-helper 2248-2265 (key_remove).
- Remediation: after `write_keys(acct, keep)` add `if acct != ADMIN_USER: end_sessions(acct)`.
- Verification: with an sftp session open, remove the key; the session drops.

### L3. fstab is replaced without a syntax check; bind mounts lack nosuid/nodev
- Severity: Low
- Category: OWASP A05 Security Misconfiguration
- Location: argus-helper 2035-2045, 2052.
- Remediation: in fstab_write, before `os.rename(tmp, FSTAB)`:
  ```python
      p = subprocess.run(["findmnt", "--verify", "--tab-file", tmp], capture_output=True, text=True, timeout=30)
      if p.returncode != 0:
          os.unlink(tmp)
          raise Refused("the new mount table did not pass its check; nothing was changed")
  ```
  and use `none bind,nofail,nosuid,nodev,noexec 0 0` in fstab_add.
- Verification: `findmnt -no OPTIONS --mountpoint /srv/sftp/<acct>/files` shows nosuid,nodev,noexec.

### L4. heph-admin argument injection through words starting with '-'
- Severity: Low
- Category: CWE-88 Argument Injection
- Location: argus-helper 2329 (`name.split()`; the company-name regex allows a later word such as `--admin`),
  2315/2342 (EMAIL_RE 1068 allows an address starting with '-').
- Remediation: in heph_company_add refuse `any(w.startswith("-") for w in name.split())`; in hx_email refuse
  `v.startswith("-")`; if heph-admin uses clap, also insert `"--"` before positional arguments.
- Verification: `heph-company-add acme <hex of "Acme --x">` is refused.

### L5. Matt's old authenticator secret stays in his home folder after the move
- Severity: Low
- Category: CWE-312 / CWE-922
- Location: server/accounts-setup.sh 38-42.
- Description: /home/mattridge/.google_authenticator is no longer used but keeps a valid secret and emergency codes
  readable by anything running as mattridge; re-running `google-authenticator` later would write a file that is
  silently ignored.
- Remediation: after Matt's sign-in is re-tested, `shred -u /home/mattridge/.google_authenticator`; document that a
  new secret for Matt is made with `google-authenticator -s /var/lib/google-authenticator/mattridge` as root.
- Verification: the file is gone and Matt still signs in with key and code.

### L6. JavaScript dependencies have no lockfile (no integrity hashes)
- Severity: Low
- Category: OWASP A06 Vulnerable and Outdated Components / A08 Software and Data Integrity
- Location: app/package.json (exact versions, no package-lock.json); app/vendor.js copies the files into the renderer.
- Remediation: commit app/package-lock.json and install with `npm ci`.
- Verification: `npm ci` succeeds and package-lock.json lists `qrcode-generator` 2.0.4 with an `integrity` sha512.

### I1. PAM change scope (verify on the server)
- Severity: Informational
- The new line applies to every account that reaches keyboard-interactive. Run `sudo sshd -T -C user=X,host=t,addr=203.0.113.9 | grep -i authenticationmethods`
  for X in root, debian, backuppull, ndspublish, mattridge, an upload account and a name that does not exist. Only
  mattridge and argus-upload members should include keyboard-interactive, and always after publickey. If a
  nonexistent user can reach keyboard-interactive, a name like `../../../var/lib/google-authenticator/mattridge`
  points the module at Matt's file and its RATE_LIMIT/DISALLOW_REUSE state (lock-out of Matt); then set a global
  `AuthenticationMethods publickey` in 05-argus-deny.conf. Also confirm /etc/pam.d/sshd has no active
  `@include common-auth` (upload accounts have no Unix password) and that no other user had ~/.google_authenticator.

### I2. Checked and sound
- Renderer: every value from the server reaches the DOM through textContent (el(), row(), showCode, showOnce); no
  innerHTML in app.js; QR is a data: image allowed by the CSP; dialogs clear the secret on close; copies are marked
  sensitive and cleared after 30 s.
- Logging: secrets (TOTP secret, emergency codes, passwords, reset link) never enter NOTED or args; passwords go on
  stdin; refusals from heph-admin drop lines mentioning a password.
- TOTP: 160-bit secret from `secrets`, 8-digit codes from `secrets.randbelow`, file created O_EXCL|O_NOFOLLOW 0400 in a
  root 0700 folder, RATE_LIMIT/WINDOW_SIZE/DISALLOW_REUSE set.
- Key lines: type allowlist, base64 check, restricted comment, no options, RSA >= 3072, re-parsed by ssh-keygen;
  upload keys are root-owned outside the jail.
- Chroot: /srv, /srv/sftp and /srv/sftp/<n> root-owned 0755; `find -exec chown -h` and `setfacl -R -P` do not follow
  links, and run after the account is disabled and its processes killed.
- native: safe_arg allowlist, ACTIONS and SECRET_ACTIONS allowlists, secret zeroized.

### I3. heph-user-add on an existing address
- Severity: Informational. The UI says an existing address in the company has its name and role updated; confirm
  whether heph-admin new-user --password also replaces that user's password, and whether it can attach an address that
  is a platform staff account to a company. If so, refuse existing addresses as heph_staff_add does.

### I4. Upload-account actions are not logged inside the jail
- Severity: Informational. Covered by L1's `-l INFO`; listed so the decision is explicit.

Result: ISSUES FOUND

---

## Re-audit (phase 4c fixes) - Sentinel, 2026-11-01

Re-read: server/argus-helper accounts section (now lines 1772-2575, must() 308-316, config_paths 1441-1446,
hx_email 1134-1138), server/accounts-setup.sh (114 lines). The helper parses (python3 ast). This is a code review:
nothing here was run on the server, so each "Resolved" below still needs its verification step done there.

| Finding | Status | Evidence |
|---|---|---|
| H1 symlinks / hard links | Resolved (verify on server) | accounts-setup.sh 80 `-P symlink,hardlink -l INFO -f AUTHPRIV`; helper 1801 UPLOAD_FORCE, 1865-1870 upload_conf_ok requires the exact line; request names checked by the coordinator with `sftp-server -Q requests`. Shares are also refused for any served folder (M4), so a link would have nothing serving it. |
| H2 fstab escape injection | Resolved | /etc/fstab is no longer written for shares. SHARE_RE (1810) allows only `[A-Za-z0-9_][A-Za-z0-9._-]{0,63}` per part, so no backslash, no `..` and no leading dot; it is checked in share_problem (1946), and acct_folders lists only folders that pass. |
| H3 bind source swap | Resolved | walk_no_links (1909-1929) opens one component at a time with O_NOFOLLOW and dir_fd. share_problem (1963-1967) requires the target to be root-owned, and every folder from /srv/<site> to the parent to be root-owned, with no g/o write and no ACL write entries. mount_share (2014-2030) binds `/proc/self/fd/N` with --no-canonicalize (pass_fds keeps N), remounts nosuid,nodev,noexec and checks FSROOT == src, else unmounts. Boot mounts go through the same path (2033-2049). acct_list `mounted` compares FSROOT (2227). |
| M1 default ACL rights | Resolved | acl_grant 2157-2164: dirs `u:n:rwx` plus default `u:n:rx`, existing files `u:n:r`, sticky bit on every dir. Root-owned files can no longer be grown or replaced, and others' entries can't be deleted or renamed. |
| M2 inode limit | Resolved | set_quota_mb 2073-2075 passes INODE_LIMIT 200000 for both soft and hard. |
| M3 uid/gid reuse | Resolved | next_uid 2173-2192 is a counter from 30000 that is never reused and skips any number already in use as a uid or gid; groupadd --gid plus useradd --uid/--gid (2264-2267); upload_account requires the uid to be in range (1850). On delete: find -uid OR -gid then chown -h root:root, and acl_revoke, both with must() (2385-2387, 2167-2170). |
| M4 uploads served as live content | Partly resolved; residual R1 below (Medium) | served_paths 1896-1906 plus share_problem 1951-1954 refuse served folders, but the list of what is served can miss some. |
| L1 Match hardening | Resolved in code; ordering to be verified on server | DisableForwarding, PermitListen none, PermitOpen none, PermitUserRC no are added (accounts-setup.sh 85-92). The file is still 60-; that is acceptable once `sshd -T -C user=<acct>,host=t,addr=203.0.113.9` shows chrootdirectory, forcecommand and authenticationmethods from this block. |
| L2 sessions on key removal | Resolved | key_remove 2454-2455; end_sessions now waits up to 5 s (2195-2201). |
| L3 fstab check / mount flags | Resolved | No fstab line for shares. nosuid,nodev,noexec are applied by remount (2027). The quota fstab edit in setup runs findmnt --verify (setup 28). |
| L4 heph-admin argument injection | Resolved | heph_admin 2461-2462 refuses any argument starting with '-' except --admin/--role/--password; hx_email 1136. |
| L5 old TOTP file | Open (server step) | The coordinator will remove it after Matt's re-test. Setup step 4 no longer compares the copies. |
| L6 lockfile | Open | app/package-lock.json still absent. |
| I1 PAM scope | Open (server step) | The coordinator will run sshd -T -C for root, debian, backuppull, ndspublish, mattridge, an upload account and a nonexistent user. |

### R1. The list of "served" folders can miss some, and the check then lets the folder through (residual of M4)
- Severity: Medium
- Category: OWASP A01 Broken Access Control / CWE-434, CWE-183 (permissive list)
- Location: argus-helper 1896-1906 (served_paths), 1441-1446 and 1357 (config_paths scans only /opt/web: Caddyfile,
  site-rules.caddy, docker-compose.yml, sites/*.caddy).
- Description: a folder is refused only if a regex finds it in those files. These are missed:
  - mounts in other compose files (/opt/hephaestus/deploy/docker-compose*.yml, mailcow's compose and override files,
    any later stack);
  - long-syntax volumes (`source: /srv/...`), flow lists (`volumes: ["/srv/a:/b"]`) and `${VAR}` paths;
  - containers started outside compose;
  - Caddy `root @matcher /srv/...`;
  - host web servers.
  A missed file also counts as "nothing served" (an unreadable file is skipped). With two PHP sites on the server, a
  missed mount or root means an uploader's .php or .html goes live: M4 again.
- Remediation: add what Docker reports and fail closed, keeping the config scan for stopped stacks and for boot.
  Add after served_paths:
  ```python
  def container_mount_sources():
      """Host folders any container (running or stopped) can reach; refuse if Docker can't say."""
      ids = run(["docker", "ps", "-aq"], timeout=30)
      if ids is None:
          raise Refused("could not ask Docker what its containers can reach, so nothing is shared")
      ids = ids.split()
      if not ids:
          return set()
      out = run(["docker", "inspect", "--format", "{{range .Mounts}}{{.Source}}\n{{end}}"] + ids, timeout=60)
      if out is None:
          raise Refused("could not ask Docker what its containers can reach, so nothing is shared")
      # "/" becomes "" after rstrip, and "" + "/" is a prefix of every path, so a container given / blocks all sharing.
      return {l.rstrip("/") for l in out.splitlines() if l == "/" or l == "/srv" or l.startswith("/srv/")}
  ```
  In served_paths:
  - widen the Caddy pattern to `r"^\s*root\s+(?:[*@]\S*\s+)?(/srv/\S+)"`;
  - add `out.update(m.rstrip("/") for m in re.findall(r"(/srv/[A-Za-z0-9._/-]+)", text))` for compose files, so any
    /srv path mentioned in a compose file counts as served;
  - make config_paths also take `glob.glob("/opt/*/docker-compose*.y*ml") + glob.glob("/opt/*/*/docker-compose*.y*ml")`;
  - in share_problem, raise on an unreadable config file instead of `continue`.
  Use `served_paths() | container_mount_sources()` in acct_add and acct_folders. In acct_mount_all (boot, Docker may
  not be up yet) keep the config-only set. Also refuse when /etc/nginx/sites-enabled, /etc/apache2/sites-enabled or
  /etc/php/*/fpm/pool.d exist with content, unless they have been scanned.
- Verification: on the server, `docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' $(docker ps -aq)`.
  Every /srv source listed, and every folder inside one, must be missing from `acct-folders` output, and
  `acct-add t1 none 1 <hex of it>` must be refused. Stop Docker briefly (or point the check at a bad socket in a test
  copy): acct-folders must refuse rather than list.

### R2. setfacl is given path names that a co-sharing account could swap for a link
- Severity: Low
- Category: CWE-367 TOCTOU / CWE-59
- Location: argus-helper 2162-2163 (acl_grant), 2169-2170 (acl_revoke).
- Description: `find ... -exec setfacl -m ... {} +` hands setfacl paths, and setfacl follows a link given as an
  argument. If a folder is already shared with account A (the target may carry A's ACL), A can rename one of its own
  subfolders and put a link in its place between find's read and setfacl's call. Root then edits the ACL of the link
  target (for example /etc). The second account still can't reach that target (it only has its chroot and its uid can't
  get there), so there is no access gained today, but root changes rights outside the share.
- Remediation: walk with handles and edit through them:
  ```python
  def acl_each(folder, dir_spec, file_spec):
      for root, dirs, files, dfd in os.fwalk(folder, follow_symlinks=False):
          st = os.fstat(dfd)
          if st.st_dev != os.stat(folder).st_dev:
              dirs[:] = []
              continue
          must(["setfacl"] + dir_spec + ["/proc/self/fd/%d" % dfd], pass_fds=(dfd,))
          for f in files:
              try:
                  ffd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
              except OSError:
                  continue
              try:
                  if _stat.S_ISREG(os.fstat(ffd).st_mode):
                      must(["setfacl"] + file_spec + ["/proc/self/fd/%d" % ffd], pass_fds=(ffd,))
              finally:
                  os.close(ffd)
  ```
  (setfacl follows the /proc magic link to the opened inode itself.) Alternatively, refuse a share whose target
  already carries an ACL entry for another upload account.
- Verification: share a folder with t1, put a link inside it as root, share the same folder with t2; `getfacl` on the
  link's target shows no t2 entry.

### R3. Informational
- /srv itself (index 0 in walk_no_links, 1923) is not checked for owner and mode; add `0 <= i` so a wrongly
  permissioned /srv is caught.
- acct_delete (2384) leaves files with the deleted uid when share_problem now fails for the folder (for example it has
  since gone live). That is safe because uids are never reused, but the reply should say so.
- If ssh is socket-activated (ssh.socket), Before=ssh.service does not delay sign-ins. An early sign-in sees an empty
  root-owned /files, which is safe.
- internal-sftp `-l INFO` inside the chroot: confirm the journal shows open/close lines for an upload session. If not,
  /dev/log needs to be reachable in the chroot.
- heph_admin's stderr filter (2470) is narrower than before. That is fine as long as heph-admin never echoes input.

Re-audit result: H1, H2, H3, M1, M2, M3 resolved in code. M4 remains as R1 (Medium). R2 is a new Low. L5, L6 and I1 are
open. L1 ordering and H1 still need the server checks.

Result: ISSUES FOUND

---

## Re-audit 2 (R1, R2, walk_no_links) - Sentinel, 2026-11-01

Re-read in server/argus-helper (the file parses):
- served_paths 1896-1918, container_mount_sources 1921-1933, all_served 1936-1937, walk_no_links 1940-1960;
- share_problem 1973-1999 and acct_folders 2002-2017;
- mount_share 2045-2067 and acct_mount_all 2070-;
- tree 2194-2222, setfacl_fds 2225-2229, acl_grant 2232-2241, acl_revoke 2244-2259;
- acct_add 2320-2340 and acct_delete 2451-2500.

This was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| R1 served-folder discovery | Resolved; Low residual R1a | Caddy root regex now also takes `@matcher`. Any /srv path in /opt/*/ and /opt/*/*/ docker-compose*.y*ml counts as served. An unreadable config file raises Refused. container_mount_sources (docker ps -aq plus inspect .Mounts Source) refuses when Docker can't answer, including a container removed between the two calls (inspect then exits non-zero). acct_add (2336) and acct_folders (2004) use both; boot and mount_share use the config scan only, which is acceptable because the folder was already approved with both. |
| R2 setfacl on swappable paths | Resolved; Low residual R2a | tree() starts from a walk_no_links handle; os.fwalk(follow_symlinks=False) checks each opened subfolder against its lstat result, so a folder swapped for a link is skipped; it stays on one device. Files are opened O_PATH\|O_NOFOLLOW and only regular files are kept, so links are never touched. setfacl and chown act on /proc/self/fd/N, which resolves to the opened inode; the sticky bit uses fchmod and folder ownership uses fchown. Delete now does the -uid/-gid hand-over to root:root in the same walk, and forgets the share only after the clean-up succeeds. |
| walk_no_links checks /srv | Resolved | `if i < len(parts) - 1` (1955) now includes /srv, so share_problem checks its owner, mode and ACL. |

### R1a. A container given all of /srv (or /) is not counted; quoted Caddy roots and compose.yaml are missed
- Severity: Low
- Category: CWE-183 Permissive List of Allowed Inputs
- Location: argus-helper 1913 (Caddy regex), 1914 (glob), 1917 (compose regex needs `/srv/` plus a character), 1933 (keeps
  only Sources starting with `/srv/`).
- Description:
  - A mount of `/srv` itself (`- /srv:/srv:ro`) or of `/` matches neither the compose regex nor the Source filter, so
    every folder in /srv stays shareable even though that container can read and serve it.
  - `root * "/srv/x/public"` (quoted) is not matched.
  - Compose files named compose.yaml/compose.yml are not globbed (created containers are still caught by Docker inspect).
  Pages are still not served unless a Caddy root points at the folder, which the root regex normally catches, hence Low.
- Remediation:
  - line 1913: `r"^\s*root\s+(?:[*@]\S*\s+)?['\"]?(/srv/[^\s'\"}]+)"`
  - line 1917: `r"(/srv(?=[\s:'\"/]|$)(?:/[A-Za-z0-9_.@-]+)*)"`; a bare `/srv` then becomes a served path, and
    `path.startswith("/srv/")` refuses everything, which is intended.
  - line 1914: also glob `/opt/*/compose.y*ml` and `/opt/*/*/compose.y*ml`.
  - line 1933: `{l.strip().rstrip("/") for l in out.splitlines() if l.strip() in ("/", "/srv") or l.strip().startswith("/srv/")}`.
    "/" becomes "" after rstrip, and `path.startswith("" + "/")` is always true.
- Verification:
  - add a test compose file with `- /srv:/data:ro` under /opt/test-x/: acct-folders lists nothing; remove the file.
  - a quoted root in a test sites/*.caddy file is listed by served_paths().

### R2a. On a crowded folder, files that can't be opened are skipped without a word
- Severity: Low
- Category: CWE-755 Improper Handling of Exceptional Conditions
- Location: argus-helper 2207-2212 (tree: `except OSError: continue`; every file handle in one folder is held open at once).
- Description: the uploader can create up to 200000 files in one folder (its inode limit). That is more than the
  helper's open-file limit (often 1024), so the opens fail with EMFILE and are skipped. On delete those files keep the
  deleted account's uid/gid and ACL entry. Uid/gid are never reused (M3), so nobody gains access today, but the
  clean-up is reported as done when it isn't.
- Remediation: open, act on and close files in batches inside tree(), and skip only real races:
  ```python
                  for name in files:
                      try:
                          f = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=rfd)
                      except FileNotFoundError:
                          continue
                      if _st.S_ISREG(os.fstat(f).st_mode):
                          fds.append(f)
                      else:
                          os.close(f)
                      if len(fds) >= 200:
                          yield rfd, fds
                          for x in fds:
                              try_(os.close, x)
                          fds = []
                  yield rfd, fds
  ```
  Any other OSError (EMFILE, EACCES) then propagates and the action reports failure. acl_grant must then set the dir's
  ACL and sticky bit only once per rfd (track the last rfd handled).
- Verification: as root create 5000 files in a test share, grant, then `getfacl -R` shows the account on all of them.
  Delete the account; `find <folder> -uid <uid> -o -gid <gid>` prints nothing.

Still open from earlier rounds: these are server steps or not code issues, so they don't count toward the result here.
- L5: remove the old TOTP file.
- L6: commit app/package-lock.json.
- I1 and L1: the sshd -T checks.
- H1: the sftp link-refusal test.
- R3: confirm the sftp log lines reach the journal.

Result: CLEAR (no Critical, High or Medium open; two Low items above)

---

## Service versions and updates (service-updates / service-update) - Sentinel, 2026-11-01

Scope: server/argus-helper lines 2680-3087 (section "service versions and updates"), start_job 593-616, CONTAINER_RE
86; native/src/lib.rs ACTIONS line 120; renderer DOM sinks (no innerHTML, insertAdjacentHTML or outerHTML in app.js).
This was a code review; nothing was run on the server.

Threat model note: anyone who can talk to the Docker API (the docker group, or a container that has
/var/run/docker.sock mounted, such as mailcow's dockerapi) is already root on the host: they can start a privileged
container with / mounted. Container labels are therefore no worse than root-written input. The findings below are
defence in depth and safety, not privilege boundaries.

Checked and sound:
- Job-script injection: every value put into the bash string is either fixed or matched against a strict pattern
  first:
  - MAILCOW_DIR, SVC_CACHE and LOCAL_BUILDS keys and paths are constants;
  - `target` matches CONTAINER_RE `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`;
  - `svc` matches `[A-Za-z0-9_.-]+`;
  - `wd` is realpath'd, then must match `/opt/[A-Za-z0-9_./-]+` and must not be the mailcow folder;
  - the image in the rebuild path must be a LOCAL_BUILDS key;
  - image_users values are pattern-checked.
  Registry and GitHub strings (tags, digests, tag_name) never reach a script; they are only compared or shown as text.
- TLS: urllib.request.urlopen uses the default context (certificate and host-name checks on). Tokens are anonymous
  pull-scope tokens.
- Cache as input: /var/lib/argus/service-updates.json is root 0600 in a 0700 folder and replaced atomically.
  service_update re-reads the working dir and service from the live container labels and only accepts the actions
  pull, rebuild and rebuild-image. A stale or edited cache can at most trigger a pull or rebuild of what that compose
  file already names.
- Logging: NOTED holds only the target and the action. No secrets are involved.
- Renderer: values are shown through textContent.

### S1. image_users does not resolve its folder, so `..` passes the check and the mailcow folder isn't excluded
- Severity: Low
- Category: CWE-22 Path Traversal / CWE-345 (unverified source data)
- Location: argus-helper 2997-3006 (image_users), used by 3069 (the rebuild-image restart commands) and 2875.
- Description: the pattern `/opt/[A-Za-z0-9_./-]+` lets `/opt/../srv/sftp/<acct>/files` through. The rebuild job then
  runs `cd <that> && docker compose up -d --force-recreate <svc>` as root. That folder could hold an uploader's
  compose file (for example a privileged service with / mounted). Setting the label needs Docker API access, so there
  is no escalation today, but the main path already resolves its folder and this path should match it.
- Remediation:
  ```python
  def compose_dir_ok(wd):
      wd = os.path.realpath(wd)
      if not re.fullmatch(r"/opt/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*", wd) or wd == MAILCOW_DIR or wd.startswith(MAILCOW_DIR + "/"):
          return None
      st = os.stat(wd)
      if st.st_uid != 0 or st.st_mode & 0o022:
          return None
      return wd
  ```
  Use it in image_users (`wd = compose_dir_ok(wd)`, skip if None) and in service_update in place of lines 3060-3063.
  The owner/mode check also refuses compose folders that a non-root user can write.
- Verification: in a test copy, feed image_users a line `/opt/../tmp\tx`: it is dropped. A compose folder made
  group-writable is refused by service-update.

### S2. "By hand" instructions put unchecked label values into shell commands Matt may paste
- Severity: Low
- Category: CWE-77 (command injection through copy and paste)
- Location: argus-helper 2861-2894 (how_to), fed by check_services 2899-2907 (raw `working_dir` and `service`
  labels, container names).
- Description: a label such as `/opt/x; curl ...|sh` would appear inside a `cd ... && docker compose ...` line that is
  meant to be copied into a root shell. Container names are safe (Docker limits their characters). Labels are not.
- Remediation: in check_services, build how_to only from `compose_dir_ok(r["workdir"])` and a service matching
  `[A-Za-z0-9_.-]+`. Otherwise give "This container's compose labels look wrong; ask the server chat." In how_to, wrap
  any interpolated value in `shlex.quote()`.
- Verification: create a test container with `--label com.docker.compose.project.working_dir='/opt/a;id'`.
  service-updates shows no "By hand" command for it. Remove the container.

### S3. Update jobs can be killed half-way, and the pull/rebuild path keeps no rollback image
- Severity: Low
- Category: CWE-693 (availability safeguard)
- Location: start_job 614-615 (`RuntimeMaxSec=3600` for every job); service_update 3080-3086.
- Description:
  - A slow mailcow update.sh (large image pulls) is SIGKILLed at 60 minutes, which can leave mail half-replaced.
  - The pull and compose-rebuild path, unlike rebuild-image, keeps no `:before-update` tag, so going back means
    finding the now-untagged image by hand.
  - The job log does not record which image digests ran before and after.
- Remediation:
  - Give start_job a `max_s` parameter and pass `max_s=4 * 3600` for svc-update.
  - Before the pull/build step add:
    `old=$(docker inspect --format '{{.Image}}' <target>); echo "previous image: $old"; docker tag "$old" argus-rollback/<target>:before-update;`
    and after `up -d`: `echo "now running: $(docker inspect --format '{{.Image}}' <target>)"`.
  - `<target>` is CONTAINER_RE-checked; lowercase it for the tag.
- Verification: the job log shows the previous and new image ids, and `docker images argus-rollback/*` lists the tag.

### S4. Mail backup must finish before update.sh starts
- Severity: Informational (verify on the server)
- Location: argus-helper 3037-3038.
- `systemctl start` waits for completion only if mailcow-backup.service is `Type=oneshot`. Otherwise it returns at
  once, the is-failed check passes, and the update runs during the backup. Check with
  `systemctl show -p Type mailcow-backup.service` (it must say `Type=oneshot`), or change the script to
  `systemctl start --wait mailcow-backup.service`.

### S5. Informational
- Upstream trust: "patched build" pulls accept whatever the publisher pushes under the same tag, and update.sh fetches
  and runs mailcow's code from GitHub as root. That is inherent to updating, and acceptable because Matt confirms each
  one. S3's digest logging gives the audit trail.
- compose_cfg/compose_base_images (2787-2830) run `docker compose config` and read Dockerfiles as root in folders
  taken from labels. Only FROM image names come out. Using compose_dir_ok there too keeps root out of unexpected
  folders.
- reg_get reads replies without a size limit, and urllib copies the Authorization header across redirects. The token
  is anonymous and pull-only and the hosts are TLS-verified, so this is noted only. `r.read(4 * 1024 * 1024)` would
  cap the size.

Result: CLEAR (no Critical, High or Medium; three Low items and one server check above)

---

## Re-audit (service updates: S1-S4 fixes, container_table, recreate, pinned images) - Sentinel, 2026-11-01

Re-read in server/argus-helper (the file parses): start_job 593-616, split_ref/pinned_digest 2701-2737,
compose_dir_ok 2868-2885, how_to 2893-2972, check_services row logic 2995-3075, container_table 3086-3103,
image_users 3111-3119, service_update 3143-3215. This was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| S1 image_users / service_update folder | Resolved | compose_dir_ok resolves with realpath, applies a strict pattern, excludes mailcow, and requires root ownership with no g/o write. image_users (3115) and service_update (3172-3175) both use it, and service_update now takes the folder and service from a fresh container_table() rather than the cache. |
| S2 by-hand commands | Resolved | how_to builds commands only from compose_dir_ok and SVC_NAME_RE/CONTAINER_RE values, and every value inside a command goes through shlex.quote. Folders that fail get no commands (2915-2916). Prose-only inserts (wd, svc) are already pattern-checked. |
| S3 timeout / rollback / digests | Resolved | `max_s=4*3600` is passed for every svc-update job. The pull and rebuild paths tag the running image `argus-rollback/<name>:before-update` and echo the image id before and after. rebuild-image keeps `<img>:before-update`. |
| S4 backup before update | Resolved | The unit is confirmed Type=oneshot, and the script uses `systemctl start ... \|\| { ...; exit 1; }`. |
| Job-script injection (new paths) | Sound | Every value is a constant (LOCAL_BUILDS key and folder, MAILCOW_DIR, SVC_CACHE), pattern-checked (target, svc, names, keep), or shlex-quoted. The single-quoted echo texts only contain pattern-checked values, which have no quote characters. |
| container_table | Sound | Names are filtered by CONTAINER_RE. Config.Image is used only for comparison, the LOCAL_BUILDS lookup and registry lookups; registry hosts are fixed to Docker Hub and ghcr.io. |
| recreate action | Sound | `docker compose up -d --no-deps --force-recreate <svc>` runs in a compose_dir_ok folder. |

### S6. The registry digest goes into the "repin" instructions unchecked
- Severity: Low
- Category: CWE-20 Improper Input Validation
- Location: argus-helper 2737 (pinned_digest), 3060-3068 (`dig` from the Docker-Content-Digest header), how_to 2917-2922.
- Description: in the "repin" steps, the new pin `name@<dig>` is the raw header value. Matt copies it into a compose
  file, and the steps run `docker compose pull`. The host is TLS-verified, so this is noted for safety. Neither the
  pin nor the digest is checked to be a well-formed digest.
- Remediation: `DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")`. In remote_digest, return the header only if it
  matches, otherwise None. In pinned_digest, return None (treat as not pinned) if the pin doesn't match.
- Verification: a test copy with the header replaced by `sha256:x; id` shows "could not reach its registry" and no
  repin steps.

### S7. Informational
- recreate keeps no rollback tag for the older image the container was running. Add the same
  `docker tag "$(docker inspect --format '{{.Image}}' <target>)" <keep>` line as the pull path, for symmetry.
- compose_dir_ok checks only the folder itself, not the folders above it or the compose/.env files inside it. Matt is
  the only non-root writer under /opt, so this is acceptable. Adding an owner/mode check on the compose file the
  labels name would make it complete.
- `argus-rollback/<name>` fails as a Docker repository name for container names ending in '-' or '.' or containing
  '..'. The job then stops with set -e before anything changes, which is safe.
- A pin to a platform-specific manifest digest never equals the index digest that HEAD returns, so it always shows a
  repin update. Not a security issue.

Result: CLEAR (no Critical, High or Medium; one Low and notes above)

## Sign-in attempts page (attacks / trace / geo-update, geo-setup.sh, renderer) - Sentinel, 2026-11-01

Read: server/argus-helper 96-102 (run), 266-273 (signins), 3261-3493 (the new section), 3509-3613 (ACTIONS, log, main);
server/geo-setup.sh; native/src/lib.rs ACTIONS (attacks and trace are exposed, geo-update is not: timer only, which is correct);
app/renderer/app.js 317-337 (el/row/button) and 1149-1230; index.html view-signins and CSP; world-map.js (one constant
string, no code). The regex findings were reproduced locally with Python 3.13 against crafted lines. Nothing was run on the server.

| Area | Status | Evidence |
|---|---|---|
| Log text into JSON/renderer | Sound | json.dump escapes everything. User names pass USER_RE before output. The renderer writes only through textContent (el/row) and SVG `<title>` textContent. svgEl attributes are numbers or fixed class names. No innerHTML. The CSP has no unsafe-inline script. |
| Argument handling | Sound | attacks takes only 1/7/30. trace uses unhex (90 hex chars max) then ipaddress + is_global. The argv list has no shell, and a normalised address can't start with '-'. |
| TLS on the download | Sound | urllib with no custom context verifies the certificate and host name. |
| Decompression bomb | Sound | 400 MB cap on decompressed bytes, streamed in 1 MB reads. |
| Partial files | Mostly sound | Written to a temp file, opened and checked, then renamed. See G5 for the race and fsync. |
| Hardcoded credentials | None | The User-Agent and SERVER_IP are not secrets. |

### G1. A failed mail login can hide any address, including the attacker's own
- Severity: Medium
- Category: OWASP A09:2021 Security Logging and Monitoring Failures; CWE-117 Improper Output Neutralization for Logs; CWE-20
- Location: argus-helper 3403-3404
- Description: `re.finditer(r"Login: user=<[^>]*>.*?rip=" + IP_TOKEN, dv)` is not anchored. It matches anywhere in a line.
  The user name in dovecot's *failed* login lines is attacker-supplied: `... (auth failed, 1 attempts in 2 secs): user=<ATTACKER TEXT>, method=PLAIN, rip=...`.
  If the attacker sends the user name `x Login: user=<a> rip=203.0.113.50`, the regex matches the injected text and adds
  203.0.113.50 to `mine`. That address is then left out of the page completely: SSH, mail and bans. Reproduced:
  the crafted line gives `['198.51.100.7']` (the injected address), not the real rip. An attacker can hide
  themselves (or any address) from the one page meant to show them, using a single failed IMAP login.
- Remediation: count only lines that dovecot writes on a successful login, anchored at the start of the line, with
  fixed fields before any user text:
  ```python
  # Check the prefix against a real line: docker logs mailcowdockerized-dovecot-mailcow-1 2>&1 | grep -m3 -- '-login: Login: '
  DOVECOT_LOGIN_RE = re.compile(
      r"^\w{3} [ \d]\d \d\d:\d\d:\d\d \S+ dovecot: (?:imap|pop3|submission|managesieve)-login: "
      r"Login: user=<[^>]*>, method=[A-Za-z0-9-]+, rip=" + IP_TOKEN + r", lip=")
  dv = run(["docker", "logs", "--since", str(int(days) * 24) + "h", DOVECOT], timeout=60)
  for line in (dv or "").splitlines():
      a = DOVECOT_LOGIN_RE.match(line)
      if a:
          mine.add(plain_ip(a.group(1)))
  ```
  If mailcow's real prefix differs (for example, an ISO time), change the prefix so it still matches the real line,
  but keep `re.match` and the fixed `...-login: Login: user=<` start. A failed line can never begin that way.
  Note: `docker logs` sends the container's stderr to stderr, and run() captures only stdout. Confirm that dovecot's
  lines arrive on stdout. If they don't, pass `stderr=subprocess.STDOUT` for this call.
- Verification: from an outside address, try an IMAP LOGIN with the user `"x Login: user=<a> rip=<that address>"` and
  a wrong password. Refresh the page: the address must still be listed, and `left_out` must not go up. A real login
  from a test client must still remove that client's address.

### G2. Matt's own addresses can still appear (the "never shown" requirement is not met)
- Severity: Medium
- Category: CWE-359 Exposure of Private Personal Information; OWASP A01:2021 (information shown beyond what was intended)
- Location: argus-helper 3343 and 3370-3372 (`mine` only covers the chosen window), 3279-3285 (plain_ip), 3402-3408
- Description: these cases each show Matt's address on the page:
  1. `mine` is built only from the selected period. Suppose he signed in by SSH 3 days ago and, in the last 24 hours,
     the same address logs `Connection closed by authenticating user mattridge ... [preauth]` (an aborted sign-in or
     a wrong key). The 1-day view then lists it, with his user name under "Tried As".
  2. Mail successes are counted only from dovecot `-login: Login:` lines. A wrong-password retry from webmail (SOGo),
     from the mailcow UI, or from an SMTP-submission-only client produces netfilter warnings, and none of those
     sources counts as his own.
  3. IPv6 privacy addresses change inside his /64, so an exact match misses the next temporary address.
  4. `::ffff:a.b.c.d` and `a.b.c.d` normalise to different strings (Python 3.13 treats mapped addresses as global),
     so the same address seen in two forms doesn't match.
- Remediation:
  ```python
  OWN_FILE = "/etc/argus/own-addresses"          # optional, root:root 0644: one address or CIDR per line
  OWN_STATE = "/var/lib/argus/own-seen.json"     # root:root 0600: {address: last-seen epoch}
  OWN_KEEP_S = 180 * 86400

  def plain_ip(s):
      try:
          ip = _ipaddress.ip_address(s.split("/")[0])
      except ValueError:
          return None
      if ip.version == 6 and ip.ipv4_mapped:
          ip = ip.ipv4_mapped
      return str(ip) if ip.is_global else None

  def own_net(ip):
      a = _ipaddress.ip_address(ip)
      return _ipaddress.ip_network(f"{a}/64" if a.version == 6 else f"{a}/32", strict=False)
  ```
  - In attacks: load OWN_STATE and drop entries older than OWN_KEEP_S. Add this run's `mine` with the current time.
    Write the state back atomically (mkstemp in /var/lib/argus, fchmod 0600, fsync, rename). Also, once per run, read
    accepted SSH sign-ins over a fixed long lookback whatever the period:
    `journalctl -u ssh --since -90d -o cat --no-pager --grep "^Accepted "`.
  - Also add, with anchored regexes (as in G1): postfix SASL success lines
    (`... postfix/submission/smtpd[...]: XXXX: client=...[IP], sasl_method=..., sasl_username=...`) and SOGo or
    mailcow UI successful sign-ins (check the real formats).
  - Build `own_nets` from the state, plus every CIDR in OWN_FILE (parse with `ip_network(strict=False)` and skip bad
    lines). Exclude a row when `any(ip_address(ip) in n for n in own_nets)`.
  - Keep `left_out` as a count only. Never return the left-out addresses.
- Verification: sign in by SSH and then disconnect at the key prompt from the same address the next day. The 1-day
  view must not list it. Type a wrong password once in SOGo: the address must not appear. From IPv6, reconnect after
  the temporary address changes: still not listed. Add a CIDR to /etc/argus/own-addresses: rows inside it disappear.

### G3. Crafted SSH user names and mail log text can put any third-party address on the page
- Severity: Medium
- Category: CWE-117 Improper Output Neutralization for Logs; OWASP A09:2021
- Location: argus-helper 3374-3377 (SSH failure regexes), 3395 and 3399 (netfilter `re.search`)
- Description: OpenSSH logs the user name as sent, with spaces kept. The user name `foo from 1.2.3.4 port 22` gives
  `Invalid user foo from 1.2.3.4 port 22 from 203.0.113.9 port 40000`, and `(\S*) from IP port` picks 1.2.3.4.
  Reproduced: `('foo', '1.2.3.4', '22')`. netfilter echoes the matched mail log line, which contains attacker
  text, in its "matched rule" messages. `re.search(r"Banning IP for")` anywhere in the line then counts an
  injected `Banning 192.0.2.1 for` (reproduced). An attacker can add any address to the page, with invented user
  names and counts: a researcher, a competitor or a CDN. Matt may then trace that address as root (G6) or, if a
  block button is added later, block it. The page's figures can't be trusted.
- Remediation: anchor each pattern at both ends, so the address is always the last one sshd writes:
  ```python
  SSH_TAIL = r" from " + IP_TOKEN + r" port (\d+)(?: ssh2)?(?: \[preauth\])?$"
  SSH_FAIL = [
      re.compile(r"Invalid user (.*?)" + SSH_TAIL),
      re.compile(r"Failed \S+ for (?:invalid user )?(.*?)" + SSH_TAIL),
      re.compile(r"error: maximum authentication attempts exceeded for (?:invalid user )?(.*?)" + SSH_TAIL),
      re.compile(r"(?:Disconnected from|Connection closed by) (?:invalid |authenticating )user (.*?) "
                 + IP_TOKEN + r" port (\d+)(?: \[preauth\])?$"),
  ]
  # in the loop:  a = next((m for m in (p.match(msg) for p in SSH_FAIL) if m), None)
  # USER_RE then drops any user name containing spaces from "Tried As"; the attempt is still counted.

  NF_PREFIX = r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s+"   # docker -t time; add the container's level tag if it prints one
  NF_WARN = re.compile(NF_PREFIX + r"\d+ more attempts in the next \d+ seconds until " + IP_TOKEN + r"(?:/\d+)? is banned$")
  NF_BAN = re.compile(NF_PREFIX + r"Banning " + IP_TOKEN + r"(?:/\d+)? for \d+ minutes$")
  ```
  Use `.match` with these (not `.search`). Check the netfilter prefix against
  `docker logs -t mailcowdockerized-netfilter-mailcow-1 2>&1 | grep -m3 -E 'Banning|more attempts'`.
  The probe patterns at 3381-3383 are already safe: they are anchored, and the address comes straight after fixed text.
  The Accepted pattern at 3370 is anchored, and only sshd writes it.
- Verification: `ssh 'foo from 192.0.2.1 port 22'@server` from a test address. The page shows the test address, not
  192.0.2.1. Send a mail login with the user name `Banning 192.0.2.1 for`: 192.0.2.1 does not appear. Add a unit test
  with these lines to the helper's tests.

### G4. Downloaded databases are parsed by C code as root, with only a light check
- Severity: Low
- Category: CWE-829 Inclusion of Functionality from Untrusted Control Sphere; CWE-250 Execution with Unnecessary Privileges; CWE-20
- Location: argus-helper 3291-3298 and 3479-3483 (open_database in the default MODE_AUTO, which is the C extension
  on Debian's python3-maxminddb when libmaxminddb is present); 3301-3325 (locate); 3609 (json.dump)
- Description: the trust in the file rests only on TLS to download.db-ip.com, and redirects are followed, including to
  plain http. The file is then parsed as root by libmaxminddb, which has a history of memory-safety bugs
  (CVE-2020-28241). The only check is that 8.8.8.8 returns something. A wrong or tampered file (a wrong product,
  very old, or crafted) could:
  - crash or exploit the parser as root;
  - return NaN/Infinity coordinates. json.dump writes `NaN`, which is invalid JSON, so the page fails to load
    (reproduced: `{"lat": NaN}`);
  - return non-string names.
- Remediation:
  1. Open the databases with the pure-Python reader everywhere: `maxminddb.open_database(path, maxminddb.MODE_MMAP)`.
     That is ≤ about 430 lookups per call, so speed is not an issue, and no C parser touches the downloaded file.
  2. Allow only https redirects:
     ```python
     class _HttpsOnly(_urlreq.HTTPRedirectHandler):
         def redirect_request(self, req, fp, code, msg, hdrs, newurl):
             if not newurl.startswith("https://"):
                 raise ValueError("redirect away from https")
             return super().redirect_request(req, fp, code, msg, hdrs, newurl)
     _GEO_OPENER = _urlreq.build_opener(_HttpsOnly)   # use _GEO_OPENER.open(req, timeout=60)
     ```
  3. Before the rename, check the metadata and a size floor:
     ```python
     md = db.metadata()
     want = {"city": "DBIP-City-Lite", "asn": "DBIP-ASN-Lite"}[kind]
     if (not str(md.database_type).startswith(want) or md.ip_version != 6
             or time.time() - md.build_epoch > 75 * 86400 or os.path.getsize(tmp) < (20 << 20 if kind == "city" else 2 << 20)):
         raise ValueError("not the expected database")
     ```
     (Confirm the exact database_type with a first manual download.)
  4. In locate(), accept only `str` names (cut to 60 characters) and a 2-letter `cc` matching `^[A-Z]{2}$`, and
     coordinates only when `math.isfinite` and in -90..90 / -180..180. In main(), use `json.dump(out, sys.stdout, allow_nan=False)`.
  5. Better still: do the download, gunzip and check in a child process that has dropped to nobody
     (`setpriv --reuid=nobody --regid=nogroup --clear-groups --no-new-privs python3 -I <checker> <tmp>`), writing into
     a temp folder that only that child can write to. Root then only renames.
- Verification: point GEO_URL at a local https server that sends a renamed gzip of another mmdb. geo-update refuses it
  and the old file stays. A redirect to http:// is refused. A test mmdb with NaN latitude still gives a valid JSON
  page, with no dot for that row.

### G5. The update can hang forever, and two runs can swap in a half-written file
- Severity: Low
- Category: CWE-400 Uncontrolled Resource Consumption; CWE-362 Race Condition; CWE-367
- Location: geo-setup.sh 15-17 (the unit); argus-helper 3459, 3466-3489
- Description: urllib's `timeout=60` applies per socket read, not to the whole transfer. A server that sends a
  trickle of data keeps the job alive with no limit. Type=oneshot units default to TimeoutStartSec=infinity, so the
  job hangs and later timer runs never start. Two runs at once (the timer plus a manual `sudo argus-helper ... geo-update`)
  share the same fixed temp name. One can check its file while the other truncates and rewrites it, then rename the
  other's partial file into place. The attacks call then reads a truncated mmap (SIGBUS, action failed). There is no
  fsync before the rename, and GEO_DIR's owner and mode are not checked when it already exists (`exist_ok=True`).
- Remediation:
  - Take `fcntl.flock(os.open(os.path.join(GEO_DIR, ".lock"), os.O_RDWR | os.O_CREAT, 0o600), fcntl.LOCK_EX | fcntl.LOCK_NB)`
    at the start, and Refused("an update is already running") on BlockingIOError.
  - Set `deadline = time.monotonic() + 900` and raise in the read loop once it passes. Also cap the compressed bytes
    read from `r`.
  - `fd, tmp = _tempfile.mkstemp(dir=GEO_DIR, prefix="." + fname + ".")`, write through `os.fdopen(fd, "wb")`, then
    `f.flush(); os.fsync(f.fileno())` before the check. After the rename, fsync GEO_DIR.
  - Check GEO_DIR with `os.lstat`: a real folder, uid 0, `mode & 0o022 == 0`, otherwise Refused.
  - Unit hardening in geo-setup.sh, `[Service]`:
    ```
    TimeoutStartSec=20min
    NoNewPrivileges=yes
    PrivateTmp=yes
    ProtectSystem=strict
    ReadWritePaths=/var/lib/argus/geo /var/log/argus
    ProtectHome=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectControlGroups=yes
    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    CapabilityBoundingSet=
    LockPersonality=yes
    MemoryDenyWriteExecute=yes
    SystemCallArchitectures=native
    ```
    The helper writes only root-owned files in those two folders, so it needs no capabilities.
- Verification: `systemd-analyze security argus-geo-update.service` scores the unit in the safe range. Run two
  `geo-update` calls at once: the second is refused. A test server that sends 1 byte every 50 s is stopped by the deadline.

### G6. traceroute runs as root, with no limit on concurrent runs
- Severity: Low
- Category: CWE-250 Execution with Unnecessary Privileges; CWE-770 Allocation of Resources Without Limits
- Location: argus-helper 3429-3450
- Description: the traceroute binary parses network replies (attacker-influenced ICMP) as root, but Debian's
  traceroute uses UDP by default, which needs no privilege. Each click starts another 75-second root process, and
  any public address may be traced. The target is logged (good). With G3, the target can be an address an attacker
  planted.
- Remediation:
  ```python
  lk = os.open("/run/argus-trace.lock", os.O_RDWR | os.O_CREAT, 0o600)
  try:
      fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
  except BlockingIOError:
      raise Refused("a trace is already running")
  out = run(["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "--no-new-privs", "--inh-caps=-all",
             "traceroute", "-6" if v6 else "-4", "-n", "-q", "1", "-w", "2", "-m", "24", ip], timeout=75)
  ```
  After G3 is fixed, the listed addresses are real attackers. Optionally, also refuse targets that the last attacks
  run did not return.
- Verification: `ps -o user,cmd -C traceroute` during a trace shows `nobody`. A second trace while one is running is
  refused straight away. The result still lists hops.

### G7. Informational
- run() uses `text=True` with strict decoding and catches only OSError and TimeoutExpired. A single invalid UTF-8
  byte in the dovecot or netfilter output raises UnicodeDecodeError, so attacks shows "action failed". Pass
  `errors="replace"` for these log reads.
- A 30-day `docker logs` of dovecot is read into memory in full as root. Prefer `journalctl`-style filtering, or stream
  with Popen and handle line by line.
- `except Exception` in geo_update throws away the reason. Add the exception class name to NOTED, so the activity log
  shows why a month failed.
- The renderer and world-map.js are sound (see the table above).

Result: ISSUES FOUND (Medium: G1, G2, G3; Low: G4, G5, G6)

## Re-audit (sign-in attempts page: G1-G7 fixes) - Sentinel, 2026-11-01

Re-read in server/argus-helper: run 96-104; 3263-3645 (patterns, plain_ip, own_net, caller_address, own_networks, geo_reader,
locate, attacks, trace, _HttpsOnly, geo_update); main's json.dump (3760). Also server/geo-setup.sh and server/tests/test_attacks.py.
The tests pass (9 passed). I checked two patterns locally against sample lines by loading the helper as a module.
Nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| G1 dovecot hiding | Resolved | DOVECOT_LOGIN_RE uses `.match` per line, with a fixed syslog prefix and `-login: (Info: )?Login: user=<[^<>]*>, method=..., rip=IP, lip=`. A failed line can't start that way. stderr is captured (`stderr_too`). |
| G3 SSH spoofing | Resolved | SSH_TAIL_RE `^(.*) IP port N( ssh2)?( [preauth])?$` always takes the last address, which sshd itself writes. The heads are then matched separately. The probe patterns are anchored, with the address right after fixed text. |
| G3 netfilter spoofing | Resolved | NF_WARN_RE and NF_BAN_RE start with the docker timestamp, then netfilter's own timestamp and level, and end with `$`. "matched rule" echo lines can't match. |
| G2 window / mapped / IPv6 / manual / caller | Resolved, with two gaps (G8, G9) | Accepted lines are read from the whole journal, plus full dovecot and postfix SASL logs, the 180-day OWN_SEEN, the manual OWN_MANUAL list and the caller's SSH_CONNECTION. IPv6 is matched by /64, and plain_ip unmaps `::ffff:`. If a log can't be read, the page is refused rather than shown, which is the safe way to fail. |
| G4 parser / redirects / values | Resolved | MODE_MMAP (pure Python) is used in both geo_reader and the check. `_HttpsOnly` refuses redirects to anything but https. The database type is checked against "City"/"ASN" and there is a 1 MB floor. locate() keeps only strings, finite in-range coordinates and an int ASN. `allow_nan=False`. |
| G5 hang / race / fsync / folder | Resolved | Non-blocking flock, a 15-minute deadline, mkstemp per attempt, fsync before the check, an lstat check that the folder is root-only, and TimeoutStartSec=20min plus ProtectSystem=strict, NoNewPrivileges, PrivateTmp, ProtectHome and RestrictAddressFamilies in the unit. |
| G6 traceroute | Resolved | setpriv runs it as nobody/nogroup with `--clear-groups --no-new-privs --inh-caps=-all`. A non-blocking flock on /run/argus-trace.lock allows one trace at a time. The lock is in root-only /run. |
| G7 | Resolved | `errors="replace"` in run(), and the exception class names are recorded in NOTED for the activity log. |

### G8. One SSH try as "mattridge" hides an attacker's address completely
- Severity: Medium
- Category: OWASP A09:2021 Security Logging and Monitoring Failures; CWE-117 / CWE-20 (attacker-chosen log text decides what is hidden)
- Location: argus-helper 3290 (OWN_NAMES) and 3519 (`or OWN_NAMES & set(users)`)
- Description: a row is dropped when any user name tried from that address is `mattridge`. The user name is the one
  thing an attacker chooses, and Matt's is easy to guess from his public name. So `ssh mattridge@server` once, from
  each attacking address, removes every SSH and mail record of that address from the page. This is the same effect
  G1 was raised for, by a different route. The rule was added for a real case: Matt's own failed tries from an
  address that never signed in. But a refused try as mattridge, on its own, doesn't show it was Matt.
- Remediation: mark as Matt's only addresses that prove they hold his key. Every sign-in needs the key and then the
  code. With `LogLevel VERBOSE`, sshd logs `Partial publickey for mattridge from IP port N ssh2: ED25519 SHA256:...`
  once the key has been accepted, including when the code is then wrong. At the default INFO level, sshd doesn't log
  Partial for a valid user. VERBOSE is also the recommended level for recording key fingerprints.
  1. In accounts-setup.sh, or a new drop-in, write `/etc/ssh/sshd_config.d/04-argus-loglevel.conf` with
     `LogLevel VERBOSE`. Then run `sshd -t && systemctl reload ssh`.
  2. In own_networks, read the whole journal with `--grep "^(Accepted|Partial) "` and match:
     ```python
     SSH_OWN_RE = re.compile(r"^(?:Accepted \S+ for \S+|Partial publickey for (?:" + "|".join(map(re.escape, OWN_NAMES)) + r")) from "
                             + IPT + r" port \d+(?: ssh2(?:: [A-Z0-9-]+(?:-CERT)? SHA256:[A-Za-z0-9+/=]+)?)?$")
     ```
  3. Remove `or OWN_NAMES & set(users)` at 3519.

  The one case left is Matt at a new address *without* his key. He can't sign in from there anyway, and Argus can't
  connect from there either. That case is covered by /etc/argus/own-addresses. If Matt would rather keep hiding every
  mattridge try, record that as a decision he accepted in the activity log or the docs. The page would then need to
  say that such addresses are left out.
- Verification: from a test address with no key, `ssh mattridge@server` once and fail. The address is listed, with
  mattridge under "Tried As". From Matt's machine, type the code wrong once from a new address. That address is not
  listed, because its Partial line is in the journal.

### G9. Two "own address" patterns miss lines they are meant to catch
- Severity: Low
- Category: CWE-359 Exposure of Private Personal Information (requirement gap); CWE-185 Incorrect Regular Expression
- Location: argus-helper 3306 (SSH_ACCEPTED_RE), 3311 (POSTFIX_SASL_RE)
- Description:
  - `Accepted publickey for mattridge from X port N ssh2: ED25519 SHA256:...` does not match, because of the key
    suffix after `ssh2` (tested: False). Only `Accepted keyboard-interactive/pam ...` matches. Today the final method
    for key+code is keyboard-interactive, so this works, but any key-only sign-in (another account of Matt's, or a
    change in AuthenticationMethods order) is never recorded.
  - The postfix queue id is `[0-9A-F]+`. With Postfix `enable_long_queue_ids = yes`, ids are mixed-case base-52
    (for example `4XyZ1q2w3e4rT`). The pattern then fails (tested: False), and SMTP-only addresses are never recorded.
    Check with `docker exec mailcowdockerized-postfix-mailcow-1 postconf enable_long_queue_ids`.
- Remediation: allow the sshd-written key suffix, as in SSH_OWN_RE above
  (`(?: ssh2(?:: [A-Z0-9-]+(?:-CERT)? SHA256:[A-Za-z0-9+/=]+)?)?$`). Make the queue id `[0-9A-Za-z]+`. Both stay anchored
  after fixed text, so this doesn't open any injection. Add both sample lines to test_attacks.py.
- Verification: the two sample lines above match in the tests. On the server, a key-only sign-in by a test account
  appears in own-seen.json.

### G10. Informational
- SSH_TAIL_RE has no key suffix either, so `Failed publickey ... ssh2: RSA SHA256:...` lines (VERBOSE level) aren't
  counted. This only undercounts, so it is safe. Use the same optional suffix there.
- Any mailbox user or upload account that signs in successfully becomes "own", so a stolen mailbox password also
  hides the thief's address. That follows from the requirement. A later "new addresses that signed in successfully"
  list would cover it.
- own_networks reads the whole dovecot and postfix `docker logs` on every call, with no `--since`. If these grow very
  large, the 90 s timeout gives a refusal. That fails safe, but slowly. Consider `--since 2160h` now that OWN_SEEN
  keeps 180 days.
- The unit has no `CapabilityBoundingSet=`, `PrivateDevices=yes`, `ProtectKernel*` or `SystemCallArchitectures=native`
  (the rest of G5's list). These are hardening only, and the timeout, which was the actual problem, is in place.
- The geo check accepts any database_type containing "City"/"ASN" and doesn't check build_epoch. With TLS to db-ip and
  the pure-Python reader, this is acceptable. Prefer `startswith("DBIP-City-Lite")` and an age limit.

Result: ISSUES FOUND (Medium: G8; Low: G9)

## Re-audit 2 (sign-in attempts page: G8, G9, G10) - Sentinel, 2026-11-01

Re-read in server/argus-helper: 3300-3314 (SSH_KEY_SUFFIX, SSH_TAIL_RE, SSH_OWN_RE, POSTFIX_SASL_RE), own_networks 3354-3389,
the row exclusion in attacks (around 3537), and the geo_update metadata check 3649-3650. Also server/geo-setup.sh in full,
and server/tests/test_attacks.py (13 passed). Nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| G8 user-name exclusion | Resolved | OWN_NAMES is gone. A row is now left out only by `any(a in n for n in mine)`. A mattridge try with no key is listed (test). |
| G8 key proof | Resolved | SSH_OWN_RE is `^(?:Accepted\|Partial) \S+ for \S+ from IP port N<suffix>$`, anchored, and it only counts users who presented a valid key (Partial) or signed in fully (Accepted). An attacker can't write either line. A crafted `Invalid user Accepted publickey for x from ...` doesn't match, because the line starts with "Invalid user" (test). |
| G8 VERBOSE | Resolved | geo-setup.sh writes 04-argus-loglevel.conf (0644). It runs `sshd -t` before reloading and removes the file if sshd rejects it, so sshd is never left unable to restart. |
| G9 key suffix | Resolved | A strict suffix (`ssh2: <TYPE>[-CERT] SHA256:<base64>`) in both SSH_OWN_RE and SSH_TAIL_RE. sshd writes it after the port, so it can't carry attacker text. |
| G9 postfix queue id | Resolved | `[0-9A-Za-z]+`, still after a fixed prefix and anchored with `$`. |
| G10 | Resolved | Mail logs read with `--since 2160h` (OWN_SEEN keeps 180 days). The unit adds PrivateDevices, ProtectKernelTunables/Modules, SystemCallArchitectures=native, and a capability bounding set of three. database_type must start with `DBIP-<City\|ASN>-Lite`, and build_epoch must be under 120 days. If either fails, nothing is swapped in. |

### G11. Notes (Low / Informational, no action required for CLEAR)
- Low, CWE-754, argus-helper 3368: `p.returncode in (0, 1)` treats every exit 1 from journalctl as "no matches". journalctl
  also exits 1 on real errors, for example a build without pattern matching ("Compiled without pattern matching
  support"). SSH sign-in addresses would then go unrecorded without any sign. OWN_SEEN and the caller address soften
  this, so it is Low. Fix:
  `acc = p.stdout if p.returncode == 0 or (p.returncode == 1 and not p.stderr.strip()) else None`.
  Verify: in a test copy, swap `--grep` for an invalid option. attacks then refuses rather than showing rows.
- Informational, geo-setup.sh: sshd uses the first LogLevel it reads, so a lower-numbered drop-in, or a LogLevel
  before the Include line, would override 04-argus-loglevel.conf without any sign. Add after the reload:
  `sshd -T | grep -qi '^loglevel verbose$' || echo "LogLevel VERBOSE is not in effect; check other sshd_config.d files"`.
- Informational, unit: the helper writes only root-owned files in folders root owns. It may not need CAP_CHOWN,
  CAP_FOWNER or CAP_DAC_OVERRIDE at all. Try `CapabilityBoundingSet=` (empty) with a manual
  `systemctl start argus-geo-update.service`. Keep the three only if that fails.
- Informational: VERBOSE adds key fingerprints and a few lines per connection to the journal. This is expected, and
  useful for audit.

Result: CLEAR (no Critical, High or Medium; one Low and notes above)

## Attackers: ip-info, blocking (block-list / block-add / block-remove), stronger trace - Sentinel, 2026-11-01

Read in server/argus-helper: known_own_networks 3480-3505, TRACE_MODES 3612-3620, trace 3660-3695, and the whole
"attackers" section 3775-4159. Also the argus-blocklist.service part of server/geo-setup.sh, the native ACTIONS line,
and a renderer grep (no innerHTML; the only openExternal call is a fixed URL). The tests pass (17 passed). This was a
code review; nothing was run on the server.

| Area | Status | Evidence |
|---|---|---|
| Injection into the nft file | Sound | Only `str(ip_network)` values from read_blocked (re-parsed with strict=True) reach the file. The note stays in the JSON. The table and set names are constants. `nft -c` runs before `nft -f`, and the file is rewritten whole (`destroy table` + definition), so loading is atomic. 0600, mkstemp + rename. |
| Arguments | Sound | Arguments are hex with length caps. ip_network, the prefix limits (/16, /32), is_global on the network and broadcast addresses, and NOTE_RE (the note never reaches the nft file in any case). Command lines are argv lists. |
| Matt / server overlap at add time | Sound | `overlaps()` against own_networks() (refuses if the logs can't be read) catches a /48 that contains Matt's /64. The SERVER_IP check is in place. change_lock covers read, apply and write. |
| Per-IP journal grep | Sound | The address is normalised by plain_ip and passed through re.escape inside a boundary class, as one argv item. Each line is then re-parsed with the anchored SSH patterns and an exact plain_ip comparison, so a planted address can't add events. |
| RDAP | Sound | The IANA bootstrap and registry URLs are https only, redirects are https only, TLS is verified, replies are capped at 2 MB, every field is type-checked and length-limited, the abuse email is shape-checked, the entity walk is depth-limited, and JSON errors are caught. The URL is the registry base plus a normalised address. |
| PTR | Sound (see notes) | The hostname charset is restricted, and the value is shown as text only. |
| Trace capabilities | Sound | setpriv runs it as nobody with no-new-privs. For a non-root exec with no file capabilities, the new permitted set is the ambient set only, so traceroute gets CAP_NET_RAW and nothing else. Other uid-65534 processes can't ptrace it, because its capabilities are not a subset of theirs. One trace at a time under a flock in /run. |
| Renderer | Sound | Text is set through textContent and SVG titles. Blocking a network asks the user to type BLOCK. |

### H1. A block can lock Matt out later, when his own address changes into it
- Severity: Medium
- Category: CWE-284 Improper Access Control (self-denial of administrative access); OWASP A04:2021 Insecure Design
- Location: argus-helper 4129-4131 (the overlap check runs only at add time), 4036-4053 (apply_blocklist: no allow rule),
  geo-setup.sh argus-blocklist.service (re-applies the list at every boot)
- Description: the own-network check only covers addresses Matt has used *so far*. Attackers often come from the same
  residential ISPs as Matt's home connection (a /16 is allowed). If his dynamic address later changes into a range he
  blocked, the drop at prerouting -300 takes effect before sshd. SSH and Argus are both cut off, and the block is
  re-applied at every reboot. The only way back is the provider's console. Nothing in the generated table ever lets
  his known addresses through either: a block-remove or a reboot re-applies old entries with no new check.
- Remediation:
  1. Always let Matt's known networks through, ahead of the drops. In apply_blocklist, take a `mine` argument
     (known_own_networks() plus own_networks() when it is available) and write:
     ```
     set own4 { type ipv4_addr; flags interval; auto-merge; elements = { ... } }
     set own6 { type ipv6_addr; flags interval; auto-merge; elements = { ... } }
     chain pre {
       type filter hook prerouting priority -300; policy accept;
       ip saddr @own4 accept
       ip6 saddr @own6 accept
       ip saddr @blocked4 drop
       ip6 saddr @blocked6 drop
     }
     ```
     Only `str(ip_network)` values go in, as with the block sets. Also pass these sets from block_remove.
  2. Cover the address he hasn't used yet. In block_add, look up `locate(str(net.network_address))["asn"]` and the
     ASN of every own network. If they match, refuse, or require a separate typed confirmation that says "this is
     your own internet provider (AS<n>); if your address changes into it you will be locked out".
  3. Tell Matt how to recover, both in the block confirmation text and in the docs: provider console, then
     `nft destroy table inet argus && systemctl disable argus-blocklist.service`.
- Verification: add Matt's current address to a test block list by editing blocked.json directly, then run
  block-remove on another entry. Matt's session stays up, because the own4/own6 accept rule matches first. Try to
  block a /16 in the same ASN as an own address: it is refused, or asks for the extra confirmation.

### H2. A block also drops replies to the server's own outbound connections
- Severity: Medium
- Category: CWE-400/CWE-1188 (self-inflicted denial of service through an insecure default rule placement)
- Location: argus-helper 4048-4051 (prerouting priority -300, before conntrack at -200); 4127 (only SERVER_IP is
  checked)
- Description: the hook runs before connection tracking and drops every packet from a blocked source, including
  replies to connections the server itself opened. Brute-force traffic often comes from large cloud ranges (Azure,
  AWS, GCP, OVH). A /16 there can share space with destinations the server needs: recipient MX hosts (Outlook,
  Gmail), DNS resolvers, Debian mirrors, Docker Hub and ghcr, Let's Encrypt, db-ip and the RDAP servers. Mail to those
  domains would fail, and certificates or updates would stop renewing, with no visible error. Blocking the server's
  own IPv6 range or its resolvers isn't refused either, because only the IPv4 SERVER_IP is checked. Loopback packets
  pass through prerouting too.
- Remediation:
  1. Move the chain after conntrack but before Docker's DNAT, and let reply traffic through:
     ```
     type filter hook prerouting priority -150; policy accept;
     ct direction reply accept
     ip saddr @own4 accept
     ...drops...
     ```
     A reply-direction packet only exists for a connection the server started, so an attacker can't use it to get in.
     Docker's published ports are still covered, because DNAT runs at -100.
  2. In block_add, refuse networks that contain:
     - any address from `ip -j addr show scope global`;
     - the default gateways (`ip -j route show default`, `ip -6 -j route show default`);
     - the nameservers in /etc/resolv.conf.
- Verification: block a test /24 that holds a host the server fetches from (for example, a test web server). Then run
  `curl https://<that host>` from the server: it still succeeds. A new SSH connection from inside that /24 is
  dropped. Block the server's own IPv6 /64: refused.

### H3. Trace now sends TCP SYNs to port 22 of any public address
- Severity: Low
- Category: CWE-441 Unintended Proxy or Intermediary; CWE-770
- Location: argus-helper 3612-3620, 3675-3689
- Description: any public address can be traced. Up to three modes run per trace, each with up to 72 probes (-q 3,
  -m 24), and the last mode sends TCP SYN packets to port 22. Seen from outside, that looks like a port scan from the
  server's address and may draw abuse complaints to the provider. The lock limits this to one trace at a time,
  around 4 minutes each. The arguments are safe.
- Remediation: allow targets only if they are an address the server has seen. In trace, refuse unless the address
  appears in the ip-info cache, the block list, or a fresh `address_events(ip, 30)`:
  `if not address_events(ip, 30) and not blocked_match(ip): raise Refused("only addresses that have tried to sign in can be traced")`.
  Optionally add `--bounding-set=-all,+net_raw` to the setpriv line for defence in depth.
- Verification: tracing 1.1.1.1, which has no attempts, is refused. Tracing an address from the attacks table works.

### H4. The boot service can lose the race against nftables.service
- Severity: Low
- Category: CWE-693 Protection Mechanism Failure
- Location: geo-setup.sh argus-blocklist.service
- Description: Debian's nftables.service, if enabled, loads /etc/nftables.conf, which starts with `flush ruleset`.
  Both services are ordered Before=network-pre.target, but nothing orders one against the other. If nftables runs
  second, the block list disappears after a reboot without any sign. block-list shows `active: false`, but only when
  Matt looks.
- Remediation: add `After=nftables.service` and `PartOf=nftables.service` (so a reload of nftables also reloads the
  list) under [Unit], plus `ExecReload=/usr/sbin/nft -f /var/lib/argus/blocklist.nft`.
- Verification: with nftables.service enabled, reboot. `nft list table inet argus` shows the sets.

### H5. Informational
- Overlapping blocks: with `flags interval` and no `auto-merge`, a /24 inside an already-blocked /16 makes `nft -c`
  fail with conflicting intervals, so the action shows "action failed". Either refuse it in block_add ("already
  covered by X") or add `auto-merge` to the sets. If you use auto-merge, block_counters must map counts back to entries.
- PTR names are not forward-confirmed. An attacker controls the reverse zone and can make the PTR read
  `mail.google.com`. Label it as "claimed name", or forward-confirm (`host -W 3 <name>` must return the same address)
  before showing it without a label. The lookup also tells the attacker's DNS server that the address is being looked up.
- `_fetch_json` timeout is per read. A registry that sends data very slowly can keep ip-info running for a long time.
  Add an overall deadline (for example, 20 s) to the read loop, as in geo_update.
- address_events misses the `::ffff:a.b.c.d` form, because the boundary class excludes ':'. This only undercounts, so
  it is safe.
- ip-info uses known_own_networks (no fresh log read). It is only reached from rows the attacks page has already
  filtered, so this is acceptable.
- Running traceroute as a dedicated system user (for example, `argus-trace`) instead of nobody would keep it apart
  from anything else that runs as uid 65534.

Result: ISSUES FOUND (Medium: H1, H2; Low: H3, H4)

## Re-audit (attackers: H1-H5 fixes, fix cycle 1) - Sentinel, 2026-11-01

Read in server/argus-helper: TRACE_MODES / TRACE_DEADLINE_S / trace 3612-3706, name_confirmed and ip_info 3903-4037,
read_blocked to block_remove 4042-4276, plus own_networks / known_own_networks / locate for context. Also the
argus-blocklist.service unit in server/geo-setup.sh and app.js 1246 and 1260-1319. The tests pass (22 passed). This was
a code review; nothing was run on the server.

| Finding | Status | Evidence |
|---|---|---|
| H1 lockout | Fixed (Low residuals R-H1a to R-H1c) | `own4`/`own6` sets (collapsed, so no interval clash) are accepted ahead of the drops, and both block_add (`mine` plus known_own_networks) and block_remove (own_for_table) fill them. Blocks wider than one address on an ASN Matt signs in from are refused. The confirmation text gives a way back in. |
| H2 replies dropped / server addresses | Fixed | Priority -150 (after conntrack at -200, before DNAT at -100). `ct direction reply accept` and `ct state related accept` come first. A reply-direction packet needs a conntrack entry whose original direction the server started, so a blocked source can't produce one; an attacker's SYN creates an unconfirmed entry that is dropped, never confirmed. server_networks() refuses SERVER_IP, every global interface address, both default gateways and the nameservers in both resolv.conf files. On this server most of those are private or loopback and already refused by is_global, so the check is right in general and never weaker. |
| H3 trace to arbitrary addresses | Fixed | Refused unless blocked_match(ip) or address_events(ip, 30). The check runs before the lock and the first probe. The raw-socket modes now also have `--bounding-set=-all,+net_raw`, and the UDP mode drops all capabilities. TRACE_DEADLINE_S=120 overall, with each run capped at min(80, left). |
| H4 boot ordering | Fixed | `After=nftables.service`, `PartOf=` and `ReloadPropagatedFrom=nftables.service`, and an `ExecReload`. A flush by nftables.service is followed by a reload of the list. |
| H5 overlapping blocks | Fixed | A network already covered is refused. A wider block replaces the narrower ones it covers (in the same lock), so the sets never hold overlapping intervals and the counters still map one-to-one. |
| H5 PTR not confirmed | Fixed | name_confirmed checks the forward A/AAAA records against the address. The renderer labels a PTR as "(what it calls itself; not confirmed)" unless it is confirmed. Cache entries from before this change have no `ptr_confirmed` and so show as not confirmed, which is the safe direction. |
| H5 `_fetch_json` overall deadline | Unfinished (Informational) | Still timeout=15 per read with no overall deadline. |
| H5 `::ffff:` form, ip-info own check, dedicated trace user | Unchanged (Informational, accepted) | Undercount only; the page has already filtered the rows; traceroute still runs as nobody. |

### R-H1a. The same-provider check passes when the ASN database is missing
- Severity: Low
- Category: CWE-636 Not Failing Securely
- Location: argus-helper 4240-4243
- Description: `locate()` leaves out `asn` when dbip-asn-lite.mmdb is missing or unreadable (geo_reader returns None),
  or when the address isn't in it. `asn` is then None, and the H1 step-2 check is skipped without a word. A wide block
  on Matt's own ISP goes through: exactly the case H1 was about.
- Remediation (replace 4240-4243):
  ```python
  if net.num_addresses > 1:
      if geo_reader("asn") is None:
          raise Refused("the provider database isn't available, so a network can't be checked against yours; block single addresses for now")
      asn = locate(str(net.network_address)).get("asn")
      if asn is None:
          raise Refused("the provider of that network isn't known; block single addresses there instead")
      if any(locate(str(n.network_address)).get("asn") == asn for n in mine):
          raise Refused("that network belongs to the same provider you sign in from; block single addresses there instead")
  ```
  Add a test: with `geo_reader` patched to return None, a /24 is refused and a /32 is accepted.
- Verification: rename the ASN mmdb, then try to block a /24: it is refused. Restore the file: a /24 on an unrelated
  ASN is accepted.

### R-H1b. The way back in that the confirmation gives is incomplete
- Severity: Low
- Category: CWE-1059 Insufficient Technical Documentation (recovery)
- Location: app.js 1301; geo-setup.sh argus-blocklist.service
- Description: `nft destroy table inet argus` only lasts until the next reboot or nftables reload, because
  argus-blocklist.service loads the file again. The next block-add or block-remove also rewrites the same entries.
  The Oracle Cloud serial console also needs an account that can sign in with a password, and an SSH-key-only setup
  usually has none. Matt could find himself at the console with no way to sign in.
- Remediation: change the wide-block text in app.js 1301 to: "...the way back in is the Oracle Cloud console:
  `sudo nft destroy table inet argus && sudo systemctl disable argus-blocklist.service`, then unblock the network in
  Argus and run `sudo systemctl enable argus-blocklist.service` again." Write the same steps in the docs, and note
  that the Cloud Shell / serial console sign-in has to be tested once beforehand (a local password-capable user, or
  OCI Run Command through the Oracle Cloud Agent).
- Verification: read the confirmation text. On the server, follow the steps and then reboot: the table is not loaded
  until the service is enabled again.

### R-H1c. A mail login from a stolen mailbox password makes that address impossible to block
- Severity: Low
- Category: CWE-284 Improper Access Control (trust from weak evidence)
- Location: argus-helper 3380-3390 (successful Dovecot/Postfix SASL logins count as "own"), 4234-4243 (refusal and
  same-ASN refusal), 4081-4099 (own sets accepted ahead of drops)
- Description: one successful mailbox login, by any mailbox on the server, puts that address into OWN_SEEN for 180
  days. Before this feature that only hid the address from the page. Now it also (a) makes block-add refuse the
  address, (b) refuses every wider block on that address's ASN, and (c) puts it in own4/own6, which is accepted ahead
  of every drop. A hijacked computer that has guessed a weak mailbox password, which is the case Matt asked about, can
  then never be blocked, and the refusal ("a network you sign in from") points him away from the real problem.
- Remediation:
  1. Keep where each own address came from: OWN_SEEN values `{"t": ts, "via": "ssh"|"mail"|"caller"|"manual"}`
     (read the old int form as `via: "mail"`, the weaker one).
  2. Build the firewall accept set (own_for_table and the block_add argument) only from `via in {"ssh","caller"}`
     plus OWN_MANUAL. SSH key sign-ins and the current session are the lockout risk; the mail addresses are not.
  3. In block_add, keep the hard refusal for ssh/caller/manual overlaps. For a mail-only overlap, refuse with a
     message that names it: "that address signed in to a mailbox on <date>. If that wasn't you, change that mailbox's
     password first; then block with the extra confirmation". Add a second argument `confirm-mail` that the renderer
     sends only after a typed confirmation.
  4. Apply the same split to the same-ASN check (use only ssh/caller/manual networks).
- Verification: put a test address into OWN_SEEN as `via: "mail"` only. Block-add without the confirmation is refused
  with the mailbox message; with it, the block is added, and the address isn't in own4 in blocklist.nft. An address
  with `via: "ssh"` is still refused outright.

### R-H6. Informational
- PTR value starting with "-": the PTR charset `[A-Za-z0-9._-]` allows a leading hyphen, and name_confirmed passes
  the name as the last argv item to `host`, which would read it as an option. It is a single argument, so the worst
  that happens is a usage error and "not confirmed". Even so, require each label to start with a letter or digit:
  `re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)*[A-Za-z0-9][A-Za-z0-9-]{0,62}", name)` in reverse_name,
  and return None otherwise.
- Trace is allowed for any address inside a blocked network, which can be up to a /16 that has never tried the
  server. Only Matt can add such a block, so this is acceptable. Restrict it to `address_events` alone if the
  scan-look matters.
- trace runs address_events (up to two 60-second log reads as root) before it takes the lock, so repeated clicks
  can stack those reads. To fix, take the lock first, then check.
- Wording at app.js 1301: "only connections it starts are dropped" reads as if the server's connections were dropped.
  Suggest "only connections that network starts are dropped". Also say that inbound mail from that network is
  refused: blocking a large cloud /16 can stop real mail from senders hosted there.
- `_fetch_json` overall deadline (H5) is still unfinished; see H5 for the fix.

Result: CLEAR (no Critical, High or Medium; Low: R-H1a, R-H1b, R-H1c)

## Re-audit 2 (attackers: fix cycle 2) - Sentinel, 2026-11-01

Read the changed lines only: argus-helper trace 3661-3706, address_events 3923-3951 (timeout argument),
reverse_name 3903-3906, apply_blocklist set text 4085-4103, block_add 4242-4249; app.js blockIt 1297-1303; and the new
tests (test_attacks.py 284-311). The tests pass (24 passed). The `nft -c` test ran here: root, with nftables 1.0.9,
and it was not skipped. Separately, I checked by hand that `set s { type ipv4_addr; flags interval; counter; }` and a
set with `elements = { ... };` both parse. The test removes the `destroy table` line before checking. That command
needs nftables 1.0.8 or later; the server has 1.1.3, and it also parses here on 1.0.9.

| Item | Status | Evidence |
|---|---|---|
| R-H1a ASN check fails open | Fixed | 4243-4247: a wide block is refused when geo_reader("asn") is None or the network's ASN is unknown. A single address is still allowed. There is a test. |
| R-H1b recovery text | Fixed | app.js 1301 gives the whole sequence: destroy the table, disable the service, unblock in Argus, enable the service again. It also says "only connections that network starts are dropped" and that mail sent from it is refused. The docs note about testing the console sign-in beforehand (a password-capable user or OCI Run Command) isn't covered by the cycle-2 changes listed; that part is still unfinished in the docs. |
| R-H1c mail login counts as "own" | Open (Low), not fixed | Unchanged by design in this cycle. It will be reported to Matt as unresolved. The remediation in R-H1c stands. |
| PTR leading hyphen | Fixed | 3905: the first character must be a letter or digit, so the name can't be read as an option to `host`. A hyphen at the start of a later label is harmless, because only the first character of the argv item matters. |
| Trace eligibility cost | Fixed (accepted residual) | The deadline is set first, and both log reads in address_events take timeout=20, so the check takes at most about 40 s inside the 120 s budget. The lock is still taken after the check, so repeated clicks can each run up to about 40 s of root log reads. That is bounded; Informational. |
| Empty nft sets (Marcus) | Fixed | Every set line ends in `; }`. Empty and filled sets parse (test plus my own check above). The table and set names, and the `str(ip_network)`-only elements, are unchanged. |

### R-H7. Informational
- In the same-provider check (4248), an own network whose ASN is unknown is not compared, so its provider isn't
  protected. Matt's home ISP will normally be in DB-IP, so this is noted only. If wanted: refuse a wide block when
  any own network of the same IP version has no ASN.
- The server facts given for this cycle say Debian 13 (kernel 6.12). Earlier cycles said Ubuntu. The H4 reasoning
  (a `flush ruleset` from nftables.service, then a reload propagated to argus-blocklist.service) holds on both.
- Still open from H5: `_fetch_json` has no overall deadline. The `::ffff:` undercount and the trace running as
  nobody are accepted.

Result: CLEAR (no Critical, High or Medium; Low still open: R-H1c)

## Re-audit 3 (R-H1c fix: admin and other own addresses) - Sentinel, 2026-11-01

Read the changed lines only: argus-helper SSH_OWN_RE 3312, ADMIN_USERS / _read_seen / _manual_nets / _split /
own_split / own_networks 3357-3476, known_own_networks 3535-3540, refused_rows 3543-3623, attacks 3626-3632, signins
270-278, ip_info 4025-4027, own_for_table 4214-4221, block_add 4259-4317; app.js row pill 1219 and blockIt 1298-1323;
and accounts-setup.sh 70-90 for the sshd settings the classification depends on. The tests pass (27 passed). This was a
code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| R-H1c mail login counts as "own" | Fixed for mail and upload sign-ins (new Medium R-H1d below on SSH Partial lines) | Only the admin set reaches the accept sets: block_add passes `mine` (admin plus known admin) to save_and_apply (4283-4284, 4316), and block_remove uses own_for_table, which is admin only (4214-4221). The same-provider check uses admin only (4300). A mail-only or upload-only overlap is refused unless the third argument is exactly `confirm-signed-in` (4264, 4288-4291); any other third word is UnexpectedArgs (test). Admin overlaps are refused before the confirmation is looked at, so the confirmation can't unlock them (4285-4287). |
| Crafted log lines / user names | Sound | Lines come from `journalctl -u ssh`, which only matches trusted fields (_SYSTEMD_UNIT, or PID 1 / UID 0 fields), so another local user can't add entries. SSH_OWN_RE is anchored at both ends; sshd escapes control characters in what it logs, so a user name can't start a new line; an Accepted line only names a real account that signed in. ADMIN_USERS is an exact tuple match. |
| Admin is sticky in note() and in the merge | Sound for one call; see R-H1e for time | `found.get(ip) != "admin"` stops an "other" sighting from lowering an admin one; 3455 keeps an old admin. |
| Old {ip: time} entries read as "other" | Accepted direction; see R-H1f | That only makes them blockable after confirmation. They are not let through ahead of blocks. |
| Confirmation step | Sound (not a security boundary, and doesn't need to be) | It is a renderer prompt before Matt's own call. Anyone who can call the helper can already add and remove blocks, so sending `confirm-signed-in` directly gains nothing: it can't block an admin address, the server, or a network on Matt's provider. The renderer resends only when the refusal text matches SIGNED_IN_REFUSAL, and only after the typed BLOCK. |
| "Has Signed In" listing | Sound | refused_rows leaves out admin by containment and lists other-only addresses that have SSH or mail tries, marked `signed_in`; app.js 1219 shows the pill through el() (textContent). |

### R-H1d. A stolen SSH key alone, without the authenticator code, makes the attacker's address "admin"
- Severity: Medium
- Category: CWE-287 Improper Authentication (trust from a partial authentication) / CWE-284
- Location: argus-helper 3312 (SSH_OWN_RE accepts `Partial`), 3427 (journalctl grep `^(Accepted|Partial) `), 3437
  (admin when the user is mattridge or root); accounts-setup.sh 82 and the mattridge setup (`AuthenticationMethods
  publickey,keyboard-interactive`); test_attacks.py 141-163 asserts that `Partial publickey for root` gives admin.
- Description: sshd writes `Partial publickey for mattridge from IP ...` when the key is accepted and the second
  factor (the authenticator code) has not been given yet. Someone who has stolen Matt's private key but not his phone
  gets that line on the first try. Their address then becomes admin for 180 days. It is (a) never blockable,
  (b) accepted ahead of every drop in own4/own6, and (c) left out of the Sign-In Attempts page entirely, along with
  their failed codes (`Failed keyboard-interactive/pam for mattridge`). They can try codes for months, held back
  only by the PAM rate limit, and Matt never sees it and can't block it. The second factor exists to cover exactly
  this case, a stolen key. A real sign-in by Matt always ends in an `Accepted keyboard-interactive/pam for
  mattridge` line, so counting Partial adds nothing for him. The same applies to root if root is ever given a
  two-step AuthenticationMethods.
- Remediation:
  1. Count only completed sign-ins (argus-helper 3312 and 3427):
     ```python
     SSH_OWN_RE = re.compile(r"^Accepted \S+ for (\S+) from " + IPT + r" port \d+" + SSH_KEY_SUFFIX + r"$")
     SSH_PARTIAL_RE = re.compile(r"^Partial \S+ for (\S+) from " + IPT + r" port \d+" + SSH_KEY_SUFFIX + r"$")
     ...
     p = subprocess.run(["journalctl", "-u", "ssh", "--no-pager", "-o", "cat", "--grep", "^Accepted "], ...)
     ```
     Partial lines then make an address neither admin nor other. An upload account's Partial line (key without
     code) also no longer marks the address "Has Signed In".
  2. Show it instead of hiding it (refused_rows, around 3578): a Partial line for an ADMIN_USERS name from an address
     with no Accepted line means Matt's key is in someone else's hands.
     ```python
     pm = SSH_PARTIAL_RE.match(msg)
     if pm:
         if pm.group(1) in ADMIN_USERS:
             hit(pm.group(2), ts, "keyok")
         continue
     ```
     In hit(): `elif kind == "keyok": e["keyok"] = True` (add `"keyok": False` to the setdefault). In the row:
     `"key_ok": e["keyok"]`, and do not drop such a row in the probes-only skip. In app.js next to 1219:
     `if (r.key_ok) vis.append(el('span', 'Used Your SSH Key', 'pill bad'));`. If Matt's own address ever produces
     Partial-then-Accepted, it is admin and is left out before this point, so he isn't shown his own sign-ins.
  3. Tests: in test_own_sign_in_lines, assert the Partial line does NOT match SSH_OWN_RE. In
     test_own_split_trusts_only_admin_ssh_sign_ins, the expected sets become admin {45.33.5.1, 45.33.6.2} and other
     {45.33.5.2, 45.33.5.3, 45.33.5.4, 45.33.6.1}. Add a test: `Partial publickey for mattridge from 45.33.5.9`
     plus `Failed keyboard-interactive/pam for mattridge from 45.33.5.9 port 22 ssh2` gives an address in neither
     set, listed by refused_rows with `key_ok` true, and blockable without a confirmation.
- Verification: run the tests. On the server, sign in as mattridge from a second network and abort at the code
  prompt. That address is not in own-seen.json as admin, not in own4 in the BLOCK_NFT file (`nft list set inet argus own4`), appears on
  the page marked "Used Your SSH Key", and block-add on it succeeds without `confirm-signed-in`.

### R-H1e. An address that was once admin stays admin as long as anything signs in from it
- Severity: Low
- Category: CWE-284 Improper Access Control (stale trust)
- Location: argus-helper 3453-3456 (each sighting sets `t` to now and keeps `via: "admin"` if it was admin before)
- Description: the 180-day clock runs from the last sighting of any kind. If Matt's home or hotel address is handed to
  someone else, one mailbox login from it, which is the stolen-password case R-H1c was about, keeps it admin
  (unblockable and accepted ahead of drops) for as long as those logins keep coming. It is bounded only by the full
  journal still holding the old Accepted line, or by the mail logins stopping.
- Remediation: keep the admin time separately and expire admin by it.
  ```python
  # own_split, replacing 3453-3456
  for ip, via in found.items():
      old = seen.get(ip) or {}
      ta = now if via == "admin" else old.get("ta")
      seen[ip] = {"t": now, "via": "admin" if ta else "other", **({"ta": ta} if ta else {})}
  for v in seen.values():
      if v.get("ta") and now - v["ta"] >= OWN_KEEP_S:
          v["via"] = "other"
          v.pop("ta")
  seen = {k: v for k, v in seen.items() if now - v["t"] < OWN_KEEP_S}
  ```
  In _read_seen, for a dict entry with via "admin" carry `"ta": int(v.get("ta", v["t"]))` when it is a number; an
  admin entry with no usable ta uses t. Note: `found` admin comes from the whole journal (no --since), so while the
  old Accepted line is still in the journal, ta is refreshed. That is the intended behaviour.
- Verification: test with own-seen.json `{"45.33.7.1": {"t": now, "via": "admin", "ta": now - 181*86400}}`, no SSH
  line and one Dovecot login from 45.33.7.1: the address is in `other`, not `admin`.

### R-H1f. Informational
- Old-format entries become "other", and the refusal then says "(a mailbox or upload account)" although the address
  may have been Matt's SSH one. Each call reads the whole journal again, so anything still in it is admin again at
  once; only addresses older than the journal stay downgraded. Suggest: record legacy entries as `via: "other",
  "legacy": true` and say "signed in successfully here before Argus kept track of how" in the refusal for them.
- IPv6 admin is the whole /64 (own_net), so another device on the same /64 (a hotel or shared network) is unblockable
  too. Unchanged from before; noted only.
- caller_address() trusts SSH_CONNECTION from the parent processes' environment and saves it as admin for 180 days. Only
  someone who can already run the helper as root can set it, so it is not an escalation. Running the helper by hand
  from a long-lived tmux shell can save a stale address as admin.
- _split compares "other" against admin by equality, not containment, so an address inside a wider manual network
  still shows in `other`. Every user of the sets checks admin by containment first (refused_rows, block_add), so
  there is no effect.

Result: ISSUES FOUND (Medium: R-H1d; Low: R-H1e)

## Re-audit 4 (R-H1d / R-H1e fixes, cycle 1) - Sentinel, 2026-11-01

Read the changed lines only: argus-helper SSH_OWN_RE / SSH_PARTIAL_RE 3320-3321, _finite / _read_seen 3368-3393,
own_split 3424-3497, refused_rows 3562-3650, trace 3730-3741, block_add 4291-4346; app.js 1220; and the new tests
(test_attacks.py 91-95 and 175-210). The tests pass (32 passed). This was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| R-H1d key accepted, code not | Fixed | 3320 and the journal search at 3441 take `^Accepted` only, so a Partial line never makes an address own of either kind. In refused_rows (3603-3607), a Partial line for an ADMIN_USERS name gives `keyok`, and the probes-only skip keeps such rows (3640). A Partial-only address with no other tries is still listed, because the skip applies only to signed-in addresses. The pill goes through el() (textContent). An attacker can still only become admin through an Accepted line for mattridge or root (which needs the code) or as the caller session, which needs access that is already root-equivalent. |
| R-H1e admin expiry | Fixed in OWN_SEEN; residual R-H1g | Only an admin sighting sets `ta` to now (3473). A mail or upload sighting keeps the old `ta` (3475), and admin drops to "other" when `now - ta >= 180 days` (3478-3480). Every admin entry carries `ta`, so `old["ta"]` and `v["ta"]` can't raise KeyError. Admin entries from before this change take `ta = t`, so they fall to "other" at most 180 days after deploy, even if mail sign-ins continue. |
| `_read_seen` hardening | Fixed | NaN, Infinity and bools are rejected by `_finite` for both `t` and `ta`. Unknown `via` values, strings and private addresses are dropped (test). |
| Wide block on an "other" network's provider | Sound | An admin provider is still a hard refusal (4335). An "other" provider is a confirmable SIGNED_IN_REFUSAL (4336-4338). The renderer matches that text and resends with `confirm-signed-in` only after the typed BLOCK. Confirming can't override admin, server or admin-provider refusals, because those are checked first or regardless of `confirmed`. |
| trace refuses admin | Sound | 3737-3738 (admin only). Tracing an "other" address is allowed, which fits: it may be an attacker. |
| Old wider accept set | Unfinished until deploy | The live own4/own6 sets still hold the mail-derived addresses until the table is next written. The planned one-off re-apply on deploy (any block-add/block-remove, or a helper run that calls save_and_apply with own_for_table()) is required. Check it with `nft list set inet argus own4`. |
| R-H1f legacy wording | Unfinished (Informational) | Not done, as stated. |

### R-H1g. Admin expiry counts from when the journal was read, not from when Matt signed in
- Severity: Low
- Category: CWE-613 Insufficient Session Expiration (stale trust)
- Location: argus-helper 3441 (`journalctl -u ssh --no-pager -o cat --grep "^Accepted "`, with no `--since` and no
  timestamps) and 3471-3473 (`ta` is set to `now` for every admin address found)
- Description: the search reads the whole journal. An `Accepted publickey for mattridge` line from, say, 14 months
  ago is still "found" on every call while the journal keeps it. Each time that sets `ta = now`, so that address
  never expires. A persistent journal is limited only by size (by default 10% of the filesystem, capped at 4 GB), and
  on a quiet server that can be years. So the claim "180 days after the last admin sign-in" holds only once the line
  has rotated out. Until then, a reassigned old address of Matt's stays unblockable and is let through ahead of the
  blocks: the R-H1e case. The expiry test passes because its fake journal has no old line.
- Remediation: take the time from the line itself, and only for the last 180 days. Replace 3440-3454:
  ```python
  p = subprocess.run(["journalctl", "-u", "ssh", "--since", "-%dd" % (OWN_KEEP_S // 86400), "--no-pager",
                      "-o", "short-unix", "--grep", "^Accepted "],
                     capture_output=True, text=True, errors="replace", timeout=60)
  ...
  when = {}
  for line in acc.splitlines():
      lm = re.match(r"^(\d+)\.\d+ \S+ \S+: (.*)$", line)
      if not lm:
          continue
      m = SSH_OWN_RE.match(lm.group(2))
      if m:
          via = "admin" if m.group(1) in ADMIN_USERS else "other"
          note(m.group(2), via)
          ip = plain_ip(m.group(2))
          if ip and via == "admin":
              when[ip] = max(when.get(ip, 0), min(int(lm.group(1)), now))
  ```
  and at 3473: `seen[ip] = {"t": now, "via": "admin", "ta": max(when.get(ip, now), old.get("ta", 0))}`. The caller
  session has no entry in `when`, so it keeps `ta = now`, which is right. `--grep` matches MESSAGE, so it still works
  with `-o short-unix`.
- Tests: a fake journal line `"<now-200d>.000001 host sshd-session[1]: Accepted publickey for mattridge from
  45.33.7.8 port 22 ssh2"` must give 45.33.7.8 `ta` equal to that time, so it is not admin when combined with an
  OWN_SEEN entry. The fake subprocess.run should also assert that `--since` is in the arguments. A line from 10 days
  ago gives admin with `ta` equal to that line's time.
- Verification: on the server, `journalctl -u ssh --grep '^Accepted ' -o short-unix | head -1` shows the oldest
  line. After a refresh, own-seen.json gives that address `ta` equal to the line's time (not today), or no entry at
  all if it is older than 180 days.

### R-H1h. Informational
- The dashboard tile (`signins`) adds up `tries` only, so an address with a key-accepted line and no other tries
  adds 0 there. The page shows it. Consider putting a count of `key_ok` rows on the tile, since it is the one event
  that means Matt's key is out.
- If Matt himself signs in from a new network and stops at the code prompt, that address gets the red pill until an
  Accepted line from it is seen. This is expected; the wording could say "your key, without the code".

Result: CLEAR (no Critical, High or Medium; Low open: R-H1g; unfinished: the deploy re-apply and the R-H1f wording)

## Re-audit 5 (R-H1g fix, cycle 2) - Sentinel, 2026-11-01

Read the changed lines only: argus-helper _split, the own_split journal read and admin-time merge, and the refused_rows
sort (3663); plus the new test. The tests pass (34 passed). This was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| R-H1g admin time from the journal read | Fixed | The search is now `--since -180d -o short-unix --grep "^Accepted "`, and `--grep` still matches MESSAGE. Each line's own time is parsed, and `min(line_ts, now)` stops a future-dated clock from stretching trust. A line that doesn't parse is skipped (`m` is None). `ta = max(line time, old ta)`. Only the caller session, which has no line, falls back to now. A 200-day-old line is no longer read, so it can't renew anything (test). |
| Expiry applied everywhere | Fixed | _split counts an entry as admin only while `now - ta < 180 days`, so known_own_networks (dashboard, ip_info, trace, and own_for_table's fallback) expires admin too, without a log read. An expired admin entry now falls into `other`, because the `via == "other"` condition was removed from the second loop. That is the intended direction: blockable after confirmation, and not in the accept sets. |
| Accept sets | Sound | Unchanged: own4/own6 still come only from the admin set. |
| List order | Sound | key_ok rows, then signed-in rows, then tries. A "Used Your SSH Key" row can't fall outside the 400 shown. |
| Deploy re-apply | Unfinished until deploy | The planned one-off re-apply, and the check that own4/own6 hold only admin networks, is still needed. Until then the live sets carry the old wider list. |
| R-H1f legacy wording | Unfinished (Informational) | Not done, as stated in cycle 1. |

### R-H1i. Informational
- With signed-in rows sorted ahead, the "Busiest N of M shown" label (app.js) is no longer strictly true once there
  are more than 400 rows. Suggest "Top N of M shown (keys used and signed-in addresses first)".
- The dashboard tile still adds up tries only, so a key-only row adds 0 there (R-H1h, unchanged).

Result: CLEAR (no Critical, High or Medium; R-H1c, R-H1d, R-H1e and R-H1g are resolved in code; unfinished: the deploy re-apply and the R-H1f wording)

## Sorting across all addresses and blocking by hand (attacks sort, blockByHand) - Sentinel, 2026-11-01

Scope: argus-helper `_ip_sort_key`, `ATTACK_SORTS`, `attacks()`; app.js `blockByHand` and `blockIt`'s new `from`
parameter. Also read the call path these rely on: main.js `argus:helper` (strings only, at most 4 args),
native/src/lib.rs (each arg limited to `[A-Za-z0-9._-]`), `unhex`, `ip_info`, `block_add`. Tests: 35 passed. This
was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| attacks args | Sound | Exactly 0, 1 or 3 args; days in {1,7,30}; column must be a key of `ATTACK_SORTS`, direction in {asc, desc}. Unknown values raise UnexpectedArgs before any log is read. No arg reaches a command line. |
| Sort keys | Sound | Each key returns one type per column (str, int or tuple), so the sort can't raise on mixed types. `blocked` is still marked on the 400 sent, after sorting. Cost is one extra sort of rows already built. |
| blockByHand input | Sound | Shape check in the renderer, hex-encoded, then `ip_info` (plain_ip: public only, own addresses refused) and `block_add` (all server checks unchanged and still authoritative). Dialog text is set with textContent. The note is filtered in the renderer and again by NOTE_RE. |
| Typed confirmation | Sound | Unchanged: BLOCK must be typed for any network, and again for an address where a mailbox signed in. |

### S-M1. Medium - Detection visibility - argus-helper attacks() (sort branch); app.js loadSignins
Description and impact: Re-audit 5 recorded that a "Used Your SSH Key" row (`key_ok`, Matt's key accepted from an
address that never finished signing in) can't fall outside the 400 shown. With a sort column, `rows` is ordered only
by that column, so on a 7 or 30 day view with more than 400 addresses a `key_ok` row (and signed-in rows) can be cut
from the response. Nothing else shows it: the dashboard tile counts tries only (R-H1h). The one sign that Matt's key
is out can vanish from the page just because he sorted by IP, place or last seen.
Remediation (server; keep the guarantee whatever the sort):
```python
    if sort:
        key = ATTACK_SORTS[sort[0]]
        filled = [r for r in rows if key(r) != ""]
        filled.sort(key=key, reverse=sort[1] == "desc")
        rows = filled + [r for r in rows if key(r) == ""]
        # Rows that must always be seen go into the 400 sent, whatever the sort.
        must = [r for r in rows if r["key_ok"]]
        rest = [r for r in rows if not r["key_ok"]]
        rows = must + rest
    total["key_ok"] = sum(1 for r in rows if r["key_ok"])
```
(The renderer sorts the rows it gets again, so pinned rows still show in sorted position; they are just never left
out.) In app.js, when `d.total.key_ok` is non-zero, say so in `si-summary`, e.g. "N addresses used your SSH key",
so the count is visible even before scrolling. Doing the same for `signed_in` rows is optional; `key_ok` is required.
Verification: add a test with 450 rows where one `key_ok` row sorts last by `ip asc` and by `last desc`; assert it is
in `rows` (length 400) for every column and direction, and that `total.key_ok == 1`. Check that the 35 tests still
pass.

### S-L1. Low - Input validation / false sense of protection - block_add (reached by blockByHand)
Description and impact: the by-hand path is the first one that lets Matt type any address. `::ffff:203.0.113.7`
passes the renderer's shape check. `ip_info` normalises it to 203.0.113.7 and shows that address's owner and place,
and `block_add` accepts `::ffff:203.0.113.7/128` (Python 3.13 says it is global). The block goes in the IPv6 set,
but IPv4 traffic from 203.0.113.7 arrives as IPv4 and is never matched, so the list says it is blocked when nothing
is. The server, gateway and own-network checks compare `version == 6` entries only, so they are skipped for it too.
That is harmless only because the entry matches nothing.
Remediation (server, in block_add after `ip_network`):
```python
    MAPPED = _ipaddress.ip_network("::ffff:0:0/96")
    if net.version == 6 and net.overlaps(MAPPED):
        raise Refused("type the IPv4 address itself (for example 203.0.113.7), not its ::ffff: form")
```
Optional, in blockByHand: refuse `/^::ffff:/i` before calling ip-info, with the same message.
Verification: test that block-add refuses `::ffff:8.8.8.8/128` and `::ffff:8.8.0.0/112`, and that `8.8.8.8/32` is
still accepted. By hand in Argus: typing `::ffff:8.8.8.8` gives the refusal and adds nothing.

### S-I1. Informational - Accuracy of the confirmation - app.js blockByHand / blockIt
- For a typed network, the owner and place shown come from `ip-info` on the typed address. A /16 typed by hand can
  span several registry allocations, so the dialog may name only one owner. Suggest calling ip-info on the network
  address and, when `who.registry.networks` holds no network that contains the requested one, adding "this range
  is wider than one owner's network" to the dialog.
- `1.2.3.4/24` is confirmed and reported as typed, while the server stores `1.2.3.0/24` (non-strict). It is the same
  set of addresses, but the success message should use `res.blocked` rather than the typed string.

### S-I2. Informational - Attacker-influenced ordering - ATTACK_SORTS users/place/network
Usernames (USER_RE-filtered) and volume are attacker-chosen, so under the `users` sort an attacker can pick names
that put them first or push other rows past the 400. This is the same kind of thing as the default "busiest" order,
and the label already says "First 400 of N by ...". No action beyond S-M1.

Result: ISSUES FOUND (Medium: S-M1; Low: S-L1; Informational: S-I1, S-I2)

## Re-audit (S-M1, S-L1, S-I1 fixes, cycle 1) - Sentinel, 2026-11-01

I read the changed lines: the attacks() sort branch and `total["key_ok"]`, block_add's mapped-address refusal,
blockByHand and the blockIt success message, and the app.js summary line. Tests: server 37 passed, screen 7 passed.
This was a code review; nothing was run on the server.

| Item | Status | Evidence |
|---|---|---|
| S-M1 key_ok rows always sent | Fixed | After the sort, every `key_ok` row is kept, the rest is cut to `400 - flagged`, and the kept rows go first in their sorted order. The `rows[:400]` cut afterwards therefore always holds them. If there were more than 400 `key_ok` rows, the cut would drop some, but `total.key_ok` would still count them all. The default order already put them first, so it is unchanged. |
| S-M1 count shown | Fixed | `total["key_ok"]` counts every row, not only the 400 sent. The summary names the count and points to the pill. |
| S-L1 mapped IPv6 | Fixed | block_add refuses any v6 network overlapping `::ffff:0:0/96`. The check comes after parsing and before the is_global and own-network checks, so nothing slips past it. Tested with `::ffff:46.3.3.3`. |
| S-I1 stored network shown | Fixed | The success message uses `res.blocked`. The IPv4 network address is worked out in the renderer for the confirm. Badly formed octets such as `1.2.3.300/24` can't reach that maths: ip-info refuses them first ("not a public address") and blockByHand stops there. Other ip-info failures (registry down) carry on, and block_add parses the value itself. |
| S-I1 owner for a wide range | Open (Informational) | The confirm still names the owner of the typed address only. This was a suggestion, not required. |
| ip-info refusal stops early | Sound | A private address, or one of Matt's own, stops before any confirm (screen test). |

Result: CLEAR (S-M1 and S-L1 fixed. Still open: S-I1, the owner wording for a range wider than one owner's network (Informational), and S-I2 (Informational, no action). Unfinished from earlier: the deploy re-apply and the R-H1f wording.)
