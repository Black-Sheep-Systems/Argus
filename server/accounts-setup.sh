#!/bin/bash
# One-time server setup for Argus upload accounts (phase 4c). Run as root by
# the server chat, never by Argus. Safe to run again: every step checks first.
# Root's own sign-in is key-only and never uses the authenticator, so a root
# session stays usable to undo the sign-in change if Matt's re-test fails.
set -euo pipefail
STAMP=$(date +%Y%m%d-%H%M%S)
GA=/var/lib/google-authenticator
PAM=/etc/pam.d/sshd
KEEP=/var/backups/argus-setup
NEWPAM='auth required pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root'
install -d -o root -g root -m 0700 "$KEEP"

# quotaon -p exits non-zero when quotas ARE on, so only its words are read.
quota_on() { case "$(quotaon -p -u / 2>/dev/null || true)" in *" is on"*) return 0;; *) return 1;; esac; }

echo "1/7 quota tools"
dpkg -s quota >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -q quota >/dev/null

echo "2/7 disk size limits on /"
if ! quota_on; then
  EDITED=0
  if ! awk '$2=="/" && $1 !~ /^#/ && $4 ~ /(^|,)usrquota(,|$)/' /etc/fstab | grep -q .; then
    cp -a /etc/fstab "$KEEP/fstab.pre-quota-$STAMP"
    awk '$2=="/" && $1 !~ /^#/ {$4=$4",usrquota"} {print}' /etc/fstab > /etc/fstab.new
    grep -q usrquota /etc/fstab.new
    [ "$(wc -l < /etc/fstab.new)" = "$(wc -l < /etc/fstab)" ]
    findmnt --verify --tab-file /etc/fstab.new >/dev/null 2>&1 || { echo "fstab check failed; nothing changed"; rm -f /etc/fstab.new; exit 1; }
    chmod 0644 /etc/fstab.new; mv /etc/fstab.new /etc/fstab
    systemctl daemon-reload
    EDITED=1
  fi
  if ! mount -o remount /; then
    [ "$EDITED" = 1 ] && { cp -a "$KEEP/fstab.pre-quota-$STAMP" /etc/fstab; systemctl daemon-reload; echo "remount failed; fstab put back"; }
    exit 1
  fi
  findmnt -no OPTIONS / | grep -q usrquota
  [ -f /aquota.user ] || quotacheck -cum /
  quotaon -u /
fi
quota_on

echo "3/7 groups and folders"
getent group argus-upload >/dev/null || groupadd --system argus-upload
getent group argus-disabled >/dev/null || groupadd --system argus-disabled
install -d -o root -g root -m 0755 /srv/sftp /etc/ssh/argus-keys
install -d -o root -g root -m 0700 "$GA" /var/lib/argus

echo "4/7 Matt's authenticator secret into the root-only folder (his original is kept until his sign-in is re-tested)"
[ -f "$GA/mattridge" ] || install -o root -g root -m 0400 /home/mattridge/.google_authenticator "$GA/mattridge"

echo "5/7 shared folders reconnected at every start"
cat > /etc/systemd/system/argus-upload-mounts.service <<'UNIT'
[Unit]
Description=Argus: connect folders shared with upload accounts
After=local-fs.target
Before=ssh.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/argus-helper --session boot-mounts acct-mount-all

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable argus-upload-mounts.service >/dev/null 2>&1

echo "6/7 SSH settings for upload accounts"
cat > /etc/ssh/sshd_config.d/05-argus-deny.conf <<'CONF'
# Argus: accounts disabled in Argus are refused at sign-in.
DenyGroups argus-disabled
CONF
cat > /etc/ssh/sshd_config.d/60-argus-upload.conf <<'CONF'
# Argus upload accounts: SFTP only (no links), locked in their own folder,
# key AND authenticator code, every file action logged.
Match Group argus-upload
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp -d /files -u 0027 -P symlink,hardlink -l INFO -f AUTHPRIV
    AuthorizedKeysFile /etc/ssh/argus-keys/%u
    AuthenticationMethods publickey,keyboard-interactive
    KbdInteractiveAuthentication yes
    PasswordAuthentication no
    DisableForwarding yes
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitListen none
    PermitOpen none
    PermitTunnel no
    PermitUserRC no
    X11Forwarding no
    PermitTTY no
CONF
chmod 0644 /etc/ssh/sshd_config.d/05-argus-deny.conf /etc/ssh/sshd_config.d/60-argus-upload.conf

echo "7/7 authenticator line in SSH's PAM settings"
if ! grep -qxF "$NEWPAM" "$PAM"; then
  cp -a "$PAM" "$KEEP/pam-sshd.pre-argus-$STAMP"
  n=$(grep -cE '^auth\s+required\s+pam_google_authenticator\.so\s*$' "$PAM" || true)
  [ "$n" = 1 ] || { echo "expected exactly one plain authenticator line in $PAM, found $n; SSH settings removed, nothing else changed"; rm -f /etc/ssh/sshd_config.d/05-argus-deny.conf /etc/ssh/sshd_config.d/60-argus-upload.conf; exit 1; }
  awk -v new="$NEWPAM" '/^auth[ \t]+required[ \t]+pam_google_authenticator\.so[ \t]*$/ {print new; next} {print}' "$PAM" > "$PAM.new"
  chmod --reference="$PAM" "$PAM.new"; mv "$PAM.new" "$PAM"
  echo "UNDO if Matt's sign-in fails: cp -a $KEEP/pam-sshd.pre-argus-$STAMP $PAM"
fi
grep -qxF "$NEWPAM" "$PAM"
if ! sshd -t; then
  [ -f "$KEEP/pam-sshd.pre-argus-$STAMP" ] && cp -a "$KEEP/pam-sshd.pre-argus-$STAMP" "$PAM"
  rm -f /etc/ssh/sshd_config.d/05-argus-deny.conf /etc/ssh/sshd_config.d/60-argus-upload.conf
  echo "sshd rejected the settings; steps 6 and 7 put back"; exit 1
fi
systemctl reload ssh
echo "done"
