#!/bin/bash
# One-time setup for Argus's sign-in attacks page. Run as root by the server chat.
# Installs the reader for DB-IP's free location databases and a monthly timer
# that refreshes them (argus-helper geo-update). Safe to run again.
set -euo pipefail
dpkg -s python3-maxminddb >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-maxminddb >/dev/null
command -v traceroute >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q traceroute >/dev/null
install -d -o root -g root -m 0755 /var/lib/argus/geo
cat > /etc/systemd/system/argus-geo-update.service <<'UNIT'
[Unit]
Description=Argus: refresh the DB-IP location databases
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=20min
ExecStart=/usr/local/sbin/argus-helper --session geo-timer geo-update
ProtectSystem=strict
ReadWritePaths=/var/lib/argus /var/log/argus
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
SystemCallArchitectures=native
UNIT
cat > /etc/systemd/system/argus-geo-update.timer <<'UNIT'
[Unit]
Description=Argus: refresh the DB-IP location databases monthly

[Timer]
OnCalendar=*-*-04 05:20
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now argus-geo-update.timer >/dev/null 2>&1
# Log the key step of a key-and-code sign-in ("Partial publickey ..."), so the
# Sign-In Attempts page can tell Matt's own addresses (right key) from attackers.
if [ ! -f /etc/ssh/sshd_config.d/04-argus-loglevel.conf ]; then
  printf '%s\n' '# Argus: log key steps, so a right key with a wrong code is recognised as Matt.' 'LogLevel VERBOSE' > /etc/ssh/sshd_config.d/04-argus-loglevel.conf
  chmod 0644 /etc/ssh/sshd_config.d/04-argus-loglevel.conf
  if sshd -t; then systemctl reload ssh; else rm -f /etc/ssh/sshd_config.d/04-argus-loglevel.conf; echo "sshd rejected LogLevel VERBOSE; left as it was"; fi
fi
# (read the whole output: grep -q would stop early and, with pipefail, look like a failure)
[ "$(sshd -T | awk 'tolower($1)=="loglevel"{print toupper($2)}')" = VERBOSE ] || echo "note: LogLevel VERBOSE is not in effect; check the other sshd_config.d files"
install -d -o root -g root -m 0755 /etc/argus
[ -f /etc/argus/own-addresses ] || printf '%s\n' '# Addresses or networks that are yours and must never appear on the Sign-In Attempts page.' '# One per line, for example 203.0.113.7 or 2001:db8:1:2::/64' > /etc/argus/own-addresses
# First download now, rather than waiting for the timer.
[ -s /var/lib/argus/geo/dbip-city-lite.mmdb ] || systemctl start argus-geo-update.service || echo "location download failed; the timer will try again"
echo done
