"""Tests for the Sign-In Attempts log parsing in argus-helper.

Run from the repository: python3 server/tests/test_attacks.py
No server needed: the helper's run() and own_split() are replaced with
fixtures, so this checks the parsing, counting and exclusion rules only."""
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import types
import unittest

sys.dont_write_bytecode = True          # don't leave a __pycache__ in server/

HERE = os.path.dirname(os.path.abspath(__file__))
loader = importlib.machinery.SourceFileLoader("helper", os.path.join(HERE, "..", "argus-helper"))
spec = importlib.util.spec_from_loader("helper", loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)
ORIGINAL_OWN_SPLIT = h.own_split

T = 1793500000
SSH = "\n".join(f"{T + i}.000001 host sshd-session[{100 + i}]: {m}" for i, m in enumerate([
    "Invalid user admin from 45.33.1.5 port 4000",
    "Received disconnect from 45.33.1.5 port 4000:11: Bye Bye [preauth]",
    "Disconnected from invalid user admin 45.33.1.5 port 4000 [preauth]",
    "Invalid user root from 45.33.1.5 port 4001",
    "Connection closed by invalid user a b 45.33.2.9 port 22 [preauth]",
    "Invalid user foo from 45.33.3.1 port 22 from 45.33.1.77 port 5000",
    "Disconnected from authenticating user mattridge 45.33.1.200 port 6000 [preauth]",
    "Connection closed by 45.33.1.6 port 7000 [preauth]",
    "Unable to negotiate with 45.33.1.7 port 7100: no matching key exchange method found.",
    "banner exchange: Connection from 45.33.1.8 port 7200: invalid format",
    "Invalid user x from 10.0.0.5 port 1",
    "error: maximum authentication attempts exceeded for invalid user test from 2001:db8::1 port 8 ssh2 [preauth]",
    "Invalid user y from 2a02:1:2:3::99 port 9",
    "Invalid user z from 2a03:4000:1::5 port 10",
    "Failed publickey for root from 45.33.1.90 port 11 ssh2: RSA SHA256:abcDEF123+/=",
]))
NF = "\n".join([
    "2026-11-01T17:56:40.404506239Z 2026-11-01 12:56:40 WARN: 9 more attempts in the next 600 seconds until 45.33.1.50/32 is banned",
    "2026-11-01T17:56:41.404506239Z 2026-11-01 12:56:41 CRIT: Banning 45.33.1.50/32 for 30 minutes",
    "2026-11-01T17:56:42.404506239Z 2026-11-01 12:56:42 WARN: user says Banning 45.33.3.66/32 for 30 minutes",
])


def fake_run(cmd, timeout=20, stderr_too=False):
    if cmd[0] == "journalctl":
        return SSH
    if cmd[:2] == ["docker", "logs"]:
        return NF
    return ""


def jlines(msgs, ts=None):
    """Journal lines as journalctl -o short-unix writes them."""
    import time
    ts = int(time.time()) - 60 if ts is None else ts
    return "\n".join(f"{ts}.000001 host sshd-session[{100 + i}]: {m}" for i, m in enumerate(msgs))


class Attacks(unittest.TestCase):
    def setUp(self):
        h.run = fake_run
        h.locate = lambda ip: {}
        h.own_split = lambda: ({h.own_net("2a02:1:2:3::1")}, {h.own_net("45.33.1.90"): 1, h.own_net("45.33.1.6"): 1})
        # 2a02:1:2:3::/64 is Matt's (admin); 45.33.1.90 and 45.33.1.6 have had a mailbox sign in

    def result(self):
        return {r["ip"]: r for r in h.attacks(["1"])["rows"]}

    def test_one_attempt_counts_once_per_connection(self):
        r = self.result()["45.33.1.5"]
        self.assertEqual(r["ssh"], 2)
        self.assertEqual(r["users"][:2], ["admin", "root"])

    def test_user_names_with_spaces_are_counted(self):
        self.assertEqual(self.result()["45.33.2.9"]["ssh"], 1)

    def test_crafted_user_name_cannot_move_the_address(self):
        rows = self.result()
        self.assertIn("45.33.1.77", rows)
        self.assertNotIn("45.33.3.1", rows)

    def test_tries_as_mattridge_without_the_key_are_listed(self):
        # Anyone can type a user name; only proving the key (a Partial or
        # Accepted line) makes an address Matt's.
        self.assertIn("45.33.1.200", self.result())

    def test_global_ipv6_attempt_is_listed(self):
        self.assertIn("2a03:4000:1::5", self.result())

    def test_key_fingerprint_suffix_still_parses(self):
        self.assertEqual(self.result()["45.33.1.90"]["ssh"], 1)

    def test_your_key_without_the_code_is_listed_and_marked(self):
        extra = (f"\n{T + 50}.000001 host sshd-session[900]: Partial publickey for mattridge from 45.33.8.1 port 22 ssh2: ED25519 SHA256:abc"
                 f"\n{T + 51}.000001 host sshd-session[900]: Failed keyboard-interactive/pam for mattridge from 45.33.8.1 port 22 ssh2")
        h.run = lambda cmd, timeout=20, stderr_too=False: (fake_run(cmd) + extra) if cmd[:1] == ["journalctl"] else fake_run(cmd)
        r = self.result()["45.33.8.1"]
        self.assertTrue(r["key_ok"])
        self.assertFalse(r["signed_in"])

    def test_your_key_row_is_shown_even_behind_400_busier_addresses(self):
        lines = [f"{T + i}.000001 host sshd-session[{i}]: Invalid user a from 45.{34 + i // 250}.{i % 250}.1 port {i}" for i in range(450)
                 for _ in (0, 1)]
        lines.append(f"{T + 999}.000001 host sshd-session[9]: Partial publickey for mattridge from 45.33.8.2 port 22 ssh2")
        big = "\n".join(lines)
        h.run = lambda cmd, timeout=20, stderr_too=False: big if cmd[:1] == ["journalctl"] else ""
        rows = h.attacks(["30"])["rows"]
        self.assertEqual(len(rows), 400)
        self.assertEqual(rows[0]["ip"], "45.33.8.2")

    def test_sorting_picks_the_400_shown_from_every_address(self):
        lines = [f"{T + i}.000001 host sshd-session[{i}]: Invalid user a from 45.{34 + i // 250}.{i % 250}.1 port {i}" for i in range(450)]
        lines += [f"{T + 999 + k}.000001 host sshd-session[9]: Invalid user b from 45.40.0.9 port {k}" for k in range(61)]
        big = "\n".join(lines)
        h.run = lambda cmd, timeout=20, stderr_too=False: big if cmd[:1] == ["journalctl"] else ""
        top = h.attacks(["30", "tries", "desc"])
        self.assertEqual(top["rows"][0]["ip"], "45.40.0.9")
        self.assertEqual(top["sort"], {"key": "tries", "dir": "desc"})
        ips = [r["ip"] for r in h.attacks(["30", "ip", "asc"])["rows"]]
        self.assertEqual(ips[:2], ["45.34.0.1", "45.34.1.1"])
        self.assertEqual(len(ips), 400)
        for bad in (["30", "tries"], ["30", "rm", "asc"], ["30", "tries", "up"]):
            with self.assertRaises(h.UnexpectedArgs):
                h.attacks(bad)

    def test_your_key_row_is_kept_under_every_sort(self):
        lines = [f"{T + i}.000001 host sshd-session[{i}]: Invalid user a from 45.{34 + i // 250}.{i % 250}.1 port {i}" for i in range(450)
                 for _ in (0, 1)]
        lines.append(f"{T + 999}.000001 host sshd-session[9]: Partial publickey for mattridge from 99.1.1.1 port 22 ssh2")
        big = "\n".join(lines)
        h.run = lambda cmd, timeout=20, stderr_too=False: big if cmd[:1] == ["journalctl"] else ""
        for col in h.ATTACK_SORTS:
            for d in ("asc", "desc"):
                res = h.attacks(["30", col, d])
                ips = [r["ip"] for r in res["rows"]]
                self.assertIn("99.1.1.1", ips, (col, d))
                self.assertEqual(len(ips), 400)
                self.assertEqual(res["total"]["key_ok"], 1)
        ips = [r["ip"] for r in h.attacks(["30", "ip", "asc"])["rows"]]
        self.assertEqual(ips[-1], "99.1.1.1")                     # kept, and still in IP order (last)

    def test_signed_in_address_with_refused_tries_is_listed_and_marked(self):
        rows = self.result()
        self.assertTrue(rows["45.33.1.90"]["signed_in"])
        self.assertFalse(rows["45.33.1.5"]["signed_in"])
        self.assertNotIn("45.33.1.6", rows)     # signed in, and only scanned: left out

    def test_probes_and_private_and_ipv6(self):
        rows = self.result()
        self.assertEqual(rows["45.33.1.7"]["probes"], 1)
        self.assertEqual(rows["45.33.1.8"]["probes"], 1)
        self.assertNotIn("10.0.0.5", rows)                 # private, never shown
        self.assertNotIn("2001:db8::1", rows)              # documentation range: not global
        self.assertNotIn("2a02:1:2:3::99", rows)           # inside Matt's /64

    def test_mail_warn_and_ban_and_planted_text(self):
        rows = self.result()
        self.assertEqual(rows["45.33.1.50"]["mail"], 2)
        self.assertEqual(rows["45.33.1.50"]["banned"], 1)
        self.assertNotIn("45.33.3.66", rows)

    def test_dovecot_and_postfix_success_lines_only(self):
        ok = "Oct 30 10:00:00 host dovecot: imap-login: Login: user=<a@b.c>, method=PLAIN, rip=45.33.1.9, lip=10.0.0.1, mpid=1, TLS"
        bad = "Oct 30 10:00:00 host dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<x Login: user=<a> rip=45.33.1.10, lip=>, method=PLAIN, rip=45.33.1.11, lip=10.0.0.1"
        self.assertEqual(h.DOVECOT_LOGIN_RE.match(ok).group(1), "45.33.1.9")
        self.assertIsNone(h.DOVECOT_LOGIN_RE.match(bad))
        sasl = "Nov  1 10:12:57 67189641cc02 postfix/submission/smtpd[43510]: 4AB12C3: client=unknown[45.33.1.12], sasl_method=PLAIN, sasl_username=a@b.c"
        fail = "Nov  1 10:12:57 67189641cc02 postfix/smtps/smtpd[43510]: warning: unknown[45.33.1.13]: SASL LOGIN authentication failed: x, sasl_username=a@b.c"
        self.assertEqual(h.POSTFIX_SASL_RE.match(sasl).group(1), "45.33.1.12")
        self.assertIsNone(h.POSTFIX_SASL_RE.match(fail))

    def test_own_sign_in_lines(self):
        for line in ("Accepted publickey for root from 45.33.4.1 port 22 ssh2: ED25519 SHA256:I8fHgkz7nhxQzFNpqIqRhxK4fN2PMbTnUr7yEn83Ylw",
                     "Accepted keyboard-interactive/pam for mattridge from 45.33.4.3 port 22 ssh2"):
            self.assertIsNotNone(h.SSH_OWN_RE.match(line), line)
        partial = "Partial publickey for mattridge from 45.33.4.2 port 22 ssh2: ED25519 SHA256:abc"
        self.assertIsNone(h.SSH_OWN_RE.match(partial))
        self.assertEqual(h.SSH_PARTIAL_RE.match(partial).group(2), "45.33.4.2")
        self.assertIsNone(h.SSH_OWN_RE.match("Invalid user Accepted publickey for x from 45.33.4.4 port 1"))
        mixed = "Nov  1 10:12:57 67189641cc02 postfix/submission/smtpd[43510]: 4kX9Lq2Zb7z9vH: client=unknown[45.33.4.5], sasl_method=PLAIN, sasl_username=a@b.c"
        self.assertEqual(h.POSTFIX_SASL_RE.match(mixed).group(1), "45.33.4.5")

    def test_own_networks_refuses_when_a_mail_log_cannot_be_read(self):
        real_sp, real_seen = h.subprocess.run, h.OWN_SEEN
        try:
            h.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr="")   # SSH: no matches
            h.run = lambda cmd, timeout=20, stderr_too=False: None                             # mail log unreadable
            h.OWN_SEEN = "/nonexistent/own-seen.json"
            with self.assertRaises(h.Refused):
                ORIGINAL_OWN_SPLIT()
        finally:
            h.subprocess.run, h.OWN_SEEN = real_sp, real_seen

    def test_own_split_trusts_only_admin_ssh_sign_ins(self):
        import json, tempfile
        d = tempfile.mkdtemp()
        seen = os.path.join(d, "own-seen.json")
        with open(seen, "w") as f:
            json.dump({"45.33.6.1": 1793400000, "45.33.6.2": {"t": 1793400000, "via": "admin"}}, f)   # old and new format
        ssh = jlines(["Accepted publickey for mattridge from 45.33.5.1 port 22 ssh2",
                      "Accepted publickey for upload1 from 45.33.5.2 port 22 ssh2",
                      "Accepted publickey for upload1 from 45.33.5.3 port 22 ssh2",
                      "Partial publickey for root from 45.33.5.3 port 23 ssh2"])
        dove = "Oct 30 10:00:00 host dovecot: imap-login: Login: user=<a@b.c>, method=PLAIN, rip=45.33.5.4, lip=10.0.0.1, mpid=1"
        real = (h.subprocess.run, h.run, h.OWN_SEEN, h.OWN_MANUAL, h.caller_address)
        try:
            h.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=ssh, stderr="")
            h.run = lambda cmd, timeout=20, stderr_too=False: dove if h.DOVECOT in cmd else ""
            h.OWN_SEEN, h.OWN_MANUAL, h.caller_address = seen, os.path.join(d, "none"), lambda: None
            admin, other = ORIGINAL_OWN_SPLIT()
        finally:
            h.subprocess.run, h.run, h.OWN_SEEN, h.OWN_MANUAL, h.caller_address = real
        net = h.own_net
        self.assertEqual(admin, {net("45.33.5.1"), net("45.33.6.2")})
        self.assertEqual(set(other), {net("45.33.5.2"), net("45.33.5.3"), net("45.33.5.4"), net("45.33.6.1")})
        with open(seen) as f:
            self.assertEqual(json.load(f)["45.33.5.3"]["via"], "other")     # a Partial line is not a sign-in

    def test_admin_trust_runs_from_the_sign_in_not_from_reading_the_journal(self):
        import time
        now = int(time.time())
        args = []
        line = "Accepted publickey for mattridge from %s port 22 ssh2"
        ssh = jlines([line % "45.33.7.8"], now - 200 * 86400) + "\n" + jlines([line % "45.33.7.9"], now - 10 * 86400)
        (admin, other), seen = self._split_with({}, ssh=ssh, args=args)
        self.assertNotIn(h.own_net("45.33.7.8"), admin)
        self.assertIn(h.own_net("45.33.7.9"), admin)
        self.assertIn("--since", args[0])
        import json
        with open(seen) as f:
            self.assertEqual(json.load(f)["45.33.7.9"]["ta"], now - 10 * 86400)

    def _split_with(self, seen_data, ssh="", dove="", args=None):
        import json, tempfile
        d = tempfile.mkdtemp()
        seen = os.path.join(d, "own-seen.json")
        with open(seen, "w") as f:
            f.write(seen_data if isinstance(seen_data, str) else json.dumps(seen_data))
        real = (h.subprocess.run, h.run, h.OWN_SEEN, h.OWN_MANUAL, h.caller_address)
        try:
            def fake(cmd, **k):
                if args is not None:
                    args.append(cmd)
                return types.SimpleNamespace(returncode=0, stdout=ssh, stderr="")
            h.subprocess.run = fake
            h.run = lambda cmd, timeout=20, stderr_too=False: dove if h.DOVECOT in cmd else ""
            h.OWN_SEEN, h.OWN_MANUAL, h.caller_address = seen, os.path.join(d, "none"), lambda: None
            return ORIGINAL_OWN_SPLIT(), seen
        finally:
            h.subprocess.run, h.run, h.OWN_SEEN, h.OWN_MANUAL, h.caller_address = real

    def test_admin_trust_expires_180_days_after_the_last_admin_sign_in(self):
        import json, time
        now = int(time.time())
        dove = "Oct 30 10:00:00 host dovecot: imap-login: Login: user=<a@b.c>, method=PLAIN, rip=45.33.7.1, lip=10.0.0.1, mpid=1"
        (admin, other), seen = self._split_with({"45.33.7.1": {"t": now - 10, "via": "admin", "ta": now - 181 * 86400}}, dove=dove)
        self.assertNotIn(h.own_net("45.33.7.1"), admin)
        self.assertIn(h.own_net("45.33.7.1"), other)
        (admin, _), _ = self._split_with({"45.33.7.2": {"t": now - 86400, "via": "admin", "ta": now - 100 * 86400}}, dove=dove.replace("7.1", "7.2"))
        self.assertIn(h.own_net("45.33.7.2"), admin)          # still within 180 days; a mail sign-in keeps it, doesn't renew it

    def test_old_entry_becomes_admin_after_an_admin_ssh_sign_in(self):
        (admin, other), _ = self._split_with({"45.33.7.3": 1793400000},
                                             ssh=jlines(["Accepted publickey for mattridge from 45.33.7.3 port 22 ssh2"]))
        self.assertIn(h.own_net("45.33.7.3"), admin)
        self.assertNotIn(h.own_net("45.33.7.3"), other)

    def test_malformed_seen_entries_are_ignored(self):
        (admin, other), _ = self._split_with('{"45.33.7.4": Infinity, "45.33.7.5": true, "10.0.0.1": 5, "45.33.7.6": {"t": 5, "via": "boss"}, "45.33.7.7": "x"}')
        self.assertEqual((admin, other), (set(), {}))

    def test_mapped_ipv4_is_normalised(self):
        self.assertEqual(h.plain_ip("::ffff:45.33.1.5"), "45.33.1.5")


class Trace(unittest.TestCase):
    def test_trace_refuses_an_address_that_never_tried(self):
        real = (h.blocked_match, h.address_events)
        h.blocked_match = lambda ip: None
        h.address_events = lambda ip, days=30, timeout=60: []
        try:
            with self.assertRaises(h.Refused):
                h.trace([b"1.1.1.1".hex()])
        finally:
            h.blocked_match, h.address_events = real

    def test_hops(self):
        out = ("traceroute to 45.33.1.5 (45.33.1.5), 24 hops max, 60 byte packets\n"
               " 1  10.0.0.1  0.412 ms\n 2  *\n 3  45.33.2.1  1.200 ms\n 4  45.33.1.5  5.100 ms !H\n")
        h.run = lambda cmd, timeout=20, stderr_too=False: out
        h.locate = lambda ip: {}
        h.blocked_match = lambda ip: None
        h.address_events = lambda ip, days=30, timeout=60: [(1, "ssh", "root")]
        h.NOTED.clear()
        r = h.trace([b"45.33.1.5".hex()])
        self.assertEqual([x["ip"] for x in r["hops"]], ["private", None, "45.33.2.1", "45.33.1.5"])


class Intel(unittest.TestCase):
    def test_visits_split_on_a_30_minute_gap(self):
        v = h.visits_of([0, 60, 1700, 1700 + 1801, 1700 + 1802, 86400 * 3])
        self.assertEqual([x[2] for x in v], [3, 2, 1])

    def test_three_probe_trace_lines(self):
        out = ("traceroute to 45.33.1.5 (45.33.1.5), 24 hops max\n"
               " 1  10.0.0.1  0.4 ms  0.5 ms  0.6 ms\n"
               " 2  * * *\n"
               " 3  45.33.2.1  1.2 ms 45.33.2.9  1.4 ms *\n"
               " 4  45.33.1.5  5.1 ms !H  5.3 ms !H  5.2 ms !H\n")
        h.locate = lambda ip: {}
        hops, reached = h.parse_trace(out, "45.33.1.5")
        self.assertEqual([x["ip"] for x in hops], ["private", None, "45.33.2.1", "45.33.1.5"])
        self.assertEqual(hops[3]["ms"], 5.2)
        self.assertTrue(reached)

    def test_registry_record_owner_network_and_nested_abuse(self):
        rec = {"name": "EXAMPLE-NET", "handle": "NET-45-33-0-0-1", "country": "US",
               "startAddress": "45.33.0.0", "endAddress": "45.33.255.255",
               "cidr0_cidrs": [{"v4prefix": "45.33.0.0", "length": 16}],
               "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Hosting"]]],
                             "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]]}]}]}
        real_fetch, real_base = h._fetch_json, h.rdap_base
        try:
            h._fetch_json = lambda url, **k: rec
            h.rdap_base = lambda ip: "https://rdap.example/"
            r = h.rdap_lookup("45.33.1.5")
        finally:
            h._fetch_json, h.rdap_base = real_fetch, real_base
        self.assertEqual(r["org"], "Example Hosting")
        self.assertEqual(r["abuse"], "abuse@example.net")
        self.assertEqual(r["networks"], ["45.33.0.0/16"])

    def test_block_refuses_own_server_private_and_too_wide(self):
        real = (h.own_split, h.server_networks)
        h.own_split = lambda: ({h.own_net("45.33.9.9")}, {})
        h.server_networks = lambda: {h._ipaddress.ip_network(h.SERVER_IP)}
        try:
            for net, why in (("10.0.0.0/24", "public"), ("45.0.0.0/8", "too wide"), ("45.33.9.0/24", "your own"),
                             (h.SERVER_IP + "/32", "cut this server off")):
                with self.assertRaises(h.Refused) as cm:
                    h.block_add([net.encode().hex(), "none"])
                self.assertIn(why, str(cm.exception))
        finally:
            h.own_split, h.server_networks = real

    def _block_with(self, entries, net, confirm=False, other=None):
        import contextlib
        saved = {}
        real = (h.read_blocked, h.save_and_apply, h.change_lock, h.server_networks, h.locate, h.known_own_networks, h.geo_reader, h.own_split)
        if h.geo_reader is not self._no_db:
            h.geo_reader = lambda kind: object()
        h.own_split = lambda: ({h.own_net("45.33.9.9")}, other or {})
        h.read_blocked = lambda: dict(entries)
        h.save_and_apply = lambda e, mine: saved.update(e=e, mine=mine)
        h.change_lock = contextlib.nullcontext
        h.server_networks = lambda: {h._ipaddress.ip_network(h.SERVER_IP)}
        h.locate = lambda ip: {"asn": 1 if ip.startswith("45.33.9") else 2}
        h.known_own_networks = lambda admin_only=False: set()
        try:
            return h.block_add([net.encode().hex(), "none"] + (["confirm-signed-in"] if confirm else [])), saved
        finally:
            (h.read_blocked, h.save_and_apply, h.change_lock, h.server_networks, h.locate, h.known_own_networks, h.geo_reader, h.own_split) = real

    @staticmethod
    def _no_db(kind):
        return None

    def test_network_block_refused_without_the_provider_database(self):
        real = h.geo_reader
        h.geo_reader = self._no_db
        try:
            with self.assertRaises(h.Refused) as cm:
                self._block_with({}, "46.1.2.0/24")
            self.assertIn("provider database", str(cm.exception))
            h.geo_reader = self._no_db
            r, _ = self._block_with({}, "46.1.2.3")
            self.assertEqual(r["blocked"], "46.1.2.3/32")
        finally:
            h.geo_reader = real

    def test_address_where_a_mailbox_signed_in_needs_confirmation(self):
        other = {h.own_net("46.2.2.2"): 1793500000}
        with self.assertRaises(h.Refused) as cm:
            self._block_with({}, "46.2.2.2", other=other)
        self.assertIn(h.SIGNED_IN_REFUSAL, str(cm.exception))
        r, saved = self._block_with({}, "46.2.2.2", confirm=True, other=other)
        self.assertEqual(r["blocked"], "46.2.2.2/32")
        self.assertTrue(r["signed_in"])
        self.assertNotIn(h.own_net("46.2.2.2"), saved["mine"])     # not let through ahead of the block
        with self.assertRaises(h.UnexpectedArgs):
            h.block_add([b"46.2.2.2".hex(), "none", "yes"])

    def test_network_on_a_provider_a_mailbox_uses_needs_confirmation(self):
        other = {h.own_net("46.5.5.5"): 1793500000}
        with self.assertRaises(h.Refused) as cm:
            self._block_with({}, "46.5.9.0/24", other=other)
        self.assertIn(h.SIGNED_IN_REFUSAL, str(cm.exception))
        r, _ = self._block_with({}, "46.5.9.0/24", confirm=True, other=other)
        self.assertEqual(r["blocked"], "46.5.9.0/24")

    def test_ipv4_written_as_ipv6_is_refused(self):
        with self.assertRaises(h.Refused) as cm:
            self._block_with({}, "::ffff:46.3.3.3")
        self.assertIn("plain IPv4", str(cm.exception))

    def test_block_inside_an_existing_block_is_refused(self):
        with self.assertRaises(h.Refused) as cm:
            self._block_with({"46.1.0.0/16": {"added": 1, "note": ""}}, "46.1.2.3")
        self.assertIn("already covered by the block on 46.1.0.0/16", str(cm.exception))

    def test_wider_block_replaces_the_ones_it_covers(self):
        r, saved = self._block_with({"46.1.2.3/32": {"added": 1, "note": ""}, "47.0.0.1/32": {"added": 1, "note": ""}},
                                    "46.1.0.0/16")
        self.assertEqual(r["replaced"], ["46.1.2.3/32"])
        self.assertEqual(sorted(saved["e"]), ["46.1.0.0/16", "47.0.0.1/32"])
        self.assertIn(h.own_net("45.33.9.9"), saved["mine"])

    def test_network_on_your_own_provider_is_refused_but_one_address_is_not(self):
        with self.assertRaises(h.Refused) as cm:
            self._block_with({}, "45.33.98.0/24")   # same provider (fixture ASN 1) as 45.33.9.9
        self.assertIn("same provider", str(cm.exception))
        r, _ = self._block_with({}, "45.33.98.7")
        self.assertEqual(r["blocked"], "45.33.98.7/32")

    def test_table_accepts_replies_and_own_networks_before_dropping(self):
        written = {}
        real_must, real_mk = h.must, h._tempfile.mkstemp
        import tempfile
        d = tempfile.mkdtemp()
        def grab(cmd, timeout=0):
            with open(cmd[-1]) as f:
                written.setdefault("text", f.read())
        h.must = grab
        real_nft = h.BLOCK_NFT
        h.BLOCK_NFT = os.path.join(d, "blocklist.nft")
        try:
            h.apply_blocklist({"46.1.0.0/16": {}}, {h.own_net("45.33.9.9"), h.own_net("45.33.9.10")})
        finally:
            h.must, h.BLOCK_NFT = real_must, real_nft
        t = written["text"]
        self.assertIn("priority -150", t)
        order = [t.index(x) for x in ("ct direction reply accept", "ip saddr @own4 accept", "ip saddr @blocked4 drop")]
        self.assertEqual(order, sorted(order))
        self.assertIn("elements = { 46.1.0.0/16 }", t)


    @unittest.skipUnless(shutil.which("nft") and hasattr(os, "geteuid") and os.geteuid() == 0, "needs nft and root")
    def test_generated_tables_parse_with_empty_and_full_sets(self):
        import subprocess
        import tempfile
        cases = [({}, set()),
                 ({"46.1.0.0/16": {}}, {h.own_net("2a02:1:2:3::99")}),
                 ({"46.1.0.0/16": {}, "2a03:4000:1::/48": {}}, {h.own_net("45.33.9.9"), h.own_net("2a02:1:2:3::99")})]
        real_must, real_nft = h.must, h.BLOCK_NFT
        d = tempfile.mkdtemp()
        texts = []

        def grab(cmd, timeout=0):
            with open(cmd[-1]) as f:
                texts.append(f.read())
            raise h.Refused("captured")
        h.must, h.BLOCK_NFT = grab, os.path.join(d, "blocklist.nft")
        try:
            for entries, mine in cases:
                with self.assertRaises(h.Refused):
                    h.apply_blocklist(entries, mine)
        finally:
            h.must, h.BLOCK_NFT = real_must, real_nft
        for t in texts:
            path = os.path.join(d, "check.nft")
            with open(path, "w") as f:
                f.write(t.replace("destroy table inet argus\n", "").replace("inet argus", "inet argus_check"))
            p = subprocess.run(["nft", "-c", "-f", path], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    sys.argv[1:] = []
    unittest.main(verbosity=1)
