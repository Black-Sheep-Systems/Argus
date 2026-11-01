"""Tests for the Sign-In Attempts log parsing in argus-helper.

Run from the repository: python3 server/tests/test_attacks.py
No server needed: the helper's run() and own_networks() are replaced with
fixtures, so this checks the parsing, counting and exclusion rules only."""
import importlib.machinery
import importlib.util
import os
import sys
import types
import unittest

sys.dont_write_bytecode = True          # don't leave a __pycache__ in server/

HERE = os.path.dirname(os.path.abspath(__file__))
loader = importlib.machinery.SourceFileLoader("helper", os.path.join(HERE, "..", "argus-helper"))
spec = importlib.util.spec_from_loader("helper", loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)
ORIGINAL_OWN_NETWORKS = h.own_networks

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


class Attacks(unittest.TestCase):
    def setUp(self):
        h.run = fake_run
        h.locate = lambda ip: {}
        h.own_networks = lambda: {h.own_net("2a02:1:2:3::1")}      # one of Matt's IPv6 /64s

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

    def test_probes_and_private_and_ipv6(self):
        rows = self.result()
        self.assertEqual(rows["45.33.1.6"]["probes"], 1)
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
                     "Partial publickey for mattridge from 45.33.4.2 port 22 ssh2: ED25519 SHA256:abc",
                     "Accepted keyboard-interactive/pam for mattridge from 45.33.4.3 port 22 ssh2"):
            self.assertIsNotNone(h.SSH_OWN_RE.match(line), line)
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
                ORIGINAL_OWN_NETWORKS()
        finally:
            h.subprocess.run, h.OWN_SEEN = real_sp, real_seen

    def test_mapped_ipv4_is_normalised(self):
        self.assertEqual(h.plain_ip("::ffff:45.33.1.5"), "45.33.1.5")


class Trace(unittest.TestCase):
    def test_hops(self):
        out = ("traceroute to 45.33.1.5 (45.33.1.5), 24 hops max, 60 byte packets\n"
               " 1  10.0.0.1  0.412 ms\n 2  *\n 3  45.33.2.1  1.200 ms\n 4  45.33.1.5  5.100 ms !H\n")
        h.run = lambda cmd, timeout=20, stderr_too=False: out
        h.locate = lambda ip: {}
        h.NOTED.clear()
        r = h.trace([b"45.33.1.5".hex()])
        self.assertEqual([x["ip"] for x in r["hops"]], ["private", None, "45.33.2.1", "45.33.1.5"])


if __name__ == "__main__":
    sys.argv[1:] = []
    unittest.main(verbosity=1)
