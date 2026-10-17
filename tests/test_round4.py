"""Round 4: Referer-free access log, sshd ListenAddress ports, PKI serialisation,
renewal recovery, unique_subject."""

import fcntl
import os
import re
import tempfile
import threading
import unittest

from dbovpn import pki, provision, users
from dbovpn.users import ServiceError
from tests import helpers
from tests.test_certs import FakeEasyRSA, legacy_pki, read
from tests.test_fixes import FakeHost

NOW = 1792224000


class AccessLogTest(unittest.TestCase):
    def setUp(self):
        self.text = provision.render("nginx-site.conf", provision.nginx_values(helpers.example_config()))

    def test_log_format_has_no_referer_or_query(self):
        fmt = re.search(r"log_format dbovpn_noref (.+?);", self.text, re.S).group(1)
        self.assertNotIn("http_referer", fmt)
        self.assertNotIn("$request ", fmt)
        self.assertNotIn("$request_uri", fmt)
        self.assertNotIn("$args", fmt)
        self.assertIn("$uri", fmt)

    def test_used_for_whole_site_and_enrol_logs_off(self):
        server = self.text[self.text.index("server {"):]
        head = server[:server.index("location")]
        self.assertIn("access_log /var/log/nginx/access.log dbovpn_noref;", head)
        for loc in ("location /enroll/", "location /admin-enroll/"):
            block = server[server.index(loc):]
            block = block[:block.index("}")]
            self.assertIn("access_log off;", block)
        self.assertEqual(self.text.count("http_referer"), 0)


class SshdPortsTest(unittest.TestCase):
    def test_listenaddress_wins_over_port(self):
        out = "port 22\nlistenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\n"
        self.assertEqual(provision.parse_sshd_ports(out), ["2222"])

    def test_multiple_and_fallback(self):
        self.assertEqual(provision.parse_sshd_ports("port 9822\nlistenaddress 0.0.0.0:9822\nlistenaddress 10.0.0.1:2200\n"),
                         ["2200", "9822"])
        self.assertEqual(provision.parse_sshd_ports("port 9822\naddressfamily any\n"), ["9822"])
        self.assertEqual(provision.parse_sshd_ports("port 22\nlistenaddress [::1]\n"), ["22"])
        self.assertEqual(provision.parse_sshd_ports(""), [])

    def test_firewalld_start_uses_listenaddress_port(self):
        class Host(FakeHost):
            def __call__(self, argv, check=True, quiet=False):
                if os.path.basename(argv[0]) == "sshd":
                    self.calls.append(argv)
                    return 0, "port 22\nlistenaddress 0.0.0.0:2222\n"
                return FakeHost.__call__(self, argv, check, quiet)
        host = Host()
        provision.ensure_firewalld_running(helpers.example_config(), run=host, log=lambda m: None)
        self.assertIn(["/usr/bin/firewall-offline-cmd", "--zone=public", "--add-port=2222/tcp"], host.calls)
        self.assertNotIn(["/usr/bin/firewall-offline-cmd", "--zone=public", "--add-port=22/tcp"], host.calls)


class PkiLockTest(unittest.TestCase):
    def test_lock_is_exclusive(self):
        cfg, d = legacy_pki()
        lock_path = os.path.join(d, ".dbo-vpn-gateway.lock")
        held = threading.Event()
        release = threading.Event()

        def holder():
            with pki.pki_lock(cfg):
                held.set()
                release.wait(5)
        t = threading.Thread(target=holder)
        t.start()
        held.wait(5)
        fd = os.open(lock_path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            release.set()
            t.join(5)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)      # free again
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_privhelper_and_setup_take_the_lock(self):
        for name in ("privhelper.py", "provision.py"):
            with open(os.path.join(helpers.ROOT, "dbovpn", name), encoding="utf-8") as fh:
                self.assertIn("pki_lock(cfg)", fh.read(), name)


class RenewClaimTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context()
        self.ctx.priv.cert_end = "2026-12-01"
        helpers.add_user(self.ctx, "ali", days=200)

    def test_second_concurrent_renewal_refused(self):
        self.ctx.conn.execute("UPDATE vpn_users SET cert_renewing = ?", (NOW - 10,))
        with self.assertRaises(ServiceError) as cm:
            users.ensure_fresh_cert(self.ctx, "ali")
        self.assertEqual(cm.exception.key, "cert_renew_busy")
        self.assertNotIn(("renew_cert", "ali"), self.ctx.priv.calls)

    def test_stale_claim_taken_over_and_cleared(self):
        self.ctx.conn.execute("UPDATE vpn_users SET cert_renewing = ?", (NOW - 3600,))
        self.assertTrue(users.ensure_fresh_cert(self.ctx, "ali"))
        self.assertEqual(users.get(self.ctx.conn, "ali")["cert_renewing"], 0)

    def test_failure_clears_claim(self):
        self.ctx.priv.fail = {"renew_cert"}
        with self.assertRaises(ServiceError):
            users.ensure_fresh_cert(self.ctx, "ali")
        self.assertEqual(users.get(self.ctx.conn, "ali")["cert_renewing"], 0)


class RenewRecoveryTest(unittest.TestCase):
    def test_finishes_run_that_stopped_after_build(self):
        cfg, d = legacy_pki()
        # State left by a run whose revoke-expired failed: old cert in expired/, new pair issued,
        # old key/req held.
        os.makedirs(os.path.join(d, "expired"))
        os.rename(os.path.join(d, "issued", "legacy.crt"), os.path.join(d, "expired", "legacy.crt"))
        for rel in ("private/legacy.key", "reqs/legacy.req"):
            os.rename(os.path.join(d, rel), os.path.join(d, rel) + pki.HELD_SUFFIX)
        for rel, text in (("issued/legacy.crt", "NEW CERT"), ("private/legacy.key", "NEW KEY"), ("reqs/legacy.req", "NEW REQ")):
            with open(os.path.join(d, rel), "w") as fh:
                fh.write(text)
        fake = FakeEasyRSA(d)
        pki.EasyRSA(cfg, run=fake).renew_client("legacy")
        self.assertEqual(fake.commands, ["revoke-expired", "gen-crl"])
        self.assertEqual(read(os.path.join(d, "issued", "legacy.crt")), "NEW CERT")
        self.assertEqual(read(os.path.join(d, "revoked", "certs_by_serial", "0A1B.crt")), "OLD CERT")
        self.assertIn("ENCRYPTED", read(os.path.join(d, "revoked", "private_by_serial", "0A1B.key")))
        leftovers = [f for _, _, fs in os.walk(d) for f in fs if f.endswith(pki.HELD_SUFFIX)]
        self.assertEqual(leftovers, [])
        # A further call is a normal renewal again, not stuck on 'expire'.
        fake.serial = "0C0D"
        pki.EasyRSA(cfg, run=fake).renew_client("legacy")
        self.assertEqual(fake.commands[-4:], ["expire", "build-client-full", "revoke-expired", "gen-crl"])

    def test_restores_run_that_stopped_before_build(self):
        cfg, d = legacy_pki()
        os.makedirs(os.path.join(d, "expired"))
        os.rename(os.path.join(d, "issued", "legacy.crt"), os.path.join(d, "expired", "legacy.crt"))
        os.rename(os.path.join(d, "private", "legacy.key"), os.path.join(d, "private", "legacy.key") + pki.HELD_SUFFIX)
        fake = FakeEasyRSA(d)
        pki.EasyRSA(cfg, run=fake).renew_client("legacy")
        self.assertEqual(fake.commands, ["expire", "build-client-full", "revoke-expired", "gen-crl"])
        self.assertEqual(read(os.path.join(d, "issued", "legacy.crt")), "NEW CERT")
        self.assertIn("ENCRYPTED", read(os.path.join(d, "revoked", "private_by_serial", "0A1B.key")))


class UniqueSubjectTest(unittest.TestCase):
    def test_detect_and_disable_with_backup(self):
        d = tempfile.mkdtemp()
        attr = os.path.join(d, "index.txt.attr")
        self.assertFalse(pki.read_unique_subject(attr))           # missing file: OpenSSL default is fine
        with open(attr, "w") as fh:
            fh.write("unique_subject = yes\n")
        self.assertTrue(pki.read_unique_subject(attr))
        self.assertTrue(pki.disable_unique_subject(attr, ".bak-test"))
        self.assertEqual(read(attr), "unique_subject = no\n")
        self.assertEqual(read(attr + ".bak-test"), "unique_subject = yes\n")
        self.assertFalse(pki.disable_unique_subject(attr, ".bak-again"))
        self.assertFalse(os.path.exists(attr + ".bak-again"))

    def test_rsa_helper(self):
        cfg, d = legacy_pki()
        with open(os.path.join(d, "index.txt.attr"), "w") as fh:
            fh.write("unique_subject = no\n")
        self.assertFalse(pki.EasyRSA(cfg).unique_subject_enabled())


if __name__ == "__main__":
    unittest.main()
