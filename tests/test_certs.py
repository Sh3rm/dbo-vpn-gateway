"""Round 3: client certificates must outlive accounts; no passphrase keys in profiles."""

import datetime
import os
import tempfile
import unittest

from dbovpn import config as config_mod
from dbovpn import jobs, pki, privhelper, provision, users
from dbovpn.users import ServiceError
from tests import helpers
from tests.helpers import TODAY
from tests.test_fixes import FakeOpenssl, make_pki

NOW = 1792224000


def row(**kw):
    base = {"needs_new_cert": 0, "cert_key_encrypted": 0, "cert_not_after": "2028-01-31",
            "expires_on": "2027-01-01", "enabled": 1}
    base.update(kw)
    return base


class PolicyTest(unittest.TestCase):
    def test_client_cert_days(self):
        self.assertEqual(helpers.example_config().client_cert_days, 455)
        with self.assertRaises(config_mod.ConfigError):
            helpers.example_config(client_cert_days="390")      # < max_expiry_days + 30

    def test_needs_new_cert(self):
        self.assertFalse(users.needs_new_cert(row()))
        self.assertTrue(users.needs_new_cert(row(needs_new_cert=1)))
        self.assertTrue(users.needs_new_cert(row(cert_key_encrypted=1)))
        self.assertTrue(users.needs_new_cert(row(cert_not_after=None)))
        # ends 2027-01-20: before last valid day + 30 (2027-01-31)
        self.assertTrue(users.needs_new_cert(row(cert_not_after="2027-01-20")))
        self.assertFalse(users.needs_new_cert(row(cert_not_after="2027-01-31")))

    def test_cert_ends_early(self):
        self.assertTrue(users.cert_ends_early(row(cert_not_after="2026-12-31")))
        self.assertFalse(users.cert_ends_early(row(cert_not_after="2027-01-01")))
        self.assertFalse(users.cert_ends_early(row(cert_not_after="2026-12-31", enabled=0)))
        self.assertFalse(users.cert_ends_early(row(cert_not_after=None)))


class FreshCertTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context()

    def test_create_records_cert_end(self):
        r = helpers.add_user(self.ctx, "ali")
        self.assertEqual(r["cert_not_after"], "2028-01-31")
        self.assertFalse(users.needs_new_cert(r))
        self.assertFalse(users.ensure_fresh_cert(self.ctx, "ali"))
        self.assertNotIn(("renew_cert", "ali"), self.ctx.priv.calls)

    def test_short_cert_renewed_on_download(self):
        self.ctx.priv.cert_end = "2026-12-01"
        helpers.add_user(self.ctx, "ali", days=200)
        self.assertTrue(users.ensure_fresh_cert(self.ctx, "ali"))
        r = users.get(self.ctx.conn, "ali")
        self.assertEqual(r["cert_not_after"], "2028-06-30")
        self.assertIn(("renew_cert", "ali"), self.ctx.priv.calls)
        actions = [a[0] for a in self.ctx.conn.execute("SELECT action FROM audit ORDER BY id")]
        self.assertEqual(actions[-1], "cert.renew")

    def test_adopted_user_always_renewed_even_with_long_cert(self):
        cfg = self.ctx.cfg
        users.adopt(self.ctx.conn, cfg, "legacy", "cli:setup", NOW, TODAY)
        users.record_cert_info(self.ctx.conn, "legacy", {"not_after": "2030-01-01", "key_encrypted": False})
        self.assertTrue(users.needs_new_cert(users.get(self.ctx.conn, "legacy")))
        self.assertTrue(users.ensure_fresh_cert(self.ctx, "legacy"))
        r = users.get(self.ctx.conn, "legacy")
        self.assertEqual(r["needs_new_cert"], 0)
        self.assertFalse(users.ensure_fresh_cert(self.ctx, "legacy"))   # only once

    def test_encrypted_key_renewed(self):
        self.ctx.priv.key_encrypted = True
        helpers.add_user(self.ctx, "ali")
        self.assertTrue(users.needs_new_cert(users.get(self.ctx.conn, "ali")))
        users.ensure_fresh_cert(self.ctx, "ali")
        self.assertEqual(users.get(self.ctx.conn, "ali")["cert_key_encrypted"], 0)

    def test_renew_failure(self):
        self.ctx.priv.cert_end = "2026-12-01"
        helpers.add_user(self.ctx, "ali", days=200)
        self.ctx.priv.fail = {"renew_cert"}
        with self.assertRaises(ServiceError) as cm:
            users.ensure_fresh_cert(self.ctx, "ali")
        self.assertEqual(cm.exception.key, "cert_renew_failed")
        actions = [a[0] for a in self.ctx.conn.execute("SELECT action FROM audit ORDER BY id")]
        self.assertEqual(actions[-1], "cert.renew_failed")


class CertWarningJobTest(unittest.TestCase):
    def test_warn_once_per_pair(self):
        from dbovpn import admins
        ctx = helpers.context()
        admins.add(ctx, "boss", "Boss", "boss@example.com", "en")
        ctx.priv.cert_end = (TODAY + datetime.timedelta(days=100)).isoformat()
        helpers.add_user(ctx, "ali", days=200)
        ctx.mailer.sent = []
        r = jobs.run_expiry(ctx.cfg, ctx.conn, ctx.ctl, ctx.mailer, NOW, TODAY)
        self.assertEqual(r["cert_short"], 1)
        self.assertEqual([m[1] for m in ctx.mailer.sent], ["cert_short"])
        r = jobs.run_expiry(ctx.cfg, ctx.conn, ctx.ctl, ctx.mailer, NOW + 3600, TODAY)
        self.assertEqual(r["cert_short"], 0)
        users.set_expiry(ctx, "ali", (TODAY + datetime.timedelta(days=300)).isoformat())
        r = jobs.run_expiry(ctx.cfg, ctx.conn, ctx.ctl, ctx.mailer, NOW + 7200, TODAY)
        self.assertEqual(r["cert_short"], 1)
        n = ctx.conn.execute("SELECT COUNT(*) FROM audit WHERE action = 'user.cert_short'").fetchone()[0]
        self.assertEqual(n, 2)

    def test_disabled_user_not_warned(self):
        ctx = helpers.context()
        ctx.priv.cert_end = (TODAY + datetime.timedelta(days=10)).isoformat()
        helpers.add_user(ctx, "ali", days=200, enabled=False)
        self.assertEqual(jobs.run_expiry(ctx.cfg, ctx.conn, ctx.ctl, ctx.mailer, NOW, TODAY)["cert_short"], 0)

    def test_mail_template_renders(self):
        from dbovpn import mailer
        for lang in ("en", "tr"):
            subject, body = mailer.render(lang, "cert_short", {
                "customer": "Example Corp", "username": "ali", "display_name": "Ali", "cert_not_after": "2027-01-12",
                "expires_on": "2027-06-01", "panel_url": "https://vpn.example.com"})
            self.assertIn("2027-01-12", body)


class FakeEasyRSA(object):
    """Simulates the Easy-RSA 3.2.1 file moves for expire / build-client-full /
    revoke-expired / gen-crl (as read from the 3.2.1 easyrsa script)."""

    def __init__(self, pki_dir, fail_build=False):
        self.pki = pki_dir
        self.fail_build = fail_build
        self.commands = []
        self.serial = "0A1B"

    def p(self, *parts):
        return os.path.join(self.pki, *parts)

    def __call__(self, argv, cwd=None):
        if argv[0].endswith("openssl"):
            if "-serial" in argv:
                return "serial=%s\n" % self.serial
            if "extendedKeyUsage" in argv:
                return "X509v3 Extended Key Usage:\n    TLS Web Client Authentication\n"
            return ""
        cmd = [a for a in argv[1:] if not a.startswith("--")]
        self.commands.append(cmd[0])
        name = cmd[1] if len(cmd) > 1 else None
        if cmd[0] == "expire":
            os.makedirs(self.p("expired"), exist_ok=True)
            os.rename(self.p("issued", name + ".crt"), self.p("expired", name + ".crt"))
        elif cmd[0] == "build-client-full":
            for f in (self.p("issued", name + ".crt"), self.p("private", name + ".key"), self.p("reqs", name + ".req")):
                if os.path.exists(f):
                    raise pki.PKIError("file already exists: %s" % f)
            if self.fail_build:
                raise pki.PKIError("build failed (fake)")
            for f, text in ((self.p("issued", name + ".crt"), "NEW CERT"), (self.p("private", name + ".key"), "NEW KEY"),
                            (self.p("reqs", name + ".req"), "NEW REQ")):
                with open(f, "w") as fh:
                    fh.write(text)
        elif cmd[0] == "revoke-expired":
            for d in ("certs_by_serial", "private_by_serial", "reqs_by_serial"):
                os.makedirs(self.p("revoked", d), exist_ok=True)
            os.rename(self.p("expired", name + ".crt"), self.p("revoked", "certs_by_serial", self.serial + ".crt"))
        elif cmd[0] == "gen-crl":
            with open(self.p("crl.pem"), "w") as fh:
                fh.write("CRL")
        return ""


def legacy_pki():
    tmp = tempfile.mkdtemp()
    pki_dir = os.path.join(tmp, "pki")
    for d in ("issued", "private", "reqs"):
        os.makedirs(os.path.join(pki_dir, d))
    for rel, text in (("issued/legacy.crt", "OLD CERT"), ("private/legacy.key",
                      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----\n"),
                      ("reqs/legacy.req", "OLD REQ")):
        with open(os.path.join(pki_dir, rel), "w") as fh:
            fh.write(text)
    cfg = helpers.example_config(pki_dir=pki_dir, crl_file=os.path.join(tmp, "crl.pem"))
    return cfg, pki_dir


def read(path):
    with open(path) as fh:
        return fh.read()


class RenewClientTest(unittest.TestCase):
    def test_new_pair_first_then_revoke(self):
        cfg, d = legacy_pki()
        fake = FakeEasyRSA(d)
        serial = pki.EasyRSA(cfg, run=fake).renew_client("legacy")
        self.assertEqual(serial, "0A1B")
        self.assertEqual(fake.commands, ["expire", "build-client-full", "revoke-expired", "gen-crl"])
        self.assertEqual(read(os.path.join(d, "issued", "legacy.crt")), "NEW CERT")
        self.assertEqual(read(os.path.join(d, "private", "legacy.key")), "NEW KEY")
        self.assertIn("ENCRYPTED", read(os.path.join(d, "revoked", "private_by_serial", "0A1B.key")))
        self.assertEqual(read(os.path.join(d, "revoked", "reqs_by_serial", "0A1B.req")), "OLD REQ")
        self.assertEqual(read(os.path.join(d, "revoked", "certs_by_serial", "0A1B.crt")), "OLD CERT")
        self.assertEqual(read(cfg.crl_file), "CRL")
        leftovers = [f for _, _, fs in os.walk(d) for f in fs if f.endswith(pki.HELD_SUFFIX)]
        self.assertEqual(leftovers, [])

    def test_build_failure_restores_old_cert(self):
        cfg, d = legacy_pki()
        fake = FakeEasyRSA(d, fail_build=True)
        with self.assertRaises(pki.PKIError):
            pki.EasyRSA(cfg, run=fake).renew_client("legacy")
        self.assertEqual(fake.commands, ["expire", "build-client-full"])     # never revoked
        self.assertEqual(read(os.path.join(d, "issued", "legacy.crt")), "OLD CERT")
        self.assertIn("ENCRYPTED", read(os.path.join(d, "private", "legacy.key")))
        self.assertEqual(read(os.path.join(d, "reqs", "legacy.req")), "OLD REQ")
        self.assertFalse(os.path.exists(os.path.join(d, "expired", "legacy.crt")))

    def test_build_uses_explicit_days(self):
        cfg, d = legacy_pki()
        seen = []

        def run(argv, cwd=None):
            seen.append(argv)
            return FakeEasyRSA(d)(argv, cwd)
        pki.EasyRSA(cfg, run=run).renew_client("legacy")
        build = [a for a in seen if "build-client-full" in a][0]
        self.assertIn("--days=455", build)
        self.assertLess(build.index("--days=455"), build.index("build-client-full"))


class EncryptedKeyProfileTest(unittest.TestCase):
    def test_refuses_encrypted_key(self):
        cfg = make_pki()
        with open(os.path.join(cfg.pki_dir, "private", "ali.key"), "w") as fh:
            fh.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----\n")
        with self.assertRaises(pki.PKIError) as cm:
            pki.build_ovpn(cfg, "ali", pki.EasyRSA(cfg, run=FakeOpenssl()))
        self.assertIn("passphrase", str(cm.exception))
        with open(os.path.join(cfg.pki_dir, "private", "ali.key"), "w") as fh:
            fh.write("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nX\n-----END RSA PRIVATE KEY-----\n")
        with self.assertRaises(pki.PKIError):
            pki.build_ovpn(cfg, "ali", pki.EasyRSA(cfg, run=FakeOpenssl()))


class PrivhelperRenewTest(unittest.TestCase):
    def test_validation(self):
        cfg = helpers.example_config()
        self.assertEqual(privhelper.validate(["renew-cert", "ali"], cfg), ("renew-cert", ["ali"]))
        self.assertEqual(privhelper.validate(["cert-info", "ali"], cfg), ("cert-info", ["ali"]))
        for bad in (["renew-cert"], ["renew-cert", "example-vpn"], ["cert-info", "../x"]):
            with self.assertRaises(privhelper.UsageError):
                privhelper.validate(bad, cfg)

    def test_renew_without_cert_issues_one(self):
        class RSA(object):
            done = []
            def cert_path(self, n): return "/nonexistent/%s.crt" % n
            def build_client(self, n): self.done.append(("build", n))
            def renew_client(self, n): self.done.append(("renew", n))
        rsa = RSA()
        privhelper.run("renew-cert", ["ali"], helpers.example_config(), rsa=rsa)
        self.assertEqual(rsa.done, [("build", "ali")])


class DoctorCertTest(unittest.TestCase):
    def test_cert_short_list(self):
        class RSA(object):
            def cert_end(self, n):
                return {"ali": datetime.date(2027, 1, 12), "veli": datetime.date(2028, 1, 1)}.get(n)
        short = provision.cert_short_list(RSA(), [["ali", "2027-06-01"], ["veli", "2027-06-01"], ["nobody", "2027-01-01"]])
        self.assertEqual(short, [("ali", "2027-01-12", "2027-06-01")])


class MigrationThreeTest(unittest.TestCase):
    def test_adopted_rows_marked(self):
        import sqlite3
        from dbovpn import db
        path = os.path.join(tempfile.mkdtemp(), "g.db")
        conn = sqlite3.connect(path, isolation_level=None)
        for script in db.MIGRATIONS[:2]:
            for stmt in script.split(";"):
                if stmt.strip():
                    conn.execute(stmt)
        conn.execute("PRAGMA user_version = 2")
        conn.execute("INSERT INTO vpn_users (username, display_name, email, profile, vpn_ip, expires_on, adopted,"
                     " created_at, created_by) VALUES ('legacy', 'L', '', 'app', '10.8.0.2', '2027-01-01', 1, 0, 'x')")
        conn.close()
        conn = db.connect(path)
        self.assertEqual(users.get(conn, "legacy")["needs_new_cert"], 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
