"""Regression tests for fix round 1 (security review and live findings)."""

import datetime
import glob
import os
import re
import sqlite3
import tempfile
import unittest

from dbovpn import admins, db, jobs, pki, provision, totp, users
from dbovpn.textutil import redact_path, slug
from dbovpn.web import i18n
from tests import helpers
from tests.helpers import TODAY

SECRET = "JBSWY3DPEHPK3PXP"
NOW = 1792224000


class TotpAsciiTest(unittest.TestCase):
    def test_non_ascii_digits_rejected(self):
        code = totp.code_at(SECRET, NOW)
        arabic = code.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
        fullwidth = code.translate(str.maketrans("0123456789", "０１２３４５６７８９"))
        self.assertIsNotNone(totp.verify(SECRET, code, NOW))
        self.assertIsNone(totp.verify(SECRET, arabic, NOW))
        self.assertIsNone(totp.verify(SECRET, fullwidth, NOW))


class TextUtilTest(unittest.TestCase):
    def test_slug_transliterates_turkish(self):
        self.assertEqual(slug("Örnek Yapı DEV"), "ornek-yapi-dev")
        self.assertEqual(slug("İĞÜŞÖÇ ığüşöç"), "igusoc-igusoc")
        self.assertEqual(slug("!!!"), "vpn")

    def test_redact_path(self):
        self.assertEqual(redact_path("/enroll/AbC-123_x"), "/enroll/<redacted>")
        self.assertEqual(redact_path("/enroll/AbC/download"), "/enroll/<redacted>/download")
        self.assertEqual(redact_path("/admin-enroll/tok"), "/admin-enroll/<redacted>")
        self.assertEqual(redact_path("/users/ali"), "/users/ali")


class AdminLockoutTest(unittest.TestCase):
    def test_counter_increments_in_sql(self):
        ctx = helpers.context()
        admins.add(ctx, "boss", "Boss", "boss@example.com", "en")
        ctx.conn.execute("UPDATE admins SET password_hash = 'fake$pw-pw-pw-pw', totp_secret = ?", (SECRET,))
        # A second worker already counted 4 failures; this request still read the row earlier.
        ctx.conn.execute("UPDATE admins SET failed_logins = 4")
        row, reason = admins.check_login(ctx.conn, ctx.cfg, "boss", "wrong", "000000", helpers.fake_verify,
                                         lambda p: None, NOW)
        self.assertIsNone(row)
        self.assertIn("locked", reason)
        self.assertGreater(admins.get(ctx.conn, "boss")["locked_until"], NOW)


class MigrationTest(unittest.TestCase):
    def test_v1_database_upgrades(self):
        path = os.path.join(tempfile.mkdtemp(), "g.db")
        conn = sqlite3.connect(path, isolation_level=None)
        for stmt in db.MIGRATIONS[0].split(";"):
            if stmt.strip():
                conn.execute(stmt)
        conn.execute("PRAGMA user_version = 1")
        conn.execute("INSERT INTO vpn_users (username, display_name, email, profile, vpn_ip, expires_on, created_at,"
                     " created_by) VALUES ('ali', 'Ali', '', 'app', '10.8.0.2', '2027-01-01', 0, 'x')")
        conn.close()
        conn = db.connect(path)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], len(db.MIGRATIONS))
        self.assertEqual(users.get(conn, "ali")["cred_epoch"], 1)
        self.assertEqual(db.migrate(conn), len(db.MIGRATIONS))
        conn.close()
        conn = db.connect(path, migrate_schema=False)
        conn.close()


class ExpiryEndsTokensTest(unittest.TestCase):
    def test_expiry_bumps_epoch(self):
        ctx = helpers.context()
        helpers.add_user(ctx, "ali")
        ctx.conn.execute("INSERT INTO vpn_sessions VALUES ('ali', 'SID', 1, ?)", (NOW,))
        ctx.conn.execute("UPDATE vpn_users SET expires_on = '2026-01-01'")
        jobs.run_expiry(ctx.cfg, ctx.conn, ctx.ctl, ctx.mailer, NOW, TODAY)
        self.assertEqual(users.get(ctx.conn, "ali")["cred_epoch"], 2)
        self.assertEqual(ctx.conn.execute("SELECT COUNT(*) FROM vpn_sessions").fetchone()[0], 0)


class FakeOpenssl(object):
    def __init__(self, eku="TLS Web Client Authentication", subject="subject=CN=example-vpn"):
        self.eku = eku
        self.subject = subject
        self.calls = []

    def __call__(self, argv, cwd=None):
        self.calls.append((argv, cwd))
        if "extendedKeyUsage" in argv:
            if self.eku is None:
                raise pki.PKIError("no EKU")
            return "X509v3 Extended Key Usage: \n    %s\n" % self.eku
        if "-subject" in argv:
            return self.subject + "\n"
        return ""


def make_pki(server_cn_file="example-vpn"):
    tmp = tempfile.mkdtemp()
    for d in ("issued", "private"):
        os.makedirs(os.path.join(tmp, "pki", d))
    files = {"pki/ca.crt": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
             "pki/issued/ali.crt": "-----BEGIN CERTIFICATE-----\nALI\n-----END CERTIFICATE-----\n",
             "pki/issued/%s.crt" % server_cn_file: "-----BEGIN CERTIFICATE-----\nSRV\n-----END CERTIFICATE-----\n",
             "pki/private/ali.key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
             "tc.key": "-----BEGIN OpenVPN Static key V1-----\nTC\n-----END OpenVPN Static key V1-----\n"}
    for name, content in files.items():
        with open(os.path.join(tmp, name), "w") as fh:
            fh.write(content)
    return helpers.example_config(pki_dir=os.path.join(tmp, "pki"), tls_crypt_key=os.path.join(tmp, "tc.key"))


class EkuTest(unittest.TestCase):
    def test_profile_requires_client_eku_and_pins_server(self):
        cfg = make_pki()
        text = pki.build_ovpn(cfg, "ali", pki.EasyRSA(cfg, run=FakeOpenssl()))
        self.assertIn("\nverify-x509-name example-vpn name\n", text)
        with self.assertRaises(pki.PKIError):
            pki.build_ovpn(cfg, "ali", pki.EasyRSA(cfg, run=FakeOpenssl(eku="TLS Web Server Authentication")))
        with self.assertRaises(pki.PKIError):
            pki.build_ovpn(cfg, "ali", pki.EasyRSA(cfg, run=FakeOpenssl(eku=None)))

    def test_server_cn_taken_from_certificate_and_quoted(self):
        cfg = make_pki()
        rsa = pki.EasyRSA(cfg, run=FakeOpenssl(subject="subject=O=Example,CN=Example VPN Server"))
        self.assertIn('\nverify-x509-name "Example VPN Server" name\n', pki.build_ovpn(cfg, "ali", rsa))

    def test_issue_cert_checks_eku(self):
        cfg = make_pki()

        class Runner(FakeOpenssl):
            def __call__(self, argv, cwd=None):
                if "build-client-full" in argv:
                    self.calls.append((argv, cwd))
                    with open(os.path.join(cfg.pki_dir, "issued", "veli.crt"), "w") as fh:
                        fh.write("x")
                    return ""
                return FakeOpenssl.__call__(self, argv, cwd)

        runner = Runner(eku="TLS Web Server Authentication")
        with self.assertRaises(pki.PKIError):
            pki.EasyRSA(cfg, run=runner).build_client("veli")
        self.assertEqual(runner.calls[0][1], cfg.pki_dir)    # Easy-RSA runs from the PKI dir

    def test_default_runner_minimal_env_and_cwd(self):
        tmp = os.path.realpath(tempfile.mkdtemp())
        os.environ["DBOVPN_TEST_LEAK"] = "1"
        try:
            out = pki.default_runner(["/usr/bin/env"], cwd=tmp)
        finally:
            del os.environ["DBOVPN_TEST_LEAK"]
        names = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
        self.assertNotIn("DBOVPN_TEST_LEAK", names)
        self.assertIn("PATH", names)
        self.assertEqual(os.path.realpath(pki.default_runner(["/bin/pwd"], cwd=tmp).strip()), tmp)


class ProvisionHelpersTest(unittest.TestCase):
    def test_parse_openssl_date(self):
        self.assertEqual(provision.parse_openssl_date("notAfter=Oct  7 12:00:00 2029 GMT\n"),
                         datetime.datetime(2029, 10, 7, 12, 0, 0))
        self.assertIsNone(provision.parse_openssl_date("garbage"))

    def test_semanage_listing(self):
        listing = ("http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000\n"
                   "http_port_t                    udp      80, 443\n"
                   "other_port_t                   tcp      8471\n"
                   "range_port_t                   tcp      8000-8100\n")
        self.assertTrue(provision.port_in_semanage_list(listing, "http_port_t", 8443))
        self.assertFalse(provision.port_in_semanage_list(listing, "http_port_t", 8471))
        self.assertTrue(provision.port_in_semanage_list(listing, "range_port_t", 8050))

    def test_selinux_label_add_then_modify(self):
        calls = []

        def run(argv, check=True, quiet=False):
            calls.append(argv)
            if argv[0].endswith("getenforce"):
                return 0, "Enforcing\n"
            if argv[1:3] == ["port", "-l"]:
                return 0, "other_port_t tcp 8471\n"
            if "-a" in argv:
                return 1, "ValueError: Port tcp/8471 already defined"
            return 0, ""
        cfg = helpers.example_config()
        self.assertTrue(provision.allow_panel_port_selinux(cfg, run=run, log=lambda m: None))
        self.assertIn(["/usr/sbin/semanage", "port", "-m", "-t", "http_port_t", "-p", "tcp", "8471"], calls)
        self.assertFalse(any("setsebool" in " ".join(c) for c in calls))


class FakeHost(object):
    """systemctl, sshd -T and firewall-offline-cmd for ensure_firewalld_running."""

    def __init__(self, active=False, ssh_port="9822", zone_services=("ssh",), zone_ports=(), default_zone="public",
                 sshd_ok=True):
        self.active = active
        self.ssh_port = ssh_port
        self.services = set(zone_services)
        self.ports = set(zone_ports)
        self.default_zone = default_zone
        self.sshd_ok = sshd_ok
        self.calls = []

    def __call__(self, argv, check=True, quiet=False):
        self.calls.append(argv)
        cmd = os.path.basename(argv[0])
        if cmd == "systemctl":
            return (0 if self.active else 3), ""
        if cmd == "sshd":
            return (0, "port %s\naddressfamily any\n" % self.ssh_port) if self.sshd_ok else (255, "error")
        if cmd == "firewall-offline-cmd":
            a = argv[-1]
            if a == "--get-default-zone":
                return 0, self.default_zone + "\n"
            if a == "--info-service=ssh":
                return 0, "ssh\n  ports: 22/tcp\n  protocols:\n"
            if a.startswith("--query-service="):
                return (0 if a.split("=")[1] in self.services else 1), ""
            if a.startswith("--query-port="):
                return (0 if (argv[1], a.split("=")[1]) in self.ports else 1), ""
            if a.startswith("--add-port="):
                self.ports.add((argv[1], a.split("=")[1]))
                return 0, ""
        raise AssertionError(argv)


class FirewalldStartTest(unittest.TestCase):
    def test_running_firewalld_untouched(self):
        host = FakeHost(active=True)
        self.assertFalse(provision.ensure_firewalld_running(helpers.example_config(), run=host, log=lambda m: None))
        self.assertEqual(len(host.calls), 1)

    def test_non_default_ssh_port_opened_before_start(self):
        host = FakeHost(ssh_port="9822")
        log = []
        self.assertTrue(provision.ensure_firewalld_running(helpers.example_config(), run=host, log=log.append))
        self.assertIn(("--zone=public", "9822/tcp"), host.ports)
        add = host.calls.index(["/usr/bin/firewall-offline-cmd", "--zone=public", "--add-port=9822/tcp"])
        start = host.calls.index(["/usr/bin/systemctl", "enable", "--now", "firewalld.service"])
        self.assertLess(add, start)
        self.assertTrue(any("9822" in m for m in log))
        self.assertFalse(any("--remove" in " ".join(c) for c in host.calls))

    def test_port_22_covered_by_ssh_service(self):
        host = FakeHost(ssh_port="22")
        provision.ensure_firewalld_running(helpers.example_config(), run=host, log=lambda m: None)
        self.assertFalse(any(c[-1].startswith("--add-port") for c in host.calls))

    def test_default_zone_also_opened(self):
        host = FakeHost(default_zone="drop-ish")
        provision.ensure_firewalld_running(helpers.example_config(), run=host, log=lambda m: None)
        self.assertIn(["/usr/bin/firewall-offline-cmd", "--zone=drop-ish", "--add-port=9822/tcp"], host.calls)

    def test_unknown_ssh_port_refuses_to_start(self):
        host = FakeHost(sshd_ok=False)
        with self.assertRaises(RuntimeError):
            provision.ensure_firewalld_running(helpers.example_config(), run=host, log=lambda m: None)
        self.assertFalse(any(c[:2] == ["/usr/bin/systemctl", "enable"] for c in host.calls))


class NginxTemplateTest(unittest.TestCase):
    def test_host_header_and_rate_limit_status(self):
        text = provision.render("nginx-site.conf", provision.nginx_values(helpers.example_config()))
        self.assertIn("proxy_set_header Host $http_host;", text)
        self.assertNotIn("proxy_set_header Host $host;", text)
        enroll = text[text.index("location /enroll/"):text.index("location /static/")]
        self.assertIn("limit_req_status 429;", enroll)
        self.assertIn("access_log off;", enroll)
        self.assertIn("error_log /var/log/nginx/error.log crit;", enroll)
        admin = text[text.index("location /admin-enroll/"):]
        self.assertIn("error_log /var/log/nginx/error.log crit;", admin)

    def test_gunicorn_timeout(self):
        with open(os.path.join(helpers.ROOT, "systemd", "dbo-vpn-gateway-web.service")) as fh:
            self.assertIn("--timeout 190", fh.read())


class AuditLabelTest(unittest.TestCase):
    def test_every_audit_action_has_a_label(self):
        codes = set()
        for path in glob.glob(os.path.join(helpers.ROOT, "dbovpn", "**", "*.py"), recursive=True):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            codes |= set(re.findall(r'audit\([^)]*?"((?:admin|cert|enroll|firewall|mail|profile|session|token|user|vpn)'
                                    r'\.[a-z_0-9]+)"', text, re.S))
            codes |= set(re.findall(r'"(vpn\.[a-z_]+)"', text))
        codes |= {"mail.expiry_7d", "mail.expiry_0d", "mail.cert_short"}
        self.assertGreater(len(codes), 30)
        for lang in ("en", "tr"):
            strings = i18n.strings(lang)
            missing = sorted(c for c in codes if "act_" + c.replace(".", "_") not in strings)
            self.assertEqual(missing, [], lang)


if __name__ == "__main__":
    unittest.main()


class LockUiTest(unittest.TestCase):
    """Round 2: lock visibility, unlock action, translated audit details."""

    def test_unlock_clears_lock_only(self):
        ctx = helpers.context()
        helpers.add_user(ctx, "ali")
        ctx.conn.execute("UPDATE vpn_users SET failed_logins = 3, locked_until = ?", (NOW + 600,))
        before = users.get(ctx.conn, "ali")
        self.assertTrue(users.is_locked(before, NOW))
        self.assertEqual([r["username"] for r in users.locked_users(ctx.conn, NOW)], ["ali"])
        users.unlock_user(ctx, "ali")
        after = users.get(ctx.conn, "ali")
        self.assertFalse(users.is_locked(after, NOW))
        self.assertEqual(after["failed_logins"], 0)
        for col in ("password_hash", "totp_secret", "cred_epoch", "enabled"):
            self.assertEqual(after[col], before[col], col)
        self.assertEqual(users.locked_users(ctx.conn, NOW), [])
        actions = [r[0] for r in ctx.conn.execute("SELECT action FROM audit ORDER BY id")]
        self.assertEqual(actions[-1], "user.unlock")
        self.assertEqual(ctx.ctl.kicked, [])

    def test_lock_expires_by_itself(self):
        row = {"locked_until": NOW + 10}
        self.assertTrue(users.is_locked(row, NOW))
        self.assertFalse(users.is_locked(row, NOW + 10))

    def test_detail_translation(self):
        self.assertEqual(i18n.detail_label("tr", "wrong password"), "hatalı parola")
        self.assertEqual(i18n.detail_label("tr", "wrong password; account locked"), "hatalı parola; hesap kilitlendi")
        self.assertEqual(i18n.detail_label("tr", "sweep: user disabled"), "periyodik kontrol: kullanıcı devre dışı")
        self.assertEqual(i18n.detail_label("tr", "renegotiation denied: odd thing"), "yenileme reddedildi: odd thing")
        self.assertEqual(i18n.detail_label("en", "locked after repeated failures"), "locked after repeated failures")
        self.assertEqual(i18n.detail_label("tr", "profile=app ip=10.8.0.2"), "profile=app ip=10.8.0.2")
        self.assertEqual(i18n.detail_label("tr", ""), "")
        self.assertEqual(i18n.action_label("tr", "user.unlock"), "Giriş kilidi kaldırıldı")
        self.assertEqual(i18n.action_label("tr", "made.up"), "made.up")

    def test_known_vpn_failure_reasons_are_translated(self):
        src = ""
        for name in ("mgmt/auth.py", "users.py", "admins.py"):
            with open(os.path.join(helpers.ROOT, "dbovpn", name), encoding="utf-8") as fh:
                src += fh.read()
        phrases = set(re.findall(r'_(?:deny|fail)\(event, (?:conn, cfg, row, now, )?"([^"%]+)"', src))
        phrases |= set(re.findall(r'return "((?:user|unknown) [a-z ]+)"', src))
        self.assertGreater(len(phrases), 8)
        for p in phrases:
            self.assertNotEqual(i18n.detail_label("tr", p), p, p)
