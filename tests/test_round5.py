"""Release 1.0.3: README, mail display name, translated audit details, traffic
sizes, waiting for killed sessions, doctor label."""

import datetime
import glob
import os
import re
import unittest
from email import message_from_bytes, policy
from email.message import EmailMessage

import dbovpn
from dbovpn import db, mailer, users
from dbovpn.ctl import CtlError
from dbovpn.textutil import human_size
from dbovpn.web import i18n
from tests import helpers
from tests.helpers import TODAY


def read(rel):
    with open(os.path.join(helpers.ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class ReadmeTest(unittest.TestCase):
    def test_example_config_in_readme_is_the_shipped_file(self):
        text = read("README.md")
        block = re.search(r"<!-- gateway.conf.example begin -->\n```ini\n(.*?)```\n<!-- gateway.conf.example end -->",
                          text, re.S)
        self.assertIsNotNone(block)
        self.assertEqual(block.group(1), read("conf/gateway.conf.example"))

    def test_reboot_warning_after_install(self):
        text = read("README.md")
        self.assertLess(text.index("dnf -y install"), text.index("Do not reboot"))
        self.assertLess(text.index("Do not reboot"), text.index("dbo-vpn-gateway setup --apply"))

    def test_versions_agree(self):
        spec = read("dbo-vpn-gateway.spec")
        version = re.search(r"^Version:\s+(\S+)", spec, re.M).group(1)
        self.assertEqual(version, dbovpn.__version__)
        self.assertIn("Sh3rm - %s-1" % version, spec.split("%changelog", 1)[1].splitlines()[1])
        urls = re.findall(r"releases/download/v([0-9.]+)/dbo-vpn-gateway-([0-9.]+)-1", read("README.md"))
        self.assertTrue(urls)
        self.assertTrue(all(a == b == version for a, b in urls), urls)


class SenderNameTest(unittest.TestCase):
    def test_default_and_custom(self):
        self.assertEqual(helpers.example_config().sender_name, "Example Corp VPN")
        cfg = helpers.example_config(customer_name="Örnek Yapı")
        self.assertEqual(cfg.sender_name, "Örnek Yapı VPN")
        self.assertEqual(helpers.example_config(sender_name="Destek").sender_name, "Destek")

    def test_non_ascii_name_is_rfc2047_and_round_trips(self):
        cfg = helpers.example_config(customer_name="Örnek Yapı")
        msg = EmailMessage()
        msg["From"] = mailer.from_header(cfg)
        msg["To"] = "a@example.com"
        msg["Subject"] = "x"
        msg.set_content("y")
        raw = msg.as_bytes()
        from_line = [l for l in raw.split(b"\n") if l.startswith(b"From:")][0]
        from_line.decode("ascii")                     # header is pure ASCII
        self.assertIn(b"=?utf-8?", from_line)
        self.assertIn(b"<vpn@example.com>", from_line)
        parsed = message_from_bytes(raw, policy=policy.default)["From"]
        self.assertEqual(parsed.addresses[0].display_name, "Örnek Yapı VPN")
        self.assertEqual(parsed.addresses[0].addr_spec, "vpn@example.com")


class AuditDetailTest(unittest.TestCase):
    def test_structured_details_render_in_both_languages(self):
        kick = db.detail("kick", reason_code="disabled", n=1)
        self.assertEqual(i18n.detail_label("tr", kick), "kullanıcı devre dışı bırakıldı, 1 oturum kapatıldı")
        self.assertEqual(i18n.detail_label("en", kick), "user disabled, 1 session(s) closed")
        login = db.detail("login", via_code="password_totp", ip="10.8.0.2")
        self.assertEqual(i18n.detail_label("tr", login), "parola + kod ile, VPN IP: 10.8.0.2")
        created = db.detail("user_created", profile="app", ip="10.8.0.2", expires_on="2027-01-15", email="a@example.com")
        self.assertEqual(i18n.detail_label("tr", created),
                         "profil: app, VPN IP: 10.8.0.2, son geçerli gün: 2027-01-15, e-posta: a@example.com")
        mail = db.detail("mail_to", email="a@example.com")
        self.assertEqual(i18n.detail_label("tr", mail), "alıcı: a@example.com")
        sweep = db.detail("kick_reason", reason_code="sweep", why="user disabled")
        self.assertEqual(i18n.detail_label("tr", sweep), "periyodik kontrol: kullanıcı devre dışı")

    def test_title_keeps_raw_key_and_legacy_rows_stay_raw(self):
        kick = db.detail("kick", reason_code="disabled", n=1)
        title = i18n.detail_title(kick)
        self.assertIn("kick", title)
        self.assertIn("reason_code=disabled", title)
        self.assertEqual(i18n.detail_label("tr", "via password+totp, vpn_ip=10.8.0.2"), "via password+totp, vpn_ip=10.8.0.2")
        self.assertEqual(i18n.detail_title("disabled (1 session)"), "disabled (1 session)")
        self.assertEqual(i18n.detail_label("tr", "wrong password"), "hatalı parola")
        self.assertEqual(i18n.detail_label("tr", "@{broken json"), "@{broken json")
        self.assertEqual(i18n.detail_label("en", db.detail("no_such_key", a=1)), "no_such_key a=1")

    def test_every_detail_key_and_code_in_code_is_translated(self):
        keys, codes = set(), set()
        for path in glob.glob(os.path.join(helpers.ROOT, "dbovpn", "**", "*.py"), recursive=True):
            text = read(os.path.relpath(path, helpers.ROOT))
            keys |= set(re.findall(r'db\.detail\("([a-z_]+)"', text))
            codes |= set(re.findall(r'_code="([a-z_0-9]+)"', text))
        keys |= {"account_vpn", "account_panel"}                       # via enroll.ACCOUNT_KIND
        codes |= {"setup_link", "admin_setup_link", "expiry_7d", "expiry_0d", "cert_short",   # mail templates
                  "password_totp", "auth_token", "disabled", "reset", "deleted", "profile_changed"}
        self.assertGreater(len(keys), 20)
        for lang in ("en", "tr"):
            strings = i18n.strings(lang)
            self.assertEqual(sorted(k for k in keys if "dtl_" + k not in strings), [], lang)
            self.assertEqual(sorted(c for c in codes if "code_" + c not in strings), [], lang)

    def test_actions_write_structured_details(self):
        ctx = helpers.context()
        helpers.add_user(ctx, "ali")
        users.set_enabled(ctx, "ali", False)
        rows = ctx.conn.execute("SELECT action, detail FROM audit WHERE detail != '' ORDER BY id").fetchall()
        self.assertTrue(rows)
        for action, detail in rows:
            self.assertTrue(detail.startswith("@{"), (action, detail))
            self.assertNotEqual(i18n.detail_label("tr", detail), detail)


class TrafficTest(unittest.TestCase):
    def test_human_size(self):
        self.assertEqual(human_size(0), "0.0 KB")
        self.assertEqual(human_size(300), "0.3 KB")
        self.assertEqual(human_size(1048575), "1024.0 KB")
        self.assertEqual(human_size(1048576), "1.0 MB")
        self.assertEqual(human_size(5 * 1048576 + 524288), "5.5 MB")
        self.assertEqual(human_size(None), "0.0 KB")

    def test_labels(self):
        self.assertEqual(i18n.strings("tr")["traffic"], "Kullanıcıdan / Kullanıcıya")
        self.assertEqual(i18n.strings("en")["traffic"], "From user / To user")

    def test_direction(self):
        # OpenVPN status 3 columns are from the server's view: Bytes Received = from the user.
        from dbovpn.mgmt import protocol
        s = protocol.session_summary({"Bytes Received": "100", "Bytes Sent": "200"})
        self.assertEqual((s["bytes_in"], s["bytes_out"]), (100, 200))
        tpl = read("dbovpn/web/templates/sessions.html")
        self.assertIn("{{ s.bytes_in|size }} / {{ s.bytes_out|size }}", tpl)


class WaitGoneTest(unittest.TestCase):
    class Ctl(object):
        def __init__(self, polls_until_gone=None, error=False):
            self.calls = 0
            self.polls = polls_until_gone
            self.error = error

        def list_sessions(self):
            self.calls += 1
            if self.error:
                raise CtlError("down")
            if self.polls is not None and self.calls > self.polls:
                return [{"common_name": "other"}]
            return [{"common_name": "ali"}, {"common_name": "other"}]

    def clock(self):
        t = [0.0]

        def now():
            return t[0]

        def sleep(s):
            t[0] += s
        return now, sleep

    def test_returns_when_gone(self):
        now, sleep = self.clock()
        ctl = self.Ctl(polls_until_gone=2)
        self.assertTrue(users.wait_sessions_gone(ctl, "ali", sleep=sleep, clock=now))
        self.assertEqual(ctl.calls, 3)

    def test_gives_up_after_timeout(self):
        now, sleep = self.clock()
        ctl = self.Ctl()
        self.assertFalse(users.wait_sessions_gone(ctl, "ali", timeout=3.0, sleep=sleep, clock=now))
        self.assertLessEqual(ctl.calls, 14)
        self.assertGreaterEqual(now(), 3.0)

    def test_ctl_down(self):
        now, sleep = self.clock()
        self.assertFalse(users.wait_sessions_gone(self.Ctl(error=True), "ali", sleep=sleep, clock=now))

    def test_used_after_kill_actions(self):
        app = read("dbovpn/web/app.py")
        block = app[app.index('if action == "enable":'):app.index("@app.route(\"/sessions\")")]
        self.assertEqual(block.count("users.wait_sessions_gone(ctl, username)"), 4)


class DoctorLabelTest(unittest.TestCase):
    def test_ipset_check_has_its_own_label(self):
        src = read("dbovpn/provision.py")
        self.assertIn("runtime entries match the database", src)
        body = src[src.index("def doctor(cfg):"):]
        db_try = body[body.index("rep = as_service_user(db_report"):body.index('check(False, "database readable')]
        self.assertNotIn("--get-entries", db_try)


if __name__ == "__main__":
    unittest.main()
