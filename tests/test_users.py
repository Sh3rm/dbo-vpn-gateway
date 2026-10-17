"""Cap counting, expiry rules, fixed addresses, and the actions' side effects."""

import datetime
import unittest

from dbovpn import users
from dbovpn.users import ServiceError
from tests import helpers
from tests.helpers import TODAY


class CapTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context(helpers.example_config(max_users="3"))

    def test_every_row_counts_and_cap_refuses(self):
        helpers.add_user(self.ctx, "enabled1")
        helpers.add_user(self.ctx, "disabled1", enabled=False)
        helpers.add_user(self.ctx, "expired1")
        self.ctx.conn.execute("UPDATE vpn_users SET expires_on = '2026-01-01' WHERE username = 'expired1'")
        self.assertEqual(users.count(self.ctx.conn), 3)
        with self.assertRaises(ServiceError) as cm:
            helpers.add_user(self.ctx, "fourth")
        self.assertEqual(cm.exception.key, "cap_reached")
        self.assertIsNone(users.get(self.ctx.conn, "fourth"))
        audit = self.ctx.conn.execute("SELECT action FROM audit WHERE target = 'fourth'").fetchall()
        self.assertEqual([r[0] for r in audit], ["user.create_refused"])

    def test_disable_does_not_free_a_slot_but_delete_does(self):
        for n in ("a1", "a2", "a3"):
            helpers.add_user(self.ctx, n)
        users.set_enabled(self.ctx, "a1", False)
        with self.assertRaises(ServiceError):
            helpers.add_user(self.ctx, "a4")
        users.delete_user(self.ctx, "a1")
        helpers.add_user(self.ctx, "a4")
        self.assertEqual(users.count(self.ctx.conn), 3)

    def test_admins_do_not_count(self):
        from dbovpn import admins
        admins.add(self.ctx, "boss", "Boss", "boss@example.com", "en")
        for n in ("a1", "a2", "a3"):
            helpers.add_user(self.ctx, n)
        self.assertEqual(users.count(self.ctx.conn), 3)


class ExpiryTest(unittest.TestCase):
    def setUp(self):
        self.cfg = helpers.example_config()

    def test_bounds(self):
        self.assertEqual(users.default_expiry(self.cfg, TODAY), TODAY + datetime.timedelta(days=90))
        users.validate_expiry(self.cfg, TODAY, TODAY)
        users.validate_expiry(self.cfg, TODAY + datetime.timedelta(days=365), TODAY)
        for bad in (TODAY - datetime.timedelta(days=1), TODAY + datetime.timedelta(days=366)):
            with self.assertRaises(ServiceError) as cm:
                users.validate_expiry(self.cfg, bad, TODAY)
            self.assertEqual(cm.exception.key, "expiry_out_of_range")
        with self.assertRaises(ServiceError):
            users.validate_expiry(self.cfg, "17.10.2026", TODAY)

    def test_last_valid_day_semantics(self):
        row = {"enabled": 1, "expires_on": TODAY.isoformat(), "password_hash": "x", "totp_secret": "y"}
        self.assertEqual(users.status(row, TODAY), "active")
        self.assertEqual(users.status(row, TODAY + datetime.timedelta(days=1)), "expired")
        self.assertEqual(users.login_refusal(row, TODAY + datetime.timedelta(days=1)), "user expired")

    def test_status_order(self):
        base = {"enabled": 1, "expires_on": "2027-01-01", "password_hash": None, "totp_secret": None}
        self.assertEqual(users.status(base, TODAY), "pending")
        self.assertEqual(users.status(dict(base, enabled=0), TODAY), "disabled")
        self.assertEqual(users.status(dict(base, expires_on="2026-01-01"), TODAY), "expired")

    def test_extend_resets_expiry_flag_and_keeps_certificate(self):
        ctx = helpers.context()
        helpers.add_user(ctx, "ali")
        ctx.conn.execute("UPDATE vpn_users SET expiry_handled = 1 WHERE username = 'ali'")
        ctx.priv.calls = []
        users.set_expiry(ctx, "ali", (TODAY + datetime.timedelta(days=200)).isoformat())
        row = users.get(ctx.conn, "ali")
        self.assertEqual(row["expiry_handled"], 0)
        self.assertEqual(ctx.priv.calls, [])


class ActionTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context()

    def test_create_issues_cert_assigns_ip_and_profile(self):
        row, raw, mail_ok = users.create_user(self.ctx, "ali.veli", "Ali Veli", "ali@example.com",
                                              (TODAY + datetime.timedelta(days=90)).isoformat())
        self.assertEqual(row["vpn_ip"], "10.8.0.2")
        self.assertEqual(row["profile"], "app")
        self.assertTrue(mail_ok)
        self.assertEqual(self.ctx.priv.calls, [("issue_cert", "ali.veli"), ("ipset_add", "app", "10.8.0.2")])
        self.assertGreaterEqual(len(raw), 43)
        self.assertIn(raw, self.ctx.mailer.sent[0][2]["link"])

    def test_ip_allocation_skips_used_and_reuses_freed(self):
        helpers.add_user(self.ctx, "u1")
        helpers.add_user(self.ctx, "u2")
        users.delete_user(self.ctx, "u1")
        self.assertEqual(helpers.add_user(self.ctx, "u3")["vpn_ip"], "10.8.0.2")

    def test_cert_failure_rolls_back(self):
        ctx = helpers.context(priv=helpers.FakePriv(fail={"issue_cert"}))
        with self.assertRaises(ServiceError) as cm:
            helpers.add_user(ctx, "ali")
        self.assertEqual(cm.exception.key, "cert_failed")
        self.assertEqual(users.count(ctx.conn), 0)

    def test_mail_failure_does_not_block(self):
        ctx = helpers.context(mailer=helpers.FakeMailer(ok=False))
        row, raw, mail_ok = users.create_user(ctx, "ali", "Ali", "ali@example.com", TODAY.isoformat())
        self.assertFalse(mail_ok)
        actions = [r[0] for r in ctx.conn.execute("SELECT action FROM audit ORDER BY id")]
        self.assertIn("mail.failed", actions)
        self.assertIn("user.create", actions)

    def test_disable_kicks_without_cert_change(self):
        helpers.add_user(self.ctx, "ali")
        self.ctx.priv.calls = []
        users.set_enabled(self.ctx, "ali", False)
        self.assertEqual(self.ctx.ctl.kicked, ["ali"])
        self.assertEqual(self.ctx.priv.calls, [])
        users.set_enabled(self.ctx, "ali", True)
        self.assertEqual(self.ctx.priv.calls, [])

    def test_delete_revokes_kicks_and_keeps_audit(self):
        helpers.add_user(self.ctx, "ali")
        users.delete_user(self.ctx, "ali")
        self.assertIn(("revoke_cert", "ali"), self.ctx.priv.calls)
        self.assertIn(("ipset_del", "app", "10.8.0.2"), self.ctx.priv.calls)
        self.assertEqual(self.ctx.ctl.kicked, ["ali"])
        self.assertIsNone(users.get(self.ctx.conn, "ali"))
        actions = [r[0] for r in self.ctx.conn.execute("SELECT action FROM audit WHERE target='ali' ORDER BY id")]
        self.assertEqual(actions[-1], "user.delete")
        self.assertIn("user.create", actions)

    def test_delete_refused_when_revoke_fails(self):
        helpers.add_user(self.ctx, "ali")
        self.ctx.priv.fail = {"revoke_cert"}
        with self.assertRaises(ServiceError):
            users.delete_user(self.ctx, "ali")
        self.assertIsNotNone(users.get(self.ctx.conn, "ali"))

    def test_kick_failure_is_audited_not_raised(self):
        ctx = helpers.context(ctl=helpers.FakeCtl(down=True))
        helpers.add_user(ctx, "ali")
        users.set_enabled(ctx, "ali", False)
        actions = [r[0] for r in ctx.conn.execute("SELECT action FROM audit ORDER BY id")]
        self.assertIn("session.kick_failed", actions)

    def test_reset_clears_credentials(self):
        helpers.add_user(self.ctx, "ali")
        raw, _ = users.reset_user(self.ctx, "ali")
        row = users.get(self.ctx.conn, "ali")
        self.assertIsNone(row["password_hash"])
        self.assertEqual(users.status(row, TODAY), "pending")
        self.assertEqual(self.ctx.ctl.kicked, ["ali"])

    def test_validation(self):
        for bad in ("A", "x", "-ali", "ali veli", "ali/../x", "a" * 65, "ali;rm"):
            with self.assertRaises(ServiceError, msg=bad):
                users.create_user(self.ctx, bad, "Name", "a@example.com", TODAY.isoformat())
        with self.assertRaises(ServiceError):
            users.create_user(self.ctx, "ali", "Name", "not-an-email", TODAY.isoformat())
        with self.assertRaises(ServiceError):
            users.create_user(self.ctx, "ali", "<script>", "a@example.com", TODAY.isoformat())
        with self.assertRaises(ServiceError):
            users.create_user(self.ctx, "example-vpn", "Server", "a@example.com", TODAY.isoformat())

    def test_adopt_ignores_cap_and_keeps_existing(self):
        cfg = helpers.example_config(max_users="1")
        ctx = helpers.context(cfg)
        helpers.add_user(ctx, "first")
        self.assertTrue(users.adopt(ctx.conn, cfg, "legacy", "cli:setup", helpers.NOW, TODAY))
        self.assertFalse(users.adopt(ctx.conn, cfg, "legacy", "cli:setup", helpers.NOW, TODAY))
        row = users.get(ctx.conn, "legacy")
        self.assertEqual(users.status(row, TODAY), "pending")
        self.assertEqual(users.count(ctx.conn), 2)


if __name__ == "__main__":
    unittest.main()
