import datetime
import unittest

from dbovpn import admins, jobs, users
from tests import helpers
from tests.helpers import TODAY

NOW = 1792224000


class ExpiryJobTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context()
        admins.add(self.ctx, "boss", "Boss", "boss@example.com", "tr")
        self.ctx.mailer.sent = []
        helpers.add_user(self.ctx, "soon", days=7)
        helpers.add_user(self.ctx, "today", days=0)
        helpers.add_user(self.ctx, "later", days=60)
        helpers.add_user(self.ctx, "gone", days=0)
        self.ctx.conn.execute("UPDATE vpn_users SET expires_on = ? WHERE username = 'gone'",
                              ((TODAY - datetime.timedelta(days=1)).isoformat(),))
        self.ctx.mailer.sent = []
        self.ctx.ctl.kicked = []

    def run_job(self, today=TODAY, now=NOW):
        return jobs.run_expiry(self.ctx.cfg, self.ctx.conn, self.ctx.ctl, self.ctx.mailer, now, today)

    def test_first_run(self):
        r = self.run_job()
        self.assertEqual(r["expired"], 1)
        self.assertEqual(self.ctx.ctl.kicked, ["gone"])
        sent = sorted((name, values["username"]) for _, name, values in self.ctx.mailer.sent)
        self.assertEqual(sent, [("expiry_0d", "gone"), ("expiry_0d", "today"), ("expiry_7d", "soon")])
        self.assertTrue(all(rcpt == ["boss@example.com"] for rcpt, _, _ in self.ctx.mailer.sent))
        self.assertEqual(users.count(self.ctx.conn), 4)     # expired still counts

    def test_reminders_once(self):
        self.run_job()
        self.ctx.mailer.sent = []
        self.ctx.ctl.kicked = []
        r = self.run_job(now=NOW + 3600)
        self.assertEqual((r["expired"], r["mail_7d"], r["mail_0d"]), (0, 0, 0))
        self.assertEqual(self.ctx.ctl.kicked, [])

    def test_extend_rearms(self):
        self.run_job()
        users.set_expiry(self.ctx, "gone", (TODAY + datetime.timedelta(days=3)).isoformat())
        self.ctx.mailer.sent = []
        r = self.run_job()
        self.assertEqual(r["mail_7d"], 1)
        r = self.run_job(today=TODAY + datetime.timedelta(days=4))
        self.assertEqual(r["expired"], 2)    # 'today' and the re-extended 'gone'

    def test_mail_failure_audited(self):
        self.ctx.mailer.ok = False
        r = self.run_job()
        self.assertEqual(r["mail_failed"], 3)
        n = self.ctx.conn.execute("SELECT COUNT(*) FROM audit WHERE action = 'mail.failed'").fetchone()[0]
        self.assertEqual(n, 3)

    def test_purges_tokens(self):
        r = self.run_job(now=NOW + 73 * 3600)
        self.assertGreaterEqual(r["tokens_purged"], 1)
        self.assertEqual(self.ctx.conn.execute("SELECT COUNT(*) FROM setup_tokens").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
