"""Setup-link lifecycle: hashed storage, TTL, single use, attempt limit, download window."""

import hashlib
import unittest

from dbovpn import enroll, tokens, totp, users
from dbovpn.users import ServiceError
from tests import helpers

NOW = 1792224000


class TokenTest(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context(clock=lambda: NOW)
        self.row, self.raw, _ = users.create_user(self.ctx, "ali", "Ali", "ali@example.com",
                                                  self.ctx.today().isoformat())
        self.conn = self.ctx.conn

    def test_only_hash_is_stored(self):
        stored = [r[0] for r in self.conn.execute("SELECT token_hash FROM setup_tokens")]
        self.assertEqual(stored, [hashlib.sha256(self.raw.encode()).hexdigest()])
        dump = "\n".join(self.conn.iterdump())
        self.assertNotIn(self.raw, dump)

    def test_ttl(self):
        self.assertIsNotNone(tokens.find_open(self.conn, "vpn", self.raw, NOW + 72 * 3600 - 1))
        self.assertIsNone(tokens.find_open(self.conn, "vpn", self.raw, NOW + 72 * 3600))
        self.assertIsNone(tokens.find_open(self.conn, "admin", self.raw, NOW))
        self.assertIsNone(tokens.find_open(self.conn, "vpn", "x" * 200, NOW))

    def test_new_link_invalidates_old(self):
        raw2, _ = users.reset_user(self.ctx, "ali")
        self.assertIsNone(tokens.find_open(self.conn, "vpn", self.raw, NOW))
        self.assertIsNotNone(tokens.find_open(self.conn, "vpn", raw2, NOW))

    def full_flow(self, raw):
        token, subject = enroll.open_token(self.conn, "vpn", raw, NOW)
        nonce = enroll.start(self.conn, token, subject, "a long enough pass", "a long enough pass",
                             helpers.fake_hash, NOW)
        token, subject = enroll.open_token(self.conn, "vpn", raw, NOW)
        code = totp.code_at(token["pending_totp_secret"], NOW)
        enroll.finish(self.conn, "vpn", token, nonce, code, "vpn:ali", "192.0.2.5", NOW)
        return token, code

    def test_complete_flow_single_use(self):
        token, code = self.full_flow(self.raw)
        row = users.get(self.conn, "ali")
        self.assertEqual(row["password_hash"], helpers.fake_hash("a long enough pass"))
        self.assertEqual(row["totp_secret"], token["pending_totp_secret"])
        self.assertEqual(row["totp_last_counter"], NOW // 30)   # proving code cannot be reused for the VPN
        self.assertEqual(users.status(row, self.ctx.today()), "active")
        self.assertEqual(enroll.open_token(self.conn, "vpn", self.raw, NOW), (None, None))
        self.assertIsNotNone(tokens.find_completed(self.conn, "vpn", self.raw, NOW + 60))
        self.assertIsNone(tokens.find_completed(self.conn, "vpn", self.raw, NOW + tokens.DOWNLOAD_WINDOW + 1))
        leftovers = self.conn.execute("SELECT pending_password_hash, pending_totp_secret FROM setup_tokens").fetchone()
        self.assertEqual(tuple(leftovers), (None, None))

    def test_password_policy(self):
        token, subject = enroll.open_token(self.conn, "vpn", self.raw, NOW)
        for pw, confirm, key in (("short", "short", "pw_too_short"), ("a long enough pass", "different one!!", "pw_mismatch"),
                                 ("ali", "ali", "pw_too_short")):
            with self.assertRaises(ServiceError) as cm:
                enroll.start(self.conn, token, subject, pw, confirm, helpers.fake_hash, NOW)
            self.assertEqual(cm.exception.key, key)

    def test_wrong_nonce_and_attempt_limit(self):
        token, subject = enroll.open_token(self.conn, "vpn", self.raw, NOW)
        nonce = enroll.start(self.conn, token, subject, "a long enough pass", "a long enough pass",
                             helpers.fake_hash, NOW)
        token, _ = enroll.open_token(self.conn, "vpn", self.raw, NOW)
        with self.assertRaises(ServiceError) as cm:
            enroll.finish(self.conn, "vpn", token, "other-browser", "123456", "vpn:ali", "", NOW)
        self.assertEqual(cm.exception.key, "enroll_restart")
        for _ in range(tokens.MAX_ATTEMPTS):
            token, _ = enroll.open_token(self.conn, "vpn", self.raw, NOW)
            with self.assertRaises(ServiceError):
                right = int(totp.code_at(token["pending_totp_secret"], NOW))
                enroll.finish(self.conn, "vpn", token, nonce, "%06d" % ((right + 500000) % 1000000), "vpn:ali", "", NOW)
        self.assertEqual(enroll.open_token(self.conn, "vpn", self.raw, NOW), (None, None))

    def test_purge(self):
        self.full_flow(self.raw)
        self.assertEqual(tokens.purge(self.conn, NOW + 60), 0)
        self.assertEqual(tokens.purge(self.conn, NOW + tokens.DOWNLOAD_WINDOW + 1), 1)
        users.reset_user(self.ctx, "ali")
        self.assertEqual(tokens.purge(self.conn, NOW + 72 * 3600), 1)

    def test_deleted_user_token_unusable(self):
        users.delete_user(self.ctx, "ali")
        self.assertEqual(enroll.open_token(self.conn, "vpn", self.raw, NOW), (None, None))


if __name__ == "__main__":
    unittest.main()
