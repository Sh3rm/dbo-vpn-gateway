"""The CONNECT/REAUTH decision, including renegotiation via auth-gen-token."""

import base64
import datetime
import unittest

from dbovpn import totp, users
from dbovpn.mgmt import auth, protocol
from tests import helpers
from tests.helpers import TODAY

SECRET = "JBSWY3DPEHPK3PXP"
NOW = 1792224000


def scrv1(password, code):
    return "SCRV1:%s:%s" % (base64.b64encode(password.encode()).decode(), base64.b64encode(code.encode()).decode())


def event(kind, env, cid=7, kid=0):
    return protocol.ClientEvent(kind, cid, kid, env)


class AuthBase(unittest.TestCase):
    def setUp(self):
        self.ctx = helpers.context()
        helpers.add_user(self.ctx, "ali", secret=SECRET)
        self.cfg = self.ctx.cfg

    def decide(self, ev, now=NOW, today=TODAY):
        return auth.decide(ev, self.ctx.conn, self.cfg, now, today, helpers.fake_verify)

    def env(self, **kw):
        base = {"common_name": "ali", "username": "ali", "session_state": "Initial", "session_id": "SID-1",
                "password": scrv1("correct horse battery", totp.code_at(SECRET, NOW)), "untrusted_ip": "192.0.2.9"}
        base.update(kw)
        return base

    def login(self):
        self.assertTrue(self.decide(event("CONNECT", self.env())).allow)


class AuthTest(AuthBase):
    def test_full_login_pushes_fixed_ip_and_routes(self):
        d = self.decide(event("CONNECT", self.env()))
        self.assertTrue(d.allow, d.reason)
        self.assertEqual(d.lines, ["ifconfig-push 10.8.0.2 255.255.255.0",
                                   'push "route 203.0.113.10 255.255.255.255"',
                                   'push "route 203.0.113.20 255.255.255.255"'])
        self.assertEqual(d.audit_action, "vpn.login")

    def test_totp_replay_rejected(self):
        self.assertTrue(self.decide(event("CONNECT", self.env())).allow)
        d = self.decide(event("CONNECT", self.env(), cid=8))
        self.assertFalse(d.allow)
        self.assertIn("TOTP", d.reason)

    def test_wrong_password_and_code(self):
        self.assertFalse(self.decide(event("CONNECT", self.env(password=scrv1("wrong", totp.code_at(SECRET, NOW))))).allow)
        self.assertFalse(self.decide(event("CONNECT", self.env(password=scrv1("correct horse battery", "000000")))).allow)
        self.assertFalse(self.decide(event("CONNECT", self.env(password="correct horse battery" + totp.code_at(SECRET, NOW)))).allow)
        self.assertFalse(self.decide(event("CONNECT", self.env(password=None))).allow)

    def test_cn_must_equal_username(self):
        d = self.decide(event("CONNECT", self.env(username="other")))
        self.assertFalse(d.allow)
        self.assertFalse(self.decide(event("CONNECT", self.env(common_name="example-vpn", username="example-vpn"))).allow)

    def test_unknown_disabled_expired_not_enrolled(self):
        self.assertFalse(self.decide(event("CONNECT", self.env(common_name="nobody", username="nobody"))).allow)
        users.set_enabled(self.ctx, "ali", False)
        d = self.decide(event("CONNECT", self.env()))
        self.assertFalse(d.allow)
        self.assertEqual(d.client_reason, auth.ACCOUNT_FAILURE)
        users.set_enabled(self.ctx, "ali", True)
        d = self.decide(event("CONNECT", self.env()), today=TODAY + datetime.timedelta(days=31))
        self.assertEqual(d.reason, "user expired")
        self.ctx.conn.execute("UPDATE vpn_users SET totp_secret = NULL")
        self.assertEqual(self.decide(event("CONNECT", self.env())).reason, "user not enrolled")

    def test_reauth_with_valid_token_needs_no_password(self):
        self.login()
        ev = event("REAUTH", self.env(session_state="Authenticated", password="SESS_ID_opaque"), kid=1)
        d = self.decide(ev)
        self.assertTrue(d.allow)
        self.assertEqual(d.lines, [])
        self.assertIsNone(d.audit_action)

    def test_reauth_of_disabled_user_is_denied_and_killed(self):
        self.login()
        users.set_enabled(self.ctx, "ali", False)
        d = self.decide(event("REAUTH", self.env(session_state="Authenticated"), kid=1))
        self.assertFalse(d.allow)
        self.assertTrue(d.kill)
        self.assertEqual(d.audit_action, "vpn.reauth_denied")

    def test_reauth_of_expired_user_is_killed(self):
        self.login()
        d = self.decide(event("REAUTH", self.env(session_state="Authenticated"), kid=1),
                        today=TODAY + datetime.timedelta(days=31))
        self.assertFalse(d.allow)
        self.assertTrue(d.kill)

    def test_bad_token_states_denied(self):
        for state in ("Expired", "Invalid", "AuthenticatedEmptyUser", "ExpiredEmptyUser", "Bogus"):
            d = self.decide(event("REAUTH", self.env(session_state=state), kid=1))
            self.assertFalse(d.allow, state)
            self.assertTrue(d.kill, state)
            d = self.decide(event("CONNECT", self.env(session_state=state)))
            self.assertFalse(d.allow, state)
            self.assertFalse(d.kill, state)

    def test_reconnect_with_token_allowed_and_gets_address(self):
        self.login()
        d = self.decide(event("CONNECT", self.env(session_state="Authenticated", password="SESS_ID_opaque")))
        self.assertTrue(d.allow)
        self.assertTrue(d.lines[0].startswith("ifconfig-push 10.8.0.2 "))

    def test_missing_session_state_means_full_check(self):
        env = self.env()
        del env["session_state"]
        self.assertTrue(self.decide(event("CONNECT", env)).allow)
        env["password"] = "SESS_ID_opaque"
        self.assertFalse(self.decide(event("CONNECT", env, cid=9)).allow)


class TokenEpochTest(AuthBase):
    """Finding 1: a token from before a reset/disable must not work after re-enrolment."""

    def token_event(self, sid="SID-1", kind="CONNECT"):
        return event(kind, self.env(session_state="Authenticated", session_id=sid, password="SESS_ID_x"),
                     kid=1 if kind == "REAUTH" else 0)

    def reenrol(self):
        self.ctx.conn.execute("UPDATE vpn_users SET password_hash = ?, totp_secret = ?, totp_last_counter = 0"
                              " WHERE username = 'ali'", (helpers.fake_hash("correct horse battery"), SECRET))

    def test_unknown_session_id_denied(self):
        self.login()
        self.assertFalse(self.decide(self.token_event("SID-other")).allow)
        env = self.env(session_state="Authenticated", password="SESS_ID_x")
        del env["session_id"]
        self.assertFalse(self.decide(event("CONNECT", env)).allow)

    def test_token_dies_on_reset(self):
        self.login()
        self.assertTrue(self.decide(self.token_event()).allow)
        users.reset_user(self.ctx, "ali")
        self.reenrol()
        self.assertFalse(self.decide(self.token_event()).allow)
        self.assertFalse(self.decide(self.token_event(kind="REAUTH")).allow)

    def test_token_dies_on_disable_then_enable(self):
        self.login()
        users.set_enabled(self.ctx, "ali", False)
        users.set_enabled(self.ctx, "ali", True)
        self.assertFalse(self.decide(self.token_event()).allow)

    def test_token_dies_on_delete_and_recreate(self):
        self.login()
        users.delete_user(self.ctx, "ali")
        helpers.add_user(self.ctx, "ali", secret=SECRET)
        self.assertFalse(self.decide(self.token_event()).allow)

    def test_new_login_records_new_session(self):
        self.login()
        users.reset_user(self.ctx, "ali")
        self.reenrol()
        env = self.env(session_id="SID-2", password=scrv1("correct horse battery", totp.code_at(SECRET, NOW + 30)))
        self.assertTrue(self.decide(event("CONNECT", env), now=NOW + 30).allow)
        self.assertTrue(self.decide(self.token_event("SID-2")).allow)


class VpnLockoutTest(AuthBase):
    """Finding 2: failed password/TOTP attempts lock the VPN account."""

    def bad(self, n, now=NOW):
        for _ in range(n):
            d = self.decide(event("CONNECT", self.env(password=scrv1("wrong", "000000"))), now=now)
            self.assertFalse(d.allow)
        return d

    def test_lock_after_five_and_audit(self):
        d = self.bad(5)
        self.assertIn("locked", d.reason)
        n = self.ctx.conn.execute("SELECT COUNT(*) FROM audit WHERE action = 'vpn.locked'").fetchone()[0]
        self.assertEqual(n, 1)
        d = self.decide(event("CONNECT", self.env()))      # right credentials, still locked
        self.assertFalse(d.allow)
        self.assertIn("locked", d.reason)
        later = NOW + 15 * 60 + 1
        env = self.env(password=scrv1("correct horse battery", totp.code_at(SECRET, later)))
        self.assertTrue(self.decide(event("CONNECT", env), now=later).allow)

    def test_success_resets_counter(self):
        self.bad(4)
        self.assertTrue(self.decide(event("CONNECT", self.env())).allow)
        self.assertEqual(users.get(self.ctx.conn, "ali")["failed_logins"], 0)

    def test_enable_clears_lock(self):
        self.bad(5)
        users.set_enabled(self.ctx, "ali", True)
        self.assertTrue(self.decide(event("CONNECT", self.env())).allow)


if __name__ == "__main__":
    unittest.main()
