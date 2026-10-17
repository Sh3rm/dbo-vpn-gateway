"""Smoke test of the Flask app. Needs python3-flask and python3-flask-wtf (skipped otherwise)."""

import os
import tempfile
import unittest

try:
    import flask  # noqa: F401
    import flask_wtf  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

from tests import helpers


@unittest.skipUnless(HAVE_FLASK, "python3-flask / python3-flask-wtf not installed")
class WebTest(unittest.TestCase):
    def setUp(self):
        from dbovpn.web.app import create_app
        self.db_path = os.path.join(tempfile.mkdtemp(), "gateway.db")
        self.cfg = helpers.example_config()
        self.app = create_app(self.cfg, priv=helpers.FakePriv(), ctl=helpers.FakeCtl(), mailer=helpers.FakeMailer(),
                              db_path=self.db_path, secret_key=b"k" * 32)
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_panel_requires_login(self):
        r = self.client.get("/", base_url="https://vpn.example.com")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_login_page_and_language(self):
        r = self.client.get("/login?lang=en", base_url="https://vpn.example.com")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Sign in", r.data)
        r = self.client.get("/login?lang=tr", base_url="https://vpn.example.com")
        self.assertIn("Giriş yap".encode("utf-8"), r.data)

    def test_bad_login_is_generic(self):
        r = self.client.post("/login", data={"username": "x", "password": "y", "code": "123456"},
                             base_url="https://vpn.example.com")
        self.assertEqual(r.status_code, 401)

    def test_csrf_failure_is_400_not_500(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        r = self.client.post("/login", data={"username": "x"}, base_url="https://vpn.example.com")
        self.assertEqual(r.status_code, 400)

    def test_exception_log_redacts_token(self):
        import logging
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        self.app.logger.addHandler(handler)

        @self.app.route("/enroll/<raw>/boom")
        def boom(raw):
            raise RuntimeError("x")
        self.app.config["PROPAGATE_EXCEPTIONS"] = False
        self.client.get("/enroll/SECRET-TOKEN/boom", base_url="https://vpn.example.com")
        text = " ".join(r.getMessage() for r in records)
        self.assertIn("/enroll/<redacted>", text)
        self.assertNotIn("SECRET-TOKEN", text)

    def test_redirect_location_is_relative(self):
        r = self.client.get("/", base_url="https://attacker.test:8443")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login")

    def test_invalid_enroll_link(self):
        r = self.client.get("/enroll/nope", base_url="https://vpn.example.com")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
