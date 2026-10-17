"""Shared fixtures: the example config, an in-memory database and fakes for
the root helper, the management daemon and the mail relay."""

import datetime
import os

from dbovpn import config as config_mod
from dbovpn import db, users

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "conf", "gateway.conf.example")
TODAY = datetime.date(2026, 10, 17)
NOW = 1792224000  # a fixed epoch second, only used where the day does not matter


def example_text():
    with open(EXAMPLE, "r", encoding="utf-8") as fh:
        return fh.read()


def example_config(**overrides):
    text = example_text()
    for key, value in overrides.items():
        lines = []
        for line in text.splitlines():
            if line.split("=")[0].strip().lstrip("#").strip() == key:
                line = "%s = %s" % (key, value)
            lines.append(line)
        text = "\n".join(lines) + "\n"
    return config_mod.parse(text, EXAMPLE)


def memory_db():
    return db.connect(":memory:")


def fake_hash(password):
    return "fake$" + password


def fake_verify(stored, password):
    return stored == "fake$" + password


class FakePriv(object):
    def __init__(self, fail=None, cert_end="2028-01-31", renewed_end="2028-06-30", key_encrypted=False):
        self.calls = []
        self.fail = fail or set()
        self.cert_end = cert_end
        self.renewed_end = renewed_end
        self.key_encrypted = key_encrypted

    def cert_info(self, u):
        # Not recorded in calls: it is a read, called after most changes.
        if "cert_info" in self.fail:
            from dbovpn.privclient import PrivError
            raise PrivError("cert_info failed (fake)")
        return {"not_after": self.cert_end, "key_encrypted": self.key_encrypted, "client_eku": True}

    def renew_cert(self, u):
        self._call("renew_cert", u)
        self.cert_end = self.renewed_end
        self.key_encrypted = False

    def _call(self, name, *args):
        self.calls.append((name,) + args)
        if name in self.fail:
            from dbovpn.privclient import PrivError
            raise PrivError("%s failed (fake)" % name)

    def issue_cert(self, u):
        self._call("issue_cert", u)

    def revoke_cert(self, u):
        self._call("revoke_cert", u)

    def build_ovpn(self, u):
        self._call("build_ovpn", u)
        return "client\n"

    def ipset_add(self, p, ip):
        self._call("ipset_add", p, ip)

    def ipset_del(self, p, ip):
        self._call("ipset_del", p, ip)


class FakeCtl(object):
    def __init__(self, down=False):
        self.kicked = []
        self.down = down

    def kick(self, username):
        if self.down:
            from dbovpn.ctl import CtlError
            raise CtlError("down (fake)")
        self.kicked.append(username)
        return 1

    def list_sessions(self):
        return []


class FakeMailer(object):
    def __init__(self, ok=True):
        self.sent = []
        self.ok = ok

    def send_template(self, recipients, name, values, language=None):
        self.sent.append((recipients, name, values))
        return (True, "") if self.ok else (False, "relay refused (fake)")


def context(cfg=None, conn=None, today=TODAY, priv=None, ctl=None, mailer=None, clock=None):
    cfg = cfg or example_config()
    conn = conn or memory_db()
    return users.Context(cfg, conn, "admin:test", "192.0.2.1", priv or FakePriv(), ctl or FakeCtl(),
                         mailer or FakeMailer(), clock=clock or (lambda: NOW), today=today)


def add_user(ctx, name, days=30, enabled=True, enrolled=True, secret="JBSWY3DPEHPK3PXP"):
    users.create_user(ctx, name, name.title(), "%s@example.com" % name,
                      (ctx.today() + datetime.timedelta(days=days)).isoformat())
    if enrolled:
        ctx.conn.execute("UPDATE vpn_users SET password_hash = ?, totp_secret = ? WHERE username = ?",
                         (fake_hash("correct horse battery"), secret, name))
    if not enabled:
        ctx.conn.execute("UPDATE vpn_users SET enabled = 0 WHERE username = ?", (name,))
    return users.get(ctx.conn, name)
