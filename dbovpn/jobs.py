"""Hourly expiry job (dbo-vpn-gateway-expiry.timer, runs as dbovpn).

- Accounts past their last valid day are marked handled, kicked and audited
  (the management daemon already refuses them at login and renegotiation).
- Admins are mailed once 7 days before the last valid day and once on it.
- Used and expired setup tokens are purged.
"""

import datetime
import logging
import sys
import time

from dbovpn import config as config_mod
from dbovpn import db, tokens, users
from dbovpn.ctl import CtlError, SessionControl
from dbovpn.mailer import Mailer

log = logging.getLogger("dbovpn.jobs")
ACTOR = "system:expiry"


def admin_recipients(conn):
    return [r["email"] for r in conn.execute(
        "SELECT email FROM admins WHERE enabled = 1 AND email != '' ORDER BY username")]


def run_expiry(cfg, conn, ctl, mailer, now=None, today=None):
    """One pass. Returns a dict of counts (for logs and tests)."""
    now = int(now if now is not None else time.time())
    today = today or datetime.date.fromtimestamp(now)
    result = {"expired": 0, "kicked": 0, "mail_7d": 0, "mail_0d": 0, "mail_failed": 0, "tokens_purged": 0,
              "cert_short": 0}

    for row in conn.execute("SELECT * FROM vpn_users WHERE expiry_handled = 0 AND expires_on < ?",
                            (today.isoformat(),)).fetchall():
        with db.transaction(conn):
            conn.execute("UPDATE vpn_users SET expiry_handled = 1 WHERE id = ?", (row["id"],))
            users.end_token_sessions(conn, row)
            db.audit(conn, ACTOR, "user.expired", row["username"], "last valid day %s" % row["expires_on"], "", now)
        result["expired"] += 1
        try:
            killed = ctl.kick(row["username"])
            if killed:
                db.audit(conn, ACTOR, "session.kick", row["username"], "expired (%d session)" % killed, "", now)
                result["kicked"] += killed
        except CtlError as exc:
            db.audit(conn, ACTOR, "session.kick_failed", row["username"], "expired: %s" % exc, "", now)

    recipients = admin_recipients(conn)
    panel = config_mod.panel_url(cfg)
    week = (today + datetime.timedelta(days=7)).isoformat()
    reminders = [
        # (column, template, condition SQL, result key)
        ("reminder_7d_for", "expiry_7d", "expires_on > ? AND expires_on <= ?", (today.isoformat(), week), "mail_7d"),
        ("reminder_0d_for", "expiry_0d", "expires_on <= ?", (today.isoformat(),), "mail_0d"),
    ]
    for column, template, cond, params, key in reminders:
        rows = conn.execute("SELECT * FROM vpn_users WHERE %s AND (%s IS NULL OR %s != expires_on)"
                            % (cond, column, column), params).fetchall()
        for row in rows:
            days_left = (users.parse_date(row["expires_on"]) - today).days
            values = {"customer": cfg.customer_name, "username": row["username"],
                      "display_name": row["display_name"], "expires_on": row["expires_on"],
                      "days_left": days_left, "panel_url": panel}
            if recipients:
                ok, error = mailer.send_template(recipients, template, values)
            else:
                ok, error = False, "no enabled admin with an e-mail address"
            with db.transaction(conn):
                # Marked as done either way: a reminder is sent once; a failure is audited.
                conn.execute("UPDATE vpn_users SET %s = expires_on WHERE id = ?" % column, (row["id"],))
                if ok:
                    db.audit(conn, ACTOR, "mail.%s" % template, row["username"],
                             "to %d admin(s)" % len(recipients), "", now)
                else:
                    db.audit(conn, ACTOR, "mail.failed", row["username"], "%s: %s" % (template, error), "", now)
            result[key if ok else "mail_failed"] += 1

    # Certificates ending before the account: warn admins once per (cert end, last day) pair.
    for row in conn.execute("SELECT * FROM vpn_users WHERE enabled = 1 AND cert_not_after IS NOT NULL"
                            " AND cert_not_after < expires_on").fetchall():
        marker = "%s|%s" % (row["cert_not_after"], row["expires_on"])
        if row["cert_warned_for"] == marker:
            continue
        values = {"customer": cfg.customer_name, "username": row["username"], "display_name": row["display_name"],
                  "cert_not_after": row["cert_not_after"], "expires_on": row["expires_on"], "panel_url": panel}
        if recipients:
            ok, error = mailer.send_template(recipients, "cert_short", values)
        else:
            ok, error = False, "no enabled admin with an e-mail address"
        with db.transaction(conn):
            conn.execute("UPDATE vpn_users SET cert_warned_for = ? WHERE id = ?", (marker, row["id"]))
            db.audit(conn, ACTOR, "user.cert_short", row["username"],
                     "certificate ends %s, last valid day %s" % (row["cert_not_after"], row["expires_on"]), "", now)
            db.audit(conn, ACTOR, "mail.cert_short" if ok else "mail.failed", row["username"],
                     "to %d admin(s)" % len(recipients) if ok else "cert_short: %s" % error, "", now)
        result["cert_short"] += 1

    with db.transaction(conn):
        purged = tokens.purge(conn, now)
        if purged:
            db.audit(conn, ACTOR, "token.purge", "", "%d setup token(s)" % purged, "", now)
        # auth-token sessions older than the token lifetime can no longer be presented.
        conn.execute("DELETE FROM vpn_sessions WHERE created_at < ?",
                     (now - cfg.auth_token_lifetime_hours * 3600 - 3600,))
    result["tokens_purged"] = purged
    return result


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    cfg = config_mod.load()
    conn = db.connect()
    result = run_expiry(cfg, conn, SessionControl(), Mailer(cfg))
    log.info("expiry run: %s", ", ".join("%s=%d" % kv for kv in sorted(result.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
