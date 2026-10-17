"""Customer admin accounts (panel only). Created, disabled and reset by DBO via the CLI."""

import time

from dbovpn import config as config_mod
from dbovpn import db, tokens, totp
from dbovpn.users import ServiceError, validate_display_name, validate_email
from dbovpn.config import USERNAME_RE, SUPPORTED_LANGUAGES


def get(conn, username):
    return conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()


def get_by_id(conn, admin_id):
    return conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()


def list_all(conn):
    return conn.execute("SELECT * FROM admins ORDER BY username").fetchall()


def is_enrolled(row):
    return bool(row["password_hash"]) and bool(row["totp_secret"])


def setup_link(cfg, raw):
    return "%s/admin-enroll/%s" % (config_mod.panel_url(cfg), raw)


def send_setup_mail(ctx, row, raw):
    values = {"customer": ctx.cfg.customer_name, "display_name": row["display_name"],
              "username": row["username"], "link": setup_link(ctx.cfg, raw),
              "hours": ctx.cfg.setup_link_ttl_hours, "panel_url": config_mod.panel_url(ctx.cfg)}
    ok, error = ctx.mailer.send_template(row["email"], "admin_setup", values, language=row["language"])
    if ok:
        ctx.audit("mail.admin_setup_link", row["username"], "to %s" % row["email"])
    else:
        ctx.audit("mail.failed", row["username"], "admin setup link to %s: %s" % (row["email"], error))
    return ok


def add(ctx, username, display_name, email, language):
    if not USERNAME_RE.match(username or ""):
        raise ServiceError("bad_username")
    if language not in SUPPORTED_LANGUAGES:
        raise ServiceError("bad_language")
    display_name = validate_display_name(display_name)
    email = validate_email(email)
    with db.transaction(ctx.conn):
        if get(ctx.conn, username) is not None:
            raise ServiceError("user_exists")
        ctx.conn.execute("INSERT INTO admins (username, display_name, email, language, created_at)"
                         " VALUES (?, ?, ?, ?, ?)", (username, display_name, email, language, ctx.now()))
        raw = tokens.create(ctx.conn, "admin", username, ctx.cfg.setup_link_ttl_hours, ctx.actor, ctx.now())
        ctx.audit("admin.add", username, "email=%s" % email)
    return raw, send_setup_mail(ctx, get(ctx.conn, username), raw)


def require(ctx, username):
    row = get(ctx.conn, username)
    if row is None:
        raise ServiceError("no_such_user")
    return row


def set_enabled(ctx, username, enabled):
    """Disable logs the admin out everywhere (session_version bump). Enable also clears a lockout."""
    row = require(ctx, username)
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE admins SET enabled = ?, failed_logins = 0, locked_until = 0,"
                         " session_version = session_version + 1 WHERE id = ?",
                         (1 if enabled else 0, row["id"]))
        ctx.audit("admin.enable" if enabled else "admin.disable", username)


def reset(ctx, username):
    """Clear password and TOTP, end sessions, and send a new setup link."""
    row = require(ctx, username)
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE admins SET password_hash = NULL, totp_secret = NULL, totp_last_counter = 0,"
                         " failed_logins = 0, locked_until = 0, session_version = session_version + 1"
                         " WHERE id = ?", (row["id"],))
        raw = tokens.create(ctx.conn, "admin", username, ctx.cfg.setup_link_ttl_hours, ctx.actor, ctx.now())
        ctx.audit("admin.reset", username)
    return raw, send_setup_mail(ctx, get(ctx.conn, username), raw)


def check_login(conn, cfg, username, password, code, verify_password, burn_time, now=None):
    """Return (admin_row or None, reason). Applies the per-account lockout.

    reason is for the audit log only; the user always sees one generic message.
    """
    now = int(now if now is not None else time.time())
    row = get(conn, username) if USERNAME_RE.match(username or "") else None
    if row is None or not row["enabled"] or not is_enrolled(row):
        burn_time(password)
        return None, "unknown, disabled or not enrolled"
    if row["locked_until"] > now:
        burn_time(password)
        return None, "locked"
    pw_ok = verify_password(row["password_hash"], password)
    counter = totp.verify(row["totp_secret"], code, now, row["totp_last_counter"]) if pw_ok else None
    if counter is not None:
        cur = conn.execute("UPDATE admins SET totp_last_counter = ?, failed_logins = 0, last_login_at = ?"
                           " WHERE id = ? AND totp_last_counter < ?", (counter, now, row["id"], counter))
        if cur.rowcount == 1:
            return get_by_id(conn, row["id"]), "ok"
    # Increment in SQL so parallel attempts (several gunicorn workers) all count.
    conn.execute("UPDATE admins SET failed_logins = failed_logins + 1 WHERE id = ?", (row["id"],))
    cur = conn.execute("UPDATE admins SET failed_logins = 0, locked_until = ? WHERE id = ? AND failed_logins >= ?",
                       (now + cfg.lockout_minutes * 60, row["id"], cfg.lockout_attempts))
    if cur.rowcount == 1:
        return None, "locked after %d failures" % cfg.lockout_attempts
    return None, "wrong password" if not pw_ok else "wrong or reused TOTP code"
