"""VPN user rules: cap, expiry, fixed addresses, and the state-changing actions.

The web panel and the CLI both call these functions, so the rules in SPEC.md
section 3 are enforced in one place. Root-only work goes through ctx.priv
(the privhelper), live sessions through ctx.ctl (the management daemon), mail
through ctx.mailer; tests pass fakes for all three.
"""

import datetime
import ipaddress
import logging
import re
import time

from dbovpn import config as config_mod
from dbovpn import db, tokens
from dbovpn.config import EMAIL_RE, USERNAME_RE
from dbovpn.ctl import CtlError
from dbovpn.privclient import PrivError

log = logging.getLogger(__name__)

DISPLAY_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,100}\Z")


class ServiceError(Exception):
    """A refused action. key is an i18n message key; params fill its placeholders."""

    def __init__(self, key, **params):
        Exception.__init__(self, key)
        self.key = key
        self.params = params


class Context(object):
    """Who is acting, from where, and the interfaces the action may use."""

    def __init__(self, cfg, conn, actor, source_ip="", priv=None, ctl=None, mailer=None,
                 clock=time.time, today=None):
        self.cfg = cfg
        self.conn = conn
        self.actor = actor
        self.source_ip = source_ip
        self.priv = priv
        self.ctl = ctl
        self.mailer = mailer
        self.clock = clock
        self._today = today

    def now(self):
        return int(self.clock())

    def today(self):
        if self._today is not None:
            return self._today
        return datetime.date.fromtimestamp(self.clock())

    def audit(self, action, target="", detail=""):
        db.audit(self.conn, self.actor, action, target, detail, self.source_ip, self.now())


# Expiry -------------------------------------------------------------------
#
# expires_on is the last day the account works (server local time). From the
# next day on it is expired: treated as disabled for login, kicked, and it
# still counts against the cap.

def parse_date(value):
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except ValueError:
        raise ServiceError("bad_date")


def expiry_bounds(cfg, today):
    return today, today + datetime.timedelta(days=cfg.max_expiry_days)


def default_expiry(cfg, today):
    return today + datetime.timedelta(days=cfg.default_expiry_days)


def validate_expiry(cfg, value, today):
    day = parse_date(value)
    low, high = expiry_bounds(cfg, today)
    if day < low or day > high:
        raise ServiceError("expiry_out_of_range", low=low.isoformat(), high=high.isoformat())
    return day


def is_expired(row, today):
    return parse_date(row["expires_on"]) < today


def is_enrolled(row):
    return bool(row["password_hash"]) and bool(row["totp_secret"])


def status(row, today):
    """One of: pending (not enrolled yet), disabled, expired, active."""
    if not row["enabled"]:
        return "disabled"
    if is_expired(row, today):
        return "expired"
    if not is_enrolled(row):
        return "pending"
    return "active"


def is_locked(row, now):
    """True while a VPN login lockout (repeated wrong password/code) is in force."""
    return (row["locked_until"] or 0) > now


# Client certificates -----------------------------------------------------------
#
# The certificate in a downloaded profile must outlive the account. Its end date
# is recorded in cert_not_after (from privhelper cert-info) because the panel
# cannot read the PKI itself.

CERT_GRACE_DAYS = 30
RENEW_CLAIM_SECONDS = 300


def needs_new_cert(row):
    """True if the next profile download must carry a freshly issued certificate:
    adopted (legacy) certificates, passphrase-protected keys, unknown end dates,
    and certificates ending before the last valid day + CERT_GRACE_DAYS."""
    if row["needs_new_cert"] or row["cert_key_encrypted"] or not row["cert_not_after"]:
        return True
    return parse_date(row["cert_not_after"]) < parse_date(row["expires_on"]) + datetime.timedelta(days=CERT_GRACE_DAYS)


def cert_ends_early(row):
    """An enabled user whose certificate ends before their last valid day."""
    return bool(row["enabled"]) and bool(row["cert_not_after"]) and \
        parse_date(row["cert_not_after"]) < parse_date(row["expires_on"])


def record_cert_info(conn, username, info):
    conn.execute("UPDATE vpn_users SET cert_not_after = ?, cert_key_encrypted = ? WHERE username = ?",
                 (info.get("not_after"), 1 if info.get("key_encrypted") else 0, username))


def refresh_cert_info(ctx, username):
    """Ask the privhelper for the certificate state and store it. Failure is audited, not raised."""
    try:
        info = ctx.priv.cert_info(username)
    except PrivError as exc:
        ctx.audit("cert.info_failed", username, str(exc))
        return None
    with db.transaction(ctx.conn):
        record_cert_info(ctx.conn, username, info)
    return info


def ensure_fresh_cert(ctx, username):
    """Called when an enrolled user downloads a profile. Issues a fresh key + certificate
    (old serial revoked afterwards) if needs_new_cert(); returns True if it did."""
    row = require(ctx, username)
    if not needs_new_cert(row):
        return False
    # Claim the renewal (a double-click or two workers must not renew twice). A claim
    # older than RENEW_CLAIM_SECONDS is considered abandoned.
    with db.transaction(ctx.conn):
        row = require(ctx, username)
        if not needs_new_cert(row):
            return False
        cur = ctx.conn.execute("UPDATE vpn_users SET cert_renewing = ? WHERE username = ? AND cert_renewing < ?",
                               (ctx.now(), username, ctx.now() - RENEW_CLAIM_SECONDS))
        if cur.rowcount != 1:
            raise ServiceError("cert_renew_busy")
    old = row["cert_not_after"]
    try:
        ctx.priv.renew_cert(username)
        info = ctx.priv.cert_info(username)
    except PrivError as exc:
        with db.transaction(ctx.conn):
            ctx.conn.execute("UPDATE vpn_users SET cert_renewing = 0 WHERE username = ?", (username,))
            ctx.audit("cert.renew_failed", username, str(exc))
        raise ServiceError("cert_renew_failed")
    with db.transaction(ctx.conn):
        record_cert_info(ctx.conn, username, info)
        ctx.conn.execute("UPDATE vpn_users SET needs_new_cert = 0, cert_warned_for = NULL, cert_renewing = 0"
                         " WHERE username = ?", (username,))
        ctx.audit("cert.renew", username, "%s -> %s" % (old or "-", info.get("not_after") or "-"))
    return True


def login_refusal(row, today):
    """Why this user may not use the VPN right now, or None if allowed."""
    if row is None:
        return "unknown user"
    if not row["enabled"]:
        return "user disabled"
    if is_expired(row, today):
        return "user expired"
    if not is_enrolled(row):
        return "user not enrolled"
    return None


# Queries --------------------------------------------------------------------

def get(conn, username):
    return conn.execute("SELECT * FROM vpn_users WHERE username = ?", (username,)).fetchone()


def list_all(conn):
    return conn.execute("SELECT * FROM vpn_users ORDER BY username").fetchall()


def count(conn):
    """Every row counts: enabled, disabled and expired alike. Only a delete frees a slot."""
    return conn.execute("SELECT COUNT(*) FROM vpn_users").fetchone()[0]


def expiring_within(conn, today, days):
    high = (today + datetime.timedelta(days=days)).isoformat()
    return conn.execute(
        "SELECT * FROM vpn_users WHERE expires_on >= ? AND expires_on <= ? ORDER BY expires_on",
        (today.isoformat(), high)).fetchall()


def allocate_ip(conn, cfg):
    """Lowest free client address in the VPN subnet. Call inside a transaction."""
    used = {row[0] for row in conn.execute("SELECT vpn_ip FROM vpn_users")}
    for ip in config_mod.client_ip_range(cfg):
        if str(ip) not in used:
            return str(ip)
    raise ServiceError("no_free_ip")


# Validation -------------------------------------------------------------------

def validate_username(cfg, username):
    if not USERNAME_RE.match(username or ""):
        raise ServiceError("bad_username")
    if username == cfg.server_cert_name:
        raise ServiceError("bad_username")
    return username


def validate_display_name(name):
    name = (name or "").strip()
    if not DISPLAY_NAME_RE.match(name):
        raise ServiceError("bad_display_name")
    return name


def validate_email(email):
    email = (email or "").strip()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise ServiceError("bad_email")
    return email


# Actions ----------------------------------------------------------------------

def setup_link(cfg, raw):
    return "%s/enroll/%s" % (config_mod.panel_url(cfg), raw)


def send_setup_mail(ctx, row, raw):
    """Mail the setup link to the user. Failure is audited, never raised."""
    values = {"customer": ctx.cfg.customer_name, "display_name": row["display_name"],
              "username": row["username"], "link": setup_link(ctx.cfg, raw),
              "hours": ctx.cfg.setup_link_ttl_hours}
    ok, error = ctx.mailer.send_template(row["email"], "vpn_setup", values)
    if ok:
        ctx.audit("mail.setup_link", row["username"], "to %s" % row["email"])
    else:
        ctx.audit("mail.failed", row["username"], "setup link to %s: %s" % (row["email"], error))
    return ok


def _kick(ctx, username, reason):
    try:
        killed = ctx.ctl.kick(username)
    except CtlError as exc:
        ctx.audit("session.kick_failed", username, "%s: %s" % (reason, exc))
        return False
    if killed:
        ctx.audit("session.kick", username, "%s (%d session)" % (reason, killed))
    return True


def create_user(ctx, username, display_name, email, expires_on):
    """Create a VPN user, issue its certificate, and return (row, raw_token, mail_ok)."""
    cfg = ctx.cfg
    username = validate_username(cfg, username)
    display_name = validate_display_name(display_name)
    email = validate_email(email)
    day = validate_expiry(cfg, expires_on, ctx.today())
    profile = cfg.profiles[cfg.default_profile]

    try:
        with db.transaction(ctx.conn):
            if get(ctx.conn, username) is not None:
                raise ServiceError("user_exists")
            used = count(ctx.conn)
            if used >= cfg.max_users:
                raise ServiceError("cap_reached", used=used, max=cfg.max_users)
            ip = allocate_ip(ctx.conn, cfg)
            ctx.conn.execute(
                "INSERT INTO vpn_users (username, display_name, email, profile, vpn_ip, expires_on,"
                " created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, display_name, email, profile.name, ip, day.isoformat(), ctx.now(), ctx.actor))
    except ServiceError as exc:
        if exc.key == "cap_reached":
            ctx.audit("user.create_refused", username, "user limit reached (%(used)d/%(max)d)" % exc.params)
        raise

    try:
        ctx.priv.issue_cert(username)
    except PrivError as exc:
        with db.transaction(ctx.conn):
            ctx.conn.execute("DELETE FROM vpn_users WHERE username = ?", (username,))
            ctx.audit("user.create_failed", username, "certificate: %s" % exc)
        raise ServiceError("cert_failed")

    try:
        ctx.priv.ipset_add(profile.name, ip)
    except PrivError as exc:
        # The user exists; 'dbo-vpn-gateway setup' re-syncs ipsets. Audit so it is visible.
        ctx.audit("firewall.ipset_failed", username, str(exc))
    refresh_cert_info(ctx, username)

    with db.transaction(ctx.conn):
        raw = tokens.create(ctx.conn, "vpn", username, cfg.setup_link_ttl_hours, ctx.actor, ctx.now())
        ctx.audit("user.create", username, "profile=%s ip=%s expires_on=%s email=%s"
                  % (profile.name, ip, day.isoformat(), email))
    row = get(ctx.conn, username)
    mail_ok = send_setup_mail(ctx, row, raw)
    return row, raw, mail_ok


def require(ctx, username):
    row = get(ctx.conn, username)
    if row is None:
        raise ServiceError("no_such_user")
    return row


def end_token_sessions(conn, row):
    """Make every OpenVPN auth-token issued so far useless for this user.

    The management daemon accepts session_state=Authenticated only for a
    session_id recorded at the user's current cred_epoch (mgmt/auth.py).
    Call inside a transaction.
    """
    conn.execute("UPDATE vpn_users SET cred_epoch = cred_epoch + 1 WHERE id = ?", (row["id"],))
    conn.execute("DELETE FROM vpn_sessions WHERE username = ?", (row["username"],))


def set_enabled(ctx, username, enabled):
    """Enable or disable. Never touches the certificate. Enabling also clears a login lockout."""
    row = require(ctx, username)
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE vpn_users SET enabled = ?, failed_logins = 0, locked_until = 0 WHERE id = ?",
                         (1 if enabled else 0, row["id"]))
        if not enabled:
            end_token_sessions(ctx.conn, row)
        ctx.audit("user.enable" if enabled else "user.disable", username)
    if not enabled:
        _kick(ctx, username, "disabled")


def set_expiry(ctx, username, expires_on):
    """Change the expiry date (extend or shorten) within the maximum. Never touches the certificate."""
    row = require(ctx, username)
    day = validate_expiry(ctx.cfg, expires_on, ctx.today())
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE vpn_users SET expires_on = ?, expiry_handled = 0 WHERE id = ?",
                         (day.isoformat(), row["id"]))
        ctx.audit("user.expiry", username, "%s -> %s" % (row["expires_on"], day.isoformat()))


def reset_user(ctx, username):
    """Clear password and TOTP, kick, and issue a new setup link. Returns (raw_token, mail_ok)."""
    row = require(ctx, username)
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE vpn_users SET password_hash = NULL, totp_secret = NULL,"
                         " totp_last_counter = 0, failed_logins = 0, locked_until = 0 WHERE id = ?", (row["id"],))
        end_token_sessions(ctx.conn, row)
        raw = tokens.create(ctx.conn, "vpn", username, ctx.cfg.setup_link_ttl_hours, ctx.actor, ctx.now())
        ctx.audit("user.reset", username)
    _kick(ctx, username, "reset")
    return raw, send_setup_mail(ctx, get(ctx.conn, username), raw)


def delete_user(ctx, username):
    """Revoke the certificate (CRL regenerated atomically), kick, and remove the row."""
    row = require(ctx, username)
    try:
        ctx.priv.revoke_cert(username)
    except PrivError as exc:
        ctx.audit("user.delete_failed", username, "revoke: %s" % exc)
        raise ServiceError("revoke_failed")
    _kick(ctx, username, "deleted")
    try:
        ctx.priv.ipset_del(row["profile"], row["vpn_ip"])
    except PrivError as exc:
        ctx.audit("firewall.ipset_failed", username, str(exc))
    with db.transaction(ctx.conn):
        tokens.invalidate_subject(ctx.conn, "vpn", username)
        end_token_sessions(ctx.conn, row)
        ctx.conn.execute("DELETE FROM vpn_users WHERE id = ?", (row["id"],))
        ctx.audit("user.delete", username, "ip=%s profile=%s" % (row["vpn_ip"], row["profile"]))


def unlock_user(ctx, username):
    """Lift a VPN login lockout. Credentials, sessions and the certificate stay as they are."""
    row = require(ctx, username)
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE vpn_users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (row["id"],))
        ctx.audit("user.unlock", username)


def locked_users(conn, now):
    return conn.execute("SELECT * FROM vpn_users WHERE locked_until > ? ORDER BY username", (now,)).fetchall()


def kick_user(ctx, username):
    require(ctx, username)
    try:
        killed = ctx.ctl.kick(username)
    except CtlError as exc:
        ctx.audit("session.kick_failed", username, str(exc))
        raise ServiceError("ctl_unreachable")
    ctx.audit("session.kick", username, "%d session" % killed)
    return killed


def assign_profile(ctx, username, profile_name):
    """DBO only (CLI). Moves the user's address to the new profile's ipset and kicks
    the session so the client picks up the new routes."""
    row = require(ctx, username)
    if profile_name not in ctx.cfg.profiles:
        raise ServiceError("no_such_profile")
    old = row["profile"]
    if old == profile_name:
        return
    ctx.priv.ipset_add(profile_name, row["vpn_ip"])
    try:
        ctx.priv.ipset_del(old, row["vpn_ip"])
    except PrivError as exc:
        ctx.audit("firewall.ipset_failed", username, str(exc))
    with db.transaction(ctx.conn):
        ctx.conn.execute("UPDATE vpn_users SET profile = ? WHERE id = ?", (profile_name, row["id"]))
        ctx.audit("user.profile", username, "%s -> %s" % (old, profile_name))
    _kick(ctx, username, "profile changed")


def adopt(conn, cfg, username, actor, now, today):
    """Import a certificate that already exists in the PKI as a VPN user (setup).

    The legacy certificate keeps working until the user downloads the new
    profile after enrolling; that download replaces it with a fresh,
    unencrypted key + certificate and revokes the legacy serial
    (needs_new_cert). The user gets the default profile, the default expiry
    and a fixed address, and must enrol (password + TOTP) through a setup link
    before the gateway lets it connect. Ignores the cap so adoption
    never drops existing users; returns False if the user already exists.
    """
    if get(conn, username) is not None:
        return False
    ip = allocate_ip(conn, cfg)
    expires = default_expiry(cfg, today).isoformat()
    conn.execute(
        "INSERT INTO vpn_users (username, display_name, email, profile, vpn_ip, expires_on, adopted,"
        " needs_new_cert, created_at, created_by) VALUES (?, ?, '', ?, ?, ?, 1, 1, ?, ?)",
        (username, username, cfg.default_profile, ip, expires, now, actor))
    db.audit(conn, actor, "user.adopt", username, "ip=%s expires_on=%s" % (ip, expires), "", now)
    return True


def ip_in_subnet(cfg, ip):
    try:
        return ipaddress.IPv4Address(ip) in cfg.subnet
    except ValueError:
        return False
