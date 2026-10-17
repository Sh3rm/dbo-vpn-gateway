"""Setup-link flow shared by VPN users (/enroll/) and admins (/admin-enroll/).

Step 1: the user sets a password; a TOTP secret is generated. Both are kept on
        the token row (password only as a hash) and bound to a random flow
        nonce stored in the browser session.
Step 2: the user scans the QR code and proves one valid code; the password
        hash and secret move to the account and the token is consumed.
Step 3 (VPN users only): the .ovpn download, only from the same browser
        session and only within tokens.DOWNLOAD_WINDOW after completion.
No Flask here, so the lifecycle is testable with the standard library.
"""

import secrets

from dbovpn import db, passwords, tokens, totp
from dbovpn.users import ServiceError

TABLE = {"vpn": "vpn_users", "admin": "admins"}
ACCOUNT_KIND = {"vpn": "account_vpn", "admin": "account_panel"}


def subject_row(conn, kind, username):
    return conn.execute("SELECT * FROM %s WHERE username = ?" % TABLE[kind], (username,)).fetchone()


def open_token(conn, kind, raw, now):
    """(token_row, subject_row) for a usable link, else (None, None)."""
    token = tokens.find_open(conn, kind, raw, now)
    if token is None:
        return None, None
    subject = subject_row(conn, kind, token["subject"])
    if subject is None:
        return None, None
    return token, subject


def start(conn, token, subject, password, confirm, hash_password, now):
    """Validate the password, store its hash and a fresh TOTP secret. Returns the flow nonce."""
    error = passwords.policy_error(password, confirm, subject["username"])
    if error:
        raise ServiceError(error, min=passwords.MIN_LENGTH)
    nonce = secrets.token_urlsafe(16)
    with db.transaction(conn):
        conn.execute("UPDATE setup_tokens SET flow_nonce = ?, pending_password_hash = ?, pending_totp_secret = ?"
                     " WHERE id = ? AND used_at IS NULL",
                     (nonce, hash_password(password), totp.generate_secret(), token["id"]))
    return nonce


def finish(conn, kind, token, nonce, code, actor, source_ip, now):
    """Check the TOTP proof; on success move credentials to the account and consume the token."""
    if not token["flow_nonce"] or not nonce or not secrets.compare_digest(token["flow_nonce"], nonce):
        raise ServiceError("enroll_restart")
    secret = token["pending_totp_secret"]
    counter = totp.verify(secret, code, now, 0)
    if counter is None:
        with db.transaction(conn):
            tokens.record_failed_attempt(conn, token["id"])
            db.audit(conn, actor, "enroll.totp_failed", token["subject"], db.detail(ACCOUNT_KIND[kind]), source_ip, now)
        raise ServiceError("totp_wrong")
    with db.transaction(conn):
        if not tokens.mark_used(conn, token["id"], now):
            raise ServiceError("link_invalid")
        # The proving code's step is stored as used, so it cannot also open the VPN or the panel.
        conn.execute("UPDATE %s SET password_hash = ?, totp_secret = ?, totp_last_counter = ? WHERE username = ?"
                     % TABLE[kind], (token["pending_password_hash"], secret, counter, token["subject"]))
        db.audit(conn, actor, "enroll.complete", token["subject"], db.detail(ACCOUNT_KIND[kind]), source_ip, now)


def provisioning(cfg, kind, token):
    issuer = cfg.customer_name + (" VPN" if kind == "vpn" else " VPN Panel")
    secret = token["pending_totp_secret"]
    return secret, totp.provisioning_uri(secret, token["subject"], issuer), issuer
