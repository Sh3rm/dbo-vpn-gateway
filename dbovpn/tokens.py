"""One-time setup links.

The raw token (32 random bytes, URL-safe base64) exists only in the link; the
database keeps its SHA-256. A token is single use, expires after the configured
TTL, and is burned after MAX_ATTEMPTS wrong TOTP proofs.
"""

import hashlib
import secrets
import time


TOKEN_BYTES = 32
MAX_ATTEMPTS = 5
# After completion the .ovpn download stays available this long, only in the
# browser session that completed the flow.
DOWNLOAD_WINDOW = 15 * 60


def hash_token(raw):
    return hashlib.sha256(raw.encode("ascii", "replace")).hexdigest()


def create(conn, kind, subject, ttl_hours, actor, now=None):
    """Create a token for subject, invalidating its earlier unused tokens. Returns the raw token.

    Must be called inside a transaction.
    """
    now = int(now if now is not None else time.time())
    raw = secrets.token_urlsafe(TOKEN_BYTES)
    conn.execute("DELETE FROM setup_tokens WHERE kind = ? AND subject = ? AND used_at IS NULL",
                 (kind, subject))
    conn.execute(
        "INSERT INTO setup_tokens (token_hash, kind, subject, created_at, expires_at, created_by)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (hash_token(raw), kind, subject, now, now + ttl_hours * 3600, actor))
    return raw


def find_open(conn, kind, raw, now=None):
    """Return the token row if it is usable (unused, unexpired, attempts left), else None."""
    now = int(now if now is not None else time.time())
    if not raw or len(raw) > 128:
        return None
    row = conn.execute("SELECT * FROM setup_tokens WHERE token_hash = ? AND kind = ?",
                       (hash_token(raw), kind)).fetchone()
    if row is None or row["used_at"] is not None or row["expires_at"] <= now:
        return None
    if row["attempts"] >= MAX_ATTEMPTS:
        return None
    return row


def find_completed(conn, kind, raw, now=None):
    """Return the token row if it was completed within the download window, else None."""
    now = int(now if now is not None else time.time())
    if not raw or len(raw) > 128:
        return None
    row = conn.execute("SELECT * FROM setup_tokens WHERE token_hash = ? AND kind = ?",
                       (hash_token(raw), kind)).fetchone()
    if row is None or row["used_at"] is None or now - row["used_at"] > DOWNLOAD_WINDOW:
        return None
    return row


def record_failed_attempt(conn, token_id):
    conn.execute("UPDATE setup_tokens SET attempts = attempts + 1 WHERE id = ?", (token_id,))


def mark_used(conn, token_id, now=None):
    """Consume the token. Returns False if it was already consumed (concurrent use)."""
    now = int(now if now is not None else time.time())
    cur = conn.execute("UPDATE setup_tokens SET used_at = ?, pending_password_hash = NULL,"
                       " pending_totp_secret = NULL WHERE id = ? AND used_at IS NULL", (now, token_id))
    return cur.rowcount == 1


def invalidate_subject(conn, kind, subject):
    conn.execute("DELETE FROM setup_tokens WHERE kind = ? AND subject = ?", (kind, subject))


def purge(conn, now=None):
    """Delete expired tokens and consumed tokens past the download window. Returns the count."""
    now = int(now if now is not None else time.time())
    cur = conn.execute(
        "DELETE FROM setup_tokens WHERE expires_at <= ? OR attempts >= ?"
        " OR (used_at IS NOT NULL AND used_at < ?)",
        (now, MAX_ATTEMPTS, now - DOWNLOAD_WINDOW))
    return cur.rowcount

