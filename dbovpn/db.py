"""SQLite storage with built-in schema migrations.

All processes that open the database run as the dbovpn user (the root CLI
drops privileges first), so the database and its WAL files stay owned by
dbovpn with mode 0600.
"""

import contextlib
import os
import sqlite3
import time

DB_PATH = "/var/lib/dbo-vpn-gateway/gateway.db"

# Each entry upgrades the schema by one version (PRAGMA user_version).
MIGRATIONS = [
    # 1: initial schema
    """
    CREATE TABLE vpn_users (
        id                INTEGER PRIMARY KEY,
        username          TEXT NOT NULL UNIQUE,
        display_name      TEXT NOT NULL,
        email             TEXT NOT NULL,
        profile           TEXT NOT NULL,
        vpn_ip            TEXT NOT NULL UNIQUE,
        enabled           INTEGER NOT NULL DEFAULT 1,
        password_hash     TEXT,
        totp_secret       TEXT,
        totp_last_counter INTEGER NOT NULL DEFAULT 0,
        expires_on        TEXT NOT NULL,
        expiry_handled    INTEGER NOT NULL DEFAULT 0,
        reminder_7d_for   TEXT,
        reminder_0d_for   TEXT,
        adopted           INTEGER NOT NULL DEFAULT 0,
        created_at        INTEGER NOT NULL,
        created_by        TEXT NOT NULL
    );
    CREATE TABLE admins (
        id                INTEGER PRIMARY KEY,
        username          TEXT NOT NULL UNIQUE,
        display_name      TEXT NOT NULL,
        email             TEXT NOT NULL,
        language          TEXT NOT NULL DEFAULT 'tr',
        enabled           INTEGER NOT NULL DEFAULT 1,
        password_hash     TEXT,
        totp_secret       TEXT,
        totp_last_counter INTEGER NOT NULL DEFAULT 0,
        failed_logins     INTEGER NOT NULL DEFAULT 0,
        locked_until      INTEGER NOT NULL DEFAULT 0,
        session_version   INTEGER NOT NULL DEFAULT 1,
        last_login_at     INTEGER,
        created_at        INTEGER NOT NULL
    );
    CREATE TABLE setup_tokens (
        id                    INTEGER PRIMARY KEY,
        token_hash            TEXT NOT NULL UNIQUE,
        kind                  TEXT NOT NULL CHECK (kind IN ('vpn', 'admin')),
        subject               TEXT NOT NULL,
        created_at            INTEGER NOT NULL,
        expires_at            INTEGER NOT NULL,
        created_by            TEXT NOT NULL,
        attempts              INTEGER NOT NULL DEFAULT 0,
        flow_nonce            TEXT,
        pending_password_hash TEXT,
        pending_totp_secret   TEXT,
        used_at               INTEGER
    );
    CREATE INDEX setup_tokens_subject ON setup_tokens (kind, subject);
    CREATE TABLE audit (
        id        INTEGER PRIMARY KEY,
        ts        INTEGER NOT NULL,
        actor     TEXT NOT NULL,
        action    TEXT NOT NULL,
        target    TEXT NOT NULL DEFAULT '',
        detail    TEXT NOT NULL DEFAULT '',
        source_ip TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX audit_ts ON audit (ts);
    """,
    # 2: auth-token sessions bound to a credential epoch, and VPN login lockout
    """
    ALTER TABLE vpn_users ADD COLUMN cred_epoch INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE vpn_users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE vpn_users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE vpn_sessions (
        username   TEXT NOT NULL,
        session_id TEXT NOT NULL,
        epoch      INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (username, session_id)
    );
    """,
    # 3: client certificate state kept in the database (the panel cannot read the PKI)
    """
    ALTER TABLE vpn_users ADD COLUMN cert_not_after TEXT;
    ALTER TABLE vpn_users ADD COLUMN cert_key_encrypted INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE vpn_users ADD COLUMN needs_new_cert INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE vpn_users ADD COLUMN cert_warned_for TEXT;
    UPDATE vpn_users SET needs_new_cert = 1 WHERE adopted = 1;
    """,
    # 4: per-user claim so only one request renews a certificate at a time
    """
    ALTER TABLE vpn_users ADD COLUMN cert_renewing INTEGER NOT NULL DEFAULT 0;
    """,
]


def connect(path=None, migrate_schema=True):
    """Open the database (creating it 0600 if missing) and apply pending migrations.

    Long-running processes migrate once at startup and pass migrate_schema=False
    for later connections (the web app opens one per request).
    """
    path = path or os.environ.get("DBOVPN_DB") or DB_PATH
    if path != ":memory:" and not os.path.exists(path):
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    if migrate_schema:
        migrate(conn)
    return conn


def migrate(conn):
    if conn.execute("PRAGMA user_version").fetchone()[0] >= len(MIGRATIONS):
        return len(MIGRATIONS)
    with transaction(conn):
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for number, script in enumerate(MIGRATIONS, start=1):
            if number <= version:
                continue
            for statement in script.split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute("PRAGMA user_version = %d" % number)
    return conn.execute("PRAGMA user_version").fetchone()[0]


@contextlib.contextmanager
def transaction(conn):
    """BEGIN IMMEDIATE ... COMMIT, so read-check-write sequences (the user cap) are atomic."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def audit(conn, actor, action, target="", detail="", source_ip="", now=None):
    """Append one audit row. Callers must never put secrets into detail."""
    conn.execute(
        "INSERT INTO audit (ts, actor, action, target, detail, source_ip) VALUES (?, ?, ?, ?, ?, ?)",
        (int(now if now is not None else time.time()), actor, action, target or "",
         detail or "", source_ip or ""))
