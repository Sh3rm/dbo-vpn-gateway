"""Decide >CLIENT:CONNECT and >CLIENT:REAUTH requests.

Renegotiation (MAN/MN line numbers: see dbovpn/mgmt/protocol.py):
  The server runs 'auth-gen-token <lifetime> <renewal> external-auth' (MAN 1590-1683).
  After the first full login OpenVPN pushes a token; on the hourly TLS
  renegotiation (reneg-sec default 3600, MAN 2566-2580) the client sends that
  token instead of the password. Because of 'external-auth', OpenVPN still
  asks us, with env session_state telling whether the token is valid
  (MAN 1640-1663). So:
    session_state=Authenticated -> no password/TOTP needed, but the account
                                   must still be enabled, enrolled, unexpired,
                                   and the token's session_id (MAN 1640-1642)
                                   must have been recorded by a full login at
                                   the user's current cred_epoch, so a reset,
                                   disable or delete ends every older token;
    session_state=Initial (or absent) -> full check: SCRV1 password + TOTP;
    Expired / Invalid / *EmptyUser   -> deny (MAN 1665-1673 strongly recommends
                                   failing these unless authenticated another way).
  A client-deny on REAUTH only invalidates the new key; the old key lives on for
  up to tran-window seconds (MN 814-824), so a denied REAUTH is followed by
  client-kill to drop the user at once.
"""

from dbovpn import config as config_mod
from dbovpn import db, totp, users
from dbovpn.config import USERNAME_RE
from dbovpn.mgmt import protocol

GENERIC_FAILURE = "Authentication failed"
ACCOUNT_FAILURE = "Account disabled or expired, contact your administrator"


class Decision(object):
    def __init__(self, allow, reason, username="", lines=None, kill=False, client_reason=None,
                 audit_action=None, audit_detail=""):
        self.allow = allow
        self.reason = reason              # goes to the OpenVPN log via client-deny, never a secret
        self.username = username
        self.lines = lines or []          # client-connect block for CONNECT
        self.kill = kill
        self.client_reason = client_reason
        self.audit_action = audit_action
        self.audit_detail = audit_detail or reason


def client_config_lines(cfg, row):
    """ifconfig-push for the fixed address (MAN 1872-1899, topology subnet: local + netmask)
    and the profile's routes."""
    profile = cfg.profiles[row["profile"]]
    lines = ["ifconfig-push %s %s" % (row["vpn_ip"], cfg.subnet.netmask)]
    for net in profile.routes():
        lines.append('push "route %s %s"' % (net.network_address, net.netmask))
    return lines


def _deny(event, reason, username="", client_reason=GENERIC_FAILURE, audit=True):
    reauth = event.kind == "REAUTH"
    action = None
    if audit:
        action = "vpn.reauth_denied" if reauth else "vpn.login_failed"
    return Decision(False, reason, username, kill=reauth, client_reason=client_reason, audit_action=action)


def _fail(event, conn, cfg, row, now, reason):
    """Count a failed password/TOTP attempt; lock the account after lockout_attempts
    failures for lockout_minutes (the [panel] lockout settings apply to VPN logins too)."""
    conn.execute("UPDATE vpn_users SET failed_logins = failed_logins + 1 WHERE id = ?", (row["id"],))
    cur = conn.execute("UPDATE vpn_users SET failed_logins = 0, locked_until = ? WHERE id = ? AND failed_logins >= ?",
                       (int(now) + cfg.lockout_minutes * 60, row["id"], cfg.lockout_attempts))
    if cur.rowcount == 1:
        db.audit(conn, "system:mgmt", "vpn.locked", row["username"],
                 db.detail("locked", n=cfg.lockout_attempts, minutes=cfg.lockout_minutes),
                 event.env.get("untrusted_ip", ""), now)
        reason += "; account locked"
    return _deny(event, reason, row["username"])


def decide(event, conn, cfg, now, today, verify_password):
    """Return a Decision for a CONNECT or REAUTH ClientEvent.

    verify_password(stored_hash, password) -> bool is injected (argon2 in production).
    """
    env = event.env
    cn = env.get("common_name", "")
    username = env.get("username", "")

    if not USERNAME_RE.match(cn) or cn == cfg.server_cert_name:
        return _deny(event, "certificate CN is not a gateway user", cn)
    if username != cn:
        return _deny(event, "username does not match certificate", cn)

    row = users.get(conn, cn)
    refusal = users.login_refusal(row, today)
    if refusal:
        client_reason = ACCOUNT_FAILURE if refusal in ("user disabled", "user expired") else GENERIC_FAILURE
        return _deny(event, refusal, cn, client_reason)
    if row["profile"] not in cfg.profiles:
        return _deny(event, "profile %s is not defined" % row["profile"], cn)
    if not users.ip_in_subnet(cfg, row["vpn_ip"]) or row["vpn_ip"] == str(config_mod.server_ip(cfg)):
        return _deny(event, "fixed address outside the VPN subnet", cn)

    state = env.get("session_state", "Initial")
    session_id = env.get("session_id", "")
    if state == "Authenticated":
        known = conn.execute("SELECT 1 FROM vpn_sessions WHERE username = ? AND session_id = ? AND epoch = ?",
                             (cn, session_id, row["cred_epoch"])).fetchone() if session_id else None
        if known is None:
            return _deny(event, "auth-token from an earlier credential epoch or unknown session", cn)
        via = "auth_token"
    elif state == "Initial":
        if row["locked_until"] > now:
            return _deny(event, "locked after repeated failures", cn)
        try:
            password, code = protocol.parse_scrv1(env.get("password", ""))
        except protocol.ProtocolError as exc:
            return _fail(event, conn, cfg, row, now, str(exc))
        if not verify_password(row["password_hash"], password):
            return _fail(event, conn, cfg, row, now, "wrong password")
        counter = totp.verify(row["totp_secret"], code, now, row["totp_last_counter"])
        if counter is None:
            return _fail(event, conn, cfg, row, now, "wrong or reused TOTP code")
        # Claim the step atomically so two connections cannot use the same code.
        cur = conn.execute("UPDATE vpn_users SET totp_last_counter = ?, failed_logins = 0 WHERE id = ?"
                           " AND totp_last_counter < ?", (counter, row["id"], counter))
        if cur.rowcount != 1:
            return _fail(event, conn, cfg, row, now, "TOTP code reused")
        if session_id:
            conn.execute("INSERT OR REPLACE INTO vpn_sessions (username, session_id, epoch, created_at)"
                         " VALUES (?, ?, ?, ?)", (cn, session_id, row["cred_epoch"], int(now)))
        via = "password_totp"
    else:
        return _deny(event, "auth-token %s" % state, cn)

    if event.kind == "REAUTH":
        return Decision(True, "reauth ok", cn)
    return Decision(True, "login ok", cn, lines=client_config_lines(cfg, row),
                    audit_action="vpn.login", audit_detail=db.detail("login", via_code=via, ip=row["vpn_ip"]))
