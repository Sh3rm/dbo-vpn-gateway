# dbo-vpn-gateway: specification

Product: an OpenVPN 2.7 remote-access gateway with a customer self-service web panel, packaged as one
RPM for Rocky Linux / RHEL 9. Every customer-specific value comes from one config file, so the same
RPM serves any number of customers.

This file is the implementation contract. Upstream OpenVPN 2.7 docs are in `docs/upstream/` (read
`openvpn-2.7-management-notes.txt` and the man page sections you rely on; do not work from memory).

## 1. Hard constraints

- Target: Rocky/RHEL 9, system Python 3.9 (`/usr/bin/python3`). Code must be valid Python 3.9: no
  `match`, no `X | Y` type unions at runtime, no 3.10+ stdlib APIs. Check every .py file with
  `ast.parse(src, feature_version=(3, 9))` in addition to normal compilation.
- Dependencies only from BaseOS/AppStream/EPEL 9 RPMs, never pip, never vendored:
  python3-flask 2.0.3, python3-gunicorn 21.2, python3-pyotp 2.9, python3-qrcode-core 6.1,
  python3-argon2-cffi 21.3, python3-flask-wtf 1.0.1, nginx 1.20, sqlite, openvpn 2.7 (OpenVPN Copr),
  easy-rsa 3.2.1 (EPEL), firewalld. Stdlib for everything else (sqlite3, smtplib, secrets, hmac, json,
  socket, configparser, logging, argparse, unittest).
- Firewall changes go through `firewall-cmd` (firewalld zones/policies/ipsets), never nftables/iptables.
- Every config file the package writes on a server starts with a comment naming dbo-vpn-gateway.
- No secrets in logs. No plain-text passwords stored anywhere.

## 2. Roles

- Customer admin (web only): unlimited count, one personal account each, created/disabled/reset by
  DBO through the CLI. Logs in with username + password + TOTP.
- VPN user: never logs in to the panel; only opens a one-time setup link, then connects to the VPN.
- DBO (root over SSH, CLI only): user cap, access profiles, admin accounts, admin TOTP reset,
  setup/adoption of the server. None of this is reachable from the web.
- Admin accounts do not count against the VPN user cap.

## 3. Rules the code enforces

- Cap: `max_users` in gateway.conf. Every VPN user row that is not deleted counts (enabled, disabled
  and expired alike). Creating a user beyond the cap is refused. Only a delete frees a slot.
- Expiry: mandatory per VPN user; default 90 days, maximum 365 days from today; admin can change and
  extend within that maximum. When it passes, the account becomes expired (treated as disabled for
  login), is kicked if connected, and still counts against the cap.
- Disable/enable/extend never re-issue a certificate. Delete revokes the certificate (Easy-RSA revoke,
  regenerate CRL atomically, kick the session) and removes the row (keep the audit trail).
- Access profiles: defined by DBO via CLI; each user has exactly one; new users get the default
  profile (the one flagged default in config). Admins see the profile, cannot change it.
- Audit: every state-changing action (web and CLI, including logins, failed logins, kicks, expiry
  job actions) is written to an audit table with time, actor, action, target, detail, source IP.

## 4. Components and file layout

- `/etc/dbo-vpn-gateway/gateway.conf` (INI, root:dbovpn 0640): customer display name, public hostname,
  OpenVPN instance name, port/proto, VPN subnet, PKI dir, `max_users`, default/max expiry days,
  setup-link TTL hours (72), admin allowlist CIDRs for nginx, mail relay host/port, sender address,
  panel languages, profile definitions or a pointer to them. Ship a commented example.
- `/var/lib/dbo-vpn-gateway/gateway.db` (SQLite, owned by `dbovpn`, 0600): schema migrations built in.
- Python package `dbovpn` under `/usr/lib/dbo-vpn-gateway/` (or site-packages), shared by all parts.
- `dbo-vpn-gateway-mgmt.service` (user `dbovpn`): long-running daemon connected to the OpenVPN
  management unix socket (`management <path> unix` + `management-client-group dbovpn` +
  `management-client-auth`). It:
  - answers `>CLIENT:CONNECT`/`>CLIENT:REAUTH` with `client-auth`/`client-deny`: certificate CN must
    equal the username; user must exist, be enabled, enrolled, not expired; password (argon2) and TOTP
    must match. Password and TOTP arrive via the static-challenge format described in the man page /
    management notes (`SCRV1:...`); parse it exactly as documented. TOTP: 30 s step, accept +-1 step,
    reject reuse of an already used step per user (store last used counter).
  - pushes the user's fixed VPN IP (`ifconfig-push`) in the `client-auth` block.
  - handles renegotiation without asking the user again: research `auth-gen-token` and how
    `>CLIENT:REAUTH` / `session_state` behave in 2.7 and pick the documented way; the hourly TLS
    renegotiation must not drop users who are still allowed, and must drop users who are not.
  - exposes a small local control socket (`/run/dbo-vpn-gateway/ctl.sock`, JSON lines, group
    dbovpn) for: list sessions, kick user. OpenVPN accepts one management client, so the web app
    never talks to OpenVPN directly.
  - fails closed: if it is down, nobody new can connect. It reconnects to OpenVPN automatically.
- Web app (Flask under gunicorn, user `dbovpn`, bound to a unix socket or 127.0.0.1): admin panel and
  the public setup page. TR and EN UI, language switch, all strings in one file per language.
  - Admin login: username + password + TOTP; per-account lockout after repeated failures; session
    cookie Secure/HttpOnly/SameSite=Strict; idle timeout 30 min; CSRF on every form (flask-wtf).
  - Pages: dashboard (usage `n / max_users`, users expiring within 14 days, connected users), users
    list, create user (username, display name, email, expiry), user detail (enable, disable, extend,
    reset, delete with confirmation, kick), sessions, audit log (read-only).
  - Create and reset produce a setup link: 32+ random bytes, only its SHA-256 stored, 72 h, single
    use. The link is shown in the panel and mailed to the user's address.
  - Public setup page `/enroll/<token>`: user sets a password (min 12 chars, confirm), scans a QR
    (otpauth URI, issuer = customer display name + " VPN"), proves one valid TOTP code, then downloads
    the `.ovpn`. The token is consumed at completion; the download is available only in that flow.
- Root helper (`/usr/libexec/dbo-vpn-gateway/privhelper`, run via a sudoers rule that allows
  `dbovpn` only this binary): fixed subcommands only, strict argument validation
  (username `^[a-z0-9][a-z0-9._-]{1,63}$`): issue cert (Easy-RSA, nopass, server CA), revoke + CRL,
  build `.ovpn` content to stdout, add/remove a VPN IP to a profile ipset.
- `.ovpn` content: client header (client, dev tun, proto, remote host/port, resolv-retry infinite,
  nobind, persist-tun, remote-cert-tls server, verb 3) plus
  `auth-user-pass`, `auth-nocache`, `static-challenge` (documented 2.7 syntax), inline ca/cert/key and
  `<tls-crypt>`. The private key is unencrypted (password + TOTP replace the key passphrase).
- Expiry/reminder job: systemd timer (hourly): expire accounts, kick them, mail admins 7 days before
  and on the expiry day (once each), purge used/expired setup tokens.
- Mail: smtplib to the relay from config, port 25, no auth, STARTTLS when offered; sender from
  config. Templates TR and EN. A mail failure is logged and audited but never blocks the action.
- CLI `/usr/sbin/dbo-vpn-gateway` (root only): `setup` (idempotent: writes OpenVPN server config,
  PKI if missing, firewalld zone/policy/ipsets, sysctl, nginx site, systemd units/timers; adopts an
  existing PKI and existing users without breaking them), `admin add|list|disable|enable|reset`,
  `user list|show`, `profile list|add|assign`, `status`, `limit` (show usage), `doctor` (checks).
- nginx site: 443 with the cert/key paths from config; `/enroll/` public with `limit_req`;
  everything else `allow` the configured CIDRs, `deny all` (403 before the app); security headers.
- Packaging: `dbo-vpn-gateway.spec` with all files, `Requires:` on the RPMs above, `%pre` user
  creation, systemd units, sudoers drop-in, logrotate if needed. Carry over the existing operational
  pieces in generalised form: CRL renew timer, OpenVPN-only autoupdate with the needs-restarting
  restart, audit rule on `/etc/openvpn`.

## 5. Tests

- `tests/` with stdlib `unittest`, runnable on Rocky 9 with the RPMs installed: TOTP window and
  replay, SCRV1 parsing, cap counting, expiry rules, token lifecycle, management protocol parser
  against recorded sample lines from the management notes, privhelper argument validation.
- Keep OpenVPN, Easy-RSA, firewall-cmd and SMTP behind small interfaces so tests run without them.
