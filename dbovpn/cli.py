"""/usr/sbin/dbo-vpn-gateway: DBO's root-only command line.

  setup [--apply]                         install/adopt; --apply also reloads firewalld and restarts OpenVPN
  admin add USER --name N --email E [--lang tr|en]
  admin list | disable USER | enable USER | reset USER
  user list | show USER
  user update USER [--name N] [--email E]  fix name/e-mail (adopted users have none)
  user link USER                          new setup link (also resets password and TOTP)
  profile list | add NAME --dest D [--dest D ...] [--description T] | assign USER PROFILE
  status | limit | doctor
  crl-renew | autoupdate                  used by the systemd timers
"""

import argparse
import datetime
import os
import sys
import time

from dbovpn import __version__, admins, db, firewall, provision, users
from dbovpn import config as config_mod
from dbovpn.config import ConfigError, PROFILE_RE, parse_destination
from dbovpn.ctl import CtlError, SessionControl
from dbovpn.mailer import Mailer
from dbovpn.privclient import PrivError, Privileged
from dbovpn.users import ServiceError
from dbovpn.web import i18n


def out(text=""):
    sys.stdout.write(text + "\n")


def table(rows, headers):
    rows = [[str(c) for c in r] for r in rows]
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    out("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
    for r in rows:
        out("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())


def service_context(cfg):
    """Drop to dbovpn and build the same context the web panel uses."""
    provision.drop_privileges()
    conn = db.connect()
    return users.Context(cfg, conn, "cli:root", "local", Privileged(), SessionControl(), Mailer(cfg))


def explain(exc):
    return i18n.translate("en", exc.key, **exc.params)


# admin ------------------------------------------------------------------------------

def cmd_admin(cfg, a):
    ctx = service_context(cfg)
    if a.action == "list":
        now = int(time.time())
        table([[r["username"], r["display_name"], r["email"], r["language"],
                "yes" if r["enabled"] else "no", "yes" if admins.is_enrolled(r) else "no",
                "locked" if r["locked_until"] > now else "",
                datetime.datetime.fromtimestamp(r["last_login_at"]).strftime("%Y-%m-%d %H:%M")
                if r["last_login_at"] else "-"] for r in admins.list_all(ctx.conn)],
              ["USER", "NAME", "EMAIL", "LANG", "ENABLED", "ENROLLED", "LOCK", "LAST LOGIN"])
        return 0
    if a.action == "add":
        if not a.name or not a.email:
            out("admin add needs --name and --email")
            return 2
        raw, mail_ok = admins.add(ctx, a.username, a.name, a.email, a.lang)
    elif a.action == "reset":
        raw, mail_ok = admins.reset(ctx, a.username)
    elif a.action in ("enable", "disable"):
        admins.set_enabled(ctx, a.username, a.action == "enable")
        out("%s %sd" % (a.username, a.action))
        return 0
    out("Setup link (shown once, valid %d h):" % cfg.setup_link_ttl_hours)
    out("  " + admins.setup_link(cfg, raw))
    out("Mail: %s" % ("sent" if mail_ok else "NOT sent (see audit log); pass the link on yourself"))
    out("The link opens only from the admin allowlist networks.")
    return 0


# user ---------------------------------------------------------------------------------

def cmd_user(cfg, a):
    ctx = service_context(cfg)
    today = ctx.today()
    if a.action == "list":
        table([[r["username"], r["display_name"], r["email"] or "-", r["profile"], r["vpn_ip"], r["expires_on"],
                users.status(r, today)] for r in users.list_all(ctx.conn)],
              ["USER", "NAME", "EMAIL", "PROFILE", "VPN IP", "LAST DAY", "STATUS"])
        out("%d / %d user slots in use" % (users.count(ctx.conn), cfg.max_users))
        return 0
    row = users.require(ctx, a.username)
    if a.action == "show":
        for key in ("username", "display_name", "email", "profile", "vpn_ip", "expires_on", "cert_not_after",
                    "enabled", "adopted", "created_by"):
            out("%-14s %s" % (key, row[key]))
        out("%-14s %s" % ("status", users.status(row, today)))
        out("%-14s %s" % ("enrolled", "yes" if users.is_enrolled(row) else "no"))
        out("%-14s %s" % ("new cert", "at next profile download" if users.needs_new_cert(row) else "no"))
        out("%-14s %s" % ("created", datetime.datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d %H:%M")))
        return 0
    if a.action == "update":
        name = users.validate_display_name(a.name) if a.name else row["display_name"]
        email = users.validate_email(a.email) if a.email else row["email"]
        with db.transaction(ctx.conn):
            ctx.conn.execute("UPDATE vpn_users SET display_name = ?, email = ? WHERE id = ?", (name, email, row["id"]))
            ctx.audit("user.update", a.username, db.detail("name_email", name=name, email=email))
        out("%s updated" % a.username)
        return 0
    if a.action == "link":
        raw, mail_ok = users.reset_user(ctx, a.username)
        out("Setup link (shown once, valid %d h):" % cfg.setup_link_ttl_hours)
        out("  " + users.setup_link(cfg, raw))
        out("Mail: %s" % ("sent" if mail_ok else "NOT sent (see audit log); pass the link on yourself"))
        return 0
    return 2


# profile --------------------------------------------------------------------------------

def cmd_profile(cfg, a):
    if a.action == "list":
        users_by_profile = provision.as_service_user(_profile_counts)
        for p in cfg.profiles.values():
            out("%s%s  (%d users)  %s" % (p.name, " [default]" if p.default else "", users_by_profile.get(p.name, 0),
                                          p.description))
            for d in p.destinations:
                out("    %s" % d)
        return 0
    if a.action == "add":
        return profile_add(cfg, a)
    if a.action == "assign":
        ctx = service_context(cfg)
        users.assign_profile(ctx, a.username, a.profile)
        out("%s now uses profile %s (session closed so the new routes apply)" % (a.username, a.profile))
        return 0
    return 2


def _profile_counts():
    conn = db.connect()
    return {r[0]: r[1] for r in conn.execute("SELECT profile, COUNT(*) FROM vpn_users GROUP BY profile")}


def profile_add(cfg, a):
    """Append a [profile NAME] section to gateway.conf (comments are kept) and apply it."""
    if not PROFILE_RE.match(a.name):
        out("profile name must match %s" % PROFILE_RE.pattern)
        return 2
    if a.name in cfg.profiles:
        out("profile %s already exists" % a.name)
        return 2
    dests = [str(parse_destination(d)) for d in a.dest]
    description = (a.description or a.name).replace("\n", " ")
    section = ("\n# Added by dbo-vpn-gateway profile add on %s\n[profile %s]\ndescription = %s\ndestinations = %s\n"
               % (datetime.date.today().strftime("%d.%m.%Y"), a.name, description, ", ".join(dests)))
    with open(cfg.path, "r", encoding="utf-8") as fh:
        text = fh.read()
    new_cfg = config_mod.parse(text.rstrip("\n") + "\n" + section, cfg.path)   # validate before writing
    with open(cfg.path, "a", encoding="utf-8") as fh:
        fh.write(section)
    out("added [profile %s] to %s" % (a.name, cfg.path))
    fw = firewall.FirewallCmd()
    firewall.apply_permanent(fw, new_cfg, lambda m: out("  " + m))
    live = set(firewall.normalize_rule(r) for r in fw.lines("--policy=%s" % cfg.policy, "--list-rich-rules"))
    old = set(firewall.normalize_rule(r) for r in firewall.desired_rules(cfg))
    if live <= old:
        # Runtime holds only gateway rules: a reload adds the new profile and cuts nobody off.
        fw.cmd("--reload")
        out("firewalld reloaded")
    else:
        out("Runtime firewall still has pre-gateway rules; the profile becomes active with: dbo-vpn-gateway setup --apply")
    return 0


# status / limit -------------------------------------------------------------------------

def _usage():
    conn = db.connect()
    today = datetime.date.today()
    rows = users.list_all(conn)
    counts = {}
    for r in rows:
        s = users.status(r, today)
        counts[s] = counts.get(s, 0) + 1
    return {"count": len(rows), "by_status": counts}


def cmd_limit(cfg, a):
    u = provision.as_service_user(_usage)
    out("%d / %d user slots in use" % (u["count"], cfg.max_users))
    for status, n in sorted(u["by_status"].items()):
        out("  %-9s %d" % (status, n))
    out("Admins do not count. Disabled and expired users count until deleted.")
    out("To change the limit edit max_users in %s." % cfg.path)
    return 0


def cmd_status(cfg, a):
    unit = "openvpn-server@%s.service" % cfg.instance
    for name in [unit, "dbo-vpn-gateway-mgmt.service", "dbo-vpn-gateway-web.service", "nginx.service"]:
        _, state = provision.sh(["/usr/bin/systemctl", "is-active", name], check=False, quiet=True)
        out("%-36s %s" % (name, state.strip()))
    try:
        sessions = SessionControl().list_sessions()
        out("%d connected" % len(sessions))
        for s in sessions:
            out("  %-20s %-15s %s" % (s["common_name"], s["vpn_ip"], s["real_address"]))
    except CtlError as exc:
        out("sessions: %s" % exc)
    return cmd_limit(cfg, a)


# main --------------------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="dbo-vpn-gateway", description="DBO OpenVPN gateway administration (root only)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    sub.required = True

    s = sub.add_parser("setup", help="install or adopt the gateway on this server (idempotent)")
    s.add_argument("--apply", action="store_true", help="also reload firewalld and restart OpenVPN (disconnects users)")

    ad = sub.add_parser("admin", help="customer admin accounts")
    ad.add_argument("action", choices=["add", "list", "disable", "enable", "reset"])
    ad.add_argument("username", nargs="?")
    ad.add_argument("--name")
    ad.add_argument("--email")
    ad.add_argument("--lang", default="tr", choices=["tr", "en"])

    us = sub.add_parser("user", help="VPN users")
    us.add_argument("action", choices=["list", "show", "update", "link"])
    us.add_argument("username", nargs="?")
    us.add_argument("--name")
    us.add_argument("--email")

    pr = sub.add_parser("profile", help="access profiles")
    pr.add_argument("action", choices=["list", "add", "assign"])
    pr.add_argument("args", nargs="*", help="add: NAME; assign: USER PROFILE")
    pr.add_argument("--dest", action="append", default=[], help="ADDRESS[/PREFIX]:PORT[-PORT]/tcp|udp")
    pr.add_argument("--description")

    for name, text in [("status", "services, sessions and usage"), ("limit", "user cap usage"),
                       ("doctor", "health checks"), ("crl-renew", "regenerate the CRL (timer)"),
                       ("autoupdate", "OpenVPN-only update (timer)")]:
        sub.add_parser(name, help=text)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        sys.stderr.write("dbo-vpn-gateway: run as root\n")
        return 2
    os.umask(0o022)
    try:
        cfg = config_mod.load()
    except ConfigError as exc:
        sys.stderr.write("config error: %s\n" % exc)
        return 2

    needs_user = {"admin": a.command == "admin" and a.action != "list",
                  "user": a.command == "user" and a.action != "list"}
    if needs_user.get(a.command) and not a.username:
        sys.stderr.write("%s %s needs a USER argument\n" % (a.command, a.action))
        return 2
    if a.command == "profile":
        need = {"list": 0, "add": 1, "assign": 2}[a.action]
        if len(a.args) != need:
            sys.stderr.write("profile %s takes %d argument(s)\n" % (a.action, need))
            return 2
        if a.action == "add":
            a.name = a.args[0]
            if not a.dest:
                sys.stderr.write("profile add needs at least one --dest\n")
                return 2
        if a.action == "assign":
            a.username, a.profile = a.args

    try:
        if a.command == "setup":
            return provision.setup(cfg, apply=a.apply)
        if a.command == "doctor":
            return provision.doctor(cfg)
        if a.command == "crl-renew":
            return provision.crl_renew(cfg)
        if a.command == "autoupdate":
            return provision.autoupdate(cfg)
        if a.command == "status":
            return cmd_status(cfg, a)
        if a.command == "limit":
            return cmd_limit(cfg, a)
        if a.command == "admin":
            return cmd_admin(cfg, a)
        if a.command == "user":
            return cmd_user(cfg, a)
        if a.command == "profile":
            return cmd_profile(cfg, a)
    except ServiceError as exc:
        sys.stderr.write("refused: %s\n" % explain(exc))
        return 1
    except (ConfigError, PrivError, firewall.FirewallError, RuntimeError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
