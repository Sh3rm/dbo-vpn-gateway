"""Server setup/adoption and health checks (root, called from the CLI).

'setup' is idempotent. On a server that already runs a hand-built OpenVPN
gateway it adopts what is there: the PKI and every valid client certificate
stay as they are, existing users are imported, the old timers and the old
audit/sysctl files are retired. Changes that would interrupt connected users
(firewalld reload, OpenVPN restart) are only made with --apply.
"""

import datetime
import json
import os
import pwd
import shutil
import string
import subprocess
import sys
import time

from dbovpn import SERVICE_USER
from dbovpn import config as config_mod
from dbovpn import firewall, pki

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_templates")

NGINX_SITE = "/etc/nginx/conf.d/dbo-vpn-gateway.conf"
SYSCTL_FILE = "/etc/sysctl.d/90-dbo-vpn-gateway.conf"
AUDIT_FILE = "/etc/audit/rules.d/51-dbo-vpn-gateway.rules"
DNF_AUTOMATIC_FILE = "/etc/dnf/automatic-dbo-vpn-gateway.conf"
WEB_ENV_FILE = "/etc/dbo-vpn-gateway/web.env"
OPENVPN = "/usr/sbin/openvpn"

UNITS = ["dbo-vpn-gateway-mgmt.service", "dbo-vpn-gateway-web.service", "dbo-vpn-gateway-expiry.timer",
         "dbo-vpn-gateway-crl-renew.timer", "dbo-vpn-gateway-autoupdate.timer"]
LEGACY_TIMERS = ["dbo-ovpn-crl-renew.timer", "dbo-ovpn-autoupdate.timer"]
LEGACY_FILES = ["/etc/audit/rules.d/51-dbo-openvpn.rules", "/etc/sysctl.d/90-dbo-openvpn.conf"]
RETIRED_SUFFIX = ".retired-by-dbo-vpn-gateway"


def say(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def sh(argv, check=True, quiet=False):
    """Run a command; return (rc, stdout). Raises on failure when check is set."""
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600, check=False)
    out = proc.stdout.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(argv), proc.returncode, out.strip()[-500:]))
    if not quiet and out.strip() and proc.returncode != 0:
        say(out.strip())
    return proc.returncode, out


def render(name, values):
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8") as fh:
        return string.Template(fh.read()).substitute(values)


def openvpn_values(cfg):
    return {
        "customer": cfg.customer_name, "port": cfg.port, "proto": cfg.proto,
        "network": cfg.subnet.network_address, "netmask": cfg.subnet.netmask,
        "pki_dir": cfg.pki_dir, "server_cert_name": cfg.server_cert_name,
        "tls_crypt_key": cfg.tls_crypt_key, "crl_file": cfg.crl_file,
        "management_socket": cfg.management_socket,
        "token_lifetime": cfg.auth_token_lifetime_hours * 3600,
        # man page --explicit-exit-notify: UDP only.
        "udp_only": "explicit-exit-notify 1" if cfg.proto == "udp" else "",
    }


def nginx_values(cfg):
    allow = "\n".join("        allow %s;" % net.with_prefixlen for net in cfg.admin_allow)
    return {"customer": cfg.customer_name, "https_port": cfg.https_port, "public_hostname": cfg.public_hostname,
            "tls_cert": cfg.tls_cert, "tls_key": cfg.tls_key, "listen_port": cfg.listen_port,
            "allow_lines": allow or "        # no admin_allow networks configured: panel closed"}


def openvpn_conf_path(cfg):
    return os.path.join(cfg.server_dir, cfg.instance + ".conf")


def write_if_changed(path, content, mode=0o644, group=None):
    """Write content atomically if it differs; keep one timestamped backup of the old file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            if fh.read() == content:
                return False
        backup = "%s.bak-%s" % (path, time.strftime("%Y%m%d%H%M%S"))
        shutil.copy2(path, backup)
        say("  backup: %s" % backup)
    except FileNotFoundError:
        pass
    pki.write_atomic(path, content, mode, group)
    say("  wrote: %s" % path)
    return True


# Running work as the service user --------------------------------------------

def drop_privileges():
    pw = pwd.getpwnam(SERVICE_USER)
    os.setgroups([pw.pw_gid])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.environ["HOME"] = pw.pw_dir
    os.umask(0o077)


def as_service_user(func, *args):
    """Run func(*args) in a child process as dbovpn; return its JSON-able result.

    The database must only ever be written by dbovpn, or root-owned WAL files
    would lock the services out.
    """
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rfd)
        code = 0
        try:
            drop_privileges()
            data = json.dumps({"ok": True, "result": func(*args)})
        except Exception as exc:
            data = json.dumps({"ok": False, "error": "%s: %s" % (exc.__class__.__name__, exc)})
            code = 1
        with os.fdopen(wfd, "w") as fh:
            fh.write(data)
        os._exit(code)
    os.close(wfd)
    with os.fdopen(rfd, "r") as fh:
        data = fh.read()
    os.waitpid(pid, 0)
    reply = json.loads(data or '{"ok": false, "error": "child produced no output"}')
    if not reply["ok"]:
        raise RuntimeError(reply["error"])
    return reply["result"]


def db_phase(cfg_path, adopt_names, cert_infos=None):
    """As dbovpn: migrate the database, adopt PKI users, record certificate state,
    return the ipset contents."""
    from dbovpn import db, users
    cfg = config_mod.load(cfg_path)
    conn = db.connect()
    now = int(time.time())
    adopted = []
    with db.transaction(conn):
        for name in adopt_names:
            if users.adopt(conn, cfg, name, "cli:setup", now, datetime.date.today()):
                adopted.append(name)
    with db.transaction(conn):
        for name, info in (cert_infos or {}).items():
            users.record_cert_info(conn, name, info)
    wanted = {name: [] for name in cfg.profiles}
    orphans = []
    for row in users.list_all(conn):
        if row["profile"] in wanted:
            wanted[row["profile"]].append(row["vpn_ip"])
        else:
            orphans.append(row["username"])
    return {"adopted": adopted, "wanted": wanted, "orphans": orphans, "count": users.count(conn)}


# setup -----------------------------------------------------------------------

def setup(cfg, apply=False):
    say("PKI (%s)" % cfg.pki_dir)
    rsa = pki.EasyRSA(cfg)
    with pki.pki_lock(cfg):
        adopt_names, cert_infos = setup_pki(cfg, rsa)
    return setup_rest(cfg, rsa, adopt_names, cert_infos, apply)


def setup_pki(cfg, rsa):
    """PKI part of setup (under pki_lock): create what is missing, list adoptable users."""
    if not rsa.has_ca():
        say("  no CA found, creating a new PKI")
        rsa.init("%s VPN CA" % cfg.customer_name)
    if not rsa.has_cert(cfg.server_cert_name):
        say("  issuing server certificate %s" % cfg.server_cert_name)
        rsa.build_server(cfg.server_cert_name)
    if not os.path.exists(cfg.tls_crypt_key):
        say("  generating tls-crypt key")
        sh([OPENVPN, "--genkey", "tls-crypt", cfg.tls_crypt_key])
        os.chmod(cfg.tls_crypt_key, 0o600)
    if not os.path.exists(cfg.crl_file):
        say("  generating CRL")
        rsa.gen_crl()
    adopt_names = []
    for name in rsa.valid_client_names():
        if not config_mod.USERNAME_RE.match(name):
            say("  WARNING: certificate CN %r is not a valid gateway user name; not adopted" % name)
        elif not rsa.is_client_cert(name):
            say("  WARNING: certificate %r has no clientAuth EKU (or no issued/%s.crt); not adopted" % (name, name))
        else:
            adopt_names.append(name)
    if pki.disable_unique_subject(rsa.path("index.txt.attr"), ".bak-%s" % time.strftime("%Y%m%d%H%M%S")):
        say("  index.txt.attr: unique_subject = yes -> no (backup kept); certificate renewal needs it")
    cert_infos = {name: rsa.cert_info(name) for name in rsa.valid_client_names()
                  if config_mod.USERNAME_RE.match(name)}
    return adopt_names, cert_infos


def setup_rest(cfg, rsa, adopt_names, cert_infos, apply):
    pending = []

    say("OpenVPN server config")
    if write_if_changed(openvpn_conf_path(cfg), render("openvpn-server.conf", openvpn_values(cfg))):
        pending.append("OpenVPN config changed")

    say("sysctl")
    if write_if_changed(SYSCTL_FILE, render("sysctl.conf", {})):
        sh(["/usr/sbin/sysctl", "-q", "-p", SYSCTL_FILE])

    say("audit rules")
    audit_changed = write_if_changed(AUDIT_FILE, render("audit.rules", {}), 0o640)

    say("panel listener")
    write_if_changed(WEB_ENV_FILE, "# Generated by dbo-vpn-gateway setup: gunicorn bind address (from [panel] listen_port).\n"
                     "DBOVPN_LISTEN=127.0.0.1:%d\n" % cfg.listen_port)

    say("dnf-automatic (OpenVPN only)")
    write_if_changed(DNF_AUTOMATIC_FILE, render("dnf-automatic.conf", {}))

    say("legacy pieces")
    for timer in LEGACY_TIMERS:
        rc, _ = sh(["/usr/bin/systemctl", "is-enabled", timer], check=False, quiet=True)
        if rc == 0:
            sh(["/usr/bin/systemctl", "disable", "--now", timer])
            say("  disabled %s (replaced by dbo-vpn-gateway timers)" % timer)
    for path in LEGACY_FILES:
        if os.path.exists(path):
            os.rename(path, path + RETIRED_SUFFIX)
            say("  retired %s -> %s%s" % (path, path, RETIRED_SUFFIX))
            if path.startswith("/etc/audit/"):
                audit_changed = True
    if audit_changed:
        sh(["/usr/sbin/augenrules", "--load"])

    say("firewalld (permanent)")
    ensure_firewalld_running(cfg, log=lambda m: say("  " + m))
    fw = firewall.FirewallCmd()
    if firewall.apply_permanent(fw, cfg, lambda m: say("  " + m)):
        pending.append("firewalld permanent config changed")

    say("database and users")
    result = as_service_user(db_phase, cfg.path, adopt_names, cert_infos)
    for name in result["adopted"]:
        say("  adopted %s (needs a setup link: dbo-vpn-gateway user link %s)" % (name, name))
    for name in result["orphans"]:
        say("  WARNING: user %s has a profile that is not in gateway.conf" % name)
    if result["count"] > cfg.max_users:
        say("  WARNING: %d users exist but max_users is %d; new users are refused until some are deleted"
            % (result["count"], cfg.max_users))
    if firewall.sync_ipset_entries(fw, cfg, result["wanted"], lambda m: say("  " + m)):
        pending.append("firewalld ipset entries changed")

    say("nginx")
    if os.path.exists(cfg.tls_cert) and os.path.exists(cfg.tls_key):
        old = None
        if os.path.exists(NGINX_SITE):
            with open(NGINX_SITE, "r", encoding="utf-8") as fh:
                old = fh.read()
        if write_if_changed(NGINX_SITE, render("nginx-site.conf", nginx_values(cfg))):
            rc, out = sh(["/usr/sbin/nginx", "-t"], check=False, quiet=True)
            if rc != 0:
                say("  ERROR: nginx -t failed, previous site restored:\n" + out.strip())
                if old is None:
                    os.unlink(NGINX_SITE)
                else:
                    pki.write_atomic(NGINX_SITE, old, 0o644)
        sh(["/usr/bin/systemctl", "enable", "--now", "nginx.service"])
        sh(["/usr/bin/systemctl", "reload", "nginx.service"])
    else:
        say("  WARNING: %s or %s missing; nginx site not written" % (cfg.tls_cert, cfg.tls_key))

    allow_panel_port_selinux(cfg)

    say("services")
    sh(["/usr/bin/systemctl", "daemon-reload"])
    sh(["/usr/bin/systemctl", "enable"] + UNITS)
    sh(["/usr/bin/systemctl", "restart", "dbo-vpn-gateway-mgmt.service", "dbo-vpn-gateway-web.service"])
    sh(["/usr/bin/systemctl", "start"] + [u for u in UNITS if u.endswith(".timer")])

    unit = "openvpn-server@%s.service" % cfg.instance
    if apply:
        say("apply: reloading firewalld and restarting %s (connected users reconnect)" % unit)
        sh([firewall.FIREWALL_CMD, "--reload"])
        sh(["/usr/bin/systemctl", "enable", unit])
        sh(["/usr/bin/systemctl", "restart", unit])
    elif pending:
        say("")
        say("PENDING: %s." % "; ".join(pending))
        say("These take effect with a firewalld reload and an OpenVPN restart, which disconnects")
        say("every VPN user for a few seconds. In a maintenance window run:")
        say("  dbo-vpn-gateway setup --apply")
    say("setup finished")
    return 0


# Certificates ---------------------------------------------------------------------

def parse_openssl_date(text):
    """'notAfter=Oct  7 12:00:00 2029 GMT' -> naive UTC datetime, or None."""
    value = text.strip().split("=", 1)[-1].strip()
    try:
        return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return None


def cert_enddate(path):
    rc, out = sh(["/usr/bin/openssl", "x509", "-enddate", "-noout", "-in", path], check=False, quiet=True)
    return parse_openssl_date(out) if rc == 0 else None


# SELinux and firewalld ---------------------------------------------------------------

SEMANAGE = "/usr/sbin/semanage"
FIREWALL_OFFLINE_CMD = "/usr/bin/firewall-offline-cmd"


def port_in_semanage_list(listing, selinux_type, port):
    """True if 'semanage port -l' output gives tcp port to selinux_type (single ports and ranges)."""
    for line in listing.splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[0] == selinux_type and fields[1] == "tcp":
            for item in fields[2].split(","):
                item = item.strip()
                low, _, high = item.partition("-")
                if low.isdigit() and int(low) <= port <= int(high or low):
                    return True
    return False


def allow_panel_port_selinux(cfg, run=None, log=say):
    """Label 127.0.0.1:<listen_port> as http_port_t so nginx (httpd_t) may proxy to it,
    instead of the broad httpd_can_network_connect boolean."""
    run = run or sh
    rc, out = run(["/usr/sbin/getenforce"], check=False, quiet=True)
    if rc != 0 or out.strip() == "Disabled":
        return False
    rc, listing = run([SEMANAGE, "port", "-l"], check=False, quiet=True)
    if rc == 0 and port_in_semanage_list(listing, "http_port_t", cfg.listen_port):
        return False
    port = str(cfg.listen_port)
    rc, _ = run([SEMANAGE, "port", "-a", "-t", "http_port_t", "-p", "tcp", port], check=False, quiet=True)
    if rc != 0:   # already defined with another type
        run([SEMANAGE, "port", "-m", "-t", "http_port_t", "-p", "tcp", port])
    log("SELinux: tcp port %s labelled http_port_t (nginx -> panel)" % port)
    return True


def parse_sshd_ports(text):
    """Ports sshd really listens on, from 'sshd -T' output.

    'listenaddress HOST:PORT' lines win (with 'ListenAddress 0.0.0.0:2222' sshd -T
    still prints 'port 22'); IPv6 appears as '[::]:2222'. 'port' lines are the
    fallback when no listenaddress carries a port."""
    ports, fallback = set(), set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        key, value = fields[0].lower(), fields[1]
        if key == "listenaddress" and ":" in value:
            port = value.rsplit(":", 1)[1]
            if port.isdigit() and not value.endswith("]"):
                ports.add(port)
        elif key == "port" and value.isdigit():
            fallback.add(value)
    return sorted(ports or fallback, key=int)


def ssh_ports(run):
    rc, out = run(["/usr/sbin/sshd", "-T"], check=False, quiet=True)
    if rc != 0:
        return []
    return parse_sshd_ports(out)


def ensure_firewalld_running(cfg, run=None, log=say):
    """Start firewalld if it is stopped, without locking the operator out.

    Before the first start, every port sshd listens on (sshd -T) is made
    reachable in the public zone and in the default zone through
    firewall-offline-cmd. Nothing the operator configured is removed.
    Returns True if firewalld was started.
    """
    run = run or sh
    rc, _ = run(["/usr/bin/systemctl", "is-active", "--quiet", "firewalld.service"], check=False, quiet=True)
    if rc == 0:
        return False
    ports = ssh_ports(run)
    if not ports:
        raise RuntimeError("firewalld is not running and the SSH port could not be read with 'sshd -T'; "
                           "not starting firewalld. Allow the SSH port, start firewalld, then run setup again.")
    rc, default_zone = run([FIREWALL_OFFLINE_CMD, "--get-default-zone"], check=False, quiet=True)
    zones = [cfg.public_zone]
    if rc == 0 and default_zone.strip() and default_zone.strip() not in zones:
        zones.append(default_zone.strip())
    for zone in zones:
        z = "--zone=%s" % zone
        ssh_service_ports = []
        if run([FIREWALL_OFFLINE_CMD, z, "--query-service=ssh"], check=False, quiet=True)[0] == 0:
            _, info = run([FIREWALL_OFFLINE_CMD, "--info-service=ssh"], check=False, quiet=True)
            for line in info.splitlines():
                if line.strip().startswith("ports:"):
                    ssh_service_ports = [p.split("/")[0] for p in line.split(":", 1)[1].split()]
        for port in ports:
            if port in ssh_service_ports:
                continue
            if run([FIREWALL_OFFLINE_CMD, z, "--query-port=%s/tcp" % port], check=False, quiet=True)[0] == 0:
                continue
            run([FIREWALL_OFFLINE_CMD, z, "--add-port=%s/tcp" % port])
            log("firewalld: allowed SSH port %s/tcp in zone %s before starting firewalld" % (port, zone))
    run(["/usr/bin/systemctl", "enable", "--now", "firewalld.service"])
    log("firewalld: enabled and started (SSH port(s) %s allowed)" % ", ".join(ports))
    return True


# crl-renew / autoupdate (timers) -----------------------------------------------

def crl_renew(cfg):
    rsa = pki.EasyRSA(cfg)
    with pki.pki_lock(cfg):
        rsa.gen_crl()
    _, out = sh(["/usr/bin/openssl", "crl", "-in", cfg.crl_file, "-noout", "-nextupdate"], check=False)
    say("CRL renewed, %s" % out.strip())
    rc, _ = sh(["/usr/bin/openssl", "x509", "-checkend", str(60 * 86400), "-noout", "-in",
                rsa.cert_path(cfg.server_cert_name)], check=False, quiet=True)
    if rc != 0:
        sys.stderr.write("WARNING: OpenVPN server certificate %s expires within 60 days, renew it\n"
                         % cfg.server_cert_name)
    return 0


def autoupdate(cfg):
    """Install new OpenVPN releases; restart OpenVPN if the package or its libraries changed."""
    unit = "openvpn-server@%s.service" % cfg.instance
    _, before = sh(["/usr/bin/rpm", "-q", "openvpn"])
    sh(["/usr/bin/dnf-automatic", DNF_AUTOMATIC_FILE, "--installupdates"])
    _, after = sh(["/usr/bin/rpm", "-q", "openvpn"])
    _, needs = sh(["/usr/bin/dnf", "-q", "needs-restarting", "-s"], check=False, quiet=True)
    if before.strip() != after.strip():
        say("OpenVPN updated: %s -> %s, restarting %s" % (before.strip(), after.strip(), unit))
        sh(["/usr/bin/systemctl", "restart", unit])
    elif unit in [line.strip() for line in needs.splitlines()]:
        say("OpenVPN uses updated libraries, restarting %s" % unit)
        sh(["/usr/bin/systemctl", "restart", unit])
    else:
        say("OpenVPN unchanged: %s" % after.strip())
    return 0


# doctor ----------------------------------------------------------------------------

def cert_short_list(rsa, accounts):
    """(username, cert end, last valid day) for accounts whose certificate ends first."""
    short = []
    for username, expires_on in accounts:
        end = rsa.cert_end(username)
        if end is not None and end.isoformat() < expires_on:
            short.append((username, end.isoformat(), expires_on))
    return short


class DryRunFirewall(firewall.FirewallCmd):
    """Runs only read commands; records what setup would change."""

    MUTATING = ("--new-", "--set-", "--add-", "--remove-")

    def __init__(self):
        firewall.FirewallCmd.__init__(self)
        self.would = []

    def cmd(self, *args, **kwargs):
        if any(a.startswith(self.MUTATING) for a in args):
            self.would.append(" ".join(args))
            return ""
        return firewall.FirewallCmd.cmd(self, *args, **kwargs)


def doctor(cfg):
    problems = []

    def check(ok, text, hint=""):
        say("%s %s" % ("OK  " if ok else "FAIL", text))
        if not ok:
            problems.append(text)
            if hint:
                say("     " + hint)

    rsa = pki.EasyRSA(cfg)
    check(rsa.has_ca(), "CA present in %s" % cfg.pki_dir)
    check(rsa.has_cert(cfg.server_cert_name), "server certificate %s" % cfg.server_cert_name)
    if rsa.has_cert(cfg.server_cert_name):
        end = cert_enddate(rsa.cert_path(cfg.server_cert_name))
        if end is None:
            check(False, "server certificate end date readable")
        else:
            days = (end - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            check(days >= 60, "server certificate valid until %s (%d days left)" % (end.strftime("%Y-%m-%d"), days),
                  "renew it before it expires")
    check(not rsa.unique_subject_enabled(), "index.txt.attr has unique_subject = no (renewal possible)",
          "run: dbo-vpn-gateway setup")
    check(os.path.exists(cfg.tls_crypt_key), "tls-crypt key %s" % cfg.tls_crypt_key)
    if os.path.exists(cfg.crl_file):
        rc, _ = sh(["/usr/bin/openssl", "crl", "-in", cfg.crl_file, "-noout"], check=False, quiet=True)
        _, out = sh(["/usr/bin/openssl", "crl", "-in", cfg.crl_file, "-noout", "-nextupdate"], check=False,
                    quiet=True)
        check(rc == 0, "CRL %s readable (%s)" % (cfg.crl_file, out.strip()))
    else:
        check(False, "CRL %s exists" % cfg.crl_file)

    try:
        with open(openvpn_conf_path(cfg), "r", encoding="utf-8") as fh:
            same = fh.read() == render("openvpn-server.conf", openvpn_values(cfg))
    except OSError:
        same = False
    check(same, "OpenVPN config matches gateway.conf", "run: dbo-vpn-gateway setup")

    unit = "openvpn-server@%s.service" % cfg.instance
    for name in [unit, "dbo-vpn-gateway-mgmt.service", "dbo-vpn-gateway-web.service", "nginx.service"]:
        rc, _ = sh(["/usr/bin/systemctl", "is-active", "--quiet", name], check=False, quiet=True)
        check(rc == 0, "%s active" % name, "journalctl -u %s -n 50" % name)
    for name in [u for u in UNITS if u.endswith(".timer")]:
        rc, _ = sh(["/usr/bin/systemctl", "is-enabled", "--quiet", name], check=False, quiet=True)
        check(rc == 0, "%s enabled" % name)
    for timer in LEGACY_TIMERS:
        rc, _ = sh(["/usr/bin/systemctl", "is-enabled", "--quiet", timer], check=False, quiet=True)
        check(rc != 0, "legacy %s not enabled" % timer, "run: dbo-vpn-gateway setup")

    check(os.path.exists(cfg.management_socket), "management socket %s" % cfg.management_socket)
    from dbovpn.ctl import CtlError, SessionControl
    try:
        n = len(SessionControl().list_sessions())
        check(True, "management daemon answers (%d connected)" % n)
    except CtlError as exc:
        check(False, "management daemon answers (%s)" % exc)

    fw = DryRunFirewall()
    try:
        firewall.apply_permanent(fw, cfg, lambda m: None)
        check(not fw.would, "firewalld permanent config as configured",
              "setup would run: " + "; ".join(fw.would[:5]))
        perm = set(firewall.normalize_rule(r) for r in fw.lines("--permanent", "--policy=%s" % cfg.policy,
                                                                 "--list-rich-rules"))
        live = set(firewall.normalize_rule(r) for r in fw.lines("--policy=%s" % cfg.policy, "--list-rich-rules"))
        check(perm == live, "firewalld runtime rules equal permanent rules", "run: dbo-vpn-gateway setup --apply")
    except firewall.FirewallError as exc:
        check(False, "firewalld readable (%s)" % exc)

    try:
        with open("/proc/sys/net/ipv4/ip_forward") as fh:
            check(fh.read().strip() == "1", "net.ipv4.ip_forward = 1")
    except OSError:
        check(False, "net.ipv4.ip_forward readable")

    rc, _ = sh(["/usr/sbin/visudo", "-cqf", "/etc/sudoers.d/dbo-vpn-gateway"], check=False, quiet=True)
    check(rc == 0, "sudoers drop-in valid")
    rc, out = sh(["/usr/sbin/nginx", "-t"], check=False, quiet=True)
    check(rc == 0, "nginx -t", out.strip().splitlines()[-1] if out.strip() else "")

    def db_report(cfg_path):
        from dbovpn import db, users, admins
        c = config_mod.load(cfg_path)
        conn = db.connect()
        rows = users.list_all(conn)
        return {"users": len(rows), "max": c.max_users,
                "admins": sum(1 for a in admins.list_all(conn) if a["enabled"] and admins.is_enrolled(a)),
                "ips": {r["profile"]: [x["vpn_ip"] for x in rows if x["profile"] == r["profile"]] for r in rows},
                "accounts": [[r["username"], r["expires_on"]] for r in rows if r["enabled"]]}
    try:
        rep = as_service_user(db_report, cfg.path)
        check(rep["users"] <= rep["max"], "users %d / max_users %d" % (rep["users"], rep["max"]))
        check(rep["admins"] > 0, "at least one enrolled, enabled admin (%d)" % rep["admins"],
              "dbo-vpn-gateway admin add ...")
        short = cert_short_list(rsa, rep["accounts"])
        check(not short, "client certificates outlive their accounts (%d enabled users)" % len(rep["accounts"]),
              "; ".join("%s: certificate ends %s, last valid day %s" % s for s in short[:10])
              + " -> reset these users (new setup link issues a new certificate)")
    except Exception as exc:
        check(False, "database readable (%s)" % exc)
        rep = {"ips": {}}
    for profile, ips in rep["ips"].items():
        if profile not in cfg.profiles:
            continue
        ipset = cfg.profiles[profile].ipset
        label = "firewalld ipset %s runtime entries match the database" % ipset
        try:
            entries = set(fw.words("--ipset=%s" % ipset, "--get-entries"))
        except firewall.FirewallError as exc:
            check(False, label, "runtime ipset not readable (%s); run: dbo-vpn-gateway setup --apply" % exc)
            continue
        missing = sorted(set(ips) - entries)
        check(not missing, label, "missing at runtime: %s" % ", ".join(missing))

    say("")
    say("%d problem(s)" % len(problems) if problems else "all checks passed")
    return 1 if problems else 0
