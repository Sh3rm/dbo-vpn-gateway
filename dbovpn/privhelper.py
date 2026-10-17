"""Root helper, run by dbovpn through sudo (/usr/libexec/dbo-vpn-gateway/privhelper).

Fixed subcommands, every argument validated before anything runs:
  issue-cert  USERNAME          Easy-RSA build-client-full USERNAME nopass
  revoke-cert USERNAME          Easy-RSA revoke + gen-crl, CRL replaced atomically
  renew-cert  USERNAME          fresh key + cert for the same CN, old serial revoked afterwards
  cert-info   USERNAME          JSON: certificate end date, key encrypted?, clientAuth EKU?
  build-ovpn  USERNAME          client profile to stdout
  ipset-add   PROFILE IP        add the user's VPN address to a profile ipset
  ipset-del   PROFILE IP        remove it
The config path is fixed; nothing from the caller's environment is used.
"""

import ipaddress
import json
import os
import sys

from dbovpn import CONFIG_PATH
from dbovpn import config as config_mod
from dbovpn.config import USERNAME_RE

COMMANDS = {
    "issue-cert": ("username",),
    "revoke-cert": ("username",),
    "renew-cert": ("username",),
    "cert-info": ("username",),
    "build-ovpn": ("username",),
    "ipset-add": ("profile", "ip"),
    "ipset-del": ("profile", "ip"),
}


class UsageError(Exception):
    pass


def validate(argv, cfg):
    """Return (command, args) or raise UsageError. argv excludes the program name."""
    if not argv or argv[0] not in COMMANDS:
        raise UsageError("unknown command")
    command, args = argv[0], list(argv[1:])
    spec = COMMANDS[command]
    if len(args) != len(spec):
        raise UsageError("%s takes %d argument(s)" % (command, len(spec)))
    for kind, value in zip(spec, args):
        if kind == "username":
            if not USERNAME_RE.match(value) or value == cfg.server_cert_name:
                raise UsageError("invalid username")
        elif kind == "profile":
            if value not in cfg.profiles:
                raise UsageError("unknown profile")
        elif kind == "ip":
            try:
                ip = ipaddress.IPv4Address(value)
            except ValueError:
                raise UsageError("invalid address")
            if ip not in config_mod.client_ip_range(cfg) or str(ip) != value:
                raise UsageError("address outside the VPN client range")
    return command, args


def run(command, args, cfg, rsa=None, fw=None, out=None):
    from dbovpn import firewall, pki
    rsa = rsa or pki.EasyRSA(cfg)
    out = out or sys.stdout
    if command == "issue-cert":
        if rsa.has_cert(args[0]):
            raise UsageError("certificate already exists")
        rsa.build_client(args[0])
    elif command == "revoke-cert":
        if not os.path.exists(rsa.cert_path(args[0])):
            # Nothing to revoke (never issued or already revoked): still refresh the CRL.
            rsa.gen_crl()
        else:
            rsa.revoke(args[0])
    elif command == "renew-cert":
        if os.path.exists(rsa.cert_path(args[0])):
            rsa.renew_client(args[0])
        else:
            rsa.build_client(args[0])      # no certificate at all: issue one
    elif command == "cert-info":
        out.write(json.dumps(rsa.cert_info(args[0])) + "\n")
    elif command == "build-ovpn":
        out.write(pki.build_ovpn(cfg, args[0], rsa))
    elif command in ("ipset-add", "ipset-del"):
        fw = fw or firewall.FirewallCmd()
        firewall.ipset_entry(fw, cfg.profiles[args[0]].ipset, args[1], command == "ipset-add")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        sys.stderr.write("privhelper: must run as root\n")
        return 2
    os.umask(0o077)
    try:
        cfg = config_mod.load(CONFIG_PATH)
        command, args = validate(argv, cfg)
        from dbovpn import pki
        with pki.pki_lock(cfg):
            run(command, args, cfg)
    except UsageError as exc:
        sys.stderr.write("privhelper: %s\n" % exc)
        return 2
    except Exception as exc:  # report one line to the caller, no traceback with paths/keys
        sys.stderr.write("privhelper: %s: %s\n" % (exc.__class__.__name__, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
