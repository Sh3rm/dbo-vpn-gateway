"""Calls the root helper through sudo. The only path from dbovpn to root.

The sudoers drop-in allows dbovpn to run exactly /usr/libexec/dbo-vpn-gateway/privhelper;
the helper validates every argument itself.
"""

import subprocess

from dbovpn import PRIVHELPER_PATH

SUDO = "/usr/bin/sudo"


class PrivError(Exception):
    pass


class Privileged(object):
    """Interface to root-only operations. Tests use a fake with the same methods."""

    def __init__(self, helper=PRIVHELPER_PATH, use_sudo=True, timeout=180):
        self.helper = helper
        self.use_sudo = use_sudo
        self.timeout = timeout

    def _run(self, *args):
        argv = ([SUDO, "-n"] if self.use_sudo else []) + [self.helper] + list(args)
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PrivError("privhelper %s failed: %s" % (args[0], exc))
        if proc.returncode != 0:
            msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise PrivError("privhelper %s failed: %s" % (args[0], msg[-1] if msg else proc.returncode))
        return proc.stdout

    def issue_cert(self, username):
        self._run("issue-cert", username)

    def revoke_cert(self, username):
        self._run("revoke-cert", username)

    def renew_cert(self, username):
        self._run("renew-cert", username)

    def cert_info(self, username):
        import json
        try:
            return json.loads(self._run("cert-info", username).decode("utf-8"))
        except ValueError:
            raise PrivError("privhelper cert-info: bad output")

    def build_ovpn(self, username):
        return self._run("build-ovpn", username).decode("utf-8")

    def ipset_add(self, profile, ip):
        self._run("ipset-add", profile, str(ip))

    def ipset_del(self, profile, ip):
        self._run("ipset-del", profile, str(ip))
