"""Easy-RSA 3.2 wrapper and .ovpn builder. Runs as root (privhelper, CLI).

The command runner is injectable so tests can record the calls instead of
running easyrsa.
"""

import contextlib
import datetime
import fcntl
import grp
import os
import re
import shutil
import subprocess
import tempfile

PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


class PKIError(Exception):
    pass


# Easy-RSA sources a 'vars' file from the current directory among other places,
# so it runs from the PKI directory with a minimal environment.
MINIMAL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
OPENSSL = "/usr/bin/openssl"
CLIENT_AUTH_EKU = "TLS Web Client Authentication"
HELD_SUFFIX = ".dbovpn-held"


@contextlib.contextmanager
def pki_lock(cfg):
    """Exclusive lock serialising every PKI change (privhelper, setup, CRL renewal).

    Two panel workers renewing the same user at once would otherwise leave an
    extra valid serial in index.txt that is in no file and can never be revoked.
    """
    directory = cfg.pki_dir if os.path.isdir(cfg.pki_dir) else cfg.server_dir
    fd = os.open(os.path.join(directory, ".dbo-vpn-gateway.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_unique_subject(attr_path):
    """True if index.txt.attr says 'unique_subject = yes' (OpenSSL then refuses a second
    valid certificate with the same subject, which a renewal needs for a moment)."""
    try:
        with open(attr_path, "r", encoding="utf-8") as fh:
            for line in fh:
                key, _, value = line.partition("=")
                if key.strip() == "unique_subject":
                    return value.strip().lower() in ("yes", "y", "true", "1")
    except FileNotFoundError:
        pass
    return False


def disable_unique_subject(attr_path, backup_suffix):
    """Rewrite unique_subject = yes to no, keeping a backup. Returns True if changed."""
    if not read_unique_subject(attr_path):
        return False
    with open(attr_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    shutil.copy2(attr_path, attr_path + backup_suffix)
    lines = ["unique_subject = no" if l.partition("=")[0].strip() == "unique_subject" else l
             for l in text.splitlines()]
    write_atomic(attr_path, "\n".join(lines) + "\n", 0o600)
    return True


def key_is_encrypted(pem):
    """True for PKCS#8 'ENCRYPTED PRIVATE KEY' and legacy 'Proc-Type: 4,ENCRYPTED' keys."""
    return "ENCRYPTED" in pem


def default_runner(argv, cwd=None):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False,
                          cwd=cwd, env=dict(MINIMAL_ENV))
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise PKIError("%s failed: %s" % (" ".join([os.path.basename(argv[0])] + argv[1:]),
                                          err[-1] if err else proc.returncode))
    return proc.stdout.decode("utf-8", "replace")


class EasyRSA(object):
    def __init__(self, cfg, run=default_runner):
        self.cfg = cfg
        self.run = run

    def _easyrsa(self, *args):
        pki = self.cfg.pki_dir
        cwd = pki if os.path.isdir(pki) else os.path.dirname(pki.rstrip("/"))
        return self.run([self.cfg.easyrsa, "--batch", "--pki=%s" % pki] + list(args), cwd=cwd)

    def path(self, *parts):
        return os.path.join(self.cfg.pki_dir, *parts)

    def cert_path(self, name):
        return self.path("issued", name + ".crt")

    def key_path(self, name):
        return self.path("private", name + ".key")

    def has_ca(self):
        return os.path.exists(self.path("ca.crt"))

    def has_cert(self, name):
        return os.path.exists(self.cert_path(name)) and os.path.exists(self.key_path(name))

    def init(self, ca_cn):
        """Create a new PKI with a passphrase-less CA (needed for unattended issuing)."""
        self._easyrsa("init-pki")
        self._easyrsa("--req-cn=%s" % ca_cn, "build-ca", "nopass")

    def build_server(self, name):
        self._easyrsa("build-server-full", name, "nopass")

    def build_client(self, name):
        # The client key is unencrypted: password + TOTP replace the key passphrase.
        self._easyrsa("--days=%d" % self.cfg.client_cert_days, "build-client-full", name, "nopass")
        if not self.is_client_cert(name):
            raise PKIError("issued certificate for %s has no clientAuth extended key usage" % name)

    def is_client_cert(self, name):
        """True if issued/<name>.crt exists and carries the clientAuth EKU.

        Without this check a server certificate (or any other leaf of the CA)
        could be adopted or packed into a client profile."""
        path = self.cert_path(name)
        if not os.path.exists(path):
            return False
        try:
            out = self.run([OPENSSL, "x509", "-in", path, "-noout", "-ext", "extendedKeyUsage"])
        except PKIError:
            return False
        return CLIENT_AUTH_EKU in out

    def revoke(self, name):
        self._easyrsa("revoke", name)
        self.gen_crl()

    def gen_crl(self):
        """Regenerate the CRL and replace the file OpenVPN reads atomically (root:openvpn 0640)."""
        self._easyrsa("gen-crl")
        install_atomic(self.path("crl.pem"), self.cfg.crl_file, 0o640, group="openvpn")

    def cert_serial(self, name, path=None):
        out = self.run([OPENSSL, "x509", "-in", path or self.cert_path(name), "-noout", "-serial"])
        return out.strip().split("=", 1)[-1].upper()

    def cert_end(self, name):
        """notAfter of issued/<name>.crt as a date (UTC), or None."""
        try:
            out = self.run([OPENSSL, "x509", "-in", self.cert_path(name), "-noout", "-enddate"])
        except PKIError:
            return None
        value = out.strip().split("=", 1)[-1].strip()
        try:
            return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").date()
        except ValueError:
            return None

    def key_encrypted(self, name):
        return key_is_encrypted(_read(self.key_path(name))) if os.path.exists(self.key_path(name)) else False

    def cert_info(self, name):
        end = self.cert_end(name) if self.has_cert(name) else None
        return {"not_after": end.isoformat() if end else None,
                "key_encrypted": self.key_encrypted(name),
                "client_eku": self.is_client_cert(name)}

    def renew_client(self, name):
        """Replace <name>'s certificate AND key, revoking the old serial only after the
        new pair exists.

        Easy-RSA 3.2.1 refuses build-client-full while issued/<name>.crt,
        private/<name>.key or reqs/<name>.req exist, and plain 'revoke' would
        invalidate the old certificate before the new one is ready. So:
          1. 'expire <name>' moves the old cert to expired/ (still valid),
          2. the old key/req are set aside (*.dbovpn-held),
          3. build-client-full makes a fresh unencrypted key + cert,
          4. 'revoke-expired <name> superseded' revokes the old serial
             (it leaves key/req alone), the set-aside key/req go where
             Easy-RSA keeps revoked material, and the CRL is regenerated.
        Any failure before step 4 restores the old state. If an earlier run
        stopped after step 3, it is finished first. Callers hold pki_lock().
        """
        expired = self.path("expired", name + ".crt")
        if os.path.exists(expired):
            old_serial = self.cert_serial(name, expired)
            if os.path.exists(self.cert_path(name)):
                # An earlier run built the new pair but did not finish: finish it now.
                self._finish_renewal(name, old_serial)
                return old_serial
            # An earlier run stopped before the build: put the old pair back first.
            self._restore_held(name)
            os.rename(expired, self.cert_path(name))
        if not os.path.exists(self.cert_path(name)):
            raise PKIError("no certificate for %s to renew" % name)
        serial = self.cert_serial(name)
        self._easyrsa("expire", name)
        try:
            for path in (self.key_path(name), self.path("reqs", name + ".req")):
                if os.path.exists(path):
                    os.rename(path, path + HELD_SUFFIX)
            self.build_client(name)
        except Exception:
            for path in (self.cert_path(name), self.key_path(name), self.path("reqs", name + ".req")):
                if os.path.exists(path):
                    os.unlink(path)
            self._restore_held(name)
            os.rename(expired, self.cert_path(name))
            raise
        self._finish_renewal(name, serial)
        return serial

    def _held(self, name):
        return [(self.key_path(name), "private_by_serial", ".key"),
                (self.path("reqs", name + ".req"), "reqs_by_serial", ".req")]

    def _restore_held(self, name):
        for path, _, _ in self._held(name):
            if os.path.exists(path + HELD_SUFFIX) and not os.path.exists(path):
                os.rename(path + HELD_SUFFIX, path)

    def _finish_renewal(self, name, serial):
        """Steps 4-5: revoke the expired (old) serial, file the held key/req, regenerate the CRL."""
        if os.path.exists(self.path("expired", name + ".crt")):
            self._easyrsa("revoke-expired", name, "superseded")
        for path, sub, ext in self._held(name):
            if os.path.exists(path + HELD_SUFFIX):
                dest = self.path("revoked", sub, serial + ext)
                if os.path.isdir(os.path.dirname(dest)) and not os.path.exists(dest):
                    os.rename(path + HELD_SUFFIX, dest)
                else:
                    os.unlink(path + HELD_SUFFIX)
        self.gen_crl()

    def unique_subject_enabled(self):
        return read_unique_subject(self.path("index.txt.attr"))

    def cert_cn(self, name):
        """Subject CN of issued/<name>.crt (openssl -nameopt RFC2253), or None."""
        try:
            out = self.run([OPENSSL, "x509", "-in", self.cert_path(name), "-noout", "-subject", "-nameopt", "RFC2253"])
        except PKIError:
            return None
        m = re.search(r"(?:^|[=,])\s*CN=((?:[^,\\]|\\.)+)", out.strip())
        return m.group(1) if m else None

    def valid_client_names(self):
        """CNs of valid (V) certificates in index.txt, without the server certificate."""
        names = []
        for status, subject in read_index(self.path("index.txt")):
            m = re.search(r"/CN=([^/]+)", subject)
            if status == "V" and m and m.group(1) != self.cfg.server_cert_name and m.group(1) not in names:
                names.append(m.group(1))
        return names


def read_index(path):
    """(status, subject) for each line of an OpenSSL CA index.txt (tab-separated)."""
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                fields = line.rstrip("\n").split("\t")
                if len(fields) >= 6:
                    rows.append((fields[0], fields[5]))
    except FileNotFoundError:
        pass
    return rows


def install_atomic(src, dst, mode, group=None):
    """Copy src to a temp file next to dst, set mode/group, then rename over dst."""
    with open(src, "rb") as fh:
        data = fh.read()
    write_atomic(dst, data, mode, group)


def write_atomic(dst, data, mode, group=None, owner_uid=0):
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory = os.path.dirname(dst) or "."
    fd, tmp = tempfile.mkstemp(prefix=".dbovpn-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0:
            gid = grp.getgrnam(group).gr_gid if group else 0
            os.chown(tmp, owner_uid, gid)
        os.rename(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def config_quote(value):
    """Quote an OpenVPN config argument if it is not a plain token."""
    if re.match(r"^[A-Za-z0-9._@-]+\Z", value):
        return value
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def build_ovpn(cfg, name, rsa=None):
    """Client profile text: the header of the old dbo-ovpn-profile script plus
    auth-user-pass, auth-nocache, static-challenge and inline ca/cert/key/tls-crypt."""
    rsa = rsa or EasyRSA(cfg)
    if not rsa.has_cert(name):
        raise PKIError("no certificate for %s" % name)
    if not rsa.is_client_cert(name):
        raise PKIError("certificate for %s is not a client certificate (no clientAuth EKU)" % name)
    key = _read(rsa.key_path(name))
    if key_is_encrypted(key):
        # Password + TOTP replace the key passphrase; never hand out a protected key.
        raise PKIError("private key of %s is passphrase-protected; issue a fresh certificate first" % name)
    cert = PEM_CERT_RE.search(_read(rsa.cert_path(name)))
    if not cert:
        raise PKIError("certificate file for %s has no PEM block" % name)
    proto = "udp" if cfg.proto == "udp" else "tcp-client"
    lines = [
        "# %s VPN profile for %s, generated by dbo-vpn-gateway on %s"
        % (cfg.customer_name, name, datetime.date.today().isoformat()),
        "client",
        "dev tun",
        "proto %s" % proto,
        "remote %s %d" % (cfg.public_hostname, cfg.port),
        "resolv-retry infinite",
        "nobind",
        "persist-tun",
        "remote-cert-tls server",
        # Pin the server certificate's CN as well, not only its EKU (MAN 3275-3296).
        "verify-x509-name %s name" % config_quote(rsa.cert_cn(cfg.server_cert_name) or cfg.server_cert_name),
        "auth-user-pass",
        "auth-nocache",
        # man page --static-challenge: 'static-challenge text echo [format]'; format
        # defaults to scrv1, left out so 2.6 clients accept the line too.
        'static-challenge "%s" 1' % cfg.static_challenge_text,
        "verb 3",
        "<ca>", _read(rsa.path("ca.crt")).strip(), "</ca>",
        "<cert>", cert.group(0).strip(), "</cert>",
        "<key>", key.strip(), "</key>",
        "<tls-crypt>", _read(cfg.tls_crypt_key).strip(), "</tls-crypt>",
    ]
    return "\n".join(lines) + "\n"
