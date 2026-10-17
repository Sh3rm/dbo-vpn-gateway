"""Load and validate /etc/dbo-vpn-gateway/gateway.conf.

Every customer-specific value lives in that one INI file. A Config object is
plain data; nothing here touches the system.
"""

import configparser
import ipaddress
import os
import re

from dbovpn import CONFIG_PATH

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}\Z")
# ipset names are limited to 31 characters; "dbovpn-" takes 7 of them.
PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}\Z")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
ZONE_RE = re.compile(r"^[A-Za-z0-9_-]{1,17}\Z")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z")
SUPPORTED_LANGUAGES = ("tr", "en")


class ConfigError(Exception):
    pass


class Destination(object):
    """One allowed destination of an access profile: network, port(s), protocol."""

    def __init__(self, network, port_from, port_to, proto):
        self.network = network
        self.port_from = port_from
        self.port_to = port_to
        self.proto = proto

    @property
    def port_spec(self):
        if self.port_from == self.port_to:
            return str(self.port_from)
        return "%d-%d" % (self.port_from, self.port_to)

    def __str__(self):
        return "%s:%s/%s" % (self.network.with_prefixlen, self.port_spec, self.proto)

    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(str(self))


def parse_destination(text):
    """Parse 'ADDRESS[/PREFIX]:PORT[-PORT]/PROTO', e.g. '203.0.113.10/32:443/tcp'."""
    m = re.match(r"^\s*([0-9.]+(?:/[0-9]{1,2})?):([0-9]{1,5})(?:-([0-9]{1,5}))?/(tcp|udp)\s*\Z", text)
    if not m:
        raise ConfigError("bad destination %r, expected ADDRESS[/PREFIX]:PORT[-PORT]/tcp|udp" % text)
    try:
        network = ipaddress.IPv4Network(m.group(1), strict=True)
    except ValueError as exc:
        raise ConfigError("bad destination address %r: %s" % (m.group(1), exc))
    port_from = int(m.group(2))
    port_to = int(m.group(3) or m.group(2))
    if not (1 <= port_from <= port_to <= 65535):
        raise ConfigError("bad port range in destination %r" % text)
    return Destination(network, port_from, port_to, m.group(4))


class Profile(object):
    def __init__(self, name, description, destinations, default):
        self.name = name
        self.description = description
        self.destinations = destinations
        self.default = default

    @property
    def ipset(self):
        return "dbovpn-" + self.name

    def routes(self):
        """Distinct networks to push as client routes, in config order."""
        seen = []
        for d in self.destinations:
            if d.network not in seen:
                seen.append(d.network)
        return seen


class Config(object):
    """Validated gateway configuration. Attribute names follow the INI keys."""

    def __init__(self, path=None):
        self.path = path


def _get(cp, section, key, default=None, required=False):
    if cp.has_option(section, key):
        value = cp.get(section, key).strip()
        if value != "":
            return value
    if required:
        raise ConfigError("[%s] %s is required" % (section, key))
    return default


def _get_int(cp, section, key, default, minimum=None, maximum=None):
    raw = _get(cp, section, key, None)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            raise ConfigError("[%s] %s must be an integer" % (section, key))
    if minimum is not None and value < minimum:
        raise ConfigError("[%s] %s must be >= %d" % (section, key, minimum))
    if maximum is not None and value > maximum:
        raise ConfigError("[%s] %s must be <= %d" % (section, key, maximum))
    return value


def _get_bool(cp, section, key, default):
    raw = _get(cp, section, key, None)
    if raw is None:
        return default
    if raw.lower() in ("1", "yes", "true", "on"):
        return True
    if raw.lower() in ("0", "no", "false", "off"):
        return False
    raise ConfigError("[%s] %s must be yes or no" % (section, key))


def _get_list(cp, section, key):
    raw = _get(cp, section, key, "") or ""
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


def parse(text, path=None):
    """Parse config text into a validated Config. Raises ConfigError."""
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text, source=path or "<config>")
    except configparser.Error as exc:
        raise ConfigError(str(exc))

    c = Config(path)

    # [gateway]
    c.customer_name = _get(cp, "gateway", "customer_name", required=True)
    c.public_hostname = _get(cp, "gateway", "public_hostname", required=True)
    if not HOSTNAME_RE.match(c.public_hostname):
        raise ConfigError("[gateway] public_hostname is not a valid host name")
    c.languages = _get_list(cp, "gateway", "languages") or ["tr", "en"]
    for lang in c.languages:
        if lang not in SUPPORTED_LANGUAGES:
            raise ConfigError("[gateway] languages: unsupported language %r" % lang)
    c.mail_language = _get(cp, "gateway", "mail_language", c.languages[0])
    if c.mail_language not in SUPPORTED_LANGUAGES:
        raise ConfigError("[gateway] mail_language must be one of %s" % ", ".join(SUPPORTED_LANGUAGES))

    # [openvpn]
    c.instance = _get(cp, "openvpn", "instance", required=True)
    if not INSTANCE_RE.match(c.instance):
        raise ConfigError("[openvpn] instance has invalid characters")
    c.port = _get_int(cp, "openvpn", "port", 1194, 1, 65535)
    c.proto = _get(cp, "openvpn", "proto", "udp")
    if c.proto not in ("udp", "tcp"):
        raise ConfigError("[openvpn] proto must be udp or tcp")
    try:
        c.subnet = ipaddress.IPv4Network(_get(cp, "openvpn", "subnet", "10.8.0.0/24"), strict=True)
    except ValueError as exc:
        raise ConfigError("[openvpn] subnet: %s" % exc)
    if not (16 <= c.subnet.prefixlen <= 29):
        raise ConfigError("[openvpn] subnet prefix must be between /16 and /29")
    c.server_dir = _get(cp, "openvpn", "server_dir", "/etc/openvpn/server")
    c.pki_dir = _get(cp, "openvpn", "pki_dir", os.path.join(c.server_dir, "pki"))
    c.server_cert_name = _get(cp, "openvpn", "server_cert_name", c.instance)
    c.tls_crypt_key = _get(cp, "openvpn", "tls_crypt_key", os.path.join(c.server_dir, "tc.key"))
    c.crl_file = _get(cp, "openvpn", "crl_file", os.path.join(c.server_dir, "crl.pem"))
    c.management_socket = _get(cp, "openvpn", "management_socket",
                               "/run/openvpn-server/%s-mgmt.sock" % c.instance)
    c.tun_interface = _get(cp, "openvpn", "tun_interface", "tun0")
    c.easyrsa = _get(cp, "openvpn", "easyrsa", "/usr/share/easy-rsa/3/easyrsa")
    c.auth_token_lifetime_hours = _get_int(cp, "openvpn", "auth_token_lifetime_hours", 12, 1, 168)
    c.static_challenge_text = _get(cp, "openvpn", "static_challenge_text", "Authenticator code")
    if '"' in c.static_challenge_text or "\\" in c.static_challenge_text:
        raise ConfigError("[openvpn] static_challenge_text must not contain quotes or backslashes")
    for key in ("server_dir", "pki_dir", "tls_crypt_key", "crl_file", "management_socket", "easyrsa"):
        if not os.path.isabs(getattr(c, key)):
            raise ConfigError("[openvpn] %s must be an absolute path" % key)

    # [users]
    _get(cp, "users", "max_users", required=True)
    # Every user gets a fixed address, so the subnet bounds the cap.
    c.max_users = _get_int(cp, "users", "max_users", None, 1, len(client_ip_range(c)))
    c.max_expiry_days = _get_int(cp, "users", "max_expiry_days", 365, 1, 365)
    c.default_expiry_days = _get_int(cp, "users", "default_expiry_days", 90, 1, c.max_expiry_days)
    c.setup_link_ttl_hours = _get_int(cp, "users", "setup_link_ttl_hours", 72, 1, 720)
    # Client certificates are issued for the longest possible account period
    # (max_expiry_days) + 30 days of grace + 60 days so a fresh certificate never
    # trips the 60-day warnings. Must cover at least max_expiry_days + 30.
    c.client_cert_days = _get_int(cp, "users", "client_cert_days", c.max_expiry_days + 90,
                                  c.max_expiry_days + 30, 3650)

    # [panel]
    c.admin_allow = []
    for cidr in _get_list(cp, "panel", "admin_allow"):
        try:
            c.admin_allow.append(ipaddress.ip_network(cidr, strict=True))
        except ValueError as exc:
            raise ConfigError("[panel] admin_allow %r: %s" % (cidr, exc))
    c.tls_cert = _get(cp, "panel", "tls_cert", required=True)
    c.tls_key = _get(cp, "panel", "tls_key", required=True)
    c.https_port = _get_int(cp, "panel", "https_port", 443, 1, 65535)
    c.listen_port = _get_int(cp, "panel", "listen_port", 8471, 1024, 65535)
    c.lockout_attempts = _get_int(cp, "panel", "lockout_attempts", 5, 1, 100)
    c.lockout_minutes = _get_int(cp, "panel", "lockout_minutes", 15, 1, 1440)
    c.idle_timeout_minutes = _get_int(cp, "panel", "idle_timeout_minutes", 30, 5, 30)
    if c.proto == "tcp" and c.port == c.https_port:
        raise ConfigError("OpenVPN tcp port and the panel https_port cannot be the same")

    # [mail]
    c.relay_host = _get(cp, "mail", "relay_host", required=True)
    c.relay_port = _get_int(cp, "mail", "relay_port", 25, 1, 65535)
    c.sender = _get(cp, "mail", "sender", required=True)
    if not EMAIL_RE.match(c.sender):
        raise ConfigError("[mail] sender is not a valid address")
    c.tls_verify = _get_bool(cp, "mail", "tls_verify", True)

    # [firewall]
    c.vpn_zone = _get(cp, "firewall", "vpn_zone", "openvpn")
    c.public_zone = _get(cp, "firewall", "public_zone", "public")
    c.policy = _get(cp, "firewall", "policy", "dbovpn-forward")
    for key in ("vpn_zone", "public_zone", "policy"):
        if not ZONE_RE.match(getattr(c, key)):
            raise ConfigError("[firewall] %s has invalid characters or is too long" % key)

    # [profile NAME] sections
    c.profiles = {}
    for section in cp.sections():
        if not section.startswith("profile "):
            continue
        name = section[len("profile "):].strip()
        if not PROFILE_RE.match(name):
            raise ConfigError("[%s]: profile name must match %s" % (section, PROFILE_RE.pattern))
        dests = [parse_destination(d) for d in _get_list(cp, section, "destinations")]
        if not dests:
            raise ConfigError("[%s] destinations is required" % section)
        c.profiles[name] = Profile(name, _get(cp, section, "description", name), dests,
                                   _get_bool(cp, section, "default", False))
    defaults = [p.name for p in c.profiles.values() if p.default]
    if len(defaults) != 1:
        raise ConfigError("exactly one [profile ...] section must have default = yes (found %d)" % len(defaults))
    c.default_profile = defaults[0]

    known = {"gateway", "openvpn", "users", "panel", "mail", "firewall"}
    for section in cp.sections():
        if section not in known and not section.startswith("profile "):
            raise ConfigError("unknown section [%s]" % section)
    return c


def load(path=None):
    """Load the config from path, $DBOVPN_CONFIG, or the default location."""
    path = path or os.environ.get("DBOVPN_CONFIG") or CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc))
    return parse(text, path)


# Derived values -----------------------------------------------------------

def server_ip(cfg):
    """OpenVPN 'server' takes the .1 address of the subnet (man page, --server)."""
    return cfg.subnet.network_address + 1


def client_ip_range(cfg):
    """Addresses that can be handed to clients: everything except network, .1 and broadcast."""
    hosts = list(cfg.subnet.hosts())
    return [ip for ip in hosts if ip != server_ip(cfg)]


def panel_url(cfg):
    if cfg.https_port == 443:
        return "https://%s" % cfg.public_hostname
    return "https://%s:%d" % (cfg.public_hostname, cfg.https_port)
