"""firewalld through firewall-cmd only (zones, policies, ipsets). Runs as root.

Layout (the same shape as a hand-built single-customer gateway):
  zone <vpn_zone> (target DROP) holds the tun interface, so VPN clients reach
  nothing on the gateway itself;
  policy <policy> (target DROP, masquerade) from <vpn_zone> to <public_zone>
  accepts only each profile's destinations, and only from that profile's ipset
  (dbovpn-<profile>, hash:ip of the users' fixed VPN addresses).
"""

import re
import subprocess

FIREWALL_CMD = "/usr/bin/firewall-cmd"


class FirewallError(Exception):
    pass


def default_runner(argv):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


class FirewallCmd(object):
    def __init__(self, run=default_runner, binary=FIREWALL_CMD):
        self.run = run
        self.binary = binary

    def cmd(self, *args, **kwargs):
        """Run firewall-cmd; return stdout. check=False returns None on a non-zero exit."""
        check = kwargs.get("check", True)
        rc, out, err = self.run([self.binary] + list(args))
        if rc != 0:
            if not check:
                return None
            raise FirewallError("firewall-cmd %s: %s" % (" ".join(args), (err or out).strip()))
        return out

    def query(self, *args):
        # firewall-cmd --query-* exits 0 for yes, 1 for no.
        rc, _, _ = self.run([self.binary] + list(args))
        return rc == 0

    def words(self, *args):
        return (self.cmd(*args) or "").split()

    def lines(self, *args):
        return [line.strip() for line in (self.cmd(*args) or "").splitlines() if line.strip()]

    def running(self):
        return self.query("--state")


def rich_rule(ipset, dest):
    """Policy rich rule allowing one destination from one profile ipset."""
    if dest.network.prefixlen == 32:
        address = str(dest.network.network_address)
    else:
        address = dest.network.with_prefixlen
    return ('rule family="ipv4" source ipset="%s" destination address="%s" port port="%s" protocol="%s" accept'
            % (ipset, address, dest.port_spec, dest.proto))


def normalize_rule(rule):
    """Compare rules regardless of spacing and an explicit /32."""
    rule = re.sub(r'address="([0-9.]+)/32"', r'address="\1"', rule)
    return " ".join(rule.split())


def desired_rules(cfg):
    rules = []
    for profile in cfg.profiles.values():
        for dest in profile.destinations:
            rules.append(rich_rule(profile.ipset, dest))
    return rules


def apply_permanent(fw, cfg, log):
    """Bring the permanent firewalld config in line with cfg. Returns True if anything changed.

    Runtime is not touched: 'firewall-cmd --reload' (setup --apply) activates it,
    together with the OpenVPN restart, so connected users are not cut off halfway.
    """
    changed = []
    p = "--permanent"

    zones = fw.words(p, "--get-zones")
    if cfg.vpn_zone not in zones:
        fw.cmd(p, "--new-zone=%s" % cfg.vpn_zone)
        changed.append("zone %s created" % cfg.vpn_zone)
    if fw.cmd(p, "--zone=%s" % cfg.vpn_zone, "--get-target").strip() != "DROP":
        fw.cmd(p, "--zone=%s" % cfg.vpn_zone, "--set-target=DROP")
        changed.append("zone %s target DROP" % cfg.vpn_zone)
    if not fw.query(p, "--zone=%s" % cfg.vpn_zone, "--query-interface=%s" % cfg.tun_interface):
        fw.cmd(p, "--zone=%s" % cfg.vpn_zone, "--add-interface=%s" % cfg.tun_interface)
        changed.append("interface %s in zone %s" % (cfg.tun_interface, cfg.vpn_zone))

    # Public side: the OpenVPN port and the panel (nginx) port.
    public = "--zone=%s" % cfg.public_zone
    if (cfg.port, cfg.proto) == (1194, "udp"):
        wanted = [("--query-service=openvpn", "--add-service=openvpn")]
    else:
        spec = "%d/%s" % (cfg.port, cfg.proto)
        wanted = [("--query-port=%s" % spec, "--add-port=%s" % spec)]
    if cfg.https_port == 443:
        wanted.append(("--query-service=https", "--add-service=https"))
    else:
        wanted.append(("--query-port=%d/tcp" % cfg.https_port, "--add-port=%d/tcp" % cfg.https_port))
    for q, add in wanted:
        if not fw.query(p, public, q):
            fw.cmd(p, public, add)
            changed.append("%s %s" % (cfg.public_zone, add))

    # One ipset per profile.
    ipsets = fw.words(p, "--get-ipsets")
    for profile in cfg.profiles.values():
        if profile.ipset not in ipsets:
            fw.cmd(p, "--new-ipset=%s" % profile.ipset, "--type=hash:ip")
            changed.append("ipset %s created" % profile.ipset)

    # The forwarding policy.
    pol = "--policy=%s" % cfg.policy
    if cfg.policy not in fw.words(p, "--get-policies"):
        fw.cmd(p, "--new-policy=%s" % cfg.policy)
        changed.append("policy %s created" % cfg.policy)
    if fw.cmd(p, pol, "--get-target").strip() != "DROP":
        fw.cmd(p, pol, "--set-target=DROP")
        changed.append("policy %s target DROP" % cfg.policy)
    if not fw.query(p, pol, "--query-ingress-zone=%s" % cfg.vpn_zone):
        fw.cmd(p, pol, "--add-ingress-zone=%s" % cfg.vpn_zone)
        changed.append("policy ingress %s" % cfg.vpn_zone)
    if not fw.query(p, pol, "--query-egress-zone=%s" % cfg.public_zone):
        fw.cmd(p, pol, "--add-egress-zone=%s" % cfg.public_zone)
        changed.append("policy egress %s" % cfg.public_zone)
    if not fw.query(p, pol, "--query-masquerade"):
        fw.cmd(p, pol, "--add-masquerade")
        changed.append("policy masquerade")

    # Rich rules: exactly the profile rules. Older unrestricted rules (the
    # pre-gateway 'any VPN client to the application' rules) are replaced.
    want = {normalize_rule(r): r for r in desired_rules(cfg)}
    have = fw.lines(p, pol, "--list-rich-rules")
    have_norm = {normalize_rule(r) for r in have}
    for rule in have:
        if normalize_rule(rule) not in want:
            fw.cmd(p, pol, "--remove-rich-rule=%s" % rule)
            changed.append("removed rule: %s" % rule)
    for norm, rule in want.items():
        if norm not in have_norm:
            fw.cmd(p, pol, "--add-rich-rule=%s" % rule)
            changed.append("added rule: %s" % rule)

    for line in changed:
        log("firewall: " + line)
    return bool(changed)


def sync_ipset_entries(fw, cfg, wanted, log):
    """Make each profile ipset's permanent entries equal wanted[profile] (list of IPs)."""
    changed = False
    for profile in cfg.profiles.values():
        target = set(wanted.get(profile.name, []))
        current = set(fw.words("--permanent", "--ipset=%s" % profile.ipset, "--get-entries"))
        for ip in sorted(current - target):
            fw.cmd("--permanent", "--ipset=%s" % profile.ipset, "--remove-entry=%s" % ip)
            log("firewall: %s -%s" % (profile.ipset, ip))
            changed = True
        for ip in sorted(target - current):
            fw.cmd("--permanent", "--ipset=%s" % profile.ipset, "--add-entry=%s" % ip)
            log("firewall: %s +%s" % (profile.ipset, ip))
            changed = True
    return changed


def ipset_entry(fw, ipset, ip, add):
    """Add or remove one entry, permanently and (if the ipset is loaded) at runtime."""
    action = "--add-entry=%s" % ip if add else "--remove-entry=%s" % ip
    query = "--query-entry=%s" % ip
    present = fw.query("--permanent", "--ipset=%s" % ipset, query)
    if present != add:
        fw.cmd("--permanent", "--ipset=%s" % ipset, action)
    if fw.running() and ipset in fw.words("--get-ipsets"):
        if fw.query("--ipset=%s" % ipset, query) != add:
            fw.cmd("--ipset=%s" % ipset, action)
