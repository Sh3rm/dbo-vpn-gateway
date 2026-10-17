import unittest

from dbovpn import firewall
from tests import helpers


class FakeFirewalld(object):
    """Minimal in-memory model of the firewall-cmd calls apply_permanent makes."""

    def __init__(self, rules=None, zones=("public",), policies=(), ipsets=None):
        self.calls = []
        self.zones = list(zones)
        self.policies = list(policies)
        self.rules = list(rules or [])
        self.ipsets = dict(ipsets or {})
        self.flags = set()

    def __call__(self, argv):
        args = argv[1:]
        self.calls.append(args)
        a = [x for x in args if x != "--permanent"]
        joined = " ".join(a)
        if a == ["--get-zones"]:
            return 0, " ".join(self.zones), ""
        if a == ["--get-policies"]:
            return 0, " ".join(self.policies), ""
        if a == ["--get-ipsets"]:
            return 0, " ".join(self.ipsets), ""
        if a[0].startswith("--new-zone="):
            self.zones.append(a[0].split("=", 1)[1]); return 0, "", ""
        if a[0].startswith("--new-policy="):
            self.policies.append(a[0].split("=", 1)[1]); return 0, "", ""
        if a[0].startswith("--new-ipset="):
            self.ipsets[a[0].split("=", 1)[1]] = set(); return 0, "", ""
        if a[-1] == "--get-target":
            return 0, ("DROP" if ("target", a[0]) in self.flags else "default") + "\n", ""
        if a[-1].startswith("--set-target="):
            self.flags.add(("target", a[0])); return 0, "", ""
        if a[-1] == "--list-rich-rules":
            return 0, "\n".join(self.rules), ""
        if a[-1].startswith("--add-rich-rule="):
            self.rules.append(a[-1].split("=", 1)[1]); return 0, "", ""
        if a[-1].startswith("--remove-rich-rule="):
            self.rules.remove(a[-1].split("=", 1)[1]); return 0, "", ""
        if a[-1] == "--get-entries":
            return 0, " ".join(sorted(self.ipsets[a[0].split("=", 1)[1]])), ""
        if a[-1].startswith("--add-entry="):
            self.ipsets[a[0].split("=", 1)[1]].add(a[-1].split("=", 1)[1]); return 0, "", ""
        if a[-1].startswith("--remove-entry="):
            self.ipsets[a[0].split("=", 1)[1]].discard(a[-1].split("=", 1)[1]); return 0, "", ""
        if a[-1].startswith("--query-"):
            return (0 if ("q", a[0], a[-1][8:]) in self.flags else 1), "", ""
        if a[-1].startswith("--add-"):
            self.flags.add(("q", a[0], a[-1][6:])); return 0, "", ""
        raise AssertionError("unexpected firewall-cmd call: %s" % joined)


LEGACY_RULE = 'rule family="ipv4" destination address="203.0.113.10/32" port port="443" protocol="tcp" accept'


class FirewallTest(unittest.TestCase):
    def test_rich_rule_text(self):
        cfg = helpers.example_config()
        self.assertEqual(firewall.desired_rules(cfg)[0],
                         'rule family="ipv4" source ipset="dbovpn-app" destination address="203.0.113.10" '
                         'port port="443" protocol="tcp" accept')

    def test_apply_is_idempotent_and_replaces_legacy_rules(self):
        cfg = helpers.example_config()
        fake = FakeFirewalld(rules=[LEGACY_RULE], zones=("public", "openvpn"))
        fw = firewall.FirewallCmd(run=fake)
        log = []
        self.assertTrue(firewall.apply_permanent(fw, cfg, log.append))
        self.assertIn("firewall: removed rule: " + LEGACY_RULE, log)
        self.assertEqual(sorted(fake.rules), sorted(firewall.desired_rules(cfg)))
        self.assertIn("dbovpn-app", fake.ipsets)
        self.assertTrue(all("--permanent" in c for c in fake.calls))
        log = []
        self.assertFalse(firewall.apply_permanent(fw, cfg, log.append), log)

    def test_normalize_handles_explicit_32(self):
        a = 'rule family="ipv4" source ipset="x" destination address="203.0.113.10/32" port port="443" protocol="tcp" accept'
        b = 'rule family="ipv4"  source ipset="x" destination address="203.0.113.10" port port="443" protocol="tcp" accept'
        self.assertEqual(firewall.normalize_rule(a), firewall.normalize_rule(b))

    def test_sync_ipset_entries(self):
        cfg = helpers.example_config()
        fake = FakeFirewalld(ipsets={"dbovpn-app": {"10.8.0.9"}})
        fw = firewall.FirewallCmd(run=fake)
        self.assertTrue(firewall.sync_ipset_entries(fw, cfg, {"app": ["10.8.0.2", "10.8.0.3"]}, lambda m: None))
        self.assertEqual(fake.ipsets["dbovpn-app"], {"10.8.0.2", "10.8.0.3"})
        self.assertFalse(firewall.sync_ipset_entries(fw, cfg, {"app": ["10.8.0.2", "10.8.0.3"]}, lambda m: None))


if __name__ == "__main__":
    unittest.main()
