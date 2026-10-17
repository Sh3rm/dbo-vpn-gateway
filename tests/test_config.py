import unittest

from dbovpn import config as config_mod
from dbovpn.config import ConfigError
from tests import helpers


class ConfigTest(unittest.TestCase):
    def test_example_parses(self):
        c = helpers.example_config()
        self.assertEqual(c.instance, "example-vpn")
        self.assertEqual(c.server_cert_name, "example-vpn")
        self.assertEqual(c.management_socket, "/run/openvpn-server/example-vpn-mgmt.sock")
        self.assertEqual(c.default_profile, "app")
        self.assertEqual([str(d) for d in c.profiles["app"].destinations],
                         ["203.0.113.10/32:443/tcp", "203.0.113.20/32:443/tcp"])
        self.assertEqual(c.max_users, 25)
        self.assertEqual(c.policy, "dbovpn-forward")
        self.assertEqual(str(config_mod.server_ip(c)), "10.8.0.1")
        r = config_mod.client_ip_range(c)
        self.assertEqual((str(r[0]), str(r[-1]), len(r)), ("10.8.0.2", "10.8.0.254", 253))

    def test_destinations(self):
        d = config_mod.parse_destination("198.51.100.0/24:8000-8010/udp")
        self.assertEqual((d.port_from, d.port_to, d.proto, d.port_spec), (8000, 8010, "udp", "8000-8010"))
        for bad in ("203.0.113.10:443", "203.0.113.10/24:443/tcp", "host:443/tcp", "203.0.113.10:0/tcp",
                    "203.0.113.10:10-5/tcp", "203.0.113.10:443/icmp"):
            with self.assertRaises(ConfigError, msg=bad):
                config_mod.parse_destination(bad)

    def test_errors(self):
        text = helpers.example_text()
        cases = [
            text.replace("max_users = 25", "max_users = 254"),
            text.replace("max_users = 25", ""),
            text.replace("default = yes", "default = no"),
            text + "\n[profile second]\ndestinations = 192.0.2.1:22/tcp\ndefault = yes\n",
            text.replace("proto = udp", "proto = sctp"),
            text.replace("[firewall]", "[firewal]"),
            text.replace("languages = tr, en", "languages = de"),
            text.replace("public_hostname = vpn.example.com", "public_hostname = vpn example"),
            text.replace("admin_allow = 198.51.100.0/24", "admin_allow = 198.51.100.1/24"),
            text.replace("port = 1194\nproto = udp", "port = 443\nproto = tcp"),
            text.replace("[profile app]", "[profile App!]"),
        ]
        for i, t in enumerate(cases):
            with self.assertRaises(ConfigError, msg=i):
                config_mod.parse(t)


if __name__ == "__main__":
    unittest.main()
