import unittest

from dbovpn import privhelper
from dbovpn.privhelper import UsageError, validate
from tests import helpers


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.cfg = helpers.example_config()

    def test_valid(self):
        self.assertEqual(validate(["issue-cert", "ali.veli"], self.cfg), ("issue-cert", ["ali.veli"]))
        self.assertEqual(validate(["revoke-cert", "a_1-x"], self.cfg), ("revoke-cert", ["a_1-x"]))
        self.assertEqual(validate(["build-ovpn", "ali"], self.cfg), ("build-ovpn", ["ali"]))
        self.assertEqual(validate(["ipset-add", "app", "10.8.0.2"], self.cfg), ("ipset-add", ["app", "10.8.0.2"]))
        self.assertEqual(validate(["ipset-del", "app", "10.8.0.254"], self.cfg)[0], "ipset-del")

    def test_rejected(self):
        bad = [
            [], ["rm"], ["issue-cert"], ["issue-cert", "a", "b"],
            ["issue-cert", "Ali"], ["issue-cert", "a"], ["issue-cert", "../../etc/passwd"],
            ["issue-cert", "-rf"], ["issue-cert", "ali veli"], ["issue-cert", "ali\n"], ["issue-cert", "x" * 65],
            ["issue-cert", "example-vpn"],              # the server certificate
            ["build-ovpn", "ali;id"], ["revoke-cert", "*"],
            ["ipset-add", "nope", "10.8.0.2"], ["ipset-add", "app", "10.8.0.1"],     # server address
            ["ipset-add", "app", "10.8.0.0"], ["ipset-add", "app", "10.8.0.255"],
            ["ipset-add", "app", "10.9.0.2"], ["ipset-add", "app", "10.8.0.02"], ["ipset-add", "app", "10.8.0.2/32"],
            ["ipset-add", "app", "fe80::1"], ["ipset-del", "app"],
        ]
        for argv in bad:
            with self.assertRaises(UsageError, msg=argv):
                validate(argv, self.cfg)


class RunTest(unittest.TestCase):
    def test_issue_refuses_existing_cert(self):
        class RSA(object):
            built = []
            def has_cert(self, name): return name == "ali"
            def build_client(self, name): self.built.append(name)
        rsa = RSA()
        with self.assertRaises(UsageError):
            privhelper.run("issue-cert", ["ali"], helpers.example_config(), rsa=rsa)
        privhelper.run("issue-cert", ["veli"], helpers.example_config(), rsa=rsa)
        self.assertEqual(rsa.built, ["veli"])

    def test_requires_root(self):
        import os
        if os.geteuid() == 0:
            self.skipTest("running as root")
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(privhelper.main(["issue-cert", "ali"]), 2)


if __name__ == "__main__":
    unittest.main()
