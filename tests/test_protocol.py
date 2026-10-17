"""Management protocol parsing against lines recorded in
docs/upstream/openvpn-2.7-management-notes.txt (MN)."""

import unittest

from dbovpn.mgmt import protocol


class Scrv1Test(unittest.TestCase):
    def test_management_notes_example(self):
        # MN 1472-1480: user "foo", password "bar", PIN 8675309.
        self.assertEqual(protocol.parse_scrv1("SCRV1:YmFy:ODY3NTMwOQ=="), ("bar", "8675309"))

    def test_empty_fields_allowed(self):
        # MN 1458-1459: either part may be empty.
        self.assertEqual(protocol.parse_scrv1("SCRV1::"), ("", ""))
        self.assertEqual(protocol.parse_scrv1("SCRV1:YmFy:"), ("bar", ""))

    def test_utf8_password(self):
        import base64
        pw = "Şifre ğüıöç 123"
        enc = "SCRV1:%s:%s" % (base64.b64encode(pw.encode()).decode(), base64.b64encode(b"123456").decode())
        self.assertEqual(protocol.parse_scrv1(enc), (pw, "123456"))

    def test_rejects_other_formats(self):
        for bad in ("bar8675309", "SCRV1:YmFy", "SCRV1:YmFy:ODY3:extra", "SCRV1:!!!:ODY3NTMwOQ==",
                    "CRV1::state::123", "", None, "scrv1:YmFy:ODY3NTMwOQ=="):
            with self.assertRaises(protocol.ProtocolError, msg=bad):
                protocol.parse_scrv1(bad)

    def test_password_with_colon_in_plaintext_is_fine(self):
        import base64
        enc = "SCRV1:%s:%s" % (base64.b64encode(b"a:b:c").decode(), base64.b64encode(b"000111").decode())
        self.assertEqual(protocol.parse_scrv1(enc), ("a:b:c", "000111"))


class NotificationTest(unittest.TestCase):
    def feed_all(self, lines):
        parser = protocol.NotificationParser()
        events = []
        for line in lines:
            ev = parser.feed(line)
            if ev is not None:
                events.append(ev)
        return events

    def test_connect_block(self):
        # Shape from MN 1213-1217.
        events = self.feed_all([
            ">CLIENT:CONNECT,7,0",
            ">CLIENT:ENV,common_name=ali.veli",
            ">CLIENT:ENV,username=ali.veli",
            ">CLIENT:ENV,password=SCRV1:YmFy:ODY3NTMwOQ==",
            ">CLIENT:ENV,untrusted_ip=192.0.2.44",
            ">CLIENT:ENV,session_state=Initial",
            ">CLIENT:ENV,END",
        ])
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev.kind, ev.cid, ev.kid), ("CONNECT", 7, 0))
        self.assertEqual(ev.env["password"], "SCRV1:YmFy:ODY3NTMwOQ==")
        self.assertEqual(ev.env["untrusted_ip"], "192.0.2.44")

    def test_reauth_and_value_with_equals(self):
        events = self.feed_all([">CLIENT:REAUTH,7,1", ">CLIENT:ENV,X509_0_CN=a=b", ">CLIENT:ENV,END"])
        self.assertEqual((events[0].kind, events[0].kid), ("REAUTH", 1))
        self.assertEqual(events[0].env["X509_0_CN"], "a=b")

    def test_established_disconnect_address(self):
        events = self.feed_all([
            ">CLIENT:ESTABLISHED,7", ">CLIENT:ENV,common_name=ali.veli", ">CLIENT:ENV,END",
            ">CLIENT:ADDRESS,7,10.8.0.2,1",
            ">CLIENT:DISCONNECT,7", ">CLIENT:ENV,bytes_received=10", ">CLIENT:ENV,END",
        ])
        self.assertEqual([e.kind for e in events], ["ESTABLISHED", "ADDRESS", "DISCONNECT"])
        self.assertEqual(events[1].extra, ("10.8.0.2", True))
        self.assertIsNone(events[0].kid)

    def test_cr_response(self):
        # MN 1245.
        events = self.feed_all([">CLIENT:CR_RESPONSE,3,2,MTIzNDU2", ">CLIENT:ENV,END"])
        self.assertEqual((events[0].kind, events[0].cid, events[0].kid, events[0].extra), ("CR_RESPONSE", 3, 2, "MTIzNDU2"))

    def test_other_realtime_messages(self):
        # MN 187 and the management greeting.
        events = self.feed_all([">HOLD:Waiting for hold release:10",
                                ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info"])
        self.assertEqual([(e.source, e.text) for e in events],
                         [("HOLD", "Waiting for hold release:10"),
                          ("INFO", "OpenVPN Management Interface Version 5 -- type 'help' for more info")])

    def test_errors(self):
        p = protocol.NotificationParser()
        with self.assertRaises(protocol.ProtocolError):
            p.feed(">CLIENT:ENV,END")
        with self.assertRaises(protocol.ProtocolError):
            p.feed(">CLIENT:CONNECT,x,0")
        with self.assertRaises(protocol.ProtocolError):
            p.feed("SUCCESS: done")
        p.feed(">CLIENT:CONNECT,1,0")
        with self.assertRaises(protocol.ProtocolError):
            p.feed(">CLIENT:CONNECT,2,0")


class CommandTest(unittest.TestCase):
    def test_client_auth_block(self):
        # MN 620-625.
        cmd = protocol.client_auth(7, 0, ["ifconfig-push 10.8.0.2 255.255.255.0",
                                          'push "route 203.0.113.10 255.255.255.255"'])
        self.assertEqual(cmd, 'client-auth 7 0\nifconfig-push 10.8.0.2 255.255.255.0\n'
                              'push "route 203.0.113.10 255.255.255.255"\nEND')

    def test_client_auth_rejects_injection(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.client_auth(1, 0, ["ok", "END"])
        with self.assertRaises(protocol.ProtocolError):
            protocol.client_auth(1, 0, ["a\nclient-kill 2"])

    def test_client_auth_nt(self):
        self.assertEqual(protocol.client_auth_nt(7, 1), "client-auth-nt 7 1")

    def test_client_deny_quoting(self):
        # MN 802 and the escaping rules at MN 1294-1304.
        self.assertEqual(protocol.client_deny(7, 0, 'bad "x" \\ y', "Authentication failed"),
                         'client-deny 7 0 "bad \\"x\\" \\\\ y" "Authentication failed"')

    def test_client_kill(self):
        # MN 858: client-kill 1 "HALT,Server shutting down for maintenance"
        self.assertEqual(protocol.client_kill(1, "HALT,Server shutting down for maintenance"),
                         'client-kill 1 "HALT,Server shutting down for maintenance"')
        self.assertEqual(protocol.client_kill(4), "client-kill 4")

    def test_quote_rejects_newline(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.quote("a\nb")


class StatusTest(unittest.TestCase):
    # Constructed from the field list for --status-version 2/3 (man page 443-459);
    # columns are read from the HEADER line, so their order does not matter.
    SAMPLE = [
        "TITLE\tOpenVPN 2.7.8 x86_64-redhat-linux-gnu",
        "TIME\t2026-10-17 10:00:00\t1792224000",
        "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received"
        "\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
        "CLIENT_LIST\tali.veli\t192.0.2.44:51820\t10.8.0.2\t\t1000\t2000\t2026-10-17 09:00:00\t1792220400"
        "\tali.veli\t7\t0\tAES-256-GCM",
        "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)",
        "ROUTING_TABLE\t10.8.0.2\tali.veli\t192.0.2.44:51820\t2026-10-17 10:00:00\t1792224000",
        "GLOBAL_STATS\tMax bcast/mcast queue length\t0",
    ]

    def test_parse(self):
        rows = protocol.parse_status3(self.SAMPLE)
        self.assertEqual(len(rows), 1)
        s = protocol.session_summary(rows[0])
        self.assertEqual(s, {"common_name": "ali.veli", "username": "ali.veli", "real_address": "192.0.2.44:51820",
                             "vpn_ip": "10.8.0.2", "bytes_in": 1000, "bytes_out": 2000, "since": 1792220400,
                             "cid": 7})

    def test_empty(self):
        self.assertEqual(protocol.parse_status3(self.SAMPLE[:3]), [])


if __name__ == "__main__":
    unittest.main()
