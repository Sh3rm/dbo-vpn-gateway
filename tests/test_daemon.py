"""The management daemon against a fake OpenVPN management socket (stdlib only)."""

import base64
import logging
import os
import queue
import socket
import tempfile
import threading
import time
import unittest

from dbovpn import totp
from dbovpn.mgmt import daemon as daemon_mod
from tests import helpers
from tests import test_protocol

SECRET = "JBSWY3DPEHPK3PXP"
logging.getLogger("dbovpn.mgmt").setLevel(logging.CRITICAL)


class FakeOpenVPN(object):
    """Accepts one management client, sends scripted lines, answers commands like OpenVPN."""

    def __init__(self, path):
        self.path = path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(1)
        self.commands = queue.Queue()
        self.conn = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.conn, _ = self.server.accept()
        self.send(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
        try:
            self._loop(self.conn.makefile("r"))
        except OSError:
            pass   # closed by tearDown

    def _loop(self, fh):
        block = None
        for line in fh:
            line = line.rstrip("\n")
            if block is not None:
                if line == "END":
                    self.commands.put("\n".join(block + [line]))
                    block = None
                    self.send("SUCCESS: client-auth command succeeded")
                else:
                    block.append(line)
                continue
            if line.startswith("client-auth "):
                block = [line]
                continue
            self.commands.put(line)
            if line == "status 3":
                for s in test_protocol.StatusTest.SAMPLE:
                    self.send(s)
                self.send("END")
            else:
                self.send("SUCCESS: %s command succeeded" % line.split()[0])

    def send(self, line):
        self.conn.sendall((line + "\n").encode())

    def close(self):
        if self.conn:
            self.conn.close()
        self.server.close()


class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dv")
        self.sock = os.path.join(self.tmp, "m.sock")
        self.db_path = os.path.join(self.tmp, "g.db")
        cfg = helpers.example_config(management_socket=self.sock)
        ctx = helpers.context(cfg, conn=__import__("dbovpn.db", fromlist=["db"]).connect(self.db_path))
        helpers.add_user(ctx, "ali.veli", secret=SECRET)
        # A session recorded by an earlier full login (auth-token bound to cred_epoch 1).
        ctx.conn.execute("INSERT INTO vpn_sessions VALUES ('ali.veli', 'SID-1', 1, 0)")
        ctx.conn.close()
        self.fake = FakeOpenVPN(self.sock)
        self.d = daemon_mod.Daemon(cfg, db_path=self.db_path, ctl_path=os.path.join(self.tmp, "c.sock"),
                                   verify_password=helpers.fake_verify)
        threading.Thread(target=self.d.worker, daemon=True).start()
        link = daemon_mod.Link(self.sock, self.d.on_event)
        link.open()
        self.d.link = link
        while self.fake.conn is None:
            time.sleep(0.01)

    def tearDown(self):
        self.d.link.close()
        self.fake.close()

    def next_command(self):
        return self.fake.commands.get(timeout=5)

    def connect_lines(self, kind, cid, kid, password, state="Initial"):
        return [">CLIENT:%s,%d,%d" % (kind, cid, kid), ">CLIENT:ENV,common_name=ali.veli",
                ">CLIENT:ENV,username=ali.veli", ">CLIENT:ENV,password=%s" % password,
                ">CLIENT:ENV,session_state=%s" % state, ">CLIENT:ENV,session_id=SID-1", ">CLIENT:ENV,untrusted_ip=192.0.2.44", ">CLIENT:ENV,END"]

    def test_connect_allowed_with_fixed_ip(self):
        code = totp.code_at(SECRET)
        pw = "SCRV1:%s:%s" % (base64.b64encode(b"correct horse battery").decode(), base64.b64encode(code.encode()).decode())
        for line in self.connect_lines("CONNECT", 3, 0, pw):
            self.fake.send(line)
        cmd = self.next_command()
        self.assertTrue(cmd.startswith("client-auth 3 0\nifconfig-push 10.8.0.2 255.255.255.0\n"), cmd)
        self.assertTrue(cmd.endswith("\nEND"))

    def test_connect_denied(self):
        for line in self.connect_lines("CONNECT", 4, 0, "SCRV1:eA==:MTIzNDU2"):
            self.fake.send(line)
        self.assertTrue(self.next_command().startswith('client-deny 4 0 "wrong password" "Authentication failed"'))

    def test_reauth_with_token_and_denied_reauth_kills(self):
        for line in self.connect_lines("REAUTH", 5, 1, "SESS_ID_x", state="Authenticated"):
            self.fake.send(line)
        self.assertEqual(self.next_command(), "client-auth-nt 5 1")
        for line in self.connect_lines("REAUTH", 5, 2, "SESS_ID_x", state="Expired"):
            self.fake.send(line)
        self.assertTrue(self.next_command().startswith("client-deny 5 2 "))
        self.assertTrue(self.next_command().startswith('client-kill 5 "HALT,'))

    def test_ctl_list_and_kick(self):
        reply = self.d.ctl_handle({"cmd": "list"})
        self.assertEqual(reply["sessions"][0]["common_name"], "ali.veli")
        self.assertEqual(self.next_command(), "status 3")
        reply = self.d.ctl_handle({"cmd": "kick", "username": "ali.veli"})
        self.assertEqual(reply, {"ok": True, "killed": 1})
        self.assertEqual(self.next_command(), "status 3")
        self.assertEqual(self.next_command(), 'client-kill 7 "%s"' % daemon_mod.KICK_MESSAGE)
        self.assertFalse(self.d.ctl_handle({"cmd": "kick", "username": "../x"})["ok"])
        self.assertFalse(self.d.ctl_handle({"cmd": "shutdown"})["ok"])

    def list_names(self):
        sessions = self.d.ctl_handle({"cmd": "list"})["sessions"]
        self.assertEqual(self.next_command(), "status 3")
        return [s["common_name"] for s in sessions]

    def wait_for(self, predicate):
        deadline = time.time() + 5
        while not predicate():
            self.assertLess(time.time(), deadline)
            time.sleep(0.01)

    def test_killed_session_hidden_until_disconnect(self):
        # OpenVPN still lists a killed client for a few seconds (delayed exit).
        self.assertEqual(self.list_names(), ["ali.veli"])
        self.assertEqual(self.d.ctl_handle({"cmd": "kick", "username": "ali.veli"}), {"ok": True, "killed": 1})
        self.next_command()                                   # status 3
        self.next_command()                                   # client-kill 7
        self.assertEqual(self.list_names(), [])               # fake OpenVPN still lists cid 7
        self.assertEqual(self.d.ctl_handle({"cmd": "kick", "username": "ali.veli"})["killed"], 0)
        self.next_command()
        self.fake.send(">CLIENT:DISCONNECT,7")
        self.fake.send(">CLIENT:ENV,common_name=ali.veli")
        self.fake.send(">CLIENT:ENV,END")
        self.wait_for(lambda: 7 not in self.d.closing)
        self.assertEqual(self.list_names(), ["ali.veli"])     # a new session with a reused name would show

    def test_closing_expires(self):
        now = [1000.0]
        self.d.clock = lambda: now[0]
        self.d.ctl_handle({"cmd": "kick", "username": "ali.veli"})
        self.next_command()
        self.next_command()
        self.assertEqual(self.list_names(), [])
        now[0] += daemon_mod.CLOSING_SECONDS + 1
        self.assertEqual(self.list_names(), ["ali.veli"])

    def test_denied_reauth_kill_is_closing(self):
        for line in self.connect_lines("REAUTH", 7, 2, "SESS_ID_x", state="Expired"):
            self.fake.send(line)
        self.assertTrue(self.next_command().startswith("client-deny 7 2 "))
        self.assertTrue(self.next_command().startswith('client-kill 7 "HALT,'))
        self.wait_for(lambda: 7 in self.d.closing)
        self.assertEqual(self.list_names(), [])

    def test_every_kill_goes_through_kill(self):
        import inspect
        src = inspect.getsource(daemon_mod.Daemon)
        self.assertEqual(src.count("protocol.client_kill("), 1)    # only inside Daemon.kill()

    def test_link_down_is_reported(self):
        self.d.link.close()
        with self.assertRaises(daemon_mod.LinkDown):
            self.d.sessions()


if __name__ == "__main__":
    unittest.main()
