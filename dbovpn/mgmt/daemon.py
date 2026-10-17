"""dbo-vpn-gateway-mgmt: the one management client of the OpenVPN server.

- Connects to the OpenVPN management unix socket and reconnects forever.
  OpenVPN started with --management-client-auth waits for this daemon to answer
  every >CLIENT:CONNECT/REAUTH, so while it is down nobody new gets in (fail closed).
- Answers with client-auth (fixed address + routes) or client-deny (+ client-kill on REAUTH).
- Serves /run/dbo-vpn-gateway/ctl.sock (JSON lines) for 'list' and 'kick',
  because OpenVPN accepts only one management client at a time (MN 150-156).
- Every SWEEP_SECONDS it closes sessions of users who are no longer allowed
  (safety net behind the panel's own kicks and the expiry job).
"""

import json
import logging
import os
import queue
import socket
import socketserver
import sys
import threading
import time
import datetime

from dbovpn import CTL_SOCKET
from dbovpn import config as config_mod
from dbovpn import db, users
from dbovpn.config import USERNAME_RE
from dbovpn.mgmt import auth, protocol

log = logging.getLogger("dbovpn.mgmt")

COMMAND_TIMEOUT = 15
SWEEP_SECONDS = 300
KICK_MESSAGE = "HALT,Session closed by the VPN administrator"


class LinkDown(Exception):
    pass


class Link(object):
    """One connection to the OpenVPN management socket.

    A reader thread splits the stream: real-time lines ('>' first, MN 1144)
    go to on_event, everything else is a command reply. Commands are
    serialized by a lock, so replies arrive in order (MN 1124-1135).
    """

    def __init__(self, path, on_event):
        self.path = path
        self.on_event = on_event
        self.lock = threading.Lock()
        self.replies = queue.Queue()
        self.alive = False
        self.sock = None
        self.closed = threading.Event()

    def open(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(self.path)
        sock.settimeout(None)
        self.sock = sock
        self.alive = True
        t = threading.Thread(target=self._reader, name="mgmt-reader", daemon=True)
        t.start()

    def _reader(self):
        parser = protocol.NotificationParser()
        fh = self.sock.makefile("rb")
        try:
            for raw in fh:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith(">"):
                    try:
                        event = parser.feed(line)
                    except protocol.ProtocolError as exc:
                        log.error("management protocol error: %s", exc)
                        parser = protocol.NotificationParser()
                        continue
                    if event is not None:
                        self.on_event(event)
                else:
                    self.replies.put(line)
        except OSError as exc:
            log.warning("management socket read error: %s", exc)
        finally:
            self.close()

    def close(self):
        if self.alive:
            log.warning("management connection closed")
        self.alive = False
        self.replies.put(None)
        try:
            self.sock.close()
        except (OSError, AttributeError):
            pass
        self.closed.set()

    def command(self, text, multiline=False):
        """Send a command; return the reply line, or the lines before END for multi-line replies."""
        with self.lock:
            if not self.alive:
                raise LinkDown("not connected to OpenVPN")
            while not self.replies.empty():   # drop leftovers of an earlier timeout
                self.replies.get_nowait()
            try:
                self.sock.sendall((text + "\n").encode("utf-8"))
            except OSError as exc:
                self.close()
                raise LinkDown(str(exc))
            lines = []
            deadline = time.time() + COMMAND_TIMEOUT
            while True:
                try:
                    line = self.replies.get(timeout=max(0.1, deadline - time.time()))
                except queue.Empty:
                    self.close()   # we cannot tell which reply belongs to whom any more
                    raise LinkDown("timeout waiting for reply to %s" % text.split()[0])
                if line is None:
                    raise LinkDown("connection closed")
                if not multiline:
                    return line
                if line == "END":
                    return lines
                if not lines and line.startswith("ERROR:"):
                    return [line]
                lines.append(line)


class Daemon(object):
    def __init__(self, cfg, db_path=None, ctl_path=CTL_SOCKET, verify_password=None):
        self.cfg = cfg
        self.db_path = db_path
        self.ctl_path = ctl_path
        self.events = queue.Queue()
        self.link = None
        if verify_password is None:
            from dbovpn.passwords import verify_password
        self.verify_password = verify_password

    # OpenVPN side -------------------------------------------------------------

    def command(self, text, multiline=False):
        link = self.link
        if link is None:
            raise LinkDown("not connected to OpenVPN")
        return link.command(text, multiline)

    def sessions(self):
        lines = self.command("status 3", multiline=True)
        if lines and lines[0].startswith("ERROR:"):
            raise LinkDown(lines[0])
        return [protocol.session_summary(r) for r in protocol.parse_status3(lines)]

    def kick(self, username):
        killed = 0
        for s in self.sessions():
            if s["common_name"] == username:
                reply = self.command(protocol.client_kill(s["cid"], KICK_MESSAGE))
                if reply.startswith("SUCCESS"):
                    killed += 1
                else:
                    log.warning("client-kill %d for %s: %s", s["cid"], username, reply)
        return killed

    # Events ---------------------------------------------------------------------

    def worker(self):
        conn = db.connect(self.db_path)
        while True:
            event = self.events.get()
            try:
                if isinstance(event, protocol.ClientEvent) and event.kind in ("CONNECT", "REAUTH"):
                    self.handle_auth(conn, event)
                elif isinstance(event, protocol.ClientEvent) and event.kind == "CR_RESPONSE":
                    # Not used by this gateway; refuse rather than leave the client hanging.
                    self.command(protocol.client_deny(event.cid, event.kid, "challenge/response not supported"))
                elif isinstance(event, protocol.ClientEvent):
                    log.info("%s cid=%d %s", event.kind, event.cid, event.env.get("common_name", ""))
                elif event.source in ("FATAL", "HOLD"):
                    log.warning(">%s:%s", event.source, event.text)
            except LinkDown as exc:
                log.warning("could not answer %r: %s", event, exc)
            except Exception:
                log.exception("error while handling %r", event)

    def handle_auth(self, conn, event):
        now = time.time()
        today = datetime.date.fromtimestamp(now)
        try:
            decision = auth.decide(event, conn, self.cfg, now, today, self.verify_password)
        except Exception:
            log.exception("auth decision failed, denying")
            decision = auth.Decision(False, "internal error", event.env.get("common_name", ""),
                                     kill=event.kind == "REAUTH", client_reason=auth.GENERIC_FAILURE)

        if decision.allow:
            if event.kind == "REAUTH":
                reply = self.command(protocol.client_auth_nt(event.cid, event.kid))
            else:
                reply = self.command(protocol.client_auth(event.cid, event.kid, decision.lines))
        else:
            reply = self.command(protocol.client_deny(event.cid, event.kid, decision.reason,
                                                      decision.client_reason))
            if decision.kill:
                self.command(protocol.client_kill(event.cid, "HALT,%s" % decision.client_reason))
        log.info("%s cid=%d kid=%d user=%s: %s (%s) -> %s", event.kind, event.cid, event.kid,
                 decision.username or "-", "allow" if decision.allow else "deny", decision.reason, reply)

        if decision.audit_action:
            target = decision.username if USERNAME_RE.match(decision.username or "") else ""
            db.audit(conn, "vpn:%s" % (target or "unknown"), decision.audit_action, target,
                     decision.audit_detail, event.env.get("untrusted_ip", ""))
            if decision.kill:
                db.audit(conn, "system:mgmt", "session.kick", target, "renegotiation denied: %s" % decision.reason)

    def sweep(self, conn):
        """Close sessions of users who are disabled, expired, reset or deleted."""
        today = datetime.date.today()
        for s in self.sessions():
            row = users.get(conn, s["common_name"])
            refusal = users.login_refusal(row, today)
            if refusal:
                self.command(protocol.client_kill(s["cid"], KICK_MESSAGE))
                db.audit(conn, "system:mgmt", "session.kick", s["common_name"], "sweep: %s" % refusal)
                log.info("sweep: killed cid=%d %s (%s)", s["cid"], s["common_name"], refusal)

    # Control socket -------------------------------------------------------------

    def ctl_handle(self, request):
        cmd = request.get("cmd")
        if cmd == "list":
            return {"ok": True, "sessions": self.sessions()}
        if cmd == "kick":
            username = request.get("username", "")
            if not USERNAME_RE.match(username):
                return {"ok": False, "error": "invalid username"}
            return {"ok": True, "killed": self.kick(username)}
        return {"ok": False, "error": "unknown command"}

    def serve_ctl(self):
        daemon = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line = self.rfile.readline(65536)
                try:
                    reply = daemon.ctl_handle(json.loads(line.decode("utf-8")))
                except ValueError:
                    reply = {"ok": False, "error": "bad request"}
                except LinkDown as exc:
                    reply = {"ok": False, "error": "OpenVPN management not connected: %s" % exc}
                self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))

        if os.path.exists(self.ctl_path):
            os.unlink(self.ctl_path)
        old = os.umask(0o117)   # socket 0660: owner and group dbovpn
        try:
            server = socketserver.ThreadingUnixStreamServer(self.ctl_path, Handler)
        finally:
            os.umask(old)
        server.daemon_threads = True
        log.info("control socket %s ready", self.ctl_path)
        server.serve_forever()

    # Main loop ------------------------------------------------------------------

    def run(self):
        threading.Thread(target=self.worker, name="auth-worker", daemon=True).start()
        threading.Thread(target=self.serve_ctl, name="ctl", daemon=True).start()
        sweep_conn = db.connect(self.db_path)
        backoff = 1
        while True:
            link = Link(self.cfg.management_socket, self.events.put)
            try:
                link.open()
            except OSError as exc:
                log.warning("cannot connect to %s: %s (retry in %ds)", self.cfg.management_socket, exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue
            log.info("connected to OpenVPN management %s", self.cfg.management_socket)
            backoff = 1
            self.link = link
            last_sweep = 0
            while not link.closed.wait(5):
                if time.time() - last_sweep >= SWEEP_SECONDS:
                    last_sweep = time.time()
                    try:
                        self.sweep(sweep_conn)
                    except LinkDown:
                        pass
                    except Exception:
                        log.exception("sweep failed")
            self.link = None


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    os.umask(0o077)
    cfg = config_mod.load()
    Daemon(cfg).run()


if __name__ == "__main__":
    main()
