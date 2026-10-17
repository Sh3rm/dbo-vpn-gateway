"""Client for the management daemon's local control socket (JSON lines).

Requests:  {"cmd": "list"}                     -> {"ok": true, "sessions": [...]}
           {"cmd": "kick", "username": "ali"}  -> {"ok": true, "killed": 1}
Errors:    {"ok": false, "error": "..."}
"""

import json
import socket

from dbovpn import CTL_SOCKET


class CtlError(Exception):
    pass


class SessionControl(object):
    """Talks to dbo-vpn-gateway-mgmt. Tests substitute a fake with the same two methods."""

    def __init__(self, path=CTL_SOCKET, timeout=10):
        self.path = path
        self.timeout = timeout

    def _call(self, request):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 4 * 1024 * 1024:
                    raise CtlError("reply too large")
        except (OSError, socket.timeout) as exc:
            raise CtlError("management daemon unreachable: %s" % exc)
        finally:
            sock.close()
        try:
            reply = json.loads(buf.decode("utf-8"))
        except ValueError:
            raise CtlError("bad reply from management daemon")
        if not reply.get("ok"):
            raise CtlError(reply.get("error", "unknown error"))
        return reply

    def list_sessions(self):
        return self._call({"cmd": "list"})["sessions"]

    def kick(self, username):
        return self._call({"cmd": "kick", "username": username})["killed"]
