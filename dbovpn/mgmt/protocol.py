"""OpenVPN 2.7 management protocol: parsing and command building, no I/O.

References are by line number to the OpenVPN 2.7 documentation:
MN  = doc/management-notes.txt, MAN = the openvpn(8) man page as plain text
(local copies in docs/upstream/openvpn-2.7-management-notes.txt and
docs/upstream/openvpn-2.7-man.txt; not tracked in git).
"""

import base64
import binascii


class ProtocolError(Exception):
    pass


# Command quoting -------------------------------------------------------------
# MN 1286-1304: same lexer as the config file; double quotes enclose a
# parameter, backslash escapes \\ and \" inside it.

def quote(text):
    text = str(text)
    if "\n" in text or "\r" in text:
        raise ProtocolError("newline in management command argument")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def client_auth(cid, kid, lines):
    """MN 620-625: 'client-auth {CID} {KID}', the client-connect text block, 'END'."""
    for line in lines:
        if "\n" in line or "\r" in line or line.strip() == "END":
            raise ProtocolError("bad line in client-auth block")
    return "\n".join(["client-auth %d %d" % (cid, kid)] + list(lines) + ["END"])


def client_auth_nt(cid, kid):
    """MN 649: authorize without a config block (used for REAUTH)."""
    return "client-auth-nt %d %d" % (cid, kid)


def client_deny(cid, kid, reason, client_reason=None):
    """MN 802: client-deny {CID} {KID} "reason-text" ["client-reason-text"]."""
    cmd = "client-deny %d %d %s" % (cid, kid, quote(reason))
    if client_reason:
        cmd += " " + quote(client_reason)
    return cmd


def client_kill(cid, message=None):
    """MN 831-858: client-kill {CID} [RESTART|HALT[,[flags][message]]], quoted if it has spaces."""
    if message:
        return "client-kill %d %s" % (cid, quote(message))
    return "client-kill %d" % cid


# Static challenge ------------------------------------------------------------

def parse_scrv1(password):
    """Split an SCRV1 password into (password, response).

    MN 1446-1459 and the worked example at MN 1472-1480: with static-challenge
    format scrv1 (MAN 1468-1480, the default) the client sends
        SCRV1:<password_base64>:<response_base64>
    Either part may be empty. Raises ProtocolError on anything else.
    """
    if not isinstance(password, str) or not password.startswith("SCRV1:"):
        raise ProtocolError("password is not in SCRV1 format")
    parts = password.split(":")
    if len(parts) != 3:
        raise ProtocolError("SCRV1 needs exactly three fields")
    try:
        pw = base64.b64decode(parts[1], validate=True).decode("utf-8")
        response = base64.b64decode(parts[2], validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ProtocolError("SCRV1 field is not valid base64/UTF-8")
    return pw, response


# Real-time notifications ----------------------------------------------------

class ClientEvent(object):
    """A complete >CLIENT: notification (MN 1194-1270)."""

    def __init__(self, kind, cid, kid=None, env=None, extra=None):
        self.kind = kind          # CONNECT, REAUTH, ESTABLISHED, DISCONNECT, ADDRESS, CR_RESPONSE
        self.cid = cid
        self.kid = kid
        self.env = env if env is not None else {}
        self.extra = extra        # ADDRESS: (addr, primary); CR_RESPONSE: base64 response

    def __repr__(self):
        return "ClientEvent(%s, cid=%s, kid=%s)" % (self.kind, self.cid, self.kid)


class Notification(object):
    """Any other real-time message: >INFO:, >HOLD:, >FATAL:, ... (MN 1137-1192)."""

    def __init__(self, source, text):
        self.source = source
        self.text = text


ENV_KINDS = ("CONNECT", "REAUTH", "ESTABLISHED", "DISCONNECT", "CR_RESPONSE")


class NotificationParser(object):
    """Feed lines starting with '>'; get back complete events.

    MN 1199-1203: a CLIENT notification, its ENV lines and the terminating
    '>CLIENT:ENV,END' are atomic, so one pending event at a time is enough.
    """

    def __init__(self):
        self.pending = None

    def feed(self, line):
        """Return a ClientEvent/Notification when one is complete, else None."""
        if not line.startswith(">"):
            raise ProtocolError("not a real-time message: %r" % line[:40])
        source, _, text = line[1:].partition(":")
        if source != "CLIENT":
            return Notification(source, text)

        if text.startswith("ENV,"):
            if self.pending is None:
                raise ProtocolError("ENV line without a CLIENT header")
            item = text[4:]
            if item == "END":
                event, self.pending = self.pending, None
                return event
            name, sep, value = item.partition("=")
            if sep:
                self.pending.env[name] = value
            return None

        if self.pending is not None:
            raise ProtocolError("new CLIENT header before ENV,END")
        kind, _, args = text.partition(",")
        fields = args.split(",") if args else []
        try:
            if kind in ("CONNECT", "REAUTH"):
                # >CLIENT:CONNECT|REAUTH,{CID},{KID}   (MN 1213)
                self.pending = ClientEvent(kind, int(fields[0]), int(fields[1]))
            elif kind in ("ESTABLISHED", "DISCONNECT"):
                # >CLIENT:ESTABLISHED,{CID} / >CLIENT:DISCONNECT,{CID}   (MN 1222, 1232)
                self.pending = ClientEvent(kind, int(fields[0]))
            elif kind == "CR_RESPONSE":
                # >CLIENT:CR_RESPONSE,{CID},{KID},{response_base64}   (MN 1245)
                self.pending = ClientEvent(kind, int(fields[0]), int(fields[1]), extra=fields[2])
            elif kind == "ADDRESS":
                # >CLIENT:ADDRESS,{CID},{ADDR},{PRI}, single line   (MN 1241)
                return ClientEvent(kind, int(fields[0]), extra=(fields[1], fields[2] == "1"))
            else:
                return Notification("CLIENT", text)
        except (IndexError, ValueError):
            raise ProtocolError("malformed CLIENT header: %r" % text[:80])
        return None


# status 3 ------------------------------------------------------------------------
# MAN 443-459: status-version 2 adds Virtual Address, Virtual IPv6 Address,
# Username, Client ID, Peer ID, Data Channel Cipher; version 3 is the same,
# tab-separated. Columns are taken from the HEADER line, not hard-coded.

def parse_status3(lines):
    """Return a list of dicts, one per CLIENT_LIST row, keyed by HEADER column names."""
    header = None
    sessions = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0] == "HEADER" and fields[1] == "CLIENT_LIST":
            header = fields[2:]
        elif fields[0] == "CLIENT_LIST" and header:
            row = dict(zip(header, fields[1:]))
            sessions.append(row)
    return sessions


def session_summary(row):
    """Stable, small view of a status row for the panel and CLI."""
    def num(key):
        try:
            return int(row.get(key, "0") or 0)
        except ValueError:
            return 0
    return {
        "common_name": row.get("Common Name", ""),
        "username": row.get("Username", ""),
        "real_address": row.get("Real Address", ""),
        "vpn_ip": row.get("Virtual Address", ""),
        "bytes_in": num("Bytes Received"),
        "bytes_out": num("Bytes Sent"),
        "since": num("Connected Since (time_t)"),
        "cid": num("Client ID"),
    }
