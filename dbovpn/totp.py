"""RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s step) with the standard library only.

Kept dependency-free so the management daemon and the tests do not need pyotp.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP = 30
DIGITS = 6


def generate_secret():
    """160-bit random secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret):
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def hotp(key, counter, digits=DIGITS):
    """RFC 4226 HOTP value for a raw key and counter, as a zero-padded string."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def counter_at(now=None):
    return int((time.time() if now is None else now) // STEP)


def code_at(secret, now=None):
    return hotp(_key(secret), counter_at(now))


def verify(secret, code, now=None, last_counter=0, window=1):
    """Check code against the steps around now.

    Returns the matching step counter, or None. A step at or below last_counter
    is never accepted, so a code that was already used cannot be replayed.
    """
    code = (code or "").strip()
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    try:
        key = _key(secret)
    except (ValueError, TypeError):
        return None
    current = counter_at(now)
    for counter in range(current - window, current + window + 1):
        if counter <= (last_counter or 0):
            continue
        if hmac.compare_digest(hotp(key, counter), code):
            return counter
    return None


def provisioning_uri(secret, account, issuer):
    """otpauth:// URI for QR enrolment (Key Uri Format used by authenticator apps)."""
    label = quote("%s:%s" % (issuer, account), safe="")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                       "digits": DIGITS, "period": STEP}, quote_via=quote)
    return "otpauth://totp/%s?%s" % (label, query)
