"""Small text helpers shared by the web app and its tests (no Flask needed)."""

import re

TURKISH_ASCII = str.maketrans({"ı": "i", "İ": "i", "ğ": "g", "Ğ": "g", "ü": "u", "Ü": "u", "ş": "s", "Ş": "s",
                               "ö": "o", "Ö": "o", "ç": "c", "Ç": "c"})
TOKEN_PATH_RE = re.compile(r"^/(enroll|admin-enroll)/[^/]+")


def slug(text):
    """ASCII file-name slug; Turkish letters are transliterated, not dropped."""
    return re.sub(r"[^a-z0-9]+", "-", text.translate(TURKISH_ASCII).lower()).strip("-") or "vpn"


def redact_path(path):
    """Hide the one-time token in /enroll/<token>... and /admin-enroll/<token>... for logs."""
    return TOKEN_PATH_RE.sub(lambda m: "/%s/<redacted>" % m.group(1), path or "")
