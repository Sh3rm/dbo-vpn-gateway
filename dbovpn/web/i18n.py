"""UI strings: one JSON file per language in dbovpn/i18n/ (tr.json, en.json)."""

import json
import os
import re

I18N_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "i18n")

_cache = {}


def strings(language):
    if language not in _cache:
        with open(os.path.join(I18N_DIR, language + ".json"), "r", encoding="utf-8") as fh:
            _cache[language] = json.load(fh)
    return _cache[language]


def translate(language, key, **params):
    text = strings(language).get(key)
    if text is None:
        text = strings("en").get(key, key)
    if params:
        try:
            return text.format(**params)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def _key(prefix, text):
    return prefix + re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _lookup(language, key):
    return strings(language).get(key) or strings("en").get(key)


def action_label(language, code):
    """Human label for an audit action code (act_<code>); unknown codes stay as they are."""
    return _lookup(language, _key("act_", code or "")) or code


def detail_label(language, text):
    """Translate known audit detail phrases (det_<phrase>); anything else stays raw.

    Details may be joined with '; ' and may carry a 'prefix: phrase' form
    (e.g. 'sweep: user disabled'); each part is translated on its own.
    """
    parts = []
    for part in (text or "").split("; "):
        head, sep, tail = part.partition(": ")
        if sep and _lookup(language, _key("det_", head)):
            parts.append("%s: %s" % (_lookup(language, _key("det_", head)),
                                     _lookup(language, _key("det_", tail)) or tail))
        else:
            parts.append(_lookup(language, _key("det_", part)) or part)
    return "; ".join(parts)
