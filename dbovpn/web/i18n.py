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


def _legacy_detail(language, text):
    parts = []
    for part in (text or "").split("; "):
        head, sep, tail = part.partition(": ")
        if sep and _lookup(language, _key("det_", head)):
            parts.append("%s: %s" % (_lookup(language, _key("det_", head)),
                                     _lookup(language, _key("det_", tail)) or tail))
        else:
            parts.append(_lookup(language, _key("det_", part)) or part)
    return "; ".join(parts)


def _structured(text):
    """(key, params) for details written with db.detail(), else None."""
    if not (text or "").startswith("@{"):
        return None
    try:
        data = json.loads(text[1:])
        return str(data["k"]), dict(data.get("p") or {})
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def detail_label(language, text):
    """Render an audit detail in the panel language.

    Structured details (db.detail): template 'dtl_<key>'; params named '*_code'
    are translated through 'code_<value>', a 'why' param through the phrase
    table, every other value stays raw (IPs, dates, e-mail addresses, errors).
    Older plain-text details: known phrases (det_<phrase>) are translated,
    'a; b' and 'prefix: phrase' forms part by part, anything else stays raw.
    """
    parsed = _structured(text)
    if parsed is None:
        return _legacy_detail(language, text)
    key, params = parsed
    values = {}
    for name, value in params.items():
        value = "" if value is None else str(value)
        if name.endswith("_code"):
            value = _lookup(language, "code_" + value) or value
        elif name == "why":
            value = _legacy_detail(language, value)
        values[name] = value
    template = _lookup(language, "dtl_" + key)
    if template is None:
        return " ".join([key] + ["%s=%s" % kv for kv in sorted(values.items())])
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return " ".join([key] + ["%s=%s" % kv for kv in sorted(values.items())])


def detail_title(text):
    """Title attribute: the English rendering plus the raw key/params, so the code
    stays greppable; plain-text details are shown raw."""
    parsed = _structured(text)
    if parsed is None:
        return text or ""
    key, params = parsed
    raw = " ".join([key] + ["%s=%s" % kv for kv in sorted(params.items())])
    return "%s [%s]" % (detail_label("en", text), raw)
