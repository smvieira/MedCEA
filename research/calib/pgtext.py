"""PostgreSQL's text forms, so the lake's digests recompute outside the database.

The research database digests a set (lake._set_digest, apps/research/db/
medcea_research_ddl.sql; the same rules in lake.snapshot_digest_check, lake_api.sql) as
the sha256 of its rows' record output texts (x::text), sorted bytewise, under TimeZone
UTC and DateStyle ISO. This module rebuilds those texts from lake-api's JSON:

- record_out:   (f1,f2,…); a field is quoted when it is empty or holds whitespace, '"',
                '\\', '(', ')' or ','; inside the quotes '"' and '\\' are doubled; NULL is
                an empty, unquoted field.
- timestamptz:  YYYY-MM-DD HH:MM:SS[.fraction without trailing zeros]+00.
- numeric:      its own text, exactly as the server wrote it (never through a float):
                loads_raw() keeps every JSON number as a Num (a str subclass).
- jsonb:        keys in jsonb's order (shorter first, then bytewise), ", " between items
                and ": " after a key, strings escaped as escape_json does, numbers raw.
- a small set:  sha256 of the sorted row texts joined with "\\n" ("" for no row).
- measurements: per hour of ingested_at (UTC), oldest first, the line
                <YYYY-MM-DDTHH:00:00Z>|<rows>|<sha256 of that hour's sorted row texts>;
                the digest is the sha256 of those lines joined with "\\n".

Standard library only. tests/test_research_calib_pgtext.py pins it, including against
digests captured from the live lake when tests/fixtures/research/ holds them.
"""
from __future__ import annotations

import datetime
import hashlib
import json


class Num(str):
    """A JSON number's own text (never converted to a float)."""

    __slots__ = ()


def loads_raw(text):
    """json.loads keeping every number as a Num (its text) and keys in their order."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8")
    return json.loads(text, parse_float=Num, parse_int=Num, parse_constant=_no_constant)


def _no_constant(name):
    raise ValueError("JSON constant %s is not a PostgreSQL value" % name)


# ── timestamps ──────────────────────────────────────────────────────────────────────
def parse_ts(v):
    """A PostgREST/ISO 8601 timestamp as an aware UTC datetime. Takes "+00" without
    minutes and 0–9 fraction digits (k8s/workbench/examples/medcea_data.py _ts, ported)."""
    if isinstance(v, datetime.datetime):
        d = v
    else:
        t = str(v).strip().replace(" ", "T", 1)
        if t.endswith("Z") or t.endswith("z"):
            t = t[:-1] + "+00:00"
        head, sep, frac = t.partition(".")
        if sep:
            n = 0
            while n < len(frac) and frac[n].isdigit():
                n += 1
            digits, zone = frac[:n], frac[n:]
            if len(digits) > 6 and digits[6:].strip("0"):
                raise ValueError("timestamp %r has more than microsecond precision" % v)
            t = head + "." + (digits + "000000")[:6] + zone
        if "T" in t and len(t) >= 3 and t[-3] in "+-" and t[-2:].isdigit():
            t += ":00"
        d = datetime.datetime.fromisoformat(t)
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc)


def norm_ts(v):
    """The one form timestamps are kept in here: UTC, YYYY-MM-DDTHH:MM:SS.ffffffZ (it
    sorts as text in time order). None stays None."""
    if v is None:
        return None
    d = parse_ts(v)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % (d.year, d.month, d.day, d.hour, d.minute, d.second,
                                                     d.microsecond)


def timestamptz_out(v):
    """PostgreSQL's timestamptz text under TimeZone UTC, DateStyle ISO."""
    if v is None:
        return None
    d = parse_ts(v)
    s = "%04d-%02d-%02d %02d:%02d:%02d" % (d.year, d.month, d.day, d.hour, d.minute, d.second)
    if d.microsecond:
        s += ("." + "%06d" % d.microsecond).rstrip("0")
    return s + "+00"


def hour_of(v):
    """date_trunc('hour', ts) as the digest line writes it: YYYY-MM-DDTHH:00:00Z."""
    d = parse_ts(v)
    return "%04d-%02d-%02dT%02d:00:00Z" % (d.year, d.month, d.day, d.hour)


# ── jsonb ───────────────────────────────────────────────────────────────────────────
def escape_json(s):
    """PostgreSQL's escape_json: the quoted string."""
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jsonb_key(k):
    b = k.encode("utf-8")
    return (len(b), b)


def jsonb_out(v):
    """jsonb's text form of a value read with loads_raw (dicts, lists, str, Num, bool,
    None). A float is refused: its text is not the server's."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, Num):
        return str(v)
    if isinstance(v, str):
        return escape_json(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (escape_json(k), jsonb_out(v[k]))
                               for k in sorted(v, key=_jsonb_key)) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(jsonb_out(x) for x in v) + "]"
    raise ValueError("cannot write %s as jsonb text (read numbers with loads_raw)" % type(v).__name__)


# ── record_out ──────────────────────────────────────────────────────────────────────
_QUOTE = set('"\\(),') | set(" \t\n\r\v\f")


def record_field(text):
    """One field of a record's text (None: NULL, the empty unquoted field)."""
    if text is None:
        return ""
    if text == "" or any(ch in _QUOTE for ch in text):
        return '"' + text.replace("\\", "\\\\").replace('"', '""') + '"'
    return text


def record_out(fields):
    return "(" + ",".join(record_field(f) for f in fields) + ")"


def field_text(value, pgtype):
    """A column value from lake-api (read with loads_raw) as PostgreSQL's output text for
    its type: text, numeric/integer/bigint, timestamptz, jsonb or boolean."""
    if value is None:
        return None
    if pgtype == "jsonb":
        return jsonb_out(value)
    if pgtype == "timestamptz":
        return timestamptz_out(value)
    if pgtype in ("numeric", "integer", "bigint"):
        if isinstance(value, bool) or not isinstance(value, (Num, int)):
            raise ValueError("a %s column holds %r, not a number" % (pgtype, value))
        return str(value)
    if pgtype == "boolean":
        if not isinstance(value, bool):
            raise ValueError("a boolean column holds %r" % (value,))
        return "t" if value else "f"
    if pgtype == "text":
        if not isinstance(value, str) or isinstance(value, Num):
            raise ValueError("a text column holds %r" % (value,))
        return value
    raise ValueError("unknown column type %r" % pgtype)


# ── digests ─────────────────────────────────────────────────────────────────────────
def _sorted_joined(texts):
    return "\n".join(sorted(texts, key=lambda t: t.encode("utf-8")))


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def set_digest(row_texts):
    """A small set's digest: sha256 of the sorted row texts joined with newlines."""
    return sha256_hex(_sorted_joined(row_texts))


def hour_line(hour, row_texts):
    """One measurement digest line: <hour>|<rows>|<sha256 of the sorted row texts>."""
    return "%s|%d|%s" % (hour, len(row_texts), set_digest(row_texts))


def measurement_lines(rows):
    """[(hour, line)] oldest first, from (ingested_at, row_text) pairs."""
    hours = {}
    for ingested_at, text in rows:
        hours.setdefault(hour_of(ingested_at), []).append(text)
    return [(h, hour_line(h, hours[h])) for h in sorted(hours)]


def measurement_digest(rows):
    """The measurement set's digest from (ingested_at, row_text) pairs."""
    return sha256_hex("\n".join(line for _, line in measurement_lines(rows)))


# The measurement row's columns, in lake.stage_measurements' order (attnum), with types.
MEASUREMENT_ROW = (("ingested_at", "timestamptz"), ("measured_at", "timestamptz"), ("unit_code", "text"),
                   ("zone_code", "text"), ("tag", "text"), ("sensor", "text"), ("value", "numeric"),
                   ("uom", "text"))


def measurement_text(row):
    """The record text of one measurement (a dict with the MEASUREMENT_ROW keys; value is
    the numeric's text, timestamps in any ISO form)."""
    fields = []
    for name, pgtype in MEASUREMENT_ROW:
        v = row.get(name)
        if v is None:
            fields.append(None)
        elif pgtype == "timestamptz":
            fields.append(timestamptz_out(v))
        else:
            fields.append(str(v))
    return record_out(fields)
