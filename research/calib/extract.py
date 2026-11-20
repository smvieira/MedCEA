"""The snapshot extract (EXTRACT_SCHEMA 1): the small sets a calibration or a scenario pins.

A committed YAML file (research/calib/extracts/snapshot-<id>-<lineage[:12]>.yaml; fetch
writes <out>/extract.yaml) holding snapshot N's recipes, recipe_lines and catalogue, each
row a mapping of its columns in lake_api's order. Every value is stored as PostgreSQL's
own output text for its column (design §9 R9): a number as its numeric text (a string),
a jsonb value as jsonb's text (keys in jsonb order, ", " and ": "), NULL as null. So the
digests the lake recorded recompute offline from the file alone (verify), and nothing a
float could round reaches it. Read a jsonb field with pgtext.loads_raw.

No person column: the lake holds none (owner decision P).
"""
from __future__ import annotations

import re

import yaml

from . import EXTRACT_SCHEMA, pgtext
from .dataset import _atomic_write
from .lake import FUNCTIONS, LakeError, row_text

SETS = ("recipes", "recipe_lines", "catalogue")
FILE = "extract.yaml"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ExtractError(Exception):
    """An extract that cannot be built or does not verify."""


def columns(fn):
    return [c for c in FUNCTIONS[fn]["columns"] if c[0] != "snapshot_id"]


def file_name(snapshot_id, lineage):
    """The committed name: snapshot-<id>-<lineage[:12]>.yaml."""
    return "snapshot-%d-%s.yaml" % (int(snapshot_id), str(lineage)[:12])


def text_row(fn, row):
    """A lake-api row as {column: PostgreSQL output text or None}, in column order."""
    return {name: pgtext.field_text(row.get(name), t) for name, t in columns(fn)}


def digest_of(fn, text_rows):
    """The set's digest from text rows (each row's fields already PostgreSQL's text)."""
    names = [n for n, _ in columns(fn)]
    for r in text_rows:
        if list(r) != names:
            raise ExtractError("a %s row has columns %s, not %s" % (fn, list(r), names))
    return pgtext.set_digest([pgtext.record_out([r[n] for n in names]) for r in text_rows])


def fetch(client, pinned):
    """The extract document of PINNED (a pinned snapshots() row): each set read from
    lake-api and its digest recomputed; refused (ExtractError) unless all three equal
    the snapshot's recorded digests."""
    n = int(pinned["snapshot_id"])
    recorded = pinned.get("digests") or {}
    doc = {"medcea_extract": EXTRACT_SCHEMA,
           "lake": {"contract_version": int(str(pinned.get("contract_version"))), "snapshot_id": n,
                    "cut_at": pgtext.norm_ts(pinned.get("cut_at")), "lineage": str(pinned.get("lineage")).lower()},
           "digests": {}}
    sets = {}
    for fn in SETS:
        raw = client.small_set(fn, n)
        rows = [text_row(fn, r) for r in raw]
        for r, raw_row in zip(rows, raw):
            if row_text(fn, raw_row) != pgtext.record_out(list(r.values())):
                raise ExtractError("a %s row's text differs between its two renderings" % fn)
        got = digest_of(fn, rows)
        want = recorded.get(fn)
        if got != want:
            raise ExtractError("snapshot %d's %s digest does not recompute (recorded %s, recomputed %s)"
                               % (n, fn, want, got))
        doc["digests"][fn] = got
        sets[fn] = rows
    doc.update(sets)
    return doc


def dumps(doc):
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=4096)


def write(path, doc):
    _atomic_write(path, dumps(doc).encode("utf-8"))


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except OSError as e:
        raise ExtractError("cannot read %s: %s" % (path, e.strerror or e)) from None
    except yaml.YAMLError as e:
        raise ExtractError("%s is not YAML: %s" % (path, e)) from None
    return doc


def verify_doc(doc, where="extract"):
    """Schema and every digest of an extract document. Returns the summary lines."""
    if not isinstance(doc, dict) or doc.get("medcea_extract") != EXTRACT_SCHEMA:
        raise ExtractError("%s is not a snapshot extract of schema %d" % (where, EXTRACT_SCHEMA))
    lake = doc.get("lake") or {}
    if not isinstance(lake.get("snapshot_id"), int) or not _HEX64.match(str(lake.get("lineage", ""))):
        raise ExtractError("%s: lake.snapshot_id and a 64-hex lake.lineage are required" % where)
    expected_keys = ["medcea_extract", "lake", "digests"] + list(SETS)
    if list(doc) != expected_keys:
        raise ExtractError("%s: keys %s, not %s" % (where, list(doc), expected_keys))
    out = []
    for fn in SETS:
        rows = doc.get(fn)
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ExtractError("%s: %s is not a list of rows" % (where, fn))
        for r in rows:
            for k, v in r.items():
                if v is not None and not isinstance(v, str):
                    raise ExtractError("%s: %s.%s holds %r: every value is PostgreSQL's text (a string) or null"
                                       % (where, fn, k, v))
        got = digest_of(fn, rows)
        if got != (doc.get("digests") or {}).get(fn):
            raise ExtractError("%s: the %s digest does not recompute (recorded %s, recomputed %s)"
                               % (where, fn, (doc.get("digests") or {}).get(fn), got))
        out.append("%s: %d rows, digest recomputes" % (fn, len(rows)))
    return out


def verify(path):
    doc = load(path)
    return ["extract %s: snapshot %s, lineage %s" % (path, (doc.get("lake") or {}).get("snapshot_id")
                                                     if isinstance(doc, dict) else "?",
                                                     (doc.get("lake") or {}).get("lineage")
                                                     if isinstance(doc, dict) else "?")] + verify_doc(doc, path)


__all__ = ["ExtractError", "LakeError", "fetch", "write", "load", "verify", "file_name", "SETS"]
