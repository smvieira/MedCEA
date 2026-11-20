"""The frozen measurement dataset (DATASET_SCHEMA 1): <out>/dataset.jsonl.

UTF-8, "\\n", deterministic. Line 1 is the header object (canonical JSON: sorted keys,
no spaces); lines 2..n are canonical JSON arrays in COLUMNS order, sorted by
(measured_at, ingested_at, tag, sensor, value text, uom). Timestamps are UTC
YYYY-MM-DDTHH:MM:SS.ffffffZ, value is the numeric's raw text or null. The header holds no
wall-clock time and no hold (those go to fetch-log.json beside it, which makes no
byte-identity claim), so fetching the same lineage again writes a byte-identical file.
content_sha256 is the sha256 of lines 2..n, each with its "\\n"; consumers pin it, never
the path.

Completeness (design §9 R9): for each snapshot k up to the pinned one, the rows fetched
with snapshot_id k are compared with snapshots()[k].rows.measurement: equal → complete,
and the snapshot's measurement digest must recompute from them (a mismatch refuses the
fetch); fewer → complete false, the difference recorded, no digest check (other units or
zones share the snapshot); more → refused.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import tempfile

from . import DATASET_SCHEMA, CALIB_VERSION, pgtext
from .lake import PAGE_SIZE, LakeError

COLUMNS = ("measured_at", "ingested_at", "unit_code", "zone_code", "tag", "sensor", "value", "uom", "snapshot_id")
FILE = "dataset.jsonl"
FETCH_LOG = "fetch-log.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DatasetError(Exception):
    """A dataset that cannot be written or read as it claims to be."""


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _key(row):
    return tuple((row[c] is None, row[c] or "") for c in ("measured_at", "ingested_at", "tag", "sensor", "value", "uom"))


def row_line(row):
    return canonical([row[c] for c in COLUMNS]) + "\n"


def content_sha256(rows):
    h = hashlib.sha256()
    for r in rows:
        h.update(row_line(r).encode("utf-8"))
    return h.hexdigest()


def series_counts(rows):
    out = {}
    for r in rows:
        k = "%s/%s" % (r["tag"], r["sensor"])
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


# ── holds ───────────────────────────────────────────────────────────────────────────
def in_hold(row, hold):
    """True when ROW lies inside HOLD: the same unit (case-insensitive), the same zone or
    a hold of every zone, measured_at in [from_at, to_at)."""
    if str(row.get("unit_code") or "").lower() != str(hold.get("unit_code") or "").lower():
        return False
    hz = hold.get("zone_code")
    if hz is not None and str(row.get("zone_code") or "").lower() != str(hz).lower():
        return False
    t = pgtext.norm_ts(row["measured_at"])
    return pgtext.norm_ts(hold["from_at"]) <= t < pgtext.norm_ts(hold["to_at"])


def check_holds(rows, holds):
    for h in holds:
        n = sum(1 for r in rows if in_hold(r, h))
        if n:
            raise DatasetError("%d reading(s) lie inside the hold %s/%s [%s, %s): the lake must never hold them"
                               % (n, h.get("unit_code"), h.get("zone_code") or "*", h["from_at"], h["to_at"]))


# ── digests ─────────────────────────────────────────────────────────────────────────
def snapshot_digests(rows):
    """{snapshot_id: measurement digest} recomputed from ROWS, per snapshot."""
    by = {}
    for r in rows:
        by.setdefault(r["snapshot_id"], []).append((r["ingested_at"], pgtext.measurement_text(r)))
    return {k: pgtext.measurement_digest(v) for k, v in sorted(by.items())}


# ── fetch ───────────────────────────────────────────────────────────────────────────
def fetch(client, snapshot_id, expect_lineage, unit, zone, page_size=None):
    """(header, rows, holds, pinned) of every reading up to snapshot SNAPSHOT_ID of UNIT/ZONE,
    pinned by EXPECT_LINEAGE, checked as the module docstring says. Raises LakeError or
    DatasetError."""
    snaps = client.snapshots()
    doc = client.pin(snapshot_id, expect_lineage, snaps)
    n = doc["snapshot_id"]
    page_size = int(page_size or PAGE_SIZE)
    rows, pages = client.measurements(n, unit, zone, limit=page_size)
    for r in rows:
        if r["snapshot_id"] > n:
            raise DatasetError("the lake reader returned a reading of snapshot %d for snapshot %d"
                               % (r["snapshot_id"], n))
        if str(r["unit_code"]).lower() != unit.lower() or str(r["zone_code"]).lower() != zone.lower():
            raise DatasetError("the lake reader returned a reading of %s/%s for %s/%s"
                               % (r["unit_code"], r["zone_code"], unit, zone))
    rows.sort(key=_key)
    recomputed = snapshot_digests(rows)
    per = []
    for s in snaps:
        k = s["snapshot_id"]
        if k > n:
            continue
        recorded_rows = (s.get("rows") or {}).get("measurement")
        if recorded_rows is None:
            raise DatasetError("snapshot %d records no measurement row count" % k)
        recorded_rows = int(str(recorded_rows))
        fetched = sum(1 for r in rows if r["snapshot_id"] == k)
        digest = (s.get("digests") or {}).get("measurement")
        entry = {"id": k, "cut_at": pgtext.norm_ts(s.get("cut_at")),
                 "previous_cut_at": pgtext.norm_ts(s.get("previous_cut_at")),
                 "digest_measurement": digest, "rows_measurement": recorded_rows, "rows_fetched": fetched}
        if fetched > recorded_rows:
            raise DatasetError("snapshot %d records %d readings but %d were fetched for %s/%s"
                               % (k, recorded_rows, fetched, unit, zone))
        if fetched == recorded_rows:
            got = recomputed.get(k, pgtext.sha256_hex(""))
            if got != digest:
                raise DatasetError("snapshot %d's measurement digest does not recompute (recorded %s, "
                                   "recomputed %s)" % (k, digest, got))
            entry.update(complete=True, missing=0, digest_verified=True)
        else:
            entry.update(complete=False, missing=recorded_rows - fetched, digest_verified=None,
                         why="the snapshot holds readings of other units or zones")
        per.append(entry)
    holds = client.holds()
    check_holds(rows, holds)
    header = {
        "medcea_dataset": DATASET_SCHEMA, "calib_version": CALIB_VERSION,
        "lake": {"contract_version": int(str(doc.get("contract_version"))), "snapshot_id": n,
                 "cut_at": pgtext.norm_ts(doc.get("cut_at")), "lineage": str(doc.get("lineage")).lower(),
                 "lineage_verified": True, "snapshots": per},
        "query": {"fn": "measurements", "p_snapshot": n, "p_unit": unit, "p_zone": zone, "p_tag": None,
                  "p_sensor": None, "page_size": page_size, "pages": pages},
        "rows": len(rows), "series": series_counts(rows), "columns": list(COLUMNS),
        "content_sha256": content_sha256(rows),
    }
    return header, rows, holds, doc


# ── write / read ────────────────────────────────────────────────────────────────────
def _atomic_write(path, data):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def write(path, header, rows):
    if header.get("content_sha256") != content_sha256(rows):
        raise DatasetError("the header's content_sha256 is not the rows'")
    data = (canonical(header) + "\n" + "".join(row_line(r) for r in rows)).encode("utf-8")
    _atomic_write(path, data)


def write_fetch_log(path, base_url, header, holds):
    log = {"fetched_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "lake_url": base_url, "dataset_content_sha256": header["content_sha256"],
           "snapshot_id": header["lake"]["snapshot_id"], "lineage": header["lake"]["lineage"], "holds": holds}
    _atomic_write(path, (json.dumps(log, sort_keys=True, indent=1) + "\n").encode("utf-8"))


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_header(header, where):
    """The header's shape beyond what content_sha256 covers (it covers only the rows): the
    lake block, its snapshots and the query, as fetch() writes them. DatasetError, never a
    KeyError, on a malformed or hand-edited header."""
    if not isinstance(header.get("content_sha256"), str) or not _HEX64.match(header["content_sha256"]):
        raise DatasetError("%s: the header's content_sha256 is not 64 hex digits" % where)
    if not _is_int(header.get("rows")) or not isinstance(header.get("series"), dict):
        raise DatasetError("%s: the header needs rows (a whole number) and series (a mapping)" % where)
    lk = header.get("lake")
    if not isinstance(lk, dict):
        raise DatasetError("%s: the header has no lake block" % where)
    if not _is_int(lk.get("snapshot_id")) or not _is_int(lk.get("contract_version")) \
            or not _HEX64.match(str(lk.get("lineage", ""))) or not isinstance(lk.get("cut_at"), str):
        raise DatasetError("%s: the header's lake block needs snapshot_id, contract_version, a 64-hex lineage "
                           "and cut_at" % where)
    snaps = lk.get("snapshots")
    if not isinstance(snaps, list):
        raise DatasetError("%s: the header's lake.snapshots is not a list" % where)
    for s in snaps:
        if not isinstance(s, dict) or not all(_is_int(s.get(k)) for k in ("id", "rows_fetched", "rows_measurement")) \
                or not isinstance(s.get("complete"), bool):
            raise DatasetError("%s: a lake.snapshots entry needs id, rows_fetched, rows_measurement (whole numbers) "
                               "and complete (true or false)" % where)
        if s["complete"] and not _HEX64.match(str(s.get("digest_measurement") or "")):
            raise DatasetError("%s: complete snapshot %d has no 64-hex digest_measurement" % (where, s["id"]))
    q = header.get("query")
    if not isinstance(q, dict) or not isinstance(q.get("p_unit"), str) or not isinstance(q.get("p_zone"), str):
        raise DatasetError("%s: the header's query needs p_unit and p_zone" % where)


def read(path, holds=None):
    """(header, rows) of a dataset file, refused (DatasetError) unless its schema, columns,
    row count, order and content_sha256 hold and, when HOLDS is given, no row lies in one."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise DatasetError("cannot read %s: %s" % (path, e.strerror or e)) from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DatasetError("%s is not UTF-8" % path) from None
    if not text.endswith("\n"):
        raise DatasetError("%s does not end with a newline" % path)
    lines = text.split("\n")[:-1]
    if not lines:
        raise DatasetError("%s is empty" % path)
    try:
        header = json.loads(lines[0])
    except ValueError:
        raise DatasetError("%s: line 1 is not a JSON header" % path) from None
    if not isinstance(header, dict) or header.get("medcea_dataset") != DATASET_SCHEMA:
        raise DatasetError("%s is not a medcea dataset of schema %d" % (path, DATASET_SCHEMA))
    if header.get("columns") != list(COLUMNS):
        raise DatasetError("%s: columns %r, not %r" % (path, header.get("columns"), list(COLUMNS)))
    check_header(header, path)
    h = hashlib.sha256()
    for line in lines[1:]:
        h.update((line + "\n").encode("utf-8"))
    if h.hexdigest() != header.get("content_sha256"):
        raise DatasetError("%s: the rows' sha256 is %s, the header says %s" % (path, h.hexdigest(),
                                                                                header.get("content_sha256")))
    rows = []
    for i, line in enumerate(lines[1:], 2):
        try:
            vals = json.loads(line)
        except ValueError:
            raise DatasetError("%s:%d is not JSON" % (path, i)) from None
        if not isinstance(vals, list) or len(vals) != len(COLUMNS):
            raise DatasetError("%s:%d is not a row of %d columns" % (path, i, len(COLUMNS)))
        rows.append(dict(zip(COLUMNS, vals)))
    if len(rows) != header.get("rows"):
        raise DatasetError("%s holds %d rows, the header says %s" % (path, len(rows), header.get("rows")))
    keys = [_key(r) for r in rows]
    if keys != sorted(keys):
        raise DatasetError("%s: the rows are not in the dataset's order" % path)
    if holds is not None:
        check_holds(rows, holds)
    return header, rows


def verify(path):
    """Every check a dataset can take offline: read() (with fetch-log.json's holds when it
    sits beside the file), the series counts, and each complete snapshot's measurement
    digest recomputed from the rows. Returns the summary lines."""
    log_path = os.path.join(os.path.dirname(os.path.abspath(path)), FETCH_LOG)
    holds = None
    if os.path.exists(log_path):
        try:
            with open(log_path, encoding="utf-8") as f:
                holds = json.load(f).get("holds")
        except (OSError, ValueError, AttributeError):
            raise DatasetError("%s is not a fetch log" % log_path) from None
    header, rows = read(path, holds=holds)
    if series_counts(rows) != header.get("series"):
        raise DatasetError("%s: the series counts are not the rows'" % path)
    digests = snapshot_digests(rows)
    out = ["dataset %s: %d rows, content_sha256 %s" % (path, len(rows), header["content_sha256"])]
    for s in header["lake"]["snapshots"]:
        if s.get("complete"):
            got = digests.get(s["id"], pgtext.sha256_hex(""))
            if got != s.get("digest_measurement"):
                raise DatasetError("%s: snapshot %d's measurement digest does not recompute" % (path, s["id"]))
            out.append("snapshot %d: %d rows, measurement digest recomputes" % (s["id"], s["rows_fetched"]))
        else:
            out.append("snapshot %d: %d of %d rows (incomplete: %s), digest not checked"
                       % (s["id"], s["rows_fetched"], s["rows_measurement"], s.get("why", "")))
    out.append("holds: %s" % ("checked against %s" % FETCH_LOG if holds is not None else "no %s beside it" % FETCH_LOG))
    return out


__all__ = ["COLUMNS", "DatasetError", "LakeError", "fetch", "write", "read", "verify", "content_sha256"]
