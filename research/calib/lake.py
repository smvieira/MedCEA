"""LakeClient: lake-api's read functions over HTTP, pinned by snapshot id and lineage.

lake-api (apps/lake-api/, PostgREST over schema lake_api of medcea_research; owner
decision O2) is network-gated and has no identity: GET <lake>/rpc/<fn>?<params>. The URL
comes from --lake or MEDCEA_LAKE (apps/research/calibrate.sh resolves the pod's address
on the host; inside the research zone a notebook has MEDCEA_LAKE already). Nothing here
writes anything.

- Every number keeps its text (pgtext.loads_raw), so a numeric reaches the dataset and the
  digest exactly as the server wrote it.
- lineage_chain() is medcea_data.py's rule, byte for byte: L_0 = '',
  L_N = sha256_hex(L_{N-1} + '\\n' + digests['measurement']) in snapshot_id order. An id
  alone does not name the same data (ids restart after a purge); a lineage does.
- measurements() pages by keyset on measured_at (never an offset): the server returns
  newest first under p_limit (PAGE_SIZE, well under MAX_LIMIT: a full 50,000-row page
  runs lake-api out of memory); a full page's oldest second is dropped and asked again
  with p_to = that second (p_to is inclusive), until a short page. Rows that share a
  measured_at come back in an unstable order; dataset.py sorts them.

The function, parameter and column names below are the reviewed form of lake_api.sql
(research/contract.py LAKE; tests/test_research_contract.py compares all three).
"""
from __future__ import annotations

import hashlib
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

from . import pgtext

MAX_LIMIT = 50000
# The page size measurements() asks for. Not MAX_LIMIT: on 20 Nov 2026 one 50,000-row page
# of snapshot 1 made lake-api's PostgREST exceed its 128Mi memory limit (OOMKilled, the
# pod restarted). 5,000 rows is about 1,000 board cycles of one unit and zone.
PAGE_SIZE = 5000
TIMEOUT_S = 45          # above lake-api's 30 s statement_timeout, so a 57014 arrives as an answer
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# name -> {"params": [...], "columns": [(name, type), ...]} (lake_api.sql's RETURNS TABLE)
FUNCTIONS = {
    "snapshots": {"params": [],
                  "columns": [("snapshot_id", "bigint"), ("cut_at", "timestamptz"), ("previous_cut_at", "timestamptz"),
                              ("created_at", "timestamptz"), ("contract_version", "integer"), ("rows", "jsonb"),
                              ("digests", "jsonb"), ("lineage", "text")]},
    "measurements": {"params": ["p_snapshot", "p_unit", "p_zone", "p_tag", "p_from", "p_to", "p_sensor", "p_limit"],
                     "columns": [("snapshot_id", "bigint"), ("ingested_at", "timestamptz"),
                                 ("measured_at", "timestamptz"), ("unit_code", "text"), ("zone_code", "text"),
                                 ("tag", "text"), ("sensor", "text"), ("value", "numeric"), ("uom", "text")]},
    "units": {"params": ["p_snapshot"],
              "columns": [("snapshot_id", "bigint"), ("unit_code", "text"), ("recipe_type", "text"),
                          ("area", "numeric"), ("height", "numeric"), ("is_active", "text")]},
    "zones": {"params": ["p_snapshot"],
              "columns": [("snapshot_id", "bigint"), ("unit_code", "text"), ("zone_code", "text"),
                          ("is_active", "text")]},
    "recipes": {"params": ["p_snapshot"],
                "columns": [("snapshot_id", "bigint"), ("recipe_id", "integer"), ("recipe_type", "text"),
                            ("status", "text")]},
    "recipe_lines": {"params": ["p_snapshot"],
                     "columns": [("snapshot_id", "bigint"), ("recipe_id", "integer"), ("seq", "integer"),
                                 ("cycle_number", "integer"), ("light_type", "text"),
                                 ("light_on_minutes", "integer"), ("light_off_minutes", "integer"),
                                 ("setpoints", "jsonb")]},
    "catalogue": {"params": ["p_snapshot"],
                  "columns": [("snapshot_id", "bigint"), ("kind", "text"), ("code", "text"), ("doc", "jsonb")]},
    "holds": {"params": [],
              "columns": [("unit_code", "text"), ("zone_code", "text"), ("from_at", "timestamptz"),
                          ("to_at", "timestamptz")]},
}

# The small sets a snapshot holds a whole copy of, keyed as lake.snapshot.digests keys them.
SMALL_SETS = ("units", "zones", "recipes", "recipe_lines", "catalogue")

LINEAGE_RULE = ("L_0 = '', L_N = hex(sha256(utf8(L_{N-1} || E'\\n' || digests->>'measurement'))), "
                "in snapshot_id order")


class LakeError(Exception):
    """lake-api refused, could not be reached, or answered something unusable. code is
    PostgreSQL's SQLSTATE when the server named one (22023, 57014, …)."""

    def __init__(self, message, code=None, status=None):
        super().__init__(message)
        self.code = code
        self.status = status


def lineage_chain(rows):
    """{snapshot_id: lineage} recomputed from snapshots() rows (medcea_data.py's rule)."""
    out, prev = {}, ""
    for row in sorted(rows, key=lambda r: int(r["snapshot_id"])):
        md = (row.get("digests") or {}).get("measurement") or ""
        prev = hashlib.sha256((prev + "\n" + md).encode("utf-8")).hexdigest()
        out[int(row["snapshot_id"])] = prev
    return out


def _int(v, what):
    try:
        if isinstance(v, bool):
            raise ValueError
        return int(str(v))
    except (TypeError, ValueError):
        raise LakeError("the lake reader answered %r for %s, not a whole number" % (v, what)) from None


class LakeClient:
    def __init__(self, base_url, timeout=TIMEOUT_S):
        base = (base_url or "").strip().rstrip("/")
        if not re.match(r"^https?://[^/\s?#]+(/[^\s?#]*)?$", base):
            raise LakeError("the lake URL %r is not http(s)://host[:port]" % base_url)
        self.base = base
        self.timeout = timeout

    # ── requests ──────────────────────────────────────────────────────────────────
    def url(self, fn, params):
        q = [(k, v) for k, v in params if v is not None]
        qs = "&".join("%s=%s" % (k, urllib.parse.quote(str(v), safe="")) for k, v in q)
        return "%s/rpc/%s%s" % (self.base, fn, ("?" + qs) if qs else "")

    def rpc(self, fn, **params):
        """GET <base>/rpc/<fn>?<params>: the decoded rows (numbers as their text). Only the
        lake_api functions and their own parameters are asked for."""
        spec = FUNCTIONS.get(fn)
        if spec is None:
            raise LakeError("no lake function %r" % fn)
        unknown = sorted(set(params) - set(spec["params"]))
        if unknown:
            raise LakeError("lake function %s has no parameter %s" % (fn, ", ".join(unknown)))
        ordered = [(k, params.get(k)) for k in spec["params"]]
        url = self.url(fn, ordered)
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            body_raw = e.read()
            e.close()
            try:
                body = pgtext.loads_raw(body_raw) if body_raw.strip() else {}
            except ValueError:
                body = {}
            code = body.get("code") if isinstance(body, dict) else None
            msg = (body.get("message") if isinstance(body, dict) else None) or ""
            if code == "22023":
                raise LakeError(msg or "refused", code, e.code) from None
            if code == "57014":
                raise LakeError("the lake reader stopped the query after its 30 s statement timeout (%s)" % fn,
                                code, e.code) from None
            raise LakeError("the lake reader answered %d %s" % (e.code, msg or code or ""), code, e.code) from None
        except (urllib.error.URLError, OSError, socket.timeout) as e:
            raise LakeError("the lake reader at %s is not reachable (%s): ./apps/lake-api/deploy.sh"
                            % (self.base, getattr(e, "reason", e))) from None
        try:
            rows = pgtext.loads_raw(raw)
        except ValueError:
            raise LakeError("the lake reader answered something that is not JSON (%s)" % fn) from None
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise LakeError("the lake reader answered something that is not a list of rows (%s)" % fn)
        return rows

    # ── snapshots ─────────────────────────────────────────────────────────────────
    def snapshots(self):
        """Every snapshot, oldest first, snapshot_id an int, plus lineage_verified."""
        rows = self.rpc("snapshots")
        for r in rows:
            r["snapshot_id"] = _int(r.get("snapshot_id"), "snapshot_id")
        chain = lineage_chain(rows)
        for r in rows:
            r["lineage_verified"] = chain.get(r["snapshot_id"]) == r.get("lineage")
        return sorted(rows, key=lambda r: r["snapshot_id"])

    def pin(self, snapshot_id, expect_lineage, snapshots=None):
        """Snapshot SNAPSHOT_ID's row, refused unless it exists, its lineage recomputes and
        equals EXPECT_LINEAGE (case-insensitive)."""
        expect = str(expect_lineage or "").strip().lower()
        if not HEX64.match(expect):
            raise LakeError("the expected lineage must be 64 hex digits (snapshots lists them)")
        rows = self.snapshots() if snapshots is None else snapshots
        for r in rows:
            if r["snapshot_id"] == int(snapshot_id):
                if not r.get("lineage_verified"):
                    raise LakeError("snapshot %s's lineage does not recompute from the snapshot list: "
                                    "./health-check.sh (Research lake reader)" % snapshot_id)
                if str(r.get("lineage")).lower() != expect:
                    raise LakeError("snapshot %s has lineage %s, not the %s you expected: it is not the same data"
                                    % (snapshot_id, r.get("lineage"), expect))
                return r
        raise LakeError("no snapshot %s in the lake (snapshots lists them)" % snapshot_id)

    # ── data ──────────────────────────────────────────────────────────────────────
    def measurements(self, snapshot_id, unit, zone, tag=None, sensor=None, limit=PAGE_SIZE):
        """(rows, pages): every reading up to snapshot SNAPSHOT_ID of UNIT/ZONE (optionally
        one tag and sensor). Rows: dicts of the measurement columns, timestamps in
        pgtext.norm_ts form, value as its numeric text (or None), snapshot_id an int.
        Unordered among rows that share a measured_at."""
        limit = int(limit)
        if not 1 <= limit <= MAX_LIMIT:
            raise LakeError("the page size must be between 1 and %d" % MAX_LIMIT)
        out, pages, p_to = [], 0, None
        while True:
            page = self.rpc("measurements", p_snapshot=int(snapshot_id), p_unit=unit, p_zone=zone, p_tag=tag,
                            p_sensor=sensor, p_to=p_to, p_limit=limit)
            pages += 1
            rows = [self._measurement(r) for r in page]
            if len(rows) > limit:
                raise LakeError("the lake reader returned %d rows for a limit of %d" % (len(rows), limit))
            if len(rows) < limit:
                out += rows
                return out, pages
            t_min = min(r["measured_at"] for r in rows)
            if all(r["measured_at"] == t_min for r in rows):
                raise LakeError("one measured_at (%s) holds %d rows or more: the keyset pager cannot split it"
                                % (t_min, limit))
            if p_to is not None and max(r["measured_at"] for r in rows) > p_to:
                raise LakeError("the lake reader returned rows after p_to: the pager would not end")
            out += [r for r in rows if r["measured_at"] != t_min]
            p_to = t_min

    @staticmethod
    def _measurement(r):
        if r.get("measured_at") is None:
            raise LakeError("the lake reader returned a reading without measured_at")
        v = r.get("value")
        if v is not None and (isinstance(v, bool) or not isinstance(v, (pgtext.Num, int))):
            raise LakeError("the lake reader returned a value that is not a number: %r" % (v,))
        return {"measured_at": pgtext.norm_ts(r.get("measured_at")),
                "ingested_at": pgtext.norm_ts(r.get("ingested_at")),
                "unit_code": r.get("unit_code"), "zone_code": r.get("zone_code"),
                "tag": r.get("tag"), "sensor": r.get("sensor"),
                "value": None if v is None else str(v), "uom": r.get("uom"),
                "snapshot_id": _int(r.get("snapshot_id"), "snapshot_id")}

    def small_set(self, fn, snapshot_id):
        """The rows of exactly snapshot SNAPSHOT_ID (an unknown snapshot gives []: pin first)."""
        if fn not in SMALL_SETS:
            raise LakeError("%s is not a small set (%s)" % (fn, ", ".join(SMALL_SETS)))
        return self.rpc(fn, p_snapshot=int(snapshot_id))

    def holds(self):
        """The held-out ranges: unit_code, zone_code (None = every zone), from_at, to_at
        (norm_ts). Never who or why."""
        return [{"unit_code": r.get("unit_code"), "zone_code": r.get("zone_code"),
                 "from_at": pgtext.norm_ts(r.get("from_at")), "to_at": pgtext.norm_ts(r.get("to_at"))}
                for r in self.rpc("holds")]


def row_text(fn, row):
    """A small-set row's record text as lake._set_digest writes it (snapshot_id left out)."""
    cols = [c for c in FUNCTIONS[fn]["columns"] if c[0] != "snapshot_id"]
    return pgtext.record_out([pgtext.field_text(row.get(name), t) for name, t in cols])
