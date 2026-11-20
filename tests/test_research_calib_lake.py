"""research/calib/lake.py, dataset.py, extract.py and cli.py against a fake lake-api.

The fake is a local http.server answering GET /rpc/<fn>?<params> as lake-api's
PostgREST does: numbers as JSON numbers with their numeric text, timestamps as
"2026-11-14T19:52:44.5+00:00", 22023 refusals as {"code": "22023", "message": …}, and
measurements newest first with rows that share a measured_at in a shuffled order (the
server's order among them is unstable). Its digests and lineages are computed here, by
an implementation independent of research/calib/pgtext.py.

- paging: ties at the page edge are neither lost nor doubled; one measured_at holding a
  whole page is refused; the default page is well under MAX_LIMIT;
- lineage_chain() = k8s/workbench/examples/medcea_data.py's (read by path, here only);
- pin(): unknown id, a lineage that does not recompute, an unexpected lineage, a
  malformed one; 22023 and 57014 passed through with their meaning;
- completeness: fewer rows (another zone) is incomplete with no digest check; more rows
  than recorded, and a digest that does not recompute, refuse the fetch;
- a reading inside a hold refuses the fetch; holds go to fetch-log.json only;
- the extract's digests recompute, a tampered one refuses; verify works offline and
  refuses an edited byte;
- refetching the same lineage writes byte-identical dataset.jsonl and extract.yaml.

Offline, standard library + PyYAML. Run:
    python3 -m unittest tests.test_research_calib_lake
"""
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from research.calib import cli, dataset, extract, lake  # noqa: E402

MEDCEA_DATA = os.path.join(REPO, "k8s", "workbench", "examples", "medcea_data.py")


# ── an independent rendering of the lake's texts (not pgtext) ──────────────────────────
class N(str):
    """A number to be written raw into the fake's JSON."""


def _ts_json(d):
    s = d.strftime("%Y-%m-%dT%H:%M:%S")
    if d.microsecond:
        s += ("." + "%06d" % d.microsecond).rstrip("0")
    return s + "+00:00"


def _ts_pg(d):
    return _ts_json(d).replace("T", " ")[:-6] + "+00"


def _q(f):
    if f is None:
        return ""
    if f == "" or any(c in f for c in ' \t\n\r\v\f"\\(),'):
        return '"' + f.replace("\\", "\\\\").replace('"', '""') + '"'
    return f


def _rec(fields):
    return "(" + ",".join(_q(f) for f in fields) + ")"


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _jsonb(v):  # the fake's jsonb text: keys short-first, N raw, strings as JSON
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (json.dumps(k), _jsonb(v[k]))
                               for k in sorted(v, key=lambda k: (len(k.encode()), k.encode()))) + "}"
    if isinstance(v, N):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


def dump(obj):
    if isinstance(obj, N):
        return str(obj)
    if isinstance(obj, dict):
        return "{" + ",".join(json.dumps(k) + ":" + dump(v) for k, v in obj.items()) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(dump(v) for v in obj) + "]"
    return json.dumps(obj, ensure_ascii=False)


T0 = datetime.datetime(2026, 11, 14, 19, 52, 44, tzinfo=datetime.timezone.utc)


class FakeLake:
    """The data and the answers. measurement rows: dicts with datetimes and N values."""

    def __init__(self, seed=1, cycles=60, other_zone=0, step_s=3):
        rnd = random.Random(seed)
        self.rows = []
        sensors = (("air_temperature", "sht45_1", "C"), ("air_humidity", "sht45_1", "RH%"),
                   ("air_temperature", "scd30_1", "C"), ("co2", "scd30_1", "ppm"))
        for i in range(cycles):
            m = T0 + datetime.timedelta(seconds=step_s * i)
            for j, (tag, sensor, uom) in enumerate(sensors):
                ing = m + datetime.timedelta(microseconds=362301 + 9000 * j + rnd.randrange(1000))
                v = N("%.2f" % (20 + rnd.random() * 10)) if not (i == 5 and j == 3) else None
                if i == 7 and j == 0:
                    v = N("26.50")              # a trailing zero the text must keep
                snap = 1 if i < cycles * 2 // 3 else 2
                self.rows.append({"snapshot_id": snap, "ingested_at": ing, "measured_at": m, "unit_code": "UNIT01",
                                  "zone_code": "ZONE01", "tag": tag, "sensor": sensor, "value": v, "uom": uom})
        for i in range(other_zone):
            m = T0 + datetime.timedelta(seconds=step_s * i + 1)
            self.rows.append({"snapshot_id": 1, "ingested_at": m + datetime.timedelta(seconds=1), "measured_at": m,
                              "unit_code": "UNIT01", "zone_code": "ZONE02", "tag": "air_temperature",
                              "sensor": "sht45_1", "value": N("21.00"), "uom": "C"})
        self.holds = [{"unit_code": "UNIT01", "zone_code": "ZONE01",
                       "from_at": T0 + datetime.timedelta(days=1), "to_at": T0 + datetime.timedelta(days=1, hours=7)}]
        self.small = {
            "units": [{"unit_code": "UNIT01", "recipe_type": "FUNGI", "area": N("0.36"), "height": N("0.60"),
                       "is_active": "Y"}],
            "zones": [{"unit_code": "UNIT01", "zone_code": "ZONE01", "is_active": "Y"}],
            "recipes": [{"recipe_id": N("2"), "recipe_type": "FUNGI", "status": "approved"}],
            "recipe_lines": [{"recipe_id": N("2"), "seq": N(str(s)), "cycle_number": N(str(s + 1)),
                              "light_type": "DARK", "light_on_minutes": N("1"), "light_off_minutes": N("1"),
                              "setpoints": {"co2": {"lower": N("1000"), "upper": N("5000")},
                                            "air_temperature": {"lower": N("20"), "upper": N("25.5")}}}
                             for s in (1, 2)],
            "catalogue": [{"kind": "quantity", "code": "co2",
                           "doc": {"max": N("5000"), "min": N("0"), "unit": "ppm", "label": 'CO2 "air"'}}],
        }
        self.n_snapshots = 2
        self.tamper = {}          # (snapshot, key) -> value overriding the recorded rows/digests
        self.error = None         # (fn, http status, code, message) to answer instead
        self.shuffle = random.Random(seed + 1)
        self.calls = []

    # digests, as lake._set_digest would write them
    def measurement_digest(self, k):
        hours = {}
        for r in self.rows:
            if r["snapshot_id"] != k:
                continue
            t = _rec([_ts_pg(r["ingested_at"]), _ts_pg(r["measured_at"]), r["unit_code"], r["zone_code"], r["tag"],
                      r["sensor"], None if r["value"] is None else str(r["value"]), r["uom"]])
            hours.setdefault(r["ingested_at"].strftime("%Y-%m-%dT%H:00:00Z"), []).append(t)
        lines = ["%s|%d|%s" % (h, len(ts), _h("\n".join(sorted(ts, key=str.encode)))) for h, ts in sorted(hours.items())]
        return _h("\n".join(lines))

    def small_text(self, fn, row):
        out = []
        for name, t in lake.FUNCTIONS[fn]["columns"]:
            if name == "snapshot_id":
                continue
            v = row.get(name)
            out.append(None if v is None else (_jsonb(v) if t == "jsonb" else str(v)))
        return _rec(out)

    def snapshots(self):
        out, prev = [], ""
        for k in range(1, self.n_snapshots + 1):
            dig = {"measurement": self.measurement_digest(k)}
            for fn in lake.SMALL_SETS:
                dig[fn] = _h("\n".join(sorted((self.small_text(fn, r) for r in self.small[fn]), key=str.encode)))
            rows = {"measurement": N(str(sum(1 for r in self.rows if r["snapshot_id"] == k))), "held_out": N("0")}
            for key, v in list(self.tamper.items()):
                if key[0] == k:
                    (rows if key[1] in ("measurement",) and isinstance(v, N) else dig)[key[1]] = v
            prev = _h(prev + "\n" + dig["measurement"])
            out.append({"snapshot_id": N(str(k)), "cut_at": _ts_json(T0 + datetime.timedelta(days=4 + k)),
                        "previous_cut_at": None if k == 1 else _ts_json(T0 + datetime.timedelta(days=3 + k)),
                        "created_at": _ts_json(T0 + datetime.timedelta(days=4 + k, seconds=5)),
                        "contract_version": N("1"), "rows": rows, "digests": dig,
                        "lineage": self.tamper.get(("lineage", k), prev)})
        return out

    def answer(self, fn, q):
        self.calls.append((fn, q))
        if self.error and self.error[0] == fn:
            return self.error[1], {"code": self.error[2], "message": self.error[3], "details": None, "hint": None}
        if fn == "snapshots":
            return 200, self.snapshots()
        if fn == "holds":
            return 200, [{"unit_code": h["unit_code"], "zone_code": h["zone_code"], "from_at": _ts_json(h["from_at"]),
                          "to_at": _ts_json(h["to_at"])} for h in self.holds]
        snap = int(q.get("p_snapshot", "0") or 0)
        if fn in lake.SMALL_SETS:
            if snap > self.n_snapshots:
                return 200, []
            return 200, [dict({"snapshot_id": N(str(snap))}, **r) for r in self.small[fn]]
        if fn == "measurements":
            if not 1 <= snap <= self.n_snapshots:
                return 400, {"code": "22023", "message": "no snapshot %s" % snap}
            limit = int(q.get("p_limit", "50000"))
            if not 1 <= limit <= 50000:
                return 400, {"code": "22023", "message": "measurements: the limit must be between 1 and 50000, not %d"
                                                         % limit}
            p_to = q.get("p_to")
            p_to = datetime.datetime.fromisoformat(p_to.replace("Z", "+00:00")) if p_to else None
            sel = [r for r in self.rows if r["snapshot_id"] <= snap
                   and r["unit_code"].lower() == q["p_unit"].lower() and r["zone_code"].lower() == q["p_zone"].lower()
                   and (p_to is None or r["measured_at"] <= p_to)
                   and ("p_tag" not in q or r["tag"] == q["p_tag"])]
            self.shuffle.shuffle(sel)
            sel.sort(key=lambda r: r["measured_at"], reverse=True)     # stable: ties stay shuffled
            sel = sel[:limit]
            return 200, [{"snapshot_id": N(str(r["snapshot_id"])), "ingested_at": _ts_json(r["ingested_at"]),
                          "measured_at": _ts_json(r["measured_at"]), "unit_code": r["unit_code"],
                          "zone_code": r["zone_code"], "tag": r["tag"], "sensor": r["sensor"], "value": r["value"],
                          "uom": r["uom"]} for r in sel]
        return 404, {"code": "PGRST202", "message": "no function"}


class Server:
    def __init__(self, fake):
        self.fake = fake
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
                fn = u.path.rsplit("/", 1)[-1] if u.path.startswith("/rpc/") else ""
                status, body = outer.fake.answer(fn, q)
                data = dump(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Base(unittest.TestCase):
    def serve(self, fake=None):
        self.fake = fake or FakeLake()
        srv = Server(self.fake)
        self.addCleanup(srv.close)
        self.client = lake.LakeClient(srv.url)
        self.url = srv.url
        return self.client

    def tmp(self):
        d = tempfile.mkdtemp(prefix="rs-calib-")
        self.addCleanup(shutil.rmtree, d)
        return d

    def lineage(self, k):
        return lake.lineage_chain(self.fake.snapshots())[k]

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main(list(argv))
            except SystemExit as e:      # argparse's usage errors
                rc = e.code
        return rc, out.getvalue(), err.getvalue()


class Paging(Base):
    def test_ties_at_the_page_edge(self):
        c = self.serve()
        want = sorted((r["measured_at"], r["tag"], r["sensor"]) for r in self.fake.rows if r["snapshot_id"] <= 2)
        for limit in (5, 6, 7, 8, 9, 13, 400):   # four readings share each measured_at
            rows, pages = c.measurements(2, "UNIT01", "ZONE01", limit=limit)
            got = sorted((datetime.datetime.fromisoformat(r["measured_at"].replace("Z", "+00:00")), r["tag"],
                          r["sensor"]) for r in rows)
            self.assertEqual(got, want, "limit %d" % limit)
            self.assertEqual(len(rows), len(want))
            self.assertGreater(pages, 1 if limit < len(want) else 0)

    def test_the_pages_are_keyset_never_offset(self):
        c = self.serve()
        c.measurements(1, "unit01", "zone01", limit=10)
        qs = [q for fn, q in self.fake.calls if fn == "measurements"]
        self.assertNotIn("p_to", qs[0])
        self.assertTrue(all("offset" not in q for q in qs))
        tos = [q["p_to"] for q in qs[1:]]
        self.assertEqual(tos, sorted(tos, reverse=True))
        self.assertEqual(len(set(tos)), len(tos))

    def test_one_second_holding_a_whole_page_is_refused(self):
        c = self.serve()
        with self.assertRaisesRegex(lake.LakeError, "one measured_at .* holds 4 rows or more"):
            c.measurements(1, "UNIT01", "ZONE01", limit=4)     # four readings per cycle

    def test_the_default_page_is_well_under_the_limit(self):
        self.assertEqual(lake.MAX_LIMIT, 50000)
        self.assertLessEqual(lake.PAGE_SIZE, 10000)

    def test_a_value_keeps_its_text(self):
        c = self.serve()
        rows, _ = c.measurements(1, "UNIT01", "ZONE01")
        self.assertIn("26.50", [r["value"] for r in rows])
        self.assertIn(None, [r["value"] for r in rows])


class Lineage(Base):
    def medcea_data(self):
        spec = importlib.util.spec_from_file_location("medcea_data_for_test", MEDCEA_DATA)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_parity_with_medcea_data(self):
        md = self.medcea_data()
        rnd = random.Random(7)
        for n in range(6):
            rows = [{"snapshot_id": k, "digests": {"measurement": "%064x" % rnd.getrandbits(256)} if k % 3 else {}}
                    for k in rnd.sample(range(1, 50), n)]
            self.assertEqual(lake.lineage_chain(rows), md.lineage_chain(rows))
        self.assertEqual(lake.lineage_chain([{"snapshot_id": "1", "digests": {"measurement": ""}}]),
                         {1: hashlib.sha256(b"\n").hexdigest()})

    def test_the_fakes_lineage_verifies(self):
        c = self.serve()
        self.assertTrue(all(r["lineage_verified"] for r in c.snapshots()))


class Pin(Base):
    def test_refusals(self):
        c = self.serve()
        good = self.lineage(1)
        self.assertEqual(c.pin(1, good.upper())["snapshot_id"], 1)
        with self.assertRaisesRegex(lake.LakeError, "no snapshot 99 in the lake"):
            c.pin(99, good)
        with self.assertRaisesRegex(lake.LakeError, "not the same data"):
            c.pin(2, good)
        with self.assertRaisesRegex(lake.LakeError, "64 hex"):
            c.pin(1, good[:12])
        self.fake.tamper[("lineage", 1)] = "0" * 64
        with self.assertRaisesRegex(lake.LakeError, "does not recompute"):
            c.pin(1, "0" * 64)

    def test_22023_and_57014_are_passed_through(self):
        c = self.serve()
        with self.assertRaises(lake.LakeError) as cm:
            c.rpc("measurements", p_snapshot=99, p_unit="UNIT01", p_zone="ZONE01")
        self.assertEqual((str(cm.exception), cm.exception.code), ("no snapshot 99", "22023"))
        self.fake.error = ("measurements", 500, "57014", "canceling statement due to statement timeout")
        with self.assertRaises(lake.LakeError) as cm:
            c.measurements(1, "UNIT01", "ZONE01")
        self.assertEqual(cm.exception.code, "57014")
        self.assertIn("30 s statement timeout", str(cm.exception))

    def test_unknown_functions_and_parameters_are_refused_before_asking(self):
        c = self.serve()
        with self.assertRaisesRegex(lake.LakeError, "no lake function"):
            c.rpc("runs")
        with self.assertRaisesRegex(lake.LakeError, "no parameter p_offset"):
            c.rpc("measurements", p_offset=10)
        self.assertEqual(self.fake.calls, [])

    def test_an_unreachable_lake(self):
        c = lake.LakeClient("http://127.0.0.1:9", timeout=2)
        with self.assertRaisesRegex(lake.LakeError, "not reachable"):
            c.snapshots()


class Fetch(Base):
    def test_complete_and_verified(self):
        c = self.serve()
        header, rows, holds, pinned = dataset.fetch(c, 2, self.lineage(2), "UNIT01", "ZONE01", page_size=9)
        self.assertEqual([s["complete"] for s in header["lake"]["snapshots"]], [True, True])
        self.assertEqual([s["digest_verified"] for s in header["lake"]["snapshots"]], [True, True])
        self.assertEqual(header["rows"], len(rows))
        self.assertEqual(header["lake"]["lineage"], self.lineage(2))
        self.assertNotIn("holds", header)
        self.assertEqual(len(holds), 1)
        self.assertEqual(header["content_sha256"], dataset.content_sha256(rows))

    def test_snapshot_1_takes_only_its_rows(self):
        c = self.serve()
        header, rows, _, _ = dataset.fetch(c, 1, self.lineage(1), "UNIT01", "ZONE01")
        self.assertEqual({r["snapshot_id"] for r in rows}, {1})
        self.assertEqual([s["id"] for s in header["lake"]["snapshots"]], [1])

    def test_another_zone_makes_it_incomplete(self):
        c = self.serve(FakeLake(other_zone=5))
        header, rows, _, _ = dataset.fetch(c, 2, self.lineage(2), "UNIT01", "ZONE01")
        s1, s2 = header["lake"]["snapshots"]
        self.assertEqual((s1["complete"], s1["missing"], s1["digest_verified"]), (False, 5, None))
        self.assertTrue(s2["complete"])

    def test_more_rows_than_recorded_is_refused(self):
        c = self.serve()
        self.fake.tamper[(1, "measurement")] = N("3")
        with self.assertRaisesRegex(dataset.DatasetError, "records 3 readings but"):
            dataset.fetch(c, 1, self.lineage(1), "UNIT01", "ZONE01")

    def test_a_digest_that_does_not_recompute_is_refused(self):
        c = self.serve()
        bad = "f" * 64
        self.fake.tamper[(2, "measurement")] = bad
        with self.assertRaisesRegex(dataset.DatasetError, "snapshot 2's measurement digest does not recompute"):
            dataset.fetch(c, 2, self.lineage(2), "UNIT01", "ZONE01")

    def test_a_reading_inside_a_hold_is_refused(self):
        fake = FakeLake()
        fake.holds[0]["from_at"] = T0 + datetime.timedelta(seconds=30)
        c = self.serve(fake)
        with self.assertRaisesRegex(dataset.DatasetError, "inside the hold UNIT01/ZONE01"):
            dataset.fetch(c, 2, self.lineage(2), "UNIT01", "ZONE01")
        fake.holds[0].update(unit_code="unit01", zone_code=None)
        with self.assertRaisesRegex(dataset.DatasetError, "inside the hold unit01/\\*"):
            dataset.fetch(c, 2, self.lineage(2), "unit01", "zone01")

    def test_the_extract_recomputes_and_a_tampered_digest_is_refused(self):
        c = self.serve()
        pinned = c.pin(1, self.lineage(1))
        doc = extract.fetch(c, pinned)
        self.assertEqual(extract.verify_doc(doc)[-1], "catalogue: 1 rows, digest recomputes")
        self.assertEqual(doc["recipe_lines"][0]["setpoints"],
                         '{"co2": {"lower": 1000, "upper": 5000}, "air_temperature": {"lower": 20, "upper": 25.5}}')
        self.assertEqual(doc["recipes"][0], {"recipe_id": "2", "recipe_type": "FUNGI", "status": "approved"})
        self.fake.tamper[(1, "recipe_lines")] = "0" * 64
        pinned = c.pin(1, self.lineage(1))
        with self.assertRaisesRegex(extract.ExtractError, "recipe_lines digest does not recompute"):
            extract.fetch(c, pinned)


class Cli(Base):
    def fetch(self, out, *extra, snap=2):
        return self.cli("fetch", "--lake", self.url, "--snapshot", str(snap), "--expect-lineage", self.lineage(snap),
                        "--unit", "UNIT01", "--zone", "ZONE01", "--out", out, *extra)

    def test_refetch_is_byte_identical(self):
        self.serve()
        d = self.tmp()
        a, b = os.path.join(d, "a"), os.path.join(d, "b")
        rc, out, err = self.fetch(a)
        self.assertEqual(rc, 0, err)
        self.assertIn("complete, measurement digest recomputes", out)
        self.assertIn("snapshot-2-%s.yaml" % self.lineage(2)[:12], out)
        rc, _, err = self.fetch(b, "--page-size", "7")
        self.assertEqual(rc, 0, err)
        with open(os.path.join(a, "extract.yaml"), "rb") as f1, open(os.path.join(b, "extract.yaml"), "rb") as f2:
            self.assertEqual(f1.read(), f2.read())
        ha, ra = dataset.read(os.path.join(a, "dataset.jsonl"))
        hb, rb = dataset.read(os.path.join(b, "dataset.jsonl"))
        self.assertEqual(ra, rb)
        self.assertEqual(ha["content_sha256"], hb["content_sha256"])
        c = os.path.join(d, "c")
        self.assertEqual(self.fetch(c)[0], 0)
        with open(os.path.join(a, "dataset.jsonl"), "rb") as f1, open(os.path.join(c, "dataset.jsonl"), "rb") as f2:
            self.assertEqual(f1.read(), f2.read())
        with open(os.path.join(a, "fetch-log.json"), encoding="utf-8") as f:
            log = json.load(f)
        self.assertEqual(log["holds"][0]["unit_code"], "UNIT01")
        self.assertEqual(log["lake_url"], self.url)

    def test_verify_offline_and_a_changed_byte(self):
        self.serve()
        d = os.path.join(self.tmp(), "s")
        self.assertEqual(self.fetch(d)[0], 0)
        for f in ("dataset.jsonl", "extract.yaml"):
            rc, out, err = self.cli("verify", os.path.join(d, f))
            self.assertEqual(rc, 0, err)
        self.assertIn("holds: checked against fetch-log.json", self.cli("verify", os.path.join(d, "dataset.jsonl"))[1])
        p = os.path.join(d, "dataset.jsonl")
        with open(p, encoding="utf-8") as f:
            text = f.read()
        i = text.index('"26.50"')
        with open(p, "w", encoding="utf-8") as f:
            f.write(text[:i] + '"26.51"' + text[i + 7:])
        rc, _, err = self.cli("verify", p)
        self.assertEqual(rc, 2)
        self.assertIn("calib: ", err)
        self.assertIn("sha256", err)
        p = os.path.join(d, "extract.yaml")
        with open(p, encoding="utf-8") as f:
            text = f.read()
        with open(p, "w", encoding="utf-8") as f:
            f.write(text.replace("approved", "approvee"))
        rc, _, err = self.cli("verify", p)
        self.assertEqual(rc, 2)
        self.assertIn("recipes digest does not recompute", err)

    def test_a_hold_moved_in_the_fetch_log_is_caught_by_verify(self):
        self.serve()
        d = os.path.join(self.tmp(), "s")
        self.assertEqual(self.fetch(d)[0], 0)
        p = os.path.join(d, "fetch-log.json")
        with open(p, encoding="utf-8") as f:
            log = json.load(f)
        log["holds"][0]["from_at"] = "2026-11-14T00:00:00.000000Z"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(log, f)
        rc, _, err = self.cli("verify", os.path.join(d, "dataset.jsonl"))
        self.assertEqual(rc, 2)
        self.assertIn("inside the hold", err)

    def test_refusals(self):
        self.serve()
        d = self.tmp()
        env = os.environ.pop("MEDCEA_LAKE", None)
        self.addCleanup(lambda: env is not None and os.environ.__setitem__("MEDCEA_LAKE", env))
        rc, _, err = self.cli("snapshots")
        self.assertEqual(rc, 2)
        self.assertIn("calib: no lake URL", err)
        rc, _, err = self.cli("fetch", "--lake", self.url, "--snapshot", "99", "--expect-lineage", "a" * 64,
                              "--unit", "UNIT01", "--zone", "ZONE01", "--out", os.path.join(d, "x"))
        self.assertEqual((rc, err.strip()), (2, "calib: no snapshot 99 in the lake (snapshots lists them)"))
        rc, _, err = self.fetch(os.path.join(d, "y"), snap=2)
        self.assertEqual(rc, 0, err)
        rc, _, err = self.fetch(os.path.join(d, "y"))
        self.assertEqual(rc, 2)
        self.assertIn("already exists", err)
        rc, _, err = self.cli("fetch", "--lake", self.url, "--snapshot", "1", "--expect-lineage", "f" * 64,
                              "--unit", "UNIT01", "--zone", "ZONE01", "--out", os.path.join(d, "z"))
        self.assertEqual(rc, 2)
        self.assertIn("not the same data", err)
        self.assertFalse(os.path.exists(os.path.join(d, "z")))
        rc, _, err = self.cli("fetch", "--lake", self.url, "--snapshot", "1", "--expect-lineage", self.lineage(1),
                              "--unit", "-x", "--zone", "ZONE01", "--out", os.path.join(d, "w"))
        self.assertEqual(rc, 2)
        rc, _, err = self.cli("fetch", "--lake", self.url, "--snapshot", "1", "--expect-lineage", self.lineage(1),
                              "--unit", "UNIT01", "--zone", "ZONE01", "--out", os.path.join(d, "v"),
                              "--page-size", "50001")
        self.assertEqual(rc, 2)
        self.assertIn("--page-size", err)
        rc, _, err = self.cli("verify", os.path.join(d, "nothing.yaml"))
        self.assertEqual(rc, 2)

    def test_snapshots_lists_lineage_and_verified(self):
        self.serve()
        rc, out, err = self.cli("snapshots", "--lake", self.url)
        self.assertEqual(rc, 0, err)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("id"))
        self.assertIn(self.lineage(1), lines[1])
        self.assertTrue(lines[2].rstrip().endswith("yes"))


if __name__ == "__main__":
    unittest.main()
