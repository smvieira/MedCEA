"""research/calib/pgtext.py: PostgreSQL's text forms, so the lake's digests recompute here.

- record_out quoting (empty, whitespace, '"', '\\', '(', ')', ','; '"' and '\\' doubled;
  NULL an empty unquoted field), timestamptz (UTC, fraction without trailing zeros, +00),
  numeric (its own text, never a float), jsonb (keys shorter-first then bytewise, ", " and
  ": ", escape_json), and the small-set and per-hour measurement digests.
- Known answers captured read-only from the live lake (snapshot 1, 20 Nov 2026) are
  pinned inline where they are short (the recipes set's digest).
- tests/fixtures/research/*.json (research Phase 3 commit D captured snapshot1.json) are
  recomputed in full: each file is a JSON object

      {"snapshot_id": 1, "lineage": "<hex>",
       "digests": {"<set>": "<hex>", ...},                 lake.snapshot.digests as recorded
       "sets": {"<set>": [<lake-api rows, verbatim>], ...},  recipes, recipe_lines, catalogue, units, zones
       "measurement_hour": {"hour": "YYYY-MM-DDTHH:00:00Z", "line": "<hour>|<n>|<hex>",
                            "rows": [<lake-api measurement rows of that ingested_at hour, verbatim>]}}

  read with pgtext.loads_raw, so numbers keep their text.

Offline, standard library + PyYAML. Run:
    python3 -m unittest tests.test_research_calib_pgtext
"""
import glob
import hashlib
import os
import sys
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from research.calib import pgtext  # noqa: E402
from research.calib.lake import SMALL_SETS, row_text  # noqa: E402

FIXTURES = sorted(glob.glob(os.path.join(REPO, "tests", "fixtures", "research", "*.json")))


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class RecordOut(unittest.TestCase):
    def test_fields(self):
        cases = {None: "", "": '""', "UNIT01": "UNIT01", "RH%": "RH%", "26.58": "26.58", "a b": '"a b"',
                 'a"b': '"a""b"', "a\\b": '"a\\\\b"', "(x": '"(x"', "x)": '"x)"', "a,b": '"a,b"',
                 "a\tb": '"a\tb"', "a\nb": '"a\nb"', "a\rb": '"a\rb"', "a\vb": '"a\vb"', "a\fb": '"a\fb"',
                 "é": "é", "{}": "{}", "[1]": "[1]", "x:y": "x:y", "'q'": "'q'"}
        for given, want in cases.items():
            self.assertEqual(pgtext.record_field(given), want, repr(given))

    def test_record(self):
        self.assertEqual(pgtext.record_out(["x", None, "", "a b"]), '(x,,"","a b")')
        self.assertEqual(pgtext.record_out([]), "()")

    def test_a_jsonb_field_is_quoted_with_its_quotes_doubled(self):
        j = pgtext.jsonb_out(pgtext.loads_raw('{"lower": 20, "upper": 25}'))
        self.assertEqual(pgtext.record_out(["2", j]), '(2,"{""lower"": 20, ""upper"": 25}")')


class Timestamps(unittest.TestCase):
    def test_timestamptz_out(self):
        cases = {"2026-11-14T19:52:44+00:00": "2026-11-14 19:52:44+00",
                 "2026-11-14T19:52:44Z": "2026-11-14 19:52:44+00",
                 "2026-11-14 19:52:44+00": "2026-11-14 19:52:44+00",
                 "2026-11-14T19:52:45.362301+00:00": "2026-11-14 19:52:45.362301+00",
                 "2026-11-14T19:52:45.1200+00:00": "2026-11-14 19:52:45.12+00",
                 "2026-11-14T19:52:45.000000Z": "2026-11-14 19:52:45+00",
                 "2026-11-14T20:52:45.5+01:00": "2026-11-14 19:52:45.5+00",
                 "2026-11-14T19:52:45.123456000Z": "2026-11-14 19:52:45.123456+00",
                 "2026-11-15T00:30:00-01:00": "2026-11-15 01:30:00+00"}
        for given, want in cases.items():
            self.assertEqual(pgtext.timestamptz_out(given), want, given)
        self.assertIsNone(pgtext.timestamptz_out(None))

    def test_norm_ts_sorts_as_time(self):
        self.assertEqual(pgtext.norm_ts("2026-11-14T19:52:44+00"), "2026-11-14T19:52:44.000000Z")
        self.assertEqual(pgtext.norm_ts("2026-11-14 20:52:44.5+01"), "2026-11-14T19:52:44.500000Z")
        a, b = pgtext.norm_ts("2026-11-14T19:52:44.9Z"), pgtext.norm_ts("2026-11-14T19:52:45Z")
        self.assertLess(a, b)

    def test_more_than_microseconds_is_refused(self):
        with self.assertRaises(ValueError):
            pgtext.norm_ts("2026-11-14T19:52:45.1234567Z")

    def test_hour(self):
        self.assertEqual(pgtext.hour_of("2026-11-14T19:59:59.999999Z"), "2026-11-14T19:00:00Z")
        self.assertEqual(pgtext.hour_of("2026-11-14T20:59:59+01:00"), "2026-11-14T19:00:00Z")


class Jsonb(unittest.TestCase):
    def test_keys_shorter_first_then_bytewise(self):
        doc = pgtext.loads_raw('{"air_temperature": {"upper": 25, "lower": 20}, "co2": {"lower": 1000}, '
                               '"air_humidity": {"lower": 90}}')
        self.assertEqual(pgtext.jsonb_out(doc), '{"co2": {"lower": 1000}, "air_humidity": {"lower": 90}, '
                                                '"air_temperature": {"lower": 20, "upper": 25}}')

    def test_numbers_keep_their_text(self):
        v = pgtext.loads_raw('{"a": 1.50, "b": 10, "c": -0.0, "d": 1e3}')
        self.assertIsInstance(v["a"], pgtext.Num)
        self.assertEqual(pgtext.jsonb_out(v), '{"a": 1.50, "b": 10, "c": -0.0, "d": 1e3}')

    def test_scalars_lists_and_escapes(self):
        v = pgtext.loads_raw('[true, false, null, "x\\"y\\\\z\\n\\t\\b\\f\\r\\u0001é", [], {}]')
        self.assertEqual(pgtext.jsonb_out(v), '[true, false, null, "x\\"y\\\\z\\n\\t\\b\\f\\r\\u0001é", [], {}]')

    def test_a_float_is_refused(self):
        with self.assertRaises(ValueError):
            pgtext.jsonb_out({"a": 1.5})

    def test_a_json_constant_is_refused(self):
        with self.assertRaises(ValueError):
            pgtext.loads_raw('[NaN]')


class FieldText(unittest.TestCase):
    def test_types(self):
        n = pgtext.loads_raw("[21.50]")[0]
        self.assertEqual(pgtext.field_text(n, "numeric"), "21.50")
        self.assertEqual(pgtext.field_text("FUNGI", "text"), "FUNGI")
        self.assertEqual(pgtext.field_text(True, "boolean"), "t")
        self.assertEqual(pgtext.field_text("2026-11-14T19:52:44+00:00", "timestamptz"), "2026-11-14 19:52:44+00")
        self.assertIsNone(pgtext.field_text(None, "jsonb"))

    def test_a_wrong_type_is_refused(self):
        for value, t in (("21.5", "numeric"), (pgtext.Num("1"), "text"), (True, "numeric"), (1.5, "numeric"),
                         ("t", "boolean"), ("x", "interval")):
            with self.assertRaises(ValueError, msg=(value, t)):
                pgtext.field_text(value, t)


class Digests(unittest.TestCase):
    def test_a_small_set(self):
        self.assertEqual(pgtext.set_digest([]), sha(""))
        self.assertEqual(pgtext.set_digest(["(b)", "(a)"]), sha("(a)\n(b)"))
        # bytewise, as COLLATE "C": 'Z' (0x5a) before 'a' (0x61), 'é' (0xc3 0xa9) after 'z'
        self.assertEqual(pgtext.set_digest(["(é)", "(a)", "(Z)"]), sha("(Z)\n(a)\n(é)"))

    def test_the_live_recipes_digest(self):
        """Captured read-only from lake-api, snapshot 1 (20 Nov 2026): lake_api.recipes(1)
        answered one row, recipe 2, FUNGI, approved; lake.snapshot.digests->>'recipes'."""
        row = pgtext.loads_raw('[{"snapshot_id":1,"recipe_id":2,"recipe_type":"FUNGI","status":"approved"}]')[0]
        self.assertEqual(row_text("recipes", row), "(2,FUNGI,approved)")
        self.assertEqual(pgtext.set_digest([row_text("recipes", row)]),
                         "e2a913ba017988ac3bafe55a04a6695e5e98dbd30cf528f2b56049f1bd59b102")

    def test_measurements_per_hour(self):
        r1 = {"ingested_at": "2026-11-14T19:52:45.362301Z", "measured_at": "2026-11-14T19:52:44Z",
              "unit_code": "UNIT01", "zone_code": "ZONE01", "tag": "air_temperature", "sensor": "sht45_1",
              "value": "26.58", "uom": "C"}
        r2 = dict(r1, ingested_at="2026-11-14T20:00:00Z", measured_at="2026-11-14T19:59:59Z", uom="RH%",
                  tag="air_humidity", value="54.2")
        r3 = dict(r1, value=None, ingested_at="2026-11-14T19:00:00.5Z")
        t1 = pgtext.measurement_text(r1)
        self.assertEqual(t1, '("2026-11-14 19:52:45.362301+00","2026-11-14 19:52:44+00",UNIT01,ZONE01,'
                             'air_temperature,sht45_1,26.58,C)')
        t3 = pgtext.measurement_text(r3)
        self.assertIn(",sht45_1,,C)", t3)
        rows = [(r["ingested_at"], pgtext.measurement_text(r)) for r in (r2, r1, r3)]
        lines = pgtext.measurement_lines(rows)
        self.assertEqual([h for h, _ in lines], ["2026-11-14T19:00:00Z", "2026-11-14T20:00:00Z"])
        l19 = "2026-11-14T19:00:00Z|2|" + sha("\n".join(sorted([t1, t3], key=lambda t: t.encode())))
        l20 = "2026-11-14T20:00:00Z|1|" + sha(pgtext.measurement_text(r2))
        self.assertEqual([l for _, l in lines], [l19, l20])
        self.assertEqual(pgtext.measurement_digest(rows), sha(l19 + "\n" + l20))
        self.assertEqual(pgtext.measurement_digest([]), sha(""))


class LiveFixtures(unittest.TestCase):
    """tests/fixtures/research/snapshot1.json: captured read-only as postgres in
    research-postgresql-0 on 20 Nov 2026 (research Phase 3 commit D, R16). The small sets
    are lake_api.<set>(1) through json_agg; the hour is every lake.measurement row of
    snapshot 1 ingested in 2026-11-14T19:00Z, its line computed in SQL by _set_digest's
    own per-hour rule; the same line recomputes from lake-api's rows of that hour."""

    def test_snapshot_1_is_captured(self):
        names = [os.path.basename(p) for p in FIXTURES]
        self.assertIn("snapshot1.json", names)
        fx = dict(self.load())[os.path.join(REPO, "tests", "fixtures", "research", "snapshot1.json")]
        self.assertEqual(sorted(fx["sets"]), sorted(SMALL_SETS))
        self.assertEqual(fx["lineage"], "096015bc225c7dbcc342b0a5f2027bbdaf2c4f94f06282a8335ae9147a74752f")
        self.assertEqual(fx["digests"]["measurement"],
                         "2729928d95b4bb4fd40b07bb951e442b4da7d970a4ae192e1e50bb4a72f4b4b1")
        self.assertEqual(fx["measurement_hour"]["line"],
                         "2026-11-14T19:00:00Z|605|d36954722392f7a6106b454db5159d348e1555d38b8d746e0e2c15be61bd05ba")

    def load(self):
        out = []
        for p in FIXTURES:
            with open(p, encoding="utf-8") as f:
                out.append((p, pgtext.loads_raw(f.read())))
        return out

    def test_the_small_sets_recompute(self):
        for path, fx in self.load():
            for fn, rows in (fx.get("sets") or {}).items():
                self.assertIn(fn, SMALL_SETS, path)
                got = pgtext.set_digest([row_text(fn, r) for r in rows])
                self.assertEqual(got, fx["digests"][fn], "%s: %s" % (os.path.basename(path), fn))

    def test_the_measurement_hour_recomputes(self):
        for path, fx in self.load():
            mh = fx.get("measurement_hour")
            if not mh:
                continue
            rows = [{k: (str(v) if isinstance(v, pgtext.Num) else v) for k, v in r.items()} for r in mh["rows"]]
            for r in rows:
                self.assertEqual(pgtext.hour_of(r["ingested_at"]), mh["hour"], path)
            texts = [pgtext.measurement_text(r) for r in rows]
            self.assertEqual(pgtext.hour_line(mh["hour"], texts), mh["line"], os.path.basename(path))


if __name__ == "__main__":
    unittest.main()
