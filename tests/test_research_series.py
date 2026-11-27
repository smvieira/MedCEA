#!/usr/bin/env python3
"""research/harness/series.py: a run's chamber time series (research Phase 4e, design rs4e 2.3), offline.

- The interval: off for None/0, refused for a bad value, coarsened to a multiple of 10 s so a run never
  has more than max_points samples (a 9000 h scenario included), and the recorder never keeps more.
- The runner: a run's result is the same bytes with and without a recorder (also when recording
  raises: the series stops and says why); every column has one value per point; the samples are at
  the first tick at or after each multiple of the interval; every relay and command switch of the run
  (trace=True) is in the changes, so decimating the samples hides none; the change list is capped.
- The file: canonical JSON, gzip with mtime 0, written through a .tmp and renamed; the same run gives
  the same bytes; read() gives the document back.

Run: cd <repo> && python3 -m unittest tests.test_research_series
"""
import copy
import gzip
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

import yaml  # noqa: E402

from research.harness import algorithms_loader, campaign, runner, series  # noqa: E402
from research.twin_plant.chamber import RELAYS  # noqa: E402

SCEN_DIR = os.path.join(REPO, "research", "harness", "scenarios")
_LOADED = []


def loaded():
    if not _LOADED:
        _LOADED.append(algorithms_loader.load(REPO, allow_dirty=True))
    return _LOADED[0]


def smoke(**changes):
    with open(os.path.join(SCEN_DIR, "smoke_air_temperature.yaml"), encoding="utf-8") as f:
        sc = yaml.safe_load(f)
    sc["metrics_from_h"] = 0
    sc.update(changes)
    return sc


def run(sc, code="IF_THEN_ELSE", rec=None, trace=False, jitter=0.0, offset=0.0, params=None):
    return runner.run_scenario(copy.deepcopy(sc), {"code": code, "params": params or {}}, 1, offset, jitter,
                               loaded=loaded(), trace=trace, series=rec)


class Interval(unittest.TestCase):
    def test_requested(self):
        self.assertIsNone(series.requested_every(None))
        self.assertIsNone(series.requested_every(0))
        self.assertEqual(series.requested_every("60"), 60.0)
        for bad in (-1, "x", True, float("nan"), float("inf")):
            with self.assertRaises(series.SeriesError):
                series.requested_every(bad)
        with self.assertRaises(series.SeriesError):
            series.SeriesRecorder(0)

    def test_coarsened_to_the_point_cap(self):
        self.assertEqual(series.effective_every(60, 3600), 60.0)
        h9000 = 9000 * 3600.0
        every = series.effective_every(60, h9000)
        self.assertEqual(every % 10, 0)
        self.assertEqual(every, 6480.0)
        # the samples are at multiples of every up to the last tick (10 s before the end): max_points of them
        self.assertEqual(int((h9000 - runner.TICK_S) // every) + 1, series.MAX_POINTS)
        self.assertEqual(series.effective_every(600, h9000), 6480.0)
        self.assertEqual(series.effective_every(10000, h9000), 10000.0)

    def test_the_recorder_never_keeps_more_than_max_points(self):
        rec = series.SeriesRecorder(1, max_points=5)
        rec.start(3600, 0, [("air_temperature", 18, 20)], RELAYS)
        self.assertEqual(rec.every, 720.0)                 # coarsened: 3600 / 5
        rec.every = 1.0                                     # forced finer: the hard cap still holds
        for t in range(100):
            rec.tick(t, {}, {}, False, 0)
            if rec.due(t):
                rec.sample(t, {}, {}, {}, False, 0, 0, {}, {})
        self.assertEqual(rec.points(), 5)
        self.assertEqual(rec.document()["columns"]["t"], [0.0, 1.0, 2.0, 3.0, 4.0])


class Runner(unittest.TestCase):
    def test_the_result_is_the_same_bytes_with_and_without(self):
        sc = smoke(duration_h=0.3)
        for code in ("IF_THEN_ELSE", "PID", "Q_LEARNING"):
            rec = series.SeriesRecorder(60)
            a, b = run(sc, code), run(sc, code, rec=rec)
            self.assertEqual(campaign.canonical(a), campaign.canonical(b), code)
            self.assertNotIn("trace", b)
            self.assertEqual(rec.points(), 18, code)        # 0, 60, ... 1020 s

    def test_columns_and_header(self):
        sc = smoke(duration_h=0.25)
        rec = series.SeriesRecorder(60, header={"run": 3, "scenario": sc["name"]})
        r = run(sc, rec=rec)
        d = rec.document()
        h = d["header"]
        self.assertEqual((h["schema"], h["run"], h["every_s"], h["max_points"], h["duration_s"]), (1, 3, 60.0, 5000, 900.0))
        self.assertEqual(set(h["loops"]), set(r["loops"]))
        self.assertEqual(h["band"], {k: [v["lower"], v["upper"]] for k, v in r["loops"].items()})
        self.assertEqual(h["relays"], list(RELAYS))
        cols = d["columns"]
        n = rec.points()
        self.assertEqual(n, 15)
        for k, v in cols.items():
            if k == "loops":
                self.assertEqual(set(v), set(h["loops"]))
                for lc in v.values():
                    self.assertEqual({x: len(y) for x, y in lc.items()}, {"value": n, "state": n, "cmd": n})
                    self.assertTrue(set(lc["state"]) <= {None, 0, 1, 2, 3})
                    self.assertTrue(set(lc["cmd"]) <= {0, 1, 2, 3})
            else:
                self.assertEqual(len(v), n, k)
        self.assertEqual(cols["t"], [60.0 * i for i in range(n)])
        self.assertTrue(all(0 <= m < (1 << len(RELAYS)) for m in cols["relays"]))
        self.assertEqual(cols["energy_wh"], sorted(cols["energy_wh"]))
        # the last cumulative energy is at most the run's total (sampled before the end)
        self.assertLessEqual(cols["energy_wh"][-1], r["energy_total_wh"] + 1e-6)

    def test_samples_take_the_first_tick_at_or_after_each_mark(self):
        rec = series.SeriesRecorder(60)
        run(smoke(duration_h=0.2), rec=rec, jitter=3.0)
        t = rec.document()["columns"]["t"]
        self.assertEqual(t[0], 0.0)
        for i, x in enumerate(t):
            self.assertGreaterEqual(x, 60.0 * i - 1e-6)
            self.assertLess(x, 60.0 * i + 14)                # a tick is 10 s, +/- the jitter

    def test_no_switch_is_hidden_by_the_decimation(self):
        sc = smoke(duration_h=0.5, disturbances=[{"at_h": 0.1, "kind": "door_open", "duration_min": 5}])
        rec = series.SeriesRecorder(600)                     # coarse samples: three of them
        tr = run(sc, rec=rec, trace=True)["trace"]
        d = rec.document()
        self.assertEqual(rec.points(), 3)
        relay_changes = [(c[0], RELAYS[c[2]], c[3]) for c in d["changes"] if c[1] == "relay"]
        want, last = [], {r: 0 for r in RELAYS}
        for e in tr:
            for r in RELAYS:
                v = 1 if e["relays"][r] else 0
                if v != last[r]:
                    want.append((round(e["t"], 3), r, v))
                    last[r] = v
        self.assertTrue(want)
        self.assertEqual(relay_changes, want)
        cmd_changes = [(c[0], d["header"]["loops"][c[2]], c[3]) for c in d["changes"] if c[1] == "cmd"]
        want, last = [], {}
        codes = {None: 0, "UP": 1, "DOWN": 2, "OFF": 3}
        for e in tr:
            for k in d["header"]["loops"]:
                v = codes[(e["loops"].get(k) or {}).get("cmd")]
                if v != last.get(k, 0):
                    want.append((round(e["t"], 3), k, v))
                    last[k] = v
        self.assertEqual(cmd_changes, want)
        self.assertEqual(d["changes_dropped"], 0)

    def test_disturbance_and_room_columns(self):
        sc = smoke(duration_h=0.3, disturbances=[{"at_h": 0.1, "kind": "extra_heat", "watts": 50, "duration_min": 3},
                                                 {"at_h": 0.2, "kind": "ambient", "temperature": 25}])
        rec = series.SeriesRecorder(60)
        run(sc, rec=rec)
        c = rec.document()["columns"]
        by_t = dict(zip(c["t"], zip(c["disturbance"], c["extra_heat_w"], c["ambient_temperature"])))
        self.assertEqual(by_t[0.0], (0, 0.0, 20.0))
        self.assertEqual(by_t[360.0], (2, 50.0, 20.0))
        self.assertEqual(by_t[600.0], (0, 0.0, 20.0))
        self.assertEqual(by_t[780.0], (0, 0.0, 25.0))

    def test_the_change_list_is_capped(self):
        rec = series.SeriesRecorder(60, max_changes=3)
        r = run(smoke(duration_h=0.3), rec=rec)
        d = rec.document()
        self.assertEqual(len(d["changes"]), 3)
        self.assertGreater(d["changes_dropped"], 0)
        self.assertEqual(campaign.canonical(r), campaign.canonical(run(smoke(duration_h=0.3))))

    def test_a_failing_recorder_never_changes_the_run(self):
        class Broken(series.SeriesRecorder):
            def sample(self, *a, **k):
                if self.points() >= 2:
                    raise RuntimeError("boom")
                return super().sample(*a, **k)
        rec = Broken(60)
        sc = smoke(duration_h=0.2)
        self.assertEqual(campaign.canonical(run(sc, rec=rec)), campaign.canonical(run(sc)))
        d = rec.document()
        self.assertEqual(rec.points(), 2)
        self.assertEqual(d["error"], {"reason": "RuntimeError: boom", "at_s": 120.0})

    def test_a_long_run_is_bounded(self):
        # 2 h at a 1-s request with a 20-point cap: the interval is coarsened to 360 s, 20 points
        rec = series.SeriesRecorder(1, max_points=20)
        run(smoke(duration_h=2), rec=rec)
        self.assertEqual(rec.every, 360.0)
        self.assertEqual(rec.points(), 20)


class File(unittest.TestCase):
    def test_bytes_and_round_trip(self):
        sc = smoke(duration_h=0.2)
        a, b = series.SeriesRecorder(60, header={"run": 0}), series.SeriesRecorder(60, header={"run": 0})
        run(sc, "PID", rec=a, params={"kp": 0.5})
        run(sc, "PID", rec=b, params={"kp": 0.5})
        self.assertEqual(a.to_bytes(), b.to_bytes())
        data = a.to_bytes()
        self.assertEqual(data[:2], b"\x1f\x8b")
        self.assertEqual(data[4:8], b"\x00\x00\x00\x00")          # gzip mtime 0
        raw = gzip.decompress(data)
        self.assertEqual(raw.decode(), series.canonical(a.document()))
        d = tempfile.mkdtemp(prefix="rs-series-")
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "series", series.file_name(7))
        sha = a.write(path)
        self.assertEqual(os.listdir(os.path.dirname(path)), ["7.json.gz"])   # no .tmp left
        with open(path, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sha)
        self.assertEqual(series.read(path), json.loads(raw))
        self.assertEqual(series.files_digest(["a", "b"]), hashlib.sha256(b"a\nb\n").hexdigest())

    def test_size_per_simulated_hour(self):
        rec = series.SeriesRecorder(60)
        run(smoke(duration_h=1), rec=rec)
        self.assertLess(len(rec.to_bytes()), 12000)              # design: about 2 KB gz per simulated hour


if __name__ == "__main__":
    unittest.main()
