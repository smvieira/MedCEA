"""apps/research-agents/campaigns.py (research Phase 4e, design rs4e 3.1): a session's campaigns from its trace and
their files on a temporary runs volume: the trace binds a cid to its session, results.jsonl is served only when its
sha256 is the trace's result_digest (409 otherwise), files the trace names that are gone answer 410, a running
campaign answers its state, results over the bound 413, runs paged, a run's series decimated (min and max per
bucket, switches kept whole) and 404 without series. Offline."""
import gzip
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
import campaigns  # noqa: E402
import mcp_sim  # noqa: E402

CID = "c" + "1" * 20
OTHER = "c" + "2" * 20
with open(os.path.join(ROOT, "tests", "fixtures", "research", "e58_campaign.json")) as _f:
    E58 = json.load(_f)
PARAMS = mcp_sim._load_params(ROOT)


def defaults_of(code):
    return PARAMS.defaults(code) if code in PARAMS.PARAMS else {}


def ev(i, event, payload, at="2026-11-27T10:00:%02dZ"):
    return {"event_id": i, "at": at % (i % 60), "actor": "mcp-sim", "event": event, "payload": payload}


def body_of(rows):
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()


def trace(digest, cid=CID, gate=True, finished=True, state="done"):
    evs = [ev(1, "session_minted", {"profile": "compare_controllers"})]
    if gate:
        evs += [ev(2, "gate_pending", {"gid": cid, "estimate_h": 3.0, "cap_h": 3.75, "runs": 36, "spec_sha256": "a" * 64}),
                ev(3, "gate_decided", {"gid": cid, "decision": "approve", "approved_cap_h": 3.0, "by_username": "bio"})]
    evs.append(ev(4, "sim_started", {"cid": cid, "spec_sha256": "a" * 64, "estimate_h": 3.0, "cap_h": 3.0}))
    if finished:
        evs.append(ev(5, "sim_finished", {"cid": cid, "state": state, "cpu_hours": 0.1, "result_digest": digest,
                                          "cap_h": 3.0}))
    return evs


def series_doc(n=5000, loops=("air_temperature",)):
    t = [i * 60.0 for i in range(n)]
    cols = {"t": t, "air_temperature": [20.0 + (i % 100) / 10 for i in range(n)], "relays": [i % 2 for i in range(n)],
            "light": [1] * n, "energy_wh": [i * 0.1 for i in range(n)],
            "loops": {k: {"value": [None if i == 7 else 21.0 for i in range(n)], "state": [0] * n, "cmd": [0] * n}
                      for k in loops}}
    cols["air_temperature"][n // 2] = 99.0        # one spike: min/max decimation must keep it
    return {"header": {"schema": 1, "every_s": 60.0, "loops": list(loops), "band": {"air_temperature": [20, 24]}},
            "columns": cols, "changes": [[t[i], "relay", 0, i % 2] for i in range(1, min(n, 400))], "changes_dropped": 0}


class Tree:
    def __init__(self, rows, series=True, n_series=None):
        self.root = tempfile.mkdtemp()
        self.dir = os.path.join(self.root, "campaigns", CID)
        os.makedirs(os.path.join(self.dir, "series"))
        self.body = body_of(rows)
        self.digest = hashlib.sha256(self.body).hexdigest()
        with open(os.path.join(self.dir, "results.jsonl"), "wb") as f:
            f.write(self.body)
        man = {"runs": len(rows), "result_digest": self.digest, "spec_digest": "a" * 64}
        if series:
            files = ["series/%d.json.gz" % i for i in range(len(rows) if n_series is None else n_series)]
            man["series"] = {"every_s": 60.0, "max_points": 5000, "files": files, "digest": "d" * 64}
            data = gzip.compress(json.dumps(series_doc()).encode(), mtime=0)
            for rel in files[:2]:
                with open(os.path.join(self.dir, rel), "wb") as f:
                    f.write(data)
        with open(os.path.join(self.dir, "manifest.json"), "w") as f:
            json.dump(man, f)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class TraceBinding(unittest.TestCase):
    def test_the_campaigns_of_a_trace(self):
        cs = campaigns.campaigns_of(trace("f" * 64))
        self.assertEqual([c["cid"] for c in cs], [CID])
        c = cs[0]
        self.assertEqual((c["state"], c["cpu_hours"], c["result_digest"], c["spec_sha256"]), ("done", 0.1, "f" * 64, "a" * 64))
        self.assertEqual(c["gate"], {"gid": CID, "estimate_h": 3.0, "cap_h": 3.75, "runs": 36, "state": "approved",
                                     "decided_by": "bio", "approved_cap_h": 3.0})
        self.assertEqual((c["started_at"], c["finished_at"]), ("2026-11-27T10:00:04Z", "2026-11-27T10:00:05Z"))

    def test_states(self):
        self.assertEqual(campaigns.campaigns_of(trace(None, finished=False))[0]["state"], "running")
        waiting = [e for e in trace(None, finished=False) if e["event"] not in ("gate_decided", "sim_started")]
        self.assertEqual(campaigns.campaigns_of(waiting)[0]["state"], "waiting")
        denied = [e for e in trace(None, finished=False) if e["event"] != "sim_started"]
        denied[2]["payload"]["decision"] = "deny"
        self.assertEqual(campaigns.campaigns_of(denied)[0]["state"], "denied")
        self.assertEqual(campaigns.campaigns_of(trace(None, state="failed"))[0]["state"], "failed")

    def test_a_cid_the_trace_does_not_name(self):
        self.assertIsNone(campaigns.campaign_of(trace("f" * 64), OTHER))
        self.assertIsNone(campaigns.campaign_of(trace("f" * 64), "../c" + "1" * 20))
        # a sim_finished alone (another session's cid written into this trace) binds nothing
        lone = [ev(1, "sim_finished", {"cid": OTHER, "state": "done", "result_digest": "f" * 64})]
        self.assertIsNone(campaigns.campaign_of(lone, OTHER))

    def test_two_writers_of_sim_finished(self):
        evs = trace("f" * 64) + [dict(ev(6, "sim_finished", {"cid": CID, "state": "done", "cpu_hours": 0.2,
                                                               "result_digest": "f" * 64}), actor="orchestrator")]
        self.assertEqual(campaigns.campaign_of(evs, CID)["cpu_hours"], 0.2)


class Files(unittest.TestCase):
    def setUp(self):
        self.t = Tree(E58["rows"])
        self.entry = campaigns.campaign_of(trace(self.t.digest), CID)

    def tearDown(self):
        self.t.close()

    def read(self, q=None, entry=None):
        return campaigns.read_campaign(self.t.root, entry or self.entry, q or {}, mcp_sim.summarise_settings,
                                       mcp_sim.summarise_row, defaults_of)

    def test_the_campaign(self):
        st, r = self.read({"limit": ["10"]})
        self.assertEqual(st, 200)
        self.assertEqual((r["cid"], r["state"], r["manifest"]["result_digest"]), (CID, "done", self.t.digest))
        want = mcp_sim.summarise_settings(E58["rows"], defaults_of, None, max_rows=campaigns.SETTINGS_MAX)
        self.assertEqual(r["by_setting"], want)
        self.assertEqual(r["by_setting"]["count"]["shown"], r["by_setting"]["count"]["total"])   # not fit to an agent
        self.assertEqual((r["runs"]["offset"], r["runs"]["total"], len(r["runs"]["rows"])), (0, 36, 10))
        self.assertEqual(r["runs"]["rows"][0], mcp_sim.summarise_row(E58["rows"][0]))
        self.assertEqual(r["series"], {"every_s": 60.0, "runs": 36})

    def test_paging_and_sort(self):
        st, r = self.read({"offset": ["30"], "limit": ["50"]})
        self.assertEqual((st, len(r["runs"]["rows"])), (200, 6))
        self.assertEqual(r["runs"]["rows"][0], mcp_sim.summarise_row(E58["rows"][30]))
        st, r = self.read({"sort": ["energy_wh"]})
        self.assertEqual(r["by_setting"]["order"], "by energy_wh, best first")
        self.assertEqual(self.read({"sort": ["nonsense"]})[0], 400)
        self.assertEqual(self.read({"limit": ["0"]})[0], 400)
        self.assertEqual(self.read({"limit": ["201"]})[0], 400)
        self.assertEqual(self.read({"offset": ["-1"]})[0], 400)

    def test_a_result_that_is_not_the_traces(self):
        with open(os.path.join(self.t.dir, "results.jsonl"), "ab") as f:
            f.write(b'{"scenario": "forged"}\n')
        self.assertEqual(self.read(), (409, {"error": "results do not match the trace"}))
        self.assertEqual(campaigns.read_run(self.t.root, self.entry, "0")[0], 409)
        self.assertEqual(campaigns.read_series(self.t.root, self.entry, "0", {})[0], 409)

    def test_gone(self):
        shutil.rmtree(self.t.dir)
        st, r = self.read()
        self.assertEqual((st, r["state"], r["result_digest"]), (410, "gone", self.t.digest))

    def test_running_waiting_and_denied(self):
        e = campaigns.campaign_of(trace(None, finished=False), CID)
        self.assertEqual(self.read(entry=e), (200, {"state": "running", "cid": CID}))
        waiting = campaigns.campaign_of([x for x in trace(None, finished=False)
                                         if x["event"] not in ("gate_decided", "sim_started")], CID)
        self.assertEqual(self.read(entry=waiting)[1]["state"], "waiting")
        self.assertEqual(campaigns.read_run(self.t.root, e, "0")[0], 409)

    def test_an_approved_campaign_not_started_is_approved_not_running(self):
        """Review of commit B: a decided gate whose simulation never started (the agent stopped polling) reads as the
        list route reads it, never "The campaign is still running"."""
        evs = [x for x in trace(None, finished=False) if x["event"] != "sim_started"]
        e = campaigns.campaign_of(evs, CID)
        self.assertEqual(e["state"], "approved")
        self.assertEqual(self.read(entry=e), (200, {"state": "approved", "cid": CID}))
        self.assertEqual(campaigns.campaigns_of(evs)[0]["state"], self.read(entry=e)[1]["state"])

    def test_a_failed_campaign_without_a_result(self):
        e = campaigns.campaign_of(trace(None, state="failed"), CID)
        st, r = self.read(entry=e)
        self.assertEqual((st, r["state"]), (200, "failed"))

    def test_too_large(self):
        old = campaigns.RESULTS_MAX
        campaigns.RESULTS_MAX = 100
        try:
            self.assertEqual(self.read()[0], 413)
        finally:
            campaigns.RESULTS_MAX = old

    def test_a_manifest_of_other_results_is_not_shown(self):
        with open(os.path.join(self.t.dir, "manifest.json"), "w") as f:
            json.dump({"result_digest": "0" * 64, "series": {"files": []}}, f)
        st, r = self.read()
        self.assertEqual((st, r["manifest"], r["series"]), (200, None, None))

    def test_a_run(self):
        self.assertEqual(campaigns.read_run(self.t.root, self.entry, "35"), (200, E58["rows"][35]))
        for n in ("36", "-1", "x", "../0", ""):
            self.assertEqual(campaigns.read_run(self.t.root, self.entry, n)[0], 404, n)


class Series(unittest.TestCase):
    def setUp(self):
        self.t = Tree(E58["rows"])
        self.entry = campaigns.campaign_of(trace(self.t.digest), CID)

    def tearDown(self):
        self.t.close()

    def test_decimated_to_the_bound(self):
        st, d = campaigns.read_series(self.t.root, self.entry, "0", {"points": ["2000"]})
        self.assertEqual(st, 200)
        c = d["columns"]
        self.assertEqual(len(c["t"]), 2000)
        self.assertEqual(d["decimated"]["from"], 5000)
        for k in ("air_temperature", "relays", "light", "energy_wh"):
            self.assertEqual(len(c[k]), 2000, k)
        self.assertEqual(len(c["loops"]["air_temperature"]["value"]), 2000)
        self.assertIn(99.0, c["air_temperature"])               # the spike survives (max of its bucket)
        self.assertEqual(max(c["energy_wh"]), max(series_doc()["columns"]["energy_wh"]))
        self.assertEqual(d["changes"], series_doc()["changes"])  # every switch whole
        self.assertEqual(d["header"], series_doc()["header"])
        self.assertEqual(c["t"][0], 0.0)
        self.assertEqual(c["t"][-1], 4999 * 60.0)

    def test_small_documents_are_not_decimated(self):
        st, d = campaigns.read_series(self.t.root, self.entry, "1", {"points": ["2000"]})
        doc = campaigns.decimate(series_doc(100), 2000)
        self.assertNotIn("decimated", doc)
        self.assertEqual(doc, series_doc(100))
        st, d = campaigns.read_series(self.t.root, self.entry, "0", {"points": ["10"]})
        self.assertEqual(len(d["columns"]["t"]), 10)

    def test_refusals(self):
        self.assertEqual(campaigns.read_series(self.t.root, self.entry, "0", {"points": ["2001"]})[0], 400)
        self.assertEqual(campaigns.read_series(self.t.root, self.entry, "0", {"points": ["x"]})[0], 400)
        self.assertEqual(campaigns.read_series(self.t.root, self.entry, "99", {})[0], 404)
        self.assertEqual(campaigns.read_series(self.t.root, self.entry, "5", {})[0], 410)   # listed, file gone

    def test_no_series_recorded(self):
        t = Tree(E58["rows"], series=False)
        try:
            e = campaigns.campaign_of(trace(t.digest), CID)
            self.assertEqual(campaigns.read_series(t.root, e, "0", {}),
                             (404, {"error": "no series recorded for this campaign"}))
            self.assertIsNone(campaigns.read_campaign(t.root, e, {}, mcp_sim.summarise_settings, mcp_sim.summarise_row,
                                                      defaults_of)[1]["series"])
        finally:
            t.close()

    def test_series_too_large(self):
        old = campaigns.SERIES_MAX
        campaigns.SERIES_MAX = 10
        try:
            self.assertEqual(campaigns.read_series(self.t.root, self.entry, "0", {})[0], 413)
        finally:
            campaigns.SERIES_MAX = old

    def test_a_gzip_bomb_stops_at_the_bound(self):
        """Decompression is counted piece by piece: a small file that inflates past SERIES_RAW_MAX is 413 with no more
        than the bound and one piece read."""
        path = os.path.join(self.t.dir, "series", "0.json.gz")
        with gzip.open(path, "wb") as f:
            for _ in range(40):
                f.write(b" " * (1024 * 1024))
        self.assertLess(os.path.getsize(path), campaigns.SERIES_MAX)
        seen = []
        real = gzip.GzipFile.read

        def read(f, n=-1):
            seen.append(n)
            return real(f, n)
        gzip.GzipFile.read = read
        try:
            st, r = campaigns.read_series(self.t.root, self.entry, "0", {})
        finally:
            gzip.GzipFile.read = real
        self.assertEqual(st, 413)
        self.assertNotIn(-1, seen)
        self.assertTrue(all(n == campaigns.SERIES_CHUNK for n in seen))
        self.assertLessEqual(len(seen) * campaigns.SERIES_CHUNK, campaigns.SERIES_RAW_MAX + 2 * campaigns.SERIES_CHUNK)

    def test_the_real_recorder_bound_fits(self):
        """series.py's largest document (MAX_POINTS samples, MAX_CHANGES changes) is under SERIES_RAW_MAX."""
        sys.path.insert(0, ROOT)
        from research.harness import series
        doc = series_doc(series.MAX_POINTS, loops=("air_temperature", "air_humidity", "co2", "substrate_temperature"))
        doc["changes"] = [[i * 1.0, "relay", 0, i % 2] for i in range(series.MAX_CHANGES)]
        self.assertLess(len(json.dumps(doc)), campaigns.SERIES_RAW_MAX // 2)


class Memory(unittest.TestCase):
    """Review of commit B: the bounds fit the orchestrator's pod (memory limit 256Mi), and one read runs at a time."""

    def test_the_bounds_fit_the_pod(self):
        with open(os.path.join(ROOT, "apps", "research-agents", "k8s", "agents.yaml")) as f:
            text = f.read()
        i = text.index("      - name: research-orchestrator")
        j = text.index("limits: {memory:", i)
        self.assertEqual(text[j:text.index("\n", j)], "limits: {memory: 256Mi}")
        self.assertLessEqual(campaigns.RESULTS_MAX, 8 * 1024 * 1024)
        self.assertLessEqual(campaigns.SERIES_RAW_MAX, 16 * 1000 * 1000)
        self.assertLessEqual(campaigns.SERIES_MAX, campaigns.SERIES_RAW_MAX)

    def test_one_read_at_a_time(self):
        t = Tree(E58["rows"])
        try:
            entry = campaigns.campaign_of(trace(t.digest), CID)
            old = campaigns.READ_WAIT_S
            campaigns.READ_WAIT_S = 0.05
            self.assertTrue(campaigns._READ.acquire(timeout=1))
            try:
                for st in (campaigns.read_run(t.root, entry, "0"),
                           campaigns.read_series(t.root, entry, "0", {}),
                           campaigns.read_campaign(t.root, entry, {}, mcp_sim.summarise_settings,
                                                   mcp_sim.summarise_row, defaults_of)):
                    self.assertEqual(st[0], 503)
            finally:
                campaigns._READ.release()
                campaigns.READ_WAIT_S = old
            self.assertEqual(campaigns.read_run(t.root, entry, "0")[0], 200)   # released again
        finally:
            t.close()

    def test_a_reader_that_raises_releases(self):
        t = Tree(E58["rows"])
        try:
            entry = campaigns.campaign_of(trace(t.digest), CID)
            with open(os.path.join(t.dir, "results.jsonl"), "wb") as f:
                f.write(b"{not json\n")
            entry["result_digest"] = hashlib.sha256(b"{not json\n").hexdigest()
            with self.assertRaises(ValueError):
                campaigns.read_run(t.root, entry, "0")
            self.assertTrue(campaigns._READ.acquire(timeout=0))
            campaigns._READ.release()
        finally:
            t.close()


class SeriesRecorder(unittest.TestCase):
    def test_a_real_recorder_document(self):
        """The shape research/harness/series.py writes decimates column for column."""
        sys.path.insert(0, ROOT)
        from research.harness import series
        rec = series.SeriesRecorder(60, header={"run": 0})
        rec.start(3600 * 100, 0, [("air_temperature", 20, 24)], ("heater", "fan"))
        for i in range(6000):
            t = i * 60.0
            rec.tick(t, {"air_temperature": "UP" if i % 50 == 0 else None}, {"heater": i % 3 == 0}, True, 1)
            rec.sample(t, {"air_temperature": 20 + i % 7}, {"air_temperature": ("ok", 21.0, None)}, {"heater": True},
                       True, i * 0.5, 1, {}, {"temperature": 18})
        doc = rec.document()
        d = campaigns.decimate(doc, 1000)
        self.assertEqual(len(d["columns"]["t"]), 1000)
        self.assertEqual(set(d["columns"]), set(doc["columns"]))
        self.assertEqual(d["changes"], doc["changes"])


if __name__ == "__main__":
    unittest.main()
