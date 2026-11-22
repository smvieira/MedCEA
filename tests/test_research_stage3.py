"""Research Phase 4b stage 3: the replay Job, the estimate Job (R7) and their plumbing, against fakes. No cluster."""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, ROOT)
import jobs  # noqa: E402
import mcp_sim  # noqa: E402
from mcp_common import ToolRefused  # noqa: E402
from research.agents import replay_job, sim_job  # noqa: E402
from test_agent_loop import FakeTools, SKILL, STANDING, go  # noqa: E402
import test_research_orchestrator as T  # noqa: E402

orch = T.orch
SID, WHO = T.SID, T.WHO


def run_replay_job(manifest, profile, listing=None):
    """What the pod does: the Job's env into replay_job.main, with the test profile as the bundle's."""
    env = {e["name"]: e["value"] for e in manifest["spec"]["template"]["spec"]["containers"][0]["env"]}
    out = io.StringIO()
    rc = replay_job.main(env, listing if listing is not None else FakeTools().list_tools(), out,
                         bundle={"profile": profile, "standing": STANDING, "skill": SKILL})
    return rc, out.getvalue()


class Replay(unittest.TestCase):
    def setUp(self):
        _, self.ev, self.profile = go()
        self.o, self.k, self.ph, self.sh = T.make()
        self.sh.sessions[SID]["active"] = False
        self.sh.answers[("GET", "/events/%s?after=0" % SID)] = (200, {"events": self.ev})
        self.sh.answers[("GET", "/events/%s?after=%d" % (SID, self.ev[-1]["event_id"]))] = (200, {"events": []})

    def finish(self, events=None):
        name = jobs.replay_job_name(SID)
        rc, log = run_replay_job(self.k.jobs[name], self.profile)
        self.k.status[name] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        self.k.pods[name] = {"name": "p", "phase": "Succeeded", "ip": ""}
        self.k.logs["p"] = "noise line\n" + log
        return rc

    def test_a_clean_session_replays_ok_end_to_end(self):
        st, r = self.o.replay(WHO, SID)
        self.assertEqual((st, r), (202, {"state": "running"}))
        job = self.k.jobs[jobs.replay_job_name(SID)]
        self.assertEqual(job["metadata"]["labels"]["app"], "replay")
        self.assertEqual(self.o.replay(WHO, SID)[0], 202)               # still running: no second Job
        self.assertEqual(len(self.k.jobs), 1)
        self.assertEqual(self.finish(), 0)
        st, r = self.o.replay(WHO, SID)
        self.assertEqual((st, r["ok"], r["first_mismatch"], r["events"]), (200, True, None, len(self.ev)))
        # traced once on the server port as the orchestrator, the Job deleted, the verdict cached
        tr = [c for c in self.sh.calls if c[0] == "POST" and c[1] == "/trace"]
        self.assertEqual(len(tr), 1)
        self.assertEqual((tr[0][2]["server"], tr[0][2]["event"], tr[0][2]["payload"]["ok"]), ("orchestrator", "replay_result", True))
        self.assertIn(jobs.replay_job_name(SID), self.k.deleted)
        self.assertEqual(self.o.replay(WHO, SID), (200, r))
        self.assertEqual(len([c for c in self.sh.calls if c[1] == "/trace"]), 1)

    def test_one_altered_byte_is_the_verdict(self):
        import copy
        ev = copy.deepcopy(self.ev)
        [e for e in ev if e["event"] == "tool_result"][1]["payload"]["result"] += " "
        self.sh.answers[("GET", "/events/%s?after=0" % SID)] = (200, {"events": ev})
        self.o.replay(WHO, SID)
        self.assertEqual(self.finish(), 0)                               # a mismatch is a verdict, the Job succeeds
        st, r = self.o.replay(WHO, SID)
        self.assertEqual((st, r["ok"]), (200, False))
        self.assertEqual(r["first_mismatch"]["event"], "tool_result")
        tr = [c for c in self.sh.calls if c[1] == "/trace"][0][2]["payload"]
        self.assertFalse(tr["ok"])

    def test_only_the_owner_and_only_after_the_session_stopped(self):
        self.assertEqual(self.o.replay(dict(WHO, person_id="p-2"), SID)[0], 404)
        self.sh.sessions[SID]["active"] = True
        self.assertEqual(self.o.replay(WHO, SID)[0], 409)
        self.assertEqual(self.k.jobs, {})

    def test_a_job_that_ends_without_a_result_is_a_failed_replay(self):
        self.o.replay(WHO, SID)
        name = jobs.replay_job_name(SID)
        self.k.status[name] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "DeadlineExceeded"}
        self.k.pods[name] = {"name": "p", "phase": "Failed", "ip": ""}
        self.k.logs["p"] = "Traceback ..."
        st, r = self.o.replay(WHO, SID)
        self.assertEqual((st, r["ok"], r["error"]), (200, False, "deadline"))

    def test_an_earlier_job_is_adopted_and_a_huge_trace_refused(self):
        self.k.jobs[jobs.replay_job_name(SID)] = {"metadata": {"name": "x"}}
        self.o.replay(WHO, SID)
        self.assertEqual(self.k.jobs[jobs.replay_job_name(SID)], {"metadata": {"name": "x"}})
        import random
        rnd = random.Random(2)
        big = [{"event_id": i + 1, "actor": "agent", "event": "x", "payload": {"x": "%032x" % rnd.getrandbits(128)}} for i in range(60000)]
        o, k, ph, sh = T.make()
        sh.sessions[SID]["active"] = False
        sh.answers[("GET", "/events/%s?after=0" % SID)] = (200, {"events": big})
        sh.answers[("GET", "/events/%s?after=60000" % SID)] = (200, {"events": []})
        st, r = o.replay(WHO, SID)
        self.assertEqual(st, 413)
        self.assertIn("replay it on the host", r["error"])

    def test_the_job_manifest_reaches_nothing(self):
        self.o.replay(WHO, SID)
        ps = self.k.jobs[jobs.replay_job_name(SID)]["spec"]["template"]["spec"]
        self.assertFalse(ps["automountServiceAccountToken"])
        self.assertEqual([v for v in ps["volumes"] if "secret" in v], [])
        self.assertNotIn("runs", {v["name"] for v in ps["volumes"]})

    def test_replay_job_failures_are_reported_not_raised(self):
        out = io.StringIO()
        rc = replay_job.main({"MEDCEA_PROFILE": "p", "MEDCEA_EVENTS_N": "1", "MEDCEA_EVENTS_0": "!!!"}, [], out,
                             bundle={"profile": self.profile, "standing": STANDING, "skill": SKILL})
        self.assertEqual(rc, 1)
        r = json.loads(out.getvalue()[len(replay_job.MARK):])
        self.assertEqual(r["state"], "failed")

    def test_events_survive_the_environment(self):
        chunks = jobs.pack_events(self.ev)
        env = {"MEDCEA_EVENTS_N": str(len(chunks)), **{"MEDCEA_EVENTS_%d" % i: c for i, c in enumerate(chunks)}}
        self.assertEqual(replay_job.read_events(env), json.loads(json.dumps(self.ev)))

    def test_replay_main_builds_the_listing_of_both_servers(self):
        import replay_main
        names = [t["name"] for t in replay_main.listing()]
        self.assertEqual(names[:5], sorted(n for n in names if n.startswith(("sim.", "propose."))))
        for n in ("sim.estimate", "sim.run", "propose.parameter_set", "lake.snapshots"):
            self.assertIn(n, names)
        self.assertTrue(all(set(t) == {"name", "description", "inputSchema"} for t in replay_main.listing()))


class EstimateApi(unittest.TestCase):
    SPEC = {"controllers": [{"code": "FLC"}]}
    LOG = 'x\nESTIMATE_RESULT {"state":"done","cpu_hours":0.5,"calibration_h":0.01,"runs":6,"controller_libraries":{"FLC":true}}\n'

    def test_start_runs_a_job_and_status_reads_its_log(self):
        o, k, ph, sh = T.make()
        st, r = o.estimate_start({"sid": SID, "spec": self.SPEC})
        self.assertEqual(st, 200)
        eid = r["eid"]
        self.assertRegex(eid, r"^e[0-9a-f]{20}$")
        self.assertEqual(o.estimate_start({"sid": SID, "spec": self.SPEC}), (200, {"eid": eid}))
        self.assertEqual(len(k.jobs), 1)
        self.assertIn("estimate-" + eid, k.jobs)
        self.assertEqual(o.estimate_status(eid), (200, {"state": "running"}))
        k.status["estimate-" + eid] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        k.pods["estimate-" + eid] = {"name": "p", "phase": "Succeeded", "ip": ""}
        k.logs["p"] = self.LOG
        st, r = o.estimate_status(eid)
        self.assertEqual((st, r["state"], r["cpu_hours"], r["runs"]), (200, "done", 0.5, 6))
        self.assertIn("estimate-" + eid, k.deleted)
        self.assertEqual(o.estimate_status(eid)[1]["cpu_hours"], 0.5)

    def test_refusals(self):
        o, k, ph, sh = T.make()
        self.assertEqual(o.estimate_start({"sid": SID})[0], 400)
        self.assertEqual(o.estimate_start({"sid": "x", "spec": {}})[0], 400)
        sh.sessions[SID]["active"] = False
        self.assertEqual(o.estimate_start({"sid": SID, "spec": {}})[0], 403)
        self.assertEqual(o.estimate_status("nope")[0], 404)
        self.assertEqual(o.estimate_status("e" + "1" * 20)[0], 404)
        sh.sessions[SID]["active"] = True
        k.fail_create = True
        st, r = o.estimate_start({"sid": SID, "spec": {}})
        self.assertEqual(st, 502)
        self.assertEqual(o.estimates, {})

    def test_a_quota_refusal_is_busy(self):
        o, k, ph, sh = T.make()

        def boom(m):
            raise RuntimeError("create job refused (403): exceeded quota: research-quota")
        k.create_job = boom
        st, r = o.estimate_start({"sid": SID, "spec": {}})
        self.assertEqual(st, 502)
        self.assertTrue(r["error"].startswith("busy"))

    def test_a_job_without_a_result_fails_the_estimate(self):
        o, k, ph, sh = T.make()
        eid = o.estimate_start({"sid": SID, "spec": {}})[1]["eid"]
        k.status["estimate-" + eid] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "DeadlineExceeded"}
        self.assertEqual(o.estimate_status(eid)[1]["state"], "failed")

    def test_stopping_the_session_deletes_its_estimate_jobs(self):
        o, k, ph, sh = T.make()
        o.track[SID] = {"person": "p-1", "job": "agent-x", "registered": True, "started": 0, "profile": "p"}
        eid = o.estimate_start({"sid": SID, "spec": {}})[1]["eid"]
        o._cleanup(SID)
        self.assertIn("estimate-" + eid, k.deleted)
        self.assertEqual(o.estimates, {})

    def test_the_http_routes(self):
        import threading
        import urllib.request
        o, k, ph, sh = T.make()
        srv = orch.make_servers(o, "127.0.0.1", (0, 0))
        for s in srv:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        try:
            port = srv[1].server_address[1]

            def call(method, path, body=None):
                req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), None if body is None else json.dumps(body).encode(),
                                             {"Content-Type": "application/json"}, method=method)
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            st, r = call("POST", "/internal/estimates", {"sid": SID, "spec": self.SPEC})
            self.assertEqual(st, 200)
            self.assertEqual(call("GET", "/internal/estimates/" + r["eid"]), (200, {"state": "running"}))
        finally:
            for s in srv:
                s.shutdown()


class Remote(unittest.TestCase):
    class Http:
        def __init__(self, answers):
            self.answers, self.calls = list(answers), []

        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            return self.answers.pop(0)

    def est(self, answers, **kw):
        t = [0.0]

        def clock():
            return t[0]

        def sleep(s):
            t[0] += s
        return mcp_sim.RemoteEstimator(self.Http(answers), sleep=sleep, clock=clock, **kw)

    def test_polls_until_done(self):
        e = self.est([(200, {"eid": "e1"}), (200, {"state": "running"}), (200, {"state": "done", "cpu_hours": 1.5, "calibration_h": 0.1, "runs": 4})])
        self.assertEqual(e.estimate({"x": 1}, sid=SID), {"cpu_hours": 1.5, "calibration_h": 0.1, "runs": 4, "inprocess": False})
        self.assertEqual(e.http.calls[0], ("POST", "/internal/estimates", {"sid": SID, "spec": {"x": 1}}))

    def test_failed_start_failed_job_and_timeout(self):
        with self.assertRaisesRegex(ToolRefused, "could not be started"):
            self.est([(502, {"error": "busy: quota"})]).estimate({}, sid=SID)
        with self.assertRaisesRegex(ToolRefused, "estimate refused: FLC's libraries"):
            self.est([(200, {"eid": "e1"}), (200, {"state": "failed", "error": "FLC's libraries are not installed"})]).estimate({}, sid=SID)
        e = self.est([(200, {"eid": "e1"})] + [(200, {"state": "running"})] * 200, timeout_s=300, poll_s=3)
        with self.assertRaisesRegex(ToolRefused, "did not finish within 300 s"):
            e.estimate({}, sid=SID)
        e = self.est([(200, {"eid": "e1"}), (500, {})])
        with self.assertRaisesRegex(ToolRefused, "did not answer"):
            e.estimate({}, sid=SID)

    def test_split_estimator_sends_flc_and_mpc_to_the_job(self):
        class L:
            def estimate(self, spec, sid=None):
                return {"cpu_hours": 0.1, "inprocess": True}

        class R:
            def estimate(self, spec, sid=None):
                return {"cpu_hours": 9, "inprocess": False}
        s = mcp_sim.SplitEstimator(L(), R())
        mk = lambda *codes: {"controllers": [{"code": c} for c in codes]}
        self.assertTrue(s.estimate(mk("PID", "IF_THEN_ELSE"))["inprocess"])
        self.assertFalse(s.estimate(mk("PID", "FLC"))["inprocess"])
        self.assertFalse(s.estimate(mk("MPC"))["inprocess"])
        self.assertTrue(s.estimate({"nonsense": 1})["inprocess"])         # malformed: the local one refuses it in words

    def test_the_local_estimator_still_refuses_flc_and_mpc_in_words(self):
        spec = {"controllers": [{"code": "FLC", "params": {}}], "scenarios": [], "seeds": [1], "clock_offsets_s": [0]}
        with self.assertRaises(ToolRefused) as c:
            mcp_sim.LocalEstimator(ROOT).estimate(spec)
        self.assertRegex(str(c.exception), "spec refused|needs an estimate Job")

    def test_the_tool_passes_the_session_to_the_estimator(self):
        seen = []

        class E:
            def estimate(self, spec, sid=None):
                seen.append(sid)
                return {"cpu_hours": 0.5, "calibration_h": 0.0, "runs": 1}

        class S:
            def trace(self, *a, **k):
                return None
        srv = mcp_sim.SimServer(S(), E(), None, repo_root=ROOT)
        srv.t_estimate({"sid": SID, "info": {}}, {"spec": {"a": 1}})
        self.assertEqual(seen, [SID])


class EstimateMode(unittest.TestCase):
    def run_job(self, runner, argv=None, env=None, **kw):
        d = tempfile.mkdtemp()
        specf = os.path.join(d, "spec.json")
        json.dump({"a": 1}, open(specf, "w"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sim_job.main((argv or ["--estimate"]) + ["--spec", specf], runner=runner, **kw)
        lines = [ln for ln in buf.getvalue().splitlines() if ln.startswith(sim_job.EST_MARK)]
        return rc, json.loads(lines[-1][len(sim_job.EST_MARK):]), buf.getvalue()

    def test_estimate_prints_one_estimate_line_and_no_sim_line(self):
        rc, r, out = self.run_job(lambda s, o, j, c: {"cpu_hours": 0.25, "calibration_h": 0.01, "runs": 3,
                                                       "controller_libraries": {"FLC": True, "MPC": False}})
        self.assertEqual((rc, r["state"], r["cpu_hours"], r["runs"]), (0, "done", 0.25, 3))
        self.assertEqual(r["controller_libraries"], {"FLC": True, "MPC": False})
        self.assertNotIn(sim_job.MARK, out)

    def test_a_refusal_is_a_failed_estimate(self):
        def boom(s, o, j, c):
            raise ValueError("FLC's libraries are not installed here")
        rc, r, _ = self.run_job(boom)
        self.assertEqual((rc, r["state"]), (1, "failed"))
        self.assertIn("libraries", r["error"])

    def test_the_default_cap_is_small_and_out_is_not_needed(self):
        seen = []

        def runner(s, o, j, c):
            seen.append(c)
            return {"cpu_hours": 0, "calibration_h": 0, "runs": 0}
        self.run_job(runner)
        self.assertEqual(seen, [sim_job.EST_CAP_H])
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                sim_job.main(["--spec", "x"], runner=runner)               # a simulation still needs --out and a cap

    def test_the_real_estimate_refuses_flc_without_its_libraries(self):
        """On a host without scikit-fuzzy the estimate must not silently price bang-bang."""
        from research.agents import estimate
        from research.harness import algorithms_loader
        loaded = algorithms_loader.load(ROOT, allow_dirty=True)
        flc = loaded.libraries.get("FLC", {})
        if flc.get("present"):
            self.skipTest("FLC's libraries are installed here")
        spec = {"controllers": [{"code": "FLC", "params": {}}]}
        with self.assertRaises(estimate.EstimateRefused):
            estimate.estimate_spec(spec, ROOT)


if __name__ == "__main__":
    unittest.main()
