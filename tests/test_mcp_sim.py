"""mcp-sim: the protocol subset, token and tool checks, the CPU gate's bands (stage 5)."""
import base64
import json
import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_fakes import FakeSession, SID, call, http_post, payload, rpc, serve  # noqa: E402
import mcp_sim  # noqa: E402

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = ["sim.estimate", "sim.run", "sim.status", "sim.results", "propose.parameter_set"]


class FakeEstimator:
    def estimate(self, spec, sid=None):          # from the runs, never from spec["claimed_h"]
        return {"cpu_hours": spec["runs"] * 0.5, "calibration_h": 0.05, "runs": spec["runs"]}


class FakeRunner:
    pool = 4

    def __init__(self):
        self.started, self.final = [], {"state": "running"}

    def start(self, cid, spec, cap_h, deadline_s, sid=None):
        self.started.append((cid, cap_h, deadline_s))

    def status(self, cid):
        return self.final


def setup(budget=None):
    s = FakeSession(TOOLS, budget)
    r = FakeRunner()
    return s, r, mcp_sim.SimServer(s, FakeEstimator(), r, repo_root=ROOT_DIR).app


class SimTest(unittest.TestCase):
    def test_protocol_subset(self):
        s, r, app = setup()
        code, resp = rpc(app, "initialize")
        self.assertEqual(resp["result"]["protocolVersion"], "2026-07-28")
        self.assertEqual(rpc(app, "nosuch")[1]["error"]["code"], -32601)
        self.assertEqual(app.handle({"jsonrpc": "1.0", "method": "ping"}, "tok", "p")[0], 400)
        names = [t["name"] for t in rpc(app, "tools/list")[1]["result"]["tools"]]
        self.assertEqual(names, sorted(TOOLS))

    def test_http_and_version_header(self):
        s, r, app = setup()
        srv = serve(app)
        try:
            port = srv.server_address[1]
            code, resp = http_post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertEqual((code, len(resp["result"]["tools"])), (200, 5))
            self.assertEqual(http_post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, token="bad")[0], 401)
            code, resp = http_post(port, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"MCP-Protocol-Version": "1999-01-01"})
            self.assertEqual((code, resp["error"]["code"]), (400, -32022))
        finally:
            srv.shutdown()

    def test_token_refused_and_revoked(self):
        s, r, app = setup()
        self.assertEqual(call(app, "sim.estimate", {"spec": {"runs": 1}}, token="nope")[0], 401)
        self.assertEqual(call(app, "sim.estimate", {"spec": {"runs": 1}}, token=None)[0], 401)
        s.active = False
        self.assertEqual(call(app, "sim.estimate", {"spec": {"runs": 1}})[0], 401)
        self.assertEqual(s.events, [])

    def test_tool_not_granted(self):
        s, r, app = setup()
        s.tools = ["sim.estimate"]
        code, resp = call(app, "sim.run", {"spec": {"runs": 1}})
        self.assertTrue(resp["result"]["isError"])
        self.assertEqual(r.started, [])
        self.assertTrue(s.of("tool_result")[0]["error"])
        self.assertEqual([t["name"] for t in rpc(app, "tools/list")[1]["result"]["tools"]], ["sim.estimate"])

    def test_estimate_ignores_agent_figure(self):
        s, r, app = setup()
        p = payload(call(app, "sim.estimate", {"spec": {"runs": 6, "claimed_h": 0.001}})[1])
        self.assertEqual(p["cpu_hours"], 3.0)
        self.assertEqual(p["gate"], "ask")

    def test_below_two_starts_at_once(self):
        s, r, app = setup()
        p = payload(call(app, "sim.run", {"spec": {"runs": 2, "claimed_h": 99}})[1])   # 1.0 CPU-h
        self.assertEqual(p["state"], "started")
        cid, cap, deadline = r.started[0]
        self.assertAlmostEqual(cap, 1.25 * 1.0 + 0.05)
        self.assertEqual(deadline, max(mcp_sim.DEADLINE_FLOOR_S, math.ceil(cap * 3600 / 4 * 1.5)))
        self.assertEqual(len(s.of("sim_started")), 1)
        self.assertEqual(s.of("gate_pending"), [])

    def test_a_tiny_campaign_still_has_time_to_start(self):
        # E48 (22 Nov 2026): a 0.0003 CPU-h cap gave a 1-s deadline and the Job failed "deadline"
        s, r, app = setup()
        call(app, "sim.run", {"spec": {"runs": 0}})   # only the 0.05 h calibration: 68 s without the floor
        self.assertEqual(r.started[0][2], mcp_sim.DEADLINE_FLOOR_S)

    def test_gate_asks_then_approves(self):
        s, r, app = setup()
        spec = {"runs": 10}                                                            # 5 CPU-h
        p = payload(call(app, "sim.run", {"spec": spec})[1])
        self.assertEqual(p["state"], "waiting for the supervisor")
        gid = p["cid"]
        self.assertEqual(s.of("gate_pending")[0]["gid"], gid)
        self.assertEqual(r.started, [])
        s.gates[gid] = {"state": "pending"}
        self.assertEqual(payload(call(app, "sim.run", {"spec": spec})[1])["state"], "waiting for the supervisor")
        s.gates[gid] = {"state": "approved", "decision": {"approved_cap_h": 6.0}}
        p = payload(call(app, "sim.status", {"cid": gid})[1])
        self.assertEqual(p["state"], "running")
        self.assertEqual(r.started[0][1], 6.0)                                         # min(1.25*5+.05, 6)
        self.assertEqual(len(r.started), 1)
        r.final = {"state": "done", "cpu_hours": 4.2, "manifest": {"runs": 10, "invalid_runs": 0, "result_digest": "d" * 64, "spec_digest": "s" * 64},
                   "rows": [{"scenario": "a", "code": "PID", "seed": 1, "valid": True, "metrics": {"rmse": 0.5, "trace": [1, 2]}}]}
        p = payload(call(app, "sim.results", {"cid": gid})[1])
        self.assertEqual(p["result_digest"], "d" * 64)
        self.assertEqual(p["top"][0]["metrics"], {"rmse": 0.5})
        self.assertEqual(s.of("sim_finished")[0]["result_digest"], "d" * 64)

    def test_gate_denied(self):
        s, r, app = setup()
        gid = payload(call(app, "sim.run", {"spec": {"runs": 10}})[1])["cid"]
        s.gates[gid] = {"state": "denied", "decision": {}}
        code, resp = call(app, "sim.status", {"cid": gid})
        self.assertTrue(resp["result"]["isError"])
        self.assertEqual(r.started, [])

    def test_over_24_refused_whatever_approved(self):
        s, r, app = setup()
        code, resp = call(app, "sim.run", {"spec": {"runs": 60}})                      # 30 CPU-h
        self.assertTrue(resp["result"]["isError"])
        self.assertEqual(s.of("gate_pending"), [])

    def test_session_budget_refusal(self):
        s, r, app = setup({"cpu_hours": 4.0})
        self.assertTrue(call(app, "sim.run", {"spec": {"runs": 10}})[1]["result"]["isError"])   # 5 > 4
        p = payload(call(app, "sim.run", {"spec": {"runs": 4}})[1])                    # 2 CPU-h: asks
        self.assertEqual(p["state"], "waiting for the supervisor")
        self.assertAlmostEqual(s.of("gate_pending")[0]["cap_h"], 2.55)                 # 1.25*2+.05
        # that reservation leaves 1.45: a second campaign of 1.5 is refused
        self.assertTrue(call(app, "sim.run", {"spec": {"runs": 3}})[1]["result"]["isError"])

    def test_handle_bound_to_session(self):
        s, r, app = setup()
        cid = payload(call(app, "sim.run", {"spec": {"runs": 2}})[1])["cid"]
        s.introspect = lambda t, a, p: {"active": True, "sid": "B" * 22, "tools": TOOLS, "budget_left": {}}
        self.assertTrue(call(app, "sim.status", {"cid": cid})[1]["result"]["isError"])

    def test_bad_arguments(self):
        s, r, app = setup()
        self.assertTrue(call(app, "sim.run", {"spec": "x"})[1]["result"]["isError"])


class JobRunnerTest(unittest.TestCase):
    """The Job-backed runner (stage 6a) and the sim_job entrypoint, with a fake Kubernetes."""
    CID = "c" + "d" * 20
    CFG = {"image": "img", "code_commit": "abc1234"}

    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "apps", "research-agents"))
        import jobs
        from test_research_orchestrator import FakeKube
        self.jobs, self.k = jobs, FakeKube()
        self.r = jobs.JobSimRunner(self.k, self.CFG, pool=3)

    def result(self, **kw):
        return self.jobs.SIM_MARK + json.dumps(dict({"state": "done", "cpu_hours": 0.25,
                                                     "manifest": {"runs": 2, "result_digest": "d" * 64},
                                                     "rows": [{"scenario": "s", "code": "PID", "seed": 1, "valid": True,
                                                               "metrics": {"x": 1}}]}, **kw))

    def test_start_builds_the_job(self):
        self.r.start(self.CID, {"scenarios": []}, 1.5, 700, sid="A" * 22)
        j = self.k.jobs["sim-" + self.CID]
        c = j["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(j["spec"]["activeDeadlineSeconds"], 700)
        self.assertEqual(j["spec"]["backoffLimit"], 0)
        self.assertEqual(c["command"][-6:], ["--out", "/runs/campaigns/" + self.CID, "--jobs", "3", "--max-cpu-hours", "1.5"][-6:])
        self.assertEqual(json.loads(base64.b64decode(next(e for e in c["env"] if e["name"] == "MEDCEA_SIM_SPEC")["value"])), {"scenarios": []})
        with self.assertRaises(ValueError):
            self.r.start("bad", {}, 1, 10)
        with self.assertRaises(ValueError):
            self.r.start(self.CID, {}, 99, 10)

    def test_status_running_done_cached(self):
        self.r.start(self.CID, {}, 1, 60)
        self.assertEqual(self.r.status(self.CID), {"state": "running"})
        n = "sim-" + self.CID
        self.k.status[n] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        self.k.pods[n] = {"name": "pod1", "phase": "Succeeded", "ip": ""}
        self.k.logs["pod1"] = "noise\n" + self.result() + "\n"
        s = self.r.status(self.CID)
        self.assertEqual((s["state"], s["cpu_hours"], s["manifest"]["result_digest"]), ("done", 0.25, "d" * 64))
        self.k.logs.clear()                                       # cached: the log is read once
        self.assertEqual(self.r.status(self.CID)["state"], "done")

    def test_failures(self):
        self.r.start(self.CID, {}, 1, 60)
        n = "sim-" + self.CID
        self.k.status[n] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "DeadlineExceeded"}
        self.assertEqual(self.r.status(self.CID), {"state": "failed", "error": "deadline"})
        r2 = self.jobs.JobSimRunner(self.k, self.CFG)
        self.assertEqual(r2.status("c" + "e" * 20)["state"], "failed")          # no such Job
        self.k.status[n] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        self.k.pods[n] = {"name": "p", "phase": "Succeeded", "ip": ""}
        self.k.logs["p"] = "no result line"
        self.assertEqual(r2.status(self.CID)["error"], "the Job ended without a result")
        r3 = self.jobs.JobSimRunner(self.k, self.CFG)
        self.k.logs["p"] = self.result(state="failed", error="cpu_cap_exceeded")
        self.k.status[n] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "BackoffLimitExceeded"}
        self.assertEqual(r3.status(self.CID)["error"], "cpu_cap_exceeded")

    def test_runs_through_mcp_sim(self):
        s = FakeSession(TOOLS)
        app = mcp_sim.SimServer(s, FakeEstimator(), self.r).app
        c, resp = call(app, "sim.run", {"spec": {"runs": 2}})
        self.assertEqual(payload(resp)["state"], "started")
        self.assertEqual(len(self.k.jobs), 1)
        n = next(iter(self.k.jobs))
        self.k.status[n] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        self.k.pods[n] = {"name": "p", "phase": "Succeeded", "ip": ""}
        self.k.logs["p"] = self.result()
        cid = payload(resp)["cid"]
        out = payload(call(app, "sim.results", {"cid": cid})[1])
        self.assertEqual((out["state"], out["result_digest"]), ("done", "d" * 64))
        self.assertEqual(s.of("sim_finished")[0]["result_digest"], "d" * 64)

    def test_remote_runner(self):
        calls = []

        class H:
            def request(self, m, path, body=None):
                calls.append((m, path, body))
                return (200, {"state": "running"}) if m == "GET" else (200, {})
        rr = mcp_sim.RemoteRunner(H(), pool=2)
        rr.start(self.CID, {"a": 1}, 1.0, 60, sid="A" * 22)
        self.assertEqual(calls[0][1:], ("/internal/sims", {"sid": "A" * 22, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1.0, "deadline_s": 60}))
        self.assertEqual(rr.status(self.CID), {"state": "running"})
        rr.http = type("H2", (), {"request": lambda s, *a, **k: (502, {"error": "x"})})()
        with self.assertRaises(mcp_sim.ToolRefused):
            rr.start(self.CID, {}, 1, 60)
        self.assertEqual(rr.status(self.CID)["state"], "failed")


class SimJobTest(unittest.TestCase):
    def run_job(self, runner, **kw):
        import contextlib
        import io
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from research.agents import sim_job
        d = tempfile.mkdtemp()
        specf = os.path.join(d, "spec.json")
        json.dump({"a": 1}, open(specf, "w"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sim_job.main(["--out", d, "--jobs", "2", "--max-cpu-hours", "1", "--spec", specf], runner=runner, **kw)
        lines = [ln for ln in buf.getvalue().splitlines() if ln.startswith(sim_job.MARK)]
        line = lines[0] if "exit_fn" in kw else lines[-1]      # a real exit ends the process at the first line
        return rc, json.loads(line[len(sim_job.MARK):]), d

    def test_done_prints_one_result_line_with_rows(self):
        def runner(spec, out, jobs, cap):
            with open(os.path.join(out, "results.jsonl"), "w") as f:
                f.write('{"scenario":"s","valid":true}\n' * 3)
            return {"runs": 3, "result_digest": "f" * 64}
        rc, r, _ = self.run_job(runner)
        self.assertEqual((rc, r["state"], len(r["rows"]), r["manifest"]["runs"]), (0, "done", 3, 3))

    def test_campaign_error_is_a_failed_result(self):
        def runner(spec, out, jobs, cap):
            raise ValueError("spec refused")
        rc, r, _ = self.run_job(runner)
        self.assertEqual((rc, r["state"], r["error"]), (1, "failed", "ValueError: spec refused"))

    def test_watchdog_stops_at_the_cap(self):
        from research.agents import sim_job
        codes = []
        real = sim_job.cpu_seconds
        calls = []

        def fake():                                              # the first read is the baseline; later ones: +5 CPU-hours
            calls.append(1)
            return real() + (5 * 3600 if len(calls) > 1 else 0)
        sim_job.cpu_seconds = fake
        try:
            def runner(spec, out, jobs, cap):
                import time
                time.sleep(0.4)
                return {"runs": 0}
            rc, r, _ = self.run_job(runner, poll=0.05, exit_fn=codes.append)
        finally:
            sim_job.cpu_seconds = real
        self.assertEqual(codes[:1], [3])
        self.assertEqual((r["state"], r["error"]), ("failed", "cpu_cap_exceeded"))

    def test_a_run_that_ends_between_two_looks_is_still_checked(self):
        # E48 (22 Nov 2026): the run ended before the watchdog's first look and was reported done over its cap
        from research.agents import sim_job
        real, calls = sim_job.cpu_seconds, []

        def fake():
            calls.append(1)
            return real() + (5 * 3600 if len(calls) > 1 else 0)
        sim_job.cpu_seconds = fake
        try:
            rc, r, _ = self.run_job(lambda spec, out, jobs, cap: {"runs": 0}, poll=3600)
        finally:
            sim_job.cpu_seconds = real
        self.assertEqual((rc, r["state"], r["error"]), (3, "failed", "cpu_cap_exceeded"))


class ProposeTest(unittest.TestCase):
    """propose.parameter_set (research Phase 4a stage 7a): validated with params.py, backed by this session's
    finished campaigns, nothing written but the document the loop traces."""

    def done(self):
        s, r, app = setup()
        cid = payload(call(app, "sim.run", {"spec": {"runs": 1}})[1])["cid"]          # 0.5 h: starts at once
        r.final = {"state": "done", "cpu_hours": 0.4, "manifest": {"runs": 1, "result_digest": "d" * 64, "spec_digest": "s" * 64}}
        return s, app, cid

    def args(self, cid, **kw):
        return dict({"algorithm_code": "PID", "params": {"cycle_time": 10.0}, "evidence": [cid], "rationale": "shorter"}, **kw)

    def test_a_proposal(self):
        s, app, cid = self.done()
        code, resp = call(app, "propose.parameter_set", self.args(cid))
        p = payload(resp)
        self.assertEqual(code, 200)
        self.assertEqual(p["proposal"]["evidence"], [{"cid": cid, "spec_digest": "s" * 64, "result_digest": "d" * 64}])
        self.assertEqual(p["proposal"]["params"], {"cycle_time": 10.0})
        self.assertRegex(p["proposal_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload(call(app, "propose.parameter_set", self.args(cid))[1])["proposal_sha256"], p["proposal_sha256"])

    def test_refusals(self):
        s, app, cid = self.done()
        for bad in (self.args(cid, params={"cycle_time": -1}), self.args(cid, params={"nosuch": 1}),
                    self.args(cid, algorithm_code="NOSUCH"), self.args(cid, evidence=[]),
                    self.args(cid, evidence=["cdeadbeefdeadbeefdead"]), self.args(cid, params=[1])):
            code, resp = call(app, "propose.parameter_set", bad)
            self.assertTrue(resp["result"]["isError"] if "result" in resp else True, bad)

    def test_running_campaign_is_no_evidence(self):
        s, r, app = setup()
        cid = payload(call(app, "sim.run", {"spec": {"runs": 1}})[1])["cid"]
        code, resp = call(app, "propose.parameter_set", self.args(cid))
        self.assertIn("isError", str(resp["result"]) if "result" in resp else "isError")
        self.assertNotIn("proposal", str(resp))


class ProfileTools(unittest.TestCase):
    """Every tool the shipped profile names, and every tool its script calls, is served by mcp-sim or
    mcp-lake (research Phase 4a stage 6b2); the script's sim.estimate runs through the real
    in-process estimator."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        import mcp_lake
        from research.agents import loop
        cls.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.p = loop.load_profile(os.path.join(cls.root, "research", "agents", "profiles", "compare_controllers.yaml"))
        s, _, sim = setup()
        served = {t["name"] for t in rpc(sim, "tools/list")[1]["result"]["tools"]}
        lake = mcp_lake.LakeServer(FakeSession(["lake.snapshots", "lake.summary", "lake.catalogue"]), None).app
        served |= {t["name"] for t in rpc(lake, "tools/list")[1]["result"]["tools"]}
        cls.served = served

    def test_every_profile_tool_is_served(self):
        self.assertEqual(sorted(set(self.p["tools"]) - self.served), [])
        for step in self.p["script"]:
            if step.get("tool"):
                self.assertIn(step["tool"], self.p["tools"])

    def test_the_scripted_spec_estimates(self):
        step = next(s for s in self.p["script"] if s.get("tool") == "sim.estimate")
        est = mcp_sim.LocalEstimator(self.root)
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            r = est.estimate(step["args"]["spec"])
        finally:
            os.chdir(cwd)
        self.assertEqual(r["runs"], 3)
        self.assertLess(r["cpu_hours"], 2)


class GateCheckProfile(unittest.TestCase):
    """E48's gate_check profile: its tools are served, and its campaign estimates at or above the gate
    (AUTO_BELOW_H) yet within the profile's CPU budget and MAX_CAMPAIGN_H, so sim.run waits for the
    supervisor instead of starting or being refused."""

    def test_the_campaign_waits_at_the_gate(self):
        from research.agents import loop
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = loop.load_profile(os.path.join(root, "research", "agents", "profiles", "gate_check.yaml"))
        self.assertLessEqual(set(p["tools"]), {"sim.estimate", "sim.run", "sim.status", "sim.results"})
        step = next(s for s in p["script"] if s.get("tool") == "sim.estimate")
        run = next(s for s in p["script"] if s.get("tool") == "sim.run")
        self.assertEqual(step["args"], run["args"])
        cwd = os.getcwd()
        os.chdir(root)
        try:
            r = mcp_sim.LocalEstimator(root).estimate(step["args"]["spec"])
        finally:
            os.chdir(cwd)
        self.assertEqual(r["runs"], 6)
        # the pod's CPU differs from the host's: keep a margin on both sides
        self.assertGreaterEqual(r["cpu_hours"], 1.25 * mcp_sim.AUTO_BELOW_H)
        self.assertLessEqual(r["cpu_hours"] + r["calibration_h"], p["caps"]["cpu_hours"] / 2)
        self.assertLess(p["caps"]["cpu_hours"], mcp_sim.MAX_CAMPAIGN_H)


class ProtocolParity(unittest.TestCase):
    def test_client_and_servers_speak_one_version(self):
        # the agent's client and the MCP servers each had their own constant, and E48's first run got 400
        import re
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        def ver(rel):
            with open(os.path.join(here, rel)) as f:
                return re.search(r'^PROTOCOL = "([^"]+)"', f.read(), re.M).group(1)
        self.assertEqual(ver("research/agents/http_tools.py"), ver("apps/research-agents/mcp_common.py"))


if __name__ == "__main__":
    unittest.main()
