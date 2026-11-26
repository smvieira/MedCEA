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
                   "rows": [{"scenario": "a", "controller": {"code": "PID", "params": {"kp": 1.234567}}, "seed": 1,
                             "valid": True, "energy_total_wh": 12.0,
                             "loops": {"air_temperature": {"rmsd_mid": 0.5, "samples": 360, "tag": "x"}}}]}
        p = payload(call(app, "sim.results", {"cid": gid})[1])
        self.assertEqual(p["result_digest"], "d" * 64)
        self.assertNotIn("top", p)                                     # the individual runs only when asked
        self.assertEqual(p["by_setting"]["settings"], [["PID", {"kp": 1.235}, 1, 1, 12.0, 0.5, None, None]])
        p = payload(call(app, "sim.results", {"cid": gid, "top": 5})[1])
        self.assertEqual(p["top"][0]["code"], "PID")
        self.assertEqual(p["top"][0]["params"], {"kp": 1.235})
        self.assertEqual(p["top"][0]["loops"], {"air_temperature": [0.5, None, None]})
        self.assertEqual(p["loop_metrics"], ["rmsd_mid", "out_of_band", "boundary_hugging"])
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

    def test_the_cap_is_the_watchdogs_not_an_up_front_refusal(self):
        # E48, 23 Nov 2026: approved with cap 0.05 against an estimate of 3, the harness refused before any run
        from unittest import mock
        from research.agents import sim_job
        from research.harness import campaign
        seen = {}

        def run_campaign(s, out, **kw):
            seen.update(kw)
            with open(os.path.join(out, "results.jsonl"), "w") as f:
                f.write('{"valid":true}\n')
            return {"runs": 1, "result_digest": "f" * 64}
        with mock.patch.object(campaign, "resolve_spec", lambda s, repo_root=None: s), \
                mock.patch.object(campaign, "run_campaign", run_campaign):
            rc, r, _ = self.run_job(None)
        self.assertEqual((rc, r["state"]), (0, "done"))
        self.assertEqual(seen["max_cpu_hours"], sim_job.CAMPAIGN_CEILING_H)
        self.assertEqual(sim_job.CAMPAIGN_CEILING_H, mcp_sim.MAX_CAMPAIGN_H)

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

    @staticmethod
    def row(code, params, seed, energy, rmsd, valid=True, offset=0.0):
        """A runner row as research/harness/runner.run_scenario writes it (the spec's own params only)."""
        return {"scenario": "smoke_air_temperature", "controller": {"code": code, "params": params},
                "seed": seed, "clock_offset_s": offset, "jitter_s": 0.0, "valid": valid, "energy_total_wh": energy,
                "loops": {"air_temperature": {"rmsd_mid": rmsd, "out_of_band": 0.0, "boundary_hugging": 0.0}}}

    # the smoke campaign of 26 Nov 2026 (IF_THEN_ELSE, PID 10 and 30, seeds 1 and 2): PID 30 nearest the middle,
    # IF_THEN_ELSE cheapest
    ROWS = [row.__func__("IF_THEN_ELSE", {}, 1, 28.33, 1.6036), row.__func__("IF_THEN_ELSE", {}, 2, 28.33, 1.6034),
            row.__func__("PID", {"cycle_time": 10.0}, 1, 85.13, 0.2885), row.__func__("PID", {"cycle_time": 10.0}, 2, 89.46, 0.3094),
            row.__func__("PID", {"cycle_time": 30.0}, 1, 84.07, 0.2775), row.__func__("PID", {"cycle_time": 30.0}, 2, 88.39, 0.3001)]

    def done(self, rows=None, runs=None):
        s, r, app = setup()
        cid = payload(call(app, "sim.run", {"spec": {"runs": 1}})[1])["cid"]          # 0.5 h: starts at once
        rows = self.ROWS if rows is None else rows
        r.final = {"state": "done", "cpu_hours": 0.4, "rows": rows,
                   "manifest": {"runs": len(rows) if runs is None else runs, "result_digest": "d" * 64, "spec_digest": "s" * 64}}
        return s, app, cid

    def args(self, cid, **kw):
        return dict({"algorithm_code": "PID", "params": {"cycle_time": 30.0}, "evidence": [cid],
                     "criterion": "air_temperature.rmsd_mid", "rationale": "longer"}, **kw)

    def refused(self, app, args):
        code, resp = call(app, "propose.parameter_set", args)
        res = resp.get("result") or {}
        self.assertTrue(res.get("isError"), resp)
        self.assertNotIn("proposal_sha256", str(resp))
        return json.loads(res["content"][0]["text"])["error"]

    def test_a_proposal(self):
        s, app, cid = self.done()
        code, resp = call(app, "propose.parameter_set", self.args(cid))
        p = payload(resp)
        self.assertEqual(code, 200)
        self.assertEqual(p["proposal"]["evidence"], [{"cid": cid, "spec_digest": "s" * 64, "result_digest": "d" * 64}])
        self.assertEqual(p["proposal"]["params"], {"cycle_time": 30.0})
        chk = p["proposal"]["check"]
        self.assertEqual((chk["criterion"], chk["lower_is_better"], chk["proposed_runs"], chk["compared_total"]),
                         ("air_temperature.rmsd_mid", True, 2, 2))
        self.assertEqual([(e["code"], e["params"], e["outcome"], e["runs"]) for e in chk["compared"]],
                         [("IF_THEN_ELSE", {}, "better", 2), ("PID", {"cycle_time": 10.0}, "better", 2)])
        self.assertEqual(chk["proposed_mean"], 0.2888)
        self.assertRegex(p["proposal_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload(call(app, "propose.parameter_set", self.args(cid))[1])["proposal_sha256"], p["proposal_sha256"])

    def test_refusals(self):
        s, app, cid = self.done()
        for bad in (self.args(cid, params={"cycle_time": -1}), self.args(cid, params={"nosuch": 1}),
                    self.args(cid, algorithm_code="NOSUCH"), self.args(cid, evidence=[]),
                    self.args(cid, evidence=["cdeadbeefdeadbeefdead"]), self.args(cid, params=[1])):
            code, resp = call(app, "propose.parameter_set", bad)
            self.assertTrue(resp["result"]["isError"] if "result" in resp else True, bad)

    def test_the_check_refuses_what_the_evidence_contradicts(self):
        """E57 (26 Nov 2026): the rationale backed PID on energy while IF_THEN_ELSE used a third of it."""
        s, app, cid = self.done()
        t = self.refused(app, self.args(cid, criterion="energy_wh"))
        self.assertIn('PID {"cycle_time":30.0} does not do better on energy_wh (lower is better): IF_THEN_ELSE {} has 28.33 '
                      "against its 86.23 on the 2 run(s) they share", t)
        t = self.refused(app, self.args(cid, params={"cycle_time": 10.0}))
        self.assertIn('PID {"cycle_time":30.0} has 0.2888 against its 0.2989', t)
        # the cheapest setting on energy passes, and an int and a float of the same value are one setting
        p = payload(call(app, "propose.parameter_set", self.args(cid, algorithm_code="IF_THEN_ELSE", params={}, criterion="energy_wh"))[1])
        self.assertEqual([e["outcome"] for e in p["proposal"]["check"]["compared"]], ["better", "better"])
        self.assertIn("proposal", payload(call(app, "propose.parameter_set", self.args(cid, params={"cycle_time": 30}))[1]))

    def test_the_check_needs_a_setting_the_evidence_ran_and_compared(self):
        s, app, cid = self.done()
        self.assertIn("was not run in the evidence", self.refused(app, self.args(cid, params={"cycle_time": 20.0})))
        self.assertIn("criterion must be", self.refused(app, self.args(cid, criterion="rmsd")))
        self.assertIn("criterion must be", self.refused(app, dict(self.args(cid), criterion=None)))
        self.assertIn("the evidence has no co2.rmsd_mid", self.refused(app, self.args(cid, criterion="co2.rmsd_mid")))
        self.assertIn("ties every other setting on air_temperature.out_of_band",
                      self.refused(app, self.args(cid, criterion="air_temperature.out_of_band")))
        s, app, cid = self.done(rows=[r for r in self.ROWS if r["controller"]["code"] == "PID" and r["controller"]["params"]["cycle_time"] == 30.0])
        self.assertIn("runs no other setting on the same scenario, seed and clock offset", self.refused(app, self.args(cid)))
        # runs on other seeds share nothing: no comparison
        other = [dict(r, seed=r["seed"] + 10) for r in self.ROWS if r["controller"]["code"] == "IF_THEN_ELSE"]
        s, app, cid = self.done(rows=[r for r in self.ROWS if r["controller"]["code"] == "PID" and r["controller"]["params"]["cycle_time"] == 30.0] + other)
        self.assertIn("runs no other setting", self.refused(app, self.args(cid)))

    def test_invalid_runs_do_not_count(self):
        rows = [dict(r, valid=False) if r["controller"]["params"].get("cycle_time") == 30.0 else r for r in self.ROWS]
        s, app, cid = self.done(rows=rows)
        self.assertIn("has no valid run with air_temperature.rmsd_mid", self.refused(app, self.args(cid)))
        # an invalid better run of another setting is no comparison: only the shared valid runs are
        rows = [dict(r, valid=False, loops={"air_temperature": {"rmsd_mid": 0.0}}) if r["controller"]["params"].get("cycle_time") == 10.0
                else r for r in self.ROWS]
        s, app, cid = self.done(rows=rows)
        chk = payload(call(app, "propose.parameter_set", self.args(cid))[1])["proposal"]["check"]
        self.assertEqual([e["code"] for e in chk["compared"]], ["IF_THEN_ELSE"])

    def test_the_check_reads_every_run(self):
        s, app, cid = self.done(runs=60)                 # sim_job keeps the first 50 rows of a campaign
        self.assertIn("the server holds 6 of its 60 runs", self.refused(app, self.args(cid)))
        s, app, cid = self.done()
        self.assertIn("names a campaign twice", self.refused(app, self.args(cid, evidence=[cid, cid])))

    def test_defaults_fill_a_row_s_parameters(self):
        """A row holds only the spec's own parameters: PID {} is PID with every default, cycle_time 10 included."""
        rows = [self.row("PID", {}, 1, 80.0, 0.2), self.row("PID", {"cycle_time": 30.0}, 1, 84.0, 0.3)]
        s, app, cid = self.done(rows=rows)
        import importlib.util
        spec = importlib.util.spec_from_file_location("p", os.path.join(ROOT_DIR, "schd", "cea", "algorithms", "params.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        full = m.defaults("PID")
        p = payload(call(app, "propose.parameter_set", self.args(cid, params=full))[1])
        self.assertEqual(p["proposal"]["check"]["compared"][0]["params"], {"cycle_time": 30.0})

    def test_runs_of_two_campaigns_meet_only_on_the_same_scenario(self):
        """Review of 26 Nov 2026: the cells were keyed on the scenario's name, so a campaign's inline scenario of
        another length under the same name counted as the same runs. A scenario is now its resolved content and the
        campaign's code: the same file in two campaigns compares, an inline variant under its name does not."""
        import yaml

        class Est:
            def estimate(self, spec, sid=None):
                return {"cpu_hours": 0.1, "calibration_h": 0.01, "runs": 1}

        class Runner:
            pool, finals = 4, {}

            def start(self, cid, spec, cap_h, deadline_s, sid=None):
                pass

            def status(self, cid):
                return self.finals[cid]

        sess, runner = FakeSession(TOOLS), Runner()
        app = mcp_sim.SimServer(sess, Est(), runner, repo_root=ROOT_DIR).app
        path = "research/harness/scenarios/smoke_air_temperature.yaml"
        with open(os.path.join(ROOT_DIR, path)) as f:
            inline = dict(yaml.safe_load(f), duration_h=24)
        code = {"commit": "c" * 40}

        def camp(spec, rows):
            cid = payload(call(app, "sim.run", {"spec": spec})[1])["cid"]
            runner.finals[cid] = {"state": "done", "cpu_hours": 0.1, "rows": rows, "manifest": {
                "runs": len(rows), "result_digest": "d" * 64, "spec_digest": cid.ljust(64, "s"), "code": code}}
            return cid

        def ctl(c, p=None):
            return {"scenarios": [path], "controllers": [dict({"code": c}, **({"params": p} if p else {}))], "seeds": [1]}

        pid = camp(ctl("PID", {"cycle_time": 30.0}), [self.row("PID", {"cycle_time": 30.0}, 1, 84.07, 0.2775)])
        ite = camp(ctl("IF_THEN_ELSE"), [self.row("IF_THEN_ELSE", {}, 1, 28.33, 1.6036)])
        longer = camp({"scenarios": [inline], "controllers": [{"code": "IF_THEN_ELSE"}], "seeds": [1]},
                      [self.row("IF_THEN_ELSE", {}, 1, 600.0, 9.0)])
        chk = payload(call(app, "propose.parameter_set", self.args(pid, evidence=[pid, ite]))[1])["proposal"]["check"]
        self.assertEqual([(e["code"], e["runs"], e["other"]) for e in chk["compared"]], [("IF_THEN_ELSE", 1, 1.604)])
        self.assertIn("runs no other setting", self.refused(app, self.args(pid, evidence=[pid, longer])))
        # a campaign whose scenarios cannot be resolved is compared within itself only
        bad = camp({"scenarios": ["nosuch.yaml"], "controllers": [{"code": "IF_THEN_ELSE"}], "seeds": [1]},
                   [self.row("IF_THEN_ELSE", {}, 1, 28.33, 1.6036)])
        self.assertIn("runs no other setting", self.refused(app, self.args(pid, evidence=[pid, bad])))
        # another code under the same file is another scenario too
        runner.finals[ite]["manifest"]["code"] = {"commit": "e" * 40}
        self.assertIn("runs no other setting", self.refused(app, self.args(pid, evidence=[pid, ite])))

    def test_the_agent_and_mcp_sim_hash_a_long_refusal_alike(self):
        """Review round 2 (26 Nov 2026): mcp-sim records a refusal up to 300 characters, the agent kept 200, so a longer
        refusal hashed differently on the two sides and replay failed on server_result_sha256. Through the agent's own
        client (HttpTools) and loop's error result (loop.ERROR_MAX), each refusal's text must hash as mcp-sim's does."""
        from research.agents import http_tools, loop
        from research.agents.context import canonical as acanon, sha as asha
        many = lambda r: dict(r, loops=dict(r["loops"], **{"substrate_temperature_reference_probe_%d" % i:
                                                            r["loops"]["air_temperature"] for i in range(6)}))
        rows = [many(r) for r in self.ROWS + [self.row("PID", {"cycle_time": 30.0, "kp": 2.0, "ki": 0.5, "kd": 0.1}, 1, 10.0, 0.01)]]
        s, app, cid = self.done(rows=rows)

        class T:
            def post(self, url, token, msg):
                return app.handle(msg, token, "10.0.0.1")

        tools = http_tools.HttpTools({"sim": "http://sim"}, "tok", transport=T())
        for args in (self.args(cid, criterion="air_temp.rmsd_mid"), self.args(cid, criterion="energy_wh"),
                     self.args(cid, params={"cycle_time": 30.0, "kp": 2.0, "ki": 0.5}),
                     self.args(cid, params={"cycle_time": 10.0}),
                     self.args(cid, params={"cycle_time": 10.0}, criterion="substrate_temperature_reference_probe_5.rmsd_mid")):
            n = len(s.of("tool_result"))
            with self.assertRaises(loop.ToolError) as cm:
                tools.call("propose.parameter_set", args)
            server = s.of("tool_result")[n]
            mine = acanon({"error": str(cm.exception)[:loop.ERROR_MAX]})
            mine = mine.decode("utf-8") if isinstance(mine, bytes) else mine
            self.assertTrue(server["error"])
            self.assertEqual(asha(mine.encode("utf-8")), server["result_sha256"], str(cm.exception))
        long_one = str(cm.exception)
        self.assertGreater(len(long_one), 200)        # the case the old 200 lost

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

    def test_every_shipped_profile_loads_and_has_its_skill(self):
        from research.agents import loop
        a = os.path.join(self.root, "research", "agents")
        names = sorted(f[:-5] for f in os.listdir(os.path.join(a, "profiles")) if f.endswith(".yaml"))
        self.assertIn("compare_controllers_gpu", names)
        for n in names:
            p = loop.load_profile(os.path.join(a, "profiles", n + ".yaml"))
            self.assertEqual(p["name"], n)
            self.assertEqual(sorted(set(p["tools"]) - self.served), [], n)
            self.assertTrue(os.path.isfile(os.path.join(a, "skills", p.get("skill", "controller_campaign") + ".md")), n)
        gpu = loop.load_profile(os.path.join(a, "profiles", "compare_controllers_gpu.yaml"))
        self.assertEqual((gpu["backend"], gpu["caps"]["context_tokens"]), ("gpu", 12000))
        self.assertEqual(gpu["finish_after"], ["propose.parameter_set"])

    def test_the_scripted_proposal_names_a_criterion(self):
        step = next(s for s in self.p["script"] if s.get("tool") == "propose.parameter_set")
        self.assertEqual((step["args"]["params"], step["args"]["criterion"]), ({"cycle_time": 30.0}, "air_temperature.rmsd_mid"))

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


class SpecSchema(unittest.TestCase):
    """The spec schema a model sees is the campaign spec's real shape (E49, 23 Nov 2026: with a bare
    {"type": "object"} the local model sent a flat spec, refused twice)."""

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_codes_are_the_parameter_schemas(self):
        params = mcp_sim._load_params(self.root)
        self.assertEqual(sorted(mcp_sim.CODES), sorted(params.PARAMS))

    def test_keys_are_resolve_specs(self):
        sys.path.insert(0, self.root)
        from research.harness import campaign
        self.assertEqual(set(mcp_sim.CAMPAIGN_SPEC["properties"]), campaign.SPEC_KEYS)

    def test_the_scripted_specs_fit_the_schema(self):
        sys.path.insert(0, self.root)
        from research.agents import loop
        p = loop.load_profile(os.path.join(self.root, "research", "agents", "profiles", "compare_controllers.yaml"))
        props = mcp_sim.CAMPAIGN_SPEC["properties"]
        ctrl = props["controllers"]["items"]
        for step in p["script"]:
            spec = (step.get("args") or {}).get("spec")
            if spec is None:
                continue
            self.assertLessEqual(set(spec), set(props))
            self.assertLessEqual(set(mcp_sim.CAMPAIGN_SPEC["required"]), set(spec))
            for c in spec["controllers"]:
                self.assertLessEqual(set(c), set(ctrl["properties"]))
                self.assertIn(c["code"], ctrl["properties"]["code"]["enum"])

    def test_the_local_profile_still_starts_well_inside_its_context(self):
        sys.path.insert(0, self.root)
        from research.agents import loop
        from research.agents.context import Context
        a = os.path.join(self.root, "research", "agents")
        p = loop.load_profile(os.path.join(a, "profiles", "compare_controllers_local.yaml"))
        s, _, sim = setup()
        import mcp_lake
        listed = {t["name"]: t for t in rpc(sim, "tools/list")[1]["result"]["tools"]}
        lake = mcp_lake.LakeServer(FakeSession(["lake.snapshots", "lake.summary", "lake.catalogue"]), None).app
        listed.update({t["name"]: t for t in rpc(lake, "tools/list")[1]["result"]["tools"]})
        spec = [{"name": n, "description": listed[n].get("description", ""), "inputSchema": listed[n]["inputSchema"]}
                for n in p["tools"] if n in listed]
        with open(os.path.join(a, "policy", "standing.md"), encoding="utf-8") as f:
            standing = f.read()
        with open(os.path.join(a, "skills", "controller_campaign_local.md"), encoding="utf-8") as f:
            skill = f.read()
        ctx = Context(standing, skill, spec)
        ctx.add("user", p["task"])
        self.assertLess(ctx.est_tokens(), p["caps"]["context_tokens"] // 2)


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


class ResultsShape(unittest.TestCase):
    """sim.results shows what the harness writes (E49, 24 Nov 2026: it read keys no row has, metrics {})."""

    def test_a_real_row(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, repo)
        import copy
        import yaml
        from research.harness import algorithms_loader, runner
        with open(os.path.join(repo, "research/harness/scenarios/smoke_air_temperature.yaml"), encoding="utf-8") as f:
            sc = yaml.safe_load(f)
        row = runner.run_scenario(copy.deepcopy(sc), {"code": "PID", "params": {"cycle_time": 30.0}}, 1,
                                  loaded=algorithms_loader.load(repo, allow_dirty=True))
        out = mcp_sim.summarise_row(row)
        self.assertEqual(out["code"], "PID")
        self.assertEqual(out["params"], {"cycle_time": 30.0})
        self.assertTrue(out["valid"])
        self.assertIn("energy_wh", out)
        self.assertTrue(out["loops"])
        for m in out["loops"].values():
            self.assertEqual(len(m), len(mcp_sim.LOOP_METRICS))
            self.assertIsInstance(m[0], float)
        self.assertNotIn("clock_offset_s", out)                 # 0 is left out
        # an agent sees the first 1000 characters of a result: three rows and the header fit
        from mcp_common import canonical
        shown = canonical({"cid": "c" * 21, "state": "done", "runs": 3, "invalid_runs": 0, "result_digest": "d" * 64,
                           "spec_digest": "s" * 64, "cpu_hours": 0.0058, "loop_metrics": list(mcp_sim.LOOP_METRICS),
                           "top": [out] * 3})
        self.assertLess(len(shown), 1000, shown)


class BySetting(unittest.TestCase):
    """sim.results' per-setting table (26 Nov 2026, E58: the model saw the campaign's first five runs, all FLC's)."""
    FIX = os.path.join(ROOT_DIR, "tests", "fixtures", "research", "e58_campaign.json")

    def setUp(self):
        with open(self.FIX, encoding="utf-8") as f:
            self.doc = json.load(f)
        self.s, self.r, self.app = setup()
        self.cid = payload(call(self.app, "sim.run", {"spec": {"runs": 1}})[1])["cid"]
        self.r.final = {"state": "done", "cpu_hours": 0.1214, "manifest": self.doc["manifest"], "rows": self.doc["rows"]}

    def results(self, **args):
        code, resp = call(self.app, "sim.results", dict(args, cid=self.cid))
        return code, resp

    def test_every_setting_within_what_the_model_sees(self):
        from mcp_common import canonical
        for sort in (None, "air_temperature.rmsd_mid", "energy_wh", "co2.boundary_hugging"):
            args = {"sort": sort} if sort else {}
            p = payload(self.results(**args)[1])
            t = p["by_setting"]
            self.assertEqual(t["count"], {"shown": 6, "total": 6})
            self.assertEqual(sorted((r[0], canonical(r[1])) for r in t["settings"]),
                             sorted([("FLC", canonical({})), ("IF_THEN_ELSE", canonical({})), ("MPC", canonical({})),
                                     ("PID", canonical({"cycle_time": 10.0})), ("PID", canonical({"cycle_time": 30.0})),
                                     ("Q_LEARNING", canonical({}))]))
            text = canonical(p)
            text = text.decode() if isinstance(text, bytes) else text
            shown = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:1000]
            for r in t["settings"]:                          # every row inside the 1000 characters an agent sees
                self.assertIn(canonical(r).decode() if isinstance(canonical(r), bytes) else canonical(r), shown, sort)

    def test_the_numbers_are_the_checks(self):
        p = payload(self.results(sort="air_temperature.rmsd_mid")[1])
        t = p["by_setting"]
        col = t["columns"].index("air_temperature.rmsd_mid")
        e = t["columns"].index("energy_wh")
        best = t["settings"][0]
        self.assertEqual((best[0], best[col], best[2], best[3]), ("MPC", 0.112, 6, 6))
        self.assertEqual(t["settings"][1][:2] + [t["settings"][1][col]], ["FLC", {}, 0.1135])
        self.assertEqual(best[e], 83.69)                     # MPC's own energy (E58's rationale quoted FLC's 92.61)
        pm = mcp_sim._load_params(ROOT_DIR)
        check = mcp_sim.compare_evidence(self.doc["rows"], "MPC", {}, "air_temperature.rmsd_mid", pm.defaults)
        self.assertEqual(check["proposed_mean"], best[col])
        means = {(c["code"], json.dumps(c["params"], sort_keys=True)): c["other"] for c in check["compared"]}
        for r in t["settings"][1:]:
            key = (r[0], json.dumps(r[1], sort_keys=True))
            self.assertEqual(means[key], r[col], key)      # one grid: each setting's runs are the shared runs
        e_sorted = payload(self.results(sort="energy_wh")[1])["by_setting"]["settings"]
        self.assertEqual([r[0] for r in e_sorted][:2], ["IF_THEN_ELSE", "Q_LEARNING"])
        self.assertEqual(payload(self.results()[1])["by_setting"]["order"], "the campaign's")

    def test_defaults_join_a_setting_and_invalid_runs_count_but_do_not_average(self):
        rows = [{"controller": {"code": "PID", "params": {}}, "seed": 1, "valid": True, "energy_total_wh": 10.0,
                 "loops": {"air_temperature": {"rmsd_mid": 1.0}}},
                {"controller": {"code": "PID", "params": {"cycle_time": 10.0}}, "seed": 2, "valid": True,
                 "energy_total_wh": 20.0, "loops": {"air_temperature": {"rmsd_mid": 3.0}}},
                {"controller": {"code": "PID", "params": {"cycle_time": 10.0}}, "seed": 3, "valid": False,
                 "energy_total_wh": 999.0, "loops": {"air_temperature": {"rmsd_mid": 999.0}}},
                {"controller": {"code": "FLC", "params": {}}, "seed": 1, "valid": False, "loops": {}}]
        self.r.final = {"state": "done", "cpu_hours": 0.1, "manifest": {"runs": 4}, "rows": rows}
        t = payload(self.results()[1])["by_setting"]
        self.assertEqual(t["settings"], [["PID", {}, 3, 2, 15.0, 2.0, None, None],
                                         ["FLC", {}, 1, 0, None, None, None, None]])
        t = payload(self.results(sort="air_temperature.rmsd_mid")[1])["by_setting"]
        self.assertEqual([r[0] for r in t["settings"]], ["PID", "FLC"])     # no value sorts last

    def test_a_sort_that_is_no_criterion_is_refused(self):
        for bad in ("air_temperature.mean", "substrate_temperature.rmsd_mid", 3, ""):
            code, resp = self.results(sort=bad)
            self.assertTrue(resp["result"]["isError"], bad)
            self.assertIn("sort must be one of this campaign's criteria", resp["result"]["content"][0]["text"])

    def test_a_long_table_keeps_its_header(self):
        rows = [{"controller": {"code": "PID", "params": {"cycle_time": float(c)}}, "seed": 1, "valid": True,
                 "energy_total_wh": 100.0 - c,
                 "loops": {k: {"rmsd_mid": c / 7, "out_of_band": 0.0, "boundary_hugging": 0.0}
                           for k in ("air_temperature", "air_humidity", "co2")}} for c in range(1, 31)]
        self.r.final = {"state": "done", "cpu_hours": 0.1, "manifest": {"runs": 30}, "rows": rows}
        from mcp_common import canonical
        p = payload(self.results(sort="energy_wh")[1])
        t = p["by_setting"]
        self.assertEqual(t["count"], {"shown": mcp_sim.SETTINGS_MAX, "total": 30})
        text = canonical(p)
        text = (text.decode() if isinstance(text, bytes) else text)[:1000]
        for k in ("columns", "count", "means_of", "order"):
            self.assertIn('"%s":' % k, text)
        self.assertIn('["PID",{"cycle_time":30.0},1,1,70.0', text)        # the best one first

    def test_the_tool_listing(self):
        tools = {t["name"]: t for t in rpc(self.app, "tools/list")[1]["result"]["tools"]}
        props = tools["sim.results"]["inputSchema"]["properties"]
        self.assertEqual(set(props), {"cid", "sort", "top"})
        self.assertEqual(tools["sim.status"]["inputSchema"], mcp_sim.CID_SCHEMA)

