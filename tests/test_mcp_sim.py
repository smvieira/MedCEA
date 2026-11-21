"""mcp-sim: the protocol subset, token and tool checks, the CPU gate's bands (stage 5)."""
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_fakes import FakeSession, SID, call, http_post, payload, rpc, serve  # noqa: E402
import mcp_sim  # noqa: E402

TOOLS = ["sim.estimate", "sim.run", "sim.status", "sim.results"]


class FakeEstimator:
    def estimate(self, spec):          # from the runs, never from spec["claimed_h"]
        return {"cpu_hours": spec["runs"] * 0.5, "calibration_h": 0.05, "runs": spec["runs"]}


class FakeRunner:
    pool = 4

    def __init__(self):
        self.started, self.final = [], {"state": "running"}

    def start(self, cid, spec, cap_h, deadline_s):
        self.started.append((cid, cap_h, deadline_s))

    def status(self, cid):
        return self.final


def setup(budget=None):
    s = FakeSession(TOOLS, budget)
    r = FakeRunner()
    return s, r, mcp_sim.SimServer(s, FakeEstimator(), r).app


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
            self.assertEqual((code, len(resp["result"]["tools"])), (200, 4))
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
        self.assertEqual(deadline, math.ceil(cap * 3600 / 4 * 1.5))
        self.assertEqual(len(s.of("sim_started")), 1)
        self.assertEqual(s.of("gate_pending"), [])

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


if __name__ == "__main__":
    unittest.main()
