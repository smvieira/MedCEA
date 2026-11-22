"""medcea-agent (research/agents/cli.py), the agent's HTTP tool client and the Job entrypoint (stage 6a)."""
import ast
import io
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from research.agents import cli, loop, http_tools, run_agent  # noqa: E402

CLI = os.path.join(ROOT, "research", "agents", "cli.py")


class FakeOrch:
    def __init__(self):
        self.calls, self.polls, self.events = [], 0, []

    def request(self, method, path, body=None, token=None):
        self.calls.append((method, path, body, token))
        if path == "/api/signin/start":
            return 200, {"device_code": "d" * 12, "user_code": "WXYZ", "verification_uri": "https://k/d", "interval": 1,
                         "expires_in": 600}
        if path == "/api/signin/poll":
            self.polls += 1
            return (400, {"error": "authorization_pending"}) if self.polls < 2 else (200, {"access_token": "A%d" % self.polls,
                                                                                         "refresh_token": "R", "expires_in": 300})
        if path == "/api/signin/refresh":
            return 200, {"access_token": "A-refreshed", "expires_in": 300}
        if path == "/api/sessions" and method == "POST":
            return 201, {"sid": "S" * 22}
        if "/events" in path:
            after = int(path.rsplit("=", 1)[1])
            return 200, {"events": [e for e in self.events if e["event_id"] > after]}
        if path.endswith("/stop") or "/gates/" in path or "/proposals/" in path:
            return 200, {"ok": True}
        if path.endswith("/replay"):
            return 200, {"ok": True, "first_mismatch": None, "events": 5}
        if method == "GET":
            return 200, {"active": True}
        return 404, {"error": "no"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def client(orch=None):
    c, out = Clock(), []
    o = orch or FakeOrch()
    return cli.Client(o, sleep=c.sleep, clock=c, out=out.append), o, out, c


class CliTest(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(open(CLI).read())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                self.assertEqual(n.level, 0, "no relative import")
                mods.add((n.module or "").split(".")[0])
        self.assertTrue(mods <= set(sys.stdlib_module_names), sorted(mods - set(sys.stdlib_module_names)))

    def test_signin_start_flow_and_token_use(self):
        c, o, out, clk = client()
        c.signin()
        self.assertIn("WXYZ", out[0])
        r = c.start("compare_controllers", {"turns": 3})
        self.assertEqual(r["sid"], "S" * 22)
        m, path, body, tok = o.calls[-1]
        self.assertEqual((m, path, body, tok), ("POST", "/api/sessions", {"profile": "compare_controllers", "budget": {"turns": 3}}, "A2"))
        c.info(r)        # what start() returned works wherever a session id does (E48, 22 Nov 2026)
        self.assertEqual(o.calls[-1][1], "/api/sessions/" + "S" * 22)

    def test_refresh_before_expiry(self):
        c, o, out, clk = client()
        c.signin()
        clk.t += 250
        c.info("S" * 22)
        self.assertEqual(o.calls[-2][1], "/api/signin/refresh")
        self.assertEqual(o.calls[-1][3], "A-refreshed")

    def test_not_signed_in_and_ended_signin(self):
        c, o, out, clk = client()
        with self.assertRaises(cli.CliError):
            c.stop("S" * 22)
        c.signin()
        o.request = lambda m, p, b=None, t=None: (400, {"error": "invalid_grant"})
        clk.t += 1000
        with self.assertRaises(cli.CliError):
            c.info("S" * 22)

    def test_refusal_is_a_cli_error_with_the_message(self):
        c, o, out, clk = client()
        c.signin()
        o.request = lambda m, p, b=None, t=None: (409, {"error": "person already has 2 active sessions"})
        with self.assertRaisesRegex(cli.CliError, "2 active sessions"):
            c.start("x")

    def test_watch_follows_until_stop(self):
        c, o, out, clk = client()
        c.signin()
        o.events = [{"event_id": 1, "event": "turn_request", "actor": "agent", "payload": {}},
                    {"event_id": 2, "event": "gate_pending", "actor": "mcp-sim", "payload": {"gid": "g1", "estimate_h": 3, "cap_h": 4}},
                    {"event_id": 3, "event": "stop", "actor": "agent", "payload": {"reason": "finished", "turns": 4}}]
        self.assertEqual(c.watch("S" * 22), "stop")
        self.assertIn("gate g1", out[2])
        self.assertIn("finished", out[3])

    def test_decide_stop_replay(self):
        c, o, out, clk = client()
        c.signin()
        c.answer("S" * 22, "gates", "g1", "approve", "ok", 2.5)
        self.assertEqual(o.calls[-1][:3], ("POST", "/api/sessions/%s/gates/g1" % ("S" * 22),
                                           {"decision": "approve", "note": "ok", "approved_cap_h": 2.5}))
        c.answer("S" * 22, "proposals", "p1", "deny")
        self.assertEqual(o.calls[-1][2], {"decision": "deny", "note": ""})
        c.stop("S" * 22)
        self.assertEqual(c.replay("S" * 22)["ok"], True)

    def test_main_commands(self):
        for argv, want in ((["start", "compare_controllers", "--budget", "turns=3"], "started"),
                           (["approve", "S" * 22, "g1", "--cap-h", "2"], "approve recorded"),
                           (["deny", "S" * 22, "g1"], "deny recorded"),
                           (["accept", "S" * 22, "p1"], "accept recorded"),
                           (["stop", "S" * 22], "stopped"),
                           (["replay", "S" * 22], '"ok": true')):
            c, o, out, clk = client()
            self.assertEqual(cli.main(argv, c), 0, argv)
            self.assertIn(want, out[-1])
        c, o, out, clk = client()
        o.request = lambda m, p, b=None, t=None: (500, {})
        self.assertEqual(cli.main(["stop", "S" * 22], c), 1)


class FakeMcp:
    def __init__(self):
        self.calls, self.status_seq = [], []

    def post(self, url, token, msg):
        self.calls.append((url, token, msg["method"], msg["params"]))
        if token != "tok":
            return 401, None
        if msg["method"] == "tools/list":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "sim.run", "description": "d"}, {"name": "sim.status", "description": "d"}]}}
        n = msg["params"]["name"]
        if n == "sim.run":
            return 200, self.ok({"cid": "cx", "state": "waiting for the supervisor"})
        if n == "sim.status":
            return 200, self.ok(self.status_seq.pop(0))
        if n == "sim.boom":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": json.dumps({"error": "refused: x"})}]}}
        return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}

    @staticmethod
    def ok(o):
        return {"jsonrpc": "2.0", "id": 1, "result": {"isError": False, "content": [{"type": "text", "text": json.dumps(o)}],
                                                       "structuredContent": o}}


class HttpToolsTest(unittest.TestCase):
    def tools(self, **kw):
        self.t = FakeMcp()
        self.slept = []
        return http_tools.HttpTools({"sim": "http://sim"}, "tok", transport=self.t, sleep=self.slept.append, poll_s=5, **kw)

    def test_list_and_call_with_bearer(self):
        t = self.tools()
        self.assertEqual([x["name"] for x in t.list_tools()], ["sim.run", "sim.status"])
        self.assertEqual(self.t.calls[0][:3], ("http://sim", "tok", "tools/list"))

    def test_gate_wait_polls_status_until_done(self):
        t = self.tools()
        self.t.status_seq = [{"state": "waiting for the supervisor"}, {"state": "running"}, {"state": "done", "cpu_hours": 0.4}]
        r = t.call("sim.run", {"spec": {}})
        self.assertEqual((r["state"], r["cpu_hours"]), ("done", 0.4))
        self.assertEqual(self.slept, [5, 5, 5])

    def test_wait_is_bounded(self):
        now = [0.0]
        t = http_tools.HttpTools({"sim": "http://sim"}, "tok", transport=(m := FakeMcp()), sleep=lambda s: now.__setitem__(0, now[0] + s),
                                 clock=lambda: now[0], poll_s=10, wait_s=25)
        m.status_seq = [{"state": "running"}] * 10
        m.ok = staticmethod(lambda o: FakeMcp.ok(o))
        self.assertEqual(t.call("sim.run", {})["state"], "running")

    def test_errors_are_tool_errors(self):
        t = self.tools()
        with self.assertRaisesRegex(loop.ToolError, "refused: x"):
            t._call("sim.boom", {})
        with self.assertRaises(loop.ToolError):
            t._call("lake.x", {})                                   # no server for the prefix
        bad = http_tools.HttpTools({"sim": "http://sim"}, "other", transport=self.t)
        with self.assertRaisesRegex(loop.ToolError, "refused"):
            bad.list_tools()


class FakeSessionAgentPort:
    def __init__(self):
        self.events, self.claimed = [], False

    def post(self, path, body):
        if path == "/claim":
            if body["claim"] != "c" * 43:
                return 403, {}
            return 200, {"token": "tok", "exp": 1}
        self.events.append(body["event"])
        return 200, {"event_id": len(self.events)}


class RunAgentTest(unittest.TestCase):
    ENV = {"MEDCEA_SID": "S" * 22, "MEDCEA_CLAIM": "c" * 43, "MEDCEA_PROFILE": "compare_controllers",
           "MEDCEA_MCP_SIM": "http://sim", "MEDCEA_MCP_LAKE": "http://lake", "MEDCEA_SESSION_URL": "http://s"}

    def test_claims_runs_the_loop_and_stops(self):
        class Mcp:
            def post(self, url, token, msg):
                if msg["method"] == "tools/list":
                    names = ["sim.estimate", "sim.run"] if "sim" in url else ["lake.query"]
                    return 200, {"result": {"tools": [{"name": n, "description": ""} for n in names]}}
                return 200, FakeMcp.ok({"state": "done", "cpu_hours": 0})
        sess = FakeSessionAgentPort()
        rc = run_agent.main(self.ENV, transport=sess, tool_transport=Mcp(), sleep=lambda s: None)
        self.assertEqual(rc, 0)
        self.assertEqual(sess.events[-1], "stop")
        self.assertIn("turn_request", sess.events)

    def test_a_local_profile_goes_through_the_gateway(self):
        env = dict(self.ENV, MEDCEA_PROFILE="compare_controllers_local", MEDCEA_MODEL_GATEWAY="http://model-gateway:8120")
        asked = []
        answers = [{"text": "Plan.", "tool": {"name": "sim.run", "args": {}}, "usage": {"prompt_tokens": 10, "output_tokens": 5}},
                   {"text": "The plan is complete.", "tool": None}]

        def gw(url, token, body, timeout):
            asked.append((url, token, body["sid"], body["turn"], sorted(body["request"]), body["request"]["tools"][0]["inputSchema"]))
            return 200, answers.pop(0)

        class Mcp:
            def post(self, url, token, msg):
                if msg["method"] == "tools/list":
                    names = ["sim.estimate", "sim.run"] if "sim" in url else ["lake.snapshots"]
                    return 200, {"result": {"tools": [{"name": n, "description": "", "inputSchema": {"type": "object", "properties": {"x": {"type": "integer"}}}} for n in names]}}
                return 200, FakeMcp.ok({"state": "done", "cpu_hours": 0})
        sess = FakeSessionAgentPort()
        rc = run_agent.main(env, transport=sess, tool_transport=Mcp(), sleep=lambda s: None, gateway_post=gw)
        self.assertEqual(rc, 0)
        self.assertEqual([a[:4] for a in asked], [("http://model-gateway:8120/v1/turn", "tok", "S" * 22, 1),
                                                 ("http://model-gateway:8120/v1/turn", "tok", "S" * 22, 2)])
        self.assertEqual(asked[0][5], {"type": "object", "properties": {"x": {"type": "integer"}}})
        # the agent wrote no turn_request/turn_response: the gateway does
        self.assertEqual(sess.events, ["tool_call", "tool_result", "stop"])

    def test_a_local_profile_without_a_gateway_exits_2(self):
        sess = FakeSessionAgentPort()
        env = dict(self.ENV, MEDCEA_PROFILE="compare_controllers_local")
        self.assertEqual(run_agent.main(env, transport=sess), 2)

    def test_refused_claim_exits_1(self):
        sess = FakeSessionAgentPort()
        rc = run_agent.main(dict(self.ENV, MEDCEA_CLAIM="x" * 43), transport=sess)
        self.assertEqual(rc, 1)
        self.assertEqual(sess.events, [])

    def test_bad_profile_name(self):
        self.assertEqual(run_agent.main(dict(self.ENV, MEDCEA_PROFILE="../x"), transport=FakeSessionAgentPort()), 2)


class WorkbenchDelivery(unittest.TestCase):
    """R34: the workbench-examples ConfigMap delivers medcea_agent.py, byte-equal to the CLI."""

    EX = os.path.join(ROOT, "k8s", "workbench", "examples")

    def test_byte_equal(self):
        with open(CLI, "rb") as a, open(os.path.join(self.EX, "medcea_agent.py"), "rb") as b:
            self.assertEqual(a.read(), b.read(), "cp research/agents/cli.py k8s/workbench/examples/medcea_agent.py")

    def test_examples_stay_small_and_flat(self):
        names = [n for n in os.listdir(self.EX) if not n.startswith("__")]
        total = sum(os.path.getsize(os.path.join(self.EX, n)) for n in names)
        self.assertLess(total, 200 * 1024)

    def test_orchestrator_default_and_env(self):
        with open(os.path.join(ROOT, "k8s", "workbench", "values-research.yaml")) as f:
            self.assertIn("MEDCEA_ORCHESTRATOR:", f.read())


if __name__ == "__main__":
    unittest.main()
