"""medcea-agent (research/agents/cli.py), the agent's HTTP tool client and the Job entrypoint (stage 6a)."""
import ast
import io
import json
import os
import sys
import contextlib
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
            return 201, {"sid": "S" * 22, "endpoint": (body or {}).get("endpoint", "local")}
        if path == "/api/sessions" and method == "GET":
            return 200, {"sessions": [], "endpoints": [
                {"name": "local", "model": "qwen3-4b", "context": 4096, "deterministic": True, "where": "this host (CPU)"},
                {"name": "gpu", "model": "Qwen/Qwen3-14B-AWQ", "context": 12288, "deterministic": True, "where": "another server"}]}
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

    def test_the_model_picker(self):
        """Research Phase 4d: endpoints() lists the models; start(profile, endpoint=) asks for one."""
        c, o, out, clk = client()
        c.signin()
        self.assertEqual([e["name"] for e in c.endpoints()], ["local", "gpu"])
        r = c.start("compare_controllers_local", endpoint="gpu")
        self.assertEqual(o.calls[-1][2], {"profile": "compare_controllers_local", "endpoint": "gpu"})
        self.assertEqual(r["endpoint"], "gpu")
        c.start("compare_controllers_local")
        self.assertNotIn("endpoint", o.calls[-1][2])
        c2, o2, out2, _ = client()
        cli.main(["endpoints"], client=c2)
        self.assertTrue(any(l.startswith("gpu ") and "Qwen/Qwen3-14B-AWQ" in l and "12288 tokens" in l for l in out2), out2)
        c3, o3, out3, _ = client()
        cli.main(["start", "compare_controllers_local", "--endpoint", "gpu"], client=c3)
        self.assertEqual(o3.calls[-1][2]["endpoint"], "gpu")
        self.assertIn("started on gpu", out3[-1])

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

    def test_watch_says_what_the_model_chose_and_collapses_the_status_checks(self):
        c, o, out, clk = client()
        c.signin()
        status = lambda i: {"event_id": i, "event": "tool_result", "actor": "mcp-sim", "payload": {"tool": "sim.status"}}
        o.events = [{"event_id": 1, "event": "turn_response", "actor": "model-gateway",
                     "payload": {"turn": 1, "response": {"tool": {"name": "sim.run", "args": {}}},
                                 "usage": {"prompt_tokens": 10, "output_tokens": 2}}},
                    {"event_id": 2, "event": "tool_call", "actor": "agent", "payload": {"tool": "sim.run", "args": {"spec": {}}}},
                    {"event_id": 3, "event": "tool_result", "actor": "mcp-sim", "payload": {"tool": "sim.run"}},
                    status(4), status(5),
                    {"event_id": 6, "event": "sim_finished", "actor": "mcp-sim", "payload": {"state": "done", "cpu_hours": 0.1}},
                    status(7),
                    {"event_id": 8, "event": "tool_result", "actor": "agent",
                     "payload": {"tool": "propose.parameter_set", "result": '{"error":"FLC {} does not do better"}'}},
                    {"event_id": 9, "event": "tool_result", "actor": "agent", "payload": {
                        "tool": "propose.parameter_set", "result": json.dumps({"proposal": {
                            "algorithm_code": "MPC", "params": {}, "check": {
                                "criterion": "air_temperature.rmsd_mid", "proposed_mean": 0.112, "proposed_runs": 6,
                                "compared": [{"code": "FLC", "params": {}, "other": 0.1135, "outcome": "better"}]}}})}},
                    {"event_id": 10, "event": "stop", "actor": "agent", "payload": {"reason": "finished", "turns": 3}}]
        self.assertEqual(c.watch("S" * 22), "stop")
        text = "\n".join(out)
        self.assertIn("turn 1: calls sim.run  [10 prompt, 2 out tokens]", text)
        self.assertIn('sim.run {"spec":{}}', text)
        self.assertIn("... 3 status check(s)", text)
        self.assertNotIn("(mcp-sim's record", text)
        self.assertIn("propose.parameter_set refused: FLC {} does not do better", text)
        self.assertIn("accepted: MPC {} on air_temperature.rmsd_mid, mean 0.112 over 6 run(s); compared: FLC {} 0.1135 (better)", text)
        before = len(out)
        o.events = o.events[2:5]
        c.watch("S" * 22, verbose=True)
        self.assertEqual(sum("mcp-sim" in line for line in out[before:]), 3)

    def test_line_names_the_proposal_id_and_a_sub_agent(self):
        # research Phase 4e (design 2.2): accept/discard take p<event_id>, which watch prints next to the proposal
        line = cli.Client.line({"event_id": 42, "event": "proposal", "actor": "agent",
                                "payload": {"agent": "a0", "tool": "propose.parameter_set", "result_sha256": "ab" * 32}})
        self.assertIn("(medcea-agent accept|discard SID p42)", line)
        self.assertNotIn("[a0]", line)
        line = cli.Client.line({"event_id": 43, "event": "proposal_decided", "actor": "research-session",
                                "payload": {"pid": "p42", "decision": "approve", "by_username": "bio"}})
        self.assertIn("p42 accepted by bio", line)
        line = cli.Client.line({"event_id": 44, "event": "tool_call", "actor": "agent",
                                "payload": {"agent": "a0.1", "parent": "a0", "tool": "sim.run"}})
        self.assertIn("[a0.1] sim.run", line)
        line = cli.Client.line({"event_id": 45, "event": "agent_spawned", "actor": "agent",
                                "payload": {"agent": "a0.1", "parent": "a0", "profile_name": "analyst", "task": "t"}})
        self.assertIn("[a0.1] a0 starts analyst: t", line)

    def test_watch_shows_the_team(self):
        # research Phase 4e A1b: a specialist's stop does not end the watch; its lines are indented; the team at the end
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_agent_team import run_team
        _, ev, _ = run_team()
        c, o, out, clk = client()
        c.signin()
        o.events = [dict(e, actor="agent") for e in ev]
        self.assertEqual(c.watch("S" * 22), "stop")
        text = "\n".join(out)
        self.assertEqual(sum(1 for line in out if " stop " in line), 3)        # both specialists' stops and the lead's
        self.assertTrue(out[-2].split()[1] == "stop" and "[a0." not in out[-2])
        self.assertIn("  [a0.1] a0 starts campaign: Estimate and run fruiting_compare.", text)
        self.assertIn('[a0.1] back to a0: finished after 3 turns, 0.25 CPU-h: "Campaign c0123456789abcdef0123 is done."', text)
        self.assertEqual(out[-1].strip(), "team: a0 (lead); a0.1 campaign (finished after 3 turns, 0.25 CPU-h); "
                                          "a0.2 tuning (finished after 2 turns, 0.0 CPU-h)")
        self.assertEqual([m["specialist"] for m in cli.Client.team(ev)], ["campaign", "tuning"])
        self.assertEqual(cli.Client.team([]), [])
        self.assertTrue(cli.Client.lead_stopped({"event": "stop", "payload": {}}))
        self.assertFalse(cli.Client.lead_stopped({"event": "stop", "payload": {"agent": "a0.1", "parent": "a0"}}))

    def test_turns_are_the_leads(self):
        ev = [{"actor": "model-gateway", "event": "turn_request", "payload": {"turn": 1, "request_sha256": "a"}},
              {"actor": "model-gateway", "event": "turn_request", "payload": {"agent": "a0.1", "turn": 1, "request_sha256": "b"}},
              {"actor": "model-gateway", "event": "turn_response", "payload": {"agent": "a0", "turn": 1, "response_sha256": "r"}}]
        self.assertEqual(cli.Client.turns(ev), {1: ("a", "r", None)})

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

    def test_replay_waits_out_the_moment_between_the_stop_and_the_job_end(self):
        # E58, 26 Nov 2026: watch returns at the agent's stop, the orchestrator counts the session as running until it
        # sees the Job end, and the replay asked in between was refused with 409.
        c, o, out, clk = client()
        c.signin()
        base, left = o.request, [2]

        def req(m, p, b=None, t=None):
            if p.endswith("/replay") and left[0]:
                left[0] -= 1
                return 409, {"error": "the session is still running: replay it after it has stopped"}
            return base(m, p, b, t)
        o.request = req
        o.events = [{"event_id": 9, "event": "stop", "actor": "agent", "payload": {"reason": "finished"}}]
        self.assertEqual(c.replay("S" * 22, poll_s=2)["ok"], True)
        self.assertEqual(left[0], 0)
        # without a stop in the record the session is really at work: refused at once, no waiting
        c, o, out, clk = client()
        c.signin()
        o.request = lambda m, p, b=None, t=None: ((409, {"error": "the session is still running: replay it after it has stopped"})
                                                  if p.endswith("/replay") else FakeOrch.request(o, m, p, b, t))
        t0 = clk.t
        with self.assertRaises(cli.CliError) as e:
            c.replay("S" * 22)
        self.assertIn("still running", str(e.exception))
        self.assertEqual(clk.t, t0)

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


def _gw(turn, req, resp, t0, t1):
    return [{"event_id": turn * 10, "at": "2026-11-23T10:00:%02d+00:00" % t0, "actor": "model-gateway", "event": "turn_request",
             "payload": {"turn": turn, "request_sha256": req}},
            {"event_id": turn * 10 + 1, "at": "2026-11-23T10:00:%02d+00:00" % t1, "actor": "model-gateway",
             "event": "turn_response", "payload": {"turn": turn, "response_sha256": resp}}]


class ReexecuteTest(unittest.TestCase):
    """E49's re-execution measurement: answers compared only while the requests are the same."""
    def test_same_requests_same_answers(self):
        a = _gw(1, "r1", "a1", 0, 5) + _gw(2, "r2", "a2", 6, 9)
        r = cli.Client.compare_turns(a, list(a))
        self.assertEqual((r["turns_compared"], r["same_answers"], r["rate"], r["ended"]), (2, 2, 1.0, None))
        self.assertEqual(r["seconds"]["first"], [5.0, 3.0])

    def test_a_different_answer_to_the_same_request(self):
        r = cli.Client.compare_turns(_gw(1, "r1", "a1", 0, 1) + _gw(2, "r2", "a2", 2, 3),
                                     _gw(1, "r1", "a1", 0, 1) + _gw(2, "r2", "XX", 2, 3))
        self.assertEqual((r["same_answers"], r["rate"], r["first_different_answer"]), (1, 0.5, 2))

    def test_a_changed_request_ends_the_comparison(self):
        r = cli.Client.compare_turns(_gw(1, "r1", "a1", 0, 1) + _gw(2, "r2", "a2", 2, 3),
                                     _gw(1, "r1", "a1", 0, 1) + _gw(2, "rX", "a2", 2, 3))
        self.assertEqual((r["turns_compared"], r["ended"]["turn"]), (1, 2))

    def test_agent_events_are_not_the_models(self):
        ev = [{"event_id": 1, "actor": "agent", "event": "turn_request", "payload": {"turn": 1, "request_sha256": "x"}}]
        self.assertEqual(cli.Client.compare_turns(ev, ev)["turns_compared"], 0)


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
                   {"text": "The plan is complete.", "tool": None},
                   {"text": "Still complete.", "tool": None}]       # nudged once (finish_after), then no_tool_call

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
                                                 ("http://model-gateway:8120/v1/turn", "tok", "S" * 22, 2),
                                                 ("http://model-gateway:8120/v1/turn", "tok", "S" * 22, 3)])
        self.assertEqual(asked[0][5], {"type": "object", "properties": {"x": {"type": "integer"}}})
        # the agent wrote no turn_request/turn_response: the gateway does
        self.assertEqual(sess.events, ["tool_call", "tool_result", "stop"])

    def test_a_profile_asks_only_its_own_servers(self):
        # gate_check names sim tools only: mcp-lake refuses its token (another audience), and listing it
        # killed the agent before its first turn (E48, 23 Nov 2026)
        asked = []

        class Mcp:
            def post(self, url, token, msg):
                asked.append(url)
                if "lake" in url:
                    return 401, None
                if msg["method"] == "tools/list":
                    return 200, {"result": {"tools": [{"name": n, "description": ""} for n in
                                                      ("sim.estimate", "sim.run", "sim.status", "sim.results")]}}
                return 200, FakeMcp.ok({"state": "done", "cpu_hours": 0})
        sess = FakeSessionAgentPort()
        rc = run_agent.main(dict(self.ENV, MEDCEA_PROFILE="gate_check"), transport=sess, tool_transport=Mcp(),
                            sleep=lambda s: None)
        self.assertEqual(rc, 0)
        self.assertFalse([u for u in asked if "lake" in u])
        self.assertEqual(sess.events[-1], "stop")

    def test_a_refused_tool_listing_exits_1_with_a_message(self):
        class Mcp:
            def post(self, url, token, msg):
                return 401, None
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = run_agent.main(self.ENV, transport=FakeSessionAgentPort(), tool_transport=Mcp(), sleep=lambda s: None)
        self.assertEqual(rc, 1)
        self.assertIn("the tool servers could not be used", err.getvalue())

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
