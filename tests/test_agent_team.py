"""Agent teams (research Phase 4e commit A1b; design 2.1, OD-4e-4, OD-4e-5): research/agents/team.py.

team.delegate {specialist, task} runs a specialist of the profile's `team:` as sub-agent a0.N, sequentially, inside
the agent loop: never wider than its lead (tools a subset, caps no larger than the lead's remaining), on the
session's one budget, bracketed by agent_spawned/agent_returned, its answer returned to the lead as a tool result.
A scripted team runs offline; its trace replays, and a mismatch names the agent it is in. A one-agent session's
trace is the trace commit A1a wrote, byte for byte."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from research.agents import context, loop, team  # noqa: E402
from research.agents.context import canonical, sha  # noqa: E402
from research.agents.model import ScriptedModel  # noqa: E402
from research.agents.replay import replay  # noqa: E402
from research.agents.trace import TraceClient  # noqa: E402
from test_agent_loop import A, PROFILE, STANDING, FakeSession, FakeTools  # noqa: E402

TEAM = os.path.join(ROOT, "tests", "fixtures", "agents", "scripted_team.yaml")
SHIPPED = os.path.join(A, "profiles", "compare_controllers_team.yaml")
LEAD_SKILL = team.read_skill("team_lead")
CID = "c0123456789abcdef0123"
RESULTS = {"sim.run": {"ok": True, "cid": CID, "state": "done", "cpu_hours": 0.25}}
A1A = "a4d8de0"          # commit A1a: agent ids, before teams


def tools():
    return FakeTools(dict(RESULTS))


def run_team(p=None, t=None, model=None, **kw):
    p = p or loop.load_profile(TEAM)
    s = FakeSession()
    tc = TraceClient(s, "S" * 22)
    tc.claim("c")
    reason = loop.run(p, STANDING, LEAD_SKILL, model or ScriptedModel(p["script"]), t or tools(), tc, **kw)
    return reason, s.events, p


def of(events, agent, event=None):
    return [e for e in events if e["payload"].get("agent", "a0") == agent and (event is None or e["event"] == event)]


def edited(**team_changes):
    """The fixture's profile, its team changed and checked again as load_profile checks it."""
    p = copy.deepcopy(loop.load_profile(TEAM))
    for k, v in team_changes.items():
        p["team"][k] = v
    team.check_profile(p)
    return p


class Profiles(unittest.TestCase):
    def test_the_shipped_team_profile(self):
        p = loop.load_profile(SHIPPED)
        self.assertEqual((p["name"], p["backend"], sorted(p["team"])), ("compare_controllers_team", "scripted",
                                                                         ["campaign", "tuning"]))
        for name, s in p["team"].items():
            self.assertTrue(os.path.isfile(os.path.join(A, "skills", s["skill"] + ".md")), name)
            self.assertLessEqual(set(s["tools"]), set(p["tools"]) - {loop.TEAM_TOOL})
            for step in s["script"]:
                if step.get("tool"):
                    self.assertIn(step["tool"], s["tools"], name)
            for k, v in s.get("caps", {}).items():
                self.assertLessEqual(v, p["caps"][k])
        # the campaign and the proposal are compare_controllers' own (estimated and checked by tests/test_mcp_sim.py)
        cc = loop.load_profile(os.path.join(A, "profiles", "compare_controllers.yaml"))
        spec = next(s for s in cc["script"] if s.get("tool") == "sim.estimate")["args"]["spec"]
        self.assertEqual([s["args"]["spec"] for s in p["team"]["campaign"]["script"] if s.get("tool")], [spec] * 3)
        prop = next(s for s in cc["script"] if s.get("tool") == "propose.parameter_set")["args"]
        self.assertEqual(p["team"]["tuning"]["script"][0]["args"], prop)

    def test_the_shipped_team_runs_offline_and_replays(self):
        p = loop.load_profile(SHIPPED)
        listing = [{"name": n, "description": n} for n in p["tools"] if n != loop.TEAM_TOOL]

        class T(FakeTools):
            def list_tools(self):
                return listing
        reason, ev, _ = run_team(p, T(dict(RESULTS, **{"lake.snapshots": {"snapshots": []}})))
        self.assertEqual(reason, "finished")
        self.assertEqual([e["payload"]["agent"] for e in ev if e["event"] == "agent_spawned"], ["a0.1", "a0.2"])
        prop = of(ev, "a0.2", "tool_call")[0]["payload"]["args"]
        self.assertEqual((prop["evidence"], prop["criterion"]), ([CID], "air_temperature.rmsd_mid"))
        self.assertEqual(replay(ev, p, STANDING, LEAD_SKILL, listing), {"ok": True, "first_mismatch": None, "events": len(ev)})

    def test_the_rules(self):
        base = loop.load_profile(TEAM)
        spec = base["team"]["campaign"]
        bad = {
            "a tool the lead lacks": dict(spec, tools=["sim.estimate", "admin.drop"]),
            "a specialist delegates": dict(spec, tools=["sim.run", loop.TEAM_TOOL]),
            "a cap above the lead's": dict(spec, caps={"cpu_hours": 3}),
            "not a cap": dict(spec, caps={"tokens": 3}),
            "no script on a scripted team": {k: v for k, v in spec.items() if k != "script"},
            "no skill": {k: v for k, v in spec.items() if k != "skill"},
            "an unknown key": dict(spec, team={}),
            "finish_after outside its tools": dict(spec, finish_after=["propose.candidate"]),
        }
        for why, s in bad.items():
            with self.assertRaises(ValueError, msg=why):
                edited(campaign=s)
        with self.assertRaises(ValueError):
            edited(**{"Bad-Name": spec})
        p = copy.deepcopy(base)
        p["tools"].remove(loop.TEAM_TOOL)
        with self.assertRaisesRegex(ValueError, "lists team.delegate"):
            team.check_profile(p)
        p = copy.deepcopy(base)
        del p["team"]
        with self.assertRaisesRegex(ValueError, "only to a profile with a team"):
            team.check_profile(p)
        p = copy.deepcopy(base)
        p["team"] = {"s%d" % i: spec for i in range(team.MAX_SPECIALISTS + 1)}
        with self.assertRaises(ValueError):
            team.check_profile(p)


class Delegation(unittest.TestCase):
    def test_events_and_parents(self):
        reason, ev, _ = run_team()
        self.assertEqual(reason, "finished")
        # the lead writes no agent key (its trace is the one-agent trace); every specialist event names it and a0
        for e in of(ev, "a0"):
            self.assertNotIn("agent", e["payload"])
        for a in ("a0.1", "a0.2"):
            mine = of(ev, a)
            self.assertTrue(mine)
            self.assertTrue(all(e["payload"]["parent"] == "a0" for e in mine))
            kinds = [e["event"] for e in mine]
            self.assertEqual((kinds[0], kinds[-2], kinds[-1]), ("agent_spawned", "stop", "agent_returned"))
        # sequential: a0.1's events, then a0.2's, each between the lead's tool_call and its tool_result
        order = [e["payload"].get("agent", "a0") for e in ev]
        first, last = order.index("a0.1"), len(order) - 1 - order[::-1].index("a0.1")
        self.assertLess(last, order.index("a0.2"))
        self.assertEqual((ev[first - 1]["event"], ev[last + 1]["event"]), ("tool_call", "tool_result"))
        self.assertEqual(ev[first - 1]["payload"]["tool"], loop.TEAM_TOOL)
        # agent_spawned: who, what, from where
        sp = of(ev, "a0.1", "agent_spawned")[0]["payload"]
        self.assertEqual((sp["profile_name"], sp["task"]), ("campaign", "Estimate and run fruiting_compare. Say which campaign you ran."))
        self.assertEqual(sp["task_sha256"], sha(sp["task"]))
        tr = of(ev, "a0.1", "turn_request")[0]["payload"]
        for k in ("profile_sha256", "skill_sha256", "tools_sha256"):
            self.assertEqual(sp[k], tr[k], k)
        self.assertEqual(sp["skill_sha256"], sha(team.read_skill("team_campaign")))

    def test_the_answer_returns_to_the_lead(self):
        _, ev, _ = run_team()
        ret = of(ev, "a0.1", "agent_returned")[0]["payload"]
        res = json.loads(ret["result"])
        self.assertEqual(res, {"agent": "a0.1", "specialist": "campaign", "stop_reason": "finished", "turns": 3,
                               "answer": "Campaign %s is done." % CID, "cid": CID})
        lead = [e["payload"] for e in of(ev, "a0", "tool_result")]
        self.assertEqual(lead[0]["result_sha256"], ret["result_sha256"])
        self.assertEqual(json.loads(lead[0]["result"]), res)
        self.assertFalse(lead[0]["error"])
        # the lead named the campaign in its next task, and the tuning specialist used it as evidence
        self.assertIn(CID, of(ev, "a0.2", "agent_spawned")[0]["payload"]["task"])
        self.assertEqual(of(ev, "a0.2", "tool_call")[0]["payload"]["args"]["evidence"], [CID])
        self.assertEqual(len(of(ev, "a0.2", "proposal")), 1)

    def test_the_answer_is_bounded(self):
        p = edited(campaign=dict(loop.load_profile(TEAM)["team"]["campaign"],
                                 script=[{"text": "x" * 1900}]))
        _, ev, _ = run_team(p)
        r = of(ev, "a0", "tool_result")[0]["payload"]
        res = json.loads(r["result"])
        # shortened below ANSWER_MAX until the whole result fits in what the lead is shown
        self.assertLess(len(res["answer"]), team.ANSWER_MAX)
        self.assertGreater(len(res["answer"]), team.ANSWER_MAX - 120)
        self.assertFalse(r["truncated"])
        self.assertEqual(set(res), {"agent", "answer", "specialist", "stop_reason", "turns"})

    def test_a_long_answer_never_cuts_the_handle_from_the_lead(self):
        # about 976 characters with quotes, backslashes and < > &: JSON and the wrapper's escaping lengthen it, and
        # sorted first, it would push cid, specialist, stop_reason and turns past what the lead is shown
        body = ('He said "done" at <step> & C:\\run; ' * 40)[:976 - len(" Campaign @last_cid ran.")]
        steps = loop.load_profile(TEAM)["team"]["campaign"]["script"]
        p = edited(campaign=dict(loop.load_profile(TEAM)["team"]["campaign"],
                                 script=steps[:2] + [{"text": body + " Campaign @last_cid ran."}]))
        _, ev, _ = run_team(p)
        r = of(ev, "a0", "tool_result")[0]["payload"]
        self.assertFalse(r["truncated"])
        res = json.loads(r["result"])
        self.assertEqual((res["cid"], res["specialist"], res["stop_reason"], res["turns"]),
                         (CID, "campaign", "finished", 3))
        self.assertTrue(res["answer"])
        text = canonical(res).decode("utf-8")
        self.assertLessEqual(len(text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")),
                             context.SHOWN_MAX)
        self.assertEqual(r["result_sha256"], of(ev, "a0.1", "agent_returned")[0]["payload"]["result_sha256"])
        # the lead's next task names the campaign
        self.assertIn(CID, of(ev, "a0.2", "agent_spawned")[0]["payload"]["task"])

    def test_a_refused_delegation_is_a_refused_call(self):
        for args in ({"specialist": "nobody", "task": "t"}, {"specialist": "campaign", "task": ""},
                     {"specialist": "campaign", "task": "t", "extra": 1}, {"specialist": "campaign"}):
            p = copy.deepcopy(loop.load_profile(TEAM))
            p["script"] = [{"tool": loop.TEAM_TOOL, "args": args}, p["script"][0], {"text": "done"}]
            reason, ev, _ = run_team(p)
            self.assertEqual(reason, "finished")
            first = of(ev, "a0", "tool_result")[0]["payload"]
            self.assertTrue(first["error"], args)
            self.assertIn("team.delegate takes {specialist, task}", first["result"])
            # no id was spent on it: the next delegation is a0.1
            self.assertEqual([e["payload"]["agent"] for e in ev if e["event"] == "agent_spawned"], ["a0.1"])

    def test_the_tools_and_the_listing(self):
        t = tools()
        _, ev, _ = run_team(t=t)
        self.assertEqual([c[0] for c in t.calls], ["sim.estimate", "sim.run", "propose.candidate"])
        lead_tools = of(ev, "a0", "turn_request")[0]["payload"]["tools_sha256"]
        listed = {x["name"]: x for x in FakeTools().list_tools()}
        listed[loop.TEAM_TOOL] = team.Team(loop.load_profile(TEAM), FakeTools(), None, None, "", "a0", {}, None,
                                           None, None, None, None).entry()
        self.assertEqual(lead_tools, sha(canonical(loop.tool_spec(loop.load_profile(TEAM)["tools"], listed, False))))
        self.assertIn("campaign: estimates a campaign", listed[loop.TEAM_TOOL]["description"])
        self.assertEqual(listed[loop.TEAM_TOOL]["inputSchema"]["properties"]["specialist"]["enum"], ["campaign", "tuning"])

    def test_a_specialist_outside_its_tools_is_refused(self):
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["team"]["tuning"]["script"] = [{"tool": "sim.run", "args": {}}, {"text": "x"}]       # the lead's tool, not its
        t = tools()
        _, ev, _ = run_team(p, t)
        r = of(ev, "a0.2", "tool_result")[0]["payload"]
        self.assertTrue(r["error"])
        self.assertIn("tool not allowed", r["result"])
        self.assertEqual([c[0] for c in t.calls], ["sim.estimate", "sim.run"])     # the campaign specialist's only


class ChildNeverWider(unittest.TestCase):
    def test_caps_are_never_above_the_leads_remaining(self):
        _, ev, p = run_team()
        lead = p["caps"]
        used = {"turns": 0, "prompt_tokens": 0, "output_tokens": 0, "cpu_hours": 0.0}
        for e in ev:
            pl = e["payload"]
            if e["event"] == "agent_spawned":
                caps = pl["caps"]
                for k in team.STATIC_CAPS:
                    self.assertLessEqual(caps[k], lead[k])
                for k in team.SHARED_CAPS:
                    self.assertLessEqual(caps[k], lead[k] - used[k] + 1e-9, (pl["agent"], k))
                self.assertLessEqual(caps["turns"], p["team"][pl["profile_name"]]["caps"]["turns"])
            elif e["event"] == "turn_request":
                used["turns"] += 1
                used["prompt_tokens"] += pl["est_prompt_tokens"]
            elif e["event"] == "turn_response":
                used["output_tokens"] += pl["usage"]["output_tokens"]
            elif e["event"] == "tool_result" and pl.get("tool") == "sim.run":
                used["cpu_hours"] += json.loads(pl["result"])["cpu_hours"]
        tuning = of(ev, "a0.2", "agent_spawned")[0]["payload"]["caps"]
        self.assertEqual(tuning["cpu_hours"], 1.75)        # 2 less the campaign's 0.25

    def test_child_profile_refuses_a_wider_want(self):
        lead = loop.load_profile(TEAM)
        with self.assertRaises(ValueError):
            loop.child_profile(lead, {"tools": ["admin.drop"]})
        with self.assertRaises(ValueError):
            loop.child_profile(lead, {"caps": {"cpu_hours": 5}})
        # what team.py builds a specialist's profile from is never wider either
        t = team.Team(lead, FakeTools(), None, None, "", "a0", dict(lead["caps"]), loop.new_shared(),
                      lambda: {"turns": 3, "prompt_tokens": 100, "output_tokens": 10, "cpu_hours": 0.5}, None, None, None)
        caps = t._child_caps(lead["team"]["campaign"])
        self.assertEqual((caps["turns"], caps["prompt_tokens"], caps["output_tokens"], caps["cpu_hours"]), (3, 100, 10, 0.5))

    def test_no_budget_left_refuses_the_delegation(self):
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["caps"]["turns"] = 1          # the delegation is the lead's last turn: nothing left for a specialist
        reason, ev, _ = run_team(p)
        self.assertEqual(reason, "turns")
        r = of(ev, "a0", "tool_result")[0]["payload"]
        self.assertTrue(r["error"])
        self.assertIn("no turns left", r["result"])
        self.assertFalse([e for e in ev if e["event"] == "agent_spawned"])

    def test_a_specialist_does_not_delegate(self):
        _, ev, _ = run_team()
        for a in ("a0.1", "a0.2"):
            self.assertNotIn(loop.TEAM_TOOL, [e["payload"]["tool"] for e in of(ev, a, "tool_call")])
        p = loop.load_profile(TEAM)
        self.assertNotIn("team", p["team"]["campaign"])


class SharedBudget(unittest.TestCase):
    def test_the_leads_stop_counts_the_whole_session(self):
        _, ev, _ = run_team()
        stop = of(ev, "a0", "stop")[0]["payload"]
        responses = [e["payload"]["usage"] for e in ev if e["event"] == "turn_response"]
        self.assertEqual(stop["prompt_tokens"], sum(u["prompt_tokens"] for u in responses))
        self.assertEqual(stop["output_tokens"], sum(u["output_tokens"] for u in responses))
        self.assertEqual(stop["cpu_hours"], 0.25)          # the campaign the specialist ran, once
        kid = of(ev, "a0.1", "stop")[0]["payload"]
        mine = [e["payload"]["usage"]["prompt_tokens"] for e in of(ev, "a0.1", "turn_response")]
        self.assertEqual((kid["prompt_tokens"], kid["cpu_hours"]), (sum(mine), 0.25))
        ret = of(ev, "a0.1", "agent_returned")[0]["payload"]
        self.assertEqual((ret["prompt_tokens"], ret["cpu_hours"], ret["turns"]), (kid["prompt_tokens"], 0.25, kid["turns"]))

    def test_a_campaign_seen_again_by_the_lead_is_counted_once(self):
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["script"].insert(1, {"tool": "sim.run", "args": {"spec": "fruiting_compare"}})   # the lead reads the same cid
        _, ev, _ = run_team(p)
        self.assertEqual(of(ev, "a0", "stop")[0]["payload"]["cpu_hours"], 0.25)

    def test_a_specialist_spending_the_budget_stops_the_lead(self):
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["caps"]["prompt_tokens"] = 1200      # the campaign specialist gets what is left and spends it
        reason, ev, _ = run_team(p)
        self.assertEqual(reason, "prompt_tokens")
        kid = of(ev, "a0.1", "stop")[0]["payload"]
        self.assertEqual(kid["reason"], "prompt_tokens")
        sp = of(ev, "a0.1", "agent_spawned")[0]["payload"]
        first = of(ev, "a0", "turn_request")[0]["payload"]["est_prompt_tokens"]
        self.assertEqual(sp["caps"]["prompt_tokens"], 1200 - first)
        self.assertFalse([e for e in ev if e["event"] == "agent_spawned" and e["payload"]["agent"] == "a0.2"])

    def test_the_session_turns_are_shared(self):
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["caps"]["turns"] = 4          # lead turn 1, then at most 3 for the campaign specialist, then nothing
        reason, ev, _ = run_team(p)
        self.assertEqual(of(ev, "a0.1", "agent_spawned")[0]["payload"]["caps"]["turns"], 3)
        self.assertEqual(reason, "turns")
        self.assertEqual(len([e for e in ev if e["event"] == "turn_request"]), 4)

    def test_the_wall_clock_is_the_leads(self):
        now = [0.0]
        p = copy.deepcopy(loop.load_profile(TEAM))
        p["script"].insert(0, {"tool": "lake.query", "args": {}})

        class Slow(FakeTools):
            def call(self, name, args):
                now[0] += {"lake.query": 3000, "sim.estimate": 1000}.get(name, 0)
                return FakeTools.call(self, name, args)
        # the specialist starts 3000 s into the lead's hour: its own hour has 2600 s left when its estimate takes
        # 1000 s, but the lead's hour has ended, and so has the specialist's
        reason, ev, _ = run_team(p, Slow(dict(RESULTS)), clock=lambda: now[0])
        self.assertEqual(of(ev, "a0.1", "stop")[0]["payload"]["reason"], "wall_h")
        self.assertEqual(reason, "wall_h")


class Replay(unittest.TestCase):
    LISTING = FakeTools().list_tools()

    def test_a_team_trace_replays(self):
        _, ev, p = run_team()
        self.assertEqual(replay(ev, p, STANDING, LEAD_SKILL, self.LISTING),
                         {"ok": True, "first_mismatch": None, "events": len(ev)})

    def test_a_tampered_specialist_answer_names_the_specialist(self):
        _, ev, p = run_team()
        ev = copy.deepcopy(ev)
        r = of(ev, "a0.2", "turn_response")[0]["payload"]
        r["response"]["tool"]["args"]["controller"] = "flc"
        v = replay(ev, p, STANDING, LEAD_SKILL, self.LISTING)
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_mismatch"]["agent"], "a0.2")

    def test_a_tampered_specialist_result_names_the_specialist(self):
        _, ev, p = run_team()
        ev = copy.deepcopy(ev)
        r = of(ev, "a0.1", "tool_result")[1]["payload"]
        r["result"] = r["result"].replace("0.25", "0.5")
        v = replay(ev, p, STANDING, LEAD_SKILL, self.LISTING)
        self.assertEqual((v["ok"], v["first_mismatch"]["agent"], v["first_mismatch"]["field"]),
                         (False, "a0.1", "result_sha256"))

    def test_a_changed_team_is_a_changed_lead_profile(self):
        _, ev, p = run_team()
        q = copy.deepcopy(p)
        q["team"]["tuning"]["caps"]["turns"] = 2        # the team is part of the lead's profile, and of its digest
        v = replay(ev, q, STANDING, LEAD_SKILL, self.LISTING)
        self.assertEqual((v["first_mismatch"]["event"], v["first_mismatch"]["agent"], v["first_mismatch"]["field"]),
                         ("turn_request", "a0", "profile_sha256"))

    def test_a_changed_skill_file_names_the_specialist(self):
        _, ev, p = run_team()
        orig = team.read_skill
        try:
            team.read_skill = lambda n: orig(n) + ("\nAnother rule." if n == "team_tuning" else "")
            v = replay(ev, p, STANDING, LEAD_SKILL, self.LISTING)
        finally:
            team.read_skill = orig
        self.assertEqual((v["first_mismatch"]["agent"], v["first_mismatch"]["field"]), ("a0.2", "skill_sha256"))

    def test_a_cut_trace_names_the_agent_it_stops_in(self):
        _, ev, p = run_team()
        at = next(i for i, e in enumerate(ev) if e["event"] == "agent_returned")
        v = replay(ev[:at], p, STANDING, LEAD_SKILL, self.LISTING)
        self.assertFalse(v["ok"])
        self.assertEqual((v["first_mismatch"]["event"], v["first_mismatch"]["agent"]), ("agent_returned", "a0.1"))

    def test_server_records_of_a_specialists_call(self):
        _, ev, p = run_team()
        call = of(ev, "a0.1", "tool_result")[1]["payload"]
        srv = {"actor": "mcp-sim", "event": "tool_result",
               "payload": {"call": 1, "agent": "a0.1", "agent_call": call["call"], "result_sha256": call["result_sha256"]}}
        self.assertTrue(replay(ev + [srv], p, STANDING, LEAD_SKILL, self.LISTING)["ok"])
        srv["payload"]["result_sha256"] = "0" * 64
        v = replay(ev + [srv], p, STANDING, LEAD_SKILL, self.LISTING)
        self.assertEqual((v["first_mismatch"]["field"], v["first_mismatch"]["agent"]), ("server_result_sha256", "a0.1"))


class AgentGateway:
    """A model endpoint serving several agents, writing the turn records the model-gateway writes (with the agent)."""
    accepts_agent = True
    id = "gateway"

    def __init__(self, answers):
        self.answers, self.events = {a: list(x) for a, x in answers.items()}, []

    def respond(self, request, agent="a0"):
        a = self.answers[agent].pop(0)
        turn = sum(1 for m in request["messages"] if m["role"] == "assistant") + 1
        base = {} if agent == "a0" else {"agent": agent}
        self.events.append({"actor": "model-gateway", "event": "turn_request",
                            "payload": dict(base, turn=turn, backend="local", request_sha256=sha(canonical(request)))})
        usage = {"prompt_tokens": 100, "output_tokens": 10}
        self.events.append({"actor": "model-gateway", "event": "turn_response",
                            "payload": dict(base, turn=turn, response=a, usage=usage)})
        return dict(a, usage=usage)


class LocalTeam(unittest.TestCase):
    """A team on a model endpoint: one model client serves every agent (told which asks), the gateway's records
    carry the agent, and replay pairs them per agent."""

    def profile(self):
        p = loop.load_profile(os.path.join(A, "profiles", "compare_controllers_local.yaml"))
        p.pop("finish_after", None)
        p["tools"] = [loop.TEAM_TOOL] + p["tools"]
        p["team"] = {"campaign": {"skill": "team_campaign", "tools": ["sim.estimate", "sim.run"], "caps": {"turns": 3}}}
        team.check_profile(p)
        return p

    def test_it_runs_and_replays(self):
        p = self.profile()
        gw = AgentGateway({
            "a0": [{"text": "Hand it over.", "tool": {"name": loop.TEAM_TOOL,
                                                      "args": {"specialist": "campaign", "task": "Run it."}}},
                   {"text": "Done.", "tool": None}],
            "a0.1": [{"text": "Run.", "tool": {"name": "sim.run", "args": {}}}, {"text": "Ran %s." % CID, "tool": None}]})
        s = FakeSession()
        tc = TraceClient(s, "S" * 22)
        tc.claim("c")
        skill = team.read_skill(p["skill"])
        self.assertEqual(loop.run(p, STANDING, skill, gw, tools(), tc), "finished")
        self.assertEqual([e["payload"].get("agent", "a0") for e in gw.events if e["event"] == "turn_request"],
                         ["a0", "a0.1", "a0.1", "a0"])
        self.assertFalse([e for e in s.events if e["event"] in ("turn_request", "turn_response")])
        self.assertEqual(of(s.events, "a0", "stop")[0]["payload"]["prompt_tokens"], 400)    # every agent's usage
        listing = FakeTools().list_tools()
        ev = s.events + gw.events
        self.assertTrue(replay(ev, p, STANDING, skill, listing)["ok"])
        bad = copy.deepcopy(ev)
        next(e for e in bad if e["actor"] == "model-gateway" and e["event"] == "turn_request"
             and e["payload"].get("agent") == "a0.1")["payload"]["request_sha256"] = "0" * 64
        v = replay(bad, p, STANDING, skill, listing)
        self.assertEqual((v["first_mismatch"]["field"], v["first_mismatch"]["agent"]), ("request_sha256", "a0.1"))


# The one-agent trace through the agent code of commit A1a and through this tree: byte for byte the same events.
_RUN = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from research.agents import loop
from research.agents.model import ScriptedModel
class Sink:
    def __init__(self): self.ev = []
    def post(self, event, payload):
        self.ev.append([event, payload]); return len(self.ev)
class Tools:
    def list_tools(self):
        return [{"name": n, "description": n} for n in ("sim.estimate", "sim.run", "sim.status", "sim.results",
                "lake.query", "lake.snapshots", "propose.candidate", "propose.parameter_set")]
    def call(self, name, args):
        if name == "sim.run":
            return {"ok": True, "cid": "c0123456789abcdef0123", "state": "done", "cpu_hours": 0.25}
        return {"ok": True}
class Gw:
    id = "gateway"
    def __init__(self): self.n = 0
    def respond(self, request):
        self.n += 1
        if self.n == 1:
            return {"text": "Run.", "tool": {"name": "sim.run", "args": {}}, "usage": {"prompt_tokens": 900, "output_tokens": 20}}
        return {"text": "Done.", "tool": None, "usage": {"prompt_tokens": 950, "output_tokens": 5}}
p = loop.load_profile(sys.argv[2])
std, sk = open(sys.argv[3]).read(), open(sys.argv[4]).read()
s = Sink()
r = loop.run(p, std, sk, Gw() if p["backend"] != "scripted" else ScriptedModel(p["script"]), Tools(), s)
print(json.dumps([r, s.ev], sort_keys=True))
'''


class OneAgentUnchanged(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        d = os.path.join(cls.tmp, "research", "agents")
        os.makedirs(d)
        try:
            for f in ("__init__.py", "loop.py", "context.py", "model.py", "trace.py"):
                out = subprocess.run(["git", "-C", ROOT, "show", "%s:research/agents/%s" % (A1A, f)],
                                     capture_output=True, check=True).stdout
                with open(os.path.join(d, f), "wb") as fh:
                    fh.write(out)
        except (OSError, subprocess.CalledProcessError):
            raise unittest.SkipTest("commit %s is not in this checkout" % A1A)
        with open(os.path.join(cls.tmp, "research", "__init__.py"), "w"):
            pass

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def trace(self, root, profile, skill):
        out = subprocess.run([sys.executable, "-I", "-c", _RUN, root, profile, os.path.join(A, "policy", "standing.md"),
                              os.path.join(A, "skills", skill + ".md")], capture_output=True, check=True, text=True)
        return out.stdout

    def test_the_trace_is_a1as(self):
        for profile, skill in ((PROFILE, "controller_campaign"),
                               (os.path.join(A, "profiles", "compare_controllers.yaml"), "controller_campaign"),
                               (os.path.join(A, "profiles", "compare_controllers_local.yaml"), "controller_campaign_local")):
            old, new = self.trace(self.tmp, profile, skill), self.trace(ROOT, profile, skill)
            self.assertTrue(json.loads(new)[1])
            self.assertEqual(old, new, os.path.basename(profile))


if __name__ == "__main__":
    unittest.main()
