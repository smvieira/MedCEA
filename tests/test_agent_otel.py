"""The OpenTelemetry export of a session (research Phase 4e commit A3; design 4.5, OD-4e-11): research/agents/otel.py.

A session's trace as OTLP/JSON (ExportTraceServiceRequest): one trace per session with deterministic ids, the session
span, an invoke_agent span per agent under its parent's, chat spans per turn with the GenAI usage, execute_tool spans
per call (ERROR on a refusal), sim.campaign spans, and gates, proposals, checkpoints and replays as span events. No
content unless asked; never the session token, claim or the supervisor's sub. Shapes: an E58-shaped one-agent session
(a model behind the gateway, a gate, a campaign, a proposal) and a scripted team's trace from A1b's loop."""
import copy
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from research.agents import loop, otel, team  # noqa: E402
from research.agents.model import ScriptedModel  # noqa: E402
from research.agents.trace import TraceClient  # noqa: E402
from test_agent_loop import STANDING, FakeSession, FakeTools  # noqa: E402

SID = "Q" * 22
SUB = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
TOKEN = "rst1.k1.%s.1795000000.%s" % (SID, "m" * 43)
NOTE = "Approved: the estimate looks sound, go ahead."
TEAM_FIXTURE = os.path.join(ROOT, "tests", "fixtures", "agents", "scripted_team.yaml")
CID = "c0123456789abcdef0123"
GEN_AI_1_37 = {     # the GenAI attribute names of semantic conventions v1.37.0 this export may use
    "gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.conversation.id", "gen_ai.agent.id", "gen_ai.agent.name",
    "gen_ai.request.model", "gen_ai.request.max_tokens", "gen_ai.request.temperature", "gen_ai.request.top_k",
    "gen_ai.request.seed", "gen_ai.response.finish_reasons", "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    "gen_ai.tool.name", "gen_ai.tool.call.id", "gen_ai.tool.type", "gen_ai.input.messages", "gen_ai.output.messages",
    "gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}


def at(sec, micro=0):
    return "2026-11-26T10:%02d:%02d.%06d+00:00" % (sec // 60, sec % 60, micro)


def ns(sec, micro=0):
    return str((1795687200 + sec) * 10 ** 9 + micro * 1000)       # 2026-11-26T10:00:00Z = 1795687200


class Rec:
    """Events as research-session's events() returns them, numbered, timed, with a fake hash chain."""
    def __init__(self):
        self.events = []

    def add(self, sec, actor, event, payload, micro=0):
        n = len(self.events) + 1
        self.events.append({"event_id": n, "at": at(sec, micro), "actor": actor, "event": event, "payload": payload,
                            "prev_hash": "%064x" % (n - 1), "hash": "%064x" % n})
        return n


def e58():
    """An E58-shaped session: compare_controllers_gpu on the gpu endpoint through the model-gateway, sim.estimate, a
    gated sim.run approved by the supervisor, the campaign run, a proposal accepted, a refused call, the stop, the
    revocation at the Job's end and a replay verdict."""
    r = Rec()
    gw = lambda sec, ev, pay, micro=0: r.add(sec, "model-gateway", ev, dict(pay, agent="a0"), micro)  # noqa: E731
    flags = {"sampler": {"temperature": 0, "seed": 1}, "endpoint_kind": "openai", "max_tokens": 1024, "ctx": 12288}
    r.add(0, "research-session", "session_minted", {"profile": "compare_controllers_gpu", "profile_sha256": "a" * 64,
                                                    "backend": "gpu", "code_commit": "555c701", "kid": "k1",
                                                    "exp": "2026-11-26T18:00:00+00:00"})
    r.add(5, "research-session", "claim_exchanged", {"peer": "10.1.2.3"})
    texts = ["Plan: estimate first.", "Plan: run it.", "Plan: check status.", "Plan: propose PID.", "Done: PID 30 s."]
    calls = [("sim.estimate", {"spec": {"scenarios": ["smoke"]}}), ("sim.run", {"spec": {"scenarios": ["smoke"]}}),
             ("sim.status", {"cid": CID}), ("propose.parameter_set", {"algorithm_code": "PID", "params": {"cycle_time": 30}})]
    sec = 10
    for i, text in enumerate(texts, 1):
        tool = calls[i - 1] if i <= len(calls) else None
        gw(sec, "turn_request", {"turn": i, "backend": "gpu", "model": "Qwen/Qwen3-14B-AWQ", "model_sha256": "",
                                 "request_sha256": "%064d" % i, "flags": flags}, micro=250000)
        resp = {"text": text, "tool": {"name": tool[0], "args": tool[1]} if tool else None}
        gw(sec + 4, "turn_response", {"turn": i, "response": resp, "response_sha256": "%064d" % (100 + i),
                                      "raw_response_sha256": "f" * 64, "finish_reason": "tool_calls" if tool else "stop",
                                      "usage": {"prompt_tokens": 900 + i, "output_tokens": 40 + i, "estimated": False}},
           micro=750000)
        if tool:
            r.add(sec + 5, "agent", "tool_call", {"turn": i, "call": i, "tool": tool[0], "args_sha256": "%064d" % (200 + i),
                                                  "args": tool[1]})
            if tool[0] == "sim.run":
                r.add(sec + 6, "mcp-sim", "gate_pending", {"gid": CID, "estimate_h": 0.4, "cap_h": 0.55, "runs": 36,
                                                           "spec_sha256": "b" * 64})
                r.add(sec + 30, "research-session", "gate_decided", {"gid": CID, "decision": "approve", "by_sub": SUB,
                                                                     "by_username": "sci", "note": NOTE,
                                                                     "approved_cap_h": 0.5})
                r.add(sec + 31, "mcp-sim", "sim_started", {"cid": CID, "spec_sha256": "b" * 64, "estimate_h": 0.4,
                                                           "cap_h": 0.5, "deadline_s": 1800})
                result, err = {"cid": CID, "state": "started"}, False
            elif tool[0] == "sim.status":
                r.add(sec + 6, "orchestrator", "sim_finished", {"cid": CID, "state": "done", "cpu_hours": 0.11,
                                                                "result_digest": "d" * 64, "cap_h": 0.5})
                r.add(sec + 7, "mcp-sim", "sim_finished", {"cid": CID, "state": "done", "cpu_hours": 0.11,
                                                           "result_digest": "d" * 64, "cap_h": 0.5})
                result, err = {"cid": CID, "state": "done", "cpu_hours": 0.11}, False
            elif tool[0] == "propose.parameter_set":
                result, err = {"proposal": {"algorithm_code": "PID", "params": {"cycle_time": 30}}}, False
            else:
                result, err = {"cpu_hours": 0.4, "runs": 36}, False
            text_r = json.dumps(result, sort_keys=True, separators=(",", ":"))
            r.add(sec + 32 if tool[0] == "sim.run" else sec + 8, "mcp-sim", "tool_result",
                  {"tool": tool[0], "call": 40 + i, "result_sha256": "%064d" % (300 + i), "bytes": len(text_r),
                   "error": err, "agent": "a0", "agent_call": i})
            r.add(sec + 33 if tool[0] == "sim.run" else sec + 9, "agent", "tool_result",
                  {"turn": i, "call": i, "tool": tool[0], "result_sha256": "%064d" % (300 + i), "bytes": len(text_r),
                   "truncated": False, "error": err, "shown_sha256": "e" * 64, "recorded_complete": True,
                   "result": text_r})
            if tool[0].startswith("propose."):
                prop = r.add(sec + 10, "agent", "proposal", {"turn": i, "call": i, "tool": tool[0],
                                                             "result_sha256": "%064d" % (300 + i)})
            if i % 2 == 0:
                r.add(sec + 11 if tool[0] != "sim.run" else sec + 34, "agent", "checkpoint",
                      {"seq": i // 2, "turn": i, "sha256": "c" * 64})
        sec += 60
    # a refused call (a tool outside the profile) on a sixth turn
    gw(sec, "turn_request", {"turn": 6, "backend": "gpu", "model": "Qwen/Qwen3-14B-AWQ", "request_sha256": "%064d" % 6,
                             "flags": flags})
    gw(sec + 1, "turn_response", {"turn": 6, "response": {"text": "Try admin.", "tool": {"name": "admin.drop", "args": {}}},
                                  "response_sha256": "%064d" % 106, "finish_reason": "tool_calls",
                                  "usage": {"prompt_tokens": 950, "output_tokens": 10, "estimated": False}})
    r.add(sec + 2, "agent", "tool_call", {"turn": 6, "call": 5, "tool": "admin.drop", "args_sha256": "0" * 64, "args": {}})
    r.add(sec + 3, "agent", "tool_result", {"turn": 6, "call": 5, "tool": "admin.drop", "result_sha256": "1" * 64,
                                            "bytes": 28, "truncated": False, "error": True, "shown_sha256": "2" * 64,
                                            "recorded_complete": True, "result": '{"error":"tool not allowed"}'})
    stop = r.add(sec + 5, "agent", "stop", {"reason": "finished", "turns": 6, "prompt_tokens": 5600,
                                            "output_tokens": 270, "cpu_hours": 0.11})
    r.add(sec + 20, "research-session", "proposal_decided", {"pid": "p%d" % prop, "decision": "approve",
                                                             "by_sub": SUB, "by_username": "sci", "note": NOTE})
    r.add(sec + 25, "research-session", "session_revoked", {"reason": "job_ended"})
    r.add(sec + 90, "orchestrator", "replay_result", {"ok": True, "events": 40, "first_mismatch": None,
                                                      "code_commit": "555c701"})
    return r.events, {"stop": stop, "prop": prop, "end_sec": sec + 5}


def team_trace():
    """The scripted team of tests/fixtures/agents/scripted_team.yaml run by the loop (commit A1b), framed by the
    session's mint and claim, each event a second after the one before."""
    p = loop.load_profile(TEAM_FIXTURE)
    s = FakeSession()
    tc = TraceClient(s, SID)
    tc.claim("c")
    tools = FakeTools({"sim.run": {"ok": True, "cid": CID, "state": "done", "cpu_hours": 0.25}})
    loop.run(p, STANDING, team.read_skill("team_lead"), ScriptedModel(p["script"]), tools, tc)
    head = [("research-session", "session_minted", {"profile": "scripted_team", "profile_sha256": "a" * 64,
                                                     "backend": "scripted", "code_commit": "abc1234", "kid": "k1"}),
            ("research-session", "claim_exchanged", {"peer": "10.1.2.3"})]
    out = []
    for i, (actor, ev, pay) in enumerate(head + [(e["actor"], e["event"], e["payload"]) for e in s.events], 1):
        out.append({"event_id": i, "at": at(i), "actor": actor, "event": ev, "payload": pay, "hash": "%064x" % i})
    return out, p


def spans_of(doc):
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"]


def attrs(obj):
    out = {}
    for a in obj.get("attributes", []):
        (k, v), = a["value"].items()
        out[a["key"]] = {"intValue": lambda x: int(x), "arrayValue": lambda x: [list(y.values())[0] for y in x["values"]]
                         }.get(k, lambda x: x)(v)
    return out


def by_name(doc, name):
    return [s for s in spans_of(doc) if s["name"] == name]


def one(doc, name):
    found = by_name(doc, name)
    assert len(found) == 1, (name, [s["name"] for s in spans_of(doc)])
    return found[0]


def events_named(span, name):
    return [e for e in span.get("events", []) if e["name"] == name]


class Ids(unittest.TestCase):
    def test_trace_and_span_ids_are_the_designs(self):
        import hashlib
        self.assertEqual(otel.trace_id(SID), hashlib.sha256(("medcea-session:" + SID).encode()).hexdigest()[:32])
        self.assertEqual(otel.span_id(SID, 7), hashlib.sha256((SID + "7").encode()).hexdigest()[:16])
        self.assertNotEqual(otel.span_id(SID, 7), otel.span_id(SID, 7, "a0"))
        self.assertNotEqual(otel.trace_id(SID), otel.trace_id("R" * 22))

    def test_the_same_trace_exports_to_the_same_bytes(self):
        ev, _ = e58()
        a = otel.dumps(otel.export(ev, {"sid": SID}))
        shuffled = list(reversed(copy.deepcopy(ev)))
        self.assertEqual(a, otel.dumps(otel.export(shuffled, {"sid": SID})))
        doc = otel.export(ev, {"sid": SID})
        ids = [s["spanId"] for s in spans_of(doc)]
        self.assertEqual(len(ids), len(set(ids)), "span ids are unique")
        self.assertTrue(all(s["traceId"] == otel.trace_id(SID) for s in spans_of(doc)))

    def test_span_ids_come_from_the_opening_events(self):
        ev, _ = e58()
        doc = otel.export(ev, {"sid": SID})
        root = one(doc, "invoke_agent compare_controllers_gpu")
        self.assertEqual(root["spanId"], otel.span_id(SID, 1))           # session_minted
        self.assertEqual(one(doc, "invoke_agent a0")["spanId"], otel.span_id(SID, 2))     # claim_exchanged
        first_chat = by_name(doc, "chat Qwen/Qwen3-14B-AWQ")[0]
        self.assertEqual(first_chat["spanId"], otel.span_id(SID, 3))     # the first turn_request


class OneAgent(unittest.TestCase):
    def setUp(self):
        self.ev, self.k = e58()
        self.doc = otel.export(self.ev, {"sid": SID, "sup_username": "sci", "sup_role": "control_scientist"})

    def test_the_span_tree(self):
        root = one(self.doc, "invoke_agent compare_controllers_gpu")
        lead = one(self.doc, "invoke_agent a0")
        self.assertNotIn("parentSpanId", root)
        self.assertEqual(lead["parentSpanId"], root["spanId"])
        chats = by_name(self.doc, "chat Qwen/Qwen3-14B-AWQ")
        self.assertEqual(len(chats), 6)
        self.assertTrue(all(c["parentSpanId"] == lead["spanId"] for c in chats))
        names = [s["name"] for s in spans_of(self.doc) if s["name"].startswith("execute_tool")]
        self.assertEqual(names, ["execute_tool sim.estimate", "execute_tool sim.run", "execute_tool sim.status",
                                 "execute_tool propose.parameter_set", "execute_tool admin.drop"])
        self.assertTrue(all(s["parentSpanId"] == lead["spanId"] for s in spans_of(self.doc) if s["name"] in names))
        camp = one(self.doc, "sim.campaign")
        self.assertEqual(camp["parentSpanId"], one(self.doc, "execute_tool sim.run")["spanId"])
        a = attrs(camp)
        self.assertEqual((a["medcea.sim.cid"], a["medcea.cpu_hours"], a["medcea.sim.state"]), (CID, 0.11, "done"))
        self.assertEqual(camp["status"]["code"], otel.STATUS_OK)
        # the second writer's record of the same end is an event, counted once
        self.assertEqual(len(events_named(camp, "sim_finished")), 1)

    def test_timing_from_the_events(self):
        root = one(self.doc, "invoke_agent compare_controllers_gpu")
        self.assertEqual(root["startTimeUnixNano"], ns(0))
        self.assertEqual(root["endTimeUnixNano"], ns(self.k["end_sec"]))     # the lead's stop, before the revocation
        lead = one(self.doc, "invoke_agent a0")
        self.assertEqual((lead["startTimeUnixNano"], lead["endTimeUnixNano"]), (ns(5), ns(self.k["end_sec"])))
        c = by_name(self.doc, "chat Qwen/Qwen3-14B-AWQ")[0]
        self.assertEqual((c["startTimeUnixNano"], c["endTimeUnixNano"]), (ns(10, 250000), ns(14, 750000)))
        run = one(self.doc, "execute_tool sim.run")
        self.assertEqual((run["startTimeUnixNano"], run["endTimeUnixNano"]), (ns(75), ns(103)))
        camp = one(self.doc, "sim.campaign")
        self.assertEqual((camp["startTimeUnixNano"], camp["endTimeUnixNano"]), (ns(101), ns(136)))
        for s in spans_of(self.doc):
            self.assertLessEqual(int(s["startTimeUnixNano"]), int(s["endTimeUnixNano"]), s["name"])

    def test_chat_attributes(self):
        c = attrs(by_name(self.doc, "chat Qwen/Qwen3-14B-AWQ")[0])
        self.assertEqual(c["gen_ai.operation.name"], "chat")
        self.assertEqual(c["gen_ai.request.model"], "Qwen/Qwen3-14B-AWQ")
        self.assertEqual(c["gen_ai.provider.name"], "openai")
        self.assertEqual((c["gen_ai.usage.input_tokens"], c["gen_ai.usage.output_tokens"]), (901, 41))
        self.assertEqual(c["gen_ai.response.finish_reasons"], ["tool_calls"])
        self.assertEqual((c["gen_ai.request.max_tokens"], c["gen_ai.request.temperature"], c["gen_ai.request.seed"]),
                         (1024, 0, 1))
        self.assertEqual(c["gen_ai.conversation.id"], SID)
        self.assertEqual(c["medcea.request.sha256"], "%064d" % 1)
        self.assertEqual(c["medcea.response.sha256"], "%064d" % 101)
        self.assertFalse(c["medcea.usage.estimated"])

    def test_sampler_values_are_doubles_and_seed_an_int(self):
        ev = copy.deepcopy(self.ev)
        for e in ev:
            if e["event"] == "turn_request":
                e["payload"]["flags"] = dict(e["payload"]["flags"], sampler={"temperature": 0, "top_k": 1, "seed": 1})
        c = by_name(otel.export(ev, {"sid": SID}), "chat Qwen/Qwen3-14B-AWQ")[0]
        raw = {a["key"]: a["value"] for a in c["attributes"]}
        # GenAI semantic conventions v1.37.0: temperature and top_k are double, seed and max_tokens int
        self.assertEqual(raw["gen_ai.request.temperature"], {"doubleValue": 0.0})
        self.assertEqual(raw["gen_ai.request.top_k"], {"doubleValue": 1.0})
        self.assertEqual(raw["gen_ai.request.seed"], {"intValue": "1"})
        self.assertEqual(raw["gen_ai.request.max_tokens"], {"intValue": "1024"})

    def test_a_refused_trace_write_says_which_and_why(self):
        ev = copy.deepcopy(self.ev)
        n = len(ev) + 1
        ev.append({"event_id": n, "at": at(400), "actor": "research-session", "event": "trace_refused",
                   "payload": {"port": "agent", "event": "tool_result", "why": "payload over 16 KiB"},
                   "prev_hash": "%064x" % (n - 1), "hash": "%064x" % n})
        root = one(otel.export(ev, {"sid": SID}), "invoke_agent compare_controllers_gpu")
        refused = events_named(root, "trace_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(attrs(refused[0]), {"medcea.trace_refused.port": "agent",
                                             "medcea.trace_refused.event": "tool_result",
                                             "medcea.reason": "payload over 16 KiB"})

    def test_tool_spans_and_a_refusal(self):
        est = one(self.doc, "execute_tool sim.estimate")
        a = attrs(est)
        self.assertEqual((a["gen_ai.operation.name"], a["gen_ai.tool.name"], a["gen_ai.tool.call.id"]),
                         ("execute_tool", "sim.estimate", "1"))
        self.assertEqual(est["status"], {"code": otel.STATUS_UNSET})
        server = events_named(est, "tool_result")
        self.assertEqual(len(server), 1, "mcp-sim's record paired by (agent, agent_call)")
        self.assertEqual(attrs(server[0])["medcea.actor"], "mcp-sim")
        bad = one(self.doc, "execute_tool admin.drop")
        self.assertEqual(bad["status"]["code"], otel.STATUS_ERROR)
        self.assertNotIn("message", bad["status"], "a refusal's text is content")
        self.assertEqual(attrs(bad)["error.type"], "tool_refused")

    def test_gates_proposals_checkpoints_replays_are_span_events(self):
        run = one(self.doc, "execute_tool sim.run")
        self.assertEqual([e["name"] for e in run["events"] if e["name"].startswith("gate")], ["gate_pending", "gate_decided"])
        g = attrs(events_named(run, "gate_decided")[0])
        self.assertEqual((g["medcea.gate.id"], g["medcea.decision"], g["medcea.decided_by"], g["medcea.gate.approved_cap_h"]),
                         (CID, "approve", "sci", 0.5))
        lead = one(self.doc, "invoke_agent a0")
        prop = events_named(lead, "proposal")[0]
        self.assertEqual(attrs(prop)["medcea.proposal.id"], "p%d" % self.k["prop"])
        self.assertEqual(attrs(events_named(lead, "proposal_decided")[0])["medcea.decision"], "approve")
        self.assertEqual(len(events_named(lead, "checkpoint")), 2)
        root = one(self.doc, "invoke_agent compare_controllers_gpu")
        self.assertTrue(attrs(events_named(root, "replay_result")[0])["medcea.replay.ok"])
        self.assertEqual(attrs(events_named(root, "session_revoked")[0])["medcea.revoke.reason"], "job_ended")

    def test_root_and_resource(self):
        root = one(self.doc, "invoke_agent compare_controllers_gpu")
        a = attrs(root)
        self.assertEqual(root["status"]["code"], otel.STATUS_OK)
        self.assertEqual((a["gen_ai.operation.name"], a["gen_ai.agent.name"], a["medcea.stop.reason"]),
                         ("invoke_agent", "compare_controllers_gpu", "finished"))
        self.assertEqual((a["medcea.supervisor.username"], a["medcea.supervisor.role"]), ("sci", "control_scientist"))
        self.assertEqual(a["medcea.backend"], "gpu")
        res = attrs(self.doc["resourceSpans"][0]["resource"])
        self.assertEqual(res["service.name"], "medcea-research-agents")
        self.assertEqual(res["medcea.session.id"], SID)
        self.assertEqual(res["medcea.code_commit"], "555c701")
        n = len(self.ev)
        self.assertEqual(res["medcea.trace.chain_head"], "%d:%064x" % (n, n))
        self.assertIs(res["medcea.export.content"], False)
        self.assertEqual(self.doc["resourceSpans"][0]["schemaUrl"], otel.SCHEMA_URL)
        self.assertEqual(otel.SCHEMA_URL, "https://opentelemetry.io/schemas/" + otel.SEMCONV)

    def test_an_older_cli_decision_names_a_digest_prefix(self):
        ev = copy.deepcopy(self.ev)
        for e in ev:
            if e["event"] == "proposal_decided":
                e["payload"]["pid"] = ("%064d" % 304)[:12]
        lead = one(otel.export(ev, {"sid": SID}), "invoke_agent a0")
        self.assertEqual(len(events_named(lead, "proposal_decided")), 1)

    def test_a_trace_without_an_end_is_incomplete(self):
        ev = [e for e in self.ev if e["event"] not in ("stop", "session_revoked", "replay_result", "proposal_decided")]
        doc = otel.export(ev, {"sid": SID})
        root = one(doc, "invoke_agent compare_controllers_gpu")
        self.assertTrue(attrs(root)["medcea.incomplete"])
        self.assertEqual(root["endTimeUnixNano"], ev[-1]["at"] and str(otel._ns(ev[-1]["at"])))
        self.assertEqual(root["status"]["code"], otel.STATUS_UNSET)

    def test_a_revoked_session_ends_at_the_revocation(self):
        ev = [e for e in self.ev if e["event"] != "stop"]
        root = one(otel.export(ev, {"sid": SID}), "invoke_agent compare_controllers_gpu")
        revoked = next(e for e in ev if e["event"] == "session_revoked")
        self.assertEqual(root["endTimeUnixNano"], str(otel._ns(revoked["at"])))
        self.assertEqual(attrs(root)["medcea.revoke.reason"], "job_ended")

    def test_a_model_error_is_an_error_span(self):
        ev = copy.deepcopy(self.ev)
        for e in ev:
            if e["event"] == "turn_response" and e["payload"]["turn"] == 6:
                e["payload"] = {"agent": "a0", "turn": 6, "error": "context_full", "status": 413}
        c = by_name(otel.export(ev, {"sid": SID}), "chat Qwen/Qwen3-14B-AWQ")[-1]
        self.assertEqual(c["status"], {"code": otel.STATUS_ERROR, "message": "context_full"})
        self.assertEqual(attrs(c)["error.type"], "context_full")

    def test_a_scripted_trace_recorded_before_agent_ids_reads_as_a0(self):
        ev = copy.deepcopy(self.ev)
        for e in ev:
            e["payload"].pop("agent", None)
            e["payload"].pop("agent_call", None)
            if e["actor"] == "model-gateway":
                e["actor"] = "agent"
        doc = otel.export(ev, {"sid": SID})
        lead = one(doc, "invoke_agent a0")
        self.assertEqual(len([s for s in spans_of(doc) if s.get("parentSpanId") == lead["spanId"]]), 11)
        est = one(doc, "execute_tool sim.estimate")
        self.assertEqual(len(events_named(est, "tool_result")), 1, "paired by trace order without agent_call")


class Content(unittest.TestCase):
    SECRET_SESSION = {"sid": SID, "sup_sub": SUB, "sup_person": "person-123", "token": TOKEN, "claim": "C" * 43,
                      "kid": "k1", "token_sha256": "9" * 64, "sup_username": "sci", "sup_role": "control_scientist"}

    def test_no_content_by_default(self):
        ev, _ = e58()
        text = otel.dumps(otel.export(ev, self.SECRET_SESSION)).decode()
        for s in ("Plan: estimate first.", "Done: PID 30 s.", NOTE, "cycle_time", "tool not allowed", "smoke",
                  "Try admin."):
            self.assertNotIn(s, text)
        self.assertNotIn("gen_ai.output.messages", text)
        self.assertNotIn("gen_ai.tool.call.result", text)

    def test_content_when_asked(self):
        ev, _ = e58()
        doc = otel.export(ev, self.SECRET_SESSION, content=True)
        text = otel.dumps(doc).decode()
        for s in ("Plan: estimate first.", NOTE, "cycle_time", "tool not allowed"):
            self.assertIn(s, text)
        c = by_name(doc, "chat Qwen/Qwen3-14B-AWQ")[0]
        out = json.loads(attrs(events_named(c, "gen_ai.output.messages")[0])["gen_ai.output.messages"])
        self.assertEqual(out, [{"role": "assistant", "finish_reason": "tool_calls",
                                "parts": [{"type": "text", "content": "Plan: estimate first."},
                                          {"type": "tool_call", "name": "sim.estimate",
                                           "arguments": {"spec": {"scenarios": ["smoke"]}}}]}])
        t = one(doc, "execute_tool sim.estimate")
        self.assertIn("gen_ai.tool.call.arguments", [e["name"] for e in t["events"]])
        self.assertIs(attrs(events_named(t, "gen_ai.tool.call.result")[0])["medcea.content.complete"], True)
        self.assertIs(attrs(doc["resourceSpans"][0]["resource"])["medcea.export.content"], True)

    def test_never_the_token_claim_or_sub(self):
        ev, _ = e58()
        for content in (False, True):
            text = otel.dumps(otel.export(ev, self.SECRET_SESSION, content=content)).decode()
            for s in (SUB, TOKEN, "C" * 43, "person-123", "9" * 64, "by_sub", "sup_sub", "10.1.2.3", '"k1"'):
                self.assertNotIn(s, text, (content, s))


class Team(unittest.TestCase):
    def setUp(self):
        self.ev, self.p = team_trace()
        self.doc = otel.export(self.ev, {"sid": SID})

    def test_the_team_tree(self):
        root = one(self.doc, "invoke_agent scripted_team")
        lead = one(self.doc, "invoke_agent a0")
        self.assertEqual(lead["parentSpanId"], root["spanId"])
        s1, s2 = one(self.doc, "invoke_agent a0.1"), one(self.doc, "invoke_agent a0.2")
        self.assertEqual((s1["parentSpanId"], s2["parentSpanId"]), (lead["spanId"], lead["spanId"]))
        self.assertEqual((attrs(s1)["gen_ai.agent.name"], attrs(s2)["gen_ai.agent.name"]), ("campaign", "tuning"))
        self.assertEqual((attrs(s1)["gen_ai.agent.id"], attrs(s1)["medcea.agent.parent"]), ("a0.1", "a0"))
        spawned = next(e for e in self.ev if e["event"] == "agent_spawned" and e["payload"]["agent"] == "a0.1")
        returned = next(e for e in self.ev if e["event"] == "agent_returned" and e["payload"]["agent"] == "a0.1")
        self.assertEqual(s1["spanId"], otel.span_id(SID, spawned["event_id"]))
        self.assertEqual((s1["startTimeUnixNano"], s1["endTimeUnixNano"]),
                         (str(otel._ns(spawned["at"])), str(otel._ns(returned["at"]))))
        self.assertEqual(attrs(s1)["medcea.stop.reason"], "finished")
        self.assertEqual(s1["status"]["code"], otel.STATUS_OK)
        # each specialist's turns and calls are under its own span; the lead's delegations under the lead's
        kids = lambda sp: [re.sub(r"^chat scripted:[0-9a-f]+$", "chat scripted", s["name"])  # noqa: E731
                           for s in spans_of(self.doc) if s.get("parentSpanId") == sp["spanId"]]
        self.assertEqual(kids(s1), ["chat scripted", "execute_tool sim.estimate", "chat scripted", "execute_tool sim.run",
                                    "chat scripted"])
        self.assertEqual(kids(s2), ["chat scripted", "execute_tool propose.candidate", "chat scripted"])
        lead_kids = kids(lead)
        self.assertEqual(lead_kids.count("execute_tool team.delegate"), 2)
        self.assertIn("invoke_agent a0.1", lead_kids)
        # a delegation's call spans its specialist
        d1 = by_name(self.doc, "execute_tool team.delegate")[0]
        self.assertLessEqual(int(d1["startTimeUnixNano"]), int(s1["startTimeUnixNano"]))
        self.assertGreaterEqual(int(d1["endTimeUnixNano"]), int(s1["endTimeUnixNano"]))

    def test_the_team_has_no_content_by_default(self):
        text = otel.dumps(self.doc).decode()
        for s in ("Estimate and run fruiting_compare", "Plan: hand the campaign", "Campaign " + CID + " is done"):
            self.assertNotIn(s, text)
        with_content = otel.dumps(otel.export(self.ev, {"sid": SID}, content=True)).decode()
        self.assertIn("Estimate and run fruiting_compare", with_content)

    def test_usage_is_per_agent(self):
        s1 = attrs(one(self.doc, "invoke_agent a0.1"))
        returned = next(e["payload"] for e in self.ev if e["event"] == "agent_returned" and e["payload"]["agent"] == "a0.1")
        self.assertEqual((s1["gen_ai.usage.input_tokens"], s1["gen_ai.usage.output_tokens"], s1["medcea.turns"]),
                         (returned["prompt_tokens"], returned["output_tokens"], returned["turns"]))
        chats = [s for s in spans_of(self.doc) if s["name"].startswith("chat scripted:")]
        self.assertEqual(len(chats), 3 + 3 + 2)      # the lead's turns, campaign's, tuning's
        for c in chats:
            self.assertEqual(attrs(c)["gen_ai.request.model"], c["name"][len("chat "):])
            self.assertTrue(attrs(c)["medcea.usage.estimated"])
            self.assertEqual(attrs(c)["gen_ai.provider.name"], "medcea.scripted")


class Shape(unittest.TestCase):
    """OTLP/JSON's ExportTraceServiceRequest: resourceSpans -> scopeSpans -> spans, ids in hex of 32 and 16 digits,
    times as decimal strings of nanoseconds, enums as numbers, an AnyValue with exactly one field."""
    HEX32, HEX16, DIGITS = re.compile(r"^[0-9a-f]{32}$"), re.compile(r"^[0-9a-f]{16}$"), re.compile(r"^[0-9]+$")

    def check_value(self, v):
        self.assertEqual(len(v), 1, v)
        (k, x), = v.items()
        self.assertIn(k, ("stringValue", "intValue", "doubleValue", "boolValue", "arrayValue"))
        if k == "intValue":
            self.assertRegex(x, self.DIGITS)
        if k == "arrayValue":
            for y in x["values"]:
                self.check_value(y)

    def check(self, doc):
        json.loads(json.dumps(doc))
        self.assertEqual(list(doc), ["resourceSpans"])
        rs = doc["resourceSpans"]
        self.assertEqual(len(rs), 1)
        self.assertEqual(set(rs[0]), {"resource", "scopeSpans", "schemaUrl"})
        for a in rs[0]["resource"]["attributes"]:
            self.check_value(a["value"])
        ss = rs[0]["scopeSpans"]
        self.assertEqual(ss[0]["scope"], {"name": otel.SCOPE, "version": otel.EXPORT_VERSION})
        used = set()
        for s in ss[0]["spans"]:
            self.assertRegex(s["traceId"], self.HEX32)
            self.assertRegex(s["spanId"], self.HEX16)
            if "parentSpanId" in s:
                self.assertRegex(s["parentSpanId"], self.HEX16)
            self.assertRegex(s["startTimeUnixNano"], self.DIGITS)
            self.assertRegex(s["endTimeUnixNano"], self.DIGITS)
            self.assertIn(s["kind"], (otel.KIND_INTERNAL, otel.KIND_CLIENT))
            self.assertIn(s["status"]["code"], (0, 1, 2))
            for a in s["attributes"]:
                self.check_value(a["value"])
                used.add(a["key"])
            for e in s.get("events", []):
                self.assertRegex(e["timeUnixNano"], self.DIGITS)
                for a in e["attributes"]:
                    self.check_value(a["value"])
                    used.add(a["key"])
            keys = {a["key"] for a in s["attributes"]}
            self.assertEqual(len(keys), len(s["attributes"]), "no attribute twice on %s" % s["name"])
        parents = {s["spanId"] for s in ss[0]["spans"]}
        for s in ss[0]["spans"]:
            if "parentSpanId" in s:
                self.assertIn(s["parentSpanId"], parents)
        self.assertEqual(sum(1 for s in ss[0]["spans"] if "parentSpanId" not in s), 1, "one root")
        return used

    def test_shapes_and_attribute_names(self):
        ev, _ = e58()
        tev, _ = team_trace()
        used = set()
        for events in (ev, tev):
            for content in (False, True):
                used |= self.check(otel.export(events, {"sid": SID}, content=content))
        gen_ai = {k for k in used if k.startswith("gen_ai.")}
        self.assertLessEqual(gen_ai, GEN_AI_1_37, sorted(gen_ai - GEN_AI_1_37))
        others = {k for k in used if not k.startswith("gen_ai.")}
        self.assertLessEqual(others, {"error.type"} | {k for k in others if k.startswith("medcea.")})
        # what each kind of span carries
        doc = otel.export(ev, {"sid": SID})
        for s in spans_of(doc):
            a = attrs(s)
            if s["name"].startswith("invoke_agent"):
                self.assertEqual(a["gen_ai.operation.name"], "invoke_agent")
                self.assertEqual(s["name"], "invoke_agent " + (a.get("gen_ai.agent.id") or a["gen_ai.agent.name"]))
            elif s["name"].startswith("chat "):
                self.assertEqual((a["gen_ai.operation.name"], s["kind"]), ("chat", otel.KIND_CLIENT))
                self.assertEqual(s["name"], "chat " + a["gen_ai.request.model"])
            elif s["name"].startswith("execute_tool "):
                self.assertEqual(a["gen_ai.operation.name"], "execute_tool")
                self.assertEqual(s["name"], "execute_tool " + a["gen_ai.tool.name"])

    def test_an_empty_trace(self):
        doc = otel.export([], {"sid": SID})
        self.assertEqual(spans_of(doc), [])
        self.check_value({"stringValue": "x"})

    def test_a_sid_is_required(self):
        with self.assertRaises((KeyError, ValueError)):
            otel.export([], {})

    def test_stdlib_only(self):
        import ast
        with open(otel.__file__, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods.add((n.module or "").split(".")[0])
        self.assertLessEqual(mods, set(sys.stdlib_module_names))


if __name__ == "__main__":
    unittest.main()
