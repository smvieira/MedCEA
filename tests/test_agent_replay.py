"""Strict replay of a recorded scripted session (research/agents/replay.py)."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_agent_loop import FakeTools, PROFILE, SKILL, STANDING, go  # noqa: E402
from research.agents import loop  # noqa: E402
from research.agents.context import sha  # noqa: E402
from research.agents.replay import replay  # noqa: E402

LISTING = FakeTools().list_tools()


def rec():
    _, ev, p = go()
    return ev, p


class Replay(unittest.TestCase):
    def test_it_reproduces_exactly(self):
        ev, p = rec()
        v = replay(ev, p, STANDING, SKILL, LISTING)
        self.assertEqual(v, {"ok": True, "first_mismatch": None, "events": len(ev)})

    def test_server_side_events_are_ignored_unless_they_disagree(self):
        ev, p = rec()
        first = [e for e in ev if e["event"] == "tool_result"][0]["payload"]
        # a server records its tool_result between the agent's tool_call and the agent's tool_result
        at = next(i for i, e in enumerate(ev) if e["event"] == "tool_result")
        srv = {"actor": "mcp-sim", "event": "tool_result", "payload": {"call": 1, "result_sha256": first["result_sha256"]}}
        self.assertTrue(replay(ev[:at] + [srv] + ev[at:], p, STANDING, SKILL, LISTING)["ok"])
        srv["payload"]["result_sha256"] = "0" * 64
        v = replay(ev[:at] + [srv] + ev[at:], p, STANDING, SKILL, LISTING)
        self.assertEqual(v["first_mismatch"]["field"], "server_result_sha256")

    def test_servers_number_their_own_calls_and_polls_add_records(self):
        # E48 (22 Nov 2026): mcp-lake's call 1 and mcp-sim's call 1 were different agent calls, and a
        # sim.run that waits records the sim.status polls too: each agent result is matched inside its window
        ev, p = rec()
        res = [i for i, e in enumerate(ev) if e["event"] == "tool_result"]
        out = list(ev)
        for k, i in reversed(list(enumerate(res))):
            sha = ev[i]["payload"]["result_sha256"]
            out[i:i] = [{"actor": "mcp-x", "event": "tool_result", "payload": {"call": 1, "result_sha256": "f" * 64}},
                        {"actor": "mcp-x", "event": "tool_result", "payload": {"call": 1, "result_sha256": sha}}]
        self.assertTrue(replay(out, p, STANDING, SKILL, LISTING)["ok"])

    def test_a_tampered_tool_result_is_a_divergence(self):
        ev, p = rec()
        ev = copy.deepcopy(ev)
        r = [e for e in ev if e["event"] == "tool_result"][1]["payload"]
        r["result"] = r["result"].replace("true", "false")
        v = replay(ev, p, STANDING, SKILL, LISTING)
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_mismatch"]["event"], "tool_result")
        self.assertEqual(v["first_mismatch"]["field"], "result_sha256")

    def test_a_tampered_digest_and_result_together_changes_the_next_request(self):
        ev, p = rec()
        ev = copy.deepcopy(ev)
        r = [e for e in ev if e["event"] == "tool_result"][0]["payload"]
        r["result"] = '{"ok":false}'
        r["result_sha256"] = sha(r["result"])
        v = replay(ev, p, STANDING, SKILL, LISTING)
        self.assertFalse(v["ok"])
        self.assertIn(v["first_mismatch"]["event"], ("tool_result", "turn_request"))

    def test_a_changed_standing_file_is_a_divergence_at_the_first_request(self):
        ev, p = rec()
        v = replay(ev, p, STANDING + "\nExtra rule.", SKILL, LISTING)
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_mismatch"]["index"], 0)
        self.assertEqual(v["first_mismatch"]["event"], "turn_request")
        self.assertIn(v["first_mismatch"]["field"], ("standing_sha256", "request_sha256", "est_prompt_tokens"))

    def test_a_changed_profile_is_a_divergence(self):
        ev, p = rec()
        p2 = copy.deepcopy(p)
        p2["caps"]["turns"] = 3
        self.assertEqual(replay(ev, p2, STANDING, SKILL, LISTING)["first_mismatch"]["field"], "profile_sha256")

    def test_a_tampered_response_is_a_divergence(self):
        ev, p = rec()
        ev = copy.deepcopy(ev)
        [e for e in ev if e["event"] == "turn_response"][1]["payload"]["response"]["tool"]["args"] = {"spec": "other"}
        v = replay(ev, p, STANDING, SKILL, LISTING)
        self.assertFalse(v["ok"])

    def test_a_truncated_trace_is_a_divergence(self):
        ev, p = rec()
        v = replay(ev[:-1], p, STANDING, SKILL, LISTING)
        self.assertFalse(v["ok"])


# ── a local session: the model's records are the gateway's (actor model-gateway), the agent's are the rest
from test_agent_loop import GatewayStub, LOCAL  # noqa: E402
from research.agents.model import ModelError  # noqa: E402


def rec_local(answers, nudge=False, **runkw):
    from test_agent_loop import go_local
    _, ev, p, gw, skill = go_local(answers, nudge=nudge, **runkw)
    if runkw.get("endpoint"):         # the gateway records the session's endpoint and its context (flags.ctx)
        for e in gw.events:
            if e["event"] == "turn_request":
                e["payload"].update(backend=runkw["endpoint"], flags={"ctx": runkw["endpoint_context"]})
    # interleave as the session would have: the gateway's pair comes before the agent's events of that turn
    out, g = [], list(gw.events)
    pending = []
    for e in ev:
        out.append(e)
    merged, gi = [], 0
    turns = 0
    for e in ev:
        if e["event"] == "tool_call":
            merged += g[gi:gi + 2]
            gi += 2
        merged.append(e)
    merged += g[gi:]
    # the last turn has no tool call: its pair precedes the stop
    stop = [e for e in merged if e["event"] == "stop"]
    merged = [e for e in merged if e["event"] != "stop"] + stop
    return merged, p, skill


LOCAL_ANSWERS = [{"text": "Plan.", "tool": {"name": "sim.run", "args": {"spec": {}}}}, {"text": "The plan is complete."}]


class ReplayLocal(unittest.TestCase):
    def setUp(self):
        self.ev, self.p, self.skill = rec_local(LOCAL_ANSWERS)

    def run_replay(self, ev=None, p=None):
        return replay(ev or self.ev, p or self.p, STANDING, self.skill, LISTING)

    def test_it_reproduces_from_the_gateways_records(self):
        self.assertEqual([e["actor"] for e in self.ev if e["event"] == "turn_response"], ["model-gateway"] * 2)
        v = self.run_replay()
        self.assertEqual(v["ok"], True, v)

    def test_a_nudged_session_reproduces(self):
        ev, p, skill = rec_local([{"text": "I cannot."}, {"text": "", "tool": {"name": "propose.parameter_set", "args": {}}},
                                  {"text": "The plan is complete."}], nudge=True)
        self.assertIn("finish_after", p)
        v = replay(ev, p, STANDING, skill, LISTING)
        self.assertEqual(v["ok"], True, v)

    def test_a_session_on_a_chosen_endpoint_reproduces(self):
        """The model picker: replay takes the endpoint and its context from the gateway's record, so a request the
        profile's own 4000 would stop replays as it ran (on 12,288)."""
        big = {"text": "", "tool": {"name": "sim.run", "args": {"spec": {"x": "y" * 20000}}}}
        ev, p, skill = rec_local([big, {"text": "done"}], endpoint="gpu", endpoint_context=12288)
        self.assertIn("tool_call", [e["event"] for e in ev])
        self.assertEqual(replay(ev, p, STANDING, skill, LISTING)["ok"], True)
        for e in ev:                  # without the record's endpoint the profile's cap stops it at once: a divergence
            if e["event"] == "turn_request":
                e["payload"].pop("backend")
        self.assertFalse(replay(ev, p, STANDING, skill, LISTING)["ok"])

    def test_a_changed_request_is_a_divergence_at_the_gateways_sha(self):
        ev = copy.deepcopy(self.ev)
        [e for e in ev if e["event"] == "turn_request"][1]["payload"]["request_sha256"] = "0" * 64
        v = self.run_replay(ev)
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_mismatch"]["field"], "request_sha256")

    def test_a_changed_response_is_a_divergence(self):
        ev = copy.deepcopy(self.ev)
        [e for e in ev if e["event"] == "turn_response"][0]["payload"]["response"]["tool"]["args"] = {"spec": {"x": 1}}
        self.assertFalse(self.run_replay(ev)["ok"])

    def test_usage_is_replayed(self):
        ev = copy.deepcopy(self.ev)
        [e for e in ev if e["event"] == "turn_response"][0]["payload"]["usage"] = {"prompt_tokens": 99999, "output_tokens": 1}
        # the recorded stop says 110 prompt tokens were spent: a different usage is a different stop payload
        v = self.run_replay(ev)
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_mismatch"]["event"], "stop")

    def test_a_model_error_stop_is_reproduced(self):
        from test_agent_loop import go_local
        _, ev, p, gw, skill = go_local([{"text": "a", "tool": {"name": "sim.run", "args": {}}}, ModelError("context_full")])
        merged = []
        g = list(gw.events)
        for e in ev:
            if e["event"] == "tool_call":
                merged += g[:2]
                g = g[2:]
            if e["event"] == "stop":
                merged += g
            merged.append(e)
        v = replay(merged, p, STANDING, skill, LISTING)
        self.assertTrue(v["ok"], v)
        self.assertEqual(merged[-1]["payload"]["reason"], "context_full")

    def test_a_malformed_call_replays_without_the_tools(self):
        from test_agent_loop import go_local
        _, ev, p, gw, skill = go_local([{"text": "I call it.", "tool": None, "tool_error": "no such tool"},
                                        {"text": "x", "tool": {"name": "sim.run", "args": {}}}, {"text": "done"}])
        merged, g = [], list(gw.events)
        for e in ev:
            if e["event"] == "tool_call":
                merged += g[:2]
                g = g[2:]
            merged.append(e)
        merged = [e for e in merged if e["event"] != "stop"] + g + [e for e in ev if e["event"] == "stop"]
        v = replay(merged, p, STANDING, skill, LISTING)
        self.assertTrue(v["ok"], v)

    def test_scripted_replay_is_unchanged_by_a_gateway_event(self):
        ev, p = rec()
        noise = {"actor": "model-gateway", "event": "turn_request", "payload": {"request_sha256": "0" * 64}}
        self.assertTrue(replay(ev[:1] + [noise] + ev[1:], p, STANDING, SKILL, LISTING)["ok"])


if __name__ == "__main__":
    unittest.main()
