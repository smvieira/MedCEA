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


if __name__ == "__main__":
    unittest.main()
