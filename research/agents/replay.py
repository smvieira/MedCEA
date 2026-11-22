"""research/agents/replay.py (AH.10): strict replay. Re-runs loop.run with the recorded model
responses and recorded tool results, against a sink that compares every event the loop emits
with the next recorded agent event (request sha256, standing/skill/profile/tools shas, tool
name and args, result digests, checkpoint, stop). Also checks that each recorded tool result
hashes to its recorded digest and, where a server recorded a tool_result for the same call,
that both digests agree. Verdict {ok, first_mismatch, events}; the first divergence ends it.
A stop caused by the clock (wall_h, turn_timeout) is not reproducible by design: the replay
clock never advances."""
import json

from . import loop
from .context import sha
from .model import RecordedModel

AGENT = ("turn_request", "turn_response", "tool_call", "tool_result", "checkpoint", "proposal", "stop")


class Divergence(Exception):
    def __init__(self, index, event, field, recorded, replayed):
        self.info = {"index": index, "event": event, "field": field, "recorded": recorded, "replayed": replayed}


class _Sink:
    def __init__(self, recorded):
        self.rec, self.i = recorded, 0

    def post(self, event, payload):
        if self.i >= len(self.rec):
            raise Divergence(self.i, event, "event", None, event)
        r = self.rec[self.i]
        if r["event"] != event:
            raise Divergence(self.i, event, "event", r["event"], event)
        for k in sorted(set(r["payload"]) | set(payload)):
            if r["payload"].get(k) != payload.get(k):
                raise Divergence(self.i, event, k, r["payload"].get(k), payload.get(k))
        self.i += 1


class _Tools:
    def __init__(self, listing, results):
        self.listing, self.results, self.n = listing, results, 0

    def list_tools(self):
        return self.listing

    def call(self, name, args):
        r = self.results[self.n]
        self.n += 1
        if r["error"]:
            raise loop.ToolError(json.loads(r["result"]).get("error", ""))
        return json.loads(r["result"])


def replay(events, profile, standing, skill, tool_listing):
    rec = [{"event": e["event"], "payload": e["payload"]} for e in events if e.get("actor") == "agent" and e["event"] in AGENT]
    # The servers' own tool_result records, per agent call: those between the agent's tool_call and its
    # tool_result, in trace order. A server numbers its calls itself (mcp-lake's call 1 and mcp-sim's call 1
    # are two calls), and the agent's client polls sim.status while a run waits, so one agent call can have
    # several server records; the agent's result must be one of them (E48, 22 Nov 2026).
    server, open_call = {}, None
    for e in events:
        pl = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        if e.get("actor") == "agent" and e["event"] == "tool_call":
            open_call = pl.get("call")
            server[open_call] = set()
        elif e.get("actor") == "agent" and e["event"] == "tool_result":
            open_call = None
        elif e["event"] == "tool_result" and open_call is not None:
            server[open_call].add(pl.get("result_sha256"))
    responses = [r["payload"]["response"] for r in rec if r["event"] == "turn_response"]
    results = [r["payload"] for r in rec if r["event"] == "tool_result"]
    for n, r in enumerate(results):
        idx = next(i for i, x in enumerate(rec) if x["payload"] is r)
        if r["recorded_complete"] and sha(r["result"]) != r["result_sha256"]:
            return _bad(idx, "tool_result", "result_sha256", r["result_sha256"], sha(r["result"]))
        sv = server.get(r["call"])
        if sv and r["result_sha256"] not in sv:
            return _bad(idx, "tool_result", "server_result_sha256", sorted(sv)[0], r["result_sha256"])
    backend = next((r["payload"]["backend"] for r in rec if r["event"] == "turn_request"), None)
    sink = _Sink(rec)
    try:
        loop.run(profile, standing, skill, RecordedModel(responses), _Tools(tool_listing, results), sink,
                 clock=lambda: 0.0, backend_id=backend)
        if sink.i != len(rec):
            raise Divergence(sink.i, rec[sink.i]["event"], "event", rec[sink.i]["event"], None)
    except Divergence as d:
        return {"ok": False, "first_mismatch": d.info, "events": sink.i}
    except (IndexError, KeyError) as e:
        return {"ok": False, "first_mismatch": {"index": sink.i, "event": None, "field": "recorded",
                                                "recorded": None, "replayed": repr(e)}, "events": sink.i}
    return {"ok": True, "first_mismatch": None, "events": sink.i}


def _bad(index, event, field, recorded, replayed):
    return {"ok": False, "first_mismatch": {"index": index, "event": event, "field": field,
                                            "recorded": recorded, "replayed": replayed}, "events": 0}
