"""research/agents/replay.py (AH.10): strict replay. Re-runs loop.run with the recorded model
responses and recorded tool results, against a sink that compares every event the loop emits
with the next recorded agent event (request sha256, standing/skill/profile/tools shas, tool
name and args, result digests, checkpoint, stop). Also checks that each recorded tool result
hashes to its recorded digest and, where a server recorded a tool_result for the same call,
that both digests agree. Verdict {ok, first_mismatch, events}; the first divergence ends it.
A stop caused by the clock (wall_h, turn_timeout) is not reproducible by design: the replay
clock never advances.

A scripted session's turn_request/turn_response are the agent's own events. A LOCAL session (4b stage 2,
profile backend local) has none from the agent: the model-gateway (actor `model-gateway`, server port)
records them, so replay takes the model's responses (and usage) from the gateway's turn_response events,
and checks each rebuilt request's sha256 against the gateway's turn_request of the same turn. A gateway
turn_response that records an error (context_full, model_error) makes the replayed model raise the same
ModelError, so the stop reason is reproduced. The agent-side comparison of everything else is unchanged;
live re-generation is not replay (llama.cpp is not batch-invariant)."""
import json

from . import loop
from .context import sha
from .context import canonical
from .model import ModelError, RecordedModel

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


class _GatewayModel:
    """Replay of a local session: the gateway's recorded responses, after checking the request's sha."""
    def __init__(self, pairs, sink):
        self.pairs, self.sink, self.id = pairs, sink, None

    def respond(self, request):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        if n >= len(self.pairs):
            raise Divergence(self.sink.i, "turn_request", "gateway_turn", None, n + 1)
        rq, rs = self.pairs[n]
        got = sha(canonical(request))
        if rq["request_sha256"] != got:
            raise Divergence(self.sink.i, "turn_request", "request_sha256", rq["request_sha256"], got)
        if rs is None:
            raise ModelError("model_error", "no recorded response")
        if "error" in rs:
            raise ModelError(rs["error"])
        out = dict(rs["response"])
        if "usage" in rs:
            out["usage"] = rs["usage"]
        return out


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
    local = profile.get("backend") == "local"
    gw_pairs = []
    if local:
        for e in events:
            if e.get("actor") != "model-gateway":
                continue
            if e["event"] == "turn_request":
                gw_pairs.append([e["payload"], None])
            elif e["event"] == "turn_response" and gw_pairs and gw_pairs[-1][1] is None:
                gw_pairs[-1][1] = e["payload"]
    responses = [r["payload"]["response"] for r in rec if r["event"] == "turn_response"]
    # a refused call (not allowed, malformed) never reaches the tools: the replayed loop does not call them either
    results = [r["payload"] for r in rec if r["event"] == "tool_result" and not _refused(r["payload"])]
    for r in [r["payload"] for r in rec if r["event"] == "tool_result"]:
        idx = next(i for i, x in enumerate(rec) if x["payload"] is r)
        if r["recorded_complete"] and sha(r["result"]) != r["result_sha256"]:
            return _bad(idx, "tool_result", "result_sha256", r["result_sha256"], sha(r["result"]))
        sv = server.get(r["call"])
        if sv and r["result_sha256"] not in sv:
            return _bad(idx, "tool_result", "server_result_sha256", sorted(sv)[0], r["result_sha256"])
    backend = next((r["payload"]["backend"] for r in rec if r["event"] == "turn_request"), None)
    sink = _Sink(rec)
    try:
        model = _GatewayModel(gw_pairs, sink) if local else RecordedModel(responses)
        loop.run(profile, standing, skill, model, _Tools(tool_listing, results), sink, clock=lambda: 0.0, backend_id=backend)
        if sink.i != len(rec):
            raise Divergence(sink.i, rec[sink.i]["event"], "event", rec[sink.i]["event"], None)
    except Divergence as d:
        return {"ok": False, "first_mismatch": d.info, "events": sink.i}
    except (IndexError, KeyError) as e:
        return {"ok": False, "first_mismatch": {"index": sink.i, "event": None, "field": "recorded",
                                                "recorded": None, "replayed": repr(e)}, "events": sink.i}
    return {"ok": True, "first_mismatch": None, "events": sink.i}


def _refused(p):
    if not p.get("error") or not p.get("recorded_complete"):
        return False
    msg = str(json.loads(p["result"]).get("error", ""))
    return msg == "tool not allowed" or msg.startswith("malformed tool call")


def _bad(index, event, field, recorded, replayed):
    return {"ok": False, "first_mismatch": {"index": index, "event": event, "field": field,
                                            "recorded": recorded, "replayed": replayed}, "events": 0}
