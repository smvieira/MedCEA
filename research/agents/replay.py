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
live re-generation is not replay (llama.cpp is not batch-invariant).

Agents (research Phase 4e, design 2.1): a sub-agent's agent-port payloads name it (a0.1 ... ) and its parent;
the lead's (a0) carry no `agent` key, and a payload without one is the lead's, so a trace recorded before compares
as a one-agent session (the comparison reads an absent `agent` as a0 on both sides) and a one-agent session
recorded now still replays under the code before. Model responses are taken per agent. A server's
tool_result is paired with the agent's call by (agent, agent_call) when the server recorded the agent's key
(params._meta), else by trace order (the records between the agent's tool_call and its tool_result). A
mismatch names its agent (first_mismatch.agent)."""
import json

from . import loop
from .context import sha
from .context import canonical
from .model import ModelError, RecordedModel

AGENT = ("turn_request", "turn_response", "tool_call", "tool_result", "checkpoint", "proposal", "stop",
         "agent_spawned", "agent_returned")
LEAD = loop.LEAD


def agent_of(payload):
    """The agent a payload belongs to: its `agent`, else the lead (every trace recorded before agent ids)."""
    a = payload.get("agent") if isinstance(payload, dict) else None
    return a if isinstance(a, str) else LEAD


class Divergence(Exception):
    def __init__(self, index, event, field, recorded, replayed, agent=LEAD):
        self.info = {"index": index, "event": event, "field": field, "recorded": recorded, "replayed": replayed,
                     "agent": agent}


def _norm(payload):
    """An absent agent is the lead: a trace recorded before agent ids compares equal to the loop's a0 payloads."""
    p = dict(payload)
    p.setdefault("agent", LEAD)
    return p


class _Sink:
    def __init__(self, recorded):
        self.rec, self.i = recorded, 0

    def post(self, event, payload):
        if self.i >= len(self.rec):
            raise Divergence(self.i, event, "event", None, event, agent_of(payload))
        r = self.rec[self.i]
        if r["event"] != event:
            raise Divergence(self.i, event, "event", r["event"], event, agent_of(r["payload"]))
        rp, pp = _norm(r["payload"]), _norm(payload)
        for k in sorted(set(rp) | set(pp)):
            if rp.get(k) != pp.get(k):
                raise Divergence(self.i, event, k, rp.get(k), pp.get(k), agent_of(r["payload"]))
        self.i += 1


class _GatewayModel:
    """Replay of a local session: the gateway's recorded responses, per agent, after checking the request's sha."""
    accepts_agent = True

    def __init__(self, pairs, sink):
        self.pairs = pairs if isinstance(pairs, dict) else {LEAD: pairs}
        self.sink, self.id = sink, None

    def respond(self, request, agent=LEAD):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        mine = self.pairs.get(agent, [])
        if n >= len(mine):
            raise Divergence(self.sink.i, "turn_request", "gateway_turn", None, n + 1, agent)
        rq, rs = mine[n]
        got = sha(canonical(request))
        if rq["request_sha256"] != got:
            raise Divergence(self.sink.i, "turn_request", "request_sha256", rq["request_sha256"], got, agent)
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
    # The servers' own tool_result records, per agent call (agent, call). A server that recorded the agent's key
    # (agent, agent_call from params._meta, research Phase 4e) is paired by it. Otherwise (a trace from before, a
    # server that did not get the key) by trace order: the records between the agent's tool_call and its
    # tool_result. A server numbers its calls itself (mcp-lake's call 1 and mcp-sim's call 1 are two calls), and
    # the agent's client polls sim.status while a run waits, so one agent call can have several server records;
    # the agent's result must be one of them (E48, 22 Nov 2026).
    server, open_call = {}, None
    for e in events:
        pl = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        if e.get("actor") == "agent" and e["event"] == "tool_call":
            open_call = (agent_of(pl), pl.get("call"))
            server.setdefault(open_call, set())
        elif e.get("actor") == "agent" and e["event"] == "tool_result":
            open_call = None
        elif e["event"] == "tool_result" and e.get("actor") != "agent":
            ac = pl.get("agent_call")
            if isinstance(ac, int) and not isinstance(ac, bool):
                server.setdefault((agent_of(pl), ac), set()).add(pl.get("result_sha256"))
            elif open_call is not None:
                server[open_call].add(pl.get("result_sha256"))
    local = loop.through_gateway(profile)
    gw_pairs = {}
    gw_first = None
    if local:
        for e in events:
            if e.get("actor") != "model-gateway":
                continue
            mine = gw_pairs.setdefault(agent_of(e["payload"]), [])
            if e["event"] == "turn_request":
                mine.append([e["payload"], None])
                gw_first = gw_first or e["payload"]
            elif e["event"] == "turn_response" and mine and mine[-1][1] is None:
                mine[-1][1] = e["payload"]
    responses = {}
    for r in rec:
        if r["event"] == "turn_response":
            responses.setdefault(agent_of(r["payload"]), []).append(r["payload"]["response"])
    # a refused call (not allowed, malformed) never reaches the tools: the replayed loop does not call them either
    results = [r["payload"] for r in rec if r["event"] == "tool_result" and not _refused(r["payload"])]
    for r in [r["payload"] for r in rec if r["event"] == "tool_result"]:
        idx = next(i for i, x in enumerate(rec) if x["payload"] is r)
        if r["recorded_complete"] and sha(r["result"]) != r["result_sha256"]:
            return _bad(idx, "tool_result", "result_sha256", r["result_sha256"], sha(r["result"]), agent_of(r))
        sv = server.get((agent_of(r), r["call"]))
        if sv and r["result_sha256"] not in sv:
            return _bad(idx, "tool_result", "server_result_sha256", sorted(sv)[0], r["result_sha256"], agent_of(r))
    backend = next((r["payload"]["backend"] for r in rec if r["event"] == "turn_request"), None)
    sink = _Sink(rec)
    try:
        model = _GatewayModel(gw_pairs, sink) if local else RecordedModel(responses)
        # the endpoint the session ran on and its context, from the gateway's first record (the model picker)
        first = gw_first or {}
        ep, ctx = first.get("backend"), (first.get("flags") or {}).get("ctx")
        loop.run(profile, standing, skill, model, _Tools(tool_listing, results), sink, clock=lambda: 0.0, backend_id=backend,
                 **({"endpoint": ep, "endpoint_context": ctx} if ep else {}))
        if sink.i != len(rec):
            raise Divergence(sink.i, rec[sink.i]["event"], "event", rec[sink.i]["event"], None,
                             agent_of(rec[sink.i]["payload"]))
    except Divergence as d:
        return {"ok": False, "first_mismatch": d.info, "events": sink.i}
    except (IndexError, KeyError) as e:
        at = rec[sink.i]["payload"] if sink.i < len(rec) else {}
        return {"ok": False, "first_mismatch": {"index": sink.i, "event": None, "field": "recorded",
                                                "recorded": None, "replayed": repr(e), "agent": agent_of(at)},
                "events": sink.i}
    return {"ok": True, "first_mismatch": None, "events": sink.i}


def _refused(p):
    if not p.get("error") or not p.get("recorded_complete"):
        return False
    msg = str(json.loads(p["result"]).get("error", ""))
    return msg == "tool not allowed" or msg.startswith("malformed tool call")


def _bad(index, event, field, recorded, replayed, agent=LEAD):
    return {"ok": False, "first_mismatch": {"index": index, "event": event, "field": field,
                                            "recorded": recorded, "replayed": replayed, "agent": agent}, "events": 0}
