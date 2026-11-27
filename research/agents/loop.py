"""research/agents/loop.py (AH.1, AH.7, AH.9): the agent loop. One turn = turn_request ->
model -> turn_response -> [tool_call -> tool_result [-> proposal]] -> [checkpoint]; the loop
ends with exactly one `stop {reason}`. Every cap of the profile is enforced here and the
stop is traced. The loop knows nothing of HTTP: `trace` has post(event, payload), `tools`
has list_tools() -> [{name, description}] and call(name, args) -> dict (raising ToolError;
call(name, args, meta={agent, call}) when it says accepts_meta), `model` has respond(request)
-> {text, tool} (respond(request, agent=...) when it says accepts_agent). Every payload the loop
writes carries the agent id (research Phase 4e). Strict replay (replay.py) drives this same
function with recorded responses and results."""
import re
import time

import yaml

from .context import Context, canonical, sha, wrap_result
from .model import ModelError, ScriptedModel

TEXT_MAX = 2000
ARGS_MAX = 2000
RECORD_MAX = 6000
# A tool's refusal as the agent keeps it: the same length mcp-sim records (mcp_common clean_text(e, 300)), so the agent's
# tool_result and the server's hash the same text and replay matches them (until 26 Nov 2026 the agent kept 200: a
# longer refusal, such as the proposal check's, failed replay on server_result_sha256 and lost its end)
ERROR_MAX = 300
LOCAL_CONTEXT_MAX = 4096     # owner decision of 21 Nov 2026: a local session is about 4k tokens of context
BACKENDS = ("scripted", "local")         # local = the endpoint on this host; any endpoint name works the same way
ENDPOINT_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
# Agent ids (research Phase 4e, design 2.1, AH.9): the lead is a0, its sub-agents a0.1, a0.2, theirs a0.1.1; depth at
# most 3. Every agent-port payload carries `agent` (and a sub-agent's also `parent`); a payload without it, as every
# trace recorded before, reads as a0. `turn` and `call` count per agent: (agent, call) is a call's key. The id is never
# part of the model request, so request digests do not move.
AGENT_RE = re.compile(r"^a0(\.[1-9][0-9]{0,2}){0,3}$")
LEAD = "a0"


def agent_ok(agent, parent=None):
    """True for a valid (agent, parent) pair: the lead without a parent, a sub-agent with the agent one level up."""
    if not isinstance(agent, str) or not AGENT_RE.match(agent):
        return False
    if agent == LEAD:
        return parent is None
    return isinstance(parent, str) and AGENT_RE.match(parent) is not None and agent.rsplit(".", 1)[0] == parent


def through_gateway(profile):
    """True when the profile's answers come from a model endpoint through the model-gateway: any backend but
    'scripted' (research Phase 4d: the backend names an endpoint of apps/research-model/endpoints.yaml)."""
    return profile.get("backend") != "scripted"
CAPS = ("turns", "prompt_tokens", "output_tokens", "cpu_hours", "wall_h", "turn_timeout_s", "context_tokens")
# optional caps.reserve_tokens: room kept for the answer. Through the gateway the next request is projected in the
# model's own tokens (its last prompt_tokens over the loop's estimate for that request), so a turn whose answer would
# run into the end of the context is not started (E49, 25 Nov 2026: a proposal cut off by the context end)


MALFORMED = "invalid_call"
# profile.finish_after: tools of which one must have succeeded before an answer without a tool call ends the session.
# Earlier, such an answer is answered with NUDGE (a user message, part of the next request and its sha) at most
# profile.nudges times (default 1), then the session stops with reason no_tool_call. E49 (25 Nov 2026): the local
# model said "I cannot make multiple tool calls" on turn 2 and the session counted as finished with nothing run.
NUDGE = ("The task is not finished: no %s has succeeded yet. Continue with exactly one tool call; "
         "a refused call can be corrected and tried again.")


class ToolError(Exception):
    pass


def load_profile(path):
    with open(path, encoding="utf-8") as f:
        p = yaml.safe_load(f)
    if not isinstance(p, dict) or not isinstance(p.get("backend"), str) or not ENDPOINT_RE.match(p["backend"]):
        raise ValueError("profile: a mapping with backend scripted or an endpoint name (local, ...) is required")
    caps = p.get("caps") or {}
    for k in CAPS:
        if not isinstance(caps.get(k), (int, float)) or isinstance(caps.get(k), bool) or caps[k] <= 0:
            raise ValueError("profile: caps.%s must be a positive number" % k)
    if not p.get("tools") or not all(isinstance(t, str) for t in p["tools"]):
        raise ValueError("profile: tools must be a list of names")
    r = caps.get("reserve_tokens", 0)
    if not isinstance(r, int) or isinstance(r, bool) or not 0 <= r < caps["context_tokens"]:
        raise ValueError("profile: caps.reserve_tokens must be a whole number below caps.context_tokens")
    if p["backend"] == "local" and caps["context_tokens"] > LOCAL_CONTEXT_MAX:
        raise ValueError("profile: a local session's caps.context_tokens is at most %d" % LOCAL_CONTEXT_MAX)
    if through_gateway(p) and not (isinstance(p.get("task"), str) and 0 < len(p["task"]) <= 2000):
        raise ValueError("profile: a model profile needs a task (the first user message, at most 2000 characters)")
    fa = p.get("finish_after", [])
    if not isinstance(fa, list) or not all(isinstance(t, str) and t in p["tools"] for t in fa):
        raise ValueError("profile: finish_after must list tools of the profile")
    n = p.get("nudges", 1)
    if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 3:
        raise ValueError("profile: nudges is a whole number from 0 to 3")
    if p["backend"] == "scripted" and not isinstance(p.get("script"), list):
        raise ValueError("profile: a scripted profile needs a script")
    return p


CONTEXT_MARGIN = 96    # the local profile's 4000 of llama-server's 4096: room for the chat template's own tokens


def context_cap(profile, endpoint=None, endpoint_context=None):
    """The context cap of a session (the model picker, research Phase 4d): the profile's caps.context_tokens on its own
    endpoint; on another endpoint the scientist chose, that endpoint's context less CONTEXT_MARGIN (at most 4096 for
    local). Replay computes it from the gateway's record (backend, flags.ctx) with this same function."""
    if endpoint is None or endpoint == profile.get("backend") or not isinstance(endpoint_context, int):
        return profile["caps"]["context_tokens"]
    cap = max(512, endpoint_context - CONTEXT_MARGIN)
    return min(cap, LOCAL_CONTEXT_MAX) if endpoint == "local" else cap


def child_profile(parent, want):
    """AH.9: a sub-agent's profile is the parent's, narrowed by `want` ({tools, caps}); never wider."""
    c = dict(parent)
    caps = dict(parent["caps"])
    for k, v in (want.get("caps") or {}).items():
        if k not in caps or v > caps[k]:
            raise ValueError("a sub-agent may not exceed the parent's cap %s" % k)
        caps[k] = v
    tools = want.get("tools", parent["tools"])
    if not set(tools) <= set(parent["tools"]):
        raise ValueError("a sub-agent may not use a tool its parent lacks")
    c["caps"], c["tools"] = caps, list(tools)
    return c


class _AgentTrace:
    """The trace as one agent writes it: a sub-agent's payloads gain `agent` and `parent`. The lead's payloads
    carry neither (absent reads as a0 everywhere), so a one-agent session replays under the code before A1a too."""
    def __init__(self, trace, agent, parent):
        self.t = trace
        self.extra = {} if agent == LEAD else dict({"agent": agent},
                                                    **({"parent": parent} if parent is not None else {}))

    def post(self, event, payload):
        return self.t.post(event, dict(payload, **self.extra))


def run(profile, standing, skill, model, tools, trace, clock=time.monotonic, backend_id=None, endpoint=None,
        endpoint_context=None, agent=LEAD, parent=None):
    if not agent_ok(agent, parent):
        raise ValueError("agent %r with parent %r is not a valid agent id" % (agent, parent))
    trace = _AgentTrace(trace, agent, parent)
    caps = dict(profile["caps"], context_tokens=context_cap(profile, endpoint, endpoint_context))
    allowed = list(profile["tools"])
    listed = {t["name"]: t for t in tools.list_tools()}
    local = through_gateway(profile)
    spec = [{"name": n, "description": listed[n].get("description", "")} for n in allowed if n in listed]
    if local:       # the gateway builds function tools from this: the schema is part of the request (and its sha)
        for t in spec:
            t["inputSchema"] = listed[t["name"]].get("inputSchema") or {"type": "object", "properties": {}}
    ctx = Context(standing, skill, spec)
    if profile.get("task"):     # a local model needs a first user message; part of the request, so of its sha
        ctx.add("user", profile["task"])
    ids = {"profile_sha256": sha(canonical(profile)), "standing_sha256": sha(standing),
           "skill_sha256": sha(skill), "tools_sha256": sha(canonical(spec))}
    backend = backend_id or model.id
    t_start = clock()
    spent = {"prompt_tokens": 0, "output_tokens": 0, "cpu_hours": 0.0}
    counted = set()
    ratio = None        # the model's prompt tokens per estimated token, from the last turn's usage (gateway only)
    call = 0
    every = int(profile.get("checkpoint_every", 4))
    finish_after = set(profile.get("finish_after", []))
    nudges = int(profile.get("nudges", 1))
    done_tools = set()

    def stop(reason, turn):
        trace.post("stop", {"reason": reason, "turns": turn, "prompt_tokens": spent["prompt_tokens"],
                            "output_tokens": spent["output_tokens"], "cpu_hours": round(spent["cpu_hours"], 6)})
        return reason

    def over():
        for k in ("prompt_tokens", "output_tokens", "cpu_hours"):
            if spent[k] > caps[k]:
                return k
        if clock() - t_start > caps["wall_h"] * 3600:
            return "wall_h"
        return None

    turn = 0
    while True:
        if turn >= caps["turns"]:
            return stop("turns", turn)
        est = ctx.est_tokens()
        if est > caps["context_tokens"]:
            return stop("context_full", turn)
        if ratio is not None and -(-est * ratio // 1) + caps.get("reserve_tokens", 0) > caps["context_tokens"]:
            return stop("context_full", turn)
        turn += 1
        req = ctx.request()
        if not local:       # a local backend's turn_request/turn_response are the model-gateway's records
            trace.post("turn_request", dict(ids, turn=turn, backend=backend, est_prompt_tokens=est,
                                            request_sha256=sha(ctx.request_bytes())))
        t0 = clock()
        try:
            # a model client that serves several agents (the gateway's, replay's) is told which one asks
            resp = model.respond(req, agent=agent) if getattr(model, "accepts_agent", False) else model.respond(req)
        except ModelError as e:
            return stop(e.reason, turn)
        if clock() - t0 > caps["turn_timeout_s"]:
            return stop("turn_timeout", turn)
        usage, bad = resp.get("usage"), resp.get("tool_error")
        resp = {"text": str(resp.get("text", ""))[:TEXT_MAX], "tool": resp.get("tool")}
        if bad and not resp["tool"]:    # a call the model wrote that could not be read: a refused call, never an exception
            resp["tool"] = {"name": MALFORMED, "args": {}}
        out_tokens = (len(canonical(resp)) + 3) // 4
        if local and isinstance(usage, dict):
            spent["prompt_tokens"] += int(usage.get("prompt_tokens", est))
            spent["output_tokens"] += int(usage.get("output_tokens", out_tokens))
            pt = usage.get("prompt_tokens")
            if isinstance(pt, int) and not isinstance(pt, bool) and pt > 0 and est > 0:
                ratio = pt / est
        else:
            spent["prompt_tokens"] += est
            spent["output_tokens"] += out_tokens
        if not local:
            trace.post("turn_response", {"turn": turn, "response": resp, "response_sha256": sha(canonical(resp)),
                                         "usage": {"prompt_tokens": est, "output_tokens": out_tokens, "estimated": True}})
        ctx.add("assistant", resp["text"], tool_call=resp["tool"])
        why = over()
        if why:
            return stop(why, turn)
        if not resp["tool"]:
            if not finish_after or finish_after & done_tools:
                return stop("finished", turn)
            if nudges <= 0:
                return stop("no_tool_call", turn)
            nudges -= 1
            ctx.add("user", NUDGE % " or ".join(sorted(finish_after)))
            continue
        call += 1
        name, args = resp["tool"]["name"], resp["tool"].get("args", {})
        ab = canonical(args)
        trace.post("tool_call", dict({"turn": turn, "call": call, "tool": name, "args_sha256": sha(ab)},
                                     **({"args": args} if len(ab) <= ARGS_MAX else {})))
        err = False
        if name == MALFORMED:
            # the whole refusal within ERROR_MAX: the gateway's reason quotes what the model wrote (26 Nov 2026)
            result, err = {"error": "malformed tool call: %s" % str(bad)[:ERROR_MAX - len("malformed tool call: ")]}, True
        elif name not in listed or name not in allowed:
            result, err = {"error": "tool not allowed"}, True
        else:
            try:
                # the MCP client sends (agent, call) as _meta; the servers record it beside their own count (design 2.1)
                result = (tools.call(name, args, meta={"agent": agent, "call": call})
                          if getattr(tools, "accepts_meta", False) else tools.call(name, args))
            except ToolError as e:
                result, err = {"error": str(e)[:ERROR_MAX]}, True
        text = canonical(result).decode("utf-8")
        wrapped, full, shown, trunc = wrap_result(name, call, text)
        trace.post("tool_result", {"turn": turn, "call": call, "tool": name, "result_sha256": full,
                                   "bytes": len(text.encode("utf-8")), "truncated": trunc, "error": err,
                                   "shown_sha256": sha(shown), "recorded_complete": len(text) <= RECORD_MAX,
                                   "result": text[:RECORD_MAX]})
        if not err:
            done_tools.add(name)
            # CPU spent = each campaign's final figure, once: an estimate is a forecast and a status or a repeated
            # sim.run of the same campaign reports it again (E48, 23 Nov 2026: 6.002 spent for 0.002 run)
            c = result.get("cpu_hours", 0) if isinstance(result, dict) else 0
            cid = result.get("cid") if isinstance(result, dict) else None
            if (isinstance(c, (int, float)) and not isinstance(c, bool) and isinstance(cid, str)
                    and result.get("state") in ("done", "failed") and cid not in counted):
                counted.add(cid)
                spent["cpu_hours"] += c
            if name.startswith("propose."):
                trace.post("proposal", {"turn": turn, "call": call, "tool": name, "result_sha256": full})
        ctx.add("tool", wrapped)
        if every and turn % every == 0:
            state = {"turn": turn, "call": call, "messages_sha256": sha(canonical(ctx.messages)), "spent": dict(spent)}
            trace.post("checkpoint", {"seq": turn // every, "turn": turn, "sha256": sha(canonical(state))})
        why = over()
        if why:
            return stop(why, turn)


def run_profile(path, standing_path, skill_path, tools, trace, model=None, **kw):
    p = load_profile(path)
    with open(standing_path, encoding="utf-8") as f:
        standing = f.read()
    with open(skill_path, encoding="utf-8") as f:
        skill = f.read()
    if model is None:
        if p["backend"] != "scripted":
            raise ValueError("a local profile needs a model (GatewayModel)")
        model = ScriptedModel(p["script"])
    return run(p, standing, skill, model, tools, trace, **kw)
