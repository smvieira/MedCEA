"""research/agents/loop.py (AH.1, AH.7, AH.9): the agent loop. One turn = turn_request ->
model -> turn_response -> [tool_call -> tool_result [-> proposal]] -> [checkpoint]; the loop
ends with exactly one `stop {reason}`. Every cap of the profile is enforced here and the
stop is traced. The loop knows nothing of HTTP: `trace` has post(event, payload), `tools`
has list_tools() -> [{name, description}] and call(name, args) -> dict (raising ToolError),
`model` has respond(request) -> {text, tool}. Strict replay (replay.py) drives this same
function with recorded responses and results."""
import re
import time

import yaml

from .context import Context, canonical, sha, wrap_result
from .model import ModelError, ScriptedModel

TEXT_MAX = 2000
ARGS_MAX = 2000
RECORD_MAX = 6000
LOCAL_CONTEXT_MAX = 4096     # owner decision of 21 Nov 2026: a local session is about 4k tokens of context
BACKENDS = ("scripted", "local")         # local = the endpoint on this host; any endpoint name works the same way
ENDPOINT_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


def through_gateway(profile):
    """True when the profile's answers come from a model endpoint through the model-gateway: any backend but
    'scripted' (research Phase 4d: the backend names an endpoint of apps/research-model/endpoints.yaml)."""
    return profile.get("backend") != "scripted"
CAPS = ("turns", "prompt_tokens", "output_tokens", "cpu_hours", "wall_h", "turn_timeout_s", "context_tokens")
# optional caps.reserve_tokens: room kept for the answer. Through the gateway the next request is projected in the
# model's own tokens (its last prompt_tokens over the loop's estimate for that request), so a turn whose answer would
# run into the end of the context is not started (E49, 25 Nov 2026: a proposal cut off by the context end)


MALFORMED = "invalid_call"


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
    if p["backend"] == "scripted" and not isinstance(p.get("script"), list):
        raise ValueError("profile: a scripted profile needs a script")
    return p


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


def run(profile, standing, skill, model, tools, trace, clock=time.monotonic, backend_id=None):
    caps = profile["caps"]
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
            resp = model.respond(req)
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
            return stop("finished", turn)
        call += 1
        name, args = resp["tool"]["name"], resp["tool"].get("args", {})
        ab = canonical(args)
        trace.post("tool_call", dict({"turn": turn, "call": call, "tool": name, "args_sha256": sha(ab)},
                                     **({"args": args} if len(ab) <= ARGS_MAX else {})))
        err = False
        if name == MALFORMED:
            result, err = {"error": "malformed tool call: %s" % str(bad)[:150]}, True
        elif name not in listed or name not in allowed:
            result, err = {"error": "tool not allowed"}, True
        else:
            try:
                result = tools.call(name, args)
            except ToolError as e:
                result, err = {"error": str(e)[:200]}, True
        text = canonical(result).decode("utf-8")
        wrapped, full, shown, trunc = wrap_result(name, call, text)
        trace.post("tool_result", {"turn": turn, "call": call, "tool": name, "result_sha256": full,
                                   "bytes": len(text.encode("utf-8")), "truncated": trunc, "error": err,
                                   "shown_sha256": sha(shown), "recorded_complete": len(text) <= RECORD_MAX,
                                   "result": text[:RECORD_MAX]})
        if not err:
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
