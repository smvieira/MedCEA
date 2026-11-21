"""research/agents/loop.py (AH.1, AH.7, AH.9): the agent loop. One turn = turn_request ->
model -> turn_response -> [tool_call -> tool_result [-> proposal]] -> [checkpoint]; the loop
ends with exactly one `stop {reason}`. Every cap of the profile is enforced here and the
stop is traced. The loop knows nothing of HTTP: `trace` has post(event, payload), `tools`
has list_tools() -> [{name, description}] and call(name, args) -> dict (raising ToolError),
`model` has respond(request) -> {text, tool}. Strict replay (replay.py) drives this same
function with recorded responses and results."""
import time

import yaml

from .context import Context, canonical, sha, wrap_result
from .model import ScriptedModel

TEXT_MAX = 2000
ARGS_MAX = 2000
RECORD_MAX = 6000
CAPS = ("turns", "prompt_tokens", "output_tokens", "cpu_hours", "wall_h", "turn_timeout_s", "context_tokens")


class ToolError(Exception):
    pass


def load_profile(path):
    with open(path, encoding="utf-8") as f:
        p = yaml.safe_load(f)
    if not isinstance(p, dict) or p.get("backend") != "scripted":
        raise ValueError("profile: a mapping with backend scripted is required")
    caps = p.get("caps") or {}
    for k in CAPS:
        if not isinstance(caps.get(k), (int, float)) or isinstance(caps.get(k), bool) or caps[k] <= 0:
            raise ValueError("profile: caps.%s must be a positive number" % k)
    if not p.get("tools") or not all(isinstance(t, str) for t in p["tools"]):
        raise ValueError("profile: tools must be a list of names")
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
    spec = [{"name": n, "description": listed[n].get("description", "")} for n in allowed if n in listed]
    ctx = Context(standing, skill, spec)
    ids = {"profile_sha256": sha(canonical(profile)), "standing_sha256": sha(standing),
           "skill_sha256": sha(skill), "tools_sha256": sha(canonical(spec))}
    backend = backend_id or model.id
    t_start = clock()
    spent = {"prompt_tokens": 0, "output_tokens": 0, "cpu_hours": 0.0}
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
        turn += 1
        req = ctx.request()
        trace.post("turn_request", dict(ids, turn=turn, backend=backend, est_prompt_tokens=est,
                                        request_sha256=sha(ctx.request_bytes())))
        t0 = clock()
        resp = model.respond(req)
        if clock() - t0 > caps["turn_timeout_s"]:
            return stop("turn_timeout", turn)
        resp = {"text": str(resp.get("text", ""))[:TEXT_MAX], "tool": resp.get("tool")}
        out_tokens = (len(canonical(resp)) + 3) // 4
        spent["prompt_tokens"] += est
        spent["output_tokens"] += out_tokens
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
        if name not in listed or name not in allowed:
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
            c = result.get("cpu_hours", 0) if isinstance(result, dict) else 0
            if isinstance(c, (int, float)) and not isinstance(c, bool):
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


def run_profile(path, standing_path, skill_path, tools, trace, **kw):
    p = load_profile(path)
    with open(standing_path, encoding="utf-8") as f:
        standing = f.read()
    with open(skill_path, encoding="utf-8") as f:
        skill = f.read()
    return run(p, standing, skill, ScriptedModel(p["script"]), tools, trace, **kw)
