"""research/agents/model.py (AH.2): one request shape, one response shape
{text, tool: {name, args} | None}. Backend `scripted` (4a): a rule-based driver that follows a
script of steps, one per assistant message so far; deterministic, no network. The local
backend (4b) goes through the gateway and is not here."""
import re

from .context import canonical, sha

_CID = re.compile(r'"cid"\s*:\s*"(c[0-9a-f]{20})"')


def _sub_last_cid(o, cid):
    if o == "@last_cid":
        return cid
    if isinstance(o, list):
        return [_sub_last_cid(x, cid) for x in o]
    if isinstance(o, dict):
        return {k: _sub_last_cid(v, cid) for k, v in o.items()}
    return o


class ScriptedModel:
    def __init__(self, script):
        self.script = [dict(s) for s in script]
        self.id = "scripted:" + sha(canonical(self.script))[:16]

    def respond(self, request):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        if n >= len(self.script):
            return {"text": "Nothing left to do.", "tool": None}
        s = self.script[n]
        args = s.get("args", {})
        if "@last_cid" in canonical(args).decode("utf-8"):
            # a campaign handle is minted by the server (it depends on the session): the step names it as
            # "@last_cid" and gets the newest one a tool result showed
            found = [m_ for t in request["messages"] if t["role"] == "tool"
                     for m_ in _CID.findall(str(t.get("content", "")))]
            cid = found[-1] if found else ""
            args = _sub_last_cid(args, cid)
        tool = {"name": s["tool"], "args": args} if s.get("tool") else None
        return {"text": s.get("text", ""), "tool": tool}


class RecordedModel:
    """Replay: the recorded responses, in order."""
    def __init__(self, responses):
        self.responses, self.id = list(responses), None

    def respond(self, request):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        return self.responses[n]
