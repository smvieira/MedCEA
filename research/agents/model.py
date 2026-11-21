"""research/agents/model.py (AH.2): one request shape, one response shape
{text, tool: {name, args} | None}. Backend `scripted` (4a): a rule-based driver that follows a
script of steps, one per assistant message so far; deterministic, no network. The local
backend (4b) goes through the gateway and is not here."""
from .context import canonical, sha


class ScriptedModel:
    def __init__(self, script):
        self.script = [dict(s) for s in script]
        self.id = "scripted:" + sha(canonical(self.script))[:16]

    def respond(self, request):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        if n >= len(self.script):
            return {"text": "Nothing left to do.", "tool": None}
        s = self.script[n]
        tool = {"name": s["tool"], "args": s.get("args", {})} if s.get("tool") else None
        return {"text": s.get("text", ""), "tool": tool}


class RecordedModel:
    """Replay: the recorded responses, in order."""
    def __init__(self, responses):
        self.responses, self.id = list(responses), None

    def respond(self, request):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        return self.responses[n]
