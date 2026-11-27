"""research/agents/model.py (AH.2): one request shape, one response shape
{text, tool: {name, args} | None}. Backend `scripted` (4a): a rule-based driver that follows a
script of steps, one per assistant message so far; deterministic, no network. Backend `local`
(4b stage 2): GatewayModel asks the model-gateway (apps/research-model/gateway.py), which writes
the turn_request/turn_response records itself."""
import json
import re
import time
import urllib.error
import urllib.request

from .context import canonical, sha

class ModelError(Exception):
    """The model could not answer this turn; `reason` becomes the stop reason of the session."""
    def __init__(self, reason, message=""):
        super().__init__(message or reason)
        self.reason = reason


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
    """Replay: the recorded responses, in order, per agent ({agent: [response, ...]}; a list is the lead's)."""
    accepts_agent = True

    def __init__(self, responses):
        self.responses = ({a: list(r) for a, r in responses.items()} if isinstance(responses, dict)
                          else {"a0": list(responses)})
        self.id = None

    def respond(self, request, agent="a0"):
        n = sum(1 for m in request["messages"] if m["role"] == "assistant")
        return self.responses.get(agent, [])[n]


class GatewayModel:
    """Backend `local`: POST {sid, turn, request} to the model-gateway with the session token (stdlib
    urllib; the token goes in a header, never in a URL or a log). 429 `busy` (one slot) is retried with
    a growing pause until `busy_wait_s`; the wait is wall time, counted by the loop's own clock.
    Anything else that is not 200 raises ModelError: 413 -> context_full, 401/403 -> model_refused,
    the rest model_error. `post(url, token, body, timeout)` -> (status, object) is injectable.
    The body names the asking agent (`agent`, research Phase 4e): the gateway records it on its turns."""
    id = "gateway"
    accepts_agent = True

    def __init__(self, url, token, sid, post=None, sleep=time.sleep, clock=time.monotonic,
                 busy_wait_s=600, timeout=600):
        self.url, self.token, self.sid = url.rstrip("/") + "/v1/turn", token, sid
        self.post, self.sleep, self.clock = post or self._post, sleep, clock
        self.busy_wait_s, self.timeout = busy_wait_s, timeout

    def _post(self, url, token, body, timeout):
        req = urllib.request.Request(url, json.dumps(body).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (OSError, ValueError):
            return 0, {}

    def respond(self, request, agent="a0"):
        turn = sum(1 for m in request["messages"] if m["role"] == "assistant") + 1
        end, pause = self.clock() + self.busy_wait_s, 2
        while True:
            st, obj = self.post(self.url, self.token, {"sid": self.sid, "agent": agent, "turn": turn, "request": request},
                                self.timeout)
            if st == 429 and self.clock() < end:
                self.sleep(pause)
                pause = min(pause * 2, 30)
                continue
            break
        if st == 200 and isinstance(obj, dict) and "text" in obj:
            return obj
        if st == 413:
            raise ModelError("context_full", "the model's context is full")
        if st in (401, 403):
            raise ModelError("model_refused", "the model gateway refused the session (%s)" % st)
        if st == 429:
            raise ModelError("model_busy", "the model stayed busy")
        raise ModelError("model_error", "the model gateway answered %s" % st)
