"""research/agents/trace.py: the agent's client of research-session's agent port (stage 3,
apps/research-agents/session.py): /claim once, then /trace per event. The transport is
injected (post(path, body) -> (status, object)); HttpTransport is the urllib one."""
import json
import urllib.error
import urllib.request


class TraceRefused(Exception):
    pass


class HttpTransport:
    def __init__(self, base, timeout=10):
        self.base, self.timeout = base.rstrip("/"), timeout

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(),
                                     {"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}


class TraceClient:
    def __init__(self, transport, sid):
        self.t, self.sid, self.token = transport, sid, None

    def claim(self, claim):
        st, obj = self.t.post("/claim", {"sid": self.sid, "claim": claim})
        if st != 200 or "token" not in obj:
            raise TraceRefused("claim refused (%s)" % st)
        self.token = obj["token"]

    def post(self, event, payload):
        st, obj = self.t.post("/trace", {"sid": self.sid, "token": self.token, "event": event, "payload": payload})
        if st != 200:
            raise TraceRefused("%s refused (%s: %s)" % (event, st, obj.get("error", "")))
        return obj.get("event_id")
