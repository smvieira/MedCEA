"""Fakes shared by tests/test_mcp_sim.py and tests/test_mcp_lake.py."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
import mcp_common  # noqa: E402

SID = "A" * 22


class FakeSession:
    def __init__(self, tools, budget_left=None):
        self.tools, self.budget_left, self.events, self.gates = tools, budget_left or {"cpu_hours": 16.0}, [], {}
        self.active = True

    def introspect(self, token, audience, peer):
        if token != "tok" or not self.active:
            return None
        return {"active": True, "sid": SID, "tools": self.tools, "budget_left": self.budget_left}

    def trace(self, sid, event, payload):
        self.events.append((sid, event, payload))
        return 200, {}

    def gate(self, sid, gid):
        return self.gates.get(gid)

    def of(self, event):
        return [p for _, e, p in self.events if e == event]


def rpc(app, method, params=None, token="tok", peer="10.0.0.1"):
    return app.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, token, peer)


def call(app, name, args, **kw):
    code, r = rpc(app, "tools/call", {"name": name, "arguments": args}, **kw)
    return code, r


def payload(r):
    return json.loads(r["result"]["content"][0]["text"])


def http_post(port, obj, token="tok", headers=None):
    req = urllib.request.Request("http://127.0.0.1:%d/mcp" % port, json.dumps(obj).encode(),
                                 dict({"Content-Type": "application/json", "Authorization": "Bearer " + token}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def serve(app):
    srv = mcp_common.make_http_server(app, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
