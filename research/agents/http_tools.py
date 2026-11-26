"""research/agents/http_tools.py (stage 6a): the agent's tool client. Speaks the MCP subset of
apps/research-agents/mcp_common.py (POST /mcp, JSON-RPC 2.0, Authorization: Bearer <session
token>) to the servers named by tool prefix (sim. -> mcp-sim, lake. -> mcp-lake). Implements the
loop's `tools` interface: list_tools() and call(name, args), raising loop.ToolError.
A sim.run that answers "waiting for the supervisor" (the CPU gate) or "running" is followed
with sim.status every `poll_s` until it is done, failed or `wait_s` has passed; the polling
is wall time, never turns. Stdlib only."""
import json
import time
import urllib.error
import urllib.request

from .loop import ERROR_MAX, ToolError

PROTOCOL = "2026-07-28"   # = apps/research-agents/mcp_common.PROTOCOL (tests/test_mcp_sim.py pins both)


class HttpTransport:
    # 330 s: sim.estimate of an FLC or MPC spec waits for the estimate Job (up to 300 s, design R7); every other call is quick
    def __init__(self, timeout=330):
        self.timeout = timeout

    def post(self, url, token, msg):
        req = urllib.request.Request(url.rstrip("/") + "/mcp", json.dumps(msg).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Bearer " + token,
                                      "MCP-Protocol-Version": PROTOCOL})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None
        except (OSError, ValueError):
            return 0, None


class HttpTools:
    def __init__(self, servers, token, transport=None, sleep=time.sleep, clock=time.monotonic, poll_s=10, wait_s=3600):
        self.servers, self.token = dict(servers), token
        self.t, self.sleep, self.clock, self.poll_s, self.wait_s = transport or HttpTransport(), sleep, clock, poll_s, wait_s
        self.n = 0

    def _rpc(self, url, method, params):
        self.n += 1
        st, r = self.t.post(url, self.token, {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        if st == 401:
            raise ToolError("the session token was refused")
        if st != 200 or not isinstance(r, dict):
            raise ToolError("the tool server did not answer (%s)" % st)
        if "error" in r:
            raise ToolError(str((r["error"] or {}).get("message", "error"))[:ERROR_MAX])
        return r["result"]

    def list_tools(self):
        out = []
        for url in self.servers.values():
            out += [{"name": t["name"], "description": t.get("description", ""), "inputSchema": t.get("inputSchema")} for t in self._rpc(url, "tools/list", {})["tools"]]
        return out

    def _call(self, name, args):
        prefix = name.split(".")[0]
        url = self.servers.get(prefix) or self.servers.get({"propose": "sim"}.get(prefix, ""))
        if url is None:
            raise ToolError("no server for this tool")
        res = self._rpc(url, "tools/call", {"name": name, "arguments": args})
        if res.get("isError"):
            try:
                msg = json.loads(res["content"][0]["text"]).get("error", "")
            except (ValueError, KeyError, IndexError, AttributeError):
                msg = "tool error"
            raise ToolError(str(msg)[:ERROR_MAX])
        if isinstance(res.get("structuredContent"), dict) and not res["structuredContent"].get("truncated"):
            return res["structuredContent"]
        try:
            return json.loads(res["content"][0]["text"])
        except (ValueError, KeyError, IndexError):
            raise ToolError("the tool answered with something that is not JSON")

    def call(self, name, args):
        r = self._call(name, args)
        if name != "sim.run" or not isinstance(r, dict):
            return r
        cid, deadline = r.get("cid"), self.clock() + self.wait_s
        while r.get("state") in ("waiting for the supervisor", "started", "running") and self.clock() < deadline:
            self.sleep(self.poll_s)
            r = self._call("sim.status", {"cid": cid})
        return r
