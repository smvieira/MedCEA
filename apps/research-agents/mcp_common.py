"""apps/research-agents/mcp_common.py (research Phase 4a, stage 5): the stdlib JSON-RPC 2.0 subset
over HTTP POST that mcp-sim and mcp-lake share (design 4.5, R29, R30).

Methods: initialize, ping, tools/list, tools/call; anything else is -32601. The session token is the
Bearer; every tools/call is checked by research-session's /introspect (audience = this server, peer =
the caller's address) and the tool must be in the session's tool list. A refused token is HTTP 401
with no detail. Tool results are canonical JSON text, control characters and < > replaced, size-limited;
the server records tool_result on the session's trace (server port, actor = this server)."""
import hashlib
import json
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL = "2026-07-28"
RESULT_MAX = 8000
BODY_MAX = 64 * 1024
CODE = re.compile(r"^[A-Za-z0-9_.%-]{1,48}$")
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha(s):
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode("utf-8")).hexdigest()


def clean_text(s, limit=RESULT_MAX):
    """Control characters and angle brackets neutralised, then cut to LIMIT characters."""
    return CTRL.sub("?", str(s)).replace("<", "?").replace(">", "?")[:limit]


def clean_code(s, counter=None):
    """R30: a tag, sensor, uom or code that is not ^[A-Za-z0-9_.%-]{1,48}$ becomes '?' (counted)."""
    if isinstance(s, str) and CODE.match(s):
        return s
    if counter is not None:
        counter[0] += 1
    return "?"


def clean_obj(o):
    if isinstance(o, str):
        return clean_text(o, 400)
    if isinstance(o, dict):
        return {clean_text(k, 80): clean_obj(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean_obj(v) for v in o]
    return o


class ToolRefused(Exception):
    """A tool's own refusal: becomes isError true with this text."""


class Session:
    """research-session's server port (8102): introspect, trace, gates. `post(path, body)` and
    `get(path)` return (status, json); tests replace them."""
    def __init__(self, base, server, timeout=10):
        self.base, self.server, self.timeout = base.rstrip("/"), server, timeout

    def _do(self, req):
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (OSError, ValueError):
            return 0, {}

    def post(self, path, body):
        return self._do(urllib.request.Request(self.base + path, canonical(body).encode(), {"Content-Type": "application/json"}))

    def get(self, path):
        return self._do(urllib.request.Request(self.base + path))

    def introspect(self, token, audience, peer):
        st, b = self.post("/introspect", {"token": token, "audience": audience, "peer": peer})
        return b if st == 200 and b.get("active") is True else None

    def trace(self, sid, event, payload):
        return self.post("/trace", {"server": self.server, "sid": sid, "event": event, "payload": payload})

    def gate(self, sid, gid):
        st, b = self.get("/gates/%s?sid=%s" % (urllib.parse.quote(gid), urllib.parse.quote(sid)))
        return b if st == 200 else None


class Tool:
    def __init__(self, name, description, schema, fn):
        self.name, self.description, self.schema, self.fn = name, description, schema, fn

    def listing(self):
        return {"name": self.name, "description": self.description, "inputSchema": self.schema}


class McpServer:
    """tools: [Tool]; each fn(ctx, args) -> dict, ctx = {sid, info (the introspect answer)}."""
    def __init__(self, name, audience, session, tools):
        self.name, self.audience, self.session = name, audience, session
        self.tools = {t.name: t for t in tools}
        self.calls = {}
        self.lock = threading.Lock()

    def tools_list(self):
        return sorted((t.listing() for t in self.tools.values()), key=lambda t: t["name"])

    def tools_list_sha256(self):
        return sha(canonical(self.tools_list()))

    def handle(self, msg, token, peer):
        """-> (http status, response object or None)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        rid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if not isinstance(params, dict):
            return 200, self._err(rid, -32602, "params must be an object")
        if method == "initialize":
            return 200, self._ok(rid, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                                       "serverInfo": {"name": self.name, "version": "1"}})
        if method == "ping":
            return 200, self._ok(rid, {})
        if method not in ("tools/list", "tools/call"):
            return 200, self._err(rid, -32601, "method not found")
        info = self.session.introspect(token, self.audience, peer) if token else None
        if info is None:
            return 401, None
        if method == "tools/list":
            allowed = set(info.get("tools") or [])
            return 200, self._ok(rid, {"tools": [t for t in self.tools_list() if t["name"] in allowed]})
        name, args = params.get("name"), params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(args, dict):
            return 200, self._err(rid, -32602, "name and arguments are required")
        sid = info["sid"]
        with self.lock:
            n = self.calls[sid] = self.calls.get(sid, 0) + 1
        if name not in self.tools or name not in (info.get("tools") or []):
            return 200, self._ok(rid, self._result(sid, name, n, {"error": "tool not allowed"}, True))
        try:
            out, err = self.tools[name].fn({"sid": sid, "info": info}, args), False
        except ToolRefused as e:
            out, err = {"error": clean_text(e, 300)}, True
        except Exception as e:                           # a tool bug is an error result, never a crash
            out, err = {"error": "tool failed: %s" % type(e).__name__}, True
            # and a line in the server's log (no arguments, no token): E48's ModuleNotFoundError left none
            first = (str(e).splitlines() or [""])[0][:200]
            sys.stderr.write("%s: tool %s failed: %s: %s\n" % (self.name, name, type(e).__name__, first))
            sys.stderr.flush()
        return 200, self._ok(rid, self._result(sid, name, n, out, err))

    def _result(self, sid, name, n, out, err):
        text = clean_text(canonical(out))
        self.session.trace(sid, "tool_result", {"tool": name, "call": n, "result_sha256": sha(text),
                                                "bytes": len(text.encode("utf-8")), "error": err})
        res = {"content": [{"type": "text", "text": text}], "isError": err}
        if isinstance(out, dict):
            res["structuredContent"] = json.loads(text) if len(text) < RESULT_MAX else {"truncated": True}
        return res

    @staticmethod
    def _ok(rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def make_http_server(app, host="0.0.0.0", port=0):
    class H(BaseHTTPRequestHandler):
        server_version = "mcp"

        def log_message(self, fmt, *a):
            pass

        def send(self, code, obj):
            b = b"" if obj is None else canonical(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self.send(200, {"ok": True, "server": app.name}) if self.path == "/healthz" else self.send(404, {})

        def do_POST(self):
            if self.path != "/mcp":
                return self.send(404, {})
            ver = self.headers.get("MCP-Protocol-Version")
            if ver is not None and ver != PROTOCOL:
                return self.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32022, "message": "unsupported version", "data": {"supported": [PROTOCOL]}}})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if not 0 < n <= BODY_MAX:
                    return self.send(413, {})
                msg = json.loads(self.rfile.read(n))
            except ValueError:
                return self.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            auth = self.headers.get("Authorization") or ""
            token = auth[7:] if auth.startswith("Bearer ") else None
            code, obj = app.handle(msg, token, self.client_address[0])
            self.send(code, obj)
    return ThreadingHTTPServer((host, port), H)
