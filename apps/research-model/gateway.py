"""apps/research-model/gateway.py (research Phase 4b stage 2; codeplan/rs4-design.md 5.3): the model gateway,
stdlib, namespace research-gw, port 8120. The one place the local model is reached from a session.

POST /v1/turn   Authorization: Bearer <session token>   body {sid, turn, request}
  request = the agent loop's internal shape {system, tools: [{name, description, inputSchema}], messages}.
  1. research-session's /introspect on the server port (audience model-gateway, peer = the caller's address);
     refused = 401 with no detail; the token's session must be the body's sid and a local-backend one.
  2. refuse (403) when the session's prompt or output tokens are spent.
  3. one slot: a second concurrent turn is 429 busy (the agent waits; its wait is wall time).
  4. translate to llama-server /v1/chat/completions: tools as function tools (a '.' in a name becomes '_',
     mapped back), tool_choice auto, the fixed greedy sampler (temperature 0, top_k 1, seed 1), thinking off
     (chat_template_kwargs.enable_thinking false), cache_prompt true, max_tokens from what the session has
     left (at most 1024).
  5. trace, as actor model-gateway on the server port: turn_request (request sha256, model pin, flags) before
     the call, turn_response (the response in the loop's shape, its sha256, the raw answer's sha256, llama-server's
     own usage) after it. A record that is refused refuses the turn: nothing the trace does not hold is returned.
  6. answer {text, tool: {name, args} | None, usage, tool_error?}: at most one tool call; a call the model
     wrote that cannot be read (no such tool, arguments that are not a JSON object, two calls, a call written
     as text) comes back as text with tool_error set, which the loop treats as a refused tool call.
A failure of the model is recorded as a turn_response {turn, error} (context_full for llama-server's
exceed_context_size_error, else model_error) and answered 413 / 502, so replay reproduces the stop.

Never logs a token, a request or an answer. Environment: RS_SESSION_SERVER_URL, RS_LLM_URL, MODEL_ALIAS,
MODEL_SHA256, LLM_CTX, RS_LLM_TIMEOUT (seconds, default 540), RS_GATEWAY_PORT (default 8120)."""
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import mcp_common                      # in the pod: ConfigMap model-gateway-code holds both files
except ImportError:                        # in the repository: apps/research-agents/mcp_common.py
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "mcp_common", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "research-agents", "mcp_common.py"))
    mcp_common = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(mcp_common)

AUDIENCE = "model-gateway"
BODY_MAX = 256 * 1024
TEXT_MAX = 2000
MAX_TOKENS_CAP = 1024
MAX_TOKENS_DEFAULT = 400
SAMPLER = {"temperature": 0, "top_k": 1, "seed": 1}        # the fixed greedy set, nothing else is ever sent
FLAGS = {"sampler": SAMPLER, "enable_thinking": False, "cache_prompt": True, "tool_choice": "auto", "slots": 1}
MALFORMED_TEXT = ("<tool_call>",)


def canonical_bytes(obj):
    return mcp_common.canonical(obj).encode("utf-8")


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode("utf-8")).hexdigest()


def fn_name(name):
    return name.replace(".", "_")


def translate(request):
    """-> (messages, tools, names): the loop's internal request as OpenAI chat messages and function tools;
    names maps the function name back to the tool's own ('lake_snapshots' -> 'lake.snapshots')."""
    names, tools = {}, []
    for t in request.get("tools") or []:
        names[fn_name(t["name"])] = t["name"]
        tools.append({"type": "function", "function": {
            "name": fn_name(t["name"]), "description": str(t.get("description", ""))[:400],
            "parameters": t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else {"type": "object", "properties": {}}}})
    msgs, n, pending = [{"role": "system", "content": request["system"]}], 0, None
    for m in request["messages"]:
        if m["role"] == "assistant" and m.get("tool_call"):
            n += 1
            pending = "call-%d" % n
            tc = m["tool_call"]
            msgs.append({"role": "assistant", "content": m.get("content", ""), "tool_calls": [{
                "id": pending, "type": "function",
                "function": {"name": fn_name(tc["name"]), "arguments": json.dumps(tc.get("args") or {}, separators=(",", ":"), sort_keys=True)}}]})
        elif m["role"] == "tool":
            msgs.append({"role": "tool", "tool_call_id": pending or "call-0", "content": m.get("content", "")})
        else:
            msgs.append({"role": m["role"], "content": m.get("content", "")})
    return msgs, tools, names


def read_answer(raw, names):
    """The llama-server answer -> ({text, tool, tool_error?}, finish_reason). Never raises."""
    try:
        choice = raw["choices"][0]
        msg = choice.get("message") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        return {"text": "", "tool": None, "tool_error": "the model's answer could not be read"}, "error"
    text = str(msg.get("content") or "")[:TEXT_MAX]
    out, calls = {"text": text, "tool": None}, msg.get("tool_calls") or []
    if len(calls) > 1:
        out["tool_error"] = "only one tool call per turn is allowed"
    elif calls:
        f = (calls[0] or {}).get("function") or {}
        name = names.get(f.get("name"))
        args = f.get("arguments")
        try:
            args = json.loads(args) if isinstance(args, str) else args
        except ValueError:
            args = None
        if name is None:
            out["tool_error"] = "no such tool"
        elif not isinstance(args, dict):
            out["tool_error"] = "the arguments are not a JSON object"
        else:
            out["tool"] = {"name": name, "args": args}
    elif any(x in text for x in MALFORMED_TEXT):
        out["tool_error"] = "a tool call was written as text"
    return out, choice.get("finish_reason")


class Llm:
    """llama-server over HTTP. post(path, body) -> (status, object); tests replace it."""
    def __init__(self, base, timeout):
        self.base, self.timeout = base.rstrip("/"), timeout

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
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


class Gateway:
    def __init__(self, session, llm, alias, model_sha256="", ctx=4096):
        self.session, self.llm, self.alias, self.model_sha256, self.ctx = session, llm, alias, model_sha256, ctx
        self.slot = threading.Lock()

    def turn(self, token, peer, body):
        """-> (http status, object)."""
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        sid, turn, req = body.get("sid"), body.get("turn"), body.get("request")
        if not (isinstance(sid, str) and isinstance(turn, int) and not isinstance(turn, bool) and turn >= 1
                and isinstance(req, dict) and isinstance(req.get("system"), str)
                and isinstance(req.get("messages"), list) and isinstance(req.get("tools", []), list)):
            return 400, {"error": "sid, turn and request {system, tools, messages} are required"}
        try:
            for t in req.get("tools", []):
                assert isinstance(t["name"], str)
            for m in req["messages"]:
                assert m["role"] in ("user", "assistant", "tool") and isinstance(m.get("content", ""), str)
                assert m.get("tool_call") is None or isinstance(m["tool_call"]["name"], str)
        except (AssertionError, KeyError, TypeError):
            return 400, {"error": "the request's tools or messages are malformed"}
        info = self.session.introspect(token, AUDIENCE, peer) if token else None
        if info is None:
            return 401, {}
        if info.get("sid") != sid or info.get("backend") != "local":
            return 403, {"error": "this session does not use the local model"}
        left = info.get("budget_left") or {}
        for k in ("prompt_tokens", "output_tokens"):
            if isinstance(left.get(k), (int, float)) and left[k] <= 0:
                return 403, {"error": "the session's %s budget is spent" % k}
        if not self.slot.acquire(blocking=False):
            return 429, {"error": "busy"}
        try:
            return self._turn(sid, turn, req, left)
        finally:
            self.slot.release()

    def _turn(self, sid, turn, req, left):
        msgs, tools, names = translate(req)
        out_left = left.get("output_tokens")
        max_tokens = MAX_TOKENS_DEFAULT if not isinstance(out_left, (int, float)) else int(max(16, min(out_left, MAX_TOKENS_CAP)))
        max_tokens = min(max_tokens, MAX_TOKENS_CAP)
        st, b = self.session.trace(sid, "turn_request", {
            "turn": turn, "backend": "local", "model": self.alias, "model_sha256": self.model_sha256,
            "request_sha256": sha(canonical_bytes(req)), "flags": dict(FLAGS, max_tokens=max_tokens, ctx=self.ctx)})
        if st != 200:
            return (403 if st == 403 else 503), {"error": "the trace did not accept the turn"}
        body = {"model": self.alias, "messages": msgs, "max_tokens": max_tokens, "cache_prompt": True, "stream": False,
                "chat_template_kwargs": {"enable_thinking": False}}
        body.update(SAMPLER)
        if tools:
            body["tools"], body["tool_choice"] = tools, "auto"
        st, raw = self.llm.post("/v1/chat/completions", body)
        if st != 200:
            ctxfull = st == 400 and "exceed_context_size" in json.dumps(raw)
            why = "context_full" if ctxfull else "model_error"
            self.session.trace(sid, "turn_response", {"turn": turn, "error": why, "status": st})
            return (413 if ctxfull else 502), {"error": why}
        resp, finish = read_answer(raw, names)
        u, tm = raw.get("usage") or {}, raw.get("timings") or {}
        usage = {"prompt_tokens": int(u.get("prompt_tokens") or 0), "output_tokens": int(u.get("completion_tokens") or 0),
                 "estimated": False}
        if isinstance(tm.get("cache_n"), int):
            usage["cache_n"] = tm["cache_n"]
        st, b = self.session.trace(sid, "turn_response", {
            "turn": turn, "response": resp, "response_sha256": sha(canonical_bytes(resp)),
            "raw_response_sha256": sha(canonical_bytes(raw)), "finish_reason": finish, "usage": usage})
        if st != 200:
            return (403 if st == 403 else 503), {"error": "the trace did not accept the answer"}
        return 200, dict(resp, usage=usage)


def make_http_server(gw, host="0.0.0.0", port=0):
    class H(BaseHTTPRequestHandler):
        server_version = "model-gateway"

        def log_message(self, fmt, *a):
            pass

        def send(self, code, obj):
            b = canonical_bytes(obj)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self.send(200, {"ok": True, "server": "model-gateway", "model": gw.alias}) if self.path == "/healthz" else self.send(404, {})

        def do_POST(self):
            if self.path != "/v1/turn":
                return self.send(404, {})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if not 0 < n <= BODY_MAX:
                    return self.send(413, {})
                body = json.loads(self.rfile.read(n))
            except ValueError:
                return self.send(400, {"error": "not JSON"})
            auth = self.headers.get("Authorization") or ""
            token = auth[7:] if auth.startswith("Bearer ") else None
            self.send(*gw.turn(token, self.client_address[0], body))
    return ThreadingHTTPServer((host, port), H)


def main():
    gw = Gateway(mcp_common.Session(os.environ["RS_SESSION_SERVER_URL"], "model-gateway"),
                 Llm(os.environ.get("RS_LLM_URL", "http://research-llm:8080"), float(os.environ.get("RS_LLM_TIMEOUT", "540"))),
                 os.environ["MODEL_ALIAS"], os.environ.get("MODEL_SHA256", ""), int(os.environ.get("LLM_CTX", "4096")))
    srv = make_http_server(gw, port=int(os.environ.get("RS_GATEWAY_PORT", "8120")))
    sys.stderr.write("model-gateway: port %d, model %s\n" % (srv.server_address[1], gw.alias))
    srv.serve_forever()


if __name__ == "__main__":
    main()
