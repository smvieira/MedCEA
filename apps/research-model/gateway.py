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
FLAGS = {"sampler": SAMPLER, "enable_thinking": False, "cache_prompt": True, "tool_choice": "auto",
         "parallel_tool_calls": False, "slots": 1}
# one call per answer: the loop runs one tool per turn. E49 (25 Nov 2026): the local model wrote several calls in
# one answer until the output limit, twice; parallel_tool_calls false asks the server for one, and if an answer
# still holds several, the first well-formed one is taken and the count of the others is recorded (dropped_calls)
MALFORMED_TEXT = ("<tool_call>",)
# a local turn is one tool call (the longest seen, E49: 120 tokens); at 1.2-1.4 tokens/s a runaway answer under the
# 1024 cap ran into the 540-s timeout and ended the session with model_error (24 Nov 2026), so the local model stops
# at 400 (about 5 min) and a cut answer comes back as a refused call the model can retry
LOCAL_MAX_OUTPUT = 400


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


# Tools as text (an endpoint's `tools: text`, research Phase 4d): for an OpenAI-compatible server without native tool
# calls (vLLM without --enable-auto-tool-choice). The tools go into the system message in the Hermes form Qwen's own
# chat template writes, a call is the text <tool_call>{"name": .., "arguments": {..}}</tool_call>, and a tool result
# goes back as a user message <tool_response>..</tool_response>, as that template renders a tool message.
TOOLS_TEXT = ("\n\n# Tools\n\nYou may call one function per answer.\n\nYou are provided with function signatures within "
              "<tools></tools> XML tags:\n<tools>\n%s\n</tools>\n\nFor the function call, return a json object with the "
              "function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n"
              "{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call>")


def translate_text(request):
    """-> (messages, None, names): the request with its tools written into the system message (TOOLS_TEXT)."""
    msgs, tools, names = translate(request)
    out = [dict(msgs[0])]
    if tools:
        out[0]["content"] += TOOLS_TEXT % "\n".join(json.dumps(t, separators=(",", ":"), sort_keys=True) for t in tools)
    for m in msgs[1:]:
        if m["role"] == "assistant" and m.get("tool_calls"):
            f = m["tool_calls"][0]["function"]
            # name first, as the instructions show and Qwen's template writes it: with sort_keys the history read
            # {"arguments": {..}, "name": ..}, and Qwen3-14B copied that and closed the name inside the arguments
            # (E58, 26 Nov 2026: twelve unreadable calls in a row). The arguments keep their sorted, compact form.
            call = '{"name":%s,"arguments":%s}' % (json.dumps(f["name"]), json.dumps(json.loads(f["arguments"]),
                                                                                  separators=(",", ":"), sort_keys=True))
            text = (m.get("content") or "").strip()
            out.append({"role": "assistant", "content": (text + "\n" if text else "") + "<tool_call>\n%s\n</tool_call>" % call})
        elif m["role"] == "tool":
            out.append({"role": "user", "content": "<tool_response>\n%s\n</tool_response>" % m["content"]})
        else:
            out.append(m)
    return out, None, names


def read_text_answer(raw, names):
    """read_answer for `tools: text`: the <tool_call> blocks of the text become tool calls (the first is taken, the
    others counted), the text outside them stays text. Never raises."""
    import re
    try:
        msg = raw["choices"][0].get("message") or {}
        content = str(msg.get("content") or "")
    except (KeyError, IndexError, TypeError, AttributeError):
        return read_answer(raw, names)
    blocks = re.findall(r"<tool_call>\s*(.*?)\s*</tool_call>", content, re.S)
    calls = []
    for b in blocks:
        try:
            d = json.loads(b)
        except ValueError:
            d = None
        if isinstance(d, dict):
            calls.append({"function": {"name": d.get("name"), "arguments": d.get("arguments")}})
        else:
            calls.append({"function": {"name": None, "arguments": None}})
    text = re.sub(r"<tool_call>.*?(</tool_call>|$)", "", content, flags=re.S).strip()
    if "<tool_call>" in content and not blocks:          # opened, never closed: cut off at the limit
        calls = [{"function": {"name": None, "arguments": None}}]
    fake = dict(raw, choices=[dict(raw["choices"][0], message={"content": text, "tool_calls": calls})])
    out, finish = read_answer(fake, names)
    if calls and out.get("tool") is None and out.get("tool_error") == "no such tool" and calls[0]["function"]["name"] is None:
        out["tool_error"] = unreadable_call(blocks[0] if blocks else content)
    return out, finish


def unreadable_call(written):
    """The refusal of a call the gateway cannot read, quoting what the model wrote (120 characters), so that it can
    correct itself: told only "could not be read", Qwen3-14B wrote the same call twelve times (E58, 26 Nov 2026)."""
    hint = ""
    try:
        d = json.loads(written)
    except ValueError:
        d = None
    if isinstance(d, dict) and "name" not in d and isinstance(d.get("arguments"), dict) and "name" in d["arguments"]:
        hint = "the name goes beside the arguments, not inside them; "
    seen = " ".join(str(written).split())
    seen = seen if len(seen) <= 120 else seen[:119] + "…"
    return ("the tool call could not be read: %s<tool_call> must hold {\"name\": .., \"arguments\": {..}}; you wrote: %s"
            % (hint, seen))



def read_answer(raw, names):
    """The llama-server answer -> ({text, tool, tool_error?}, finish_reason). Never raises. Of several calls the
    first is read and the others are counted in the internal key '_dropped' (the gateway records it beside the
    response, never in it)."""
    try:
        choice = raw["choices"][0]
        msg = choice.get("message") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        return {"text": "", "tool": None, "tool_error": "the model's answer could not be read"}, "error"
    text = str(msg.get("content") or "")[:TEXT_MAX]
    out, calls = {"text": text, "tool": None}, msg.get("tool_calls") or []
    if len(calls) > 1:
        out["_dropped"] = len(calls) - 1
    if calls:
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
    finish = choice.get("finish_reason")
    if finish == "length" and out["tool"] is None and "tool_error" not in out:
        out["tool_error"] = ("the answer was cut off at the output limit without a tool call: "
                             "answer with one tool call, or a short final answer")
    return out, finish


class Llm:
    """llama-server over HTTP. post(path, body) -> (status, object); tests replace it."""
    def __init__(self, base, timeout):
        self.base, self.timeout = base.rstrip("/"), timeout

    def post(self, path, body, headers=None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), h)
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


class LlamaBackend:
    """The model on this host (llama-server): today's request, byte for byte (endpoint 'local')."""
    kind = "llama"

    def __init__(self, llm, alias, model_sha256="", ctx=4096, name="local"):
        self.llm, self.alias, self.model_sha256, self.ctx, self.name = llm, alias, model_sha256, ctx, name
        self.flags = dict(FLAGS)
        self.max_output = LOCAL_MAX_OUTPUT

    def body(self, msgs, tools, max_tokens):
        b = {"model": self.alias, "messages": msgs, "max_tokens": max_tokens, "cache_prompt": True, "stream": False,
             "chat_template_kwargs": {"enable_thinking": False}}
        b.update(SAMPLER)
        if tools:
            b["tools"], b["tool_choice"], b["parallel_tool_calls"] = tools, "auto", False
        return b

    @staticmethod
    def context_full(st, raw):
        return st == 400 and "exceed_context_size" in json.dumps(raw)


class OpenAIBackend:
    """An OpenAI-compatible server (vLLM, Ollama, llama.cpp elsewhere; research Phase 4d): Chat Completions with
    function tools, temperature 0, a seed only where the endpoint says it is deterministic, the API key (if any)
    read from a file mounted into this pod only. Never sends llama-server's own fields."""
    kind = "openai"

    def __init__(self, llm, name, model, ctx, max_output=MAX_TOKENS_CAP, deterministic=False, key_file=None,
                 thinking=None, tools="native"):
        self.llm, self.name, self.alias, self.ctx = llm, name, model, ctx
        self.model_sha256, self.max_output, self.deterministic, self.key_file = "", max_output, deterministic, key_file
        self.thinking, self.tools = thinking, tools
        self.flags = {"sampler": dict({"temperature": 0}, **({"seed": 1} if deterministic else {})),
                      "tool_choice": "auto", "parallel_tool_calls": False, "slots": 1, "endpoint_kind": "openai",
                      "tools": tools}
        if thinking is not None:
            self.flags["enable_thinking"] = thinking
        if tools == "text":
            self.translate, self.read = translate_text, read_text_answer

    def headers(self):
        if not self.key_file:
            return {}
        with open(self.key_file, encoding="utf-8") as f:
            return {"Authorization": "Bearer " + f.read().strip()}

    def body(self, msgs, tools, max_tokens):
        b = {"model": self.alias, "messages": msgs, "max_tokens": max_tokens, "stream": False, "temperature": 0}
        if self.deterministic:
            b["seed"] = 1
        if self.thinking is not None:      # Qwen3 on vLLM thinks unless told (its chat template's switch)
            b["chat_template_kwargs"] = {"enable_thinking": self.thinking}
        if tools:
            b["tools"], b["tool_choice"], b["parallel_tool_calls"] = tools, "auto", False
        return b

    @staticmethod
    def context_full(st, raw):
        t = json.dumps(raw)
        return st == 400 and ("context_length_exceeded" in t or "maximum context length" in t)   # OpenAI / vLLM


ENDPOINT_KINDS = ("llama", "openai")


def load_endpoints(path, enabled, local=None, llm_factory=None, key_dir="/keys"):
    """endpoints.json -> {name: backend} for the names in `enabled` (RS_ENDPOINTS). 'local' is the given
    LlamaBackend (its url and pin come from the deploy's environment); every other entry is
    {kind: openai, url, model, context, max_output?, deterministic?, key: none|secret}. A name enabled but not in
    the file, or of a kind not built yet (anthropic: Phase 5), stops the gateway at start."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    eps, out = doc.get("endpoints") or {}, {}
    for name in enabled:
        e = eps.get(name)
        if not isinstance(e, dict):
            raise ValueError("endpoint %s is enabled but not in %s" % (name, path))
        if name == "local":
            if local is None:
                raise ValueError("endpoint local needs the model on this host (RS_LLM_URL, MODEL_ALIAS)")
            out[name] = local
            continue
        if e.get("kind") not in ENDPOINT_KINDS or e.get("kind") == "llama":
            raise ValueError("endpoint %s: kind %r is not available here" % (name, e.get("kind")))
        if not (isinstance(e.get("url"), str) and e["url"].startswith(("http://", "https://"))
                and isinstance(e.get("model"), str) and isinstance(e.get("context"), int)):
            raise ValueError("endpoint %s needs url, model and context" % name)
        if e.get("tools", "native") not in ("native", "text") or e.get("thinking") not in (None, True, False):
            raise ValueError("endpoint %s: tools is native or text, thinking true, false or absent" % name)
        key = os.path.join(key_dir, name) if e.get("key") == "secret" else None
        if key and not os.path.isfile(key):
            raise ValueError("endpoint %s needs its key at %s (Secret model-gateway-keys)" % (name, key))
        llm = (llm_factory or (lambda u: Llm(u, 540)))(e["url"])
        out[name] = OpenAIBackend(llm, name, e["model"], e["context"], int(e.get("max_output", MAX_TOKENS_CAP)),
                                  bool(e.get("deterministic")), key, e.get("thinking"), e.get("tools", "native"))
    return out


class Gateway:
    def __init__(self, session, llm=None, alias=None, model_sha256="", ctx=4096, backends=None):
        """backends {endpoint name: backend}; the older form (llm, alias, model_sha256, ctx) is the one local model."""
        self.session = session
        self.backends = backends if backends is not None else {"local": LlamaBackend(llm, alias, model_sha256, ctx)}
        first = next(iter(self.backends.values()))
        self.alias = first.alias
        self.slots = {n: threading.Lock() for n in self.backends}

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
        backend = self.backends.get(info.get("backend"))
        if info.get("sid") != sid or backend is None:
            return 403, {"error": "this session does not use a model endpoint this gateway serves"}
        left = info.get("budget_left") or {}
        for k in ("prompt_tokens", "output_tokens"):
            if isinstance(left.get(k), (int, float)) and left[k] <= 0:
                return 403, {"error": "the session's %s budget is spent" % k}
        slot = self.slots[info["backend"]]
        if not slot.acquire(blocking=False):
            return 429, {"error": "busy"}
        try:
            return self._turn(sid, turn, req, left, backend)
        finally:
            slot.release()

    def _turn(self, sid, turn, req, left, backend):
        msgs, tools, names = getattr(backend, "translate", translate)(req)
        out_left = left.get("output_tokens")
        max_tokens = MAX_TOKENS_DEFAULT if not isinstance(out_left, (int, float)) else int(max(16, min(out_left, MAX_TOKENS_CAP)))
        max_tokens = min(max_tokens, MAX_TOKENS_CAP, getattr(backend, "max_output", MAX_TOKENS_CAP))
        st, b = self.session.trace(sid, "turn_request", {
            "turn": turn, "backend": backend.name, "model": backend.alias, "model_sha256": backend.model_sha256,
            "request_sha256": sha(canonical_bytes(req)), "flags": dict(backend.flags, max_tokens=max_tokens, ctx=backend.ctx)})
        if st != 200:
            return (403 if st == 403 else 503), {"error": "the trace did not accept the turn"}
        body = backend.body(msgs, tools, max_tokens)
        hdr = backend.headers() if hasattr(backend, "headers") else {}
        st, raw = backend.llm.post("/v1/chat/completions", body, hdr) if hdr else backend.llm.post("/v1/chat/completions", body)
        if st != 200:
            ctxfull = backend.context_full(st, raw)
            why = "context_full" if ctxfull else "model_error"
            self.session.trace(sid, "turn_response", {"turn": turn, "error": why, "status": st})
            return (413 if ctxfull else 502), {"error": why}
        resp, finish = getattr(backend, "read", read_answer)(raw, names)
        dropped = resp.pop("_dropped", 0)
        u, tm = raw.get("usage") or {}, raw.get("timings") or {}
        usage = {"prompt_tokens": int(u.get("prompt_tokens") or 0), "output_tokens": int(u.get("completion_tokens") or 0),
                 "estimated": False}
        if isinstance(tm.get("cache_n"), int):
            usage["cache_n"] = tm["cache_n"]
        st, b = self.session.trace(sid, "turn_response", {
            "turn": turn, "response": resp, "response_sha256": sha(canonical_bytes(resp)),
            "raw_response_sha256": sha(canonical_bytes(raw)), "finish_reason": finish, "usage": usage,
            **({"dropped_calls": dropped} if dropped else {})})
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
    timeout = float(os.environ.get("RS_LLM_TIMEOUT", "540"))
    local = LlamaBackend(Llm(os.environ.get("RS_LLM_URL", "http://research-llm:8080"), timeout),
                         os.environ["MODEL_ALIAS"], os.environ.get("MODEL_SHA256", ""), int(os.environ.get("LLM_CTX", "4096")))
    enabled = [e for e in os.environ.get("RS_ENDPOINTS", "local").split() if e]
    path = os.environ.get("RS_ENDPOINTS_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints.json"))
    backends = load_endpoints(path, enabled, local, lambda u: Llm(u, timeout))
    gw = Gateway(mcp_common.Session(os.environ["RS_SESSION_SERVER_URL"], "model-gateway"), backends=backends)
    srv = make_http_server(gw, port=int(os.environ.get("RS_GATEWAY_PORT", "8120")))
    sys.stderr.write("model-gateway: port %d, endpoints %s\n" % (srv.server_address[1], " ".join(
        "%s=%s" % (n, b.alias) for n, b in sorted(backends.items()))))
    srv.serve_forever()


if __name__ == "__main__":
    main()
