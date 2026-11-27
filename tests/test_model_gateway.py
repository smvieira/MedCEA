#!/usr/bin/env python3
"""tests/test_model_gateway.py — research Phase 4b stage 2: apps/research-model/gateway.py against a fake
llama-server and a fake research-session (server port), both real HTTP servers on ephemeral ports.

  Translation   tools as function tools with '.' -> '_' and back, the fixed greedy sampler and nothing else,
                thinking off, cache_prompt, max_tokens bounded, assistant tool calls and tool results in order
  Answers       text, one tool call, usage; a malformed call is text with tool_error, never an exception
  Refusals      no token / refused token 401, another session or a scripted one 403, a spent budget 403,
                a second concurrent turn 429 busy, a bad body 400, a refused trace
  Trace         turn_request and turn_response as actor model-gateway, request sha = the loop's, the failure records
  Secrets       nothing printed to stdout or stderr holds the token or a request body

  python3 tests/test_model_gateway.py
"""
import contextlib
import io
import json
import os
import sys
import threading
import unittest
import tempfile
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "apps", "research-model"))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
import gateway  # noqa: E402
import mcp_common  # noqa: E402
from research.agents import context  # noqa: E402

TOKEN = "rst1.k.SID.9999999999.mac-secret-marker"
SID = "S" * 22


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class FakeSession:
    """research-session's server port: /introspect and /trace."""
    def __init__(self):
        self.events, self.introspects = [], []
        self.info = {"active": True, "sid": SID, "backend": "local", "tools": ["lake.snapshots"],
                     "budget_left": {"prompt_tokens": 1000, "output_tokens": 800}}
        self.refuse = set()
        me = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/introspect":
                    me.introspects.append(b)
                    out = me.info if b["token"] == TOKEN else {"active": False}
                    code = 200
                elif self.path == "/trace":
                    if b["event"] in me.refuse:
                        code, out = 403, {"error": "refused"}
                    else:
                        me.events.append(b)
                        code, out = 200, {"event_id": len(me.events)}
                else:
                    code, out = 404, {}
                raw = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        self.srv = serve(H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]


class FakeLlama:
    def __init__(self):
        self.requests, self.answer, self.status, self.gate = [], None, 200, None
        self.headers = []
        me = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                me.requests.append((self.path, b))
                me.headers.append(dict(self.headers))
                if me.gate:
                    me.gate.wait(5)
                out = me.answer if me.answer is not None else text_answer("done")
                raw = json.dumps(out).encode()
                self.send_response(me.status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        self.srv = serve(H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]


def text_answer(text, calls=None, finish="stop"):
    msg = {"role": "assistant", "content": text}
    if calls is not None:
        msg["tool_calls"] = calls
    return {"choices": [{"message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 321, "completion_tokens": 17}, "timings": {"cache_n": 300}}


def call(name, args):
    return {"id": "x", "type": "function", "function": {"name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}}


REQ = {"system": "SYS", "tools": [
    {"name": "lake.snapshots", "description": "List snapshots.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "sim.run", "description": "Run.", "inputSchema": {"type": "object", "properties": {"spec": {"type": "object"}}}}],
    "messages": [{"role": "user", "content": "Do it."}]}


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.sess, self.llm = FakeSession(), FakeLlama()
        self.gw = gateway.Gateway(mcp_common.Session(self.sess.url, "model-gateway"), gateway.Llm(self.llm.url, 5),
                                  "alias-1", "ab" * 32, 4096)

    def tearDown(self):
        for s in (self.sess.srv, self.llm.srv):
            s.shutdown()
            s.server_close()

    def turn(self, req=None, token=TOKEN, turn=1, sid=SID):
        return self.gw.turn(token, "10.0.0.7", {"sid": sid, "turn": turn, "request": req or REQ})

    # ── translation
    def test_translation_and_the_fixed_sampler(self):
        self.llm.answer = text_answer("ok")
        st, out = self.turn()
        self.assertEqual(st, 200)
        path, b = self.llm.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual([t["function"]["name"] for t in b["tools"]], ["lake_snapshots", "sim_run"])
        self.assertEqual(b["tools"][1]["function"]["parameters"]["properties"], {"spec": {"type": "object"}})
        self.assertEqual(b["tool_choice"], "auto")
        self.assertEqual(b["chat_template_kwargs"], {"enable_thinking": False})
        self.assertIs(b["cache_prompt"], True)
        # nothing in the body but the fixed greedy set, the model, the messages and the caps
        self.assertEqual(set(b) - {"model", "messages", "tools", "tool_choice", "max_tokens", "cache_prompt", "stream",
                                   "chat_template_kwargs", "parallel_tool_calls"}, {"temperature", "top_k", "seed"})
        self.assertIs(b["parallel_tool_calls"], False)
        self.assertEqual((b["temperature"], b["top_k"], b["seed"]), (0, 1, 1))
        self.assertEqual(b["model"], "alias-1")
        self.assertEqual(b["messages"], [{"role": "system", "content": "SYS"}, {"role": "user", "content": "Do it."}])

    def test_history_with_a_tool_call_and_its_result(self):
        req = dict(REQ, messages=REQ["messages"] + [
            {"role": "assistant", "content": "plan", "tool_call": {"name": "lake.snapshots", "args": {}}},
            {"role": "tool", "content": "<tool_result>x</tool_result>"}])
        self.turn(req, turn=2)
        m = self.llm.requests[0][1]["messages"]
        self.assertEqual(m[2]["tool_calls"][0]["function"]["name"], "lake_snapshots")
        self.assertEqual(m[2]["tool_calls"][0]["function"]["arguments"], "{}")
        self.assertEqual(m[3], {"role": "tool", "tool_call_id": m[2]["tool_calls"][0]["id"], "content": "<tool_result>x</tool_result>"})

    def test_max_tokens_is_bounded_by_the_session_and_the_local_limit(self):
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], gateway.LOCAL_MAX_OUTPUT)      # 800 left
        self.sess.info["budget_left"]["output_tokens"] = 5000
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], 400)
        self.sess.info["budget_left"]["output_tokens"] = 250
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], 250)
        self.sess.info["budget_left"]["output_tokens"] = 3
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], 16)

    def test_no_tools_sends_none(self):
        self.turn(dict(REQ, tools=[]))
        self.assertNotIn("tools", self.llm.requests[0][1])
        self.assertNotIn("tool_choice", self.llm.requests[0][1])

    # ── answers
    def test_a_tool_call_is_mapped_back(self):
        self.llm.answer = text_answer("Plan.", [call("sim_run", {"spec": {"a": 1}})])
        st, out = self.turn()
        self.assertEqual(st, 200)
        self.assertEqual(out["tool"], {"name": "sim.run", "args": {"spec": {"a": 1}}})
        self.assertEqual(out["text"], "Plan.")
        self.assertEqual(out["usage"], {"prompt_tokens": 321, "output_tokens": 17, "estimated": False, "cache_n": 300})
        self.assertNotIn("tool_error", out)

    def test_malformed_calls_are_text_with_an_error_flag(self):
        for name, ans in (("unknown tool", text_answer("", [call("nope", {})])),
                          ("arguments not JSON", text_answer("", [call("sim_run", "{broken")])),
                          ("arguments not an object", text_answer("", [call("sim_run", "[1]")])),
                          ("written as text", text_answer('<tool_call>{"name": "sim_run"}</tool_call>')),
                          ("no choices", {"error": "x"})):
            with self.subTest(name):
                self.llm.answer = ans
                st, out = self.turn()
                self.assertEqual(st, 200)
                self.assertIsNone(out["tool"])
                self.assertTrue(out["tool_error"])
                self.assertIn("text", out)

    def test_of_several_calls_the_first_is_taken(self):
        """E49, 25 Nov 2026: the local model wrote several calls in one answer; one is asked for
        (parallel_tool_calls false), and of several the first is read and the rest counted in the record."""
        self.llm.answer = text_answer("", [call("sim_run", {"spec": {}}), call("lake_snapshots", {})], finish="length")
        st, out = self.turn()
        self.assertEqual(st, 200)
        self.assertEqual(out["tool"], {"name": "sim.run", "args": {"spec": {}}})
        self.assertNotIn("tool_error", out)
        self.assertNotIn("_dropped", out)
        rec = [e for e in self.sess.events if e["event"] == "turn_response"][-1]["payload"]
        self.assertEqual(rec["dropped_calls"], 1)
        self.assertNotIn("_dropped", rec["response"])
        self.assertIs(self.llm.requests[-1][1]["parallel_tool_calls"], False)
        req = [e for e in self.sess.events if e["event"] == "turn_request"][-1]["payload"]
        self.assertIs(req["flags"]["parallel_tool_calls"], False)
        # a bad first call is still a refused call
        self.llm.answer = text_answer("", [call("nope", {}), call("sim_run", {})])
        self.assertTrue(self.turn()[1]["tool_error"])
        self.llm.answer = text_answer("", [call("sim_run", {})])
        self.turn()
        rec = [e for e in self.sess.events if e["event"] == "turn_response"][-1]["payload"]
        self.assertNotIn("dropped_calls", rec)

    def test_an_answer_cut_at_the_limit_is_a_refused_call(self):
        """E49, 24 Nov 2026: a runaway answer must come back as something the model can retry, not model_error."""
        self.llm.answer = text_answer("I will now " * 50, finish="length")
        st, out = self.turn()
        self.assertEqual(st, 200)
        self.assertIsNone(out["tool"])
        self.assertIn("cut off", out["tool_error"])
        self.llm.answer = text_answer("", [call("sim_run", {"spec": {}})], finish="length")
        st, out = self.turn()
        self.assertEqual(out["tool"], {"name": "sim.run", "args": {"spec": {}}})                # a whole call stands
        self.assertNotIn("tool_error", out)
        self.llm.answer = text_answer("All done.", finish="stop")
        self.assertNotIn("tool_error", self.turn()[1])

    def test_text_is_cut(self):
        self.llm.answer = text_answer("x" * 5000)
        self.assertEqual(len(self.turn()[1]["text"]), gateway.TEXT_MAX)

    # ── refusals
    def test_introspection_refusals(self):
        self.assertEqual(self.turn(token=None)[0], 401)
        self.assertEqual(self.turn(token="bad")[0], 401)
        self.assertEqual(self.sess.introspects[-1], {"token": "bad", "audience": "model-gateway", "peer": "10.0.0.7"})
        self.assertEqual(self.llm.requests, [])
        self.assertEqual(self.sess.events, [])

    def test_wrong_session_or_backend(self):
        self.assertEqual(self.turn(sid="T" * 22)[0], 403)
        self.sess.info["backend"] = "scripted"
        self.assertEqual(self.turn()[0], 403)
        self.assertEqual(self.llm.requests, [])

    def test_a_spent_budget_is_refused_before_the_model(self):
        self.sess.info["budget_left"]["prompt_tokens"] = 0
        st, out = self.turn()
        self.assertEqual(st, 403)
        self.assertIn("prompt_tokens", out["error"])
        self.sess.info["budget_left"] = {"output_tokens": -1}
        self.assertEqual(self.turn()[0], 403)
        self.assertEqual(self.llm.requests, [])
        self.assertEqual(self.sess.events, [])

    def test_bad_bodies(self):
        for body in (None, [], {"sid": SID}, {"sid": SID, "turn": 0, "request": REQ}, {"sid": SID, "turn": True, "request": REQ},
                     {"sid": SID, "turn": 1, "request": {"system": "x"}},
                     {"sid": SID, "turn": 1, "request": dict(REQ, messages=[{"role": "system", "content": "x"}])},
                     {"sid": SID, "turn": 1, "request": dict(REQ, tools=[{"description": "no name"}])}):
            with self.subTest(body=str(body)[:40]):
                self.assertEqual(self.gw.turn(TOKEN, "10.0.0.7", body)[0], 400)
        self.assertEqual(self.sess.introspects, [])

    def test_one_slot_a_second_turn_is_busy(self):
        self.llm.gate = threading.Event()
        res = []
        t = threading.Thread(target=lambda: res.append(self.turn()))
        t.start()
        for _ in range(100):
            if self.llm.requests:
                break
            threading.Event().wait(0.02)
        self.assertEqual(self.turn(), (429, {"error": "busy"}))
        self.llm.gate.set()
        t.join(5)
        self.assertEqual(res[0][0], 200)
        self.assertEqual(self.turn()[0], 200)      # the slot is free again

    # ── trace
    def test_the_trace_records_both_sides_as_the_gateway(self):
        self.llm.answer = text_answer("Plan.", [call("sim_run", {"spec": {}})])
        st, out = self.turn(turn=3)
        ev = self.sess.events
        self.assertEqual([e["event"] for e in ev], ["turn_request", "turn_response"])
        self.assertTrue(all(e["server"] == "model-gateway" and e["sid"] == SID for e in ev))
        rq, rs = ev[0]["payload"], ev[1]["payload"]
        self.assertEqual(rq["turn"], 3)
        self.assertEqual(rq["backend"], "local")
        self.assertEqual(rq["model"], "alias-1")
        self.assertEqual(rq["model_sha256"], "ab" * 32)
        self.assertEqual(rq["request_sha256"], context.sha(context.canonical(REQ)))   # the loop's own hash
        self.assertEqual(rq["flags"]["sampler"], {"temperature": 0, "top_k": 1, "seed": 1})
        self.assertIs(rq["flags"]["enable_thinking"], False)
        resp = {"text": "Plan.", "tool": {"name": "sim.run", "args": {"spec": {}}}}
        self.assertEqual(rs["response"], resp)
        self.assertEqual(rs["response_sha256"], context.sha(context.canonical(resp)))
        self.assertEqual(rs["usage"]["prompt_tokens"], 321)
        self.assertRegex(rs["raw_response_sha256"], "^[0-9a-f]{64}$")
        self.assertEqual(out["usage"], rs["usage"])

    def test_the_asking_agent_is_recorded_on_both_sides(self):
        # research Phase 4e (design 2.1): absent = the lead a0; a sub-agent's id is copied; a malformed one is 400
        self.turn()
        self.assertEqual([e["payload"]["agent"] for e in self.sess.events], ["a0", "a0"])
        st, _ = self.gw.turn(TOKEN, "10.0.0.7", {"sid": SID, "agent": "a0.2", "turn": 1, "request": REQ})
        self.assertEqual(st, 200)
        self.assertEqual([e["payload"]["agent"] for e in self.sess.events[2:]], ["a0.2", "a0.2"])
        n = len(self.sess.events)
        for bad in ("a1", "a0.0", "a0.1.2.3.4", 7, ""):
            st, _ = self.gw.turn(TOKEN, "10.0.0.7", {"sid": SID, "agent": bad, "turn": 1, "request": REQ})
            self.assertEqual(st, 400, bad)
        self.assertEqual(len(self.sess.events), n)          # nothing recorded for a refused body

    def test_a_refused_request_record_refuses_the_turn(self):
        self.sess.refuse = {"turn_request"}
        self.assertEqual(self.turn()[0], 403)
        self.assertEqual(self.llm.requests, [])

    def test_a_refused_response_record_withholds_the_answer(self):
        self.sess.refuse = {"turn_response"}
        self.assertEqual(self.turn()[0], 403)

    def test_a_model_failure_is_recorded_and_answered(self):
        self.llm.status, self.llm.answer = 500, {"error": "boom"}
        self.assertEqual(self.turn()[0], 502)
        self.assertEqual(self.sess.events[-1]["payload"], {"agent": "a0", "turn": 1, "error": "model_error", "status": 500})
        self.llm.status, self.llm.answer = 400, {"error": {"type": "exceed_context_size_error"}}
        self.assertEqual(self.turn(turn=2)[0], 413)
        self.assertEqual(self.sess.events[-1]["payload"]["error"], "context_full")

    def test_an_unreachable_model_is_a_502(self):
        self.gw.backends["local"].llm = gateway.Llm("http://127.0.0.1:1", 1)
        self.assertEqual(self.turn()[0], 502)

    # ── the HTTP face and secrets
    def test_http_and_nothing_secret_is_printed(self):
        srv = gateway.make_http_server(self.gw, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:%d" % srv.server_address[1]
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                req = urllib.request.Request(url + "/v1/turn", json.dumps({"sid": SID, "turn": 1, "request": REQ}).encode(),
                                             {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    self.assertEqual(r.status, 200)
                    self.assertIn("usage", json.loads(r.read()))
                bad = urllib.request.Request(url + "/v1/turn", b"{}", {"Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(bad, timeout=5)
                self.assertEqual(e.exception.code, 400)
                with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
                    self.assertEqual(json.loads(r.read())["model"], "alias-1")
        finally:
            srv.shutdown()
            srv.server_close()
        text = out.getvalue() + err.getvalue()
        for secret in (TOKEN, "mac-secret-marker", "Do it."):
            self.assertNotIn(secret, text)
        src = open(os.path.join(ROOT, "apps", "research-model", "gateway.py")).read()
        self.assertNotIn("print(", src)
        self.assertNotRegex(src, r"stderr\.write\([^)]*(token|body|request)")


if __name__ == "__main__":
    unittest.main()


class EndpointTest(unittest.TestCase):
    """Research Phase 4d: a session names its endpoint; the gateway serves only those it was given."""
    def setUp(self):
        self.sess, self.llm, self.remote = FakeSession(), FakeLlama(), FakeLlama()
        d = tempfile.mkdtemp()
        self.key = os.path.join(d, "api-key")
        with open(self.key, "w") as f:
            f.write("k-123\n")
        self.gw = gateway.Gateway(mcp_common.Session(self.sess.url, "model-gateway"), backends={
            "local": gateway.LlamaBackend(gateway.Llm(self.llm.url, 5), "alias-1", "ab" * 32, 4096),
            "gpu-lab": gateway.OpenAIBackend(gateway.Llm(self.remote.url, 5), "gpu-lab", "Qwen/Qwen3-32B", 32768, 2048,
                                             deterministic=True, key_file=self.key)})

    def tearDown(self):
        for s in (self.sess.srv, self.llm.srv, self.remote.srv):
            s.shutdown()
            s.server_close()

    def turn(self):
        return self.gw.turn(TOKEN, "10.0.0.7", {"sid": SID, "turn": 1, "request": REQ})

    def test_an_openai_endpoint_gets_a_plain_request_and_its_key(self):
        self.sess.info["backend"] = "gpu-lab"
        self.assertEqual(self.turn()[0], 200)
        self.assertEqual(self.llm.requests, [])
        path, body = self.remote.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual((body["model"], body["temperature"], body["seed"], body["tool_choice"]), ("Qwen/Qwen3-32B", 0, 1, "auto"))
        for k in ("top_k", "cache_prompt", "chat_template_kwargs"):
            self.assertNotIn(k, body)
        self.assertEqual(self.remote.headers[0].get("Authorization"), "Bearer k-123")
        req = next(e for e in self.sess.events if e["event"] == "turn_request")["payload"]
        self.assertEqual((req["backend"], req["model"]), ("gpu-lab", "Qwen/Qwen3-32B"))
        self.assertNotIn("k-123", json.dumps(self.sess.events))

    def test_a_non_deterministic_endpoint_gets_no_seed(self):
        self.gw.backends["gpu-lab"].deterministic = False
        self.sess.info["backend"] = "gpu-lab"
        self.turn()
        self.assertNotIn("seed", self.remote.requests[0][1])

    def test_the_local_request_is_unchanged(self):
        self.assertEqual(self.turn()[0], 200)
        body = self.llm.requests[0][1]
        self.assertEqual((body["top_k"], body["cache_prompt"], body["seed"]), (1, True, 1))
        self.assertNotIn("Authorization", self.llm.headers[0])

    def text_backend(self):
        b = gateway.OpenAIBackend(gateway.Llm(self.remote.url, 5), "gpu", "Qwen/Qwen3-14B-AWQ", 12288, 1024,
                                  deterministic=True, key_file=self.key, thinking=False, tools="text")
        self.gw.backends["gpu"] = b
        self.gw.slots["gpu"] = __import__("threading").Lock()
        self.sess.info["backend"] = "gpu"
        return b

    def test_thinking_off_and_tools_as_text(self):
        """A vLLM server without native tool calls (tools: text) and Qwen3's thinking switched off (thinking: false)."""
        self.text_backend()
        self.remote.answer = text_answer('Estimating.\n<tool_call>\n{"name": "sim_run", "arguments": {"spec": {"a": 1}}}\n</tool_call>')
        req = dict(REQ, messages=REQ["messages"] + [
            {"role": "assistant", "content": "First.", "tool_call": {"name": "lake.snapshots", "args": {}}},
            {"role": "tool", "content": "<tool_result>[]</tool_result>"}])
        st, out = self.gw.turn(TOKEN, "10.0.0.7", {"sid": SID, "turn": 2, "request": req})
        self.assertEqual(st, 200, out)
        self.assertEqual(out["tool"], {"name": "sim.run", "args": {"spec": {"a": 1}}})
        self.assertEqual(out["text"], "Estimating.")
        body = self.remote.requests[-1][1]
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        for k in ("tools", "tool_choice", "parallel_tool_calls", "top_k", "cache_prompt"):
            self.assertNotIn(k, body)
        m = body["messages"]
        self.assertTrue(m[0]["content"].startswith("SYS\n\n# Tools"))
        self.assertIn('"name":"sim_run"', m[0]["content"])
        self.assertEqual(m[2], {"role": "assistant", "content": 'First.\n<tool_call>\n{"name":"lake_snapshots","arguments":{}}\n</tool_call>'})
        self.assertEqual(m[3], {"role": "user", "content": "<tool_response>\n<tool_result>[]</tool_result>\n</tool_response>"})
        self.assertEqual(self.remote.headers[-1].get("Authorization"), "Bearer k-123")
        rq = [e for e in self.sess.events if e["event"] == "turn_request"][-1]["payload"]
        self.assertEqual((rq["flags"]["tools"], rq["flags"]["enable_thinking"]), ("text", False))

    def test_an_unreadable_call_is_quoted_within_the_agents_limit(self):
        long = '{"name": "sim_run", "arguments": {"spec": ' + '{"code": "PID", "params": {}}, ' * 20
        e = gateway.unreadable_call(long)
        self.assertIn("you wrote: {\"name\": \"sim_run\"", e)
        self.assertTrue(e.endswith("\u2026"))
        self.assertLessEqual(len("malformed tool call: " + e), 300)       # loop.ERROR_MAX: never cut

    def test_text_calls_that_cannot_be_read(self):
        self.text_backend()
        for name, content, want in (
                ("no closing tag", '<tool_call>\n{"name": "sim_run", "argu', "could not be read"),
                ("not JSON", "<tool_call>\n{name: sim_run}\n</tool_call>", "could not be read"),
                # E58, 26 Nov 2026: Qwen3-14B's answer, name inside the arguments (its history read name last)
                ("name inside the arguments",
                 '<tool_call>\n{"arguments":{"cid":"c76a9a5d7577ed723c3a3","name":"sim_results"}\n}\n</tool_call>',
                 'beside the arguments, not inside them; <tool_call> must hold {"name": .., "arguments": {..}}; '
                 'you wrote: {"arguments":{"cid":"c76a9a5d7577ed723c3a3","name":"sim_results"} }'),
                ("unknown tool", '<tool_call>{"name": "nope", "arguments": {}}</tool_call>', "no such tool"),
                ("arguments not an object", '<tool_call>{"name": "sim_run", "arguments": [1]}</tool_call>', "not a JSON object")):
            with self.subTest(name):
                self.remote.answer = text_answer(content)
                st, out = self.turn()
                self.assertEqual(st, 200)
                self.assertIsNone(out["tool"])
                self.assertIn(want, out["tool_error"])
        self.remote.answer = text_answer('<tool_call>{"name": "sim_run", "arguments": {}}</tool_call>'
                                         '<tool_call>{"name": "lake_snapshots", "arguments": {}}</tool_call>')
        st, out = self.turn()
        self.assertEqual(out["tool"], {"name": "sim.run", "args": {}})
        self.assertEqual([e for e in self.sess.events if e["event"] == "turn_response"][-1]["payload"]["dropped_calls"], 1)
        self.remote.answer = text_answer("The plan is complete.")
        st, out = self.turn()
        self.assertEqual((out["tool"], out.get("tool_error"), out["text"]), (None, None, "The plan is complete."))

    def test_a_vllm_context_overflow_is_context_full(self):
        """vLLM answers 400 'This model's maximum context length is …' (checked against the server on 25 Nov 2026)."""
        b = self.text_backend()
        self.assertTrue(b.context_full(400, {"error": {"message": "This model's maximum context length is 12288 tokens. However, "
                                                       "your prompt contains at least 12289 input tokens", "code": 400}}))
        self.assertFalse(b.context_full(400, {"error": {"message": "\"auto\" tool choice requires --enable-auto-tool-choice"}}))

    def test_a_session_of_an_endpoint_not_served_is_refused(self):
        self.sess.info["backend"] = "claude"
        self.assertEqual(self.turn()[0], 403)
        self.sess.info["backend"] = "scripted"
        self.assertEqual(self.turn()[0], 403)

    def test_load_endpoints(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "endpoints.json")
        with open(p, "w") as f:
            json.dump({"endpoints": {"local": {"kind": "llama"},
                                     "gpu-lab": {"kind": "openai", "url": "http://192.168.1.50:8000", "model": "m", "context": 32768,
                                                 "key": "secret"},
                                     "claude": {"kind": "anthropic", "model": "x", "context": 1}}}, f)
        local = self.gw.backends["local"]
        k = tempfile.mkdtemp()
        with self.assertRaises(ValueError):                  # a secret key that is not mounted stops the gateway
            gateway.load_endpoints(p, ["local", "gpu-lab"], local, key_dir=k)
        with open(os.path.join(k, "gpu-lab"), "w") as f:
            f.write("k-1\n")
        b = gateway.load_endpoints(p, ["local", "gpu-lab"], local, key_dir=k)
        self.assertIs(b["local"], local)
        self.assertEqual((b["gpu-lab"].alias, b["gpu-lab"].key_file, b["gpu-lab"].deterministic, b["gpu-lab"].tools,
                          b["gpu-lab"].thinking), ("m", os.path.join(k, "gpu-lab"), False, "native", None))
        for enabled in (["nope"], ["claude"]):
            with self.assertRaises(ValueError):
                gateway.load_endpoints(p, enabled, local)

    def test_the_shipped_file_enables_only_the_local_model(self):
        p = os.path.join(ROOT, "apps", "research-model", "endpoints.json")
        with open(p) as f:
            self.assertEqual(sorted(json.load(f)["endpoints"]), ["local"])
        self.assertEqual(list(gateway.load_endpoints(p, ["local"], self.gw.backends["local"])), ["local"])

