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
        me = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                me.requests.append((self.path, b))
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
                                   "chat_template_kwargs"}, {"temperature", "top_k", "seed"})
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

    def test_max_tokens_is_bounded_by_the_session_and_1024(self):
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], 800)
        self.sess.info["budget_left"]["output_tokens"] = 5000
        self.turn()
        self.assertEqual(self.llm.requests[-1][1]["max_tokens"], 1024)
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
                          ("two calls", text_answer("", [call("sim_run", {}), call("lake_snapshots", {})])),
                          ("written as text", text_answer('<tool_call>{"name": "sim_run"}</tool_call>')),
                          ("no choices", {"error": "x"})):
            with self.subTest(name):
                self.llm.answer = ans
                st, out = self.turn()
                self.assertEqual(st, 200)
                self.assertIsNone(out["tool"])
                self.assertTrue(out["tool_error"])
                self.assertIn("text", out)

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
        self.assertEqual(self.sess.events[-1]["payload"], {"turn": 1, "error": "model_error", "status": 500})
        self.llm.status, self.llm.answer = 400, {"error": {"type": "exceed_context_size_error"}}
        self.assertEqual(self.turn(turn=2)[0], 413)
        self.assertEqual(self.sess.events[-1]["payload"]["error"], "context_full")

    def test_an_unreachable_model_is_a_502(self):
        self.gw.llm = gateway.Llm("http://127.0.0.1:1", 1)
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
