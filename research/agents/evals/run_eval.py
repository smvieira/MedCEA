"""research/agents/evals/run_eval.py — the offline tool-call eval against one running
llama-server (research Phase 4b step 0, codeplan/rs4-design.md R26). Stdlib (urllib) and
the grader; no lake data, no session, no cluster call: apps/research-model/bench.sh starts
the server and gives its address.

    python3 -m research.agents.evals.run_eval --url http://<pod ip>:8080 --key-file F
        --model-key 8b --alias <name> --out FILE [--fixtures DIR] [--timeout S] [--deadline EPOCH]

1. GET /props (the chat template, so a "Generic" fallback is seen) and one request with
   only the standing prefix (its token count, and the prefix cached for what follows).
2. Every fixture conversation once, greedy (temperature 0, top_k 1, seed 1), thinking off
   (chat_template_kwargs.enable_thinking false), max_tokens 400, cache_prompt true; graded.
3. The 5-turn transcript: each request the previous one plus the model's answer and one
   recorded tool result; timings.prompt_n against the tokens appended (prefix reuse).
The output JSON holds the scores, every grade, and each raw answer with its timings. It is
written after every conversation with "complete": false, so a run that is stopped (a recipe
run starting: bench.sh kills it; the deadline) keeps what it graded; "complete": true only
at the end. --deadline (epoch seconds, bench.sh's one end time for the whole eval) bounds
every request and stops between conversations once passed (exit 3, the partial file kept).
The API key is read from the file and sent as a header; it is never printed.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

from . import grader

MAX_TOKENS = 400


class ServerError(Exception):
    pass


class OutOfTime(Exception):
    pass


class Client:
    def __init__(self, url, key, timeout, deadline=None, clock=time.time):
        self.url = url.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.deadline = deadline
        self.clock = clock

    def left(self):
        return None if self.deadline is None else self.deadline - self.clock()

    def check_time(self):
        left = self.left()
        if left is not None and left <= 0:
            raise OutOfTime("the eval's end time has passed")

    def call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + self.key})
        self.check_time()
        timeout = self.timeout
        left = self.left()
        if left is not None:
            timeout = max(1.0, min(timeout, left))
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise ServerError("%s %s: HTTP %d %s" % (method, path, e.code, e.read()[:200].decode("utf-8", "replace"))) from None
        except (urllib.error.URLError, OSError) as e:
            raise ServerError("%s %s: %s" % (method, path, e)) from None
        try:
            return json.loads(raw), time.monotonic() - t0
        except ValueError:
            raise ServerError("%s %s: not JSON" % (method, path)) from None


def request_body(fx, messages, alias, max_tokens=MAX_TOKENS):
    return {"model": alias, "messages": messages, "tools": fx["tools"], "tool_choice": "auto",
            "temperature": 0, "top_k": 1, "seed": 1, "max_tokens": max_tokens, "cache_prompt": True,
            "chat_template_kwargs": {"enable_thinking": False}}


def _timings(resp, wall):
    t = resp.get("timings") or {}
    u = resp.get("usage") or {}
    return {"prompt_n": t.get("prompt_n"), "prompt_per_second": t.get("prompt_per_second"),
            "predicted_n": t.get("predicted_n"), "predicted_per_second": t.get("predicted_per_second"),
            "cache_n": t.get("cache_n"), "prompt_tokens": u.get("prompt_tokens"),
            "completion_tokens": u.get("completion_tokens"), "wall_s": round(wall, 2)}


def run(client, fx, alias, log=print, save=None):
    """Every conversation, then the transcript. SAVE(out) is called after each step with
    out["complete"] False; OutOfTime stops between steps (out["stopped"] says so)."""
    out = {"alias": alias, "complete": False, "grades": [], "answers": [], "scores": grader.scores([])}
    try:
        _run(client, fx, alias, log, save, out)
    except OutOfTime as e:
        out["stopped"] = str(e)
        log("stopped: %s" % e)
        return out
    out["complete"] = True
    return out


def _run(client, fx, alias, log, save, out):
    save = save or (lambda o: None)
    try:
        props, _ = client.call("GET", "/props")
        tmpl = props.get("chat_template") or ""
        out["props"] = {"chat_template_sha256": hashlib.sha256(tmpl.encode("utf-8")).hexdigest(),
                        "chat_template_has_tools": ("tool_call" in tmpl) or ("tools" in tmpl),
                        "build_info": props.get("build_info"), "model_path": props.get("model_path"),
                        "n_ctx": (props.get("default_generation_settings") or {}).get("n_ctx")}
    except ServerError as e:
        out["props"] = {"error": str(e)}
    resp, wall = client.call("POST", "/v1/chat/completions",
                             request_body(fx, [{"role": "system", "content": fx["standing"]},
                                               {"role": "user", "content": "Reply OK."}], alias, 4))
    out["standing_prefix"] = {"chars": grader.standing_prefix_chars(fx), **_timings(resp, wall)}
    log("standing prefix: %s tokens in %.0f s" % (out["standing_prefix"]["prompt_tokens"], wall))

    grades, answers = [], []
    out["grades"], out["answers"] = grades, answers
    out["scores"] = grader.scores(grades)
    save(out)
    for conv in fx["conversations"]:
        client.check_time()
        body = request_body(fx, grader.build_messages(fx, conv["messages"]), alias)
        try:
            resp, wall = client.call("POST", "/v1/chat/completions", body)
        except ServerError as e:
            resp, wall = {"error": str(e)}, 0.0
        g = grader.grade(fx, conv, resp)
        grades.append(g)
        answers.append({"id": conv["id"], "response": resp, "timings": _timings(resp, wall)})
        out["scores"] = grader.scores(grades)
        save(out)
        log("%-28s %s  %s" % (conv["id"], "pass" if g["passed"] else "FAIL", "; ".join(g["problems"])[:160]))
    out["transcript"] = transcript(client, fx, alias, log)
    save(out)


def transcript(client, fx, alias, log=print):
    tr = fx["transcript"]
    messages = [{"role": "system", "content": fx["standing"]}, {"role": "user", "content": tr["first_user"]}]
    turns = []
    for n in range(tr["turns"]):
        client.check_time()
        try:
            resp, wall = client.call("POST", "/v1/chat/completions", request_body(fx, messages, alias))
        except ServerError as e:
            turns.append({"error": str(e)})
            break
        t = _timings(resp, wall)
        turns.append(t)
        log("transcript turn %d: prompt %s tokens, %s processed (%.0f s)" % (n + 1, t["prompt_tokens"], t["prompt_n"], wall))
        msg = ((resp.get("choices") or [{}])[0].get("message")) or {}
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "", **({"tool_calls": calls} if calls else {})})
        if calls:
            for tc in calls:
                name = ((tc or {}).get("function") or {}).get("name", "?")
                result = tr["results"].get(name, {"error": "no recorded result for %s" % name})
                messages.append({"role": "tool", "tool_call_id": tc.get("id", "?"),
                                 "content": grader.wrap_tool_result(name, tc.get("id", "?"), result, fx["mcp_names"])})
        else:
            messages.append({"role": "user", "content": tr["nudge"]})
    return {"requests": turns, **grader.prefix_reuse([t for t in turns if "error" not in t])}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m research.agents.evals.run_eval")
    ap.add_argument("--url", required=True)
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--model-key", required=True)
    ap.add_argument("--alias", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fixtures", default=grader.FIXTURES)
    ap.add_argument("--timeout", type=float, default=1800)
    ap.add_argument("--deadline", type=float, help="epoch seconds: no request runs past it")
    a = ap.parse_args(argv)
    with open(a.key_file, encoding="ascii") as f:
        key = f.read().strip()
    fx = grader.load_fixtures(a.fixtures)
    t0 = time.monotonic()
    fixtures = sorted(c["id"] for c in fx["conversations"])

    def save(o):
        doc = dict(o, model_key=a.model_key, seconds=round(time.monotonic() - t0, 1), fixtures=fixtures)
        tmp = a.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        os.replace(tmp, a.out)
    try:
        out = run(Client(a.url, key, a.timeout, a.deadline), fx, a.alias, save=save)
    except ServerError as e:
        print("eval: %s" % e, file=sys.stderr)
        return 2
    save(out)
    s = out["scores"]
    print("eval %s: %d/%d passed, tool-call validity %s, spec validity %s, injection resisted %s, prefix %s%s"
          % (a.model_key, s["passed"], s["conversations"], s["tool_call_validity"], s["spec_validity"],
             s["injection_resisted"], (out.get("transcript") or {}).get("verdict", "unmeasured"),
             "" if out["complete"] else " (stopped: %s)" % out.get("stopped")))
    return 0 if out["complete"] else 3


if __name__ == "__main__":
    sys.exit(main())
