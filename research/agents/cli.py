#!/usr/bin/env python3
"""medcea-agent (research Phase 4a, stage 6a; design AH.11, R12, R34). Stdlib only, and byte-equal
to the medcea_agent.py the workbench-examples ConfigMap delivers to notebooks (research Phase 4a), so it
imports nothing from this repository.

  medcea-agent endpoints                                      the model picker: the models this install offers
  medcea-agent start PROFILE [--budget k=v ...] [--ttl-s N] [--endpoint NAME]
                                                              start a session (on NAME's model); prints its id
  medcea-agent watch SID                                      follow the trace until the agent stops
  medcea-agent approve SID GID [--note T] [--cap-h H]         approve a gate (the supervisor only)
  medcea-agent deny SID GID [--note T]
  medcea-agent accept SID PID | discard SID PID [--note T]    decide a proposal
  medcea-agent stop SID                                       revoke the session, delete its Jobs
  medcea-agent replay SID                                     strict replay verdict (a Job; waits for it)
  medcea-agent reexecute SID                                  run the session's profile again and compare the model's answers
  medcea-agent signin                                         device sign-in only

The person signs in with a device code through the orchestrator's relay (the notebook has no
route to Keycloak); the tokens live in this process's memory only and are refreshed through the
same relay. In a notebook: c = Client(); c.signin(); c.start("compare_controllers").
MEDCEA_ORCHESTRATOR names the orchestrator (default http://research-orchestrator.<namespace>:8090,
namespace from MEDCEA_AGENTS_NAMESPACE)."""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REFRESH_MARGIN_S = 60


class CliError(Exception):
    pass


class Transport:
    def __init__(self, base, timeout=30):
        self.base, self.timeout = base.rstrip("/"), timeout

    def request(self, method, path, body=None, token=None):
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
            h["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, None if body is None else json.dumps(body).encode(), h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (OSError, ValueError) as e:
            raise CliError("the orchestrator is not reachable (%s)" % type(e).__name__)


def _epoch(ts):
    """An event's 'at' (ISO 8601, as the orchestrator returns it) as seconds since the epoch."""
    from datetime import datetime
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def _sid(x):
    """A session id, or what start() returned ({"sid": ..., "exp": ..., "job": ...})."""
    return x["sid"] if isinstance(x, dict) else x


class Client:
    def __init__(self, transport=None, sleep=time.sleep, clock=time.time, out=None):
        if transport is None:
            base = os.environ.get("MEDCEA_ORCHESTRATOR") or "http://research-orchestrator.%s:8090" % (
                os.environ.get("MEDCEA_AGENTS_NAMESPACE", "medcea-research-agents"))
            transport = Transport(base)
        self.t, self.sleep, self.clock = transport, sleep, clock
        self.out = out or (lambda s: print(s, flush=True))
        self.access = self.refresh_token = None
        self.expires = 0

    # ── sign-in (R12)
    def signin(self, timeout_s=600):
        st, d = self.t.request("POST", "/api/signin/start", {})
        if st != 200:
            raise CliError("sign-in could not start (%s)" % (d or {}).get("error", st))
        self.out("Open %s and enter the code %s" % (d.get("verification_uri_complete") or d["verification_uri"], d["user_code"]))
        end, wait = self.clock() + min(timeout_s, int(d.get("expires_in", 600))), max(1, int(d.get("interval", 5)))
        while self.clock() < end:
            self.sleep(wait)
            st, r = self.t.request("POST", "/api/signin/poll", {"device_code": d["device_code"]})
            if st == 200:
                return self._take(r)
            err = (r or {}).get("error")
            if err == "slow_down":
                wait += 5
            elif err != "authorization_pending":
                raise CliError("sign-in failed (%s)" % (err or st))
        raise CliError("sign-in timed out")

    def _take(self, r):
        self.access, self.refresh_token = r["access_token"], r.get("refresh_token") or self.refresh_token
        self.expires = self.clock() + int(r.get("expires_in", 300))

    def token(self):
        if not self.access:
            raise CliError("not signed in: run signin first")
        if self.clock() > self.expires - REFRESH_MARGIN_S:
            st, r = self.t.request("POST", "/api/signin/refresh", {"refresh_token": self.refresh_token})
            if st != 200:
                self.access = None
                raise CliError("the sign-in ended: sign in again")
            self._take(r)
        return self.access

    def _call(self, method, path, body=None):
        st, r = self.t.request(method, path, body, self.token())
        if st >= 400:
            raise CliError("%s (%s)" % ((r or {}).get("error", "refused"), st))
        return r

    # ── commands
    def endpoints(self):
        """The model picker: the model endpoints this install offers, [{name, model, context, deterministic, tools,
        where}]. Pass a name as start(profile, endpoint=name)."""
        return self._call("GET", "/api/sessions").get("endpoints", [])

    def start(self, profile, budget=None, ttl_s=None, endpoint=None):
        """endpoint: one of endpoints()' names, instead of the profile's own model (a model profile only)."""
        body = {"profile": profile}
        if endpoint:
            body["endpoint"] = endpoint
        if budget:
            body["budget"] = budget
        if ttl_s:
            body["ttl_s"] = ttl_s
        return self._call("POST", "/api/sessions", body)

    def info(self, sid):
        sid = _sid(sid)
        return self._call("GET", "/api/sessions/" + sid)

    def events(self, sid, after=0):
        sid = _sid(sid)
        return self._call("GET", "/api/sessions/%s/events?after=%d" % (sid, after))["events"]

    def answer(self, sid, kind, xid, decision, note="", cap_h=None):
        sid = _sid(sid)
        body = {"decision": decision, "note": note}
        if cap_h is not None:
            body["approved_cap_h"] = cap_h
        return self._call("POST", "/api/sessions/%s/%s/%s" % (sid, kind, urllib.parse.quote(xid)), body)

    def stop(self, sid):
        sid = _sid(sid)
        return self._call("POST", "/api/sessions/%s/stop" % sid, {})

    def replay(self, sid, wait_s=600, poll_s=5):
        """Strict replay, run by the orchestrator as a Job: asks, then asks again every poll_s seconds until the verdict
        {ok, first_mismatch, events} is there (the answer is 202 {state: running} until then). Right after the agent's
        stop the orchestrator still counts the session as running until it sees the Job end (a few seconds): that 409
        is waited out while the record holds a stop; a session still at work is refused at once."""
        sid = _sid(sid)
        t0 = self.clock()
        while True:
            st, r = self.t.request("POST", "/api/sessions/%s/replay" % sid, {}, self.token())
            if st == 409 and "still running" in str((r or {}).get("error", "")) \
                    and any(e["event"] == "stop" for e in self.events(sid)) and self.clock() - t0 <= wait_s:
                self.sleep(poll_s)
                continue
            if st >= 400:
                raise CliError("%s (%s)" % ((r or {}).get("error", "refused"), st))
            if not (isinstance(r, dict) and r.get("state") == "running"):
                return r
            if self.clock() - t0 > wait_s:
                raise CliError("the replay Job is still running after %d s: ask again later" % wait_s)
            self.sleep(poll_s)

    @staticmethod
    def turns(events):
        """{turn: (request_sha256, response_sha256 or None, seconds or None)} from the model-gateway's records of a
        local session (a scripted session has none: its answers are the profile's)."""
        out, at = {}, {}
        for e in events:
            p = e.get("payload") or {}
            if e.get("actor") != "model-gateway" or not isinstance(p.get("turn"), int):
                continue
            t = p["turn"]
            if e["event"] == "turn_request":
                out[t], at[t] = (p.get("request_sha256"), None, None), e.get("at")
            elif e["event"] == "turn_response" and t in out:
                secs = None
                if at.get(t) and e.get("at"):
                    try:
                        secs = round(_epoch(e["at"]) - _epoch(at[t]), 3)
                    except ValueError:
                        secs = None
                out[t] = (out[t][0], p.get("response_sha256"), secs)
        return out

    @classmethod
    def compare_turns(cls, first, second):
        """E49's re-execution check (design 5.4: not evidence, a measurement). Turn by turn, while both sessions sent
        the model the same request, its answers must be the same (greedy, one slot, the same seed and pin). The
        first request that differs (a tool result changed, e.g. a timing-based estimate) ends the comparison:
        what follows is a different conversation. rate = same answers / turns compared."""
        a, b = cls.turns(first), cls.turns(second)
        compared, same, first_diff, ended = 0, 0, None, None
        for t in sorted(set(a) & set(b)):
            if a[t][0] != b[t][0]:
                ended = {"turn": t, "why": "the requests differ (an earlier tool result changed)"}
                break
            if a[t][1] is None or b[t][1] is None:
                ended = {"turn": t, "why": "a turn has no answer"}
                break
            compared += 1
            if a[t][1] == b[t][1]:
                same += 1
            elif first_diff is None:
                first_diff = t
        return {"turns_compared": compared, "same_answers": same,
                "rate": round(same / compared, 4) if compared else None,
                "first_different_answer": first_diff, "ended": ended,
                "seconds": {"first": [a[t][2] for t in sorted(a)], "second": [b[t][2] for t in sorted(b)]}}

    def reexecute(self, sid, watch=True):
        """Start a new session with SID's profile and compare the model's answers turn by turn (compare_turns).
        The new session runs like any other (its gate, its budget); returns the comparison and both ids."""
        sid = _sid(sid)
        info = self.info(sid)
        if info.get("backend") in (None, "scripted"):
            raise CliError("session %s is not a model session: nothing to re-execute" % sid)
        new = self.start(info["profile"], endpoint=info["backend"])["sid"]      # on the model it ran on
        if watch:
            self.watch(new)
        r = self.compare_turns(self.events(sid), self.events(new))
        r.update(first=sid, second=new, profile=info["profile"])
        return r

    @staticmethod
    def _short(x, n=110):
        """One line of at most n characters: a string as it is, anything else as compact JSON."""
        s = x if isinstance(x, str) else json.dumps(x, separators=(",", ":"), sort_keys=True)
        s = " ".join(str(s).split())
        return s if len(s) <= n else s[:n - 1] + "\u2026"

    @classmethod
    def line(cls, e):
        """One readable line per trace event: what the model chose, what each tool answered, what it cost."""
        p, ev = e.get("payload") or {}, e["event"]
        tool, sh = p.get("tool"), cls._short
        if ev == "session_minted":
            detail = "%s on %s" % (p.get("profile"), p.get("backend"))
        elif ev == "turn_request":
            detail = "turn %s: asking %s" % (p.get("turn"), p.get("model") or p.get("backend") or "the model")
        elif ev == "turn_response":
            r, u = p.get("response") or {}, p.get("usage") or {}
            cost = "  [%s prompt, %s out tokens]" % (u.get("prompt_tokens"), u.get("output_tokens")) if u else ""
            if p.get("error"):
                detail = "turn %s: %s" % (p.get("turn"), p["error"])
            elif r.get("tool"):
                detail = "turn %s: calls %s%s" % (p.get("turn"), (r["tool"] or {}).get("name"), cost)
            elif r.get("tool_error"):
                detail = "turn %s: a call it could not write: %s%s" % (p.get("turn"), sh(r["tool_error"], 70), cost)
            else:
                detail = 'turn %s: says "%s"%s' % (p.get("turn"), sh(r.get("text") or "", 70), cost)
        elif ev == "tool_call":
            detail = "%s %s" % (tool, sh(p["args"], 90)) if "args" in p else "%s" % tool
        elif ev == "tool_result":
            if "result" in p:
                res = p["result"]
                try:
                    obj = json.loads(res)
                except (TypeError, ValueError):
                    obj = None
                prop = obj.get("proposal") if isinstance(obj, dict) else None
                if isinstance(prop, dict) and isinstance(prop.get("check"), dict):
                    ck = prop["check"]
                    others = ", ".join("%s %s %s (%s)" % (o.get("code"), sh(o.get("params") or {}, 30), o.get("other"),
                                                          o.get("outcome")) for o in ck.get("compared") or [])
                    detail = "%s accepted: %s %s on %s, mean %s over %s run(s); compared: %s" % (
                        tool, prop.get("algorithm_code"), sh(prop.get("params") or {}, 40), ck.get("criterion"),
                        ck.get("proposed_mean"), ck.get("proposed_runs"), others)
                elif isinstance(obj, dict) and set(obj) == {"error"}:
                    detail = "%s refused: %s" % (tool, sh(obj["error"], 140))
                else:
                    detail = "%s -> %s" % (tool, sh(res, 140))
            else:
                detail = "%s (%s's record%s)" % (tool, e.get("actor", ""), ", error" if p.get("error") else "")
        elif ev == "sim_started":
            detail = "campaign %s: estimate %s CPU-h, cap %s" % (p.get("cid"), p.get("estimate_h"), p.get("cap_h"))
        elif ev == "gate_pending":
            detail = "gate %s: estimate %s CPU-h, cap %s (medcea-agent approve|deny SID %s)" % (
                p.get("gid"), p.get("estimate_h"), p.get("cap_h"), p.get("gid"))
        elif ev == "stop":
            detail = "reason %s after %s turns" % (p.get("reason"), p.get("turns"))
        elif ev == "proposal":
            detail = "%s, document %s" % (tool, str(p.get("result_sha256", ""))[:12])
        elif ev == "sim_finished":
            detail = "%s, %s CPU-h" % (p.get("state"), p.get("cpu_hours"))
        elif ev == "checkpoint":
            detail = "after turn %s" % p.get("turn")
        else:
            detail = ""
        return "%5d  %-18s %-16s %s" % (e["event_id"], ev, e.get("actor", ""), detail)

    def watch(self, sid, poll_s=3, max_s=8 * 3600, verbose=False):
        """Print the session's events until it stops. A tool server's own record of a call the agent records too is
        left out, and the agent's sim.status checks while a campaign runs (every 10 s) are one waiting line; verbose=True
        prints every event as it is."""
        sid = _sid(sid)
        after, end, waiting = 0, self.clock() + max_s, 0
        while self.clock() < end:
            batch = self.events(sid, after)
            for e in batch:
                after = e["event_id"]
                p = e.get("payload") or {}
                server_record = e["event"] == "tool_result" and e.get("actor") in ("mcp-sim", "mcp-lake")
                if not verbose and server_record and p.get("tool") == "sim.status":
                    if not waiting:
                        self.out("%5s  %s" % ("", "... the campaign runs; the agent checks sim.status every 10 s"))
                    waiting += 1
                    continue
                if waiting and not (e["event"] == "sim_finished" and not verbose):
                    self.out("%5s  %s" % ("", "... %d status check(s)" % waiting))
                    waiting = 0
                if not verbose and server_record:
                    continue
                self.out(self.line(e))
                if e["event"] in ("stop", "session_revoked"):
                    return e["event"]
            if not batch and not self.info(sid).get("active"):
                return "inactive"
            self.sleep(poll_s)
        return "timeout"


def main(argv=None, client=None):
    ap = argparse.ArgumentParser(prog="medcea-agent", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("signin")
    s = sub.add_parser("start")
    s.add_argument("profile")
    s.add_argument("--budget", nargs="*", default=[], metavar="KEY=VALUE")
    s.add_argument("--ttl-s", type=int)
    s.add_argument("--endpoint", help="a model endpoint of `medcea-agent endpoints` instead of the profile's own")
    sub.add_parser("endpoints")
    for n in ("watch", "stop", "replay", "reexecute"):
        sub.add_parser(n).add_argument("sid")
    for n in ("approve", "deny", "accept", "discard"):
        p = sub.add_parser(n)
        p.add_argument("sid")
        p.add_argument("id")
        p.add_argument("--note", default="")
        if n == "approve":
            p.add_argument("--cap-h", type=float)
    a = ap.parse_args(argv)
    c = client or Client()
    try:
        c.signin()
        if a.cmd == "signin":
            c.out("signed in")
        elif a.cmd == "start":
            budget = {}
            for kv in a.budget:
                k, _, v = kv.partition("=")
                budget[k] = float(v) if "." in v else int(v)
            r = c.start(a.profile, budget, a.ttl_s, a.endpoint)
            c.out("session %s started on %s" % (r["sid"], r.get("endpoint", "its profile's model")))
        elif a.cmd == "endpoints":
            for e in c.endpoints():
                c.out("%-12s %-46s %6s tokens  %s%s" % (e.get("name"), e.get("model"), e.get("context"), e.get("where", ""),
                                                        "" if e.get("deterministic") else "  (not deterministic)"))
        elif a.cmd == "watch":
            c.out("ended: %s" % c.watch(a.sid))
        elif a.cmd in ("approve", "deny"):
            c.answer(a.sid, "gates", a.id, a.cmd, a.note, getattr(a, "cap_h", None))
            c.out("%s recorded" % a.cmd)
        elif a.cmd in ("accept", "discard"):
            c.answer(a.sid, "proposals", a.id, "approve" if a.cmd == "accept" else "deny", a.note)
            c.out("%s recorded" % a.cmd)
        elif a.cmd == "stop":
            c.stop(a.sid)
            c.out("stopped")
        elif a.cmd == "replay":
            c.out(json.dumps(c.replay(a.sid), sort_keys=True))
        elif a.cmd == "reexecute":
            c.out(json.dumps(c.reexecute(a.sid), sort_keys=True))
    except CliError as e:
        print("medcea-agent: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
