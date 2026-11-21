#!/usr/bin/env python3
"""medcea-agent (research Phase 4a, stage 6a; design AH.11, R12, R34). Stdlib only, and byte-equal
to the medcea_agent.py the workbench-examples ConfigMap delivers to notebooks (research Phase 4a), so it
imports nothing from this repository.

  medcea-agent start PROFILE [--budget k=v ...] [--ttl-s N]   start a session; prints its id
  medcea-agent watch SID                                      follow the trace until the agent stops
  medcea-agent approve SID GID [--note T] [--cap-h H]         approve a gate (the supervisor only)
  medcea-agent deny SID GID [--note T]
  medcea-agent accept SID PID | discard SID PID [--note T]    decide a proposal
  medcea-agent stop SID                                       revoke the session, delete its Jobs
  medcea-agent replay SID                                     strict replay verdict
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
    def start(self, profile, budget=None, ttl_s=None):
        body = {"profile": profile}
        if budget:
            body["budget"] = budget
        if ttl_s:
            body["ttl_s"] = ttl_s
        return self._call("POST", "/api/sessions", body)

    def info(self, sid):
        return self._call("GET", "/api/sessions/" + sid)

    def events(self, sid, after=0):
        return self._call("GET", "/api/sessions/%s/events?after=%d" % (sid, after))["events"]

    def answer(self, sid, kind, xid, decision, note="", cap_h=None):
        body = {"decision": decision, "note": note}
        if cap_h is not None:
            body["approved_cap_h"] = cap_h
        return self._call("POST", "/api/sessions/%s/%s/%s" % (sid, kind, urllib.parse.quote(xid)), body)

    def stop(self, sid):
        return self._call("POST", "/api/sessions/%s/stop" % sid, {})

    def replay(self, sid):
        return self._call("POST", "/api/sessions/%s/replay" % sid, {})

    @staticmethod
    def line(e):
        p = e.get("payload") or {}
        detail = {"gate_pending": "gate %s: estimate %s CPU-h, cap %s (medcea-agent approve|deny SID %s)" % (
                      p.get("gid"), p.get("estimate_h"), p.get("cap_h"), p.get("gid")),
                  "stop": "reason %s after %s turns" % (p.get("reason"), p.get("turns")),
                  "tool_call": "%s" % p.get("tool"), "proposal": "%s" % p.get("tool"),
                  "sim_finished": "%s, %s CPU-h" % (p.get("state"), p.get("cpu_hours"))}.get(e["event"], "")
        return "%5d  %-18s %-16s %s" % (e["event_id"], e["event"], e.get("actor", ""), detail)

    def watch(self, sid, poll_s=3, max_s=8 * 3600):
        after, end = 0, self.clock() + max_s
        while self.clock() < end:
            batch = self.events(sid, after)
            for e in batch:
                self.out(self.line(e))
                after = e["event_id"]
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
    for n in ("watch", "stop", "replay"):
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
            r = c.start(a.profile, budget, a.ttl_s)
            c.out("session %s started" % r["sid"])
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
    except CliError as e:
        print("medcea-agent: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
