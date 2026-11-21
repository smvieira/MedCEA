#!/usr/bin/env python3
"""research-orchestrator (research Phase 4a, stage 6a; design 4.2, R10, R12).

Port 8090 (person API, the medcea-agent CLI; checked with the platform library's check() as
service research-orchestrator):
  POST /api/signin/start|poll|refresh      public relay to research-session /signin/* (R12)
  POST /api/sessions                       C   start: mint, then Job agent-<h(sid)>
  GET  /api/sessions                       R   the supervisor's own sessions started by this process
  GET  /api/sessions/<sid>                 R   state, budget, spent
  GET  /api/sessions/<sid>/events?after=N  R   trace events
  POST /api/sessions/<sid>/gates/<gid>     U   approve|deny (forwarded with the person's token)
  POST /api/sessions/<sid>/proposals/<pid> U   accept|discard (same)
  POST /api/sessions/<sid>/stop            U   revoke, delete agent and sim Jobs
  POST /api/sessions/<sid>/replay          R   501 until the replay Job exists (6b)
Port 8091 (sim API, mcp-sim only, network-gated): POST /internal/sims, GET /internal/sims/<cid>.

Lifecycle (R10): tick() registers the agent pod's IP with research-session when the pod is
Running (the claim can then be exchanged from that IP only) and revokes the session when the
Job ends; a pod that never ran within START_GRACE_S is stopped. Holds no secret that can mint
or attribute: the person's token is only forwarded. Never logs a token or a body."""
import hashlib
import importlib.util
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import jobs  # noqa: E402

SERVICE = "research-orchestrator"
SID = re.compile(r"^[A-Za-z0-9_-]{22}$")
XID = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,39}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
START_GRACE_S = 150
BUDGET_KEYS = ("turns", "prompt_tokens", "output_tokens", "cpu_hours")


class Http:
    """urllib JSON client for research-session: request(method, path, body, headers) -> (status, obj)."""

    def __init__(self, base, timeout=15):
        self.base, self.timeout = base.rstrip("/"), timeout

    def request(self, method, path, body=None, headers=None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, None if body is None else json.dumps(body).encode(), h, method=method)
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


class Orchestrator:
    def __init__(self, cfg, kube, person_http, server_http, iam=None, replayer=None, clock=time.time):
        """cfg: image, code_commit, session_url, mcp_sim_url, mcp_lake_url, profiles_dir, pool.
        person_http -> research-session 8100 (person routes, /mint), server_http -> 8102."""
        self.cfg, self.kube, self.ph, self.sh, self.iam = cfg, kube, person_http, server_http, iam
        self.replayer, self.clock = replayer, clock
        self.runner = jobs.JobSimRunner(kube, cfg, cfg.get("pool", 2))
        self.track = {}
        self.lock = threading.Lock()

    # ── profile
    def _profile(self, name):
        if not isinstance(name, str) or not NAME.match(name):
            return None
        path = os.path.join(self.cfg["profiles_dir"], name + ".yaml")
        if not os.path.isfile(path):
            return None
        sys.path.insert(0, ROOT)
        from research.agents import loop
        from research.agents.context import canonical, sha
        p = loop.load_profile(path)
        return p, sha(canonical(p))

    # ── person routes
    def start(self, who, token, body):
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        got = self._profile(body.get("profile"))
        if got is None:
            return 400, {"error": "unknown profile"}
        prof, psha = got
        budget = {k: prof["caps"][k] for k in BUDGET_KEYS if k in prof["caps"]}
        want = body.get("budget") or {}
        if not isinstance(want, dict):
            return 400, {"error": "budget must be an object"}
        for k, v in want.items():                      # a request may only narrow the profile's caps
            if k not in budget or isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= budget[k]:
                return 400, {"error": "budget.%s must be a positive number within the profile's cap" % k}
            budget[k] = v
        mint = {"profile": prof["name"], "profile_sha256": psha, "tools": list(prof["tools"]), "budget": budget,
                "backend": "scripted", "code_commit": self.cfg["code_commit"]}
        if "ttl_s" in body:
            mint["ttl_s"] = body["ttl_s"]
        st, m = self.ph.request("POST", "/mint", mint, {"X-Forwarded-Access-Token": token})
        if st != 201:
            return (st if st in (400, 403, 409) else 502), {"error": (m or {}).get("error", "the session service refused")}
        sid = m["sid"]
        try:
            self.kube.create_job(jobs.agent_job(self.cfg, sid, m["claim"], prof["name"], prof["caps"]["wall_h"]))
        except Exception:
            self.sh.request("POST", "/sessions/%s/revoke" % sid, {"reason": "agent Job could not be created"})
            return 502, {"error": "the agent Job could not be created"}
        with self.lock:
            self.track[sid] = {"person": who["person_id"], "job": jobs.agent_job_name(sid), "registered": False,
                               "started": self.clock(), "profile": prof["name"]}
        return 201, {"sid": sid, "exp": m["exp"], "job": jobs.agent_job_name(sid)}

    def _own(self, who, sid):
        if not SID.match(sid or ""):
            return None
        st, i = self.sh.request("GET", "/sessions/" + sid)
        if st != 200 or i.get("sup_person") != who["person_id"]:
            return None
        return i

    def listing(self, who):
        with self.lock:
            sids = [s for s, t in self.track.items() if t["person"] == who["person_id"]]
        return 200, {"sessions": [{"sid": s, "profile": self.track[s]["profile"]} for s in sids if s in self.track]}

    def info(self, who, sid):
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        return 200, {k: i[k] for k in ("sid", "profile", "backend", "exp", "claimed", "active", "revoked", "budget", "spent")}

    def events(self, who, sid, after):
        if self._own(who, sid) is None:
            return 404, {"error": "no such session"}
        st, r = self.sh.request("GET", "/events/%s?after=%d" % (sid, after))
        return (200, r) if st == 200 else (502, {"error": "the session service did not answer"})

    def decide(self, who, token, kind, sid, xid, body):
        if self._own(who, sid) is None or not XID.match(xid or ""):
            return 404, {"error": "no such session"}
        body = dict(body) if isinstance(body, dict) else {}
        if kind == "gates" and body.get("decision") == "approve" and "approved_cap_h" not in body:
            st, g = self.sh.request("GET", "/gates/%s?sid=%s" % (urllib.parse.quote(xid), sid))
            cap = (g.get("pending") or {}).get("cap_h") if st == 200 else None
            if not isinstance(cap, (int, float)) or isinstance(cap, bool):
                return 404, {"error": "no such gate"}
            body["approved_cap_h"] = round(cap + 0.0005, 3)       # as estimated: the server's own cap
        st, r = self.ph.request("POST", "/sessions/%s/%s/%s" % (sid, kind, xid), body, {"X-Forwarded-Access-Token": token})
        return (st if st in (200, 400, 403, 404, 409) else 502), r or {"error": "the session service refused"}

    def stop(self, who, token, sid):
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        st, r = self.ph.request("POST", "/revoke", {"sid": sid, "reason": "stopped by the supervisor"},
                                {"X-Forwarded-Access-Token": token})
        if st != 200:
            return (st if st in (403, 404) else 502), r or {"error": "the session service refused"}
        self._cleanup(sid)
        return 200, {"revoked": r.get("revoked", True)}

    def replay(self, who, sid):
        if self._own(who, sid) is None:
            return 404, {"error": "no such session"}
        if self.replayer is None:
            return 501, {"error": "replay runs as a Job in the next stage"}
        st, r = self.sh.request("GET", "/events/%s?after=0" % sid)
        return 200, self.replayer(sid, r.get("events", []))

    # ── lifecycle (R10)
    def _cleanup(self, sid):
        with self.lock:
            t = self.track.pop(sid, None)
        if t:
            self.kube.delete_job(t["job"])
        for cid, s in list(self.runner.owner.items()):
            if s == sid:
                self.runner.delete(cid)
                self.runner.owner.pop(cid, None)

    def tick(self):
        now = self.clock()
        with self.lock:
            items = list(self.track.items())
        for sid, t in items:
            try:
                pod = self.kube.pod_of_job(t["job"])
                if pod and pod.get("phase") == "Running" and pod.get("ip") and not t["registered"]:
                    st, _ = self.sh.request("PUT", "/claims/%s/expect" % sid, {"peer": pod["ip"]})
                    if st in (200, 409):
                        t["registered"] = True
                js = self.kube.job_status(t["job"])
                ended = js is None or js["succeeded"] or js["failed"]
                if ended or (not t["registered"] and now - t["started"] > START_GRACE_S and not (pod and pod.get("phase") == "Running")):
                    self.sh.request("POST", "/sessions/%s/revoke" % sid,
                                    {"reason": "job ended" if ended else "pod did not start"})
                    self._cleanup(sid)
            except Exception as e:                          # one session's failure never stops the others
                sys.stderr.write("tick %s\n" % type(e).__name__)

    # ── sim API (mcp-sim)
    def sim_start(self, body):
        if not isinstance(body, dict) or not isinstance(body.get("spec"), dict):
            return 400, {"error": "spec is required"}
        sid, cid = body.get("sid"), body.get("cid")
        cap, dl = body.get("cap_h"), body.get("deadline_s")
        if not (SID.match(sid or "") and jobs.CID.match(cid or "")
                and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (cap, dl))):
            return 400, {"error": "sid, cid, cap_h and deadline_s are required"}
        st, i = self.sh.request("GET", "/sessions/" + sid)
        if st != 200 or not i.get("active"):
            return 403, {"error": "the session is not active"}
        try:
            self.runner.start(cid, body["spec"], cap, dl, sid=sid)
        except ValueError as e:
            return 400, {"error": str(e)}
        except Exception:
            return 502, {"error": "the simulation Job could not be created"}
        return 200, {"cid": cid}

    def sim_status(self, cid):
        if not jobs.CID.match(cid or ""):
            return 404, {"error": "no such campaign"}
        return 200, self.runner.status(cid)

    def healthz(self):
        with self.lock:
            return {"ok": True, "tracked": len(self.track)}


def _handler(orch, port_name):
    class H(BaseHTTPRequestHandler):
        server_version = "research-orchestrator"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s %s\n" % (port_name, self.command, urllib.parse.urlsplit(self.path).path[:60]))

        def send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                    return self.send(415, {"error": "Content-Type must be application/json"})
                if not 0 < n <= 262144:
                    return self.send(400, {"error": "a JSON body of at most 256 KiB is required"})
                return json.loads(self.rfile.read(n))
            except ValueError:
                return self.send(400, {"error": "a JSON body is required"})

        def route(self):
            try:
                u = urllib.parse.urlsplit(self.path)
                getattr(self, "r_" + port_name)(u.path, urllib.parse.parse_qs(u.query))
            except Exception as e:
                sys.stderr.write("error %s\n" % type(e).__name__)
                self.send(500, {"error": "Something went wrong on our side."})

        do_GET = do_POST = route

        def r_person(self, path, q):
            if self.command == "GET" and path == "/healthz":
                return self.send(200, orch.healthz())
            m = re.match(r"^/api/signin/(start|poll|refresh)$", path)
            if m and self.command == "POST":
                b = self.body()
                if not isinstance(b, dict):
                    return None
                st, r = orch.sh.request("POST", "/signin/" + m.group(1), b)
                return self.send(st if st in (200, 400, 429, 503) else 502, r or {"error": "sign-in is not available"})
            d = orch.iam.check(SERVICE, self.command, path, self.headers)
            if not d.allow:
                return self.send(d.status, {"error": d.reason})
            who = d.who or {}
            if not UUID.match(str(who.get("sub") or "")) or not who.get("person_id"):
                return self.send(403, {"error": "the token has no account uuid or person_id"})
            token = self.headers.get("X-Forwarded-Access-Token") or ""
            if path == "/api/sessions":
                if self.command == "GET":
                    return self.send(*orch.listing(who))
                b = self.body()
                return None if not isinstance(b, dict) else self.send(*orch.start(who, token, b))
            m = re.match(r"^/api/sessions/([^/]+)(?:/(events|stop|replay|(gates|proposals)/([^/]+)))?$", path)
            if not m:
                return self.send(404, {"error": "not found"})
            sid, sub = m.group(1), m.group(2)
            if sub is None and self.command == "GET":
                return self.send(*orch.info(who, sid))
            if sub == "events" and self.command == "GET":
                a = (q.get("after") or ["0"])[0]
                return self.send(*orch.events(who, sid, int(a) if a.isdigit() else 0))
            if self.command != "POST":
                return self.send(405, {"error": "method not allowed"})
            b = self.body()
            if not isinstance(b, dict):
                return None
            if sub == "stop":
                return self.send(*orch.stop(who, token, sid))
            if sub == "replay":
                return self.send(*orch.replay(who, sid))
            if m.group(3):
                return self.send(*orch.decide(who, token, m.group(3), sid, m.group(4), b))
            self.send(404, {"error": "not found"})

        def r_sim(self, path, q):
            if self.command == "POST" and path == "/internal/sims":
                b = self.body()
                return None if not isinstance(b, dict) else self.send(*orch.sim_start(b))
            m = re.match(r"^/internal/sims/([^/]+)$", path)
            if m and self.command == "GET":
                return self.send(*orch.sim_status(m.group(1)))
            self.send(404, {"error": "not found"})
    return H


def make_servers(orch, host="0.0.0.0", ports=(8090, 8091)):
    return [ThreadingHTTPServer((host, p), _handler(orch, n)) for p, n in zip(ports, ("person", "sim"))]


def main():
    from kube import KubeClient
    spec = importlib.util.spec_from_file_location("medcea_iam", os.environ.get("MEDCEA_IAM_LIB", "/iam/medcea_iam.py"))
    iam = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(iam)
    cfg = {"image": os.environ["RS_AGENT_IMAGE"], "code_commit": os.environ["RS_CODE_COMMIT"],
           "session_url": os.environ["RS_SESSION_AGENT_URL"], "mcp_sim_url": os.environ["RS_MCP_SIM_URL"],
           "mcp_lake_url": os.environ["RS_MCP_LAKE_URL"], "profiles_dir": os.environ.get(
               "RS_PROFILES_DIR", os.path.join(ROOT, "research", "agents", "profiles")),
           "pool": int(os.environ.get("RS_SIM_POOL", "2"))}
    orch = Orchestrator(cfg, KubeClient(os.environ["RS_AGENTS_NAMESPACE"]),
                        Http(os.environ["RS_SESSION_PERSON_URL"]), Http(os.environ["RS_SESSION_SERVER_URL"]), iam)

    def loop():
        while True:
            orch.tick()
            time.sleep(5)
    threading.Thread(target=loop, daemon=True).start()
    srvs = make_servers(orch)
    threading.Thread(target=srvs[1].serve_forever, daemon=True).start()
    sys.stderr.write("research-orchestrator: ports 8090 8091\n")
    srvs[0].serve_forever()


if __name__ == "__main__":
    main()
