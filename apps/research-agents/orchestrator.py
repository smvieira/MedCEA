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
  POST /api/sessions/<sid>/replay          R   strict replay as Job replay-<h(sid)>: 202 {state: running} until it ends,
                                               then 200 with the verdict {ok, first_mismatch, events} (re-POST to poll);
                                               409 while the session is still active
Port 8091 (sim API, mcp-sim only, network-gated): POST /internal/sims, GET /internal/sims/<cid>,
  POST /internal/estimates {sid, spec} -> {eid}, GET /internal/estimates/<eid> (Job estimate-<eid>, FLC/MPC specs, R7).

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
        """cfg: image, code_commit, session_url, mcp_sim_url, mcp_lake_url, profiles_dir, pool, model_gateway_url (empty: no local model).
        person_http -> research-session 8100 (person routes, /mint), server_http -> 8102."""
        self.cfg, self.kube, self.ph, self.sh, self.iam = cfg, kube, person_http, server_http, iam
        self.replayer, self.clock = replayer, clock
        self.runner = jobs.JobSimRunner(kube, cfg, cfg.get("pool", 2))
        self.track = {}
        self.replays = {}                 # sid -> {"job", "final"}
        self.estimates = {}               # eid -> {"sid", "final"}
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
        if prof["backend"] == "local" and not self.cfg.get("model_gateway_url"):
            return 409, {"error": "this profile uses the local model, which is not available: no model gateway is configured "
                                  "(RESEARCH_LOCAL_MODEL is not true, or ./apps/research-agents/deploy.sh has not run since the model was deployed)"}
        budget = {k: prof["caps"][k] for k in BUDGET_KEYS if k in prof["caps"]}
        want = body.get("budget") or {}
        if not isinstance(want, dict):
            return 400, {"error": "budget must be an object"}
        for k, v in want.items():                      # a request may only narrow the profile's caps
            if k not in budget or isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= budget[k]:
                return 400, {"error": "budget.%s must be a positive number within the profile's cap" % k}
            budget[k] = v
        mint = {"profile": prof["name"], "profile_sha256": psha, "tools": list(prof["tools"]), "budget": budget,
                "backend": prof["backend"], "code_commit": self.cfg["code_commit"]}
        if "ttl_s" in body:
            mint["ttl_s"] = body["ttl_s"]
        st, m = self.ph.request("POST", "/mint", mint, {"X-Forwarded-Access-Token": token})
        if st != 201:
            return (st if st in (400, 403, 409) else 502), {"error": (m or {}).get("error", "the session service refused")}
        sid = m["sid"]
        try:
            self.kube.create_job(jobs.agent_job(self.cfg, sid, m["claim"], prof["name"], prof["caps"]["wall_h"]))
        except Exception as e:     # KubeError carries the API's status, never a token
            sys.stderr.write("research-orchestrator: agent Job for a session not created: %s\n" % e)
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
        """Strict replay (design 4.7) as a Job. The events come from research-session's server port here and travel
        in the Job's environment (policy-neutral: the Job reaches nothing). The verdict is read from the Job's log
        (REPLAY_RESULT), traced as `replay_result` by this server (the allowed actor), and cached until a restart."""
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        if self.replayer is not None:                      # tests and a host run may inject one
            st, r = self.sh.request("GET", "/events/%s?after=0" % sid)
            return 200, self.replayer(sid, r.get("events", []))
        with self.lock:
            rec = self.replays.get(sid)
        if rec and rec.get("final"):
            return 200, rec["final"]
        name = jobs.replay_job_name(sid)
        if rec is None:
            if i.get("active"):
                return 409, {"error": "the session is still running: replay it after it has stopped"}
            events, after = [], 0
            while True:
                st, r = self.sh.request("GET", "/events/%s?after=%d" % (sid, after))
                if st != 200:
                    return 502, {"error": "the session service did not answer"}
                got = r.get("events", [])
                if not got:
                    break
                events += got
                after = got[-1]["event_id"]
                if len(events) > 100000:
                    return 413, {"error": "the session's trace is too large to replay"}
            try:
                if self.kube.job_status(name) is None:         # an earlier Job (lifetime 1 h) is adopted, not repeated
                    self.kube.create_job(jobs.replay_job(self.cfg, sid, i["profile"], events))
            except ValueError as e:
                return 413, {"error": str(e)}
            except Exception as e:
                sys.stderr.write("research-orchestrator: replay Job for a session not created: %s\n" % e)
                return 502, {"error": "the replay Job could not be created"}
            with self.lock:
                self.replays[sid] = rec = {"job": name, "final": None}
        res = self._job_result(name, jobs.REPLAY_MARK)
        if res is None:
            return 202, {"state": "running"}
        v = res if res.get("state") != "failed" else {"ok": False, "first_mismatch": None, "events": 0,
                                                    "error": str(res.get("error", "the replay Job failed"))[:200]}
        out = {"ok": bool(v.get("ok")), "first_mismatch": v.get("first_mismatch"), "events": v.get("events", 0)}
        if v.get("error"):
            out["error"] = v["error"]
        self.sh.request("POST", "/trace", {"server": "orchestrator", "sid": sid, "event": "replay_result",
                                           "payload": self._trim({"ok": out["ok"], "events": out["events"],
                                                                  "first_mismatch": out["first_mismatch"],
                                                                  "code_commit": self.cfg["code_commit"]})})
        with self.lock:
            rec["final"] = out
        self.kube.delete_job(name)
        return 200, out

    @staticmethod
    def _trim(obj, n=300):
        """Strings cut to n characters (the payload limit is 16 KiB; a mismatch can hold a whole request sha or text)."""
        if isinstance(obj, str):
            return obj[:n]
        if isinstance(obj, dict):
            return {k: Orchestrator._trim(v, n) for k, v in obj.items()}
        if isinstance(obj, list):
            return [Orchestrator._trim(v, n) for v in obj[:20]]
        return obj

    def _job_result(self, name, mark):
        """The parsed `mark` line of a finished Job, a failure object when it ended without one, None while it runs."""
        js = self.kube.job_status(name)
        if js is None:
            return {"state": "failed", "error": "the Job is gone"}
        if not (js["succeeded"] or js["failed"]):
            return None
        pod = self.kube.pod_of_job(name)
        res = None
        if pod:
            try:
                res = jobs.parse_result(self.kube.pod_log(pod["name"], jobs.LOG_MAX), mark)
            except Exception:
                res = None
        if res is not None:
            return res
        return {"state": "failed", "error": "deadline" if js.get("reason") == "DeadlineExceeded" else "the Job ended without a result"}

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
        for eid, e in list(self.estimates.items()):
            if e["sid"] == sid:
                self.estimates.pop(eid, None)
                self.kube.delete_job(jobs.estimate_job_name(eid))

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
                    failed = bool(js and js["failed"])
                    if failed and pod:
                        self._log_failed(t["job"], pod["name"])
                    self.sh.request("POST", "/sessions/%s/revoke" % sid,
                                    {"reason": ("job failed" if failed else "job ended") if ended else "pod did not start"})
                    self._cleanup(sid)
            except Exception as e:                          # one session's failure never stops the others
                sys.stderr.write("tick %s\n" % type(e).__name__)

    def _log_failed(self, job, pod):
        """The last lines of a failed agent Job's log into this pod's log, before the cleanup deletes the Job:
        an agent that died at start left nothing to read (E48, 23 Nov 2026). run_agent never prints a token
        or claim; each line is cut to 300 characters."""
        try:
            text = self.kube.pod_log(pod, limit=8192)
            if isinstance(text, bytes):
                text = text.decode("utf-8", "replace")
            lines = [ln[:300] for ln in str(text).splitlines() if ln.strip()][-20:]
        except Exception as e:
            lines = ["(its log could not be read: %s)" % type(e).__name__]
        sys.stderr.write("research-orchestrator: agent Job %s failed; the end of its log:\n" % job)
        for ln in lines:
            sys.stderr.write("  | %s\n" % ln)
        sys.stderr.flush()

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
        except Exception as e:
            sys.stderr.write("research-orchestrator: simulation Job %s not created: %s\n" % (cid, e))
            return 502, {"error": "the simulation Job could not be created"}
        return 200, {"cid": cid}

    def sim_status(self, cid):
        if not jobs.CID.match(cid or ""):
            return 404, {"error": "no such campaign"}
        return 200, self.runner.status(cid)

    def estimate_start(self, body):
        """R7: an estimate Job for a spec with FLC or MPC. The id is the session's and the spec's, so asking again
        for the same spec adopts the Job (or its cached answer) instead of starting another."""
        if not isinstance(body, dict) or not isinstance(body.get("spec"), dict):
            return 400, {"error": "spec is required"}
        sid = body.get("sid")
        if not SID.match(sid or ""):
            return 400, {"error": "sid is required"}
        st, i = self.sh.request("GET", "/sessions/" + sid)
        if st != 200 or not i.get("active"):
            return 403, {"error": "the session is not active"}
        sys.path.insert(0, ROOT)
        from research.agents.context import canonical, sha
        eid = "e" + sha(sid + sha(canonical(body["spec"])))[:20]
        with self.lock:
            known = eid in self.estimates
            self.estimates.setdefault(eid, {"sid": sid, "final": None})
        if not known:
            try:
                self.kube.create_job(jobs.estimate_job(self.cfg, eid, body["spec"]))
            except ValueError as e:
                with self.lock:
                    self.estimates.pop(eid, None)
                return 400, {"error": str(e)}
            except Exception as e:
                with self.lock:
                    self.estimates.pop(eid, None)
                sys.stderr.write("research-orchestrator: estimate Job %s not created: %s\n" % (eid, e))
                msg = str(e)
                return 502, {"error": "busy: the research-agents quota is full, try again in a minute" if "exceeded quota" in msg
                             else "the estimate Job could not be created"}
        return 200, {"eid": eid}

    def estimate_status(self, eid):
        if not jobs.EID.match(eid or ""):
            return 404, {"error": "no such estimate"}
        with self.lock:
            e = self.estimates.get(eid)
        if e is None:
            return 404, {"error": "no such estimate"}
        if e["final"]:
            return 200, e["final"]
        res = self._job_result(jobs.estimate_job_name(eid), jobs.EST_MARK)
        if res is None:
            return 200, {"state": "running"}
        out = {k: res[k] for k in ("state", "cpu_hours", "calibration_h", "runs", "error", "controller_libraries") if k in res}
        if out.get("state") not in ("done", "failed"):
            out = {"state": "failed", "error": "the estimate Job ended without a result"}
        e["final"] = out
        self.kube.delete_job(jobs.estimate_job_name(eid))
        return 200, out

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
            if self.command == "POST" and path == "/internal/estimates":
                b = self.body()
                return None if not isinstance(b, dict) else self.send(*orch.estimate_start(b))
            m = re.match(r"^/internal/sims/([^/]+)$", path)
            if m and self.command == "GET":
                return self.send(*orch.sim_status(m.group(1)))
            m = re.match(r"^/internal/estimates/([^/]+)$", path)
            if m and self.command == "GET":
                return self.send(*orch.estimate_status(m.group(1)))
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
           "pool": int(os.environ.get("RS_SIM_POOL", "2")),
           "model_gateway_url": os.environ.get("RS_MODEL_GATEWAY_URL", "")}
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
