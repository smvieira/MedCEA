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
 research Phase 4e (the research console, design rs4e 3.1; with the access policy version that names its host):
  GET  /api/me                             R   {username, role, can: {start, decide, stop, replay, reexecute}}
  GET  /api/profiles                       R   {profiles: [{name, backend, caps, tools, skill, team?}], endpoints}
  GET  /api/sessions?before=&limit=        R   also `history` (research-session's sessions_of) and next_before
  GET  /api/sessions/<sid>/events?wait=S   R   long-poll: up to S (<= 20) s, also bounded by the token's exp - 5 s
  GET  /api/sessions/<sid>/campaigns       R   the session's campaigns from its trace (campaigns.py)
  GET  /api/sessions/<sid>/campaigns/<cid>[?sort=&offset=&limit=]           R   manifest, by_setting, a page of runs
  GET  /api/sessions/<sid>/campaigns/<cid>/runs/<n>                         R   result row n
  GET  /api/sessions/<sid>/campaigns/<cid>/runs/<n>/series?points=          R   the run's chamber series, decimated
  GET  /api/sessions/<sid>/otel[?content=1]                                 R   the session as OpenTelemetry (otel.py)
  POST /api/sessions/<sid>/reexecute       C   the same profile on the session's model, recorded as `reexecutes`
Port 8091 (sim API, mcp-sim only, network-gated): POST /internal/sims, GET /internal/sims/<cid>,
  POST /internal/estimates {sid, spec} -> {eid}, GET /internal/estimates/<eid> (Job estimate-<eid>, FLC/MPC specs, R7).

Lifecycle (R10): tick() registers the agent pod's IP with research-session when the pod is
Running (the claim can then be exchanged from that IP only) and revokes the session when the
Job ends; a pod that never ran within START_GRACE_S is stopped. When a simulation Job ends, tick()
writes its sim_finished as actor orchestrator (research Phase 4e; session_status counts one per
campaign, whichever of mcp-sim and the orchestrator wrote it). Holds no secret that can mint
or attribute: the person's token is only forwarded. Never logs a token or a body."""
import gzip
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


def _root_on_path():
    """ROOT on sys.path once (research/ and the bundle's top level): handlers call it per request, so it never adds
    a second copy."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)


def _log_name(v):
    """A username as the log may print it: [A-Za-z0-9._@-], at most 64 characters, else '?'."""
    return v if isinstance(v, str) and re.match(r"^[A-Za-z0-9._@-]{1,64}$", v) else "?"


import campaigns  # noqa: E402
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
        self.sim_caps = {}                # cid -> the cap the campaign was started with
        self.sims_reported = set()        # cids whose sim_finished this process wrote
        self.facts = {}                   # sid -> what the trace says of a session (_facts), read incrementally
        self.sleep = time.sleep
        self.lock = threading.Lock()

    def endpoints(self):
        """The model endpoints this install enables (RESEARCH_ENDPOINTS, research Phase 4d); 'local' alone by default."""
        e = self.cfg.get("endpoints")
        return set(e) if e is not None else {"local"}

    def inventory(self):
        """The model picker's list (RS_ENDPOINTS_INVENTORY: name, model, context, deterministic, tools, where; never a
        URL or a key), only the enabled endpoints, in their configured order."""
        en = self.endpoints()
        return [dict(i) for i in self.cfg.get("inventory") or [] if isinstance(i, dict) and i.get("name") in en]

    # ── profile
    def _profile(self, name):
        if not isinstance(name, str) or not NAME.match(name):
            return None
        path = os.path.join(self.cfg["profiles_dir"], name + ".yaml")
        if not os.path.isfile(path):
            return None
        _root_on_path()
        from research.agents import loop
        from research.agents.context import canonical, sha
        p = loop.load_profile(path)
        return p, sha(canonical(p))

    # ── person routes
    def start(self, who, token, body, reexecutes=None):
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        got = self._profile(body.get("profile"))
        if got is None:
            return 400, {"error": "unknown profile"}
        prof, psha = got
        chosen = body.get("endpoint")             # the model picker: an enabled endpoint instead of the profile's own
        if chosen is not None:
            if prof["backend"] == "scripted":
                return 400, {"error": "a scripted profile has no model to choose"}
            if not isinstance(chosen, str) or chosen not in self.endpoints():
                return 409, {"error": "the endpoint %s is not enabled on this install (RESEARCH_ENDPOINTS); choose one of %s"
                                      % (str(chosen)[:40], ", ".join(i["name"] for i in self.inventory()) or "none")}
            ep = next((i for i in self.inventory() if i["name"] == chosen), None)
            if ep is None or not isinstance(ep.get("context"), int):
                return 409, {"error": "the endpoint %s is enabled but not in the model inventory: run ./apps/research-agents/deploy.sh"
                                      % chosen}
        backend = chosen or prof["backend"]
        if backend != "scripted" and not self.cfg.get("model_gateway_url"):
            return 409, {"error": "this profile uses the local model, which is not available: no model gateway is configured "
                                  "(RESEARCH_LOCAL_MODEL is not true, or ./apps/research-agents/deploy.sh has not run since the model was deployed)"}
        if backend != "scripted" and backend not in self.endpoints():
            return 409, {"error": "this profile uses the endpoint %s, which is not enabled on this install (RESEARCH_ENDPOINTS)"
                                  % backend}
        if backend != "scripted" and backend == prof["backend"]:
            # a profile on its own endpoint, left out or named (the picker, reexecute), keeps its caps.context_tokens
            # (loop.context_cap): refuse one this install's endpoint cannot hold (e.g. compare_controllers_gpu on an
            # endpoint named gpu with a smaller context)
            own = next((i for i in self.inventory() if i["name"] == backend), None)
            ctx = own.get("context") if own else None
            if isinstance(ctx, int) and not isinstance(ctx, bool):
                from research.agents import loop
                room = ctx - loop.CONTEXT_MARGIN
                if prof["caps"]["context_tokens"] > room:
                    return 409, {"error": "the profile %s needs %d tokens of context and the endpoint %s holds %d (%d less "
                                          "the chat template's %d): choose another profile, or this one with an endpoint "
                                          "that holds more" % (prof["name"], prof["caps"]["context_tokens"], backend, room,
                                                               ctx, loop.CONTEXT_MARGIN)}
        budget = {k: prof["caps"][k] for k in BUDGET_KEYS if k in prof["caps"]}
        want = body.get("budget") or {}
        if not isinstance(want, dict):
            return 400, {"error": "budget must be an object"}
        for k, v in want.items():                      # a request may only narrow the profile's caps
            if k not in budget or isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= budget[k]:
                return 400, {"error": "budget.%s must be a positive number within the profile's cap" % k}
            budget[k] = v
        mint = {"profile": prof["name"], "profile_sha256": psha, "tools": list(prof["tools"]), "budget": budget,
                "backend": backend, "code_commit": self.cfg["code_commit"]}
        if "ttl_s" in body:
            mint["ttl_s"] = body["ttl_s"]
        if reexecutes:
            mint["reexecutes"] = reexecutes
        st, m = self.ph.request("POST", "/mint", mint, {"X-Forwarded-Access-Token": token})
        if st != 201:
            return (st if st in (400, 403, 409) else 502), {"error": (m or {}).get("error", "the session service refused")}
        sid = m["sid"]
        try:
            self.kube.create_job(jobs.agent_job(self.cfg, sid, m["claim"], prof["name"], prof["caps"]["wall_h"],
                                                {"name": ep["name"], "context": ep["context"]} if chosen else None))
        except Exception as e:     # KubeError carries the API's status, never a token
            sys.stderr.write("research-orchestrator: agent Job for a session not created: %s\n" % e)
            self.sh.request("POST", "/sessions/%s/revoke" % sid, {"reason": "agent Job could not be created"})
            return 502, {"error": "the agent Job could not be created"}
        with self.lock:
            self.track[sid] = {"person": who["person_id"], "job": jobs.agent_job_name(sid), "registered": False,
                               "started": self.clock(), "profile": prof["name"], "backend": backend, "exp": m["exp"]}
        out = {"sid": sid, "exp": m["exp"], "job": jobs.agent_job_name(sid), "endpoint": backend}
        if reexecutes:
            out["reexecutes"] = reexecutes
        return 201, out

    def _own(self, who, sid):
        if not SID.match(sid or ""):
            return None
        st, i = self.sh.request("GET", "/sessions/" + sid)
        if st != 200 or i.get("sup_person") != who["person_id"]:
            return None
        return i

    def listing(self, who, q=None):
        """The sessions this process started for the person (running ones: state, backend, exp) and, research Phase 4e,
        the person's history from research-session (agent_trace.sessions_of, newest first, keyset `before`). The person
        is the verified token's, never a query parameter."""
        q = q or {}
        before, limit = (q.get("before") or [""])[0], (q.get("limit") or [""])[0]
        if before and not re.match(r"^[1-9][0-9]{0,17}$", before):
            return 400, {"error": "before must be a positive event id"}
        if limit and not (re.match(r"^[0-9]{1,3}$", limit) and 1 <= int(limit) <= 200):
            return 400, {"error": "limit is 1 to 200"}
        with self.lock:
            run = [dict(sid=s, profile=t["profile"], state="running" if t["registered"] else "starting",
                        backend=t.get("backend"), exp=t.get("exp"))
                   for s, t in self.track.items() if t["person"] == who["person_id"]]
        out = {"sessions": run, "endpoints": self.inventory(), "history": [], "next_before": None}
        path = "/persons/%s/sessions" % urllib.parse.quote(str(who["person_id"]), safe="")
        qs = "&".join(x for x in ("before=" + before if before else "", "limit=" + limit if limit else "") if x)
        st, r = self.sh.request("GET", path + ("?" + qs if qs else ""))
        if st == 200 and isinstance(r, dict) and isinstance(r.get("sessions"), list):
            out["history"] = r["sessions"]
            out["next_before"] = r.get("next_before")
        else:
            out["history_error"] = "the session history is not available (the session service did not answer)"
        return 200, out

    def _pages(self, sid, after=0, cap=100000):
        """Events after `after`, page by page (research-session answers 1000 at most): (events, None) or (None, error)."""
        out = []
        while True:
            st, r = self.sh.request("GET", "/events/%s?after=%d" % (sid, after))
            if st != 200 or not isinstance(r, dict):
                return None, (502, {"error": "the session service did not answer"})
            got = r.get("events") or []
            out += got
            if len(got) < 1000 or not got:
                return out, None
            after = got[-1]["event_id"]
            if len(out) > cap:
                return None, (413, {"error": "the session's trace is longer than %d events" % cap})

    def _facts(self, sid):
        """What the trace says of a session that research-session's row does not: code_commit and reexecutes
        (session_minted), revoke_reason (session_revoked) and the agents (lead and specialists, agent_spawned). Read
        incrementally from the last event seen; callers have checked ownership first."""
        with self.lock:
            f = dict(self.facts.get(sid) or {"after": 0, "code_commit": None, "reexecutes": None,
                                              "revoke_reason": None, "agents": [{"id": "a0", "parent": None}]})
            f["agents"] = list(f["agents"])
        got, err = self._pages(sid, f["after"])
        if err:
            return f
        for e in got:
            p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
            if e.get("event") == "session_minted":
                f["code_commit"], f["reexecutes"] = p.get("code_commit"), p.get("reexecutes")
            elif e.get("event") == "session_revoked":
                f["revoke_reason"] = p.get("reason")
            elif e.get("event") == "agent_spawned" and isinstance(p.get("agent"), str) \
                    and all(a["id"] != p["agent"] for a in f["agents"]):
                f["agents"].append({"id": p["agent"], "parent": p.get("parent"), "profile": p.get("profile_name")})
            f["after"] = max(f["after"], e.get("event_id") or 0)
        with self.lock:
            if len(self.facts) > 500 and sid not in self.facts:
                self.facts.pop(next(iter(self.facts)))
            self.facts[sid] = f
        return f

    def info(self, who, sid):
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        out = {k: i[k] for k in ("sid", "profile", "backend", "exp", "claimed", "active", "revoked", "budget", "spent")}
        out.update({k: i.get(k) for k in ("sup_username", "sup_role", "created_at")})
        f = self._facts(sid)
        out.update(code_commit=f["code_commit"], revoke_reason=f["revoke_reason"], agents=f["agents"])
        if f["reexecutes"]:
            out["reexecutes"] = f["reexecutes"]
        return 200, out

    def events(self, who, sid, after, wait=0, token_exp=None):
        """One page of events after `after`. wait (0..20 s, research Phase 4e): hold the answer until an event arrives
        or the wait ends, re-reading every second; the wait never outlives the caller's token (exp - 5 s), so a person
        whose role is taken away stops seeing new events at the token's end."""
        if self._own(who, sid) is None:
            return 404, {"error": "no such session"}
        end = self.clock() + max(0, min(int(wait or 0), 20))
        if isinstance(token_exp, (int, float)) and not isinstance(token_exp, bool):
            end = min(end, token_exp - 5)
        while True:
            st, r = self.sh.request("GET", "/events/%s?after=%d" % (sid, after))
            if st != 200:
                return 502, {"error": "the session service did not answer"}
            left = end - self.clock()
            if (isinstance(r, dict) and r.get("events")) or left <= 0:
                return 200, r
            self.sleep(min(1.0, left))

    # ── research Phase 4e: the research console's reads (design rs4e 3.1)
    CAN = {"start": "POST /api/sessions", "decide": "POST /api/sessions/<sid>/gates/<gid>",
           "stop": "POST /api/sessions/<sid>/stop", "replay": "POST /api/sessions/<sid>/replay",
           "reexecute": "POST /api/sessions/<sid>/reexecute"}

    def me(self, d):
        """{username, role, can}: can from a dry look-up of the orchestrator's own routes in routes.json (the routes the
        buttons call), each true when one of the person's roles holds that route's level; null when the table cannot
        be read (the page then shows every button and the server decides)."""
        who = getattr(d, "who", None) or {}
        role = self.iam.actor_role(d) if hasattr(self.iam, "actor_role") else None
        table = self.iam._load(self.iam.ROUTES_FILE) if hasattr(self.iam, "_load") and hasattr(self.iam, "ROUTES_FILE") else None
        routes = (((table or {}).get("services") or {}).get(SERVICE) or {}).get("routes") if isinstance(table, dict) else None
        can = None
        if isinstance(routes, dict):
            roles = set(who.get("roles") or [])
            can = {k: bool(isinstance(routes.get(key), dict) and roles & set(routes[key].get("roles") or {}))
                   for k, key in self.CAN.items()}
        return 200, {"username": who.get("username"), "role": role, "can": can}

    def profiles(self):
        """The bundle's profiles (research/agents/profiles/*.yaml) as the start form needs them; one that does not load
        is left out (and named in the log)."""
        _root_on_path()
        from research.agents import loop
        d, out = self.cfg["profiles_dir"], []
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            name = fn[:-5]
            if not fn.endswith(".yaml") or not NAME.match(name):
                continue
            try:
                p = loop.load_profile(os.path.join(d, fn))
            except Exception as e:
                sys.stderr.write("research-orchestrator: profile %s does not load: %s\n" % (name, type(e).__name__))
                continue
            item = {"name": name, "backend": p["backend"], "caps": p["caps"], "tools": list(p["tools"]),
                    "skill": p.get("skill")}
            if isinstance(p.get("team"), dict):
                item["team"] = sorted(p["team"])
            out.append(item)
        return 200, {"profiles": out, "endpoints": self.inventory()}

    def _campaign_events(self, who, sid):
        if self._own(who, sid) is None:
            return None, (404, {"error": "no such session"})
        return self._pages(sid)

    def campaigns(self, who, sid):
        evs, err = self._campaign_events(who, sid)
        if err:
            return err
        return 200, {"campaigns": campaigns.campaigns_of(evs)}

    def _campaign(self, who, sid, cid):
        evs, err = self._campaign_events(who, sid)
        if err:
            return None, err
        c = campaigns.campaign_of(evs, cid)
        if c is None:
            return None, (404, {"error": "no such campaign"})
        return c, None

    @staticmethod
    def _defaults_of():
        _root_on_path()
        import mcp_sim
        pmod = mcp_sim._load_params(ROOT)
        return mcp_sim, (lambda code: pmod.defaults(code) if code in pmod.PARAMS else {})

    def campaign(self, who, sid, cid, q):
        c, err = self._campaign(who, sid, cid)
        if err:
            return err
        ms, defaults_of = self._defaults_of()
        return campaigns.read_campaign(self.cfg.get("runs_root", "/runs"), c, q, ms.summarise_settings,
                                       ms.summarise_row, defaults_of)

    def run(self, who, sid, cid, n):
        c, err = self._campaign(who, sid, cid)
        if err:
            return err
        return campaigns.read_run(self.cfg.get("runs_root", "/runs"), c, n)

    def series(self, who, sid, cid, n, q):
        c, err = self._campaign(who, sid, cid)
        if err:
            return err
        return campaigns.read_series(self.cfg.get("runs_root", "/runs"), c, n, q)

    def otel(self, who, sid, content=False):
        """The session as an OTLP/JSON export (research/agents/otel.py; design rs4e 4.5): digests and sizes only unless
        content is asked for; the session token, claim and person sub never appear."""
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        evs, err = self._pages(sid)
        if err:
            return err
        _root_on_path()
        from research.agents import otel
        f = self._facts(sid)
        kind = next((e.get("kind") for e in self.cfg.get("inventory") or [] if isinstance(e, dict)
                     and e.get("name") == i.get("backend")), None)
        session = {"sid": sid, "profile": i.get("profile"), "backend": i.get("backend"), "code_commit": f["code_commit"],
                   "sup_username": i.get("sup_username"), "sup_role": i.get("sup_role"), "endpoint_kind": kind}
        if content:
            # design rs4e 4.5: an export with content is a recorded choice; the trace has no event kind for it, so the
            # orchestrator's log names the session and the person (never the token or the content)
            sys.stderr.write("research-orchestrator: an OpenTelemetry export with content of session %s for %s\n"
                             % (sid, _log_name(who.get("username"))))
        return 200, otel.export(evs, session, content=bool(content))

    def reexecute(self, who, token, sid):
        """POST /api/sessions/<sid>/reexecute (OD-4e-8): the session's profile again, on the model it ran on, minted with
        `reexecutes` = sid (recorded in the new session's session_minted); the same refusals as POST /api/sessions."""
        i = self._own(who, sid)
        if i is None:
            return 404, {"error": "no such session"}
        if i.get("backend") in (None, "scripted"):
            return 409, {"error": "the session is not a model session: nothing to re-execute"}
        return self.start(who, token, {"profile": i["profile"], "endpoint": i["backend"]}, reexecutes=sid)

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
                self._report_stopped(cid, sid)
                self.runner.delete(cid)
                self.runner.owner.pop(cid, None)
                self.sim_caps.pop(cid, None)
                self.sims_reported.discard(cid)
        for eid, e in list(self.estimates.items()):
            if e["sid"] == sid:
                self.estimates.pop(eid, None)
                self.kube.delete_job(jobs.estimate_job_name(eid))

    def _report_sims(self):
        """sim_finished, as actor orchestrator, when a simulation Job ends (research Phase 4e, design 2.2): the
        campaign's CPU is then on the trace even when the agent never asks sim.status again. mcp-sim may write its
        own; session_status counts one per cid, whichever order. A refused record (403) is not retried."""
        for cid, sid in list(self.runner.owner.items()):
            if cid not in self.sims_reported:
                self._report_sim(cid, sid)

    def _report_sim(self, cid, sid, stopping=False):
        """One campaign's sim_finished once its Job ended. stopping: the session's end is about to delete the Job, so
        a campaign still running is recorded as failed with its CPU unknown (cpu_hours null: session_status counts
        it as 0, as it did before) and the trace never leaves it running."""
        s = self.runner.status(cid)
        if isinstance(s, dict) and s.get("state") in ("done", "failed"):
            try:
                cpu = round(float(s.get("cpu_hours") or 0), 6)
            except (TypeError, ValueError):
                cpu = 0.0
            pay = {"cid": cid, "state": s["state"], "cpu_hours": cpu,
                   "result_digest": (s.get("manifest") or {}).get("result_digest") if isinstance(s.get("manifest"), dict) else None}
        elif stopping:
            pay = {"cid": cid, "state": "failed", "cpu_hours": None, "result_digest": None,
                   "error": "stopped with the session before the Job finished"}
        else:
            return
        if isinstance(self.sim_caps.get(cid), (int, float)):
            pay["cap_h"] = round(self.sim_caps[cid], 6)
        st, _ = self.sh.request("POST", "/trace", {"server": "orchestrator", "sid": sid, "event": "sim_finished",
                                                   "payload": pay})
        if st in (200, 403):
            self.sims_reported.add(cid)

    def _report_stopped(self, cid, sid):
        """Before the session's cleanup deletes a campaign's Job: one attempt, since the Job then goes."""
        if cid in self.sims_reported:
            return
        try:
            self._report_sim(cid, sid, stopping=True)
        except Exception as e:                              # never stops the cleanup
            sys.stderr.write("cleanup sims %s\n" % type(e).__name__)

    def tick(self):
        now = self.clock()
        try:
            self._report_sims()
        except Exception as e:                              # never stops the session lifecycle below
            sys.stderr.write("tick sims %s\n" % type(e).__name__)
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
            self.sim_caps[cid] = cap
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
        _root_on_path()
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

        def send(self, code, obj, gz=False):
            b = json.dumps(obj).encode()
            gz = gz and "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
            if gz:
                b = gzip.compress(b, 6, mtime=0)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if gz:
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
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
            # research Phase 4e (design rs4e §1, CSRF): a POST that carries an Origin must come from the
            # research console's own origin (RS_CONSOLE_ORIGIN); the CLI's urllib sends none and passes.
            # With the 415 JSON rule and the proxy's SameSite=Lax cookie, access-api's defence.
            origin = self.headers.get("Origin")
            if self.command == "POST" and origin is not None and origin != orch.cfg.get("console_origin"):
                return self.send(403, {"error": "wrong origin"})
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
            if self.command == "GET" and path == "/api/me":
                return self.send(*orch.me(d))
            if self.command == "GET" and path == "/api/profiles":
                return self.send(*orch.profiles())
            if path == "/api/sessions":
                if self.command == "GET":
                    return self.send(*orch.listing(who, q))
                b = self.body()
                return None if not isinstance(b, dict) else self.send(*orch.start(who, token, b))
            m = re.match(r"^/api/sessions/([^/]+)/campaigns(?:/([^/]+)(?:/runs/([^/]+)(/series)?)?)?$", path)
            if m and self.command == "GET":
                sid, cid, n = m.group(1), m.group(2), m.group(3)
                if cid is None:
                    return self.send(*orch.campaigns(who, sid))
                if n is None:
                    return self.send(*orch.campaign(who, sid, cid, q))
                if m.group(4):
                    return self.send(*orch.series(who, sid, cid, n, q), gz=True)
                return self.send(*orch.run(who, sid, cid, n))
            m = re.match(r"^/api/sessions/([^/]+)(?:/(events|stop|replay|reexecute|otel|(gates|proposals)/([^/]+)))?$", path)
            if not m:
                return self.send(404, {"error": "not found"})
            sid, sub = m.group(1), m.group(2)
            if sub is None and self.command == "GET":
                return self.send(*orch.info(who, sid))
            if sub == "events" and self.command == "GET":
                a = (q.get("after") or ["0"])[0]
                w = (q.get("wait") or ["0"])[0]
                return self.send(*orch.events(who, sid, int(a) if a.isdigit() else 0,
                                              int(w) if w.isdigit() and len(w) < 4 else 0, _token_exp(token)))
            if sub == "otel" and self.command == "GET":
                return self.send(*orch.otel(who, sid, (q.get("content") or ["0"])[0] in ("1", "true")))
            if self.command != "POST":
                return self.send(405, {"error": "method not allowed"})
            b = self.body()
            if not isinstance(b, dict):
                return None
            if sub == "stop":
                return self.send(*orch.stop(who, token, sid))
            if sub == "replay":
                return self.send(*orch.replay(who, sid))
            if sub == "reexecute":
                return self.send(*orch.reexecute(who, token, sid))
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


def _token_exp(token):
    """The exp claim of the person's token (already verified by check()), or None: the long-poll's bound."""
    import base64
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        exp = claims.get("exp")
        return exp if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
    except (IndexError, ValueError, AttributeError, TypeError):
        return None


def _inventory(b64):
    """RS_ENDPOINTS_INVENTORY (base64 JSON list) -> list; empty or unreadable -> [] (the picker then lists nothing)."""
    import base64
    try:
        v = json.loads(base64.b64decode(b64.encode(), validate=True).decode()) if b64 else []
    except (ValueError, UnicodeDecodeError):
        sys.stderr.write("research-orchestrator: RS_ENDPOINTS_INVENTORY is unreadable\n")
        return []
    return v if isinstance(v, list) else []


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
           "series_every": float(os.environ.get("RS_SIM_SERIES_EVERY", "60")),
           # research Phase 4e: the only Origin a browser POST may carry (empty: none may)
           "console_origin": os.environ.get("RS_CONSOLE_ORIGIN", "") or None,
           "model_gateway_url": os.environ.get("RS_MODEL_GATEWAY_URL", ""),
           "endpoints": [e for e in os.environ.get("RS_ENDPOINTS", "local").split() if e],
           "inventory": _inventory(os.environ.get("RS_ENDPOINTS_INVENTORY", ""))}
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
