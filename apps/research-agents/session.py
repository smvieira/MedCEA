#!/usr/bin/env python3
"""research-session (research Phase 4a, stage 3; design section 3.4 with R8-R10).

The only holder of the session-token key and of the rs_session database login. Three ports,
one handler class each; the actor of a trace event is the PORT (and, on the server port, the
declared server name checked by the database's allow-list), never a body field.

  8100 person  POST /mint /revoke /sessions/<sid>/gates/<gid> /sessions/<sid>/proposals/<pid>;
               GET /healthz (public).  Person routes: the platform's check() (token verified
               against the realm keys, route table), uuid sub, person_id claim, one own role.
  8101 agent   POST /claim (one-time claim -> the session token, bound to the registered pod
               IP) and /trace (agent event types, the session token in the body).
  8102 server  POST /introspect, /trace; PUT/POST /claims/<sid>/expect; GET /events/<sid>,
               /gates/<gid>?sid=, /sessions/<sid>; POST /sessions/<sid>/revoke (the orchestrator,
               Job ended), /signin/start|poll|refresh (device-code relay for client research-agent, R12).  Callers are network-gated (mcp-sim, mcp-lake, orchestrator).

Token: rst1.<kid>.<sid>.<exp>.<mac>, mac = b64url(HMAC-SHA256(K_tok, "medcea-research-session|rst1|kid|sid|exp")),
K_tok = HMAC-SHA256(master, b"medcea research session token v1"). Only sha256(token) is stored.
Active iff mac, kid, exp, no revocation, sha256 = the row's, exp = the row's, peer = the registered
pod IP. Everything about a session (hashes, metadata, the registered pod IP, the claim state) is read
from the database (session_state); at start the service revokes every still-active session
(reason service_restart, R10), so a restart fails closed.
Never logs a token, a claim or the key. DB access goes through the Db adapter (PgDb for production).
"""
import base64
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

SERVICE = "research-session"
MAX_TTL = 8 * 3600
CLAIM_TTL = 120
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SID = re.compile(r"^[A-Za-z0-9_-]{22}$")
B64 = re.compile(r"^[A-Za-z0-9_-]{43}$")
KID = re.compile(r"^[0-9a-f]{8}$")
NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,39}$")
AGENT_EVENTS = ("turn_request", "turn_response", "tool_call", "tool_result", "checkpoint", "proposal", "stop")
SERVER_EVENTS = ("tool_result", "gate_pending", "sim_started", "sim_finished", "replay_result",
                 "turn_request", "turn_response")
SERVERS = ("mcp-sim", "mcp-lake", "orchestrator", "model-gateway")
CLIENT_ID = "research-agent"
SCOPE = "openid groups medcea-identity"
TOOL_SERVER = {"lake": "mcp-lake", "sim": "mcp-sim", "propose": "research-session"}


class Conflict(Exception):
    pass


class NotFound(Exception):
    pass


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256_hex(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


class Keys:
    def __init__(self, master_hex):
        master = bytes.fromhex(master_hex.strip())
        if len(master) < 32:
            raise ValueError("the session key must be at least 32 bytes")
        self.kid = hashlib.sha256(master).hexdigest()[:8]
        self.k = hmac.new(master, b"medcea research session token v1", hashlib.sha256).digest()

    def mac(self, sid, exp):
        msg = "medcea-research-session|rst1|%s|%s|%d" % (self.kid, sid, exp)
        return b64u(hmac.new(self.k, msg.encode(), hashlib.sha256).digest())

    def token(self, sid, exp):
        return "rst1.%s.%s.%d.%s" % (self.kid, sid, exp, self.mac(sid, exp))

    def parse(self, token):
        """(sid, exp) of a well-formed token with a valid mac, else (None, reason)."""
        if not isinstance(token, str) or len(token) > 120:
            return None, "malformed"
        p = token.split(".")
        if len(p) != 5 or p[0] != "rst1" or not KID.match(p[1]) or not SID.match(p[2]) \
                or not p[3].isdigit() or not B64.match(p[4]):
            return None, "malformed"
        if p[1] != self.kid:
            return None, "unknown kid"
        exp = int(p[3])
        if not hmac.compare_digest(p[4], self.mac(p[2], exp)):
            return None, "bad mac"
        return (p[2], exp), None


class KeycloakRelay:
    """The realm's form-encoded POSTs for the sign-in relay; post(path, form) -> (status, object). Bodies never logged."""

    def __init__(self, realm_url, timeout=10):
        self.base, self.timeout = realm_url.rstrip("/"), timeout

    def post(self, path, form):
        import urllib.error
        import urllib.parse
        import urllib.request
        req = urllib.request.Request(self.base + path, urllib.parse.urlencode(form).encode(),
                                     {"Content-Type": "application/x-www-form-urlencoded"})
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


class PgDb:
    """The production adapter: psycopg2, login rs_session, password from a file/env, never argv."""

    def __init__(self, dsn_kwargs):
        import psycopg2
        self.pg = psycopg2
        self.kw = dsn_kwargs
        self.lock = threading.Lock()
        self.conn = None

    def _run(self, sql, args=()):
        with self.lock:
            for attempt in (0, 1):
                try:
                    if self.conn is None or self.conn.closed:
                        self.conn = self.pg.connect(**self.kw)
                        self.conn.autocommit = False
                    with self.conn.cursor() as cur:
                        cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        cur.execute(sql, args)
                        rows = cur.fetchall() if cur.description else []
                    self.conn.commit()
                    return rows
                except self.pg.errors.Error as e:  # a statement error: the connection is fine
                    self.conn.rollback()
                    if getattr(e, "pgcode", None) == "53400":
                        raise Conflict(str(e).splitlines()[0])
                    if getattr(e, "pgcode", None) == "22023":
                        raise NotFound(str(e).splitlines()[0])
                    raise
                except self.pg.OperationalError:
                    self.conn = None
                    if attempt:
                        raise

    def open_session(self, **k):
        return self._run("SELECT agent_trace.open_session(%s,%s,%s,%s,%s::uuid,%s,%s,%s,%s,%s,%s::text[],%s::jsonb,%s,%s,%s)",
                         (k["sid"], k["kid"], k["token_sha256"], k["claim_sha256"], k["sup_sub"], k["sup_person"],
                          k["sup_role"], k["sup_username"], k["profile"], k["profile_sha256"], list(k["tools"]),
                          json.dumps(k["budget"]), k["backend"], k["code_commit"], k["exp"]))[0][0]

    def append_event(self, port, sid, actor, event, payload, token_sha256=None):
        r = self._run("SELECT event_id, refused FROM agent_trace.append_event(%s,%s,%s,%s,%s::jsonb,%s)",
                      (port, sid, actor, event, json.dumps(payload), token_sha256))[0]
        return r[0], r[1]

    def use_claim(self, sid, peer):
        return self._run("SELECT agent_trace.use_claim(%s, %s::inet)", (sid, peer))[0][0]

    def revoke(self, sid, reason, by_sub):
        return self._run("SELECT agent_trace.revoke(%s,%s,%s::uuid)", (sid, reason, by_sub))[0][0]

    def session_status(self, sid):
        r = self._run("SELECT active, revoked, extract(epoch FROM exp)::bigint, backend, budget, spent "
                      "FROM agent_trace.session_status(%s)", (sid,))
        if not r:
            raise NotFound("no session")
        a, rv, exp, backend, budget, spent = r[0]
        return {"active": a, "revoked": rv, "exp": int(exp), "backend": backend, "budget": budget, "spent": spent}

    def set_expect(self, sid, peer):
        return self._run("SELECT agent_trace.set_expect(%s, %s::inet)", (sid, peer))[0][0]

    def session_state(self, sid):
        r = self._run("SELECT token_sha256, claim_sha256, created_at, exp, sup_sub::text, sup_person, sup_role, "
                      "sup_username, profile, profile_sha256, tools, budget, backend, expect, claimed "
                      "FROM agent_trace.session_state(%s)", (sid,))
        if not r:
            raise NotFound("no session")
        k = ("token_sha256", "claim_sha256", "created_at", "exp", "sup_sub", "sup_person", "sup_role",
             "sup_username", "profile", "profile_sha256", "tools", "budget", "backend", "expect", "claimed")
        return dict(zip(k, r[0]))

    def active_sessions(self):
        return [r[0] for r in self._run("SELECT sid FROM agent_trace.active_sessions()")]

    def events(self, sid, after=0):
        rows = self._run("SELECT event_id, at, actor, event, payload, prev_hash, hash FROM agent_trace.events(%s,%s)",
                         (sid, after))
        return [{"event_id": r[0], "at": r[1].isoformat(), "actor": r[2], "event": r[3], "payload": r[4],
                 "prev_hash": r[5], "hash": r[6]} for r in rows]


class Service:
    """State and rules; the three handler classes only parse HTTP and call this."""

    def __init__(self, keys, db, iam, clock=time.time):
        self.keys, self.db, self.iam, self.clock = keys, db, iam, clock
        self.lock = threading.Lock()
        self.kc = None           # KeycloakRelay (R12) or None
        self.signin_hits = {}
        self.last_anchor = None  # (event_id, hash) the service last wrote: /healthz, R11

    def revoke_all_active(self):
        """At start: every session still active is revoked (R10), so a restart fails closed."""
        n = 0
        for sid in self.db.active_sessions():
            try:
                if self.db.revoke(sid, "service_restart", None):
                    n += 1
            except NotFound:
                pass
        return n

    def _rec(self, sid):
        """The session's database state, or None."""
        try:
            return self.db.session_state(sid)
        except NotFound:
            return None

    # ── helpers
    def note(self, sid, eid):
        """Remember the (event_id, hash) just written: /healthz reports it (R11)."""
        if eid:
            try:
                ev = self.db.events(sid, eid - 1)
                if ev and ev[0]["event_id"] == eid:
                    self.last_anchor = (eid, ev[0]["hash"])
            except Exception:
                pass

    def _meta_active(self, sid, token, peer):
        """The R9 rule; (record, None) or (None, reason)."""
        rec = self._rec(sid)
        if rec is None:
            return None, "no such session"
        parsed, why = self.keys.parse(token)
        if parsed is None:
            return None, why
        if sha256_hex(token) != rec["token_sha256"] or parsed[1] != rec["exp"]:
            return None, "not the session's token"
        if parsed[1] <= self.clock():
            return None, "expired"
        if not rec["claimed"] or not peer or peer != rec["expect"]:
            return None, "peer is not the registered pod"
        try:
            st = self.db.session_status(sid)
        except NotFound:
            return None, "no session row"
        if not st["active"]:
            return None, "revoked or expired"
        return (rec, st), None

    # ── person routes
    def mint(self, who, body):
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        roles = who.get("roles") or []
        if len(roles) != 1:
            return 403, {"error": "exactly one own platform role is required"}
        profile, backend = body.get("profile"), body.get("backend", "scripted")
        tools, budget = body.get("tools"), body.get("budget") or {}
        psha, commit = body.get("profile_sha256"), body.get("code_commit")
        ttl = body.get("ttl_s", 7200)
        if not (isinstance(profile, str) and NAME.match(profile) and backend in ("scripted", "local")
                and isinstance(tools, list) and tools and all(isinstance(t, str) and re.match(r"^[a-z]+\.[a-z_]+$|^propose$", t) for t in tools)
                and isinstance(budget, dict) and isinstance(psha, str) and re.match(r"^[0-9a-f]{64}$", psha)
                and isinstance(commit, str) and re.match(r"^[0-9a-f]{7,40}$", commit)
                and isinstance(ttl, int) and not isinstance(ttl, bool) and 60 <= ttl <= MAX_TTL):
            return 400, {"error": "profile, backend, tools, budget, profile_sha256, code_commit or ttl_s is invalid"}
        sid = b64u(secrets.token_bytes(16))
        exp = int(self.clock()) + ttl
        token = self.keys.token(sid, exp)
        claim = b64u(secrets.token_bytes(32))
        try:
            self.db.open_session(sid=sid, kid=self.keys.kid, token_sha256=sha256_hex(token),
                                 claim_sha256=sha256_hex(claim), sup_sub=who["sub"], sup_person=who["person_id"],
                                 sup_role=roles[0], sup_username=who.get("username") or "", profile=profile,
                                 profile_sha256=psha, tools=tools, budget=budget, backend=backend,
                                 code_commit=commit, exp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)))
        except Conflict as e:
            return 409, {"error": str(e)}
        return 201, {"sid": sid, "claim": claim, "claim_valid_s": CLAIM_TTL, "exp": exp}

    def _own(self, who, sid):
        rec = self._rec(sid)
        if rec is None or rec["sup_person"] != who["person_id"]:
            return None
        return rec

    def revoke(self, who, body):
        sid = (body or {}).get("sid") if isinstance(body, dict) else None
        if not isinstance(sid, str) or not SID.match(sid) or self._own(who, sid) is None:
            return 404, {"error": "no such session"}
        reason = (body.get("reason") or "revoked by the supervisor")
        return 200, {"revoked": bool(self.db.revoke(sid, str(reason)[:200], who["sub"]))}

    def decide(self, who, kind, sid, xid, body):
        """gate_decided / proposal_decided, attributed to the person."""
        if not SID.match(sid) or self._own(who, sid) is None:
            return 404, {"error": "no such session"}
        d = (body or {}).get("decision") if isinstance(body, dict) else None
        if d not in ("approve", "deny") or not re.match(r"^[A-Za-z0-9_.-]{1,40}$", xid):
            return 400, {"error": "decision must be approve or deny; id is invalid"}
        pay = {"gid" if kind == "gate" else "pid": xid, "decision": d, "by_sub": who["sub"],
               "by_username": who.get("username") or "", "note": str((body.get("note") or ""))[:500]}
        if kind == "gate" and d == "approve":
            cap = body.get("approved_cap_h")
            if not isinstance(cap, (int, float)) or isinstance(cap, bool) or not 0 < cap <= 100:
                return 400, {"error": "approved_cap_h is required to approve a gate"}
            pay["approved_cap_h"] = cap
        eid, why = self.db.append_event("person", sid, "research-session",
                                        "gate_decided" if kind == "gate" else "proposal_decided", pay)
        if why:
            return 403, {"error": why}
        self.note(sid, eid)
        return 200, {"event_id": eid}

    # ── agent port
    def expect(self, sid, body):
        ip = (body or {}).get("peer") if isinstance(body, dict) else None
        try:
            ip = str(ipaddress.ip_address(ip))
        except (ValueError, TypeError):
            return 400, {"error": "peer must be an IP address"}
        try:
            r = self.db.set_expect(sid, ip)
        except NotFound:
            return 404, {"error": "no such session"}
        if r != "ok":
            return 409, {"error": "a pod is already registered for this session"}
        return 200, {"expect": ip}

    def claim(self, peer, body):
        sid = body.get("sid") if isinstance(body, dict) else None
        claim = body.get("claim") if isinstance(body, dict) else None
        if not (isinstance(sid, str) and SID.match(sid) and isinstance(claim, str) and B64.match(claim)):
            return 400, {"error": "sid and claim are required"}
        rec = self._rec(sid)
        if rec is None:
            return 403, {"error": "refused"}
        if rec["expect"] is None or peer != rec["expect"]:
            return 403, {"error": "refused"}
        if rec["claimed"] or self.clock() > rec["created_at"] + CLAIM_TTL:
            # a second use of a claim: the database records it and revokes the session
            try:
                self.db.use_claim(sid, peer)
            except NotFound:
                pass
            return 403, {"error": "refused"}
        if not hmac.compare_digest(sha256_hex(claim), rec["claim_sha256"]):
            return 403, {"error": "refused"}
        if not self.db.use_claim(sid, peer):
            return 403, {"error": "refused"}
        return 200, {"token": self.keys.token(sid, rec["exp"]), "exp": rec["exp"]}

    def trace(self, port, peer, body):
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        sid, ev, pay = body.get("sid"), body.get("event"), body.get("payload", {})
        if not (isinstance(sid, str) and SID.match(sid) and isinstance(ev, str)):
            return 400, {"error": "sid and event are required"}
        if port == "agent":
            tok = body.get("token")
            # refused before the database for a bad token; an event outside the port's list is the database's refusal (recorded)
            rec, why = self._meta_active(sid, tok, peer)
            if rec is None:
                return 403, {"error": "refused"}
            eid, refused = self.db.append_event("agent", sid, "agent", ev, pay, sha256_hex(tok))
        else:
            actor = body.get("server")
            if actor not in SERVERS:
                return 400, {"error": "server must name the calling server"}
            eid, refused = self.db.append_event("server", sid, actor, ev, pay)
        if refused:
            return 403, {"error": refused}
        self.note(sid, eid)
        return 200, {"event_id": eid}

    # ── server port
    def introspect(self, body):
        inactive = (200, {"active": False})
        if not isinstance(body, dict):
            return inactive
        sid_exp, why = self.keys.parse(body.get("token"))
        if sid_exp is None:
            return inactive
        rec_st, why = self._meta_active(sid_exp[0], body["token"], body.get("peer"))
        if rec_st is None:
            return inactive
        rec, st = rec_st
        aud = body.get("audience")
        auds = {TOOL_SERVER[t.split(".")[0]] for t in rec["tools"] if t.split(".")[0] in TOOL_SERVER}
        if aud not in auds | {"orchestrator", "model-gateway"}:
            return inactive
        left = {k: (v - float(st["spent"].get(k, 0))) for k, v in st["budget"].items()
                if isinstance(v, (int, float)) and not isinstance(v, bool) and k in st["spent"]}
        return 200, {"active": True, "sid": sid_exp[0], "sup_sub": rec["sup_sub"], "sup_person": rec["sup_person"],
                     "sup_role": rec["sup_role"], "profile": rec["profile"], "profile_sha256": rec["profile_sha256"],
                     "tools": [t for t in rec["tools"] if TOOL_SERVER.get(t.split(".")[0]) == aud or aud in ("orchestrator", "model-gateway")],
                     "backend": rec["backend"], "budget_left": left, "exp": rec["exp"]}

    def info(self, sid):
        """GET /sessions/<sid> (server port): what the orchestrator needs to check ownership and lifecycle."""
        rec = self._rec(sid) if SID.match(sid or "") else None
        if rec is None:
            return 404, {"error": "no such session"}
        st = self.db.session_status(sid)
        return 200, {"sid": sid, "sup_person": rec["sup_person"], "sup_sub": rec["sup_sub"], "profile": rec["profile"],
                     "backend": rec["backend"], "exp": rec["exp"], "claimed": rec["claimed"], "expect": rec["expect"],
                     "active": st["active"], "revoked": st["revoked"], "budget": st["budget"], "spent": st["spent"]}

    def revoke_by_orchestrator(self, sid, body):
        """POST /sessions/<sid>/revoke (server port): the orchestrator ends a session whose Job ended (R10)."""
        if not SID.match(sid or "") or self._rec(sid) is None:
            return 404, {"error": "no such session"}
        reason = str((body or {}).get("reason") or "job ended")[:200] if isinstance(body, dict) else "job ended"
        return 200, {"revoked": bool(self.db.revoke(sid, reason, None))}

    # ── device sign-in relay (R12): the only code that talks to Keycloak
    def signin(self, op, peer, body):
        kc = self.kc
        if kc is None:
            return 503, {"error": "sign-in is not configured"}
        if not isinstance(body, dict):
            return 400, {"error": "a JSON object is required"}
        now = self.clock()
        if op == "start":
            with self.lock:
                hits = [t for t in self.signin_hits.get(peer, []) if now - t < 60]
                if len(hits) >= 10:
                    return 429, {"error": "too many sign-in starts"}
                self.signin_hits[peer] = hits + [now]
            st, r = kc.post("/protocol/openid-connect/auth/device", {"client_id": CLIENT_ID, "scope": SCOPE})
            keep = ("device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval")
            return (200, {k: r[k] for k in keep if k in r}) if st == 200 else (502, {"error": "Keycloak refused the device request"})
        if op == "poll":
            dc = body.get("device_code")
            if not isinstance(dc, str) or not 8 <= len(dc) <= 512:
                return 400, {"error": "device_code is required"}
            st, r = kc.post("/protocol/openid-connect/token", {
                "client_id": CLIENT_ID, "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": dc})
        elif op == "refresh":
            rt = body.get("refresh_token")
            if not isinstance(rt, str) or not 8 <= len(rt) <= 4096:
                return 400, {"error": "refresh_token is required"}
            st, r = kc.post("/protocol/openid-connect/token", {
                "client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt})
        else:
            return 404, {"error": "not found"}
        if st == 200:
            return 200, {k: r[k] for k in ("access_token", "refresh_token", "expires_in", "refresh_expires_in") if k in r}
        if isinstance(r, dict) and r.get("error") in ("authorization_pending", "slow_down", "expired_token", "access_denied",
                                                       "invalid_grant"):
            return 400, {"error": r["error"]}
        return 502, {"error": "Keycloak refused the request"}

    def events_of(self, sid, after):
        if not SID.match(sid):
            return 404, {"error": "no such session"}
        try:
            return 200, {"events": self.db.events(sid, after)}
        except NotFound:
            return 404, {"error": "no such session"}

    def gate(self, sid, gid):
        if not SID.match(sid or "") or not re.match(r"^[A-Za-z0-9_.-]{1,40}$", gid):
            return 404, {"error": "no such gate"}
        pending, decided = None, None
        for e in self.db.events(sid, 0):
            if e["payload"].get("gid") == gid:
                if e["event"] == "gate_pending" and pending is None:
                    pending = e
                elif e["event"] == "gate_decided" and decided is None:
                    decided = e
        if pending is None:
            return 404, {"error": "no such gate"}
        out = {"gid": gid, "state": "pending", "pending": pending["payload"]}
        if decided:
            out.update(state="approved" if decided["payload"].get("decision") == "approve" else "denied",
                       decision=decided["payload"], event_id=decided["event_id"])
        return 200, out

    def healthz(self):
        a = self.last_anchor
        return {"ok": True, "kid": self.keys.kid, "anchor": {"event_id": a[0], "hash": a[1]} if a else None}


def _handler(svc, port_name):
    class H(BaseHTTPRequestHandler):
        server_version = "research-session"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):   # request line only: never a body or a header
            sys.stderr.write("%s %s %s\n" % (port_name, self.command, urlsplit(self.path).path.split("?")[0][:60]))

        def send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def body(self):
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self.send(415, {"error": "Content-Type must be application/json"})
                return None
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if not 0 < n <= 65536:
                    raise ValueError
                return json.loads(self.rfile.read(n))
            except ValueError:
                self.send(400, {"error": "a JSON body of at most 64 KiB is required"})
                return None

        def route(self):
            try:
                u = urlsplit(self.path)
                getattr(self, "r_" + port_name)(u.path, parse_qs(u.query))
            except (NotFound,):
                self.send(404, {"error": "not found"})
            except Exception as e:   # never the message: it could carry a value
                sys.stderr.write("error %s\n" % type(e).__name__)
                self.send(500, {"error": "Something went wrong on our side."})

        do_GET = do_POST = do_PUT = route

        # 8100
        def r_person(self, path, q):
            if self.command == "GET" and path == "/healthz":
                return self.send(200, svc.healthz())
            d = svc.iam.check(SERVICE, self.command, path, self.headers)
            if not d.allow:
                return self.send(d.status, {"error": d.reason})
            who = d.who or {}
            if not UUID.match(str(who.get("sub") or "")):
                return self.send(401, {"error": "the token has no account uuid"})
            if not who.get("person_id"):
                return self.send(403, {"error": "the token has no person_id"})
            if self.command != "POST":
                return self.send(405, {"error": "method not allowed"})
            b = self.body()
            if b is None:
                return
            m = re.match(r"^/sessions/([^/]+)/(gates|proposals)/([^/]+)$", path)
            if path == "/mint":
                return self.send(*svc.mint(who, b))
            if path == "/revoke":
                return self.send(*svc.revoke(who, b))
            if m:
                return self.send(*svc.decide(who, "gate" if m.group(2) == "gates" else "proposal", m.group(1), m.group(3), b))
            self.send(404, {"error": "not found"})

        # 8101
        def r_agent(self, path, q):
            if self.command != "POST" or path not in ("/claim", "/trace"):
                return self.send(404, {"error": "not found"})
            b = self.body()
            if b is None:
                return
            peer = self.client_address[0]
            self.send(*(svc.claim(peer, b) if path == "/claim" else svc.trace("agent", peer, b)))

        # 8102
        def r_server(self, path, q):
            if self.command == "GET":
                m = re.match(r"^/events/([^/]+)$", path)
                if m:
                    after = (q.get("after") or ["0"])[0]
                    return self.send(*svc.events_of(m.group(1), int(after) if after.isdigit() else 0))
                m = re.match(r"^/gates/([^/]+)$", path)
                if m:
                    return self.send(*svc.gate((q.get("sid") or [""])[0], m.group(1)))
                m = re.match(r"^/sessions/([^/]+)$", path)
                if m:
                    return self.send(*svc.info(m.group(1)))
                return self.send(404, {"error": "not found"})
            m = re.match(r"^/sessions/([^/]+)/revoke$", path)
            if m and self.command == "POST":
                b = self.body()
                return None if b is None else self.send(*svc.revoke_by_orchestrator(m.group(1), b))
            m = re.match(r"^/signin/(start|poll|refresh)$", path)
            if m and self.command == "POST":
                b = self.body()
                return None if b is None else self.send(*svc.signin(m.group(1), self.client_address[0], b))
            m = re.match(r"^/claims/([^/]+)/expect$", path)
            if m and self.command in ("PUT", "POST"):
                b = self.body()
                return None if b is None else self.send(*svc.expect(m.group(1), b))
            if self.command == "POST" and path in ("/introspect", "/trace"):
                b = self.body()
                if b is None:
                    return
                self.send(*(svc.introspect(b) if path == "/introspect" else svc.trace("server", None, b)))
                return
            self.send(404, {"error": "not found"})
    return H


def make_servers(svc, host="0.0.0.0", ports=(8100, 8101, 8102)):
    return [ThreadingHTTPServer((host, p), _handler(svc, n)) for p, n in zip(ports, ("person", "agent", "server"))]


def _load_iam(path):
    spec = importlib.util.spec_from_file_location("medcea_iam", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    with open(os.environ["RS_SESSION_KEY_FILE"]) as f:
        keys = Keys(f.read())
    with open(os.environ["RS_SESSION_DB_PASS_FILE"]) as f:
        pw = f.read().strip()
    db = PgDb(dict(host=os.environ["RS_DB_HOST"], dbname=os.environ.get("RS_DB_NAME", "medcea_research"),
                   user="rs_session", password=pw, connect_timeout=5))
    svc = Service(keys, db, _load_iam(os.environ.get("MEDCEA_IAM_LIB", "/iam/medcea_iam.py")))
    if os.environ.get("RS_KEYCLOAK_REALM_URL"):
        svc.kc = KeycloakRelay(os.environ["RS_KEYCLOAK_REALM_URL"])
    sys.stderr.write("research-session: revoked %d active session(s) at start\n" % svc.revoke_all_active())
    srvs = make_servers(svc)
    for s in srvs[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    sys.stderr.write("research-session: ports 8100 8101 8102, kid %s\n" % keys.kid)
    srvs[0].serve_forever()


if __name__ == "__main__":
    main()
