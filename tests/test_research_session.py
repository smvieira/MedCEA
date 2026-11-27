#!/usr/bin/env python3
"""tests/test_research_session.py — research-session (stage 3): the real handlers on ephemeral
localhost ports, a fake database adapter, a throwaway realm key for person tokens."""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_JWT = True
except ImportError:
    HAVE_JWT = False

ISSUER = "https://keycloak.test/realms/medcea"
SUB = "11111111-2222-3333-4444-555555555555"


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakeDb:
    """Mirrors agent_trace's rules that the service relies on."""

    def __init__(self, ses):
        self.s = ses
        self.rows, self.events_, self.revoked, self.claims, self.expired = {}, [], set(), set(), set()
        self.expects, self.clock = {}, time.time

    def open_session(self, **k):
        if sum(1 for r in self.rows.values() if r["sup_person"] == k["sup_person"] and r["sid"] not in self.revoked) >= 2:
            raise self.s.Conflict("agent_trace: person already has 2 active sessions (max_active)")
        self.rows[k["sid"]] = dict(k, created_at=int(self.clock()))
        return self._add(k["sid"], "research-session", "session_minted")

    def _add(self, sid, actor, ev, pay=None):
        self.events_.append({"event_id": len(self.events_) + 1, "at": "2026-11-21T00:00:00+00:00", "actor": actor,
                             "event": ev, "payload": pay or {}, "prev_hash": "p", "hash": "h%d" % len(self.events_)})
        self.events_[-1]["sid"] = sid
        return len(self.events_)

    def active(self, sid):
        return sid in self.rows and sid not in self.revoked and sid not in self.expired

    def append_event(self, port, sid, actor, event, payload, token_sha256=None):
        lists = {"agent": self.s.AGENT_EVENTS, "server": self.s.SERVER_EVENTS,
                 "person": ("session_minted", "claim_exchanged", "claim_reused", "gate_decided", "proposal_decided", "session_revoked")}
        if event not in lists[port]:
            return None, "the %s port may not write %s" % (port, event)
        if port == "agent" and token_sha256 != self.rows[sid]["token_sha256"]:
            return None, "the token is not the session's"
        if port == "server" and event == "tool_result" and actor not in ("mcp-sim", "mcp-lake"):
            return None, "the server may not write it"
        if not self.active(sid) and port != "person" and event not in ("sim_finished", "replay_result"):
            return None, "the session is revoked or expired"
        return self._add(sid, "agent" if port == "agent" else actor, event, payload), None

    def use_claim(self, sid, peer):
        if not self.active(sid):
            return False
        if sid in self.claims:
            self._add(sid, "research-session", "claim_reused")
            self.revoke(sid, "claim_reused", None)
            return False
        self.claims.add(sid)
        self._add(sid, "research-session", "claim_exchanged")
        return True

    def revoke(self, sid, reason, by):
        if sid in self.revoked:
            return False
        self.revoked.add(sid)
        self._add(sid, "research-session", "session_revoked")
        return True

    def set_expect(self, sid, peer):
        if sid not in self.rows:
            raise self.s.NotFound("no")
        if sid in self.claims:
            return "claimed"
        if self.expects.setdefault(sid, peer) != peer:
            return "conflict"
        return "ok"

    def session_state(self, sid):
        if sid not in self.rows:
            raise self.s.NotFound("no")
        r = self.rows[sid]
        return {"token_sha256": r["token_sha256"], "claim_sha256": r["claim_sha256"], "created_at": r["created_at"],
                "exp": r["exp"] if isinstance(r["exp"], int) else self.exp_epoch(r["exp"]), "sup_sub": r["sup_sub"],
                "sup_person": r["sup_person"], "sup_role": r["sup_role"], "sup_username": r["sup_username"],
                "profile": r["profile"], "profile_sha256": r["profile_sha256"], "tools": r["tools"],
                "budget": r["budget"], "backend": r["backend"], "expect": self.expects.get(sid),
                "claimed": sid in self.claims}

    @staticmethod
    def exp_epoch(iso):
        import calendar
        return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))

    def active_sessions(self):
        return [sid for sid in self.rows if self.active(sid)]

    def session_status(self, sid):
        if sid not in self.rows:
            raise self.s.NotFound("no")
        r = self.rows[sid]
        return {"active": self.active(sid), "revoked": sid in self.revoked, "exp": 0, "backend": r["backend"],
                "budget": r["budget"], "spent": {"turns": 3, "cpu_hours": 0.5}}

    def events(self, sid, after=0):
        # agent_trace.events answers at most 1000 per call, oldest first
        return [e for e in self.events_ if e["sid"] == sid and e["event_id"] > after][:1000]

    def sessions_of(self, person, before=None, limit=50):
        mine = [(e["event_id"], e["sid"]) for e in self.events_ if e["event"] == "session_minted"
                and self.rows[e["sid"]]["sup_person"] == person and (before is None or e["event_id"] < before)]
        return [{"sid": sid, "mint_event_id": eid, "reexecutes": self.rows[sid].get("reexecutes"),
                 "revoked": sid in self.revoked} for eid, sid in sorted(mine, reverse=True)[:limit]]


@unittest.skipUnless(HAVE_JWT, "PyJWT/cryptography not installed on this host")
class SessionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["MEDCEA_IAM_ROUTES"] = os.path.join(cls.tmp, "routes.json")
        os.environ["MEDCEA_IAM_SETTINGS"] = os.path.join(cls.tmp, "settings.json")
        os.environ["MEDCEA_IAM_JWKS"] = os.path.join(cls.tmp, "jwks.json")
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        jwk.update(kid="k1", alg="RS256", use="sig")
        json.dump({"keys": [jwk]}, open(os.environ["MEDCEA_IAM_JWKS"], "w"))
        json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": True}, open(os.environ["MEDCEA_IAM_SETTINGS"], "w"))
        route = {"levels": ["C"], "group": "research_campaigns", "roles": {"bio_scientist": None}}
        table = {"roles": ["bio_scientist", "qa", "engineer"], "public": {}, "services": {"research-session": {
            "clients": ["research-agent"], "routes": {"POST /mint": route, "POST /revoke": route,
                                                     "POST /sessions/<sid>/gates/<gid>": route,
                                                     "POST /sessions/<sid>/proposals/<pid>": route}}}}
        json.dump(table, open(os.environ["MEDCEA_IAM_ROUTES"], "w"))
        cls.iam = load("medcea_iam", "apps/iam/lib/medcea_iam.py")
        cls.s = load("research_session", "apps/research-agents/session.py")

    def setUp(self):
        self.db = FakeDb(self.s)
        self.keys = self.s.Keys("ab" * 32)
        self.now = [time.time()]
        self.db.clock = lambda: self.now[0]
        self.svc = self.s.Service(self.keys, self.db, self.iam, clock=lambda: self.now[0])
        self.log = io.StringIO()
        self.srvs = self.s.make_servers(self.svc, "127.0.0.1", (0, 0, 0))
        self.ports = [s.server_address[1] for s in self.srvs]
        self.errcm = contextlib.redirect_stderr(self.log)
        self.errcm.__enter__()
        for s in self.srvs:
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def tearDown(self):
        for s in self.srvs:
            s.shutdown()
            s.server_close()
        self.errcm.__exit__(None, None, None)

    # helpers
    def person_token(self, roles=("bio_scientist",), **over):
        now = int(time.time())
        c = {"iss": ISSUER, "aud": ["medcea-api"], "sub": SUB, "typ": "Bearer", "azp": "research-agent", "iat": now,
             "exp": now + 300, "preferred_username": "bio", "person_id": "p-1", "groups": list(roles)}
        c.update(over)
        return jwt.encode({k: v for k, v in c.items() if v is not None}, self.key, algorithm="RS256", headers={"kid": "k1"})

    def call(self, which, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.ports[which], path), data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    MINT = {"profile": "baseline", "tools": ["lake.query", "sim.run", "propose"], "budget": {"turns": 10, "cpu_hours": 2},
            "profile_sha256": "a" * 64, "code_commit": "abc1234", "backend": "scripted"}

    def mint(self, **kw):
        st, r = self.call(0, "POST", "/mint", self.MINT, self.person_token(**kw))
        return st, r

    def claimed(self):
        st, r = self.mint()
        self.assertEqual(st, 201, r)
        sid = r["sid"]
        self.assertEqual(self.call(2, "PUT", "/claims/%s/expect" % sid, {"peer": "127.0.0.1"})[0], 200)
        st, c = self.call(1, "POST", "/claim", {"sid": sid, "claim": r["claim"]})
        self.assertEqual(st, 200, c)
        return sid, c["token"], r

    # tests
    def test_mint_rules(self):
        self.assertEqual(self.mint(roles=("engineer",))[0], 403)           # route table: no C
        self.assertEqual(self.mint(person_id=None)[0], 403)                # no person_id
        self.assertEqual(self.call(0, "POST", "/mint", self.MINT)[0], 401)  # no token
        st, r = self.mint()
        self.assertEqual(st, 201)
        self.assertNotIn("token", r)                                       # never returned at mint
        self.assertEqual(len(r["sid"]), 22)
        row = self.db.rows[r["sid"]]
        self.assertEqual(row["sup_person"], "p-1")
        self.assertEqual(len(row["token_sha256"]), 64)

    def test_two_active_then_409(self):
        self.assertEqual(self.mint()[0], 201)
        self.assertEqual(self.mint()[0], 201)
        self.assertEqual(self.mint()[0], 409)

    def test_ttl_over_8h_refused(self):
        b = dict(self.MINT, ttl_s=9 * 3600)
        self.assertEqual(self.call(0, "POST", "/mint", b, self.person_token())[0], 400)

    def test_claim_wrong_peer_and_reuse(self):
        st, r = self.mint()
        sid = r["sid"]
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": sid, "claim": r["claim"]})[0], 409)  # no pod registered yet: retry, nothing used
        self.assertTrue(self.db.active(sid))
        self.call(2, "PUT", "/claims/%s/expect" % sid, {"peer": "10.9.9.9"})
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": sid, "claim": r["claim"]})[0], 403)  # wrong peer
        self.assertTrue(self.db.active(sid))                       # a stranger cannot revoke it
        self.db.expects[sid] = "127.0.0.1"
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": sid, "claim": "x" * 43})[0], 403)  # wrong claim
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": sid, "claim": r["claim"]})[0], 200)
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": sid, "claim": r["claim"]})[0], 403)  # reuse
        self.assertFalse(self.db.active(sid))                      # reuse revoked it
        self.assertIn("claim_reused", [e["event"] for e in self.db.events_])

    def test_claim_expires(self):
        st, r = self.mint()
        self.call(2, "PUT", "/claims/%s/expect" % r["sid"], {"peer": "127.0.0.1"})
        self.now[0] += 121
        self.assertEqual(self.call(1, "POST", "/claim", {"sid": r["sid"], "claim": r["claim"]})[0], 403)

    def test_introspect_active_revoked_expired_peer(self):
        sid, tok, _ = self.claimed()
        q = {"token": tok, "audience": "mcp-sim", "peer": "127.0.0.1"}
        st, r = self.call(2, "POST", "/introspect", q)
        self.assertTrue(r["active"])
        # only this audience's tools: since stage 7a mcp-sim also serves propose.* (TOOL_SERVER)
        self.assertEqual(r["tools"], ["sim.run", "propose"])
        self.assertNotIn("lake.query", r["tools"])
        self.assertEqual(r["budget_left"]["turns"], 7)
        self.assertEqual(self.call(2, "POST", "/introspect", dict(q, peer="10.0.0.5"))[1], {"active": False})
        self.assertEqual(self.call(2, "POST", "/introspect", dict(q, audience="mcp-other"))[1], {"active": False})
        self.db.revoked.add(sid)
        self.assertEqual(self.call(2, "POST", "/introspect", q)[1], {"active": False})
        self.db.revoked.clear()
        self.now[0] += 3 * 3600
        self.assertEqual(self.call(2, "POST", "/introspect", q)[1], {"active": False})

    def test_state_is_in_the_database_not_the_process(self):
        sid, tok, _ = self.claimed()
        q = {"token": tok, "audience": "mcp-sim", "peer": "127.0.0.1"}
        self.svc.__init__(self.keys, self.db, self.iam, clock=lambda: self.now[0])   # a fresh process, same database
        self.assertTrue(self.call(2, "POST", "/introspect", q)[1]["active"])
        self.assertEqual(self.call(2, "PUT", "/claims/%s/expect" % sid, {"peer": "10.1.1.1"})[0], 409)

    def test_expect_conflict_and_same_peer(self):
        st, r = self.mint()
        p = "/claims/%s/expect" % r["sid"]
        self.assertEqual(self.call(2, "PUT", p, {"peer": "10.1.1.1"})[0], 200)
        self.assertEqual(self.call(2, "PUT", p, {"peer": "10.1.1.1"})[0], 200)
        self.assertEqual(self.call(2, "PUT", p, {"peer": "10.1.1.2"})[0], 409)
        self.assertEqual(self.call(2, "PUT", "/claims/%s/expect" % ("A" * 22), {"peer": "10.1.1.1"})[0], 404)

    def test_revoke_all_at_start(self):
        a = self.mint()[1]["sid"]
        b = self.mint()[1]["sid"]
        self.db.revoked.add(b)
        self.assertEqual(self.svc.revoke_all_active(), 1)
        self.assertFalse(self.db.active(a))
        self.assertEqual(self.svc.revoke_all_active(), 0)

    def test_info_and_orchestrator_revoke(self):
        sid, tok, _ = self.claimed()
        st, r = self.call(2, "GET", "/sessions/%s" % sid)
        self.assertEqual((st, r["sup_person"], r["active"], r["claimed"]), (200, "p-1", True, True))
        self.assertEqual(self.call(2, "GET", "/sessions/%s" % ("A" * 22))[0], 404)
        self.assertEqual(self.call(2, "POST", "/sessions/%s/revoke" % sid, {"reason": "job ended"})[1], {"revoked": True})
        self.assertFalse(self.db.active(sid))

    def test_signin_relay(self):
        posts = []

        class Kc:
            def post(s, path, form):
                posts.append((path, form))
                if path.endswith("/device"):
                    return 200, {"device_code": "d" * 20, "user_code": "ABCD", "verification_uri": "https://k/x",
                                 "expires_in": 600, "interval": 5, "extra": "dropped"}
                if form.get("device_code") == "p" * 20:
                    return 400, {"error": "authorization_pending", "error_description": "secret detail"}
                return 200, {"access_token": "a", "refresh_token": "r", "expires_in": 300, "id_token": "dropped"}
        self.svc.kc = Kc()
        st, r = self.call(2, "POST", "/signin/start", {})
        self.assertEqual((st, sorted(r)), (200, ["device_code", "expires_in", "interval", "user_code", "verification_uri"]))
        self.assertEqual(posts[0][1], {"client_id": "research-agent", "scope": "openid groups medcea-identity"})
        self.assertEqual(self.call(2, "POST", "/signin/poll", {"device_code": "p" * 20}), (400, {"error": "authorization_pending"}))
        st, r = self.call(2, "POST", "/signin/refresh", {"refresh_token": "r" * 20})
        self.assertEqual((st, sorted(r)), (200, ["access_token", "expires_in", "refresh_token"]))
        self.assertEqual(self.call(2, "POST", "/signin/poll", {})[0], 400)
        for _ in range(10):
            st = self.call(2, "POST", "/signin/start", {})[0]
        self.assertEqual(st, 429)
        self.svc.kc = None
        self.assertEqual(self.call(2, "POST", "/signin/start", {})[0], 503)

    def test_hmac_tamper_refused(self):
        sid, tok, _ = self.claimed()
        p = tok.split(".")
        for bad in (".".join(p[:4] + [p[4][:-1] + ("A" if p[4][-1] != "A" else "B")]),
                    ".".join(p[:3] + [str(int(p[3]) + 1000), p[4]]),
                    tok + "x", "rst1.bad", ".".join(["rst1", "00000000"] + p[2:])):
            self.assertEqual(self.call(2, "POST", "/introspect", {"token": bad, "audience": "mcp-sim", "peer": "127.0.0.1"})[1],
                             {"active": False}, bad)
        # a token of another key
        other = self.s.Keys("cd" * 32).token(sid, int(p[3]))
        self.assertEqual(self.call(2, "POST", "/introspect", {"token": other, "audience": "mcp-sim", "peer": "127.0.0.1"})[1],
                         {"active": False})

    def test_trace_per_port(self):
        sid, tok, _ = self.claimed()
        ok = self.call(1, "POST", "/trace", {"sid": sid, "token": tok, "event": "tool_call", "payload": {"n": 1}})
        self.assertEqual(ok[0], 200)
        self.assertEqual(self.db.events_[-1]["actor"], "agent")
        for ev in ("gate_decided", "sim_finished", "session_minted"):  # agent may not write these
            self.assertEqual(self.call(1, "POST", "/trace", {"sid": sid, "token": tok, "event": ev, "payload": {}})[0], 403, ev)
        # an actor field in the body is ignored on the agent port
        self.call(1, "POST", "/trace", {"sid": sid, "token": tok, "event": "stop", "payload": {}, "actor": "mcp-sim", "server": "mcp-sim"})
        self.assertEqual(self.db.events_[-1]["actor"], "agent")
        self.assertEqual(self.call(1, "POST", "/trace", {"sid": sid, "token": "rst1.x", "event": "stop", "payload": {}})[0], 403)
        # server port: a server event is fine, an agent event with a wrong actor is not
        self.assertEqual(self.call(2, "POST", "/trace", {"sid": sid, "server": "mcp-sim", "event": "sim_started", "payload": {}})[0], 200)
        self.assertEqual(self.call(2, "POST", "/trace", {"sid": sid, "server": "mcp-lake", "event": "tool_call", "payload": {}})[0], 403)
        self.assertEqual(self.call(2, "POST", "/trace", {"sid": sid, "server": "agent", "event": "tool_result", "payload": {}})[0], 400)
        self.assertEqual(self.call(2, "POST", "/trace", {"sid": sid, "event": "tool_result", "payload": {}})[0], 400)
        # routes of the other ports do not exist here
        self.assertEqual(self.call(1, "POST", "/introspect", {})[0], 404)
        self.assertEqual(self.call(2, "POST", "/claim", {})[0], 404)
        self.assertEqual(self.call(0, "GET", "/events/%s" % sid)[0], 401)   # person port has no server reads

    def test_revoke_and_gate_decisions(self):
        sid, tok, _ = self.claimed()
        self.db._add(sid, "mcp-sim", "gate_pending", {"gid": "g1", "estimate_h": 1})
        st, g = self.call(2, "GET", "/gates/g1?sid=" + sid)
        self.assertEqual(g["state"], "pending")
        t = self.person_token()
        self.assertEqual(self.call(0, "POST", "/sessions/%s/gates/g1" % sid, {"decision": "approve"}, t)[0], 400)  # cap needed
        st, r = self.call(0, "POST", "/sessions/%s/gates/g1" % sid, {"decision": "approve", "approved_cap_h": 1.25}, t)
        self.assertEqual(st, 200, r)
        self.assertEqual(self.call(2, "GET", "/gates/g1?sid=" + sid)[1]["state"], "approved")
        # another person cannot touch the session
        other = self.person_token(person_id="p-2")
        self.assertEqual(self.call(0, "POST", "/revoke", {"sid": sid}, other)[0], 404)
        self.assertEqual(self.call(0, "POST", "/revoke", {"sid": sid}, t)[1], {"revoked": True})
        self.assertEqual(self.call(2, "POST", "/introspect", {"token": tok, "audience": "mcp-sim", "peer": "127.0.0.1"})[1],
                         {"active": False})
        self.assertEqual(self.call(2, "GET", "/events/%s" % sid)[0], 200)

    def test_gate_decisions_need_a_pending_undecided_gate(self):
        # research Phase 4e (design 2.2): 404 for a gate that was never pending, 409 once decided
        sid, tok, _ = self.claimed()
        t = self.person_token()
        dec = lambda gid, d="deny": self.call(0, "POST", "/sessions/%s/gates/%s" % (sid, gid), {"decision": d, "note": "n"}, t)
        self.assertEqual(dec("g9"), (404, {"error": "no such gate"}))
        self.db._add(sid, "mcp-sim", "gate_pending", {"gid": "g2", "estimate_h": 1})
        self.assertEqual(dec("g2")[0], 200)
        self.assertEqual(dec("g2"), (409, {"error": "this gate is already decided"}))
        st, r = self.call(0, "POST", "/sessions/%s/gates/g2" % sid, {"decision": "approve", "approved_cap_h": 1}, t)
        self.assertEqual(st, 409)
        self.assertEqual(sum(1 for e in self.db.events_ if e["event"] == "gate_decided"), 1)

    def test_proposal_ids(self):
        sid, tok, _ = self.claimed()
        t = self.person_token()
        dec = lambda pid, d="approve": self.call(0, "POST", "/sessions/%s/proposals/%s" % (sid, pid), {"decision": d}, t)
        self.assertEqual(dec("p1")[0], 404)                                    # session_minted is no proposal
        digest = "ab12cd34" * 8
        eid = self.db._add(sid, "agent", "proposal", {"tool": "propose.parameter_set", "result_sha256": digest})
        self.assertEqual(dec("p%d" % (eid + 50))[0], 404)
        self.assertEqual(dec("x1"), (404, {"error": "no such proposal"}))
        self.assertEqual(dec(digest[:16])[0], 200)                             # the CLI's 16-hex prefix
        d = [e for e in self.db.events_ if e["event"] == "proposal_decided"][-1]["payload"]
        self.assertEqual(d["pid"], "p%d" % eid)                                 # recorded as the event's id
        self.assertEqual(dec("p%d" % eid, "deny"), (409, {"error": "this proposal is already decided"}))
        self.assertEqual(dec(digest[:40])[0], 409)
        # a decision recorded before under the digest prefix also counts
        eid2 = self.db._add(sid, "agent", "proposal", {"result_sha256": "ef" * 32})
        self.db._add(sid, "research-session", "proposal_decided", {"pid": ("ef" * 32)[:20], "decision": "deny"})
        self.assertEqual(dec("p%d" % eid2)[0], 409)
        # a prefix naming two proposals is refused with their ids
        self.db._add(sid, "agent", "proposal", {"result_sha256": "77" * 32})
        self.db._add(sid, "agent", "proposal", {"result_sha256": "77" * 32})
        st, r = dec("77" * 8)
        self.assertEqual(st, 409)
        self.assertIn("names 2 proposals", r["error"])
        # a server's event called proposal is not the agent's
        eid3 = self.db._add(sid, "mcp-sim", "proposal", {"result_sha256": "99" * 32})
        self.assertEqual(dec("p%d" % eid3)[0], 404)

    def test_old_watch_ids(self):
        # before p<event_id>, the watch printed 12 hex of the digest and decide() recorded what was typed
        sid, tok, _ = self.claimed()
        t = self.person_token()
        dec = lambda pid, d="approve": self.call(0, "POST", "/sessions/%s/proposals/%s" % (sid, pid), {"decision": d}, t)
        eid = self.db._add(sid, "agent", "proposal", {"result_sha256": "c3" * 32})
        self.db._add(sid, "research-session", "proposal_decided", {"pid": ("c3" * 32)[:12], "decision": "deny"})
        self.assertEqual(dec("p%d" % eid), (409, {"error": "this proposal is already decided"}))
        self.assertEqual(dec(("c3" * 32)[:12]), (409, {"error": "this proposal is already decided"}))
        eid2 = self.db._add(sid, "agent", "proposal", {"result_sha256": "d4" * 32})
        self.assertEqual(dec(("d4" * 32)[:12])[0], 200)                       # the old 12-hex form still resolves
        d = [e for e in self.db.events_ if e["event"] == "proposal_decided"][-1]["payload"]
        self.assertEqual(d["pid"], "p%d" % eid2)
        self.assertEqual(sum(1 for e in self.db.events_ if e["event"] == "proposal_decided"), 2)

    def test_overlapping_decisions_record_one(self):
        # two requests at the same time: the check and the append are one step, so one 200 and one 409
        sid, tok, _ = self.claimed()
        t = self.person_token()
        self.db._add(sid, "mcp-sim", "gate_pending", {"gid": "g5", "estimate_h": 1})
        pe = self.db._add(sid, "agent", "proposal", {"result_sha256": "e5" * 32})
        orig = self.svc.all_events

        def slow(sid_):
            out = orig(sid_)
            time.sleep(0.3)
            return out
        self.svc.all_events = slow
        for path, bodies, ev in (("/sessions/%s/gates/g5" % sid,
                                  ({"decision": "deny"}, {"decision": "approve", "approved_cap_h": 100}), "gate_decided"),
                                 ("/sessions/%s/proposals/p%d" % (sid, pe),
                                  ({"decision": "deny"}, {"decision": "approve"}), "proposal_decided")):
            res = []
            th = [threading.Thread(target=lambda b=b: res.append(self.call(0, "POST", path, b, t)[0])) for b in bodies]
            for x in th:
                x.start()
            for x in th:
                x.join()
            self.assertEqual(sorted(res), [200, 409], path)
            self.assertEqual(sum(1 for e in self.db.events_ if e["event"] == ev), 1, ev)

    def test_lookups_read_past_the_first_page(self):
        sid, tok, _ = self.claimed()
        for i in range(1500):
            self.db._add(sid, "agent", "tool_call", {"call": i})
        self.db._add(sid, "mcp-sim", "gate_pending", {"gid": "late", "estimate_h": 1})
        eid = self.db._add(sid, "agent", "proposal", {"result_sha256": "cd" * 32})
        self.assertEqual(self.call(2, "GET", "/gates/late?sid=" + sid)[1]["state"], "pending")
        t = self.person_token()
        self.assertEqual(self.call(0, "POST", "/sessions/%s/gates/late" % sid,
                                   {"decision": "approve", "approved_cap_h": 2}, t)[0], 200)
        self.assertEqual(self.call(2, "GET", "/gates/late?sid=" + sid)[1]["state"], "approved")
        self.assertEqual(self.call(0, "POST", "/sessions/%s/proposals/p%d" % (sid, eid), {"decision": "deny"}, t)[0], 200)
        self.assertGreater(len(self.svc.all_events(sid)), 1000)

    def test_info_names_the_supervisor(self):
        sid, tok, _ = self.claimed()
        r = self.call(2, "GET", "/sessions/%s" % sid)[1]
        self.assertEqual((r["sup_username"], r["sup_role"]), ("bio", "bio_scientist"))
        self.assertIsInstance(r["created_at"], int)

    def test_mint_reexecutes_and_sessions_of(self):
        st, a = self.mint()
        b = dict(self.MINT, reexecutes=a["sid"])
        st, r = self.call(0, "POST", "/mint", b, self.person_token())
        self.assertEqual(st, 201, r)
        self.assertEqual(self.db.rows[r["sid"]]["reexecutes"], a["sid"])
        self.db.revoked.update((a["sid"], r["sid"]))
        # another person's session, or no session at all, is not one to re-execute
        self.assertEqual(self.call(0, "POST", "/mint", b, self.person_token(person_id="p-2"))[0], 400)
        self.assertEqual(self.call(0, "POST", "/mint", dict(self.MINT, reexecutes="Z" * 22), self.person_token())[0], 400)
        st, out = self.svc.sessions_of("p-1", None, 1)
        self.assertEqual(st, 200)
        self.assertEqual([x["sid"] for x in out["sessions"]], [r["sid"]])
        st, out2 = self.svc.sessions_of("p-1", out["next_before"], 10)
        self.assertEqual(([x["sid"] for x in out2["sessions"]], out2["next_before"]), ([a["sid"]], None))
        for bad in (("", None, 5), ("p-1", 0, 5), ("p-1", None, 0), ("p-1", None, 201), ("p-1", True, 5)):
            self.assertEqual(self.svc.sessions_of(*bad)[0], 400, bad)

    def test_healthz_and_anchor(self):
        st, r = self.call(0, "GET", "/healthz")
        self.assertEqual((st, r["kid"], r["anchor"]), (200, self.keys.kid, None))
        self.mint()
        self.assertIsNone(self.svc.last_anchor)   # open_session is the DB's; decisions and traces move it
        sid, tok, _ = self.claimed()
        self.call(1, "POST", "/trace", {"sid": sid, "token": tok, "event": "stop", "payload": {}})
        self.assertIsNotNone(self.call(0, "GET", "/healthz")[1]["anchor"])

    def test_secrets_never_logged(self):
        sid, tok, r = self.claimed()
        self.call(2, "POST", "/introspect", {"token": tok, "audience": "mcp-sim", "peer": "1.2.3.4"})
        self.call(1, "POST", "/trace", {"sid": sid, "token": tok, "event": "stop", "payload": {}})
        self.call(1, "POST", "/trace", {"sid": sid, "token": tok + "x", "event": "stop", "payload": {}})
        out = self.log.getvalue()
        for secret in (tok, r["claim"], self.person_token(), "ab" * 32):
            self.assertNotIn(secret, out)
        self.assertNotIn(tok.split(".")[4], out)
        src = open(os.path.join(REPO, "apps/research-agents/session.py")).read()
        self.assertNotIn("print(", src)


class KeysTest(unittest.TestCase):
    def test_kid_and_short_key(self):
        s = load("research_session2", "apps/research-agents/session.py")
        with self.assertRaises(ValueError):
            s.Keys("ab" * 8)
        k = s.Keys("00" * 32)
        self.assertEqual(len(k.kid), 8)
        tok = k.token("A" * 22, 1900000000)
        self.assertLessEqual(len(tok), 120)
        self.assertEqual(k.parse(tok)[0], ("A" * 22, 1900000000))


if __name__ == "__main__":
    unittest.main()
