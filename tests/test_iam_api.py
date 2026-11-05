#!/usr/bin/env python3
"""tests/test_iam_api.py — iam-api's MQTT Explorer credential endpoint (IAM 3.5), offline.

The real medcea_iam library and the compiled route table and mqtt.json, tokens signed with
a throwaway RSA key (as tests/test_medcea_iam.py), the real handler on a loopback port;
the database is a stub that records every statement.
  - /healthz answers without a token; 401 without a token, 403 for an operator (route),
    401 for a token of another client (azp)
  - 415 without JSON, 403 from another Origin, 409 while IAM_MQTT_PERSON is false,
    503 without or with a damaged mqtt.json, 503 when not logged in as iam_svc
  - an engineer gets 200: set_actor -> the re-issue guard -> retire beyond max_active ->
    INSERT credential -> INSERT acl rows (root-prefixed, the table's CHECK) ->
    append_history('mqtt_credential_issued') -> commit; the password verifies with
    infra/mqtt-passwd.py --verify (stdin) and appears in no log line, the username is
    explorer-<user>-<6 hex>, Cache-Control no-store
  - an account changed after the token was issued gets 403 and nothing is committed

Run from the repository root:  python3 tests/test_iam_api.py
Needs PyJWT and cryptography on the host; skipped without them.
"""
import datetime
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import model, mqtt, routes  # noqa: E402

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_JWT = True
except ImportError:
    HAVE_JWT = False

ISSUER = "https://keycloak.test/realms/medcea"
DOMAIN = "mqtt-explorer.test"
SUB = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
TOPIC_CHECK = re.compile(r"^[a-z][a-z0-9-]{1,30}/(\+|[A-Za-z0-9_-]+)/(\+|[A-Za-z0-9_-]+)/(sense|control|control_setpoint)/#$")
TMP = tempfile.mkdtemp()
POLICY_DOMAIN = "policy.test"
# read by policy_api (the Policy UI's port, IAM 4.3) when iam-api.py imports it
os.environ.update(POLICY_DOMAIN=POLICY_DOMAIN, ACCESS_DOMAIN="access.test",
                  MEDCEA_COMPILER_DIR=os.path.join(REPO, "apps", "iam"),
                  POLICY_HTML=os.path.join(REPO, "apps", "iam", "html", "policy.html"))


def write_settings(person, jwt_mode=True):
    with open(os.path.join(TMP, "settings.json"), "w") as f:
        json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": True,
                   "switches": {"IAM_MQTT_PERSON": person, "IAM_POSTGREST_JWT": jwt_mode,
                                "written_at": "2026-10-31T00:00:00Z"}}, f)
    # the library re-reads a file when its mtime changes
    t = time.time() + (1 if person else 2)
    os.utime(os.path.join(TMP, "settings.json"), (t, t))


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.last = None

    def execute(self, sql, params=None):
        self.db.log.append((" ".join(sql.split()), params))
        self.last = sql

    def fetchone(self):
        if "_changed_since" in self.last:
            return (self.db.changed,)
        if "RETURNING expires_at" in self.last:
            return (datetime.datetime(2026, 10, 31, 20, 0, tzinfo=datetime.timezone.utc),)
        return (1,)


class FakeDB:
    def __init__(self):
        self.log, self.changed, self.committed, self.rolled_back = [], False, False, False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


@unittest.skipUnless(HAVE_JWT, "PyJWT/cryptography not installed on this host")
class IamApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = model.load_defaults()
        with open(os.path.join(TMP, "routes.json"), "w") as f:
            f.write(routes.dumps(routes.compile(p)))
        cls.doc = mqtt.compile(p)
        cls.mqtt_file = os.path.join(TMP, "mqtt.json")
        with open(cls.mqtt_file, "w") as f:
            f.write(mqtt.dumps(cls.doc))
        write_settings(True)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        jwk.update(kid="k1", alg="RS256", use="sig")
        with open(os.path.join(TMP, "jwks.json"), "w") as f:
            json.dump({"keys": [jwk]}, f)
        os.environ.update(MEDCEA_IAM_ROUTES=os.path.join(TMP, "routes.json"),
                          MEDCEA_IAM_SETTINGS=os.path.join(TMP, "settings.json"),
                          MEDCEA_IAM_JWKS=os.path.join(TMP, "jwks.json"),
                          MEDCEA_IAM_LIB=os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py"),
                          MEDCEA_IAM_MQTT=cls.mqtt_file, MQTT_PASSWD_PY=os.path.join(REPO, "infra", "mqtt-passwd.py"),
                          MQTTX_DOMAIN=DOMAIN, PG_USER="iam_svc", PROJECT_NAME="medcea")
        spec = importlib.util.spec_from_file_location("iam_api", os.path.join(REPO, "apps", "iam", "iam-api.py"))
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)
        cls.logs = io.StringIO()
        cls.api.log = lambda *a: cls.logs.write(" ".join(map(str, a)) + "\n")
        from http.server import ThreadingHTTPServer
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.MqttCredential)
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.db = FakeDB()
        self.api.db = lambda: self.db
        write_settings(True)
        with open(self.mqtt_file, "w") as f:
            f.write(mqtt.dumps(self.doc))

    def token(self, roles, azp="mqtt-explorer", iat=None):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": ["medcea-api"], "sub": SUB, "typ": "Bearer", "azp": azp,
                  "iat": iat or now, "exp": now + 300, "preferred_username": "eve.e", "person_id": "p-eve",
                  "groups": roles}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def post(self, token=None, ctype="application/json", origin="https://" + DOMAIN, path="/_mqtt-credential"):
        h = {"Content-Type": ctype, "Origin": origin}
        if token:
            h["X-Forwarded-Access-Token"] = token
        req = urllib.request.Request(self.url + path, data=b"{}", headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read()), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read() or b"{}"), dict(e.headers)

    def test_healthz_public(self):
        with urllib.request.urlopen(self.url + "/healthz", timeout=10) as r:
            body = json.loads(r.read())
        self.assertEqual(body["service"], "iam-mqttx")
        self.assertIs(body["mode"], True)
        self.assertEqual(body["mqtt_digest"], self.doc["digest"])

    def test_refusals_before_the_database(self):
        eng = self.token(["engineer"])
        self.assertEqual(self.post()[0], 401)
        self.assertEqual(self.post(self.token(["operator"]))[0], 403)
        self.assertEqual(self.post(self.token(["engineer"], azp="portal"))[0], 401)
        self.assertEqual(self.post(eng, ctype="application/x-www-form-urlencoded")[0], 415)
        self.assertEqual(self.post(eng, origin="https://evil.invalid")[0], 403)
        write_settings(False)
        self.assertEqual(self.post(eng)[0], 409)
        write_settings(True)
        os.remove(self.mqtt_file)
        self.assertEqual(self.post(eng)[0], 503)
        with open(self.mqtt_file, "w") as f:
            f.write(mqtt.dumps(dict(self.doc, ttl_hours=99)))   # body changed, digest not
        self.assertEqual(self.post(eng)[0], 503)
        self.assertEqual(self.db.log, [])

    def test_not_iam_svc(self):
        self.api.PG["user"] = "postgres"
        try:
            self.assertEqual(self.post(self.token(["engineer"]))[0], 503)
        finally:
            self.api.PG["user"] = "iam_svc"

    def test_engineer_gets_a_credential(self):
        self.logs.truncate(0)
        status, body, headers = self.post(self.token(["engineer"]))
        self.assertEqual(status, 200, body)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertRegex(body["username"], r"^explorer-eve\.e-[0-9a-f]{6}$")
        rows = self.doc["roles"]["engineer"]
        self.assertEqual(sorted(body["read"]), sorted("medcea/" + r["topic"] for r in rows if r["access"] == "read"))
        self.assertEqual(body["write"], ["medcea/+/+/control/#"])
        sql = [s for s, _ in self.db.log]
        order = [next(i for i, s in enumerate(sql) if k in s) for k in
                 ("medcea_auth.set_actor", "iam._changed_since", "UPDATE medcea.mqtt_service_credential",
                  "INSERT INTO medcea.mqtt_service_credential", "INSERT INTO medcea.mqtt_service_acl",
                  "iam_policy.append_history")]
        self.assertEqual(order, sorted(order))
        self.assertTrue(self.db.committed)
        acl = [p for s, p in self.db.log if s.startswith("INSERT INTO medcea.mqtt_service_acl")]
        self.assertEqual(len(acl), len(rows))
        for _, access, topic in acl:
            self.assertRegex(topic, TOPIC_CHECK)
        hist = next(p for s, p in self.db.log if "append_history" in s)
        self.assertEqual(hist[0], "mqtt_credential_issued")
        self.assertEqual(json.loads(hist[1])["person_sub"], SUB)
        cred = next(p for s, p in self.db.log if s.startswith("INSERT INTO medcea.mqtt_service_credential"))
        self.assertEqual(cred[0], body["username"])
        self.assertEqual(cred[3], self.doc["ttl_hours"])
        retire = next(p for s, p in self.db.log if s.startswith("UPDATE medcea.mqtt_service_credential"))
        self.assertEqual(retire[2], self.doc["max_active"] - 1)
        v = subprocess.run([sys.executable, os.path.join(REPO, "infra", "mqtt-passwd.py"), "--verify", cred[1]],
                           input=body["password"], text=True)
        self.assertEqual(v.returncode, 0)
        self.assertNotIn(body["password"], self.logs.getvalue())
        self.assertNotIn(body["password"], json.dumps(self.db.log[-1]))
        self.assertIn(body["username"], self.logs.getvalue())

    def test_changed_since_sign_in(self):
        self.db.changed = True
        status, body, _ = self.post(self.token(["engineer"]))
        self.assertEqual(status, 403)
        self.assertIn("changed since you signed in", body["error"])
        self.assertFalse(self.db.committed)
        self.assertTrue(self.db.rolled_back)
        self.assertFalse([s for s, _ in self.db.log if s.startswith("INSERT")])
        # iam._changed_since (IAM 4.3): the sub, the person and the token's iat
        call = [p for s, p in self.db.log if "iam._changed_since" in s][0]
        self.assertEqual(call[:2], (SUB, "p-eve"))
        self.assertIsInstance(call[2], int)

    def test_digest_is_the_compilers(self):
        body = {k: v for k, v in self.doc.items() if k != "digest"}
        self.assertEqual(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                         self.doc["digest"])



# ── the Policy UI's port (IAM 4.3, 4.4) ─────────────────────────────────────────────────
class DbError(Exception):
    """pg8000's DatabaseError shape: args[0] is {C: SQLSTATE, M: message}."""

    def __init__(self, code, msg):
        super().__init__({"C": code, "M": msg})


class PolicyCursor:
    """Answers the Policy UI's reads and the author functions from a small model of
    iam_policy: version 1 = defaults.yaml's rows (bootstrap, applied), more as drafted."""

    def __init__(self, db):
        self.db, self.result, self.description = db, [], []

    def execute(self, sql, params=None):
        q = " ".join(sql.split())
        self.db.log.append((q, params))
        d = self.db
        if q in d.fail:
            raise DbError(*d.fail[q])
        for fn, err in d.fail_fn.items():
            if ".%s(" % fn in q:
                raise DbError(*err)
        if "_changed_since" in q:
            cols, rows = ["c"], [(d.changed,)]
        elif "pg_advisory_xact_lock" in q or "medcea_auth.set_actor" in q:
            cols, rows = ["x"], [("",)]
        elif "WHERE status = 'applied'" in q:
            cols, rows = ["version"], [(1,)]
        elif q.startswith("SELECT entries_digest, status FROM iam_policy.version"):
            v = d.versions.get(params[0])
            cols, rows = ["entries_digest", "status"], ([(v["entries_digest"], v["status"])] if v else [])
        elif q.startswith("SELECT version, kind, status, groups, roles, entries_digest, skeleton_digest"):
            v = d.versions.get(params[0])
            cols = ["version", "kind", "status", "groups", "roles", "entries_digest", "skeleton_digest"]
            rows = [tuple(v.get(c) for c in cols)] if v else []
        elif "FROM iam_policy.entry" in q:
            cols, rows = ["role", "group_code", "level", "constraint_name"], \
                [(e["role"], e["group_code"], e["level"], e["constraint_name"]) for e in d.entries[params[0]]]
        elif "FROM iam_policy.waiver" in q:
            cols = ["id", "invariant", "subject", "group_code", "target", "levels", "review_by", "rationale", "controls", "objects"]
            rows = [(w["id"], w["invariant"], w["subject"], w["group"], w["target"], w["levels"],
                     datetime.date.fromisoformat(w["review_by"]), w["rationale"], w["controls"], w.get("objects") or [])
                    for w in d.ew["waivers"]]
        elif "FROM iam_policy.version v LEFT JOIN iam_policy.skeleton s" in q:
            sel = q.split("SELECT ", 1)[1].split(" FROM", 1)[0].split(", ")
            cols = [c.split(" AS ")[-1].split(".")[-1] for c in sel]
            rows = []
            for n in sorted(d.versions, reverse=True):
                v = dict.fromkeys(cols)
                v.update({k: x for k, x in d.versions[n].items() if k in cols})
                rows.append(tuple(v[c] for c in cols))
        elif "iam_policy.entries_digest(" in q:
            cols, rows = ["d"], [(d.digest(params[0]),)]
        elif "iam_policy.new_draft(" in q:
            n = max(d.versions) + 1
            d.versions[n] = dict(version=n, kind="change", status="draft", reason=params[1], based_on=1,
                                 groups=d.versions[1]["groups"], roles=d.versions[1]["roles"])
            d.entries[n] = [dict(e) for e in d.entries[1]]
            cols, rows = ["v"], [(n,)]
        elif "iam_policy.save_entry(" in q:
            v, role, group, levels = params[0], params[1], params[2], json.loads(params[3])
            if d.versions[v]["status"] != "draft":
                raise DbError("22023", "version %d is not a draft" % v)
            if group not in d.versions[v]["groups"] or role not in d.versions[v]["roles"]:
                raise DbError("22023", "no role %s or group %s in the accepted skeleton" % (role, group))
            d.entries[v] = [e for e in d.entries[v] if (e["role"], e["group_code"]) != (role, group)] + \
                [{"role": role, "group_code": group, "level": l, "constraint_name": c} for l, c in levels.items()]
            if d.corrupt_save:
                d.entries[v].append({"role": "qa", "group_code": "zones", "level": "D", "constraint_name": None})
            d.versions[v]["checker_verdict"] = json.loads(params[5]).get("ok")
            cols, rows = ["x"], [("",)]
        elif "iam_policy.submit(" in q:
            v = d.versions[params[0]]
            v.update(status="submitted", entries_digest=d.digest(params[0]), skeleton_digest=d.skel_digest)
            cols, rows = ["d"], [(d.submit_digest or v["entries_digest"],)]
        elif "iam_policy.withdraw(" in q:
            d.versions[params[0]]["status"] = "withdrawn"
            cols, rows = ["x"], [("",)]
        elif "iam_policy.why_not(" in q:
            cols, rows = ["may_approve", "why_not_code", "needs_token_path"], [(True, None, True)]
        elif q.startswith("SELECT DISTINCT ON (h.version) h.version, h.event"):
            cols = ["version", "event", "outcome"]
            rows = [(n, e, o) for n, (e, o) in sorted(d.apply_events.items())]
        elif "FROM iam_policy.history h WHERE h.version = %s AND h.event IN" in q:
            cols, rows = ["name", "person"], [("admin", "p-admin")]
        elif "FROM iam_policy.skeleton s WHERE s.accepted_at" in q:
            cols, rows = ["digest"], [(d.skel_digest,)]
        elif "FROM iam_policy.version_diff" in q:
            cols, rows = ["diff", "diff_digest"], ([d.vdiff[params[0]]] if params[0] in d.vdiff else [])
        elif "break_glass_seen" in q:
            cols, rows = ["event_id", "at", "components"], d.bg_open
        elif "current_setting('medcea.iam_db_roles'" in q:
            cols, rows = ["s"], [(d.db_roles,)]
        elif "verify_chain" in q:
            cols, rows = ["ok", "events", "first_bad_event", "detail", "head"], [(True, 50, None, None, "50:abc")]
        elif "audit_versions" in q:
            cols, rows = ["version", "finding", "detail"], []
        elif "FROM iam_policy.history" in q:
            cols, rows = ["event_id", "at", "event", "version", "actor_name", "reason", "payload"], \
                [(48, datetime.datetime(2026, 11, 3, 10, 0, tzinfo=datetime.timezone.utc), "bootstrap_applied", 1,
                  "system:apply", "version 1", '{"version": 1}')]
        else:
            cols, rows = ["x"], [(1,)]
        self.description = [(c,) for c in cols]
        self.result = rows

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return list(self.result)


class PolicyDB(FakeDB):
    def __init__(self, ew):
        super().__init__()
        from compiler import source
        self.source = source
        skel = source.skeleton(source.factory())
        self.skel_digest = source.skeleton_digest(skel)
        self.ew, self.db_roles, self.claimant, self.confirmed_at = ew, "true", "p-someone-else", None
        self.versions = {1: dict(version=1, kind="bootstrap", status="applied", reason="the factory policy",
                                 applied_at=datetime.datetime(2026, 11, 3, 9, 59, tzinfo=datetime.timezone.utc),
                                 claimed_by_person=self.claimant, confirmed_at=None, entries_digest="d1",
                                 groups=sorted(skel["resource_groups"]), roles=sorted(skel["roles"]),
                                 skeleton_digest=self.skel_digest)}
        self.entries = {1: [dict(e) for e in ew["entries"]]}
        self.fail, self.fail_fn, self.vdiff, self.bg_open = {}, {}, {}, []
        self.corrupt_save, self.submit_digest = False, None
        self.apply_events = {1: ("bootstrap_applied", None)}   # {version: (latest apply event, outcome)}

    def digest(self, n):
        v = self.versions[n]
        return self.source.entries_digest(v["kind"], v["groups"], v["roles"], self.entries[n], self.ew["waivers"])

    def cursor(self):
        self.versions[1]["confirmed_at"] = self.confirmed_at
        self.versions[1]["claimed_by_person"] = self.claimant
        return PolicyCursor(self)


class FakeConfigApi:
    """config-api's /rpc/<fn>: records the call, answers (status, body) as told."""

    def __init__(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        outer = self
        self.calls, self.answer = [], (204, b"")

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.calls.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(n) or b"{}")))
                status, body = outer.answer
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]


@unittest.skipUnless(HAVE_JWT, "PyJWT/cryptography not installed on this host")
class PolicyAdminTest(IamApiTest):
    """iam-api :8083 (policy_api.PolicyAdmin): the read routes, confirm/dispute forwarded."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from compiler import source
        cls.ew = source.entries_and_waivers(source.factory())
        cls.pa = cls.api.policy_api
        cls.pa.medcea_iam, cls.pa.log = cls.api._medcea_iam, cls.api.log
        cls.cfg = FakeConfigApi()
        cls.pa.CONFIG_API_URL = cls.cfg.url
        from http.server import ThreadingHTTPServer
        cls.psrv = ThreadingHTTPServer(("127.0.0.1", 0), cls.pa.PolicyAdmin)
        cls.psrv.daemon_threads = True
        threading.Thread(target=cls.psrv.serve_forever, daemon=True).start()
        cls.purl = "http://127.0.0.1:%d" % cls.psrv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.psrv.shutdown()
        cls.cfg.srv.shutdown()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.pdb = PolicyDB(self.ew)
        self.pa.db = lambda: self.pdb
        self.cfg.calls.clear()
        self.cfg.answer = (204, b"")

    def ptoken(self, roles, person="p-qa", azp="policy"):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": ["medcea-api"], "sub": SUB, "typ": "Bearer", "azp": azp, "iat": now,
                  "exp": now + 300, "preferred_username": "quinn.q", "groups": roles}
        if person:
            claims["person_id"] = person
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def req(self, path, token=None, body=None, origin="https://" + POLICY_DOMAIN, ctype="application/json", method=None):
        h = {"Accept": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h.update({"Content-Type": ctype, "Origin": origin})
        r = urllib.request.Request(self.purl + path, data=data, headers=h, method=method or ("POST" if body is not None else "GET"))
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if resp.headers.get("Content-Type", "").startswith("application/json") else raw), dict(resp.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read() or b"{}"), dict(e.headers)

    def test_healthz_public(self):
        status, body, _ = self.req("/healthz")
        self.assertEqual(status, 200)
        self.assertIs(body["policy_port"], True)
        self.assertIs(body["enforce_always"], True)
        from compiler import source
        self.assertEqual(body["skeleton_digest"], source.skeleton_digest(source.skeleton(source.factory())))

    def test_refusals(self):
        self.assertEqual(self.req("/api/me")[0], 401)
        self.assertEqual(self.req("/api/me", self.ptoken(["engineer"]))[0], 403)            # route
        self.assertEqual(self.req("/api/me", self.ptoken(["qa"], azp="portal"))[0], 401)     # client
        status, body, _ = self.req("/api/me", self.ptoken(["qa"], person=None))
        self.assertEqual(status, 403)
        self.assertIn("person_id", body["error"])
        status, body, _ = self.req("/api/policy/1/diff", self.ptoken(["qa"]))               # 4.4: bootstrap
        self.assertEqual(status, 409)
        self.assertIn("only a change or skeleton version has an approval diff", body["error"])

    def test_me_per_role(self):
        tabs = ("matrix", "changes", "approval", "whocan", "identities", "breakglass", "history", "confirm")
        acts = ("draft", "edit", "submit", "withdraw", "approve", "return")
        self.assertEqual(self.req("/api/me", self.ptoken(["production_manager"]))[0], 403)   # no route on iam
        for role, can, act, inc in (
                ("qa", {"matrix", "changes", "approval", "whocan", "identities", "breakglass", "history", "confirm"},
                 {"approve", "return"}, ["auditor"]),
                ("admin", {"matrix", "changes", "whocan", "identities", "breakglass"},
                 {"draft", "edit", "submit", "withdraw"}, []),
                ("auditor", {"matrix", "changes", "whocan", "identities", "breakglass", "history"}, set(), []),
                ("qp", {"history"}, set(), [])):
            status, body, h = self.req("/api/me", self.ptoken([role]))
            self.assertEqual(status, 200, (role, body))
            self.assertEqual(body["can"], {t: t in can for t in tabs}, role)
            self.assertEqual(body["acts"], {a: a in act for a in acts}, role)
            self.assertEqual(body["includes"], inc, role)
            self.assertEqual(body["role"], role)
            self.assertEqual(h.get("Cache-Control"), "no-store")
        self.assertEqual(body["attest"], "I did not run apply.sh for this version.")
        self.assertEqual(body["skeleton_attest"], "I did not run apply.sh --propose-skeleton for this version.")
        self.assertEqual(set(self.pa.ACTS), set(acts))

    def test_matrix_of_version_1(self):
        status, body, _ = self.req("/api/policy/applied", self.ptoken(["qa"]))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["version"], 1)
        from compiler import model
        p = model.load_defaults()
        self.assertEqual(set(body["cells"]), {g for g in p.groups if p.matrix.get(g)})
        self.assertEqual(body["cells"]["iam_policy"]["qa"]["constraints"], {"A": "not_own_author"})
        self.assertEqual(body["checker"]["errors"], [])
        self.assertTrue(all(r["help"] for r in body["roles"]), "every role has help")
        self.assertTrue(all(g["help"] for g in body["groups"]), "every group has help")
        self.assertTrue(all(l["help"] or l["summary"] for l in body["levels"]))
        self.assertEqual(body["dropped"], 0)

    def test_explain_and_versions(self):
        status, body, _ = self.req("/api/policy/1/explain?role=qa&group=iam_policy", self.ptoken(["auditor"]))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["levels"], ["A", "R"])
        self.assertTrue(body["changed"]["same"])
        self.assertEqual(self.req("/api/policy/1/explain?role=nobody&group=iam_policy", self.ptoken(["qa"]))[0], 404)
        status, body, _ = self.req("/api/policy", self.ptoken(["qa"]))
        self.assertEqual(status, 200)
        self.assertTrue(body["versions"][0]["needs_confirmation"])
        status, body, _ = self.req("/api/policy/history?version=1", self.ptoken(["qp"]))
        self.assertEqual((status, body["events"][0]["event"]), (200, "bootstrap_applied"))
        status, body, _ = self.req("/api/policy/chain", self.ptoken(["qa"]))
        self.assertEqual((status, body["ok"]), (200, True))

    def test_confirm_forwarded_with_the_callers_token(self):
        tok = self.ptoken(["qa"])
        status, body, _ = self.req("/api/policy/1/confirm", tok, {"note": "read it", "attest": "I did not run apply.sh for this version."})
        self.assertEqual(status, 200, body)
        path, auth, args = self.cfg.calls[-1]
        self.assertEqual(path, "/rpc/confirm_policy")
        self.assertEqual(auth, "Bearer " + tok)
        self.assertEqual(args, {"p_version": 1, "p_note": "read it", "p_attest": "I did not run apply.sh for this version."})
        self.assertNotIn(tok, self.logs.getvalue())
        self.req("/api/policy/1/dispute", tok, {"note": "not what we meant"})
        self.assertEqual(self.cfg.calls[-1][0], "/rpc/dispute_policy")
        self.assertEqual(self.cfg.calls[-1][2], {"p_version": 1, "p_note": "not what we meant"})

    def test_confirm_refusals(self):
        tok = self.ptoken(["qa"])
        self.assertEqual(self.req("/api/policy/1/confirm", tok, {"note": "x"}, ctype="text/plain")[0], 415)
        self.assertEqual(self.req("/api/policy/1/confirm", tok, {"note": "x"}, origin="https://evil.test")[0], 403)
        self.assertEqual(self.req("/api/policy/1/confirm", tok, {"note": " "})[0], 400)
        self.assertEqual(self.req("/api/policy/1/confirm", self.ptoken(["admin"]), {"note": "x"})[0], 403)   # A: qa
        for answer, want in (((403, b'{"code":"42501","message":"apply.sh recorded you as running version 1: another qa person confirms it"}'), 403),
                             ((400, b'{"code":"22023","message":"version 1 is already confirmed "}'), 409),
                             ((401, b'{"code":"PGRST301","message":"JWT expired"}'), 401),
                             ((401, b'{"code":"42501","message":"permission denied for function confirm_policy"}'), 503)):
            self.cfg.answer = answer
            status, body, _ = self.req("/api/policy/1/confirm", tok, {"note": "x", "attest": "y"})
            self.assertEqual(status, want, (answer, body))
        n = len(self.cfg.calls)
        self.pdb_roles_false()
        status, body, _ = self.req("/api/policy/1/confirm", tok, {"note": "x"})
        self.assertEqual(status, 503)
        self.assertEqual(len(self.cfg.calls), n, "nothing forwarded under IAM_DB_ROLES=false")
        write_settings(True, jwt_mode=False)
        self.pdb.db_roles = "true"
        self.assertEqual(self.req("/api/policy/1/confirm", tok, {"note": "x"})[0], 503)

    def pdb_roles_false(self):
        self.pdb.db_roles = "false"

    def test_changed_since(self):
        self.pdb.changed = True
        status, body, _ = self.req("/api/policy", self.ptoken(["qa"]))
        self.assertEqual(status, 403)
        self.assertIn("changed since you signed in", body["error"])
        call = [p for s, p in self.pdb.log if "iam._changed_since" in s][0]
        self.assertEqual(call[:2], (SUB, "p-qa"))

    def test_page_served(self):
        status, body, h = self.req("/", self.ptoken(["qa"]))
        self.assertEqual(status, 200)
        self.assertIn(b"policy-logic:begin", body)
        self.assertTrue(h["Content-Type"].startswith("text/html"))


    # ── IAM 4.4: the write side, the diff, the forwarded approval ────────────────────────
    def put(self, path, token, body, **kw):
        return self.req(path, token, body, method="PUT", **kw)

    def sql(self, needle):
        """[(index, params)] of the logged statements containing needle."""
        return [(i, p) for i, (s, p) in enumerate(self.pdb.log) if needle in s]

    def first(self, needle):
        hits = self.sql(needle)
        self.assertTrue(hits, needle)
        return hits[0][0]

    def open_version(self, status="submitted", change=None, kind="change"):
        """Version 2 in the fake: version 1's rows with change(entries) applied."""
        d = self.pdb
        ents = [dict(e) for e in d.entries[1]]
        if change:
            ents = change(ents)
        d.entries[2] = ents
        d.versions[2] = dict(version=2, kind=kind, status=status, reason="test", based_on=1,
                             groups=d.versions[1]["groups"], roles=d.versions[1]["roles"],
                             skeleton_digest=d.skel_digest, created_by_person="p-host")
        d.versions[2]["entries_digest"] = d.digest(2) if status != "draft" else None
        return d.versions[2]

    @staticmethod
    def without_engineer_on(group):
        return lambda ents: [e for e in ents if not (e["role"] == "engineer" and e["group_code"] == group)]

    def engineer_group(self):
        return next(e["group_code"] for e in self.pdb.entries[1] if e["role"] == "engineer")

    def test_version_columns_and_author_events(self):
        with open(os.path.join(REPO, "apps", "database", "medcea_db_migrations.sql")) as f:
            mig = f.read()
        table = mig[mig.index("CREATE TABLE IF NOT EXISTS iam_policy.version ("):]
        table = table[:table.index(");")]
        cols = set(re.findall(r"^\s+([a-z_]+)\s", table, re.M)) | set(re.findall(r"\['version', '([a-z_]+)'", mig))
        self.assertEqual([c for c in self.pa.VERSION_COLS if c not in cols], [])
        body = mig[mig.index("FUNCTION iam_policy._authors("):]
        events = re.search(r"h\.event IN \(([^)]*)\)", body).group(1)
        self.assertEqual(tuple(re.findall(r"'([a-z_]+)'", events)), self.pa.AUTHOR_EVENTS)

    def test_draft(self):
        tok = self.ptoken(["admin"], person="p-admin")
        status, body, _ = self.req("/api/policy/draft", tok, {"from": "applied", "reason": "test: a draft"})
        self.assertEqual(status, 201, body)
        self.assertEqual(body["version"], 2)
        self.assertIs(body["verdict"]["ok"], True)
        self.assertTrue(self.pdb.committed)
        # the lock first, then set_actor with the person_id (never the sub), then any row read
        lock, actor = self.first("pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'))"), \
            self.first("medcea_auth.set_actor")
        self.assertLess(lock, actor)
        self.assertLess(actor, self.first("FROM iam_policy"))
        self.assertEqual(self.pdb.log[actor][1], (SUB, "p-admin", "quinn.q", "admin"))
        # new_draft gets the factory cells and waivers (table shape)
        nd = self.sql("iam_policy.new_draft(")[0][1]
        self.assertEqual(nd[:2], ("applied", "test: a draft"))
        self.assertEqual(json.loads(nd[3]), self.ew["entries"])
        self.assertEqual([w["group_code"] for w in json.loads(nd[4])], [w["group"] for w in self.ew["waivers"]])
        # the verdict at creation: one save_entry of the first (group, role) in byte order, the whole cell
        saves = self.sql("iam_policy.save_entry(")
        self.assertEqual(len(saves), 1)
        g, r = min({(e["group_code"], e["role"]) for e in self.ew["entries"]}, key=lambda k: (k[0].encode(), k[1].encode()))
        args = saves[0][1]
        self.assertEqual(args[:3], (2, r, g))
        self.assertEqual(json.loads(args[3]), {e["level"]: e["constraint_name"] for e in self.ew["entries"]
                                               if (e["group_code"], e["role"]) == (g, r)})
        self.assertTrue(args[4].endswith("(checker run when the draft was created)"))
        verdict = json.loads(args[5])
        self.assertEqual((verdict["ok"], verdict["errors"]), (True, []))
        from compiler import source
        self.assertEqual(verdict["checker_digest"], source.compiler_digest())
        self.assertEqual(len(self.sql("iam_policy.entries_digest(")), 2, "the digest before and after the save")
        self.assertEqual(self.pdb.digest(2), self.pdb.source.entries_digest(
            "change", self.pdb.versions[2]["groups"], self.pdb.versions[2]["roles"], self.ew["entries"], self.ew["waivers"]))

    def test_draft_from_a_base_with_a_retired_group(self):
        # a narrowing skeleton retired a group the applied version still has rows for, and its
        # code sorts first: the verdict goes on the first cell the accepted skeleton still has
        self.pdb.entries[1].append({"role": "admin", "group_code": "aaa_retired", "level": "R", "constraint_name": None})
        tok = self.ptoken(["admin"], person="p-admin")
        status, body, _ = self.req("/api/policy/draft", tok, {"from": "applied", "reason": "test: a draft"})
        self.assertEqual(status, 201, body)
        self.assertTrue(self.pdb.committed)
        saves = self.sql("iam_policy.save_entry(")
        self.assertEqual(len(saves), 1)
        g, r = min({(e["group_code"], e["role"]) for e in self.ew["entries"]}, key=lambda k: (k[0].encode(), k[1].encode()))
        self.assertEqual(saves[0][1][:3], (2, r, g))

    def test_draft_with_no_live_cell_leaves_the_verdict_unset(self):
        d = self.pdb
        d.entries[1] = [{"role": "admin", "group_code": "aaa_retired", "level": "R", "constraint_name": None}]
        tok = self.ptoken(["admin"], person="p-admin")
        status, body, _ = self.req("/api/policy/draft", tok, {"from": "applied", "reason": "test: a draft"})
        self.assertEqual(status, 201, body)
        self.assertFalse(self.sql("iam_policy.save_entry("))
        self.assertTrue(d.committed)

    def test_draft_refusals(self):
        tok = self.ptoken(["admin"], person="p-admin")
        self.assertEqual(self.req("/api/policy/draft", tok, {"from": "latest", "reason": "x"})[0], 400)
        self.assertEqual(self.req("/api/policy/draft", tok, {"from": "applied", "reason": " "})[0], 400)
        self.assertEqual(self.req("/api/policy/draft", self.ptoken(["qa"]), {"from": "applied", "reason": "x"})[0], 403)
        self.pdb.fail_fn["new_draft"] = ("23505", "version 2 is still open: take it through or withdraw it first")
        status, body, _ = self.req("/api/policy/draft", tok, {"from": "applied", "reason": "x"})
        self.assertEqual((status, body["error"]), (409, "version 2 is still open: take it through or withdraw it first"))
        self.assertFalse(self.pdb.committed)
        del self.pdb.fail_fn["new_draft"]
        self.pdb.fail_fn["_changed_since"] = ("55000", "policy changes need the access component: run ./apps/access/deploy.sh")
        self.assertEqual(self.req("/api/policy/draft", tok, {"from": "applied", "reason": "x"})[0], 503)
        del self.pdb.fail_fn["_changed_since"]
        self.pdb.corrupt_save = True                 # the verdict save must leave the digest as it was
        status, body, _ = self.req("/api/policy/draft", tok, {"from": "defaults", "reason": "x"})
        self.assertEqual(status, 500, body)
        self.assertFalse(self.pdb.committed)

    def test_entry(self):
        tok = self.ptoken(["admin"], person="p-admin")
        self.open_version("draft")
        for bad in ({"role": "operator", "group": "master_data", "levels": {"Z": None}, "reason": "x"},
                    {"role": "operator", "group": "master_data", "levels": {"R": "nope"}, "reason": "x"},
                    {"role": "nobody", "group": "master_data", "levels": {"R": None}, "reason": "x"},
                    {"role": "operator", "group": "master_data", "levels": ["R"], "reason": "x"},
                    {"role": "operator", "group": "master_data", "levels": {"R": None}, "reason": ""}):
            status, body, _ = self.put("/api/policy/2/entry", tok, bad)
            self.assertEqual(status, 400, (bad, body))
        self.assertFalse(self.sql("iam_policy.save_entry("))
        # a red cell (I16: U without C and R) still saves, with ok false and the compiler digest
        status, body, _ = self.put("/api/policy/2/entry", tok,
                                   {"role": "operator", "group": "master_data", "levels": {"U": None}, "reason": "test: red"})
        self.assertEqual(status, 200, body)
        self.assertIs(body["verdict"]["ok"], False)
        self.assertTrue(any(e.startswith("I16 master_data.operator") for e in body["verdict"]["errors"]))
        self.assertEqual(body["cell"], {"levels": ["U"], "constraints": {}})
        save = self.sql("iam_policy.save_entry(")[0]
        verdict = json.loads(save[1][5])
        self.assertIs(verdict["ok"], False)
        from compiler import source
        self.assertEqual(verdict["checker_digest"], source.compiler_digest())
        self.assertEqual(json.loads(save[1][3]), {"U": None})
        self.assertLess(self.first("pg_advisory_xact_lock"), self.first("FROM iam_policy.entry"))
        self.assertTrue(self.pdb.committed)
        # not a draft: 409 before any save
        self.pdb.versions[2]["status"] = "submitted"
        n = len(self.sql("iam_policy.save_entry("))
        status, body, _ = self.put("/api/policy/2/entry", tok,
                                   {"role": "operator", "group": "master_data", "levels": {"R": None}, "reason": "x"})
        self.assertEqual((status, body["error"]), (409, "version 2 is not a draft"))
        self.assertEqual(len(self.sql("iam_policy.save_entry(")), n)
        # PUT is JSON from the page's own Origin, and U on iam_policy (admin)
        self.assertEqual(self.put("/api/policy/2/entry", tok, {}, ctype="text/plain")[0], 415)
        self.assertEqual(self.put("/api/policy/2/entry", tok, {}, origin="https://evil.test")[0], 403)
        self.assertEqual(self.put("/api/policy/2/entry", self.ptoken(["qa"]), {})[0], 403)
        self.assertEqual(self.put("/api/policy/2/other", tok, {})[0], 403)      # not in the route table

    def test_submit(self):
        tok = self.ptoken(["admin"], person="p-admin")
        self.open_version("draft", change=lambda ents: [e for e in ents if not (e["role"] == "operator"
                                                                                and e["group_code"] == "master_data")]
                          + [{"role": "operator", "group_code": "master_data", "level": "U", "constraint_name": None}])
        status, body, _ = self.req("/api/policy/2/submit", tok, {"reason": "test: submit"})
        self.assertEqual(status, 409, body)
        self.assertIn("version 2 fails the checker now", body["error"])
        self.assertTrue(body["errors"])
        self.assertFalse(self.sql("iam_policy.submit("), "the database is not asked")
        self.open_version("draft", change=self.without_engineer_on(self.engineer_group()))
        self.pdb.submit_digest = "0" * 64              # submit stored other rows than those checked
        status, body, _ = self.req("/api/policy/2/submit", tok, {"reason": "test: submit"})
        self.assertEqual((status, body["error"]), (409, "version 2 changed while it was checked: reload the page"))
        self.assertFalse(self.pdb.committed)
        self.pdb.submit_digest = None
        self.pdb.versions[2]["status"] = "draft"
        status, body, _ = self.req("/api/policy/2/submit", tok, {"reason": "test: submit"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["entries_digest"], self.pdb.digest(2))
        self.assertTrue(self.pdb.committed)
        self.assertLess(self.first("pg_advisory_xact_lock"), self.first("FROM iam_policy.entry"))

    def test_withdraw(self):
        tok = self.ptoken(["admin"], person="p-admin")
        self.open_version("approved")
        self.assertEqual(self.req("/api/policy/2/withdraw", tok, {"reason": ""})[0], 400)
        status, body, _ = self.req("/api/policy/2/withdraw", tok, {"reason": "test: withdraw"})
        self.assertEqual((status, body), (200, {"ok": True}))
        self.assertEqual(self.sql("iam_policy.withdraw(")[0][1][:2], (2, "test: withdraw"))
        self.assertEqual(self.pdb.versions[2]["status"], "withdrawn")
        self.assertTrue(self.pdb.committed)
        self.pdb.fail_fn["withdraw"] = ("22023", "version 2 is not open")
        self.assertEqual(self.req("/api/policy/2/withdraw", tok, {"reason": "again"})[0], 409)

    def change_diff_expected(self):
        from compiler import explain, source
        p1 = self.pa.composed(PolicyCursor(self.pdb), 1)[0]
        p2 = self.pa.composed(PolicyCursor(self.pdb), 2)[0]
        doc = explain.diff_document("change", 2, 1, self.pdb.versions[2]["entries_digest"], p1, p2)
        return source.canonical(doc), doc

    def test_diff_of_a_change(self):
        self.open_version("submitted", change=self.without_engineer_on(self.engineer_group()))
        status, body, h = self.req("/api/policy/2/diff?against=applied", self.ptoken(["qa"]))
        self.assertEqual(status, 200)
        want, doc = self.change_diff_expected()
        self.assertEqual(body, json.loads(want))
        raw = urllib.request.urlopen(urllib.request.Request(
            self.purl + "/api/policy/2/diff?against=applied",
            headers={"X-Forwarded-Access-Token": self.ptoken(["qa"])}), timeout=60).read()
        self.assertEqual(raw, want)
        self.assertEqual(h["X-Medcea-Skeleton-Digest"], self.pdb.skel_digest)
        self.assertEqual(h["X-Medcea-Diff-Digest"], hashlib.sha256(want).hexdigest())
        self.assertEqual(h.get("Cache-Control"), "no-store")
        self.assertTrue(doc["cells"])
        self.assertEqual(set(doc["roles"]), {"engineer"})
        self.assertEqual(self.req("/api/policy/2/diff?against=1", self.ptoken(["qa"]))[0], 400)

    def skeleton_version(self, roles=None):
        """Version 2 of kind skeleton with a host-stored diff (jsonb text, as psql returns it)."""
        from compiler import source
        v = self.open_version("submitted", kind="skeleton")
        doc = {"schema": 1, "kind": "skeleton", "version": 2, "against": 1, "entries_digest": v["entries_digest"],
               "skeleton": {"from": self.pdb.skel_digest, "to": "f" * 64, "sections": ["hosts"]},
               "cells": [], "waivers": {"added": [], "removed": []}, "roles": roles or {},
               "system": {"added": [["host", "NEW_DOMAIN → svc é"]], "removed": []}}
        b = source.canonical(doc)
        self.pdb.vdiff[2] = (source.pg_jsonb_text(doc), hashlib.sha256(b).hexdigest())
        return b

    def test_diff_of_a_skeleton_version(self):
        b = self.skeleton_version()
        status, body, h = self.req("/api/policy/2/diff", self.ptoken(["auditor"]))
        self.assertEqual(status, 200)
        self.assertEqual(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), b)
        self.assertEqual(h["X-Medcea-Diff-Digest"], hashlib.sha256(b).hexdigest())
        self.assertEqual(h["X-Medcea-Skeleton-Digest"], self.pdb.skel_digest)
        self.pdb.vdiff[2] = (self.pdb.vdiff[2][0], "0" * 64)
        status, body, _ = self.req("/api/policy/2/diff", self.ptoken(["auditor"]))
        self.assertEqual((status, body["error"]), (500, "the stored diff of version 2 does not hash to its digest"))

    def approve(self, body, token=None):
        return self.req("/api/policy/2/approve", token or self.ptoken(["qa"]), body)

    def test_approve_a_change(self):
        self.open_version("submitted", change=self.without_engineer_on(self.engineer_group()))
        want, doc = self.change_diff_expected()
        good = {"note": "test: read it", "entries_digest": doc["entries_digest"],
                "diff_digest": hashlib.sha256(want).hexdigest(), "skeleton_digest": self.pdb.skel_digest}
        for k in ("entries_digest", "diff_digest", "skeleton_digest"):
            status, body, _ = self.approve(dict(good, **{k: "ABC"}))
            self.assertEqual(status, 400, k)
        for k in ("diff_digest", "skeleton_digest"):
            status, body, _ = self.approve(dict(good, **{k: "e" * 64}))
            self.assertEqual(status, 409, k)
            self.assertIn("the diff you approved is not the one the Policy service computes now", body["error"])
        self.assertEqual(self.cfg.calls, [], "nothing forwarded")
        tok = self.ptoken(["qa"])
        status, body, _ = self.approve(good, tok)
        self.assertEqual(status, 200, body)
        path, auth, args = self.cfg.calls[-1]
        self.assertEqual((path, auth), ("/rpc/approve_policy", "Bearer " + tok))
        self.assertEqual(args, {"p_version": 2, "p_note": "test: read it", "p_entries_digest": good["entries_digest"],
                                "p_diff_digest": good["diff_digest"], "p_skeleton_digest": good["skeleton_digest"]})
        self.assertNotIn(tok, self.logs.getvalue())
        self.assertEqual(self.req("/api/policy/2/approve", self.ptoken(["admin"]), good)[0], 403)   # A: qa
        for answer, want_status in (((403, b'{"code":"28000","message":"this client may only call medcea.approve_policy"}'), 403),
                                    ((404, b'{"code":"PGRST202","message":"Could not find the function"}'), 503),
                                    ((404, b'{"code":"42883","message":"function does not exist"}'), 503),
                                    ((403, b'{"code":"42501","message":"you are an author of version 2: another qa person approves it"}'), 403),
                                    ((400, b'{"code":"22023","message":"a policy break-glass is open (event 7)"}'), 409)):
            self.cfg.answer = answer
            status, body, _ = self.approve(good)
            self.assertEqual(status, want_status, (answer, body))
        n = len(self.cfg.calls)
        self.pdb.db_roles = "false"
        self.assertEqual(self.approve(good)[0], 503)
        self.pdb.db_roles = "true"
        write_settings(True, jwt_mode=False)
        self.assertEqual(self.approve(good)[0], 503)
        write_settings(True)
        self.assertEqual(len(self.cfg.calls), n, "nothing forwarded with a switch false")

    def test_approve_refuses_a_widening_of_the_approvers_role(self):
        g = next(g for g in sorted(self.pdb.versions[1]["groups"])
                 if not any(e["role"] == "auditor" and e["group_code"] == g for e in self.pdb.entries[1]))
        self.open_version("submitted", change=lambda ents: ents + [
            {"role": "auditor", "group_code": g, "level": "R", "constraint_name": None}])
        want, doc = self.change_diff_expected()
        self.assertTrue(doc["roles"]["auditor"]["added"])
        good = {"note": "test", "entries_digest": doc["entries_digest"],
                "diff_digest": hashlib.sha256(want).hexdigest(), "skeleton_digest": self.pdb.skel_digest}
        status, body, _ = self.approve(good)                     # qa includes auditor
        self.assertEqual((status, body["error"]), (403, "version 2 widens role auditor, which you hold: you may not approve it"))
        self.assertEqual(self.cfg.calls, [])

    def test_approve_a_skeleton_version(self):
        b = self.skeleton_version()
        good = {"note": "test: read the diff", "entries_digest": self.pdb.versions[2]["entries_digest"],
                "diff_digest": hashlib.sha256(b).hexdigest(), "skeleton_digest": self.pdb.skel_digest,
                "attest": self.pa.SKELETON_ATTEST}
        for attest in (None, "I did not run apply.sh for this version.", self.pa.SKELETON_ATTEST + " "):
            status, body, _ = self.approve(dict(good, attest=attest))
            self.assertEqual(status, 400, attest)
            self.assertIn("needs the attestation", body["error"])
        status, body, _ = self.approve(dict(good, diff_digest="e" * 64))
        self.assertEqual(status, 409)
        self.assertEqual(self.cfg.calls, [])
        status, body, _ = self.approve(good)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.cfg.calls[-1][2]["p_note"],
                         "I did not run apply.sh --propose-skeleton for this version. test: read the diff")
        self.skeleton_version(roles={"qa": {"added": [["host", "X_DOMAIN", None]], "removed": []}})
        status, body, _ = self.approve(dict(good, diff_digest=self.pdb.vdiff[2][1]))
        self.assertEqual((status, body["error"]), (403, "version 2 widens role qa, which you hold: you may not approve it"))

    def test_return_forwarded(self):
        self.open_version("submitted")
        self.assertEqual(self.req("/api/policy/2/return", self.ptoken(["qa"]), {"note": ""})[0], 400)
        tok = self.ptoken(["qa"])
        status, body, _ = self.req("/api/policy/2/return", tok, {"note": "test: not yet"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.cfg.calls[-1], ("/rpc/return_policy", "Bearer " + tok, {"p_version": 2, "p_note": "test: not yet"}))

    def test_versions_with_an_open_one(self):
        self.open_version("submitted", kind="skeleton")
        status, body, _ = self.req("/api/policy", self.ptoken(["qa"]))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["open"], 2)
        self.assertEqual(body["accepted_skeleton_digest"], self.pdb.skel_digest)
        v2 = body["versions"][0]
        self.assertEqual(v2["why_not"], {"may_approve": True, "why_not_code": None, "needs_token_path": True})
        self.assertEqual(v2["authors"], [{"name": "admin", "person": "p-admin"},
                                         {"name": None, "person": "p-host", "claimed": True}])
        actor = self.first("medcea_auth.set_actor")
        self.assertLess(actor, self.first("iam_policy.why_not("))
        self.assertEqual(self.pdb.log[actor][1], (SUB, "p-qa", "quinn.q", "qa"))
        self.assertIn("LEFT JOIN iam_policy.skeleton s", self.pdb.log[self.first("FROM iam_policy.version v")][0])
        self.assertFalse(self.pdb.committed)

    def test_apply_state_per_version(self):
        """§14.8.12: rollout incomplete (apply_started with no later end, partial_apply mixed or
        reverting), reverted (apply_reverted or partial_apply reverted on an approved version)."""
        d = self.pdb
        cases = {   # version: (kind, status, latest apply event, outcome, want)
            2: ("change", "approved", "apply_reverted", None, "reverted"),
            3: ("change", "approved", "partial_apply", "reverted", "reverted"),
            4: ("change", "superseded", "apply_started", None, "rollout incomplete"),
            5: ("change", "superseded", "partial_apply", "mixed", "rollout incomplete"),
            6: ("rollback", "withdrawn", "partial_apply", "reverted", None),
            7: ("change", "superseded", "applied", None, None),
            8: ("rollback", "superseded", "partial_apply", "reverting", "rollout incomplete"),
            9: ("change", "approved", None, None, None),
        }
        for n, (kind, status, event, outcome, _want) in cases.items():
            d.versions[n] = dict(version=n, kind=kind, status=status, reason="test", based_on=1,
                                 groups=d.versions[1]["groups"], roles=d.versions[1]["roles"])
            d.entries[n] = d.entries[1]
            if event:
                d.apply_events[n] = (event, outcome)
        status, body, _ = self.req("/api/policy", self.ptoken(["auditor"], person="p-aud"))
        self.assertEqual(status, 200, body)
        got = {v["version"]: v["apply_state"] for v in body["versions"]}
        self.assertEqual(got, {1: None, **{n: c[4] for n, c in cases.items()}})
        q = self.pdb.log[self.first("SELECT DISTINCT ON (h.version)")][0]
        self.assertIn("ORDER BY h.version, h.event_id DESC", q)
        self.assertEqual(set(re.findall(r"'([a-z_]+)'", q.split(" IN (", 1)[1])), set(self.pa.APPLY_EVENTS))
        self.assertEqual(set(self.pa.APPLY_EVENTS),
                         {"apply_started", "applied", "bootstrap_applied", "partial_apply", "apply_reverted"})
        self.assertFalse(self.pdb.committed)

    def test_apply_state_events_are_the_sources(self):
        """Each event of APPLY_EVENTS is one policy_db_state reads as an apply event."""
        with open(os.path.join(REPO, "infra", "lib-policy-source.sh")) as f:
            ps = f.read()
        lst = re.search(r"h\.event IN \(('apply_started'[^)]*)\)", ps).group(1)
        self.assertLessEqual(set(self.pa.APPLY_EVENTS), set(re.findall(r"'([a-z_]+)'", lst)))
        # the apply state of one event in isolation, the status deciding "reverted"
        f = self.pa.apply_state
        self.assertEqual(f("partial_apply", "reverted", "approved"), "reverted")
        self.assertIsNone(f("partial_apply", "reverted", "withdrawn"))
        self.assertIsNone(f("apply_reverted", None, "applied"))
        self.assertEqual(f("apply_started", None, "applied"), "rollout incomplete")
        self.assertIsNone(f("bootstrap_applied", None, "applied"))
        self.assertIsNone(f(None, None, "draft"))

    def test_who_can_identities_break_glass(self):
        tok = self.ptoken(["admin"], person="p-admin")
        status, body, _ = self.req("/api/policy/who-can", tok)
        self.assertEqual(status, 200, body)
        names = {o["name"] for o in body["objects"]}
        self.assertIn("POLICY_DOMAIN", names)
        status, body, _ = self.req("/api/policy/who-can?object=POLICY_DOMAIN", tok)
        self.assertEqual(status, 200, body)
        self.assertEqual({r["role"] for r in body["roles"]}, {"admin", "auditor", "qa", "qp"})
        status, body, _ = self.req("/api/policy/who-can?object=POLICY_DOMAIN&level=A", tok)
        self.assertEqual({r["role"] for r in body["roles"]}, {"qa"})
        self.assertEqual(self.req("/api/policy/who-can?object=POLICY_DOMAIN&level=Z", tok)[0], 400)
        self.assertEqual(self.req("/api/policy/who-can?object=group:nothing", tok)[0], 404)
        status, body, _ = self.req("/api/policy/service-identities", tok)
        self.assertEqual(status, 200, body)
        svc = {i["key"]: i for i in body["identities"]}
        self.assertEqual(svc["svc_iam"]["password_key"], "IAM_SVC_DB_PASS")
        self.assertEqual(svc["svc_iam"]["ceiling"]["iam_policy"], ["R", "C", "U"])
        self.assertTrue(svc["svc_iam"]["groups"]["iam_policy"]["help"])
        self.pdb.bg_open = [(7, datetime.datetime(2026, 11, 4, 9, 0, tzinfo=datetime.timezone.utc), '["infra"]')]
        status, body, _ = self.req("/api/policy/break-glass", tok)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["identities"][0]["identity"])
        self.assertEqual(body["open_overrides"], [{"event_id": 7, "at": "2026-11-04T09:00:00+00:00", "components": ["infra"]}])
        q = self.pdb.log[self.first("break_glass_seen")][0]
        for k in ("'break_glass_ended'", "'since_event'", "'component'", "'source' = 'file'", "'components'"):
            self.assertIn(k, q)

if __name__ == "__main__":
    unittest.main()
