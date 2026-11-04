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



# ── the Policy UI's port (IAM 4.3) ──────────────────────────────────────────────────────
class PolicyCursor:
    """Answers the Policy UI's reads from version 1 = defaults.yaml's rows."""

    def __init__(self, db):
        self.db, self.result, self.description = db, [], []

    def execute(self, sql, params=None):
        q = " ".join(sql.split())
        self.db.log.append((q, params))
        d = self.db
        if "_changed_since" in q:
            cols, rows = ["c"], [(d.changed,)]
        elif "WHERE status = 'applied'" in q:
            cols, rows = ["version"], [(1,)]
        elif "SELECT entries_digest FROM iam_policy.version" in q:
            cols, rows = ["entries_digest"], ([("d1",)] if params[0] == 1 else [])
        elif "FROM iam_policy.entry" in q:
            cols, rows = ["role", "group_code", "level", "constraint_name"], \
                [(e["role"], e["group_code"], e["level"], e["constraint_name"]) for e in d.ew["entries"]]
        elif "FROM iam_policy.waiver" in q:
            cols = ["id", "invariant", "subject", "group_code", "target", "levels", "review_by", "rationale", "controls", "objects"]
            rows = [(w["id"], w["invariant"], w["subject"], w["group"], w["target"], w["levels"],
                     datetime.date.fromisoformat(w["review_by"]), w["rationale"], w["controls"], w.get("objects") or [])
                    for w in d.ew["waivers"]]
        elif "FROM iam_policy.version ORDER BY" in q:
            cols = [c.strip() for c in q.split("SELECT ", 1)[1].split(" FROM", 1)[0].split(",")]
            v = dict.fromkeys(cols)
            v.update(version=1, kind="bootstrap", status="applied", reason="the factory policy",
                     applied_at=datetime.datetime(2026, 11, 3, 9, 59, tzinfo=datetime.timezone.utc),
                     claimed_by_person=d.claimant, confirmed_at=d.confirmed_at)
            rows = [tuple(v[c] for c in cols)]
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
        self.ew, self.db_roles, self.claimant, self.confirmed_at = ew, "true", "p-someone-else", None

    def cursor(self):
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

    def req(self, path, token=None, body=None, origin="https://" + POLICY_DOMAIN, ctype="application/json"):
        h = {"Accept": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h.update({"Content-Type": ctype, "Origin": origin})
        r = urllib.request.Request(self.purl + path, data=data, headers=h, method="POST" if body is not None else "GET")
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
        self.assertEqual(self.req("/api/policy/1/diff", self.ptoken(["qa"]))[0], 404)       # 4.4

    def test_me_per_role(self):
        for role, want in (("qa", {"matrix": True, "history": True, "confirm": True}),
                           ("admin", {"matrix": True, "history": False, "confirm": False}),
                           ("auditor", {"matrix": True, "history": True, "confirm": False}),
                           ("qp", {"matrix": False, "history": True, "confirm": False})):
            status, body, h = self.req("/api/me", self.ptoken([role]))
            self.assertEqual(status, 200, (role, body))
            self.assertEqual(body["can"], want, role)
            self.assertEqual(body["role"], role)
            self.assertEqual(h.get("Cache-Control"), "no-store")
        self.assertEqual(body["attest"], "I did not run apply.sh for this version.")

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


if __name__ == "__main__":
    unittest.main()
