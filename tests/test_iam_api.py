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


def write_settings(person):
    with open(os.path.join(TMP, "settings.json"), "w") as f:
        json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": True,
                   "switches": {"IAM_MQTT_PERSON": person, "written_at": "2026-10-31T00:00:00Z"}}, f)
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
        if "user_status_history" in self.last:
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
        p = model.load()
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
                 ("medcea_auth.set_actor", "iam.user_status_history", "UPDATE medcea.mqtt_service_credential",
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

    def test_digest_is_the_compilers(self):
        body = {k: v for k, v in self.doc.items() if k != "digest"}
        self.assertEqual(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                         self.doc["digest"])


if __name__ == "__main__":
    unittest.main()
