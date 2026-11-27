#!/usr/bin/env python3
"""tests/test_research_console_server.py — research Phase 4e: apps/research-console/console.py, the research
console's page server (codeplan/rs4e-design.md §1, §7), on an ephemeral localhost port with the real medcea_iam
and a throwaway realm key:

  401 without a token and with a medcea-api token (the service's audience is medcea-research), 403 for a role
  outside research_campaigns, 200 with the console's headers (CSP, nosniff, no-referrer, no-cache) for a
  scientist, the manifest's names only (traversal, unlisted, the mount's ..data entries and MANIFEST keys all
  404), /healthz without a token, HEAD, POST refused, no token or path in the log.

    python3 tests/test_research_console_server.py
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
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


def dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@unittest.skipUnless(HAVE_JWT, "PyJWT/cryptography not installed on this host")
class ConsoleServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["MEDCEA_IAM_ROUTES"] = os.path.join(cls.tmp, "routes.json")
        os.environ["MEDCEA_IAM_SETTINGS"] = os.path.join(cls.tmp, "settings.json")
        os.environ["MEDCEA_IAM_JWKS"] = os.path.join(cls.tmp, "jwks.json")
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        jwk.update(kid="k1", alg="RS256", use="sig")
        dump({"keys": [jwk]}, os.environ["MEDCEA_IAM_JWKS"])
        dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": False}, os.environ["MEDCEA_IAM_SETTINGS"])
        route = {"levels": ["R"], "group": "research_campaigns",
                 "roles": {"bio_scientist": None, "control_scientist": None, "engineer": None}}
        # as commit B's routes.json will say: the console's own audience (its pod's `audience` key)
        table = {"roles": ["bio_scientist", "control_scientist", "engineer", "qa"], "role_includes": {},
                 "public": {"*": ["GET /healthz"]},
                 "services": {"research-console": {"clients": ["research-console"], "audience": "medcea-research",
                                                   "routes": {"GET /": route, "GET /static/<file>": route,
                                                              "GET /static/<dir>/<file>": route}}}}
        dump(table, os.environ["MEDCEA_IAM_ROUTES"])
        cls.srv_dir = os.path.join(cls.tmp, "srv")
        os.makedirs(cls.srv_dir)
        files = {"index.html": b"<!doctype html><title>c</title>", "console.js": b"var x = 1;",
                 "uplot/uPlot.min.js": b"/* uplot */", "uplot/LICENSE": b"MIT"}
        doc = {"schema": 1, "signout": "https://agents.medcea/oauth2/sign_out",
               "files": {n: {"key": n.replace("/", "__"), "sha256": hashlib.sha256(b).hexdigest()} for n, b in files.items()}}
        doc["files"]["evil"] = {"key": "../routes.json", "sha256": "x"}
        doc["files"]["data.js"] = {"key": "..data", "sha256": "x"}
        for n, b in files.items():
            with open(os.path.join(cls.srv_dir, n.replace("/", "__")), "wb") as f:
                f.write(b)
        with open(os.path.join(cls.srv_dir, "secret.txt"), "w") as f:
            f.write("not listed")
        cls.manifest = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        with open(os.path.join(cls.srv_dir, "MANIFEST.json"), "wb") as f:
            f.write(cls.manifest)
        os.environ["RS_CONSOLE_DIR"] = cls.srv_dir
        os.environ["MEDCEA_IAM_LIB"] = os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py")
        cls.c = load("research_console", "apps/research-console/console.py")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.log = io.StringIO()
        self.errcm = contextlib.redirect_stderr(self.log)
        self.errcm.__enter__()
        self.srv = self.c.make_server("127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.errcm.__exit__(None, None, None)

    def token(self, roles=("bio_scientist",), aud="medcea-research", azp="research-console"):
        now = int(time.time())
        c = {"iss": ISSUER, "aud": [aud], "sub": SUB, "typ": "Bearer", "azp": azp, "iat": now, "exp": now + 300,
             "preferred_username": "bio", "person_id": "p-1", "groups": list(roles)}
        return jwt.encode(c, self.key, algorithm="RS256", headers={"kid": "k1"})

    def get(self, path, token=None, method="GET"):
        h = {"X-Forwarded-Access-Token": token} if token else {}
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), method=method, headers=h,
                                     data=b"{}" if method == "POST" else None)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def test_healthz_without_a_token(self):
        st, body, h = self.get("/healthz")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body), {"service": "research-console", "files": 6,
                                            "manifest_sha256": hashlib.sha256(self.manifest).hexdigest()})
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])

    def test_refused_without_the_right_token(self):
        self.assertEqual(self.get("/")[0], 401)
        self.assertEqual(self.get("/", self.token(aud="medcea-api"))[0], 401)        # the platform audience
        self.assertEqual(self.get("/", self.token(azp="research-agent"))[0], 401)    # not the host's client
        st, body, h = self.get("/", self.token(roles=("qa",)))
        self.assertEqual(st, 403)
        self.assertIn("X-Content-Type-Options", h)                                   # refusals carry the headers too

    def test_a_scientist_gets_the_page_with_the_headers(self):
        st, body, h = self.get("/", self.token())
        self.assertEqual((st, body), (200, b"<!doctype html><title>c</title>"))
        self.assertEqual(h["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(h["Content-Security-Policy"],
                         "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                         "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.assertEqual((h["X-Content-Type-Options"], h["Referrer-Policy"], h["Cache-Control"]), ("nosniff", "no-referrer", "no-cache"))
        st, body, h = self.get("/static/uplot/uPlot.min.js", self.token(roles=("engineer",)))
        self.assertEqual((st, body, h["Content-Type"]), (200, b"/* uplot */", "text/javascript; charset=utf-8"))
        st, body, h = self.get("/static/MANIFEST.json", self.token())
        self.assertEqual((st, body), (200, self.manifest))
        st, body, h = self.get("/static/uplot/LICENSE", self.token())
        self.assertEqual((st, h["Content-Type"]), (200, "text/plain; charset=utf-8"))
        st, body, h = self.get("/", self.token(), method="HEAD")
        self.assertEqual((st, body), (200, b""))

    def test_only_the_manifests_names(self):
        t = self.token()
        for path in ("/static/secret.txt", "/static/../routes.json", "/static/%2e%2e/routes.json", "/static/evil",
                     "/static/data.js", "/static/uplot__uPlot.min.js", "/static/a/b/c.js", "/index.html", "/static/",
                     "/static/..%2froutes.json", "/srv/MANIFEST.json"):
            with self.subTest(path):
                st, body, h = self.get(path, t)
                self.assertIn(st, (403, 404), path)   # 403: a path the route table has no route for
                self.assertNotIn(b"not listed", body)
                self.assertNotIn(b"research_campaigns", body)
        self.assertIsNone(self.c.lookup("../routes.json", self.srv_dir))
        self.assertIsNone(self.c.lookup("evil", self.srv_dir))
        self.assertIsNone(self.c.lookup("data.js", self.srv_dir))

    def test_post_refused_and_nothing_logged(self):
        t = self.token()
        st, body, h = self.get("/", t, method="POST")
        self.assertIn(st, (403, 405))
        self.assertNotIn(t, self.log.getvalue())
        self.assertNotIn("X-Forwarded-Access-Token", self.log.getvalue())

    def test_without_the_library_every_check_is_503(self):
        lib = os.environ["MEDCEA_IAM_LIB"]
        try:
            self.c.IAM_LIB = os.path.join(self.tmp, "missing.py")
            self.c._IAM.clear()
            self.assertEqual(self.get("/", self.token())[0], 503)
            self.assertEqual(self.get("/healthz")[0], 200)
        finally:
            self.c.IAM_LIB = lib
            self.c._IAM.clear()


if __name__ == "__main__":
    unittest.main()
