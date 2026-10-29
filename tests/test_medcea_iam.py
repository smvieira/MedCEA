#!/usr/bin/env python3
"""tests/test_medcea_iam.py — medcea_iam.check() against the compiled route table, with
tokens signed by a throwaway RSA key (no Keycloak, no cluster).

Run from the repository root:  python3 tests/test_medcea_iam.py
Needs PyJWT and cryptography on the host; skipped without them (the services install
them in their own containers).
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import model, routes  # noqa: E402

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_JWT = True
except ImportError:
    HAVE_JWT = False

ISSUER = "https://keycloak.test/realms/medcea"


def _load_lib(tmp):
    os.environ["MEDCEA_IAM_ROUTES"] = os.path.join(tmp, "routes.json")
    os.environ["MEDCEA_IAM_SETTINGS"] = os.path.join(tmp, "settings.json")
    os.environ["MEDCEA_IAM_JWKS"] = os.path.join(tmp, "jwks.json")
    spec = importlib.util.spec_from_file_location("medcea_iam", os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(HAVE_JWT, "PyJWT/cryptography not installed on this host")
class CheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        with open(os.path.join(cls.tmp, "routes.json"), "w") as f:
            f.write(routes.dumps(routes.compile(model.load())))
        with open(os.path.join(cls.tmp, "settings.json"), "w") as f:
            json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": False}, f)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        jwk.update(kid="k1", alg="RS256", use="sig")
        with open(os.path.join(cls.tmp, "jwks.json"), "w") as f:
            json.dump({"keys": [jwk]}, f)
        cls.iam = _load_lib(cls.tmp)

    def token(self, roles, azp="scheduler", key=None, kid="k1", **over):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": ["medcea-api", "account"], "sub": "u-1", "typ": "Bearer", "azp": azp,
                  "iat": now, "exp": now + 300, "preferred_username": "tester", "person_id": "p-1",
                  "groups": roles + ["default-roles-medcea"]}
        claims.update(over)
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": kid})

    def check(self, service, method, path, token=None, header="X-Forwarded-Access-Token"):
        h = {header: (("Bearer " + token) if header == "Authorization" else token)} if token else {}
        return self.iam.check(service, method, path, h)

    def test_allowed_and_refused_by_role(self):
        d = self.check("scheduler", "GET", "/api/runs?limit=5", self.token(["engineer"]))
        self.assertTrue(d.allow, d)
        self.assertEqual(d.who["roles"], ["engineer"])            # default-roles-* dropped
        d = self.check("scheduler", "POST", "/api/runs", self.token(["engineer"]))
        self.assertFalse(d.allow)
        self.assertEqual(d.status, 403)
        self.assertTrue(self.check("scheduler", "POST", "/api/runs", self.token(["production_manager"])).allow)

    def test_composite_and_constraint(self):
        d = self.check("monitor", "GET", "/api/measurements/UNIT01", self.token(["operator"], azp="monitor"))
        self.assertTrue(d.allow)
        self.assertEqual(d.constraints, ["own_zone"])
        self.assertTrue(self.check("monitor", "GET", "/api/runs", self.token(["qa"], azp="monitor")).allow)
        self.assertFalse(self.check("monitor", "GET", "/api/runs", self.token(["admin"], azp="monitor")).allow)

    def test_literal_route_wins_and_unknown_routes_refused(self):
        d = self.check("scheduler", "GET", "/api/runs/active", self.token(["operator"]))
        self.assertEqual(d.route, "GET /api/runs/active")
        d = self.check("scheduler", "POST", "/api/logs/delete", self.token(["admin"]))
        self.assertFalse(d.allow)
        self.assertIn("not in scheduler's route table", d.reason)

    def test_token_checks(self):
        self.assertEqual(self.check("scheduler", "GET", "/api/runs").status, 401)
        self.assertIn("not a JWT", self.check("scheduler", "GET", "/api/runs", "forged").reason)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertIn("token refused", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], key=other)).reason)
        self.assertIn("no realm key", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], kid="k9")).reason)
        self.assertIn("token refused", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], exp=1)).reason)
        self.assertIn("token refused", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], aud="account")).reason)
        self.assertIn("token refused", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], iss="https://evil/x")).reason)
        self.assertIn("type", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], typ="ID")).reason)
        self.assertIn("client 'monitor'", self.check("scheduler", "GET", "/api/runs", self.token(["qa"], azp="monitor")).reason)
        self.assertTrue(self.check("scheduler", "GET", "/api/runs", self.token(["qa"], azp="config"),
                                   header="Authorization").allow)

    def test_public_and_shared(self):
        self.assertTrue(self.check("access", "GET", "/healthz").allow)
        self.assertTrue(self.check("access-public", "OPTIONS", "/api/register").allow)
        d = self.check("access-public", "DELETE", "/api/register")
        self.assertEqual((d.allow, d.status), (False, 401))      # public-only service, not "unknown"
        self.assertEqual(self.check("nonesuch", "GET", "/x").status, 503)
        for azp in ("portal", "config", "mqtt-explorer"):     # /_account/ on every signed-in host
            self.assertTrue(self.check("access-profile", "GET", "/_account/api/me",
                                       self.token(["bio_scientist"], azp=azp)).allow, azp)

    def test_actor_role(self):
        # the own role the scheduler passes to medcea_auth.set_actor (the database's
        # _own_role rule): composites collapse to the including role
        def role(roles):
            return self.iam.actor_role(self.check("scheduler", "GET", "/api/runs", self.token(roles)))
        self.assertEqual(role(["operator"]), "operator")
        self.assertEqual(role(["production_manager", "operator"]), "production_manager")
        self.assertEqual(role(["qa", "auditor"]), "qa")
        self.assertIsNone(role(["engineer", "qa"]))                 # two own roles
        self.assertIsNone(role([]))                                 # no platform role
        self.assertIsNone(self.iam.actor_role(self.check("scheduler", "GET", "/api/runs")))   # no token
        self.assertIsNone(self.iam.actor_role(None))
        # a route table compiled before role_includes: None, never a guess
        tmp = tempfile.mkdtemp()
        doc = routes.compile(model.load())
        doc.pop("role_includes")
        with open(os.path.join(tmp, "routes.json"), "w") as f:
            json.dump(doc, f)
        old = _load_lib(tmp)
        d = self.iam.Decision(True, 200, "allowed", who={"sub": "u-1", "roles": ["operator"]})
        self.assertIsNone(old.actor_role(d))
        self.assertEqual(self.iam.actor_role(d), "operator")
        _load_lib(self.tmp)

    def test_missing_files_fail_closed(self):
        # Without a route table every request is refused with 503; whether that refusal
        # is enforced comes from IAM_ENFORCE in the pod when settings.json is missing too.
        lib = _load_lib(tempfile.mkdtemp())
        d = lib.check("scheduler", "GET", "/api/runs", {})
        self.assertFalse(d.allow)
        self.assertEqual(d.status, 503)
        for env, want in (("", False), ("true", True)):
            os.environ["IAM_ENFORCE"] = env
            self.assertIs(lib.enforcing(), want)
        os.environ.pop("IAM_ENFORCE")
        self.assertFalse(self.iam.enforcing())       # settings.json says false: it wins


if __name__ == "__main__":
    unittest.main(verbosity=1)
