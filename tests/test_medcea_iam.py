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


def _handler(method, path, headers=None):
    """A stand-in BaseHTTPRequestHandler for http_check(): records the statuses sent."""
    import io

    class H:
        pass
    h = H()
    h.command, h.path, h.headers, h.wfile, h.sent = method, path, headers or {}, io.BytesIO(), []
    h.send_response = lambda code: h.sent.append(code)
    h.send_header = lambda k, v: None
    h.end_headers = lambda: None
    return h


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
        self.assertEqual(d.constraints, ["own_unit"])
        self.assertTrue(self.check("monitor", "GET", "/api/runs", self.token(["qa"], azp="monitor")).allow)
        self.assertFalse(self.check("monitor", "GET", "/api/runs", self.token(["admin"], azp="monitor")).allow)

    def test_own_unit_sub(self):
        # IAM 2.6: the uuid whose units bound an own_unit read, or None when not limited
        sub = self.iam.own_unit_sub
        uid = "11111111-1111-4111-8111-111111111111"
        tok = self.token(["operator"], azp="monitor", sub=uid)
        self.assertEqual(sub(self.check("monitor", "GET", "/api/measurements/UNIT01", tok)), uid)
        self.assertEqual(sub(self.check("monitor", "GET", "/api/runs", self.token(["operator"], azp="monitor"))),
                         self.iam.NIL_SUB)                              # sub 'u-1' is no account uuid
        pm = self.token(["production_manager", "operator"], azp="monitor", sub=uid)
        self.assertIsNone(sub(self.check("monitor", "GET", "/api/runs", pm)))        # an unconstrained grant wins
        self.assertIsNone(sub(self.check("monitor", "GET", "/api/runs", self.token(["qa"], azp="monitor"))))
        self.assertIsNone(sub(self.check("monitor", "GET", "/api/runs", self.token(["admin"], azp="monitor"))))  # refused
        op = self.token(["operator"], sub=uid)
        self.assertIsNone(sub(self.check("scheduler", "POST", "/api/runs/1/execute", op)))   # assigned_run only
        self.assertEqual(sub(self.check("scheduler", "GET", "/api/runs/7/log", op)), uid)
        self.assertIsNone(sub(None))

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
        # IAM 2.6: a service that cannot verify any token answers 503, not 401 (its fault,
        # not the person's): no keys, or no issuer
        for name, settings in (("jwks.json", {"issuer": ISSUER}), ("settings.json", {"audience": "medcea-api"})):
            tmp = tempfile.mkdtemp()
            for f in ("routes.json", "jwks.json"):
                if f != name:
                    with open(os.path.join(self.tmp, f)) as src, open(os.path.join(tmp, f), "w") as dst:
                        dst.write(src.read())
            with open(os.path.join(tmp, "settings.json"), "w") as f:
                json.dump(settings, f)
            d = _load_lib(tmp).check("scheduler", "GET", "/api/runs", {"X-Forwarded-Access-Token": self.token(["qa"])})
            self.assertEqual(d.status, 503, d)
            self.assertIn("keys" if name == "jwks.json" else "issuer", d.reason)
        self.assertEqual(self.check("scheduler", "GET", "/api/runs", self.token(["qa"], kid="k9")).status, 401)
        _load_lib(self.tmp)

    def test_settings_enforce_true(self):
        # IAM 2.6: settings.json's enforce beats the pod's copy; a refusal is sent, with one
        # 'refused' line; a constraint is reported, not evaluated, under true too
        import contextlib
        import io
        tmp = tempfile.mkdtemp()
        for f in ("routes.json", "jwks.json"):
            with open(os.path.join(self.tmp, f)) as src, open(os.path.join(tmp, f), "w") as dst:
                dst.write(src.read())
        with open(os.path.join(tmp, "settings.json"), "w") as f:
            json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": True}, f)
        try:
            lib = _load_lib(tmp)
            os.environ["IAM_ENFORCE"] = "false"
            self.assertIs(lib.enforcing(), True)
            h, err = _handler("GET", "/_account/api/me"), io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIs(lib.http_check(h, "access-profile"), False)
            self.assertEqual(h.sent, [401])
            lines = err.getvalue().splitlines()
            self.assertEqual(len(lines), 1, lines)
            self.assertIn("medcea_iam: refused", lines[0])
            op = {"X-Forwarded-Access-Token": self.token(["operator"], azp="monitor")}
            d = lib.check("monitor", "GET", "/api/runs", op)
            self.assertTrue(d.allow, d)
            self.assertEqual(d.constraints, ["own_unit"])
            d = lib.check("monitor", "GET", "/api/nonesuch", op)
            self.assertEqual((d.allow, d.status), (False, 403))
        finally:
            os.environ.pop("IAM_ENFORCE", None)
            _load_lib(self.tmp)


class TableQueriesTest(unittest.TestCase):
    """widening(), roles_including(), allows(), exportable() (2.6) and http_check(enforce=) (IAM 2.7): read the
    route table only, so no PyJWT is needed."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()
        cls.tmp = tempfile.mkdtemp()
        with open(os.path.join(cls.tmp, "routes.json"), "w") as f:
            f.write(routes.dumps(routes.compile(cls.policy)))
        with open(os.path.join(cls.tmp, "settings.json"), "w") as f:
            json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": False}, f)
        cls.iam = _load_lib(cls.tmp)

    def test_widening(self):
        w = self.iam.widening("operator", "production_manager")
        self.assertEqual(w, [list(x) for x in self.policy.widening("operator", "production_manager")])
        self.assertEqual(len(w), 12)
        self.assertEqual(self.iam.widening("production_manager", "operator"), [])
        self.assertEqual(len(self.iam.widening(None, "operator")), 9)
        self.assertEqual(self.iam.widening("qa", "qa"), [])
        # a table compiled before 2.7 has no widening: None, never "narrowing"
        tmp = tempfile.mkdtemp()
        doc = routes.compile(self.policy)
        doc.pop("widening")
        with open(os.path.join(tmp, "routes.json"), "w") as f:
            json.dump(doc, f)
        old = _load_lib(tmp)
        self.assertIsNone(old.widening("production_manager", "operator"))
        self.assertIsNone(_load_lib(tempfile.mkdtemp()).widening(None, "operator"))
        _load_lib(self.tmp)

    def test_roles_including(self):
        self.assertEqual(self.iam.roles_including("auditor"), ["qa"])
        self.assertEqual(self.iam.roles_including("operator"), ["production_manager"])
        self.assertEqual(self.iam.roles_including("admin"), [])
        self.assertEqual(self.iam.roles_including("nonesuch"), [])

    def test_exportable(self):
        # IAM 2.6: what Database Management may export, scoped by actor_role() (the role
        # log_export records)
        from types import SimpleNamespace as D
        ex = self.iam.exportable
        qp = ex(D(who={"roles": ["qp"]}))
        self.assertEqual(sorted(qp), ["audit_histories", "measurements", "runs"])
        self.assertIn("medcea.measurement", qp["measurements"])
        every = sorted(self.policy.groups["db_export"]["mirrors"])
        self.assertEqual(sorted(ex(D(who={"roles": ["qa"]}))), every)
        self.assertEqual(sorted(ex(D(who={"roles": ["qa", "auditor"]}))), every)   # the composite collapses to qa
        self.assertEqual(ex(D(who={"roles": ["operator"]})), {})
        self.assertEqual(ex(D(who={"roles": ["qa", "qp"]})), {})                    # two own roles: no scope
        self.assertEqual(ex(D(who=None)), {})
        self.assertEqual(ex(None), {})
        # a table compiled before 2.6 has no exports: None, so dbmgmt fails closed
        tmp = tempfile.mkdtemp()
        doc = routes.compile(self.policy)
        doc.pop("exports")
        with open(os.path.join(tmp, "routes.json"), "w") as f:
            json.dump(doc, f)
        self.assertIsNone(_load_lib(tmp).exportable(D(who={"roles": ["qp"]})))
        _load_lib(self.tmp)

    def test_allows(self):
        a = self.iam.allows
        for role in ("admin", "qa", "qp", "auditor"):
            self.assertTrue(a([role], "access", "GET", "/"), role)
            self.assertTrue(a([role, "default-roles-medcea"], "access", "GET", "/api/me"), role)
        self.assertFalse(a(["operator"], "access", "GET", "/"))
        self.assertTrue(a(["qa"], "access", "POST", "/api/decisions/7/confirm"))       # constrained: counts
        self.assertFalse(a(["admin"], "access", "POST", "/api/decisions/7/confirm"))
        self.assertTrue(a(["admin"], "access", "POST", "/api/decisions/7/withdraw"))
        self.assertFalse(a(["admin"], "access", "GET", "/api/config-history"))          # I2
        self.assertTrue(a(["qp"], "access", "GET", "/api/review/3"))
        self.assertFalse(a(["qa"], "access", "GET", "/api/users"))
        self.assertFalse(a(["admin"], "access", "GET", "/api/nonesuch"))
        self.assertFalse(a(["admin"], "nonesuch", "GET", "/"))
        self.assertFalse(a([], "access", "GET", "/"))
        self.assertTrue(a([], "access", "GET", "/healthz"))                              # public
        self.assertFalse(_load_lib(tempfile.mkdtemp()).allows(["admin"], "access", "GET", "/"))
        _load_lib(self.tmp)

    def _handler(self, method, path):
        return _handler(method, path)

    def test_http_check_enforce(self):
        import contextlib
        import io
        for enforce, sent, ok in ((True, [401], False), (None, [], True), (False, [], True)):
            h, err = self._handler("GET", "/api/users"), io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIs(self.iam.http_check(h, "access", enforce=enforce), ok, enforce)
            self.assertEqual(h.sent, sent, enforce)
            lines = err.getvalue().splitlines()
            self.assertEqual(len(lines), 1, lines)                   # exactly one log line
            self.assertIn("medcea_iam: refused" if enforce else "medcea_iam: would refuse", lines[0])
        h = self._handler("GET", "/healthz")                        # public: no log, no refusal
        self.assertTrue(self.iam.http_check(h, "access", enforce=True))
        self.assertEqual(h.sent, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
