#!/usr/bin/env python3
"""tests/test_superset_render.py — apps/superset (stage B of "Superset for data analysis"),
offline: no cluster, no image, no lock on the repository.

  Render     the three templates filled by lib-render.sh's `render` with the exact lists
             apps/superset/deploy.sh passes: no ${VAR} left, each list = the template's
             variables, every image pinned by digest, no secret in any plain value (the
             secrets are sentinels that must not appear in a pod spec), non-root uid 1000,
             read-only root, resources, hostAliases, SUPERSET_PORT, service links off,
             the checksum annotation, the hash-checked pip command.
  Requirements  three wheels, each `==` pinned with a sha256, the versions the image's
             Python 3.10 can install, Authlib past the October 2026 advisories.
  Config     superset_config.py loaded with stub Superset/FAB/Flask modules: secrets from
             the environment, a short key, an empty or Admin mapping refused, the session
             limits, no Scarf/Mapbox host in the CSP, CORS off, every risky flag off.
  Security   medcea_security.py's OAuth view with stubs: an unmapped person gets the 403
             page and auth_user_oauth is never called; a mapped one gets a fresh permanent
             session without the access token; logout has no id_token_hint; the 1 h end
             and the blocked routes in before_request.
  Bootstrap  bootstrap.py against fake objects: the connection's flags, its uuid,
             svc_superset only, the viewer role exactly database_access, nobody Admin.
  Deploy     deploy.sh/uninstall.sh in a scratch tree with a stub kubectl and policy:
             unknown options exit 2 before log and lock; the stage-B skip exits 0 and
             applies nothing; --gate-only without a deployment says "not deployed" and
             never compiles; a policy that lost Superset stops a running one.

  python3 tests/test_superset_render.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import timedelta
from unittest import mock

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402

APP = os.path.join(REPO, "apps", "superset")
K8S = os.path.join(APP, "k8s")
DIGEST = "sha256:16b50bbef6648912a79e3293d418fefa743ce555d36c5af6b85d859119ed7f88"
IMAGE = "docker.io/apache/superset:6.1.0@" + DIGEST

SECRETS = {
    "SUPERSET_SECRET_KEY": "sentinel-secret-key-0123456789abcdef0123456789",
    "SUPERSET_META_DB_PASS": "sentinel-meta-pass",
    "SUPERSET_CLIENT_SECRET": "sentinel-client-secret",
}
MAPPING = {"bio_scientist": ["Alpha", "sql_lab"], "engineer": ["Alpha", "sql_lab"],
           "qp": ["Gamma", "MedCEA Viewer"]}
PLAIN = {
    "NAMESPACE": "medcea", "KEYCLOAK_DOMAIN": "keycloak.medcea", "KEYCLOAK_REALM": "medcea",
    "SUPERSET_DOMAIN": "superset.medcea", "PORTAL_DOMAIN": "portal.medcea",
    "PLATFORM_IP": "100.64.0.1", "SUPERSET_CONFIG_CHECKSUM": "c" * 64,
    "PG_SECRET": "db-svc-superset", "PG_SECRET_KEY": "password",
    "SUPERSET_DB_USER": "svc_superset", "POSTGRES_DB": "medcea_db",
}


def deploy_text():
    with open(os.path.join(APP, "deploy.sh")) as f:
        return f.read()


def bash_array(name):
    m = re.search(r"^%s=\(([^)]*)\)" % name, deploy_text(), re.M)
    assert m, name
    return m.group(1).split()


def template_vars(path):
    with open(path) as f:
        return set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", f.read()))


def render(path, names, env):
    out = subprocess.run(
        ["bash", "-c", 'source "$1/infra/lib-render.sh"; f="$2"; shift 2; render "$f" "$@"',
         "x", REPO, path] + list(names),
        env=dict(os.environ, **env), capture_output=True, text=True, check=True)
    return out.stdout


def all_env():
    return dict(PLAIN, SUPERSET_ROLES_MAPPING=json.dumps(MAPPING, sort_keys=True), **SECRETS)


def pod_specs(docs):
    for d in docs:
        if d and d["kind"] in ("Deployment", "Job"):
            yield d["kind"], d["spec"]["template"]


class Render(unittest.TestCase):
    def test_lists_match_the_templates(self):
        # one list for both pod templates (deploy.sh _POD_VARS): each uses a part of it,
        # together all of it, and nothing outside it (an unlisted name stays literal text)
        pods = set(bash_array("_POD_VARS"))
        web = template_vars(os.path.join(K8S, "superset.yaml"))
        init = template_vars(os.path.join(K8S, "superset-init.yaml"))
        self.assertLessEqual(web, pods)
        self.assertLessEqual(init, pods)
        self.assertEqual(web | init, pods)
        self.assertEqual(template_vars(os.path.join(K8S, "superset-secret.yaml")), set(bash_array("_SECRET_VARS")))

    def rendered(self):
        env = all_env()
        out = {}
        for name, lst in (("superset.yaml", "_POD_VARS"), ("superset-init.yaml", "_POD_VARS"),
                          ("superset-secret.yaml", "_SECRET_VARS")):
            text = render(os.path.join(K8S, name), bash_array(lst), env)
            self.assertNotIn("${", text, name)
            out[name] = (text, list(yaml.safe_load_all(text)))
        return out

    def test_no_secret_in_a_pod_spec(self):
        r = self.rendered()
        for name in ("superset.yaml", "superset-init.yaml"):
            text = r[name][0]
            for v in SECRETS.values():
                self.assertNotIn(v, text, name)
            self.assertNotIn("bio_scientist", text, name)  # the mapping lives in the Secret only
            for kind, tpl in pod_specs(r[name][1]):
                for c in tpl["spec"].get("initContainers", []) + tpl["spec"]["containers"]:
                    for e in c.get("env", []):
                        if re.search(r"PASS|SECRET|_KEY$|MAPPING", e["name"]):
                            self.assertIn("valueFrom", e, "%s %s" % (kind, e["name"]))
                            self.assertNotIn("value", e, "%s %s" % (kind, e["name"]))

    def test_secret(self):
        docs = self.rendered()["superset-secret.yaml"][1]
        self.assertEqual(len(docs), 1)
        s = docs[0]
        self.assertEqual((s["kind"], s["metadata"]["name"], s["metadata"]["labels"]["app"]),
                         ("Secret", "superset-secrets", "superset"))
        self.assertEqual(s["stringData"]["SUPERSET_SECRET_KEY"], SECRETS["SUPERSET_SECRET_KEY"])
        self.assertEqual(json.loads(s["stringData"]["SUPERSET_ROLES_MAPPING"]), MAPPING)
        # every secretKeyRef of superset-secrets names a key the Secret has
        for name in ("superset.yaml", "superset-init.yaml"):
            for _, tpl in pod_specs(self.rendered()[name][1]):
                for c in tpl["spec"]["containers"]:
                    for e in c.get("env", []):
                        ref = e.get("valueFrom", {}).get("secretKeyRef")
                        if ref and ref["name"] == "superset-secrets":
                            self.assertIn(ref["key"], s["stringData"])

    def test_pods(self):
        r = self.rendered()
        seen = set()
        for name in ("superset.yaml", "superset-init.yaml"):
            for kind, tpl in pod_specs(r[name][1]):
                seen.add(kind)
                spec = tpl["spec"]
                self.assertEqual(tpl["metadata"]["annotations"]["medcea/config-checksum"], "c" * 64)
                sc = spec["securityContext"]
                self.assertEqual((sc["runAsNonRoot"], sc["runAsUser"], sc["runAsGroup"]), (True, 1000, 1000))
                self.assertIs(spec["automountServiceAccountToken"], False)
                self.assertIs(spec["enableServiceLinks"], False)
                deps = spec["initContainers"]
                self.assertEqual([c["name"] for c in deps], ["superset-deps"])
                cmd = deps[0]["command"]
                self.assertEqual(cmd[:2], ["/usr/local/bin/pip3", "install"])
                for flag in ("--isolated", "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-cache-dir"):
                    self.assertIn(flag, cmd)
                self.assertEqual(cmd[cmd.index("--target") + 1], "/opt/extra")
                self.assertEqual(cmd[cmd.index("-r") + 1], "/app/pythonpath/requirements.txt")
                for c in deps + spec["containers"]:
                    self.assertEqual(c["image"], IMAGE)
                    self.assertIn("limits", c["resources"])
                    self.assertIn("requests", c["resources"])
                    csc = c["securityContext"]
                    self.assertIs(csc["readOnlyRootFilesystem"], True)
                    self.assertIs(csc["allowPrivilegeEscalation"], False)
                    self.assertEqual(csc["capabilities"]["drop"], ["ALL"])
                    mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
                    for p in ("/tmp", "/app/superset_home", "/opt/extra", "/app/pythonpath"):
                        self.assertIn(p, mounts, c["name"])
                main = spec["containers"][0]
                env = {e["name"]: e for e in main["env"]}
                self.assertEqual(env["SUPERSET_PORT"]["value"], "8088")
                self.assertEqual(env["PYTHONPATH"]["value"], "/opt/extra:/app/pythonpath")
                self.assertEqual(env["SUPERSET_CONFIG_PATH"]["value"], "/app/pythonpath/superset_config.py")
                self.assertIs(next(m for m in main["volumeMounts"] if m["mountPath"] == "/opt/extra")["readOnly"], True)
                if kind == "Deployment":
                    self.assertEqual(spec["hostAliases"], [{"ip": "100.64.0.1", "hostnames": ["keycloak.medcea"]}])
                    self.assertEqual(env["REQUESTS_CA_BUNDLE"]["value"], "/etc/medcea-ca/ca.crt")
                    self.assertEqual(env["SUPERSET_DB_USER"]["value"], "svc_superset")
                    for p in ("startupProbe", "readinessProbe", "livenessProbe"):
                        self.assertEqual(main[p]["httpGet"], {"path": "/health", "port": 8088})
                else:
                    self.assertEqual(env["MEDCEA_DATA_DB_USER"]["value"], "svc_superset")
                    self.assertEqual(env["MEDCEA_DATA_DB_PASS"]["valueFrom"]["secretKeyRef"],
                                     {"name": "db-svc-superset", "key": "password"})
                    self.assertIn("bootstrap.py", " ".join(main["command"]))
                    self.assertEqual(spec["restartPolicy"], "Never")
        self.assertEqual(seen, {"Deployment", "Job"})
        dep = next(d for d in r["superset.yaml"][1] if d["kind"] == "Deployment")
        self.assertEqual(dep["spec"]["revisionHistoryLimit"], 0)
        ing = next(d for d in r["superset.yaml"][1] if d["kind"] == "Ingress")
        self.assertEqual(ing["spec"]["tls"], [{"hosts": ["superset.medcea"], "secretName": "cea-tls"}])
        for d in r["superset.yaml"][1]:
            self.assertEqual(d["metadata"]["labels"]["app"], "superset")


class Requirements(unittest.TestCase):
    def test_pinned_and_hashed(self):
        with open(os.path.join(APP, "requirements.txt")) as f:
            lines = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
        pins = {}
        for line in lines:
            m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})", line)
            self.assertTrue(m, line)
            pins[m.group(1).lower()] = tuple(int(x) for x in m.group(2).split("."))
        self.assertEqual(set(pins), {"psycopg2-binary", "authlib", "joserfc"})
        self.assertGreaterEqual(pins["authlib"], (1, 9, 1))     # the October 2026 advisories
        self.assertLess(pins["authlib"], (2,))                   # FAB 5.0.2: Authlib <2.0
        self.assertGreaterEqual(pins["joserfc"], (1, 7, 6))
        self.assertLess(pins["joserfc"], (1, 8))                 # 1.8 needs Python >= 3.11; the image has 3.10


# --- stub modules ---------------------------------------------------------------------

class Session(dict):
    permanent = False


class Resp:
    def __init__(self, body, status=200, mimetype=None, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}


class Args(dict):
    def to_dict(self, flat=True):
        return {k: [v] for k, v in self.items()}


def stub_modules():
    """sys.modules entries for Flask, FAB, Flask-Login and Superset, plus their state."""
    st = types.SimpleNamespace(
        session=Session(), g=types.SimpleNamespace(user=None),
        request=types.SimpleNamespace(args=Args(), path="/", query_string=b""),
        app=types.SimpleNamespace(config={}), user=types.SimpleNamespace(is_authenticated=False),
        logins=[], logouts=[])

    flask = types.ModuleType("flask")
    flask.Response = Resp
    flask.current_app = st.app
    flask.g = st.g
    flask.session = st.session
    flask.request = st.request
    flask.redirect = lambda url: ("redirect", url)
    flask.jsonify = lambda **kw: kw
    login = types.ModuleType("flask_login")

    class _Current:
        def __getattr__(self, name):
            return getattr(st.user, name)
    login.current_user = _Current()
    login.login_user = lambda user, remember=False: st.logins.append((user, remember))
    login.logout_user = lambda: st.logouts.append(True)

    fab = types.ModuleType("flask_appbuilder")
    fab_sec = types.ModuleType("flask_appbuilder.security")
    fab_utils = types.ModuleType("flask_appbuilder.security.utils")
    fab_utils.generate_random_string = lambda: "r" * 30
    fab_views = types.ModuleType("flask_appbuilder.security.views")

    class AuthOAuthView:
        pass
    fab_views.AuthOAuthView = AuthOAuthView
    fab_mgr = types.ModuleType("flask_appbuilder.security.manager")
    fab_mgr.AUTH_OAUTH = 4
    fab_ub = types.ModuleType("flask_appbuilder.utils")
    fab_base = types.ModuleType("flask_appbuilder.utils.base")
    fab_base.get_safe_redirect = lambda url: url if url.startswith("/") and not url.startswith("//") else "/"
    fab_v = types.ModuleType("flask_appbuilder.views")
    fab_v.expose = lambda *a, **k: (lambda f: f)
    sup = types.ModuleType("superset")
    sup_sec = types.ModuleType("superset.security")

    class SupersetSecurityManager:
        register_superset_auth_view = True
        register_superset_registeruser_view = True
    sup_sec.SupersetSecurityManager = SupersetSecurityManager
    mods = {"flask": flask, "flask_login": login, "flask_appbuilder": fab,
            "flask_appbuilder.security": fab_sec, "flask_appbuilder.security.utils": fab_utils,
            "flask_appbuilder.security.views": fab_views, "flask_appbuilder.security.manager": fab_mgr,
            "flask_appbuilder.utils": fab_ub, "flask_appbuilder.utils.base": fab_base,
            "flask_appbuilder.views": fab_v, "superset": sup, "superset.security": sup_sec}
    return mods, st


def load(name, mods):
    """Import apps/superset/<name>.py fresh, with the stub modules in place."""
    import importlib.util
    for m in ("medcea_security", "superset_config", "bootstrap"):
        sys.modules.pop(m, None)
    with mock.patch.dict(sys.modules, mods):
        sys.path.insert(0, APP)
        try:
            spec = importlib.util.spec_from_file_location(name, os.path.join(APP, name + ".py"))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            return mod
        finally:
            sys.path.remove(APP)
            for m in ("medcea_security", "superset_config", "bootstrap"):
                sys.modules.pop(m, None)


CONFIG_ENV = {
    "SUPERSET_SECRET_KEY": "k" * 64, "MEDCEA_NAMESPACE": "medcea",
    "SUPERSET_META_DB_PASS": "meta.pass~1", "KEYCLOAK_DOMAIN": "keycloak.medcea",
    "KEYCLOAK_REALM": "medcea", "SUPERSET_DOMAIN": "superset.medcea", "PORTAL_DOMAIN": "portal.medcea",
    "SUPERSET_CLIENT_SECRET": "client", "SUPERSET_ROLES_MAPPING": json.dumps(MAPPING),
}


class Config(unittest.TestCase):
    def config(self, **env):
        mods, _ = stub_modules()
        with mock.patch.dict(os.environ, dict(CONFIG_ENV, **env), clear=False):
            return load("superset_config", mods)

    def test_values(self):
        c = self.config()
        upper = {k for k in vars(c) if k.isupper()}
        self.assertEqual(c.SECRET_KEY, "k" * 64)
        self.assertEqual(c.AUTH_TYPE, 4)
        self.assertEqual(c.CUSTOM_SECURITY_MANAGER.__name__, "MedceaSecurityManager")
        self.assertIs(c.CUSTOM_SECURITY_MANAGER.register_superset_auth_view, False)
        self.assertIs(c.CUSTOM_SECURITY_MANAGER.register_superset_registeruser_view, False)
        self.assertEqual(c.AUTH_ROLES_MAPPING, MAPPING)
        self.assertIs(c.AUTH_ROLES_SYNC_AT_LOGIN, True)
        self.assertIs(c.AUTH_USER_REGISTRATION_ROLE, None)
        self.assertIs(c.PUBLIC_ROLE_LIKE, None)
        self.assertIn("superset_meta:meta.pass~1@rdbms-postgresql.medcea.svc.cluster.local:5432/superset",
                      c.SQLALCHEMY_DATABASE_URI)
        p = c.OAUTH_PROVIDERS[0]
        self.assertEqual(p["name"], "keycloak")
        ra = p["remote_app"]
        self.assertEqual(ra["client_id"], "superset")
        self.assertEqual(ra["server_metadata_url"],
                         "https://keycloak.medcea/realms/medcea/.well-known/openid-configuration")
        self.assertTrue(ra["api_base_url"].endswith("/protocol/"))
        self.assertIn("groups", ra["client_kwargs"]["scope"].split())
        self.assertEqual(ra["client_kwargs"]["code_challenge_method"], "S256")
        self.assertEqual(c.MEDCEA_CALLBACK_URL, "https://superset.medcea/oauth-authorized/keycloak")
        self.assertEqual(c.PERMANENT_SESSION_LIFETIME, timedelta(minutes=5))
        self.assertIs(c.SESSION_REFRESH_EACH_REQUEST, True)
        self.assertEqual(c.MEDCEA_SESSION_MAX_SECONDS, 3600)
        self.assertIs(c.SESSION_COOKIE_SECURE, True)
        self.assertIs(c.TALISMAN_CONFIG["session_cookie_secure"], True)
        self.assertIs(c.ENABLE_CORS, False)
        self.assertIs(c.ENABLE_PROXY_FIX, True)
        self.assertEqual(c.PROXY_FIX_CONFIG["x_prefix"], 0)
        csp = json.dumps(c.TALISMAN_CONFIG)
        for host in ("scarf", "mapbox", "openstreetmap", "osm.ch", "cartocdn", "terrestris", "document360"):
            self.assertNotIn(host, csp)
        self.assertTrue(c.FEATURE_FLAGS)
        self.assertFalse(any(c.FEATURE_FLAGS.values()))
        self.assertIsNone(c.CELERY_CONFIG)
        self.assertIsNone(c.RESULTS_BACKEND)
        for k in ("CACHE_CONFIG", "DATA_CACHE_CONFIG", "THUMBNAIL_CACHE_CONFIG"):
            self.assertEqual(getattr(c, k), {"CACHE_TYPE": "NullCache"})
        self.assertIs(c.DEBUG, False)
        self.assertIs(c.PREVENT_UNSAFE_DB_CONNECTIONS, True)
        self.assertNotEqual(c.GUEST_TOKEN_JWT_SECRET, "test-guest-secret-change-me")
        self.assertEqual(c.LOGOUT_REDIRECT_URL, c.MEDCEA_LOGOUT_URL)
        self.assertNotIn("id_token_hint", c.MEDCEA_LOGOUT_URL)
        self.assertTrue(c.MEDCEA_LOGOUT_URL.startswith(
            "https://keycloak.medcea/realms/medcea/protocol/openid-connect/logout?client_id=superset&"))
        self.assertIn("post_logout_redirect_uri=https%3A%2F%2Fsuperset.medcea%2F", c.MEDCEA_LOGOUT_URL)
        for k in ("MEDCEA_CALLBACK_URL", "MEDCEA_PORTAL_URL", "MEDCEA_LOGOUT_URL", "FLASK_APP_MUTATOR"):
            self.assertIn(k, upper)  # Superset copies UPPERCASE names only
        app = mock.Mock()
        c.FLASK_APP_MUTATOR(app)
        app.before_request.assert_called_once()

    def test_refusals(self):
        with self.assertRaises(RuntimeError):
            self.config(SUPERSET_SECRET_KEY="short")
        with self.assertRaises(RuntimeError):
            self.config(SUPERSET_SECRET_KEY="CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET_xxxxxxxx")
        for bad in ("{}", "", "[]", json.dumps({"admin": ["Admin"]}),
                    json.dumps({"qa": ["Alpha"]}), json.dumps({"x y": ["Gamma", "MedCEA Viewer"]})):
            with self.assertRaises(ValueError, msg=bad):
                self.config(SUPERSET_ROLES_MAPPING=bad)
        mods, _ = stub_modules()
        env = {k: v for k, v in CONFIG_ENV.items() if k != "SUPERSET_CLIENT_SECRET"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(KeyError):
                load("superset_config", mods)


class FakeRemote:
    def __init__(self, resp=None, error=None):
        self.resp, self.error, self.redirects = resp, error, []

    def authorize_access_token(self):
        if self.error:
            raise self.error
        return self.resp

    def authorize_redirect(self, redirect_uri, state):
        self.redirects.append((redirect_uri, state))
        return ("redirect", "https://keycloak.medcea/auth?state=" + state)


class Security(unittest.TestCase):
    def setUp(self):
        self.mods, self.st = stub_modules()
        self.ms = load("medcea_security", self.mods)
        self.st.app.config.update(
            AUTH_ROLES_MAPPING=MAPPING, MEDCEA_PORTAL_URL="https://portal.medcea/",
            MEDCEA_CALLBACK_URL="https://superset.medcea/oauth-authorized/keycloak",
            MEDCEA_LOGOUT_URL="https://keycloak.medcea/logout", MEDCEA_SESSION_MAX_SECONDS=3600)
        self.auth_calls = []
        self.user = types.SimpleNamespace(name="u")

        sm = self.ms.MedceaSecurityManager()
        sm.oauth_remotes = {"keycloak": FakeRemote()}
        sm.oauth_user_info = sm.get_oauth_user_info
        sm.auth_user_oauth = lambda info: (self.auth_calls.append(info), self.user)[1]
        self.sm = sm
        self.view = self.ms.MedceaOAuthView()
        self.view.appbuilder = types.SimpleNamespace(sm=sm, get_url_for_index="/superset/welcome/")

    def callback(self, groups, next_url="/sqllab/"):
        import jwt
        self.st.session.clear()
        self.st.session.update({"oauth_state": "s" * 30, "_state_keycloak_x": {"data": 1}})
        state = jwt.encode({"next": [next_url]}, "s" * 30, algorithm="HS256")
        self.st.request.args = Args(state=state)
        self.sm.oauth_remotes["keycloak"].resp = {
            "access_token": "AT-sentinel", "userinfo": {"preferred_username": "ana", "groups": groups,
                                                        "email": "ana@x.org"}}
        return self.view.oauth_authorized("keycloak")

    def test_unmapped_person_is_refused_before_a_user_exists(self):
        for groups in ([], ["operator"], ["qa", "auditor"]):
            r = self.callback(groups)
            self.assertIsInstance(r, Resp)
            self.assertEqual(r.status, 403)
            self.assertIn("No access to Superset", r.body)
            self.assertIn("bio_scientist", r.body)
            self.assertIn('href="/logout/"', r.body)
            self.assertEqual(self.auth_calls, [])
            self.assertEqual(self.st.logins, [])

    def test_mapped_person_gets_a_fresh_session(self):
        r = self.callback(["engineer", "operator"])
        self.assertEqual(r, ("redirect", "/sqllab/"))
        self.assertEqual(len(self.auth_calls), 1)
        self.assertEqual(self.auth_calls[0]["username"], "ana")
        self.assertEqual(self.auth_calls[0]["role_keys"], ["engineer", "operator"])
        self.assertEqual(self.st.logins, [(self.user, False)])
        self.assertIs(self.st.session.permanent, True)
        self.assertEqual(set(self.st.session), {self.ms.LOGIN_AT})  # no token, no Authlib state
        self.assertNotIn("AT-sentinel", repr(self.st.session))
        self.assertEqual(self.callback(["qp"], next_url="https://evil.example/")[1], "/")

    def test_failed_sign_ins_render_a_page(self):
        self.sm.oauth_remotes["keycloak"].error = RuntimeError("mismatching_state")
        r = self.callback(["engineer"])
        self.assertEqual(r.status, 400)
        self.assertIn("Try again", r.body)
        self.sm.oauth_remotes["keycloak"].error = None
        self.sm.oauth_remotes["keycloak"].resp = {"userinfo": {"groups": ["engineer"]}}
        self.st.request.args = Args(state="x")
        self.assertEqual(self.view.oauth_authorized("keycloak").status, 400)  # no username
        self.assertEqual(self.view.oauth_authorized("github").status, 404)
        self.assertEqual(self.auth_calls, [])
        # a deactivated Superset user
        self.sm.auth_user_oauth = lambda info: None
        self.assertEqual(self.callback(["engineer"]).status, 403)
        self.assertEqual(self.st.logins, [])

    def test_login_goes_to_keycloak(self):
        self.st.request.query_string = b"next=%2Fsqllab%2F"
        self.assertEqual(self.view.login(), ("redirect", "/login/keycloak?next=%2Fsqllab%2F"))
        self.st.request.args = Args(next="/sqllab/")
        self.view.login("keycloak")
        uri, state = self.sm.oauth_remotes["keycloak"].redirects[-1]
        self.assertEqual(uri, "https://superset.medcea/oauth-authorized/keycloak")
        import jwt
        self.assertEqual(jwt.decode(state, self.st.session["oauth_state"], algorithms=["HS256"]),
                         {"next": ["/sqllab/"]})
        self.assertEqual(self.view.login("github").status, 404)

    def test_logout(self):
        self.st.session.update({"oauth": ("tok", ""), "x": 1})
        self.assertEqual(self.view.logout(), ("redirect", "https://keycloak.medcea/logout"))
        self.assertEqual(dict(self.st.session), {})
        self.assertEqual(self.st.logouts, [True])

    def test_before_request(self):
        import time
        for p in ("/register/", "/register/activation/abc", "/api/v1/security/login",
                  "/api/v1/security/refresh", "/api/v1/security/guest_token/", "/registeruser/form"):
            self.st.request.path = p
            self.assertEqual(self.ms.before_request().status, 404, p)
        self.st.request.path = "/superset/welcome/"
        self.assertIsNone(self.ms.before_request())  # anonymous: FAB sends it to /login/
        self.st.user.is_authenticated = True
        self.st.session[self.ms.LOGIN_AT] = int(time.time()) - 60
        self.assertIsNone(self.ms.before_request())
        self.st.session[self.ms.LOGIN_AT] = int(time.time()) - 3601
        r = self.ms.before_request()
        self.assertEqual(r, ("redirect", "/login/?next=%2Fsuperset%2Fwelcome%2F"))
        self.assertEqual(dict(self.st.session), {})
        self.st.request.path = "/api/v1/chart/"
        r = self.ms.before_request()  # no sign-in time at all
        self.assertEqual(r[1], 401)

    def test_pure_helpers(self):
        ms = self.ms
        self.assertTrue(ms.session_expired(None, 100, 3600))
        self.assertTrue(ms.session_expired(True, 100, 3600))
        self.assertFalse(ms.session_expired(100, 3699, 3600))
        self.assertTrue(ms.session_expired(100, 3700, 3600))
        self.assertTrue(ms.session_expired(10000, 100, 3600))  # from the future
        self.assertEqual(ms.admitted(MAPPING, ["qp", "x", "qp"]), ["qp"])
        with self.assertRaises(ValueError):
            ms.userinfo_from_claims({"groups": ["qp"]})
        self.assertEqual(ms.userinfo_from_claims({"preferred_username": "a", "groups": "qp"})["role_keys"], [])
        self.assertEqual(ms.parse_roles_mapping(json.dumps({"qc": ["MedCEA Viewer", "Gamma"]})),
                         {"qc": ["MedCEA Viewer", "Gamma"]})
        url = ms.end_session_url("kc", "medcea", "superset", "https://s/")
        self.assertNotIn("id_token_hint", url)
        with self.assertRaises(ValueError):
            self.sm.get_oauth_user_info("github", {})


class FakeRole:
    def __init__(self, name, perms=()):
        self.name, self.permissions = name, list(perms)


def pv(p, v):
    return types.SimpleNamespace(permission=types.SimpleNamespace(name=p), view_menu=types.SimpleNamespace(name=v))


class FakeSM:
    def __init__(self, roles, users):
        self.roles, self.users = {r.name: r for r in roles}, users

    def add_role(self, name):
        return self.roles.setdefault(name, FakeRole(name))

    def find_role(self, name):
        return self.roles.get(name)

    def add_permission_view_menu(self, p, v):
        return pv(p, v)

    def add_permission_role(self, role, perm):
        role.permissions.append(perm)

    def del_permission_role(self, role, perm):
        role.permissions.remove(perm)

    def get_all_users(self):
        return self.users

    def update_user(self, user):
        return None


class Bootstrap(unittest.TestCase):
    def setUp(self):
        mods, _ = stub_modules()
        self.b = load("bootstrap", mods)

    def test_data_uri(self):
        env = {"MEDCEA_DATA_DB_USER": "svc_superset", "MEDCEA_DATA_DB_PASS": "p/w",
               "MEDCEA_NAMESPACE": "medcea", "MEDCEA_DATA_DB_NAME": "medcea_db"}
        self.assertEqual(self.b.data_uri(env),
                         "postgresql+psycopg2://svc_superset:p%2Fw@rdbms-postgresql.medcea.svc.cluster.local:5432/medcea_db")
        for user in ("postgres", "", "svc_grafana"):
            with self.assertRaises(self.b.Refused):
                self.b.data_uri(dict(env, MEDCEA_DATA_DB_USER=user))
        with self.assertRaises(self.b.Refused):
            self.b.data_uri(dict(env, MEDCEA_DATA_DB_PASS=""))

    def test_connection(self):
        b = self.b
        added = []

        class DB:
            def __init__(self, **kw):
                self.__dict__.update(kw)
                self.extra = None

            def set_sqlalchemy_uri(self, uri):
                self.uri = uri.replace("pw", "XXXXXXXXXX")

        class Q:
            def __init__(self, row):
                self.row = row

            def filter_by(self, **kw):
                return self

            def first(self):
                return self.row

        session = types.SimpleNamespace(query=lambda cls: Q(None), add=added.append)
        d = b.ensure_connection(session, DB, "postgresql+psycopg2://svc_superset:pw@h/db")
        self.assertEqual(added, [d])
        self.assertEqual(str(d.uuid), b.DB_UUID)
        self.assertEqual(d.database_name, "MedCEA")
        self.assertEqual(b.flag_problems(d), [])
        for k in ("allow_dml", "allow_ctas", "allow_cvas", "allow_file_upload", "allow_run_async", "impersonate_user"):
            self.assertIs(getattr(d, k), False, k)
        self.assertIs(d.expose_in_sqllab, True)
        self.assertIn("default_transaction_read_only=on", d.extra)
        d.allow_dml = True
        self.assertEqual(b.flag_problems(d), ["allow_dml is True, not False"])
        other = DB(database_name="MedCEA", uuid="00000000-0000-0000-0000-000000000000")
        session = types.SimpleNamespace(query=lambda cls: Q(other), add=added.append)
        with self.assertRaises(b.Refused):
            b.ensure_connection(session, DB, "x")

    def test_roles(self):
        b = self.b
        db = types.SimpleNamespace(perm="[MedCEA].(id:3)")
        viewer = FakeRole("MedCEA Viewer", [pv("can_read", "Dashboard"), pv("database_access", "[MedCEA].(id:3)")])
        public = FakeRole("Public", [pv("can_read", "Chart")])
        admin, alpha = FakeRole("Admin"), FakeRole("Alpha")
        users = [types.SimpleNamespace(username="ana", roles=[admin, alpha]),
                 types.SimpleNamespace(username="bo", roles=[alpha])]
        sm = FakeSM([viewer, public, admin, alpha], users)
        b.ensure_viewer_role(sm, db)
        self.assertEqual([(p.permission.name, p.view_menu.name) for p in viewer.permissions],
                         [("database_access", "[MedCEA].(id:3)")])
        sm2 = FakeSM([alpha], [])
        b.ensure_viewer_role(sm2, db)
        self.assertEqual(len(sm2.roles["MedCEA Viewer"].permissions), 1)
        self.assertEqual(b.strip_admins_and_public(sm), ["ana"])
        self.assertEqual([r.name for r in users[0].roles], ["Alpha"])
        self.assertEqual(public.permissions, [])


# --- the scripts, in a scratch tree --------------------------------------------------

STUB_KUBECTL = r"""#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case "$*" in
  "get deployment superset"*) [[ -n "${STUB_DEPLOYED:-}" ]] && exit 0; exit 1 ;;
  *"jsonpath={.spec.replicas}"*) echo 1 ;;
  "get secret superset-secrets"*) printf %s "${STUB_LIVE_MAPPING:-}" | base64 ;;
  "get cm portal-html"*) exit 1 ;;
esac
exit 0
"""


class Scripts(unittest.TestCase):
    def setUp(self):
        self.root = scratch_repo("medcea-superset-")
        shutil.copytree(APP, os.path.join(self.root, "apps", "superset"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.log = os.path.join(self.root, "calls.log")
        bin_dir = os.path.join(self.root, "bin")
        os.makedirs(bin_dir)
        kubectl = os.path.join(bin_dir, "kubectl")
        with open(kubectl, "w") as f:
            f.write(STUB_KUBECTL)
        os.chmod(kubectl, 0o755)
        with open(os.path.join(self.root, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s"; KUBECTL="%s"\n' % (kubectl, kubectl))
        with open(os.path.join(self.root, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n')
        with open(os.path.join(self.root, "infra", "lib-policy-tools.sh"), "w") as f:
            f.write('policy_tool() { echo "policy_tool $*" >> "$STUB_LOG"; '
                    '[[ "$STUB_TOOL_RC" == 0 ]] && echo "$STUB_TOOL_OUT"; return "$STUB_TOOL_RC"; }\n')
        with open(os.path.join(self.root, "config.env"), "w") as f:
            f.write('DOMAIN=medcea\nNAMESPACE=medcea\nPROJECT_NAME=medcea\n')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_script(self, script, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_TOOL_RC": "5", "STUB_TOOL_OUT": ""}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG", "MEDCEA_CONFIRMED"):
            e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, "apps", "superset", script)] + list(args),
                           env=e, capture_output=True, text=True, timeout=60)
        calls = []
        if os.path.exists(self.log):
            with open(self.log) as f:
                calls = f.read().splitlines()
        # medcea_log sends stderr through the same tee as stdout: read both as one text
        r.out = r.stdout + r.stderr
        return r, calls

    def test_syntax(self):
        for s in ("deploy.sh", "uninstall.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)

    def test_unknown_options_exit_2_before_log_and_lock(self):
        for script, args in (("deploy.sh", ["--x"]), ("deploy.sh", ["--gate-only", "--x"]),
                             ("uninstall.sh", ["--purge"]), ("uninstall.sh", ["--purge-data", "x"])):
            r, calls = self.run_script(script, *args)
            self.assertEqual(r.returncode, 2, (script, args, r.stderr))
            self.assertIn("unknown arguments", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
            self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))
            self.assertEqual(calls, [])

    def test_stage_b_skip(self):
        r, calls = self.run_script("deploy.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skipped: Superset is not in the applied access policy yet (stage C)", r.stdout)
        self.assertEqual(calls[0], "init medcea")
        self.assertEqual(calls[-1], "finish medcea superset")
        self.assertIn("policy_tool superset", calls)
        for c in calls:
            self.assertNotRegex(c, r"^(apply|create|scale|delete|exec|rollout)\b", c)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "logs")))  # it logs

    def test_iam_gates_false_skips(self):
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("IAM_GATES=false", r.out)
        self.assertFalse(any(c.startswith(("apply", "scale")) for c in calls))

    def test_broken_policy_refuses(self):
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("finish medcea superset", calls)

    def test_policy_lost_stops_a_running_superset(self):
        r, calls = self.run_script("deploy.sh", STUB_DEPLOYED="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        # deleted, not scaled to 0: deploy-infra re-enables the card and health checks the
        # mapping whenever deployment/superset exists (review of 6 Nov 2026)
        self.assertTrue(any(c.startswith("delete deployment superset -n medcea") for c in calls), calls)
        self.assertFalse(any(c.startswith(("apply", "scale")) for c in calls))

    def test_gate_only(self):
        r, calls = self.run_script("deploy.sh", "--gate-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUPERSET_DOMAIN (superset): not deployed", r.stdout)
        self.assertFalse(any(c.startswith("policy_tool") for c in calls))
        self.assertEqual(calls[-1], "finish medcea superset")
        out = json.dumps(MAPPING, sort_keys=True, separators=(",", ":"))
        r, calls = self.run_script("deploy.sh", "--gate-only", STUB_DEPLOYED="1", STUB_TOOL_RC="0",
                                   STUB_TOOL_OUT=json.dumps(MAPPING), STUB_LIVE_MAPPING=out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUPERSET_DOMAIN (superset): unchanged", r.stdout)
        self.assertFalse(any(c.startswith(("apply", "scale", "rollout")) for c in calls))

    def test_compiled_mapping_is_checked(self):
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="0", STUB_TOOL_OUT='{"admin": ["Admin"]}')
        self.assertEqual(r.returncode, 1)
        self.assertIn("not one Superset accepts", r.out)
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        self.assertEqual(r.returncode, 1)  # the next refusal: no secrets in config.env
        self.assertIn("SUPERSET_SECRET_KEY SUPERSET_META_DB_PASS SUPERSET_CLIENT_SECRET empty", r.out)
        self.assertFalse(any(c.startswith("apply") for c in calls))

    def test_uninstall_keeps_the_data(self):
        r, calls = self.run_script("uninstall.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("delete deployment,job,service,ingress,secret,configmap -n medcea -l app=superset --ignore-not-found", calls)
        self.assertIn("Kept the metadata database", r.stdout)
        self.assertFalse(any(c.startswith("exec") for c in calls))

    def test_dashboards_hold_only_the_readme(self):
        self.assertEqual(sorted(os.listdir(os.path.join(APP, "dashboards"))), ["README.md"])


if __name__ == "__main__":
    unittest.main()
