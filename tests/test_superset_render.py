#!/usr/bin/env python3
"""tests/test_superset_render.py — apps/superset (stages B and C of "Superset for data
analysis"), offline: no cluster, no image, no lock on the repository.

  Render     the three templates filled by lib-render.sh's `render` with the exact lists
             apps/superset/deploy.sh passes: no ${VAR} left, each list = the template's
             variables, every image pinned by digest, no secret in any plain value (the
             secrets are sentinels that must not appear in a pod spec), non-root uid 1000,
             read-only root, resources, hostAliases, SUPERSET_PORT, service links off,
             the checksum annotation, the hash-checked pip command, which installs from the
             wheel cache only (N10: --no-index, a read-only hostPath, the cache owner's uid),
             the wheel Job's pip download, the sign-out return (N4).
  Requirements  three wheels, each `==` pinned with a sha256, the versions the image's
             Python 3.10 can install, Authlib past the October 2026 advisories.
  Config     superset_config.py loaded with stub Superset/FAB/Flask modules: secrets from
             the environment, a short key, an empty or Admin mapping refused, the session
             limits, no Scarf/Mapbox host in the CSP, CORS off, every risky flag off, the
             end-session's return from MEDCEA_LOGOUT_RETURN (superset_logout_return).
  Security   medcea_security.py's OAuth view with stubs: an unmapped person gets the 403
             page and auth_user_oauth is never called; a mapped one gets a fresh permanent
             session without the access token; logout has no id_token_hint; the 1 h end
             and the blocked routes in before_request.
  Bootstrap  bootstrap.py against fake objects: the connection's flags, its uuid,
             svc_superset only, the viewer role exactly database_access, nobody Admin.
  Deploy     deploy.sh/uninstall.sh in a scratch tree with a stub kubectl and policy:
             unknown options exit 2 before log and lock; "not in the policy, or nobody
             admitted" (policy_tool rc 5) skips with exit 0 and applies nothing;
             IAM_DB_SERVICE_ROLES not true skips (F7) and stops a running one, in both
             modes; true with a postgres fallback dies; --gate-only without a deployment
             says "not deployed" and never compiles; "unchanged" only while the Secret holds
             the compiled mapping and every running pod carries its checksum (a re-render
             that stopped after the Secret converges); an incomplete or root-owned wheel
             cache defers (exit 4) only an addition and stops anything else, never exit 1;
             a policy that lost Superset stops a running one; the full path to the portal
             card (the wheel Job, with its own ConfigMap, only while a wheel is missing, and
             before the Secret: a failed download changes nothing the pods read); the
             pod's checksum is superset_config_checksum of the objects as applied (the stub
             cluster keeps what it was sent), which health recomputes.
  Policy tool  infra/lib-policy-tools.sh's superset branch on has-tool --admitting's
             exit codes (a stub cli.py): 3 is rc 5 with "gives no role a setting yet".

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
    "MEDCEA_LOGOUT_RETURN": "https://ai-workbench.medcea/hub/logout",
    "SUPERSET_WHEEL_DIR": "/var/lib/medcea/superset-wheels",
    "SUPERSET_WHEEL_UID": "1234", "SUPERSET_WHEEL_GID": "1235",
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
        self.assertEqual(template_vars(os.path.join(K8S, "superset-wheels.yaml")), set(bash_array("_WHEEL_VARS")))

    def rendered(self):
        env = all_env()
        out = {}
        for name, lst in (("superset.yaml", "_POD_VARS"), ("superset-init.yaml", "_POD_VARS"),
                          ("superset-secret.yaml", "_SECRET_VARS"), ("superset-wheels.yaml", "_WHEEL_VARS")):
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
                for flag in ("--isolated", "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-cache-dir",
                             "--no-index"):
                    self.assertIn(flag, cmd)
                # the wheel cache only (N10): no index, so a pod start needs no PyPI
                self.assertNotIn("--index-url", cmd)
                self.assertNotIn("pypi.org", " ".join(cmd))
                self.assertEqual(cmd[cmd.index("--find-links") + 1], "/wheels")
                self.assertEqual(cmd[cmd.index("--target") + 1], "/opt/extra")
                self.assertEqual(cmd[cmd.index("-r") + 1], "/app/pythonpath/requirements.txt")
                dsc = deps[0]["securityContext"]
                self.assertEqual((dsc["runAsUser"], dsc["runAsGroup"]), (1234, 1235))  # the cache's owner
                dm = {m["mountPath"]: m for m in deps[0]["volumeMounts"]}
                self.assertEqual((dm["/wheels"]["name"], dm["/wheels"]["readOnly"]), ("wheels", True))
                vols = {v["name"]: v for v in spec["volumes"]}
                self.assertEqual(vols["wheels"]["hostPath"],
                                 {"path": "/var/lib/medcea/superset-wheels", "type": "Directory"})
                for c in spec["containers"]:  # the main container never sees the cache
                    self.assertNotIn("/wheels", [m["mountPath"] for m in c["volumeMounts"]])
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
                self.assertEqual(env["MEDCEA_LOGOUT_RETURN"]["value"], "https://ai-workbench.medcea/hub/logout")
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

    def test_wheel_job(self):
        docs = self.rendered()["superset-wheels.yaml"][1]
        self.assertEqual(len(docs), 1)
        job = docs[0]
        self.assertEqual((job["kind"], job["metadata"]["name"], job["metadata"]["labels"]["app"]),
                         ("Job", "superset-wheels", "superset"))  # uninstall's -l app=superset
        spec = job["spec"]["template"]["spec"]
        self.assertEqual(spec["securityContext"]["runAsUser"], 1234)
        self.assertIs(spec["securityContext"]["runAsNonRoot"], True)
        self.assertIs(spec["automountServiceAccountToken"], False)
        (c,) = spec["containers"]
        self.assertEqual(c["image"], IMAGE)
        cmd = c["command"]
        self.assertEqual(cmd[:2], ["/usr/local/bin/pip3", "download"])
        for flag in ("--isolated", "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-cache-dir"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("--dest") + 1], "/wheels")
        self.assertEqual(cmd[cmd.index("-r") + 1], "/app/pythonpath/requirements.txt")
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
        self.assertNotIn("readOnly", mounts["/wheels"])
        self.assertIs(mounts["/app/pythonpath"]["readOnly"], True)
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(vols["wheels"]["hostPath"], {"path": "/var/lib/medcea/superset-wheels", "type": "Directory"})
        self.assertEqual(vols["config"]["configMap"]["name"], "superset-wheels")   # never superset-config
        self.assertNotIn("envFrom", c)
        for e in c.get("env", []):
            self.assertNotRegex(e["name"], "PASS|SECRET|KEY")


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
    "MEDCEA_LOGOUT_RETURN": "https://ai-workbench.medcea/hub/logout",
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
        # N4: Keycloak returns into the platform's one-hop chain, not to Superset itself
        self.assertIn("post_logout_redirect_uri=https%3A%2F%2Fai-workbench.medcea%2Fhub%2Flogout", c.MEDCEA_LOGOUT_URL)
        self.assertEqual(c.MEDCEA_LOGOUT_RETURN, "https://ai-workbench.medcea/hub/logout")
        c = self.config(MEDCEA_LOGOUT_RETURN="https://portal.medcea/oauth2/sign_out?rd=%2F")
        self.assertTrue(c.MEDCEA_LOGOUT_URL.endswith(
            "&post_logout_redirect_uri=https%3A%2F%2Fportal.medcea%2Foauth2%2Fsign_out%3Frd%3D%252F"), c.MEDCEA_LOGOUT_URL)
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
        for bad in ("http://portal.medcea/", "", "https://x y"):
            with self.assertRaises(RuntimeError, msg=bad):
                self.config(MEDCEA_LOGOUT_RETURN=bad)
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

# Read verbs answer from $STUB_DIR; every call is logged by its arguments (never stdin);
# a manifest on stdin is consumed (and kept in applied.yaml); the wheel Job's apply
# "downloads" by copying $STUB_WHEEL_SRC into $STUB_WHEEL_DST. The cluster keeps what it
# is sent (stub_store.py): Secret superset-secrets → secret.json, ConfigMap
# superset-config → cm.json (`create configmap --dry-run` renders its --from-file
# arguments), Deployment superset → pods.json, one Running pod with the template's
# annotations; deleting the Deployment removes it. So a checksum read before the apply
# differs from one read after it.
STUB_KUBECTL = r"""#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case " $* " in *" -f - "*|*" -i "*) in="$(cat)" ;; esac
store() { printf '%s' "$in" | python3 "$(dirname "$0")/stub_store.py" "$@"; }
case "$*" in
  "get deployment superset"*) [[ -n "${STUB_DEPLOYED:-}" ]] && exit 0; exit 1 ;;
  *"jsonpath={.spec.replicas}"*) echo 1 ;;
  "get secret superset-secrets"*"SUPERSET_ROLES_MAPPING"*)
    if [[ -n "${STUB_LIVE_MAPPING:-}" ]]; then printf %s "$STUB_LIVE_MAPPING" | base64
    else in=""; store mapping || exit 1; fi ;;
  "get secret superset-secrets -n medcea -o json") cat "$STUB_DIR/secret.json" 2>/dev/null || exit 1 ;;
  "get configmap superset-config -n medcea -o json") cat "$STUB_DIR/cm.json" 2>/dev/null || exit 1 ;;
  "get pod -n medcea -l app=superset,component=web -o json")
    [[ -z "${STUB_PODS_FAIL:-}" ]] || exit 1
    cat "$STUB_DIR/pods.json" 2>/dev/null || echo '{"items": []}' ;;
  "get storageclass microk8s-hostpath"*) printf %s "${STUB_PVDIR:-}" ;;
  "get pod -n medcea -l app.kubernetes.io/name=postgresql"*) printf rdbms-postgresql-0 ;;
  "get job superset-wheels"*) printf %s "${STUB_WHEELS_JOB:-1/}" ;;
  "get job superset-init"*) printf 1/ ;;
  "get cm portal-html"*) exit 1 ;;
  "create configmap "*"--dry-run=client -o yaml") in=""; store cm "$@" ;;
  "label --local -f - "*) printf '%s\n' "$in" ;;
  "delete deployment superset "*) rm -f "$STUB_DIR/pods.json" ;;
  "apply --server-side "*) store apply ;;
  "apply -f -")
    printf '%s\n---\n' "$in" >> "$STUB_DIR/applied.yaml"
    store apply
    if grep -q "name: superset-wheels" <<<"$in" && grep -q "kind: Job" <<<"$in" && [[ -n "${STUB_WHEEL_SRC:-}" ]]; then
        cp "$STUB_WHEEL_SRC"/*.whl "$STUB_WHEEL_DST"/
    fi ;;
esac
exit 0
"""
STUB_STORE = r"""
import base64, json, os, sys
import yaml
d, mode = os.environ["STUB_DIR"], sys.argv[1]
if mode == "mapping":   # the live Secret's SUPERSET_ROLES_MAPPING, base64 as jsonpath gives it
    try:
        print(json.load(open(os.path.join(d, "secret.json")))["data"]["SUPERSET_ROLES_MAPPING"], end="")
    except Exception:
        sys.exit(1)
elif mode == "cm":      # create configmap NAME -n NS --from-file=K=PATH... --dry-run=client -o yaml
    args = sys.argv[2:]
    data = {}
    for a in args:
        if a.startswith("--from-file="):
            k, path = a[len("--from-file="):].split("=", 1)
            data[k] = open(path).read()
    print(yaml.safe_dump({"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": args[2], "namespace": args[args.index("-n") + 1]}, "data": data}))
else:                   # apply: keep the objects the checksum and the pods are read from
    for doc in yaml.safe_load_all(sys.stdin.read()):
        if not doc:
            continue
        kind, name = doc.get("kind"), doc["metadata"]["name"]
        if (kind, name) == ("Secret", "superset-secrets"):
            data = {k: base64.b64encode(str(v).encode()).decode() for k, v in (doc.get("stringData") or {}).items()}
            data.update(doc.get("data") or {})
            json.dump({"kind": "Secret", "data": data}, open(os.path.join(d, "secret.json"), "w"))
        elif (kind, name) == ("ConfigMap", "superset-config"):
            json.dump({"kind": "ConfigMap", "data": doc.get("data") or {}}, open(os.path.join(d, "cm.json"), "w"))
        elif (kind, name) == ("Deployment", "superset"):
            ann = doc["spec"]["template"]["metadata"].get("annotations") or {}
            json.dump({"items": [{"metadata": {"name": "superset-new", "annotations": ann},
                                  "status": {"phase": "Running"}}]}, open(os.path.join(d, "pods.json"), "w"))
"""

FAKE_WHEELS = {"psycopg2_binary-2.9.9-cp310-cp310-manylinux_2_17_x86_64.whl": b"fake psycopg2 wheel\n",
               "authlib-1.9.5-py2.py3-none-any.whl": b"fake authlib wheel\n",
               "joserfc-1.7.7-py3-none-any.whl": b"fake joserfc wheel\n"}
CONFIG_SECRETS = {"SUPERSET_SECRET_KEY": "s" * 64, "SUPERSET_META_DB_PASS": "metaPass.0123456789",
                  "SUPERSET_CLIENT_SECRET": "clientSecret0123456789", "SVC_SUPERSET_DB_PASS": "svcPass0123456789"}


class Scripts(unittest.TestCase):
    def setUp(self):
        import hashlib
        self.root = scratch_repo("medcea-superset-")
        shutil.copytree(APP, os.path.join(self.root, "apps", "superset"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(os.path.join(REPO, "infra", "pg-scram.py"), os.path.join(self.root, "infra", "pg-scram.py"))
        self.log = os.path.join(self.root, "calls.log")
        self.stub = os.path.join(self.root, "stub")
        os.makedirs(self.stub)
        bin_dir = os.path.join(self.root, "bin")
        os.makedirs(bin_dir)
        kubectl = os.path.join(bin_dir, "kubectl")
        with open(kubectl, "w") as f:
            f.write(STUB_KUBECTL)
        os.chmod(kubectl, 0o755)
        with open(os.path.join(bin_dir, "stub_store.py"), "w") as f:
            f.write(STUB_STORE)
        self.bin = bin_dir
        with open(os.path.join(self.root, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s"; KUBECTL="%s"\n' % (kubectl, kubectl))
        with open(os.path.join(self.root, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    # the state the version guard asks for (apps/iam/deploy.sh's call)
                    'policy_db_state() { echo "policy_db_state $1" >> "$STUB_LOG"; [[ -n "${STUB_PS_FAIL:-}" ]] && return 1; '
                    'echo "${STUB_PS_STATE:-version-3}"; }\n')
        with open(os.path.join(self.root, "infra", "lib-policy-tools.sh"), "w") as f:
            f.write('policy_tool() { echo "policy_tool $*" >> "$STUB_LOG"; '
                    '[[ "$STUB_TOOL_RC" == 0 ]] && echo "$STUB_TOOL_OUT"; return "$STUB_TOOL_RC"; }\n')
        # db_client as it answers under IAM 2.5; _dba_psql (exec in the pod) stays the real one
        with open(os.path.join(self.root, "infra", "lib-db-roles.sh"), "w") as f:
            f.write('source "$REPO_ROOT/apps/database/lib-db-apply.sh"\n'
                    'db_client() { echo "db_client $*" >> "$STUB_LOG"; DBC_USER="${STUB_DBC_USER:-svc_superset}"; '
                    'DBC_SECRET=db-svc-superset; DBC_SECRET_KEY=password; DBC_PASS=x; }\n')
        with open(os.path.join(self.root, "infra", "lib-wait.sh"), "w") as f:
            f.write('wait_for_http() { echo "wait_for_http $*" >> "$STUB_LOG"; }\n')
        self.pvdir = os.path.join(self.root, "pv")
        self.wheels = os.path.join(self.root, "wheels")
        self.src = os.path.join(self.root, "wheel-src")
        os.makedirs(self.src)
        lines = []
        for n, data in FAKE_WHEELS.items():
            with open(os.path.join(self.src, n), "wb") as f:
                f.write(data)
            pin = {"psycopg2": "psycopg2-binary==2.9.9", "authlib": "Authlib==1.9.5", "joserfc": "joserfc==1.7.7"}
            lines.append("%s --hash=sha256:%s" % (pin[n.split("-")[0].split("_")[0]], hashlib.sha256(data).hexdigest()))
        # the scratch copy pins the fake wheels, so the cache check can be complete
        with open(os.path.join(self.root, "apps", "superset", "requirements.txt"), "w") as f:
            f.write("# scratch pins\n" + "\n".join(lines) + "\n")
        self.write_config()

    def write_config(self, **extra):
        conf = dict(DOMAIN="medcea", NAMESPACE="medcea", PROJECT_NAME="medcea", **extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def full_config(self, **extra):
        conf = dict(CONFIG_SECRETS, IAM_DB_SERVICE_ROLES="true", SUPERSET_WHEEL_DIR=self.wheels,
                    KEYCLOAK_REALM="medcea", PLATFORM_IP="100.64.0.1", WORKBENCH_ENABLED="true")
        conf.update(extra)
        self.write_config(**conf)

    def live_objects(self, mapping=MAPPING, cm_extra=""):
        """Secret superset-secrets and ConfigMap superset-config as the stub cluster answers them
        (CM_EXTRA appended to every file: an older ConfigMap than the tree's)."""
        import base64
        data = dict(CONFIG_SECRETS, SUPERSET_ROLES_MAPPING=json.dumps(mapping, sort_keys=True, separators=(",", ":")))
        data.pop("SVC_SUPERSET_DB_PASS")
        with open(os.path.join(self.stub, "secret.json"), "w") as f:
            json.dump({"kind": "Secret", "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}, f)
        cm = {}
        for n in ("superset_config.py", "medcea_security.py", "bootstrap.py", "requirements.txt"):
            with open(os.path.join(self.root, "apps", "superset", n)) as f:
                cm[n] = f.read() + cm_extra
        with open(os.path.join(self.stub, "cm.json"), "w") as f:
            json.dump({"kind": "ConfigMap", "data": cm}, f)

    def running_pod(self, checksum):
        """One running web pod started with CHECKSUM (medcea/config-checksum)."""
        with open(os.path.join(self.stub, "pods.json"), "w") as f:
            json.dump({"items": [{"metadata": {"name": "superset-old", "annotations": {"medcea/config-checksum": checksum}},
                                  "status": {"phase": "Running"}}]}, f)

    def fill_cache(self):
        os.makedirs(self.wheels, mode=0o700, exist_ok=True)
        for n in FAKE_WHEELS:
            shutil.copy(os.path.join(self.src, n), self.wheels)

    def root_owned_stat(self):
        """A PATH dir whose stat says the wheel cache belongs to root (a sudo cp/chown by hand)."""
        d = os.path.join(self.root, "rootstat")
        os.makedirs(d, exist_ok=True)
        real = shutil.which("stat")
        with open(os.path.join(d, "stat"), "w") as f:
            f.write('#!/bin/bash\nfor a; do [[ "$a" == "%s" ]] && { echo 0; exit 0; }; done\nexec %s "$@"\n'
                    % (self.wheels, real))
        os.chmod(os.path.join(d, "stat"), 0o755)
        return d + ":" + os.environ["PATH"]

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_script(self, script, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub, "STUB_TOOL_RC": "5", "STUB_TOOL_OUT": "",
                              "STUB_PVDIR": self.pvdir, "STUB_WHEEL_DST": self.wheels}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG", "MEDCEA_CONFIRMED", "IAM_DB_SERVICE_ROLES",
                  "SUPERSET_WHEEL_DIR", "WORKBENCH_ENABLED"):
            e.pop(k, None)
        e.update({k: v for k, v in env.items() if k in ("IAM_DB_SERVICE_ROLES",)})
        r = subprocess.run(["bash", os.path.join(self.root, "apps", "superset", script)] + list(args),
                           env=e, capture_output=True, text=True, timeout=120)
        calls = []
        if os.path.exists(self.log):
            with open(self.log) as f:
                calls = f.read().splitlines()
            os.remove(self.log)
        # medcea_log sends stderr through the same tee as stdout: read both as one text
        r.out = r.stdout + r.stderr
        for v in CONFIG_SECRETS.values():
            self.assertNotIn(v, r.out + "\n".join(calls))
        return r, calls

    def applied(self):
        p = os.path.join(self.stub, "applied.yaml")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [d for d in yaml.safe_load_all(f.read()) if d]

    def test_syntax(self):
        for s in ("deploy.sh", "uninstall.sh", "lib-superset.sh"):
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

    def test_not_in_the_policy_skips(self):
        # policy_tool rc 5: no superset tool block, or (stage C, F1) its group gives no role
        # a setting yet; the same skip either way
        r, calls = self.run_script("deploy.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skipped: Superset is not in the applied access policy, or no role is given a setting", r.stdout)
        self.assertNotIn("stage C", r.out)
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

    def test_service_roles_false_skips_and_stops(self):
        # F7: an install whose config.env keeps IAM_DB_SERVICE_ROLES=false, with the tool in the
        # policy: a skip, exit 0, before any secret is asked for or any object applied
        for deployed in ("", "1"):
            with self.subTest(deployed=bool(deployed)):
                r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING),
                                           STUB_DEPLOYED=deployed)
                self.assertEqual(r.returncode, 0, r.out)
                self.assertIn("skipped: Superset needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)",
                              r.stdout)
                self.assertNotIn("empty in config.env", r.out)
                self.assertEqual(calls[-1], "finish medcea superset")
                self.assertFalse(any(c.startswith(("apply", "scale", "exec", "db_client")) for c in calls), calls)
                stopped = any(c.startswith("delete deployment superset -n medcea") for c in calls)
                self.assertEqual(stopped, bool(deployed), calls)
        # --gate-only on a running one stops it too, so a rollback of the switch never
        # strands a pod
        r, calls = self.run_script("deploy.sh", "--gate-only", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING),
                                   STUB_DEPLOYED="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("SUPERSET_DOMAIN (superset): re-rendered (stopped", r.stdout)
        self.assertIn("IAM_DB_SERVICE_ROLES is not true", r.stdout)
        self.assertTrue(any(c.startswith("delete deployment superset -n medcea") for c in calls), calls)
        self.assertFalse(any(c.startswith(("apply", "scale")) for c in calls))

    def test_service_roles_true_with_a_postgres_fallback_dies(self):
        # under true a fallback is a fault (a missing Secret or password), not a skip
        self.full_config()
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING),
                                   STUB_DBC_USER="postgres")
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("would log in as postgres, not svc_superset", r.out)
        self.assertNotIn("finish medcea superset", calls)
        self.assertFalse(any(c.startswith(("apply", "exec")) for c in calls), calls)

    def test_no_applied_version_skips_and_says_what_to_run(self):
        # the iam bootstrap waited (state empty) or 008c is missing (none): the mapping came
        # from defaults.yaml, so a skip, exit 0, before any secret or object; after the
        # bootstrap nothing redeploys Superset, so the message names the command
        self.full_config()
        tool = dict(STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        for st in ("empty", "none"):
            for deployed in ("", "1"):
                with self.subTest(state=st, deployed=bool(deployed)):
                    r, calls = self.run_script("deploy.sh", STUB_PS_STATE=st, STUB_DEPLOYED=deployed, **tool)
                    self.assertEqual(r.returncode, 0, r.out)
                    self.assertIn(f"skipped: no version of the access policy is applied yet (state {st})", r.stdout)
                    self.assertIn("run ./apps/superset/deploy.sh once ./apps/iam/deploy.sh has applied version 1",
                                  r.stdout)
                    self.assertNotIn("Sign-in roles", r.out)
                    self.assertIn("policy_db_state medcea", calls)
                    self.assertEqual(calls[-1], "finish medcea superset")
                    self.assertFalse(any(c.startswith(("apply", "scale", "exec", "create", "db_client")) for c in calls),
                                     calls)
                    stopped = any(c.startswith("delete deployment superset -n medcea") for c in calls)
                    self.assertEqual(stopped, bool(deployed), calls)
                    self.assertFalse(os.path.exists(self.wheels))   # not even the cache
        # asked after the earlier skips: not in the policy, or IAM_DB_SERVICE_ROLES false,
        # need no database
        r, calls = self.run_script("deploy.sh", STUB_PS_STATE="empty")
        self.assertIn("skipped: Superset is not in the applied access policy", r.stdout)
        self.assertNotIn("policy_db_state medcea", calls)
        # unreadable, or a state the init should have refused: a failure, never a skip
        for env in (dict(STUB_PS_FAIL="1"), dict(STUB_PS_STATE="partial")):
            with self.subTest(**env):
                r, calls = self.run_script("deploy.sh", **env, **tool)
                self.assertEqual(r.returncode, 1, r.out)
                self.assertIn("./apps/iam/apply.sh --status", r.out)
                self.assertNotIn("finish medcea superset", calls)
                self.assertFalse(any(c.startswith(("apply", "exec", "delete")) for c in calls), calls)
        # --gate-only does not ask: apply.sh runs it with a version applied
        self.fill_cache()
        r, calls = self.run_script("deploy.sh", "--gate-only", STUB_PS_STATE="empty", **tool)
        self.assertNotIn("policy_db_state medcea", calls)

    def test_gate_only(self):
        r, calls = self.run_script("deploy.sh", "--gate-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUPERSET_DOMAIN (superset): not deployed", r.stdout)
        self.assertFalse(any(c.startswith("policy_tool") for c in calls))
        self.assertEqual(calls[-1], "finish medcea superset")
        self.full_config()
        self.live_objects()
        self.running_pod(self.checksum())
        r, calls = self.run_script("deploy.sh", "--gate-only", STUB_DEPLOYED="1", STUB_TOOL_RC="0",
                                   STUB_TOOL_OUT=json.dumps(MAPPING))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUPERSET_DOMAIN (superset): unchanged", r.stdout)
        self.assertFalse(any(c.startswith(("apply", "create", "scale", "rollout", "delete")) for c in calls))
        self.assertFalse(os.path.exists(self.wheels))  # an unchanged gate never needs the cache

    def test_gate_only_is_not_unchanged_while_a_pod_runs_an_older_secret(self):
        # the Secret holds the compiled mapping, but the running pod was started before it
        # (a re-render or full deploy that died after _apply_secret; the mapping is a
        # secretKeyRef env, read at start only): drift, re-rendered, so apply.sh's next
        # attempt and --resume converge instead of printing "unchanged"
        self.full_config()
        self.fill_cache()
        self.live_objects()
        tool = dict(STUB_DEPLOYED="1", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        for pods in ("stale", "unreadable"):
            with self.subTest(pods=pods):
                self.running_pod("0" * 64)
                r, calls = self.run_script("deploy.sh", "--gate-only", STUB_PODS_FAIL="1" if pods == "unreadable" else "",
                                           **tool)
                if pods == "unreadable":   # the re-render's own check cannot read them either
                    self.assertEqual(r.returncode, 1, r.out)
                    self.assertIn("still carries another configuration", r.out)
                else:
                    self.assertEqual(r.returncode, 0, r.out)
                    self.assertIn("SUPERSET_DOMAIN (superset): re-rendered (role mapping)", r.stdout)
                self.assertNotIn("unchanged", r.stdout)
                self.assertTrue(any(c.startswith("rollout status deployment/superset") for c in calls), calls)
        # the re-render left a current pod: the next run is unchanged
        r, calls = self.run_script("deploy.sh", "--gate-only", **tool)
        self.assertIn("SUPERSET_DOMAIN (superset): unchanged", r.stdout)

    def test_gate_only_defers_only_an_addition_and_stops_anything_else(self):
        # a re-render restarts the pod, whose init container installs from the cache only;
        # --gate-only never downloads. Exit 4 (apply.sh's apply_deferred, supersetroles
        # dropped from step 9, never a revert) only while the running Superset admits a
        # subset of what the policy gives, the same way; otherwise it fails closed
        self.full_config()
        tool = dict(STUB_DEPLOYED="1", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        added = {"engineer": MAPPING["engineer"]}                       # the policy adds two roles
        narrowed = dict(MAPPING, control_scientist=["Alpha", "sql_lab"])  # the policy took one away
        changed = dict(MAPPING, qp=["Alpha", "sql_lab"])                   # the policy made qp a viewer
        cases = [("absent", added, True, "wheel cache %s does not exist" % self.wheels),
                 ("partial", added, True, "lacks psycopg2-binary==2.9.9 Authlib==1.9.5"),
                 ("absent", narrowed, True, "does not exist"),
                 ("partial", changed, True, "lacks"),
                 ("absent", added, False, "does not exist")]                # the pod runs an unknown Secret
        for cache, live, current, why in cases:
            with self.subTest(cache=cache, live=sorted(live), current=current):
                shutil.rmtree(self.wheels, ignore_errors=True)
                if cache == "partial":
                    os.makedirs(self.wheels, mode=0o700)
                    shutil.copy(os.path.join(self.src, "joserfc-1.7.7-py3-none-any.whl"), self.wheels)
                self.live_objects(live)
                self.running_pod(self.checksum() if current else "0" * 64)
                if os.path.exists(os.path.join(self.stub, "applied.yaml")):
                    os.remove(os.path.join(self.stub, "applied.yaml"))
                r, calls = self.run_script("deploy.sh", "--gate-only", **tool)
                self.assertIn(why, r.out)
                for c in calls:
                    self.assertNotRegex(c, r"^(apply|create|scale|rollout)\b", c)
                self.assertEqual(self.applied(), [])
                stopped = any(c.startswith("delete deployment superset -n medcea") for c in calls)
                if live is added and current:
                    self.assertEqual(r.returncode, 4, r.out)
                    self.assertIn("SUPERSET_DOMAIN (superset): deferred", r.out)
                    self.assertNotIn("finish medcea superset", calls)   # a deferral ends no break-glass
                    self.assertFalse(stopped, calls)
                else:
                    self.assertEqual(r.returncode, 0, r.out)
                    self.assertIn("SUPERSET_DOMAIN (superset): re-rendered (stopped", r.stdout)
                    self.assertEqual(calls[-1], "finish medcea superset")
                    self.assertTrue(stopped, calls)

    def test_gate_only_never_fails_on_the_cache(self):
        # a root-owned cache, or one inside the volumes' directory: a deferral or a stop as
        # for a missing wheel, never exit 1 (rollout() would revert the version for it)
        self.full_config()
        self.fill_cache()
        tool = dict(STUB_DEPLOYED="1", STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        for setup, why in (("root", "belongs to root"), ("pvdir", "is inside the volumes' directory")):
            for live, rc in (({"engineer": MAPPING["engineer"]}, 4), (dict(MAPPING, qc=["Gamma", "MedCEA Viewer"]), 0)):
                with self.subTest(setup=setup, rc=rc):
                    env = dict(tool)
                    if setup == "root":
                        env["PATH"] = self.root_owned_stat()
                    else:
                        self.full_config(SUPERSET_WHEEL_DIR=os.path.join(self.pvdir, "wheels"))
                    self.live_objects(live)
                    self.running_pod(self.checksum())
                    r, calls = self.run_script("deploy.sh", "--gate-only", **env)
                    self.assertEqual(r.returncode, rc, r.out)
                    self.assertIn(why, r.out)
                    self.assertFalse(any(c.startswith(("apply", "create", "scale", "rollout")) for c in calls), calls)
            self.full_config()

    def test_gate_only_rerenders_a_drifted_mapping(self):
        self.full_config()
        self.fill_cache()
        old = {"engineer": MAPPING["engineer"]}
        self.live_objects(old)
        before = self.checksum()
        self.running_pod(before)
        r, calls = self.run_script("deploy.sh", "--gate-only", STUB_DEPLOYED="1", STUB_TOOL_RC="0",
                                   STUB_TOOL_OUT=json.dumps(MAPPING))
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("SUPERSET_DOMAIN (superset): re-rendered (role mapping)", r.stdout)
        self.assertFalse(any("superset-wheels" in c for c in calls), calls)  # never a download
        dep = next(d for d in self.applied() if d["kind"] == "Deployment")
        ann = dep["spec"]["template"]["metadata"]["annotations"]["medcea/config-checksum"]
        # the checksum of the Secret as applied (the new mapping), not the one read before
        self.assertEqual(ann, self.checksum())
        self.assertNotEqual(ann, before)
        with open(os.path.join(self.stub, "secret.json")) as f:
            import base64
            live = json.loads(base64.b64decode(json.load(f)["data"]["SUPERSET_ROLES_MAPPING"]))
        self.assertEqual(live, MAPPING)

    def checksum(self):
        """superset_config_checksum against the stub cluster, as health-check.sh calls it."""
        e = clean_env(STUB_LOG=os.devnull, STUB_DIR=self.stub, KUBECTL=os.path.join(self.root, "bin", "kubectl"))
        r = subprocess.run(["bash", "-c", 'source "$1"; superset_config_checksum medcea',
                            "x", os.path.join(self.root, "apps", "superset", "lib-superset.sh")],
                           env=e, capture_output=True, text=True, check=True)
        self.assertRegex(r.stdout.strip(), r"^[0-9a-f]{64}$")
        return r.stdout.strip()

    def test_full_path(self):
        # every step against the stub cluster: the cache filled by the wheel Job (only while
        # a wheel is missing), the init Job, the web pod, the portal card
        self.full_config()
        self.live_objects({"engineer": MAPPING["engineer"]}, cm_extra="# an older ConfigMap\n")
        before = self.checksum()
        tool = dict(STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING), STUB_WHEEL_SRC=self.src)
        r, calls = self.run_script("deploy.sh", **tool)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("Superset deployed: https://superset.medcea", r.stdout)
        self.assertNotEqual(self.checksum(), before)   # the stub kept the applied objects
        self.assertIn("downloading into the wheel cache", r.stdout)
        self.assertEqual(os.stat(self.wheels).st_mode & 0o777, 0o700)
        self.assertEqual(calls[-1], "finish medcea superset")
        self.assertIn("db_client medcea svc_superset", calls)
        self.assertIn("wait_for_http https://superset.medcea/health 180 Superset", calls)
        order = [c for c in calls if c.startswith(("exec -i", "apply --server-side", "apply -f -", "rollout status"))]
        db = next(c for c in order if c.startswith("exec -i"))
        self.assertTrue(db.startswith("exec -i -n medcea rdbms-postgresql-0"), order)  # the metadata database
        self.assertLess(order.index(db), order.index(next(c for c in order if c.startswith("apply --server-side"))))
        # the wheel cache before the metadata database and the Secret: a failed download
        # changes nothing the running pod reads
        self.assertLess(calls.index(next(c for c in calls if c.startswith("create configmap superset-wheels"))),
                        calls.index(db))
        self.assertIn("delete job,configmap superset-wheels -n medcea --ignore-not-found", calls)
        docs = self.applied()
        kinds = [(d["kind"], d["metadata"]["name"]) for d in docs if d.get("kind") in ("Job", "Deployment")]
        self.assertEqual(kinds, [("Job", "superset-wheels"), ("Job", "superset-init"), ("Deployment", "superset")])
        cms = [d for d in docs if d.get("kind") == "ConfigMap"]
        self.assertEqual([(d["metadata"]["name"], sorted(d["data"])) for d in cms],
                         [("superset-wheels", ["requirements.txt"]),
                          ("superset-config", ["bootstrap.py", "medcea_security.py", "requirements.txt",
                                               "superset_config.py"])])
        uid = os.getuid()
        for d in docs:
            if d.get("kind") in ("Job", "Deployment"):
                spec = d["spec"]["template"]["spec"]
                for c in spec.get("initContainers", []):
                    self.assertEqual(c["securityContext"]["runAsUser"], uid)
                if d["metadata"]["name"] != "superset-wheels":
                    self.assertEqual(d["spec"]["template"]["metadata"]["annotations"]["medcea/config-checksum"],
                                     self.checksum())
        dep = docs[[k for k in ((d.get("kind"), d["metadata"]["name"]) for d in docs)].index(("Deployment", "superset"))]
        env = {e["name"]: e.get("value") for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["MEDCEA_LOGOUT_RETURN"], "https://ai-workbench.medcea/hub/logout")
        # a second run: the cache is complete, no wheel Job
        os.remove(os.path.join(self.stub, "applied.yaml"))
        self.full_config(WORKBENCH_ENABLED="false")
        r, calls = self.run_script("deploy.sh", **tool)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("wheel cache complete", r.stdout)
        self.assertFalse(any("superset-wheels" in c for c in calls), calls)
        dep = next(d for d in self.applied() if d["kind"] == "Deployment")
        env = {e["name"]: e.get("value") for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["MEDCEA_LOGOUT_RETURN"], "https://portal.medcea/oauth2/sign_out?rd=%2F")

    def test_full_path_refuses_a_failed_download_and_the_pv_dir(self):
        self.full_config()
        self.live_objects()
        tool = dict(STUB_TOOL_RC="0", STUB_TOOL_OUT=json.dumps(MAPPING))
        r, calls = self.run_script("deploy.sh", STUB_WHEELS_JOB="/1", **tool)
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("wheels could not be downloaded", r.out)
        self.assertIn("the running Superset (if any) is unchanged", r.out)
        self.assertFalse(any("superset-init" in c for c in calls), calls)
        # and it is: no Secret, no superset-config, no metadata database
        self.assertFalse(any(c.startswith(("apply --server-side", "exec")) for c in calls), calls)
        self.assertFalse(any(c.startswith("create configmap superset-config") for c in calls), calls)
        r, calls = self.run_script("deploy.sh", **tool)   # the Job "succeeded" but wrote nothing
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("still lacks", r.out)
        self.full_config(SUPERSET_WHEEL_DIR=os.path.join(self.pvdir, "wheels"))
        r, calls = self.run_script("deploy.sh", **tool)
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("is inside the volumes' directory", r.out)
        self.assertFalse(any(c.startswith(("exec", "apply")) for c in calls), calls)
        self.full_config(SUPERSET_WHEEL_DIR="relative/dir")
        r, calls = self.run_script("deploy.sh", **tool)
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("must be an absolute path", r.out)

    def test_compiled_mapping_is_checked(self):
        r, calls = self.run_script("deploy.sh", STUB_TOOL_RC="0", STUB_TOOL_OUT='{"admin": ["Admin"]}')
        self.assertEqual(r.returncode, 1)
        self.assertIn("not one Superset accepts", r.out)
        self.write_config(IAM_DB_SERVICE_ROLES="true")
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


class ConfigChecksum(unittest.TestCase):
    """superset_config_checksum: the data of the live Secret and ConfigMap, nothing else."""

    def run_lib(self, secret, cm):
        tmp = tempfile.mkdtemp(prefix="medcea-ss-sum-")
        try:
            kubectl = os.path.join(tmp, "kubectl")
            with open(kubectl, "w") as f:
                f.write('#!/bin/sh\ncase "$*" in\n'
                        '  "get secret superset-secrets -n ns -o json") cat "%s/s.json" ;;\n'
                        '  "get configmap superset-config -n ns -o json") cat "%s/c.json" ;;\n'
                        '  *) exit 9 ;;\nesac\n' % (tmp, tmp))
            os.chmod(kubectl, 0o755)
            for n, doc in (("s.json", secret), ("c.json", cm)):
                if doc is not None:
                    with open(os.path.join(tmp, n), "w") as f:
                        f.write(doc if isinstance(doc, str) else json.dumps(doc))
            r = subprocess.run(["bash", "-c", 'source "$1"; superset_config_checksum ns',
                                "x", os.path.join(APP, "lib-superset.sh")],
                               env=clean_env(KUBECTL=kubectl), capture_output=True, text=True)
            return r.returncode, r.stdout.strip(), r.stderr
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_digest(self):
        import base64
        b64 = lambda v: base64.b64encode(v.encode()).decode()
        sec = {"kind": "Secret", "metadata": {"name": "superset-secrets", "resourceVersion": "1"},
               "data": {"SUPERSET_SECRET_KEY": b64("k" * 64), "SUPERSET_ROLES_MAPPING": b64('{"qp":["Gamma"]}')}}
        cm = {"kind": "ConfigMap", "metadata": {"name": "superset-config"}, "data": {"a.py": "x = 1\n"}}
        rc, one, err = self.run_lib(sec, cm)
        self.assertEqual(rc, 0, err)
        self.assertRegex(one, r"^[0-9a-f]{64}$")
        self.assertNotIn("k" * 64, one + err)
        # metadata does not count; a value, a key or a file does
        sec2 = json.loads(json.dumps(sec))
        sec2["metadata"]["resourceVersion"] = "2"
        self.assertEqual(self.run_lib(sec2, cm)[1], one)
        sec2["data"]["SUPERSET_ROLES_MAPPING"] = b64('{"qc":["Gamma"]}')
        self.assertNotEqual(self.run_lib(sec2, cm)[1], one)
        cm2 = dict(cm, data={"a.py": "x = 2\n"})
        self.assertNotEqual(self.run_lib(sec, cm2)[1], one)
        # missing or unreadable: rc 1, nothing printed
        for s_, c_ in ((None, cm), (sec, None), ("not json", cm), (sec, {"kind": "Secret"})):
            rc, out, _ = self.run_lib(s_, c_)
            self.assertEqual((rc, out), (1, ""))

    def test_wheel_dir_and_missing(self):
        lib = os.path.join(APP, "lib-superset.sh")
        def run(cmd, **env):
            return subprocess.run(["bash", "-c", 'source "$1"; ' + cmd, "x", lib],
                                  env=clean_env(**env), capture_output=True, text=True)
        e = {k: v for k, v in clean_env().items() if k != "SUPERSET_WHEEL_DIR"}
        r = subprocess.run(["bash", "-c", 'source "$1"; PROJECT_NAME=demo superset_wheel_dir', "x", lib],
                           env=e, capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "/var/lib/demo/superset-wheels")
        self.assertEqual(run("superset_wheel_dir", SUPERSET_WHEEL_DIR="/srv/w/").stdout.strip(), "/srv/w")
        for bad in ("srv/w", "/srv/../etc", "/srv/w x", "/"):
            r = run("superset_wheel_dir", SUPERSET_WHEEL_DIR=bad)
            self.assertEqual(r.returncode, 1, bad)
        tmp = tempfile.mkdtemp(prefix="medcea-ss-whl-")
        try:
            import hashlib
            with open(os.path.join(tmp, "a-1-py3-none-any.whl"), "wb") as f:
                f.write(b"A")
            req = os.path.join(tmp, "req.txt")
            with open(req, "w") as f:
                f.write("# c\na==1 --hash=sha256:%s\nb==2 --hash=sha256:%s\n"
                        % (hashlib.sha256(b"A").hexdigest(), "0" * 64))
            r = run('superset_wheels_missing "$D" "$R"', D=tmp, R=req)
            self.assertEqual((r.returncode, r.stdout.split()), (0, ["b==2"]))
            r = run('superset_wheels_missing "$D/none" "$R"', D=tmp, R=req)
            self.assertEqual(r.returncode, 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        # the real pins: one line each, as the deploy's check reads them
        with open(os.path.join(APP, "requirements.txt")) as f:
            n = sum(1 for l in f if "--hash=sha256:" in l and not l.lstrip().startswith("#"))
        self.assertEqual(n, 3)


class PolicyTool(unittest.TestCase):
    """infra/lib-policy-tools.sh's superset branch against a stub cli.py (has-tool exit codes)."""

    def run_tool(self, has_tool_rc, compile_out='{"qp": ["Gamma", "MedCEA Viewer"]}', **env):
        root = tempfile.mkdtemp(prefix="medcea-ss-pt-")
        try:
            os.makedirs(os.path.join(root, "apps", "iam", "compiler"))
            log = os.path.join(root, "cli.log")
            with open(os.path.join(root, "apps", "iam", "compiler", "cli.py"), "w") as f:
                f.write("import sys\nopen(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
                        "if sys.argv[1] == 'has-tool':\n    sys.exit(%d)\nprint(%r)\n" % (log, has_tool_rc, compile_out))
            r = subprocess.run(["bash", "-c", 'source "$1"; policy_tool superset', "x",
                                os.path.join(REPO, "infra", "lib-policy-tools.sh")],
                               env=clean_env(**dict({"REPO_ROOT": root, "IAM_GATES": "true"}, **env)), capture_output=True, text=True)
            calls = []
            if os.path.exists(log):
                with open(log) as f:
                    calls = f.read().splitlines()
            return r.returncode, r.stdout.strip(), r.stderr, calls
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_exit_codes(self):
        rc, out, err, calls = self.run_tool(0)
        self.assertEqual((rc, out), (0, '{"qp": ["Gamma", "MedCEA Viewer"]}'))
        self.assertEqual(calls, ["has-tool superset --admitting", "compile superset"])
        rc, out, err, calls = self.run_tool(1)
        self.assertEqual((rc, out), (5, ""))
        self.assertIn("no group has a superset tool block", err)
        self.assertEqual(calls, ["has-tool superset --admitting"])
        # F1: the tool block without cells (the skeleton version before its change version)
        rc, out, err, calls = self.run_tool(3)
        self.assertEqual((rc, out), (5, ""))
        self.assertIn("Superset's policy group gives no role a setting yet", err)
        self.assertEqual(calls, ["has-tool superset --admitting"])   # never compiled
        for broken in (2, 7):
            self.assertEqual(self.run_tool(broken)[:2], (1, ""))
        rc, out, err, calls = self.run_tool(0, IAM_GATES="false")
        self.assertEqual((rc, out, calls), (3, "", []))


if __name__ == "__main__":
    unittest.main()
