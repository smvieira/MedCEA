#!/usr/bin/env python3
"""tests/test_postgrest.py — IAM Phase 2b offline checks (stdlib unittest, no cluster).

    python3 tests/test_postgrest.py

- IAM_POSTGREST_JWT=false renders exactly e97aab6's config-api and nginx (the
  goldens in tests/golden/, rendered with NAMESPACE=medcea POSTGRES_PASS=DUMMYPASS):
  the rollback is byte for byte;
- the JWT templates differ from them only by contract C1 (config-api) and by the
  Bearer map and the blanked headers on /api/ (nginx), and every ${VAR} they hold
  is in the render call's list;
- the token lifespan outlives cookie_refresh with margin, and nothing overrides it
  per client;
- no SQL reads request.headers or request.cookies, the down file grants anon no
  EXECUTE but register_mqtt_credential and pre_request, nothing under apps/ points
  a service at another /iam/ or sends X-Test-Who;
- no changed script echoes a password; infra/jwks-sig.py on a Keycloak-shaped set;
- infra/lib-postgrest.sh against a fake kubectl: pgrst_live_mode (rolling only with
  two templates live), pgrst_db_auth_pass (the database deploy's password choice per
  live mode), and the switch order (Secret version on the pod, restart after ALTER,
  nginx before config-api when switching back).
"""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S = os.path.join(ROOT, "apps", "frontend", "k8s")


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def slurp(path):
    """A file's text, or None when it is not UTF-8 text."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        return None


def render(path, env):
    """infra/lib-render.sh's render, with exactly the variables in env."""
    script = 'source "$1/infra/lib-render.sh"; f="$2"; shift 2; render "$f" "$@"'
    out = subprocess.run(["bash", "-c", script, "render", ROOT, path] + sorted(env),
                         env=dict(os.environ, **env), capture_output=True, text=True, check=True)
    return out.stdout


def body(text):
    """A manifest without its leading comment block (the JWT templates explain themselves)."""
    lines = text.splitlines()
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    return lines


def render_calls(script_text, template):
    """The variable lists of every `render …/<template> VAR…` in a script."""
    out = []
    for m in re.finditer(r'render\s+"[^"]*/' + re.escape(template) + r'"((?:\s+[A-Z_][A-Z0-9_]*)*)', script_text):
        out.append(set(m.group(1).split()))
    return out


LEGACY = {"NAMESPACE": "medcea", "POSTGRES_PASS": "DUMMYPASS"}
JWT = {"NAMESPACE": "medcea", "JWKS_CHECKSUM": "0123abcd", "AUTH_SECRET_VERSION": "4242"}

C1_ADDED = [
    "      annotations:",
    '        medcea/jwks-checksum: "0123abcd"',
    '        medcea/auth-secret-version: "4242"',
    "        - name: AUTHENTICATOR_PASSWORD",
    "          valueFrom:",
    "            secretKeyRef:",
    "              name: db-authenticator",
    "              key: password",
    '          value: "postgres://authenticator:$(AUTHENTICATOR_PASSWORD)@rdbms-postgresql.medcea.svc.cluster.local:5432/medcea_db"',
    "        - name: PGRST_JWT_SECRET",
    "          valueFrom:",
    "            secretKeyRef:",
    "              name: medcea-jwks",
    "              key: jwks-sig.json",
    "        - name: PGRST_JWT_AUD",
    '          value: "medcea-api"',
    "        - name: PGRST_JWT_ROLE_CLAIM_KEY",
    '          value: ".medcea_pgrst_role"',
    "        - name: PGRST_DB_PRE_REQUEST",
    '          value: "medcea_auth.pre_request"',
]
C1_REMOVED = [
    '          value: "postgres://authenticator:DUMMYPASS@rdbms-postgresql.medcea.svc.cluster.local:5432/medcea_db"',
]
BLANKED = ["X-Forwarded-Access-Token", "Cookie", "X-Forwarded-User", "X-Forwarded-Email",
           "X-Forwarded-Preferred-Username", "X-Forwarded-Groups"]


def line_diff(a, b):
    """Lines only in a and only in b, as multisets (order-insensitive)."""
    import collections
    ca, cb = collections.Counter(a), collections.Counter(b)
    return sorted((ca - cb).elements()), sorted((cb - ca).elements())


def locations(conf):
    """nginx `location X { … }` blocks by X (one level of braces, as in our confs)."""
    out = {}
    for m in re.finditer(r"location\s+(\S+)\s*\{(.*?)\n\s*\}", conf, re.S):
        out[m.group(1)] = m.group(2)
    return out


class Templates(unittest.TestCase):
    def test_false_renders_e97aab6_exactly(self):
        self.assertEqual(render(os.path.join(K8S, "config-api.yaml"), LEGACY),
                         read("tests", "golden", "config-api.yaml"))
        self.assertEqual(render(os.path.join(K8S, "config-ui-nginx.yaml"), {"NAMESPACE": "medcea"}),
                         read("tests", "golden", "config-ui-nginx.yaml"))

    def test_jwt_config_api_differs_only_by_c1(self):
        jwt = body(render(os.path.join(K8S, "config-api-jwt.yaml"), JWT))
        gold = read("tests", "golden", "config-api.yaml").splitlines()
        removed, added = line_diff(gold, jwt)
        self.assertEqual(removed, sorted(C1_REMOVED))
        self.assertEqual(added, sorted(C1_ADDED))
        text = "\n".join(jwt)
        # $(VAR) expands only from variables listed earlier
        self.assertLess(text.index("name: AUTHENTICATOR_PASSWORD"), text.index("name: PGRST_DB_URI"))
        self.assertNotIn("DUMMYPASS", text)
        self.assertNotIn("POSTGRES_PASS", text)
        self.assertIn("path: /", text)           # the probe stays GET /
        self.assertNotIn("PGRST_ADMIN_SERVER_PORT", text)

    def test_jwt_nginx(self):
        gold = read("tests", "golden", "config-ui-nginx.yaml")
        jwt = "\n".join(body(render(os.path.join(K8S, "config-ui-nginx-jwt.yaml"), {"NAMESPACE": "medcea"})))
        self.assertRegex(jwt, r'map \$http_x_forwarded_access_token \$medcea_pgrst_auth \{\s*""\s+"";\s*'
                              r'default\s+"Bearer \$http_x_forwarded_access_token";\s*\}')
        self.assertIn("never set preserveRequestValue", jwt)
        self.assertLess(jwt.index("map $http"), jwt.index("server {"))
        lj, lg = locations(jwt), locations(gold)
        self.assertEqual(set(lj), set(lg))
        api = lj["/api/"]
        self.assertIn("proxy_set_header Authorization $medcea_pgrst_auth;", api)
        for h in BLANKED:
            self.assertIn('proxy_set_header %s "";' % h, api, h)
        for loc in lg:
            if loc != "/api/":
                self.assertEqual(lj[loc], lg[loc], loc)
        # only /api/ carries the token
        self.assertEqual(jwt.count("$medcea_pgrst_auth"), 2)
        self.assertNotIn("preserveRequestValue", read("k8s", "oauth2-proxy", "values-common.yaml"))
        self.assertNotIn("preserveRequestValue", read("k8s", "oauth2-proxy", "values-app.yaml"))
        self.assertRegex(read("k8s", "oauth2-proxy", "values-app.yaml"), r"pass_access_token\s*=\s*true")
        self.assertRegex(read("k8s", "oauth2-proxy", "values-app.yaml"), r"pass_authorization_header\s*=\s*false")

    def test_render_lists_cover_every_variable(self):
        scripts = read("apps", "frontend", "deploy.sh") + read("infra", "lib-postgrest.sh")
        for tpl in ("config-api.yaml", "config-api-jwt.yaml", "config-ui-nginx.yaml", "config-ui-nginx-jwt.yaml"):
            wanted = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", read("apps", "frontend", "k8s", tpl)))
            calls = render_calls(scripts, tpl)
            self.assertTrue(calls, "no render call for " + tpl)
            for listed in calls:
                self.assertTrue(wanted <= listed, "%s: %s not listed" % (tpl, sorted(wanted - listed)))
        # nothing of either JWT template survives as literal ${…}
        for tpl, env in (("config-api-jwt.yaml", JWT), ("config-ui-nginx-jwt.yaml", {"NAMESPACE": "medcea"})):
            self.assertNotIn("${", render(os.path.join(K8S, tpl), env), tpl)


class Freshness(unittest.TestCase):
    def test_lifespan_outlives_cookie_refresh(self):
        m = re.search(r'"accessTokenLifespan"\s*:\s*(\d+)', read("deploy-infra.sh"))
        self.assertIsNotNone(m, "deploy-infra.sh does not pin accessTokenLifespan")
        life = int(m.group(1))
        # every oauth2-proxy values file; the config proxy's is values-app.yaml
        seen = {}
        for d, _, files in os.walk(ROOT):
            if "/.git" in d:
                continue
            for f in files:
                if f.endswith(".yaml") and "oauth2" in os.path.join(d, f).replace(ROOT, ""):
                    for r in re.finditer(r'^\s*cookie_refresh\s*=\s*"(\d+)([ms])"',
                                         slurp(os.path.join(d, f)) or "", re.M):
                        seen[os.path.join(d, f)] = int(r.group(1)) * (60 if r.group(2) == "m" else 1)
        self.assertIn(os.path.join(ROOT, "k8s", "oauth2-proxy", "values-app.yaml"), seen)
        self.assertEqual(seen[os.path.join(ROOT, "k8s", "oauth2-proxy", "values-app.yaml")], 240)
        for f, refresh in seen.items():
            self.assertLess(refresh + 30, life, f)

    def test_no_client_overrides_the_lifespan(self):
        me = os.path.abspath(__file__)
        pat = re.compile(r"""["']access\.token\.lifespan["']""")
        for d, _, files in os.walk(ROOT):
            if "/.git" in d or "/node_modules" in d or "/.venv" in d:
                continue
            for f in files:
                p = os.path.join(d, f)
                if p == me or not f.endswith((".sh", ".py", ".yaml", ".json", ".ftl", ".js")):
                    continue
                txt = slurp(p)
                if txt is None:
                    continue
                self.assertIsNone(pat.search(txt), p)


class Database(unittest.TestCase):
    def sql_sources(self):
        for d, _, files in os.walk(os.path.join(ROOT, "apps")):
            for f in files:
                if f.endswith(".sql"):
                    yield os.path.join(d, f), slurp(os.path.join(d, f)) or ""
        for mode in ("additive", "enforce"):
            for part in ("functions", "body"):
                out = subprocess.run([sys.executable, os.path.join(ROOT, "apps", "iam", "compiler", "cli.py"),
                                      "compile", "grants", "--mode", mode, "--part", part],
                                     capture_output=True, text=True, check=True).stdout
                yield "grants %s %s" % (mode, part), out

    def test_no_sql_reads_request_headers_or_cookies(self):
        for name, txt in self.sql_sources():
            self.assertNotRegex(txt, r"request\.(headers|cookies)", name)

    def test_down_file_grants_anon_no_other_execute(self):
        txt = read("apps", "database", "medcea_db_migrations_down_008b.sql")
        code = "\n".join(l.split("--", 1)[0] for l in txt.splitlines())
        grants = re.findall(r"GRANT\s+(?:ALL|EXECUTE)[^;]*?\bON\s+(?:ALL\s+)?FUNCTIONS?\b([^;]*?)\bTO\s+([^;]*);", code, re.S | re.I)
        to_anon = [g[0].strip() for g in grants if re.search(r"\banon\b", g[1])]
        self.assertEqual(sorted(to_anon), sorted([
            "medcea.register_mqtt_credential(text, text, integer, text, text)",
            "medcea_auth.pre_request()"]))
        self.assertNotRegex(code, r"DEFAULT PRIVILEGES[^;]*GRANT[^;]*FUNCTIONS[^;]*anon")

    def test_pre_request_exempts_only_the_anonymous_root(self):
        fn = subprocess.run([sys.executable, os.path.join(ROOT, "apps", "iam", "compiler", "cli.py"),
                             "compile", "grants", "--mode", "enforce", "--part", "functions"],
                            capture_output=True, text=True, check=True).stdout
        pre = fn[fn.index("FUNCTION medcea_auth.pre_request()"):]
        pre = pre[:pre.index("$pre$;")]
        no_token = pre[pre.index("IF c IS NULL OR c - 'role'"):pre.index("RAISE EXCEPTION 'no token'")]
        self.assertIn("current_setting('request.method', true) = 'GET'", no_token)
        self.assertIn("current_setting('request.path', true) = '/'", no_token)
        self.assertEqual(pre.count("RETURN;"), 2)   # not enforcing; the anonymous GET /


class Hygiene(unittest.TestCase):
    CHANGED = ["infra/lib-postgrest.sh", "apps/frontend/deploy.sh", "apps/database/deploy.sh",
               "apps/database/uninstall.sh", "health-check.sh", "tests/iam-postgrest.sh",
               "tests/iam-db-fixture.sh"]

    def test_no_test_hooks_under_apps(self):
        for d, _, files in os.walk(os.path.join(ROOT, "apps")):
            for f in files:
                p = os.path.join(d, f)
                txt = slurp(p)
                if txt is None:
                    continue
                self.assertNotIn("X-Test-Who", txt, p)
                if p.endswith(os.path.join("iam", "lib", "medcea_iam.py")):
                    continue   # the library's own defaults
                self.assertNotRegex(txt, r"MEDCEA_IAM_(ROUTES|SETTINGS|JWKS)", p)

    def test_no_password_echoed(self):
        bad = re.compile(r"\b(echo|printf)\b[^|\n]*\$\{?!?[A-Za-z_]*(_PASS|PASSWORD|_pass)\b")
        for rel in self.CHANGED:
            if not os.path.exists(os.path.join(ROOT, rel)):
                continue
            for n, line in enumerate(read(rel).splitlines(), 1):
                s = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
                self.assertNotRegex(s, r"\bset\s+-[a-z]*x", "%s:%d" % (rel, n))
                m = bad.search(s)
                if m and "|" not in s[m.end():]:
                    self.fail("%s:%d may print a password: %s" % (rel, n, line.strip()))


# ── infra/lib-postgrest.sh against a fake kubectl ────────────────────────────────
# FAKE_* variables are the cluster: the deployment's env names, generation and
# observedGeneration, the ReplicaSets' pod counts, the Secret's password (base64).
FAKE_KUBECTL = r"""
fake_kubectl() {
    [[ -n "${FAKE_FAIL:-}" ]] && return 1
    local a="$*"
    case "$a" in
        *"get deployment config-api"*"-o name"*) [[ -n "${FAKE_ENVS+x}" ]] && echo deployment.apps/config-api; return 0 ;;
        *"get deployment config-api"*"env[*]"*) printf '%s\n' $FAKE_ENVS ;;
        *"get deployment config-api"*"generation"*) echo "$FAKE_GEN" ;;
        *"get rs"*) printf '%s\n' $FAKE_RS ;;
        *"get secret db-authenticator"*) printf '%s' "${FAKE_SECRET_B64:-}" ;;
        *) echo "fake_kubectl: unexpected: $a" >&2; return 1 ;;
    esac
}
KUBECTL=fake_kubectl
REPO_ROOT="$1"
_dba_psql() { :; }
source "$REPO_ROOT/infra/lib-postgrest.sh"
"""


def lib(script, **env):
    """Run SCRIPT after sourcing lib-postgrest.sh with the fake kubectl; (rc, stdout, stderr)."""
    p = subprocess.run(["bash", "-c", FAKE_KUBECTL + script, "t", ROOT],
                       env=dict({k: v for k, v in os.environ.items() if not k.startswith("FAKE_")}, **env),
                       capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr


JWT_ENVS = "AUTHENTICATOR_PASSWORD PGRST_DB_URI PGRST_JWT_SECRET PGRST_DB_PRE_REQUEST"
LEGACY_ENVS = "PGRST_DB_URI PGRST_DB_SCHEMAS"


class LiveMode(unittest.TestCase):
    def test_template_modes(self):
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_ENVS=JWT_ENVS, FAKE_GEN="3 3", FAKE_RS="1 0")
        self.assertEqual(out, "jwt")
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_ENVS=LEGACY_ENVS, FAKE_GEN="3 3", FAKE_RS="0 1")
        self.assertEqual(out, "legacy")
        rc, out, _ = lib('pgrst_live_mode medcea-x')
        self.assertEqual(out, "absent")

    def test_single_unready_template_is_its_mode(self):
        # one ReplicaSet with a pod that is not available (a purged authenticator):
        # the old check (availableReplicas != replicas) called this rolling and the
        # database deploy refused the very step that recovers it
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_ENVS=LEGACY_ENVS, FAKE_GEN="5 5", FAKE_RS="1")
        self.assertEqual((rc, out), (0, "legacy"))

    def test_two_templates_live_or_unseen_spec_is_rolling(self):
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_ENVS=JWT_ENVS, FAKE_GEN="4 4", FAKE_RS="1 1")
        self.assertEqual(out, "rolling")
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_ENVS=JWT_ENVS, FAKE_GEN="5 4", FAKE_RS="1")
        self.assertEqual(out, "rolling")

    def test_kubectl_error_is_exit_2(self):
        rc, out, _ = lib('pgrst_live_mode medcea-x', FAKE_FAIL="1")
        self.assertEqual(rc, 2)


class DbAuthPass(unittest.TestCase):
    """apps/database/deploy.sh's choice of authenticator's password (spec S2)."""
    PW = {"POSTGRES_PASS": "pg-legacy", "AUTHENTICATOR_DB_PASS": "auth-config"}
    SHOW = ('if pgrst_db_auth_pass medcea-x "$FLAG"; then '
            'case "$_PGRST_DB_AUTH_PASS" in "$POSTGRES_PASS") w=POSTGRES_PASS ;; "$AUTHENTICATOR_DB_PASS") w=AUTHENTICATOR_DB_PASS ;;'
            ' secret-pw) w=SECRET ;; *) w=other ;; esac; echo "$_PGRST_DB_LIVE $w $_PGRST_DB_WRITE_SECRET"; '
            'else echo "refused $_PGRST_DB_LIVE"; fi')

    def choose(self, flag, **env):
        rc, out, err = lib(self.SHOW, FLAG=flag, **dict(self.PW, **env))
        self.assertEqual(rc, 0, err)
        return out, err

    def test_absent_follows_the_flag(self):
        self.assertEqual(self.choose("true")[0], "absent AUTHENTICATOR_DB_PASS true")
        self.assertEqual(self.choose("false")[0], "absent POSTGRES_PASS true")

    def test_legacy_keeps_postgres_pass_whatever_the_flag(self):
        out, err = self.choose("true", FAKE_ENVS=LEGACY_ENVS, FAKE_GEN="2 2", FAKE_RS="1")
        self.assertEqual(out, "legacy POSTGRES_PASS true")
        self.assertIn("./apps/frontend/deploy.sh switches", err)

    def test_jwt_takes_the_secret_and_leaves_it_alone(self):
        b64 = __import__("base64").b64encode(b"secret-pw").decode()
        out, err = self.choose("true", FAKE_ENVS=JWT_ENVS, FAKE_GEN="2 2", FAKE_RS="1", FAKE_SECRET_B64=b64)
        self.assertEqual(out, "jwt SECRET false")
        self.assertIn("differs from AUTHENTICATOR_DB_PASS", err)
        self.assertNotIn("secret-pw", err)

    def test_jwt_without_its_secret_writes_it(self):
        out, err = self.choose("true", FAKE_ENVS=JWT_ENVS, FAKE_GEN="2 2", FAKE_RS="1")
        self.assertEqual(out, "jwt AUTHENTICATOR_DB_PASS true")

    def test_rolling_and_errors_refuse(self):
        self.assertEqual(self.choose("true", FAKE_ENVS=JWT_ENVS, FAKE_GEN="2 2", FAKE_RS="1 1")[0], "refused rolling")
        self.assertEqual(self.choose("false", FAKE_FAIL="1")[0], "refused error")

    def test_database_deploy_uses_it(self):
        dep = read("apps", "database", "deploy.sh")
        self.assertIn('pgrst_db_auth_pass "$NAMESPACE"', dep)
        self.assertIn('DBPW_authenticator="$_PGRST_DB_AUTH_PASS"', dep)
        self.assertNotIn("get secret db-authenticator", dep)   # one implementation, the tested one
        self.assertIn('"$_PGRST_DB_WRITE_SECRET" != true', dep)


class SwitchOrder(unittest.TestCase):
    def test_password_rotation_rolls_the_pod(self):
        tpl = read("apps", "frontend", "k8s", "config-api-jwt.yaml")
        self.assertIn('medcea/auth-secret-version: "${AUTH_SECRET_VERSION}"', tpl)
        lp = read("infra", "lib-postgrest.sh")
        # the version is read after the Secret's apply and before the template's
        self.assertLess(lp.index("render \"$REPO_ROOT/apps/database/k8s/db-role-secret.yaml\""),
                        lp.index("AUTH_SECRET_VERSION=\"$($KUBECTL get secret db-authenticator"))
        self.assertLess(lp.index("AUTH_SECRET_VERSION=\"$($KUBECTL get secret db-authenticator"),
                        lp.index("render \"$REPO_ROOT/apps/frontend/k8s/config-api-jwt.yaml\""))

    def test_new_pod_restarted_after_the_alter(self):
        lp = read("infra", "lib-postgrest.sh")
        dep = lp[lp.index("pgrst_deploy() {"):]
        a = dep.index('PGRST_NEW_AUTH_PASS="$new_pass" pgrst_set_auth_password')
        self.assertLess(dep.index("_pgrst_wait_started"), a)
        self.assertLess(a, dep.index("_pgrst_kick_unready"))
        self.assertLess(dep.index("_pgrst_kick_unready"), dep.index("rollout status deployment/config-api"))

    def test_restart_only_while_paused(self):
        # unpaused, the new pod can turn ready between the read and the delete, the
        # old one is scaled down, and the delete leaves config-api with no pod
        lp = read("infra", "lib-postgrest.sh")
        dep = lp[lp.index("pgrst_deploy() {"):]
        pause = dep.index("rollout pause deployment/config-api")
        kick = dep.index("_pgrst_kick_unready")
        self.assertLess(dep.index("_pgrst_wait_started"), pause)
        self.assertLess(pause, dep.index('PGRST_NEW_AUTH_PASS="$new_pass" pgrst_set_auth_password'))
        self.assertLess(kick, dep.index('_pgrst_resume "$ns"', kick))
        self.assertLess(dep.index('_pgrst_resume "$ns"', kick), dep.index("rollout status deployment/config-api"))
        # resumed after the preflight (a refusal changes nothing) and before any
        # apply, and before the failure path's undo
        self.assertLess(dep.index("pgrst_preflight"), dep.index('_pgrst_resume "$ns"'))
        self.assertLess(dep.index('_pgrst_resume "$ns"'), dep.index("$KUBECTL apply"))
        fail = dep.index("did not come up in the new mode")
        self.assertLess(dep.index('_pgrst_resume "$ns"', fail), dep.index("rollout undo"))

    def test_frontend_false_stops_tokens_before_config_api(self):
        fe = read("apps", "frontend", "deploy.sh")
        branch = fe.index('if [[ "$IAM_POSTGREST_JWT" == "false" ]] && [[ "$(pgrst_template_mode')
        restart = fe.index("rollout restart deployment/config-ui", branch)
        switch = fe.index('pgrst_deploy "$IAM_POSTGREST_JWT"')
        self.assertLess(branch, restart)
        self.assertLess(restart, switch)
        # the conf rendered in that branch is the legacy one (no Bearer)
        conf = fe[fe.index("_nginx_conf() {"):branch]
        self.assertIn('config-ui-nginx.yaml" NAMESPACE', conf)


SAMPLE = {"keys": [
    {"kid": "zz-enc", "kty": "RSA", "alg": "RSA-OAEP", "use": "enc", "n": "AQAB", "e": "AQAB",
     "x5c": ["MIIC"], "x5t": "a", "x5t#S256": "b"},
    {"kid": "bb-sig", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "nnnn", "e": "AQAB",
     "x5c": ["MIIC"], "x5t": "c", "x5t#S256": "d"},
    {"kid": "aa-sig", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "mmmm", "e": "AQAB", "x5c": ["MIIC"]},
    {"kid": "hs", "kty": "oct", "alg": "HS256", "use": "sig", "k": "secret"},
]}


class JwksSig(unittest.TestCase):
    def run_sig(self, data):
        return subprocess.run([sys.executable, os.path.join(ROOT, "infra", "jwks-sig.py")],
                              input=data, capture_output=True, text=True)

    def test_keycloak_shaped(self):
        p = self.run_sig(json.dumps(SAMPLE))
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        self.assertEqual([k["kid"] for k in got["keys"]], ["aa-sig", "bb-sig"])
        for k in got["keys"]:
            self.assertEqual(sorted(k), ["alg", "e", "kid", "kty", "n", "use"])
        self.assertEqual(p.stdout, json.dumps(got, sort_keys=True, separators=(",", ":")))
        # byte-stable whatever the input order
        again = self.run_sig(json.dumps({"keys": list(reversed(SAMPLE["keys"]))}, indent=2))
        self.assertEqual(again.stdout, p.stdout)
        self.assertNotIn("secret", p.stdout)

    def test_no_signing_key(self):
        for data in (json.dumps({"keys": [SAMPLE["keys"][0]]}), "{}", "not json"):
            p = self.run_sig(data)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(p.stdout, "")
            self.assertIn("jwks-sig:", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=1)
