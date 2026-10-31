#!/usr/bin/env python3
"""IAM 3.3, offline: Node-RED's flows against git, its admin-API token and its settings.js.

- apps/node-red/flows_diff.py (health-check.sh noderedflows, waiver W1's control) as
  health-check runs it (python3 -I, a subprocess): the git flow as deploy.sh renders it is
  OK; a layout move is OK; a key the editor adds is WARN; a changed function body, a deleted
  node or an empty flow list is FAIL; an extra tab is WARN; a sentinel password in the live
  flows never reaches stdout or stderr. `render` refuses a placeholder it cannot fill.
- infra/lib-node-red.sh: nr_flow_values plus the secret placeholders cover every
  placeholder in apps/node-red/flows/*.json; nr_curl sends the token from a pipe (never in
  argv) and no header at all while the Secret is missing (fake kubectl and curl).
- k8s/node-red/settings.js under node (skipped without node): the compiled rights at login,
  none for a role the policy does not list, the deploy token, and the fail-closed fallback.

Run: python3 tests/test_node_red_flows.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIFF = os.path.join(ROOT, "apps", "node-red", "flows_diff.py")
FLOWS = os.path.join(ROOT, "apps", "node-red", "flows")
SENTINEL = "s3ntinel-PW-do-not-print"
sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))


def flow_values(ns="medcea"):
    """nr_flow_values NS, as health-check.sh and deploy.sh get it."""
    out = subprocess.run(["bash", "-c", 'source "$1/infra/lib-node-red.sh"; nr_flow_values "$2"', "-", ROOT, ns],
                         capture_output=True, text=True, env={"PATH": os.environ["PATH"]}, check=True).stdout
    return out


class FlowsDiffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.values = os.path.join(cls.tmp, "values")
        with open(cls.values, "w") as f:
            f.write(flow_values())
        cls.files = sorted(os.path.join(FLOWS, n) for n in os.listdir(FLOWS) if n.endswith(".json"))
        env = dict(os.environ, NR_MQTT_PASS="mqtt-pw", NR_PG_USER="svc_ingest", NR_PG_PASS=SENTINEL)
        nodes = []
        for path in cls.files:
            with open(cls.values) as v:
                r = subprocess.run([sys.executable, "-I", DIFF, "render", path], stdin=v,
                                   capture_output=True, text=True, env=env, check=True)
            nodes += json.loads(r.stdout)
        for n in nodes:   # Node-RED keeps credentials in flows_cred.json, not flows.json
            n.pop("credentials", None)
        cls.deployed = nodes

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_diff(self, live):
        r = subprocess.run([sys.executable, "-I", DIFF, "diff", "--git", FLOWS, "--values", self.values],
                           input=json.dumps(live), capture_output=True, text=True)
        self.assertNotIn(SENTINEL, r.stdout + r.stderr)
        return r.returncode, r.stdout

    def live(self):
        return json.loads(json.dumps(self.deployed))

    def node(self, live, ntype):
        return next(n for n in live if n["type"] == ntype)

    def test_deployed_is_ok(self):
        code, out = self.run_diff(self.live())
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("OK"))

    def test_layout_move_is_ok(self):
        live = self.live()
        for n in live:
            if "x" in n:
                n["x"] += 40
                n["y"] += 20
        self.assertEqual(self.run_diff(live)[0], 0)

    def test_editor_default_key_is_warn(self):
        live = self.live()
        self.node(live, "debug")["targetType"] = "msg"
        code, out = self.run_diff(live)
        self.assertEqual(code, 1, out)
        self.assertIn("targetType", out)

    def test_changed_function_fails_naming_the_node(self):
        live = self.live()
        fn = self.node(live, "function")
        fn["func"] = "return null;"
        code, out = self.run_diff(live)
        self.assertEqual(code, 2)
        self.assertIn(f"changed function {fn['id']}", out)
        self.assertIn("keys func", out)
        self.assertNotIn("return null", out)   # key names, never values

    def test_deleted_node_fails(self):
        live = self.live()
        gone = self.node(live, "postgresql")
        live.remove(gone)
        code, out = self.run_diff(live)
        self.assertEqual(code, 2)
        self.assertIn(f"missing postgresql {gone['id']}", out)

    def test_extra_tab_is_warn(self):
        live = self.live() + [{"id": "t2", "type": "tab", "label": "Experiments"},
                              {"id": "n2", "type": "inject", "z": "t2", "x": 1, "y": 1, "wires": []}]
        code, out = self.run_diff(live)
        self.assertEqual(code, 1, out)
        self.assertIn('not in git: 2 node(s) on "Experiments"', out)

    def test_empty_fails_with_the_hint(self):
        for live in ([], ""):
            r = subprocess.run([sys.executable, "-I", DIFF, "diff", "--git", FLOWS, "--values", self.values],
                               input=live if isinstance(live, str) else json.dumps(live), capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("./apps/node-red/deploy.sh", r.stdout)

    def test_password_change_is_masked_and_unprinted(self):
        live = self.live()
        cfg = self.node(live, "postgreSQLConfig")
        self.assertEqual(cfg["password"], SENTINEL)
        cfg["password"] = SENTINEL + "-changed"
        self.assertEqual(self.run_diff(live)[0], 0)   # dbclients checks the login, not this diff

    def test_unreadable(self):
        r = subprocess.run([sys.executable, "-I", DIFF, "diff", "--git", FLOWS, "--values", self.values],
                           input="{not json", capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)

    def test_render_refuses_a_missing_secret(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NR_")}
        with open(self.values) as v:
            r = subprocess.run([sys.executable, "-I", DIFF, "render", self.files[0]], stdin=v,
                               capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("__PG_PASS__", r.stderr)

    def test_placeholders_covered(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("flows_diff", DIFF)
        fd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fd)
        known = {line.split()[0] for line in flow_values().splitlines()} | set(fd.SECRET_ENV)
        used = set()
        for path in self.files:
            with open(path) as f:
                used |= set(re.findall(r"__[A-Z][A-Z0-9_]*__", f.read()))
        self.assertEqual(used - known, set())
        # no secret in the values health-check passes on (they reach no command line either)
        self.assertEqual({line.split()[0] for line in flow_values().splitlines()} & set(fd.SECRET_ENV), set())
        # deploy.sh fills the secret ones through flows_diff's environment, under these names
        with open(os.path.join(ROOT, "apps", "node-red", "deploy.sh")) as f:
            deploy = f.read()
        for var in fd.SECRET_ENV.values():
            self.assertIn(f'{var}="$', deploy)


FAKE = r"""
fake_kubectl() {
    case "$*" in
        "get secret node-red-admin-tokens -n "*) [[ -n "${FAKE_TOKEN:-}" ]] || return 1; printf '%s' "$FAKE_TOKEN" | base64 ;;
        *) return 1 ;;
    esac
}
curl() {   # records argv and the header file's content
    printf 'ARGV %s\n' "$*"
    local a prev=""
    for a in "$@"; do
        [[ "$prev" == -H && "$a" == @* ]] && printf 'HEADER %s' "$(cat "${a#@}")"
        prev="$a"
    done
    echo
}
KUBECTL=fake_kubectl
REPO_ROOT="$1"
set -euo pipefail
source "$REPO_ROOT/infra/lib-node-red.sh"
nr_token medcea
nr_curl medcea -sf http://localhost:1880/flows
echo "SUB $(nr_curl medcea -s http://localhost:1880/nodes)"
"""


class NrCurlTest(unittest.TestCase):
    def run_fake(self, token):
        env = {"PATH": os.environ["PATH"]}
        if token:
            env["FAKE_TOKEN"] = token
        return subprocess.run(["bash", "-c", FAKE, "-", ROOT], capture_output=True, text=True, env=env)

    def test_token_from_a_pipe(self):
        tok = "a" * 64
        r = self.run_fake(tok)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = [l for l in r.stdout.splitlines() if l.startswith("ARGV")]
        self.assertTrue(argv and all(tok not in l for l in argv), r.stdout)
        self.assertIn(f"HEADER Authorization: Bearer {tok}", r.stdout)
        self.assertIn("SUB ARGV", r.stdout)

    def test_no_secret_no_header(self):
        r = self.run_fake("")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("HEADER", r.stdout)
        self.assertNotIn("-H", r.stdout)
        self.assertEqual(r.stderr.count("no Secret node-red-admin-tokens"), 1)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class SettingsJsTest(unittest.TestCase):
    JS = r"""
const s = require(process.argv[2]);
const a = s.adminAuth;
const out = {type: a.type, autoLogin: a.strategy && a.strategy.autoLogin,
             arity: a.strategy && a.strategy.options.verify.length};
const done = (k) => (err, user) => { out[k] = user; };
(async () => {
  if (a.type === 'strategy') {
    const v = a.strategy.options.verify;
    v('iss', {_json: {preferred_username: 'eng', groups: ['engineer']}}, {}, {}, 't', 'a', 'r', {}, done('login_eng'));
    v('iss', {_json: {preferred_username: 'adm', groups: ['admin']}}, {}, {}, 't', 'a', 'r', {}, done('login_adm'));
    out.eng = await a.users('eng');
    out.adm = await a.users('adm');
    out.unknown = await a.users('nobody');
  }
  out.tok_ok = await a.tokens(process.env.NR_DEPLOY_TOKEN);
  out.tok_bad = await a.tokens('x'.repeat(64));
  out.tok_empty = await a.tokens('');
  console.log(JSON.stringify(out));
})();
"""

    def run_js(self, module=True, policy=True):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        mod = os.path.join(tmp, "passport-openidconnect")
        if module:
            os.makedirs(mod)
            with open(os.path.join(mod, "index.js"), "w") as f:
                f.write("exports.Strategy = function Strategy() {};\n")
        pol = os.path.join(tmp, "permissions.json")
        if policy:
            from compiler import model, tools
            with open(pol, "w") as f:
                json.dump(tools.node_red_permissions(model.load()), f)
        script = os.path.join(tmp, "t.js")
        with open(script, "w") as f:
            f.write(self.JS)
        env = dict(os.environ, NR_ADMIN_AUTH="on", NR_DEPLOY_TOKEN="d" * 64,
                   NR_AUTH_OIDC_MODULE=mod, NR_AUTH_POLICY_FILE=pol, NR_OIDC_CLIENT_SECRET="cs")
        r = subprocess.run(["node", script, os.path.join(ROOT, "k8s", "node-red", "settings.js")],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("d" * 64, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1]), r.stderr

    def test_rights_from_the_policy(self):
        out, _ = self.run_js()
        from compiler import model, tools
        want = tools.node_red_permissions(model.load())["permissions"]["engineer"]
        self.assertEqual(out["type"], "strategy")
        self.assertTrue(out["autoLogin"])
        self.assertEqual(out["arity"], 9)
        self.assertEqual(out["login_eng"], {"username": "eng"})
        self.assertEqual(out["eng"], {"username": "eng", "permissions": sorted(want)})
        self.assertIsNone(out["adm"])        # admin: no editor
        self.assertIsNone(out["unknown"])
        self.assertEqual(out["tok_ok"], {"username": "system:deploy", "permissions": "*"})
        self.assertIsNone(out["tok_bad"])
        self.assertIsNone(out["tok_empty"])

    def test_fails_closed(self):
        for module, policy in ((False, True), (True, False)):
            out, err = self.run_js(module, policy)
            self.assertEqual(out["type"], "credentials")
            self.assertEqual(out["tok_ok"], {"username": "system:deploy", "permissions": "*"})
            self.assertIn("refuses everyone", err)


if __name__ == "__main__":
    unittest.main(verbosity=1)
