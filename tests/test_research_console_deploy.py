#!/usr/bin/env python3
"""tests/test_research_console_deploy.py — research Phase 4e, commit A2: the research console's platform wiring
(codeplan/rs4e-design.md §1, §5.1, §6, §9; owner decisions of 27 Nov 2026).

Offline (stdlib unittest + PyYAML), in scratch trees with a fake cluster:
  Manifest   k8s/console.yaml rendered: the render list, the pinned image, no token, no Secret, no hostPath, the
             unpack init container identical to research-agents', the page and iam mounts, the html annotation.
  Values     k8s/values-console.yaml: the two upstreams in the research-agents namespace, medcea-research as the
             extra audience, pass_access_token, cookie_refresh 240 s, no /_account/; app_gate's APP_GATE_VARS.
  Page       page.py: MANIFEST.json (canonical, signout, a key per static name, vendor/ dropped), the ConfigMap
             (annotation = sha256 of the manifest), names console.py would not serve and the size limit refused.
  Deploy     apps/research-console/deploy.sh: --help, unknown options exit 2 before log and lock, each skip line,
             the refusals, the full path (page, page server, its proxy through app_gate, the card), --gate-only.
  Uninstall  the proxy, its 403 page, -l app=research-console, the card; nothing of the orchestrator.
  Wiring     chained from apps/research/deploy.sh after research-agents and first in its uninstall; deploy-apps
             POLICY_COMPILING; the bundle holds console.py; the orchestrator's RS_CONSOLE_ORIGIN; the portal card
             and render list; _SVC_DOMAINS; config.env.example; deploy-infra's client block; medcea.sh.
  Health     rsconsole against a fake kubectl: SKIP without the host or the Deployment, OK, every FAIL and WARN.

  python3 tests/test_research_console_deploy.py
"""
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402
import test_health_phase5 as h5  # noqa: E402

APP = os.path.join(REPO, "apps", "research-console")
AG, RNS = "medcea-research-agents", "medcea-research"
PINS = json.load(open(os.path.join(REPO, "apps", "research-model", "pins.json")))
SIGNOUT = "https://agents.medcea/oauth2/sign_out?rd=x"


def read(p):
    with open(os.path.join(REPO, p) if not os.path.isabs(p) else p) as f:
        return f.read()


def code(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def sh(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


def render(rel, **env):
    names = sorted(env)
    r = subprocess.run(["bash", "-c", 'source infra/lib-render.sh; render "$@"', "-", rel] + names, cwd=REPO,
                       env=clean_env(**env), capture_output=True, text=True, check=True)
    return r.stdout


def load_page():
    import importlib.util
    spec = importlib.util.spec_from_file_location("rc_page", os.path.join(APP, "page.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Manifest(unittest.TestCase):
    LISTED = "RESEARCH_AGENTS_NAMESPACE CONSOLE_IMAGE CONSOLE_HTML_SHA256 RS_CODE_COMMIT RS_BUNDLE_SHA256".split()

    def setUp(self):
        self.text = render("apps/research-console/k8s/console.yaml", RESEARCH_AGENTS_NAMESPACE=AG,
                           CONSOLE_IMAGE=PINS["python_image"], CONSOLE_HTML_SHA256="ab" * 32, RS_CODE_COMMIT="c" * 40,
                           RS_BUNDLE_SHA256="d" * 64)
        self.docs = [d for d in yaml.safe_load_all(self.text) if d]
        self.dep = [d for d in self.docs if d["kind"] == "Deployment"][0]
        self.pod = self.dep["spec"]["template"]["spec"]

    def test_the_render_list(self):
        src = read("apps/research-console/k8s/console.yaml")
        head = re.search(r"Render list: ([A-Z0-9_ \n#]+?)\n# A static", src).group(1).replace("#", " ").split()
        self.assertEqual(head, self.LISTED)
        self.assertEqual(set(re.findall(r"\$\{([A-Z0-9_]+)\}", code(src))), set(self.LISTED))
        self.assertNotIn("${", self.text)
        dep = read("apps/research-console/deploy.sh")
        self.assertIn('render "$APP_DIR/k8s/console.yaml" ' + " ".join(self.LISTED), dep)

    def test_hardening_no_token_no_secret(self):
        self.assertEqual([(d["kind"], d["metadata"]["name"]) for d in self.docs],
                         [("Deployment", "research-console"), ("Service", "research-console")])
        self.assertIs(self.pod["automountServiceAccountToken"], False)
        self.assertIs(self.pod["enableServiceLinks"], False)
        self.assertNotIn("serviceAccountName", self.pod)
        self.assertEqual(self.pod["priorityClassName"], "medcea-research-low")
        sc = self.pod["securityContext"]
        self.assertEqual((sc["runAsUser"], sc["runAsNonRoot"], sc["seccompProfile"]["type"]), (65534, True, "RuntimeDefault"))
        for c in self.pod["containers"] + self.pod["initContainers"]:
            self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True, c["name"])
            self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
            self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
            self.assertEqual(c["image"], PINS["python_image"])
        text = json.dumps(self.pod)
        for bad in ("secret", "Secret", "hostPath", "hostNetwork", "NodePort"):
            self.assertNotIn(bad, text)
        main = self.pod["containers"][0]
        self.assertEqual(main["name"], "console")
        self.assertEqual(main["resources"], {"requests": {"cpu": "50m", "memory": "96Mi"}, "limits": {"memory": "192Mi"}})
        self.assertEqual(self.dep["spec"]["revisionHistoryLimit"], 0)
        self.assertEqual(main["command"], ["python3", "/opt/medcea/apps/research-console/console.py"])
        for p in ("readinessProbe", "livenessProbe"):
            self.assertIn("127.0.0.1:8080/healthz", " ".join(main[p]["exec"]["command"]))
        svc = self.docs[1]
        self.assertEqual((svc["spec"]["type"], svc["spec"]["ports"][0]["port"]), ("ClusterIP", 8080))
        # part-of is never medcea-research: research-agents' uninstall removes that label in this namespace
        self.assertEqual(self.dep["metadata"]["labels"]["app.kubernetes.io/part-of"], "medcea-research-console")

    def test_mounts_and_annotations(self):
        vols = {v["name"]: v for v in self.pod["volumes"]}
        self.assertEqual(vols["html"], {"name": "html", "configMap": {"name": "research-console-html"}})
        self.assertEqual(vols["iam"]["configMap"], {"name": "medcea-iam-lib", "optional": True})
        self.assertEqual(vols["jwks"]["configMap"], {"name": "medcea-jwks", "optional": True})
        self.assertEqual(vols["bundle"]["configMap"], {"name": "research-code"})
        self.assertEqual(vols["wheels"]["persistentVolumeClaim"], {"claimName": "research-wheels", "readOnly": True})
        mounts = {m["mountPath"]: m for m in self.pod["containers"][0]["volumeMounts"]}
        for path in ("/srv", "/iam", "/jwks", "/opt/medcea"):
            self.assertTrue(mounts[path]["readOnly"], path)
        ann = self.dep["spec"]["template"]["metadata"]["annotations"]
        self.assertEqual(ann["medcea/html-sha256"], "ab" * 32)

    def test_the_unpack_is_research_agents(self):
        ag = [d for d in yaml.safe_load_all(read("apps/research-agents/k8s/agents.yaml")) if d and d["kind"] == "Deployment"]
        theirs = ag[0]["spec"]["template"]["spec"]["initContainers"][0]
        mine = self.pod["initContainers"][0]
        self.assertEqual(mine["command"], theirs["command"])
        self.assertEqual(mine["volumeMounts"], theirs["volumeMounts"])


class Values(unittest.TestCase):
    def test_upstreams_audience_and_no_account(self):
        src = read("apps/research-console/k8s/values-console.yaml")
        self.assertEqual(set(re.findall(r"\$\{([A-Z_]+)\}", code(src))),
                         {"KEYCLOAK_DOMAIN", "KEYCLOAK_REALM", "NAMESPACE", "ALLOWED_GROUPS", "RESEARCH_AGENTS_NAMESPACE"})
        text = render("apps/research-console/k8s/values-console.yaml", KEYCLOAK_DOMAIN="keycloak.medcea", KEYCLOAK_REALM="medcea",
                      NAMESPACE="medcea", ALLOWED_GROUPS='["bio_scientist"]', RESEARCH_AGENTS_NAMESPACE=AG)
        conf = yaml.safe_load(text)["configuration"]["content"]
        self.assertIn('upstreams = ["http://research-console.%s.svc.cluster.local:8080/", '
                      '"http://research-orchestrator.%s.svc.cluster.local:8090/api/"]' % (AG, AG), conf)
        for want in ('oidc_extra_audiences = ["medcea-research"]', "pass_access_token = true", 'cookie_refresh = "240s"',
                     "skip_oidc_discovery = true", 'provider = "oidc"', "skip_provider_button = true",
                     'allowed_groups = ["bio_scientist"]', 'custom_templates_dir = "/templates"',
                     "cookie_secure = true", 'cookie_samesite = "lax"'):
            self.assertIn(want, conf)
        self.assertNotIn("_account", conf)
        self.assertNotIn("${", text)

    def test_app_gate_vars(self):
        """APP_GATE_VARS adds names to app_gate's render list; unset, every other call renders what it did."""
        lib = read("infra/lib-oauth2-proxy.sh")
        body = lib[lib.index("app_gate() {"):]
        body = body[:body.index("\n}\n")]
        self.assertEqual(body.count("ALLOWED_GROUPS ${APP_GATE_VARS:-} > \"$values\""), 2)
        dep = read("apps/research-console/deploy.sh")
        self.assertIn('APP_GATE_VARS=RESEARCH_AGENTS_NAMESPACE app_gate "$_MODE" "$RELEASE" research-console', dep)
        self.assertNotIn("APP_GATE_VARS", "".join(read(p) for p in ("apps/frontend/deploy.sh", "apps/monitor/deploy.sh",
                                                                    "apps/scheduler/deploy.sh", "apps/mqtt-explorer/deploy.sh")))

    def test_logout_url(self):
        lib = os.path.join(REPO, "infra", "lib-oauth2-proxy.sh")
        for wb, back in (("true", "https://ai-workbench.medcea/hub/logout"),
                         ("false", "https://portal.medcea/oauth2/sign_out?rd=%2F")):
            r = subprocess.run(["bash", "-c", 'source "$1"; research_console_logout_url', "-", lib], capture_output=True, text=True,
                               env=clean_env(RESEARCH_CONSOLE_DOMAIN="agents.medcea", KEYCLOAK_DOMAIN="keycloak.medcea",
                                             KEYCLOAK_REALM="medcea", WORKBENCH_ENABLED=wb, WORKBENCH_DOMAIN="ai-workbench.medcea",
                                             PORTAL_DOMAIN="portal.medcea"))
            self.assertEqual(r.returncode, 0, r.stderr)
            import urllib.parse
            url = r.stdout.strip()
            self.assertTrue(url.startswith("https://agents.medcea/oauth2/sign_out?rd="), url)
            end = urllib.parse.unquote(url.split("rd=", 1)[1])
            self.assertTrue(end.startswith("https://keycloak.medcea/realms/medcea/protocol/openid-connect/logout?"
                                           "client_id=research-console&post_logout_redirect_uri="), end)
            self.assertEqual(urllib.parse.unquote(end.split("post_logout_redirect_uri=", 1)[1]), back)
            self.assertNotIn("id_token_hint", url)


class Page(unittest.TestCase):
    def setUp(self):
        self.page = load_page()
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "vendor", "uplot"))
        for rel, body in (("index.html", b"<!doctype html>"), ("console.js", b"x=1"), ("vendor/uplot/uPlot.min.js", b"u"),
                          ("vendor/uplot/LICENSE", b"MIT"), ("logo.png", b"\x89PNG\x00\xff"), (".hidden", b"no")):
            with open(os.path.join(self.d, rel), "wb") as f:
                f.write(body)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_the_manifest(self):
        raw, fs = self.page.manifest(SIGNOUT, self.d)
        doc = json.loads(raw)
        self.assertEqual(raw, json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(doc["signout"], SIGNOUT)
        self.assertEqual(sorted(doc["files"]), ["console.js", "index.html", "logo.png", "uplot/LICENSE", "uplot/uPlot.min.js"])
        self.assertEqual(doc["files"]["uplot/uPlot.min.js"], {"key": "uplot__uPlot.min.js", "sha256": hashlib.sha256(b"u").hexdigest()})

    def test_the_configmap(self):
        cm = self.page.configmap(AG, SIGNOUT, self.d)
        raw = cm["data"]["MANIFEST.json"].encode()
        self.assertEqual(cm["metadata"]["annotations"]["medcea/console-sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((cm["metadata"]["name"], cm["metadata"]["namespace"]), ("research-console-html", AG))
        self.assertEqual(cm["metadata"]["labels"]["app"], "research-console")
        self.assertEqual(base64.b64decode(cm["binaryData"]["logo.png"]), b"\x89PNG\x00\xff")
        self.assertEqual(cm["data"]["uplot__uPlot.min.js"], "u")
        self.assertNotIn(".hidden", json.dumps(cm))

    def test_refusals(self):
        os.makedirs(os.path.join(self.d, "a", "b"))
        with open(os.path.join(self.d, "a", "b", "c.js"), "w") as f:
            f.write("x")
        with self.assertRaises(self.page.PageError):
            self.page.manifest(SIGNOUT, self.d)     # two slashes: console.py would not serve it
        shutil.rmtree(os.path.join(self.d, "a"))
        with self.assertRaises(self.page.PageError):
            self.page.manifest("http://agents.medcea/x", self.d)
        with open(os.path.join(self.d, "big.js"), "w") as f:
            f.write("x" * (self.page.LIMIT + 1))
        with self.assertRaises(self.page.PageError):
            self.page.configmap(AG, SIGNOUT, self.d)
        os.remove(os.path.join(self.d, "index.html"))
        r = subprocess.run([sys.executable, os.path.join(APP, "page.py"), "sha", SIGNOUT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)   # the repository's own page builds
        self.assertEqual(subprocess.run([sys.executable, os.path.join(APP, "page.py"), "nope"], capture_output=True).returncode, 2)

    def test_the_repository_page_and_the_server_agree(self):
        """page.py's names are console.py's NAME, and the repository's page builds with nothing inline."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("rc_console", os.path.join(APP, "console.py"))
        console = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(console)
        self.assertEqual(self.page.NAME.pattern, console.NAME.pattern)
        cm = self.page.configmap(AG, SIGNOUT)
        self.assertIn("index.html", json.loads(cm["data"]["MANIFEST.json"])["files"])
        html = read("apps/research-console/html/index.html")
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)|<style|\sstyle=|\son[a-z]+=")   # CSP: nothing inline


STUB_KUBECTL = r"""#!/usr/bin/env bash
a="$*"; echo "kubectl ${a//$'\n'/ }" >> "$STUB_LOG"
n=$(ls "$STUB_DIR" | grep -c '^in-' || true)
case "$*" in
  "get namespace "*) [[ "${STUB_NO_NS:-}" == "" || "$*" != *"${STUB_NO_NS}"* ]]; exit $? ;;
  "get deployment research-orchestrator "*) [[ -z "${STUB_NO_ORCH:-}" ]]; exit $? ;;
  "get deployment research-console -n "*) [[ -z "${STUB_DEPLOYED:-}" ]] || echo deployment.apps/research-console ;;
  "get deployment research-console-oauth2-proxy "*) [[ -n "${STUB_PROXY:-}" ]] || exit 1; [[ "$*" != *jsonpath* ]] || echo "${STUB_PAGE_SHA:-}" ;;
  "get configmap research-console-oauth2-proxy -n "*) echo '{"data": {"oauth2_proxy.cfg": "allowed_groups = [\"bio_scientist\", \"control_scientist\", \"engineer\"]\n"}}' ;;
  "get configmap research-console-oauth2-proxy-templates "*) [[ -n "${STUB_PROXY:-}" ]] || exit 1; cat "$STUB_DIR/page" 2>/dev/null ;;
  "get networkpolicy -n "*) [[ -n "${STUB_NO_NETPOL:-}" ]] || echo networkpolicy.networking.k8s.io/ra-default-deny ;;
  *"configmap research-code"*code-commit*) echo "${STUB_COMMIT:-}" ;;
  *"configmap research-code"*code-sha256*) echo "${STUB_BUNDLE_SHA:-$(printf 'e%.0s' {1..64})}" ;;
  "get cm portal-html "*) exit 1 ;;
  "create configmap "*) cat > /dev/null; echo "kind: ConfigMap" ;;
  "rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  "apply "*) cat > "$STUB_DIR/in-$(printf %03d "$n")-apply" ;;
esac
exit 0
"""
STUB_MK8S = r"""#!/usr/bin/env bash
case "$1" in
  helm3) a="$*"; echo "helm ${a#helm3 }" >> "$STUB_LOG" ;;
  kubectl) shift; exec "$(dirname "$0")/kubectl" "$@" ;;
esac
exit 0
"""
STUB_CURL = r"""#!/usr/bin/env bash
echo "curl $*" >> "$STUB_LOG"
printf 302
"""
STUB_CLI = r"""import os, sys
open(os.environ["STUB_LOG"], "a").write("cli " + " ".join(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[0] == "has-host":
    sys.exit(int(os.environ.get("STUB_HOST_RC", "0")))
if a[0] == "pod-zone":
    rc = int(os.environ.get("STUB_POD_ZONE_RC", "0"))
    if rc == 0:
        print(os.environ.get("STUB_POD_ZONE", "research-agents"))
    sys.exit(rc)
if a[:2] == ["compile", "proxy"]:
    print('["bio_scientist", "control_scientist", "engineer"]')
    sys.exit(0)
if a[0] == "describe-gate":
    print("Research console\tBio scientist, Control scientist, Engineer")
    sys.exit(0)
sys.exit(9)
"""


class Tree(unittest.TestCase):
    def setUp(self):
        self.root = scratch_repo("medcea-rconsole-")
        r = self.root
        shutil.copytree(APP, os.path.join(r, "apps", "research-console"), ignore=shutil.ignore_patterns("__pycache__"))
        os.makedirs(os.path.join(r, "apps", "research-model"))
        shutil.copy(os.path.join(REPO, "apps", "research-model", "pins.json"), os.path.join(r, "apps", "research-model"))
        os.makedirs(os.path.join(r, "k8s", "oauth2-proxy"))
        for f in ("error.html", "values-common.yaml"):
            shutil.copy(os.path.join(REPO, "k8s", "oauth2-proxy", f), os.path.join(r, "k8s", "oauth2-proxy", f))
        self.git("init", "-q")
        self.git("add", "apps/research-console")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
        self.commit = subprocess.run(["git", "-C", r, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        self.bin, self.stub, self.log = os.path.join(r, "bin"), os.path.join(r, "stub"), os.path.join(r, "calls.log")
        os.makedirs(self.bin)
        os.makedirs(self.stub)
        sh(os.path.join(self.bin, "kubectl"), STUB_KUBECTL)
        sh(os.path.join(self.bin, "mk8s"), STUB_MK8S)
        sh(os.path.join(self.bin, "curl"), STUB_CURL)
        with open(os.path.join(r, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s/mk8s"; KUBECTL="%s/kubectl"\n' % (self.bin, self.bin))
        with open(os.path.join(r, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    'policy_db_state() { echo "${STUB_PS_STATE:-version-13}"; }\n')
        with open(os.path.join(r, "infra", "lib-policy-artefacts.sh"), "w") as f:
            f.write('source "$SCRIPT_DIR/infra/lib-policy-tools.sh"\n'
                    '_pa_zonenetpol_equal() { echo "zonenetpol_equal $1" >> "$STUB_LOG"; return "${STUB_EQ_RC:-0}"; }\n')
        with open(os.path.join(r, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write(STUB_CLI)
        self.write_config()

    def git(self, *a):
        subprocess.run(["git", "-C", self.root] + list(a), check=True, capture_output=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, **extra):
        conf = dict(NAMESPACE="medcea", PROJECT_NAME="medcea", DOMAIN="medcea", RESEARCH_ENABLED="true", RESEARCH_NAMESPACE=RNS,
                    KEYCLOAK_DOMAIN="keycloak.medcea", KEYCLOAK_REALM="medcea", PORTAL_DOMAIN="portal.medcea",
                    WORKBENCH_DOMAIN="ai-workbench.medcea", WORKBENCH_ENABLED="true",
                    RESEARCH_CONSOLE_CLIENT_SECRET="client-secret-xyz", RESEARCH_CONSOLE_COOKIE_SECRET="cookie-secret-xyz")
        conf.update(extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def run_script(self, rel, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub, "STUB_COMMIT": self.commit,
                              "PATH": self.bin + ":" + os.environ["PATH"]}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG", "IAM_GATES"):
            e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, rel)] + list(args), env=e, capture_output=True, text=True,
                           timeout=120, stdin=subprocess.DEVNULL, cwd=self.root)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        if os.path.exists(self.log):
            os.remove(self.log)
        r.out = r.stdout + r.stderr
        return r, calls

    def applies(self):
        out = []
        for f in sorted(os.listdir(self.stub)):
            if f.endswith("-apply"):
                text = read(os.path.join(self.stub, f))
                try:
                    out += [d for d in yaml.safe_load_all(text) if d and d.get("metadata")]
                except yaml.YAMLError:
                    out.append({"kind": "?", "metadata": {"name": "?"}})
        for f in os.listdir(self.stub):
            if f.endswith("-apply"):
                os.remove(os.path.join(self.stub, f))
        return out


class Deploy(Tree):
    DEPLOY = "apps/research-console/deploy.sh"

    def skip(self, why, **env):
        r, calls = self.run_script(self.DEPLOY, **env)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: " + why, r.out)
        self.assertEqual(self.applies(), [])
        self.assertFalse([c for c in calls if c.startswith("helm ")])
        self.assertEqual(calls[-1], "finish medcea research-console")
        return r, calls

    def test_syntax_options_help(self):
        for s in ("deploy.sh", "uninstall.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)
            r, calls = self.run_script("apps/research-console/" + s, "--bogus")
            self.assertEqual(r.returncode, 2)
            self.assertIn("unknown arguments", r.out)
        r, calls = self.run_script(self.DEPLOY, "--gate-only", "x")
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))
        self.assertEqual(calls, [])
        r, calls = self.run_script(self.DEPLOY, "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipped: the applied access policy has no research console yet", r.out)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))

    def test_skips(self):
        self.write_config(RESEARCH_ENABLED="false")
        self.skip("RESEARCH_ENABLED is not true")
        self.write_config()
        r, calls = self.skip("the applied access policy has no research console yet", STUB_HOST_RC="1")
        self.assertIn("cli has-host RESEARCH_CONSOLE_DOMAIN", calls)
        for st in ("none", "empty"):
            self.skip("no version of the access policy is applied yet (state %s)" % st, STUB_PS_STATE=st)
        self.skip("namespace %s does not exist yet" % AG, STUB_NO_NS=AG)
        self.skip("no research-orchestrator yet (./apps/research-agents/deploy.sh)", STUB_NO_ORCH="1")

    def test_a_skip_names_a_running_console(self):
        r, calls = self.skip("the applied access policy has no research console yet", STUB_HOST_RC="1", STUB_DEPLOYED="1")
        self.assertIn("the research console is still running (left alone)", r.out)

    def test_refusals(self):
        bad_commit = "f" * 40
        for env, want in (({"STUB_HOST_RC": "2"}, "cannot be read"),
                          ({"STUB_POD_ZONE": "research"}, "must put the pod research-console in the research-agents zone"),
                          ({"STUB_POD_ZONE_RC": "1"}, "must put the pod research-console in the research-agents zone"),
                          ({"STUB_PS_STATE": "partial"}, "state in the database is 'partial'"),
                          ({"STUB_EQ_RC": "1"}, "are not the compiled ones"), ({"STUB_EQ_RC": "2"}, "cannot compare"),
                          ({"STUB_NO_NETPOL": "1"}, "no NetworkPolicy in"),
                          ({"STUB_COMMIT": ""}, "no code bundle"),
                          ({"STUB_COMMIT": bad_commit}, "has no apps/research-console/console.py")):
            r, calls = self.run_script(self.DEPLOY, **env)
            self.assertEqual(r.returncode, 1, (env, r.out))
            self.assertIn(want, r.out, env)
            self.assertEqual(self.applies(), [], env)
            self.assertFalse([c for c in calls if c.startswith("helm ")], env)
            self.assertNotIn("finish medcea research-console", calls)
        self.write_config(RESEARCH_CONSOLE_COOKIE_SECRET="")
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 1)
        self.assertIn("RESEARCH_CONSOLE_CLIENT_SECRET or RESEARCH_CONSOLE_COOKIE_SECRET is empty", r.out)
        self.write_config(RESEARCH_CONSOLE_DOMAIN="Agents_Bad")
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 1)
        self.assertIn("is not a host name", r.out)

    def test_full_path(self):
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(calls[0], "init medcea")
        self.assertEqual(calls[-1], "finish medcea research-console")
        self.assertIn("zonenetpol_equal research-agents", calls)
        docs = self.applies()
        kinds = [(d["kind"], d["metadata"]["name"]) for d in docs]
        self.assertEqual(kinds[:3], [("ConfigMap", "research-console-html"), ("Deployment", "research-console"),
                                     ("Service", "research-console")])
        cm, dep = docs[0], docs[1]
        manifest = json.loads(cm["data"]["MANIFEST.json"])
        self.assertTrue(manifest["signout"].startswith("https://agents.medcea/oauth2/sign_out?rd="))
        self.assertEqual(dep["spec"]["template"]["metadata"]["annotations"]["medcea/html-sha256"],
                         cm["metadata"]["annotations"]["medcea/console-sha256"])
        self.assertEqual(dep["spec"]["template"]["metadata"]["annotations"]["medcea/code-commit"], self.commit)
        self.assertEqual(dep["metadata"]["namespace"], AG)
        # the page server applied server-side; the proxy through app_gate, after the page server's rollout
        self.assertTrue([c for c in calls if c.startswith("kubectl apply --server-side --force-conflicts "
                                                          "--field-manager=medcea-research-console")])
        i_roll = calls.index("kubectl rollout status deployment/research-console -n %s --timeout=5m" % AG)
        helm = [i for i, c in enumerate(calls) if c.startswith("helm upgrade --install research-console-oauth2-proxy")]
        self.assertEqual(len(helm), 1)
        self.assertLess(i_roll, helm[0])
        h = calls[helm[0]]
        self.assertIn("--namespace medcea", h)
        self.assertIn("configuration.clientID=research-console", h)
        self.assertIn("ingress.hostname=agents.medcea", h)
        self.assertIn("kubectl delete ingress research-console -n medcea --ignore-not-found", calls)
        self.assertIn("kubectl get cm portal-html -n medcea -o jsonpath={.data.index\\.html}", calls)   # portal_card enable
        self.assertTrue([c for c in calls if c.startswith("curl ") and "https://agents.medcea/" in c])
        self.assertTrue([c for c in calls if c == "cli compile proxy RESEARCH_CONSOLE_DOMAIN"])
        self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("app-research-console-deploy-")])
        # the values helm got: rendered with the research-agents namespace
        self.assertNotIn("cookie-secret-xyz", "\n".join(c for c in calls if not c.startswith("helm ")))

    def test_gate_only(self):
        r, calls = self.run_script(self.DEPLOY, "--gate-only", STUB_HOST_RC="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("RESEARCH_CONSOLE_DOMAIN (research-console-oauth2-proxy): not deployed (the applied access policy "
                      "has no research console yet)", r.out)
        self.assertEqual(self.applies(), [])
        self.assertFalse([c for c in calls if c.startswith("helm ")])
        self.assertEqual(calls[-1], "finish medcea research-console")
        r, calls = self.run_script(self.DEPLOY, "--gate-only", STUB_HOST_RC="1", STUB_PROXY="1")
        self.assertIn("not in the applied access policy; the running proxy is left as it is", r.out)
        r, calls = self.run_script(self.DEPLOY, "--gate-only")          # the host, no proxy yet
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("RESEARCH_CONSOLE_DOMAIN (research-console-oauth2-proxy): not deployed (the app's full deploy installs it)", r.out)
        self.assertFalse([c for c in calls if c.startswith("helm ")])
        r, calls = self.run_script(self.DEPLOY, "--gate-only", STUB_PROXY="1")   # deployed, its 403 page drifted
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("RESEARCH_CONSOLE_DOMAIN (research-console-oauth2-proxy): re-rendered (", r.out)
        self.assertEqual(len([c for c in calls if c.startswith("helm upgrade --install research-console-oauth2-proxy")]), 1)
        self.assertFalse([c for c in calls if "rollout restart" in c])
        self.assertFalse([c for c in calls if "research-console-html" in c or "console.yaml" in c])


class Uninstall(Tree):
    def test_uninstall(self):
        r, calls = self.run_script("apps/research-console/uninstall.sh")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("helm uninstall research-console-oauth2-proxy -n medcea --wait --timeout 3m", calls)
        self.assertIn("kubectl delete configmap research-console-oauth2-proxy-templates -n medcea --ignore-not-found", calls)
        self.assertIn("kubectl delete deployment,service,configmap -l app=research-console -n %s --ignore-not-found" % AG, calls)
        self.assertFalse([c for c in calls if "research-orchestrator" in c or "agent_trace" in c or "pvc" in c])
        self.assertIn("kubectl get cm portal-html -n medcea -o jsonpath={.data.index\\.html}", calls)


class Wiring(unittest.TestCase):
    def test_research_chain(self):
        dep, un = read("apps/research/deploy.sh"), read("apps/research/uninstall.sh")
        self.assertLess(dep.index('bash "$REPO_ROOT/apps/research-agents/deploy.sh"'),
                        dep.index('bash "$REPO_ROOT/apps/research-console/deploy.sh"'))
        self.assertLess(dep.index('bash "$REPO_ROOT/apps/research-console/deploy.sh"'), dep.rindex("policy_source_finish"))
        self.assertLess(un.index('bash "$REPO_ROOT/apps/research-console/uninstall.sh"'),
                        un.index('bash "$REPO_ROOT/apps/research-agents/uninstall.sh"'))
        self.assertRegex(read("deploy-apps.sh"), r"POLICY_COMPILING=\([^)]*\bresearch-console\b")

    def test_the_bundle_holds_console_py_and_the_origin(self):
        ag = read("apps/research-agents/deploy.sh")
        self.assertRegex(ag, r"_PATHS=\([^)]*apps/research-console/console\.py\)")
        self.assertIn('RS_CONSOLE_ORIGIN="https://${RESEARCH_CONSOLE_DOMAIN:-agents.${DOMAIN:-medcea}}"', ag)
        self.assertRegex(ag, r"RS_ENDPOINTS_INVENTORY RS_CONSOLE_ORIGIN \| \$KUBECTL apply -f -")
        y = read("apps/research-agents/k8s/agents.yaml")
        self.assertIn('- name: RS_CONSOLE_ORIGIN\n          value: "${RS_CONSOLE_ORIGIN}"', y)

    def test_portal_card_and_render(self):
        p = read("k8s/portal/portal.yaml")
        self.assertRegex(p, r'(?s)<div class="card card-dis" data-href="https://\$\{RESEARCH_CONSOLE_DOMAIN\}">.*?'
                            r'<div class="ct">Agent campaigns</div>.*?</div><!--/card-->')
        infra = read("deploy-infra.sh")
        render = [l for l in infra.splitlines() if l.startswith('render "$SCRIPT_DIR/k8s/portal/portal.yaml"')][0]
        self.assertIn(" RESEARCH_CONSOLE_DOMAIN ", render + " ")
        sec = infra[infra.index('render "$SCRIPT_DIR/k8s/portal/portal.yaml"'):infra.index("rollout restart deployment/portal")]
        self.assertIn('kubectl get deployment research-console -n "$(zone_namespace research-agents)"', sec)
        self.assertIn('PORTAL_CARD_NO_RESTART=1 KUBECTL="$MK8S kubectl" portal_card enable "https://${RESEARCH_CONSOLE_DOMAIN}"', sec)

    def test_svc_domains_and_config(self):
        infra = read("deploy-infra.sh")
        start = infra.index("_SVC_DOMAINS=()")
        block = infra[start:infra.index("\ndone\n", start) + 6]
        e = {k: v for k, v in os.environ.items() if not k.endswith("_DOMAIN")}
        e["DOMAIN"] = "medcea"
        out = subprocess.run(["bash", "-c", block + 'printf "%s\\n" "${_SVC_DOMAINS[@]}"'], capture_output=True,
                             text=True, env=e, check=True).stdout.split()
        self.assertIn("agents.medcea", out)
        ex = read("config.env.example")
        self.assertEqual(re.findall(r"^RESEARCH_CONSOLE_[A-Z_]+=.*$", ex, re.M),
                         ['RESEARCH_CONSOLE_DOMAIN="agents.$DOMAIN"', 'RESEARCH_CONSOLE_CLIENT_SECRET=""',
                          'RESEARCH_CONSOLE_COOKIE_SECRET=""'])

    def test_medcea_entries(self):
        t = read("medcea.sh")
        for fn in ("a_research_console_deploy", "a_research_console_uninstall", "a_policy_rs4e_switch"):
            self.assertIn("%s()" % fn, t)
            self.assertRegex(t, r'(?m)^    "%s\|' % fn)
        self.assertIn("for c in access edge-wizard frontend iam monitor mqtt-explorer research-console scheduler superset; do", t)

    def test_orchestrator_origin_rule(self):
        o = read("apps/research-agents/orchestrator.py")
        self.assertIn('"console_origin": os.environ.get("RS_CONSOLE_ORIGIN", "") or None', o)
        self.assertIn('self.send_header("X-Content-Type-Options", "nosniff")', o)


# ── Health: rsconsole ─────────────────────────────────────────────────────────────────
def console_policy():
    import test_policy
    sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
    from compiler import model
    return test_policy.console_shape(model.load_defaults().data)


class Health(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = h5.Tree()
        os.makedirs(cls.t.path("apps", "research-console", "html", "vendor", "uplot"), exist_ok=True)
        with open(cls.t.path("apps", "research-console", "html", "vendor", "uplot", "VERSION"), "w") as f:
            f.write("uplot 1.6.31 (MIT)\n%s  uPlot.min.js\n%s  LICENSE\n" % ("a" * 64, "b" * 64))
        cls.policy = cls.t.path("apps", "iam", "policy", "defaults.yaml")
        with open(cls.policy) as f:
            cls.factory = f.read()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def setUp(self):
        with open(self.policy, "w") as f:
            yaml.safe_dump(console_policy(), f, sort_keys=False)

    def tearDown(self):
        with open(self.policy, "w") as f:
            f.write(self.factory)

    def dep(self, **spec):
        s = {"automountServiceAccountToken": False, "volumes": [{"name": "html", "configMap": {"name": "research-console-html"}}],
             "containers": [{"name": "console"}]}
        s.update(spec)
        return json.dumps({"spec": {"template": {"spec": s}}})

    def check(self, dep=None, pods=None, cm_sha="c" * 64, age=600, probe=None, absent=False):
        pod_spec = json.loads(dep or self.dep())["spec"]["template"]["spec"]
        if pods is None:
            pods = {"items": [{"metadata": {"name": "research-console-1"}, "status": {"phase": "Running"}, "spec": pod_spec}]}
        cm = {"metadata": {"annotations": {"medcea/console-sha256": cm_sha},
                           "managedFields": [{"manager": "kubectl", "time": h5.iso(age)}]}}
        pr = {"healthz": {"service": "research-console", "manifest_sha256": "c" * 64, "files": 3}, "root": 401,
              "files": {"index.html": "d" * 64, "uplot/uPlot.min.js": "a" * 64, "uplot/LICENSE": "b" * 64}}
        pr.update(probe or {})
        rules = [h5.rule(r"^get deployment research-console -n %s " % AG, "", 1, 'Error from server (NotFound): x not found\n')] \
            if absent else [h5.rule(r"^get deployment research-console -n %s " % AG, dep or self.dep())]
        rules += [h5.rule(r"^get pods -n %s -l app=research-console" % AG, json.dumps(pods)),
                  h5.rule(r"^get configmap research-console-html -n %s -o json --show-managed-fields" % AG, json.dumps(cm)),
                  h5.rule(r"^exec -n %s deploy/research-console -c console -- python3 -c" % AG, json.dumps(pr) + "\n")]
        self.t.scenario(rules)
        r = self.t.fn("check_rsconsole", 'check_rsconsole "Research console" medcea', helpers=())
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec"), c)
        return r

    def test_ok(self):
        r = self.check()
        self.assertEqual(r, "OK|Research console|research-console serves manifest cccccccccccc (3 files); / refuses without a "
                            "token (401); no Secret, no token")

    def test_skips(self):
        with open(self.policy, "w") as f:
            f.write(self.factory)
        self.assertEqual(self.check(), "SKIP|Research console|the applied access policy has no research console yet "
                                       "(RESEARCH_CONSOLE_DOMAIN)")
        self.setUp()
        self.assertTrue(self.check(absent=True).startswith("SKIP|Research console|no deployment research-console in %s" % AG))

    def test_fails(self):
        r = self.check(probe={"healthz": {"manifest_sha256": "e" * 64, "files": 3}})
        self.assertTrue(r.startswith("FAIL|Research console|the pod serves manifest eeeeeeeeeeee, the ConfigMap holds cccccccccccc since"), r)
        r = self.check(probe={"root": 200})
        self.assertIn("FAIL|Research console|GET / without a token answered 200, not 401", r)
        r = self.check(probe={"files": {"uplot/uPlot.min.js": "f" * 64, "uplot/LICENSE": "b" * 64}})
        self.assertIn("vendor file uplot/uPlot.min.js: served ffffffffffff, VERSION records aaaaaaaaaaaa", r)
        self.assertTrue(r.startswith("FAIL|"), r)
        r = self.check(dep=self.dep(automountServiceAccountToken=True))
        self.assertIn("the Deployment's pod carries a ServiceAccount token", r)
        r = self.check(dep=self.dep(volumes=[{"name": "k", "secret": {"secretName": "x"}}]))
        self.assertIn("the Deployment's pod carries Secret volume x", r)
        r = self.check(dep=self.dep(containers=[{"name": "console", "env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]}]))
        self.assertIn("Secret s in env", r)
        self.assertTrue(r.startswith("FAIL|"), r)

    def test_warns(self):
        r = self.check(probe={"healthz": {"manifest_sha256": "e" * 64, "files": 3}}, age=30)
        self.assertTrue(r.startswith("WARN|"), r)
        self.assertRegex(r, r"since 3[0-9] s \(the kubelet syncs within 120 s\)")
        r = self.check(pods={"items": []})
        self.assertTrue(r.startswith("WARN|Research console|no Running research-console pod"), r)
        r = self.check(probe={"healthz": None})
        self.assertTrue(r.startswith("WARN|Research console|research-console does not answer /healthz"), r)

    def test_conf_dispatch_and_help(self):
        conf = read("health-checks.conf")
        lines = [l for l in conf.splitlines() if l.strip() and not l.startswith("#")]
        rows = [[x.strip() for x in l.split("|")[:3]] for l in lines]
        types = [r[1] for r in rows]
        self.assertEqual(rows[types.index("rsllm") + 1], ["Research console", "rsconsole", "$NAMESPACE"])
        src = read("health-check.sh")
        self.assertRegex(src, r'(?m)^        rsconsole\)\s+check_rsconsole "\$name" "\$target" ;;$')
        self.assertIn("${CYAN}rsconsole${NC}", src)
        self.assertNotRegex(h5.body("check_rsconsole", src), r"\$KUBECTL (apply|delete|create|patch|edit|set|scale|rollout|label)\b")


if __name__ == "__main__":
    unittest.main()
