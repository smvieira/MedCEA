#!/usr/bin/env python3
"""tests/test_research_agents_deploy.py — research Phase 4a stage 6b1: the namespaces and the deploy of the
agent machinery (design rs4 R2, R3, R4, OD11).

Offline (stdlib unittest), in scratch trees with a fake cluster:
  Manifests    k8s/research-{gw,agents}/{namespace,quota,limitrange}.yaml (zone label, PSA baseline, no-token
               default ServiceAccount, the OD11 quota lines, no default CPU limit); apps/research-agents/k8s
               (every pod hardened, no Secret in research-agents, the orchestrator the only pod with a
               token and a Role limited to Jobs and its own pods, secrets by file mount only in -gw).
  Namespaces   infra/deploy-research-{gw,agents}-namespace.sh: --help, unknown options exit 2 before log
               and lock, the skip lines, the full path (three manifests and pa_zonenetpol) and --policy-only.
  Helpers      zone_namespace / zone_netpol_args; apply_check's zone targets only while the policy has them.
  Deploy       apps/research-agents/deploy.sh: each skip line, the refusals, the full path in order, the bundle
               (BUNDLE.json, deterministic, refused while dirty), no secret in any argv; uninstall.
  Wiring       the research deploy chains it after lake-api and its uninstall runs it first; configure.sh
               generates the key; deploy-infra calls the two scripts after the research namespace.

  python3 tests/test_research_agents_deploy.py
"""
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402

APP = os.path.join(REPO, "apps", "research-agents")
HMAC = "ab" * 32
DBPASS = "rsSessionPass0123456789"
GW, AG, RNS = "medcea-research-gw", "medcea-research-agents", "medcea-research"


def read(p):
    with open(os.path.join(REPO, p) if not os.path.isabs(p) else p) as f:
        return f.read()


def code(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def render(template, **env):
    e = clean_env(**env)
    r = subprocess.run(["bash", "-c", 'source "$1"; shift; render "$@"', "-",
                        os.path.join(REPO, "infra", "lib-render.sh"), template] + sorted(env),
                       env=e, capture_output=True, text=True, check=True)
    return r.stdout


def docs(text):
    import yaml
    return [d for d in yaml.safe_load_all(text) if d]


def render_vars(path):
    """The names a template's header declares in 'Render list:' (the rest of that comment line)."""
    m = re.search(r"Render list: ([A-Z0-9_ ]+)", read(path))
    return m.group(1).split()


def full_render(path):
    names = render_vars(path)
    return render(os.path.join(REPO, path), **{n: "x-" + n.lower().replace("_", "-") for n in names})


class Manifests(unittest.TestCase):
    def test_namespaces(self):
        for zone, var in (("research-gw", "RESEARCH_GW_NAMESPACE"), ("research-agents", "RESEARCH_AGENTS_NAMESPACE")):
            ns, sa = docs(render(os.path.join(REPO, "k8s", zone, "namespace.yaml"), **{var: "ns1"}))
            self.assertEqual(ns["metadata"]["name"], "ns1")
            lab = ns["metadata"]["labels"]
            self.assertEqual(lab["medcea/zone"], zone)
            self.assertEqual(lab["pod-security.kubernetes.io/enforce"], "baseline")
            self.assertEqual((sa["kind"], sa["metadata"]["name"], sa["automountServiceAccountToken"]),
                             ("ServiceAccount", "default", False))
            lr, = docs(render(os.path.join(REPO, "k8s", zone, "limitrange.yaml"), **{var: "ns1"}))
            item = lr["spec"]["limits"][0]
            self.assertEqual(item["default"], {"memory": "512Mi"})   # no default CPU limit
            self.assertNotIn("cpu", item["default"])
            q, = docs(render(os.path.join(REPO, "k8s", zone, "quota.yaml"), **{var: "ns1"}))
            self.assertEqual(q["metadata"]["namespace"], "ns1")

    def test_quota_lines_od11(self):
        q, = docs(render(os.path.join(REPO, "k8s", "research-agents", "quota.yaml"), RESEARCH_AGENTS_NAMESPACE="a"))
        self.assertEqual(q["spec"]["hard"], {"requests.cpu": "5", "requests.memory": "4Gi", "limits.memory": "12Gi",
                                             "pods": "10", "persistentvolumeclaims": "4", "requests.storage": "12Gi"})
        q, = docs(render(os.path.join(REPO, "k8s", "research-gw", "quota.yaml"), RESEARCH_GW_NAMESPACE="g"))
        self.assertEqual((q["spec"]["hard"]["requests.cpu"], q["spec"]["hard"]["requests.memory"],
                          q["spec"]["hard"]["limits.memory"]), ("7", "13Gi", "13Gi"))
        self.assertIn("sum  4750m", read("k8s/research-agents/quota.yaml"))

    def test_research_quota_unchanged(self):
        q, = docs(render(os.path.join(REPO, "k8s", "research", "quota.yaml"), RESEARCH_NAMESPACE="r"))
        self.assertEqual(q["spec"]["hard"]["requests.cpu"], "4")   # R2/R19: unchanged

    def test_every_variable_is_in_the_render_list(self):
        for path in ("apps/research-agents/k8s/agents.yaml", "apps/research-agents/k8s/research-session.yaml",
                     "apps/research-agents/k8s/session-secrets.yaml", "apps/research-agents/k8s/wheels.yaml",
                     "apps/research-agents/k8s/runs.yaml", "k8s/research-gw/namespace.yaml",
                     "k8s/research-agents/quota.yaml"):
            used = set(re.findall(r"\$\{([A-Z_0-9]+)\}", code(read(path))))
            self.assertEqual(used, set(render_vars(path)), path)
            self.assertNotIn("${", full_render(path), path)

    def pods(self, path):
        out = []
        for d in docs(full_render(path)):
            if d["kind"] == "Deployment":
                out.append(d)
        return out

    def test_pods_are_hardened(self):
        for path in ("apps/research-agents/k8s/agents.yaml", "apps/research-agents/k8s/research-session.yaml"):
            for d in self.pods(path):
                spec = d["spec"]["template"]["spec"]
                name = d["metadata"]["name"]
                self.assertEqual(spec["priorityClassName"], "medcea-research-low", name)
                self.assertIs(spec["enableServiceLinks"], False, name)
                sc = spec["securityContext"]
                self.assertEqual((sc["runAsNonRoot"], sc["runAsUser"], sc["seccompProfile"]["type"]),
                                 (True, 65534, "RuntimeDefault"), name)
                self.assertEqual(d["spec"]["revisionHistoryLimit"], 0)
                for c in spec["containers"] + spec["initContainers"]:
                    self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True, name)
                    self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False, name)
                    self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
                    self.assertIn("memory", c["resources"]["limits"], name)
                    self.assertIn("cpu", c["resources"]["requests"], name)
                    self.assertNotIn("cpu", c["resources"]["limits"], name)
                    self.assertRegex(c["image"], r"^x-rs-image$")
                self.assertFalse([v for v in spec["volumes"] if "hostPath" in v], name)   # PSA baseline

    def test_the_image_is_the_pinned_digest(self):
        pin = json.load(open(os.path.join(REPO, "apps", "research-model", "pins.json")))["python_image"]
        self.assertRegex(pin, r"^python:3\.14\.\d+-slim@sha256:[0-9a-f]{64}$")

    def test_only_the_orchestrator_has_a_token_and_rights(self):
        tokens = {}
        for path in ("apps/research-agents/k8s/agents.yaml", "apps/research-agents/k8s/research-session.yaml"):
            for d in self.pods(path):
                spec = d["spec"]["template"]["spec"]
                tokens[d["metadata"]["name"]] = (spec["automountServiceAccountToken"], spec.get("serviceAccountName"))
        self.assertEqual(tokens, {"research-orchestrator": (True, "research-orchestrator"),
                                  "mcp-sim": (False, None), "mcp-lake": (False, None), "research-session": (False, None)})
        ds = docs(full_render("apps/research-agents/k8s/agents.yaml"))
        role, = [d for d in ds if d["kind"] == "Role"]
        self.assertEqual(role["rules"], [
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create", "get", "list", "watch", "delete"]},
            {"apiGroups": [""], "resources": ["pods", "pods/log"], "verbs": ["get", "list"]}])
        self.assertFalse([d for d in ds if d["kind"] in ("ClusterRole", "ClusterRoleBinding", "Secret")])
        text = full_render("apps/research-agents/k8s/agents.yaml")
        self.assertNotIn("secretKeyRef", text)
        self.assertNotIn("secretName", text)   # no Secret in research-agents (R2)

    def test_secrets_only_in_gw_and_only_by_file(self):
        text = full_render("apps/research-agents/k8s/research-session.yaml")
        self.assertNotIn("secretKeyRef", text)
        d, = self.pods("apps/research-agents/k8s/research-session.yaml")
        spec = d["spec"]["template"]["spec"]
        self.assertEqual(sorted(v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v),
                         ["research-session-db", "research-session-key"])
        env = {e["name"]: e.get("value") for e in spec["containers"][0]["env"]}
        self.assertEqual(env["RS_SESSION_KEY_FILE"], "/auth/key/key")
        self.assertEqual(env["RS_SESSION_DB_PASS_FILE"], "/auth/db/password")
        self.assertEqual([p["containerPort"] for p in spec["containers"][0]["ports"]], [8100, 8101, 8102])
        sec = docs(render(os.path.join(REPO, "apps/research-agents/k8s/session-secrets.yaml"),
                          RESEARCH_GW_NAMESPACE="g", RS_SESSION_HMAC_KEY=HMAC, RS_SESSION_DB_PASS=DBPASS))
        self.assertEqual({s["metadata"]["name"]: s["stringData"] for s in sec},
                         {"research-session-key": {"key": HMAC}, "research-session-db": {"password": DBPASS}})

    def test_env_matches_what_the_entrypoints_read(self):
        orch = read("apps/research-agents/orchestrator.py")
        d, = [x for x in self.pods("apps/research-agents/k8s/agents.yaml") if x["metadata"]["name"] == "research-orchestrator"]
        have = {e["name"] for e in d["spec"]["template"]["spec"]["containers"][0]["env"]}
        for name in re.findall(r'os\.environ(?:\.get)?[\[(]"([A-Z_]+)"', orch.split("def main")[1]):
            if name != "RS_PROFILES_DIR":
                self.assertIn(name, have)
        for pod, src in (("mcp-sim", "mcp_sim.py"), ("mcp-lake", "mcp_lake.py")):
            d, = [x for x in self.pods("apps/research-agents/k8s/agents.yaml") if x["metadata"]["name"] == pod]
            have = {e["name"] for e in d["spec"]["template"]["spec"]["containers"][0]["env"]}
            main = read("apps/research-agents/" + src).split("def main")[1]
            for name in re.findall(r'os\.environ(?:\.get)?[\[(]"([A-Z_]+)"', main):
                self.assertIn(name, have, pod)

    def test_wheel_requirements_are_hash_pinned(self):
        for f, n in (("requirements-services.txt", 6), ("requirements-controllers.txt", 6)):
            lines = [l for l in read("apps/research-agents/" + f).splitlines() if l.strip() and not l.startswith("#")]
            self.assertGreaterEqual(len(lines), n, f)
            for l in lines:
                self.assertRegex(l, r"^[A-Za-z0-9._-]+==[0-9.]+ --hash=sha256:[0-9a-f]{64}$", f)

    def test_the_controller_pins_are_the_hosts_and_name_every_library(self):
        """FLC and MPC need these six; the host venv (research/requirements.txt) runs the same controllers on python 3.14."""
        pins = lambda f: {l.split(" ")[0] for l in read(f).splitlines() if l.strip() and not l.startswith("#")}
        ctrl = pins("apps/research-agents/requirements-controllers.txt")
        self.assertEqual({p.split("==")[0] for p in ctrl}, {"gekko", "networkx", "numpy", "packaging", "scikit-fuzzy", "scipy"})
        self.assertLessEqual(ctrl, pins("research/requirements.txt"))
        self.assertFalse(ctrl & pins("apps/research-agents/requirements-services.txt"))

    def test_wheel_volume(self):
        pv, pvc = docs(render(os.path.join(REPO, "apps/research-agents/k8s/wheels.yaml"),
                              WHEEL_NS="n", WHEEL_PV="n-research-wheels", WHEEL_PATH="/w/gw"))
        self.assertEqual((pv["spec"]["accessModes"], pv["spec"]["hostPath"]["path"],
                          pv["spec"]["claimRef"]["namespace"]), (["ReadOnlyMany"], "/w/gw", "n"))
        self.assertEqual(pvc["spec"]["volumeName"], "n-research-wheels")


STUB_KUBECTL = r"""#!/usr/bin/env bash
a="$*"; echo "kubectl ${a//$'\n'/ }" >> "$STUB_LOG"
n=$(ls "$STUB_DIR" | grep -c '^in-' || true)
case "$*" in
  "get namespace "*" -o name") [[ "${STUB_NO_NS:-}" == "" || "$*" != *"${STUB_NO_NS}"* ]] && echo "namespace/$3"; exit 0 ;;
  "get namespace "*) [[ "${STUB_NO_NS:-}" == "" || "$*" != *"${STUB_NO_NS}"* ]]; exit $? ;;
  "get deployment -n "*" -l "*) [[ -z "${STUB_DEPLOYED:-}" ]] || echo deployment.apps/research-session ;;
  "get statefulset research-postgresql "*) [[ -z "${STUB_NO_STS:-}" ]]; exit $? ;;
  "get networkpolicy -n "*) [[ -n "${STUB_NO_NETPOL:-}" ]] || echo networkpolicy.networking.k8s.io/gw-default-deny ;;
  "get secret research-session-key "*) printf '11-12-' ;;
  "get configmap medcea-iam-lib "*) echo '{"data": {"routes.json": "{}", "medcea_iam.py": "x"}, "metadata": {"name": "medcea-iam-lib", "resourceVersion": "1"}}' ;;
  "get secret medcea-jwks "*) echo '{"data": {"jwks.json": "e30="}, "metadata": {"name": "medcea-jwks"}}' ;;
  "rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  "apply "*) cat > "$STUB_DIR/in-$(printf %03d "$n")-apply" ;;
esac
exit 0
"""
STUB_PIP = r"""#!/usr/bin/env bash
echo "pip $*" >> "$STUB_LOG"
d=""; while [ $# -gt 0 ]; do [ "$1" = "-d" ] && d="$2"; shift; done
mkdir -p "$d"; printf 'wheel-one' > "$d/one-1-py3-none-any.whl"; printf 'wheel-two' > "$d/two-2-py3-none-any.whl"; printf 'wheel-ctrl' > "$d/ctrl-3-py3-none-any.whl"
"""


def sh(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


class Tree(unittest.TestCase):
    """A scratch tree: the real libraries, apps/research-agents, a git history, a fake cluster and cli.py."""

    def setUp(self):
        self.root = scratch_repo("medcea-ragents-")
        r = self.root
        shutil.copytree(APP, os.path.join(r, "apps", "research-agents"), ignore=shutil.ignore_patterns("__pycache__"))
        for d in ("k8s/research-gw", "k8s/research-agents"):
            shutil.copytree(os.path.join(REPO, d), os.path.join(r, d))
        for f in ("deploy-research-gw-namespace.sh", "deploy-research-agents-namespace.sh"):
            shutil.copy(os.path.join(REPO, "infra", f), os.path.join(r, "infra", f))
        os.makedirs(os.path.join(r, "apps", "research-model"))
        shutil.copy(os.path.join(REPO, "apps", "research-model", "pins.json"), os.path.join(r, "apps", "research-model", "pins.json"))
        for f in ("endpoints.json", "endpoints_config.py"):      # the model picker's inventory (research Phase 4d)
            shutil.copy(os.path.join(REPO, "apps", "research-model", f), os.path.join(r, "apps", "research-model", f))
        for rel, text in (("schd/cea/a.py", "A = 1\n"), ("research/b.py", "B = 2\n"),
                          ("apps/database/recipe_types.yaml", "x: 1\n"), ("edge/templates/esp32-control.json", "{}\n"),
                          ("apps/research/db/lake_api.sql", "select 1;\n")):
            p = os.path.join(r, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        # the wheel pins of the scratch tree: two fake wheels the fake pip writes
        with open(os.path.join(r, "apps", "research-agents", "requirements-services.txt"), "w") as f:
            for n, body in (("one", b"wheel-one"), ("two", b"wheel-two")):
                f.write("%s==1 --hash=sha256:%s\n" % (n, hashlib.sha256(body).hexdigest()))
        with open(os.path.join(r, "apps", "research-agents", "requirements-controllers.txt"), "w") as f:
            f.write("ctrl==3 --hash=sha256:%s\n" % hashlib.sha256(b"wheel-ctrl").hexdigest())
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")
        self.log = os.path.join(r, "calls.log")
        self.stub = os.path.join(r, "stub")
        self.bin = os.path.join(r, "bin")
        os.makedirs(self.stub)
        os.makedirs(self.bin)
        sh(os.path.join(self.bin, "kubectl"), STUB_KUBECTL)
        sh(os.path.join(self.bin, "pip"), STUB_PIP)
        # microk8s as the namespace scripts call it: `status` ok, `kubectl` the same stub
        sh(os.path.join(self.bin, "microk8s"), '#!/usr/bin/env bash\n[ "$1" = status ] && exit 0\nshift\nexec "$(dirname "$0")/kubectl" "$@"\n')
        with open(os.path.join(r, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s/mk8s"; KUBECTL="%s/kubectl"\n' % (self.bin, self.bin))
        with open(os.path.join(r, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    'policy_db_state() { echo "policy_db_state $1" >> "$STUB_LOG"; echo "${STUB_PS_STATE:-version-7}"; }\n')
        with open(os.path.join(r, "infra", "lib-policy-artefacts.sh"), "w") as f:
            f.write('source "$SCRIPT_DIR/infra/lib-policy-tools.sh"\n'
                    '_pa_line() { echo "pa_line $*" >> "$STUB_LOG"; }\n'
                    '_pa_zone_has() { echo "zone_has $1" >> "$STUB_LOG"; return "${STUB_ZONE_RC:-0}"; }\n'
                    'pa_zonenetpol() { echo "pa_zonenetpol $*" >> "$STUB_LOG"; }\n'
                    '_pa_zonenetpol_equal() { echo "zonenetpol_equal $1 SCRIPT_DIR=$SCRIPT_DIR" >> "$STUB_LOG"; return "${STUB_EQ_RC:-0}"; }\n')
        with open(os.path.join(r, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write('import os, sys\nopen(os.environ["STUB_LOG"], "a").write("cli " + " ".join(sys.argv[1:]) + "\\n")\n'
                    'z = {"research-orchestrator": "research-agents", "research-session": "research-gw"}.get(sys.argv[2], "research")\n'
                    'rc = int(os.environ.get("STUB_POD_ZONE_RC", "0"))\n'
                    'print(os.environ.get("STUB_POD_ZONE", z)) if rc == 0 else None\n'
                    'sys.exit(rc)\n')
        self.wheels = os.path.join(r, "wheels")
        self.write_config()

    def git(self, *a):
        subprocess.run(["git", "-C", self.root] + list(a), check=True, capture_output=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, **extra):
        conf = dict(NAMESPACE="medcea", PROJECT_NAME="medcea", RESEARCH_ENABLED="true", RESEARCH_NAMESPACE=RNS,
                    RS_SESSION_HMAC_KEY=HMAC, RS_SESSION_DB_PASS=DBPASS, RESEARCH_WHEEL_DIR=self.wheels)
        conf.update(extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def run_script(self, rel, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub, "MEDCEA_RESEARCH_PIP": os.path.join(self.bin, "pip"),
                              "PATH": self.bin + ":" + os.environ["PATH"]}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG"):
            if k not in env:
                e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, rel)] + list(args), env=e, capture_output=True, text=True,
                           timeout=90, stdin=subprocess.DEVNULL, cwd=self.root)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        if os.path.exists(self.log):
            os.remove(self.log)
        r.out = r.stdout + r.stderr
        for secret in (HMAC, DBPASS):
            self.assertNotIn(secret, "\n".join(calls), "a secret in an argv")
            self.assertNotIn(secret, r.out, "a secret printed")
        return r, calls

    def applies(self):
        return [read(os.path.join(self.stub, f)) for f in sorted(os.listdir(self.stub)) if f.endswith("-apply")]

    def clear_applies(self):
        for f in os.listdir(self.stub):
            os.remove(os.path.join(self.stub, f))


NS_SCRIPTS = (("research-gw", "RESEARCH_GW_NAMESPACE", GW, "gwnetpol"),
              ("research-agents", "RESEARCH_AGENTS_NAMESPACE", AG, "ranetpol"))


class Namespaces(Tree):
    def script(self, zone):
        return "infra/deploy-%s-namespace.sh" % zone

    def test_syntax_help_and_unknown_options(self):
        for zone, var, ns, key in NS_SCRIPTS:
            subprocess.run(["bash", "-n", os.path.join(REPO, self.script(zone))], check=True)
            r, calls = self.run_script(self.script(zone), "--help")
            self.assertEqual(r.returncode, 0)
            self.assertIn(key, r.out)
            r, calls = self.run_script(self.script(zone), "--bogus")
            self.assertEqual(r.returncode, 2, r.out)
            self.assertIn("unknown arguments", r.out)
            self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
            self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))

    def test_skips(self):
        for zone, var, ns, key in NS_SCRIPTS:
            self.write_config(RESEARCH_ENABLED="false")
            r, calls = self.run_script(self.script(zone))
            self.assertEqual(r.returncode, 0, r.out)
            self.assertIn("skipped: RESEARCH_ENABLED is not true", r.out)
            self.assertEqual(self.applies(), [])
            self.assertFalse([c for c in calls if c.startswith(("cli", "init", "zone_has"))])
            r, calls = self.run_script(self.script(zone), "--policy-only")
            self.assertIn("pa_line %s not deployed" % key, calls)
            self.write_config()
            r, calls = self.run_script(self.script(zone), STUB_ZONE_RC="1")
            self.assertEqual(r.returncode, 0, r.out)
            self.assertIn("skipped: the applied access policy has no %s zone yet" % zone, r.out)
            self.assertIn("zone_has %s" % zone, calls)
            self.assertEqual(calls[-1], "finish medcea deploy-%s-namespace" % zone)
            self.assertEqual(self.applies(), [])
            r, calls = self.run_script(self.script(zone), "--policy-only", STUB_ZONE_RC="1")
            self.assertIn("pa_line %s not deployed" % key, calls)

    def test_full_path(self):
        for zone, var, ns, key in NS_SCRIPTS:
            self.clear_applies()
            r, calls = self.run_script(self.script(zone))
            self.assertEqual(r.returncode, 0, r.out)
            self.assertEqual(calls[0], "init medcea")
            ds = [d for t in self.applies() for d in docs(t)]
            self.assertEqual([d["kind"] for d in ds], ["Namespace", "ServiceAccount", "ResourceQuota", "LimitRange"])
            self.assertEqual({d["metadata"]["namespace"] if d["kind"] != "Namespace" else d["metadata"]["name"] for d in ds}, {ns})
            self.assertIn("pa_zonenetpol %s full" % zone, calls)
            self.assertEqual(calls[-1], "finish medcea deploy-%s-namespace" % zone)
            self.assertLess(calls.index("init medcea"), calls.index("zone_has %s" % zone))
            self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("deploy-%s-namespace-" % zone)])

    def test_policy_only_applies_nothing_itself(self):
        for zone, var, ns, key in NS_SCRIPTS:
            r, calls = self.run_script(self.script(zone), "--policy-only")
            self.assertEqual(r.returncode, 0, r.out)
            self.assertIn("pa_zonenetpol %s scoped" % zone, calls)
            self.assertEqual(self.applies(), [])

    def test_invalid_or_equal_namespaces_are_refused(self):
        r, calls = self.run_script(self.script("research-gw"), RESEARCH_GW_NAMESPACE="Bad_Name")
        # the environment is overridden by config.env: write it there
        self.write_config(RESEARCH_GW_NAMESPACE="Bad_Name")
        r, calls = self.run_script(self.script("research-gw"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("must match", r.out)
        self.write_config(RESEARCH_GW_NAMESPACE=RNS)   # equal to the research namespace
        r, calls = self.run_script(self.script("research-gw"))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.applies(), [])

    def test_a_namespace_left_after_switching_off_is_named(self):
        self.write_config(RESEARCH_ENABLED="false")
        r, calls = self.run_script(self.script("research-agents"))
        self.assertIn("is still there and is left as it is", r.out)


def bash_fn(snippet, **env):
    e = clean_env(NAMESPACE="medcea", **env)
    r = subprocess.run(["bash", "-c", 'source "$1"; %s' % snippet, "-", os.path.join(REPO, "infra", "lib-policy-tools.sh")],
                       env=e, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


class Helpers(unittest.TestCase):
    def test_zone_namespace_defaults_and_overrides(self):
        rc, out, _ = bash_fn("for z in research research-gw research-agents; do zone_namespace $z; done")
        self.assertEqual(out.split(), ["medcea-research", "medcea-research-gw", "medcea-research-agents"])
        rc, out, _ = bash_fn("zone_namespace research-gw; zone_namespace research-agents",
                             RESEARCH_NAMESPACE="r", RESEARCH_GW_NAMESPACE="g", RESEARCH_AGENTS_NAMESPACE="a")
        self.assertEqual(out.split(), ["g", "a"])
        rc, out, err = bash_fn("zone_namespace platform")
        self.assertEqual(rc, 2)

    def test_zone_netpol_args(self):
        rc, out, _ = bash_fn("zone_netpol_args research-gw")
        self.assertEqual(out.split(), ["--zone", "research-gw", "--namespace", "medcea-research-gw",
                                       "--platform-namespace", "medcea", "--zone-namespace", "research=medcea-research",
                                       "--zone-namespace", "research-agents=medcea-research-agents"])
        rc, out, _ = bash_fn("zone_netpol_args research")
        self.assertEqual(out.split().count("--zone-namespace"), 2)
        self.assertNotIn("research=", out)

    def test_the_compiler_accepts_these_arguments(self):
        sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
        sys.path.insert(0, os.path.join(REPO, "apps", "iam", "compiler"))
        import apply_check
        import netpol  # noqa: F401
        # the factory policy (4a's commit B) has the research-agents zone: its policies compile
        rc, out, err = bash_fn("zone_netpol_args research-agents")
        args = out.split() + ["--node-ip", "192.0.2.1"]
        r = subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"), "--defaults",
                            "compile", "netpol"] + args, capture_output=True, text=True, env=clean_env())
        self.assertEqual(r.returncode, 0, r.stderr)
        names = [i["metadata"]["name"] for i in json.loads(r.stdout)["items"]]
        self.assertEqual(names[0], "ra-default-deny")
        self.assertIn("ra-mcp-sim", names)
        self.assertEqual(apply_check.netpol_zone_args("research-agents")[:6], args[:6])

    def test_apply_check_zone_targets(self):
        sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
        sys.path.insert(0, os.path.join(REPO, "apps", "iam", "compiler"))
        import apply_check
        import model
        self.assertEqual(apply_check.ZONE_TARGETS["research-gw"], "netpol-research-gw")
        self.assertEqual(apply_check.target_owners({"research-gw"})["netpol-research-gw"],
                         "./infra/deploy-research-gw-namespace.sh --policy-only")
        self.assertEqual(apply_check.target_owners({"research-agents"})["netpol-research-agents"],
                         "./infra/deploy-research-agents-namespace.sh --policy-only")
        self.assertNotIn("netpol-research-gw", apply_check.target_owners(set()))
        # version 9's policy has neither zone: no target, no digest key (versions 1-9 audit as recorded)
        sys.path.insert(0, os.path.join(REPO, "tests"))
        import rs2b_fixture
        names = [n for n, _ in apply_check.targets(model.Policy(rs2b_fixture.v9_policy()))]
        self.assertFalse([n for n in names if n.startswith("netpol-research-")])
        names = [n for n, _ in apply_check.targets(model.load_defaults())]   # 4a's commit B names both
        self.assertIn("netpol-research-gw", names)
        self.assertIn("netpol-research-agents", names)
        outs = {"routes": (0, '{"digest": "d"}', ""), "mqtt": (0, '{"digest": "m"}', ""), "netpol-research-gw": (0, "g", ""),
                "netpol-research-agents": (0, "a", "")}
        d = apply_check.digests_of(outs)
        self.assertEqual((d["netpol_research_gw"], d["netpol_research_agents"]), (apply_check.sha("g"), apply_check.sha("a")))
        d = apply_check.digests_of({"routes": outs["routes"], "mqtt": outs["mqtt"]})
        self.assertFalse([k for k in d if k.startswith("netpol_research")])
        import cli
        self.assertTrue({"netpol_research_gw", "netpol_research_agents"} <= set(cli.OPTIONAL_ARTEFACT_KEYS))


class Deploy(Tree):
    DEPLOY = "apps/research-agents/deploy.sh"

    def skip(self, why, **env):
        r, calls = self.run_script(self.DEPLOY, **env)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: " + why, r.out)
        self.assertEqual(self.applies(), [])
        self.assertEqual(calls[-1], "finish medcea research-agents")
        return r, calls

    def test_syntax_and_options(self):
        for s in ("deploy.sh", "uninstall.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)
        r, calls = self.run_script(self.DEPLOY, "--bogus")
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))
        r, calls = self.run_script(self.DEPLOY, "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipped: the applied access policy has no agent campaigns yet", r.out)

    def test_skips(self):
        self.write_config(RESEARCH_ENABLED="false")
        r, calls = self.skip("RESEARCH_ENABLED is not true")
        self.assertFalse([c for c in calls if c.startswith("cli ")])
        self.write_config()
        r, calls = self.skip("the applied access policy has no agent campaigns yet", STUB_POD_ZONE_RC="1")
        self.assertIn("cli pod-zone research-orchestrator", calls)
        for st in ("none", "empty"):
            self.skip("no version of the access policy is applied yet (state %s)" % st, STUB_PS_STATE=st)
        self.skip("namespace %s does not exist yet" % GW, STUB_NO_NS=GW)
        self.skip("namespace %s does not exist yet" % AG, STUB_NO_NS=AG)
        self.skip("no research database yet (./apps/research/deploy.sh)", STUB_NO_STS="1")

    def test_a_skip_names_running_pods_and_leaves_them(self):
        r, calls = self.skip("the applied access policy has no agent campaigns yet", STUB_POD_ZONE_RC="1", STUB_DEPLOYED="1")
        self.assertIn("agent pods are still running in %s (left alone)" % GW, r.out)
        self.assertIn("agent pods are still running in %s (left alone)" % AG, r.out)

    def test_wrong_zones_and_bad_states_refuse(self):
        for env, want in (({"STUB_POD_ZONE": "research"}, "it lives only in research-agents"),
                          ({"STUB_POD_ZONE_RC": "2"}, "cli.py pod-zone research-orchestrator exit 2")):
            r, calls = self.run_script(self.DEPLOY, **env)
            self.assertEqual(r.returncode, 1, env)
            self.assertIn(want, r.out)
            self.assertNotIn("finish medcea research-agents", calls)
        for st in ("partial", "unreachable"):
            r, calls = self.run_script(self.DEPLOY, STUB_PS_STATE=st)
            self.assertEqual(r.returncode, 1, st)
        self.assertEqual(self.applies(), [])

    def test_preconditions(self):
        for conf, want in ((dict(RS_SESSION_HMAC_KEY=""), "RS_SESSION_HMAC_KEY"), (dict(RS_SESSION_HMAC_KEY="zz"), "RS_SESSION_HMAC_KEY"),
                           (dict(RS_SESSION_DB_PASS=""), "RS_SESSION_DB_PASS"), (dict(RS_SESSION_DB_PASS="a b"), "RS_SESSION_DB_PASS"),
                           (dict(RESEARCH_GW_NAMESPACE=RNS), "must all differ"), (dict(RESEARCH_WHEEL_DIR="rel/dir"), "absolute path")):
            self.write_config(**conf)
            r, calls = self.run_script(self.DEPLOY)
            self.assertEqual(r.returncode, 1, conf)
            self.assertIn(want, r.out)
            self.assertEqual(self.applies(), [], conf)

    def test_never_an_open_pod(self):
        for env, want in (({"STUB_EQ_RC": "1"}, "are not the compiled ones"), ({"STUB_EQ_RC": "2"}, "cannot compare"),
                          ({"STUB_NO_NETPOL": "1"}, "no NetworkPolicy in")):
            r, calls = self.run_script(self.DEPLOY, **env)
            self.assertEqual(r.returncode, 1, (env, r.out))
            self.assertIn(want, r.out)
            self.assertEqual(self.applies(), [], env)
            self.assertNotIn("finish medcea research-agents", calls)

    def test_full_path(self):
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(calls[0], "init medcea")
        self.assertEqual(calls[-1], "finish medcea research-agents")
        self.assertIn("zonenetpol_equal research-gw SCRIPT_DIR=%s" % self.root, calls)
        self.assertIn("zonenetpol_equal research-agents SCRIPT_DIR=%s" % self.root, calls)
        # the wheels came first, once per zone, from the pinned hashes
        self.assertEqual([c for c in calls if c.startswith("pip ")].__len__(), 4)   # two zones, two requirement files
        for zd in ("gw", "agents"):
            self.assertEqual(sorted(os.listdir(os.path.join(self.wheels, zd))),
                             ["ctrl-3-py3-none-any.whl", "one-1-py3-none-any.whl", "two-2-py3-none-any.whl"])
        kinds = []
        for t in self.applies():
            for d in docs(t):
                kinds.append((d["kind"], d["metadata"]["name"], d["metadata"].get("namespace")))
        names = [k for k in kinds]
        self.assertEqual([k[:2] for k in names[:5]], [("PersistentVolume", GW + "-research-wheels"), ("PersistentVolumeClaim", "research-wheels"),
                                                      ("PersistentVolume", AG + "-research-wheels"), ("PersistentVolumeClaim", "research-wheels"),
                                                      ("PersistentVolumeClaim", "research-runs")])
        secrets = [k for k in kinds if k[0] == "Secret"]
        self.assertEqual([(k[1], k[2]) for k in secrets], [("research-session-key", GW), ("research-session-db", GW)])
        self.assertFalse([k for k in kinds if k[0] == "Secret" and k[2] == AG])
        # order: secrets before the iam copies before the bundle before the pods
        order = [k[0] + "/" + k[1] for k in kinds]
        self.assertLess(order.index("Secret/research-session-db"), order.index("ConfigMap/medcea-iam-lib"))
        self.assertLess(order.index("ConfigMap/medcea-jwks"), order.index("ConfigMap/research-code"))
        self.assertLess(order.index("ConfigMap/research-code"), order.index("Deployment/research-session"))
        self.assertLess(order.index("Deployment/research-session"), order.index("Deployment/research-orchestrator"))
        rollouts = [c for c in calls if c.startswith("kubectl rollout status")]
        self.assertEqual(rollouts, ["kubectl rollout status deployment/research-session -n %s --timeout=5m" % GW] +
                         ["kubectl rollout status deployment/%s -n %s --timeout=5m" % (d, AG) for d in ("research-orchestrator", "mcp-sim", "mcp-lake")])
        # the jwks Secret reaches both namespaces as a ConfigMap of public keys
        self.assertEqual(sum(1 for k in kinds if k[:2] == ("ConfigMap", "medcea-jwks")), 2)
        manifest_text = "".join(self.applies())
        self.assertNotIn("${", manifest_text)
        self.assertIn("medcea/auth-secret-version: \"11-12-\"", manifest_text)
        self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("app-research-agents-deploy-")])
        # a second run downloads nothing
        self.clear_applies()
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertFalse([c for c in calls if c.startswith("pip ")])

    def test_the_gateway_address_follows_the_local_model_switch(self):
        def orch_env():
            for t in self.applies():
                for d in docs(t):
                    if d["kind"] == "Deployment" and d["metadata"]["name"] == "research-orchestrator":
                        return {e["name"]: e.get("value") for e in d["spec"]["template"]["spec"]["containers"][0]["env"]}
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(orch_env()["RS_MODEL_GATEWAY_URL"], "")          # no local model: the orchestrator refuses local profiles
        self.clear_applies()
        self.write_config(RESEARCH_LOCAL_MODEL="true")
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(orch_env()["RS_MODEL_GATEWAY_URL"], "http://model-gateway.%s.svc.cluster.local:8120" % GW)

    def test_the_bundle(self):
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        cms = [d for t in self.applies() for d in docs(t) if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "research-code"]
        self.assertEqual({c["metadata"]["namespace"] for c in cms}, {GW, AG})
        commit = subprocess.run(["git", "-C", self.root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        raw = base64.b64decode(cms[0]["binaryData"]["code.tgz"])
        self.assertEqual(cms[0]["metadata"]["annotations"]["medcea/code-sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(cms[0]["metadata"]["annotations"]["medcea/code-commit"], commit)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            names = tf.getnames()
            bundle = json.loads(tf.extractfile("BUNDLE.json").read())
        self.assertNotIn(".", names)
        self.assertNotIn("./", names)
        for want in ("schd/cea/a.py", "research/b.py", "apps/research-agents/session.py", "apps/database/recipe_types.yaml",
                     "edge/templates/esp32-control.json", "apps/research/db/lake_api.sql"):
            self.assertIn(want, names)
        self.assertEqual((bundle["commit"], bundle["dirty"]), (commit, False))
        self.assertEqual(bundle["files"]["schd/cea/a.py"], subprocess.run(
            ["git", "-C", self.root, "rev-parse", "HEAD:schd/cea/a.py"], capture_output=True, text=True).stdout.strip())
        # server-side apply (the last-applied annotation would copy the bundle), deterministic bytes
        self.assertTrue([c for c in calls if c.startswith("kubectl apply --server-side --force-conflicts --field-manager=medcea-research-agents")])
        self.clear_applies()
        r, calls = self.run_script(self.DEPLOY)
        cms2 = [d for t in self.applies() for d in docs(t) if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "research-code"]
        self.assertEqual(cms2[0]["binaryData"], cms[0]["binaryData"])

    def test_a_dirty_bundle_path_is_refused(self):
        with open(os.path.join(self.root, "research", "b.py"), "a") as f:
            f.write("C = 3\n")
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 1)
        self.assertIn("differ from HEAD", r.out)
        self.assertFalse([t for t in self.applies() if "research-code" in t])
        self.assertNotIn("finish medcea research-agents", calls)

    def test_wheels_that_do_not_match_are_refused(self):
        sh(os.path.join(self.bin, "pip2"), STUB_PIP.replace("wheel-two", "other"))
        r, calls = self.run_script(self.DEPLOY, MEDCEA_RESEARCH_PIP=os.path.join(self.bin, "pip2"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("do not match the pinned hashes", r.out)
        self.assertEqual(self.applies(), [])

    def test_a_failed_rollout_dies(self):
        r, calls = self.run_script(self.DEPLOY, STUB_ROLLOUT_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("research-session did not become ready", r.out)
        self.assertNotIn("finish medcea research-agents", calls)


class Uninstall(Tree):
    def test_removes_the_machinery_and_keeps_the_data(self):
        r, calls = self.run_script("apps/research-agents/uninstall.sh")
        self.assertEqual(r.returncode, 0, r.out)
        text = "\n".join(calls)
        self.assertIn("kubectl delete jobs --all -n %s" % AG, text)
        self.assertIn("kubectl delete rolebinding,role,serviceaccount research-orchestrator -n %s" % AG, text)
        self.assertIn("kubectl delete secret research-session-key research-session-db -n %s" % GW, text)
        self.assertIn("kubectl delete pv %s-research-wheels %s-research-wheels" % (GW, AG), text)
        self.assertNotIn("research-runs", text)         # kept without --purge-data
        self.assertNotIn("delete namespace", text)
        self.assertNotIn("helm", text)
        r, calls = self.run_script("apps/research-agents/uninstall.sh", "--purge-data")
        self.assertIn("kubectl delete pvc research-runs -n %s" % AG, "\n".join(calls))

    def test_no_namespaces(self):
        r, calls = self.run_script("apps/research-agents/uninstall.sh", STUB_NO_NS="medcea-research")
        self.assertEqual(r.returncode, 0)
        self.assertIn("does not exist: nothing to remove there", r.out)

    def test_unknown_option(self):
        r, calls = self.run_script("apps/research-agents/uninstall.sh", "--bogus")
        self.assertEqual(r.returncode, 2)


class Wiring(unittest.TestCase):
    def test_research_deploy_chains_it_after_lake_api(self):
        t = code(read("apps/research/deploy.sh"))
        self.assertIn('bash "$REPO_ROOT/apps/research-agents/deploy.sh"', t)
        self.assertLess(t.index("apps/lake-api/deploy.sh"), t.index("apps/research-agents/deploy.sh"))
        self.assertLess(t.index("apps/research-agents/deploy.sh"), t.rindex('policy_source_finish "$NAMESPACE" research'))

    def test_research_uninstall_runs_it_before_lake_api(self):
        t = code(read("apps/research/uninstall.sh"))
        self.assertLess(t.index("apps/research-agents/uninstall.sh"), t.index("apps/lake-api/uninstall.sh"))

    def test_deploy_apps_counts_it(self):
        self.assertIn("research-agents", re.search(r"POLICY_COMPILING=\(([^)]*)\)", read("deploy-apps.sh")).group(1).split())

    def test_configure_and_example(self):
        self.assertIn("RS_SESSION_HMAC_KEY", read("infra/configure.sh"))
        ex = read("config.env.example")
        for k in ('RS_SESSION_HMAC_KEY=""', 'RESEARCH_GW_NAMESPACE="${RESEARCH_NAMESPACE}-gw"',
                  'RESEARCH_AGENTS_NAMESPACE="${RESEARCH_NAMESPACE}-agents"', 'RESEARCH_WHEEL_DIR=""'):
            self.assertIn(k, ex)

    def test_deploy_infra_calls_the_zones_after_the_research_namespace(self):
        t = code(read("deploy-infra.sh"))
        a = t.index('"$SCRIPT_DIR/infra/deploy-research-namespace.sh"')
        b = t.index('"$SCRIPT_DIR/infra/deploy-research-$_rz-namespace.sh"')
        self.assertLess(a, b)
        self.assertIn("for _rz in gw agents", t)
        # validated like RESEARCH_NAMESPACE; reset and uninstall remove labelled namespaces only
        self.assertIn("RESEARCH_GW_NAMESPACE RESEARCH_AGENTS_NAMESPACE", t)
        self.assertIn('== "$_zl" ]]', t)

    def test_deploy_policy_runs_the_zones_scoped(self):
        # 7a: deploy-policy.sh runs the zones' scoped modes while RESEARCH_ENABLED, "not deployed" without the zone
        t = code(read("infra/deploy-policy.sh"))
        self.assertIn('pa_zonenetpol "$_z" scoped', t)
        self.assertIn("for _z in research-gw research-agents", t)
        self.assertLess(t.index("pa_rsnetpol scoped"), t.index('pa_zonenetpol "$_z" scoped'))


class JobManifests(unittest.TestCase):
    """Stage 6b2: agent and sim Jobs carry what the Deployments of agents.yaml carry."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(REPO, "apps", "research-agents"))
        import jobs
        cfg = {"image": "img@sha256:" + "a" * 64, "code_commit": "abc", "session_url": "http://s", "mcp_sim_url": "http://m",
               "mcp_lake_url": "http://l"}
        cls.agent = jobs.agent_job(cfg, "A" * 22, "c" * 43, "compare_controllers", 1)
        cls.sim = jobs.sim_job(cfg, "c" + "0" * 20, {"x": 1}, 1, 3600, 2)
        cls.est = jobs.estimate_job(cfg, "e" + "0" * 20, {"x": 1})
        cls.rep = jobs.replay_job(cfg, "A" * 22, "compare_controllers", [{"event_id": 1, "event": "stop", "actor": "agent", "payload": {}}])

    def test_pod_hardening(self):
        for j in (self.agent, self.sim, self.est, self.rep):
            ps = j["spec"]["template"]["spec"]
            self.assertFalse(ps["automountServiceAccountToken"])
            self.assertEqual(ps["priorityClassName"], "medcea-research-low")
            self.assertEqual(ps["securityContext"]["runAsUser"], 65534)
            self.assertIn("activeDeadlineSeconds", j["spec"])
            self.assertNotIn("ownerReferences", j["metadata"])
            for c in ps["initContainers"] + ps["containers"]:
                sc = c["securityContext"]
                self.assertTrue(sc["readOnlyRootFilesystem"])
                self.assertFalse(sc["allowPrivilegeEscalation"])
                self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})
                self.assertIn("memory", c["resources"]["limits"])

    def test_unpack_matches_the_deployments(self):
        text = open(os.path.join(REPO, "apps", "research-agents", "k8s", "agents.yaml")).read()
        text = text.replace('\\"', '"')
        for j in (self.agent, self.sim, self.est, self.rep):
            cmd = j["spec"]["template"]["spec"]["initContainers"][0]["command"][2]
            base = cmd.split("; python3 -m pip install", 1)
            self.assertIn(base[0] + "; python3 -m pip install" + base[1].split("; python3")[0], text)
        # only the sim and estimate Jobs install the controller wheels, and never a Deployment
        has = lambda j: "requirements-controllers.txt" in j["spec"]["template"]["spec"]["initContainers"][0]["command"][2]
        self.assertEqual([has(j) for j in (self.agent, self.sim, self.est, self.rep)], [False, True, True, False])
        self.assertNotIn("requirements-controllers", text)

    def test_volumes(self):
        names = lambda j: {v["name"] for v in j["spec"]["template"]["spec"]["volumes"]}
        self.assertNotIn("runs", names(self.agent))
        self.assertIn("runs", names(self.sim))
        m = self.sim["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        self.assertIn({"name": "runs", "mountPath": "/runs"}, m)
        for j in (self.agent, self.sim, self.est, self.rep):
            secrets = [v for v in j["spec"]["template"]["spec"]["volumes"] if "secret" in v]
            self.assertEqual(secrets, [])


    def test_estimate_and_replay_jobs(self):
        import jobs
        self.assertEqual(self.est["metadata"]["name"], "estimate-e" + "0" * 20)
        self.assertEqual(self.est["spec"]["activeDeadlineSeconds"], 600)
        c = self.est["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["command"], ["python3", "-m", "research.agents.sim_job", "--estimate"])
        self.assertEqual(c["resources"], {"requests": {"cpu": "250m", "memory": "512Mi"}, "limits": {"memory": "1Gi"}})
        self.assertNotIn("runs", {v["name"] for v in self.est["spec"]["template"]["spec"]["volumes"]})
        r = self.rep["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(self.rep["metadata"]["name"], jobs.replay_job_name("A" * 22))
        self.assertRegex(self.rep["metadata"]["name"], r"^replay-[0-9a-f]{20}$")
        self.assertEqual(r["command"], ["python3", "apps/research-agents/replay_main.py"])
        env = {e["name"]: e["value"] for e in r["env"]}
        self.assertEqual(env["MEDCEA_EVENTS_N"], "1")
        self.assertTrue(all(len(v) <= jobs.EVENT_CHUNK for k, v in env.items() if k.startswith("MEDCEA_EVENTS_")))
        self.assertEqual(jobs.EVENT_CHUNK + 20, 90020)   # one environment string stays under Linux's 128 KiB

    def test_events_pack_in_chunks_and_refuse_a_huge_trace(self):
        import jobs, random
        rnd = random.Random(1)
        big = [{"event_id": i, "payload": {"x": "%032x" % rnd.getrandbits(128)}} for i in range(60000)]
        with self.assertRaisesRegex(ValueError, "too large to replay as a Job"):
            jobs.pack_events(big)
        mid = jobs.pack_events(big[:12000])
        self.assertGreater(len(mid), 1)
        self.assertTrue(all(len(c) <= jobs.EVENT_CHUNK for c in mid))


if __name__ == "__main__":
    unittest.main()
