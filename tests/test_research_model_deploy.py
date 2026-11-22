#!/usr/bin/env python3
"""tests/test_research_model_deploy.py — research Phase 4b stage 1: the local model's pod, its switch and its
health check (design rs4 5.2, 5.4, 5.5, with the owner's decisions of 21 Nov 2026: Qwen3-4B-Instruct-2507
Q4_K_M, context 4096).

Offline (stdlib unittest), in a scratch tree with a fake cluster:
  Manifest   apps/research-model/k8s/llm.yaml rendered: pinned digest image, -c 4096 through CTX, threads from the
             CPU request (downward API), memory request = limit, no CPU limit, hardened pod, init container
             that checks the pin and AVX, read-only static PV, no Secret, no secret anywhere.
  Script     container/llm-serve.sh against a fake llama-server: its arguments, optional flags only when listed.
  Deploy     apps/research-model/deploy.sh: --help, unknown options exit 2 before log and lock, each skip line,
             the refusals (open pod, root), the fetch through bench.sh, the full path; uninstall keeps the model.
  Switch     config.env.example, an older config.env merges to false, medcea.sh recipes, deploy-apps wiring.
  Health     rsllm against a fake kubectl and curl.

  python3 tests/test_research_model_deploy.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402
import test_health_phase5 as h5  # noqa: E402

APP = os.path.join(REPO, "apps", "research-model")
GW, RNS = "medcea-research-gw", "medcea-research"
PINS = json.load(open(os.path.join(APP, "pins.json")))
M4 = PINS["models"]["4b"]
SHA = M4["sha256"]
ALIAS = "%s-%s" % (M4["file"][:-5].lower(), SHA[:12])


def read(p):
    with open(os.path.join(REPO, p) if not os.path.isabs(p) else p) as f:
        return f.read()


def code(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def sh(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


def render_llm(**over):
    names = re.search(r"Render list: ([A-Z0-9_ ]+)", read("apps/research-model/k8s/llm.yaml")).group(1).split()
    env = {n: "x-" + n.lower().replace("_", "-") for n in names}
    env.update(MODEL_UID="1000", MODEL_GID="1000", LLM_CTX="4096", MODEL_SHA256=SHA,
               LLAMA_IMAGE_SERVER=PINS["llama_cpp"]["image_server"], MODEL_PV=GW + "-research-models",
               RESEARCH_GW_NAMESPACE=GW, MODEL_DIR="/var/lib/medcea/research-models", MODEL_ALIAS=ALIAS)
    env.update(over)
    e = clean_env(**env)
    r = subprocess.run(["bash", "-c", 'source "$1"; shift; render "$@"', "-", os.path.join(REPO, "infra", "lib-render.sh"),
                        os.path.join(APP, "k8s", "llm.yaml")] + sorted(env), env=e, capture_output=True, text=True, check=True)
    import yaml
    return [d for d in yaml.safe_load_all(r.stdout) if d], r.stdout


class Manifest(unittest.TestCase):
    def setUp(self):
        self.docs, self.text = render_llm()
        self.dep = [d for d in self.docs if d["kind"] == "Deployment"][0]
        self.pod = self.dep["spec"]["template"]["spec"]
        self.main = self.pod["containers"][0]

    def test_every_variable_is_in_the_render_list(self):
        used = set(re.findall(r"\$\{([A-Z_0-9]+)\}", code(read("apps/research-model/k8s/llm.yaml"))))
        listed = set(re.search(r"Render list: ([A-Z0-9_ ]+)", read("apps/research-model/k8s/llm.yaml")).group(1).split())
        self.assertEqual(used, listed)
        self.assertNotIn("${", self.text)

    def test_image_pinned_and_context(self):
        self.assertRegex(self.main["image"], r"^ghcr\.io/ggml-org/llama\.cpp:server-b12182@sha256:[0-9a-f]{64}$")
        env = {e["name"]: e for e in self.main["env"]}
        self.assertEqual(env["CTX"]["value"], "4096")
        self.assertEqual(env["MODEL"]["value"], "/models/%s.gguf" % SHA)
        self.assertEqual(env["LLM_MODEL_SHA256"]["value"], SHA)
        self.assertEqual(env["THREADS"]["valueFrom"]["resourceFieldRef"]["resource"], "requests.cpu")

    def test_resources(self):
        r = self.main["resources"]
        self.assertEqual(r["requests"], {"cpu": "6", "memory": "6Gi"})
        self.assertEqual(r["limits"], {"memory": "6Gi"})   # no CPU limit (OD10)

    def test_hardening(self):
        sc = self.pod["securityContext"]
        self.assertTrue(sc["runAsNonRoot"])
        self.assertNotIn(sc["runAsUser"], (0, "0"))
        self.assertEqual(self.pod["priorityClassName"], "medcea-research-low")
        self.assertIs(self.pod["automountServiceAccountToken"], False)
        self.assertIs(self.pod["enableServiceLinks"], False)
        for c in self.pod["containers"] + self.pod["initContainers"]:
            self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True, c["name"])
            self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
            self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertEqual(self.dep["metadata"]["labels"]["app"], "research-llm")

    def test_no_secret_and_no_hostpath_in_the_pod(self):
        self.assertNotIn("secret", json.dumps(self.pod).lower().replace("secretkeyref", "X") .replace("automountserviceaccounttoken", ""))
        for v in self.pod["volumes"]:
            self.assertNotIn("hostPath", v)
        pv = [d for d in self.docs if d["kind"] == "PersistentVolume"][0]
        self.assertEqual(pv["spec"]["accessModes"], ["ReadOnlyMany"])
        self.assertEqual(pv["spec"]["claimRef"], {"namespace": GW, "name": "research-models"})
        self.assertIn("hostPath", pv["spec"])

    def test_init_checks_the_pin_and_avx(self):
        init = self.pod["initContainers"][0]
        cmd = init["command"][-1]
        self.assertIn("grep -qw avx /proc/cpuinfo", cmd)
        self.assertIn("sha256sum -c", cmd)
        self.assertIn(SHA, cmd)

    def test_probe_and_service(self):
        self.assertEqual(self.main["readinessProbe"]["httpGet"]["path"], "/health")
        svc = [d for d in self.docs if d["kind"] == "Service"][0]
        self.assertEqual((svc["spec"]["type"], svc["spec"]["ports"][0]["port"]), ("ClusterIP", 8080))

    def test_slots_dir_is_an_emptydir(self):
        vols = {v["name"]: v for v in self.pod["volumes"]}
        self.assertIn("emptyDir", vols["slots"])
        self.assertTrue([m for m in self.main["volumeMounts"] if m["mountPath"] == "/slots"])


class GatewayManifest(unittest.TestCase):
    """k8s/gateway.yaml (stage 2): the model gateway's pod and Service."""
    def render(self):
        import yaml
        r = subprocess.run(["bash", "-c", 'source infra/lib-render.sh; render apps/research-model/k8s/gateway.yaml '
                            'RESEARCH_GW_NAMESPACE GATEWAY_IMAGE MODEL_ALIAS MODEL_SHA256 LLM_CTX GATEWAY_CODE_SHA256'],
                           cwd=REPO, capture_output=True, text=True,
                           env=dict(clean_env(), RESEARCH_GW_NAMESPACE=GW, GATEWAY_IMAGE=PINS["python_image"], MODEL_ALIAS=ALIAS,
                                    MODEL_SHA256=SHA, LLM_CTX="4096", GATEWAY_CODE_SHA256="ab" * 32))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("${", r.stdout)
        return [d for d in yaml.safe_load_all(r.stdout) if d]

    def test_render_list_is_complete(self):
        head = [l for l in read("apps/research-model/k8s/gateway.yaml").splitlines() if l.startswith("# Render list:")][0]
        listed = set(head.split(":", 1)[1].split())
        used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", read("apps/research-model/k8s/gateway.yaml")))
        self.assertEqual(listed, used)
        self.assertIn("RESEARCH_GW_NAMESPACE GATEWAY_IMAGE MODEL_ALIAS MODEL_SHA256 LLM_CTX GATEWAY_CODE_SHA256", read("apps/research-model/deploy.sh"))

    def test_pod(self):
        dep, svc = self.render()
        spec = dep["spec"]["template"]["spec"]
        c = spec["containers"][0]
        self.assertEqual(dep["metadata"]["namespace"], GW)
        self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(c["image"], PINS["python_image"])
        self.assertEqual(spec["priorityClassName"], "medcea-research-low")
        self.assertIs(spec["automountServiceAccountToken"], False)
        self.assertIs(spec["enableServiceLinks"], False)
        self.assertEqual(spec["securityContext"]["runAsUser"], 65534)
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertIn("memory", c["resources"]["limits"])
        self.assertEqual(dep["spec"]["template"]["metadata"]["annotations"]["medcea/code-sha256"], "ab" * 32)
        env = {e["name"]: e.get("value") for e in c["env"]}
        self.assertEqual(env["RS_SESSION_SERVER_URL"], "http://research-session.%s.svc.cluster.local:8102" % GW)
        self.assertEqual(env["RS_LLM_URL"], "http://research-llm.%s.svc.cluster.local:8080" % GW)
        self.assertEqual(env["MODEL_ALIAS"], ALIAS)

    def test_no_secret_no_hostpath_no_pv(self):
        docs = self.render()
        text = json.dumps(docs)
        for bad in ("secretKeyRef", "\"secret\"", "hostPath", "PersistentVolume", "NodePort", "LoadBalancer", "hostNetwork"):
            self.assertNotIn(bad, text)
        self.assertEqual([v["name"] for v in docs[0]["spec"]["template"]["spec"]["volumes"]], ["code"])

    def test_service_is_clusterip_8120(self):
        svc = self.render()[1]
        self.assertEqual(svc["spec"]["type"], "ClusterIP")
        self.assertEqual(svc["spec"]["ports"][0]["port"], 8120)
        self.assertEqual(svc["spec"]["selector"], {"app": "model-gateway"})


class Serve(unittest.TestCase):
    def run_serve(self, help_text):
        d = __import__("tempfile").mkdtemp()
        try:
            fake = os.path.join(d, "llama-server")
            sh(fake, '#!/bin/sh\nif [ "$1" = --help ]; then cat <<\'H\'\n%s\nH\nexit 0; fi\necho "ARGS $*"\n' % help_text)
            e = clean_env(LLAMA_SERVER=fake, MODEL="/models/x.gguf", ALIAS="a", THREADS="6", CTX="4096")
            r = subprocess.run(["sh", os.path.join(APP, "container", "llm-serve.sh")], env=e, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            return [l for l in r.stdout.splitlines() if l.startswith("ARGS ")][0]
        finally:
            shutil.rmtree(d)

    def test_args(self):
        full = "--metrics\n--no-webui\n--cache-prompt\n--slot-save-path PATH\n--samplers SAMPLERS"
        a = self.run_serve(full)
        for want in ("-m /models/x.gguf", "--alias a", "--host 0.0.0.0", "--port 8080", "-t 6 -tb 6", "-c 4096", "-np 1", "--jinja",
                     "--temp 0", "--top-k 1", "--seed 1", "--metrics", "--no-webui", "--cache-prompt", "--slot-save-path /slots",
                     "--samplers top_k"):
            self.assertIn(want, a)
        self.assertNotIn("api-key", a)

    def test_optional_flags_only_when_listed(self):
        a = self.run_serve("--metrics")
        self.assertIn("--metrics", a)
        for no in ("--no-webui", "--cache-prompt", "--slot-save-path", "--samplers"):
            self.assertNotIn(no, a)
        self.assertIn("-c 4096", a)

    def test_syntax(self):
        subprocess.run(["sh", "-n", os.path.join(APP, "container", "llm-serve.sh")], check=True)


STUB_KUBECTL = r"""#!/usr/bin/env bash
a="$*"; echo "kubectl ${a//$'\n'/ }" >> "$STUB_LOG"
n=$(ls "$STUB_DIR" | grep -c '^in-' || true)
case "$*" in
  "get namespace "*) [[ "${STUB_NO_NS:-}" == "" || "$*" != *"${STUB_NO_NS}"* ]]; exit $? ;;
  "get deployment research-llm "*) [[ -z "${STUB_DEPLOYED:-}" ]] || echo deployment.apps/research-llm ;;
  "get networkpolicy -n "*) [[ -n "${STUB_NO_NETPOL:-}" ]] || echo networkpolicy.networking.k8s.io/gw-default-deny ;;
  "rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  "apply "*) cat > "$STUB_DIR/in-$(printf %03d "$n")-apply" ;;
esac
exit 0
"""
STUB_BENCH = r"""#!/usr/bin/env bash
echo "bench $*" >> "$STUB_LOG"
[[ -z "${STUB_FETCH_FAIL:-}" ]] || exit 1
touch "$RESEARCH_MODEL_DIR/%s.gguf"
""" % SHA


class Tree(unittest.TestCase):
    def setUp(self):
        self.root = scratch_repo("medcea-rmodel-")
        r = self.root
        shutil.copytree(APP, os.path.join(r, "apps", "research-model"), ignore=shutil.ignore_patterns("__pycache__"))
        os.makedirs(os.path.join(r, "apps", "research-agents"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "research-agents", "mcp_common.py"), os.path.join(r, "apps", "research-agents"))
        self.bin = os.path.join(r, "bin")
        self.stub = os.path.join(r, "stub")
        self.models = os.path.join(r, "models")
        os.makedirs(self.bin)
        os.makedirs(self.stub)
        os.makedirs(self.models)
        os.chmod(self.models, 0o700)
        self.log = os.path.join(r, "calls.log")
        sh(os.path.join(self.bin, "kubectl"), STUB_KUBECTL)
        sh(os.path.join(r, "apps", "research-model", "bench.sh"), STUB_BENCH)
        with open(os.path.join(r, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s/mk8s"; KUBECTL="%s/kubectl"\n' % (self.bin, self.bin))
        with open(os.path.join(r, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    'policy_db_state() { echo "${STUB_PS_STATE:-version-7}"; }\n')
        with open(os.path.join(r, "infra", "lib-policy-artefacts.sh"), "w") as f:
            f.write('source "$SCRIPT_DIR/infra/lib-policy-tools.sh"\n'
                    '_pa_zonenetpol_equal() { echo "zonenetpol_equal $1" >> "$STUB_LOG"; return "${STUB_EQ_RC:-0}"; }\n')
        with open(os.path.join(r, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write('import os, sys\nopen(os.environ["STUB_LOG"], "a").write("cli " + " ".join(sys.argv[1:]) + "\\n")\n'
                    'rc = int(os.environ.get("STUB_POD_ZONE_RC", "0"))\n'
                    'print(os.environ.get("STUB_POD_ZONE", "research-gw")) if rc == 0 else None\nsys.exit(rc)\n')
        self.write_config()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, **extra):
        conf = dict(NAMESPACE="medcea", PROJECT_NAME="medcea", RESEARCH_ENABLED="true", RESEARCH_LOCAL_MODEL="true",
                    RESEARCH_NAMESPACE=RNS, RESEARCH_MODEL_DIR=self.models)
        conf.update(extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def run_script(self, rel, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub, "RESEARCH_MODEL_DIR": self.models,
                              "PATH": self.bin + ":" + os.environ["PATH"]}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG"):
            e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, rel)] + list(args), env=e, capture_output=True, text=True,
                           timeout=90, stdin=subprocess.DEVNULL, cwd=self.root)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        if os.path.exists(self.log):
            os.remove(self.log)
        r.out = r.stdout + r.stderr
        return r, calls

    def applies(self):
        import yaml
        out = []
        for f in sorted(os.listdir(self.stub)):
            if f.endswith("-apply"):
                out += [d for d in yaml.safe_load_all(read(os.path.join(self.stub, f))) if d]
        return out

    def have_model(self):
        open(os.path.join(self.models, SHA + ".gguf"), "w").close()


class Deploy(Tree):
    DEPLOY = "apps/research-model/deploy.sh"

    def skip(self, why, **env):
        r, calls = self.run_script(self.DEPLOY, **env)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: " + why, r.out)
        self.assertEqual(self.applies(), [])
        self.assertEqual(calls[-1], "finish medcea research-model")
        return r, calls

    def test_syntax_options_help(self):
        for s in ("deploy.sh", "uninstall.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)
        for s in ("deploy.sh", "uninstall.sh"):
            r, calls = self.run_script("apps/research-model/" + s, "--bogus")
            self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))
        r, calls = self.run_script(self.DEPLOY, "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipped: RESEARCH_LOCAL_MODEL is not true", r.out)

    def test_skips(self):
        self.write_config(RESEARCH_ENABLED="false")
        self.skip("RESEARCH_ENABLED is not true")
        self.write_config(RESEARCH_LOCAL_MODEL="false")
        r, calls = self.skip("RESEARCH_LOCAL_MODEL is not true")
        self.assertFalse([c for c in calls if c.startswith("cli ")])
        self.write_config()
        r, calls = self.skip("the applied access policy has no research-llm pod yet", STUB_POD_ZONE_RC="1")
        self.assertIn("cli pod-zone research-llm", calls)
        for st in ("none", "empty"):
            self.skip("no version of the access policy is applied yet (state %s)" % st, STUB_PS_STATE=st)
        self.skip("namespace %s does not exist yet" % GW, STUB_NO_NS=GW)

    def test_a_skip_names_a_running_pod(self):
        r, calls = self.skip("the applied access policy has no research-llm pod yet", STUB_POD_ZONE_RC="1", STUB_DEPLOYED="1")
        self.assertIn("research-llm is still running in %s (left alone)" % GW, r.out)

    def test_refusals(self):
        for env, want in (({"STUB_POD_ZONE": "research"}, "it lives only in research-gw"),
                          ({"STUB_POD_ZONE_RC": "2"}, "cannot be read"),
                          ({"STUB_PS_STATE": "partial"}, "state in the database is 'partial'"),
                          ({"STUB_EQ_RC": "1"}, "are not the compiled ones"), ({"STUB_EQ_RC": "2"}, "cannot compare"),
                          ({"STUB_NO_NETPOL": "1"}, "no NetworkPolicy in")):
            self.have_model()
            r, calls = self.run_script(self.DEPLOY, **env)
            self.assertEqual(r.returncode, 1, (env, r.out))
            self.assertIn(want, r.out)
            self.assertEqual(self.applies(), [], env)
            self.assertNotIn("finish medcea research-model", calls)
        self.write_config(RESEARCH_MODEL_DIR="rel/dir")
        r, calls = self.run_script(self.DEPLOY, RESEARCH_MODEL_DIR="")
        self.assertEqual(r.returncode, 1)
        self.assertIn("absolute path", r.out)

    def test_fetches_a_missing_model_through_bench(self):
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("bench fetch --models 4b", calls)
        r, calls = self.run_script(self.DEPLOY)          # now present: no second fetch
        self.assertFalse([c for c in calls if c.startswith("bench ")])

    def test_a_failed_fetch_applies_nothing(self):
        r, calls = self.run_script(self.DEPLOY, STUB_FETCH_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("the fetch did not finish", r.out)
        self.assertEqual(self.applies(), [])

    def test_full_path(self):
        self.have_model()
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(calls[0], "init medcea")
        self.assertEqual(calls[-1], "finish medcea research-model")
        self.assertIn("zonenetpol_equal research-gw", calls)
        kinds = [(d["kind"], d["metadata"]["name"]) for d in self.applies()]
        self.assertEqual(kinds, [("ConfigMap", "research-llm-script"), ("PersistentVolume", GW + "-research-models"),
                                 ("PersistentVolumeClaim", "research-models"), ("Deployment", "research-llm"),
                                 ("Service", "research-llm"), ("ConfigMap", "model-gateway-code"),
                                 ("Deployment", "model-gateway"), ("Service", "model-gateway")])
        gcm = [d for d in self.applies() if d["metadata"]["name"] == "model-gateway-code"][0]
        self.assertEqual(gcm["data"]["gateway.py"], read("apps/research-model/gateway.py"))
        self.assertEqual(gcm["data"]["mcp_common.py"], read("apps/research-agents/mcp_common.py"))
        self.assertIn("kubectl rollout status deployment/model-gateway -n %s --timeout=5m" % GW, calls)
        cm = self.applies()[0]
        self.assertEqual(cm["data"]["llm-serve.sh"], read("apps/research-model/container/llm-serve.sh"))
        dep = [d for d in self.applies() if d["kind"] == "Deployment" and d["metadata"]["name"] == "research-llm"][0]
        main = dep["spec"]["template"]["spec"]["containers"][0]
        env = {e["name"]: e.get("value") for e in main["env"]}
        self.assertEqual((env["CTX"], env["ALIAS"], env["LLM_MODEL_SHA256"]), ("4096", ALIAS, SHA))
        self.assertEqual(dep["spec"]["template"]["spec"]["securityContext"]["runAsUser"], os.stat(self.models).st_uid)
        self.assertIn("kubectl rollout status deployment/research-llm -n %s --timeout=10m" % GW, calls)
        pv = [d for d in self.applies() if d["kind"] == "PersistentVolume"][0]
        self.assertEqual(pv["spec"]["hostPath"]["path"], self.models)
        self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("app-research-model-deploy-")])
        # nothing in any argv or manifest is a secret: the deploy handles none
        self.assertNotIn("${", json.dumps([d for d in self.applies() if d["kind"] != "ConfigMap"]))

    def test_a_failed_rollout_dies(self):
        self.have_model()
        r, calls = self.run_script(self.DEPLOY, STUB_ROLLOUT_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("research-llm did not become ready", r.out)
        self.assertNotIn("finish medcea research-model", calls)

    def test_a_pin_is_read_from_pins_json(self):
        p = os.path.join(self.root, "apps", "research-model", "pins.json")
        d = json.load(open(p))
        d["llama_cpp"]["image_server"] = "ghcr.io/x/y:server-b1"
        json.dump(d, open(p, "w"))
        self.have_model()
        r, calls = self.run_script(self.DEPLOY)
        self.assertEqual(r.returncode, 1)
        self.assertIn("pinned by digest", r.out)


class Uninstall(Tree):
    def test_removes_the_server_and_keeps_the_model(self):
        self.have_model()
        r, calls = self.run_script("apps/research-model/uninstall.sh")
        self.assertEqual(r.returncode, 0, r.out)
        text = "\n".join(calls)
        self.assertIn("kubectl delete deployment,service research-llm -n %s" % GW, text)
        self.assertIn("kubectl delete deployment,service model-gateway -n %s" % GW, text)
        self.assertIn("kubectl delete configmap model-gateway-code -n %s" % GW, text)
        self.assertLess(text.index("delete deployment,service model-gateway"), text.index("delete deployment,service research-llm"))
        self.assertIn("kubectl delete pvc research-models -n %s" % GW, text)
        self.assertIn("kubectl delete pv %s-research-models" % GW, text)
        self.assertNotIn("delete namespace", text)
        self.assertTrue(os.path.exists(os.path.join(self.models, SHA + ".gguf")))

    def test_no_namespace(self):
        r, calls = self.run_script("apps/research-model/uninstall.sh", STUB_NO_NS=GW)
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to remove there", r.out)


class Wiring(unittest.TestCase):
    def test_deploy_apps_counts_it(self):
        self.assertIn("research-model", re.search(r"POLICY_COMPILING=\(([^)]*)\)", read("deploy-apps.sh")).group(1).split())

    def test_does_not_clash_with_the_agents_uninstall(self):
        # research-agents' uninstall deletes by label app.kubernetes.io/part-of=medcea-research in research-gw
        self.assertNotIn("part-of: medcea-research\n", read("apps/research-model/k8s/llm.yaml"))

    def test_example_and_older_config_merge(self):
        ex = read("config.env.example")
        self.assertRegex(ex, r'(?m)^RESEARCH_LOCAL_MODEL="false"$')
        self.assertRegex(ex, r'(?m)^RESEARCH_MODEL_DIR=""$')
        # configure.sh rebuilds a config.env from the template: a file without the line gets the template's false
        self.assertNotRegex(read("infra/configure.sh"), r'RESEARCH_LOCAL_MODEL="true"')

    def test_medcea_menu_and_recipes(self):
        t = read("medcea.sh")
        for fn in ("a_research_model_deploy", "a_research_model_uninstall", "a_research_model_switch"):
            self.assertIn("%s()" % fn, t)
            self.assertRegex(t, r'(?m)^    "%s\|' % fn)
        self.assertIn("RESEARCH_LOCAL_MODEL:enable)", t)
        self.assertIn("RESEARCH_LOCAL_MODEL:rollback)", t)
        self.assertIn('"set RESEARCH_LOCAL_MODEL true" "run ./apps/research-model/deploy.sh" "run ./health-check.sh"', t)
        self.assertIn('"set RESEARCH_LOCAL_MODEL false" "run ./apps/research-model/uninstall.sh"', t)

    def test_conf_and_dispatch(self):
        conf = read("health-checks.conf")
        lines = [l for l in conf.splitlines() if l.strip() and not l.startswith("#")]
        types = [l.split("|")[1].strip() for l in lines]
        self.assertEqual(types[types.index("rsagent") + 1], "rsllm")
        self.assertRegex(read("health-check.sh"), r'(?m)^        rsllm\)\s+check_rsllm "\$name" "\$target" ;;$')
        self.assertNotRegex(h5.body("check_rsllm"), r"\$KUBECTL (apply|delete|create|patch|edit|set|scale|rollout|label)\b")
        self.assertNotIn("/completion", h5.body("check_rsllm"))   # it generates nothing
        self.assertNotIn("/v1/", h5.body("check_rsllm"))


CURL = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
if "-m" not in a:
    sys.exit(98)
sc = json.load(open(os.path.join(os.environ["FAKE_DIR"], "scenario.json")))
url = [x for x in a if x.startswith("http")][0]
path = "/" + url.split(":8080/", 1)[1]
with open(os.path.join(os.environ["FAKE_DIR"], "calls.log"), "a") as f:
    f.write(json.dumps({"tool": "curl", "argv": a, "stdin": ""}) + "\n")
v = sc.get("urls", {}).get(path)
if v is None:
    sys.exit(7)
sys.stdout.write(v)
'''
PROPS = json.dumps({"model_alias": ALIAS, "chat_template": "{% if tools %}x{% endif %}", "default_generation_settings": {"n_ctx": 4096}})
METRICS = "llamacpp:predicted_tokens_seconds 3.2\nllamacpp:tokens_predicted_total 900\n"


class Health(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = h5.Tree()
        sh_path = os.path.join(cls.t.bin, "curl")
        os.remove(sh_path)
        sh(sh_path, CURL)
        os.makedirs(cls.t.path("infra"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "infra", "lib-policy-tools.sh"), cls.t.path("infra", "lib-policy-tools.sh"))
        os.makedirs(cls.t.path("apps", "research-model"), exist_ok=True)
        shutil.copy(os.path.join(APP, "pins.json"), cls.t.path("apps", "research-model", "pins.json"))
        os.makedirs(cls.t.path("research", "agents", "bench"), exist_ok=True)
        json.dump({"bench": {"best": {"4b": {"gen_tok_s": 3.8}}}}, open(cls.t.path("research", "agents", "bench", "2026-11-21.json"), "w"))

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def check(self, sha=SHA, pod="Running|10.1.2.3|True\n", urls=None, local="true", enabled="true", dep=True):
        rules = []
        if dep:
            rules.append(h5.rule(r"^get deployment research-llm -n %s " % GW, sha))
        rules.append(h5.rule(r"^get pods -n %s -l app=research-llm " % GW, pod))
        u = {"/health": '{"status":"ok"}', "/props": PROPS, "/metrics": METRICS}
        u.update(urls or {})
        self.t.scenario(rules, urls=u)
        r = self.t.fn("check_rsllm", 'check_rsllm "Local model" medcea', helpers=(), RESEARCH_LOCAL_MODEL=local, RESEARCH_ENABLED=enabled)
        for c in self.t.calls():
            if c["tool"] != "curl":
                self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
            else:
                self.assertNotIn("-X", c["argv"])
                self.assertNotIn("-d", c["argv"])
        return r

    def test_ok(self):
        self.assertEqual(self.check(), "OK|Local model|research-llm runs the pinned model; model pin %s matches;/health ok;alias is the pin's;context 4096;generation 3.2 tok/s (bench 3.8)" % SHA[:12])

    def test_skips(self):
        self.assertTrue(self.check(local="false").startswith("SKIP|Local model|the local model is switched off"))
        self.assertTrue(self.check(enabled="false").startswith("SKIP|Local model|the research sandbox is switched off"))

    def test_no_deployment_warns(self):
        r = self.check(dep=False)
        self.assertTrue(r.startswith("WARN|Local model|RESEARCH_LOCAL_MODEL is true but there is no deployment research-llm"), r)

    def test_pin_mismatch_fails(self):
        r = self.check(sha="ab" * 32)
        self.assertTrue(r.startswith("FAIL|Local model|research-llm runs model abababababab"), r)
        r = self.check(urls={"/props": json.dumps({"model_alias": "other", "chat_template": "x", "default_generation_settings": {"n_ctx": 4096}})})
        self.assertTrue(r.startswith("FAIL|Local model|research-llm answers as model 'other'"), r)

    def test_warns(self):
        self.assertIn("is not Ready (Pending)", self.check(pod="Pending||False\n"))
        self.assertIn("is not Ready", self.check(pod="Running|10.1.2.3|False\n"))
        self.assertIn("does not answer /health ok", self.check(urls={"/health": '{"error":"loading"}'}))
        r = self.check(urls={"/props": json.dumps({"model_alias": ALIAS, "chat_template": "", "default_generation_settings": {"n_ctx": 16384}})})
        self.assertTrue(r.startswith("WARN|"), r)
        self.assertIn("the context is 16384 tokens, the decision is 4096", r)
        self.assertIn("no chat template", r)
        self.assertIn("below half of the bench's 3.8 tok/s", self.check(urls={"/metrics": "llamacpp:predicted_tokens_seconds 1.0\nllamacpp:tokens_predicted_total 50\n"}))
        # no generation yet: nothing to judge
        self.assertTrue(self.check(urls={"/metrics": "llamacpp:predicted_tokens_seconds 0\nllamacpp:tokens_predicted_total 0\n"}).startswith("OK|"))


if __name__ == "__main__":
    unittest.main()
