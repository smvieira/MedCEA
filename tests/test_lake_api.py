#!/usr/bin/env python3
"""tests/test_lake_api.py — the research sandbox's snapshot reader, apps/lake-api (Phase 2b).

Offline (stdlib unittest), in a scratch tree (tests/_scratch.py) with a fake cluster:
  Render     k8s/lake-api.yaml and k8s/auth-secret.yaml through infra/lib-render.sh: the
             pinned image, PostgREST's settings (lake_api, rs_lake_reader, no JWT secret),
             the password only by secretKeyRef (never in a `value:`), PGRST_DB_PASS listed
             before the URI that expands it, the pod's hardening (non-root, read-only root,
             no service account token, no service links, the low PriorityClass), the
             annotations that restart it on a new password or a changed lake_api.sql.
  Deploy     apps/lake-api/deploy.sh against a fake kubectl, curl, cli.py and policy source:
             unknown options exit 2 before the log and the lock; each skip line (exit 0,
             policy_source_finish, a running lake-api named and left alone); the zone it
             must live in; the refusals without the zone's compiled NetworkPolicies; the
             full path in order (Secret, manifest, rollout, a 200 from the pod); no secret
             in any argv or output.
  Uninstall  apps/lake-api/uninstall.sh: removes app=lake-api in the research namespace,
             never the research database.
  Wiring     apps/research/deploy.sh runs it last and its uninstall first; deploy-apps.sh
             counts it among the components that compile the policy.

  python3 tests/test_lake_api.py
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402

APP = os.path.join(REPO, "apps", "lake-api")
LAKE_API_SQL = os.path.join(REPO, "apps", "research", "db", "lake_api.sql")
PASS = "rsLakeApiPass0123456789"
RNS = "medcea-research"
IMAGE = ("postgrest/postgrest:v12.2.3@sha256:"
         "729bf65c733b73f5b52777f0e4b853f22ed73aa67a22d38269d289779b0a8401")


def read(p):
    with open(p) as f:
        return f.read()


def code(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def render(template, **env):
    """infra/lib-render.sh render TEMPLATE VAR... with the values in the environment."""
    e = clean_env(**env)
    r = subprocess.run(["bash", "-c", 'source "$1"; shift; render "$@"', "-",
                        os.path.join(REPO, "infra", "lib-render.sh"), template] + sorted(env),
                       env=e, capture_output=True, text=True, check=True)
    return r.stdout


class Render(unittest.TestCase):
    def setUp(self):
        import yaml
        self.yaml = yaml
        self.text = render(os.path.join(APP, "k8s", "lake-api.yaml"), RESEARCH_NAMESPACE=RNS,
                           LAKE_AUTH_VERSION="4711", LAKE_SCHEMA_SHA256="ab" * 32)
        self.docs = {d["kind"]: d for d in yaml.safe_load_all(self.text)}

    def test_everything_rendered(self):
        self.assertNotIn("${", self.text)
        tmpl = read(os.path.join(APP, "k8s", "lake-api.yaml"))
        used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", code(tmpl)))
        self.assertEqual(used, {"RESEARCH_NAMESPACE", "LAKE_AUTH_VERSION", "LAKE_SCHEMA_SHA256"})
        # the deploy renders with exactly that list
        dep = read(os.path.join(APP, "deploy.sh"))
        self.assertIn('render "$SCRIPT_DIR/k8s/lake-api.yaml" RESEARCH_NAMESPACE LAKE_AUTH_VERSION LAKE_SCHEMA_SHA256',
                      dep)
        self.assertIn('render "$SCRIPT_DIR/k8s/auth-secret.yaml" RESEARCH_NAMESPACE RS_LAKE_API_DB_PASS', dep)
        # $(PGRST_DB_PASS) is Kubernetes', not envsubst's
        self.assertIn("postgres://rs_lake_api:$(PGRST_DB_PASS)@research-postgresql.%s.svc.cluster.local:5432/"
                      "medcea_research" % RNS, self.text)

    def test_postgrest(self):
        dep = self.docs["Deployment"]
        self.assertEqual(dep["metadata"]["namespace"], RNS)
        self.assertEqual(dep["spec"]["replicas"], 1)
        self.assertEqual(dep["spec"]["revisionHistoryLimit"], 0)
        (c,) = dep["spec"]["template"]["spec"]["containers"]
        self.assertEqual(c["image"], IMAGE)
        self.assertEqual(c["imagePullPolicy"], "IfNotPresent")
        env = c["env"]
        self.assertEqual(env[0]["name"], "PGRST_DB_PASS")   # before the URI that expands it
        self.assertEqual(env[0]["valueFrom"], {"secretKeyRef": {"name": "lake-api-auth", "key": "password"}})
        vals = {e["name"]: e.get("value") for e in env[1:]}
        self.assertEqual(vals["PGRST_DB_SCHEMAS"], "lake_api")
        self.assertEqual(vals["PGRST_DB_ANON_ROLE"], "rs_lake_reader")
        self.assertEqual(vals["PGRST_DB_MAX_ROWS"], "50000")
        self.assertEqual(vals["PGRST_DB_POOL"], "5")
        self.assertEqual(vals["PGRST_SERVER_PORT"], "3000")
        self.assertTrue(vals["PGRST_DB_URI"].startswith("postgres://rs_lake_api:$(PGRST_DB_PASS)@"))
        # no identity (O2): no JWT secret, no audience, no pre-request
        self.assertFalse([n for n in vals if n.startswith("PGRST_JWT") or n == "PGRST_DB_PRE_REQUEST"])
        self.assertNotIn("JWT", self.text.split("apiVersion", 1)[1])
        for probe in ("readinessProbe", "livenessProbe"):
            self.assertEqual(c[probe]["httpGet"], {"path": "/", "port": 3000})

    def test_hardening(self):
        spec = self.docs["Deployment"]["spec"]["template"]["spec"]
        self.assertEqual(spec["priorityClassName"], "medcea-research-low")
        self.assertIs(spec["automountServiceAccountToken"], False)
        self.assertIs(spec["enableServiceLinks"], False)
        sc = spec["securityContext"]
        self.assertIs(sc["runAsNonRoot"], True)
        self.assertEqual(sc["runAsUser"], 65534)
        self.assertEqual(sc["seccompProfile"], {"type": "RuntimeDefault"})
        (c,) = spec["containers"]
        self.assertEqual(c["securityContext"], {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}})
        self.assertEqual(c["resources"], {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}})
        ann = self.docs["Deployment"]["spec"]["template"]["metadata"]["annotations"]
        self.assertEqual(ann, {"medcea/auth-secret-version": "4711", "medcea/schema-sha256": "ab" * 32})
        self.assertEqual(self.docs["Deployment"]["spec"]["template"]["metadata"]["labels"]["app"], "lake-api")

    def test_service(self):
        svc = self.docs["Service"]
        self.assertEqual((svc["metadata"]["name"], svc["metadata"]["namespace"]), ("lake-api", RNS))
        self.assertEqual(svc["spec"]["selector"], {"app": "lake-api"})
        self.assertEqual([(p["port"], p["targetPort"]) for p in svc["spec"]["ports"]], [(3000, 3000)])
        self.assertNotIn("type", svc["spec"])   # ClusterIP: the zone's policy admits the notebooks and the node

    def test_secret(self):
        text = render(os.path.join(APP, "k8s", "auth-secret.yaml"), RESEARCH_NAMESPACE=RNS, RS_LAKE_API_DB_PASS=PASS)
        d = self.yaml.safe_load(text)
        self.assertEqual((d["kind"], d["metadata"]["name"], d["metadata"]["namespace"]),
                         ("Secret", "lake-api-auth", RNS))
        self.assertEqual(d["metadata"]["labels"]["app"], "lake-api")   # uninstall's selector
        self.assertEqual(d["stringData"], {"password": PASS})
        # the password reaches the pod only by secretKeyRef, never in a plain value
        for line in self.text.splitlines():
            if "value:" in line:
                self.assertNotIn(PASS, line)


STUB_KUBECTL = r"""#!/usr/bin/env bash
a="$*"; echo "kubectl ${a//$'\n'/ }" >> "$STUB_LOG"
n=$(ls "$STUB_DIR" | grep -c '^in-' || true)
case "$*" in
  "get namespace "*) [[ -z "${STUB_NO_NS:-}" ]]; exit $? ;;
  "get deployment lake-api "*) [[ -n "${STUB_DEPLOYED:-}" ]]; exit $? ;;
  "get statefulset research-postgresql "*) [[ -z "${STUB_NO_STS:-}" ]]; exit $? ;;
  "get networkpolicy rs-lake-api "*) [[ -z "${STUB_NO_NETPOL:-}" ]] && echo networkpolicy/rs-lake-api; [[ -z "${STUB_NO_NETPOL:-}" ]]; exit $? ;;
  "get secret lake-api-auth "*) printf 4711 ;;
  "get pod "*) printf %s "${STUB_POD_IP-10.1.2.3}" ;;
  "rollout status "*) exit "${STUB_ROLLOUT_RC:-0}" ;;
  "apply "*) cat > "$STUB_DIR/in-$(printf %03d "$n")-apply" ;;
esac
exit 0
"""
STUB_CURL = r"""#!/usr/bin/env bash
echo "curl $*" >> "$STUB_LOG"
printf %s "${STUB_HTTP:-200}"
"""


class Tree(unittest.TestCase):
    """A scratch tree with apps/lake-api, the real log, lock and render libraries, a fake cluster."""

    def setUp(self):
        self.root = scratch_repo("medcea-lake-api-")
        shutil.copytree(APP, os.path.join(self.root, "apps", "lake-api"))
        os.makedirs(os.path.join(self.root, "apps", "research", "db"))
        shutil.copy(LAKE_API_SQL, os.path.join(self.root, "apps", "research", "db", "lake_api.sql"))
        self.log = os.path.join(self.root, "calls.log")
        self.stub = os.path.join(self.root, "stub")
        self.bin = os.path.join(self.root, "bin")
        os.makedirs(self.stub)
        os.makedirs(self.bin)
        for name, text in (("kubectl", STUB_KUBECTL), ("curl", STUB_CURL)):
            with open(os.path.join(self.bin, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(self.bin, name), 0o755)
        with open(os.path.join(self.root, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s/mk8s"; KUBECTL="%s/kubectl"\n' % (self.bin, self.bin))
        with open(os.path.join(self.root, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    'policy_db_state() { echo "policy_db_state $1" >> "$STUB_LOG"; echo "${STUB_PS_STATE:-version-7}"; }\n')
        # the zone's NetworkPolicies against the compile (area 2's shared reader), stubbed;
        # it is called in a subshell with SCRIPT_DIR at the repository
        with open(os.path.join(self.root, "infra", "lib-policy-artefacts.sh"), "w") as f:
            f.write('_pa_rsnetpol_equal() { echo "rsnetpol_equal SCRIPT_DIR=$SCRIPT_DIR" >> "$STUB_LOG"; '
                    'return "${STUB_RSNP_RC:-0}"; }\n')
        with open(os.path.join(self.root, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write('import os, sys\nopen(os.environ["STUB_LOG"], "a").write("cli " + " ".join(sys.argv[1:]) + "\\n")\n'
                    'z = os.environ.get("STUB_POD_ZONE", "research")\n'
                    'rc = int(os.environ.get("STUB_POD_ZONE_RC", "0"))\n'
                    'print(z) if rc == 0 else None\n'
                    'sys.exit(rc)\n')
        self.write_config()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, **extra):
        conf = dict(NAMESPACE="medcea", PROJECT_NAME="medcea", RESEARCH_ENABLED="true", RESEARCH_NAMESPACE=RNS,
                    RS_LAKE_API_DB_PASS=PASS)
        conf.update(extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def run_script(self, script, *args, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub,
                              "PATH": self.bin + ":" + os.environ["PATH"]}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG", "RESEARCH_ENABLED"):
            if k not in env:
                e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, "apps", "lake-api", script)] + list(args),
                           env=e, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        if os.path.exists(self.log):
            os.remove(self.log)
        r.out = r.stdout + r.stderr
        self.assertNotIn(PASS, "\n".join(calls), "the password in an argv")
        self.assertNotIn(PASS, r.out, "the password printed")
        return r, calls

    def applies(self):
        return [read(os.path.join(self.stub, f)) for f in sorted(os.listdir(self.stub)) if f.endswith("-apply")]

    def no_log_no_lock(self):
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))


class Deploy(Tree):
    def test_syntax(self):
        for s in ("deploy.sh", "uninstall.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)
            self.assertTrue(os.access(os.path.join(APP, s), os.X_OK), s)

    def test_unknown_options_exit_2_before_log_and_lock(self):
        for script, args in (("deploy.sh", ["--x"]), ("deploy.sh", ["--help", "x"]), ("uninstall.sh", ["--purge-data"])):
            r, calls = self.run_script(script, *args)
            self.assertEqual(r.returncode, 2, (script, args, r.out))
            self.assertIn("unknown arguments", r.stderr)
            self.assertEqual(calls, [])
            self.no_log_no_lock()
        for script in ("deploy.sh", "uninstall.sh"):
            r, calls = self.run_script(script, "--help")
            self.assertEqual(r.returncode, 0)
            self.assertEqual(calls, [])
            self.no_log_no_lock()

    def skip(self, line, **env):
        r, calls = self.run_script("deploy.sh", **env)
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("[lake-api]", r.stdout)
        self.assertIn("skipped: " + line, r.stdout)
        self.assertEqual(r.stdout.count("skipped:"), 1)
        self.assertEqual(calls[-1], "finish medcea lake-api")
        self.assertFalse([c for c in calls if c.startswith(("kubectl apply", "kubectl delete", "curl"))], calls)
        self.assertEqual(self.applies(), [])
        return r, calls

    def test_skips(self):
        self.write_config(RESEARCH_ENABLED="false")
        r, calls = self.skip("RESEARCH_ENABLED is not true")
        self.assertFalse([c for c in calls if c.startswith("cli ")])
        self.write_config()
        r, calls = self.skip("the applied access policy has no lake-api pod yet", STUB_POD_ZONE_RC="1")
        self.assertIn("cli pod-zone lake-api", calls)
        for st in ("none", "empty"):
            self.skip("no version of the access policy is applied yet (state %s)" % st, STUB_PS_STATE=st)
        self.skip("namespace %s does not exist yet" % RNS, STUB_NO_NS="1")
        self.skip("no research database yet (./apps/research/deploy.sh)", STUB_NO_STS="1")

    def test_a_skip_names_a_running_lake_api_and_leaves_it(self):
        r, calls = self.skip("the applied access policy has no lake-api pod yet", STUB_POD_ZONE_RC="1", STUB_DEPLOYED="1")
        self.assertIn("lake-api is still running in %s (left alone)" % RNS, r.out)

    def test_it_lives_only_in_the_research_zone(self):
        for env, want in (({"STUB_POD_ZONE": "platform"}, "it lives only in the research zone"),
                          ({"STUB_POD_ZONE_RC": "2"}, "cli.py pod-zone lake-api exit 2")):
            r, calls = self.run_script("deploy.sh", **env)
            self.assertEqual(r.returncode, 1, env)
            self.assertIn(want, r.out)
            self.assertNotIn("finish medcea lake-api", calls)
            self.assertEqual(self.applies(), [])

    def test_bad_states_refuse(self):
        for st in ("partial", "unreachable"):
            r, calls = self.run_script("deploy.sh", STUB_PS_STATE=st)
            self.assertEqual(r.returncode, 1, st)
            self.assertNotIn("finish medcea lake-api", calls)

    def test_never_an_open_pod(self):
        for env, want in (({"STUB_NO_NETPOL": "1"}, "NetworkPolicy rs-lake-api is not in %s" % RNS),
                          ({"STUB_RSNP_RC": "1"}, "are not the compiled ones"),
                          ({"STUB_RSNP_RC": "2"}, "cannot compare")):
            r, calls = self.run_script("deploy.sh", **env)
            self.assertEqual(r.returncode, 1, (env, r.out))
            self.assertIn(want, r.out)
            self.assertEqual(self.applies(), [], env)
            self.assertNotIn("finish medcea lake-api", calls)
        r, calls = self.run_script("deploy.sh")
        self.assertIn("rsnetpol_equal SCRIPT_DIR=%s" % self.root, calls)   # the repository, in a subshell
        nl = calls.index("kubectl get networkpolicy rs-lake-api -n %s -l medcea/rs-netpol=true -o name" % RNS)
        self.assertLess(nl, calls.index("rsnetpol_equal SCRIPT_DIR=%s" % self.root))

    def test_missing_password(self):
        for v in ("", "has space"):
            self.write_config(RS_LAKE_API_DB_PASS=v)
            r, calls = self.run_script("deploy.sh")
            self.assertEqual(r.returncode, 1)
            self.assertIn("RS_LAKE_API_DB_PASS", r.out)
            self.assertEqual(self.applies(), [])

    def test_full_path(self):
        r, calls = self.run_script("deploy.sh")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(calls[0], "init medcea")
        self.assertEqual(calls[-1], "finish medcea lake-api")
        steps = [c for c in calls if c.startswith(("kubectl apply", "kubectl rollout", "curl", "kubectl get secret"))]
        self.assertEqual(steps, [
            "kubectl apply -f -",
            "kubectl get secret lake-api-auth -n %s -o jsonpath={.metadata.resourceVersion}" % RNS,
            "kubectl apply -f -",
            "kubectl rollout status deployment/lake-api -n %s --timeout=5m" % RNS,
            "curl -s -m 10 -o /dev/null -w %{http_code} http://10.1.2.3:3000/"])
        secret, manifest = self.applies()
        self.assertIn("name: lake-api-auth", secret)
        self.assertIn('password: "%s"' % PASS, secret)
        self.assertIn("kind: Deployment", manifest)
        self.assertIn('medcea/auth-secret-version: "4711"', manifest)
        sha = hashlib.sha256(read(LAKE_API_SQL).encode()).hexdigest()
        self.assertIn('medcea/schema-sha256: "%s"' % sha, manifest)
        self.assertNotIn(PASS, manifest)
        self.assertNotIn("${", manifest)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "logs")))
        self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("app-lake-api-deploy-")])

    def test_it_must_answer(self):
        for env, want in (({"STUB_HTTP": "503"}, "answered '503', not 200"),
                          ({"STUB_POD_IP": ""}, "cannot read lake-api's pod address"),
                          ({"STUB_ROLLOUT_RC": "1"}, "did not become ready")):
            r, calls = self.run_script("deploy.sh", **env)
            self.assertEqual(r.returncode, 1, env)
            self.assertIn(want, r.out)
            self.assertNotIn("finish medcea lake-api", calls)

    def test_logging_and_lock_order(self):
        for s in ("deploy.sh", "uninstall.sh"):
            t = code(read(os.path.join(APP, s)))
            self.assertLess(t.index("medcea_log "), t.index("medcea_lock"), s)
            self.assertLess(t.index("exit 2"), t.index("medcea_log "), s)
        t = read(os.path.join(APP, "deploy.sh"))
        self.assertIn("medcea_log app-lake-api-deploy", t)
        self.assertIn("medcea_log app-lake-api-uninstall", read(os.path.join(APP, "uninstall.sh")))
        self.assertTrue(t.rstrip().endswith('policy_source_finish "$NAMESPACE" lake-api'))
        self.assertIn('policy_source_init "$NAMESPACE" || exit $?', t)


class Uninstall(Tree):
    def test_removes_the_reader_only(self):
        r, calls = self.run_script("uninstall.sh")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("kubectl delete deployment,service,secret -n %s -l app=lake-api --ignore-not-found" % RNS, calls)
        self.assertFalse([c for c in calls if "research-postgresql" in c or "pvc" in c or c.startswith("kubectl exec")])
        self.assertEqual([c for c in calls if c.startswith("kubectl delete")],
                         ["kubectl delete deployment,service,secret -n %s -l app=lake-api --ignore-not-found" % RNS])

    def test_no_namespace(self):
        r, calls = self.run_script("uninstall.sh", STUB_NO_NS="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("no lake-api to remove", r.out)
        self.assertFalse([c for c in calls if c.startswith("kubectl delete")])


class Wiring(unittest.TestCase):
    def test_research_deploy_runs_it_last(self):
        t = code(read(os.path.join(REPO, "apps", "research", "deploy.sh")))
        run = t.index('bash "$REPO_ROOT/apps/lake-api/deploy.sh" || _lrc=$?')
        self.assertLess(t.index("assert_grants.sql"), run)
        self.assertLess(run, t.rindex('policy_source_finish "$NAMESPACE" research'))
        self.assertTrue(t.rstrip().endswith('policy_source_finish "$NAMESPACE" research'))
        self.assertIn("[[ $_lrc == 0 ]] || exit $_lrc", t)
        # its schema before the passwords (the role must exist), after the DDL, before the grants
        self.assertLess(t.index("medcea_research_ddl.sql"), t.index("db/lake_api.sql"))
        self.assertLess(t.index("db/lake_api.sql"), t.index("ALTER ROLE rs_lake_api PASSWORD"))
        self.assertLess(t.index("ALTER ROLE rs_lake_api PASSWORD"), t.index("db/grants.sql"))

    def test_research_uninstall_runs_it_first(self):
        t = code(read(os.path.join(REPO, "apps", "research", "uninstall.sh")))
        self.assertLess(t.index('bash "$REPO_ROOT/apps/lake-api/uninstall.sh"'),
                        t.index("delete secret research-export-writer"))

    def test_deploy_apps_counts_it(self):
        t = read(os.path.join(REPO, "deploy-apps.sh"))
        self.assertIn("lake-api", re.search(r"POLICY_COMPILING=\(([^)]*)\)", t).group(1).split())

    def test_configure_generates_the_password(self):
        t = read(os.path.join(REPO, "infra", "configure.sh"))
        loop = t[t.index("for _v in SVC_INGEST_DB_PASS"):]
        loop = loop[:loop.index("done")]
        self.assertIn("RS_LAKE_API_DB_PASS", loop)
        # before the early exit, so an existing install gets it
        self.assertLess(t.index("for _v in SVC_INGEST_DB_PASS"), t.index('if [[ "$MODE" == "missing" ]]'))
        ex = read(os.path.join(REPO, "config.env.example"))
        self.assertIn('RS_LAKE_API_DB_PASS=""', ex)
        self.assertEqual(re.findall(r'^RESEARCH_ENABLED=.*$', ex, re.M), ['RESEARCH_ENABLED="true"'])


if __name__ == "__main__":
    unittest.main()
