#!/usr/bin/env python3
"""tests/test_research_namespace.py — the research sandbox's zone (Phase 2a, commit A). Offline.

  Render      k8s/research/*.yaml: the namespace's label, PriorityClass medcea-research-low
              (-100, not the global default, never preempts), the quota's keys, the
              LimitRange's defaults without a CPU limit; nothing left unrendered.
  Script      infra/deploy-research-namespace.sh in a scratch tree (tests/_scratch.py) with a
              fake microk8s/kubectl first on PATH and the real compiler on a scratch
              defaults.yaml (plus commit B's research zone where a case needs it), under a
              lock and a verified policy source as deploy-infra holds them: unknown options
              exit 2 before the log and the lock; RESEARCH_ENABLED false (with and without a
              namespace left), no research zone, a bad RESEARCH_NAMESPACE; the full path (the
              four manifests, the zone's policies with the node's addresses, a stale one
              deleted in the research namespace only); --policy-only unchanged / re-rendered /
              not deployed; no password in any argv.
  Wiring      deploy-infra.sh (validation, the call after pa_netpol full, --reset), deploy-policy.sh
              and lib-policy-artefacts.sh (pa_rsnetpol never touches the platform's label).

Run: python3 tests/test_research_namespace.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from _scratch import clean_env, scratch_repo  # noqa: E402

NS, RNS = "medcea", "medcea-research"
SECRETS = {"RESEARCH_DB_PASS": "rsDbPass0123456789ab", "RS_EXPORT_WRITER_DB_PASS": "rsWriter0123456789ab",
           "RS_BACKUP_DB_PASS": "rsBackup0123456789ab", "SVC_RESEARCH_EXPORT_DB_PASS": "svcRsExp0123456789ab",
           "POSTGRES_PASS": "pgPass0123456789abcd"}
NODE_IPS = "192.0.2.10 10.1.0.7/32  "


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def render(rel, **env):
    names = " ".join(env)
    r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-render.sh"; render "{REPO}/{rel}" {names}'],
                       capture_output=True, text=True, env=dict(os.environ, **env), check=True)
    return r.stdout


def code(text):
    return "\n".join(re.sub(r"\s+#\s.*$", "", l) for l in text.splitlines() if not l.lstrip().startswith("#"))


class Render(unittest.TestCase):
    def load(self, f, **env):
        text = render(f"k8s/research/{f}", **env)
        self.assertNotIn("${", text, f)
        return yaml.safe_load(text)

    def test_namespace(self):
        d = self.load("namespace.yaml", RESEARCH_NAMESPACE=RNS)
        self.assertEqual((d["kind"], d["metadata"]["name"]), ("Namespace", RNS))
        self.assertEqual(d["metadata"]["labels"], {"medcea/zone": "research"})

    def test_priority_class(self):
        d = self.load("priorityclass.yaml")
        self.assertEqual(d["kind"], "PriorityClass")
        self.assertEqual(d["metadata"]["name"], "medcea-research-low")
        self.assertEqual(d["value"], -100)
        self.assertIs(d["globalDefault"], False)
        self.assertEqual(d["preemptionPolicy"], "Never")
        self.assertNotIn("namespace", d["metadata"])   # cluster-scoped

    def test_quota(self):
        d = self.load("quota.yaml", RESEARCH_NAMESPACE=RNS)
        self.assertEqual((d["kind"], d["metadata"]["name"], d["metadata"]["namespace"]),
                         ("ResourceQuota", "research-quota", RNS))
        self.assertEqual(set(d["spec"]["hard"]), {"requests.cpu", "requests.memory", "limits.memory", "pods",
                                                   "persistentvolumeclaims", "requests.storage"})
        self.assertNotIn("limits.cpu", d["spec"]["hard"])   # no CPU limit is ever required
        # the sizing table is in the file, and its sums fit under the lines
        text = read("k8s/research/quota.yaml")
        self.assertIn("research-postgresql (2a)", text)
        m = re.search(r"#   sum\s+(\d+)m\s+([\d.]+)Gi\s+([\d.]+)Gi\s+(\d+)\s+(\d+)Gi", text)
        cpu_m, req_gi, lim_gi, pvcs, storage = m.groups()
        hard = d["spec"]["hard"]
        self.assertLessEqual(int(cpu_m), int(hard["requests.cpu"]) * 1000)
        self.assertLessEqual(float(req_gi), float(hard["requests.memory"].rstrip("Gi")))
        self.assertLessEqual(float(lim_gi), float(hard["limits.memory"].rstrip("Gi")))
        self.assertLessEqual(int(pvcs), int(hard["persistentvolumeclaims"]))
        self.assertLessEqual(int(storage), int(hard["requests.storage"].rstrip("Gi")))
        # RESEARCH_DB_STORAGE's default fits
        self.assertIn('RESEARCH_DB_STORAGE="10Gi"', read("config.env.example"))

    def test_limit_range_without_a_cpu_limit(self):
        d = self.load("limitrange.yaml", RESEARCH_NAMESPACE=RNS)
        self.assertEqual((d["kind"], d["metadata"]["name"], d["metadata"]["namespace"]),
                         ("LimitRange", "research-limits", RNS))
        (lim,) = d["spec"]["limits"]
        self.assertEqual(lim["type"], "Container")
        self.assertEqual(set(lim["defaultRequest"]), {"cpu", "memory"})
        self.assertEqual(set(lim["default"]), {"memory"})
        self.assertNotIn("max", lim)


# ── a fake microk8s/kubectl ─────────────────────────────────────────────────────
FAKE = r'''#!/usr/bin/env python3
import json, os, sys, yaml
argv = sys.argv[1:]
st_path, log_path = os.environ["FAKE_STATE"], os.environ["FAKE_LOG"]
try:
    st = json.load(open(st_path))
except (OSError, ValueError):
    st = {}
st.setdefault("ns", {}); st.setdefault("netpol", {}); st.setdefault("objs", {})
stdin = ""
if argv[:1] == ["status"]:
    sys.exit(0)
if argv[:1] != ["kubectl"]:
    sys.exit(1)
a = argv[1:]
write = a[:1] in (["apply"], ["delete"], ["create"], ["patch"], ["label"], ["annotate"])
if a[:2] == ["apply", "-f"]:
    stdin = sys.stdin.read()
with open(log_path, "a") as f:
    f.write(json.dumps({"argv": a, "write": write, "stdin": stdin}) + "\n")
def opt(name):
    return a[a.index(name) + 1] if name in a else None
def save():
    json.dump(st, open(st_path, "w"), sort_keys=True)
if a[:2] == ["apply", "-f"]:
    docs = [d for d in yaml.safe_load_all(stdin) if d]
    items = []
    for d in docs:
        items += d["items"] if d.get("kind") == "List" else [d]
    for o in items:
        k, md = o["kind"], o["metadata"]
        if k == "Namespace":
            st["ns"][md["name"]] = md.get("labels") or {}
        elif k == "NetworkPolicy":
            st["netpol"].setdefault(md["namespace"], {})[md["name"]] = o
        else:
            st["objs"]["%s/%s/%s" % (k, md.get("namespace", ""), md["name"])] = o
    save(); sys.exit(0)
if a[:2] == ["get", "namespace"]:
    n = a[2]
    if n not in st["ns"]:
        print('Error from server (NotFound): namespaces "%s" not found' % n, file=sys.stderr); sys.exit(1)
    o = opt("-o")
    if o == "name":
        print("namespace/" + n)
    elif o and o.startswith("jsonpath={.metadata.labels.medcea/zone}"):
        print(st["ns"][n].get("medcea/zone", ""), end="")
    sys.exit(0)
if a[:2] == ["get", "nodes"]:
    print(os.environ.get("FAKE_NODE_IPS", ""), end=""); sys.exit(0)
if a[:2] == ["get", "netpol"]:
    ns, sel = opt("-n"), opt("-l")
    key, val = sel.split("=")
    items = [o for o in st["netpol"].get(ns, {}).values() if (o["metadata"].get("labels") or {}).get(key) == val]
    o = opt("-o")
    if o == "json":
        print(json.dumps({"items": items}))
    else:
        print(" ".join(i["metadata"]["name"] for i in items), end="")
    sys.exit(0)
if a[:2] == ["delete", "netpol"]:
    ns, name = opt("-n"), a[-1]
    st["netpol"].get(ns, {}).pop(name, None); save(); sys.exit(0)
print("fake kubectl: unhandled " + " ".join(a), file=sys.stderr)
sys.exit(1)
'''


def research_zone(d):
    """commit B's research zone (as tests/test_research_netpol.py builds it)."""
    net = d["network"]
    net["zones"] = {"research": {}}
    net["pods"]["research-postgresql"] = {
        "zone": "research",
        "selector": {"app.kubernetes.io/instance": "research-postgresql", "app.kubernetes.io/name": "postgresql"},
        "carries": {},
        "ingress": [{"port": 5432, "from": ["client:research-export", "client:backup", "node"],
                     "why": "the exporter, the nightly backup, kubelet probes"}]}
    net["clients"]["research-export"] = {"selector": {"app": "research-export"},
                                         "egress": [{"pod": "research-postgresql", "port": 5432}]}
    net["clients"]["backup"] = {"selector": {"app": "medcea-backup"},
                                "egress": [{"pod": "research-postgresql", "port": 5432}]}
    return d


class Tree:
    def __init__(self, zone=False, enabled="true", extra=""):
        self.root = scratch_repo(prefix="medcea-rsns-")
        for rel in ("infra/deploy-research-namespace.sh",):
            shutil.copy(os.path.join(REPO, rel), self.path(rel))
        shutil.copytree(os.path.join(REPO, "k8s", "research"), self.path("k8s", "research"))
        if zone:
            p = self.path("apps", "iam", "policy", "defaults.yaml")
            with open(p) as f:
                d = yaml.safe_load(f)
            with open(p, "w") as f:
                yaml.safe_dump(research_zone(d), f, sort_keys=False)
        cfg = "".join(f'{k}="{v}"\n' for k, v in SECRETS.items())
        with open(self.path("config.env"), "w") as f:
            f.write(f'PROJECT_NAME="medcea"\nNAMESPACE="{NS}"\nRESEARCH_NAMESPACE="${{NAMESPACE}}-research"\n'
                    f'RESEARCH_ENABLED="{enabled}"\n' + cfg + extra)
        self.bin = self.path(".fake", "bin")
        os.makedirs(self.bin)
        fake = self.path(".fake", "fake.py")
        with open(fake, "w") as f:
            f.write(FAKE)
        os.chmod(fake, 0o755)
        os.symlink(fake, os.path.join(self.bin, "microk8s"))
        self.state, self.log = self.path(".fake", "state.json"), self.path(".fake", "log.jsonl")

    def path(self, *p):
        return os.path.join(self.root, *p)

    def seed(self, ns=(), netpols=()):
        st = {"ns": {n: {"medcea/zone": "research"} for n in ns}, "netpol": {}, "objs": {}}
        for nsn, name, labels, spec in netpols:
            st["netpol"].setdefault(nsn, {})[name] = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                                                       "metadata": {"name": name, "namespace": nsn, "labels": labels},
                                                       "spec": spec}
        with open(self.state, "w") as f:
            json.dump(st, f)

    def st(self):
        with open(self.state) as f:
            return json.load(f)

    def calls(self):
        try:
            with open(self.log) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def run(self, *args, locked=True):
        script = "./infra/deploy-research-namespace.sh " + " ".join(args)
        if locked:   # deploy-infra's lock and its verified policy source, inherited
            script = ('exec 9>>"$PWD/.medcea.lock"; flock -n 9 || exit 99\n'
                      'export MEDCEA_LOCK_HELD=$$ MEDCEA_POLICY_SOURCE_DONE=$$\n' + script + "\nexit $?\n")
        env = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_STATE=self.state, FAKE_LOG=self.log,
                        FAKE_NODE_IPS=NODE_IPS, MEDCEA_NO_LOG="1", HOME=self.root)
        env.pop("MEDCEA_LOG_FILE", None)
        for k in list(env):
            if k.startswith(("RESEARCH_", "NAMESPACE", "KUBECONFIG")):
                env.pop(k)
        return subprocess.run(["bash", "-c", script], cwd=self.root, env=env, capture_output=True, text=True,
                              timeout=300)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class Script(unittest.TestCase):
    def tree(self, **kw):
        t = Tree(**kw)
        self.addCleanup(t.close)
        return t

    def writes(self, t):
        return [c for c in t.calls() if c["write"]]

    def test_unknown_options_exit_2_before_the_log_and_the_lock(self):
        t = self.tree()
        for args in (("--x",), ("--policy-only", "x"), ("full",)):
            r = t.run(*args, locked=False)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("unknown arguments", r.stderr)
        self.assertFalse(os.path.exists(t.path(".medcea.lock")))
        self.assertFalse(os.path.exists(t.path("logs")))
        self.assertEqual(t.calls(), [])
        r = t.run("--help", locked=False)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--policy-only", r.stdout)

    def test_switched_off(self):
        t = self.tree(zone=True, enabled="false")
        r = t.run(locked=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skipped: RESEARCH_ENABLED is not true", r.stdout)
        self.assertNotIn("WARNING", r.stderr)
        self.assertEqual(self.writes(t), [])
        r = t.run("--policy-only", locked=False)
        self.assertIn("rsnetpol: not deployed", r.stdout)

    def test_switched_off_with_the_namespace_left(self):
        t = self.tree(zone=True, enabled="false")
        t.seed(ns=[RNS])
        r = t.run(locked=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RESEARCH_ENABLED is not true, but namespace medcea-research is still there", r.stderr)
        self.assertIn("kubectl delete namespace medcea-research", r.stderr)
        self.assertIn("kubectl delete priorityclass medcea-research-low", r.stderr)
        self.assertEqual(self.writes(t), [])
        self.assertIn(RNS, t.st()["ns"])

    def test_no_research_zone_yet(self):
        t = self.tree(zone=False)
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skipped: the applied access policy has no research zone yet", r.stdout)
        self.assertEqual(self.writes(t), [])
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rsnetpol: not deployed", r.stdout)
        self.assertEqual(self.writes(t), [])

    def test_a_bad_research_namespace(self):
        for line in ('RESEARCH_NAMESPACE="medcea"\n', 'RESEARCH_NAMESPACE="Bad_Name"\n'):
            with self.subTest(line):
                t = self.tree(zone=True, extra=line)
                r = t.run()
                self.assertEqual(r.returncode, 1)
                self.assertIn("RESEARCH_NAMESPACE=", r.stderr)
                self.assertEqual(self.writes(t), [])

    def test_the_full_path(self):
        t = self.tree(zone=True)
        # a platform policy carrying the platform's label, and a stale research one
        t.seed(netpols=[(NS, "iam-monitor", {"medcea/iam-netpol": "true"}, {"podSelector": {}}),
                        (NS, "rs-research-postgresql", {"medcea/rs-netpol": "true"}, {"podSelector": {}}),
                        (RNS, "rs-old-pod", {"medcea/rs-netpol": "true"}, {"podSelector": {}})])
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        st = t.st()
        self.assertEqual(st["ns"][RNS], {"medcea/zone": "research"})
        self.assertEqual(set(st["objs"]), {"PriorityClass//medcea-research-low", "ResourceQuota/medcea-research/research-quota",
                                           "LimitRange/medcea-research/research-limits"})
        pols = st["netpol"][RNS]
        self.assertEqual(set(pols), {"rs-default-deny", "rs-dns", "rs-research-postgresql"})
        self.assertEqual(pols["rs-default-deny"]["spec"], {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
        for p in pols.values():
            self.assertEqual(p["metadata"]["labels"].get("medcea/rs-netpol"), "true")
        # the node's addresses (the calico annotation's /32 stripped), as pa_netpol reads them
        cidrs = json.dumps(pols["rs-research-postgresql"]["spec"])
        self.assertIn('"192.0.2.10/32"', cidrs)
        self.assertIn('"10.1.0.7/32"', cidrs)
        # the platform namespace is untouched, whatever label its policies carry
        self.assertEqual(set(st["netpol"][NS]), {"iam-monitor", "rs-research-postgresql"})
        for c in self.writes(t):
            if c["argv"][0] == "delete":
                self.assertEqual(c["argv"], ["delete", "netpol", "-n", RNS, "rs-old-pod"])
        # order: namespace first, the policies after the quota and limits
        applied = [yaml.safe_load(c["stdin"])["kind"] for c in self.writes(t) if c["argv"][0] == "apply"]
        self.assertEqual(applied, ["Namespace", "PriorityClass", "ResourceQuota", "LimitRange", "List"])

        # --policy-only on what the full path left: unchanged, nothing written
        n = len(t.calls())
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rsnetpol: unchanged", r.stdout)
        self.assertEqual([c for c in t.calls()[n:] if c["write"]], [])
        # a drift: one spec changed, a stray labelled one → re-rendered, only in the research namespace
        st = t.st()
        st["netpol"][RNS]["rs-default-deny"]["spec"] = {"podSelector": {}, "policyTypes": ["Ingress"]}
        st["netpol"][RNS]["rs-stray"] = dict(st["netpol"][RNS]["rs-dns"], metadata={
            "name": "rs-stray", "namespace": RNS, "labels": {"medcea/rs-netpol": "true"}})
        with open(t.state, "w") as f:
            json.dump(st, f)
        n = len(t.calls())
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rsnetpol: re-rendered", r.stdout)
        w = [c for c in t.calls()[n:] if c["write"]]
        self.assertEqual([c["argv"][:2] for c in w], [["apply", "-f"], ["delete", "netpol"]])
        self.assertEqual(w[1]["argv"], ["delete", "netpol", "-n", RNS, "rs-stray"])
        self.assertEqual(t.st()["netpol"][RNS]["rs-default-deny"]["spec"]["policyTypes"], ["Ingress", "Egress"])
        n = len(t.calls())
        r = t.run("--policy-only")
        self.assertIn("rsnetpol: unchanged", r.stdout)
        self.assertEqual([c for c in t.calls()[n:] if c["write"]], [])

    def test_policy_only_without_the_namespace(self):
        t = self.tree(zone=True)
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rsnetpol: not deployed", r.stdout)
        self.assertEqual(self.writes(t), [])

    def test_no_secret_in_any_argv_or_manifest(self):
        t = self.tree(zone=True)
        t.seed(ns=[RNS])
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stderr)
        blob = json.dumps(t.calls()) + r.stdout + r.stderr
        for k, v in SECRETS.items():
            self.assertNotIn(v, blob, k)


class Wiring(unittest.TestCase):
    def test_entry_script_conventions(self):
        t = code(read("infra/deploy-research-namespace.sh"))
        self.assertLess(t.index("unknown arguments"), t.index("medcea_log deploy-research-namespace"))
        self.assertLess(t.index("medcea_log deploy-research-namespace"), t.index("medcea_lock"))
        self.assertLess(t.index("medcea_lock"), t.index('source config.env'))
        self.assertRegex(t, r'policy_source_init "\$NAMESPACE" \|\| exit \$\?')
        self.assertLess(t.index('policy_source_init "$NAMESPACE"'), t.index("_pa_rs_zone"))
        self.assertTrue(t.rstrip().endswith('policy_source_finish "$NAMESPACE" deploy-research-namespace'))
        # the component name break_glass_seen records for this script (lib-policy-source _ps_components)
        self.assertIn('*)                     c="$(basename "$0" .sh)" ;;', read("infra/lib-policy-source.sh"))
        self.assertLess(t.index("set -euo pipefail"), t.index("source config.env"))
        self.assertGreater(t.index("set -euo pipefail"), t.index("unknown arguments"))

    def test_deploy_infra(self):
        t = code(read("deploy-infra.sh"))
        self.assertLess(t.index("pa_netpol full"), t.index('"$SCRIPT_DIR/infra/deploy-research-namespace.sh"'))
        self.assertIn('[[ ! "$RESEARCH_NAMESPACE" =~ ^[a-z][a-z0-9-]{1,52}$ || "$RESEARCH_NAMESPACE" == "$NAMESPACE" ]]', t)
        reset = t[t.index('if [[ "${1:-}" == "--reset" ]]'):t.index('infra/configure.sh"')]
        self.assertLess(reset.index("Type 'reset' to confirm"), reset.index('helm3 list -n "$_RNS"'))
        self.assertIn("{.metadata.labels.medcea/zone}", reset)   # only a namespace labelled as the zone
        self.assertIn("delete priorityclass medcea-research-low", reset)
        self.assertLess(reset.index('delete namespace "$_RNS"'), reset.index('delete namespace "$NAMESPACE"'))

    def test_deploy_policy(self):
        t = code(read("infra/deploy-policy.sh"))
        i = t.index("pa_netpol scoped")
        j = t.index("pa_rsnetpol scoped")
        self.assertLess(i, j)
        self.assertLess(j, t.index("pa_node_red_auth scoped"))
        self.assertIn('if [[ "${RESEARCH_ENABLED:-false}" == "true" ]]; then', t[i:j])
        self.assertIn("_pa_rs_zone", t[i:j])

    def test_pa_rsnetpol_stays_in_its_zone(self):
        lib = read("infra/lib-policy-artefacts.sh")
        f = lib[lib.index("pa_rsnetpol() {"):lib.index("#   pa_node_red_auth")]
        self.assertNotIn("iam-netpol", code(f))
        self.assertNotIn('-n "$NAMESPACE"', f)
        self.assertIn("compile netpol --zone research", f)
        self.assertIn('--platform-namespace "$NAMESPACE"', f)


if __name__ == "__main__":
    unittest.main()
