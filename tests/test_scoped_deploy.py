#!/usr/bin/env python3
"""tests/test_scoped_deploy.py — IAM 4.2b, the scoped re-render (design §14.5.6). Offline.

Every case runs in scratch trees (the working tree, and PRE_42B from git) with
tests/fake_cluster.py first on PATH as microk8s, curl, systemctl, pgrep and friends: a
stateful fake cluster, one JSON line per command in a log. Nothing reaches the host's
cluster, its lock or its state/.

  Transcript   each block deploy-infra.sh ran inline before 4.2b, and each app's gate
               block, issues the same commands from PRE_42B's text and from today's
               function (normalised: temporary paths). Declared difference: the gate
               page's sha256 (one more read of RELEASE-templates and one more --set
               podAnnotations.medcea/gate-page-sha256 per gated proxy).
  Scoped       against a cluster seeded by the full functions, ./deploy-infra.sh
               --policy-only, ./infra/deploy-workbench.sh --policy-only and every app's
               --gate-only print "unchanged" and write nothing; one drift re-renders
               exactly that target, with no rollout restart; Superset's (stage C) says
               "not deployed" on a cluster without it.
  Arguments    an unknown option exits 2 and runs nothing.
  Wizard       a drift with a flash in the unit's cgroup exits 4 and restarts nothing.
  Resume       owners --scoped, the apply_deferred record, and health counting only the
               deferrals after the version's last applied record.

Run: python3 tests/test_scoped_deploy.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PRE_42B = "8a65abe"
FAKE = os.path.join(HERE, "fake_cluster.py")
FAKE_NAMES = ("microk8s", "curl", "systemctl", "pgrep", "sleep", "fuser", "loginctl", "journalctl", "sudo")

CONFIG = """\
PROJECT_NAME="medcea"
NAMESPACE="medcea"
KEYCLOAK_REALM="medcea"
DOMAIN="medcea"
PLATFORM_IP="192.0.2.10"
KEYCLOAK_DOMAIN="keycloak.medcea"
PORTAL_DOMAIN="portal.medcea"
NODE_RED_DOMAIN="node-red.medcea"
GRAFANA_DOMAIN="grafana.medcea"
PGADMIN_DOMAIN="pgadmin.medcea"
ACCESS_DOMAIN="access.medcea"
POLICY_DOMAIN="policy.medcea"
POLICY_CLIENT_SECRET="polsecret"
POLICY_COOKIE_SECRET="polcookie0123456789abcdef0123456"
SCHEDULER_DOMAIN="scheduler.medcea"
MONITOR_DOMAIN="monitor.medcea"
MQTTX_DOMAIN="mqtt-explorer.medcea"
DBMGMT_DOMAIN="dbmgmt.medcea"
WORKBENCH_DOMAIN="ai-workbench.medcea"
ONBOARD_DOMAIN="onboard-device.medcea"
ADMIN_USER="admin"
ADMIN_PASS="adminpass"
ADMIN_EMAIL="admin@medcea.example.org"
POSTGRES_USER="postgres"
POSTGRES_PASS="pgpass"
POSTGRES_DB="medcea_db"
GRAFANA_OAUTH_SECRET="gfsecret"
GRAFANA_BREAKGLASS_PASS="gfbreak"
OAUTH2_PROXY_SECRET="nrsecret"
OAUTH2_COOKIE_SECRET="nrcookie0123456789abcdef01234567"
PORTAL_OAUTH2_PROXY_SECRET="portalsecret"
PORTAL_COOKIE_SECRET="portalcookie0123456789abcdef0123"
PGADMIN_OAUTH_SECRET="pgasecret"
CONFIG_OAUTH2_PROXY_SECRET="cfgsecret"
CONFIG_COOKIE_SECRET="cfgcookie0123456789abcdef0123456"
DBMGMT_CLIENT_SECRET="dbsecret"
DBMGMT_COOKIE_SECRET="dbcookie0123456789abcdef01234567"
SCHEDULER_CLIENT_SECRET="schsecret"
SCHEDULER_COOKIE_SECRET="schcookie0123456789abcdef0123456"
MONITOR_CLIENT_SECRET="monsecret"
MONITOR_COOKIE_SECRET="moncookie0123456789abcdef0123456"
MQTTX_CLIENT_SECRET="mqxsecret"
MQTTX_COOKIE_SECRET="mqxcookie0123456789abcdef0123456"
ACCESS_CLIENT_SECRET="accsecret"
ACCESS_COOKIE_SECRET="acccookie0123456789abcdef0123456"
WORKBENCH_SECRET="wbsecret"
EDGE_WIZARD_SECRET="ewsecret"
EDGE_WIZARD_PORT="8088"
MQTT_SCHEDULER_PASS="mqsch"
IAM_GATES="true"
IAM_NETPOL="true"
IAM_ENFORCE="false"
IAM_POSTGREST_JWT="false"
IAM_DB_ROLES="false"
IAM_MQTT_PERSON="false"
WORKBENCH_ENABLED="true"
"""

# deploy-infra.sh's blocks: (function, start marker, end marker, trailing chars dropped)
INFRA_BLOCKS = [
    ("pa_iam_lib", "# The access policy's check (codeplan IAM plan 1.1/1.2)", "    exit 1\nfi\n\n# NetworkPolicies",
     len("\n# NetworkPolicies")),
    ("pa_netpol", "# NetworkPolicies of the application pods", "        exit 1\n    fi\nfi\n", 0),
    ("pa_node_red_auth", 'if _NR_PERMS="$(python3', "    exit 1\nfi\n", 0),
    ("pa_grafana", 'echo -e "\\n${GREEN}Pre-wiring Grafana Postgres datasource...${NC}"',
     "previous one until ./deploy-infra.sh sets it.${NC}\" >&2\nfi\n", 0),
    ("pa_node_red_proxy", 'echo -e "\\n${GREEN}[7/10] Deploying OAuth2 Proxy', "    exit 1\n}\n", 0),
    ("pa_pgadmin", 'echo -e "\\n${GREEN}[8/10] Deploying pgAdmin...${NC}"', '  -n "$NAMESPACE" --timeout=16m\n', 0),
    ("pa_portal_proxy", "# Portal OAuth2 Proxy (Keycloak client: portal)\n",
     '$MK8S kubectl rollout restart deployment/portal-oauth2-proxy -n "$NAMESPACE"\n', 0),
]
# each app's gate block before 4.2b: (script, start marker, end marker, today's call)
APP_BLOCKS = [
    ("apps/frontend/deploy.sh", "_CFG_VALUES=$(mktemp", 'rm -f "$_CFG_VALUES"\n', "_gate config"),
    ("apps/frontend/deploy.sh", "_DB_VALUES=$(mktemp", 'rm -f "$_DB_VALUES"\n', "_gate dbmgmt"),
    ("apps/scheduler/deploy.sh", "_VALUES=$(mktemp /tmp/scheduler", 'rm -f "$_VALUES"\n', "_gate"),
    ("apps/monitor/deploy.sh", "_VALUES=$(mktemp /tmp/monitor", 'rm -f "$_VALUES"\n', "_gate"),
    ("apps/mqtt-explorer/deploy.sh", "_VALUES=$(mktemp /tmp/mqttx", 'rm -f "$_VALUES"\n', "_gate"),
    ("apps/access/deploy.sh", "# =============================================================================\n# 5. Proof",
     "# =============================================================================\n# 7. Portal card", "_gate"),
]
APP_PRELUDE = """
APP_DIR="$REPO_ROOT/apps/x"; SCRIPT_DIR="$REPO_ROOT/{appdir}"
log() {{ echo "[app] $*"; }}; warn() {{ echo "[app] $*" >&2; }}; die() {{ echo "[app] ERROR: $*" >&2; exit 1; }}
ACCESS_PROOF_TIMEOUT=0
CONFIG_DOMAIN="config.$DOMAIN"
_COMPILED_GROUPS="$(policy_groups ACCESS_DOMAIN)"
_MODE=full
"""

def _blocks_of(text, start, end, drop=0):
    i = text.index(start)
    j = text.index(end, i) + len(end) - drop
    return text[i:j]


def _gate_def(text):
    """an app's _gate() definition, up to the scoped branch that follows it"""
    i = text.index("_gate() {")
    j = text.index('\nif [[ "$_MODE" == scoped ]]; then', i)
    return text[i:j] + "\n"


class Env:
    """a scratch tree, its fake bin directory and its fake cluster"""

    def __init__(self, rev=None):
        self.root = tempfile.mkdtemp(prefix="medcea-scoped-")
        self.tree = os.path.join(self.root, "tree")
        os.makedirs(self.tree)
        if rev:
            arch = subprocess.run(["git", "-C", REPO, "archive", rev], check=True, capture_output=True).stdout
            subprocess.run(["tar", "-x", "-C", self.tree], input=arch, check=True)
        else:
            files = subprocess.run(["git", "-C", REPO, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                   check=True, capture_output=True).stdout.decode().split("\0")
            for f in files:
                src = os.path.join(REPO, f)
                if f and os.path.isfile(src) and not f.startswith(("logs/", "state/")):
                    dst = os.path.join(self.tree, f)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
        with open(os.path.join(self.tree, "config.env"), "w") as f:
            f.write(CONFIG)
        self.bin = os.path.join(self.root, "bin")
        os.makedirs(self.bin)
        for n in FAKE_NAMES:
            os.symlink(FAKE, os.path.join(self.bin, n))
        self.state = os.path.join(self.root, "state.json")
        self.log = os.path.join(self.root, "log.jsonl")
        self.pgrep = os.path.join(self.root, "pgrep.txt")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def env(self, **extra):
        e = {k: v for k, v in os.environ.items()
             if not k.startswith(("MEDCEA_", "KUBECONFIG")) and k not in ("REPO_ROOT", "SCRIPT_DIR")}
        e.update(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_STATE=self.state, FAKE_LOG=self.log,
                 FAKE_PGREP=self.pgrep, MEDCEA_NO_LOG="1", HOME=self.root)
        e.update(extra)
        return e

    def bash(self, script, locked=False, **extra):
        """script in the tree; locked: under the deploy lock and a verified policy source, as
        a parent deploy (apply.sh, the guide) would hold them"""
        if locked:
            script = ('exec 9>>"$PWD/.medcea.lock"; flock -n 9 || exit 99\n'
                      'export MEDCEA_LOCK_HELD=$$ MEDCEA_POLICY_SOURCE_DONE=$$\n' + script + '\nexit $?\n')
        return subprocess.run(["bash", "-c", script], cwd=self.tree, env=self.env(**extra),
                              capture_output=True, text=True, timeout=600)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as f:
            return [json.loads(x) for x in f if x.strip()]

    def reset_log(self):
        if os.path.exists(self.log):
            os.remove(self.log)

    def store(self):
        with open(self.state) as f:
            return json.load(f)

    def put(self, st):
        with open(self.state, "w") as f:
            json.dump(st, f)


TMP = re.compile(r"/tmp/[^\s/'\"]+")


def normalise(calls, declared=True, root=None):
    """the transcript: the scratch tree and temporary paths replaced, the background
    port-forwards (racing the next command) counted rather than placed; with declared, the
    gate page's sha256 (its read and its --set) and db_clients_live's question whether
    Superset is deployed (stage B, read-only, prints nothing without it) dropped"""
    out, forwards = [], 0
    for c in calls:
        argv = [a.replace(root, "TREE") if root else a for a in c["argv"]]
        argv = [TMP.sub("/tmp/T", a) for a in argv]
        if c["cmd"] == "kubectl" and argv[:1] == ["port-forward"]:
            forwards += 1
            continue
        if declared:
            if c["cmd"] == "kubectl" and argv[:2] == ["get", "configmap"] and len(argv) > 2 \
               and argv[2].endswith("-templates") and any(a.startswith("jsonpath=") for a in argv):
                continue
            if c["cmd"] == "kubectl" and argv[:3] == ["get", "deployment", "superset"]:
                continue
            keep = []
            for a in argv:
                if a.startswith("podAnnotations.medcea/gate-page-sha256="):
                    keep.pop()   # its --set
                    continue
                keep.append(a)
            argv = keep
        out.append((c["cmd"], tuple(argv), c.get("stdin"), tuple(c.get("values") or ())))
    return out + [("port-forwards", forwards)]


def writes(calls):
    return [c for c in calls if c["write"]]


INFRA_PRELUDE = """set -e
SCRIPT_DIR="$PWD"; REPO_ROOT="$PWD"
source config.env
MK8S=microk8s; KUBECTL="microk8s kubectl"
RED=; YELLOW=; GREEN=; NC=
source infra/lib-render.sh
source infra/lib-oauth2-proxy.sh
source infra/lib-keycloak-admin.sh
source infra/lib-db-roles.sh
source apps/database/lib-db-apply.sh
policy_grafana
_MQP=false
"""


class Transcript(unittest.TestCase):
    maxDiff = None
    """the full deploys issue PRE_42B's commands (§14.5.6)"""

    @classmethod
    def setUpClass(cls):
        cls.old, cls.new = Env(PRE_42B), Env()

    @classmethod
    def tearDownClass(cls):
        cls.old.cleanup()
        cls.new.cleanup()

    def _pair(self, old_script, new_script):
        res = []
        for e, s in ((self.old, old_script), (self.new, new_script)):
            e.reset_log()
            e.put({})
            r = e.bash(s)
            res.append((r, normalise(e.calls(), root=e.tree)))
        return res

    def test_infra_blocks(self):
        with open(os.path.join(self.old.tree, "deploy-infra.sh")) as f:
            old_text = f.read()
        for fn, start, end, drop in INFRA_BLOCKS:
            with self.subTest(block=fn):
                block = _blocks_of(old_text, start, end, drop)
                (ro, to), (rn, tn) = self._pair(INFRA_PRELUDE + block,
                                                INFRA_PRELUDE + "source infra/lib-policy-artefacts.sh\n" + fn + " full\n")
                self.assertEqual(ro.returncode, rn.returncode, (ro.stderr[-800:], rn.stderr[-800:]))
                self.assertTrue(to, f"{fn}: the old block issued no command")
                self.assertEqual(to, tn)

    def test_mqtt_retire(self):
        with open(os.path.join(self.old.tree, "deploy-infra.sh")) as f:
            block = _blocks_of(f.read(), '    if [[ -n "${IAM_MQTT_DIGEST:-}" ]]; then\n', "        fi\n    fi\n")
        pre = INFRA_PRELUDE + 'IAM_MQTT_DIGEST=abc\n'
        (ro, to), (rn, tn) = self._pair(pre + block, pre + "source infra/lib-policy-artefacts.sh\npa_mqtt_retire\n")
        self.assertEqual((ro.returncode, to), (rn.returncode, tn))

    def test_app_gates(self):
        for script, start, end, call in APP_BLOCKS:
            with self.subTest(script=script, call=call):
                with open(os.path.join(self.old.tree, script)) as f:
                    old_block = _blocks_of(f.read(), start, end)
                with open(os.path.join(self.new.tree, script)) as f:
                    new_def = _gate_def(f.read())
                pre = INFRA_PRELUDE.replace("set -e\n", "set -euo pipefail\n") + "source infra/lib-wait.sh\n" \
                    + APP_PRELUDE.format(appdir=os.path.dirname(script))
                (ro, to), (rn, tn) = self._pair(pre + old_block, pre + new_def + call + "\n")
                self.assertEqual(ro.returncode, rn.returncode, (ro.stderr[-800:], rn.stderr[-800:]))
                self.assertTrue(to)
                self.assertEqual(to, tn)

    def test_declared_difference_only(self):
        """without dropping the declared lines, a gated proxy differs exactly by them"""
        e = self.new
        e.reset_log()
        e.put({})
        with open(os.path.join(e.tree, "apps/monitor/deploy.sh")) as f:
            new_def = _gate_def(f.read())
        pre = INFRA_PRELUDE + "source infra/lib-wait.sh\n" + APP_PRELUDE.format(appdir="apps/monitor")
        e.bash(pre + new_def + "_gate\n")
        full, dropped = normalise(e.calls(), declared=False), normalise(e.calls())
        self.assertEqual(len(full) - len(dropped), 1)   # the page read
        helm = [c for c in e.calls() if c["cmd"] == "helm" and c["argv"][0] == "upgrade"]
        self.assertTrue(any(a.startswith("podAnnotations.medcea/gate-page-sha256=") for a in helm[0]["argv"]))


SEED = INFRA_PRELUDE + """source infra/lib-wait.sh
source infra/lib-policy-artefacts.sh
microk8s kubectl apply -f - <<'EOF'
{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "rdbms-postgresql-0",
 "labels": {"app.kubernetes.io/name": "postgresql", "app.kubernetes.io/instance": "rdbms"}}}
EOF
pa_iam_lib full
pa_netpol full
pa_node_red_auth full
pa_grafana full
pa_node_red_proxy full
pa_pgadmin full
pa_portal_proxy full
_MODE=full
app_gate full config-oauth2-proxy config "$CONFIG_OAUTH2_PROXY_SECRET" "$CONFIG_COOKIE_SECRET" CONFIG_DOMAIN config.medcea k8s/oauth2-proxy/values-app.yaml config-ui
app_gate full dbmgmt-oauth2-proxy dbmgmt "$DBMGMT_CLIENT_SECRET" "$DBMGMT_COOKIE_SECRET" DBMGMT_DOMAIN "$DBMGMT_DOMAIN" k8s/oauth2-proxy/values-app.yaml dbmgmt
app_gate full scheduler-oauth2-proxy scheduler "$SCHEDULER_CLIENT_SECRET" "$SCHEDULER_COOKIE_SECRET" SCHEDULER_DOMAIN "$SCHEDULER_DOMAIN" k8s/oauth2-proxy/values-app.yaml scheduler
app_gate full monitor-oauth2-proxy monitor "$MONITOR_CLIENT_SECRET" "$MONITOR_COOKIE_SECRET" MONITOR_DOMAIN "$MONITOR_DOMAIN" k8s/oauth2-proxy/values-app.yaml monitor
app_gate full mqttx-oauth2-proxy mqtt-explorer "$MQTTX_CLIENT_SECRET" "$MQTTX_COOKIE_SECRET" MQTTX_DOMAIN "$MQTTX_DOMAIN" apps/mqtt-explorer/k8s/oauth2-proxy-values.yaml
app_gate full access-oauth2-proxy access "$ACCESS_CLIENT_SECRET" "$ACCESS_COOKIE_SECRET" ACCESS_DOMAIN "$ACCESS_DOMAIN" apps/access/k8s/oauth2-proxy-values.yaml
app_gate full iam-oauth2-proxy policy "$POLICY_CLIENT_SECRET" "$POLICY_COOKIE_SECRET" POLICY_DOMAIN "$POLICY_DOMAIN" k8s/oauth2-proxy/values-app.yaml iam-admin
"""
SCOPED = [
    ("./deploy-infra.sh --policy-only", "deploy-infra"),
    ("./infra/deploy-workbench.sh --policy-only", "workbench"),
    ("./apps/frontend/deploy.sh --gate-only", "frontend"),
    ("./apps/scheduler/deploy.sh --gate-only", "scheduler"),
    ("./apps/monitor/deploy.sh --gate-only", "monitor"),
    ("./apps/mqtt-explorer/deploy.sh --gate-only", "mqtt-explorer"),
    ("./apps/access/deploy.sh --gate-only", "access"),
    ("./apps/iam/deploy.sh --gate-only", "iam"),
]


class Scoped(unittest.TestCase):
    """the scoped modes act on drift only (§14.5.6)"""

    def setUp(self):
        self.e = Env()
        self.e.put({})
        r = self.e.bash(SEED)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        r = self.e.bash("./infra/deploy-workbench.sh", locked=True)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        self.e.reset_log()

    def tearDown(self):
        self.e.cleanup()

    def run_scoped(self, cmd):
        self.e.reset_log()
        r = self.e.bash(cmd, locked=True)
        self.assertEqual(r.returncode, 0, f"{cmd}: {r.stdout[-2000:]}{r.stderr[-2000:]}")
        return r, self.e.calls()

    def test_equal_cluster_writes_nothing(self):
        for cmd, _ in SCOPED:
            with self.subTest(cmd=cmd):
                r, calls = self.run_scoped(cmd)
                self.assertEqual(writes(calls), [], r.stdout[-2000:])
                self.assertNotIn("re-rendered", r.stdout)
                self.assertIn("unchanged", r.stdout, r.stdout[-1500:])
                self.assertFalse(any(c["cmd"] == "kubectl" and c["argv"][:1] == ["port-forward"] for c in calls),
                                 "a scoped mode asked Keycloak with nothing drifted")

    def test_policy_only_prints_every_target(self):
        r, _ = self.run_scoped("./deploy-infra.sh --policy-only")
        for target in ("medcea-iam-lib", "netpol", "node-red-auth", "grafana", "NODE_RED_DOMAIN", "pgadmin",
                       "PORTAL_DOMAIN"):
            self.assertRegex(r.stdout, rf"{re.escape(target)}[^\n]*: unchanged")

    def test_one_drift_one_target(self):
        st = self.e.store()
        st["configmap/node-red-auth"]["data"]["permissions.json"] = "{}"
        self.e.put(st)
        r, calls = self.run_scoped("./deploy-infra.sh --policy-only")
        self.assertRegex(r.stdout, r"node-red-auth: re-rendered")
        w = writes(calls)
        self.assertEqual(len(w), 1, w)
        self.assertEqual(w[0]["argv"][:1], ["apply"])
        self.assertNotEqual(self.e.store()["configmap/node-red-auth"]["data"]["permissions.json"], "{}")
        r, calls = self.run_scoped("./deploy-infra.sh --policy-only")   # and then it is equal again
        self.assertEqual(writes(calls), [])

    def test_gate_drift_rerenders_without_restart(self):
        st = self.e.store()
        cm = st["configmap/scheduler-oauth2-proxy"]["data"]
        cm["oauth2_proxy.cfg"] = re.sub(r"(?m)^(\s*allowed_groups\s*=).*$", r'\1 ["admin"]', cm["oauth2_proxy.cfg"])
        self.e.put(st)
        r, calls = self.run_scoped("./apps/scheduler/deploy.sh --gate-only")
        self.assertIn("re-rendered", r.stdout)
        w = writes(calls)
        self.assertTrue(any(c["cmd"] == "helm" and "scheduler-oauth2-proxy" in c["argv"] for c in w), w)
        self.assertFalse(any(c["cmd"] == "kubectl" and c["argv"][:2] == ["rollout", "restart"] for c in w), w)
        self.assertTrue(all(c["cmd"] == "helm" or "scheduler-oauth2-proxy-templates" in " ".join(c["argv"])
                            or c["argv"][:1] == ["apply"] for c in w), w)
        r, calls = self.run_scoped("./apps/scheduler/deploy.sh --gate-only")
        self.assertEqual(writes(calls), [])

    def test_gate_page_drift(self):
        st = self.e.store()
        st["deployment/monitor-oauth2-proxy"]["spec"]["template"]["metadata"]["annotations"] = {}
        self.e.put(st)
        r, calls = self.run_scoped("./apps/monitor/deploy.sh --gate-only")
        self.assertIn("re-rendered (403 page)", r.stdout)

    def test_grafana_drift_rerenders_the_section(self):
        st = self.e.store()
        for e in st["deployment/grafana"]["spec"]["template"]["spec"]["containers"][0]["env"]:
            if e["name"] == "GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH":
                e["value"] = "'Admin'"
        self.e.put(st)
        r, calls = self.run_scoped("./deploy-infra.sh --policy-only")
        self.assertRegex(r.stdout, r"grafana: re-rendered")
        w = writes(calls)
        self.assertTrue(any(c["cmd"] == "helm" and "grafana" in c["argv"] for c in w))
        self.assertFalse(any("oauth2-proxy" in " ".join(c["argv"]) for c in w), w)

    def test_pgadmin_drift_asks_keycloak(self):
        st = self.e.store()
        st["secret/pgadmin-config"]["data"]["oauth2-config"] = "W3siT0FVVEgyX0FERElUSU9OQUxfQ0xBSU1TIjogTm9uZX1d"
        self.e.put(st)
        r, calls = self.run_scoped("./deploy-infra.sh --policy-only")
        self.assertRegex(r.stdout, r"pgadmin: re-rendered")
        self.assertTrue(any(c["cmd"] == "kubectl" and c["argv"][:1] == ["port-forward"] for c in calls))

    def test_workbench_drift(self):
        import base64
        import yaml
        st = self.e.store()
        v = yaml.safe_load(base64.b64decode(st["secret/hub"]["data"]["values.yaml"]))
        v["hub"]["config"]["GenericOAuthenticator"]["allowed_groups"] = ["admin"]
        st["secret/hub"]["data"]["values.yaml"] = base64.b64encode(yaml.safe_dump(v).encode()).decode()
        self.e.put(st)
        r, calls = self.run_scoped("./infra/deploy-workbench.sh --policy-only")
        self.assertIn("re-rendered", r.stdout)
        w = writes(calls)
        self.assertEqual([c["cmd"] for c in w], ["helm"], w)   # not the examples ConfigMap

    def test_superset_gate_not_deployed(self):
        """Superset stage C: owners --scoped runs superset's --gate-only too; with no
        deployment/superset it says so, compiles nothing and writes nothing (apply.sh's
        rollout of the skeleton and change versions before the first install)."""
        r, calls = self.run_scoped("./apps/superset/deploy.sh --gate-only")
        self.assertIn("SUPERSET_DOMAIN (superset): not deployed", r.stdout)
        self.assertEqual(writes(calls), [])
        self.assertNotIn("re-rendered", r.stdout)

    def test_frontend_gate_only_never_pgrst(self):
        st = self.e.store()
        st.pop("deployment/config-oauth2-proxy")
        self.e.put(st)
        r, calls = self.run_scoped("./apps/frontend/deploy.sh --gate-only")
        self.assertIn("CONFIG_DOMAIN (config-oauth2-proxy): not deployed", r.stdout)
        self.assertEqual(writes(calls), [])
        self.assertFalse(any("config-api" in " ".join(c["argv"]) for c in calls))


class Arguments(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.cleanup()

    def test_unknown_option_refused(self):
        for cmd in ("./deploy-infra.sh --polcy-only", "./deploy-infra.sh --reset --x", "./deploy-infra.sh a b",
                    "./infra/deploy-workbench.sh --gate-only", "./infra/deploy-policy.sh --x",
                    "./apps/frontend/deploy.sh --policy-only", "./apps/scheduler/deploy.sh x",
                    "./apps/monitor/deploy.sh --gate-only x", "./apps/mqtt-explorer/deploy.sh -h",
                    "./apps/access/deploy.sh --all", "./apps/iam/deploy.sh --bootstrap",
                    "./apps/edge-wizard/deploy.sh --x", "./apps/superset/deploy.sh --policy-only"):
            with self.subTest(cmd=cmd):
                self.e.reset_log()
                r = self.e.bash(cmd)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("unknown arguments", r.stderr)
                self.assertEqual(self.e.calls(), [])
                self.assertFalse(os.path.exists(os.path.join(self.e.tree, ".medcea.lock")))


class Wizard(unittest.TestCase):
    """the edge wizard's --gate-only: a drift restarts the unit, or defers (exit 4)"""

    def setUp(self):
        self.e = Env()
        self.e.put({})
        os.makedirs(os.path.join(self.e.root, ".config/systemd/user"))
        r = self.e.bash("source config.env; REPO_ROOT=$PWD; source infra/lib-policy-tools.sh; policy_tool edge-wizard")
        self.roles = r.stdout.strip()
        self.assertTrue(self.roles, r.stderr)
        self.next = os.path.join(self.e.root, "pgrep-next.txt")
        with open(self.next, "w") as f:
            f.write(f"4242 python3 edge/src/host/wizard_server.py --daemon --required-role {self.roles}\n")

    def tearDown(self):
        self.e.cleanup()

    def wizard(self, argv, cgroup=""):
        with open(self.e.pgrep, "w") as f:
            f.write(argv)
        self.e.reset_log()
        return self.e.bash("./apps/edge-wizard/deploy.sh --gate-only", locked=True,
                           FAKE_CGROUP=cgroup, FAKE_PGREP_NEXT=self.next)

    def test_equal(self):
        r = self.wizard(f"4242 python3 wizard_server.py --daemon --required-role {self.roles}\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("unchanged", r.stdout)
        self.assertEqual(writes(self.e.calls()), [])

    def test_drift_restarts(self):
        r = self.wizard("4242 python3 wizard_server.py --daemon --required-role engineer\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("re-rendered", r.stdout)
        self.assertEqual([c["argv"] for c in writes(self.e.calls())], [["--user", "restart", "cea-edge-wizard"]])

    def test_drift_with_flash_defers(self):
        with open("/proc/self/cgroup") as f:
            cg = f.read().strip().split("::", 1)[-1]
        if not os.access(f"/sys/fs/cgroup{cg}/cgroup.procs", os.R_OK):
            self.skipTest("no readable cgroup v2 for this process")
        flash = subprocess.Popen(["bash", "-c", "sleep 60; true", "flash-device.sh"])   # not exec'd: bash stays
        try:
            r = self.wizard("4242 python3 wizard_server.py --daemon --required-role engineer\n", cgroup=cg)
        finally:
            flash.kill()
            flash.wait()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("deferred", r.stdout + r.stderr)
        self.assertEqual(writes(self.e.calls()), [])


class Resume(unittest.TestCase):
    """apply.sh --resume's pieces (the database side is the live check)"""

    def py(self, *args):
        return subprocess.run([sys.executable, os.path.join(REPO, "apps/iam/apply_check.py"), *args],
                              capture_output=True, text=True)

    def test_owners_scoped(self):
        r = self.py("owners", "--scoped")
        cmds = r.stdout.split()
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "./deploy-infra.sh --policy-only")
        self.assertEqual(lines[1], "./infra/deploy-workbench.sh --policy-only")
        self.assertEqual(len(lines), len(set(lines)))
        self.assertNotIn("./apps/database/deploy.sh", cmds)
        for line in lines[2:]:
            self.assertRegex(line, r"^\./apps/[a-z-]+/deploy\.sh --gate-only$")

    def test_deferred_record(self):
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, "s.json")
            with open(st, "w") as f:
                json.dump({"version": 3, "kind": "change"}, f)
            out = os.path.join(d, "r.sql")
            r = self.py("deferred-record", "--state", st, "--target", "edge-wizard", "--reason", "a flash",
                        "--command", "./apps/edge-wizard/deploy.sh --gate-only", "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                sql = f.read()
            self.assertIn("_set_internal_actor('system:apply')", sql)
            self.assertIn("iam_policy._record('apply_deferred'", sql)

    def test_health_counts_only_open_deferrals(self):
        with open(os.path.join(REPO, "infra/lib-policy-source.sh")) as f:
            text = f.read()
        i = text.index("'apply_deferred_open'")
        self.assertIn("c.event IN ('applied', 'bootstrap_applied')", text[i:i + 600])
        self.assertIn("'apply_deferred')", text[text.index("'last_apply_event'"):][:600])

    def test_resume_accepts_a_deferral(self):
        with open(os.path.join(REPO, "apps/iam/apply.sh")) as f:
            text = f.read()
        self.assertRegex(text, r"\n    apply_deferred\) log ")
        self.assertIn('mapfile -t cmds < <(py "$CHECK" owners --scoped)', text)   # AS.rollout (4.5)
        self.assertRegex(text, r"\n +4\) if \[\[ ! \" \$\{DEFERRED\[\*\]\} \" == \*\" \$cmd \"\* \]\]; then\n +DEFERRED\+=")


if __name__ == "__main__":
    unittest.main()
