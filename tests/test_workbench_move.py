#!/usr/bin/env python3
"""tests/test_workbench_move.py — the AI workbench between the platform namespace and the
research zone (research sandbox Phase 2b, commit A), offline.

infra/deploy-workbench.sh runs in a scratch tree (tests/_scratch.py) with the real compiler on
the factory policy (v7: placement platform) or on commit B's shapes (tests/rs2b_fixture.py
b_policy: placement research, no network.clients.notebooks, no token client
workbench-notebook), under a lock and a verified policy source as deploy-infra or apply.sh
hold them, with a stateful fake microk8s (kubectl and helm3), sudo, curl (wait_for_http and
Keycloak's admin API on the --move port-forward 18095), fuser and sleep first on PATH. The
homes are real directories in a scratch volume directory (the StorageClass's pvDir), so the
copy is a real `cp -a`.

  Table     the decision table of codeplan SPEC §2.1: a release in the other namespace exits 4
            with the --move line (full) or "deferred" (--policy-only) and writes nothing; the
            research placement with RESEARCH_ENABLED not true is a skip (exit 0); two releases
            refuse; a zone that is not ready refuses; a fresh research install issues
            workbench-tls and applies Role medcea-hub before helm, frees the Released homes of
            an earlier install, and installs with both values files; --policy-only there is
            "unchanged", and a drifted A2 hook re-renders without TLS or Role
  Move      --move's refusals (switches, a running server, no terminal, a zone not ready, a
            namespace missing) change nothing; the move itself: hub and proxy scaled to 0, then
            the mount re-check, every home and hub-db-dir Retain before the uninstall, the
            Keycloak client disabled by read-modify-write only when the policy lacks the token
            client, each home copied with sudo into <pvDir>/<dst>-<claim>-pvc-<uuid4> (the
            hub administrator's own not), its PV (hostPath type, capacity, nodeAffinity,
            claimRef, labels) and PVC applied server-side, the source claim labelled
            moved-to, TLS and Role before the install, what is left listed; a re-run copies
            nothing again; the move back replaces the stale labelled copy; a pod that still
            mounts a home after the scale-down gives the hub back and refuses

Run: python3 tests/test_workbench_move.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from _scratch import clean_env, scratch_repo  # noqa: E402
import rs2b_fixture  # noqa: E402

NS, RNS = "medcea", "medcea-research"
UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
NODE_IPS = "192.0.2.10 "

CONFIG = f"""PROJECT_NAME="medcea"
NAMESPACE="{NS}"
RESEARCH_NAMESPACE="{RNS}"
KEYCLOAK_REALM="medcea"
DOMAIN="medcea"
KEYCLOAK_DOMAIN="keycloak.medcea"
PORTAL_DOMAIN="portal.medcea"
WORKBENCH_DOMAIN="ai-workbench.medcea"
WORKBENCH_SECRET="wbsecret-do-not-print"
ADMIN_USER="admin"
KC_DEPLOYER_SECRET="kcdeployer-do-not-print"
IAM_GATES="true"
IAM_POSTGREST_JWT="false"
IAM_DB_ROLES="false"
"""

FAKE = r'''#!/usr/bin/env python3
"""a stateful fake of microk8s (kubectl, helm3), sudo, curl, fuser and sleep"""
import base64, json, os, subprocess, sys
import yaml

ST, LOG = os.environ["FAKE_STATE"], os.environ["FAKE_LOG"]
me = os.path.basename(sys.argv[0])
argv = sys.argv[1:]


def load():
    try:
        with open(ST) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(st):
    with open(ST, "w") as f:
        json.dump(st, f, sort_keys=True)


def log(cmd, args, write, stdin=None):
    with open(LOG, "a") as f:
        f.write(json.dumps({"cmd": cmd, "argv": args, "write": write, "stdin": stdin}) + "\n")


def opt(a, *names):
    for n in names:
        if n in a:
            return a[a.index(n) + 1]
        for x in a:
            if x.startswith(n + "="):
                return x.split("=", 1)[1]
    return None


def sel_match(obj, sel):
    if not sel:
        return True
    labels = obj.get("metadata", {}).get("labels") or {}
    for term in sel.split(","):
        k, eq, v = term.partition("=")
        if eq and labels.get(k) != v:
            return False
        if not eq and k not in labels:
            return False
    return True


def ns_of(o):
    return o.get("metadata", {}).get("namespace", "")


def kubectl(a):
    st = load()
    st.setdefault("objs", {})
    objs = st["objs"]
    verb = a[0]
    stdin = sys.stdin.read() if ("-f" in a and opt(a, "-f") == "-") else None
    write = verb in ("apply", "delete", "patch", "label", "scale", "annotate") or (
        verb == "create" and not any(x.startswith("--dry-run") for x in a))
    log("kubectl", a, write, stdin)
    ns = opt(a, "-n", "--namespace")
    out = opt(a, "-o")
    pos = [x for i, x in enumerate(a) if not x.startswith("-") and (i == 0 or a[i - 1] not in
           ("-n", "--namespace", "-o", "-l", "-p", "--type", "--timeout", "-c", "--tail", "--replicas", "-f",
            "--field-manager", "--cert", "--key"))]
    if verb in ("port-forward", "rollout", "logs"):
        return 0
    if verb == "get":
        kind = pos[1].split(".")[0] if len(pos) > 1 else ""
        kind = {"netpol": "networkpolicy", "networkpolicies": "networkpolicy", "persistentvolumeclaim": "pvc",
                "persistentvolumeclaims": "pvc", "persistentvolume": "pv", "persistentvolumes": "pv",
                "deploy": "deployment", "deployments": "deployment", "po": "pod", "pods": "pod",
                "nodes": "node", "namespaces": "namespace", "secrets": "secret"}.get(kind, kind)
        if kind == "node":
            sys.stdout.write(os.environ.get("FAKE_NODE_IPS", ""))
            return 0
        if kind == "storageclass":
            sys.stdout.write(st.get("pvdir", ""))
            return 0
        name = pos[2] if len(pos) > 2 else None
        cluster = kind in ("pv", "namespace")
        if name:
            o = objs.get(f"{kind}/{'' if cluster else ns}/{name}")
            if o is None:
                print(f'Error from server (NotFound): {kind} "{name}" not found', file=sys.stderr)
                return 1
            if out == "name":
                print(f"{kind}/{name}")
            elif out and out.startswith("jsonpath="):
                if "values\\.yaml" in out:
                    sys.stdout.write(o.get("data", {}).get("values.yaml", ""))
            else:
                print(json.dumps(o))
            return 0
        items = [o for k, o in sorted(objs.items()) if k.startswith(kind + "/")
                 and (cluster or ns_of(o) == ns) and sel_match(o, opt(a, "-l"))]
        if out == "name":
            for o in items:
                print(f"{kind}/{o['metadata']['name']}")
        else:
            print(json.dumps({"kind": "List", "items": items}))
        return 0
    if verb == "scale":
        n = opt(a, "--replicas")
        for d in pos[2:]:
            st.setdefault("scaled", []).append([ns, d, n])
            if n == "0":   # the hub and proxy pods go
                for k in [k for k, o in objs.items() if k.startswith("pod/") and ns_of(o) == ns
                          and (o["metadata"].get("labels") or {}).get("component") == d]:
                    objs.pop(k)
        save(st)
        return 0
    if verb == "patch":
        kind = {"pv": "pv", "persistentvolume": "pv"}.get(pos[1], pos[1])
        o = objs[f"{kind}//{pos[2]}"]
        def merge(x, y):
            for k, v in y.items():
                if v is None:
                    x.pop(k, None)
                elif isinstance(v, dict) and isinstance(x.get(k), dict):
                    merge(x[k], v)
                else:
                    x[k] = v
        merge(o, json.loads(opt(a, "-p")))
        save(st)
        return 0
    if verb == "label":
        o = objs[f"pv//{pos[2]}"] if pos[1] in ("pv", "persistentvolume") else objs[f"pvc/{ns}/{pos[2]}"]
        for kv in pos[3:]:
            k, eq, v = kv.partition("=")
            if not eq and k.endswith("-"):
                o["metadata"].setdefault("labels", {}).pop(k[:-1], None)
            else:
                o["metadata"].setdefault("labels", {})[k] = v
        save(st)
        return 0
    if verb == "delete":
        objs.pop(f"pvc/{ns}/{pos[2]}", None)
        for k, p in objs.items():   # a Retain PV whose claim went is Released
            ref = (p.get("spec") or {}).get("claimRef") or {}
            if k.startswith("pv/") and ref.get("namespace") == ns and ref.get("name") == pos[2]:
                p.setdefault("status", {})["phase"] = "Released"
        save(st)
        return 0
    if verb == "create" and pos[1] in ("configmap", "secret"):
        name = pos[3] if pos[1] == "secret" else pos[2]
        kind = "Secret" if pos[1] == "secret" else "ConfigMap"
        print(yaml.safe_dump({"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": ns}}))
        return 0
    if verb == "apply":
        for d in yaml.safe_load_all(stdin or ""):
            if not d:
                continue
            for o in (d.get("items") or [] if d.get("kind") == "List" else [d]):
                kind = {"PersistentVolume": "pv", "PersistentVolumeClaim": "pvc"}.get(o["kind"], o["kind"].lower())
                cluster = kind in ("pv",)
                o_ns = "" if cluster else (o["metadata"].get("namespace") or ns or "")
                o["metadata"]["namespace"] = o_ns
                if kind == "pvc":
                    o.setdefault("status", {})["phase"] = "Bound"
                if kind == "pv":
                    o.setdefault("status", {})["phase"] = "Bound"
                objs[f"{kind}/{o_ns}/{o['metadata']['name']}"] = o
        save(st)
        return 0
    return 0


def helm(a):
    st = load()
    st.setdefault("releases", {})
    if a[:1] == ["list"]:
        log("helm", a, False)
        print(json.dumps([{"name": "workbench", "namespace": n} for n in sorted(st["releases"])]))
        return 0
    if a[:1] in (["repo"],):
        log("helm", a, False)
        return 0
    ns = opt(a, "--namespace", "-n")
    if a[:1] == ["uninstall"]:
        log("helm", a, True)
        st["releases"].pop(ns, None)
        objs = st.setdefault("objs", {})
        for k in [k for k, o in objs.items() if ns_of(o) == ns and (k.startswith(("deployment/", "secret/hub"))
                  or k == f"pvc/{ns}/hub-db-dir")]:
            objs.pop(k)
        for k, p in objs.items():
            ref = (p.get("spec") or {}).get("claimRef") or {}
            if k.startswith("pv/") and ref.get("namespace") == ns and ref.get("name") == "hub-db-dir":
                p.setdefault("status", {})["phase"] = "Released"
        save(st)
        return 0
    vals = {}
    files = [a[i + 1] for i, x in enumerate(a) if x == "--values"]
    for f in files:
        with open(f) as fh:
            v = yaml.safe_load(fh) or {}
        def merge(x, y):
            out = dict(x)
            for k, w in y.items():
                out[k] = merge(out[k], w) if isinstance(w, dict) and isinstance(out.get(k), dict) else w
            return out
        vals = merge(vals, v)
    log("helm", a, True)
    st["releases"][ns] = True
    objs = st.setdefault("objs", {})
    objs[f"secret/{ns}/hub"] = {"kind": "Secret", "metadata": {"name": "hub", "namespace": ns},
                                "data": {"values.yaml": base64.b64encode(yaml.safe_dump(vals).encode()).decode()}}
    for d in ("hub", "proxy"):
        objs[f"deployment/{ns}/{d}"] = {"kind": "Deployment", "metadata": {"name": d, "namespace": ns}}
    save(st)
    return 0


def curl(a):
    url = next((x for x in a if x.startswith("http")), "")
    method = opt(a, "-X") or "GET"
    body = sys.stdin.read() if "--data-binary" in a or any(x.endswith("@-") for x in a) else None
    log("curl", a, method in ("PUT", "POST", "DELETE"), body if method == "PUT" else None)
    st = load()
    kc = st.get("keycloak")
    def answer(code, text=""):
        if "-w" in a:
            sys.stdout.write(str(code))
        elif text and "-o" not in a:
            sys.stdout.write(text)
        return 22 if ("-sf" in a or "-f" in a) and code >= 400 else 0
    if "/hub/login" in url:
        return answer(200)
    if kc is None or ":18095/" not in url:
        return 7
    if url.endswith("/protocol/openid-connect/token"):
        return answer(200, json.dumps({"access_token": "tok"}))
    if "/admin/realms/master/users" in url:
        return answer(200, "[]")
    if "/clients?clientId=" in url:
        cid = url.split("clientId=")[1]
        c = kc.get(cid)
        return answer(200, json.dumps([{"id": "u-" + cid, "clientId": cid}] if c else []))
    if "/clients/u-" in url:
        cid = url.split("/clients/u-")[1]
        if method == "PUT":
            kc[cid] = json.loads(body)
            save(st)
            return answer(204)
        return answer(200, json.dumps(kc[cid]))
    return answer(404)


def sudo(a):
    log("sudo", a, True)
    if a[:1] == ["-p"]:
        a = a[2:]
    return subprocess.run(a).returncode


if me == "microk8s":
    if argv[:1] == ["status"]:
        sys.exit(0)
    if argv[:1] == ["kubectl"]:
        sys.exit(kubectl(argv[1:]))
    if argv[:1] == ["helm3"]:
        sys.exit(helm(argv[1:]))
    sys.exit(0)
if me == "curl":
    sys.exit(curl(argv))
if me == "sudo":
    sys.exit(sudo(argv))
log(me, argv, False)
sys.exit(0)
'''


def pv(name, ns, claim, path, size="10Gi", policy="Delete", phase="Bound", labels=None):
    return {"apiVersion": "v1", "kind": "PersistentVolume",
            "metadata": {"name": name, "namespace": "", "labels": labels or {}},
            "spec": {"capacity": {"storage": size}, "accessModes": ["ReadWriteOnce"],
                     "persistentVolumeReclaimPolicy": policy, "storageClassName": "microk8s-hostpath",
                     "hostPath": {"path": path, "type": "DirectoryOrCreate"},
                     "claimRef": {"namespace": ns, "name": claim, "uid": "uid-" + name, "resourceVersion": "7"},
                     "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                         {"key": "kubernetes.io/hostname", "operator": "In", "values": ["host1"]}]}]}}},
            "status": {"phase": phase}}


def pvc(name, ns, volume, size="10Gi", labels=None):
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": name, "namespace": ns, "labels": labels or {}},
            "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "microk8s-hostpath",
                     "volumeName": volume, "resources": {"requests": {"storage": size}}},
            "status": {"phase": "Bound"}}


class Tree:
    """a scratch tree with deploy-workbench, its templates and a fake cluster"""

    def __init__(self, research=False, enabled="true", extra=""):
        self.root = scratch_repo(prefix="medcea-wbmove-")
        for rel in ("infra/deploy-workbench.sh",):
            shutil.copy(os.path.join(REPO, rel), self.path(rel))
        shutil.copytree(os.path.join(REPO, "k8s", "workbench"), self.path("k8s", "workbench"))
        os.makedirs(self.path("apps", "backup"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "backup", "lib-backup.sh"), self.path("apps", "backup", "lib-backup.sh"))
        if research:
            with open(self.path("apps", "iam", "policy", "defaults.yaml"), "w") as f:
                yaml.safe_dump(rs2b_fixture.b_policy(), f, sort_keys=False)
        with open(self.path("config.env"), "w") as f:
            f.write(CONFIG + f'RESEARCH_ENABLED="{enabled}"\n' + extra)
        self.fake = self.path(".fake")
        self.bin = os.path.join(self.fake, "bin")
        os.makedirs(self.bin)
        with open(os.path.join(self.fake, "fake.py"), "w") as f:
            f.write(FAKE)
        os.chmod(os.path.join(self.fake, "fake.py"), 0o755)
        for n in ("microk8s", "curl", "sudo", "fuser", "sleep"):
            os.symlink(os.path.join(self.fake, "fake.py"), os.path.join(self.bin, n))
        self.state, self.log = os.path.join(self.fake, "state.json"), os.path.join(self.fake, "log.jsonl")
        self.pvdir = self.path(".storage")
        os.makedirs(self.pvdir)
        # the platform CA (deploy-infra makes it): workbench-tls is issued from it
        ca = self.path(".ca")
        os.makedirs(ca)
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", os.path.join(ca, "ca.key")],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-x509", "-new", "-key", os.path.join(ca, "ca.key"), "-sha256", "-days", "30",
                        "-subj", "/CN=test CA", "-out", os.path.join(ca, "ca.crt")], check=True, capture_output=True)
        self.st = {"objs": {}, "releases": {}, "pvdir": self.pvdir}

    def path(self, *p):
        return os.path.join(self.root, *p)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # ── the cluster ─────────────────────────────────────────────────────────────
    def put(self, o):
        kind = {"PersistentVolume": "pv", "PersistentVolumeClaim": "pvc"}.get(o["kind"], o["kind"].lower())
        cluster = kind in ("pv", "namespace")
        self.st["objs"][f"{kind}/{'' if cluster else o['metadata'].get('namespace', '')}/{o['metadata']['name']}"] = o

    def namespace(self, n):
        self.put({"kind": "Namespace", "metadata": {"name": n}})

    def zone_policies(self):
        """the compiled research zone's NetworkPolicies, as pa_rsnetpol applies them"""
        out = subprocess.run([sys.executable, self.path("apps", "iam", "compiler", "cli.py"), "compile", "netpol",
                              "--zone", "research", "--namespace", RNS, "--platform-namespace", NS,
                              "--node-ip", NODE_IPS.strip()], capture_output=True, text=True, check=True,
                             env=clean_env(), cwd=self.root).stdout
        for i in json.loads(out)["items"]:
            i["metadata"]["namespace"] = RNS
            self.st["objs"][f"networkpolicy/{RNS}/{i['metadata']['name']}"] = i

    def home(self, ns, claim, pvname, labels=None, files=("notebook.ipynb",), pv_labels=None, **kw):
        """a home: its directory, its PV (pv_labels) and its claim (labels)"""
        d = os.path.join(self.pvdir, f"{ns}-{claim}-pvc-{pvname[4:]}")
        os.makedirs(d)
        for f in files:
            with open(os.path.join(d, f), "w") as fh:
                fh.write(f"{claim}:{f}\n")
        self.put(pv(pvname, ns, claim, d, labels=pv_labels, **kw))
        self.put(pvc(claim, ns, pvname, labels=labels))
        return d

    def release(self, ns, servers=()):
        self.st["releases"][ns] = True
        for d in ("hub", "proxy"):
            self.put({"kind": "Deployment", "metadata": {"name": d, "namespace": ns}})
            self.put({"kind": "Pod", "metadata": {"name": d + "-abc", "namespace": ns,
                                                  "labels": {"app": "jupyterhub", "component": d}},
                      "spec": {"volumes": [{"name": "pvc", "persistentVolumeClaim": {"claimName": "hub-db-dir"}}]
                               if d == "hub" else []}})
        for s in servers:
            self.put({"kind": "Pod", "metadata": {"name": "jupyter-" + s, "namespace": ns,
                                                  "labels": {"app": "jupyterhub", "component": "singleuser-server"}},
                      "spec": {"volumes": [{"name": "home", "persistentVolumeClaim": {"claimName": "claim-" + s}}]}})

    def keycloak(self, enabled=True):
        self.st["keycloak"] = {"workbench-notebook": {"id": "u-workbench-notebook", "clientId": "workbench-notebook",
                                                      "enabled": enabled, "publicClient": True,
                                                      "serviceAccountsEnabled": False,
                                                      "attributes": {"oauth2.device.authorization.grant.enabled": "true"}}}

    def seed(self):
        with open(self.state, "w") as f:
            json.dump(self.st, f)

    def load(self):
        with open(self.state) as f:
            return json.load(f)

    def calls(self):
        try:
            with open(self.log) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def run(self, *args, confirmed=True, **extra):
        self.seed()
        if os.path.exists(self.log):
            os.remove(self.log)
        script = ('exec 9>>"$PWD/.medcea.lock"; flock -n 9 || exit 99\n'
                  'export MEDCEA_LOCK_HELD=$$ MEDCEA_POLICY_SOURCE_DONE=$$\n'
                  './infra/deploy-workbench.sh ' + " ".join(args) + ' </dev/null\nexit $?\n')
        env = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_STATE=self.state, FAKE_LOG=self.log,
                        FAKE_NODE_IPS=NODE_IPS, MEDCEA_NO_LOG="1", HOME=self.root, **extra)
        env.pop("MEDCEA_LOG_FILE", None)
        if confirmed:
            env["MEDCEA_CONFIRMED"] = "1"
        else:
            env.pop("MEDCEA_CONFIRMED", None)
        for k in list(env):
            if k.startswith(("RESEARCH_", "NAMESPACE", "KUBECONFIG", "WORKBENCH_")):
                env.pop(k)
        r = subprocess.run(["bash", "-c", script], cwd=self.root, env=env, capture_output=True, text=True, timeout=600)
        with open(self.state) as f:
            self.st = json.load(f)
        self.assertNoSecret(r)
        return r

    @staticmethod
    def assertNoSecret(r):
        assert "do-not-print" not in r.stdout + r.stderr, "a secret was printed"


def writes(calls):
    return [c for c in calls if c["write"]]


def idx(calls, pred):
    for i, c in enumerate(calls):
        if pred(c):
            return i
    return -1


def is_helm_install(c, ns=None):
    return c["cmd"] == "helm" and c["argv"][:2] == ["upgrade", "--install"] and (ns is None or ns in c["argv"])


class Base(unittest.TestCase):
    def tree(self, **kw):
        t = Tree(**kw)
        self.addCleanup(t.close)
        return t


class Table(Base):
    def test_platform_release_in_research_moves_back(self):
        t = self.tree(research=False)
        t.namespace(NS); t.namespace(RNS)
        t.release(RNS)
        r = t.run()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("the AI workbench moves back with ./infra/deploy-workbench.sh --move", r.stdout)
        self.assertEqual(writes(t.calls()), [])
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("WORKBENCH_DOMAIN (workbench): deferred (the AI workbench moves back with", r.stdout)
        self.assertEqual(writes(t.calls()), [])

    def test_research_release_in_platform_moves(self):
        t = self.tree(research=True)
        t.namespace(NS); t.namespace(RNS)
        t.release(NS)
        for args in ((), ("--policy-only",)):
            r = t.run(*args)
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertIn("the AI workbench moves with ./infra/deploy-workbench.sh --move", r.stdout)
            self.assertEqual(writes(t.calls()), [])
            # before _policy: the gate was never compiled
            self.assertNotIn("Gate:", r.stdout)

    def test_research_switched_off_is_a_skip(self):
        t = self.tree(research=True, enabled="false")
        t.release(NS)
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("skipped: the AI workbench lives in the research zone (the access policy) and RESEARCH_ENABLED is not true",
                      r.stdout)
        self.assertIn("left as it is", r.stderr)
        self.assertEqual(writes(t.calls()), [])
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0)
        self.assertIn("WORKBENCH_DOMAIN (workbench): not deployed (RESEARCH_ENABLED is not true; a running hub is left as it is)",
                      r.stdout)

    def test_two_releases_refuse(self):
        t = self.tree(research=False)
        t.release(NS); t.release(RNS)
        for args in ((), ("--policy-only",)):
            r = t.run(*args)
            self.assertEqual(r.returncode, 1)
            self.assertIn(f"exists in two namespaces ({NS} {RNS})", r.stderr)
            self.assertEqual(writes(t.calls()), [])

    def test_zone_not_ready_refuses(self):
        t = self.tree(research=True)
        t.namespace(NS); t.namespace(RNS)   # no zone policies applied
        r = t.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not the compiled ones", r.stderr)
        self.assertEqual(writes(t.calls()), [])

    def test_fresh_research_install(self):
        t = self.tree(research=True)
        t.namespace(NS); t.namespace(RNS); t.zone_policies()
        # a home an earlier move made, Released after the research namespace was reset
        kept = t.home(RNS, "claim-bob", "pvc-11111111-2222-4333-8444-555555555555", policy="Retain",
                      phase="Released", pv_labels={"medcea/workbench-home": "claim-bob"})
        del t.st["objs"][f"pvc/{RNS}/claim-bob"]
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        calls = t.calls()
        inst = idx(calls, lambda c: is_helm_install(c, RNS))
        self.assertGreater(inst, 0)
        self.assertIn("--namespace", calls[inst]["argv"])
        self.assertEqual(calls[inst]["argv"][calls[inst]["argv"].index("--namespace") + 1], RNS)
        self.assertEqual(calls[inst]["argv"].count("--values"), 2)
        tls = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:3] == ["create", "secret", "tls"])
        rbac = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:1] == ["apply"] and "kind: Role" in (c["stdin"] or ""))
        self.assertTrue(0 < tls < inst and 0 < rbac < inst, (tls, rbac, inst))
        self.assertIn("workbench-tls", calls[tls]["argv"])
        self.assertEqual(calls[tls]["argv"][calls[tls]["argv"].index("-n") + 1], RNS)
        # the certificate: this host only, from the platform CA, the key private
        crt = subprocess.run(["openssl", "x509", "-in", t.path(".ca", "workbench.crt"), "-noout", "-ext", "subjectAltName"],
                             capture_output=True, text=True, check=True).stdout
        self.assertIn("DNS:ai-workbench.medcea", crt)
        self.assertNotIn("IP Address", crt)
        self.assertEqual(os.stat(t.path(".ca", "workbench.key")).st_mode & 0o777, 0o600)
        # the kept home is free for its claim again
        p = t.st["objs"][f"pv//pvc-11111111-2222-4333-8444-555555555555"]
        self.assertNotIn("uid", p["spec"]["claimRef"])
        self.assertEqual(p["spec"]["claimRef"]["name"], "claim-bob")
        self.assertTrue(os.path.isdir(kept))
        # the stored values: the overlay and its hook, the endpoints gone
        import base64
        v = yaml.safe_load(base64.b64decode(t.st["objs"][f"secret/{RNS}/hub"]["data"]["values.yaml"]))
        self.assertIn("medcea-a2", v["hub"]["extraConfig"])
        self.assertNotIn("MEDCEA_API", v["singleuser"]["extraEnv"])
        self.assertEqual(v["singleuser"]["networkPolicy"]["egress"], [])
        # the examples in the zone
        self.assertTrue(any(c["cmd"] == "kubectl" and c["argv"][:3] == ["create", "configmap", "workbench-examples"]
                            and RNS in c["argv"] for c in calls))
        # nothing for the platform namespace
        self.assertFalse(any(is_helm_install(c, NS) and RNS not in c["argv"] for c in calls))
        # --policy-only now: unchanged, nothing written
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("WORKBENCH_DOMAIN (workbench): unchanged", r.stdout)
        self.assertEqual(writes(t.calls()), [])
        # a drifted A2 hook re-renders: helm only (no certificate, no Role)
        v["hub"]["extraConfig"]["medcea-a2"] = "pass\n"
        t.st["objs"][f"secret/{RNS}/hub"]["data"]["values.yaml"] = base64.b64encode(yaml.safe_dump(v).encode()).decode()
        r = t.run("--policy-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("re-rendered", r.stdout)
        self.assertEqual([c["cmd"] for c in writes(t.calls())], ["helm"])

    def test_platform_unchanged(self):
        """v7: placement platform, release in the platform namespace: today's path (one values
        file, the platform namespace, no certificate, no Role)."""
        t = self.tree(research=False)
        t.namespace(NS)
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        calls = t.calls()
        inst = [c for c in calls if is_helm_install(c)]
        self.assertEqual(len(inst), 1)
        a = inst[0]["argv"]
        self.assertEqual(a, ["upgrade", "--install", "workbench", "jupyterhub/jupyterhub", "--version", "4.4.4",
                             "--namespace", NS, "--values", a[a.index("--values") + 1], "--timeout", "10m"])
        self.assertFalse(any(c["argv"][:2] == ["create", "secret"] for c in calls if c["cmd"] == "kubectl"))
        self.assertFalse(any("kind: Role" in (c["stdin"] or "") for c in calls))


class Move(Base):
    def research_tree(self, **kw):
        t = self.tree(research=True, **kw)
        t.namespace(NS); t.namespace(RNS); t.zone_policies()
        t.release(NS)
        self.alice = t.home(NS, "claim-alice", "pvc-aaaaaaaa-0000-4000-8000-000000000001", files=("a.ipynb", ".bashrc"))
        self.admin = t.home(NS, "claim-admin", "pvc-aaaaaaaa-0000-4000-8000-000000000002")
        self.hubdb = t.home(NS, "hub-db-dir", "pvc-aaaaaaaa-0000-4000-8000-000000000003", size="1Gi", files=("jupyterhub.sqlite",))
        t.keycloak()
        return t

    def assert_nothing_moved(self, t, r):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([c for c in writes(t.calls()) if c["cmd"] != "kubectl" or c["argv"][:1] != ["scale"]], [])
        self.assertIn(NS, t.st["releases"])

    def test_refusals(self):
        t = self.research_tree(extra='WORKBENCH_ENABLED="false"\n')
        r = t.run("--move")
        self.assertIn("WORKBENCH_ENABLED is not true", r.stderr)
        self.assert_nothing_moved(t, r)
        t = self.research_tree(enabled="false")
        r = t.run("--move")
        self.assertIn("RESEARCH_ENABLED is not true", r.stderr)
        self.assert_nothing_moved(t, r)
        t = self.research_tree()
        t.release(NS, servers=["alice"])
        r = t.run("--move")
        self.assertIn("servers still run in medcea", r.stderr)
        self.assert_nothing_moved(t, r)
        t = self.research_tree()
        r = t.run("--move", confirmed=False)
        self.assertIn("no terminal to confirm the move on", r.stderr)
        self.assert_nothing_moved(t, r)
        t = self.research_tree()
        t.st["objs"] = {k: v for k, v in t.st["objs"].items() if not k.startswith("networkpolicy/")}
        r = t.run("--move")
        self.assertIn("not the compiled ones", r.stderr)
        self.assert_nothing_moved(t, r)

    def test_move_into_the_zone(self):
        t = self.research_tree()
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-4000:])
        calls = t.calls()
        st = t.st
        # 3. the hub and the proxy stopped first, then the mount re-check
        scale = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:1] == ["scale"])
        self.assertEqual(calls[scale]["argv"][:4], ["scale", "deployment", "hub", "proxy"])
        self.assertIn("--replicas=0", calls[scale]["argv"])
        recheck = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:2] == ["get", "pods"]
                      and "-l" not in c["argv"] and NS in c["argv"])
        self.assertGreater(recheck, scale)
        # 4. Retain before the uninstall, for every home and the hub's database
        uninstall = idx(calls, lambda c: c["cmd"] == "helm" and c["argv"][:1] == ["uninstall"])
        patches = [i for i, c in enumerate(calls) if c["cmd"] == "kubectl" and c["argv"][:2] == ["patch", "pv"]
                   and "Retain" in " ".join(c["argv"])]
        self.assertEqual(len(patches), 3)
        self.assertTrue(all(recheck < i < uninstall for i in patches), (patches, uninstall))
        for n in ("1", "2", "3"):
            self.assertEqual(st["objs"][f"pv//pvc-aaaaaaaa-0000-4000-8000-00000000000{n}"]["spec"]
                             ["persistentVolumeReclaimPolicy"], "Retain")
        self.assertIn(self.alice, r.stdout)   # the listing names the directories
        # 5. Keycloak: read-modify-write, enabled false, the rest as read; on port 18095; before the uninstall
        puts = [i for i, c in enumerate(calls) if c["cmd"] == "curl" and "-X" in c["argv"]
                and c["argv"][c["argv"].index("-X") + 1] == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertLess(puts[0], uninstall)
        self.assertIn("http://localhost:18095/admin/realms/medcea/clients/u-workbench-notebook", calls[puts[0]]["argv"])
        body = json.loads(calls[puts[0]]["stdin"])
        self.assertEqual(body, dict(st["keycloak"]["workbench-notebook"]))
        self.assertIs(body["enabled"], False)
        self.assertIs(body["serviceAccountsEnabled"], False)
        self.assertEqual(body["attributes"], {"oauth2.device.authorization.grant.enabled": "true"})
        self.assertTrue(any(c["cmd"] == "kubectl" and c["argv"][:1] == ["port-forward"] and "18095:80" in c["argv"]
                            for c in calls))
        self.assertIn("client workbench-notebook disabled", r.stdout)
        # 6. the release left the platform; hub-db-dir's volume stays
        self.assertNotIn(NS, st["releases"])
        self.assertTrue(os.path.isdir(self.hubdb))
        # 7. alice copied with sudo into <pvDir>/<dst>-<claim>-pvc-<uuid4>; the admin's not
        cps = [c for c in calls if c["cmd"] == "sudo" and "cp" in c["argv"]]
        self.assertEqual(len(cps), 1)
        a = cps[0]["argv"]
        self.assertEqual(a[0], "-p")
        self.assertIn("(to copy the home claim-alice into medcea-research)", a[1])
        self.assertEqual(a[2:6], ["cp", "-a", "--no-target-directory", self.alice])
        dst = a[6]
        self.assertRegex(dst, "^" + re.escape(t.pvdir + f"/{RNS}-claim-alice-pvc-") + UUID_RE + "$")
        with open(os.path.join(dst, "a.ipynb")) as f:
            self.assertEqual(f.read(), "claim-alice:a.ipynb\n")
        self.assertTrue(os.path.isfile(os.path.join(self.alice, "a.ipynb")))   # the source stays
        self.assertIn("claim-admin: not copied", r.stdout)
        self.assertFalse(any(f"{RNS}-claim-admin" in x for x in os.listdir(t.pvdir)))
        # its volume and claim, server-side, with the field manager
        uid = dst.rsplit("-pvc-", 1)[1]
        new_pv = st["objs"][f"pv//pvc-{uid}"]
        self.assertEqual(new_pv["spec"]["hostPath"], {"path": dst, "type": "DirectoryOrCreate"})
        self.assertEqual(new_pv["spec"]["persistentVolumeReclaimPolicy"], "Retain")
        self.assertEqual(new_pv["spec"]["capacity"], {"storage": "10Gi"})
        self.assertEqual(new_pv["spec"]["storageClassName"], "microk8s-hostpath")
        self.assertEqual(new_pv["spec"]["claimRef"]["namespace"], RNS)
        self.assertEqual(new_pv["spec"]["claimRef"]["name"], "claim-alice")
        self.assertEqual(new_pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"],
                         ["host1"])
        self.assertEqual(new_pv["metadata"]["labels"], {"medcea/workbench-home": "claim-alice", "medcea/moved-from": NS})
        new_pvc = st["objs"][f"pvc/{RNS}/claim-alice"]
        self.assertEqual(new_pvc["spec"]["volumeName"], f"pvc-{uid}")
        self.assertEqual(new_pvc["metadata"]["labels"], {"medcea/moved-from": NS})
        self.assertEqual(new_pvc["spec"]["resources"]["requests"]["storage"], "10Gi")
        ssa = [c for c in calls if c["cmd"] == "kubectl" and c["argv"][:2] == ["apply", "--server-side"]]
        self.assertTrue(ssa and all("--field-manager=medcea-workbench-move" in c["argv"] for c in ssa))
        # the source claim stays Bound, labelled
        self.assertEqual(st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"], {"medcea/moved-to": RNS})
        self.assertNotIn("medcea/moved-to", st["objs"][f"pvc/{NS}/claim-admin"]["metadata"]["labels"])
        # 9-10. certificate and Role before the install into the zone, with both values files
        inst = idx(calls, lambda c: is_helm_install(c, RNS))
        tls = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:3] == ["create", "secret", "tls"])
        rbac = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:1] == ["apply"] and "kind: Role" in (c["stdin"] or ""))
        copy = idx(calls, lambda c: c["cmd"] == "sudo" and "cp" in c["argv"])
        self.assertTrue(uninstall < copy < tls < inst and rbac < inst, (uninstall, copy, tls, rbac, inst))
        self.assertEqual(calls[inst]["argv"].count("--values"), 2)
        # 11. what is left, named
        tail = r.stdout[r.stdout.index("Left behind by the move"):]
        for s in ("claim claim-alice in medcea", "claim claim-admin in medcea", "not moved", "hub-db-dir",
                  self.hubdb, "sudo rm -rf " + self.alice):
            self.assertIn(s, tail)
        # nothing on disk deleted
        for d in (self.alice, self.admin, self.hubdb):
            self.assertTrue(os.path.isdir(d), d)
        self.assertFalse(any(c["cmd"] == "sudo" and "rm" in c["argv"] for c in calls))

        # a re-run copies nothing again and uninstalls nothing
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        calls = t.calls()
        self.assertFalse(any(c["cmd"] == "sudo" and "cp" in c["argv"] for c in calls))
        self.assertFalse(any(c["cmd"] == "helm" and c["argv"][:1] == ["uninstall"] for c in calls))
        self.assertIn(f"claim-alice: not copied (already in {RNS})", r.stdout)
        self.assertIn("client workbench-notebook was disabled already", r.stdout)

    def test_a_home_still_mounted_gives_the_hub_back(self):
        t = self.research_tree()
        # a server pod that the singleuser label check does not see (another label), but mounts a home
        t.put({"kind": "Pod", "metadata": {"name": "odd", "namespace": NS, "labels": {"app": "other"}},
               "spec": {"volumes": [{"name": "h", "persistentVolumeClaim": {"claimName": "claim-alice"}}]}})
        r = t.run("--move")
        self.assertEqual(r.returncode, 1)
        self.assertIn("still mounts a home: claim-alice (odd)", r.stderr)
        scales = [c["argv"] for c in t.calls() if c["cmd"] == "kubectl" and c["argv"][:1] == ["scale"]]
        self.assertEqual([x[-1] if x[-1].startswith("--replicas") else [y for y in x if y.startswith("--replicas")][0]
                          for x in scales], ["--replicas=0", "--replicas=1"])
        self.assertIn(NS, t.st["releases"])
        self.assertFalse(any(c["cmd"] in ("sudo", "curl") and c["write"] for c in t.calls()))
        self.assertFalse(any(c["cmd"] == "kubectl" and c["argv"][:1] == ["patch"] for c in t.calls()))

    def test_move_back(self):
        """v7 again (a revert version): placement platform, release in the zone. The zone's
        copy of alice (moved-from medcea) goes back; the platform's stale claim (moved-to the
        zone) is replaced; Keycloak is not touched (the policy names the client again)."""
        t = self.tree(research=False)
        t.namespace(NS); t.namespace(RNS)
        t.release(RNS)
        zone_alice = t.home(RNS, "claim-alice", "pvc-bbbbbbbb-0000-4000-8000-000000000001",
                            files=("a.ipynb", "new-after-move.py"), labels={"medcea/moved-from": NS}, policy="Retain")
        old = t.home(NS, "claim-alice", "pvc-cccccccc-0000-4000-8000-000000000001", labels={"medcea/moved-to": RNS},
                     policy="Retain")
        t.keycloak(enabled=False)
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-4000:])
        calls = t.calls()
        dele = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:2] == ["delete", "pvc"])
        self.assertEqual(calls[dele]["argv"][2], "claim-alice")
        self.assertIn(NS, calls[dele]["argv"])
        cp = idx(calls, lambda c: c["cmd"] == "sudo" and "cp" in c["argv"])
        self.assertLess(dele, cp)
        self.assertEqual(calls[cp]["argv"][5], zone_alice)
        self.assertRegex(calls[cp]["argv"][6], re.escape(t.pvdir + f"/{NS}-claim-alice-pvc-") + UUID_RE)
        self.assertTrue(os.path.isfile(os.path.join(calls[cp]["argv"][6], "new-after-move.py")))
        self.assertTrue(os.path.isdir(old))   # the stale copy's directory stays (Retain)
        new = t.st["objs"][f"pvc/{NS}/claim-alice"]
        self.assertEqual(new["metadata"]["labels"], {"medcea/moved-from": RNS})
        self.assertFalse(any(c["cmd"] == "curl" and ":18095/" in " ".join(c["argv"]) for c in calls))
        self.assertIn("left as it is (./deploy-infra.sh keeps it)", r.stdout)
        inst = [c for c in calls if is_helm_install(c)]
        self.assertEqual(len(inst), 1)
        self.assertEqual(inst[0]["argv"][inst[0]["argv"].index("--namespace") + 1], NS)
        self.assertEqual(inst[0]["argv"].count("--values"), 1)
        self.assertFalse(any(c["cmd"] == "kubectl" and c["argv"][:3] == ["create", "secret", "tls"] for c in calls))
        self.assertNotIn(RNS, t.st["releases"])

    def test_a_kept_home_is_bound_again_not_copied(self):
        """--move after a failed install: the zone's Released home (labelled, claimRef = the
        zone's claim) is bound again; nothing is copied for it."""
        t = self.research_tree()
        t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"] = {"medcea/moved-to": RNS}   # the earlier move
        t.home(RNS, "claim-alice", "pvc-dddddddd-0000-4000-8000-000000000001", policy="Retain", phase="Released",
               pv_labels={"medcea/workbench-home": "claim-alice", "medcea/moved-from": NS})
        del t.st["objs"][f"pvc/{RNS}/claim-alice"]
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("claim-alice: bound again to its kept volume pvc-dddddddd-0000-4000-8000-000000000001", r.stdout)
        self.assertFalse(any(c["cmd"] == "sudo" and "cp" in c["argv"] for c in t.calls()))
        c = t.st["objs"][f"pvc/{RNS}/claim-alice"]
        self.assertEqual(c["spec"]["volumeName"], "pvc-dddddddd-0000-4000-8000-000000000001")
        self.assertNotIn("uid", t.st["objs"]["pv//pvc-dddddddd-0000-4000-8000-000000000001"]["spec"]["claimRef"])


class MoveReview(Move):
    """Review of commit A (19 Nov 2026): a home is never offered for removal unless a move copied
    it, never bound to a stale or missing copy, and nothing a failed run leaves is silent."""

    def test_a_fresh_install_next_to_unmoved_homes_refuses(self):
        """--move stopped after the uninstall: a plain run must not install an empty hub next to
        the homes it would shadow; exit 4 with the move line, nothing written."""
        t = self.research_tree()
        del t.st["releases"][NS]
        for d in ("hub", "proxy"):
            t.st["objs"].pop(f"deployment/{NS}/{d}")
            t.st["objs"].pop(f"pod/{NS}/{d}-abc")
        r = t.run()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("the AI workbench moves with ./infra/deploy-workbench.sh --move", r.stdout)
        self.assertIn(f"{NS} still holds homes not moved to {RNS}: claim-alice)", r.stdout)
        self.assertEqual(writes(t.calls()), [])
        # once moved (the source labelled, the copy there), the fresh install goes on
        t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"] = {"medcea/moved-to": RNS}
        t.put(pvc("claim-alice", RNS, "pvc-eeeeeeee-0000-4000-8000-000000000001", labels={"medcea/moved-from": NS}))
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertTrue(any(is_helm_install(c, RNS) for c in t.calls()))

    def test_a_home_the_zone_made_itself_is_a_conflict(self):
        """The zone holds an empty claim-alice no move made (a fresh install's sign-in): neither
        side is touched, and the report gives no removal command for the platform's home."""
        t = self.research_tree()
        t.home(RNS, "claim-alice", "pvc-ffffffff-0000-4000-8000-000000000001", files=())
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("claim-alice: not moved: medcea-research holds its own claim-alice", r.stderr)
        self.assertFalse(any(c["cmd"] == "sudo" and "cp" in c["argv"] for c in t.calls()))
        self.assertNotIn("medcea/moved-to", t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"])
        tail = r.stdout[r.stdout.index("Left behind by the move"):]
        self.assertNotIn("sudo rm -rf " + self.alice, tail)
        self.assertIn("claim claim-alice in medcea was NOT moved", tail)
        self.assertIn("not moved, an administrator decides (above): claim-alice", r.stderr)

    def test_several_kept_volumes_bind_none(self):
        t = self.research_tree()
        t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"] = {"medcea/moved-to": RNS}
        for n in ("1", "2"):
            t.home(RNS, "claim-alice", f"pvc-dddddddd-0000-4000-8000-00000000000{n}", policy="Retain", phase="Released",
                   pv_labels={"medcea/workbench-home": "claim-alice", "medcea/moved-from": NS})
        del t.st["objs"][f"pvc/{RNS}/claim-alice"]
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("several kept volumes could hold it in medcea-research (pvc-dddddddd-0000-4000-8000-000000000001 "
                      "pvc-dddddddd-0000-4000-8000-000000000002)", r.stderr)
        self.assertNotIn(f"pvc/{RNS}/claim-alice", t.st["objs"])
        self.assertFalse(any(c["cmd"] == "kubectl" and c["argv"][:2] == ["patch", "pv"] and "uid" in " ".join(c["argv"])
                             for c in t.calls()))
        self.assertNotIn("sudo rm -rf " + self.alice, r.stdout)

    def test_a_home_moved_back_since_is_copied_not_rebound(self):
        """The source claim was moved back from the zone (moved-from): it is newer than any
        volume the zone kept, so it is copied, never the kept one bound."""
        t = self.research_tree()
        t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"] = {"medcea/moved-from": RNS}
        t.home(RNS, "claim-alice", "pvc-dddddddd-0000-4000-8000-000000000001", policy="Retain", phase="Released",
               pv_labels={"medcea/workbench-home": "claim-alice", "medcea/moved-from": NS})
        del t.st["objs"][f"pvc/{RNS}/claim-alice"]
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertTrue(any(c["cmd"] == "sudo" and "cp" in c["argv"] and self.alice in c["argv"] for c in t.calls()))
        self.assertNotEqual(t.st["objs"][f"pvc/{RNS}/claim-alice"]["spec"]["volumeName"],
                            "pvc-dddddddd-0000-4000-8000-000000000001")

    def test_a_kept_volume_without_its_directory_is_not_bound(self):
        t = self.research_tree()
        t.st["objs"][f"pvc/{NS}/claim-alice"]["metadata"]["labels"] = {"medcea/moved-to": RNS}
        d = t.home(RNS, "claim-alice", "pvc-dddddddd-0000-4000-8000-000000000001", policy="Retain", phase="Released",
                   pv_labels={"medcea/workbench-home": "claim-alice", "medcea/moved-from": NS})
        shutil.rmtree(d)
        del t.st["objs"][f"pvc/{RNS}/claim-alice"]
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("which is not on this host: copied from medcea instead", r.stderr)
        self.assertTrue(any(c["cmd"] == "sudo" and "cp" in c["argv"] for c in t.calls()))

    def test_replace_retires_the_stale_copy(self):
        """The move back marks the zone's old copy superseded before the claim goes, so a later
        rebind can never pick it."""
        t = self.tree(research=False)
        t.namespace(NS); t.namespace(RNS)
        t.release(RNS)
        t.home(RNS, "claim-alice", "pvc-bbbbbbbb-0000-4000-8000-000000000001", labels={"medcea/moved-from": NS},
               policy="Retain")
        t.home(NS, "claim-alice", "pvc-cccccccc-0000-4000-8000-000000000001", labels={"medcea/moved-to": RNS},
               policy="Retain", pv_labels={"medcea/workbench-home": "claim-alice", "medcea/moved-from": RNS})
        t.keycloak(enabled=False)
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        old = t.st["objs"]["pv//pvc-cccccccc-0000-4000-8000-000000000001"]["metadata"]["labels"]
        self.assertEqual(old, {"medcea/moved-from": RNS, "medcea/superseded": "true"})
        calls = t.calls()
        lab = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:2] == ["label", "pv"])
        dele = idx(calls, lambda c: c["cmd"] == "kubectl" and c["argv"][:2] == ["delete", "pvc"])
        self.assertTrue(0 <= lab < dele, (lab, dele))

    def test_a_copy_without_a_volume_is_listed(self):
        """A failed earlier run left a copy no volume names: the report lists it for removal."""
        t = self.research_tree()
        stray = os.path.join(t.pvdir, f"{RNS}-claim-alice-pvc-99999999-0000-4000-8000-000000000001")
        os.makedirs(stray)
        r = t.run("--move")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        tail = r.stdout[r.stdout.index("Left behind by the move"):]
        self.assertIn(f"{stray}: a copy an earlier run made, used by no volume", tail)
        self.assertIn("sudo rm -rf " + stray, tail)
        self.assertTrue(os.path.isdir(stray))

    def test_a_failed_move_leaves_no_temporary_folder(self):
        t = self.research_tree()
        t.put({"kind": "Pod", "metadata": {"name": "odd", "namespace": NS, "labels": {"app": "other"}},
               "spec": {"volumes": [{"name": "h", "persistentVolumeClaim": {"claimName": "claim-alice"}}]}})
        tmp = t.path("tmpdir")
        os.makedirs(tmp)
        r = t.run("--move", TMPDIR=tmp)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(os.listdir(tmp), [])
        self.assertIn("Keycloak client workbench-notebook disabled", r.stderr)   # what stays, said

    def test_a_fresh_install_binds_only_a_single_existing_kept_home(self):
        t = self.tree(research=True)
        t.namespace(NS); t.namespace(RNS); t.zone_policies()
        for n in ("1", "2"):
            t.home(RNS, "claim-bob", f"pvc-11111111-2222-4333-8444-55555555555{n}", policy="Retain", phase="Released",
                   pv_labels={"medcea/workbench-home": "claim-bob"})
        gone = t.home(RNS, "claim-eve", "pvc-11111111-2222-4333-8444-555555555559", policy="Retain", phase="Released",
                      pv_labels={"medcea/workbench-home": "claim-eve"})
        shutil.rmtree(gone)
        for c in ("claim-bob", "claim-eve"):
            del t.st["objs"][f"pvc/{RNS}/{c}"]
        r = t.run()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("claim-bob in medcea-research: several kept volumes could hold it", r.stderr)
        self.assertIn("which is not on this host: not bound again", r.stderr)
        for k, o in t.st["objs"].items():
            if k.startswith("pv//"):
                self.assertIn("uid", o["spec"]["claimRef"], k)


class Static(unittest.TestCase):
    def test_library_conventions(self):
        with open(os.path.join(REPO, "infra", "lib-workbench.sh")) as f:
            lib = f.read()
        code = "\n".join(l for l in lib.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r"\brm -rf\b")      # nothing on disk is deleted
        self.assertNotIn("medcea_lock", code)          # a library: the caller holds the lock
        with open(os.path.join(REPO, "infra", "deploy-workbench.sh")) as f:
            src = f.read()
        # unknown options exit 2 before the log and the lock; the placement before the gate
        self.assertLess(src.index("--move) _MODE=move"), src.index("medcea_log deploy-workbench"))
        self.assertLess(src.index("policy_source_init"), src.index('WB_PLACEMENT="$(workbench_placement)"'))
        self.assertLess(src.index('WB_PLACEMENT="$(workbench_placement)"'), src.index("\n_policy\n"))
        self.assertIn("9>&- &", src)                   # the port-forward never holds the lock
        self.assertNotRegex(src, r"(?m)^\s*sudo\b[^\n]*\brm\b")


if __name__ == "__main__":
    unittest.main()
