#!/usr/bin/env python3
"""tests/test_apply.py — apps/iam/apply.sh and apps/iam/apply_check.py (IAM Phase 4, slice
4.2a; design §14.4.9, §14.4.10, §14.4.11, §14.4.17; --propose-skeleton and --withdraw-open of
slice 4.4, §14.7.6).

Offline. apply.sh runs in a scratch tree (tests/_scratch.py: state/ and .medcea.lock resolve
inside the copy) against a fake cluster: `microk8s` (kubectl, and psql through `kubectl exec`)
and `curl` (Keycloak's admin API) on PATH answer from a scenario file, and log every call to a
transcript; `helm3` and every writing kubectl verb fail if called. health-check.sh is a stub that
logs the conf it was given. Nothing here touches a cluster, Keycloak or the repository's state/.

The transcript proves the bootstrap's order (state, chain, Keycloak, compile, the live digests,
the bundle, the host file, the grants check, the record, the report), that it never rolls,
applies or deletes anything, and that --check-only and --status write nothing.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from _scratch import clean_env, scratch_repo  # noqa: E402

import apply_check  # noqa: E402
from compiler import model, source  # noqa: E402

ADMIN = "11111111-1111-4111-8111-111111111111"
QA = "22222222-2222-4222-8222-222222222222"
ENG = "33333333-3333-4333-8333-333333333333"

FAKE = r'''#!/usr/bin/env python3
# A fake microk8s / curl / health-check.sh for tests/test_apply.py (by the name it runs as).
import json, os, re, sys
FD = os.environ["FAKE_DIR"]
ROOT = os.environ["FAKE_ROOT"]
me = os.path.basename(sys.argv[0])
sc = json.load(open(os.path.join(FD, "scenario.json")))


def log(kind, **kw):
    with open(os.path.join(FD, "calls.log"), "a") as f:
        f.write(json.dumps(dict(kind=kind, **kw)) + "\n")


def state():
    return json.load(open(os.path.join(FD, "state.json")))


def put_state(d):
    json.dump(d, open(os.path.join(FD, "state.json"), "w"))


def committed():
    sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
    import apply_check
    from compiler import source
    d = apply_check.simulate_state()
    for k, v in (sc.get("post_state") or {}).items():
        d[k] = v
    if sc.get("post_review_by"):
        d["waivers"][0]["review_by"] = sc["post_review_by"]
        rows = source.state_rows(d)
        d["entries_digest"] = source.entries_digest("bootstrap", d["groups"], d["roles"], rows["entries"], rows["waivers"])
    d["last_apply_event"] = {"event": "apply_started", "event_id": 40, "at": "2026-11-02T10:00:00+00:00"}
    return d


def count(kind, pred):
    try:
        with open(os.path.join(FD, "calls.log")) as f:
            return sum(1 for l in f if (lambda c: c["kind"] == kind and pred(c))(json.loads(l)))
    except FileNotFoundError:
        return 0


def main_pid():
    """apply.sh's own shell: the highest ancestor whose command line names it."""
    pid, found = os.getpid(), None
    while pid > 1:
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read()
            pid2 = int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
        except OSError:
            break
        if b"apps/iam/apply.sh" in cmd:
            found = pid
        pid = pid2
    return found


def b64var(sql, name):
    import base64
    m = re.search(r"\\set %s '([^']*)'" % re.escape(name), sql)
    return base64.b64decode(m.group(1)).decode("utf-8") if m else None


def bundle(sql, name, new_state, fail_key):
    """IAM 4.5: a forward or revert bundle: its SQL kept, the state moved on a commit."""
    mark = "the revert's POST" if name == "revert" else "(apply_check.py bundle-sql; design §14.8.4 step 7)"
    n = count("psql", lambda c: mark in c["sql"])
    with open(os.path.join(FD, f"{name}-{n}.sql"), "w") as f:
        f.write(sql)
    fail = sc.get(fail_key)
    if fail is True or (isinstance(fail, int) and not isinstance(fail, bool) and n <= fail):
        print("ERROR:  version 2 is not approved any more: nothing was applied", file=sys.stderr)
        return 3
    sig = sc.get("bundle_sigint") if name == "forward" else None
    if sig == "rollback":
        import signal
        os.kill(main_pid(), signal.SIGINT)
        print("ERROR:  canceling statement due to user request", file=sys.stderr)
        return 3
    before = state()
    put_state(dict(new_state, last_apply_event=new_state.get("last_apply_event")
                   or {"event": "apply_started", "event_id": 50 + n, "at": "2026-11-04T10:01:00+00:00"}))
    d = b64var(sql, "apply_digests")
    live = os.path.join(FD, "live_routes")
    if d:
        if not os.path.exists(live + ".before"):
            open(live + ".before", "w").write(open(live).read() if os.path.exists(live) else sc.get("initial_routes", ""))
        open(live, "w").write(json.loads(d)["routes"])
    elif os.path.exists(live + ".before"):
        open(live, "w").write(open(live + ".before").read())
    if sig == "commit":
        import signal
        os.kill(main_pid(), signal.SIGINT)
    if sc.get("bundle_stream_lost"):
        print("error: lost connection to pod", file=sys.stderr)
        return 1
    return 0


def psql(db, args, sql):
    log("psql", db=db, sql=sql)
    if db == "postgres" and "pg_database" in sql:
        print("1" if sc.get("db", True) else "")
        return 0
    if "-- apply_check.py approval-doc" in sql:   # IAM 4.5: the version read (READ ONLY)
        n = re.search(r"iam_policy\.entries_digest\((\d+)\)", sql).group(1)
        reads = count("psql", lambda c: "-- apply_check.py approval-doc" in c["sql"])
        doc = (sc.get("docs_after") or {}).get(n) if reads >= 2 else None
        print(json.dumps(doc or (sc.get("docs") or {}).get(n) or {"version": None, "pending": None}))
        return 0
    if "verify_chain()" in sql and "h.hash" in sql and len(sql) < 2000:
        print(("t" if sc.get("chain_ok", True) else "f") + "|41|" + "ab" * 32)
        return 0
    if "max(x.version)" in sql and len(sql) < 2000:
        print(sc.get("next_version", 2))
        return 0
    if "BEGIN TRANSACTION READ ONLY" in sql:
        print(json.dumps(state()))
        return 0
    if "-- apps/iam/apply.sh: the revert's POST" in sql:
        return bundle(sql, "revert", sc.get("revert_state") or {}, "revert_fail")
    if "(apply_check.py bundle-sql; design §14.8.4 step 7)" in sql:
        return bundle(sql, "forward", sc.get("applied_state") or {}, "bundle_fail")
    if "_build_version('bootstrap'" in sql:
        with open(os.path.join(FD, "bundle.sql"), "w") as f:
            f.write(sql)
        if sc.get("bundle_fail"):
            print("ERROR:  version 1 does not store the entries of defaults.yaml", file=sys.stderr)
            return 3
        put_state(committed())
        if sc.get("bundle_stream_lost"):   # the COMMIT reached PostgreSQL, the exec stream did not survive
            print("error: lost connection to pod", file=sys.stderr)
            return 1
        return 0
    m = re.search(r"_record\('(bootstrap_applied|applied|partial_apply|apply_deferred)'", sql)
    if m:
        with open(os.path.join(FD, "record.sql"), "w") as f:
            f.write(sql)
        if sc.get("record_fail"):
            print("ERROR:  _record refused", file=sys.stderr)
            return 3
        payload = json.loads(b64var(sql, "payload"))
        try:
            n = sum(1 for _ in open(os.path.join(FD, "records.jsonl")))
        except FileNotFoundError:
            n = 0
        with open(os.path.join(FD, "records.jsonl"), "a") as f:
            f.write(json.dumps({"event": m.group(1), "payload": payload}) + "\n")
        d = state()
        if m.group(1) != "apply_deferred" and payload.get("version") == d.get("version"):
            d["last_apply_event"] = {"event": m.group(1), "event_id": 42 + n, "at": "2026-11-02T10:01:00+00:00",
                                     "outcome": payload.get("outcome")}
            put_state(d)
        print(42 + n)
        return 0
    if "_record('account_seeded'" in sql:
        if sc.get("seed_fail"):
            print("ERROR:  _record: fact_id is not the content hash", file=sys.stderr)
            return 3
        return 0
    if "_propose_skeleton(" in sql:   # IAM 4.4: apply.sh --propose-skeleton's one transaction
        with open(os.path.join(FD, "propose.sql"), "w") as f:
            f.write(sql)
        if sc.get("propose_fail"):
            print("ERROR:  another version was created meanwhile (the diff names version 2): run apply.sh again",
                  file=sys.stderr)
            return 3
        print(sc.get("next_version", 2))
        return 0
    if "_withdraw_open(" in sql:      # IAM 4.4: apply.sh --withdraw-open
        with open(os.path.join(FD, "withdraw.sql"), "w") as f:
            f.write(sql)
        if sc.get("withdraw_fail"):
            print("ERROR:  another version was opened meanwhile (withdrawn: 3, shown: 2): nothing was withdrawn",
                  file=sys.stderr)
            return 3
        print(re.search(r"\\set want_version '(\d+)'", sql).group(1))
        return 0
    if "max(x.version)" in sql:
        print(sc.get("next_version", 2))
        return 0
    if "obj_description" in sql:
        c = sc.get("comment")
        print("f|" if c is None else "t|" + c)
        return 0
    if "iam_db_roles" in sql and "platform_setting" in sql:
        print(sc.get("mode", "false"))
        return 0
    if "to_regnamespace('iam')" in sql:
        print("t|t|t|t")
        return 0
    if "mqtt_service_credential" in sql:
        print("f")
        return 0
    return 0


def kubectl(a):
    log("kubectl", argv=a)
    w = [x for i, x in enumerate(a) if x != "-n" and (i == 0 or a[i - 1] != "-n")]
    verb = w[0] if w else ""
    if verb == "exec":
        pod = a[a.index("--") - 1]
        if not pod or pod.startswith("-") or pod in ("medcea", "exec"):
            print("error: expected 'exec (POD | TYPE/NAME) [-c CONTAINER] [flags] -- COMMAND [args...]'", file=sys.stderr)
            return 1
        rest = a[a.index("--") + 1:]
        if pod in ("deployment/iam-api", "deployment/mosquitto"):   # IAM 4.5: not deployed here
            print(f'Error from server (NotFound): deployments.apps "{pod[11:]}" not found', file=sys.stderr)
            return 1
        if rest == ["cat", "/iam/routes.json"]:   # IAM 4.5: wait_routes, per Ready pod
            p = [x for dep in (sc.get("deployments") or {}).values() for x in dep["pods"] if x["name"] == pod]
            live = os.path.join(FD, "live_routes")
            digest = open(live).read() if os.path.exists(live) else sc.get("initial_routes", "")
            if p and p[0].get("stuck"):
                digest = sc.get("initial_routes", "")
            print(json.dumps({"digest": digest}))
            return 0
        i = rest.index("-c")
        db, pargs = rest[i + 2], rest[i + 3:]
        sql = ""
        if "-c" in pargs:
            sql = pargs[pargs.index("-c") + 1]
        else:
            sql = sys.stdin.read()
        return psql(db, pargs, sql)
    if verb == "port-forward":
        return 0
    if verb == "wait":
        return 1 if sc.get("pg_unready") else 0
    if verb == "get":
        what = w[1] if len(w) > 1 else ""
        if what == "statefulset":
            if sc.get("pg", True):
                print(f"statefulset.apps/{w[2]}")
                return 0
            print(f'Error from server (NotFound): statefulsets.apps "{w[2]}" not found', file=sys.stderr)
            return 1
        if what == "deployment" and len(w) > 2 and w[2] in (sc.get("unreadable_deployments") or []):
            print("The connection to the server 127.0.0.1:16443 was refused", file=sys.stderr)   # not NotFound
            return 1
        if what == "deployment" and len(w) > 2 and w[2] in (sc.get("deployments") or {}):
            print(json.dumps({"spec": {"selector": {"matchLabels": {"app": w[2]}}}}))
            return 0
        if what == "pods" and "-l" in a:
            app = a[a.index("-l") + 1].split("=", 1)[1]
            pods = ((sc.get("deployments") or {}).get(app) or {}).get("pods") or []
            print(json.dumps({"items": [{"metadata": {"name": p["name"]}, "status": {"conditions": [
                {"type": "Ready", "status": "True" if p.get("ready", True) else "False"}]}} for p in pods]}))
            return 0
        if what == "pod" and "-l" in a:
            print("rdbms-postgresql-0", end="")
            return 0
        if what == "pod":
            print("True", end="")
            return 0
        if what == "configmap" and len(w) > 2 and w[2] == "medcea-iam-lib":
            cm = sc.get("configmap")
            if cm is None:
                print('Error from server (NotFound): configmaps "medcea-iam-lib" not found', file=sys.stderr)
                return 1
            key = "mqtt" if "mqtt-digest" in " ".join(a) else "routes"
            print(cm.get(key, ""), end="")
            return 0
        print(f'Error from server (NotFound): {what} not found', file=sys.stderr)
        return 1
    print(f"fake kubectl: refusing to {verb}", file=sys.stderr)
    return 99


def curl(a):
    url = next((x for x in a if x.startswith("http")), "")
    out, fmt, fail = None, None, "-f" in a or "-sf" in a
    for i, x in enumerate(a):
        if x == "-o":
            out = a[i + 1]
        if x == "-w":
            fmt = a[i + 1]
    log("curl", url=url, method=a[a.index("-X") + 1] if "-X" in a else "GET")
    if sc.get("kc_down"):
        if fmt:
            print("000", end="")
        return 7
    path = url.split("/", 3)[3] if url.count("/") >= 3 else ""
    path, _, query = path.partition("?")
    users = sc.get("users", [])
    if sc.get("users_after") and count("psql", lambda c: "-- apply_check.py approval-doc" in c["sql"]) >= 2:
        users = sc["users_after"]     # Keycloak changed while the confirmation waited (step 6c)
    code, body = 404, {"error": "not found"}
    if path == "realms/medcea/protocol/openid-connect/certs":
        code, body = sc.get("certs_code", 200), sc.get("jwks") or {"keys": []}
    elif re.fullmatch(r"admin/realms/medcea/roles/[a-z_]+/composites", path):
        role = path.split("/")[4]
        comps = sc.get("composites") or {"qa": ["auditor"], "production_manager": ["operator"]}
        code, body = 200, [{"name": r, "clientRole": False} for r in comps.get(role, [])]
    elif path.endswith("protocol/openid-connect/token"):
        sys.stdin.read()
        code, body = 200, {"access_token": "fake-token"}
    elif path == "admin/realms/master/users":
        code, body = 200, []
    elif path == "admin/realms/medcea/users" and "username=" in query:
        from urllib.parse import parse_qs
        u = parse_qs(query)["username"][0]
        code, body = 200, [dict((k, v) for k, v in x.items() if k != "roles") for x in users if x["username"] == u]
    elif re.fullmatch(r"admin/realms/medcea/roles/[a-z_]+/users", path):
        role = path.split("/")[4]
        code, body = 200, [{"id": x["id"], "username": x["username"], "enabled": x["enabled"]}
                           for x in users if role in x.get("roles", [])]
    elif re.fullmatch(r"admin/realms/medcea/users/[0-9a-f-]{36}/role-mappings/realm/composite", path):
        hit = [x for x in users if x["id"] == path.split("/")[4]]
        if hit:
            code, body = 200, [{"name": r} for r in hit[0].get("roles", [])]
    elif re.fullmatch(r"admin/realms/medcea/users/[0-9a-f-]{36}", path):
        hit = [x for x in users if x["id"] == path.rsplit("/", 1)[1]]
        if hit:
            code, body = 200, dict((k, v) for k, v in hit[0].items() if k != "roles")
    text = json.dumps(body)
    if out:
        if out != "/dev/null":
            open(out, "w").write(text)
    elif not fmt:
        print(text)
    if fmt:
        print(code, end="")
    return 22 if fail and code >= 400 else 0


def health(a):
    path = a[a.index("-c") + 1]
    conf = open(path).read()
    lines = [l.strip() for l in conf.splitlines() if l.strip() and not l.startswith("#")]
    log("health", conf=lines)
    names = [l.split("|")[0].strip() for l in lines]
    if any(n.startswith("step9:") for n in names):   # IAM 4.5: step 6b's baseline and step 9
        if sc.get("tamper_staged"):   # the staged file edited after step 5 (the sha256 pin refuses it)
            staged = os.path.join(os.path.dirname(path), "stage", "staged", "policy-applied.yaml")
            with open(staged, "a") as f:
                f.write("# edited\n")
        worst = 0
        for n in names:
            t = n.split(":", 1)[1]
            seq = (sc.get("checks") or {}).get(t, "OK")
            if isinstance(seq, list):
                i = count("health", lambda c: any(l.startswith(n + " ") for l in c["conf"])) - 1
                seq = seq[min(i, len(seq) - 1)]
            print(f"  [ {seq:^4} ]  {n}")
            worst = worst or seq == "FAIL"
        return 1 if worst else 0
    if any("iamgrants" in l for l in lines):
        if sc.get("health_sigint"):   # Ctrl-C while the grants check runs (after the COMMIT)
            import signal
            os.kill(os.getppid(), signal.SIGINT)
        return sc.get("health_rc", 0)
    if any(l.split("|")[1].strip() == "iamartefacts" for l in lines) and len(lines) == 1:
        return sc.get("artefacts_rc", 0)
    return 0


if me == "microk8s":
    a = sys.argv[1:]
    if a[:1] == ["status"]:
        sys.exit(0)
    if a[:1] == ["kubectl"]:
        sys.exit(kubectl(a[1:]))
    log("microk8s", argv=a)
    print(f"fake microk8s: refusing {a[:1]}", file=sys.stderr)
    sys.exit(99)
if me == "curl":
    sys.exit(curl(sys.argv[1:]))
if me == "health-check.sh":
    sys.exit(health(sys.argv[1:]))
log(me, argv=sys.argv[1:])
print(f"fake {me}: refusing", file=sys.stderr)
sys.exit(99)
'''

SCOPED_STUB = r'''#!/bin/sh
# a shell script (deploy-apps.sh runs component deploys with bash); the stub itself is python
exec python3 - "$0" "$@" <<'PY'
import os, sys
rel = "@REL@"
sys.argv = sys.argv[1:]
log = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "@UP@.fake", "scoped.log")
try:
    prior = sum(1 for l in open(log) if l.startswith(rel + " "))
except FileNotFoundError:
    prior = 0
with open(log, "a") as f:
    f.write(" ".join([rel] + sys.argv[1:]) + "\n")
for item in os.environ.get("FAKE_SCOPED", "").split(";"):
    if item.startswith(rel + "="):
        rc, _, n = item.split("=", 1)[1].partition(":")
        if not n or prior < int(n):
            sys.exit(int(rc))
PY
'''

CONFIG = """NAMESPACE=medcea
POSTGRES_DB=medcea_db
PROJECT_NAME=medcea
KEYCLOAK_REALM=medcea
DOMAIN=example.test
IAM_DB_ROLES=false
IAM_MQTT_PERSON=false
KC_DEPLOYER_SECRET=fake-deployer-secret
ADMIN_USER=admin
"""


def users():
    return [
        {"id": ADMIN, "username": "admin", "enabled": True, "attributes": {"person_id": ["p-admin"]}, "roles": ["admin"]},
        {"id": QA, "username": "quinn", "enabled": True, "attributes": {"person_id": ["p-qa"]}, "roles": ["qa"]},
        {"id": ENG, "username": "eve", "enabled": True, "attributes": {"person_id": ["p-eng"]}, "roles": ["engineer"]},
    ]


def empty_state():
    return {"state": "empty", "version": None, "kind": None, "status": None, "entries_digest": None,
            "groups": None, "roles": None, "based_on": None, "confirmed_at": None, "disputed_at": None,
            "claimed_by_person": None, "accepted": None, "entries": [], "waivers": [], "last_apply_event": None,
            "break_glass_open": [], "system_functions": {"system_as": True, "record": True}}


def v1_digest():
    """version 1's routes digest (= defaults.yaml's; the label is not hashed)."""
    p = subprocess.run([sys.executable, os.path.join(REPO, "apps/iam/compiler/cli.py"), "--defaults", "compile", "routes"],
                       capture_output=True, text=True, check=True, env=clean_env())
    return json.loads(p.stdout)["digest"]


class Tree:
    """A scratch tree with apply.sh, the iam deploy and a fake cluster."""

    def __init__(self, **scenario):
        self.root = scratch_repo("medcea-apply-")
        for f in ("apps/iam/apply.sh", "apps/iam/deploy.sh", "apps/iam/iam-api.py", "infra/mqtt-passwd.py",
                  "infra/jwks-sig.py"):
            dst = os.path.join(self.root, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy(os.path.join(REPO, f), dst)
        shutil.copytree(os.path.join(REPO, "apps/iam/k8s"), os.path.join(self.root, "apps/iam/k8s"))
        for f in ("medcea_db_migrations_down_008b.sql", "medcea_db_migrations_008b_enforce.sql"):
            shutil.copy(os.path.join(REPO, "apps/database", f), os.path.join(self.root, "apps/database", f))
        shutil.copy(os.path.join(REPO, "infra/pg-scram.py"), os.path.join(self.root, "infra/pg-scram.py"))
        with open(os.path.join(self.root, "config.env"), "w") as f:
            f.write(CONFIG)
        self.fd = os.path.join(self.root, ".fake")
        # the scoped modes --resume runs (IAM 4.2b): stubs that log their argv to .fake/scoped.log
        # (the iam deploy is the real one: its --gate-only says "no gate before slice 4.3"); IAM
        # 4.5's fault injection, offline only: FAKE_SCOPED="<rel>=<rc>[:<n>];…" fails the first
        # n runs of <rel> (all without :n) with exit rc
        for rel in ("deploy-infra.sh", "infra/deploy-workbench.sh") + tuple(
                f"apps/{c}/deploy.sh" for c in ("access", "edge-wizard", "frontend", "monitor", "mqtt-explorer",
                                                 "scheduler")):
            dst = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as f:
                f.write(SCOPED_STUB.replace("@REL@", rel).replace("@UP@", "../" * rel.count("/")))
            os.chmod(dst, 0o755)
        self.bin = os.path.join(self.fd, "bin")
        os.makedirs(self.bin)
        fake = os.path.join(self.fd, "fake.py")
        with open(fake, "w") as f:
            f.write(FAKE)
        os.chmod(fake, 0o755)
        for name in ("microk8s", "curl", "helm", "helm3", "kubectl"):
            os.symlink(fake, os.path.join(self.bin, name))
        shutil.copy(fake, os.path.join(self.root, "health-check.sh"))
        with open(os.path.join(self.bin, "sleep"), "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(os.path.join(self.bin, "sleep"), 0o755)
        sc = {"users": users(), "configmap": {"routes": V1, "mqtt": "m" * 64}, "comment": f"policy {V1}"}
        sc.update(scenario)
        self.scenario(sc)
        self.state(scenario.get("initial_state") or empty_state())

    def scenario(self, sc):
        with open(os.path.join(self.fd, "scenario.json"), "w") as f:
            json.dump(sc, f)

    def state(self, d):
        with open(os.path.join(self.fd, "state.json"), "w") as f:
            json.dump(d, f)

    def read_state(self):
        with open(os.path.join(self.fd, "state.json")) as f:
            return json.load(f)

    def run(self, *args, script="apps/iam/apply.sh", **env):
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.fd, FAKE_ROOT=self.root,
                      MEDCEA_NO_LOG="1", MEDCEA_CONFIRMED="1", HOME=self.root)
        e.pop("MEDCEA_LOG_FILE", None)
        e.update(env)
        return subprocess.run(["bash", os.path.join(self.root, script), *args], capture_output=True, text=True,
                              env=e, cwd=self.root, stdin=subprocess.DEVNULL, timeout=600)

    def calls(self):
        try:
            with open(os.path.join(self.fd, "calls.log")) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def path(self, *p):
        return os.path.join(self.root, *p)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


WRITE_SQL = ("_build_version", "_accept_skeleton(", "_mark_applied", "_record(", "_sync_skeleton(",
             "_propose_skeleton(", "_withdraw_open(")


def writes(calls):
    """Every call that could change the cluster or the database."""
    out = []
    for c in calls:
        if (c["kind"] == "psql" and not c["sql"].startswith("BEGIN TRANSACTION READ ONLY")
                and any(w in c["sql"] for w in WRITE_SQL)):
            out.append(("psql", c["sql"][:80]))
        elif c["kind"] == "kubectl" and c["argv"][:1] and c["argv"][0] not in ("get", "exec", "port-forward", "wait"):
            out.append(("kubectl", c["argv"][0]))
        elif c["kind"] in ("microk8s", "helm", "helm3", "kubectl-standalone"):
            out.append((c["kind"], c.get("argv")))
        elif c["kind"] == "curl" and c["method"] != "GET" and "openid-connect/token" not in c["url"]:
            out.append(("curl", c["method"]))
    return out


def b64var(sql, name):
    m = re.search(r"\\set %s '([^']*)'" % re.escape(name), sql)
    return base64.b64decode(m.group(1)).decode("utf-8") if m else None


V1 = None


def read_repo(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def setUpModule():
    global V1
    V1 = v1_digest()


class Bootstrap(unittest.TestCase):
    """The bootstrap column of design §14.4.9, end to end against the fake cluster."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        # a malformed queued fact: the flush warns and the bootstrap goes on (critique sec-5)
        os.mkdir(cls.t.path("state"), 0o700)
        with open(cls.t.path("state", "seed-facts.jsonl"), "w") as f:
            f.write('{"fact": "nonsense"}\n')
        cls.p = cls.t.run("--bootstrap", "--by", "admin")
        cls.calls = cls.t.calls()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def test_exit_and_host_file(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)
        src = source.read_host_file(self.t.path("state", "policy-applied.yaml"))
        self.assertEqual((src.version, src.header["kind"]), (1, "bootstrap"))
        st = os.stat(self.t.path("state", "policy-applied.yaml"))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertIn("version 1 (bootstrap) applied", self.p.stdout)

    def test_order(self):
        def first(pred):
            return next(i for i, c in enumerate(self.calls) if pred(c))
        state_read = first(lambda c: c["kind"] == "psql" and "BEGIN TRANSACTION READ ONLY" in c["sql"])
        chain = first(lambda c: c["kind"] == "psql" and "verify_chain()" in c["sql"])
        by = first(lambda c: c["kind"] == "curl" and "username=admin" in c["url"])
        cm = first(lambda c: c["kind"] == "kubectl" and c["argv"][:2] == ["get", "configmap"])
        bundle = first(lambda c: c["kind"] == "psql" and "_build_version('bootstrap'" in c["sql"])
        verify = first(lambda c: c["kind"] == "health" and any("iamgrants" in l for l in c["conf"]))
        rec = first(lambda c: c["kind"] == "psql" and "_record('bootstrap_applied'" in c["sql"])
        report = first(lambda c: c["kind"] == "health" and any("iampolicy" in l for l in c["conf"]))
        self.assertLess(state_read, chain)
        self.assertLess(chain, by)
        self.assertLess(by, cm)
        self.assertLess(cm, bundle)
        self.assertLess(bundle, verify)
        self.assertLess(verify, rec)
        self.assertLess(rec, report)    # iampolicy never runs before the record
        self.assertTrue(os.path.exists(self.t.path("state", "policy-applied.yaml")))

    def test_verify_conf_is_exactly_iamgrants(self):
        confs = [c["conf"] for c in self.calls if c["kind"] == "health"]
        self.assertEqual(confs[0], ["Database grants | iamgrants | $POSTGRES_DB |"])
        self.assertEqual([l.split("|")[1].strip() for l in confs[1]], ["iampolicy", "iamartefacts"])
        self.assertEqual(len(confs), 2)

    def test_nothing_rolled_applied_or_deleted(self):
        w = [x for x in writes(self.calls) if x[0] != "psql"]
        self.assertEqual(w, [])
        for c in self.calls:
            if c["kind"] == "kubectl":
                self.assertNotIn(c["argv"][0], ("rollout", "apply", "delete", "create", "annotate", "patch", "set"))

    def test_bundle_sql(self):
        with open(os.path.join(self.t.fd, "bundle.sql")) as f:
            sql = f.read()
        self.assertIn("SELECT medcea_auth._set_internal_actor('system:apply');", sql)
        self.assertLess(sql.index("_accept_skeleton("), sql.index("_sync_skeleton("))
        self.assertLess(sql.index("_sync_skeleton("), sql.index("_build_version('bootstrap'"))
        self.assertLess(sql.index("_build_version('bootstrap'"), sql.index("_mark_applied(:v"))
        self.assertIn("transaction_isolation", sql)
        body = json.loads(b64var(sql, "skel_body"))
        self.assertEqual(source.skeleton_digest(body), source.skeleton_digest(source.factory()))
        self.assertEqual(b64var(sql, "skel_commit"), "unknown")       # no .git: recorded as unknown
        self.assertEqual(b64var(sql, "v1_by_person"), "p-admin")
        self.assertIn(f"\\set v1_by_sub '{ADMIN}'", sql)
        digests = json.loads(b64var(sql, "v1_digests"))
        self.assertEqual(digests["routes"], V1)
        self.assertEqual(set(digests["tools"]), {"grafana", "jupyterhub_allowed", "jupyterhub_admin", "node_red",
                                                 "edge_wizard", "pgadmin"})
        self.assertIn("v1_want", sql)
        want = re.search(r"\\set v1_want '([0-9a-f]{64})'", sql).group(1)
        self.assertEqual(want, source.policy_entries_digest(source.factory(), "bootstrap"))

    def test_record(self):
        with open(os.path.join(self.t.fd, "record.sql")) as f:
            sql = f.read()
        self.assertIn("_set_internal_actor('system:apply')", sql)
        payload = json.loads(b64var(sql, "payload"))
        for k in ("version", "kind", "os_user", "claimed_by_sub", "claimed_by_person", "git_commit", "skeleton_digest",
                  "compiler_digest", "based_on", "rollback_of", "artefacts", "changed", "deferred", "apply_log",
                  "chain_head_before"):
            self.assertIn(k, payload)
        self.assertEqual((payload["version"], payload["kind"], payload["claimed_by_sub"]), (1, "bootstrap", ADMIN))
        self.assertEqual(payload["chain_head_before"], {"id": 41, "hash": "ab" * 32})
        self.assertNotIn("apply_log_sha256", payload)
        self.assertNotIn("resumed", payload)

    def test_warnings(self):
        self.assertIn("unknown", self.p.stderr)                        # git_commit unknown: a warning
        self.assertIn("seed-facts.jsonl", self.p.stderr)              # the unflushable queue: a warning
        self.assertTrue(os.path.exists(self.t.path("state", "seed-facts.jsonl")))
        self.assertIn("someone can approve", self.p.stdout)

    def test_a_second_bootstrap_refuses(self):
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("policy versions exist", p.stderr)


class Refusals(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    def assertNoWrites(self):
        self.assertEqual(writes(self.t.calls()), [])
        self.assertFalse(os.path.exists(self.t.path("state", "policy-applied.yaml")))

    def test_a_non_empty_table(self):
        d = apply_check.simulate_state()
        self.t.state(d)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("--bootstrap is only for an empty iam_policy.version", p.stderr)

    def test_no_008c_waits(self):
        self.t.state({"state": "none", "detail": "no migration 008c", "break_glass_open": []})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("waits", p.stderr)
        self.assertNoWrites()

    def test_a_host_file_present(self):
        os.mkdir(self.t.path("state"), 0o700)
        with open(self.t.path("state", "policy-applied.yaml"), "w") as f:
            f.write("# medcea-applied: forged\n")
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("state/policy-applied.yaml exists", p.stderr)
        self.assertEqual(writes(self.t.calls()), [])

    def test_break_glass(self):
        p = self.t.run("--bootstrap", "--by", "admin", MEDCEA_POLICY_FILE=self.t.path("apps/iam/policy/defaults.yaml"),
                       MEDCEA_POLICY_BREAK_GLASS="test")
        self.assertEqual(p.returncode, 2)
        self.assertIn("no bootstrap under break-glass", p.stderr)
        self.assertNoWrites()

    def test_an_unknown_by(self):
        p = self.t.run("--bootstrap", "--by", "nobody")
        self.assertEqual(p.returncode, 2)
        self.assertIn("no such account", p.stderr)
        self.assertNoWrites()

    def test_a_disabled_by(self):
        u = users()
        u[0]["enabled"] = False
        self.t.scenario({"users": u, "configmap": None, "comment": None})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("disabled", p.stderr)

    def test_keycloak_down_waits(self):
        self.t.scenario({"kc_down": True, "users": users()})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("Keycloak", p.stderr)
        self.assertNoWrites()

    def test_a_bad_chain(self):
        self.t.scenario({"chain_ok": False, "users": users()})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1)
        self.assertIn("verify_chain() is false", p.stderr)
        self.assertNoWrites()

    def test_a_dirty_tree(self):
        g = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test", "GIT_COMMITTER_NAME": "t",
             "GIT_COMMITTER_EMAIL": "t@example.test", "HOME": self.t.root}
        env = dict(os.environ, **g)
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "scratch"]):
            subprocess.run(["git", "-C", self.t.root, *cmd], check=True, env=env, capture_output=True)
        with open(self.t.path("apps/iam/policy/defaults.yaml"), "a") as f:
            f.write("\n# a local edit\n")
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1)
        self.assertIn("apps/iam has uncommitted changes", p.stderr)
        self.assertNoWrites()

    def test_live_routes_digest_differs(self):
        self.t.scenario({"users": users(), "configmap": {"routes": "0" * 64}, "comment": f"policy {V1}"})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1)
        self.assertIn("version 1 would not be what is live", p.stderr)
        self.assertNoWrites()

    def test_role_widening_comment_differs(self):
        self.t.scenario({"users": users(), "configmap": {"routes": V1}, "comment": "policy " + "0" * 64})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1)
        self.assertIn("medcea_auth.role_widening()", p.stderr)
        self.assertNoWrites()

    def test_simulated_host_file_differs(self):
        # a forced waiver_from_row difference: the host file as psql's rows build it differs
        p_src = self.t.path("apps/iam/compiler/source.py")
        with open(p_src) as f:
            text = f.read()
        text = text.replace('"objects": list(row.get("objects") or []), "review_by": rb,',
                            '"objects": list(row.get("objects") or []), "review_by": "2099-12-31",', 1)
        with open(p_src, "w") as f:
            f.write(text)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("v1 must compile to exactly what defaults.yaml compiles to", p.stderr)
        self.assertIn("the simulated host file", p.stderr)
        self.assertNoWrites()

    def test_bundle_failure(self):
        self.t.scenario({"bundle_fail": True, "users": users(), "configmap": None, "comment": None})
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 1)
        self.assertIn("rolled back", p.stderr)
        self.assertFalse(os.path.exists(self.t.path("state", "policy-applied.yaml")))
        self.assertEqual(self.t.read_state()["state"], "empty")

    def test_no_configmap_and_no_function_are_not_compared(self):
        self.t.scenario({"users": users(), "configmap": None, "comment": None})
        p = self.t.run("--bootstrap", "--by", "admin", "--check-only")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("not deployed yet, not compared", p.stdout)
        self.assertIn("not compiled yet, not compared", p.stdout)
        self.assertIn("would bootstrap version 1", p.stdout)

    def test_a_forged_lock_marker(self):
        # MEDCEA_LOCK_HELD names no live holder of .medcea.lock above apply.sh: refused before anything
        p = self.t.run("--bootstrap", "--by", "admin", MEDCEA_LOCK_HELD="1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("only under the deploy lock", p.stderr)
        self.assertEqual(self.t.calls(), [])

    def test_later_modes(self):
        # IAM 4.5: <N> and --rollback-to are real; with no applied version both wait (exit 2)
        for args in (["1", "--by", "admin"], ["--rollback-to", "1", "--by", "admin", "--reason", "test: r"]):
            with self.subTest(args):
                p = self.t.run(*args)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertNotIn("arrives with IAM", p.stderr)
                self.assertIn("no applied version", p.stderr)
        self.assertEqual(writes(self.t.calls()), [])
        for args in (["0", "--by", "admin"], ["1x", "--by", "admin"], ["1"], ["1", "--by", "admin", "--reason", "r"],
                     ["--rollback-to", "1", "--by", "admin"], ["--audit", "1", "--by", "admin"], ["--audit"],
                     ["1", "2", "--by", "admin"], ["--rollback-to", "-1", "--by", "admin", "--reason", "r"]):
            with self.subTest(args):
                self.assertEqual(self.t.run(*args).returncode, 2)

    def test_usage(self):
        for args in ([], ["--bootstrap"], ["--bootstrap", "--by", "-x"], ["--status", "--by", "admin"], ["--nope"],
                     ["--bootstrap", "--by", "admin", "--reason", "r"], ["--resume", "--by", "admin", "--from-git", "HEAD"],
                     ["--withdraw-open", "--by", "admin", "--reason", "r", "--from-git", "HEAD"],
                     ["--propose-skeleton", "--withdraw-open", "--by", "admin", "--reason", "r"]):
            with self.subTest(args):
                self.assertEqual(self.t.run(*args).returncode, 2)


class AfterCommit(unittest.TestCase):
    """Every failure after the bundle's COMMIT is exit 3; --resume finishes it (critique ops-8, ops-9)."""

    def tearDown(self):
        self.t.close()

    def test_grants_check_fails(self):
        self.t = Tree(health_rc=1)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("--resume", p.stderr)
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "apply_started")

    def test_written_host_file_compiles_differently(self):
        self.t = Tree(post_review_by="2099-12-31")
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("compiles differently", p.stderr)

    def test_write_applied_fails_then_resume(self):
        self.t = Tree()
        os.mkdir(self.t.path("state"), 0o755)          # not 700: the writer refuses it
        os.chmod(self.t.path("state"), 0o755)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("cannot write state/policy-applied.yaml", p.stderr)
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "apply_started")
        # the operator fixes state/; --resume (as a later iam deploy runs it) finishes the apply
        os.chmod(self.t.path("state"), 0o700)
        before = len(self.t.calls())
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        calls = self.t.calls()[before:]
        self.assertFalse([c for c in calls if c["kind"] == "psql" and "_build_version" in c["sql"]])
        with open(os.path.join(self.t.fd, "record.sql")) as f:
            payload = json.loads(b64var(f.read(), "payload"))
        self.assertEqual((payload["kind"], payload.get("resumed")), ("bootstrap", True))
        self.assertTrue(os.path.exists(self.t.path("state", "policy-applied.yaml")))
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "bootstrap_applied")
        # nothing left to resume
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0)
        self.assertIn("nothing to resume (latest: bootstrap_applied 42)", p.stdout)


    def test_bundle_failure_after_its_commit(self):
        # kubectl exec failed after the COMMIT reached PostgreSQL: the database is asked, and
        # the answer (version 1 exists) is exit 3 with --resume, never "nothing was changed"
        self.t = Tree(bundle_stream_lost=True)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("its COMMIT reached PostgreSQL", p.stderr)
        self.assertIn("--resume", p.stderr)
        self.assertNotIn("nothing was changed", p.stderr)
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "apply_started")

    def test_resume_compares_with_the_committed_version_not_git(self):
        # committed, then a matrix cell changed in git before the resume: the skeleton gate is
        # equal, and the reference is version 1 from the database rows, so the resume finishes
        # and records version 1's artefact digests (review 4.2a)
        self.t = Tree(health_rc=1)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stderr)
        pol = self.t.path("apps", "iam", "policy", "defaults.yaml")
        with open(pol) as f:
            text = f.read()
        data = yaml.safe_load(text)
        data["matrix"]["portal"]["engineer"] = []
        from compiler import cli as cli_mod
        lines = text.splitlines(keepends=True)
        a, b = cli_mod._top_blocks(lines)["matrix"]
        new = yaml.safe_dump({"matrix": data["matrix"]}, sort_keys=False, allow_unicode=True, width=1000)
        with open(pol, "w") as f:
            f.write("".join(lines[:a]) + new + "".join(lines[b:]))
        with open(pol) as f:
            self.assertNotEqual(source.policy_entries_digest(yaml.safe_load(f)), self.t.read_state()["entries_digest"])
        sc = {"users": users(), "configmap": {"routes": V1, "mqtt": "m" * 64}, "comment": f"policy {V1}"}
        self.t.scenario(sc)
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("compiles to exactly what the committed version compiles to", p.stdout)
        with open(os.path.join(self.t.fd, "record.sql")) as f:
            payload = json.loads(b64var(f.read(), "payload"))
        self.assertEqual(payload["artefacts"]["routes"], V1)
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "bootstrap_applied")
        # step 8 (IAM 4.2b): every scoped mode, deploy-infra's first, the workbench's next
        with open(os.path.join(self.t.fd, "scoped.log")) as f:
            ran = f.read().splitlines()
        self.assertEqual(ran[:2], ["deploy-infra.sh --policy-only", "infra/deploy-workbench.sh --policy-only"])
        self.assertEqual(len(ran), 8)
        self.assertTrue(all(r.endswith(" --gate-only") for r in ran[2:]), ran)

    def test_a_signal_after_the_commit_is_exit_3(self):
        # the trap knows the phase: after the COMMIT an interrupt is 3 and names --resume
        self.t = Tree(health_sigint=True)
        p = self.t.run("--bootstrap", "--by", "admin")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("interrupted: version 1 is committed", p.stderr)
        self.assertEqual(self.t.read_state()["last_apply_event"]["event"], "apply_started")
        t = read_repo("apps/iam/apply.sh")
        self.assertNotIn("trap 'exit 130' INT TERM", t)
        self.assertIn("trap on_signal INT TERM HUP", t)
        body = t[t.index("on_signal() {"):t.index("trap on_signal")]
        self.assertIn('if [[ -n "$VERSION" ]]', body)
        self.assertIn("exit 3", body)
        self.assertIn("exit 130", body)
        self.assertLess(t.index('VERSION=""\non_signal'), t.index('dba_policy_bundle "$NAMESPACE"'))
        # VERSION is set only once the database holds the version
        self.assertLess(t.index('dba_policy_bundle "$NAMESPACE"'), t.index("    VERSION=1\n"))

    def test_iam_deploy_maps_every_apply_exit(self):
        self.t = Tree()
        t = read_repo("apps/iam/deploy.sh")
        self.assertIn('130) die "the policy bootstrap was interrupted before its commit: nothing was changed"', t)
        self.assertNotIn('*) die "the policy bootstrap refused (see above): nothing was changed"', t)


class ReadOnlyModes(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    def test_check_only_takes_no_lock_and_writes_nothing(self):
        os.mkdir(self.t.path("state"), 0o700)
        with open(self.t.path("state", "seed-facts.jsonl"), "w") as f:
            f.write(json.dumps(apply_check.seed_fact("observed", "quinn", QA, "qa", "p-qa")) + "\n")
        p = self.t.run("--bootstrap", "--check-only", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("would bootstrap version 1", p.stdout)
        self.assertIn("1 queued account fact(s)", p.stdout)
        self.assertEqual(writes(self.t.calls()), [])
        self.assertFalse(os.path.exists(self.t.path(".medcea.lock")))
        self.assertEqual(sorted(os.listdir(self.t.path("state"))), ["seed-facts.jsonl"])
        self.assertFalse([c for c in self.t.calls() if c["kind"] == "psql" and "account_seeded" in c["sql"]])

    def test_status_empty_and_applied(self):
        p = self.t.run("--status")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("state: empty", p.stdout)
        self.assertIn("who can approve", p.stdout)
        d = apply_check.simulate_state()
        d["last_apply_event"] = {"event": "bootstrap_applied", "event_id": 42, "at": "2026-11-02T10:00:00+00:00"}
        d.update(last_events=[{"event_id": 42, "event": "bootstrap_applied", "version": 1, "actor": "system:apply",
                               "at": "2026-11-02T10:00:00+00:00"}], chain_ok=True, seeded={})
        self.t.state(d)
        p = self.t.run("--status")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("applied: version 1 (bootstrap)", p.stdout)
        self.assertIn("waiting for qa (4.3)", p.stdout)
        self.assertIn(": equal", p.stdout)
        self.assertIn("host file: absent", p.stdout)
        self.assertEqual(writes(self.t.calls()), [])
        self.assertFalse(os.path.exists(self.t.path(".medcea.lock")))

    def test_status_unreachable(self):
        self.t.scenario({"users": users(), "pg": True})
        with open(os.path.join(self.t.fd, "scenario.json")) as f:
            sc = json.load(f)
        sc["db"] = True
        self.t.scenario(sc)
        self.t.state({"state": "unreachable", "detail": "x", "break_glass_open": []})
        p = self.t.run("--status")
        self.assertEqual(p.returncode, 1)


class IamDeploy(unittest.TestCase):
    """The bootstrap section of apps/iam/deploy.sh on a fresh install (§14.4.4's order, steps 6-7):
    state empty -> the bootstrap runs in iam, and its re-read init sees version-1."""

    def test_fresh_install_bootstraps_in_iam(self):
        t = Tree(configmap=None, comment=None)
        try:
            p = t.run(script="apps/iam/deploy.sh", MEDCEA_POLICY_BOOTSTRAP_BY="admin")
            self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
            self.assertIn("version 1 (bootstrap) applied", p.stdout)
            self.assertEqual(t.read_state()["last_apply_event"]["event"], "bootstrap_applied")
            reads = [i for i, c in enumerate(t.calls()) if c["kind"] == "psql" and "BEGIN TRANSACTION READ ONLY" in c["sql"]]
            rec = next(i for i, c in enumerate(t.calls()) if c["kind"] == "psql" and "_record('bootstrap_applied'" in c["sql"])
            self.assertTrue(any(i > rec for i in reads))       # the init read the state again: version-1
            self.assertIn("iam-api not deployed", p.stderr)     # skip_api, after the bootstrap (F-1)
            # a second deploy: version-1, no bootstrap, no resume
            before = len(t.calls())
            p = t.run(script="apps/iam/deploy.sh")
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertIn("applied: 1", p.stdout)
            self.assertFalse([c for c in t.calls()[before:] if c["kind"] == "psql" and "_build_version" in c["sql"]])
        finally:
            t.close()

    def test_a_bootstrap_that_waits_is_a_warning(self):
        t = Tree(kc_down=True, configmap=None, comment=None)
        try:
            p = t.run(script="apps/iam/deploy.sh")
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertIn("policy bootstrap waits", p.stderr)
        finally:
            t.close()

    def test_an_unfinished_apply_is_resumed(self):
        t = Tree()
        try:
            d = apply_check.simulate_state()
            d["last_apply_event"] = {"event": "apply_started", "event_id": 40, "at": "2026-11-02T10:00:00+00:00"}
            t.state(d)
            p = t.run(script="apps/iam/deploy.sh")
            self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
            self.assertIn("finishing it (apply.sh --resume)", p.stderr)
            self.assertEqual(t.read_state()["last_apply_event"]["event"], "bootstrap_applied")
        finally:
            t.close()


STUB_DEPLOY = r'''#!/usr/bin/env bash
# A stub component deploy for FreshInstallOrder: it reads the policy as a compiling
# component does (policy_source_init under deploy-apps' lock) and logs what it saw.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/config.env"
source "$ROOT/infra/lib-mk8s.sh"
source "$ROOT/infra/lib-policy-source.sh"
policy_source_init "$NAMESPACE" || exit $?
d="$(mktemp -d)"
st="$(policy_db_state "$NAMESPACE" "$d/s.json")" || st=error
rm -rf "$d"
host=absent; [[ -f "$ROOT/state/policy-applied.yaml" ]] && host=present
echo "$(basename "$(dirname "${BASH_SOURCE[0]}")") $st $host" >> "$ROOT/.fake/order.log"
'''


class FreshInstallOrder(unittest.TestCase):
    """§14.4.17: `deploy-apps.sh --all` on a fresh install (a fake cluster moving none ->
    empty -> version-1): the bootstrap runs in iam, the components before iam compile with
    no version (state empty, no host file), and every component after it sees version-1 and
    the host file. The component deploys are stubs except iam's."""

    BEFORE = ("access", "database", "frontend")
    AFTER = ("monitor", "scheduler")

    def tree(self, **sc):
        t = Tree(configmap=None, comment=None, **sc)
        shutil.copy(os.path.join(REPO, "deploy-apps.sh"), t.path("deploy-apps.sh"))
        # a scratch tree: the host package check is not under test
        with open(t.path("infra/lib-prereqs.sh"), "w") as f:
            f.write("check_prereqs() { :; }\n")
        for c in self.BEFORE + self.AFTER:
            p = t.path("apps", c, "deploy.sh")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(STUB_DEPLOY)
        return t

    def order(self, t):
        try:
            with open(t.path(".fake", "order.log")) as f:
                return [l.split() for l in f.read().splitlines()]
        except FileNotFoundError:
            return []

    def test_bootstrap_runs_in_iam_and_later_components_see_version_1(self):
        t = self.tree()
        try:
            # no migration 008c answer yet would be "none": the database deploy moves it to
            # empty; with the stubs the fake cluster starts at empty (008c applied, no version)
            p = t.run("--all", script="deploy-apps.sh", MEDCEA_POLICY_BOOTSTRAP_BY="admin")
            self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
            self.assertIn("version 1 (bootstrap) applied", p.stdout + p.stderr)
            seen = self.order(t)
            self.assertEqual([s[0] for s in seen], list(self.BEFORE + self.AFTER))
            for comp, st, host in seen:
                with self.subTest(comp):
                    if comp in self.BEFORE:
                        self.assertEqual((st, host), ("empty", "absent"))
                    else:
                        self.assertEqual((st, host), ("version-1", "present"))
            builds = [c for c in t.calls() if c["kind"] == "psql" and "_build_version('bootstrap'" in c["sql"]]
            self.assertEqual(len(builds), 1)
            self.assertEqual(t.read_state()["last_apply_event"]["event"], "bootstrap_applied")
            self.assertFalse([w for w in writes(t.calls()) if w[0] != "psql"])
        finally:
            t.close()

    def test_unreachable_postgres_stops_before_the_first_component(self):
        """ops-6: deploy-apps probes policy_db_state once and exits 1 on unreachable, before
        any component (stub or iam) runs."""
        t = self.tree(pg_unready=True)
        try:
            p = t.run("--all", script="deploy-apps.sh")
            self.assertEqual(p.returncode, 1, p.stdout[-2000:] + p.stderr[-2000:])
            self.assertIn("PostgreSQL is not Ready", p.stdout + p.stderr)
            self.assertEqual(self.order(t), [])
            self.assertNotIn("Installing:", p.stdout)
            self.assertFalse([c for c in t.calls() if c["kind"] == "psql"])
            # one probe: a single wait for the pod, then the stop
            self.assertEqual(len([c for c in t.calls() if c["kind"] == "kubectl" and c["argv"][:1] == ["wait"]]), 1)
        finally:
            t.close()


def applied_state(**kw):
    """version 1 applied (bootstrap_applied), the --full fields apply.sh's 4.4 modes read."""
    d = apply_check.simulate_state()
    d.update(last_apply_event={"event": "bootstrap_applied", "event_id": 42, "at": "2026-11-02T10:01:00+00:00"},
             chain_ok=True, open_versions=[])
    d.update(kw)
    return d


GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.test"}
POLICY = "apps/iam/policy/defaults.yaml"
# git edits of defaults.yaml, each committed on its own branch of the scratch tree
WIDE = ('routes: {"GET /api/recipes": R}}', 'routes: {"GET /api/recipes": R, "GET /api/recipes/extra": R}}')
PROSE = ("Independent approver of configuration, access decisions and policy changes.",
         "Independent approver of configuration, access decisions and changes to the policy.")
RED = ("    includes: [auditor]\n", "    includes: [auditor, admin]\n")


def id_un():
    return subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()


class ProposeSkeleton(unittest.TestCase):
    """apply.sh --propose-skeleton (IAM 4.4, design §14.7.6), against the fake cluster and a
    scratch tree with a git history: the deploying tree (HEAD) stays at the accepted skeleton,
    the proposals are commits on branches."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        env = dict(os.environ, HOME=cls.t.root, **GIT_ENV)

        def git(*a):
            return subprocess.run(["git", "-C", cls.t.root, *a], check=True, env=env, capture_output=True,
                                  text=True).stdout.strip()
        git("init", "-q", "-b", "main")
        with open(cls.t.path(".git", "info", "exclude"), "a") as f:
            f.write(".fake/\n.medcea.lock\nstate/\n")
        git("add", "-A")
        git("commit", "-qm", "scratch")
        cls.base = git("rev-parse", "HEAD")
        cls.rev = {}
        for name, (a, b) in (("wide", WIDE), ("prose", PROSE), ("red", RED)):
            git("checkout", "-q", "-b", name, "main")
            with open(cls.t.path(POLICY)) as f:
                text = f.read()
            assert text.count(a) == 1, name
            with open(cls.t.path(POLICY), "w") as f:
                f.write(text.replace(a, b))
            git("commit", "-qam", name)
            cls.rev[name] = git("rev-parse", "HEAD")
        git("checkout", "-q", "main")
        cls.wide_data = yaml.safe_load(git("show", f"{cls.rev['wide']}:{POLICY}"))

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def setUp(self):
        self.t.state(applied_state())
        self.t.scenario({"users": users(), "configmap": {"routes": V1, "mqtt": "m" * 64}, "comment": f"policy {V1}"})
        for f in ("calls.log", "propose.sql"):
            try:
                os.remove(os.path.join(self.t.fd, f))
            except FileNotFoundError:
                pass

    def run_(self, *args, **env):
        return self.t.run("--propose-skeleton", "--by", "admin", *args, **env)

    def sql(self):
        with open(os.path.join(self.t.fd, "propose.sql")) as f:
            return f.read()

    def assertNothingProposed(self):
        self.assertFalse([c for c in self.t.calls() if c["kind"] == "psql" and "_propose_skeleton(" in c["sql"]])
        self.assertEqual(writes(self.t.calls()), [])

    def test_a_widening_is_submitted(self):
        p = self.run_("--reason", "test: a new recipes route", "--from-git", "wide")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("version 2 (skeleton) submitted: a qa person other than admin", p.stdout)
        self.assertNotIn("arrives with IAM 4.5", p.stdout)
        self.assertIn("run ./apps/iam/apply.sh 2 --by <you>", p.stdout)
        self.assertIn("route scheduler GET /api/recipes/extra", p.stdout)
        self.assertNotIn("WARNING", p.stderr)          # HEAD is at the accepted skeleton
        sql = self.sql()
        # --from-git reads the revision: its skeleton and its commit
        self.assertIn(f"\\set digest '{source.skeleton_digest(self.wide_data)}'", sql)
        self.assertEqual(b64var(sql, "commit"), self.rev["wide"])
        body = json.loads(b64var(sql, "body"))
        self.assertEqual(source.skeleton_digest(body), source.skeleton_digest(self.wide_data))
        # the claimed --by, resolved in Keycloak; the reason carries the username and the OS user
        self.assertIn(f"\\set by_sub '{ADMIN}'", sql)
        self.assertEqual(b64var(sql, "by_person"), "p-admin")
        self.assertEqual(b64var(sql, "reason"), "test: a new recipes route [apply.sh --propose-skeleton, --by admin "
                                                f"(claimed), OS user {id_un()}]")
        # the diff document: canonical bytes, its digest, against the accepted skeleton
        doc = json.loads(b64var(sql, "diff"))
        want = re.search(r"\\set diff_digest '([0-9a-f]{64})'", sql).group(1)
        self.assertEqual(hashlib.sha256(source.canonical(doc)).hexdigest(), want)
        self.assertEqual(b64var(sql, "diff").encode("utf-8"), source.canonical(doc))
        st = applied_state()
        self.assertEqual((doc["kind"], doc["version"], doc["against"]), ("skeleton", 2, 1))
        self.assertEqual(doc["skeleton"]["from"], st["accepted"]["digest"])
        self.assertEqual(doc["skeleton"]["to"], source.skeleton_digest(self.wide_data))
        self.assertIn("qa", doc["roles"])
        # the entries digest _propose_skeleton will store (asserted in the transaction)
        rows = source.state_rows(st)
        skel = source.skeleton(self.wide_data)
        ed = source.entries_digest("skeleton", list(skel["resource_groups"]), list(skel["roles"]), rows["entries"],
                                   rows["waivers"])
        self.assertEqual(doc["entries_digest"], ed)
        self.assertIn(f"\\set want_entries '{ed}'", sql)
        self.assertIn("\\set want_version '2'", sql)
        self.assertIn("_set_internal_actor('system:apply')", sql)
        self.assertIn("transaction_isolation", sql)
        self.assertLess(sql.index("pg_advisory_xact_lock"), sql.index("_propose_skeleton("))
        self.assertLess(sql.index("_propose_skeleton("), sql.index("iam_policy.entries_digest("))
        # every value base64 (or hex/uuid/number) in \set, nothing on argv
        for line in sql.splitlines():
            if line.startswith("\\set"):
                self.assertRegex(line, r"^\\set [a-z0-9_]+ '[A-Za-z0-9+/=\-]*'$")
        self.assertNotRegex(sql, SQL_KEYWORD_QUALIFIED)
        for c in self.t.calls():
            if c["kind"] == "kubectl":
                self.assertNotIn("a new recipes route", json.dumps(c["argv"]))
        # one transaction (psql -1), and nothing but the proposal written
        exe = [c["argv"] for c in self.t.calls() if c["kind"] == "kubectl" and c["argv"][:1] == ["exec"]]
        self.assertTrue(any("-1" in a for a in exe))
        self.assertEqual(len(writes(self.t.calls())), 1)
        self.assertFalse(os.path.exists(self.t.path("state", "policy-applied.yaml")))

    def test_order_resolve_by_before_propose(self):
        p = self.run_("--reason", "test: order", "--from-git", "wide")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        calls = self.t.calls()

        def first(pred):
            return next(i for i, c in enumerate(calls) if pred(c))
        state = first(lambda c: c["kind"] == "psql" and "BEGIN TRANSACTION READ ONLY" in c["sql"])
        chain = first(lambda c: c["kind"] == "psql" and "verify_chain()" in c["sql"] and "h.hash" in c["sql"])
        by = first(lambda c: c["kind"] == "curl" and "username=admin" in c["url"])
        nxt = first(lambda c: c["kind"] == "psql" and "max(x.version)" in c["sql"] and "_propose_skeleton" not in c["sql"])
        prop = first(lambda c: c["kind"] == "psql" and "_propose_skeleton(" in c["sql"])
        self.assertLess(state, chain)
        self.assertLess(chain, by)
        self.assertLess(by, nxt)
        self.assertLess(nxt, prop)
        # in the script too: resolve_by before apply_check.py propose
        s = read_repo("apps/iam/apply.sh")
        blk = s[s.index('if [[ "$MODE" == propose-skeleton ]]; then'):s.index('if [[ "$MODE" == withdraw-open ]]; then')]
        self.assertLess(blk.index("    resolve_by\n"), blk.index('py "$CHECK" propose'))

    def test_equal_narrowing_and_red_refuse(self):
        for rev, rc, text in (("main", 1, "nothing to approve: this skeleton is the accepted one"),
                              ("prose", 1, "nothing to approve: it adds no access; deploy as usual"),
                              ("red", 1, "the proposed skeleton fails the checker with the applied matrix")):
            with self.subTest(rev):
                p = self.run_("--reason", "test: refused", "--from-git", rev)
                self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
                self.assertIn(text, p.stderr)
                self.assertNothingProposed()

    def test_an_open_version_refuses(self):
        self.t.state(applied_state(open_versions=[{"version": 2, "kind": "change", "status": "submitted",
                                                   "age_days": 0, "authors": ["alice"], "reason": "r"}]))
        p = self.run_("--reason", "test: refused", "--from-git", "wide")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("version 2 (change, submitted) is still open", p.stderr)
        self.assertNothingProposed()

    def test_usage_and_preconditions(self):
        for args, env, text in (
                (["--reason", "test: r"], {}, "propose a skeleton change from a commit: --from-git <rev>"),
                (["--from-git", "wide"], {}, "needs --reason"),
                (["--reason", "-x", "--from-git", "wide"], {}, "needs --reason"),
                (["--reason", "test: r", "--from-git", "-x"], {}, "is not a revision"),
                (["--reason", "test: r", "--from-git", "wide"],
                 {"MEDCEA_POLICY_FILE": "x.yaml", "MEDCEA_POLICY_BREAK_GLASS": "t"}, "no skeleton proposal under break-glass"),
                (["--reason", "test: r", "--from-git", "nosuchbranch"], {}, "no such commit")):
            with self.subTest(args):
                p = self.run_(*args, **env)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn(text, p.stderr)
                self.assertNothingProposed()

    def test_state_preconditions(self):
        for st, rc, text in ((empty_state(), 2, "no applied version: ./apps/iam/deploy.sh bootstraps it"),
                             (applied_state(last_apply_event={"event": "apply_started", "event_id": 40, "at": "x"}), 1,
                              "is being applied (apply_started)")):
            with self.subTest(text):
                self.t.state(st)
                p = self.run_("--reason", "test: r", "--from-git", "wide")
                self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
                self.assertIn(text, p.stderr)
                self.assertNothingProposed()

    def test_a_tree_off_the_accepted_skeleton_warns_only(self):
        path = self.t.path(POLICY)
        with open(path) as f:
            text = f.read()
        try:
            with open(path, "w") as f:
                f.write(text.replace(*PROSE))
            p = self.run_("--reason", "test: r", "--from-git", "wide", "--check-only")
        finally:
            with open(path, "w") as f:
                f.write(text)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("this tree's skeleton is not the accepted one: deploys refuse a widening", p.stderr)

    def test_check_only_takes_no_lock_and_writes_nothing(self):
        lock = self.t.path(".medcea.lock")
        if os.path.exists(lock):
            os.remove(lock)
        p = self.run_("--reason", "test: r", "--from-git", "wide", "--check-only")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("would submit skeleton version 2", p.stdout)
        self.assertIn("diff digest ", p.stdout)
        self.assertNothingProposed()
        self.assertFalse(os.path.exists(lock))

    def test_no_terminal_without_confirmation(self):
        p = self.run_("--reason", "test: r", "--from-git", "wide", MEDCEA_CONFIRMED="")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("refusing without a terminal", p.stderr)
        self.assertNothingProposed()

    def test_a_rolled_back_proposal(self):
        self.t.scenario({"users": users(), "propose_fail": True})
        p = self.run_("--reason", "test: r", "--from-git", "wide")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("another version was created meanwhile", p.stderr)
        self.assertIn("the proposal was rolled back", p.stderr)

    def test_a_by_without_a_maker_role_warns(self):
        p = self.t.run("--propose-skeleton", "--by", "quinn", "--reason", "test: r", "--from-git", "wide", "--check-only")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("--by quinn holds no maker role of iam_policy (admin)", p.stderr)
        p = self.run_("--reason", "test: r", "--from-git", "wide", "--check-only")
        self.assertNotIn("holds no maker role", p.stderr)


class WithdrawOpen(unittest.TestCase):
    """apply.sh --withdraw-open (IAM 4.4, design §14.7.6): the host path, no Keycloak."""

    OPEN = {"version": 2, "kind": "change", "status": "approved", "age_days": 1, "reason": "test: a draft",
            "authors": ["alice", "bob"], "skeleton_digest": None, "diff_from": None, "approved_at": "x"}

    def setUp(self):
        self.t = Tree()
        self.t.state(applied_state(open_versions=[self.OPEN]))

    def tearDown(self):
        self.t.close()

    def run_(self, *args, **env):
        return self.t.run("--withdraw-open", "--by", "admin", "--reason", "test: rollback", *args, **env)

    def assertNoKeycloak(self):
        self.assertEqual([c for c in self.t.calls() if c["kind"] == "curl"], [])

    def test_nothing_open(self):
        self.t.state(applied_state())
        p = self.run_()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("nothing is open", p.stdout)
        self.assertEqual(writes(self.t.calls()), [])
        self.assertNoKeycloak()

    def test_the_open_version_is_withdrawn(self):
        p = self.run_()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("open: version 2 (change, approved), reason: test: a draft", p.stdout)
        self.assertIn("authors: alice, bob", p.stdout)
        self.assertIn("version 2 withdrawn (system:apply)", p.stdout)
        with open(os.path.join(self.t.fd, "withdraw.sql")) as f:
            sql = f.read()
        self.assertEqual(b64var(sql, "reason"), "test: rollback [apply.sh --withdraw-open, --by admin (claimed), "
                                                f"OS user {id_un()}]")
        self.assertIn("\\set want_version '2'", sql)
        self.assertIn("_set_internal_actor('system:apply')", sql)
        self.assertLess(sql.index("_withdraw_open("), sql.index("another version was opened meanwhile"))
        self.assertNotRegex(sql, SQL_KEYWORD_QUALIFIED)
        self.assertNoKeycloak()
        self.assertTrue(os.path.exists(self.t.path(".medcea.lock")))

    def test_another_version_meanwhile_rolls_back(self):
        self.t.scenario({"users": users(), "withdraw_fail": True})
        p = self.run_()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("another version was opened meanwhile", p.stderr)
        self.assertIn("the withdraw was rolled back", p.stderr)

    def test_check_only_writes_nothing(self):
        p = self.run_("--check-only")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("would withdraw version 2", p.stdout)
        self.assertEqual(writes(self.t.calls()), [])
        self.assertFalse(os.path.exists(self.t.path(".medcea.lock")))
        self.assertNoKeycloak()

    def test_no_terminal_without_confirmation(self):
        p = self.run_(MEDCEA_CONFIRMED="")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("refusing without a terminal", p.stderr)
        self.assertEqual(writes(self.t.calls()), [])

    def test_unreachable_and_usage(self):
        self.t.state({"state": "unreachable", "detail": "rdbms-postgresql-0 is not Ready", "break_glass_open": []})
        self.assertEqual(self.run_().returncode, 1)
        p = self.t.run("--withdraw-open", "--by", "admin")
        self.assertEqual(p.returncode, 2)
        self.assertIn("needs --reason", p.stderr)

    def test_asks_y_n(self):
        s = read_repo("apps/iam/apply.sh")
        blk = s[s.index('if [[ "$MODE" == withdraw-open ]]; then'):s.index("# <N> and --rollback-to K")]
        self.assertIn('confirm "Withdraw version $OV ($OKIND, $OSTATUS)? [y/N] " y', blk)
        self.assertNotIn("kc_start", blk)
        self.assertNotIn("resolve_by", blk)
        self.assertLess(blk.index("confirm "), blk.index("withdraw-sql"))



class CanApprove(unittest.TestCase):
    DUAL = {"iam_policy": {"approver_roles": ["qa"], "maker_roles": ["admin"]},
            "iam_users": {"approver_roles": ["qa"], "maker_roles": ["admin"]}}

    def acc(self, sub, roles, person, enabled=True):
        return {"sub": sub, "username": sub, "enabled": enabled, "roles": roles, "person_id": person}

    def test_fine(self):
        self.assertEqual(apply_check.can_approve(self.DUAL, [self.acc("a", ["admin"], "p1"), self.acc("q", ["qa"], "p2")]), [])

    def test_none(self):
        probs = apply_check.can_approve(self.DUAL, [])
        self.assertEqual(len(probs), 4)
        self.assertTrue(all("no enabled account holds" in p for p in probs))

    def test_approver_is_a_makers_person(self):
        probs = apply_check.can_approve(self.DUAL, [self.acc("a", ["admin"], "p1"), self.acc("q", ["qa"], "p1")])
        self.assertEqual(len(probs), 2)
        self.assertIn("no enabled approver whose person_id is not an enabled maker's (iam_policy", probs[0])

    def test_a_disabled_maker_is_ignored(self):
        probs = apply_check.can_approve(self.DUAL, [self.acc("a", ["admin"], "p1", enabled=False),
                                                    self.acc("a2", ["admin"], "p3"), self.acc("q", ["qa"], "p1")])
        self.assertEqual(probs, [])

    def test_accounts_expand_composites(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "users"))
            with open(os.path.join(d, "qa.json"), "w") as f:
                json.dump([{"id": QA, "username": "quinn", "enabled": True}], f)
            with open(os.path.join(d, "users", f"{QA}.json"), "w") as f:
                json.dump({"id": QA, "username": "quinn", "enabled": True, "attributes": {"person_id": ["p-qa"]}}, f)
            acc = apply_check.accounts_from_dir(d)
            self.assertEqual(acc[0]["person_id"], "p-qa")
            self.assertEqual(acc[0]["roles"], ["auditor", "qa"])   # qa includes auditor
        finally:
            shutil.rmtree(d)

    def test_by_user(self):
        u = users()
        self.assertEqual(apply_check.by_user(u, "admin"), (ADMIN, "p-admin"))
        for bad in ([], [dict(u[0], enabled=False)], [dict(u[0], attributes={})]):
            with self.subTest(bad), self.assertRaises(SystemExit):
                apply_check.by_user(bad, "admin")


# NULLIF, COALESCE, GREATEST and LEAST are SQL syntax, not functions: qualified they
# parse, and fail only when they run ("function pg_catalog.nullif(text, unknown) does
# not exist", the 4.2a fixture's bootstrap bundle)
SQL_KEYWORD_QUALIFIED = re.compile(r"(?i)\bpg_catalog\s*\.\s*(nullif|coalesce|greatest|least)\s*\(")


class SqlKeywordsNotQualified(unittest.TestCase):
    def test_no_file_qualifies_a_sql_keyword(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        hits = []
        for top in ("apps", "infra", "tests"):
            for d, _, names in os.walk(os.path.join(root, top)):
                for name in names:
                    if not name.endswith((".sql", ".sh", ".py")) or name == "test_apply.py":
                        continue
                    f = os.path.join(d, name)
                    with open(f, errors="replace") as fh:
                        for n, line in enumerate(fh, 1):
                            if SQL_KEYWORD_QUALIFIED.search(line):
                                hits.append(f"{os.path.relpath(f, root)}:{n}")
        self.assertEqual(hits, [])


class BundleSql(unittest.TestCase):
    def test_values_travel_base64(self):
        st = apply_check.simulate_state()
        data = source.factory()
        data["about"] = "quotes ' \" and a backslash \\ and non-ASCII: São Tomé — ok"
        st2 = dict(st, accepted=dict(st["accepted"], digest=source.skeleton_digest(source.skeleton(data))))
        pre, post = apply_check.bundle_sql(st2, ADMIN, "p-o'brien", "/l", "c" * 40, {}, data=data)
        body = json.loads(b64var(pre, "skel_body"))
        self.assertEqual(body["about"], data["about"])
        self.assertEqual(b64var(post, "v1_by_person"), "p-o'brien")
        for line in (pre + post).splitlines():
            if line.startswith("\\set"):
                self.assertRegex(line, r"^\\set [a-z0-9_]+ '[A-Za-z0-9+/=\-]*'$")
        self.assertNotIn("_record(", pre + post)            # the fixture writes bootstrap_applied itself
        self.assertIn(":v,", post)
        self.assertNotRegex(pre + post, SQL_KEYWORD_QUALIFIED)
        try:
            import pglast  # noqa: F401
        except ImportError:
            return
        from pglast import parser
        sql = re.sub(r"^\\set .*$", "", pre + post, flags=re.M).replace("\\g /dev/null", ";").replace("\\gset", ";")
        sql = re.sub(r":'(\w+)'", "'x'", sql)
        sql = re.sub(r"(?<!:):(\w+)\b", "1", sql)
        parser.parse_sql(sql)

    def test_refuses_another_skeleton_or_matrix(self):
        st = apply_check.simulate_state()
        with self.assertRaises(SystemExit):
            apply_check.bundle_sql(dict(st, entries_digest="0" * 64), ADMIN, "p", "", "c")
        with self.assertRaises(SystemExit):
            apply_check.bundle_sql(st, "not-a-uuid", "p", "", "c")

    def test_simulated_state_round_trips_dates(self):
        st = apply_check.simulate_state()
        for w in st["waivers"]:
            self.assertRegex(w["review_by"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual([w["id"] for w in st["waivers"]], sorted(w["id"] for w in st["waivers"]))


class Health(unittest.TestCase):
    """apply_check.py health: iampolicy's rows of design §14.4.14."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.chmod(self.d, 0o700)
        self.host = os.path.join(self.d, "policy-applied.yaml")
        self.st = apply_check.simulate_state()
        self.st.update(last_apply_event={"event": "bootstrap_applied", "event_id": 42, "at": "x"}, chain_ok=True,
                       unconfirmed=[{"version": 1, "kind": "bootstrap", "status": "applied"}])

    def tearDown(self):
        shutil.rmtree(self.d)

    def write_host(self, text=None):
        with open(self.host, "w") as f:
            f.write(text or source.host_file_text(self.st, "unknown", "2026-11-02T00:00:00Z"))

    def levels(self, **kw):
        return [l for l, _ in apply_check.health(self.st, self.host, **kw)]

    def test_ok_before_confirmation_is_possible(self):
        self.write_host()
        out = apply_check.health(self.st, self.host)
        self.assertEqual(out, [("OK", "version 1 (bootstrap), qa confirms it in the Policy UI once it exists (IAM 4.3)")])
        self.assertIn("WARN", self.levels(policy_port="true"))

    def test_a_forged_body_fails(self):
        self.write_host()
        forged = dict(self.st)
        forged["entries"] = [e for e in self.st["entries"] if not (e["role"] == "admin" and e["group_code"] == "iam_users")]
        rows = source.state_rows(forged)
        forged["entries_digest"] = source.entries_digest("bootstrap", forged["groups"], forged["roles"],
                                                         rows["entries"], rows["waivers"])
        text = source.host_file_text(forged, "unknown", "2026-11-02T00:00:00Z")
        # keep line 1 of the genuine file: a consistent forgery of the body only
        genuine = source.host_file_text(self.st, "unknown", "2026-11-02T00:00:00Z").split("\n", 1)[0]
        self.write_host(genuine + "\n" + text.split("\n", 1)[1])
        out = apply_check.health(self.st, self.host)
        self.assertIn("FAIL", [l for l, _ in out])

    def test_empty_with_008c_fails(self):
        out = apply_check.health(empty_state(), self.host)
        self.assertEqual(out[0][0], "FAIL")
        self.assertIn("no applied version", out[0][1])
        self.assertEqual(apply_check.health({"state": "none", "detail": "no 008c"}, self.host)[0][0], "SKIP")

    def test_a_past_widening_accept_fails(self):
        self.write_host()
        body = source.skeleton(source.factory())
        wider = json.loads(json.dumps(body))
        wider["public_routes"] = list(wider.get("public_routes") or []) + [
            {"service": "monitor", "route": "GET /api/test-public", "why": "test"}]
        self.st["accepts"] = [{"event_id": 7, "from": "a" * 64, "to": "b" * 64, "from_body": body, "to_body": wider,
                               "version": 1, "entries": self.st["entries"], "waivers": self.st["waivers"],
                               "reviewed_by_version": None}]
        out = apply_check.health(self.st, self.host)
        self.assertTrue(any(l == "FAIL" and "was accepted at event 7 but widens" in d for l, d in out), out)
        self.st["accepts"][0]["reviewed_by_version"] = 2
        self.assertIn("FAIL", self.levels())        # IAM 4.5: a bare reviewed_by_version is recomputed
        self.st["accepts"][0].update(rv_kind="skeleton", rv_status="applied", rv_skeleton="b" * 64)
        self.assertNotIn("FAIL", self.levels())

    def test_break_glass_open_per_component(self):
        self.write_host()
        self.st["break_glass_open"] = [{"event_id": 9, "reason": "r", "components": ["iam", "monitor"], "open": ["monitor"]}]
        out = apply_check.health(self.st, self.host)
        self.assertTrue(any(l == "FAIL" and "still open for monitor" in d for l, d in out), out)

    def test_apply_started_running_or_not(self):
        self.write_host()
        self.st["last_apply_event"] = {"event": "apply_started", "event_id": 40, "at": "x"}
        self.assertIn("FAIL", self.levels(holders=""))
        # a holder of the lock (a guide-held lock's child) whose command line is apply.sh
        p = subprocess.Popen(["bash", "-c", "sleep 30; :", "apps/iam/apply.sh"])
        try:
            out = apply_check.health(self.st, self.host, holders=f"{os.getpid()} {p.pid}")
            self.assertIn(("WARN", "an apply is in progress"), out)
        finally:
            p.kill()
            p.wait()

    def test_queued_seed_facts_warn(self):
        self.write_host()
        with open(os.path.join(self.d, "seed-facts.jsonl"), "w") as f:
            f.write(json.dumps(apply_check.seed_fact("observed", "quinn", QA, "qa", "p-qa")) + "\n")
        out = apply_check.health(self.st, self.host)
        self.assertIn(("WARN", "1 account fact(s) not yet recorded: the next deploy flushes them"), out)

    def test_waiver_review(self):
        import datetime
        self.write_host()
        self.st["waivers_review"] = [{"id": "W1", "review_by": "2026-01-01"}, {"id": "W2", "review_by": "2026-11-20"}]
        out = apply_check.health(self.st, self.host, today=datetime.date(2026, 11, 2))
        self.assertIn("FAIL", [l for l, d in out if "W1" in d])
        self.assertIn("WARN", [l for l, d in out if "W2" in d])

    def test_reverted_decisions_not_reviewed_warn(self):
        """§14.4.14 WARN: apply_reverted decisions not yet reviewed (the state document's
        reverted_unreviewed, only revert events with an unreviewed decision listed)."""
        self.write_host()
        self.st["reverted_unreviewed"] = [{"event_id": 77, "version": 2, "at": "x", "unreviewed": 3}]
        out = apply_check.health(self.st, self.host)
        warn = [d for l, d in out if l == "WARN" and "event 77" in d]
        self.assertEqual(len(warn), 1, out)
        self.assertIn("3 account decision(s) made while version 2 was applied are not reviewed", warn[0])
        self.assertNotIn("FAIL", [l for l, _ in out])
        self.st["reverted_unreviewed"] = []
        self.assertEqual(self.levels(), ["OK"])

    def test_state_query_lists_reverted_decisions_only_with_the_access_schema(self):
        """The --full state query asks iam.account_decision only behind psql's \\if (the
        access component may be absent), and counts the decisions still 'applied' between
        the reverted version's apply event and the revert."""
        r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-policy-source.sh"; _ps_state_sql true'],
                           capture_output=True, text=True, env=clean_env())
        sql = r.stdout
        self.assertIn("to_regclass('iam.account_decision') IS NOT NULL AS has_decisions \\gset", sql)
        i, j = sql.index("\\if :has_decisions"), sql.index("\\else\nSELECT '[]' AS reverted_unreviewed")
        self.assertIn("iam.account_decision", sql[i:j])
        self.assertNotIn("iam.account_decision d", sql[:i] + sql[j:])
        self.assertIn("d.status = 'applied'", sql[i:j])
        self.assertIn("h.event = 'apply_reverted'", sql[i:j])
        self.assertIn("'reverted_unreviewed', :'reverted_unreviewed'::jsonb", sql)
        self.assertNotIn("reverted_unreviewed", subprocess.run(
            ["bash", "-c", f'source "{REPO}/infra/lib-policy-source.sh"; _ps_state_sql false'],
            capture_output=True, text=True, env=clean_env()).stdout)


class SeedFacts(unittest.TestCase):
    def test_fact_id_is_the_content_hash(self):
        f = apply_check.seed_fact("person_id_set", "quinn", QA, None, QA)
        self.assertIsNone(f["role"])
        self.assertEqual(f["fact_id"], source.fact_id(f))
        g = apply_check.seed_fact("person_id_set", "quinn", QA, None, QA, at="2030-01-01T00:00:00Z")
        self.assertEqual(f["fact_id"], g["fact_id"])     # when and by whom are not content
        self.assertTrue(f["person_id_set"] and not f["created"] and not f["observed"])

    def test_queue_needs_the_lock_and_writes_600(self):
        root = scratch_repo("medcea-seed-")
        try:
            fact = json.dumps(apply_check.seed_fact("created", "quinn", QA, "qa", None))
            inp = os.path.join(root, "facts.jsonl")
            with open(inp, "w") as f:
                f.write(fact + "\n")
            py = os.path.join(root, "apps/iam/apply_check.py")
            p = subprocess.run([sys.executable, py, "seed-queue", "--in", inp], capture_output=True, text=True,
                               env=clean_env())
            self.assertEqual(p.returncode, 2)
            self.assertIn("deploy lock", p.stderr)
            lock = os.path.join(root, "infra", "lib-lock.sh")
            p = subprocess.run(["bash", "-c", f'source "{lock}"; medcea_lock; python3 "{py}" seed-queue --in "{inp}"; '
                                              f'python3 "{py}" seed-queue --in "{inp}"'],
                               capture_output=True, text=True, env=clean_env())
            self.assertEqual(p.returncode, 0, p.stderr)
            q = os.path.join(root, "state", "seed-facts.jsonl")
            self.assertEqual(stat.S_IMODE(os.stat(q).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(q)).st_mode), 0o700)
            self.assertEqual(len(source.seed_lines(q)), 2)     # appended; _record dedups by content
            with open(inp, "w") as f:
                f.write('{"fact": "created", "username": "x", "sub": "y", "fact_id": "' + "0" * 64 + '"}\n')
            p = subprocess.run(["bash", "-c", f'source "{lock}"; medcea_lock; python3 "{py}" seed-queue --in "{inp}"'],
                               capture_output=True, text=True, env=clean_env())
            self.assertEqual(p.returncode, 2)
        finally:
            shutil.rmtree(root)


class ExportApplied(unittest.TestCase):
    """cli.py export-applied: parsed, it is the applied matrix and waivers; every byte outside
    matrix: and waivers: is defaults.yaml's."""

    def test_round_trip(self):
        root = scratch_repo("medcea-export-")
        try:
            os.mkdir(os.path.join(root, "state"), 0o700)
            st = apply_check.simulate_state()
            with open(os.path.join(root, "state", "policy-applied.yaml"), "w") as f:
                f.write(source.host_file_text(st, "unknown", "2026-11-02T00:00:00Z"))
            p = subprocess.run([sys.executable, os.path.join(root, "apps/iam/compiler/cli.py"), "export-applied"],
                               capture_output=True, text=True, env=clean_env())
            self.assertEqual(p.returncode, 0, p.stderr)
            import yaml
            out = yaml.safe_load(p.stdout)
            composed, _ = source.compose_applied(st)
            self.assertEqual(out["matrix"], composed["matrix"])
            self.assertEqual([source.waiver_row(w) for w in out["waivers"]], [source.waiver_row(w) for w in composed["waivers"]])
            sys.path.insert(0, os.path.join(REPO, "apps", "iam", "compiler"))
            from compiler import cli
            with open(source.DEFAULTS) as f:
                orig = f.read().splitlines(keepends=True)
            new = p.stdout.splitlines(keepends=True)
            bo, bn = cli._top_blocks(orig), cli._top_blocks(new)
            for key in bo:
                if key in ("matrix", "waivers"):
                    continue
                self.assertEqual(orig[bo[key][0]:bo[key][1]], new[bn[key][0]:bn[key][1]], key)
        finally:
            shutil.rmtree(root)


class Wiring(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            return f.read()

    def test_no_signal_gap_once_a_bundle_committed(self):
        """on_signal reads BUNDLE_SENT, then VERSION/PHASE: a committed bundle sets VERSION
        (forward) or PHASE=reverting (the revert) before BUNDLE_SENT is cleared, so a signal
        between the COMMIT and the caller never reads as "nothing was changed" (exit 130)."""
        s = self.read("apps/iam/apply.sh")
        rb = s[s.index("run_bundle() {"):s.index("bundle_committed() {")]
        self.assertIn("if ((rc == 0)); then\n        bundle_committed\n        return 0", rb)
        bc = s[s.index("bundle_committed() {"):s.index("pa_json() {")]
        self.assertLess(bc.index('VERSION="$BUNDLE_TARGET" PHASE=forward'), bc.index('BUNDLE_SENT=""'))
        self.assertLess(bc.index("PHASE=reverting"), bc.index('BUNDLE_SENT=""'))
        # the revert phase starts only once the revert committed
        rev = s[s.index("# the revert (design §14.8.6)"):s.index("post_state \"$PREV\"")]
        self.assertNotIn("PHASE=reverting", rev)

    def test_apply_is_an_entry_script(self):
        s = "\n".join(l for l in self.read("apps/iam/apply.sh").splitlines() if not l.lstrip().startswith("#"))
        self.assertLess(s.index("medcea_log apply-policy"), s.index("medcea_lock"))
        self.assertIn('source "$REPO_ROOT/infra/lib-policy-source.sh"', s)
        self.assertIn("medcea_lock_verify", s)
        self.assertNotRegex(s, r"--password|client_secret=|Bearer \$")       # no secret in argv

    def test_iam_deploy_bootstraps_before_iam_api(self):
        s = self.read("apps/iam/deploy.sh")
        self.assertLess(s.index('"$SCRIPT_DIR/apply.sh" --bootstrap'), s.index("# iam-api (IAM 3.5)"))
        self.assertLess(s.index("policy_source_init \"$NAMESPACE\" || exit $?"), s.index("Policy versions..."))
        self.assertIn('MEDCEA_POLICY_BOOTSTRAP_BY:-$ADMIN_USER', s)
        # skip_api, --gate-only (IAM 4.3) and the success path
        self.assertEqual(s.count("policy_source_finish \"$NAMESPACE\" iam"), 3)

    def test_deploy_infra_records_or_queues_seed_facts(self):
        s = self.read("deploy-infra.sh")
        a = s.index("Setting person_id on enabled accounts")
        b = s.index("account_seeded \"$_line\"")
        self.assertLess(a, b)
        self.assertIn("seed-queue --in /dev/stdin", s)
        self.assertIn("_seed_fact created", s)
        self.assertIn("_seed_fact person_id_set", s)
        self.assertIn("_seed_fact observed", s)
        self.assertIn("*skip-4.1*", s)


# ── IAM 4.5: applying an approved version (design §14.8.11) ─────────────────────────
# A fixed 2048-bit RSA test key (public modulus, private exponent; e = 65537) and a compact JWS
# it signed: the verifier is tested with no `cryptography`. The private exponent signs the
# test tokens below with pow() alone (PKCS#1 v1.5 is deterministic). Never a realm key.
N_HEX = ("b1cede3946d4250c55f1bb5a49441172694c9553973037af890d289d303104ea72799d2e77a794f2176138a813736ea7ed83186dacfaa"
         "fa785d3fbfb48af8082c505a64d74a93f1db51cbed03b960903df09f77e481d7eee226877407c80e1b7bec36cfb84184e59dfcf3fbb8eb6"
         "3aecbd8f75c31f3a1157f7faec8d57d2486e2179278b72ebb3214e7c19d9b43aa14588b38ce0710200da10b353b584f96a663a3e6843e8e"
         "ec23ab0440802ec0c5d239c4a6eb3518e3a6f8fc1c8b10e6700d8859a5dc99fb39d92e016f9ffaa4b1ef200c7a435313584635ece515c9e"
         "8c3fb932379be48470b919914591af2473a0a0b4302ab2f33455871277e0014e8a6a85")
D_HEX = ("3113fc855566310e5a9a97daafe6633a6fe8d23ecf0db6bbc8d9ccf560dbe6e8ca22d9f3d2d5d012e7c924ae4a7ace21a3e3fa2b810220d"
         "7333a9e8ec432a25ccb57bd337144009bde9074a00812684d47e9a45a983a8152919a16c5c1ed2bb5b5533e6848bf1216a9e40bf4ba762a3"
         "0363d1185836a5a672c422266511b45ca4905d7786c652016543b5a0903709d87af8cc9e0e702e7a092271e54668c169f56a9782323086e2"
         "066a03c41483a07c003ac4571be51087d66476ce08807b86257ebec26b1adacf2a5e583712b68dd3c450ee31baea3041355cfe21505bf5f2"
         "e7e7372adfc044d890c02dedf8dd3f07cda1a7a449f14d3c1175c33f15735179")
VECTOR_JWS = ("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIyMjIyMjIyMi0yMjIyLTQyMjItODIyMi0yMj"
              "IyMjIyMjIyMjIiLCJqdGkiOiJ2ZWN0b3ItanRpIiwiaWF0IjoxNzkzNzg2NDAwLCJleHAiOjE3OTM3ODY3MDB9.TYSfv-nH05-HcbHd8wwCHtg"
              "ZoGEq2-vvh60iXBgb5e8irOv0JbaD_VOTvWszi5Z-mwcIbSCxIE4x8sM94ITXsKAUNPPMskS7qhTJqJj535cjLjP8_qQMblk4578TAbVev9RrMP"
              "QagIG8N57Fo38cY0k3ThQBqP6f4-IU9voN5zf8to97VoeRJYKrctmVdMHDddLrSFTFXS7omkN7aoz9y8n0i1gchsxcuadyzueqE4LrXfaIoUN1Z"
              "uk6jEg5K4eTUts_pTj_Tt0OUY9YqfdjSGGZiID_qON7Y4qeGZXH2LIw8DLycvx7JihLe1vfjfS1ishT9Ln7bYbedaBuOPgOgg")
KID = "test-key-1"
KEY_N, KEY_D = int(N_HEX, 16), int(D_HEX, 16)
IAT = 1793786400                                  # 2026-11-04T10:00:00Z
APPROVED_AT = "2026-11-04T10:00:05+00:00"
ISSUER_T = "https://keycloak.example.test/realms/medcea"   # config.env's DOMAIN=example.test
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
ADMIN2 = "44444444-4444-4444-8444-444444444444"
QA2 = "55555555-5555-4555-8555-555555555555"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def int_b64(i):
    return b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))


JWKS = {"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": int_b64(KEY_N), "e": "AQAB"},
                 {"kty": "RSA", "kid": "enc-1", "use": "enc", "alg": "RSA-OAEP", "n": int_b64(KEY_N), "e": "AQAB"}]}


def sign(claims, kid=KID, alg="RS256", n=KEY_N, d=KEY_D):
    """A compact JWS signed RS256 with pow() (the test key's private exponent)."""
    h = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    k = (n.bit_length() + 7) // 8
    t = DIGEST_INFO_SHA256 + hashlib.sha256(f"{h}.{p}".encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return f"{h}.{p}.{b64u(pow(int.from_bytes(em, 'big'), d, n).to_bytes(k, 'big'))}"


def qa_claims(jti="jti-2", **over):
    c = {"sub": QA, "person_id": "p-qa", "jti": jti, "iat": IAT, "exp": IAT + 300, "azp": "policy",
         "aud": ["medcea-api", "account"], "typ": "Bearer", "iss": ISSUER_T,
         "groups": ["qa", "auditor", "default-roles-medcea"]}
    c.update(over)
    return c


def change_version(st, n=2, cell=("device_history", "maintenance"), claims=None, jti="jti-2", other=(), **v_over):
    """(version document, state once applied) of change version n: version st's rows with one
    cell removed (maintenance's R on device_history: a narrowing no account holds), approved by quinn with a
    token signed by the test key, as approval-sql's document carries it."""
    import copy as _copy
    entries = [e for e in st["entries"] if (e["group_code"], e["role"]) != cell]
    waivers = _copy.deepcopy(st["waivers"])
    rows = source.state_rows({"entries": entries, "waivers": waivers})
    ed = source.entries_digest("change", st["groups"], st["roles"], rows["entries"], rows["waivers"])
    v = {"version": n, "kind": "change", "status": "approved", "based_on": st["version"], "groups": st["groups"],
         "roles": st["roles"], "entries_digest": ed, "skeleton_digest": None,
         "approved_skeleton_digest": st["accepted"]["digest"], "approved_by_sub": QA, "approved_by_person": "p-qa",
         "approved_by_name": "quinn", "approved_at": APPROVED_AT, "approved_iat": IAT, "confirmed_at": None,
         "disputed_at": None, "rollback_of": None, "reason": "test: narrow maintenance"}
    v["diff_digest"] = hashlib.sha256(source.canonical(apply_check.change_doc(
        st, {"version": v, "entries": entries, "waivers": waivers}))).hexdigest()
    v.update(v_over)
    c = claims if claims is not None else qa_claims(jti)
    jws = sign(c)
    ev = {"version": n, "source": "token", "role": "qa", "person": "p-qa", "sub": QA, "iat": IAT, "jti": c.get("jti"),
          "azp": "policy", "entries_digest": ed, "diff_digest": v["diff_digest"],
          "skeleton_digest": st["accepted"]["digest"], "jws_sha256": hashlib.sha256(jws.encode()).hexdigest()}
    doc = {"version": v, "entries_digest_sql": ed, "applied_version": st["version"],
           "approval": {"event": {"event_id": 60, "payload": ev, "actor_name": "quinn"},
                        "evidence": {"jws": jws, "claims": c}, "other_approved": list(other),
                        "other_approved_jti": [o["jti"] for o in other]},
           "authors": [{"sub": ADMIN, "person": "p-admin"}], "entries": entries, "waivers": waivers, "diff": None,
           "skeletons": {st["accepted"]["digest"]: {"body": st["accepted"]["body"], "git_commit": "unknown"}},
           "apply_started": None, "audit_findings": [], "pending": []}
    post = dict(st, state=f"version-{n}", version=n, kind="change", status="applied", entries_digest=ed,
                entries=entries, waivers=waivers, based_on=st["version"], last_apply_event=None)
    return doc, post


def kc_dir(d, users_, approver=QA, approver_roles=("qa",), authors=(), composites=None):
    """A Keycloak dump laid out as apply.sh's kc_dump writes it."""
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "users"))
    os.makedirs(os.path.join(d, "authors"))
    os.makedirs(os.path.join(d, "composites"))
    skel = source.skeleton(source.factory())
    with open(os.path.join(d, "skeleton.json"), "w") as f:
        json.dump(skel, f)
    for role in skel["roles"]:
        with open(os.path.join(d, f"{role}.json"), "w") as f:
            json.dump([{"id": u["id"], "username": u["username"], "enabled": u["enabled"]}
                       for u in users_ if role in u.get("roles", [])], f)
    for u in users_:
        with open(os.path.join(d, "users", f"{u['id']}.json"), "w") as f:
            json.dump({k: v for k, v in u.items() if k != "roles"}, f)
        if u["id"] == approver:
            with open(os.path.join(d, "approver.json"), "w") as f:
                json.dump({k: v for k, v in u.items() if k != "roles"}, f)
            with open(os.path.join(d, "approver-roles.json"), "w") as f:
                json.dump([{"name": r} for r in approver_roles], f)
        if u["id"] in authors:
            with open(os.path.join(d, "authors", f"{u['id']}.json"), "w") as f:
                json.dump({k: v for k, v in u.items() if k != "roles"}, f)
    comps = composites if composites is not None else {"qa": ["auditor"], "production_manager": ["operator"]}
    for r, inc in comps.items():
        with open(os.path.join(d, "composites", f"{r}.json"), "w") as f:
            json.dump([{"name": x, "clientRole": False} for x in inc], f)


class Rs256Vector(unittest.TestCase):
    """apply_check.verify_rs256 (design §14.8.5), stdlib only, against literals."""

    def test_the_vector_verifies(self):
        hdr, claims, jwk = apply_check.verify_rs256(VECTOR_JWS, JWKS)
        self.assertEqual((hdr["alg"], hdr["kid"]), ("RS256", KID))
        self.assertEqual((claims["sub"], claims["jti"], claims["iat"]), (QA, "vector-jti", IAT))
        self.assertEqual(jwk, {"kid": KID, "n": JWKS["keys"][0]["n"], "e": "AQAB"})
        self.assertEqual(apply_check.signing_keys(JWKS)["keys"][0]["kid"], KID)
        self.assertEqual(len(apply_check.signing_keys(JWKS)["keys"]), 1)       # the encryption key is no signer
        # the test signer reproduces the vector byte for byte (PKCS#1 v1.5 is deterministic)
        h, p, _ = VECTOR_JWS.split(".")
        self.assertEqual(sign(json.loads(base64.urlsafe_b64decode(p + "==")), kid=KID), VECTOR_JWS)

    def refused(self, jws, jwks=None, cls=apply_check.JwsError):
        with self.assertRaises(cls) as cm:
            apply_check.verify_rs256(jws, jwks or JWKS)
        return str(cm.exception)

    def test_refusals(self):
        h, p, s = VECTOR_JWS.split(".")
        sig = bytearray(base64.urlsafe_b64decode(s + "=="))
        sig[-1] ^= 1
        self.assertIn("does not verify", self.refused(f"{h}.{p}.{b64u(bytes(sig))}"))
        claims = json.loads(base64.urlsafe_b64decode(p + "=="))
        p2 = b64u(json.dumps(dict(claims, jti="vector-jtj"), separators=(",", ":")).encode())
        self.assertIn("does not verify", self.refused(f"{h}.{p2}.{s}"))
        for alg in ("none", "HS256"):
            h2 = b64u(json.dumps({"alg": alg, "kid": KID}).encode())
            self.assertIn("is not RS256", self.refused(f"{h2}.{p}.{s}"))
        self.assertIn("is not RS256", self.refused(f"{b64u(json.dumps({'alg': 'none'}).encode())}.{p}.x"))
        e = self.refused(sign(claims, kid="rotated"), cls=apply_check.UnknownKid)
        self.assertEqual(e, "rotated")
        short = base64.urlsafe_b64decode(s + "==")[1:]
        self.assertIn("malformed", self.refused(f"{h}.{p}.{b64u(short)}"))
        big = (KEY_N + 1).to_bytes(256, "big")
        self.assertIn("malformed", self.refused(f"{h}.{p}.{b64u(big)}"))
        self.assertIn("not a compact JWS", self.refused(f"{h}.{p}"))
        self.assertIn("base64url", self.refused(f"{h}.{p}.{s}=="))

    def test_cross_check_with_cryptography(self):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
        except ImportError:
            self.skipTest("cryptography is not installed")
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n, d = k.public_key().public_numbers().n, k.private_numbers().d
        jwks = {"keys": [{"kty": "RSA", "kid": "x", "use": "sig", "alg": "RS256", "n": int_b64(n), "e": "AQAB"}]}
        jws = sign(qa_claims(), kid="x", n=n, d=d)
        h, p, s = jws.split(".")
        theirs = k.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(base64.urlsafe_b64decode(s + "=="), theirs)
        self.assertEqual(apply_check.verify_rs256(jws, jwks)[1]["jti"], "jti-2")
        k.public_key().verify(theirs, f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())


class CheckApproval(unittest.TestCase):
    """Step 4 (design §14.8.4, §14.8.5) against a fake Keycloak dump and version document;
    the stage (both compiles) is built once."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="medcea-check-")
        cls.st = applied_state()
        cls.doc, _ = change_version(cls.st)
        rc, lines = apply_check.stage(cls.st, cls.doc, os.path.join(cls.d, "stage"), "unknown")
        assert rc == 0, lines

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def check(self, doc=None, users_=None, jwks=None, stage=None, mode="apply", **kc):
        k = os.path.join(self.d, "kc")
        kc.setdefault("authors", (ADMIN,))
        kc_dir(k, users_ if users_ is not None else users(), **kc)
        return apply_check.check_approval(doc or self.doc, k, jwks or JWKS, stage or os.path.join(self.d, "stage"),
                                          ISSUER_T, mode, 2, state=self.st)

    def refusals(self, *a, **kw):
        return self.check(*a, **kw)[0]

    def assertRefused(self, text, *a, **kw):
        r = self.refusals(*a, **kw)
        self.assertTrue(any(text in x for x in r), r)

    def variant(self, claims=None, ev=None, v=None, evidence=None, **kw):
        import copy as _copy
        doc, _ = change_version(self.st, claims=claims, **kw)
        doc = _copy.deepcopy(doc)
        doc["approval"]["event"]["payload"].update(ev or {})
        doc["version"].update(v or {})
        doc["approval"]["evidence"].update(evidence or {})
        return doc

    def test_a_clean_approval(self):
        r, w, notes, info = self.check()
        self.assertEqual((r, w), ([], []))
        self.assertEqual(info["jwk"]["kid"], KID)
        self.assertEqual(info["event_id"], 60)

    def test_evidence(self):
        self.assertRefused("is not from a token", self.variant(ev={"source": "deploy"}))
        self.assertRefused("is not the one its approved event hashed", self.variant(ev={"jws_sha256": "0" * 64}))
        self.assertRefused("claims are not the ones recorded",
                           self.variant(evidence={"claims": dict(qa_claims(), extra=1)}))
        # PostgREST's request.jwt.claims carries the role it took (C1: anon) and nothing else
        self.assertEqual(self.refusals(doc=self.variant(evidence={"claims": dict(qa_claims(), role="anon")})), [])
        self.assertRefused("claims are not the ones recorded",
                           self.variant(evidence={"claims": dict(qa_claims(), role="rr_qa")}))
        cr = apply_check.claims_recorded
        self.assertTrue(cr({"a": 1}, '{"a": 1, "role": "anon"}'))
        self.assertFalse(cr({"a": 1, "role": "x"}, {"a": 1, "role": "anon"}))   # the token's own role is compared
        self.assertFalse(cr({"a": 1}, {"a": 1, "role": "anon", "b": 2}))
        self.assertFalse(cr({"a": 1}, None))
        self.assertRefused("no longer published: withdraw version 2 and draft again",
                           jwks={"keys": [dict(JWKS["keys"][0], kid="rotated")]})

    def test_claims(self):
        for over, text in (({"iat": IAT + 40, "exp": IAT + 340}, "iat is not approved_iat"),
                           ({"exp": IAT - 40}, "outside its token's lifetime"),
                           ({"typ": "ID"}, "typ is 'ID'"),
                           ({"iss": "https://evil.test/realms/medcea"}, "iss is"),
                           ({"azp": "config"}, "not the policy host's client 'policy'"),
                           ({"aud": "account"}, "aud lacks medcea-api"),
                           ({"person_id": "p-other"}, "person_id is not approved_by_person"),
                           ({"groups": ["qa", "admin"]}, "own role")):
            with self.subTest(over):
                self.assertRefused(text, self.variant(claims=qa_claims(**over)))
        # iat after approved_at + 30: the token was issued after the approval was recorded
        late = IAT + 40
        self.assertRefused("outside its token's lifetime",
                           self.variant(claims=qa_claims(iat=late, exp=late + 300), ev={"iat": late}, v={"approved_iat": late}))

    def test_eligibility_now(self):
        u = users()
        self.assertRefused("is disabled now", users_=[dict(x, enabled=x["id"] != QA) for x in u])
        self.assertRefused("no longer holds an approver role", approver_roles=("auditor",))
        # the role held only through a composite: Keycloak's effective roles name it, accepted
        self.assertEqual(self.refusals(approver_roles=("qa-lead", "qa", "auditor")), [])
        pid = [dict(x, attributes={"person_id": ["p-new"]}) if x["id"] == QA else x for x in u]
        self.assertRefused("person_id is not the approved person", users_=pid)
        self.assertRefused("the approver's account (", users_=[x for x in u if x["id"] != QA] + [], approver="none")

    def test_authors(self):
        doc = self.variant()
        doc["authors"] = [{"sub": QA, "person": None}]
        self.assertRefused("is an author", doc)
        doc["authors"] = [{"sub": ADMIN2, "person": "p-qa"}]
        self.assertRefused("is an author", doc)
        # an author account whose person_id became the approver's since it authored
        doc["authors"] = [{"sub": ADMIN2, "person": "p-old"}]
        u = users() + [{"id": ADMIN2, "username": "alex", "enabled": False, "attributes": {"person_id": ["p-qa"]},
                        "roles": []}]
        self.assertRefused("is an author", doc, users_=u, authors=(ADMIN2,))

    def test_i17_a_maker_of_the_same_person(self):
        twin = {"id": ADMIN2, "username": "quinn-admin", "enabled": True, "attributes": {"person_id": ["p-qa"]},
                "roles": ["admin"]}
        self.assertRefused("holds the enabled maker account quinn-admin (I17)", users_=users() + [twin])
        self.assertEqual(self.refusals(users_=users() + [dict(twin, enabled=False)]), [])   # OA-b: disabled is fine

    def test_no_account_decision_is_consulted(self):
        # a seeded QA_USER with no decision of its own passes: Keycloak now is the rule
        st = dict(self.st, seeded={QA: [{"event_id": 9, "fact": "observed", "username": "quinn", "role": "qa",
                                         "person_id": "p-qa"}]})
        k = os.path.join(self.d, "kc")
        kc_dir(k, users(), authors=(ADMIN,))
        r, _, notes, _ = apply_check.check_approval(self.doc, k, JWKS, os.path.join(self.d, "stage"), ISSUER_T,
                                                    "apply", 2, state=st)
        self.assertEqual(r, [])
        self.assertIn("event 9 observed quinn", " ".join(notes))
        self.assertNotIn("account_decision", apply_check.approval_doc_sql(2).split("'pending'")[0].split("\\endif")[1])

    def test_composites(self):
        self.assertRefused("Keycloak's role qa includes nothing", composites={"production_manager": ["operator"]})
        acc = source.skeleton(source.factory())
        prop = json.loads(json.dumps(acc))
        prop["roles"]["qa"]["includes"] = ["auditor", "operator"]
        k = os.path.join(self.d, "kc")
        kc_dir(k, users())
        self.assertTrue(any("changes role composites" in x for x in apply_check.composite_problems(k, acc, prop)))
        self.assertEqual(apply_check.composite_problems(k, acc, acc), [])

    def test_the_approvers_person_widened(self):
        """S-B4: another enabled account of the approver's person holds a role version N widens."""
        p1 = model.Policy(source.read_host_file(os.path.join(self.d, "stage", "prev.yaml")).data)
        data = json.loads(json.dumps(p1.data))
        data["matrix"]["master_data"]["qp"] = ["R", "C"]
        p2 = model.Policy(data)
        acc = [{"sub": QA, "username": "quinn", "enabled": True, "roles": ["auditor", "qa"], "person_id": "p-qa"},
               {"sub": QA2, "username": "quinn-qp", "enabled": True, "roles": ["qp"], "person_id": "p-qa"}]
        out = apply_check.person_widening_problems(self.doc, acc, p1, p2, 2)
        self.assertEqual(len(out), 1)
        self.assertIn("widens role qp, which quinn-qp (an enabled account of the approver's person) holds", out[0])
        acc[1]["enabled"] = False
        self.assertEqual(apply_check.person_widening_problems(self.doc, acc, p1, p2, 2), [])

    def test_the_approvers_person_holds_a_new_role(self):
        """S-B4: a role version N adds, held in Keycloak by another enabled account of the
        approver's person, widens it by its whole reach (absent from the applied policy)."""
        p1 = model.Policy(source.read_host_file(os.path.join(self.d, "stage", "prev.yaml")).data)
        data = json.loads(json.dumps(p1.data))
        data["roles"]["lab_lead"] = json.loads(json.dumps(data["roles"]["qp"]))
        if "db_role" in data["roles"]["lab_lead"]:
            data["roles"]["lab_lead"]["db_role"] = "rr_lab_lead"
        data["matrix"]["master_data"]["lab_lead"] = ["R"]
        p2 = model.Policy(data)
        self.assertNotIn("lab_lead", p1.roles)
        acc = [{"sub": QA, "username": "quinn", "enabled": True, "roles": ["auditor", "qa"], "person_id": "p-qa"},
               {"sub": QA2, "username": "quinn-lead", "enabled": True, "roles": ["lab_lead"], "person_id": "p-qa"}]
        out = apply_check.person_widening_problems(self.doc, acc, p1, p2, 2)
        self.assertEqual(len(out), 1)
        self.assertIn("widens role lab_lead, which quinn-lead", out[0])

    def test_someone_can_still_approve(self):
        u = [x for x in users() if x["id"] != ADMIN]            # no maker left
        self.assertRefused("after version 2: no enabled account holds a maker role of iam_policy", users_=u)
        r, w, _, _ = self.check(users_=u, mode="rollback")
        self.assertEqual(r, [])
        self.assertTrue(any("after this rollback: no enabled account holds a maker role" in x for x in w), w)

    def test_jti_replay(self):
        self.assertRefused("was also used to approve version 5", self.variant(other=[{"version": 5, "jti": "jti-2"}]))
        # confirm, return and dispute evidence never reaches other_approved (one session's token)
        sql = apply_check.approval_doc_sql(2)
        self.assertIn("FROM iam_policy.approval_evidence o WHERE o.event = 'approved' AND o.version <> 2", sql)
        self.assertEqual(self.refusals(self.variant(other=[{"version": 5, "jti": "jti-other"}])), [])

    def test_azp_from_the_applied_compile(self):
        stage = os.path.join(self.d, "stage-azp")
        shutil.rmtree(stage, ignore_errors=True)
        shutil.copytree(os.path.join(self.d, "stage"), stage)
        path = os.path.join(stage, "staged-outs", "grants-json.out")
        with open(path) as f:
            g = json.load(f)
        g["only_rpc"] = {"policy-renamed": g["only_rpc"]["policy"]}
        with open(path, "w") as f:
            json.dump(g, f)
        self.assertEqual(self.refusals(stage=stage), [])           # version N's own client is not the rule
        path = os.path.join(stage, "prev", "grants-json.out")
        with open(path, "w") as f:
            json.dump(g, f)
        self.assertRefused("not the policy host's client 'policy-renamed'", stage=stage)
        g["only_rpc"] = {}
        with open(path, "w") as f:
            json.dump(g, f)
        with self.assertRaises(source.SourceError):
            self.check(stage=stage)


class FakeCur:
    """policy_api's cursor for change_diff: the rows of two versions, in iam-api's order."""

    def __init__(self, versions, applied):
        self.v, self.applied, self.res, self.description = versions, applied, None, None

    def execute(self, sql, args=()):
        s = " ".join(sql.split())
        if s.startswith("SELECT version FROM iam_policy.version WHERE status = 'applied'"):
            self.res = [(self.applied,)]
        elif s.startswith("SELECT entries_digest, status FROM iam_policy.version"):
            x = self.v[args[0]]
            self.res = [(x["entries_digest"], x["status"])]
        elif "FROM iam_policy.entry" in s:
            rows = sorted(self.v[args[0]]["entries"], key=lambda e: (e["role"], e["group_code"], e["level"]))
            self.description = [("role",), ("group_code",), ("level",), ("constraint_name",)]
            self.res = [(e["role"], e["group_code"], e["level"] + " " * 0, e["constraint_name"]) for e in rows]
        elif "FROM iam_policy.waiver" in s:
            import datetime as _dt
            cols = ("id", "invariant", "subject", "group_code", "target", "levels", "review_by", "rationale",
                    "controls", "objects")
            self.description = [(c,) for c in cols]
            self.res = [tuple(_dt.date.fromisoformat(w[c]) if c == "review_by" and w.get(c) else w.get(c) for c in cols)
                        for w in sorted(self.v[args[0]]["waivers"], key=lambda w: w["id"])]
        else:
            raise AssertionError(s)

    def fetchone(self):
        return self.res[0] if self.res else None

    def fetchall(self):
        return self.res


class ApplyDiffParity(unittest.TestCase):
    """Step 6 (design §14.8.4): the host's change document is byte for byte iam-api's."""

    def test_byte_identical_to_iam_api(self):
        import importlib
        import random
        os.environ["MEDCEA_COMPILER_DIR"] = os.path.join(REPO, "apps", "iam")
        pa = importlib.import_module("policy_api")
        st = applied_state()
        doc, _ = change_version(st)
        versions = {1: {"entries_digest": st["entries_digest"], "status": "applied", "entries": st["entries"],
                        "waivers": st["waivers"]},
                    2: {"entries_digest": doc["version"]["entries_digest"], "status": "approved",
                        "entries": doc["entries"], "waivers": doc["waivers"]}}
        b, digest, _, _ = pa.change_diff(FakeCur(versions, 1), {"version": 2, "status": "approved",
                                                                  "entries_digest": doc["version"]["entries_digest"]})
        # the state document's rows in another order (COLLATE "C", and shuffled): order-free
        shuffled = json.loads(json.dumps(doc))
        random.Random(7).shuffle(shuffled["entries"])
        shuffled["waivers"].reverse()
        st2 = json.loads(json.dumps(st))
        random.Random(9).shuffle(st2["entries"])
        mine = source.canonical(apply_check.change_doc(st2, shuffled))
        self.assertEqual(mine, b)
        self.assertEqual(hashlib.sha256(mine).hexdigest(), digest)
        self.assertEqual(digest, doc["version"]["diff_digest"])
        self.assertTrue(any(w.get("review_by") for w in st["waivers"]))   # dates as strings and as date objects

    def test_diff_check_refuses_a_moved_diff(self):
        st = applied_state()
        doc, _ = change_version(st, diff_digest="0" * 64)
        d = tempfile.mkdtemp()
        try:
            rc, lines = apply_check.diff_check(st, doc, d)
        finally:
            shutil.rmtree(d)
        self.assertEqual(rc, 1)
        self.assertIn("is not the one qa approved", lines[0])
        self.assertIn("withdraw it and draft again", lines[0])


class SummaryDetail(unittest.TestCase):
    """Step 6's summary names what moves (design §14.8.4): each changed host's admitted roles
    before → after, the tools' settings, MQTT rows per role, the NetworkPolicies that differ."""

    def test_before_and_after(self):
        def outs(roles, grafana, mqtt_rows, np_spec):
            return {"proxy-ACCESS_DOMAIN": (0, json.dumps(roles) + "\n", ""), "grafana": (0, grafana + "\n", ""),
                    "mqtt": (0, json.dumps({"roles": {"engineer": mqtt_rows}}), ""),
                    "netpol": (0, json.dumps({"items": [{"metadata": {"name": "iam-access"}, "spec": np_spec}]}), ""),
                    "routes": (0, "{}", "")}
        row = {"access": "read", "topic": "+/+/sense/#", "constraint": None}
        wrow = {"access": "write", "topic": "+/+/control/#", "constraint": "commissioning_unit"}
        a = outs(["admin", "qa"], "'Viewer'", [row], {"x": 1})
        b = outs(["admin", "auditor", "qa"], "'Editor'", [row, wrow], {"x": 2})
        lines = apply_check._changed_detail(a, b, ["grafana", "mqtt", "netpol", "proxy-ACCESS_DOMAIN"])
        self.assertIn("  host ACCESS_DOMAIN: admin, qa → admin, auditor, qa (+auditor)", lines)
        self.assertIn("  tool grafana: 'Viewer'\n    → 'Editor'", lines)
        self.assertIn("  mqtt engineer: + write +/+/control/# (commissioning_unit)", lines)
        self.assertIn("  netpol iam-access: changed", lines)
        self.assertEqual(apply_check._changed_detail(a, a, []), [])


class GateDecision(unittest.TestCase):
    """Step 2.4 (design §14.8.4): the gate's verdicts and the exception for exactly an approved
    skeleton version's digest (whose HEAD carries it)."""

    def setUp(self):
        self.st = applied_state()
        git = source.factory()
        self.skel = source.skeleton(git)
        self.digest = source.skeleton_digest(git)
        acc = dict(self.st["accepted"], digest="a" * 64)
        self.st["accepted"] = acc
        self.doc = {"version": {"version": 3, "kind": "skeleton", "status": "approved", "based_on": 1,
                                "skeleton_digest": self.digest},
                    "skeletons": {self.digest: {"body": json.loads(source.canonical(self.skel)), "git_commit": "c0ffee1"}},
                    "diff": {"diff": json.dumps({"skeleton": {"from": "a" * 64}}), "diff_digest": "d" * 64}}

    def decide(self, doc=None, rc=3, verdict="widening", mode="apply", head=True):
        return apply_check.gate_decision(self.st, doc or self.doc, {"verdict": verdict}, rc, mode, 3, head)

    def test_the_approved_skeleton_version_proceeds(self):
        rc, lines = self.decide()
        self.assertEqual(rc, 0, lines)
        self.assertIn("admitted as skeleton version 3", lines[0])
        rc, lines = self.decide(head=False)
        self.assertEqual(rc, 0)
        self.assertIn("is not an ancestor of HEAD", lines[-1])

    def test_refusals(self):
        import copy as _copy
        for change, text in ((("version", "status", "submitted"), "is submitted, not approved"),
                             (("version", "based_on", 0), "was approved on version 0"),
                             (("version", "kind", "change"), "is not a skeleton version"),
                             (("version", "skeleton_digest", "b" * 64), "is not the one version 3 proposes")):
            with self.subTest(text):
                d = _copy.deepcopy(self.doc)
                d[change[0]][change[1]] = change[2]
                rc, lines = self.decide(d)
                self.assertEqual(rc, 1)
                self.assertIn(text, lines[0])
        d = _copy.deepcopy(self.doc)
        d["skeletons"][self.digest]["body"]["about"] = "another body"
        self.assertIn("is not the body stored", self.decide(d)[1][0])
        d = _copy.deepcopy(self.doc)
        d["diff"]["diff"] = json.dumps({"skeleton": {"from": "c" * 64}})
        rc, lines = self.decide(d)
        self.assertEqual(rc, 1)
        self.assertIn("withdraw it and propose again", lines[0])
        self.assertEqual(self.decide(rc=0, verdict="narrowing")[0], 2)
        self.assertEqual(self.decide(rc=3, mode="rollback")[0], 1)            # a rollback never widens
        self.assertEqual(self.decide(rc=2, verdict="refused")[0], 1)
        rc, lines = self.decide(rc=0, verdict="equal")                         # HEAD is not at the proposal
        self.assertEqual(rc, 1)
        self.assertIn("check out the proposal's commit c0ffee1", lines[0])


class RollbackBound(unittest.TestCase):
    """--rollback-to K's eligibility and bound (design §14.8.7, OA-c), offline."""

    def k_doc(self, kind="bootstrap", status="superseded", **v):
        st = applied_state()
        doc = {"version": dict({"version": 1, "kind": kind, "status": status, "confirmed_at": "2026-11-03T10:00:00+00:00",
                                "disputed_at": None}, **v),
               "entries": st["entries"], "waivers": st["waivers"],
               "apply_started": {"skeleton_digest": st["accepted"]["digest"], "commit": "unknown"},
               "skeletons": {st["accepted"]["digest"]: {"body": st["accepted"]["body"], "git_commit": "unknown"}},
               "audit_findings": [], "pending": []}
        return st, doc

    def test_targets(self):
        st, doc = self.k_doc()
        self.assertEqual(apply_check.rollback_problems(doc, st, JWKS, 1), ([], []))
        for v, text in (({"confirmed_at": None}, "never confirmed by qa"), ({"disputed_at": "x"}, "qa disputed it"),
                        ({"status": "withdrawn"}, "it is withdrawn, not superseded")):
            with self.subTest(text):
                st, doc = self.k_doc(**v)
                r, _ = apply_check.rollback_problems(doc, st, JWKS, 1)
                self.assertTrue(any(text in x for x in r), r)
        st, doc = self.k_doc(kind="change")
        r, _ = apply_check.rollback_problems(doc, st, JWKS, 1)
        self.assertTrue(any("has no token evidence" in x for x in r), r)
        st0 = applied_state()
        cdoc, _ = change_version(st0)
        cdoc["version"]["status"] = "superseded"
        self.assertEqual(apply_check.rollback_problems(cdoc, st0, JWKS, 2), ([], []))
        r, w = apply_check.rollback_problems(cdoc, st0, {"keys": []}, 2)
        self.assertEqual(r, [])
        self.assertIn("the approval stands on its record", w[0])          # a rotated key never blocks a rollback

    def test_the_bound(self):
        st, doc = self.k_doc()
        self.assertEqual(apply_check.rollback_bound(doc, 1), ([], []))
        # K approved under a narrower skeleton that today's widens: refused
        narrow = json.loads(json.dumps(st["accepted"]["body"]))
        cut = None
        for g in narrow["resource_groups"].values():
            for m in g.get("members") or []:
                if cut is None and isinstance(m, dict) and len(m.get("routes") or {}) > 1:
                    cut = sorted(m["routes"])[0]
                    m["routes"].pop(cut)              # K was approved without this route
        self.assertIsNotNone(cut)
        d = source.skeleton_digest(narrow)
        doc["skeletons"] = {d: {"body": narrow, "git_commit": "unknown"}}
        doc["apply_started"]["skeleton_digest"] = d
        r, _ = apply_check.rollback_bound(doc, 1)
        self.assertEqual(len(r), 1, r)
        self.assertIn("under today's skeleton grants more than was approved", r[0])
        self.assertIn("New draft from version 1", r[0])
        # one rule: apply.sh's bound is explain.rollback_bound's (RollbackBoundTest pins that one)
        from compiler import explain
        b = explain.rollback_bound(source.factory(), apply_check.git_skeleton_of(d, narrow, "unknown"),
                                   source.state_rows(doc))
        self.assertEqual(r, [explain.rollback_refusal(1, b)])

    def test_rows_of_a_retired_group_are_dropped(self):
        st, doc = self.k_doc()
        doc["entries"] = doc["entries"] + [{"role": "qa", "group_code": "retired_group", "level": "R",
                                            "constraint_name": None}]
        r, notes = apply_check.rollback_bound(doc, 1)
        self.assertEqual(r, [])
        self.assertIn("1 row(s) of version 1 name a group or role today's skeleton retired", notes[0])

    def test_jsonb_body_composes_like_its_yaml(self):
        st, doc = self.k_doc()
        body = json.loads(source.canonical(st["accepted"]["body"]))          # jsonb: keys sorted
        skel = apply_check.git_skeleton_of(st["accepted"]["digest"], body, "unknown")
        self.assertEqual(list(skel["levels"]), list(source.factory()["levels"]))
        rows = source.state_rows(doc)
        p_yaml = model.Policy(source.compose(source.skeleton(source.factory()), rows))
        p_json = model.Policy(source.compose(skel, rows))
        from compiler import explain
        for r in p_yaml.roles:
            self.assertEqual(explain.reach(p_yaml, r), explain.reach(p_json, r), r)


class BundleSql45(unittest.TestCase):
    """Step 7's PRE and POST (design §14.8.4, §14.8.6, §14.8.7): values base64, the asserts."""

    META = {"version": 2, "kind": "change", "entries_digest": "e" * 64, "skeleton_digest": "s" * 64,
            "prev_version": 1, "prev_entries_digest": "p" * 64, "rollback_of": None}

    def check_sets(self, sql):
        for line in sql.splitlines():
            if line.startswith("\\set"):
                self.assertRegex(line, r"^\\set [a-z0-9_]+ '[A-Za-z0-9+/=\-]*'$")
        self.assertNotRegex(sql, SQL_KEYWORD_QUALIFIED)

    def test_change(self):
        pre, post = apply_check.apply_bundle_sql("change", self.META, ADMIN, "p-o'brien", "/l", "c" * 40, {}, "d" * 64)
        self.check_sets(pre + post)
        self.assertIn("FOR UPDATE", pre)
        self.assertIn("is not approved any more", pre)
        self.assertIn("\\set want_diff '" + "d" * 64 + "'", pre)
        self.assertIn("_mark_applied(:v,", post)
        self.assertIn("is not applied with the staged entries", post)
        self.assertNotIn("_accept_skeleton", pre)
        self.assertEqual(b64var(post, "apply_by_person"), "p-o'brien")
        self.assertEqual(json.loads(b64var(post, "apply_digests"))["skeleton_digest"], "s" * 64)

    def test_a_record_with_an_extra_says_its_own_reason(self):
        """apply-record --extra without a reason is refused: the bootstrap's default text would
        go into the chain for a partial_apply or an applied record (append-only)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        st, ex, out = (os.path.join(d, n) for n in ("state.json", "extra.json", "record.sql"))
        with open(st, "w") as f:
            json.dump({"version": 2, "kind": "change", "based_on": 1, "accepted": {"digest": "s" * 64}}, f)
        args = ["apply-record", "--event", "partial_apply", "--state", st, "--by-sub", ADMIN, "--by-person", "p",
                "--commit", "c" * 40, "--extra", ex, "--out", out]
        with open(ex, "w") as f:
            json.dump({"version": 2, "outcome": "mixed"}, f)
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()) as err:
            apply_check.main(args)
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("has no reason", err.getvalue())
        with open(ex, "w") as f:
            json.dump({"version": 2, "outcome": "mixed", "reason": "version 2 (change): left mixed"}, f)
        self.assertEqual(apply_check.main(args), 0)
        with open(out) as f:
            pl = json.loads(b64var(f.read(), "payload"))
        self.assertEqual(pl["reason"], "version 2 (change): left mixed")

    def test_skeleton(self):
        body = source.skeleton(source.factory())
        d = source.skeleton_digest(body)
        pre, post = apply_check.apply_bundle_sql("skeleton", dict(self.META, kind="skeleton"), ADMIN, "p", "", "c" * 40,
                                                 {}, "d" * 64, (d, body, "f" * 40))
        self.check_sets(pre + post)
        self.assertLess(pre.index("FOR UPDATE"), pre.index("_accept_skeleton("))
        self.assertLess(pre.index("_accept_skeleton("), pre.index("_sync_skeleton("))
        self.assertEqual(json.loads(b64var(pre, "skel_summary"))["reviewed_by_version"], 2)
        self.assertIn("iam_policy._accepted() IS DISTINCT FROM", post)

    def test_rollback(self):
        pre, post = apply_check.apply_bundle_sql("rollback", dict(self.META, kind="rollback", version=3, rollback_of=1),
                                                 ADMIN, "p", "", "c" * 40, {}, None, None, (1, 2, "test: back"))
        self.check_sets(pre + post)
        self.assertLess(pre.index("_withdraw_open("), pre.index("_build_version('rollback'"))
        self.assertIn("FROM iam_policy.entry e WHERE e.version = :k", pre)      # K's rows read in SQL
        self.assertIn("FROM iam_policy.waiver w WHERE w.version = :k", pre)
        self.assertIn("another version was created meanwhile", pre)
        self.assertEqual(b64var(pre, "rb_withdraw"), "withdrawn by rollback to version 1: test: back")
        self.assertIn("_mark_applied(:v,", post)

    def test_revert(self):
        pre, post = apply_check.revert_bundle_sql({"version": "1", "entries_digest": "a" * 64}, 2, "why", ["x"])
        self.check_sets(pre + post)
        self.assertIn("did not supersede version", pre)
        self.assertLess(post.index("_mark_reverted(:rv, :prev"), post.index("_record('partial_apply'"))
        payload = json.loads(b64var(post, "revert_payload"))
        self.assertEqual((payload["version"], payload["outcome"], payload["reverted_version"], payload["failed_targets"]),
                         (1, "reverting", 2, ["x"]))


def git_tree(t):
    """A scratch tree under git, apps/iam clean (apply.sh <N> refuses -dirty and unknown)."""
    env = dict(os.environ, HOME=t.root, **GIT_ENV)

    def git(*a):
        return subprocess.run(["git", "-C", t.root, *a], check=True, env=env, capture_output=True, text=True).stdout.strip()
    git("init", "-q", "-b", "main")
    with open(t.path(".git", "info", "exclude"), "a") as f:
        f.write(".fake/\n.medcea.lock\nstate/\n__pycache__/\n")
    git("add", "-A")
    git("commit", "-qm", "scratch")
    return git


class ApplyVersion(unittest.TestCase):
    """apply.sh <N> (design §14.8.4-§14.8.6) end to end against the fake cluster, in a scratch
    tree under git; change version 2 narrows maintenance's R on device_history (no account holds it)."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        cls.git = staticmethod(git_tree(cls.t))
        cls.st = applied_state()
        cls.doc, cls.post = change_version(cls.st)

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def reset(self, state=None, **sc):
        shutil.rmtree(self.t.path("state"), ignore_errors=True)
        for f in os.listdir(self.t.fd):
            if f not in ("fake.py", "bin"):
                os.remove(os.path.join(self.t.fd, f))
        base = {"users": users(), "jwks": JWKS, "docs": {"2": self.doc}, "applied_state": self.post,
                "revert_state": dict(self.st, last_apply_event={"event": "partial_apply", "event_id": 70,
                                                                  "outcome": "reverting"}),
                "initial_routes": V1, "configmap": {"routes": V1, "mqtt": "m" * 64}, "comment": f"policy {V1}"}
        base.update(sc)
        self.t.scenario(base)
        self.t.state(state or self.st)

    def run_(self, *args, **env):
        return self.t.run("2", "--by", "admin", *args, **env)

    def records(self):
        try:
            with open(os.path.join(self.t.fd, "records.jsonl")) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def forwards(self):
        return sorted(f for f in os.listdir(self.t.fd) if f.startswith("forward-"))

    def scoped(self):
        try:
            with open(os.path.join(self.t.fd, "scoped.log")) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def test_applied(self):
        self.reset()
        p = self.run_()
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        calls = self.t.calls()

        def first(pred):
            return next(i for i, c in enumerate(calls) if pred(c))
        doc1 = first(lambda c: c["kind"] == "psql" and "-- apply_check.py approval-doc" in c["sql"])
        chain = first(lambda c: c["kind"] == "psql" and "h.hash" in c["sql"] and len(c["sql"]) < 2000)
        by = first(lambda c: c["kind"] == "curl" and "username=admin" in c["url"])
        certs = first(lambda c: c["kind"] == "curl" and c["url"].endswith("/certs"))
        appr = first(lambda c: c["kind"] == "curl" and c["url"].endswith(f"/users/{QA}"))
        base = first(lambda c: c["kind"] == "health" and any(l.startswith("step9:") for l in c["conf"]))
        doc2 = [i for i, c in enumerate(calls) if c["kind"] == "psql" and "-- apply_check.py approval-doc" in c["sql"]][1]
        bundle = first(lambda c: c["kind"] == "psql" and "(apply_check.py bundle-sql; design §14.8.4 step 7)" in c["sql"])
        rec = first(lambda c: c["kind"] == "psql" and "_record('applied'" in c["sql"] and len(c["sql"]) < 20000)
        self.assertLess(doc1, chain)
        self.assertLess(chain, by)
        self.assertLess(by, certs)
        self.assertLess(certs, appr)
        self.assertLess(appr, base)
        self.assertLess(base, doc2)            # step 6c after the confirmation
        self.assertLess(doc2, bundle)
        self.assertLess(bundle, rec)
        # the bundle compiled version 2 (--staged): role_widening()'s comment is its routes digest
        sql = calls[bundle]["sql"]
        with open(self.t.path("state", "policy-applied.yaml")) as f:
            self.assertIn("version=2 kind=change", f.readline())
        r2 = json.loads(b64var(sql, "apply_digests"))["routes"]
        self.assertNotEqual(r2, V1)
        self.assertIn(f"policy {r2}", sql)
        self.assertNotIn(f"policy {V1}", sql)
        self.assertIn("is not approved any more", sql)
        self.assertIn("is not applied with the staged entries", sql)
        # every scoped mode once, then the record with 4.5's fields
        self.assertEqual(len(self.scoped()), 8)
        recs = self.records()
        self.assertEqual([r["event"] for r in recs], ["applied"])
        pl = recs[0]["payload"]
        self.assertEqual((pl["version"], pl["kind"], pl["attempts"], pl["rollback_of"]), (2, "change", 1, None))
        self.assertEqual(pl["approved_by"], {"sub": QA, "person": "p-qa", "event_id": 60})
        self.assertEqual(pl["jwk"]["kid"], KID)
        self.assertEqual(pl["chain_head_before"], {"id": 41, "hash": "ab" * 32})
        self.assertIn("apply_log_sha256", pl)
        self.assertIn("routes", pl["changed"])
        self.assertEqual(pl["reason"], "version 2 (change) applied, approved by quinn")
        self.assertIn("chain head before the apply: 41:" + "ab" * 32, p.stdout)
        # step 9's eight checks; iampolicy never inside it
        confs = [c["conf"] for c in calls if c["kind"] == "health" and any(l.startswith("step9:") for l in c["conf"])]
        self.assertEqual(len(confs), 2)              # the baseline and one verify
        self.assertEqual([l.split("|")[1].strip() for l in confs[1]],
                         ["iamgrants", "iamenforce", "grafanarole", "iamworkbench", "onboardroles", "pgadminroles",
                          "noderedauth", "iamartefacts"])
        self.assertFalse(any("iampolicy" in l for c in confs for l in c))
        self.assertEqual([w for w in writes(calls) if w[0] != "psql"], [])

    def test_check_only_takes_no_lock_and_reads_only(self):
        self.reset()
        lock = self.t.path(".medcea.lock")
        if os.path.exists(lock):
            os.remove(lock)
        p = self.run_("--check-only")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("version 2 would apply", p.stdout)
        self.assertFalse(os.path.exists(lock))
        self.assertFalse(os.path.exists(self.t.path("state", "policy-applied.yaml")))
        self.assertIn("state/policy-applied.yaml is not version 1's", p.stderr)
        for c in self.t.calls():
            if c["kind"] == "psql" and c["db"] != "postgres":
                self.assertTrue(c["sql"].startswith("BEGIN TRANSACTION READ ONLY"), c["sql"][:200])
        self.assertEqual(writes(self.t.calls()), [])

    def test_refused_before_anything(self):
        withdrawn = json.loads(json.dumps(self.doc))
        withdrawn["version"]["status"] = "withdrawn"
        boot = json.loads(json.dumps(self.doc))
        boot["version"]["kind"] = "bootstrap"
        pend = json.loads(json.dumps(self.doc))
        pend["pending"] = [{"decision_id": 7, "kind": "grant", "username": "zoe", "made_at": "2026-11-04T09:00:00+00:00"}]
        bg = dict(self.st, break_glass_open=[{"event_id": 9, "reason": "r", "open": ["monitor"]}])
        for kw, env, rc, text in (
                ({"docs": {"2": withdrawn}}, {}, 1, "version 2 is withdrawn: nothing to apply"),
                ({"docs": {"2": boot}}, {}, 2, "is a bootstrap version"),
                ({"docs": {"2": pend}}, {}, 1, "1 account decision(s) wait for qa"),
                ({"state": bg}, {}, 1, "a policy break-glass is open"),
                ({"state": dict(self.st, last_apply_event={"event": "apply_started", "event_id": 4})}, {}, 1,
                 "finish version 1 first"),
                ({}, {"MEDCEA_POLICY_FILE": "x.yaml", "MEDCEA_POLICY_BREAK_GLASS": "t"}, 2, "no apply under break-glass"),
                ({"jwks": {"keys": []}}, {}, 2, "cannot read the realm's signing keys"),
                ({"users": [u for u in users() if u["id"] != QA]}, {}, 1, "no longer exists in Keycloak"),
                ({"docs": {"2": change_version(self.st, diff_digest="0" * 64)[0]}}, {}, 1, "withdraw it and draft again")):
            with self.subTest(text):
                self.reset(**kw)
                p = self.run_(**env)
                self.assertEqual(p.returncode, rc, p.stdout[-2000:] + p.stderr[-2000:])
                self.assertIn(text, p.stderr)
                self.assertEqual(self.forwards(), [])
                self.assertEqual(writes(self.t.calls()), [])

    def test_a_dirty_or_unknown_commit(self):
        self.reset()
        path = self.t.path("apps/iam/policy/defaults.yaml")
        with open(path) as f:
            text = f.read()
        try:
            with open(path, "a") as f:
                f.write("\n# a local edit\n")
            p = self.run_()
            self.assertEqual(p.returncode, 1, p.stderr[-2000:])
            self.assertIn("apps/iam has uncommitted changes", p.stderr)
        finally:
            with open(path, "w") as f:
                f.write(text)
        # a git that fails: unknown is never a pass
        fake_git = os.path.join(self.t.fd, "bin", "git")
        with open(fake_git, "w") as f:
            f.write("#!/bin/sh\nexit 128\n")
        os.chmod(fake_git, 0o755)
        try:
            p = self.run_()
        finally:
            os.remove(fake_git)
        self.assertEqual(p.returncode, 2, p.stderr[-2000:])
        self.assertIn("cannot record a reproducible commit", p.stderr)
        self.assertEqual(writes(self.t.calls()), [])

    def test_a_stale_host_file_is_rewritten_first(self):
        self.reset()
        other = json.loads(json.dumps(self.st))
        other["waivers"][0]["review_by"] = "2099-12-31"
        rows = source.state_rows(other)
        other["entries_digest"] = source.entries_digest("bootstrap", other["groups"], other["roles"], rows["entries"],
                                                        rows["waivers"])
        os.makedirs(self.t.path("state"), mode=0o700)
        with open(self.t.path("state", "policy-applied.yaml"), "w") as f:
            f.write(source.host_file_text(other, "unknown", "2026-11-01T00:00:00Z"))
        p = self.run_("--check-only")
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertIn("is not version 1's (different)", p.stderr)
        self.reset(tamper_staged=True)
        os.makedirs(self.t.path("state"), mode=0o700)
        with open(self.t.path("state", "policy-applied.yaml"), "w") as f:
            f.write(source.host_file_text(other, "unknown", "2026-11-01T00:00:00Z"))
        p = self.run_()
        self.assertIn("rewritten: it differed from the database", p.stdout)
        # the staged file edited after step 5: the bundle's cli.py --staged refuses the sha256 pin
        self.assertEqual(p.returncode, 1, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("is not the one apply.sh staged", p.stderr)
        self.assertIn("the bundle was rolled back", p.stderr)
        self.assertEqual(self.forwards(), [])

    def test_keycloak_changed_while_the_confirmation_waited(self):
        twin = {"id": ADMIN2, "username": "quinn-admin", "enabled": True, "attributes": {"person_id": ["p-qa"]},
                "roles": ["admin"]}
        pend = json.loads(json.dumps(self.doc))
        pend["pending"] = [{"decision_id": 8, "kind": "grant", "username": "zoe", "made_at": "x"}]
        for kw in ({"users_after": [dict(u, enabled=u["id"] != QA) for u in users()]},
                   {"users_after": users() + [twin]},
                   {"docs_after": {"2": pend}}):
            with self.subTest(list(kw)):
                self.reset(**kw)
                p = self.run_()
                self.assertEqual(p.returncode, 1, p.stdout[-2000:] + p.stderr[-2000:])
                self.assertIn("something changed while the confirmation waited", p.stderr)
                self.assertEqual(self.forwards(), [])

    def test_a_check_failing_before_the_apply(self):
        self.reset(checks={"pgadminroles": "FAIL"})
        p = self.run_()
        self.assertEqual(p.returncode, 2, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("these checks fail before the apply (above: pgadminroles): fix them first", p.stderr)
        self.assertEqual(self.forwards(), [])

    def test_no_terminal_without_confirmation(self):
        self.reset()
        p = self.run_(MEDCEA_CONFIRMED="")
        self.assertEqual(p.returncode, 1, p.stderr[-2000:])
        self.assertIn("refusing without a terminal", p.stderr)
        self.assertEqual(self.forwards(), [])

    def test_signals_while_the_bundle_runs(self):
        self.reset(bundle_sigint="commit")
        p = self.run_()
        self.assertEqual(p.returncode, 3, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("the bundle's COMMIT reached PostgreSQL", p.stderr)
        self.assertIn("--resume", p.stderr)
        self.reset(bundle_sigint="rollback")
        p = self.run_()
        self.assertEqual(p.returncode, 130, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("the bundle was rolled back: nothing was changed", p.stderr)

    def test_a_transport_failure_after_the_commit(self):
        self.reset(bundle_stream_lost=True)
        p = self.run_()
        # design §14.8.4 step 7: committed, not finished (exit 3, --resume), nothing recorded yet
        self.assertEqual(p.returncode, 3, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("its COMMIT reached PostgreSQL", p.stderr)
        self.assertIn("version 2 is committed but its apply is not finished", p.stderr)
        self.assertEqual(self.records(), [])
        self.reset(bundle_fail=True)
        p = self.run_()
        self.assertEqual(p.returncode, 1, p.stderr[-2000:])
        self.assertIn("the bundle was rolled back", p.stderr)
        self.assertEqual(self.records(), [])

    def test_step_8_fails_once(self):
        self.reset()
        p = self.run_(FAKE_SCOPED="apps/frontend/deploy.sh=1:1")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertEqual(self.records()[0]["payload"]["attempts"], 2)
        ran = self.scoped()
        self.assertEqual(ran.count("apps/frontend/deploy.sh --gate-only"), 2)
        self.assertEqual(ran.count("deploy-infra.sh --policy-only"), 1)          # retried from the failed one

    def test_failing_three_times_reverts(self):
        self.reset()
        p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:3")
        self.assertEqual(p.returncode, 1, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("version 2 was not applied: the rollout failed", p.stderr)
        self.assertIn("the previous version 1 is back", p.stderr)
        with open(os.path.join(self.t.fd, "revert-1.sql")) as f:
            sql = f.read()
        self.assertIn("did not supersede version", sql)
        self.assertIn("_mark_reverted(:rv, :prev", sql)
        pl = json.loads(b64var(sql, "revert_payload"))
        self.assertEqual((pl["version"], pl["outcome"], pl["reverted_version"]), (1, "reverting", 2))
        self.assertIn(f"policy {V1}", sql)                                     # compiled from prev.yaml
        recs = self.records()
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"].get("outcome")) for r in recs],
                         [("partial_apply", 2, "reverted"), ("applied", 1, None)])
        self.assertEqual(recs[1]["payload"]["reverted_from"], 2)
        self.assertIn("./apps/monitor/deploy.sh --gate-only", recs[0]["payload"]["failed_targets"][0])
        # each record says its own reason, never the bootstrap's text (the chain keeps it)
        self.assertEqual((recs[0]["payload"]["based_on"], recs[0]["payload"]["attempts"]), (1, 3))
        self.assertRegex(recs[0]["payload"]["reason"],
                         r"^version 2 \(change\): its rollout failed after 3 attempt\(s\) \(.*monitor.*\); reverted to version 1$")
        self.assertEqual(recs[1]["payload"]["reason"], "version 1 put back: the apply of version 2 was reverted")
        self.assertNotIn("bootstrapped", json.dumps([r["payload"] for r in recs]))
        st = self.t.read_state()
        self.assertEqual((st["version"], st["last_apply_event"]["event"]), (1, "applied"))
        with open(self.t.path("state", "policy-applied.yaml")) as f:
            self.assertIn("version=1 kind=bootstrap", f.readline())

    def test_the_revert_bundle_fails(self):
        self.reset(revert_fail=True)
        p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:3")
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("partial_apply mixed", p.stderr)
        recs = self.records()
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"]["outcome"]) for r in recs],
                         [("partial_apply", 2, "mixed")])
        self.assertRegex(recs[0]["payload"]["reason"], r"^version 2 \(change\): its rollout failed .*; left mixed, ")

    def test_the_revert_bundle_cannot_be_built(self):
        """Nothing was reverted: version 2 stays applied, partial_apply {mixed} under it, and
        the message names version 2's --resume, never the revert's (PHASE stays mixed until
        the revert bundle commits)."""
        self.reset()
        ac = self.t.path("apps/iam/apply_check.py")
        with open(ac) as f:
            orig = f.read()
        self.git("update-index", "--assume-unchanged", "apps/iam/apply_check.py")   # the commit stays clean
        try:
            with open(ac, "w") as f:
                f.write(orig.replace('            elif a.kind == "revert":\n',
                                     '            elif a.kind == "revert":\n                die("test: no revert bundle", 1)\n', 1))
            p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:3")
        finally:
            with open(ac, "w") as f:
                f.write(orig)
            self.git("update-index", "--no-assume-unchanged", "apps/iam/apply_check.py")
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("cannot build the revert bundle", p.stderr)
        self.assertIn("version 2 is committed but its rollout is not finished (partial_apply)", p.stderr)
        self.assertNotIn("the revert of version 2 to version 1", p.stderr)
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"]["outcome"]) for r in self.records()],
                         [("partial_apply", 2, "mixed")])
        self.assertFalse([f for f in os.listdir(self.t.fd) if f.startswith("revert-")])

    def test_the_previous_rollout_fails_then_resume(self):
        self.reset()
        p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:6")
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("the revert of version 2 to version 1 is committed but not finished", p.stderr)
        self.assertEqual(self.records(), [])
        st = self.t.read_state()
        self.assertEqual((st["version"], st["last_apply_event"]["outcome"]), (1, "reverting"))
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        recs = self.records()
        # version 1 is the bootstrap: its resumed record is bootstrap_applied, as before 4.5
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"].get("resumed")) for r in recs],
                         [("bootstrap_applied", 1, True)])

    def test_a_signal_during_the_reverts_rollout(self):
        self.reset()
        stub = self.t.path("apps/scheduler/deploy.sh")
        with open(stub) as f:
            orig = f.read()
        try:
            # the scheduler's scoped mode interrupts apply.sh once the revert is committed
            with open(stub, "w") as f:
                f.write(orig.rsplit("PY\n", 1)[0] + "\nimport json, signal\nst = json.load(open(os.path.join(os.path.dirname(log), 'state.json')))\n"
                        "if (st.get('last_apply_event') or {}).get('outcome') == 'reverting':\n"
                        "    sys.path.insert(0, os.path.dirname(log))\n"
                        "    os.environ['FAKE_DIR'] = os.path.dirname(log)\n"
                        "    p = os.getppid()\n"
                        "    os.kill(p, signal.SIGINT)\nPY\n")
            p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:3")
        finally:
            with open(stub, "w") as f:
                f.write(orig)
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("the revert of version 2 to version 1 is committed but not finished", p.stderr)
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertEqual([(r["event"], r["payload"]["version"]) for r in self.records()], [("bootstrap_applied", 1)])

    def test_wait_routes(self):
        deps = {"monitor": {"pods": [{"name": "monitor-a"}, {"name": "monitor-b", "stuck": True},
                                     {"name": "monitor-c", "ready": False, "stuck": True}]},
                "access": {"pods": [{"name": "access-a"}]}}
        self.reset(deployments=deps)
        p = self.run_(MEDCEA_APPLY_ROUTES_WAIT="10")
        self.assertEqual(p.returncode, 1, p.stdout[-3000:] + p.stderr[-3000:])
        recs = self.records()
        self.assertEqual(recs[0]["payload"]["failed_targets"], ["routes.json on monitor-b"])
        self.assertEqual(recs[1]["payload"]["reverted_from"], 2)
        # an unready pod is not asked; absent Deployments are skipped
        execs = [c["argv"] for c in self.t.calls() if c["kind"] == "kubectl" and c["argv"][:1] == ["exec"]
                 and "cat" in c["argv"]]
        self.assertFalse([a for a in execs if "monitor-c" in a])
        self.assertTrue([a for a in execs if "access-a" in a])

    def test_wait_routes_an_unreadable_deployment_lags(self):
        """Only NotFound skips a Deployment (design §14.8.6 step 8): an API error lags, so the
        wait never passes without asking the pods."""
        self.reset(unreadable_deployments=["scheduler"])
        p = self.run_(MEDCEA_APPLY_ROUTES_WAIT="5")
        # the revert's own rollout waits on the same Deployment: committed, not finished
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("routes.json on scheduler (unreadable) lags behind", p.stderr)
        self.assertIn("the rollout of version 1 failed too (routes.json on scheduler (unreadable))", p.stderr)

    def test_a_deferred_wizard(self):
        self.reset()
        p = self.run_(FAKE_SCOPED="apps/edge-wizard/deploy.sh=4")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("deferred: ./apps/edge-wizard/deploy.sh --gate-only", p.stderr)
        recs = self.records()
        self.assertEqual([r["event"] for r in recs], ["applied", "apply_deferred"])
        self.assertEqual(recs[0]["payload"]["deferred"], ["./apps/edge-wizard/deploy.sh --gate-only"])
        confs = [c["conf"] for c in self.t.calls() if c["kind"] == "health" and any(l.startswith("step9:") for l in c["conf"])]
        self.assertTrue(any("onboardroles" in l for l in confs[0]))             # the baseline asks it
        self.assertFalse(any("onboardroles" in l for l in confs[-1]))           # step 9 drops it

    def test_resume_with_an_unrelated_fail(self):
        st = dict(self.post, last_apply_event={"event": "apply_started", "event_id": 50})
        self.reset(state=st, checks={"pgadminroles": "FAIL"})
        p = self.t.run("--resume", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("still FAILing after the scoped modes: pgadminroles", p.stderr)
        recs = self.records()
        self.assertEqual([(r["event"], r["payload"].get("resumed")) for r in recs], [("applied", True)])
        self.assertTrue([c for c in self.t.calls() if c["kind"] == "health"
                         and c["conf"] == ["Database grants | iamgrants | $POSTGRES_DB |"]])
        # under the wizard's deferral too
        self.reset(state=st)
        p = self.t.run("--resume", "--by", "admin", FAKE_SCOPED="apps/edge-wizard/deploy.sh=4")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertEqual([r["event"] for r in self.records()], ["applied", "apply_deferred"])


SKEL_WIDE = ('routes: {"POST /_mqtt-credential": R}}',
             'routes: {"POST /_mqtt-credential": R, "GET /_mqtt-credential/status": R}}')


class ApplySkeleton(unittest.TestCase):
    """apply.sh N for an approved skeleton version (design §14.8.4 step 2.4): HEAD carries the
    proposal (a route engineer gains), the accepted skeleton is still the older one; the gate's
    exception admits exactly that digest. A failed rollout is never reverted (owner decision 3)."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        git = git_tree(cls.t)
        cls.st = applied_state()
        pol = cls.t.path(POLICY)
        with open(pol) as f:
            text = f.read()
        with open(pol, "w") as f:
            f.write(text.replace(*SKEL_WIDE))
        git("commit", "-qam", "wide")
        commit = git("rev-parse", "HEAD")
        saved = source.DEFAULTS
        source.DEFAULTS = pol                     # the proposal is the git tree's skeleton
        try:
            wide = source.factory()
            body = json.loads(source.canonical(source.skeleton(wide)))
            digest = source.skeleton_digest(wide)
            groups = sorted(body["resource_groups"], key=source._bytes)
            roles = sorted(body["roles"], key=source._bytes)
            rows = source.state_rows(cls.st)
            ed = source.entries_digest("skeleton", groups, roles, rows["entries"], rows["waivers"])
            v = {"version": 2, "kind": "skeleton", "status": "approved", "based_on": 1, "groups": groups, "roles": roles,
                 "entries_digest": ed, "skeleton_digest": digest, "approved_skeleton_digest": digest,
                 "approved_by_sub": QA, "approved_by_person": "p-qa", "approved_by_name": "quinn",
                 "approved_at": APPROVED_AT, "approved_iat": IAT, "confirmed_at": None, "disputed_at": None}
            d = apply_check.skeleton_doc(cls.st, {"version": v, "entries": cls.st["entries"], "waivers": cls.st["waivers"]})
            v["diff_digest"] = hashlib.sha256(source.canonical(d)).hexdigest()
        finally:
            source.DEFAULTS = saved
        c = qa_claims("jti-s")
        jws = sign(c)
        ev = {"version": 2, "source": "token", "role": "qa", "person": "p-qa", "sub": QA, "iat": IAT, "jti": "jti-s",
              "azp": "policy", "entries_digest": ed, "diff_digest": v["diff_digest"], "skeleton_digest": digest,
              "jws_sha256": hashlib.sha256(jws.encode()).hexdigest()}
        cls.doc = {"version": v, "entries_digest_sql": ed, "applied_version": 1,
                   "approval": {"event": {"event_id": 61, "payload": ev, "actor_name": "quinn"},
                                "evidence": {"jws": jws, "claims": c}, "other_approved": [], "other_approved_jti": []},
                   "authors": [{"sub": ADMIN, "person": "p-admin"}], "entries": cls.st["entries"],
                   "waivers": cls.st["waivers"],
                   "diff": {"diff": json.dumps(d), "diff_digest": v["diff_digest"]},
                   "skeletons": {digest: {"body": body, "git_commit": commit}}, "apply_started": None,
                   "audit_findings": [], "pending": []}
        cls.post = dict(cls.st, state="version-2", version=2, kind="skeleton", entries_digest=ed, groups=groups,
                        roles=roles, based_on=1, last_apply_event=None,
                        accepted={"digest": digest, "body": body, "git_commit": commit, "reviewed_by_version": 2})

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def reset(self, doc=None, **sc):
        shutil.rmtree(self.t.path("state"), ignore_errors=True)
        for f in os.listdir(self.t.fd):
            if f not in ("fake.py", "bin"):
                os.remove(os.path.join(self.t.fd, f))
        # version 1's host file, written by the deploy before HEAD moved to the proposal
        os.makedirs(self.t.path("state"), mode=0o700)
        with open(self.t.path("state", "policy-applied.yaml"), "w") as f:
            f.write(source.host_file_text(self.st, "unknown", "2026-11-04T09:00:00Z"))
        os.chmod(self.t.path("state", "policy-applied.yaml"), 0o600)
        base = {"users": users(), "jwks": JWKS, "docs": {"2": doc or self.doc}, "applied_state": self.post,
                "initial_routes": V1, "configmap": None, "comment": None}
        base.update(sc)
        self.t.scenario(base)
        self.t.state(self.st)

    def test_an_absent_host_file_is_written_with_the_accepted_skeleton(self):
        """Step 2.3 with HEAD at the proposal: version 1's host file is composed with the
        accepted skeleton (git_skeleton_of), never HEAD's, which compose_applied refuses."""
        self.reset()
        os.remove(self.t.path("state", "policy-applied.yaml"))
        p = self.t.run("2", "--by", "admin", "--check-only")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("state/policy-applied.yaml is not version 1's (absent): the apply rewrites it first", p.stderr)
        self.assertFalse(os.path.exists(self.t.path("state", "policy-applied.yaml")))
        p = self.t.run("2", "--by", "admin")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("state/policy-applied.yaml: version 1 (bootstrap) written", p.stdout)
        with open(self.t.path("state", "policy-applied.yaml")) as f:
            self.assertIn("version=2 kind=skeleton", f.readline())

    def test_the_gate_exception_admits_the_approved_digest(self):
        self.reset()
        p = self.t.run("2", "--by", "admin", "--check-only")
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("admitted as skeleton version 2", p.stdout)
        self.assertIn("version 2 would apply", p.stdout)
        sub = json.loads(json.dumps(self.doc))
        sub["version"]["status"] = "submitted"
        self.reset(sub)
        p = self.t.run("2", "--by", "admin", "--check-only")
        self.assertEqual(p.returncode, 1, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("is submitted, not approved", p.stderr)

    def test_a_failed_rollout_is_not_reverted(self):
        self.reset()
        p = self.t.run("2", "--by", "admin", FAKE_SCOPED="apps/monitor/deploy.sh=1")
        self.assertEqual(p.returncode, 3, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("a skeleton version is not reverted", p.stderr)
        self.assertFalse([f for f in os.listdir(self.t.fd) if f.startswith("revert-")])
        with open(os.path.join(self.t.fd, "records.jsonl")) as f:
            recs = [json.loads(l) for l in f]
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"]["outcome"]) for r in recs],
                         [("partial_apply", 2, "mixed")])
        self.assertRegex(recs[0]["payload"]["reason"], r"^version 2 \(skeleton\): its rollout failed .*; left mixed, ")
        with open(os.path.join(self.t.fd, "forward-1.sql")) as f:
            sql = f.read()
        self.assertLess(sql.index("_accept_skeleton("), sql.index("_mark_applied(:v,"))
        self.assertEqual(json.loads(b64var(sql, "skel_summary"))["reviewed_by_version"], 2)


class AuditMode(unittest.TestCase):
    """apply.sh --audit N (design §14.8.10): one READ ONLY transaction, no lock, cli.py
    audit-version on the document; its exit code is apply.sh's."""

    def test_read_only_and_handed_to_audit_version(self):
        t = Tree()
        try:
            st = applied_state()
            doc, _ = change_version(st)
            t.state(st)
            t.scenario({"users": users(), "docs": {"2": doc}})
            p = t.run("--audit", "2")
            self.assertEqual(p.returncode, 2, p.stdout[-2000:] + p.stderr[-2000:])   # no apply_started recorded
            self.assertIn("cannot reproduce this record", p.stdout)
            self.assertFalse(os.path.exists(t.path(".medcea.lock")))
            reads = [c["sql"] for c in t.calls() if c["kind"] == "psql" and c["db"] != "postgres"]
            self.assertTrue(all(s.startswith("BEGIN TRANSACTION READ ONLY") for s in reads))
            audit = [s for s in reads if "-- apply_check.py approval-doc" in s]
            self.assertEqual(len(audit), 1)
            for key in ("'applied'", "'previous'", "'chain'", "'apply_started'", "'approval'", "'audit_findings'"):
                self.assertIn(key, audit[0])
            self.assertEqual(writes(t.calls()), [])
            self.assertEqual([c for c in t.calls() if c["kind"] == "curl"], [])
        finally:
            t.close()

    def test_the_document(self):
        d = tempfile.mkdtemp()
        try:
            raw = os.path.join(d, "raw.json")
            with open(raw, "w") as f:
                f.write("\n" + json.dumps({"version": {"version": 2}, "audit_findings": [
                    {"version": 2, "finding": "sequence"}, {"version": 1, "finding": "x"}]}) + "\n")
            out = os.path.join(d, "audit.json")
            self.assertEqual(apply_check.main(["audit-doc", "--in", raw, "--issuer", ISSUER_T, "--out", out]), 0)
            with open(out) as f:
                doc = json.load(f)
            self.assertEqual(doc["issuer"], ISSUER_T)
            self.assertEqual(doc["audit_findings"], [{"version": 2, "finding": "sequence"}])
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        finally:
            shutil.rmtree(d)


class FakeHelmFail(unittest.TestCase):
    """tests/fake_cluster.py's FAKE_HELM_FAIL=<release>[:n] (design §14.8.11): offline fault
    injection for step 8; nothing like it ships in production."""

    def test_the_first_n_upgrades_fail(self):
        d = tempfile.mkdtemp()
        try:
            mk = os.path.join(d, "microk8s")
            os.symlink(os.path.join(HERE, "fake_cluster.py"), mk)
            env = clean_env(FAKE_STATE=os.path.join(d, "state.json"), FAKE_LOG=os.path.join(d, "log.jsonl"),
                            FAKE_HELM_FAIL="grafana:2")
            vals = os.path.join(d, "v.yaml")
            with open(vals, "w") as f:
                f.write("env: {}\n")

            def up(rel):
                return subprocess.run([sys.executable, mk, "helm3", "upgrade", "--install", rel, "grafana/grafana",
                                       "--values", vals], env=env, capture_output=True, text=True).returncode
            self.assertEqual([up("grafana"), up("grafana"), up("grafana"), up("other")], [1, 1, 0, 0])
            with open(os.path.join(d, "log.jsonl")) as f:
                self.assertEqual([json.loads(l)["write"] for l in f], [False, False, True, True])
            env["FAKE_HELM_FAIL"] = "grafana"
            self.assertEqual(up("grafana"), 1)
        finally:
            shutil.rmtree(d)

    def test_nothing_in_production_reads_it(self):
        for rel in ("apps/iam/apply.sh", "apps/iam/apply_check.py", "infra/lib-policy-source.sh",
                    "apps/database/lib-db-apply.sh", "deploy-infra.sh"):
            self.assertNotIn("FAKE_", read_repo(rel), rel)


class RollbackTo(unittest.TestCase):
    """apply.sh --rollback-to K (design §14.8.7) against the fake cluster: version 2 applied,
    version 1 (the bootstrap) superseded and confirmed."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        git_tree(cls.t)
        st1 = applied_state()
        _, cls.st = change_version(st1)
        cls.st["last_apply_event"] = {"event": "applied", "event_id": 60, "at": "x"}
        cls.k = {"version": dict({"version": 1, "kind": "bootstrap", "status": "superseded",
                                  "confirmed_at": "2026-11-03T10:00:00+00:00", "disputed_at": None,
                                  "entries_digest": st1["entries_digest"]}),
                 "entries_digest_sql": st1["entries_digest"], "applied_version": 2,
                 "entries": st1["entries"], "waivers": st1["waivers"],
                 "apply_started": {"skeleton_digest": st1["accepted"]["digest"], "commit": "unknown"},
                 "skeletons": {st1["accepted"]["digest"]: {"body": st1["accepted"]["body"], "git_commit": "unknown"}},
                 "audit_findings": [], "pending": [], "authors": [], "approval": None}
        rows = source.state_rows(st1)
        groups = sorted(st1["accepted"]["body"]["resource_groups"], key=source._bytes)
        roles = sorted(st1["accepted"]["body"]["roles"], key=source._bytes)
        ed = source.entries_digest("rollback", groups, roles, rows["entries"], rows["waivers"])
        cls.post = dict(st1, state="version-3", version=3, kind="rollback", entries_digest=ed, based_on=2,
                        last_apply_event=None)

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def reset(self, k=None, **sc):
        shutil.rmtree(self.t.path("state"), ignore_errors=True)
        for f in os.listdir(self.t.fd):
            if f not in ("fake.py", "bin"):
                os.remove(os.path.join(self.t.fd, f))
        base = {"users": users(), "jwks": JWKS, "docs": {"1": k or self.k}, "applied_state": self.post,
                "next_version": 3, "initial_routes": "r" * 64, "configmap": None, "comment": None}
        base.update(sc)
        self.t.scenario(base)
        self.t.state(dict(self.st, open_versions=sc.pop("open_versions", [])))

    def run_(self, *args, **env):
        return self.t.run("--rollback-to", "1", "--by", "admin", "--reason", "test: back to 1", *args, **env)

    records = ApplyVersion.records

    def test_rolled_back(self):
        self.reset(open_versions=[{"version": 4, "kind": "change", "status": "draft", "reason": "r", "authors": []}])
        p = self.run_()
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("version 4 (draft) will be withdrawn", p.stderr)
        self.assertIn("version 3 (rollback to 1) applied: a qa person other than admin confirms it", p.stdout)
        with open(os.path.join(self.t.fd, "forward-1.sql")) as f:
            sql = f.read()
        self.assertLess(sql.index("_withdraw_open("), sql.index("_build_version('rollback'"))
        self.assertIn("FROM iam_policy.entry e WHERE e.version = :k", sql)
        self.assertIn("\\set want_version '3'", sql)
        self.assertEqual(b64var(sql, "rb_reason"), f"test: back to 1 [apply.sh --rollback-to, --by admin (claimed), OS user {id_un()}]")
        pl = self.records()[0]["payload"]
        self.assertEqual((pl["version"], pl["kind"], pl["rollback_of"]), (3, "rollback", 1))
        self.assertTrue(pl["reason"].startswith("test: back to 1 [apply.sh --rollback-to"))
        self.assertNotIn("approved_by", pl)
        with open(self.t.path("state", "policy-applied.yaml")) as f:
            self.assertIn("version=3 kind=rollback", f.readline())

    def test_a_reverted_rollback_says_rollback_to_again(self):
        """A cleanly reverted rollback names --rollback-to K, never `apply.sh K` (which is refused)."""
        self.reset(revert_state=dict(self.st, last_apply_event={"event": "partial_apply", "event_id": 70,
                                                                 "outcome": "reverting"}))
        p = self.run_(FAKE_SCOPED="apps/monitor/deploy.sh=1:3")
        self.assertEqual(p.returncode, 1, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("version 3 was not applied", p.stderr)
        self.assertIn('run ./apps/iam/apply.sh --rollback-to 1 --by <you> --reason "<why>" again', p.stderr)
        self.assertNotIn("apply.sh 1 again", p.stderr)
        self.assertEqual([(r["event"], r["payload"]["version"], r["payload"].get("outcome")) for r in self.records()],
                         [("partial_apply", 3, "reverted"), ("applied", 2, None)])

    def test_not_a_target(self):
        import copy as _copy
        cdoc = _copy.deepcopy(self.k)
        cdoc["version"].update(kind="change", confirmed_at=None)
        for v, text in (({"confirmed_at": None}, "never confirmed by qa"), ({"disputed_at": "2026-11-03"}, "qa disputed it"),
                        ({"status": "withdrawn"}, "it is withdrawn")):
            with self.subTest(text):
                k = _copy.deepcopy(self.k)
                k["version"].update(v)
                self.reset(k)
                p = self.run_()
                self.assertEqual(p.returncode, 1, p.stderr[-2000:])
                self.assertIn("version 1 cannot be rolled back to", p.stderr)
                self.assertIn(text, p.stderr)
                self.assertEqual(writes(self.t.calls()), [])
        self.reset(cdoc)
        p = self.run_()
        self.assertEqual(p.returncode, 1)
        self.assertIn("its approval has no token evidence", p.stderr)

    def test_pending_listed_not_refused_and_typed_yes(self):
        import copy as _copy
        k = _copy.deepcopy(self.k)
        k["pending"] = [{"decision_id": 7, "kind": "grant", "username": "zoe", "made_at": "x"}]
        self.reset(k)
        p = self.run_("--check-only")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("1 account decision(s) wait for qa", p.stderr)
        self.assertIn("version 3 (rollback to version 1) would apply", p.stdout)
        self.reset()
        p = self.run_(MEDCEA_CONFIRMED="")
        self.assertEqual(p.returncode, 1)
        self.assertIn("refusing without a terminal", p.stderr)
        s = read_repo("apps/iam/apply.sh")
        self.assertIn('Type yes to roll back to version $K: " yes', s)

    def test_a_pre_failing_check_is_reported_only(self):
        self.reset(checks={"pgadminroles": "FAIL"})
        p = self.run_()
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        self.assertIn("pre-failing, reported and never revert-driving: pgadminroles", p.stderr)
        self.assertEqual(self.records()[0]["payload"]["pre_failing"], ["pgadminroles"])


if __name__ == "__main__":
    unittest.main()
