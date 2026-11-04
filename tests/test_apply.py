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
import hashlib
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
from compiler import source  # noqa: E402

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


def psql(db, args, sql):
    log("psql", db=db, sql=sql)
    if db == "postgres" and "pg_database" in sql:
        print("1" if sc.get("db", True) else "")
        return 0
    if "BEGIN TRANSACTION READ ONLY" in sql:
        print(json.dumps(state()))
        return 0
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
    m = re.search(r"_record\('(bootstrap_applied|applied)'", sql)
    if m:
        with open(os.path.join(FD, "record.sql"), "w") as f:
            f.write(sql)
        if sc.get("record_fail"):
            print("ERROR:  _record refused", file=sys.stderr)
            return 3
        d = state()
        d["last_apply_event"] = {"event": m.group(1), "event_id": 42, "at": "2026-11-02T10:01:00+00:00"}
        put_state(d)
        print("42")
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
    if "verify_chain()" in sql and "h.hash" in sql:
        print(("t" if sc.get("chain_ok", True) else "f") + "|41|" + "ab" * 32)
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
    code, body = 404, {"error": "not found"}
    if path.endswith("protocol/openid-connect/token"):
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
    conf = open(a[a.index("-c") + 1]).read()
    lines = [l.strip() for l in conf.splitlines() if l.strip() and not l.startswith("#")]
    log("health", conf=lines)
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
        for f in ("apps/iam/apply.sh", "apps/iam/deploy.sh", "apps/iam/iam-api.py", "infra/mqtt-passwd.py"):
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
        # (the iam deploy is the real one: its --gate-only says "no gate before slice 4.3")
        for rel in ("deploy-infra.sh", "infra/deploy-workbench.sh") + tuple(
                f"apps/{c}/deploy.sh" for c in ("access", "edge-wizard", "frontend", "monitor", "mqtt-explorer",
                                                 "scheduler")):
            dst = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as f:
                f.write(f'#!/bin/sh\necho "{rel} $*" >> "$(dirname "$0")/{"../" * rel.count("/")}.fake/scoped.log"\nexit 0\n')
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
        for args, slice_ in ((["1", "--by", "admin"], "4.5"), (["--rollback-to", "1", "--by", "admin"], "4.5")):
            with self.subTest(args):
                p = self.t.run(*args)
                self.assertEqual(p.returncode, 2)
                self.assertIn(f"arrives with IAM {slice_}", p.stderr)
        self.assertEqual(self.t.calls(), [])

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
        self.assertIn("arrives with IAM 4.5 (./apps/iam/apply.sh 2)", p.stdout)
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
        blk = s[s.index('if [[ "$MODE" == withdraw-open ]]; then'):s.index("# --resume (design")]
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


if __name__ == "__main__":
    unittest.main()
