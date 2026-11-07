#!/usr/bin/env python3
"""tests/test_health_policy.py — health-check.sh's iampolicy and iamartefacts (IAM Phase 4,
slice 4.2a; design §14.4.14; the open versions of 4.4, §14.7.6).

Offline. Each check runs in a scratch tree (tests/_scratch.py: state/ and .medcea.lock resolve
inside the copy, so the live host's state/policy-applied.yaml never changes an outcome) against
a fake `kubectl`/`microk8s` on PATH that answers from a scenario file, refuses every writing
verb and logs its calls. The function tests take each check's body out of health-check.sh
(as tests/test_policy.py's _health_fn does); one end-to-end test runs a copy of health-check.sh
itself with a two-line check list, through policy_source_init --read-only, so the state
document really comes from the read-only init and its directory is removed at exit.
Nothing here touches a cluster or the repository's state/.
"""
import base64
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
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from _scratch import clean_env, scratch_repo  # noqa: E402

import apply_check  # noqa: E402
from compiler import source  # noqa: E402

FAKE = r'''#!/usr/bin/env python3
# A fake kubectl / microk8s for tests/test_health_policy.py: read-only verbs only.
import json, os, sys
FD = os.environ["FAKE_DIR"]
sc = json.load(open(os.path.join(FD, "scenario.json")))


def log(**kw):
    with open(os.path.join(FD, "calls.log"), "a") as f:
        f.write(json.dumps(kw) + "\n")


def psql(db, sql):
    if db == "postgres" and "pg_database" in sql:
        print("1")
        return 0
    if "BEGIN TRANSACTION READ ONLY" in sql:
        print(json.dumps(json.load(open(os.path.join(FD, "state.json")))))
        return 0
    print("ERROR:  fake psql: unexpected statement", file=sys.stderr)
    return 3


def kubectl(a):
    log(argv=a)
    w = [x for i, x in enumerate(a) if x != "-n" and (i == 0 or a[i - 1] != "-n")]
    verb = w[0] if w else ""
    if verb == "version":
        return 0
    if verb == "exec":
        rest = a[a.index("--") + 1:]
        if rest[0] == "python3":      # iam-api's /healthz on :8083 (IAM 4.3)
            if "iam_healthz" not in sc:
                return 1
            print(json.dumps(sc["iam_healthz"]))
            return 0
        i = rest.index("-c")
        return psql(rest[i + 2], sys.stdin.read())
    if verb != "get":
        print(f"fake kubectl: refusing to {verb}", file=sys.stderr)
        return 99
    if sc.get("api_down"):
        print("The connection to the server 127.0.0.1:16443 was refused", file=sys.stderr)
        return 1
    what = w[1] if len(w) > 1 else ""
    if what == "statefulset":
        print(f"statefulset.apps/{w[2]}")
        return 0
    if what == "pod" and "-l" in a:
        print("rdbms-postgresql-0", end="")
        return 0
    if what == "pod":
        print("True", end="")
        return 0
    if what == "configmap":
        names = [x for x in w[2:] if not x.startswith("-") and x != "json"]
        cms = sc.get("configmaps", {})
        if "--ignore-not-found" in a:
            print(json.dumps({"apiVersion": "v1", "kind": "List",
                              "items": [cms[n] for n in names if n in cms]}))
            return 0
        if names and names[0] in cms:
            print(json.dumps(cms[names[0]]))
            return 0
        print(f'Error from server (NotFound): configmaps "{names[0] if names else ""}" not found', file=sys.stderr)
        return 1
    print(f"Error from server (NotFound): {what} not found", file=sys.stderr)
    return 1


a = sys.argv[1:]
if os.path.basename(sys.argv[0]) == "microk8s":
    if a[:1] != ["kubectl"]:
        print(f"fake microk8s: refusing {a[:1]}", file=sys.stderr)
        sys.exit(99)
    a = a[1:]
sys.exit(kubectl(a))
'''

STAMP = "2026-11-02T00:00:00Z"


def body(fn):
    with open(os.path.join(REPO, "health-check.sh")) as f:
        src = f.read()
    return re.search(rf"(?ms)^{fn}\(\) \{{.*?^\}}", src).group(0)


def cm_doc(name, data=None, annotations=None):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "annotations": annotations or {}}, "data": data or {}}


class Tree:
    """A scratch tree, a fake kubectl and a state document."""

    def __init__(self):
        self.root = scratch_repo("medcea-health-")
        shutil.copy(os.path.join(REPO, "health-check.sh"), self.path("health-check.sh"))
        os.makedirs(self.path("apps/backup"))
        shutil.copy(os.path.join(REPO, "apps/backup/lib-backup.sh"), self.path("apps/backup/lib-backup.sh"))
        with open(self.path("config.env"), "w") as f:
            f.write("NAMESPACE=medcea\nPOSTGRES_DB=medcea_db\n")
        self.fd = self.path(".fake")
        self.bin = os.path.join(self.fd, "bin")
        os.makedirs(self.bin)
        fake = os.path.join(self.fd, "fake.py")
        with open(fake, "w") as f:
            f.write(FAKE)
        os.chmod(fake, 0o755)
        for n in ("kubectl", "microk8s"):
            os.symlink(fake, os.path.join(self.bin, n))
        self.scenario({})
        self.st = apply_check.simulate_state()
        self.st.update(last_apply_event={"event": "bootstrap_applied", "event_id": 42, "at": "x"}, chain_ok=True,
                       unconfirmed=[{"version": 1, "kind": "bootstrap", "status": "applied"}])

    def path(self, *p):
        return os.path.join(self.root, *p)

    def scenario(self, sc):
        with open(os.path.join(self.fd, "scenario.json"), "w") as f:
            json.dump(sc, f)

    def write_state(self, st=None):
        p = os.path.join(self.fd, "state.json")
        with open(p, "w") as f:
            json.dump(self.st if st is None else st, f)
        return p

    def write_host(self, text=None):
        os.makedirs(self.path("state"), mode=0o700, exist_ok=True)
        with open(self.path("state", "policy-applied.yaml"), "w") as f:
            f.write(text if text is not None else source.host_file_text(self.st, "unknown", STAMP))
        os.chmod(self.path("state", "policy-applied.yaml"), 0o600)

    def env(self, **extra):
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.fd, MEDCEA_NO_LOG="1")
        e.pop("MEDCEA_LOG_FILE", None)
        e.update(extra)
        return e

    def fn(self, fn, call, setup="", **env):
        """One check function of health-check.sh in this tree; its _record line(s)."""
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={self.root}\nTIMEOUT=5\nKUBECTL=kubectl\n'
                  f'NAMESPACE=medcea\nsource "$SCRIPT_DIR/infra/lib-policy-source.sh"\n{setup}\n{body(fn)}\n{call}\n')
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=self.env(**env), timeout=300)
        return p.stdout.strip()

    def calls(self):
        try:
            with open(os.path.join(self.fd, "calls.log")) as f:
                return [json.loads(l)["argv"] for l in f]
        except FileNotFoundError:
            return []

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class IamPolicy(unittest.TestCase):
    """check_iampolicy: the state document of the read-only init, judged by apply_check.py health."""

    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    def run_check(self, state_file=None, verdict="ok", detail=""):
        setup = (f'POLICY_SOURCE_STATE_FILE={state_file or ""}\nPOLICY_SOURCE_VERDICT={verdict}\n'
                 f'POLICY_SOURCE_DETAIL="{detail}"')
        return self.t.fn("check_iampolicy", 'check_iampolicy "Access policy version" medcea_db', setup)

    def test_ok_before_confirmation_is_possible(self):
        self.t.write_host()
        out = self.run_check(self.t.write_state())
        self.assertEqual(out, "OK|Access policy version|version 1 (bootstrap), qa confirms it in the Policy UI "
                              "once it exists (IAM 4.3)")

    def test_the_policy_ui_running(self):
        # IAM 4.3: iam-api answers policy_port on :8083 — v1 unconfirmed WARNs, another
        # applied version FAILs, another skeleton WARNs
        self.t.write_host()
        sk = self.t.st["accepted"]["digest"]
        self.t.scenario({"iam_healthz": {"policy_port": True, "applied_version": 1, "skeleton_digest": sk}})
        self.assertEqual(self.run_check(self.t.write_state()),
                         "WARN|Access policy version|version 1 (bootstrap) is not confirmed by qa yet (the Policy UI)")
        self.t.scenario({"iam_healthz": {"policy_port": True, "applied_version": 2, "skeleton_digest": "0" * 64}})
        out = self.run_check(self.t.write_state())
        self.assertTrue(out.startswith("FAIL|Access policy version|"), out)
        self.assertIn("reports applied version 2", out)
        self.assertIn("ships skeleton 000000000000", out)
        st = dict(self.t.st, unconfirmed=[], confirmed_at="2026-11-04T10:00:00Z")
        self.t.st = st
        self.t.write_host()
        self.t.scenario({"iam_healthz": {"policy_port": True, "applied_version": 1, "skeleton_digest": sk}})
        self.assertTrue(self.run_check(self.t.write_state()).startswith("OK|Access policy version|version 1 (bootstrap), skeleton"))

    def test_an_approved_version_waits_for_its_apply(self):
        # IAM 4.5 (design §14.8.8): the instruction is apply.sh N; after a reverted apply the
        # version is approved again (_mark_reverted), and the detail says so
        self.t.write_host()
        self.t.st["open_versions"] = [{"version": 2, "kind": "change", "status": "approved", "age_days": 0,
                                       "skeleton_digest": self.t.st["accepted"]["digest"], "diff_from": None,
                                       "reverted": False}]
        self.assertEqual(self.run_check(self.t.write_state()),
                         "WARN|Access policy version|version 2 (change) is approved: ./apps/iam/apply.sh 2 --by <you> "
                         "applies it")
        self.t.st["open_versions"][0]["reverted"] = True
        self.assertEqual(self.run_check(self.t.write_state()),
                         "WARN|Access policy version|version 2 (change) is approved again after a reverted apply: "
                         "./apps/iam/apply.sh 2 --by <you>")
        # a five-digit version and the longest kind still fit health-check.sh's 160 characters
        self.t.st["open_versions"][0].update(version=12345, kind="skeleton")
        out = self.run_check(self.t.write_state())
        self.assertTrue(out.endswith("./apps/iam/apply.sh 12345 --by <you>"), out)
        self.assertLessEqual(len(out.split("|", 2)[2]), 160, out)
        self.t.st["open_versions"][0].update(version=2, kind="change", status="submitted")
        self.assertTrue(self.run_check(self.t.write_state()).startswith("OK|"))

    def test_a_stale_skeleton_proposal_warns(self):
        # a narrowing deploy accepted another skeleton under the open skeleton version
        self.t.write_host()
        acc = self.t.st["accepted"]["digest"]
        self.t.st["open_versions"] = [{"version": 2, "kind": "skeleton", "status": "submitted", "age_days": 0,
                                       "skeleton_digest": "a" * 64, "diff_from": "b" * 64}]
        self.assertEqual(self.run_check(self.t.write_state()),
                         f"WARN|Access policy version|skeleton version 2 was proposed against skeleton {'b' * 12}, the "
                         f"accepted one is now {acc[:12]}: return it and propose again")
        self.t.st["open_versions"][0]["diff_from"] = acc
        self.assertTrue(self.run_check(self.t.write_state()).startswith("OK|"))

    def test_a_proposed_widening_in_the_tree_still_fails(self):
        # the deploying tree carries the proposed skeleton: a deploy refuses it, so it stays a
        # FAIL, and the detail says to put HEAD back (the proposal waits on its branch)
        self.t.write_host()
        pol = self.t.path("apps", "iam", "policy", "defaults.yaml")
        with open(pol) as f:
            text = f.read()
        a = 'routes: {"GET /api/recipes": R}}'
        self.assertEqual(text.count(a), 1)
        with open(pol, "w") as f:
            f.write(text.replace(a, 'routes: {"GET /api/recipes": R, "GET /api/recipes/extra": R}}'))
        with open(pol) as f:
            wide = source.skeleton_digest(yaml.safe_load(f))
        out = self.run_check(self.t.write_state())
        self.assertTrue(out.startswith("FAIL|Access policy version|"), out)
        self.assertIn("a deploy would refuse it (cli.py skeleton-gate)", out)
        self.t.st["open_versions"] = [{"version": 2, "kind": "skeleton", "status": "approved", "age_days": 0,
                                       "skeleton_digest": wide, "diff_from": self.t.st["accepted"]["digest"]}]
        out = self.run_check(self.t.write_state())
        self.assertTrue(out.startswith("FAIL|Access policy version|"), out)
        # through health-check.sh, which cuts each detail at 160 characters: the whole instruction.
        # IAM 4.5 (design §14.8.8): an approved proposal names its apply
        self.assertIn("the git skeleton widens: a deploy refuses it (approved as version 2: ./apps/iam/apply.sh 2 "
                      "--by <you>)", out)
        self.assertIn("version 2 (skeleton) is approved: ./apps/iam/apply.sh 2 --by <you> applies it", out)
        # the whole detail (health-check.sh cuts each at 160 characters), from the scratch tree's judge
        p = subprocess.run([sys.executable, self.t.path("apps", "iam", "apply_check.py"), "health", "--state",
                            self.t.write_state(), "--host-file", self.t.path("state", "policy-applied.yaml")],
                           capture_output=True, text=True, env=self.t.env(), timeout=300)
        self.assertIn("FAIL|the git skeleton widens: a deploy refuses it (approved as version 2: ./apps/iam/apply.sh 2 "
                      "--by <you>)", p.stdout.splitlines())
        for line in p.stdout.splitlines():
            self.assertLessEqual(len(line.split("|", 1)[1]), 160, line)
        # --status names the approved version too (the scratch tree's judge: its git skeleton)
        p = subprocess.run([sys.executable, self.t.path("apps", "iam", "apply_check.py"), "status", "--state",
                            self.t.write_state(), "--gate-rc", "3"],
                           capture_output=True, text=True, env=self.t.env(), timeout=300, cwd=self.t.root)
        self.assertIn("WIDENING: refused by every deploy; approved as skeleton version 2: ./apps/iam/apply.sh 2 "
                      "--by <you> applies it", p.stdout)
        # a proposal still submitted: the old instruction (put HEAD back)
        self.t.st["open_versions"][0]["status"] = "submitted"
        out = self.run_check(self.t.write_state())
        self.assertIn("the git skeleton widens: a deploy refuses it (proposed as version 2, submitted: put HEAD back "
                      "at the accepted skeleton; the proposal waits on its branch)", out)
        self.t.st["open_versions"][0]["status"] = "approved"
        # the longest status and a five-digit version still fit
        self.t.st["open_versions"][0].update(version=12345, status="submitted")
        p = subprocess.run([sys.executable, self.t.path("apps", "iam", "apply_check.py"), "health", "--state",
                            self.t.write_state(), "--host-file", self.t.path("state", "policy-applied.yaml")],
                           capture_output=True, text=True, env=self.t.env(), timeout=300)
        wide = [l for l in p.stdout.splitlines() if "git skeleton widens" in l]
        self.assertEqual(len(wide), 1, p.stdout)
        self.assertTrue(wide[0].endswith("the proposal waits on its branch)"), wide[0])
        self.assertLessEqual(len(wide[0].split("|", 1)[1]), 160, wide[0])

    def test_skip_without_kubectl_or_008c(self):
        self.assertEqual(self.run_check(None, "skip", "no usable kubectl"),
                         "SKIP|Access policy version|no usable kubectl")
        st = self.t.write_state({"state": "none", "detail": "no iam_policy.skeleton in medcea_db"})
        self.assertTrue(self.run_check(st).startswith("SKIP|Access policy version|no iam_policy.skeleton"))
        # a host file without any policy version: the read-only init's verdict wins over SKIP
        out = self.run_check(st, "fail", "state/policy-applied.yaml exists but the database has no policy versions")
        self.assertEqual(out, "FAIL|Access policy version|state/policy-applied.yaml exists but the database has no "
                              "policy versions")

    def test_an_unreadable_database_fails(self):
        f = os.path.join(self.t.fd, "empty.json")
        open(f, "w").close()   # policy_db_state truncates OUT first, then returns 1
        out = self.run_check(f, "fail", "ERROR: [policy] cannot read the applied policy from PostgreSQL: boom")
        self.assertTrue(out.startswith("FAIL|Access policy version|cannot read the applied policy: "), out)
        st = self.t.write_state({"state": "unreachable", "detail": "rdbms-postgresql-0 is not Ready"})
        self.assertEqual(self.run_check(st), "FAIL|Access policy version|PostgreSQL is not Ready: "
                                             "rdbms-postgresql-0 is not Ready")

    def test_empty_with_008c_fails(self):
        st = dict(self.t.st, state="empty", version=None, accepted=None, entries=[], waivers=[])
        out = self.run_check(self.t.write_state(st))
        self.assertTrue(out.startswith("FAIL|Access policy version|no applied version: a widening git change is "
                                       "not gated until version 1 exists"), out)

    def test_absent_or_edited_host_file_fails(self):
        out = self.run_check(self.t.write_state())
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("policy-applied.yaml", out)
        text = source.host_file_text(self.t.st, "unknown", STAMP)
        self.t.write_host(text.replace("W1", "W9", 1) if "W1" in text else text + "# edited\nx: 1\n")
        self.assertTrue(self.run_check(self.t.write_state()).startswith("FAIL|"))

    def test_worst_line_wins_and_every_problem_is_listed(self):
        self.t.write_host()
        self.t.st["waivers_review"] = [{"id": "W1", "review_by": "2000-01-01"}, {"id": "W2", "review_by": "2999-01-01"}]
        os.makedirs(self.t.path("state"), exist_ok=True)
        with open(self.t.path("state", "seed-facts.jsonl"), "w") as f:
            f.write(json.dumps(apply_check.seed_fact("observed", "quinn", "22222222-2222-4222-8222-222222222222",
                                                     "qa", "p-qa")) + "\n")
        out = self.run_check(self.t.write_state())
        level, name, detail = out.split("|", 2)
        self.assertEqual((level, name), ("FAIL", "Access policy version"))
        self.assertIn("waiver W1: review_by 2000-01-01 has passed", detail)
        self.assertIn("1 account fact(s) not yet recorded", detail)
        self.assertEqual(out.count("\n"), 0)

    def test_warn_only(self):
        self.t.write_host()
        os.makedirs(self.t.path("state"), exist_ok=True)
        with open(self.t.path("state", "seed-facts.jsonl"), "w") as f:
            f.write(json.dumps(apply_check.seed_fact("observed", "quinn", "22222222-2222-4222-8222-222222222222",
                                                     "qa", "p-qa")) + "\n")
        self.assertEqual(self.run_check(self.t.write_state()),
                         "WARN|Access policy version|1 account fact(s) not yet recorded: the next deploy flushes them")

    def test_long_details_are_cut_to_160(self):
        self.t.write_host()
        self.t.st["break_glass_open"] = [{"event_id": 9, "reason": "r" * 300, "components": ["iam"], "open": ["iam"]}]
        detail = self.run_check(self.t.write_state()).split("|", 2)[2]
        self.assertEqual(len(detail), 160)
        self.assertTrue(detail.startswith("policy break-glass event 9"))

    def test_an_apply_holding_the_lock_is_in_progress(self):
        self.t.write_host()
        self.t.st["last_apply_event"] = {"event": "apply_started", "event_id": 40, "at": "x"}
        st = self.t.write_state()
        self.assertTrue(self.run_check(st).startswith("FAIL|Access policy version|version 1 was committed"))
        lock = self.t.path(".medcea.lock")
        # a holder of the scratch tree's lock whose command line names apps/iam/apply.sh
        p = subprocess.Popen(["bash", "-c", 'exec 9>>"$1"; sleep 30; :', "apps/iam/apply.sh", lock])
        try:
            for _ in range(50):
                if os.path.exists(f"/proc/{p.pid}/fd/9"):
                    break
                import time
                time.sleep(0.05)
            self.assertEqual(self.run_check(st), "WARN|Access policy version|an apply is in progress")
        finally:
            p.kill()
            p.wait()

    def test_a_crash_of_the_judge_fails(self):
        f = os.path.join(self.t.fd, "bad.json")
        with open(f, "w") as fh:
            fh.write("{not json")
        out = self.run_check(f)
        self.assertTrue(out.startswith("FAIL|Access policy version|apply_check.py health failed (exit "), out)

    def test_it_never_runs_flock_or_writes(self):
        self.t.write_host()
        before = sorted(os.listdir(self.t.path("state")))
        self.run_check(self.t.write_state())
        self.assertEqual(sorted(os.listdir(self.t.path("state"))), before)
        self.assertNotIn("flock", body("check_iampolicy"))
        # one kubectl of its own (IAM 4.3): iam-api's /healthz on :8083, read in the pod; the
        # init read the state
        calls = self.t.calls()
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(calls[0][:4], ["exec", "-n", "medcea", "deployment/iam-api"])
        self.assertIn("http://127.0.0.1:8083/healthz", calls[0][-1])


class Apply45(unittest.TestCase):
    """IAM 4.5 (design §14.8.8): what health says around apply.sh N, its revert and --rollback-to.
    Every detail goes through health-check.sh's check_iampolicy (cut at 160 characters)."""

    NAME = "Access policy version"

    def setUp(self):
        self.t = Tree()
        self.t.write_host()

    def tearDown(self):
        self.t.close()

    def run_check(self, scenario=None):
        if scenario is not None:
            self.t.scenario(scenario)
        setup = f'POLICY_SOURCE_STATE_FILE={self.t.write_state()}\nPOLICY_SOURCE_VERDICT=ok\nPOLICY_SOURCE_DETAIL=""'
        return self.t.fn("check_iampolicy", f'check_iampolicy "{self.NAME}" medcea_db', setup)

    def details(self, out):
        level, name, detail = out.split("|", 2)
        self.assertEqual(name, self.NAME)
        parts = detail.split(";")
        for d in parts:
            self.assertLessEqual(len(d), 160, d)
        return level, parts

    def as_version(self, v, kind):
        """The applied version renumbered (its host file rewritten to match)."""
        self.t.st.update(state=f"version-{v}", version=v, kind=kind, unconfirmed=[])
        self.t.st["entries_digest"] = source.entries_digest(kind, self.t.st["groups"], self.t.st["roles"],
                                                            self.t.st["entries"], self.t.st["waivers"])
        self.t.write_host()

    def test_a_clean_revert_ends_with_applied_under_the_previous_version(self):
        # the revert's records: apply_reverted and partial_apply {reverted} under N, then
        # applied {reverted_from: N} under prev, the latest apply event again
        self.t.st["last_apply_event"] = {"event": "applied", "event_id": 60, "at": "x", "outcome": None}
        self.t.st["last_events"] = [{"event_id": 60, "event": "applied", "version": 1},
                                    {"event_id": 59, "event": "partial_apply", "version": 2},
                                    {"event_id": 58, "event": "apply_reverted", "version": 2},
                                    {"event_id": 57, "event": "apply_started", "version": 2}]
        self.assertTrue(self.run_check().startswith("OK|"))
        # without the closing applied the rule still FAILs (no tolerance was added)
        self.t.st["last_events"] = self.t.st["last_events"][1:]
        level, parts = self.details(self.run_check())
        self.assertEqual(level, "FAIL")
        self.assertIn("the latest apply event (apply_reverted 58) names version 2, the applied one is 1", parts)

    def test_partial_apply_fails_and_an_unfinished_revert_says_so(self):
        self.t.st["last_apply_event"] = {"event": "partial_apply", "event_id": 61, "at": "x", "outcome": "mixed"}
        self.assertEqual(self.run_check(), f"FAIL|{self.NAME}|version 1: partial_apply "
                                           "(./apps/iam/apply.sh --resume --by <you>)")
        self.t.st["last_apply_event"]["outcome"] = "reverting"
        self.assertEqual(self.run_check(), f"FAIL|{self.NAME}|version 1: a revert is unfinished "
                                           "(./apps/iam/apply.sh --resume --by <you>)")

    def test_the_sequence_finding_waits_while_an_apply_runs(self):
        self.t.st["last_apply_event"] = {"event": "apply_started", "event_id": 40, "at": "x"}
        self.t.st["audit_findings"] = [{"version": 1, "finding": "sequence"}]
        level, parts = self.details(self.run_check())
        self.assertEqual(level, "FAIL")
        self.assertIn("audit_versions(): version 1 sequence", parts)
        self.assertTrue(any(p.startswith("version 1 was committed but its apply did not record its end") for p in parts))
        lock = self.t.path(".medcea.lock")
        # it must outlive two checks, each of which can take seconds; its own session, so the
        # finally kills its sleep too (an orphan would keep the lock and the test's output open)
        p = subprocess.Popen(["bash", "-c", 'exec 9>>"$1"; sleep 600; :', "apps/iam/apply.sh", lock],
                             start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(200):
                if os.path.exists(f"/proc/{p.pid}/fd/9"):
                    break
                import time
                time.sleep(0.05)
            self.assertEqual(self.run_check(), f"WARN|{self.NAME}|an apply is in progress")
            # another version's sequence finding, or another finding, is still a FAIL
            self.t.st["audit_findings"] = [{"version": 1, "finding": "sequence"}, {"version": 1, "finding": "approval_mismatch"}]
            level, parts = self.details(self.run_check())
            self.assertEqual(level, "FAIL")
            self.assertEqual(sorted(parts), ["an apply is in progress", "audit_versions(): version 1 approval_mismatch"])
        finally:
            os.killpg(p.pid, 9)
            p.wait()

    def _accept(self, **rv):
        """An accept whose to_body widens over its from_body (a route removed from 'from')."""
        to = self.t.st["accepted"]["body"]
        frm = json.loads(json.dumps(to))
        api = [m for m in frm["resource_groups"]["recipes"]["members"] if m.get("type") == "api"
               and m.get("service") == "scheduler"]
        self.assertEqual(api[0]["routes"], {"GET /api/recipes": "R"})
        api[0]["routes"] = {}
        a = {"event_id": 70, "from": "f" * 64, "to": self.t.st["accepted"]["digest"], "from_body": frm, "to_body": to,
             "version": 1, "reviewed_by_version": 2, "entries": self.t.st["entries"], "waivers": self.t.st["waivers"]}
        a.update(rv)
        self.t.st["accepts"] = [a]

    def test_the_accepts_audit_checks_reviewed_by_version(self):
        acc = self.t.st["accepted"]["digest"]
        want = f"FAIL|{self.NAME}|skeleton {acc[:12]} was accepted at event 70 but widens over {'f' * 12}"
        # a forged summary: no such version
        self._accept(rv_kind=None, rv_status=None, rv_skeleton=None)
        self.assertEqual(self.run_check(), want)
        # a change version, an approved (not applied) skeleton version, another digest: recomputed
        for bad in ({"rv_kind": "change", "rv_status": "applied", "rv_skeleton": acc},
                    {"rv_kind": "skeleton", "rv_status": "approved", "rv_skeleton": acc},
                    {"rv_kind": "skeleton", "rv_status": "applied", "rv_skeleton": "e" * 64}):
            self._accept(**bad)
            self.assertEqual(self.run_check(), want, bad)
        # the applied (or since superseded) skeleton version proposing that digest: reviewed
        for status in ("applied", "superseded"):
            self._accept(rv_kind="skeleton", rv_status=status, rv_skeleton=acc)
            self.assertTrue(self.run_check().startswith("OK|"), status)

    def _narrow_git(self):
        pol = self.t.path("apps", "iam", "policy", "defaults.yaml")
        with open(pol) as f:
            text = f.read()
        a = '"GET /api/algorithms": R, "PUT /api/algorithms/<id>": U, "GET /api/param-sets": R}'
        self.assertEqual(text.count(a), 1)
        with open(pol, "w") as f:
            f.write(text.replace(a, '"GET /api/algorithms": R, "PUT /api/algorithms/<id>": U}'))

    def test_a_narrowing_git_skeleton_would_undo_an_applied_skeleton_version(self):
        self._narrow_git()
        self.t.st["last_events"] = []
        self.assertEqual(self.run_check(), f"WARN|{self.NAME}|the git skeleton narrows: accepted at the next deploy")
        self.t.st["accepted"]["reviewed_by_version"] = 12345
        self.assertEqual(self.run_check(), f"WARN|{self.NAME}|git skeleton narrows: a deploy would undo skeleton "
                                           "version 12345; keep its commit on the deployed branch")
        gate = os.path.join(self.t.fd, "gate.json")
        with open(gate, "w") as f:
            json.dump({"verdict": "narrowing"}, f)
        p = subprocess.run([sys.executable, self.t.path("apps", "iam", "apply_check.py"), "status", "--state",
                            self.t.write_state(), "--gate", gate], capture_output=True, text=True, env=self.t.env(),
                           timeout=300, cwd=self.t.root)
        self.assertIn("narrowing: a deploy would accept it and undo skeleton version 12345", p.stdout)

    def test_an_unconfirmed_or_disputed_rollback(self):
        self.as_version(3, "rollback")
        sk = self.t.st["accepted"]["digest"]
        live = {"iam_healthz": {"policy_port": True, "applied_version": 3, "skeleton_digest": sk}}
        self.t.st["unconfirmed"] = [{"version": 3, "kind": "rollback", "status": "applied"}]
        self.assertEqual(self.run_check(live), f"WARN|{self.NAME}|version 3 (rollback) is not confirmed by qa yet "
                                               "(the Policy UI)")
        self.t.st.update(unconfirmed=[], disputed_at="2026-11-04T10:00:00Z", disputed_not_superseded=[3])
        self.assertEqual(self.run_check(live), f"FAIL|{self.NAME}|version 3 is disputed and not superseded")
        self.t.st.update(disputed_at=None, disputed_not_superseded=[], confirmed_at="2026-11-04T10:00:00Z")
        self.assertTrue(self.run_check(live).startswith(f"OK|{self.NAME}|version 3 (rollback), skeleton"))

    def test_the_state_query_reads_what_these_need(self):
        """The --full query: the reverted_unreviewed window from the reverted version's
        apply_started; the accept's reviewed version; the outcome of the last apply event;
        the accepted skeleton's reviewed_by_version; an open version's earlier revert."""
        sql = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-policy-source.sh"; _ps_state_sql true'],
                             capture_output=True, text=True, env=clean_env()).stdout
        i, j = sql.index("\\if :has_decisions"), sql.index("\\else\nSELECT '[]' AS reverted_unreviewed")
        self.assertIn("WHERE a.event = 'apply_started' AND a.event_id < h.event_id", sql[i:j])
        self.assertNotIn("'bootstrap_applied') AND a.event_id < h.event_id", sql[i:j])
        self.assertIn("'rv_kind', rv.kind, 'rv_status', rv.status, 'rv_skeleton', rv.skeleton_digest", sql)
        self.assertIn("LEFT JOIN iam_policy.version rv ON rv.version = CASE WHEN h.payload ->> 'reviewed_by_version' "
                      "~ '^[0-9]+$'", sql)
        self.assertIn("'outcome', h.payload ->> 'outcome'", sql)
        self.assertIn("'reviewed_by_version', s.reviewed_by_version", sql)
        self.assertIn("'reverted', EXISTS (SELECT 1 FROM iam_policy.history r WHERE r.version = v.version "
                      "AND r.event = 'apply_reverted')", sql)
        base = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-policy-source.sh"; _ps_state_sql false'],
                              capture_output=True, text=True, env=clean_env()).stdout
        self.assertIn("'outcome', h.payload ->> 'outcome'", base)
        self.assertNotIn("rv_kind", base)


class IamArtefacts(unittest.TestCase):
    """check_iamartefacts: routes, mqtt and every proxy gate against the applied version's compile."""

    @classmethod
    def setUpClass(cls):
        cls.t = Tree()
        cli = cls.t.path("apps/iam/compiler/cli.py")
        env = cls.t.env()

        def comp(*a):
            return subprocess.run([sys.executable, cli, *a], capture_output=True, text=True, env=env,
                                  check=True).stdout
        cls.routes = comp("compile", "routes")
        cls.mqtt = comp("compile", "mqtt")
        cls.rd, cls.md = json.loads(cls.routes)["digest"], json.loads(cls.mqtt)["digest"]
        sys.path.insert(0, cls.t.path("apps/iam"))
        p = source.factory()
        cls.proxies = dict(p["network"]["proxies"])
        cls.lists = {h: json.loads(comp("compile", "proxy", h)) for h in cls.proxies}

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def setUp(self):
        try:
            os.remove(os.path.join(self.t.fd, "calls.log"))
        except FileNotFoundError:
            pass

    def gate_cm(self, host, roles=None, line=True):
        roles = self.lists[host] if roles is None else roles
        cfg = 'email_domains = ["*"]\n'
        if line:
            cfg += "allowed_groups = [" + ",".join(f'"{r}"' for r in roles) + "]\n"
        return cm_doc(self.proxies[host], {"oauth2_proxy.cfg": cfg})

    def scenario(self, skip=("POLICY_DOMAIN",), lib=None, gates=None, **sc):
        cms = {}
        if lib is not False:
            cms["medcea-iam-lib"] = lib or cm_doc(
                "medcea-iam-lib", {"routes.json": self.routes, "mqtt.json": self.mqtt, "settings.json": "{}"},
                {"medcea/routes-digest": self.rd, "medcea/mqtt-digest": self.md})
        for h in self.proxies:
            if h not in skip:
                cms[self.proxies[h]] = (gates or {}).get(h) or self.gate_cm(h)
        sc["configmaps"] = cms
        self.t.scenario(sc)

    def run_check(self, **env):
        return self.t.fn("check_iamartefacts", 'check_iamartefacts "Policy artefacts" medcea', **env)

    def test_ok_counts_gates_and_hosts_not_deployed(self):
        self.scenario()
        n = len(self.proxies)
        self.assertEqual(self.run_check(), f"OK|Policy artefacts|routes, mqtt and {n - 1} gates equal the applied "
                                           "version's compile; 1 hosts not deployed")
        self.assertTrue(all(a[0] == "get" for a in self.t.calls()), self.t.calls())

    def test_skip_without_the_configmap(self):
        self.scenario(lib=False)
        self.assertEqual(self.run_check(), "SKIP|Policy artefacts|no ConfigMap medcea-iam-lib in medcea yet "
                                           "(./deploy-infra.sh)")

    def test_an_unreadable_cluster_fails(self):
        self.scenario(api_down=True)
        self.assertTrue(self.run_check().startswith("FAIL|Policy artefacts|cannot read ConfigMap medcea-iam-lib: "))

    def test_a_stale_routes_or_mqtt_digest_fails(self):
        lib = cm_doc("medcea-iam-lib", {"routes.json": self.routes, "mqtt.json": self.mqtt},
                     {"medcea/routes-digest": "0" * 64, "medcea/mqtt-digest": self.md})
        self.scenario(lib=lib)
        out = self.run_check()
        self.assertTrue(out.startswith("FAIL|Policy artefacts|routes: annotation 000000000000, routes.json "
                                       f"{self.rd[:12]}, the applied version compiles {self.rd[:12]} (./deploy-infra.sh)"),
                        out)
        lib = cm_doc("medcea-iam-lib", {"routes.json": self.routes, "mqtt.json": "{}"},
                     {"medcea/routes-digest": self.rd, "medcea/mqtt-digest": self.md})
        self.scenario(lib=lib)
        self.assertIn("mqtt: annotation", self.run_check())

    def test_a_gate_that_differs_fails_naming_its_deploy(self):
        self.scenario(gates={"MONITOR_DOMAIN": self.gate_cm("MONITOR_DOMAIN", ["admin", "operator"])})
        out = self.run_check()
        self.assertTrue(out.startswith("FAIL|Policy artefacts|gate MONITOR_DOMAIN (monitor-oauth2-proxy) admits "
                                       "[admin operator], the applied version compiles ["), out)
        self.assertIn("(./apps/monitor/deploy.sh)", out)
        self.scenario(gates={"PORTAL_DOMAIN": self.gate_cm("PORTAL_DOMAIN", line=False)})
        self.assertIn("gate PORTAL_DOMAIN (portal-oauth2-proxy) has no allowed_groups", self.run_check())

    def test_the_user_managers_admin_fallback_warns(self):
        self.scenario(gates={"ACCESS_DOMAIN": self.gate_cm("ACCESS_DOMAIN", ["admin"])})
        self.assertEqual(self.run_check(), "WARN|Policy artefacts|the User Manager's gate is admin-only: not every "
                                           "access pod proved it enforces (./apps/access/deploy.sh)")

    def test_iam_gates_false_compares_the_pre_policy_lists(self):
        pre = ["operator", "qa", "auditor", "admin"]
        gates = {h: self.gate_cm(h, pre) for h in self.proxies if h not in ("NODE_RED_DOMAIN", "MQTTX_DOMAIN")}
        gates["ACCESS_DOMAIN"] = self.gate_cm("ACCESS_DOMAIN", ["admin"])
        self.scenario(gates=gates)
        self.assertTrue(self.run_check(IAM_GATES="false").startswith("OK|Policy artefacts|"))
        self.scenario()   # the compiled lists while IAM_GATES=false: every pre-policy host differs
        self.assertTrue(self.run_check(IAM_GATES="false").startswith("FAIL|"))

    def test_it_reads_the_applied_version(self):
        """With a host file, the compile reads it: the label is unhashed, so the digest is the same."""
        st = apply_check.simulate_state()
        self.t.write_host(source.host_file_text(st, "unknown", STAMP))
        try:
            self.scenario()
            self.assertTrue(self.run_check().startswith("OK|"))
        finally:
            shutil.rmtree(self.t.path("state"))


class EndToEnd(unittest.TestCase):
    """health-check.sh itself: the read-only init's state document reaches iampolicy, then is removed."""

    def test_two_checks_through_the_read_only_init(self):
        t = Tree()
        try:
            t.write_host()
            t.write_state()
            conf = t.path("two.conf")
            with open(conf, "w") as f:
                f.write("Access policy version    | iampolicy | $POSTGRES_DB |\n"
                        "Policy artefacts         | iamartefacts | $NAMESPACE |\n")
            t.scenario({"configmaps": {}})
            # its own TMPDIR: a leak shows here whatever else runs at the same time, and a
            # leak cannot hide in another directory
            tmp = t.path("tmp")
            os.mkdir(tmp, 0o700)
            p = subprocess.run(["bash", t.path("health-check.sh"), "-c", conf, "-v"], capture_output=True,
                               text=True, env=t.env(TMPDIR=tmp), cwd=t.root, stdin=subprocess.DEVNULL, timeout=600)
            out = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout)
            self.assertRegex(out, r"\[  OK  \]  Access policy version\s+version 1 \(bootstrap\), qa confirms it")
            self.assertRegex(out, r"\[ SKIP \]  Policy artefacts\s+no ConfigMap medcea-iam-lib in medcea yet")
            self.assertIn("All 2 checks passed.", out)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(os.listdir(tmp), [], "the state document's directory was left behind")
            verbs = {a[0] for a in t.calls()}
            self.assertLessEqual(verbs, {"version", "get", "exec"})
        finally:
            t.close()


SS_KUBECTL = r"""#!/bin/sh
# a fake kubectl for check_supersetroles: read verbs only, answers from $FAKE_DIR
echo "$*" >> "$FAKE_DIR/calls.log"
case "$*" in
  "get deployment superset -n medcea") test -f "$FAKE_DIR/deploy.json" ;;
  "get deployment,replicaset -n medcea -l app=superset -o json") test -f "$FAKE_DIR/deploy.json" && cat "$FAKE_DIR/deploy.json" ;;
  "get secret superset-secrets -n medcea -o json") test -f "$FAKE_DIR/secret.json" && cat "$FAKE_DIR/secret.json" ;;
  "get configmap superset-config -n medcea -o json") test -f "$FAKE_DIR/cm.json" && cat "$FAKE_DIR/cm.json" ;;
  "get pod -n medcea -l app=superset,component=web -o json") test -f "$FAKE_DIR/pods.json" && cat "$FAKE_DIR/pods.json" ;;
  *) echo "fake kubectl: unexpected $*" >&2; exit 99 ;;
esac
"""

SS_KEY = "ab" * 32
SS_PASS = "Zq8sY1pXv0rT4mN7bW2c"
SS_MAP = {"engineer": ["Alpha", "sql_lab"], "qp": ["Gamma", "MedCEA Viewer"]}


def ss_deploy(env=None, image="docker.io/apache/superset:6.1.0@sha256:" + "8b" * 32, rs_env=None, init_env=None):
    base = [{"name": "SUPERSET_DB_USER", "value": "svc_superset"},
            {"name": "SUPERSET_PORT", "value": "8088"},
            {"name": "SUPERSET_SECRET_KEY", "valueFrom": {"secretKeyRef": {"name": "superset-secrets",
                                                                           "key": "SUPERSET_SECRET_KEY"}}}]

    def obj(kind, name, env_):
        return {"kind": kind, "metadata": {"name": name},
                "spec": {"template": {"spec": {
                    "initContainers": [{"name": "superset-deps", "image": image, "env": init_env or []}],
                    "containers": [{"name": "superset", "image": image, "env": env_}]}}}}
    items = [obj("Deployment", "superset", env if env is not None else base)]
    if rs_env is not None:
        items.append(obj("ReplicaSet", "superset-old", rs_env))
    return {"kind": "List", "items": items}


def ss_secret(key=SS_KEY, mapping=SS_MAP, drop=()):
    data = {"SUPERSET_SECRET_KEY": key, "SUPERSET_META_DB_PASS": SS_PASS, "SVC_SUPERSET_DB_PASS": "Kp3vW9xT2qL8nB5mR1sD",
            "SUPERSET_CLIENT_SECRET": "c" * 32, "SUPERSET_ROLES_MAPPING": json.dumps(mapping)}
    return {"kind": "Secret", "metadata": {"name": "superset-secrets"},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items() if k not in drop}}


SS_CM = {"kind": "ConfigMap", "metadata": {"name": "superset-config"},
         "data": {"superset_config.py": "APP_NAME = 'x'\n", "requirements.txt": "a==1 --hash=sha256:" + "0" * 64 + "\n"}}


def ss_pods(*checksums, phase="Running"):
    return {"kind": "List", "items": [
        {"metadata": {"name": "superset-%d" % i, "annotations": {"medcea/config-checksum": c} if c else {}},
         "status": {"phase": phase}} for i, c in enumerate(checksums)]}


class SupersetRoles(unittest.TestCase):
    """check_supersetroles (Superset stages B and C): a fake kubectl, policy_tool stubbed or
    the real library in a scratch tree (commit A's policy without the tool: rc 5; the factory
    policy since commit B: the mapping); the live-pod checksum through
    apps/superset/lib-superset.sh, the deploy's own."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="medcea-ss-")
        self.fd = os.path.join(self.tmp, "fake")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.fd)
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "kubectl"), "w") as f:
            f.write(SS_KUBECTL)
        os.chmod(os.path.join(self.bin, "kubectl"), 0o755)
        self.put_lib(self.tmp)

    @staticmethod
    def put_lib(root):
        os.makedirs(os.path.join(root, "apps", "superset"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "superset", "lib-superset.sh"),
                    os.path.join(root, "apps", "superset", "lib-superset.sh"))

    def live_sum(self):
        """What apps/superset/deploy.sh writes into the pod template for the fake cluster."""
        p = subprocess.run(["bash", "-c", 'source "$1"; superset_config_checksum medcea', "x",
                            os.path.join(REPO, "apps", "superset", "lib-superset.sh")],
                           env=clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.fd,
                                         KUBECTL="kubectl"), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.strip()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cluster(self, deploy=None, secret=None, cm=SS_CM, pods=True):
        for n, doc in (("deploy.json", deploy), ("secret.json", secret), ("cm.json", cm)):
            if doc is not None:
                with open(os.path.join(self.fd, n), "w") as f:
                    json.dump(doc, f)
        if pods is True:   # one running pod started with the live Secret and ConfigMap
            pods = ss_pods(self.live_sum()) if secret is not None else ss_pods()
        if pods is not None:
            with open(os.path.join(self.fd, "pods.json"), "w") as f:
                json.dump(pods, f)

    def run_check(self, want=None, rc=0, stub=True, root=None, **env):
        setup = ""
        if stub:
            setup = ('policy_tool() { [ "$1" = superset ] || return 2; [ "$FAKE_RC" = 0 ] || return "$FAKE_RC"; '
                     'echo "$FAKE_WANT"; }')
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={root or self.tmp}\nTIMEOUT=5\nKUBECTL=kubectl\n'
                  f'NAMESPACE=medcea\n{setup}\n{body("check_supersetroles")}\ncheck_supersetroles "Superset roles" medcea\n')
        e = clean_env(**dict(dict(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.fd, FAKE_RC=str(rc),
                                  FAKE_WANT=json.dumps(want if want is not None else SS_MAP), MEDCEA_NO_LOG="1",
                                  IAM_DB_SERVICE_ROLES="true"), **env))
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=120)
        out = p.stdout.strip()
        for secret in (SS_KEY, SS_PASS, "Kp3vW9xT2qL8nB5mR1sD", "c" * 32):
            self.assertNotIn(secret, out + p.stderr)
        with open(os.path.join(self.fd, "calls.log")) as f:
            for call in f:
                self.assertRegex(call, r"^get ", call)
        status, _, msg = out.split("|", 2)
        return status, msg

    def test_skip_when_not_deployed(self):
        status, msg = self.run_check()
        self.assertEqual(status, "SKIP", msg)
        self.assertIn("once the applied access policy gives a role a Superset setting", msg)
        self.assertNotIn("stage C", msg)
        # F7: a fresh install has IAM_DB_SERVICE_ROLES=false, and the deploy skips for it
        for v in ("false", ""):
            status, msg = self.run_check(IAM_DB_SERVICE_ROLES=v)
            self.assertEqual(status, "SKIP", msg)
            self.assertIn("it needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)", msg)

    def test_service_roles_false_while_deployed_warns(self):
        self.cluster(ss_deploy(), ss_secret())
        status, msg = self.run_check(IAM_DB_SERVICE_ROLES="false")
        self.assertEqual(status, "WARN", msg)
        self.assertIn("the next ./apps/superset/deploy.sh (or --gate-only) stops Superset", msg)

    def test_live_checksum(self):
        # F10: the mapping is a secretKeyRef env, read at start only. A pod started before
        # the Secret changed FAILs although the Secret itself matches the policy.
        self.cluster(ss_deploy(), ss_secret())
        good = self.live_sum()
        self.assertRegex(good, r"^[0-9a-f]{64}$")
        self.assertEqual(self.run_check()[0], "OK")
        for pods, why in ((ss_pods("f" * 64), "another checksum"), (ss_pods(None), "no annotation"),
                          (ss_pods(good, "e" * 64), "one of two pods")):
            with self.subTest(why):
                self.cluster(ss_deploy(), ss_secret(), pods=pods)
                status, msg = self.run_check()
                self.assertEqual(status, "FAIL", msg)
                self.assertIn("was started with another Secret or ConfigMap (medcea/config-checksum)", msg)
        # the ConfigMap counts as much as the Secret
        self.cluster(ss_deploy(), ss_secret(), pods=ss_pods(good),
                     cm=dict(SS_CM, data={"superset_config.py": "APP_NAME = 'y'\n"}))
        self.assertEqual(self.run_check()[0], "FAIL")
        # no running pod (a pending one does not count): WARN; unreadable pods or ConfigMap: FAIL
        self.cluster(ss_deploy(), ss_secret(), pods=ss_pods(good, phase="Pending"))
        status, msg = self.run_check()
        self.assertEqual(status, "WARN", msg)
        self.assertIn("no running Superset pod", msg)
        os.remove(os.path.join(self.fd, "pods.json"))
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("cannot compare the running Superset", msg)
        self.cluster(ss_deploy(), ss_secret(), pods=ss_pods(good))
        os.remove(os.path.join(self.fd, "cm.json"))
        self.assertEqual(self.run_check()[0], "FAIL")

    def test_ok(self):
        self.cluster(ss_deploy(), ss_secret())
        status, msg = self.run_check(want={"qp": ["MedCEA Viewer", "Gamma"], "engineer": ["sql_lab", "Alpha"]})
        self.assertEqual(status, "OK", msg)
        self.assertIn("maps engineer, qp from the access policy", msg)

    def test_mapping_drift_fails(self):
        self.cluster(ss_deploy(), ss_secret(mapping=dict(SS_MAP, qa=["Gamma", "MedCEA Viewer"])))
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("AUTH_ROLES_MAPPING is", msg)
        self.assertIn('"qa"', msg)
        self.cluster(secret=ss_secret(mapping={"engineer": ["Admin"]}))
        self.assertEqual(self.run_check()[0], "FAIL")

    def test_plain_env_secret_fails(self):
        cases = {
            "by name": dict(env=[{"name": "SUPERSET_DB_USER", "value": "svc_superset"},
                                 {"name": "SUPERSET_SECRET_KEY", "value": "x"}]),
            "by value": dict(env=[{"name": "SUPERSET_DB_USER", "value": "svc_superset"},
                                  {"name": "SQLA_URL", "value": SS_PASS}]),
            "in an init container": dict(init_env=[{"name": "SUPERSET_META_DB_PASS", "value": "y"}]),
            "in a kept ReplicaSet": dict(rs_env=[{"name": "SUPERSET_CLIENT_SECRET", "value": "z"}]),
        }
        for why, kw in cases.items():
            with self.subTest(why):
                self.cluster(ss_deploy(**kw), ss_secret())
                status, msg = self.run_check()
                self.assertEqual(status, "FAIL", msg)
                self.assertIn("plain env values in", msg)

    def test_secret_problems_fail(self):
        for secret, want in ((None, "Secret superset-secrets is missing"),
                             (ss_secret(key=""), "SUPERSET_SECRET_KEY is empty"),
                             (ss_secret(drop=("SUPERSET_SECRET_KEY",)), "SUPERSET_SECRET_KEY is empty"),
                             (ss_secret(key="CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"), "is default"),
                             (ss_secret(key="short"), "is short"),
                             (ss_secret(drop=("SUPERSET_ROLES_MAPPING",)), "AUTH_ROLES_MAPPING is ?")):
            with self.subTest(want):
                for n in ("deploy.json", "secret.json"):
                    if os.path.exists(os.path.join(self.fd, n)):
                        os.remove(os.path.join(self.fd, n))
                self.cluster(ss_deploy(), secret)
                status, msg = self.run_check()
                self.assertEqual(status, "FAIL", msg)
                self.assertIn(want, msg)

    def test_connection_user_and_image(self):
        self.cluster(ss_deploy(env=[{"name": "SUPERSET_DB_USER", "value": "postgres"}]), ss_secret())
        status, msg = self.run_check()
        self.assertEqual((status, "logs in as postgres, not svc_superset" in msg), ("FAIL", True), msg)
        self.cluster(ss_deploy(env=[]), ss_secret())
        self.assertIn("logs in as -", self.run_check()[1])
        self.cluster(ss_deploy(image="apache/superset:6.1.0"), ss_secret())
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("not pinned by digest: apache/superset:6.1.0", msg)

    def test_policy_tool_answers(self):
        self.cluster(ss_deploy(), ss_secret())
        status, msg = self.run_check(rc=3)
        self.assertEqual(status, "WARN", msg)
        self.assertIn("IAM_GATES=false", msg)
        status, msg = self.run_check(rc=5)
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("has no superset tool, or no role is given a setting", msg)
        self.assertIn("./apps/superset/deploy.sh --gate-only stops it", msg)
        status, msg = self.run_check(rc=1)
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("cannot compile", msg)

    def test_unreadable_fails(self):
        self.cluster(ss_deploy(), ss_secret())
        with open(os.path.join(self.fd, "deploy.json"), "w") as f:
            f.write("not json")
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("cannot read", msg)

    def test_the_real_library_today(self):
        """The real policy_tool in a scratch tree: commit A's policy (no superset tool) FAILs a
        deployed Superset; the factory policy since stage C's commit B gives the six roles
        their mapping (N1, N2), and a Secret holding it is OK."""
        sys.path.insert(0, HERE)
        import test_policy
        from compiler import model, tools
        factory = model.load_defaults()
        root = scratch_repo("medcea-ss-")
        try:
            self.put_lib(root)
            with open(os.path.join(root, "apps", "iam", "policy", "defaults.yaml"), "w") as f:
                yaml.safe_dump(test_policy.without_superset(json.loads(json.dumps(factory.data))), f)
            self.cluster(ss_deploy(), ss_secret())
            status, msg = self.run_check(stub=False, root=root, IAM_GATES="true")
            self.assertEqual(status, "FAIL", msg)
            self.assertIn("has no superset tool", msg)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        root = scratch_repo("medcea-ss-")
        try:
            self.put_lib(root)
            mapping = tools.superset_roles_mapping(factory)
            self.cluster(ss_deploy(), ss_secret(mapping=mapping))
            status, msg = self.run_check(stub=False, root=root, IAM_GATES="true")
            self.assertEqual(status, "OK", msg)
            self.assertIn("maps bio_scientist, control_scientist, engineer, production_manager, qc, qp", msg)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class Wiring(unittest.TestCase):
    """The conf lines, the dispatch and the help, as design §14.4.14 names them."""

    def test_conf_dispatch_and_help(self):
        with open(os.path.join(REPO, "health-checks.conf")) as f:
            conf = f.read()
        lines = [l for l in conf.splitlines() if l.strip() and not l.startswith("#")]
        names = [l.split("|")[0].strip() for l in lines]
        i = names.index("Database grants")
        self.assertEqual(names[i + 1:i + 3], ["Access policy version", "Policy artefacts"])
        self.assertEqual([l.split("|")[1].strip() for l in lines[i + 1:i + 3]], ["iampolicy", "iamartefacts"])
        self.assertEqual(len(lines), 56)
        # Superset stage B: one more check, SKIP until Superset is deployed (stage C: none more)
        row = [l for l in lines if l.split("|")[0].strip() == "Superset roles"]
        self.assertEqual([x.strip() for x in row[0].split("|")[1:3]], ["supersetroles", "$NAMESPACE"])
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
        self.assertIn('iampolicy)    check_iampolicy "$name" "$target" ;;', src)
        self.assertIn('iamartefacts) check_iamartefacts "$name" "$target" ;;', src)
        self.assertIn("${CYAN}iampolicy${NC}", src)
        self.assertIn("${CYAN}iamartefacts${NC}", src)
        self.assertIn('supersetroles) check_supersetroles "$name" "$target" ;;', src)
        self.assertIn("${CYAN}supersetroles${NC}", src)
        # the state document's directory is removed at exit
        self.assertRegex(src, r"trap 'rm -rf \"\$\(dirname \"\$POLICY_SOURCE_STATE_FILE\"\)\"' EXIT")


if __name__ == "__main__":
    unittest.main()
