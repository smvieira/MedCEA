#!/usr/bin/env python3
"""tests/test_health_research.py — health-check.sh's research sandbox checks (Phase 2a).

Offline. Each check runs in a scratch tree (tests/test_health_phase5.py's Tree: a
tests/_scratch.py copy) against its fake kubectl, which refuses every writing verb and logs
each call with its stdin. Nothing reaches a cluster or the repository's state/.

  RsNetpol        rsnetpol: every branch (no kubectl, switched off with and without the
                  namespace, no research zone, a broken policy, the namespace missing,
                  unreadable, missing / differing / extra policies, labelled or not (the chart's
                  own allow-all), the compiled set), against
                  a stub cli.py in the scratch tree (it logs its argv; the zone's compile is the
                  compiler's own business, tests/test_research_netpol.py)
  RsNetpolRealCli the scratch tree's real cli.py on commit A's defaults.yaml (no research zone)
                  SKIPs
  RsExportAge     rsexport_age_status alone: OK / WARN past 26 h / FAIL past 72 h, no snapshot
                  SKIP on the first day, WARN then FAIL later
  RsExport        rsexport: no CronJob, unreadable CronJob, the read-only psql (SQL on stdin,
                  PGOPTIONS read-only, the guards), unbuilt / partial database, unreadable
                  numbers, reserved rows in the lake, no reservation, the age, OK
  RsGrants        rsgrants (Phase 2b): every Secret reference a pod spec can make, per
                  allow-list class (the probe before the notebook labels it carries), Roles on
                  secrets or *, RoleBindings to a ClusterRole, assert_grants.sql run read-only
                  (its lines FAIL), no database yet, the skip and warn branches
  RsLake          rslake (Phase 2b): no lake-api SKIPs; the lake roles' assert lines FAIL (others
                  are rsgrants'); the pod, its root from the host, the newest snapshot's digest
                  check (read-only, SQL on stdin)
  WbAccounts      wbaccounts (Phase 2b): the hub's sqlite read mode=ro in the placement's
                  namespace, names only; the realm's enabled accounts read-only; WARN only
  IamWorkbench    iamworkbench's placement (Phase 2b) against the scratch tree's real cli.py and
                  libraries: v7 (platform: today's rules) and commit B's policy (research: the
                  zone rules, no egress rule), a release in the other namespace or in both
  Wiring          the conf lines and their places, the dispatch lines, the help

    python3 tests/test_health_research.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_health_phase5 as h5  # noqa: E402
from _scratch import clean_env  # noqa: E402

rule = h5.rule

# The stub compiler: answers `has-zone research` and `compile netpol --zone research …` from
# $FAKE_DIR/cli.json and logs its argv, so the check's own logic is tested on its own.
STUB_CLI = r'''#!/usr/bin/env python3
import json, os, sys
FD = os.environ["FAKE_DIR"]
sc = json.load(open(os.path.join(FD, "cli.json")))
with open(os.path.join(FD, "cli.log"), "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:2] == ["has-zone", "research"]:
    sys.exit(sc.get("has_zone", 1))
if a[:1] == ["pod-zone"] and len(a) == 2:
    if sc.get("pod_zone_rc"):
        sys.exit(sc["pod_zone_rc"])
    z = (sc.get("pod_zone") or {}).get(a[1])
    if z is None:
        sys.exit(1)
    print(z)
    sys.exit(0)
if a[:2] == ["compile", "netpol"] and "--zone" in a:
    if sc.get("compile_rc", 0):
        print("broken", file=sys.stderr)
        sys.exit(sc["compile_rc"])
    sys.stdout.write(json.dumps({"apiVersion": "v1", "kind": "List", "items": sc.get("items", [])}))
    sys.exit(0)
print("stub cli: unexpected " + " ".join(a), file=sys.stderr)
sys.exit(2)
'''

LABELS = {"medcea/rs-netpol": "true"}


def np(name, spec):
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "medcea-research", "labels": LABELS,
                         "annotations": {"medcea/source": "access policy"}},
            "spec": spec}


DENY = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
DNS = {"podSelector": {}, "policyTypes": ["Egress"],
       "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                           "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                   "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]}
PG = {"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "research-postgresql",
                                      "app.kubernetes.io/name": "postgresql"}},
      "policyTypes": ["Ingress"],
      "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "medcea"}},
                             "podSelector": {"matchLabels": {"app": "research-export"}}},
                            {"ipBlock": {"cidr": "10.0.0.5/32"}}],
                   "ports": [{"protocol": "TCP", "port": 5432}]}]}
WANT = [np("rs-default-deny", DENY), np("rs-dns", DNS), np("rs-research-postgresql", PG)]


def live_doc(items):
    out = []
    for i in items:
        i = json.loads(json.dumps(i))
        # what the API server adds; the check compares specs only
        i["metadata"].update({"uid": "u-" + i["metadata"]["name"], "resourceVersion": "7",
                              "creationTimestamp": "2026-11-18T03:00:00Z", "generation": 1})
        out.append(i)
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": out})


NS_OK = rule(r"^get namespace medcea-research -o name$", "namespace/medcea-research\n")
NODES = rule(r"^get nodes -o jsonpath=", "10.0.0.5 10.1.0.1/32  \n")


class StubTree(h5.Tree):
    def __init__(self):
        super().__init__()
        cli = self.path("apps", "iam", "compiler", "cli.py")
        with open(cli, "w") as f:
            f.write(STUB_CLI)
        os.chmod(cli, 0o755)
        # rsgrants and rslake send the research deploy's own assert file (Phase 2b)
        os.makedirs(self.path("apps", "research", "db"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "research", "db", "assert_grants.sql"),
                    self.path("apps", "research", "db", "assert_grants.sql"))

    def cli(self, **sc):
        sc.setdefault("has_zone", 1)
        with open(os.path.join(self.fd, "cli.json"), "w") as f:
            json.dump(sc, f)
        try:
            os.remove(os.path.join(self.fd, "cli.log"))
        except FileNotFoundError:
            pass

    def cli_calls(self):
        try:
            with open(os.path.join(self.fd, "cli.log")) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []


class RsNetpol(unittest.TestCase):
    NAME = "Research network policies"

    @classmethod
    def setUpClass(cls):
        cls.t = StubTree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, rules, enabled="true", has_zone=0, items=WANT, compile_rc=0, call=None, **env):
        self.t.scenario(rules)
        self.t.cli(has_zone=has_zone, items=items, compile_rc=compile_rc)
        if enabled is not None:
            env["RESEARCH_ENABLED"] = enabled
        r = self.t.fn("check_rsnetpol", call or f'check_rsnetpol "{self.NAME}" medcea', helpers=(), **env)
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    def full(self, live, **kw):
        return self.run_check([NS_OK, NODES, rule(r"^get netpol -n medcea-research -o json$",
                                                  live_doc(live))], **kw)

    def test_no_kubectl_skips(self):
        r = self.run_check([], call=f'KUBECTL=no-such-kubectl-x check_rsnetpol "{self.NAME}" medcea')
        self.assertEqual(r, f"SKIP|{self.NAME}|no usable kubectl")
        self.assertEqual(self.t.calls(), [])

    def test_switched_off(self):
        for enabled in (None, "false", ""):
            with self.subTest(enabled=enabled):
                r = self.run_check([], enabled=enabled)
                self.assertEqual(r, f"SKIP|{self.NAME}|the research sandbox is switched off (RESEARCH_ENABLED is not true)")
                self.assertEqual(self.t.cli_calls(), [])
        r = self.run_check([NS_OK], enabled="false")
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|RESEARCH_ENABLED is not true, yet namespace medcea-research "
                                     "exists"), r)
        self.assertIn("microk8s kubectl delete namespace medcea-research", r)

    def test_research_namespace_from_config(self):
        r = self.run_check([rule(r"^get namespace lab-zone -o name$", "namespace/lab-zone\n")], enabled="false",
                           RESEARCH_NAMESPACE="lab-zone")
        self.assertIn("namespace lab-zone exists", r)

    def test_unreadable_namespace_warns(self):
        r = self.run_check([rule(r"^get namespace", "", 1, "Unable to connect to the server: timeout\n")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read namespace medcea-research: Unable to connect to the "
                            "server: timeout")

    def test_no_research_zone_skips(self):
        for rules in ([], [NS_OK]):
            r = self.run_check(rules, has_zone=1)
            self.assertEqual(r, f"SKIP|{self.NAME}|the applied access policy has no research zone yet")
            self.assertEqual(self.t.cli_calls(), [["has-zone", "research"]])

    def test_broken_policy_warns(self):
        r = self.run_check([NS_OK], has_zone=2)
        self.assertEqual(r, f"WARN|{self.NAME}|cannot tell whether the applied access policy has a research zone "
                            "(python3 apps/iam/compiler/cli.py check)")

    def test_enabled_without_namespace_warns(self):
        r = self.run_check([])
        self.assertEqual(r, f"WARN|{self.NAME}|RESEARCH_ENABLED=true, but namespace medcea-research does not exist "
                            "(./deploy-infra.sh)")

    def test_ok_and_the_compile_arguments(self):
        r = self.full(WANT)
        self.assertEqual(r, f"OK|{self.NAME}|3 research NetworkPolicies, the compiled set (default deny included)")
        self.assertEqual(self.t.cli_calls()[-1],
                         ["compile", "netpol", "--zone", "research", "--namespace", "medcea-research",
                          "--platform-namespace", "medcea", "--node-ip", "10.0.0.5", "--node-ip", "10.1.0.1"])
        # the node addresses with pa_netpol's jsonpath
        nodes = [c for c in self.t.calls() if c["argv"][:2] == ["get", "nodes"]]
        self.assertEqual(len(nodes), 1)
        with open(os.path.join(REPO, "infra", "lib-policy-artefacts.sh")) as f:
            jp = re.search(r"get nodes -o jsonpath='([^']+)'", f.read()).group(1)
        self.assertEqual(nodes[0]["argv"][3], "jsonpath=" + jp)

    def test_missing_default_deny_fails(self):
        r = self.full(WANT[1:])
        self.assertEqual(r, f"FAIL|{self.NAME}|the research zone admits more than the policy compiles: "
                            "missing: rs-default-deny (./deploy-infra.sh)")

    def test_a_differing_spec_fails(self):
        wider = json.loads(json.dumps(PG))
        wider["ingress"][0]["from"].append({"namespaceSelector": {}})
        r = self.full([WANT[0], WANT[1], np("rs-research-postgresql", wider)])
        self.assertEqual(r, f"FAIL|{self.NAME}|the research zone admits more than the policy compiles: "
                            "spec differs: rs-research-postgresql (./deploy-infra.sh)")
        # key order alone is no difference
        reordered = {k: PG[k] for k in reversed(list(PG))}
        self.assertTrue(self.full([WANT[0], WANT[1], np("rs-research-postgresql", reordered)]).startswith("OK|"))

    def test_both_fail_reasons_and_an_extra(self):
        r = self.full([WANT[1], np("rs-research-postgresql", DENY), np("rs-old", DENY)])
        self.assertEqual(r, f"FAIL|{self.NAME}|the research zone admits more than the policy compiles: "
                            "missing: rs-default-deny (./deploy-infra.sh); spec differs: rs-research-postgresql "
                            "(./deploy-infra.sh); labelled but not compiled: rs-old (./deploy-infra.sh deletes them)")

    def test_a_labelled_extra_fails(self):
        # policies are additive: a compiled set plus one more admits more than the set
        r = self.full(WANT + [np("rs-gone", DENY), np("rs-old", DENY)])
        self.assertEqual(r, f"FAIL|{self.NAME}|the research zone admits more than the policy compiles: "
                            "labelled but not compiled: rs-gone rs-old (./deploy-infra.sh deletes them)")

    def test_an_unlabelled_policy_fails(self):
        # what bitnamicharts/postgresql renders with primary.networkPolicy.enabled left true: an allow-all
        chart = np("research-postgresql", {"podSelector": {"matchLabels": {"app.kubernetes.io/instance":
                                                                           "research-postgresql"}},
                                           "policyTypes": ["Ingress", "Egress"], "egress": [{}],
                                           "ingress": [{"ports": [{"port": 5432, "protocol": "TCP"}]}]})
        chart["metadata"]["labels"] = {"app.kubernetes.io/managed-by": "Helm"}
        hand = np("allow-all", {"podSelector": {}, "ingress": [{}]})
        del hand["metadata"]["labels"]
        r = self.full(WANT + [chart, hand])
        self.assertEqual(r, f"FAIL|{self.NAME}|the research zone admits more than the policy compiles: not the "
                            "zone's, no medcea/rs-netpol=true label: allow-all research-postgresql, which widens the "
                            "zone past its default deny (microk8s kubectl delete networkpolicy -n medcea-research "
                            "<name>)")
        # every policy is read, not only the labelled ones
        reads = [c["argv"] for c in self.t.calls() if c["argv"][:2] == ["get", "netpol"]]
        self.assertEqual(reads, [["get", "netpol", "-n", "medcea-research", "-o", "json"]])

    def test_unreadable_netpol_or_nodes_warn(self):
        r = self.run_check([NS_OK, NODES, rule(r"^get netpol", "", 1, "error: forbidden\n")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read the NetworkPolicies in medcea-research: error: forbidden")
        r = self.run_check([NS_OK, rule(r"^get netpol", live_doc(WANT)), rule(r"^get nodes", "", 1, "error: x\n")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read the node addresses: error: x")
        r = self.run_check([NS_OK, NODES, rule(r"^get netpol", "not json")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot parse the live or compiled research NetworkPolicies")

    def test_compile_failure_and_empty_compile_warn(self):
        r = self.full(WANT, compile_rc=1)
        self.assertEqual(r, f"WARN|{self.NAME}|the research NetworkPolicies do not compile "
                            "(python3 apps/iam/compiler/cli.py check)")
        r = self.full([], items=[])
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|the applied policy has a research zone but compiles no "
                                     "research NetworkPolicy"), r)


class RsNetpolRealCli(unittest.TestCase):
    """The scratch tree's own cli.py on commit A's defaults.yaml (no state/; since commit B
    the tree's own defaults.yaml has the zone, so commit A's is written over it)."""

    def test_commit_a_skips(self):
        t = h5.Tree()
        try:
            cli = t.path("apps", "iam", "compiler", "cli.py")
            g = subprocess.run(["git", "-C", REPO, "show", "5c892a3:apps/iam/policy/defaults.yaml"],
                               capture_output=True, text=True)
            if g.returncode != 0:
                self.skipTest(f"no git revision 5c892a3: {g.stderr.strip()}")
            with open(t.path("apps", "iam", "policy", "defaults.yaml"), "w") as f:
                f.write(g.stdout)
            p = subprocess.run([sys.executable, cli, "has-zone", "research"], capture_output=True, text=True,
                               env=clean_env())
            if p.returncode == 2 and "invalid choice" in p.stderr:
                self.skipTest("cli.py has no has-zone yet (the compiler part of Phase 2a)")
            self.assertEqual(p.returncode, 1, p.stderr)
            t.scenario([NS_OK])
            r = t.fn("check_rsnetpol", 'check_rsnetpol "R" medcea', helpers=(), RESEARCH_ENABLED="true")
            self.assertEqual(r, "SKIP|R|the applied access policy has no research zone yet")
        finally:
            t.close()


class RsExportAge(unittest.TestCase):
    NOW = 1_800_000_000
    H = 3600

    def age(self, last, created_age_h=200):
        script = (h5.body("rsexport_age_status") + "\nRSEXPORT_WARN_H=26\nRSEXPORT_FAIL_H=72\nNAMESPACE=medcea\n"
                  f'rsexport_age_status {self.NOW} "{last}" {self.NOW - created_age_h * self.H}\n')
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout.strip()

    def test_ages(self):
        self.assertEqual(self.age(self.NOW - 3 * self.H), "OK|newest snapshot 3 h old")
        self.assertEqual(self.age(self.NOW - 26 * self.H), "OK|newest snapshot 26 h old")
        self.assertEqual(self.age(self.NOW + 60), "OK|newest snapshot 0 h old")      # a clock ahead
        r = self.age(self.NOW - 27 * self.H)
        self.assertTrue(r.startswith("WARN|newest snapshot is 27 h old (over 26 h: microk8s kubectl -n medcea get "
                                     "jobs -l app=research-export)"), r)
        self.assertTrue(self.age(self.NOW - 72 * self.H).startswith("WARN|"))
        r = self.age(self.NOW - 73 * self.H)
        self.assertTrue(r.startswith("FAIL|newest snapshot is 73 h old (over 72 h"), r)

    def test_no_snapshot(self):
        r = self.age("", created_age_h=5)
        self.assertTrue(r.startswith("SKIP|no snapshot yet: the first export runs at 03:00 UTC"), r)
        self.assertTrue(self.age("", created_age_h=30).startswith("WARN|no snapshot since the CronJob was created 30 h ago"))
        self.assertTrue(self.age("", created_age_h=80).startswith("FAIL|no snapshot since the CronJob was created 80 h ago"))

    def test_the_limits_are_the_backups(self):
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
        self.assertIn("RSEXPORT_WARN_H=26\n", src)
        self.assertIn("RSEXPORT_FAIL_H=72\n", src)


def iso(seconds_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds_ago))


class RsExport(unittest.TestCase):
    NAME = "Research export"

    @classmethod
    def setUpClass(cls):
        cls.t = h5.Tree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, psql_out=None, psql_rc=0, cron_age=10 * 86400, cron_rule=None, call=None):
        rules = [cron_rule or rule(r"^get cronjob research-export -n medcea -o jsonpath=\{\.metadata\.creationTimestamp\}$",
                                   iso(cron_age))]
        if psql_out is not None:
            rules.append(rule(r"^exec -i -n medcea-research research-postgresql-0 -- ", psql_out, psql_rc,
                              stdin=r"to_regclass\('lake\.snapshot'\)"))
        self.t.scenario(rules)
        r = self.t.fn("check_rsexport", call or f'check_rsexport "{self.NAME}" medcea',
                      helpers=("rsexport_age_status",), RSEXPORT_WARN_H="26", RSEXPORT_FAIL_H="72")
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    @staticmethod
    def doc(sid="12", age_s=3600, reserved="0", nres="2"):
        epoch = int(time.time()) - age_s
        snap = f"snap|{sid}|{epoch}" if sid else "snap||"
        return f"{snap}\nreserved|{reserved if sid else '-'}\nreservations|{nres}\n"

    def test_no_cronjob_skips(self):
        r = self.run_check(cron_rule=rule(r"^no such call$"))
        self.assertEqual(r, f"SKIP|{self.NAME}|no CronJob research-export in medcea (./apps/research-export/deploy.sh)")
        self.assertEqual([c["argv"][0] for c in self.t.calls()], ["get"])

    def test_no_kubectl_skips(self):
        r = self.run_check(call=f'KUBECTL=no-such-kubectl-x check_rsexport "{self.NAME}" medcea')
        self.assertEqual(r, f"SKIP|{self.NAME}|no usable kubectl")

    def test_unreadable_cronjob_warns(self):
        r = self.run_check(cron_rule=rule(r"^get cronjob", "", 1, "Unable to connect to the server\n"))
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read CronJob research-export in medcea: Unable to connect to "
                            "the server")

    def test_ok_and_the_session_is_read_only(self):
        r = self.run_check(self.doc())
        self.assertEqual(r, f"OK|{self.NAME}|newest snapshot 1 h old (snapshot 12, no reserved rows in it);"
                            "2 reservation(s)")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)
        a = ex[0]["argv"]
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", a)
        self.assertIn("medcea_research", a)
        self.assertIn('PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"', " ".join(a))
        sql = ex[0]["stdin"]
        for s in (r"\if :has_lake", r"\if :has_vault", "vault.reserved_rows_in(", "FROM vault.reservation",
                  "state|unbuilt", "state|partial"):
            self.assertIn(s, sql)
        self.assertNotRegex(sql, r"(?i)\b(insert|update|delete|truncate|create|drop|alter|grant)\b")

    def test_reserved_rows_fail(self):
        r = self.run_check(self.doc(reserved="41"))
        self.assertEqual(r, f"FAIL|{self.NAME}|41 measurement rows of snapshot 12 fall in a reservation: held-out "
                            "data reached the lake (./apps/research/reserve.sh list)")
        r = self.run_check(self.doc(reserved="3", age_s=80 * 3600))
        self.assertTrue(r.startswith(f"FAIL|{self.NAME}|3 measurement rows of snapshot 12"), r)
        self.assertIn(";newest snapshot is 80 h old (over 72 h", r)

    def test_no_reservation_warns(self):
        r = self.run_check(self.doc(nres="0"))
        self.assertEqual(r, f"WARN|{self.NAME}|no reservation yet: nothing is held out for validation "
                            "(./apps/research/reserve.sh add --by <qa user> --unit U --from T --to T --reason R)")

    def test_age(self):
        r = self.run_check(self.doc(age_s=30 * 3600))
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|newest snapshot is 30 h old (over 26 h"), r)
        r = self.run_check(self.doc(age_s=100 * 3600))
        self.assertTrue(r.startswith(f"FAIL|{self.NAME}|newest snapshot is 100 h old (over 72 h"), r)

    def test_first_day_without_a_snapshot(self):
        r = self.run_check(self.doc(sid=""), cron_age=3600)
        self.assertTrue(r.startswith(f"SKIP|{self.NAME}|no snapshot yet: the first export runs at 03:00 UTC"), r)
        self.assertTrue(r.endswith(";2 reservation(s)"), r)
        r = self.run_check(self.doc(sid="", nres="0"), cron_age=3600)
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|no reservation yet"), r)
        r = self.run_check(self.doc(sid=""), cron_age=4 * 86400)
        self.assertTrue(r.startswith(f"FAIL|{self.NAME}|no snapshot since the CronJob was created 96 h ago"), r)

    def test_unbuilt_or_partial_database_warns(self):
        for state in ("unbuilt", "partial"):
            r = self.run_check(f"state|{state}\n")
            self.assertEqual(r, f"WARN|{self.NAME}|the research database in medcea-research has no lake.snapshot, "
                                "vault.reservation or vault.reserved_rows_in yet (./apps/research/deploy.sh)")

    def test_unreadable_warns(self):
        r = self.run_check('psql: error: FATAL:  database "medcea_research" does not exist\n', psql_rc=2)
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read the research database in medcea-research: psql: error: "
                            'FATAL:  database "medcea_research" does not exist')
        # no pod: the fake kubectl has no rule for the exec
        r = self.run_check(None)
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|cannot read the research database in medcea-research"), r)
        for out in ("snap|x|1\nreserved|0\nreservations|1\n", self.doc(reserved="?"), self.doc(nres=""), "garbage\n"):
            with self.subTest(out=out):
                r = self.run_check(out)
                self.assertEqual(r, f"WARN|{self.NAME}|cannot read the newest snapshot or the reservations in "
                                    "medcea-research")

    def test_research_namespace_from_config(self):
        self.t.scenario([rule(r"^get cronjob", iso(86400 * 5)),
                         rule(r"^exec -i -n lab-zone research-postgresql-0 ", self.doc())])
        r = self.t.fn("check_rsexport", f'check_rsexport "{self.NAME}" medcea', helpers=("rsexport_age_status",),
                      RESEARCH_NAMESPACE="lab-zone", RSEXPORT_WARN_H="26", RSEXPORT_FAIL_H="72")
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)

    def test_never_writes(self):
        with open(os.path.join(REPO, "health-check.sh")) as f:
            fn = h5.body("check_rsexport", f.read())
        self.assertNotRegex(fn, r"\$KUBECTL (apply|delete|create|patch|edit|set|scale|rollout)\b")


# ── Phase 2b: rsgrants, rslake, wbaccounts, iamworkbench's placement ─────────────────────
def pod(name, labels, spec, kind="Pod", uid=None, owner=None):
    """owner: (kind, name, uid) of the controller ownerReference"""
    meta = {"name": name, "labels": labels}
    if uid:
        meta["uid"] = uid
    if owner:
        meta["ownerReferences"] = [{"kind": owner[0], "name": owner[1], "uid": owner[2], "controller": True}]
    if kind == "Pod":
        return {"kind": "Pod", "metadata": meta, "spec": spec}
    meta.pop("labels")
    return {"kind": kind, "metadata": meta,
            "spec": {"template": {"metadata": {"labels": labels}, "spec": spec}}}


def env_secret(n):
    return {"containers": [{"name": "c", "env": [{"name": "P", "valueFrom": {"secretKeyRef": {"name": n, "key": "k"}}}]}]}


PG_LABELS = {"app.kubernetes.io/instance": "research-postgresql", "app.kubernetes.io/name": "postgresql"}
HUB_LABELS = {"app": "jupyterhub", "component": "hub", "release": "workbench"}
NB_LABELS = {"app": "jupyterhub", "component": "singleuser-server", "release": "workbench"}
HUB_SPEC = {"containers": [{"name": "hub"}], "volumes": [{"name": "c", "secret": {"secretName": "hub"}}]}
ZONE_OK = [
    pod("research-postgresql-0", PG_LABELS, env_secret("research-postgresql-auth"),
        owner=("StatefulSet", "research-postgresql", "u-ss")),
    pod("research-postgresql", PG_LABELS, env_secret("research-postgresql-auth"), kind="StatefulSet", uid="u-ss"),
    pod("lake-api", {"app": "lake-api"}, env_secret("lake-api-auth"), kind="Deployment", uid="u-lake"),
    pod("hub", HUB_LABELS, HUB_SPEC, kind="Deployment", uid="u-hub"),
    pod("hub-5f7", HUB_LABELS, HUB_SPEC, kind="ReplicaSet", uid="u-hubrs", owner=("Deployment", "hub", "u-hub")),
    pod("hub-1", HUB_LABELS, HUB_SPEC, owner=("ReplicaSet", "hub-5f7", "u-hubrs")),
    pod("proxy", dict(HUB_LABELS, component="proxy"), env_secret("hub"), kind="Deployment", uid="u-proxy"),
    pod("proxy-1", dict(HUB_LABELS, component="proxy"), env_secret("hub"), owner=("Deployment", "proxy", "u-proxy")),
    pod("jupyter-bio", NB_LABELS, {"containers": [{"name": "n"}], "volumes": [
        {"name": "f", "secret": {"secretName": "singleuser"}},
        {"name": "t", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}},
                                                {"configMap": {"name": "kube-root-ca.crt"}}]}}]}),
    {"kind": "Role", "metadata": {"name": "medcea-hub"},
     "rules": [{"apiGroups": [""], "resources": ["pods", "persistentvolumeclaims"],
                "verbs": ["get", "watch", "list", "create", "delete"]},
               {"apiGroups": [""], "resources": ["events"], "verbs": ["get", "watch", "list"]}]},
    {"kind": "RoleBinding", "metadata": {"name": "medcea-hub"}, "roleRef": {"kind": "Role", "name": "medcea-hub"}},
]
ZONE_GET = r"^get pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs,roles,rolebindings,services -n medcea-research -o json$"
PG_SS = rule(r"^get statefulset research-postgresql -n medcea-research -o name$", "statefulset.apps/research-postgresql\n")
ASSERT_STDIN = r"rs_export_writer"


def zone(items):
    return rule(ZONE_GET, json.dumps({"kind": "List", "items": items}))


def assert_rule(out="", rc=0):
    return rule(r"^exec -i -n medcea-research research-postgresql-0 -- ", out, rc, stdin=ASSERT_STDIN)


class RsGrants(unittest.TestCase):
    NAME = "Research grants and Secrets"

    @classmethod
    def setUpClass(cls):
        cls.t = StubTree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, rules, enabled="true", has_zone=0, call=None, **env):
        self.t.scenario(rules)
        self.t.cli(has_zone=has_zone)
        env["RESEARCH_ENABLED"] = enabled
        r = self.t.fn("check_rsgrants", call or f'check_rsgrants "{self.NAME}" medcea',
                      helpers=("_rs_zone_ns", "_rs_assert_grants"), **env)
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    def full(self, items=ZONE_OK, assert_out="", assert_rc=0, db=True):
        return self.run_check([NS_OK, zone(items)] + ([PG_SS, assert_rule(assert_out, assert_rc)] if db else []))

    def test_ok_and_read_only(self):
        r = self.full()
        self.assertEqual(r, f"OK|{self.NAME}|9 pod spec(s) in medcea-research name only their own Secrets; no Role on "
                            "secrets, no ClusterRole bound, no Service exposed;the research database's grants are "
                            "db/grants.sql's")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)
        a = " ".join(ex[0]["argv"])
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on", a)
        self.assertIn("medcea_research", a)
        with open(os.path.join(REPO, "apps", "research", "db", "assert_grants.sql")) as f:
            self.assertEqual(ex[0]["stdin"], f.read())          # the deploy's own file, on stdin

    def test_every_reference_counts(self):
        nb = NB_LABELS
        cases = {
            "envFrom": {"containers": [{"name": "n", "envFrom": [{"secretRef": {"name": "db-svc-x"}}]}]},
            "initContainers": {"containers": [], "initContainers": [
                {"name": "i", "env": [{"name": "P", "valueFrom": {"secretKeyRef": {"name": "db-svc-x", "key": "k"}}}]}]},
            "volume": {"containers": [], "volumes": [{"name": "v", "secret": {"secretName": "db-svc-x"}}]},
            "projected": {"containers": [], "volumes": [{"name": "v", "projected": {"sources": [
                {"secret": {"name": "db-svc-x"}}]}}]},
            "imagePullSecrets": {"containers": [], "imagePullSecrets": [{"name": "db-svc-x"}]},
        }
        for what, spec in cases.items():
            with self.subTest(what):
                r = self.full(ZONE_OK + [pod("jupyter-x", nb, spec)])
                self.assertEqual(r, f"FAIL|{self.NAME}|Secrets outside the allow-list: pod/jupyter-x: db-svc-x")

    def test_each_class_keeps_to_its_own(self):
        cases = [(pod("hub-2", HUB_LABELS, env_secret("singleuser"), owner=("Deployment", "hub", "u-hub")),
                  "pod/hub-2: singleuser"),
                 (pod("jupyter-y", NB_LABELS, env_secret("hub")), "pod/jupyter-y: hub"),
                 (pod("lake-api-2", {"app": "lake-api"}, env_secret("research-postgresql-auth"),
                      owner=("Deployment", "lake-api", "u-lake")),
                  "pod/lake-api-2: research-postgresql-auth"),
                 (pod("probe", dict(NB_LABELS, **{"medcea/probe": "iam-research"}), env_secret("singleuser")),
                  "pod/probe: singleuser"),
                 (pod("other", {"app": "x"}, env_secret("hub"), kind="CronJob"), None)]
        for item, want in cases:
            with self.subTest(item["metadata"]["name"]):
                if item["kind"] == "CronJob":
                    t = item["spec"].pop("template")
                    item["spec"] = {"jobTemplate": {"spec": {"template": t}}}
                    want = "cronjob/other: hub"
                r = self.full(ZONE_OK + [item])
                self.assertEqual(r, f"FAIL|{self.NAME}|Secrets outside the allow-list: {want}")

    def test_labels_alone_grant_nothing(self):
        """Review of commit A: the hub may create pods with any label and any ownerReference.
        A pod labelled as the database (or lake-api, or the hub) without its real controller,
        or naming a controller by a uid that is not the listed one, gets no Secret."""
        fake_pg = pod("pg-copy", PG_LABELS, env_secret("research-postgresql-auth"))
        forged = pod("pg-forged", PG_LABELS, env_secret("research-postgresql-auth"),
                     owner=("StatefulSet", "research-postgresql", "u-guessed"))
        fake_lake = pod("lake-copy", {"app": "lake-api"}, env_secret("lake-api-auth"))
        fake_hub = pod("hub-copy", HUB_LABELS, HUB_SPEC)
        for item, want in ((fake_pg, "pod/pg-copy: research-postgresql-auth"),
                           (forged, "pod/pg-forged: research-postgresql-auth"),
                           (fake_lake, "pod/lake-copy: lake-api-auth"),
                           (fake_hub, "pod/hub-copy: hub")):
            with self.subTest(item["metadata"]["name"]):
                r = self.full(ZONE_OK + [item])
                self.assertEqual(r, f"FAIL|{self.NAME}|Secrets outside the allow-list: {want}")

    def test_an_exposed_service_fails(self):
        items = [{"kind": "Service", "metadata": {"name": "lake-api"}, "spec": {"type": "ClusterIP"}},
                 {"kind": "Service", "metadata": {"name": "np"}, "spec": {"type": "NodePort"}},
                 {"kind": "Service", "metadata": {"name": "lb"}, "spec": {"type": "LoadBalancer"}},
                 {"kind": "Service", "metadata": {"name": "ext"}, "spec": {"type": "ClusterIP", "externalIPs": ["192.0.2.9"]}}]
        r = self.full(ZONE_OK + items)
        self.assertEqual(r, f"FAIL|{self.NAME}|Service(s) reachable from outside the cluster (the zone admits node: "
                            "a NodePort would open lake-api to the LAN): ext (externalIPs) lb (LoadBalancer) np (NodePort)")
        r = self.full(ZONE_OK + items[:1])
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)

    def test_roles_and_bindings(self):
        wide = {"kind": "Role", "metadata": {"name": "wide"}, "rules": [{"resources": ["secrets"], "verbs": ["get"]}]}
        star = {"kind": "Role", "metadata": {"name": "star"}, "rules": [{"resources": ["*"], "verbs": ["*"]}]}
        crb = {"kind": "RoleBinding", "metadata": {"name": "edit"}, "roleRef": {"kind": "ClusterRole", "name": "edit"}}
        r = self.full(ZONE_OK + [wide, star, crb])
        self.assertEqual(r, f"FAIL|{self.NAME}|Role(s) granting secrets or *: star wide;"
                            "RoleBinding(s) binding a ClusterRole: edit (edit)")

    def test_assert_lines_fail(self):
        r = self.full(assert_out="PUBLIC may execute lake_api.holds()\nrs_lake_api is a member of pg_monitor\n")
        self.assertEqual(r, f"FAIL|{self.NAME}|the research database's grants are not db/grants.sql's (2 problem(s)): "
                            "PUBLIC may execute lake_api.holds(); rs_lake_api is a member of pg_monitor "
                            "(./apps/research/deploy.sh)")

    def test_no_database_yet(self):
        r = self.full(db=False)
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)
        self.assertTrue(r.endswith(";no research database yet"), r)
        self.assertEqual([c for c in self.t.calls() if c["argv"][0] == "exec"], [])

    def test_unreadable_warns(self):
        r = self.run_check([NS_OK, rule(r"^get pods,", "", 1, "error: forbidden\n")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read the workloads and Roles in medcea-research: error: forbidden")
        r = self.run_check([NS_OK, rule(r"^get pods,", "not json")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot parse the workloads and Roles in medcea-research")
        r = self.full(assert_out='psql: error: FATAL:  database "medcea_research" does not exist\n', assert_rc=2)
        self.assertEqual(r, f"WARN|{self.NAME}|cannot check the research database's grants: psql: error: FATAL:  "
                            'database "medcea_research" does not exist')

    def test_skips(self):
        r = self.run_check([], enabled="false")
        self.assertEqual(r, f"SKIP|{self.NAME}|the research sandbox is switched off (RESEARCH_ENABLED is not true)")
        r = self.run_check([NS_OK], has_zone=1)
        self.assertEqual(r, f"SKIP|{self.NAME}|the applied access policy has no research zone yet")
        r = self.run_check([NS_OK], has_zone=2)
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|cannot tell whether the applied access policy has a research zone"), r)
        r = self.run_check([])
        self.assertEqual(r, f"SKIP|{self.NAME}|namespace medcea-research does not exist (Research network policies reports it)")
        r = self.run_check([], call=f'KUBECTL=no-such-kubectl-x check_rsgrants "{self.NAME}" medcea')
        self.assertEqual(r, f"SKIP|{self.NAME}|no usable kubectl")
        # switched off with the namespace left: still checked
        r = self.run_check([NS_OK, zone(ZONE_OK), PG_SS, assert_rule()], enabled="false")
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)


LAKE_DEP = rule(r"^get deployment lake-api -n medcea-research -o name$", "deployment.apps/lake-api\n")
LAKE_PODS = rule(r"^get pods -n medcea-research -l app=lake-api ", "lake-api-1 Running 10.1.2.3\n")


def digest_rule(out, rc=0):
    return rule(r"^exec -i -n medcea-research research-postgresql-0 -- ", out, rc, stdin=r"snapshot_digest_check")


class RsLake(unittest.TestCase):
    NAME = "Research lake reader"

    @classmethod
    def setUpClass(cls):
        cls.t = StubTree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, rules, code="200", **env):
        sc = {} if code is None else {"realm": code}
        self.t.scenario(rules, **sc)
        self.t.cli(has_zone=0)
        env.setdefault("RESEARCH_ENABLED", "true")
        r = self.t.fn("check_rslake", f'check_rslake "{self.NAME}" medcea',
                      helpers=("_rs_zone_ns", "_rs_assert_grants"), **env)
        for c in self.t.calls():
            if c["tool"] != "curl":
                self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    def full(self, assert_out="", digest="newest|4\ngood|measurement\ngood|units\n", pods=LAKE_PODS, code="200"):
        return self.run_check([NS_OK, LAKE_DEP, digest_rule(digest), assert_rule(assert_out), pods], code=code)

    def test_no_lake_api_skips(self):
        r = self.run_check([NS_OK])
        self.assertEqual(r, f"SKIP|{self.NAME}|no deployment lake-api in medcea-research (./apps/lake-api/deploy.sh, "
                            "once the policy has its pod)")
        r = self.run_check([], RESEARCH_ENABLED="false")
        self.assertTrue(r.startswith(f"SKIP|{self.NAME}|the research sandbox is switched off"), r)

    def test_ok(self):
        r = self.full()
        self.assertEqual(r, f"OK|{self.NAME}|rs_lake_api reads only through lake_api;lake-api-1 answers on :3000;"
                            "snapshot 4: its 2 set digest(s) recompute")
        curl = [c for c in self.t.calls() if c["tool"] == "curl"]
        self.assertEqual(len(curl), 1)
        self.assertIn("http://10.1.2.3:3000/", curl[0]["argv"])
        self.assertIn("-m", curl[0]["argv"])
        dig = [c for c in self.t.calls() if c["argv"][0] == "exec" and "snapshot_digest_check" in c["stdin"]]
        self.assertEqual(len(dig), 1)
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", dig[0]["argv"])
        self.assertNotRegex(dig[0]["stdin"], r"(?i)\b(insert|update|delete|truncate|create|drop|alter|grant)\b")

    def test_lake_role_lines_fail_others_do_not(self):
        r = self.full(assert_out="rs_lake_api lacks its statement_timeout setting\nPUBLIC may execute lake.latest_cut()\n")
        self.assertEqual(r, f"FAIL|{self.NAME}|rs_lake_api / rs_lake_reader break the lake reader's rules (1 problem(s)): "
                            "rs_lake_api lacks its statement_timeout setting (./apps/research/deploy.sh)")
        r = self.full(assert_out="PUBLIC may execute lake.latest_cut()\n")
        self.assertTrue(r.startswith(f"OK|{self.NAME}|rs_lake_api reads only through lake_api"), r)

    def test_warnings(self):
        r = self.full(pods=rule(r"^get pods -n medcea-research -l app=lake-api ", "lake-api-1 Pending \n"))
        self.assertEqual(r, f"WARN|{self.NAME}|no lake-api pod is Running in medcea-research (microk8s kubectl -n "
                            "medcea-research describe deployment lake-api)")
        r = self.full(code="503")
        self.assertEqual(r, f"WARN|{self.NAME}|lake-api-1 at 10.1.2.3:3000 answered 503 from the host, not 200 (the "
                            "snapshot reader is down, or rs-lake-api does not admit the node)")
        r = self.full(code=None)
        self.assertIn("answered nothing from the host", r)
        r = self.full(digest="newest|4\ngood|units\nbad|measurement\n")
        self.assertEqual(r, f"WARN|{self.NAME}|snapshot 4: the recorded digest of measurement is not the one its lake "
                            "rows give (lake.snapshot_digest_check(4)): the lake changed after the export, or the digest "
                            "rule did")
        r = self.full(digest="state|nocheck\n")
        self.assertIn("no lake.snapshot_digest_check yet", r)
        r = self.full(digest="newest|x\n")
        self.assertIn("cannot read the newest snapshot's digest check", r)

    def test_no_snapshot_yet(self):
        r = self.full(digest="newest|-\n")
        self.assertTrue(r.endswith(";no snapshot yet"), r)
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)


HUB_POD = rule(r"^get pods -n medcea-research -l app=jupyterhub,component=hub --field-selector=status\.phase=Running ",
               "hub-7d9\n")


def kc_rule(accounts, realm=1, rc=0):
    out = f"realm|{realm}\n" + "".join(f"account|{a}\n" for a in accounts)
    return rule(r"^exec -i -n medcea rdbms-postgresql-0 -- ", out, rc, stdin=r"user_entity")


def hub_rule(users, rc=0, ns="medcea-research", out=None):
    if out is None:
        out = "".join(f"user|{u}\n" for u in users) + "end|\n"
    return rule(rf"^exec -n {ns} hub-7d9 -c hub -- python3 -c ", out, rc)


class WbAccounts(unittest.TestCase):
    NAME = "Workbench accounts"

    @classmethod
    def setUpClass(cls):
        cls.t = StubTree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, rules, placement="research", **env):
        self.t.scenario(rules)
        if placement == "broken":
            self.t.cli(pod_zone_rc=2)
        else:
            self.t.cli(pod_zone={"hub": "research"} if placement == "research" else {})
        r = self.t.fn("check_wbaccounts", f'check_wbaccounts "{self.NAME}" medcea', helpers=(), **env)
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    def test_ok_and_read_only(self):
        r = self.run_check([HUB_POD, hub_rule(["alice", "bio2"]), kc_rule(["alice", "bio2", "qa"])])
        self.assertEqual(r, f"OK|{self.NAME}|2 hub user(s) in medcea-research, each an enabled account of realm medcea")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 2)
        probe = ex[0]["argv"][-1]
        self.assertIn("mode=ro", probe)
        self.assertIn("SELECT name FROM users", probe)
        self.assertNotRegex(probe, r"(?i)\b(insert|update|delete)\b|api_tokens|oauth")
        kc = ex[1]
        self.assertIn("-d keycloak", " ".join(kc["argv"]))
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", kc["argv"])
        self.assertIn("u.enabled", kc["stdin"])
        self.assertNotRegex(kc["stdin"], r"(?i)\b(insert|update|delete|credential|secret)\b")

    def test_stale_users_warn_by_name(self):
        r = self.run_check([HUB_POD, hub_rule(["alice", "test-admin-a1b2c3", "Bob"]), kc_rule(["alice", "bob"])],
                           WORKBENCH_DOMAIN="workbench.medcea")
        self.assertEqual(r, f"WARN|{self.NAME}|hub user(s) without an enabled account in realm medcea: test-admin-a1b2c3 "
                            "— remove them in https://workbench.medcea/hub/admin (their own hub API tokens outlive "
                            "the account)")

    def test_platform_placement_reads_the_platform_namespace(self):
        r = self.run_check([rule(r"^get pods -n medcea -l app=jupyterhub,component=hub ", "hub-7d9\n"),
                            hub_rule(["alice"], ns="medcea"), kc_rule(["alice"])], placement="platform")
        self.assertEqual(r, f"OK|{self.NAME}|1 hub user(s) in medcea, each an enabled account of realm medcea")

    def test_skips_and_warnings(self):
        r = self.run_check([], WORKBENCH_ENABLED="false")
        self.assertEqual(r, f"SKIP|{self.NAME}|WORKBENCH_ENABLED is not true")
        r = self.run_check([rule(r"^get pods -n medcea-research", "")])
        self.assertEqual(r, f"SKIP|{self.NAME}|no running hub in medcea-research")
        r = self.run_check([], placement="broken")
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|cannot tell where the access policy places the AI workbench"), r)
        r = self.run_check([HUB_POD, hub_rule([], rc=1, out="sqlite3.OperationalError: unable to open database file\n")])
        self.assertEqual(r, f"WARN|{self.NAME}|cannot read the hub's users in hub-7d9: sqlite3.OperationalError: unable "
                            "to open database file")
        r = self.run_check([HUB_POD, hub_rule(["a"]), kc_rule([], realm=0)])
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|cannot read realm medcea's accounts"), r)


class IamWorkbench(unittest.TestCase):
    """The real cli.py and libraries of a scratch tree: v7's defaults.yaml (platform placement)
    or commit B's (tests/rs2b_fixture.py b_policy: research placement)."""
    NAME = "AI Workbench gate"

    @classmethod
    def setUpClass(cls):
        import yaml
        import rs2b_fixture
        cls.trees = {}
        for place, data in (("platform", None), ("research", rs2b_fixture.b_policy())):
            t = h5.Tree()
            if data is not None:
                with open(t.path("apps", "iam", "policy", "defaults.yaml"), "w") as f:
                    yaml.safe_dump(data, f, sort_keys=False)
            cli = t.path("apps", "iam", "compiler", "cli.py")
            got = {}
            for k in ("allowed_groups", "admin_groups"):
                p = subprocess.run([sys.executable, cli, "compile", "jupyterhub", "--setting", k],
                                   capture_output=True, text=True, env=clean_env())
                assert p.returncode == 0, p.stderr
                got[k] = json.loads(p.stdout)
            cls.trees[place] = (t, got)

    @classmethod
    def tearDownClass(cls):
        for t, _ in cls.trees.values():
            t.close()

    def values(self, place, **over):
        _, got = self.trees[place]
        v = {"hub": {"config": {"Authenticator": {"allow_all": False, "admin_users": [], "allow_existing_users": False,
                                                  "enable_auth_state": False},
                                "GenericOAuthenticator": {"allowed_groups": got["allowed_groups"],
                                                          "auth_state_groups_key": "oauth_user.groups",
                                                          "client_secret": "s3cret-never-printed"},
                                "KubeSpawner": {"delete_pvc": False}},
                     "loadRoles": {"workbench-admin": {"scopes": ["admin-ui", "list:users", "read:users", "servers",
                                                                  "delete:users"],
                                                       "groups": got["admin_groups"], "users": []},
                                   "admin": {"users": []}}},
             "singleuser": {"networkPolicy": {"enabled": True, "egress": [],
                                              "egressAllowRules": {"privateIPs": False, "cloudMetadataServer": False}}}}
        if place == "research":
            v["singleuser"]["networkPolicy"] = {"enabled": False}
            v["singleuser"]["cloudMetadata"] = {"blockWithIptables": False}
            v["hub"]["extraConfig"] = {"medcea-a2": "def _medcea_a2(spawner):\n    pass\n"
                                                    "c.KubeSpawner.pre_spawn_hook = _medcea_a2\n"}
        for path, x in over.items():
            d = v
            keys = path.split(".")
            for k in keys[:-1]:
                d = d.setdefault(k, {})
            if x is None:
                d.pop(keys[-1], None)
            else:
                d[keys[-1]] = x
        return v

    def rules(self, wbns, values, other=None, netpols="rs-default-deny rs-hub", roles=None, prio="medcea-research-low"):
        import base64
        import yaml
        b64 = base64.b64encode(yaml.safe_dump(values).encode()).decode()
        rs = [rule(rf"^get secret hub -n {wbns} -o name$", "secret/hub\n"),
              rule(rf"^get secret hub -n {wbns} -o jsonpath=", b64),
              rule(rf"^get deployment hub -n {wbns} -o jsonpath=", "sum1"),
              rule(rf"^get pods -n {wbns} -l component=hub --field-selector=status\.phase=Running -o "
                   r"jsonpath=\{range \.items\[\*\]\}\{\.metadata\.annotations", "sum1\n"),
              rule(rf"^get pods -n {wbns} -l component=hub --field-selector=status\.phase=Running -o "
                   r"jsonpath=\{range \.items\[\*\]\}\{\.metadata\.name\}=", f"hub-1={prio}\n"),
              rule(rf"^get netpol -n {wbns} -o jsonpath=", netpols),
              rule(rf"^get roles -n {wbns} -o json$", json.dumps({"items": roles or [ZONE_OK[-2]]}))]
        if other:
            rs.insert(0, rule(rf"^get secret hub -n {other} -o name$", "secret/hub\n"))
        return rs

    def run_check(self, place, rules, **env):
        t, _ = self.trees[place]
        t.scenario(rules)
        r = t.fn("check_iamworkbench", f'check_iamworkbench "{self.NAME}" medcea',
                 helpers=("_wb_hub_secret", "_wb_research_rules"), ADMIN_USER="admin", **env)
        for c in t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        self.assertNotIn("s3cret-never-printed", r)
        return r

    def test_platform_is_todays(self):
        r = self.run_check("platform", self.rules("medcea", self.values("platform")))
        self.assertTrue(r.startswith(f"OK|{self.NAME}|admits "), r)
        self.assertNotIn("research zone", r)
        t, _ = self.trees["platform"]
        reads = [c["argv"] for c in t.calls()]
        self.assertFalse(any(a[:2] in (["get", "netpol"], ["get", "roles"]) for a in reads), reads)
        # today's egress rule applies on the platform
        r = self.run_check("platform", self.rules("medcea", self.values("platform", **{"singleuser.networkPolicy.enabled": False})))
        self.assertEqual(r, f"FAIL|{self.NAME}|the notebooks' NetworkPolicy is off or allows private addresses")

    def test_research_ok(self):
        r = self.run_check("research", self.rules("medcea-research", self.values("research")))
        self.assertTrue(r.startswith(f"OK|{self.NAME}|admits "), r)
        self.assertTrue(r.endswith("; in the research zone (namespace medcea-research: no chart NetworkPolicy, no Role on "
                                   "secrets, the hub preemptible)"), r)

    def test_research_rules(self):
        cases = [
            ({"singleuser.networkPolicy.enabled": True}, {}, "singleuser.networkPolicy.enabled is true, not false"),
            ({"singleuser.networkPolicy.enabled": None}, {}, "singleuser.networkPolicy.enabled is null, not false"),
            ({"singleuser.cloudMetadata.blockWithIptables": True}, {}, "blockWithIptables is true, not false"),
            ({"hub.extraConfig": {}}, {}, "the hook hub.extraConfig.medcea-a2 is missing"),
            ({}, {"netpols": "rs-default-deny hub singleuser"}, "the chart's own NetworkPolicy hub singleuser is in medcea-research"),
            ({}, {"roles": [{"metadata": {"name": "r"}, "rules": [{"resources": ["secrets"], "verbs": ["get"]}]}]},
             "Role(s) r in medcea-research grant secrets"),
            ({}, {"prio": ""}, "hub pod hub-1 runs without priorityClassName medcea-research-low"),
        ]
        for over, kw, text in cases:
            with self.subTest(text):
                r = self.run_check("research", self.rules("medcea-research", self.values("research", **over), **kw))
                self.assertTrue(r.startswith(f"FAIL|{self.NAME}|"), r)
                self.assertIn(text, r)

    def test_research_skips_the_platform_egress_rule(self):
        # no notebooks NetworkPolicy and no egress at all: the platform rule would FAIL this
        r = self.run_check("research", self.rules("medcea-research", self.values("research")))
        self.assertNotIn("egress", r)
        self.assertTrue(r.startswith("OK|"), r)

    def test_the_release_in_the_other_namespace_defers(self):
        rs = [rule(r"^get secret hub -n medcea -o name$", "secret/hub\n")]
        r = self.run_check("research", rs)
        self.assertEqual(r, f"WARN|{self.NAME}|deferred: ./infra/deploy-workbench.sh --move (the access policy places the "
                            "AI workbench in the research zone, namespace medcea-research; its hub still runs in medcea)")
        r = self.run_check("platform", [rule(r"^get secret hub -n medcea-research -o name$", "secret/hub\n")])
        self.assertTrue(r.startswith(f"WARN|{self.NAME}|deferred: ./infra/deploy-workbench.sh --move (the access policy "
                                     "places the AI workbench in the platform namespace medcea"), r)

    def test_two_namespaces_fail(self):
        r = self.run_check("research", self.rules("medcea-research", self.values("research"), other="medcea"))
        self.assertEqual(r, f"FAIL|{self.NAME}|the workbench release is in two namespaces, medcea-research and medcea: "
                            "remove the one the access policy does not place it in (research) by hand")

    def test_not_deployed_skips(self):
        r = self.run_check("research", [])
        self.assertEqual(r, f"SKIP|{self.NAME}|no hub Secret in medcea-research (workbench not deployed)")

    def test_research_namespace_from_config(self):
        r = self.run_check("research", self.rules("lab-zone", self.values("research")), RESEARCH_NAMESPACE="lab-zone")
        self.assertTrue(r.startswith(f"OK|{self.NAME}|"), r)


class Wiring(unittest.TestCase):
    def test_conf_dispatch_and_help(self):
        with open(os.path.join(REPO, "health-checks.conf")) as f:
            lines = [l for l in f.read().splitlines() if l.strip() and not l.startswith("#")]
        rows = [[x.strip() for x in l.split("|")[:3]] for l in lines]
        types = [r[1] for r in rows]
        i = types.index("iamnetpol")
        self.assertEqual(rows[i + 1], ["Research network policies", "rsnetpol", "$NAMESPACE"])
        i = types.index("backupage")
        self.assertEqual(rows[i + 1], ["Research export", "rsexport", "$NAMESPACE"])
        # Phase 2b
        self.assertEqual(rows[i + 2], ["Research grants and Secrets", "rsgrants", "$NAMESPACE"])
        self.assertEqual(rows[i + 3], ["Research lake reader", "rslake", "$NAMESPACE"])
        i = types.index("iamworkbench")
        self.assertEqual(rows[i], ["AI Workbench gate", "iamworkbench", "$NAMESPACE"])
        self.assertEqual(rows[i + 1], ["Workbench accounts", "wbaccounts", "$NAMESPACE"])
        for t in ("rsnetpol", "rsexport", "rsgrants", "rslake", "wbaccounts"):
            self.assertEqual(types.count(t), 1, t)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
        for t in ("rsnetpol", "rsexport", "rsgrants", "rslake", "wbaccounts"):
            self.assertRegex(src, r"(?m)^        %s\)\s+check_%s \"\$name\" \"\$target\" ;;$" % (t, t))
            self.assertIn("${CYAN}%s${NC}" % t, src)
        with open(os.path.join(REPO, "health-checks.conf")) as f:
            head = f.read().split("\n\n")[0]
        for t in ("rsnetpol", "rsexport", "rsgrants", "rslake", "wbaccounts"):
            self.assertIn("#   " + t, head)
        # wbaccounts never FAILs; every check here is read-only
        self.assertNotIn("_record FAIL", h5.body("check_wbaccounts", src))
        for fn in ("check_rsgrants", "check_rslake", "check_wbaccounts", "check_iamworkbench", "_wb_research_rules",
                   "_rs_zone_ns", "_rs_assert_grants"):
            self.assertNotRegex(h5.body(fn, src), r"\$KUBECTL (apply|delete|create|patch|edit|set|scale|rollout|label)\b", fn)
        # rsexport's FAIL is held-out data or the age only; rsnetpol's FAIL is a missing or differing policy
        net = h5.body("check_rsnetpol", src)
        self.assertEqual(len(re.findall(r"_record FAIL", net)), 1)
        self.assertNotIn("_record FAIL", h5.body("check_rsexport", src).replace('_record FAIL "$name" "${fails[*]}"', ""))

    def test_help_runs_without_config(self):
        p = subprocess.run(["bash", os.path.join(REPO, "health-check.sh"), "--help"], capture_output=True, text=True,
                           env=clean_env(MEDCEA_NO_LOG="1"), timeout=60)
        self.assertEqual(p.returncode, 0)
        for t in ("rsnetpol", "rsexport", "rsgrants", "rslake", "wbaccounts"):
            self.assertIn(t, p.stdout)


if __name__ == "__main__":
    unittest.main()
