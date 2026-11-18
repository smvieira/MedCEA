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
  RsNetpolRealCli the scratch tree's real cli.py on defaults.yaml (commit A: no research zone)
                  SKIPs
  RsExportAge     rsexport_age_status alone: OK / WARN past 26 h / FAIL past 72 h, no snapshot
                  SKIP on the first day, WARN then FAIL later
  RsExport        rsexport: no CronJob, unreadable CronJob, the read-only psql (SQL on stdin,
                  PGOPTIONS read-only, the guards), unbuilt / partial database, unreadable
                  numbers, reserved rows in the lake, no reservation, the age, OK
  Wiring          the conf lines and their places, the dispatch lines, the help

    python3 tests/test_health_research.py
"""
import json
import os
import re
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

    def cli(self, **sc):
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
    """The scratch tree's own cli.py on its defaults.yaml (no state/: commit A's policy)."""

    def test_commit_a_skips(self):
        t = h5.Tree()
        try:
            cli = t.path("apps", "iam", "compiler", "cli.py")
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
        for t in ("rsnetpol", "rsexport"):
            self.assertEqual(types.count(t), 1, t)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
        for t in ("rsnetpol", "rsexport"):
            self.assertRegex(src, r"(?m)^        %s\)\s+check_%s \"\$name\" \"\$target\" ;;$" % (t, t))
            self.assertIn("${CYAN}%s${NC}" % t, src)
        with open(os.path.join(REPO, "health-checks.conf")) as f:
            head = f.read().split("\n\n")[0]
        self.assertIn("#   rsnetpol", head)
        self.assertIn("#   rsexport", head)
        # rsexport's FAIL is held-out data or the age only; rsnetpol's FAIL is a missing or differing policy
        net = h5.body("check_rsnetpol", src)
        self.assertEqual(len(re.findall(r"_record FAIL", net)), 1)
        self.assertNotIn("_record FAIL", h5.body("check_rsexport", src).replace('_record FAIL "$name" "${fails[*]}"', ""))

    def test_help_runs_without_config(self):
        p = subprocess.run(["bash", os.path.join(REPO, "health-check.sh"), "--help"], capture_output=True, text=True,
                           env=clean_env(MEDCEA_NO_LOG="1"), timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn("rsnetpol", p.stdout)
        self.assertIn("rsexport", p.stdout)


if __name__ == "__main__":
    unittest.main()
