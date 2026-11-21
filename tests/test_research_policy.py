#!/usr/bin/env python3
"""tests/test_research_policy.py — the research sandbox's policy in defaults.yaml (research
sandbox Phase 2a, commit B; owner decisions P/F/S of 18 Nov 2026).

Reads the real factory policy, not a fixture (tests/test_research_netpol.py holds the
compiler's zone rules on fixtures; tests/test_policy_source.py PhaseRS2aBDelta the delta
against commit A).

  Invariant   I18 holds on the factory policy, is in the invariants block, and catches a
              production role or an engineer C on a research group; the research groups are
              research_workbench and research_export
  Groups      svc_research_export (ceiling research_export R, its password variable) and
              research_export (zone research, class regulated, no matrix row): its members
              are the eleven functions of migration 013, signatures exactly as the migration
              declares and revokes them, each at R for svc_research_export only
  Zone        cli.py has-zone research exits 0; compile netpol --zone research gives
              rs-default-deny, rs-dns and rs-research-postgresql, whose 5432 admits the two
              platform clients (namespaceSelector AND podSelector) and the node addresses;
              the platform NetworkPolicies are byte for byte commit A's
  Approval    apply_check.barred_approvers is empty for this change: qa and auditor may approve
  Phase2b     research sandbox Phase 2b, commit B (owner decisions of 19 Nov 2026): the zone
              pods hub, workbench-proxy, notebooks and lake-api with their hops, the internet
              hop's excluded ranges, lake-api admitted by research-postgresql, the notebooks
              client gone (no workbench-notebook azp), I19 in the block, the factory matrix
              carrying the change version's cells (measurements without the two scientists,
              analysis {}); barred_approvers empty for the skeleton version (against ad420b0)
              and for the change version (qa and auditor may approve both)

Run from the repository root:  python3 tests/test_research_policy.py
Offline; cli.py runs in a scratch copy (tests/_scratch.py), so no state/ of this host.
"""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
from compiler import explain, grants, invariants, model, netpol, source  # noqa: E402
import apply_check  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "tests"))
from _scratch import clean_env, scratch_repo  # noqa: E402

COMMIT_A = "5c892a3"   # research sandbox Phase 2a, commit A: code only, the policy before B
COMMIT_2B_A = "ad420b0"   # research sandbox Phase 2b, commit A: code only, version 7's policy
NS, RNS = "medcea", "medcea-research"
IPS = ["10.1.110.128", "192.168.1.200"]
PG_SEL = {"app.kubernetes.io/instance": "research-postgresql", "app.kubernetes.io/name": "postgresql"}
MIGRATIONS = os.path.join(REPO, "apps", "database", "medcea_db_migrations.sql")


def factory():
    """Version 9's policy (Phase 2b's factory file): research Phase 4a's commit B added zones and
    pods after these tests were written, so it is undone (tests/rs2b_fixture.py v9_policy)."""
    import rs2b_fixture
    return model.Policy(rs2b_fixture.v9_policy())


def migration_013():
    """The text of migration 013's block (up to its nonce)."""
    with open(MIGRATIONS, encoding="utf-8") as f:
        text = f.read()
    start = text.index("-- ── Migration 013")
    end = text.index("'013:last_nonce'", start)
    return text[start:end]


class Invariant(unittest.TestCase):
    def test_factory_policy_passes(self):
        errors, _ = invariants.check(factory())
        self.assertEqual(errors, [])

    def test_i18_in_the_block(self):
        inv = {i["code"]: i for i in factory().data["invariants"]}
        self.assertIn("I18", inv)
        i18 = inv["I18"]
        self.assertEqual(i18["kind"], "matrix")
        for word in ("zone research", *invariants.I18_NONE, "engineer", "at most R",
                     invariants.I18_PROMOTION_GROUP, "admin's K on research_workbench"):
            self.assertIn(word, i18["rule"])
        self.assertTrue(i18["rationale"] and i18["cites"])

    def test_research_groups(self):
        self.assertEqual(sorted(g for g, gd in factory().groups.items() if gd.get("zone") == "research"),
                         ["research_export", "research_workbench"])

    def test_i18_catches(self):
        cases = (("research_export", "operator", ["R"], "I18 operator"),
                 ("research_export", "qp", ["R"], "I18 qp"),
                 ("research_export", "engineer", ["R", "C"], "I18 engineer"),
                 ("research_workbench", "maintenance", ["R"], "I18 maintenance"),
                 ("research_workbench", "qc", ["R"], "I18 qc"))
        for g, r, cell, frag in cases:
            with self.subTest(f"{r} on {g}"):
                d = copy.deepcopy(factory().data)
                d["matrix"].setdefault(g, {})[r] = cell
                errors, _ = invariants.check(model.Policy(d))
                self.assertTrue(any(e.startswith(frag) for e in errors), errors[:4])

    def test_engineer_r_and_admin_k_allowed(self):
        p = factory()
        self.assertEqual(p.data["matrix"]["research_workbench"]["engineer"], ["R"])
        self.assertEqual(p.data["matrix"]["research_workbench"]["admin"], ["K"])


class Groups(unittest.TestCase):
    def test_service_identity(self):
        svc = factory().services["svc_research_export"]
        self.assertEqual(svc["ceiling"], {"research_export": ["R"]})
        self.assertEqual((svc["db_role"], svc["db_password"]), ("svc_research_export", "SVC_RESEARCH_EXPORT_DB_PASS"))
        self.assertNotIn("managed_by", svc)
        self.assertNotIn("mqtt_user", svc)

    def test_group(self):
        p = factory()
        g = p.groups["research_export"]
        self.assertEqual((g["class"], g["zone"]), ("regulated", "research"))
        for f in ("label", "description", "why_this_class", "risk"):
            self.assertTrue(g.get(f), f)
        self.assertNotIn("research_export", p.matrix)   # no person cell (no change version)
        for r in p.roles:
            self.assertEqual(p.effective("research_export", r), set(), r)

    def test_members_are_migration_013s_functions(self):
        block = migration_013()
        created = []
        for m in re.finditer(r"CREATE OR REPLACE FUNCTION (medcea\.research_[a-z_]+)\(([^)]*)\)", block):
            types = [a.strip().split()[-1] for a in m.group(2).split(",") if a.strip()]
            created.append(f"{m.group(1)}({', '.join(types)})")
        revoked = re.findall(r"^REVOKE ALL ON FUNCTION (medcea\.research_[a-z_]+\([^)]*\)) FROM PUBLIC;$", block, re.M)
        members = [m["function"] for m in factory().groups["research_export"]["members"]]
        self.assertEqual(len(members), 11)
        self.assertEqual(sorted(members), sorted(created))
        self.assertEqual(sorted(members), sorted(revoked))   # written exactly as the migration revokes them
        for m in factory().groups["research_export"]["members"]:
            with self.subTest(m["function"]):
                self.assertEqual((m["type"], m["level"], m["service_only"]), ("data", "R", ["svc_research_export"]))
                self.assertNotIn("writes", m)

    def test_only_the_exporter_executes_them(self):
        doc = grants.document(factory(), False, False)
        fns = {grants.norm_sig(m["function"]) for m in factory().groups["research_export"]["members"]}
        holders = {(g, o) for g, kind, o, priv in doc["privileges"] if kind == "function" and o in fns}
        self.assertEqual({g for g, _ in holders}, {"svc_research_export"})
        self.assertEqual({o for _, o in holders}, fns)
        mine = sorted((kind, o, priv) for g, kind, o, priv in doc["privileges"] if g == "svc_research_export")
        self.assertEqual(mine, sorted([("function", f, "EXECUTE") for f in fns] + [("schema", "medcea", "USAGE")]))
        self.assertIn("svc_research_export", grants.login_roles(factory()))


class Zone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = scratch_repo()
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def run_cli(self, *argv, cli=None):
        return subprocess.run([sys.executable, cli or self.cli, *argv], capture_output=True, text=True,
                              env=clean_env(), cwd=self.root)

    def test_has_zone(self):
        r = self.run_cli("--defaults", "has-zone", "research")
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)

    def test_zone_netpol(self):
        argv = ["--defaults", "compile", "netpol", "--zone", "research", "--namespace", RNS,
                "--platform-namespace", NS, "--zone-namespace", "research-gw=" + RNS + "-gw",
                "--zone-namespace", "research-agents=" + RNS + "-agents"]
        for ip in IPS:
            argv += ["--node-ip", ip]
        r = self.run_cli(*argv)
        self.assertEqual(r.returncode, 0, r.stderr)
        lst = json.loads(r.stdout)
        items = {i["metadata"]["name"]: i for i in lst["items"]}
        self.assertEqual([i["metadata"]["name"] for i in lst["items"]],
                         ["rs-default-deny", "rs-dns", "rs-research-postgresql",
                          "rs-hub", "rs-workbench-proxy", "rs-notebooks", "rs-lake-api"])   # + Phase 2b
        for i in lst["items"]:
            self.assertEqual(i["metadata"]["namespace"], RNS)
            self.assertEqual(i["metadata"]["labels"], {"medcea/rs-netpol": "true"})
        self.assertEqual(items["rs-default-deny"]["spec"], {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
        self.assertEqual(items["rs-dns"]["spec"]["policyTypes"], ["Egress"])
        spec = items["rs-research-postgresql"]["spec"]
        self.assertEqual(spec["podSelector"], {"matchLabels": PG_SEL})
        self.assertEqual(spec["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("egress", spec)
        ns = {"matchLabels": {"kubernetes.io/metadata.name": NS}}
        self.assertEqual(spec["ingress"], [{
            "ports": [{"protocol": "TCP", "port": 5432}],
            "from": [{"namespaceSelector": ns, "podSelector": {"matchLabels": {"app": "research-export"}}},
                     {"namespaceSelector": ns, "podSelector": {"matchLabels": {"app": "medcea-backup"}}},
                     {"podSelector": {"matchLabels": {"app": "lake-api"}}},   # Phase 2b: same zone, no namespaceSelector
                 {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": RNS + "-gw"}},
                  "podSelector": {"matchLabels": {"app": "research-session"}}}]   # Phase 4a: another zone
            + [{"ipBlock": {"cidr": f"{ip}/32"}} for ip in IPS]}])
        self.assertEqual(lst, netpol.compile_zone(model.load_defaults(), "research", RNS, NS, IPS,
                                                  {"research-gw": RNS + "-gw", "research-agents": RNS + "-agents"}))

    def test_client_egress(self):
        for c in ("research-export", "backup"):
            with self.subTest(c):
                r = self.run_cli("--defaults", "compile", "egress", c, "--zone", "research", "--namespace", RNS,
                                 "--platform-namespace", NS)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(json.loads(r.stdout), [{
                    "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": RNS}},
                            "podSelector": {"matchLabels": PG_SEL}}],
                    "ports": [{"protocol": "TCP", "port": 5432}]}])

    def test_platform_netpol_is_commit_as(self):
        old = tempfile.mkdtemp(prefix="medcea-rsa-")
        try:
            r = subprocess.run(f'git -C "{REPO}" archive {COMMIT_A} apps/iam/compiler apps/iam/policy | tar -x -C "{old}"',
                               shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"no git archive of {COMMIT_A}: {r.stderr.strip()}")
            argv = ["compile", "netpol", "--namespace", NS] + [x for ip in IPS for x in ("--node-ip", ip)]
            a = self.run_cli(*argv, cli=os.path.join(old, "apps", "iam", "compiler", "cli.py"))
            b = self.run_cli("--defaults", *argv)
            self.assertEqual((a.returncode, b.returncode), (0, 0), a.stderr + b.stderr)
            self.assertNotIn("research", b.stdout)
            # Phase 2b, commit B: the one difference is config-api's port 3000 losing the
            # notebooks peer (network.clients.notebooks removed, decision D2)
            old_list, new_list = json.loads(a.stdout), json.loads(b.stdout)
            nb = {"podSelector": {"matchLabels": {"app": "jupyterhub", "component": "singleuser-server",
                                                  "release": "workbench"}}}
            for item in old_list["items"]:
                if item["metadata"]["name"] == "iam-config-api":
                    for rule in item["spec"]["ingress"]:
                        self.assertIn(nb, rule["from"])
                        rule["from"].remove(nb)
            self.assertEqual(new_list, old_list)
            self.assertNotIn("singleuser-server", b.stdout)
        finally:
            shutil.rmtree(old, ignore_errors=True)

    def test_apply_target(self):
        self.assertIn("netpol-research", [n for n, _ in apply_check.targets(factory())])


class Approval(unittest.TestCase):
    def test_nobody_barred(self):
        r = subprocess.run(["git", "-C", REPO, "show", f"{COMMIT_A}:apps/iam/policy/defaults.yaml"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest(f"no git revision {COMMIT_A}: {r.stderr.strip()}")
        import yaml
        a = yaml.safe_load(r.stdout)
        p = factory().data
        rows = source.entries_and_waivers(a)
        g = json.loads(json.dumps(explain.gate(a, p, rows)))
        self.assertEqual(g["verdict"], "widening")
        self.assertEqual(set(g["added"]), {"_system", "_sections"})
        self.assertEqual(apply_check.barred_approvers(p["roles"], g["added"]), [])



class Phase2b(unittest.TestCase):
    """Research sandbox Phase 2b, commit B (the skeleton version) and the factory matrix's
    change version (owner decisions of 17 and 19 Nov 2026)."""

    def test_the_zone_pods(self):
        net = factory().data["network"]
        self.assertEqual(net["zones"]["research"]["internet_except"],
                         ["10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"])
        pods = net["pods"]
        self.assertEqual(sorted(n for n, pd in pods.items() if pd.get("zone") == "research"),
                         ["hub", "lake-api", "notebooks", "research-postgresql", "workbench-proxy"])
        hops = {n: [{k: v for k, v in h.items() if k != "why"} for h in pods[n]["egress"]]
                for n in ("hub", "workbench-proxy", "notebooks", "lake-api")}
        self.assertEqual(hops, {
            "hub": [{"pod": "workbench-proxy", "port": 8001}, {"pod": "notebooks", "port": 8888},
                    {"platform": {"app": "keycloak"}, "port": 8080}, {"node": True, "port": 16443}],
            "workbench-proxy": [{"pod": "hub", "port": 8081}, {"pod": "notebooks", "port": 8888}],
            "notebooks": [{"pod": "hub", "port": 8081}, {"pod": "lake-api", "port": 3000},
                          {"internet": True, "ports": [443]}],
            "lake-api": [{"pod": "research-postgresql", "port": 5432}]})
        self.assertEqual(pods["lake-api"]["ingress"][0]["from"], ["pod:notebooks", "node"])
        self.assertIn("pod:lake-api", pods["research-postgresql"]["ingress"][0]["from"])
        for n in ("hub", "workbench-proxy", "notebooks", "lake-api"):
            self.assertEqual(pods[n]["carries"], {}, n)   # no route-table service in the zone (O2)

    def test_the_notebooks_client_is_gone(self):
        p = factory()
        self.assertNotIn("notebooks", p.data["network"]["clients"])
        self.assertNotIn("client:notebooks", json.dumps(p.data["network"]))
        self.assertNotIn("workbench-notebook", grants.token_clients(p))
        self.assertEqual(grants.read_only_clients(p), [])

    def test_i19(self):
        inv = {i["code"]: i for i in factory().data["invariants"]}
        self.assertEqual(inv["I19"]["kind"], "matrix")
        self.assertIn("admin holds nothing, except K on research_workbench", inv["I19"]["rule"])
        self.assertEqual(factory().matrix["research_workbench"]["admin"], ["K"])
        d = copy.deepcopy(factory().data)
        d["matrix"]["research_workbench"]["admin"] = ["K", "R"]
        self.assertIn("I19 admin holds ['K', 'R'] on research group research_workbench",
                      invariants.check(model.Policy(d))[0])

    def test_the_factory_cells(self):
        m = factory().data["matrix"]
        self.assertEqual(m["analysis"], {})
        for r in ("bio_scientist", "control_scientist"):
            self.assertNotIn(r, m["measurements"])
        self.assertEqual(m["research_workbench"], {"qa": ["R"], "engineer": ["R"], "bio_scientist": ["R", "C", "U"],
                                                   "control_scientist": ["R", "C", "U"], "admin": ["K"]})

    def _v7(self):
        r = subprocess.run(["git", "-C", REPO, "show", f"{COMMIT_2B_A}:apps/iam/policy/defaults.yaml"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest(f"no git revision {COMMIT_2B_A}: {r.stderr.strip()}")
        import yaml
        return yaml.safe_load(r.stdout)

    def test_nobody_barred_from_the_skeleton_version(self):
        a, p = self._v7(), factory().data
        g = json.loads(json.dumps(explain.gate(a, p, source.entries_and_waivers(a))))
        self.assertEqual(g["verdict"], "widening")
        self.assertEqual(set(g["added"]), {"_system", "_sections"})
        barred = apply_check.barred_approvers(p["roles"], g["added"])
        self.assertEqual(barred, [])
        self.assertNotIn("qa", barred)
        self.assertNotIn("auditor", barred)

    def test_nobody_barred_from_the_change_version(self):
        a, p = self._v7(), factory()
        s = model.Policy(source.compose(source.skeleton(p.data), source.entries_and_waivers(a)))
        roles = explain.diff(s, p)["roles"]
        added = {r: v["added"] for r, v in roles.items() if v.get("added")}
        self.assertEqual(added, {})
        self.assertEqual(apply_check.barred_approvers(p.data["roles"], added), [])
        for r in sorted(p.roles):
            self.assertFalse(model.widening_between(s, p, r), r)


if __name__ == "__main__":
    unittest.main()
