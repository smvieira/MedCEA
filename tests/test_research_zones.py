"""tests/test_research_zones.py — research Phase 4a stage 1: the policy compiler's three
research zones (design codeplan/rs4-design.md R2), offline.

The fixture is the factory policy (Phase 2b's commit B, lake-api included) with the two new zones,
research-agents and research-gw, and a small cross-zone shape like 4a's commit B will add:
an orchestrator (research-agents) that research-session (research-gw) admits, a send-only
agent Job, and a lake reader hop into the research zone.

  Zones      the three zones, their prefixes and labels; the factory and version-7 policies
             compile exactly as before (no new zone: nothing changes)
  Check      a research-gw pod admits only research-agents and research-gw pods and the node;
             a send-only zone pod (egress, no ingress) passes, a platform pod without ingress
             still fails; an unknown zone is still an error
  Compile    a cross-zone peer and hop carry the other zone's namespaceSelector (AND the pod
             selector); without that zone's namespace compile_zone raises; a send-only pod's
             policy denies all ingress
  Cli        compile netpol --zone research-gw --zone-namespace research-agents=...; a bad
             --zone-namespace is exit 2; --zone-namespace without --zone is exit 2

  python3 tests/test_research_zones.py
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
from compiler import invariants, model, netpol  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "tests"))
from _scratch import clean_env  # noqa: E402

NS, RNS, ANS, GNS = "medcea", "medcea-research", "medcea-research-agents", "medcea-research-gw"
IPS = ["192.0.2.1"]


def v7():
    import rs2b_fixture
    return rs2b_fixture.v7_policy()


def three_zones():
    """Version 7 with the two new zones and a 4a-like cross-zone shape."""
    import rs2b_fixture
    d = rs2b_fixture.v9_policy()     # the factory policy before Phase 4a's commit B (Phase 2b's)
    net = d["network"]
    net["zones"]["research-agents"] = {}
    net["zones"]["research-gw"] = {}
    net["pods"]["research-session"] = {
        "zone": "research-gw", "selector": {"app": "research-session"},
        "ingress": [{"port": 8100, "from": ["pod:research-orchestrator", "node"]},
                    {"port": 8101, "from": ["pod:agent"]}]}
    net["pods"]["research-orchestrator"] = {
        "zone": "research-agents", "selector": {"app": "research-orchestrator"},
        "ingress": [{"port": 8090, "from": ["node"]}],
        "egress": [{"pod": "research-session", "port": 8100}]}
    net["pods"]["agent"] = {
        "zone": "research-agents", "selector": {"app": "agent"},
        "egress": [{"pod": "research-session", "port": 8101}, {"pod": "lake-api", "port": 3000}]}
    # lake-api (research zone, version 7) admits the agent across zones, reciprocally
    net["pods"]["lake-api"]["ingress"][0]["from"].append("pod:agent")
    return d


def errors_of(d):
    return [e for e in invariants.check(model.Policy(d))[0] if e.startswith("network")]


def by_name(lst):
    return {i["metadata"]["name"]: i for i in lst["items"]}


class Zones(unittest.TestCase):
    def test_the_three_zones(self):
        self.assertEqual(netpol.ZONES["research"], ("rs", "medcea/rs-netpol"))
        self.assertEqual(netpol.ZONES["research-agents"], ("ra", "medcea/ra-netpol"))
        self.assertEqual(netpol.ZONES["research-gw"], ("gw", "medcea/gw-netpol"))
        self.assertEqual(netpol.zone_label("research-gw"), "medcea/gw-netpol")

    def test_policies_without_the_new_zones_compile_as_before(self):
        for d in (v7(), __import__('rs2b_fixture').v9_policy()):
            p = model.Policy(d)
            self.assertEqual(netpol.compile_zone(p, "research", RNS, NS, IPS),
                             netpol.compile_zone(p, "research", RNS, NS, IPS, {"research-agents": ANS}))
            for z in ("research-agents", "research-gw"):
                self.assertEqual(netpol.compile_zone(p, z, ANS, NS, IPS)["items"], [])


class Check(unittest.TestCase):
    def test_the_fixture_passes(self):
        self.assertEqual(errors_of(three_zones()), [])

    def test_gw_admits_only_agents_and_gw(self):
        for src in ("pod:lake-api", "ingress", "proxy:" + next(iter(model.load_defaults().data["network"]["proxies"]))):
            with self.subTest(src):
                d = three_zones()
                d["network"]["pods"]["research-session"]["ingress"][0]["from"].append(src)
                errs = errors_of(d)
                self.assertTrue(any("a research-gw pod admits only those" in e for e in errs), errs)

    def test_send_only_zone_pod(self):
        d = three_zones()
        self.assertNotIn("ingress", d["network"]["pods"]["agent"])
        self.assertEqual(errors_of(d), [])
        d["network"]["pods"]["agent"].pop("egress")
        d["network"]["pods"]["research-session"]["ingress"][1]["from"] = ["pod:research-orchestrator"]
        d["network"]["pods"]["lake-api"]["ingress"][0]["from"].remove("pod:agent")
        self.assertTrue(any("pod agent admits nothing" in e for e in errors_of(d)))

    def test_unknown_zone_still_refused(self):
        d = three_zones()
        d["network"]["zones"]["lab"] = {}
        self.assertTrue(any("unknown zone 'lab'" in e for e in errors_of(d)))


class Compile(unittest.TestCase):
    def setUp(self):
        self.p = model.Policy(three_zones())
        self.all = {"research": RNS, "research-agents": ANS, "research-gw": GNS}

    def zone(self, z, others=True):
        ns = self.all[z]
        return netpol.compile_zone(self.p, z, ns, NS, IPS,
                                   {k: v for k, v in self.all.items() if k != z} if others else None)

    def test_gw_peer_from_agents_carries_its_namespace(self):
        items = by_name(self.zone("research-gw"))
        rule = items["gw-research-session"]["spec"]["ingress"][0]
        self.assertIn({"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ANS}},
                       "podSelector": {"matchLabels": {"app": "research-orchestrator"}}}, rule["from"])
        self.assertIn({"ipBlock": {"cidr": "192.0.2.1/32"}}, rule["from"])
        self.assertEqual(items["gw-research-session"]["metadata"]["labels"], {"medcea/gw-netpol": "true"})

    def test_agent_hops_across_zones_and_admits_nothing(self):
        items = by_name(self.zone("research-agents"))
        spec = items["ra-agent"]["spec"]
        self.assertEqual(spec["ingress"], [])
        self.assertEqual(spec["policyTypes"], ["Ingress", "Egress"])
        self.assertEqual(spec["egress"][0]["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], GNS)
        self.assertEqual(spec["egress"][1]["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], RNS)
        self.assertIn("ra-default-deny", items)
        self.assertIn("ra-dns", items)

    def test_research_admits_the_agent_across_zones(self):
        rule = by_name(self.zone("research"))["rs-lake-api"]["spec"]["ingress"][0]
        self.assertIn({"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ANS}},
                       "podSelector": {"matchLabels": {"app": "agent"}}}, rule["from"])

    def test_without_the_other_namespace_it_raises(self):
        with self.assertRaisesRegex(ValueError, "zone research-agents's namespace|needs that zone's namespace"):
            self.zone("research-gw", others=False)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(three_zones(), f, allow_unicode=True, sort_keys=False)
            path = f.name
        try:
            return subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),
                                   "--file", path, "--label", "fixture"] + list(args),
                                  capture_output=True, text=True, env=clean_env(), cwd=REPO)
        finally:
            os.unlink(path)

    def test_compile_gw_with_the_agents_namespace(self):
        r = self.run_cli("compile", "netpol", "--zone", "research-gw", "--namespace", GNS,
                         "--platform-namespace", NS, "--zone-namespace", "research-agents=" + ANS,
                         "--node-ip", "192.0.2.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        names = {i["metadata"]["name"] for i in json.loads(r.stdout)["items"]}
        self.assertEqual(names, {"gw-default-deny", "gw-dns", "gw-research-session"})

    def test_bad_zone_namespace(self):
        for pair in ("lab=x", "research-agents", "research-agents=Bad_NS"):
            with self.subTest(pair):
                r = self.run_cli("compile", "netpol", "--zone", "research-gw", "--namespace", GNS,
                                 "--platform-namespace", NS, "--zone-namespace", pair)
                self.assertEqual(r.returncode, 2, r.stderr)
        r = self.run_cli("compile", "netpol", "--namespace", NS, "--zone-namespace", "research-agents=" + ANS)
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_missing_other_namespace_is_an_error(self):
        r = self.run_cli("compile", "netpol", "--zone", "research-gw", "--namespace", GNS,
                         "--platform-namespace", NS, "--node-ip", "192.0.2.1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("namespace", r.stderr)


if __name__ == "__main__":
    unittest.main()
