#!/usr/bin/env python3
"""tests/test_research_netpol.py — the research zone in the policy compiler (research sandbox
Phase 2a, commit A's code; commit B puts the zone into defaults.yaml).

The fixture is a deep copy of defaults.yaml with commit B's `network:` (re)written: zone
research, the pod research-postgresql (zone research, 5432 from client:research-export,
client:backup and node) and the two platform clients with their hop to it. Since commit B
the factory policy has them itself, so the "no zone" cases use without_research(): the
factory policy with every zone key, zone pod and zone-bound client taken out.

  Check       netpol.check's zone rules (unknown zone, a pod or client in a zone the
              section lacks, a platform pod admitting a zone source, egress on a platform
              pod, a hop not admitted, a zone pod admitted as pod: without its hop)
  Compile     the platform List unchanged by the zone pods; the zone List: default deny,
              DNS to kube-dns, rs-<pod> with one AND peer (namespaceSelector +
              podSelector) per cross-zone source, the node addresses, labels and names;
              an empty List without the zone; the node addresses required
  Egress      netpol.egress across zones (needs the namespaces), egress_zones, a zone pod's hops
  Artefacts   test_policy_source.artefacts()/cli_argv() on the fixture: every key compiles
              through cli.py; a cross-zone client is keyed egress-<client>@research
  CliEgress   compile egress --zone/--namespace/--platform-namespace; notebooks byte-identical
  Cli         has-zone's exit codes and compile netpol --zone in a scratch copy
  ApplyCheck  the netpol-research target, its digest and owner only while the zone exists
  I18         the invariant on a group marked zone: research
  HopForms    Phase 2b: a zone pod's {platform}, {node: true} and {internet: true} hops (exact
              JSON, list order, every checker error, internet_except, _needs_node, ingress and
              node sources on a zone pod), and a zone without them compiled as 5504958 did
  SystemReach explain.system_reach's pod-egress tuples (none under v7)
  Questions   cli.py pod-zone, has-client, has-token-client (exit 0/1/2) on v7, commit B's
              shapes (tests/rs2b_fixture.py b_policy) and a broken policy
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
import apply_check  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "tests"))
from _scratch import clean_env, scratch_repo  # noqa: E402

NS, RNS = "medcea", "medcea-research"
PG_SEL = {"app.kubernetes.io/instance": "research-postgresql", "app.kubernetes.io/name": "postgresql"}


def defaults():
    """Version 7's policy (commit A's factory file): the base these tests were written on.
    Commit B changed the factory file, so it is rebuilt from it (tests/rs2b_fixture.py
    v7_policy, byte for byte)."""
    import rs2b_fixture
    return rs2b_fixture.v7_policy()


def research(d=None):
    """defaults.yaml (or d) plus the research zone of commit B's `network:`."""
    d = d or defaults()
    net = d["network"]
    net["zones"] = {"research": {}}
    net["pods"]["research-postgresql"] = {
        "zone": "research", "selector": dict(PG_SEL), "carries": {},
        "ingress": [{"port": 5432, "from": ["client:research-export", "client:backup", "node"],
                     "why": "the exporter, the nightly backup, kubelet probes"}]}
    net["clients"]["research-export"] = {"selector": {"app": "research-export"},
                                         "egress": [{"pod": "research-postgresql", "port": 5432}]}
    net["clients"]["backup"] = {"selector": {"app": "medcea-backup"},
                                "egress": [{"pod": "research-postgresql", "port": 5432}]}
    return d


def without_research(d=None):
    """defaults.yaml (or d) with no research zone: network.zones, the zone pods, the clients
    whose hops reach one and every group's `zone` key taken out (the policy before commit B,
    as far as these tests read it)."""
    d = d or defaults()
    net = d["network"]
    zoned = {n for n, pd in net.get("pods", {}).items() if pd.get("zone")}
    net.pop("zones", None)
    for n in zoned:
        del net["pods"][n]
    for c in [c for c, cd in net.get("clients", {}).items()
              if any(h.get("pod") in zoned for h in cd.get("egress") or [])]:
        del net["clients"][c]
    for gd in d["resource_groups"].values():
        gd.pop("zone", None)
    return d


def errors_of(d):
    return invariants.check(model.Policy(d))[0]


def zone_list(d, ips=("192.0.2.1",)):
    return netpol.compile_zone(model.Policy(d), "research", RNS, NS, list(ips))


def by_name(lst):
    return {i["metadata"]["name"]: i for i in lst["items"]}


class Check(unittest.TestCase):
    def test_fixture_passes(self):
        self.assertEqual(errors_of(research()), [])

    def assertCaught(self, d, fragment):
        errs = errors_of(d)
        self.assertTrue(any(fragment in e for e in errs), f"not caught by {fragment!r}: {errs[:4]}")

    def test_unknown_zone(self):
        d = research()
        d["network"]["zones"]["lab"] = {}
        self.assertCaught(d, "unknown zone 'lab'")

    def test_zones_not_a_mapping(self):
        d = research()
        d["network"]["zones"] = ["research"]
        self.assertCaught(d, "zones must map")

    def test_pod_in_a_zone_the_section_lacks(self):
        d = research()
        del d["network"]["zones"]
        self.assertCaught(d, "pod research-postgresql: zone 'research' is not in network.zones")

    def test_client_in_an_unknown_zone(self):
        d = research()
        d["network"]["clients"]["backup"]["zone"] = "lab"
        self.assertCaught(d, "client backup: zone 'lab' is not in network.zones")

    def test_platform_pod_admits_only_platform_sources(self):
        d = research()
        d["network"]["clients"]["research-export"]["zone"] = "research"
        self.assertEqual(errors_of(d), [])   # a zone client reaching a zone pod is fine
        # a platform pod admitting a zone client is refused
        d["network"]["pods"]["config-api"]["ingress"][0]["from"].append("client:research-export")
        d["network"]["clients"]["research-export"]["egress"].append({"pod": "config-api", "port": 3000})
        self.assertCaught(d, "source client:research-export is in zone research; a platform pod admits only")

    def test_egress_on_a_platform_pod(self):
        d = research()
        d["network"]["pods"]["monitor"]["egress"] = [{"pod": "research-postgresql", "port": 5432}]
        self.assertCaught(d, "pod monitor: egress hops are compiled only for a zone pod")

    def test_zone_hop_not_admitted(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["egress"] = [{"pod": "config-api", "port": 3000}]
        self.assertCaught(d, "reaches pod config-api port 3000, which does not admit pod:research-postgresql")

    def test_zone_hop_to_an_unknown_pod(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["egress"] = [{"pod": "nowhere", "port": 1}]
        self.assertCaught(d, "hop to unknown pod nowhere")

    def test_zone_hop_shape(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["egress"] = [{"selector": {"app": "x"}, "port": 1}]
        self.assertCaught(d, "a zone pod's hop is {pod, port}")

    def test_zone_pod_admitted_without_its_hop(self):
        d = research()
        d["network"]["pods"]["research-orchestrator"] = {
            "zone": "research", "selector": {"app": "orchestrator"}, "carries": {},
            "ingress": [{"port": 8080, "from": ["node"]}]}
        d["network"]["pods"]["research-postgresql"]["ingress"][0]["from"].append("pod:research-orchestrator")
        self.assertCaught(d, "admits pod:research-orchestrator, a zone pod with no egress hop there")
        d["network"]["pods"]["research-orchestrator"]["egress"] = [{"pod": "research-postgresql", "port": 5432}]
        self.assertEqual(errors_of(d), [])

    def test_client_hop_must_be_admitted_across_zones(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["ingress"][0]["from"].remove("client:backup")
        self.assertCaught(d, "client backup reaches pod research-postgresql port 5432, which does not admit client:backup")


class Compile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = research()
        cls.lst = zone_list(cls.d, ["10.1.110.128", "192.168.1.200", "10.1.110.128"])
        cls.items = by_name(cls.lst)

    def test_platform_list_unchanged(self):
        base = netpol.compile(model.Policy(defaults()), NS, ["192.0.2.1"])
        self.assertEqual(netpol.compile(model.Policy(self.d), NS, ["192.0.2.1"]), base)

    def test_names_order_labels_namespace(self):
        self.assertEqual(self.lst["kind"], "List")
        self.assertEqual([i["metadata"]["name"] for i in self.lst["items"]],
                         ["rs-default-deny", "rs-dns", "rs-research-postgresql"])
        for i in self.lst["items"]:
            self.assertEqual(i["kind"], "NetworkPolicy")
            self.assertEqual(i["apiVersion"], "networking.k8s.io/v1")
            self.assertEqual(i["metadata"]["namespace"], RNS)
            self.assertEqual(i["metadata"]["labels"], {"medcea/rs-netpol": "true"})
            self.assertTrue(i["metadata"]["annotations"]["medcea/source"].startswith("apps/iam/policy/defaults.yaml "))
        self.assertEqual(self.items["rs-research-postgresql"]["metadata"]["annotations"]["medcea/source"],
                         "apps/iam/policy/defaults.yaml network.pods.research-postgresql")
        self.assertEqual(netpol.zone_label("research"), "medcea/rs-netpol")

    def test_default_deny(self):
        self.assertEqual(self.items["rs-default-deny"]["spec"],
                         {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})

    def test_dns(self):
        self.assertEqual(self.items["rs-dns"]["spec"], {
            "podSelector": {}, "policyTypes": ["Egress"],
            "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]})

    def test_pod_and_semantics(self):
        spec = self.items["rs-research-postgresql"]["spec"]
        self.assertEqual(spec["podSelector"], {"matchLabels": PG_SEL})
        self.assertEqual(spec["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("egress", spec)   # no hops: the default deny holds
        self.assertEqual(len(spec["ingress"]), 1)
        rule = spec["ingress"][0]
        self.assertEqual(rule["ports"], [{"protocol": "TCP", "port": 5432}])
        ns = {"matchLabels": {"kubernetes.io/metadata.name": NS}}
        # one element per source: namespaceSelector AND podSelector in the same element
        self.assertEqual(rule["from"][:2], [
            {"namespaceSelector": ns, "podSelector": {"matchLabels": {"app": "research-export"}}},
            {"namespaceSelector": ns, "podSelector": {"matchLabels": {"app": "medcea-backup"}}}])
        for peer in rule["from"]:
            self.assertFalse(set(peer) == {"namespaceSelector"} or set(peer) == {"podSelector"},
                             f"an OR-able bare peer: {peer}")

    def test_node_addresses(self):
        rule = self.items["rs-research-postgresql"]["spec"]["ingress"][0]
        self.assertEqual(rule["from"][2:], [{"ipBlock": {"cidr": "10.1.110.128/32"}},
                                            {"ipBlock": {"cidr": "192.168.1.200/32"}}])

    def test_node_required(self):
        with self.assertRaisesRegex(ValueError, "no node address"):
            zone_list(self.d, [])
        # the platform compile does not need them for a zone pod's `node`
        d = research()
        for pd in d["network"]["pods"].values():
            if not pd.get("zone"):
                for r in pd["ingress"]:
                    r["from"] = [s for s in r["from"] if s != "node"] or ["ingress"]
        netpol.compile(model.Policy(d), NS, [])

    def test_empty_without_the_zone(self):
        bare = model.Policy(without_research())
        self.assertEqual(netpol.compile_zone(bare, "research", RNS, NS, []),
                         {"apiVersion": "v1", "kind": "List", "items": []})
        self.assertFalse(netpol.has_zone(bare, "research"))
        self.assertTrue(netpol.has_zone(self.d, "research"))
        self.assertTrue(netpol.has_zone(model.load_defaults(), "research"))   # commit B
        self.assertEqual(netpol.zones(bare), [])

    def test_unknown_zone_name(self):
        with self.assertRaises(ValueError):
            netpol.compile_zone(model.Policy(self.d), "lab", RNS, NS, ["192.0.2.1"])

    def test_same_zone_peer_is_a_bare_pod_selector(self):
        d = research()
        d["network"]["pods"]["research-orchestrator"] = {
            "zone": "research", "selector": {"app": "orchestrator"}, "carries": {},
            "ingress": [{"port": 8080, "from": ["node"]}],
            "egress": [{"pod": "research-postgresql", "port": 5432}]}
        d["network"]["pods"]["research-postgresql"]["ingress"][0]["from"].append("pod:research-orchestrator")
        self.assertEqual(errors_of(d), [])
        items = by_name(zone_list(d))
        self.assertIn({"podSelector": {"matchLabels": {"app": "orchestrator"}}},
                      items["rs-research-postgresql"]["spec"]["ingress"][0]["from"])
        self.assertEqual(items["rs-research-orchestrator"]["spec"]["egress"],
                         [{"to": [{"podSelector": {"matchLabels": PG_SEL}}],
                           "ports": [{"protocol": "TCP", "port": 5432}]}])

    def test_zone_hop_to_a_platform_pod_is_namespaced(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["egress"] = [{"pod": "config-api", "port": 3000}]
        d["network"]["pods"]["config-api"]["ingress"][0]["from"].append("pod:research-postgresql")
        # a platform pod admitting a zone pod is refused by check(): the hop compiles, the
        # platform side cannot (one rule, kept for a later phase)
        self.assertTrue(any("a platform pod admits only" in e for e in errors_of(d)))
        hop = netpol.compile_zone(model.Policy(d), "research", RNS, NS, ["192.0.2.1"])["items"][2]["spec"]["egress"]
        self.assertEqual(hop[0]["to"][0]["namespaceSelector"], {"matchLabels": {"kubernetes.io/metadata.name": NS}})


class Egress(unittest.TestCase):
    def test_platform_client_to_a_zone_pod(self):
        p = model.Policy(research())
        with self.assertRaisesRegex(ValueError, "zone research needs that zone's namespace"):
            netpol.egress(p, "research-export")
        self.assertEqual(netpol.egress(p, "research-export", {None: NS, "research": RNS}), [
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": RNS}},
                     "podSelector": {"matchLabels": PG_SEL}}],
             "ports": [{"protocol": "TCP", "port": 5432}]}])

    def test_notebooks_unchanged(self):
        self.assertEqual(netpol.egress(model.Policy(research()), "notebooks"),
                         netpol.egress(model.Policy(defaults()), "notebooks"))

    def test_egress_zones(self):
        p = model.Policy(research())
        self.assertEqual(netpol.egress_zones(p, "research-export"), [None, "research"])
        self.assertEqual(netpol.egress_zones(p, "backup"), [None, "research"])
        self.assertEqual(netpol.egress_zones(p, "notebooks"), [])
        with self.assertRaisesRegex(ValueError, "no network client"):
            netpol.egress_zones(p, "nobody")


class Artefacts(unittest.TestCase):
    """test_policy_source.artefacts() and cli_argv() on the research fixture: every key
    compiles, and through cli.py with the argv cli_argv gives it, byte for byte."""

    @classmethod
    def setUpClass(cls):
        import test_policy_source as tps
        cls.tps = tps
        cls.p = model.Policy(research())
        cls.want = tps.artefacts(cls.p)
        cls.root = scratch_repo()
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")
        cls.fx = os.path.join(cls.root, "research.yaml")
        with open(cls.fx, "w", encoding="utf-8") as f:
            yaml.safe_dump(research(), f, sort_keys=False, allow_unicode=True, width=1000)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_cross_zone_keys(self):
        egress = sorted(k for k in self.want if k.startswith("egress-"))
        self.assertIn("egress-notebooks", egress)                      # today's key unchanged
        self.assertIn("egress-research-export@research", egress)
        self.assertIn("egress-backup@research", egress)
        self.assertEqual(self.tps.cli_argv("egress-notebooks"), ["compile", "egress", "notebooks"])
        self.assertEqual(self.tps.cli_argv("egress-backup@research"),
                         ["compile", "egress", "backup", "--zone", "research", "--namespace", RNS,
                          "--platform-namespace", NS])
        self.assertEqual(json.loads(self.want["egress-research-export@research"]),
                         netpol.egress(self.p, "research-export", {None: NS, "research": RNS}))

    def test_defaults_keys_unchanged(self):
        d = self.tps.artefacts(model.Policy(without_research()))
        self.assertFalse([k for k in d if "@" in k or k == "netpol-research"])
        self.assertEqual(set(self.tps.artefacts(model.Policy(defaults()))), set(self.want))   # version 7

    def test_every_key_compiles_through_the_cli(self):
        bad = []
        for key in sorted(self.want):
            argv = self.tps.cli_argv(key)
            r = subprocess.run([sys.executable, self.cli, "--file", self.fx, "--label", "defaults.yaml", *argv],
                               capture_output=True, text=True, env=clean_env(), cwd=self.root)
            if (r.returncode, r.stdout) != (0, self.want[key]):
                bad.append(f"{key}: rc {r.returncode} {r.stderr.strip()[-200:]}")
        self.assertEqual(bad, [])


class CliEgress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = scratch_repo()
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")
        cls.fx = os.path.join(cls.root, "research.yaml")
        with open(cls.fx, "w", encoding="utf-8") as f:
            yaml.safe_dump(research(), f, sort_keys=False, allow_unicode=True, width=1000)
        cls.v7 = os.path.join(cls.root, "v7.yaml")   # version 7's policy (commit B changed the factory file)
        with open(cls.v7, "w", encoding="utf-8") as f:
            yaml.safe_dump(defaults(), f, sort_keys=False, allow_unicode=True, width=1000)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def run_cli(self, *argv):
        return subprocess.run([sys.executable, self.cli, *argv], capture_output=True, text=True, env=clean_env(),
                              cwd=self.root)

    def test_notebooks_byte_identical(self):
        a = self.run_cli("--file", self.v7, "compile", "egress", "notebooks")
        b = self.run_cli("--file", self.fx, "compile", "egress", "notebooks")
        c = self.run_cli("--file", self.fx, "compile", "egress", "notebooks", "--zone", "research",
                         "--namespace", RNS, "--platform-namespace", NS)
        self.assertEqual((a.returncode, b.returncode, c.returncode), (0, 0, 0), a.stderr + b.stderr + c.stderr)
        self.assertEqual(a.stdout, json.dumps(netpol.egress(model.Policy(defaults()), "notebooks"),
                                              sort_keys=True, separators=(",", ":")) + "\n")
        self.assertEqual(b.stdout, a.stdout)
        self.assertEqual(c.stdout, a.stdout)

    def test_cross_zone_client(self):
        r = self.run_cli("--file", self.fx, "compile", "egress", "research-export", "--zone", "research",
                         "--namespace", RNS, "--platform-namespace", NS)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout),
                         netpol.egress(model.Policy(research()), "research-export", {None: NS, "research": RNS}))

    def test_cross_zone_client_without_namespaces(self):
        r = self.run_cli("--file", self.fx, "compile", "egress", "backup")
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertIn("needs that zone's namespace", r.stderr)

    def test_usage_errors(self):
        for argv, msg in ((["--zone", "research", "--namespace", RNS], "needs --namespace and --platform-namespace"),
                          (["--zone", "lab", "--namespace", RNS, "--platform-namespace", NS], "unknown zone lab"),
                          (["--namespace", RNS], "go only with --zone"),
                          (["--platform-namespace", NS], "go only with --zone")):
            r = self.run_cli("--file", self.fx, "compile", "egress", "backup", *argv)
            self.assertEqual(r.returncode, 2, argv)
            self.assertIn(msg, r.stderr)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = scratch_repo()
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")
        cls.fx = os.path.join(cls.root, "research.yaml")
        with open(cls.fx, "w", encoding="utf-8") as f:
            yaml.safe_dump(research(), f, sort_keys=False, allow_unicode=True, width=1000)
        cls.v7 = os.path.join(cls.root, "v7.yaml")   # version 7's policy (commit B changed the factory file)
        with open(cls.v7, "w", encoding="utf-8") as f:
            yaml.safe_dump(defaults(), f, sort_keys=False, allow_unicode=True, width=1000)
        broken = research()
        broken["network"]["zones"]["lab"] = {}
        cls.broken = os.path.join(cls.root, "broken.yaml")
        with open(cls.broken, "w", encoding="utf-8") as f:
            yaml.safe_dump(broken, f, sort_keys=False, allow_unicode=True, width=1000)
        cls.bare = os.path.join(cls.root, "bare.yaml")
        with open(cls.bare, "w", encoding="utf-8") as f:
            yaml.safe_dump(without_research(), f, sort_keys=False, allow_unicode=True, width=1000)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def run_cli(self, *argv):
        return subprocess.run([sys.executable, self.cli, *argv], capture_output=True, text=True, env=clean_env(),
                              cwd=self.root)

    def test_has_zone(self):
        r = self.run_cli("--file", self.fx, "has-zone", "research")
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)
        r = self.run_cli("--file", self.bare, "has-zone", "research")
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        r = self.run_cli("--defaults", "has-zone", "research")   # commit B
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)
        r = self.run_cli("--file", self.fx, "has-zone", "lab")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown zone lab", r.stderr)
        r = self.run_cli("--file", self.broken, "has-zone", "research")
        self.assertEqual(r.returncode, 2)
        self.assertIn("refusing to answer", r.stderr)

    def test_compile_zone(self):
        r = self.run_cli("--file", self.fx, "compile", "netpol", "--zone", "research", "--namespace", RNS,
                         "--platform-namespace", NS, "--node-ip", "192.0.2.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        want = zone_list(research())
        self.assertEqual(r.stdout, json.dumps(want, indent=1) + "\n")

    def test_compile_zone_absent(self):
        r = self.run_cli("--file", self.bare, "compile", "netpol", "--zone", "research", "--namespace", RNS,
                         "--platform-namespace", NS, "--node-ip", "192.0.2.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"apiVersion": "v1", "kind": "List", "items": []})

    def test_compile_platform_unchanged_by_the_zone(self):
        a = self.run_cli("--file", self.v7, "compile", "netpol", "--namespace", NS, "--node-ip", "192.0.2.1")
        b = self.run_cli("--file", self.fx, "compile", "netpol", "--namespace", NS, "--node-ip", "192.0.2.1")
        self.assertEqual((a.returncode, b.returncode), (0, 0))
        self.assertEqual(a.stdout, b.stdout)

    def test_usage_errors(self):
        r = self.run_cli("--file", self.fx, "compile", "netpol", "--zone", "research", "--namespace", RNS)
        self.assertEqual(r.returncode, 2)
        self.assertIn("needs --platform-namespace", r.stderr)
        r = self.run_cli("--file", self.fx, "compile", "netpol", "--namespace", NS, "--platform-namespace", NS,
                         "--node-ip", "192.0.2.1")
        self.assertEqual(r.returncode, 2)
        r = self.run_cli("--file", self.fx, "compile", "netpol", "--zone", "lab", "--namespace", RNS,
                         "--platform-namespace", NS)
        self.assertEqual(r.returncode, 2)
        r = self.run_cli("--file", self.fx, "compile", "netpol", "--zone", "research", "--namespace", RNS,
                         "--platform-namespace", NS)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no node address", r.stderr)


class ApplyCheck(unittest.TestCase):
    def test_targets_only_with_the_zone(self):
        base = apply_check.targets(model.Policy(without_research()))
        self.assertNotIn("netpol-research", [n for n, _ in base])
        self.assertIn("netpol-research", [n for n, _ in apply_check.targets(model.load_defaults())])   # commit B
        with_zone = apply_check.targets(model.Policy(research()))
        self.assertEqual([t for t in with_zone if t[0] != "netpol-research"], base)
        argv = dict(with_zone)["netpol-research"]
        self.assertEqual(argv, ["compile", "netpol", "--zone", "research", "--namespace", "medcea-research",
                                "--platform-namespace", "medcea", "--node-ip", "192.0.2.1"])

    def test_digests_only_with_the_target(self):
        outs = {"routes": (0, '{"digest": "r"}', ""), "mqtt": (0, '{"digest": "m"}', ""),
                "netpol": (0, "n", ""), "grants-json": (0, "g", "")}
        d = apply_check.digests_of(outs, commit="c", skeleton_digest="s")
        self.assertNotIn("netpol_research", d)
        outs["netpol-research"] = (0, "z", "")
        d = apply_check.digests_of(outs, commit="c", skeleton_digest="s")
        self.assertEqual(d["netpol_research"], apply_check.sha("z"))

    def test_owners_only_with_the_zone(self):
        self.assertEqual(apply_check.target_owners(set()), apply_check.TARGET_OWNER)
        self.assertNotIn("./infra/deploy-research-namespace.sh --policy-only", apply_check.scoped_commands(set()))
        self.assertNotIn("./infra/deploy-research-namespace.sh", apply_check.full_deploys(set()))
        self.assertEqual(apply_check.target_owners({"research"})["netpol-research"],
                         "./infra/deploy-research-namespace.sh --policy-only")
        sc = apply_check.scoped_commands({"research"})
        self.assertEqual(sc.count("./infra/deploy-research-namespace.sh --policy-only"), 1)
        self.assertEqual(sc[0], "./deploy-infra.sh --policy-only")
        self.assertEqual([c for c in sc if "research" not in c], apply_check.scoped_commands(set()))
        self.assertIn("./infra/deploy-research-namespace.sh", apply_check.full_deploys({"research"}))

    def test_changed_detail_names_zone_policies(self):
        a = {"netpol-research": (0, json.dumps({"items": []}), "")}
        b = {"netpol-research": (0, json.dumps(zone_list(research())), "")}
        lines = apply_check._changed_detail(a, b, {"netpol-research"})
        self.assertEqual(lines, ["  netpol rs-default-deny: added", "  netpol rs-dns: added",
                                 "  netpol rs-research-postgresql: added"])


class I18(unittest.TestCase):
    def zoned(self):
        d = defaults()
        d["resource_groups"]["research_workbench"]["zone"] = "research"
        return d

    def test_research_workbench_in_the_zone_passes(self):
        # today's cells: qa R, engineer R, the scientists R C U, admin K (allowed)
        self.assertEqual(errors_of(self.zoned()), [])

    def test_admin_keeps_k(self):
        d = self.zoned()
        self.assertEqual(d["matrix"]["research_workbench"]["admin"], ["K"])
        self.assertFalse([e for e in errors_of(d) if e.startswith("I18")])

    def test_the_production_roles(self):
        for r in invariants.I18_NONE:
            with self.subTest(r):
                d = self.zoned()
                d["matrix"]["research_workbench"][r] = ["R"]
                self.assertTrue(any(e.startswith(f"I18 {r} holds") for e in errors_of(d)), errors_of(d)[:3])

    def test_engineer_exceptions(self):
        # owner decision of 17 Nov 2026: the engineer is operational only in research, R
        # everywhere but the promotion group's C; a plant-model group gets R at most
        for g, ok, bad in ((invariants.I18_PROMOTION_GROUP, ["R", "C"], ["R", "C", "U"]),
                           ("research_plant_model", ["R"], ["R", "C"])):
            with self.subTest(g):
                d = self.zoned()
                gd = {k: v for k, v in copy.deepcopy(d["resource_groups"]["research_workbench"]).items() if k != "tool"}
                gd["members"] = [{"type": "data", "object": f"medcea.{g}_fixture"}]
                d["resource_groups"][g] = gd
                d["matrix"][g] = {"engineer": ok}
                self.assertEqual(errors_of(d), [])
                d["matrix"][g] = {"engineer": bad}
                self.assertTrue(any(e.startswith("I18 engineer holds") for e in errors_of(d)), errors_of(d)[:3])

    def test_no_zone_no_i18(self):
        d = without_research()
        d["matrix"]["research_workbench"]["maintenance"] = ["R"]   # I6 allows it; I18 needs the zone
        self.assertFalse([e for e in errors_of(d) if "I18" in e])

    def test_zone_value_validated(self):
        d = defaults()
        d["resource_groups"]["research_workbench"]["zone"] = "Research"
        self.assertIn("group research_workbench: zone 'Research' unknown (known: research)", errors_of(d))


if __name__ == "__main__":
    unittest.main()


# ── research sandbox Phase 2b, commit A: the zone pods' hop forms and the three questions ──
sys.path.insert(0, os.path.join(REPO, "tests"))
import rs2b_fixture  # noqa: E402

from compiler import explain  # noqa: E402

KC = {"app": "keycloak"}
EXCEPT = list(rs2b_fixture.INTERNET_EXCEPT)


def hops(*h, except_=True):
    """research() with research-postgresql's egress = h (and the zone's internet_except)."""
    d = research()
    if except_:
        d["network"]["zones"]["research"] = {"internet_except": list(EXCEPT)}
    d["network"]["pods"]["research-postgresql"]["egress"] = list(h)
    return d


def pg_egress(d, ips=("192.0.2.2", "192.0.2.1", "192.0.2.1")):
    return by_name(zone_list(d, ips))["rs-research-postgresql"]["spec"].get("egress")


def old_netpol():
    """netpol.py of PRE_RS2B (5504958) as a module of its own (it imports only re)."""
    import importlib.util
    text = subprocess.run(["git", "-C", REPO, "show", "5504958:apps/iam/compiler/netpol.py"],
                          capture_output=True, text=True, check=True).stdout
    spec = importlib.util.spec_from_loader("netpol_pre_rs2b", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(text, "netpol_pre_rs2b.py", "exec"), mod.__dict__)
    return mod


class HopForms(unittest.TestCase):
    """netpol's zone-pod hop forms {pod}, {platform}, {node: true} and {internet: true}."""

    def assertCaught(self, d, fragment):
        errs = errors_of(d)
        self.assertTrue(any(fragment in e for e in errs), f"not caught by {fragment!r}: {errs[:4]}")

    def test_each_form_passes_the_checker(self):
        d = hops({"platform": dict(KC), "port": 8080, "why": "x"}, {"node": True, "port": 16443},
                 {"internet": True, "ports": [443, 80], "why": "y"})
        self.assertEqual(errors_of(d), [])
        self.assertEqual(errors_of(rs2b_fixture.b_policy()), [])
        self.assertEqual(errors_of(rs2b_fixture.with_notebooks_client(rs2b_fixture.b_policy())), [])

    def test_platform_hop_compiles(self):
        self.assertEqual(pg_egress(hops({"platform": dict(KC), "port": 8080})), [
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
                     "podSelector": {"matchLabels": KC}}],
             "ports": [{"protocol": "TCP", "port": 8080}]}])

    def test_node_hop_compiles(self):
        self.assertEqual(pg_egress(hops({"node": True, "port": 16443})), [
            {"to": [{"ipBlock": {"cidr": "192.0.2.1/32"}}, {"ipBlock": {"cidr": "192.0.2.2/32"}}],
             "ports": [{"protocol": "TCP", "port": 16443}]}])

    def test_internet_hop_compiles(self):
        self.assertEqual(pg_egress(hops({"internet": True, "ports": [443, 80]})), [
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": EXCEPT}}],
             "ports": [{"protocol": "TCP", "port": 443}, {"protocol": "TCP", "port": 80}]}])

    def test_internet_except_keeps_yaml_order(self):
        d = hops({"internet": True, "ports": [443]})
        d["network"]["zones"]["research"]["internet_except"] = ["192.168.0.0/16", "10.0.0.0/8"]
        self.assertEqual(pg_egress(d)[0]["to"][0]["ipBlock"]["except"], ["192.168.0.0/16", "10.0.0.0/8"])

    def test_hops_in_list_order(self):
        d = rs2b_fixture.b_policy()
        hub = by_name(zone_list(d))["rs-hub"]["spec"]["egress"]
        self.assertEqual([list(r["to"][0])[0] for r in hub], ["podSelector", "podSelector", "namespaceSelector", "ipBlock"])
        self.assertEqual([r["ports"][0]["port"] for r in hub], [8001, 8888, 8080, 16443])
        self.assertEqual(by_name(zone_list(d))["rs-lake-api"]["spec"]["egress"], [
            {"to": [{"podSelector": {"matchLabels": PG_SEL}}], "ports": [{"protocol": "TCP", "port": 5432}]}])

    def test_b_policy_names(self):
        self.assertEqual(sorted(by_name(zone_list(rs2b_fixture.b_policy()))),
                         ["rs-default-deny", "rs-dns", "rs-hub", "rs-lake-api", "rs-notebooks",
                          "rs-research-postgresql", "rs-workbench-proxy"])

    def test_no_new_form_is_byte_identical(self):
        # a zone whose pods use only {pod, port} hops compiles as 5504958 compiled it
        old = old_netpol()
        b = rs2b_fixture.b_policy()
        for pd in b["network"]["pods"].values():
            if pd.get("egress"):
                pd["egress"] = [h for h in pd["egress"] if "pod" in h]
        del b["network"]["zones"]["research"]["internet_except"]
        for d in (research(), b, defaults()):
            p = model.Policy(d)
            for args in (("research", RNS, NS, ["192.0.2.1"]),):
                self.assertEqual(json.dumps(netpol.compile_zone(p, *args), sort_keys=False),
                                 json.dumps(old.compile_zone(p, *args), sort_keys=False))
            self.assertEqual(json.dumps(netpol.compile(p, NS, ["192.0.2.1"])),
                             json.dumps(old.compile(p, NS, ["192.0.2.1"])))
            self.assertEqual(old.check(p), netpol.check(p))

    def test_needs_node_counts_node_hops(self):
        d = hops({"node": True, "port": 16443})
        d["network"]["pods"]["research-postgresql"]["ingress"][0]["from"].remove("node")
        self.assertEqual(errors_of(d), [])
        self.assertTrue(netpol._needs_node(d["network"], "research"))
        with self.assertRaisesRegex(ValueError, "no node address"):
            zone_list(d, ())
        d2 = copy.deepcopy(d)
        d2["network"]["pods"]["research-postgresql"]["egress"] = [{"internet": True, "ports": [443]}]
        self.assertFalse(netpol._needs_node(d2["network"], "research"))
        self.assertEqual(len(zone_list(d2, ())["items"]), 3)

    def test_ingress_and_node_sources_on_a_zone_pod(self):
        d = research()
        d["network"]["pods"]["research-postgresql"]["ingress"].append({"port": 8000, "from": ["ingress", "node"]})
        self.assertEqual(errors_of(d), [])
        rules = by_name(zone_list(d))["rs-research-postgresql"]["spec"]["ingress"]
        self.assertEqual(rules[-1]["from"], [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name":
                                                   d["network"]["ingress_namespace"]}}},
            {"ipBlock": {"cidr": "192.0.2.1/32"}}])

    # each checker error, one distinct message
    SHAPE = ("a zone pod's hop is {pod, port}, {platform, port}, {node: true, port}, {internet: true, ports} "
             "or {address, port}")

    def test_shape(self):
        for h in ("x", {"port": 1}, {"pod": "research-postgresql", "node": True, "port": 1},
                  {"platform": dict(KC), "port": 1, "pods": 1}, {"node": True, "port": 1, "ports": [1]},
                  {"internet": True, "ports": [443], "selector": {}}):
            with self.subTest(h=h):
                self.assertCaught(hops(h), self.SHAPE)
                self.assertCaught(hops(h), "a zone pod's hop is {pod, port}")

    def test_port_not_an_integer(self):
        for h in ({"platform": dict(KC), "port": "8080"}, {"node": True}, {"node": True, "port": True},
                  {"platform": dict(KC), "port": 0}, {"node": True, "port": 65536}):
            with self.subTest(h=h):
                self.assertCaught(hops(h), "is not an integer")

    def test_platform_selector(self):
        for sel in ({}, None, "keycloak", {"app": 1}, [["app", "keycloak"]]):
            with self.subTest(sel=sel):
                self.assertCaught(hops({"platform": sel, "port": 8080}),
                                  "a platform hop names a non-empty selector")

    def test_platform_hop_selecting_a_network_pod(self):
        d = hops({"platform": {"app": "config-api"}, "port": 3000})
        self.assertCaught(d, "platform hop {'app': 'config-api'} selects network pod config-api; "
                             "a network pod admits only sources of its own zone")
        self.assertCaught(hops({"platform": dict(PG_SEL), "port": 5432}), "selects network pod research-postgresql")

    def test_node_value(self):
        for v in (False, "true", 1, {}):
            with self.subTest(v=v):
                self.assertCaught(hops({"node": v, "port": 1}), "a node hop is {node: true, port}")

    def test_internet_shape(self):
        msg = "an internet hop is {internet: true, ports: [..]} (TCP ports, no port key)"
        for h in ({"internet": 1, "ports": [443]}, {"internet": True, "ports": [443], "port": 443},
                  {"internet": True}, {"internet": True, "ports": []}, {"internet": True, "ports": 443},
                  {"internet": True, "ports": [0]}, {"internet": True, "ports": [65536]},
                  {"internet": True, "ports": ["443"]}, {"internet": True, "ports": [True]}):
            with self.subTest(h=h):
                self.assertCaught(hops(h), msg)

    def test_internet_needs_except(self):
        self.assertCaught(hops({"internet": True, "ports": [443]}, except_=False),
                          "an internet hop needs network.zones.research.internet_except "
                          "(the private ranges it must not reach)")

    def test_internet_except_validated(self):
        msg = "network: zone research: internet_except must be a non-empty list of IPv4 networks"
        for ex in ([], "10.0.0.0/8", ["10.0.0.1/8"], ["::/0"], [10], ["10.0.0.0/8", "nope"], None):
            with self.subTest(ex=ex):
                d = research()
                d["network"]["zones"]["research"] = {"internet_except": ex}
                self.assertCaught(d, msg)
        d = research()
        d["network"]["zones"]["research"] = {"internet_except": list(EXCEPT)}
        self.assertEqual(errors_of(d), [])   # without any internet hop, a valid list alone is fine

    def test_internet_except_must_cover_the_private_ranges(self):
        """Review of commit A: a syntactically valid list that leaves a private range reachable
        (an internet hop on 5432 would reach rdbms and the LAN) is refused, not only reviewed."""
        for ex, missing in ((["192.0.2.0/32"], "10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16"),
                            ([x for x in EXCEPT if x != "100.64.0.0/10"], "100.64.0.0/10"),
                            (["10.0.0.0/9", "10.128.0.0/9", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12"],
                             "10.0.0.0/8, 192.168.0.0/16")):
            with self.subTest(ex=ex):
                d = research()
                d["network"]["zones"]["research"] = {"internet_except": ex}
                self.assertCaught(d, "internet_except must cover 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, "
                                     "172.16.0.0/12, 192.168.0.0/16 (the cluster's and the LAN's private ranges, "
                                     "CGNAT and link-local); missing: " + missing)
        for ex in (["0.0.0.0/0"], ["10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12",
                                   "192.168.0.0/16", "203.0.113.7/32"]):
            d = research()
            d["network"]["zones"]["research"] = {"internet_except": ex}
            self.assertEqual(errors_of(d), [], ex)   # wider, or more, is fine

    def test_address_hop(self):
        """Research Phase 4d: one host outside the cluster (a model server on the tailnet), by its /32."""
        d = hops({"address": "100.71.228.99/32", "port": 8000, "why": "the GPU model server"})
        self.assertEqual(errors_of(d), [])
        self.assertEqual(pg_egress(d), [{"to": [{"ipBlock": {"cidr": "100.71.228.99/32"}}],
                                         "ports": [{"protocol": "TCP", "port": 8000}]}])
        self.assertEqual(errors_of(hops({"address": "192.168.1.50/32", "port": 11434})), [])
        msg = "an address hop names one IPv4 host as A.B.C.D/32"
        for a in ("100.71.228.99", "100.71.228.0/24", "100.71.228.99/31", "0.0.0.0/32", "127.0.0.1/32",
                  "169.254.169.254/32", "224.0.0.1/32", "255.255.255.255/32", "::1/128", "host:8000", 1, None):
            with self.subTest(a=a):
                self.assertCaught(hops({"address": a, "port": 8000}), msg)
        for h in ({"address": "100.71.228.99/32"}, {"address": "100.71.228.99/32", "port": "8000"}):
            self.assertCaught(hops(h), "is not an integer")
        self.assertCaught(hops({"address": "100.71.228.99/32", "port": 8000, "ports": [1]}), self.SHAPE)

    def test_pod_rules_only_for_the_pod_form(self):
        # a platform/node/internet hop is never read as "a hop to a pod that does not admit it"
        errs = errors_of(hops({"platform": dict(KC), "port": 8080}, {"node": True, "port": 16443},
                              {"internet": True, "ports": [443]}))
        self.assertFalse([e for e in errs if "does not admit" in e or "unknown pod" in e], errs)

    def test_compile_refuses_an_internet_hop_without_except(self):
        with self.assertRaisesRegex(ValueError, "internet_except"):
            zone_list(hops({"internet": True, "ports": [443]}, except_=False))


class SystemReach(unittest.TestCase):
    """explain.system_reach's pod-egress tuples (no path registration in commit A)."""

    def tuples(self, d):
        return sorted(t for t in explain.system_reach(model.Policy(d)) if t[0] == "pod-egress")

    def test_none_under_v7(self):
        self.assertEqual(self.tuples(defaults()), [])
        self.assertEqual(self.tuples(research()), [])

    def test_each_form(self):
        d = hops({"pod": "config-api", "port": 3000}, {"platform": dict(KC), "port": 8080},
                 {"node": True, "port": 16443}, {"internet": True, "ports": [443, 80]})
        self.assertEqual(self.tuples(d), sorted([
            ("pod-egress", "research-postgresql", "pod", "config-api", 3000),
            ("pod-egress", "research-postgresql", "platform", '{"app":"keycloak"}', 8080),
            ("pod-egress", "research-postgresql", "node", "", 16443),
            ("pod-egress", "research-postgresql", "internet", "", 443),
            ("pod-egress", "research-postgresql", "internet", "", 80)]))

    def test_an_address_hop(self):
        self.assertEqual(self.tuples(hops({"address": "100.71.228.99/32", "port": 8000})),
                         [("pod-egress", "research-postgresql", "address", "100.71.228.99/32", 8000)])

    def test_b_policy(self):
        t = self.tuples(rs2b_fixture.b_policy())
        self.assertIn(("pod-egress", "hub", "platform", '{"app":"keycloak"}', 8080), t)
        self.assertIn(("pod-egress", "hub", "node", "", 16443), t)
        self.assertIn(("pod-egress", "notebooks", "internet", "", 443), t)
        self.assertIn(("pod-egress", "lake-api", "pod", "research-postgresql", 5432), t)
        self.assertEqual(len(t), 10)

    def test_a_new_hop_widens(self):
        a = rs2b_fixture.b_policy()
        b = copy.deepcopy(a)
        b["network"]["pods"]["notebooks"]["egress"][-1]["ports"] = [443, 22]
        self.assertEqual(explain.system_reach(model.Policy(b)) - explain.system_reach(model.Policy(a)),
                         {("pod-egress", "notebooks", "internet", "", 22)})


class Questions(unittest.TestCase):
    """cli.py pod-zone / has-client / has-token-client: exit 0, 1, 2; stdout only pod-zone's word."""

    @classmethod
    def setUpClass(cls):
        cls.root = scratch_repo()
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")
        cls.files = {}
        broken = research()
        broken["network"]["zones"]["lab"] = {}
        for name, d in (("v7", defaults()), ("b", rs2b_fixture.b_policy()), ("broken", broken)):
            cls.files[name] = os.path.join(cls.root, f"{name}.yaml")
            with open(cls.files[name], "w", encoding="utf-8") as f:
                yaml.safe_dump(d, f, sort_keys=False, allow_unicode=True, width=1000)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def ask(self, which, *argv):
        r = subprocess.run([sys.executable, self.cli, "--file", self.files[which], *argv], capture_output=True,
                           text=True, env=clean_env(), cwd=self.root)
        return r.returncode, r.stdout

    def test_pod_zone(self):
        self.assertEqual(self.ask("v7", "pod-zone", "research-postgresql"), (0, "research\n"))
        self.assertEqual(self.ask("v7", "pod-zone", "config-api"), (0, "platform\n"))
        self.assertEqual(self.ask("v7", "pod-zone", "hub"), (1, ""))
        self.assertEqual(self.ask("v7", "pod-zone", "lake-api"), (1, ""))
        self.assertEqual(self.ask("b", "pod-zone", "hub"), (0, "research\n"))
        self.assertEqual(self.ask("b", "pod-zone", "lake-api"), (0, "research\n"))
        self.assertEqual(self.ask("broken", "pod-zone", "config-api"), (2, ""))

    def test_has_client(self):
        self.assertEqual(self.ask("v7", "has-client", "notebooks"), (0, ""))
        self.assertEqual(self.ask("v7", "has-client", "backup"), (0, ""))
        self.assertEqual(self.ask("b", "has-client", "notebooks"), (1, ""))
        self.assertEqual(self.ask("v7", "has-client", "nobody"), (1, ""))
        self.assertEqual(self.ask("broken", "has-client", "notebooks"), (2, ""))

    def test_has_token_client(self):
        self.assertEqual(self.ask("v7", "has-token-client", "workbench-notebook"), (0, ""))
        self.assertEqual(self.ask("v7", "has-token-client", "notebooks"), (1, ""))   # the client's name is no azp
        self.assertEqual(self.ask("b", "has-token-client", "workbench-notebook"), (1, ""))
        self.assertEqual(self.ask("broken", "has-token-client", "workbench-notebook"), (2, ""))

    def test_documented(self):
        from compiler import cli
        for c in ("pod-zone NAME", "has-client NAME", "has-token-client NAME"):
            self.assertIn(f"cli.py {c}", cli.__doc__)
        self.assertFalse({"pod-zone", "has-client", "has-token-client"} & set(cli.OWN_SOURCE + cli.SKELETON_ONLY))
