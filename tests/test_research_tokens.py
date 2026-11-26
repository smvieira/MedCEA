"""tests/test_research_tokens.py — research Phase 4a, the compiler's zone-service pieces
(design rs4 §2.1-2.3, R20), offline: a pod's `token_clients` (checks, routes.json `clients` and
`audience`, the pod-token-client tuple, cli has-token-client), `dns: true` per pod in the two new
zones, and medcea_iam's per-service audience. Version 9's policy gains a small shape like 4a's
commit B (the factory file after B carries the real one).

  python3 tests/test_research_tokens.py
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
sys.path.insert(0, os.path.join(REPO, "tests"))
from compiler import explain, invariants, model, netpol, routes  # noqa: E402
from _scratch import clean_env  # noqa: E402
import rs2b_fixture  # noqa: E402


def shape():
    d = rs2b_fixture.v9_policy()
    net = d["network"]
    net["zones"].update({"research-agents": {}, "research-gw": {}})
    net["pods"]["research-session"] = {
        "zone": "research-gw", "selector": {"app": "research-session"}, "carries": {"research-session": 8100},
        "token_clients": [{"client": "research-agent", "audience": "medcea-research"}], "dns": True,
        "ingress": [{"port": 8100, "from": ["pod:research-orchestrator", "pod:agent"]}]}
    net["pods"]["research-orchestrator"] = {
        "zone": "research-agents", "selector": {"app": "research-orchestrator"},
        "carries": {"research-orchestrator": 8090}, "dns": True,
        "token_clients": [{"client": "research-agent", "audience": "medcea-research"}],
        "ingress": [{"port": 8090, "from": ["pod:notebooks"]}],
        "egress": [{"pod": "research-session", "port": 8100}]}
    net["pods"]["agent"] = {"zone": "research-agents", "selector": {"app": "agent"},
                            "egress": [{"pod": "research-session", "port": 8100}]}
    net["pods"]["notebooks"]["egress"].append({"pod": "research-orchestrator", "port": 8090})
    return d


def errors(d):
    return netpol.check(model.Policy(d))


class TokenClients(unittest.TestCase):
    def test_the_shape_passes(self):
        self.assertEqual(errors(shape()), [])

    def test_refusals(self):
        def with_(mutate):
            d = shape()
            mutate(d["network"]["pods"]["research-session"])
            return errors(d)
        self.assertTrue(any("audience" in e for e in with_(lambda p: p["token_clients"][0].update(audience="medcea-api"))))
        self.assertTrue(any("host's client" in e for e in with_(lambda p: p["token_clients"][0].update(client="portal"))))
        self.assertTrue(any("listed twice" in e for e in with_(lambda p: p["token_clients"].append(dict(p["token_clients"][0])))))
        self.assertTrue(any("carries a service" in e for e in with_(lambda p: p.update(carries={}))))
        self.assertTrue(any("{client, audience}" in e for e in with_(lambda p: p.update(token_clients=[{"client": "x"}]))))
        self.assertTrue(any("non-empty list" in e for e in with_(lambda p: p.update(token_clients=[]))))

    def test_dns_flag(self):
        d = shape()
        d["network"]["pods"]["lake-api"]["dns"] = True
        self.assertTrue(any("dns is per pod only" in e for e in errors(d)))
        d = shape()
        d["network"]["pods"]["agent"]["dns"] = "yes"
        self.assertTrue(any("dns must be true or false" in e for e in errors(d)))

    def test_routes_clients_and_audience_only_where_set(self):
        d = shape()
        d["resource_groups"]["research_workbench"]["members"].append(
            {"type": "api", "service": "research-session", "routes": {"POST /mint": "C"}})
        doc = routes.compile(model.Policy(d))
        self.assertEqual(doc["services"]["research-session"]["clients"], ["research-agent"])
        self.assertEqual(doc["services"]["research-session"]["audience"], "medcea-research")
        for name, svc in doc["services"].items():
            if name != "research-session":
                self.assertNotIn("audience", svc, name)
        base = routes.compile(model.Policy(rs2b_fixture.v9_policy()))
        self.assertTrue(all("audience" not in s for s in base["services"].values()))

    def test_tuples(self):
        tup = explain.system_reach(model.Policy(shape()))
        self.assertIn(("pod-token-client", "research-session", "research-session", "research-agent", "medcea-research"), tup)
        self.assertIn(("pod-dns", "research-orchestrator"), tup)
        self.assertNotIn(("pod-dns", "agent"), tup)
        none = explain.system_reach(model.Policy(rs2b_fixture.v9_policy()))
        self.assertFalse([t for t in none if t[0] in ("pod-token-client", "pod-dns")])

    def run_cli(self, *args):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(shape(), f, sort_keys=False, allow_unicode=True)
            path = f.name
        try:
            return subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),
                                   "--file", path, "--label", "fixture"] + list(args),
                                  capture_output=True, text=True, env=clean_env(), cwd=REPO)
        finally:
            os.unlink(path)

    def test_has_token_client(self):
        self.assertEqual(self.run_cli("has-token-client", "research-agent").returncode, 0)
        self.assertEqual(self.run_cli("has-token-client", "nobody").returncode, 1)


class PerPodDns(unittest.TestCase):
    def names(self, zone, d):
        doc = netpol.compile_zone(model.Policy(d), zone, "ns-" + zone, "medcea", ["192.0.2.1"],
                                  {"research": "medcea-research", "research-gw": "g", "research-agents": "a"})
        return [i["metadata"]["name"] for i in doc["items"]]

    def test_per_pod_in_the_new_zones(self):
        d = shape()
        self.assertEqual(self.names("research-agents", d),
                         ["ra-default-deny", "ra-dns-research-orchestrator", "ra-research-orchestrator", "ra-agent"])
        self.assertEqual(self.names("research-gw", d), ["gw-default-deny", "gw-dns-research-session", "gw-research-session"])

    def test_the_research_zone_keeps_rs_dns(self):
        self.assertIn("rs-dns", self.names("research", shape()))

    def test_a_zone_without_the_flag_keeps_its_zone_wide_policy(self):
        d = shape()
        for p in d["network"]["pods"].values():
            p.pop("dns", None)
        self.assertIn("ra-dns", self.names("research-agents", d))


class Audience(unittest.TestCase):
    def test_verify_takes_the_service_audience(self):
        spec = __import__("importlib.util").util.spec_from_file_location(
            "medcea_iam", os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py"))
        mod = __import__("importlib.util").util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        import inspect
        self.assertIn("audience", inspect.signature(mod.verify).parameters)
        src = inspect.getsource(mod)
        self.assertIn('svc.get("audience")', src)
        self.assertIn('audience=audience or s.get("audience", "medcea-api")', src)


if __name__ == "__main__":
    unittest.main()
