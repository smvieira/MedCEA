#!/usr/bin/env python3
"""tests/test_workbench_placement.py — where the AI workbench runs, and its egress hops, from
the access policy (research sandbox Phase 2b, commit A; codeplan SPEC §1.6–1.7).

  Placement   infra/lib-policy-tools.sh workbench_placement / workbench_namespace: `platform`
              and $NAMESPACE under version 7 (no hub pod), `research` and
              ${RESEARCH_NAMESPACE:-<ns>-research} under commit B's shapes (network.pods.hub,
              zone research), `platform` for a hub pod without a zone, rc 1 for a policy that
              fails its checks; IAM_GATES does not change it
  Egress      infra/lib-oauth2-proxy.sh policy_workbench_egress: today's answer under v7 for
              each switch pair (the compiled hops only while IAM_POSTGREST_JWT and IAM_DB_ROLES
              are true), '[]' without network.clients.notebooks or in research placement, rc 1
              for a broken policy; works whether or not the caller sourced lib-policy-tools.sh
  Close       workbench_egress_close against a fake kubectl: under v7 it closes the hops as
              before; without network.clients.notebooks it prints 0 and never asks kubectl or
              compiles; a broken policy returns 1

Every case runs the libraries in a scratch_repo() tree whose defaults.yaml is the policy under
test (no state/, so the source rule reads that file); nothing touches the repository's state/.
"""
import copy
import json
import os
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
import rs2b_fixture  # noqa: E402
from compiler import model, netpol  # noqa: E402

_TREES = {}


def readf(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def v7():
    return copy.deepcopy(model.load_defaults().data)


def hub_without_zone():
    d = rs2b_fixture.b_policy()
    # the hub as a platform pod: no zone, no egress (a platform pod has none), no zone source
    hub = d["network"]["pods"]["hub"]
    hub.pop("zone")
    hub.pop("egress")
    hub["ingress"] = [{"port": 8081, "from": ["node"]}]
    for name in ("workbench-proxy", "notebooks"):
        d["network"]["pods"][name]["egress"] = [h for h in d["network"]["pods"][name]["egress"]
                                                if h.get("pod") != "hub"]
    d["network"]["pods"]["notebooks"]["ingress"][0]["from"] = ["pod:workbench-proxy"]
    d["network"]["pods"]["workbench-proxy"]["ingress"] = [d["network"]["pods"]["workbench-proxy"]["ingress"][0]]
    return d


def broken():
    d = v7()
    d["network"]["zones"]["lab"] = {}
    return d


POLICIES = {
    "v7": v7,
    "b": rs2b_fixture.b_policy,
    "b+client": lambda: rs2b_fixture.with_notebooks_client(rs2b_fixture.b_policy()),
    "hub-platform": hub_without_zone,
    "broken": broken,
}


def tree(name):
    """A scratch tree whose apps/iam/policy/defaults.yaml is POLICIES[name]."""
    if name not in _TREES:
        root = scratch_repo(f"medcea-wbplace-{name}-")
        with open(os.path.join(root, "apps", "iam", "policy", "defaults.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(POLICIES[name](), f, sort_keys=False, allow_unicode=True, width=1000)
        _TREES[name] = root
    return _TREES[name]


def tearDownModule():
    for root in _TREES.values():
        shutil.rmtree(root, ignore_errors=True)


def bash(policy, script, **env):
    """script in bash with REPO_ROOT at the policy's scratch tree; (rc, stdout, stderr)."""
    root = tree(policy)
    base = {"NAMESPACE": "medcea"}
    base.update(env)
    r = subprocess.run(["bash", "-c", f'REPO_ROOT="{root}"; ' + script], capture_output=True, text=True,
                       env=clean_env(**base), cwd=root)
    return r.returncode, r.stdout, r.stderr


TOOLS = 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; '
PROXY = 'source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"; '


class Policies(unittest.TestCase):
    def test_the_fixtures(self):
        from compiler import invariants
        for name in ("v7", "b", "b+client", "hub-platform"):
            with self.subTest(name):
                self.assertEqual(invariants.check(model.Policy(POLICIES[name]()))[0], [])
        self.assertTrue(invariants.check(model.Policy(broken()))[0])


class Placement(unittest.TestCase):
    def ask(self, policy, fn, **env):
        return bash(policy, TOOLS + f'{fn}; echo "rc=$?"', **env)

    def test_v7_is_the_platform(self):
        rc, out, err = self.ask("v7", "workbench_placement")
        self.assertEqual(out, "platform\nrc=0\n", err)
        rc, out, err = self.ask("v7", "workbench_namespace", RESEARCH_NAMESPACE="lab")
        self.assertEqual(out, "medcea\nrc=0\n", err)

    def test_commit_b_is_the_research_zone(self):
        for policy in ("b", "b+client"):
            with self.subTest(policy):
                self.assertEqual(self.ask(policy, "workbench_placement")[1], "research\nrc=0\n")
                self.assertEqual(self.ask(policy, "workbench_namespace")[1], "medcea-research\nrc=0\n")
                self.assertEqual(self.ask(policy, "workbench_namespace", RESEARCH_NAMESPACE="rs-x")[1], "rs-x\nrc=0\n")
                self.assertEqual(self.ask(policy, "workbench_namespace", NAMESPACE="plant")[1],
                                 "plant-research\nrc=0\n")

    def test_iam_gates_does_not_move_it(self):
        self.assertEqual(self.ask("b", "workbench_placement", IAM_GATES="false")[1], "research\nrc=0\n")
        self.assertEqual(self.ask("v7", "workbench_placement", IAM_GATES="false")[1], "platform\nrc=0\n")

    def test_a_hub_without_a_zone_is_the_platform(self):
        self.assertEqual(self.ask("hub-platform", "workbench_placement")[1], "platform\nrc=0\n")
        self.assertEqual(self.ask("hub-platform", "workbench_namespace")[1], "medcea\nrc=0\n")

    def test_a_broken_policy(self):
        rc, out, err = self.ask("broken", "workbench_placement")
        self.assertEqual(out, "rc=1\n")
        self.assertIn("workbench_placement: cannot read the access policy", err)
        self.assertEqual(self.ask("broken", "workbench_namespace")[1], "rc=1\n")

    def test_never_keys_on_the_group_zone(self):
        # version 7 already marks research_workbench zone: research
        self.assertEqual(model.Policy(v7()).groups["research_workbench"].get("zone"), "research")
        text = readf(os.path.join(REPO, "infra", "lib-policy-tools.sh"))
        body = text[text.index("workbench_placement() {"):]
        self.assertIn("pod-zone hub", body)
        self.assertNotIn("research_workbench", body)


class Egress(unittest.TestCase):
    def egress(self, policy, tools_first=False, **env):
        script = (TOOLS if tools_first else "") + PROXY + 'policy_workbench_egress; rc=$?; printf "%s|%s" "$rc" "$WORKBENCH_EGRESS"'
        rc, out, err = bash(policy, script, **env)
        code, _, value = out.partition("|")
        return int(code), value, err

    def compiled(self, policy):
        p = model.Policy(POLICIES[policy]())
        return json.dumps(netpol.egress(p, "notebooks"), sort_keys=True, separators=(",", ":"))

    def test_v7_unchanged(self):
        on = dict(IAM_POSTGREST_JWT="true", IAM_DB_ROLES="true")
        self.assertEqual(self.egress("v7", **on)[:2], (0, self.compiled("v7")))
        for env in ({}, dict(IAM_POSTGREST_JWT="true"), dict(IAM_DB_ROLES="true"),
                    dict(IAM_POSTGREST_JWT="false", IAM_DB_ROLES="true")):
            with self.subTest(env=env):
                self.assertEqual(self.egress("v7", **env)[:2], (0, "[]"))

    def test_no_client_is_empty(self):
        on = dict(IAM_POSTGREST_JWT="true", IAM_DB_ROLES="true")
        self.assertEqual(self.egress("b", **on)[:2], (0, "[]"))
        self.assertEqual(self.egress("b", tools_first=True, **on)[:2], (0, "[]"))

    def test_research_placement_is_empty_even_with_the_client(self):
        on = dict(IAM_POSTGREST_JWT="true", IAM_DB_ROLES="true")
        self.assertEqual(self.egress("b+client", **on)[:2], (0, "[]"))
        self.assertEqual(self.egress("b+client", tools_first=True, **on)[:2], (0, "[]"))

    def test_a_broken_policy(self):
        rc, value, err = self.egress("broken")
        self.assertEqual(rc, 1)
        rc, value, err = self.egress("broken", IAM_POSTGREST_JWT="true", IAM_DB_ROLES="true")
        self.assertEqual(rc, 1)

    def test_lib_comments(self):
        text = readf(os.path.join(REPO, "infra", "lib-oauth2-proxy.sh"))
        body = text[text.index("policy_workbench_egress() {"):]
        body = body[:body.index("\n}\n")]
        self.assertLess(body.index("has-client notebooks"), body.index("compile egress notebooks"))


class Close(unittest.TestCase):
    NETPOL = {"kind": "NetworkPolicy", "metadata": {"name": "singleuser"}, "spec": {"egress": [
        {"to": [{"podSelector": {"matchLabels": {"app": "config-api"}}}], "ports": [{"port": 3000}]},
        {"to": [{"podSelector": {"matchLabels": {"app": "keycloak"}}}], "ports": [{"port": 8080}]},
        {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]}}

    def run_close(self, policy):
        d = tempfile.mkdtemp(prefix="medcea-wbclose-")
        self.addCleanup(shutil.rmtree, d, True)
        k = os.path.join(d, "kubectl")
        with open(os.path.join(d, "netpol.json"), "w") as f:
            json.dump(self.NETPOL, f)
        with open(k, "w") as f:
            f.write('#!/bin/sh\necho "$1" >> "$(dirname "$0")/calls"\ncase "$1" in\n'
                    '  get) cat "$(dirname "$0")/netpol.json" ;;\n'
                    '  patch) shift; while [ "$1" != "-p" ]; do shift; done; printf %s "$2" > "$(dirname "$0")/patch" ;;\n'
                    '  *) exit 1 ;;\nesac\n')
        os.chmod(k, 0o755)
        rc, out, err = bash(policy, PROXY + 'n="$(workbench_egress_close medcea)" || exit 1; echo "n=$n"', KUBECTL=k)
        calls = readf(os.path.join(d, "calls")).split() if os.path.exists(os.path.join(d, "calls")) else []
        patch = os.path.join(d, "patch")
        return rc, out.strip(), calls, (json.loads(readf(patch)) if os.path.exists(patch) else None)

    def test_v7_closes_the_hops(self):
        rc, out, calls, patch = self.run_close("v7")
        self.assertEqual((rc, out), (0, "n=2"))
        self.assertEqual(calls, ["get", "patch"])
        self.assertEqual([op["path"] for op in patch if op["op"] == "remove"], ["/spec/egress/1", "/spec/egress/0"])

    def test_no_client_is_a_no_op(self):
        rc, out, calls, patch = self.run_close("b")
        self.assertEqual((rc, out, calls, patch), (0, "n=0", [], None))

    def test_a_broken_policy(self):
        rc, out, calls, patch = self.run_close("broken")
        self.assertEqual((rc, patch), (1, None))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
