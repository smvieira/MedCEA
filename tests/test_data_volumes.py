#!/usr/bin/env python3
"""tests/test_data_volumes.py — infra/lib-data-volumes.sh data_volumes_warn after the AI
workbench's move into the research zone (research sandbox Phase 2b, commit A), offline.

A fake kubectl answers from a table (anything else exits 1, as the cluster that does not know
it). The research namespace's homes and hub database are listed after the research database,
under their own header; a home whose volume is Retain says it is kept on this host after the
claim goes and must be removed by hand; a claim labelled medcea/moved-to says it was left
behind by the move (the copy there is the live one); nothing is said for a research namespace
without homes, one equal to the platform's, or one the cluster cannot list; the platform's
wording of tests/test_workbench_data.py HomesTest is unchanged (that file holds it).

Run: python3 tests/test_data_volumes.py
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SD = "/var/snap/microk8s/common/default-storage"


def pvc(name, vol, size="10Gi", labels=None):
    return {"metadata": {"name": name, "labels": labels or {}}, "spec": {"volumeName": vol},
            "status": {"capacity": {"storage": size}}}


class Warn(unittest.TestCase):
    def run_warn(self, table, **env):
        """table: {kubectl argv joined by spaces: stdout}; anything else exits 1"""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cases = "".join(f"  {json.dumps(k)}) printf '%s' {json.dumps(v)} ;;\n" for k, v in table.items())
        k = os.path.join(d, "kubectl")
        with open(k, "w") as f:
            f.write('#!/bin/bash\ncase "$*" in\n' + cases + "  *) exit 1 ;;\nesac\n")
        os.chmod(k, 0o755)
        os.makedirs(os.path.join(d, "no-backups"))
        e = {k_: v for k_, v in os.environ.items() if k_ != "RESEARCH_NAMESPACE"}
        e.update(KUBECTL=k, BACKUP_DIR=os.path.join(d, "no-backups"), **env)
        r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-data-volumes.sh"; data_volumes_warn medcea; echo "rc=$?"'],
                           env=e, capture_output=True, text=True)
        self.assertTrue(r.stdout.rstrip().endswith("rc=0"), r.stdout + r.stderr)
        return r.stdout

    def test_research_homes_and_hub_database(self):
        rpvcs = {"items": [pvc("claim-alice", "pvc-r1", labels={"medcea/moved-from": "medcea"}),
                           pvc("hub-db-dir", "pvc-r2", "1Gi"), pvc("data-research-postgresql-0", "pvc-r3")]}
        out = self.run_warn({
            "get pvc -n medcea -o json": '{"items": []}',
            "get pvc -n medcea-research -o json": json.dumps(rpvcs),
            "get pv pvc-r1 -o jsonpath={.spec.hostPath.path}": f"{SD}/medcea-research-claim-alice-pvc-r1",
            "get pv pvc-r1 -o jsonpath={.spec.persistentVolumeReclaimPolicy}": "Retain",
            "get pv pvc-r2 -o jsonpath={.spec.hostPath.path}": f"{SD}/medcea-research-hub-db-dir-pvc-r2",
            "get pv pvc-r2 -o jsonpath={.spec.persistentVolumeReclaimPolicy}": "Delete",
        }, RESEARCH_NAMESPACE="medcea-research")
        self.assertIn("AI workbench homes in the research namespace medcea-research that this deletes (nothing backs them up)", out)
        self.assertIn(f"alice: claim-alice (10Gi), on this host in {SD}/medcea-research-claim-alice-pvc-r1; kept on this host "
                      "after the claim goes (Retain): remove its directory by hand when no longer needed", out)
        self.assertIn(f"the hub's database: hub-db-dir (1Gi), on this host in {SD}/medcea-research-hub-db-dir-pvc-r2\n", out)
        self.assertNotIn("data-research-postgresql-0 (", out.split("AI workbench homes in the research")[1])
        self.assertNotIn("left behind", out)

    def test_platform_home_left_behind_by_the_move(self):
        pvcs = {"items": [pvc("claim-alice", "pvc-1", labels={"medcea/moved-to": "medcea-research"}),
                          pvc("claim-bob", "pvc-2")]}
        out = self.run_warn({
            "get pvc -n medcea -o json": json.dumps(pvcs),
            "get pv pvc-1 -o jsonpath={.spec.hostPath.path}": f"{SD}/medcea-claim-alice-pvc-1",
            "get pv pvc-1 -o jsonpath={.spec.persistentVolumeReclaimPolicy}": "Retain",
            "get pv pvc-2 -o jsonpath={.spec.hostPath.path}": f"{SD}/medcea-claim-bob-pvc-2",
            "get pv pvc-2 -o jsonpath={.spec.persistentVolumeReclaimPolicy}": "Delete",
        })
        self.assertIn(f"alice: claim-alice (10Gi), on this host in {SD}/medcea-claim-alice-pvc-1; left behind by the move to "
                      "medcea-research (the copy there is the live one); kept on this host after the claim goes (Retain): "
                      "remove its directory by hand when no longer needed", out)
        self.assertIn(f"bob: claim-bob (10Gi), on this host in {SD}/medcea-claim-bob-pvc-2\n", out)
        # the platform's header and advice as before (tests/test_workbench_data.py HomesTest)
        self.assertIn("AI workbench homes that this deletes (nothing backs them up):", out)
        self.assertIn("SAVE_TO_GIT.md", out)
        self.assertNotIn("research namespace", out)

    def test_nothing_said(self):
        base = {"get pvc -n medcea -o json": '{"items": []}'}
        for env, extra in (({}, {}),
                           ({"RESEARCH_NAMESPACE": "medcea"}, {"get pvc -n medcea -o json": '{"items": []}'}),
                           ({"RESEARCH_NAMESPACE": "medcea-research"}, {}),
                           ({"RESEARCH_NAMESPACE": "medcea-research"},
                            {"get pvc -n medcea-research -o json": '{"items": [{"metadata": {"name": "data-research-postgresql-0"}}]}'})):
            with self.subTest(env=env, extra=extra):
                self.assertEqual(self.run_warn(dict(base, **extra), **env).strip(), "rc=0")

    def test_research_homes_when_the_platform_cannot_be_listed(self):
        out = self.run_warn({"get pvc -n medcea-research -o json": json.dumps({"items": [pvc("claim-alice", "pvc-r1")]})},
                            RESEARCH_NAMESPACE="medcea-research")
        self.assertIn("Could not list the AI workbench homes", out)
        self.assertIn("AI workbench homes in the research namespace medcea-research that this deletes", out)
        self.assertIn("alice: claim-alice (10Gi)\n", out)

    def test_order(self):
        out = self.run_warn({
            "get pvc -n medcea -o json": json.dumps({"items": [pvc("claim-bob", "pvc-2")]}),
            "get pvc data-research-postgresql-0 -n medcea-research -o jsonpath={.spec.volumeName}{\"\\t\"}{.status.capacity.storage}":
                "pvc-db\t10Gi",
            "get pvc -n medcea-research -o json": json.dumps({"items": [pvc("claim-alice", "pvc-r1")]}),
        }, RESEARCH_NAMESPACE="medcea-research")
        a = out.index("AI workbench homes that this deletes")
        b = out.index("The research database's volume")
        c = out.index("AI workbench homes in the research namespace")
        self.assertLess(a, b)
        self.assertLess(b, c)


if __name__ == "__main__":
    unittest.main()
