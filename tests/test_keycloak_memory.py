"""tests/test_keycloak_memory.py — Keycloak's memory limit and heap (20 Nov 2026).

A plain `start` runs Keycloak's build step in a second JVM before the server's, both under
one container limit; at Keycloak's default heap (70 % of the limit) each, the pod was
OOM-killed at start on a 24-CPU host with the old fixed 2Gi. The limit is now
KEYCLOAK_MEMORY_LIMIT (config.env, default 3Gi) and the heap is capped by JAVA_OPTS_KC_HEAP.

  Render     the manifest rendered with deploy-infra.sh's own render list carries the limit
             and the heap options, and no ${...} is left
  Validate   deploy-infra.sh's own check: an unset value becomes 3Gi, 512Mi passes, 3G and
             0Gi are refused
  Template   config.env.example has the key with the default

    python3 tests/test_keycloak_memory.py
"""
import os
import re
import subprocess
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(REPO, "deploy-infra.sh")).read()


def render_call():
    m = re.search(r'^render "\$SCRIPT_DIR/k8s/keycloak/keycloak\.yaml" ([A-Z_ ]+) \|', SRC, re.M)
    return m.group(1).split()


def validation_block():
    m = re.search(r'^KEYCLOAK_MEMORY_LIMIT="\$\{KEYCLOAK_MEMORY_LIMIT:-3Gi\}"\n.*?^fi\n', SRC, re.S | re.M)
    return m.group(0)


class Render(unittest.TestCase):
    def test_limit_and_heap(self):
        env = dict(os.environ, NAMESPACE="ns", POSTGRES_USER="postgres", POSTGRES_PASS="pw",
                   KEYCLOAK_DOMAIN="keycloak.example.org", _KC_THEME_SUM="abc",
                   KEYCLOAK_MEMORY_LIMIT="3Gi")
        script = 'source infra/lib-render.sh; render k8s/keycloak/keycloak.yaml ' + " ".join(render_call())
        out = subprocess.run(["bash", "-c", script], cwd=REPO, env=env, capture_output=True,
                             text=True, check=True).stdout
        self.assertNotIn("${", out)
        dep = next(d for d in yaml.safe_load_all(out) if d and d.get("kind") == "Deployment")
        c = dep["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["resources"]["limits"]["memory"], "3Gi")
        envs = {e["name"]: e.get("value") for e in c["env"]}
        self.assertEqual(envs["JAVA_OPTS_KC_HEAP"], "-XX:MaxRAMPercentage=50 -XX:InitialRAMPercentage=25")

    def test_variable_is_on_the_render_list(self):
        self.assertIn("KEYCLOAK_MEMORY_LIMIT", render_call())


class Validate(unittest.TestCase):
    def run_block(self, value):
        pre = "" if value is None else "KEYCLOAK_MEMORY_LIMIT=%s\n" % value
        script = 'RED=; NC=\nunset KEYCLOAK_MEMORY_LIMIT\n' + pre + validation_block() + 'echo "$KEYCLOAK_MEMORY_LIMIT"\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_default(self):
        r = self.run_block(None)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "3Gi"))

    def test_mebibytes_pass(self):
        self.assertEqual(self.run_block("2560Mi").stdout.strip(), "2560Mi")

    def test_refused(self):
        for bad in ("3G", "0Gi", "3gi", "3Gi;x"):
            r = self.run_block("'%s'" % bad)
            self.assertEqual(r.returncode, 1, bad)
            self.assertIn("KEYCLOAK_MEMORY_LIMIT", r.stderr)


class Template(unittest.TestCase):
    def test_example_has_the_default(self):
        ex = open(os.path.join(REPO, "config.env.example")).read()
        self.assertRegex(ex, r'(?m)^KEYCLOAK_MEMORY_LIMIT="3Gi"$')


if __name__ == "__main__":
    unittest.main()
