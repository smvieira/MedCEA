"""apps/research-model/endpoints_config.py (research Phase 4d): model endpoints come from config.env, never from code."""
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-model"))
import endpoints_config as ec       # noqa: E402

BASE = os.path.join(ROOT, "apps", "research-model", "endpoints.json")
KEY = "sk-test-0123456789abcdef"
GPU = {"RESEARCH_ENDPOINT_GPU_URL": "http://100.71.228.99:8000", "RESEARCH_ENDPOINT_GPU_MODEL": "Qwen/Qwen3-14B-AWQ",
       "RESEARCH_ENDPOINT_GPU_CONTEXT": "12288", "RESEARCH_ENDPOINT_GPU_MAX_OUTPUT": "1024",
       "RESEARCH_ENDPOINT_GPU_DETERMINISTIC": "true", "RESEARCH_ENDPOINT_GPU_THINKING": "false",
       "RESEARCH_ENDPOINT_GPU_TOOLS": "text", "RESEARCH_ENDPOINT_GPU_KEY": KEY}


class Document(unittest.TestCase):
    def test_nothing_configured_is_the_shipped_file(self):
        d = ec.document(BASE, {}, ["local"])
        self.assertEqual(sorted(d["endpoints"]), ["local"])

    def test_an_endpoint_from_config_env(self):
        d = ec.document(BASE, GPU, ["local", "gpu"])
        self.assertEqual(d["endpoints"]["gpu"], {"kind": "openai", "url": "http://100.71.228.99:8000", "model": "Qwen/Qwen3-14B-AWQ",
                                                  "context": 12288, "max_output": 1024, "deterministic": True, "tools": "text",
                                                  "key": "secret", "thinking": False})
        self.assertNotIn(KEY, json.dumps(d))          # the key never reaches the ConfigMap

    def test_names_map_to_variables(self):
        env = {k.replace("_GPU_", "_LAB_GPU2_"): v for k, v in GPU.items()}
        self.assertIn("lab-gpu2", ec.document(BASE, env, ["lab-gpu2"])["endpoints"])

    def test_refusals(self):
        def bad(change=None, drop=None, enabled=("gpu",), extra=None):
            env = dict(GPU, **(change or {}), **(extra or {}))
            for k in drop or ():
                env.pop(k)
            with self.assertRaises(ec.ConfigError, msg=(change, drop, enabled, extra)):
                ec.document(BASE, env, list(enabled))
        bad(enabled=("nope",))                                         # enabled but defined nowhere
        bad({"RESEARCH_ENDPOINT_GPU_URL": "http://h:8000/v1"})          # a path
        bad({"RESEARCH_ENDPOINT_GPU_URL": "ftp://h"})
        bad({"RESEARCH_ENDPOINT_GPU_CONTEXT": "lots"})
        bad({"RESEARCH_ENDPOINT_GPU_CONTEXT": "100"})
        bad({"RESEARCH_ENDPOINT_GPU_MAX_OUTPUT": "5000"})
        bad({"RESEARCH_ENDPOINT_GPU_DETERMINISTIC": "yes"})
        bad(drop=["RESEARCH_ENDPOINT_GPU_DETERMINISTIC"])
        bad({"RESEARCH_ENDPOINT_GPU_THINKING": "no"})
        bad({"RESEARCH_ENDPOINT_GPU_TOOLS": "xml"})
        bad({"RESEARCH_ENDPOINT_GPU_MODEL": ""})
        bad({"RESEARCH_ENDPOINT_GPU_KEY": "has space here"})
        bad(extra={"RESEARCH_ENDPOINT_LOCAL_URL": "http://h:1"}, enabled=())      # local is the shipped one
        bad(extra={"RESEARCH_ENDPOINT_9X_URL": "http://h:1"}, enabled=())

    def test_optional_fields(self):
        env = dict(GPU)
        for k in ("RESEARCH_ENDPOINT_GPU_THINKING", "RESEARCH_ENDPOINT_GPU_TOOLS", "RESEARCH_ENDPOINT_GPU_KEY",
                  "RESEARCH_ENDPOINT_GPU_MAX_OUTPUT"):
            env.pop(k)
        e = ec.document(BASE, env, ["gpu"])["endpoints"]["gpu"]
        self.assertEqual((e["tools"], e["key"], e["max_output"]), ("native", "none", 1024))
        self.assertNotIn("thinking", e)


PINS = os.path.join(ROOT, "apps", "research-model", "pins.json")


class Inventory(unittest.TestCase):
    """The model picker's list: what a scientist chooses from; never a URL, address or key."""
    def test_local_and_a_configured_endpoint(self):
        inv = ec.inventory(BASE, GPU, ["local", "gpu"], PINS)
        self.assertEqual([i["name"] for i in inv], ["local", "gpu"])
        with open(PINS) as f:
            m = json.load(f)["models"]["4b"]
        self.assertEqual(inv[0]["model"], m["file"][:-5].lower() + "-" + m["sha256"][:12])     # the deploy's alias
        self.assertEqual((inv[0]["context"], inv[0]["where"]), (4096, "this host (CPU)"))
        self.assertEqual(inv[1], {"name": "gpu", "kind": "openai", "model": "Qwen/Qwen3-14B-AWQ", "context": 12288,
                                  "deterministic": True, "tools": "text", "thinking": False, "where": "another server"})
        text = json.dumps(inv)
        for secret in (KEY, "100.71.228.99", "http"):
            self.assertNotIn(secret, text)

    def test_only_the_enabled_in_their_order(self):
        self.assertEqual([i["name"] for i in ec.inventory(BASE, GPU, ["gpu"], PINS)], ["gpu"])
        self.assertEqual([i["name"] for i in ec.inventory(BASE, GPU, ["gpu", "local"], PINS)], ["gpu", "local"])
        with self.assertRaises(ec.ConfigError):
            ec.inventory(BASE, {}, ["gpu"], PINS)

    def test_cli_prints_base64_json(self):
        import base64
        r = Cli.run_cli(None, "inventory", BASE, "local gpu", PINS, env=GPU)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([i["name"] for i in json.loads(base64.b64decode(r.stdout))], ["local", "gpu"])


class SecretDoc(unittest.TestCase):
    def test_the_secret_holds_only_keys(self):
        s = ec.secret("ns-gw", dict(GPU, RESEARCH_ENDPOINT_OPEN_URL="http://h:1"))
        self.assertEqual((s["kind"], s["metadata"]["name"], s["metadata"]["namespace"]), ("Secret", "model-gateway-keys", "ns-gw"))
        self.assertEqual(s["stringData"], {"gpu": KEY})

    def test_no_endpoint_is_an_empty_secret(self):
        self.assertEqual(ec.secret("ns", {})["stringData"], {})


class Cli(unittest.TestCase):
    def run_cli(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("RESEARCH_ENDPOINT_")}
        e.update(env or {})
        return subprocess.run([sys.executable, os.path.join(ROOT, "apps", "research-model", "endpoints_config.py")] + list(args),
                              capture_output=True, text=True, env=e)

    def test_reads_its_environment_and_never_prints_a_key_on_a_refusal(self):
        r = self.run_cli("doc", BASE, "local gpu", env=GPU)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"gpu"', r.stdout)
        self.assertNotIn(KEY, r.stdout + r.stderr)
        r = self.run_cli("doc", BASE, "local gpu", env=dict(GPU, RESEARCH_ENDPOINT_GPU_CONTEXT="x"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("endpoints:", r.stderr)
        self.assertNotIn(KEY, r.stdout + r.stderr)
        self.assertEqual(self.run_cli("nope").returncode, 2)

    def test_the_deploy_passes_the_variables_by_environment(self):
        sh = open(os.path.join(ROOT, "apps", "research-model", "deploy.sh"), encoding="utf-8").read()
        self.assertIn('for _v in $(compgen -v RESEARCH_ENDPOINT_); do export "$_v"; done', sh)
        self.assertNotRegex(sh, r"endpoints_config\.py[^\n]*\$RESEARCH_ENDPOINT_")


if __name__ == "__main__":
    unittest.main()
