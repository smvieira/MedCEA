#!/usr/bin/env python3
"""tests/test_research_bench.py — research Phase 4b step 0's bench, fetch and report
(apps/research-model/, codeplan/rs4-design.md §5.1, R24-R28), offline: no cluster, no network
but a local HTTP server, no model.

- bench.sh's arguments: --help without config.env; no command, an unknown command, an
  unknown option, an option of another command, more than 12 threads: exit 2 before the
  log and the lock (no logs/ written).
- benchlib.py plan on a two-socket topology like the host's: one hardware thread per physical
  core of socket 0 for -t 6 (mask 0x555), the socket's hyper-threads for -t 12, more refused;
  the cheapest runs first and the deepest last; the runtime estimate from the design's ranges
  (the full plan about 3 h expected) and the refusal (exit 2) above --max-hours.
- bench.sh bench against a fake microk8s: refused (exit 1, no Job applied) while a recipe
  run is R or S and when medcea.recipe_run cannot be read (the psql is read-only: PGOPTIONS
  default_transaction_read_only=on, SQL on stdin); with no run it applies the ConfigMap and
  the Job, parses the canned log and writes research/agents/bench/<date>.json.
- The manifests: every ${VAR} in the render list the header names and bench.sh passes,
  nothing left after render, the pinned images by digest, no service account token or
  service links, non-root, read-only root, every capability dropped, a memory request equal
  to its limit, no CPU limit, the label app=research-llm-bench, the model folder read-only
  where it is only read.
- container/bench-run.sh under dash with a stub llama-bench: the CPU mask, --cpu-strict,
  --numa and --no-warmup only when the build's --help lists them, a run needing --numa
  skipped otherwise, the @@ markers; serve.sh: the key only as --api-key-file.
- fetch_model.py against a local HTTP server: a whole fetch, a resume with a Range request
  (also across a redirect), a server that ignores Range (restarted), a sha256 mismatch
  (exit 1, the partial removed), a file already there verified, never renamed before its
  hash matches.
- The report: parse-bench on a canned log (the AVX check), the merge keeps earlier keys, and
  the recommendation's thresholds (8B below 1.5 tok/s generation or 3 tok/s prompt, or
  clearly worse tool-call validity → 4B).

Run: python3 tests/test_research_bench.py
"""
import hashlib
import http.server
import json
import os
import re
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "apps", "research-model")
sys.path.insert(0, APP)
import benchlib  # noqa: E402
import fetch_model  # noqa: E402

SH = shutil.which("dash") or "/bin/sh"
PINS = benchlib.load_pins()


def fake_sys(root, sockets=2, cores=6, ht=2):
    """A /sys like the host's: CPUs interleaved across the sockets, hyper-threads last."""
    base = os.path.join(root, "devices", "system", "cpu")
    n = sockets * cores * ht
    for cpu in range(n):
        d = os.path.join(base, "cpu%d" % cpu, "topology")
        os.makedirs(d)
        pkg, core = cpu % sockets, (cpu // sockets) % cores
        with open(os.path.join(d, "physical_package_id"), "w") as f:
            f.write("%d\n" % pkg)
        with open(os.path.join(d, "core_id"), "w") as f:
            f.write("%d\n" % core)
    for s in range(sockets):
        d = os.path.join(root, "devices", "system", "node", "node%d" % s)
        os.makedirs(d)
        with open(os.path.join(d, "cpulist"), "w") as f:
            f.write(",".join(str(c) for c in range(n) if c % sockets == s) + "\n")
    return root


# ── the plan ─────────────────────────────────────────────────────────────────────
class Plan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sys = fake_sys(self.tmp)
        self.topo = benchlib.topology(self.sys)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_topology_and_masks(self):
        s0 = self.topo["sockets"][0]
        self.assertEqual(s0["physical"], [0, 2, 4, 6, 8, 10])
        self.assertEqual(s0["all"], [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22])
        self.assertEqual(benchlib.cpus_for(self.topo, 0, 6), [0, 2, 4, 6, 8, 10])
        self.assertEqual(benchlib.cpu_mask([0, 2, 4, 6, 8, 10]), "0x555")
        self.assertEqual(benchlib.cpu_mask(benchlib.cpus_for(self.topo, 0, 12)), "0x555555")
        self.assertEqual(benchlib.cpus_for(self.topo, 1, 6), [1, 3, 5, 7, 9, 11])
        with self.assertRaises(benchlib.PlanError):
            benchlib.cpus_for(self.topo, 0, 13)
        with self.assertRaises(benchlib.PlanError):
            benchlib.cpus_for(self.topo, 2, 6)

    def test_the_full_plan(self):
        runs = benchlib.build_plan(PINS, self.topo, ["8b", "4b"], [6, 12], ["none", "isolate"], [0, 4096, 12288])
        names = [r["name"] for r in runs]
        self.assertEqual(names[0], "warmup-8b")
        self.assertEqual(names[-2:], ["depth-8b-d12288", "depth-4b-d12288"])
        self.assertLess(names.index("depth-4b-d0"), names.index("depth-8b-d4096"))
        self.assertTrue(all(not r["discard"] for r in runs if not r["name"].startswith("warmup")))
        sweep = [r for r in runs if r["name"].startswith("sweep-")]
        self.assertEqual(len(sweep), 8)
        self.assertTrue(all(r["numa_required"] for r in sweep))
        d = [r for r in runs if r["name"] == "depth-8b-d12288"][0]
        self.assertEqual(d["args"][d["args"].index("-d") + 1], "12288")
        self.assertEqual(d["mask"], "0x555")
        self.assertEqual(d["numa"], "isolate")
        tests = {t for r in runs for t in r["tests"] if not r["discard"]}
        for t in [("pp", 512, 0), ("tg", 128, 0), ("pp", 4096, 0), ("pp", 512, 4096), ("tg", 128, 4096),
                  ("pp", 512, 12288), ("tg", 128, 12288)]:
            self.assertIn(t, tests)
        tsv = benchlib.plan_tsv(runs).splitlines()
        self.assertEqual(len(tsv), len(runs))
        for line in tsv:
            f = line.split("\t")
            self.assertEqual(len(f), 6)
            self.assertTrue(all(benchlib.TOKEN_RE.match(a) for a in f[5].split(" ")), line)
        est = benchlib.plan_estimate(PINS, runs)
        h = est["expected"]["total_s"] / 3600
        self.assertTrue(2.5 < h < 3.5, h)
        self.assertGreater(est["pessimistic"]["total_s"], est["expected"]["total_s"])

    def test_depth_config_outside_the_sweep_measures_depth_0_itself(self):
        runs = benchlib.build_plan(PINS, self.topo, ["8b"], [12], ["none"], [0, 4096])
        d0 = [r for r in runs if r["name"] == "depth-8b-d0"][0]
        self.assertIn(("tg", 128, 0), d0["tests"])
        self.assertIn("512,4096", d0["args"])

    def test_refusals(self):
        for bad in (dict(models=["7b"]), dict(numa_modes=["interleave"]), dict(depths=[4096])):
            kw = dict(models=["8b"], threads=[6], numa_modes=["none"], depths=[0])
            kw.update(bad)
            with self.assertRaises(benchlib.PlanError, msg=bad):
                benchlib.build_plan(PINS, self.topo, kw["models"], kw["threads"], kw["numa_modes"], kw["depths"])

    def run_plan(self, *args):
        return subprocess.run([sys.executable, os.path.join(APP, "benchlib.py"), "plan", "--sys", self.sys] + list(args),
                              capture_output=True, text=True)

    def test_cli_prints_first_and_refuses_over_the_cap(self):
        p = self.run_plan()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Estimated runtime:", p.stdout)
        self.assertIn("cap is 3.5 h", p.stdout)
        p = self.run_plan("--max-hours", "1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("Estimated runtime:", p.stdout)
        self.assertIn("Refused: the expected runtime is over the 1.0 h cap", p.stderr)
        p = self.run_plan("--models", "8b", "--threads", "6", "--numa", "none", "--depths", "0,4096", "--max-hours", "1")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.run_plan("--threads", "6,6").returncode, 2)

    def test_eval_estimate(self):
        fx = os.path.join(ROOT, "research", "agents", "evals", "fixtures")
        s8 = benchlib.eval_seconds(PINS, "8b", fx)
        s4 = benchlib.eval_seconds(PINS, "4b", fx)
        self.assertGreater(s8, s4)
        self.assertLess((s8 + s4) / 3600, 3.5)


# ── bench.sh against a fake microk8s ─────────────────────────────────────────────
FAKE_MK8S = r'''#!/usr/bin/env python3
import os, sys
log = os.environ["FAKE_LOG"]
a = sys.argv[1:]
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(log, "a") as f:
    f.write("ARGV " + " ".join(a) + "\n")
    if stdin:
        f.write("STDIN " + stdin.replace("\n", "\\n") + "\n")
    f.write("ENV_PGOPTIONS " + " ".join(x for x in a if "PGOPTIONS" in x) + "\n")
if a[:1] == ["status"]:
    sys.exit(0)
if a[:1] != ["kubectl"]:
    sys.exit(0)
k = a[1:]
j = " ".join(k)
if k[:1] == ["exec"]:
    if os.environ.get("FAKE_PSQL_FAIL"):
        print("psql: error: connection refused"); sys.exit(2)
    for r in os.environ.get("FAKE_RUNS", "").split():
        print("run|" + r)
    print("checked|ok"); sys.exit(0)
if k[:2] == ["get", "storageclass"]:
    print(os.environ.get("FAKE_PVDIR", "/var/snap/microk8s/common/default-storage")); sys.exit(0)
if k[:2] == ["get", "priorityclass"]:
    sys.exit(1)
if k[:2] == ["get", "namespace"]:
    sys.exit(0)
if k[:2] == ["get", "job"]:
    print("1/"); sys.exit(0)
if k[:1] == ["logs"]:
    sys.stdout.write(open(os.environ["FAKE_BENCH_LOG"]).read()); sys.exit(0)
if k[:2] == ["create", "configmap"] or k[:3] == ["create", "secret", "generic"]:
    print("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x"); sys.exit(0)
if k[:1] == ["label"]:
    sys.stdout.write(stdin); sys.exit(0)
if k[:1] == ["apply"]:
    with open(log, "a") as f:
        f.write("APPLIED " + stdin.replace("\n", "\\n") + "\n")
    sys.exit(0)
sys.exit(0)
'''


def canned_log():
    def res(n_prompt, n_gen, depth, ts, t=6):
        return {"n_prompt": n_prompt, "n_gen": n_gen, "n_depth": depth, "avg_ts": ts, "stddev_ts": 0.0,
                "n_threads": t, "cpu_mask": "0x555"}
    out = ["@@HELP cpu_mask=1 cpu_strict=1 n_depth=1 numa=1 no_warmup=1", "@@TASKSET 1", "@@SYSINFO",
           "load_backend: loaded CPU backend from /app/libggml-cpu-sandybridge.so",
           "system_info: n_threads = 1 | CPU : SSE3 = 1 | SSSE3 = 1 | AVX = 1 | AVX2 = 0 | F16C = 0 |",
           "@@SYSINFO_RC 0"]
    for name, rows in (("warmup-8b", [res(64, 0, 0, 5.0), res(0, 8, 0, 2.0)]),
                       ("sweep-8b-t6-none", [res(512, 0, 0, 6.5), res(0, 128, 0, 2.6)]),
                       ("sweep-8b-t12-isolate", [res(512, 0, 0, 7.1, 12), res(0, 128, 0, 2.4, 12)]),
                       ("depth-8b-d12288", [res(512, 0, 12288, 4.0), res(0, 128, 12288, 1.9)]),
                       ("sweep-4b-t6-none", [res(512, 0, 0, 14.0), res(0, 128, 0, 5.1)])):
        out += ["@@BEGIN " + name, "# llama-bench ...", "@@JSON", json.dumps(rows), "", "@@STDERR",
                "@@END %s rc=0 seconds=60" % name]
    out += ["@@SKIP sweep-4b-t6-isolate this llama-bench has no --numa", "@@DONE"]
    return "\n".join(out) + "\n"


class BenchScript(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.tree = os.path.join(self.t, "tree")
        os.makedirs(os.path.join(self.tree, "infra"))
        for f in ("lib-log.sh", "lib-lock.sh", "lib-mk8s.sh", "lib-render.sh"):
            shutil.copy(os.path.join(ROOT, "infra", f), os.path.join(self.tree, "infra", f))
        shutil.copytree(APP, os.path.join(self.tree, "apps", "research-model"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(os.path.join(ROOT, "research"), os.path.join(self.tree, "research"),
                        ignore=shutil.ignore_patterns("__pycache__", ".venv", "runs"))
        self.bin = os.path.join(self.t, "bin")
        os.makedirs(self.bin)
        p = os.path.join(self.bin, "microk8s")
        with open(p, "w") as f:
            f.write(FAKE_MK8S)
        os.chmod(p, 0o755)
        self.models = os.path.join(self.t, "models")
        os.makedirs(self.models, mode=0o700)
        for k in ("8b", "4b"):
            open(os.path.join(self.models, PINS["models"][k]["sha256"] + ".gguf"), "w").close()
        self.meminfo = os.path.join(self.t, "meminfo")
        with open(self.meminfo, "w") as f:
            f.write("MemTotal:       31457280 kB\nMemAvailable:   23068672 kB\n")
        self.flog = os.path.join(self.t, "fake.log")
        self.blog = os.path.join(self.t, "bench.out")
        with open(self.blog, "w") as f:
            f.write(canned_log())

    def tearDown(self):
        shutil.rmtree(self.t)

    def config(self):
        with open(os.path.join(self.tree, "config.env"), "w") as f:
            f.write('PROJECT_NAME="medcea"\nNAMESPACE="medcea"\nPOSTGRES_DB="medcea_db"\n'
                    'RESEARCH_MODEL_DIR="%s"\n' % self.models)

    def run_bench(self, *args, env=None, config=True):
        if config:
            self.config()
        e = {k: v for k, v in os.environ.items() if not k.startswith("MEDCEA_")}
        e.update({"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_LOG": self.flog, "FAKE_BENCH_LOG": self.blog,
                  "MEDCEA_BENCH_MEMINFO": self.meminfo})
        e.update(env or {})
        return subprocess.run(["bash", os.path.join(self.tree, "apps", "research-model", "bench.sh")] + list(args),
                              capture_output=True, text=True, env=e, cwd=self.t, timeout=300,
                              stdin=subprocess.DEVNULL)

    def fake_log(self):
        return open(self.flog).read() if os.path.exists(self.flog) else ""

    def test_usage_errors_exit_2_before_the_log_and_the_lock(self):
        for args in ([], ["nope"], ["bench", "--bogus"], ["bench", "--date", "2026-11-21"], ["fetch", "--threads", "6"],
                     ["bench", "--threads", "6,13"], ["bench", "--models", "7b"], ["eval", "--eval-threads", "24"],
                     ["bench", "--max-hours", "x"], ["report", "--date", "21-11-2026"], ["bench", "--models"]):
            with self.subTest(args):
                p = self.run_bench(*args)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.tree, "logs")), args)
                self.assertFalse(os.path.exists(os.path.join(self.tree, ".medcea.lock")), args)

    def test_help_needs_no_config(self):
        p = self.run_bench("--help", config=False)
        self.assertEqual(p.returncode, 0)
        self.assertIn("apps/research-model/bench.sh fetch", p.stdout)
        self.assertNotIn("Run from anywhere", p.stdout.split("\n")[0])

    def test_refused_while_a_run_is_r_or_s(self):
        p = self.run_bench("bench", "--max-hours", "4", env={"FAKE_RUNS": "7|R 9|S"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("Refused while a recipe run is R or S", p.stdout + p.stderr)
        self.assertIn("run 7  status R", p.stdout + p.stderr)
        self.assertIn("Estimated runtime:", p.stdout)      # the plan is printed first
        log = self.fake_log()
        self.assertNotIn("APPLIED", log)
        self.assertIn("default_transaction_read_only=on", log)
        self.assertIn("recipe_run_status IN ('R', 'S')", log)
        self.assertIn("rdbms-postgresql-0", log)

    def test_refused_when_the_runs_cannot_be_read(self):
        p = self.run_bench("bench", "--max-hours", "4", env={"FAKE_PSQL_FAIL": "1"})
        self.assertEqual(p.returncode, 1)
        self.assertIn("never runs unchecked", p.stdout + p.stderr)
        self.assertNotIn("APPLIED", self.fake_log())

    def test_refused_over_the_cap_before_anything(self):
        p = self.run_bench("bench", "--max-hours", "1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("over the 1.0 h cap", p.stdout + p.stderr)
        self.assertNotIn("exec", self.fake_log())

    def test_refused_with_too_little_memory(self):
        with open(self.meminfo, "w") as f:
            f.write("MemAvailable:   4194304 kB\n")
        p = self.run_bench("bench", "--max-hours", "4")
        self.assertEqual(p.returncode, 1)
        self.assertIn("of memory available", p.stdout + p.stderr)
        self.assertNotIn("APPLIED", self.fake_log())

    def test_unfetched_models(self):
        os.remove(os.path.join(self.models, PINS["models"]["4b"]["sha256"] + ".gguf"))
        p = self.run_bench("bench", "--max-hours", "4")
        self.assertEqual(p.returncode, 2)
        self.assertIn("bench.sh fetch --models 4b", p.stdout + p.stderr)

    def test_bench_runs_and_reports(self):
        p = self.run_bench("bench", "--max-hours", "4", "--depths", "0,4096")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        log = self.fake_log()
        self.assertIn("kind: Job", log)
        self.assertIn("name: research-llm-bench", log)
        self.assertIn(PINS["llama_cpp"]["image_full"], log)
        self.assertIn("memory: 10Gi", log)
        self.assertNotIn("${", log.split("APPLIED", 1)[1])
        lock = os.path.join(self.tree, ".medcea.lock")
        self.assertTrue(os.path.exists(lock))
        reps = os.listdir(os.path.join(self.tree, "research", "agents", "bench"))
        dated = [r for r in reps if re.match(r"^20\d\d-\d\d-\d\d\.json$", r)]
        self.assertEqual(len(dated), 1, reps)
        rep = json.load(open(os.path.join(self.tree, "research", "agents", "bench", dated[0])))
        self.assertEqual(rep["bench"]["avx_check"], "pass")
        self.assertEqual(rep["bench"]["best"]["8b"]["gen_tok_s"], 2.6)
        self.assertEqual(rep["recommendation"]["model"], "8b")
        self.assertIn("machine", rep)
        logs = os.listdir(os.path.join(self.tree, "logs"))
        self.assertTrue(any(l.startswith("research-llm-bench-") and l.endswith(".log") for l in logs), logs)
        raw = [l for l in logs if l.endswith(".out")][0]
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tree, "logs", raw)).st_mode), 0o600)

    def test_cleanup_never_touches_the_models(self):
        p = self.run_bench("cleanup")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("delete job,pod,configmap,secret -l app=research-llm-bench", self.fake_log())
        self.assertEqual(len(os.listdir(self.models)), 2)


# ── the manifests ────────────────────────────────────────────────────────────────
class Manifests(unittest.TestCase):
    VALUES = {"NAMESPACE": "medcea", "PYTHON_IMAGE": PINS["python_image"], "MODEL_DIR": "/var/lib/medcea/research-models",
              "MODEL_UID": "1000", "MODEL_GID": "1000", "FETCH_DEADLINE_S": "10800", "PRIORITY_CLASS": "",
              "LLAMA_IMAGE_FULL": PINS["llama_cpp"]["image_full"], "BENCH_DEADLINE_S": "14400", "BENCH_MEMORY": "10Gi",
              "SYSINFO_MODEL": "/models/x.gguf", "LLAMA_IMAGE_SERVER": PINS["llama_cpp"]["image_server"],
              "EVAL_DEADLINE_S": "14400", "SERVER_MEMORY": "12Gi", "MODEL_KEY": "8b", "MODEL_FILE": "x.gguf",
              "MODEL_ALIAS": "Qwen3-8B-Q4_K_M.gguf", "LLM_THREADS": "6", "LLM_CPUS": "0,2,4,6,8,10", "LLM_MASK": "0x555",
              "LLM_CTX": "24576"}

    def render(self, name):
        path = os.path.join(APP, "k8s", name)
        text = open(path).read()
        header = re.search(r"render %s ([A-Z_ ]+)\n" % re.escape(name), text).group(1).split()
        used = set(re.findall(r"\$\{([A-Z_]+)\}", text))
        self.assertEqual(set(header), used, name)
        bench = open(os.path.join(APP, "bench.sh")).read()
        call = re.search(r'render "\$HERE/k8s/%s" ((?:[A-Z_ ]|\\\n)+)' % re.escape(name), bench).group(1)
        self.assertEqual(set(call.replace("\\", " ").split()), used, name)
        env = dict(os.environ, **self.VALUES)
        out = subprocess.run(["bash", "-c", 'source "$0"; render "$1" ' + " ".join(header),
                              os.path.join(ROOT, "infra", "lib-render.sh"), path],
                             capture_output=True, text=True, env=env, check=True).stdout
        self.assertNotIn("${", out)
        import yaml
        return yaml.safe_load(out)

    def pod(self, doc):
        return doc["spec"]["template"]["spec"] if doc["kind"] == "Job" else doc["spec"]

    def check_common(self, doc, image, memory):
        self.assertEqual(doc["metadata"]["labels"]["app"], "research-llm-bench")
        spec = self.pod(doc)
        if doc["kind"] == "Job":
            self.assertEqual(doc["spec"]["backoffLimit"], 0)
            self.assertGreater(doc["spec"]["activeDeadlineSeconds"], 0)
            self.assertEqual(doc["spec"]["template"]["metadata"]["labels"]["app"], "research-llm-bench")
        else:
            self.assertGreater(spec["activeDeadlineSeconds"], 0)
        self.assertIs(spec["automountServiceAccountToken"], False)
        self.assertIs(spec["enableServiceLinks"], False)
        self.assertEqual(spec["restartPolicy"], "Never")
        sc = spec["securityContext"]
        self.assertIs(sc["runAsNonRoot"], True)
        self.assertEqual(sc["runAsUser"], 1000)
        self.assertEqual(sc["seccompProfile"]["type"], "RuntimeDefault")
        (c,) = spec["containers"]
        self.assertEqual(c["image"], image)
        self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
        self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertNotIn("cpu", c["resources"]["limits"])
        self.assertIn("cpu", c["resources"]["requests"])
        self.assertEqual(c["resources"]["requests"]["memory"], memory)
        self.assertEqual(c["resources"]["limits"]["memory"], memory)
        mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
        self.assertIn("/tmp", mounts)
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(vols["models"]["hostPath"]["path"], "/var/lib/medcea/research-models")
        self.assertNotIn("env", [] if "env" not in c else [e["name"] for e in c["env"] if "valueFrom" in e])
        return c, mounts, vols

    def test_fetch(self):
        doc = self.render("fetch-job.yaml")
        c, mounts, _ = self.check_common(doc, PINS["python_image"], "512Mi")
        self.assertNotIn("readOnly", mounts["/models"])            # it writes the folder
        self.assertEqual(c["command"][:2], ["python3", "-I"])

    def test_bench(self):
        doc = self.render("bench-job.yaml")
        c, mounts, _ = self.check_common(doc, PINS["llama_cpp"]["image_full"], "10Gi")
        self.assertIs(mounts["/models"]["readOnly"], True)
        self.assertEqual(c["resources"]["requests"]["cpu"], "100m")

    def test_eval(self):
        doc = self.render("eval-pod.yaml")
        c, mounts, vols = self.check_common(doc, PINS["llama_cpp"]["image_server"], "12Gi")
        self.assertIs(mounts["/models"]["readOnly"], True)
        self.assertEqual(vols["keys"]["secret"]["secretName"], "research-llm-bench-key")
        self.assertEqual(doc["metadata"]["name"], "research-llm-eval-8b")
        self.assertEqual(c["readinessProbe"]["httpGet"]["path"], "/health")

    def test_pins(self):
        self.assertTrue(PINS["llama_cpp"]["image_full"].startswith("ghcr.io/ggml-org/llama.cpp:full-b12182@sha256:"))
        self.assertTrue(PINS["llama_cpp"]["image_server"].startswith("ghcr.io/ggml-org/llama.cpp:server-b12182@sha256:"))
        self.assertTrue(PINS["python_image"].startswith("python:3.14.4-slim@sha256:"))
        for k, m in PINS["models"].items():
            self.assertRegex(m["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(m["revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(m["licence"], "Apache-2.0")
        self.assertEqual(PINS["models"]["8b"]["sha256"][:8], "d98cdcbd")
        self.assertEqual(PINS["models"]["4b"]["sha256"][:8], "3605803b")


# ── the container scripts ────────────────────────────────────────────────────────
STUB_BENCH = """#!/bin/sh
if [ "$1" = --help ]; then printf '%s\\n' "$STUB_HELP"; exit 0; fi
echo "$*" >> "$STUB_ARGS"
echo '[{"n_prompt": 512, "n_gen": 0, "n_depth": 0, "avg_ts": 6.0, "n_threads": 6}]'
echo "load_backend: loaded CPU backend from libggml-cpu-sandybridge.so" >&2
"""


class ContainerScripts(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.stub = os.path.join(self.t, "llama-bench")
        with open(self.stub, "w") as f:
            f.write(STUB_BENCH)
        os.chmod(self.stub, 0o755)
        self.plan = os.path.join(self.t, "plan.tsv")
        with open(self.plan, "w") as f:
            f.write("sweep-8b-t6-isolate\t0,2,4\t0x15\tisolate\t1\t-m /models/a.gguf -p 512 -n 128 -t 3 -r 1\n"
                    "depth-8b-d4096\t0,2,4\t0x15\tisolate\t0\t-m /models/a.gguf -p 512 -n 128 -d 4096 -t 3 -r 1\n")

    def tearDown(self):
        shutil.rmtree(self.t)

    def run_script(self, help_text):
        env = dict(os.environ, LLAMA_BENCH=self.stub, LLAMA_SERVER="/nonexistent", BENCH_PLAN=self.plan,
                   BENCH_WORK=self.t, STUB_HELP=help_text, STUB_ARGS=os.path.join(self.t, "args"))
        p = subprocess.run([SH, os.path.join(APP, "container", "bench-run.sh")], capture_output=True, text=True, env=env)
        args = open(os.path.join(self.t, "args")).read().splitlines() if os.path.exists(os.path.join(self.t, "args")) else []
        return p, args

    def test_every_flag_when_the_build_has_it(self):
        p, args = self.run_script("  -C, --cpu-mask <hex>\n  --cpu-strict <0|1>\n  -d, --n-depth <n>\n"
                                  "  --numa <distribute|isolate|numactl>\n  --no-warmup\n")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("@@HELP cpu_mask=1 cpu_strict=1 n_depth=1 numa=1 no_warmup=1", p.stdout)
        self.assertEqual(len(args), 2)
        self.assertIn("--numa isolate -C 0x15 --cpu-strict 1 --no-warmup -o json", args[0])
        self.assertIn("-d 4096", args[1])
        parsed = benchlib.parse_bench(p.stdout)
        self.assertTrue(parsed["done"])
        self.assertEqual([r["name"] for r in parsed["runs"]], ["sweep-8b-t6-isolate", "depth-8b-d4096"])
        self.assertEqual(parsed["runs"][0]["results"][0]["avg_ts"], 6.0)
        self.assertEqual(parsed["avx_check"], "pass")       # the sandybridge backend was loaded

    def test_without_the_optional_flags(self):
        p, args = self.run_script("  -p, --n-prompt <n>\n")
        self.assertEqual(p.returncode, 0)
        self.assertIn("@@SKIP sweep-8b-t6-isolate this llama-bench has no --numa", p.stdout)
        self.assertIn("@@SKIP depth-8b-d4096 this llama-bench has no -d/--n-depth", p.stdout)
        self.assertEqual(args, [])

    def test_serve_passes_the_key_only_as_a_file(self):
        stub = os.path.join(self.t, "llama-server")
        with open(stub, "w") as f:
            f.write('#!/bin/sh\nif [ "$1" = --help ]; then echo "  --metrics"; echo "  --cache-prompt"; exit 0; fi\n'
                    'echo "ARGS $*"\n')
        os.chmod(stub, 0o755)
        env = dict(os.environ, LLAMA_SERVER=stub, MODEL="/models/a.gguf", ALIAS="a", THREADS="6",
                   CPUS="0,2,4,6,8,10", MASK="0x555", CTX="24576")
        p = subprocess.run([SH, os.path.join(APP, "container", "serve.sh")], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        line = [l for l in p.stdout.splitlines() if l.startswith("ARGS ")][0]
        for want in ("--api-key-file /keys/key", "--jinja", "-np 1", "--temp 0", "--top-k 1", "--seed 1",
                     "-c 24576", "--metrics", "--cache-prompt"):
            self.assertIn(want, line)
        self.assertNotIn("--api-key ", line)
        self.assertNotIn("--no-webui", line)


# ── fetch_model.py against a local HTTP server ───────────────────────────────────
class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        srv = self.server
        srv.requests.append((self.path, self.headers.get("Range")))
        if self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", "/blob/" + self.path.split("/", 2)[2])
            self.end_headers()
            return
        body = srv.body
        rng = self.headers.get("Range")
        if rng and srv.ranges:
            start = int(re.match(r"bytes=(\d+)-", rng).group(1))
            self.send_response(206)
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, len(body) - 1, len(body)))
            body = body[start:]
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Fetch(unittest.TestCase):
    def setUp(self):
        self.body = os.urandom(3 * 1024 * 1024 + 17)
        self.sha = hashlib.sha256(self.body).hexdigest()
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        self.srv.daemon_threads = True
        self.srv.body, self.srv.ranges, self.srv.requests = self.body, True, []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.dir)

    def pin(self, path="/blob/m.gguf", sha=None):
        return {"url": self.base + path, "sha256": sha or self.sha, "size_bytes": len(self.body),
                "file": "m.gguf", "repo": "r/r", "revision": "0" * 40, "name": "m", "licence": "Apache-2.0"}

    def final(self, sha=None):
        return os.path.join(self.dir, (sha or self.sha) + ".gguf")

    def test_whole_fetch(self):
        fetch_model.fetch_one("m", self.pin(), self.dir)
        self.assertEqual(open(self.final(), "rb").read(), self.body)
        self.assertFalse(os.path.exists(self.final() + ".partial"))
        prov = json.load(open(os.path.join(self.dir, self.sha + ".json")))
        self.assertEqual(prov["sha256"], self.sha)
        self.assertEqual(self.srv.requests, [("/blob/m.gguf", None)])

    def test_resume_with_range_across_a_redirect(self):
        with open(self.final() + ".partial", "wb") as f:
            f.write(self.body[:1000000])
        fetch_model.fetch_one("m", self.pin("/redirect/m.gguf"), self.dir)
        self.assertEqual(open(self.final(), "rb").read(), self.body)
        self.assertEqual(self.srv.requests, [("/redirect/m.gguf", "bytes=1000000-"), ("/blob/m.gguf", "bytes=1000000-")])

    def test_server_ignoring_range_restarts(self):
        self.srv.ranges = False
        with open(self.final() + ".partial", "wb") as f:
            f.write(b"x" * 5000)                  # junk: must not survive
        fetch_model.fetch_one("m", self.pin(), self.dir)
        self.assertEqual(open(self.final(), "rb").read(), self.body)

    def test_sha_mismatch_refused_and_partial_removed(self):
        wrong = "0" * 64
        with self.assertRaises(fetch_model.FetchError) as cm:
            fetch_model.fetch_one("m", self.pin(sha=wrong), self.dir)
        self.assertEqual(cm.exception.code, 1)
        self.assertFalse(os.path.exists(self.final(wrong)))
        self.assertFalse(os.path.exists(self.final(wrong) + ".partial"))

    def test_corrupt_partial_is_caught_by_the_hash(self):
        with open(self.final() + ".partial", "wb") as f:
            f.write(b"\0" * 1000)                 # wrong bytes, right length prefix
        with self.assertRaises(fetch_model.FetchError) as cm:
            fetch_model.fetch_one("m", self.pin(), self.dir)
        self.assertEqual(cm.exception.code, 1)
        self.assertFalse(os.path.exists(self.final()))

    def test_a_file_already_there(self):
        with open(self.final(), "wb") as f:
            f.write(self.body)
        fetch_model.fetch_one("m", self.pin(), self.dir)
        self.assertEqual(self.srv.requests, [])
        with open(self.final(), "ab") as f:
            f.write(b"!")
        with self.assertRaises(fetch_model.FetchError) as cm:
            fetch_model.fetch_one("m", self.pin(), self.dir)
        self.assertEqual(cm.exception.code, 1)

    def test_more_bytes_than_the_pin(self):
        pin = self.pin()
        pin["size_bytes"] = 1000
        with self.assertRaises(fetch_model.FetchError) as cm:
            fetch_model.fetch_one("m", pin, self.dir)
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(os.listdir(self.dir), [])

    def test_cli(self):
        pins = os.path.join(self.dir, "models.json")
        with open(pins, "w") as f:
            json.dump({"m": self.pin()}, f)
        p = subprocess.run([sys.executable, "-I", os.path.join(APP, "fetch_model.py"), "--dir", self.dir,
                            "--pins", pins], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, "-I", os.path.join(APP, "fetch_model.py"), "--dir", self.dir,
                            "--pins", pins, "--verify-only"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("verified", p.stdout)


# ── the report ───────────────────────────────────────────────────────────────────
class Report(unittest.TestCase):
    def test_parse_and_avx(self):
        parsed = benchlib.parse_bench(canned_log())
        self.assertTrue(parsed["done"])
        self.assertEqual(parsed["avx_check"], "pass")
        self.assertEqual(parsed["skipped"][0]["name"], "sweep-4b-t6-isolate")
        self.assertEqual(benchlib.avx_check(["system_info: AVX = 1 | AVX2 = 1 |"]), "fail")
        self.assertEqual(benchlib.avx_check(["nothing"]), "unknown")
        rows = benchlib.bench_rows(parsed)
        self.assertFalse(any(r["run"].startswith("warmup") for r in rows))
        best = benchlib.best_rates(rows, "8b")
        self.assertEqual(best["prompt_tok_s"], 7.1)
        self.assertEqual(best["prompt_config"], {"threads": 12, "numa": None})
        self.assertEqual(best["gen_tok_s"], 2.6)

    def test_an_incomplete_log(self):
        text = canned_log().replace("@@DONE\n", "")
        parsed = benchlib.parse_bench(text)
        self.assertFalse(parsed["done"])
        self.assertEqual(len(parsed["runs"]), 5)

    def test_recommendation(self):
        r = lambda g, p: {"gen_tok_s": g, "prompt_tok_s": p}
        ev = lambda v: {"scores": {"tool_call_validity": v}}
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, {})[0], "8b")
        self.assertEqual(benchlib.recommend({"8b": r(1.4, 6)}, {})[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 2.9)}, {})[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, {"8b": ev(0.70), "4b": ev(0.90)})[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, {"8b": ev(0.80), "4b": ev(0.90)})[0], "8b")
        self.assertIsNone(benchlib.recommend({}, {})[0])

    def test_merge_keeps_earlier_parts(self):
        bench = benchlib.parse_bench(canned_log())
        rep = benchlib.merge_report({}, PINS, machine={"cpu_model": "x"}, bench=bench, today="2026-11-21")
        self.assertEqual(rep["recommendation"]["model"], "8b")
        ev = {"model_key": "8b", "scores": {"tool_call_validity": 0.5}}
        ev4 = {"model_key": "4b", "scores": {"tool_call_validity": 0.95}}
        rep2 = benchlib.merge_report(rep, PINS, evals=[ev, ev4])
        self.assertEqual(rep2["machine"], {"cpu_model": "x"})
        self.assertIn("bench", rep2)
        self.assertEqual(rep2["date"], "2026-11-21")
        self.assertEqual(rep2["recommendation"]["model"], "4b")
        self.assertEqual(rep2["pins"]["models"]["8b"]["sha256"], PINS["models"]["8b"]["sha256"])

    def test_machine_facts(self):
        t = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(t, "proc"))
            with open(os.path.join(t, "proc", "cpuinfo"), "w") as f:
                f.write("processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2430L 0 @ 2.00GHz\n"
                        "flags\t\t: fpu sse4_2 avx\n\nprocessor\t: 1\n")
            with open(os.path.join(t, "proc", "meminfo"), "w") as f:
                f.write("MemTotal:       31457280 kB\nMemAvailable:   22020096 kB\n")
            fake_sys(os.path.join(t, "sys"))
            m = benchlib.machine_facts(os.path.join(t, "proc"), os.path.join(t, "sys"))
            self.assertEqual(m["simd"]["avx"], True)
            self.assertEqual(m["simd"]["avx2"], False)
            self.assertEqual(m["sockets"], 2)
            self.assertEqual(m["physical_cores"], 12)
            self.assertEqual(m["mem_total_gib"], 30.0)
        finally:
            shutil.rmtree(t)


if __name__ == "__main__":
    unittest.main()
