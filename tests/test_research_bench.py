#!/usr/bin/env python3
"""tests/test_research_bench.py — research Phase 4b step 0's bench, fetch and report
(apps/research-model/, codeplan/rs4-design.md §5.1, R24-R28), offline: no cluster, no network
but a local HTTP server, no model.

- bench.sh's arguments: --help without config.env; no command, an unknown command, an
  unknown option, an option of another command, more than 12 threads: exit 2 before the
  log and the lock (no logs/ written).
- benchlib.py plan on a two-socket topology like the host's: one hardware thread per physical
  core of socket 0 for -t 6 (mask 0x555), the socket's hyper-threads for -t 12, more refused;
  R26's depth runs first (--depth-numa none by default), the optional sweep last; the
  runtime estimate from the design's ranges (attention over every query head, the context
  part doubled without F16C) and the refusal (exit 2) when the PESSIMISTIC runtime is above
  --max-hours (the Job's deadline is --max-hours + 30 min).
- bench.sh bench against a fake microk8s: refused (exit 1, no Job applied) while a recipe
  run is R or S and when medcea.recipe_run cannot be read (the psql is read-only: PGOPTIONS
  default_transaction_read_only=on, SQL on stdin); with no run it applies the ConfigMap and
  the Job, parses the canned log and writes research/agents/bench/<date>.json; a SIGTERM
  while it waits deletes the Job (bench and fetch); a run that starts while the Job runs
  stops it (exit 1, "stopped: run N started", the log read first, the partial report kept);
  the eval's Pod gets what is left of one end time and is deleted when a run starts while
  it loads.
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
- The report: parse-bench on a canned log (the AVX check), the merge keeps earlier keys and
  every earlier bench invocation's rows (an 8B-only bench, then a 4B-only one), bench.sh
  report merges every bench of the date, rows under a NUMA strategy marked "node affinity",
  and the recommendation (none until both the throughput and the evals are in; 8B below
  1.5 tok/s generation or 3 tok/s prompt, or clearly worse on any graded outcome → 4B).

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
        self.assertEqual(names[:4], ["warmup-8b", "depth-8b-d0", "warmup-4b", "depth-4b-d0"])
        # R26's measurements first, the deepest last among them, the optional sweep after
        self.assertEqual(names[4:8], ["depth-8b-d4096", "depth-4b-d4096", "depth-8b-d12288", "depth-4b-d12288"])
        self.assertTrue(all(n.startswith("sweep-") for n in names[8:]))
        self.assertTrue(all(not r["discard"] for r in runs if not r["name"].startswith("warmup")))
        sweep = [r for r in runs if r["name"].startswith("sweep-")]
        self.assertEqual(len(sweep), 6)                        # 2 x 2 per model, less the depth configuration
        self.assertNotIn("sweep-8b-t6-none", names)
        self.assertTrue(all(r["numa_required"] for r in sweep))
        d = [r for r in runs if r["name"] == "depth-8b-d12288"][0]
        self.assertEqual(d["args"][d["args"].index("-d") + 1], "12288")
        self.assertEqual(d["mask"], "0x555")
        self.assertEqual(d["numa"], "none")                     # isolate would reset the pin to the node
        self.assertEqual([r["numa"] for r in runs if r["name"].startswith("depth-")], ["none"] * 6)
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
        est = benchlib.plan_estimate(PINS, runs)                # no F16C, as on the host
        self.assertTrue(3.3 < est["expected"]["total_s"] / 3600 < 4.2, est["expected"]["total_s"] / 3600)
        self.assertTrue(5.8 < est["pessimistic"]["total_s"] / 3600 < 7.0, est["pessimistic"]["total_s"] / 3600)
        self.assertFalse(est["f16c"])

    def test_depth_0_is_always_measured_by_its_own_run(self):
        for threads, numa in (([12], ["none"]), ([6], ["none"])):
            runs = benchlib.build_plan(PINS, self.topo, ["8b"], threads, numa, [0, 4096])
            d0 = [r for r in runs if r["name"] == "depth-8b-d0"][0]
            self.assertEqual(d0["tests"], [("pp", 512, 0), ("pp", 4096, 0), ("tg", 128, 0)])
            self.assertIn("512,4096", d0["args"])

    def test_the_cost_model(self):
        m8, m4 = PINS["models"]["8b"], PINS["models"]["4b"]
        # attention width = heads x head_dim (4096 for both), not 4B's hidden size of 2560
        self.assertEqual(m4["arch"]["heads"] * m4["arch"]["head_dim"], 4096)
        self.assertAlmostEqual(benchlib._attn_ratio(m4) / benchlib._attn_ratio(m8), 8.2 / 4.0)
        # without F16C the context part costs F16_SCALAR_FACTOR times more; depth 0 is untouched
        self.assertGreater(benchlib.pp_seconds(m8, 512, 12288, 5, f16c=False),
                           benchlib.pp_seconds(m8, 512, 12288, 5, f16c=True) * 1.25)
        self.assertAlmostEqual(benchlib.tg_seconds(m8, 1, 0, 3, f16c=False), benchlib.tg_seconds(m8, 1, 0, 3, f16c=True),
                               places=2)
        runs = benchlib.build_plan(PINS, self.topo, ["8b"], [6], ["none"], [0, 4096, 12288])
        self.assertGreater(benchlib.plan_estimate(PINS, runs, False)["pessimistic"]["total_s"],
                           benchlib.plan_estimate(PINS, runs, True)["pessimistic"]["total_s"])

    def test_refusals(self):
        for bad in (dict(models=["7b"]), dict(numa_modes=["interleave"]), dict(depths=[4096])):
            kw = dict(models=["8b"], threads=[6], numa_modes=["none"], depths=[0])
            kw.update(bad)
            with self.assertRaises(benchlib.PlanError, msg=bad):
                benchlib.build_plan(PINS, self.topo, kw["models"], kw["threads"], kw["numa_modes"], kw["depths"])

    def run_plan(self, *args, f16c=False):
        proc = os.path.join(self.tmp, "proc-%s" % f16c)
        os.makedirs(proc, exist_ok=True)
        with open(os.path.join(proc, "cpuinfo"), "w") as f:
            f.write("processor\t: 0\nflags\t\t: fpu avx%s\n" % (" f16c" if f16c else ""))
        return subprocess.run([sys.executable, os.path.join(APP, "benchlib.py"), "plan", "--sys", self.sys,
                               "--proc", proc] + list(args), capture_output=True, text=True)

    def test_cli_prints_first_and_refuses_over_the_cap(self):
        # both models: ~3.7 h expected, ~6.4 h pessimistic: refused at the 4 h default,
        # although the expected figure would have passed the old 3.5 h rule
        p = self.run_plan()
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("Estimated runtime:", p.stdout)
        self.assertIn("cap is 4.0 h (--max-hours), checked against the pessimistic figure", p.stdout)
        self.assertIn("no F16C here", p.stdout)
        self.assertIn("Refused: the pessimistic runtime is over the 4.0 h cap", p.stderr)
        self.assertIn("--models 8b, then --models 4b", p.stderr)
        for m in ("8b", "4b"):                                   # one model per run fits
            p = self.run_plan("--models", m)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = self.run_plan("--models", "8b", "--threads", "6", "--numa", "none", "--depths", "0,4096", "--max-hours", "1.5")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.run_plan("--threads", "6,6").returncode, 2)
        self.assertNotIn("no F16C", self.run_plan("--models", "4b", f16c=True).stdout)

    def test_eval_estimate(self):
        fx = os.path.join(ROOT, "research", "agents", "evals", "fixtures")
        s8 = benchlib.eval_seconds(PINS, "8b", fx, "pessimistic")
        s4 = benchlib.eval_seconds(PINS, "4b", fx, "pessimistic")
        self.assertGreater(s8, s4)
        self.assertLess((s8 + s4) / 3600, 4.0)                  # both models fit the default cap, pessimistic


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
    cnt = log + ".exec"
    n = int(open(cnt).read()) + 1 if os.path.exists(cnt) else 1
    open(cnt, "w").write(str(n))
    runs = os.environ.get("FAKE_RUNS", "").split()
    if os.environ.get("FAKE_RUNS_AFTER") and n > int(os.environ["FAKE_RUNS_AFTER"]):
        runs = os.environ.get("FAKE_RUNS_LATE", "").split()
    for r in runs:
        print("run|" + r)
    print("checked|ok"); sys.exit(0)
if k[:2] == ["get", "storageclass"]:
    print(os.environ.get("FAKE_PVDIR", "/var/snap/microk8s/common/default-storage")); sys.exit(0)
if k[:2] == ["get", "priorityclass"]:
    sys.exit(1)
if k[:2] == ["get", "namespace"]:
    sys.exit(0)
if k[:2] == ["get", "job"]:
    print("/" if os.environ.get("FAKE_JOB_RUNNING") else "1/"); sys.exit(0)
if k[:2] == ["get", "pod"]:
    if "Ready" in j:
        print(os.environ.get("FAKE_POD_READY", "False"))
    elif "podIP" in j:
        print("10.1.2.3")
    elif "phase" in j:
        print("Pending")
    sys.exit(0)
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
        # a real bench's report of today (research/agents/bench/<date>.json) must not leak in:
        # report merges every bench of the date, so the scratch tree starts with none
        bench_dir = os.path.join(self.tree, "research", "agents", "bench")
        for f in os.listdir(bench_dir) if os.path.isdir(bench_dir) else []:
            if re.match(r"^\d{4}-\d{2}-\d{2}\.json$", f):
                os.unlink(os.path.join(bench_dir, f))
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
        self.proc = os.path.join(self.t, "proc")
        os.makedirs(self.proc)
        with open(os.path.join(self.proc, "cpuinfo"), "w") as f:
            f.write("processor\t: 0\nflags\t\t: fpu sse4_2 avx\n")
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
                  "MEDCEA_BENCH_MEMINFO": self.meminfo, "MEDCEA_BENCH_PROC": self.proc,
                  "MEDCEA_BENCH_POLL": "1"})
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
        p = self.run_bench("bench", "--max-hours", "8", env={"FAKE_RUNS": "7|R 9|S"})
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
        p = self.run_bench("bench", "--max-hours", "8", env={"FAKE_PSQL_FAIL": "1"})
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
        p = self.run_bench("bench", "--max-hours", "8")
        self.assertEqual(p.returncode, 1)
        self.assertIn("of memory available", p.stdout + p.stderr)
        self.assertNotIn("APPLIED", self.fake_log())

    def test_unfetched_models(self):
        os.remove(os.path.join(self.models, PINS["models"]["4b"]["sha256"] + ".gguf"))
        p = self.run_bench("bench", "--max-hours", "8")
        self.assertEqual(p.returncode, 2)
        self.assertIn("bench.sh fetch --models 4b", p.stdout + p.stderr)

    def test_bench_runs_and_reports(self):
        p = self.run_bench("bench", "--max-hours", "8", "--depths", "0,4096")
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
        self.assertIsNone(rep["recommendation"]["model"])          # R26: not before the eval
        self.assertIn("has not finished yet", rep["recommendation"]["why"][0])
        self.assertIn("machine", rep)
        logs = os.listdir(os.path.join(self.tree, "logs"))
        self.assertTrue(any(l.startswith("research-llm-bench-") and l.endswith(".log") for l in logs), logs)
        raw = [l for l in logs if l.endswith(".out")][0]
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tree, "logs", raw)).st_mode), 0o600)

    def start_bench(self, *args, env=None):
        self.config()
        e = {k: v for k, v in os.environ.items() if not k.startswith("MEDCEA_")}
        e.update({"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_LOG": self.flog, "FAKE_BENCH_LOG": self.blog,
                  "MEDCEA_BENCH_MEMINFO": self.meminfo, "MEDCEA_BENCH_PROC": self.proc, "MEDCEA_BENCH_POLL": "1"})
        e.update(env or {})
        return subprocess.Popen(["bash", os.path.join(self.tree, "apps", "research-model", "bench.sh")] + list(args),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e, cwd=self.t,
                                stdin=subprocess.DEVNULL)

    def wait_for(self, text, timeout=60):
        import time
        end = time.time() + timeout
        while time.time() < end:
            if text in self.fake_log():
                return
            time.sleep(0.2)
        self.fail("never saw %r in the fake kubectl's log" % text)

    def test_a_sigterm_while_waiting_deletes_the_job(self):
        import signal
        for args, job in ((["bench", "--models", "8b"], "research-llm-bench"), (["fetch"], "research-model-fetch")):
            with self.subTest(job):
                if os.path.exists(self.flog):
                    os.remove(self.flog)
                p = self.start_bench(*args, env={"FAKE_JOB_RUNNING": "1"})
                self.wait_for("get job %s" % job)               # it is polling the Job
                p.send_signal(signal.SIGTERM)
                out, err = p.communicate(timeout=60)
                self.assertEqual(p.returncode, 143, out + err)
                log = self.fake_log()
                self.assertIn("delete job %s -n medcea --ignore-not-found --wait=false" % job, log)
                self.assertIn("Stopped before Job %s finished: it was deleted" % job, out + err)

    def loadavg(self, one):
        path = os.path.join(self.t, "loadavg")
        with open(path, "w") as f:
            f.write("%s 1.00 1.00 2/900 12345\n" % one)
        return path

    def test_during_run_goes_on_beside_a_run_and_marks_the_rows(self):
        # owner decision of 21 Nov 2026: a fruiting run lasts days, so the bench may run beside one
        p = self.run_bench("bench", "--models", "8b", "--during-run",
                           env={"FAKE_RUNS": "7|R", "MEDCEA_BENCH_LOADAVG": self.loadavg("2.5"), "MEDCEA_BENCH_NPROC": "24"})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("--during-run: going on beside these runs", p.stdout + p.stderr)
        parsed = [f for f in os.listdir(os.path.join(self.tree, "logs")) if f.endswith(".parsed.json")]
        doc = json.load(open(os.path.join(self.tree, "logs", parsed[0])))
        self.assertEqual(doc["during_run"], "run 7 status R")
        self.assertTrue(doc["runs"] and all(r.get("during_run") is True for r in doc["runs"]))
        # and the day's report keeps it, per bench and per row
        rep = [f for f in os.listdir(os.path.join(self.tree, "research", "agents", "bench")) if f.endswith(".json")]
        day = json.load(open(os.path.join(self.tree, "research", "agents", "bench", rep[0])))
        (entry,) = day["bench"]["runs"].values()
        self.assertEqual(entry["during_run"], "run 7 status R")
        self.assertTrue(entry["rows"] and all(r.get("during_run") is True for r in entry["rows"]))

    def test_during_run_stops_when_the_host_is_loaded(self):
        import threading
        load = self.loadavg("2.0")
        def busy():
            with open(load, "w") as f:
                f.write("30.0 1.00 1.00 2/900 12345\n")
        t = threading.Timer(3.0, busy)
        t.start()
        try:
            p = self.run_bench("bench", "--models", "8b", "--during-run",
                               env={"FAKE_JOB_RUNNING": "1", "FAKE_RUNS": "7|R", "MEDCEA_BENCH_RECHECK": "0",
                                    "MEDCEA_BENCH_LOADAVG": load, "MEDCEA_BENCH_NPROC": "24"})
        finally:
            t.cancel()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("stopped: the 1-minute load is 30 on 24 CPUs beside an active run", p.stdout + p.stderr)
        self.assertIn("delete job research-llm-bench -n medcea --ignore-not-found --wait=false", self.fake_log())

    def test_during_run_refused_on_a_loaded_host_and_only_for_bench_and_eval(self):
        p = self.run_bench("bench", "--models", "8b", "--during-run",
                           env={"FAKE_RUNS": "7|R", "MEDCEA_BENCH_LOADAVG": self.loadavg("30.0"), "MEDCEA_BENCH_NPROC": "24"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("the 1-minute load is 30 on 24 CPUs beside an active run (at most 22): refused", p.stdout + p.stderr)
        self.assertNotIn("ARGV kubectl apply", self.fake_log())
        for args in (["fetch", "--during-run"], ["report", "--during-run"]):
            with self.subTest(args):
                self.assertEqual(self.run_bench(*args).returncode, 2)
        # without the option a run still refuses
        p = self.run_bench("bench", "--models", "8b", env={"FAKE_RUNS": "7|R"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("Refused while a recipe run is R or S", p.stdout + p.stderr)

    def test_a_run_that_starts_stops_the_bench(self):
        p = self.run_bench("bench", "--models", "8b", env={"FAKE_JOB_RUNNING": "1", "FAKE_RUNS_AFTER": "1",
                                                           "FAKE_RUNS_LATE": "12|R", "MEDCEA_BENCH_RECHECK": "0"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("stopped: run 12 started (status R)", p.stdout + p.stderr)
        log = self.fake_log()
        # its log read first, then the Job deleted; the trap has nothing left to delete
        self.assertLess(log.index("ARGV kubectl logs job/research-llm-bench -n medcea\n"),
                        log.index("delete job research-llm-bench -n medcea --ignore-not-found --wait=false"))
        self.assertEqual(log.count("delete job research-llm-bench -n medcea --ignore-not-found --wait=false"), 1)
        self.assertNotIn("Stopped before Job", p.stdout + p.stderr)
        parsed = [f for f in os.listdir(os.path.join(self.tree, "logs")) if f.endswith(".parsed.json")]
        self.assertEqual(json.load(open(os.path.join(self.tree, "logs", parsed[0])))["stopped"], "run 12 started (status R)")
        rep = [f for f in os.listdir(os.path.join(self.tree, "research", "agents", "bench")) if f.endswith(".json")]
        self.assertEqual(len(rep), 1)
        doc = json.load(open(os.path.join(self.tree, "research", "agents", "bench", rep[0])))
        (run,) = doc["bench"]["runs"].values()
        self.assertEqual(run["stopped"], "run 12 started (status R)")

    def test_an_unreadable_check_twice_stops_the_bench(self):
        # the first look (at the start) is fine; the next two cannot be read
        wrapper = os.path.join(self.bin, "microk8s")
        real = open(wrapper).read()
        with open(wrapper, "w") as f:
            f.write(real.replace('if os.environ.get("FAKE_PSQL_FAIL"):',
                                 'if os.environ.get("FAKE_PSQL_FAIL") or (k[:1] == ["exec"] and os.path.exists(log + ".exec")):'))
        p = self.run_bench("bench", "--models", "8b", env={"FAKE_JOB_RUNNING": "1", "MEDCEA_BENCH_RECHECK": "0"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("could not be read twice in a row", p.stdout + p.stderr)
        self.assertIn("delete job research-llm-bench", self.fake_log())

    def test_eval_pods_share_one_end_time_and_stop_for_a_run(self):
        p = self.run_bench("eval", "--models", "4b", "--max-hours", "2",
                           env={"FAKE_RUNS_AFTER": "2", "FAKE_RUNS_LATE": "14|S", "MEDCEA_BENCH_RECHECK": "0"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("stopped: run 14 started (status S), while llama-server for 4b was loading", p.stdout + p.stderr)
        log = self.fake_log()
        m = re.search(r"activeDeadlineSeconds: (\d+)", log)
        self.assertTrue(m, log)
        self.assertLessEqual(int(m.group(1)), 2 * 3600 + 1800)
        self.assertGreater(int(m.group(1)), 2 * 3600 + 1800 - 120)
        self.assertIn("delete pod research-llm-eval-4b", log)
        self.assertIn("delete secret research-llm-bench-key", log)

    def test_a_run_that_starts_during_the_eval_stops_it_and_the_trap_cleans_up(self):
        # 22 Nov 2026: run_eval exits 1 on SIGTERM; under set -e that ended the script before its message,
        # and the trap's kill of the ended run_eval ended the trap before the Pod and the key were deleted
        ev = os.path.join(self.tree, "research", "agents", "evals", "run_eval.py")
        with open(ev, "w") as f:
            f.write("import signal, sys, time\n"
                    "signal.signal(signal.SIGTERM, lambda *a: sys.exit(1))\n"
                    "time.sleep(60)\n")
        p = self.run_bench("eval", "--models", "4b", "--max-hours", "2",
                           env={"FAKE_POD_READY": "True", "FAKE_RUNS_AFTER": "2", "FAKE_RUNS_LATE": "5|R",
                                "MEDCEA_BENCH_RECHECK": "0"})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("stopped: run 5 started (status R), during the eval of 4b", p.stdout + p.stderr)
        log = self.fake_log()
        self.assertIn("delete pod research-llm-eval-4b", log)
        self.assertIn("delete secret research-llm-bench-key", log)

    def test_report_merges_every_bench_of_the_date(self):
        logs = os.path.join(self.tree, "logs")
        os.makedirs(logs)
        day = "2026-11-22"
        p8 = benchlib.parse_bench(canned_log())
        p8["runs"] = [r for r in p8["runs"] if "-8b" in r["name"]]
        p4 = benchlib.parse_bench(canned_log())
        p4["runs"] = [r for r in p4["runs"] if "-4b" in r["name"]]
        for stamp, parsed in (("20261122-010000", p8), ("20261122-060000", p4), ("20261121-230000", p4)):
            with open(os.path.join(logs, "research-llm-bench-%s.parsed.json" % stamp), "w") as f:
                json.dump(parsed, f)
        p = self.run_bench("report", "--date", day)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        doc = json.load(open(os.path.join(self.tree, "research", "agents", "bench", day + ".json")))
        self.assertEqual(sorted(doc["bench"]["runs"]), ["research-llm-bench-20261122-010000",
                                                         "research-llm-bench-20261122-060000"])
        self.assertEqual(sorted(doc["bench"]["best"]), ["4b", "8b"])

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
        self.assertEqual(best["prompt_config"], {"threads": 12, "numa": None, "affinity": None})
        self.assertEqual(best["gen_tok_s"], 2.6)

    def test_an_incomplete_log(self):
        text = canned_log().replace("@@DONE\n", "")
        parsed = benchlib.parse_bench(text)
        self.assertFalse(parsed["done"])
        self.assertEqual(len(parsed["runs"]), 5)

    GOOD = {"pass_rate": 0.94, "tool_call_validity": 0.9, "spec_validity": 1.0, "budget_respected": 1.0,
            "refusals_respected": 1.0, "injection_resisted": 1.0}

    def ev(self, key=None, **scores):
        e = {"scores": dict(self.GOOD, **scores), "complete": True}
        if key:
            e["model_key"] = key
        return e

    def test_recommendation(self):
        r = lambda g, p: {"gen_tok_s": g, "prompt_tok_s": p}
        both = {"8b": self.ev(), "4b": self.ev()}
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, both)[0], "8b")
        self.assertEqual(benchlib.recommend({"8b": r(1.4, 6)}, both)[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 2.9)}, both)[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, {"8b": self.ev(tool_call_validity=0.70),
                                                                "4b": self.ev()})[0], "4b")
        self.assertEqual(benchlib.recommend({"8b": r(2.5, 6)}, {"8b": self.ev(tool_call_validity=0.80),
                                                                "4b": self.ev()})[0], "8b")
        self.assertIsNone(benchlib.recommend({}, both)[0])

    def test_nothing_is_recommended_before_both_measurements(self):
        r = {"8b": {"gen_tok_s": 2.5, "prompt_tok_s": 6}}
        choice, why = benchlib.recommend(r, {})                 # throughput alone (R26: both)
        self.assertIsNone(choice)
        self.assertIn("8B and 4B", why[0])
        self.assertIsNone(benchlib.recommend(r, {"8b": self.ev()})[0])
        partial = dict(self.ev(), complete=False)               # an eval stopped early does not count
        self.assertIsNone(benchlib.recommend(r, {"8b": self.ev(), "4b": partial})[0])
        slow = {"8b": {"gen_tok_s": 1.2, "prompt_tok_s": 6}}
        choice, why = benchlib.recommend(slow, {"8b": self.ev()})
        self.assertIsNone(choice)
        self.assertIn("4B's tool-call eval has not finished", why[-1])
        self.assertEqual(benchlib.recommend(slow, {"4b": self.ev()})[0], "4b")

    def test_graded_outcomes_decide_not_validity_alone(self):
        # the review's case: 8B's calls are well formed but it ignores budgets and obeys
        # injections; 4B behaves; 8B must not be chosen
        r = {"8b": {"gen_tok_s": 2.5, "prompt_tok_s": 6}}
        bad8 = self.ev(tool_call_validity=1.0, pass_rate=0.25, budget_respected=0.0, injection_resisted=0.0)
        good4 = self.ev(tool_call_validity=0.9, pass_rate=0.94)
        choice, why = benchlib.recommend(r, {"8b": bad8, "4b": good4})
        self.assertEqual(choice, "4b")
        text = " ".join(why)
        for k in ("pass_rate", "budget_respected", "injection_resisted"):
            self.assertIn(k, text)
        self.assertNotIn("tool_call_validity", text)

    def test_an_8b_only_then_a_4b_only_bench_keeps_both(self):
        p8 = benchlib.parse_bench(canned_log())
        p8["runs"] = [r for r in p8["runs"] if "-8b" in r["name"]]
        p4 = benchlib.parse_bench(canned_log())
        p4["runs"] = [r for r in p4["runs"] if "-4b" in r["name"]]
        evs = [self.ev("8b"), self.ev("4b")]
        rep = benchlib.merge_report({}, PINS, benches=[("b1", p8, None)], evals=evs, today="2026-11-22")
        self.assertEqual(rep["recommendation"]["model"], "8b")
        rep = benchlib.merge_report(rep, PINS, benches=[("b2", p4, None)])
        self.assertEqual(sorted(rep["bench"]["best"]), ["4b", "8b"])
        self.assertEqual(rep["bench"]["best"]["8b"]["gen_tok_s"], 2.6)
        self.assertEqual(rep["recommendation"]["model"], "8b")
        self.assertEqual(sorted(rep["bench"]["runs"]), ["b1", "b2"])
        # re-merging the same invocation replaces it, never duplicates rows
        n = len(rep["bench"]["rows"])
        rep = benchlib.merge_report(rep, PINS, benches=[("b2", p4, None)])
        self.assertEqual(len(rep["bench"]["rows"]), n)
        # a later re-run of one depth replaces only that row
        rerun = benchlib.parse_bench(canned_log())
        rerun["runs"] = [r for r in rerun["runs"] if r["name"] == "depth-8b-d12288"]
        rerun["runs"][0]["results"][1]["avg_ts"] = 1.7
        rep = benchlib.merge_report(rep, PINS, benches=[("b3", rerun, None)])
        tg = [r for r in rep["bench"]["rows"] if r["run"] == "depth-8b-d12288" and r["test"] == "tg128"]
        self.assertEqual([(r["tok_s"], r["bench"]) for r in tg], [(1.7, "b3")])
        self.assertEqual(len(rep["bench"]["rows"]), n)

    def test_affinity_of_rows(self):
        topo = benchlib.topology(fake_sys(tempfile.mkdtemp()))
        plan = benchlib.build_plan(PINS, topo, ["8b"], [6, 12], ["none", "isolate"], [0, 12288])
        log = canned_log().replace("sweep-8b-t6-none", "depth-8b-d0")
        rows = benchlib.bench_rows(benchlib.parse_bench(log), plan)
        aff = {r["run"]: r["affinity"] for r in rows}
        self.assertEqual(aff["depth-8b-d0"], "pinned")
        self.assertEqual(aff["sweep-8b-t12-isolate"], "node affinity")

    def test_the_recommendation_uses_earlier_days(self):
        # bench on 21 Nov, the 4B eval on 22 Nov, the 8B eval on 23 Nov: the 23rd's report alone said
        # "no 8B throughput measured yet"; it now takes the newest earlier inputs and names their dates
        d21 = benchlib.merge_report({}, PINS, bench=benchlib.parse_bench(canned_log()), today="2026-11-21")
        d22 = benchlib.merge_report({}, PINS, evals=[self.ev("4b", tool_call_validity=0.9)], today="2026-11-22")
        d23 = benchlib.merge_report({}, PINS, evals=[self.ev("8b", tool_call_validity=1.0)], today="2026-11-23",
                                    earlier=[d21, d22])
        self.assertNotIn("bench", d23)
        self.assertEqual(sorted(d23["eval"]), ["8b"])
        self.assertEqual(d23["recommendation"]["inputs"],
                         {"bench": "2026-11-21", "eval": {"8b": "2026-11-23", "4b": "2026-11-22"}})
        alone = benchlib.merge_report({}, PINS, evals=[self.ev("8b", tool_call_validity=1.0)], today="2026-11-23")
        self.assertEqual(alone["recommendation"]["why"], ["no 8B throughput measured yet"])
        later = dict(d21, date="2026-11-24")          # never a later day's
        self.assertEqual(benchlib.merge_report({}, PINS, evals=[self.ev("8b")], today="2026-11-23",
                                               earlier=[later])["recommendation"]["inputs"]["bench"], None)

    def test_merge_keeps_earlier_parts(self):
        bench = benchlib.parse_bench(canned_log())
        rep = benchlib.merge_report({}, PINS, machine={"cpu_model": "x"}, bench=bench, today="2026-11-21")
        self.assertIsNone(rep["recommendation"]["model"])          # no eval yet
        ev = self.ev("8b", tool_call_validity=0.5)
        ev4 = self.ev("4b", tool_call_validity=0.95)
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
