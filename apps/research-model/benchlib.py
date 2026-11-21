#!/usr/bin/env python3
"""apps/research-model/benchlib.py — the host side of research Phase 4b step 0 (the bench
and the offline tool-call eval; codeplan/rs4-design.md §5.1, R24-R28). Stdlib only; run by
apps/research-model/bench.sh, tested offline by tests/test_research_bench.py.

    benchlib.py topology [--sys DIR]
    benchlib.py plan --models 8b,4b --threads 6,12 --numa none,isolate --depths 0,4096,12288
                     [--depth-threads 6] [--depth-numa isolate] [--socket 0] [--sys DIR]
                     [--max-hours 3] [--tsv FILE] [--json FILE]
    benchlib.py eval-estimate --models 8b,4b --fixtures DIR [--max-hours H]
    benchlib.py parse-bench RAW OUT.json
    benchlib.py machine [--proc DIR] [--sys DIR]
    benchlib.py report --out FILE [--bench F] [--eval F ...] [--machine F] [--date D]

The runtime estimate uses the design's throughput ranges (§5.1's table: they are per model
at the planned 6 threads; 12 threads on the same socket's hyper-threads are assumed no
faster, a conservative choice), slowed with context as the attention work (prompt) and the
KV reads (generation) grow; "expected" is each range's midpoint, "pessimistic" its low end.
A plan whose expected runtime is over --max-hours is refused (exit 2). llama-bench fills
the context to the depth again for every test (-r 1), so a test at depth 12288 costs the
fill too; the plan therefore measures pp4096 only at depth 0 and pp512/tg128 at the depths.
"""
import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "pins.json")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_./,=:-]+$")
LOAD_OVERHEAD_S = 20           # one llama-bench process: start, mmap of a warm page cache
PAGE_IN_BYTES_S = 150e6        # the first read of a model from disk (bytes/s)
SYSINFO_S = 60                 # the llama-server start that prints system_info
EVAL_GEN_AVG = 200             # tokens a fixture answer takes on average (max_tokens 400)
SERVER_START_S = 90            # llama-server: load and warm the model
DEFAULT_MAX_HOURS = 3.5        # "about three hours": the full plan is ~3.0 h expected


class PlanError(Exception):
    pass


def load_pins(path=PINS):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ── topology (R24: one hardware thread per physical core of one socket) ──────────
def _read(path):
    with open(path, encoding="ascii") as f:
        return f.read().strip()


def topology(sysroot="/sys"):
    """{"sockets": {pkg: {"physical": [cpu...], "all": [cpu...]}}, "nodes": {n: [cpu...]}}
    from /sys/devices/system/{cpu,node}: physical = the lowest-numbered thread of each core."""
    base = os.path.join(sysroot, "devices", "system", "cpu")
    cores, allc = {}, {}
    for name in os.listdir(base):
        m = re.match(r"^cpu(\d+)$", name)
        if not m or not os.path.isdir(os.path.join(base, name, "topology")):
            continue
        cpu = int(m.group(1))
        pkg = int(_read(os.path.join(base, name, "topology", "physical_package_id")))
        core = int(_read(os.path.join(base, name, "topology", "core_id")))
        allc.setdefault(pkg, []).append(cpu)
        key = (pkg, core)
        cores[key] = min(cpu, cores.get(key, cpu))
    if not allc:
        raise PlanError("no CPU topology under %s" % base)
    sockets = {}
    for pkg in sorted(allc):
        sockets[pkg] = {"physical": sorted(c for (p, _), c in cores.items() if p == pkg),
                        "all": sorted(allc[pkg])}
    nodes = {}
    nbase = os.path.join(sysroot, "devices", "system", "node")
    if os.path.isdir(nbase):
        for name in sorted(os.listdir(nbase)):
            m = re.match(r"^node(\d+)$", name)
            if m and os.path.exists(os.path.join(nbase, name, "cpulist")):
                nodes[int(m.group(1))] = parse_cpulist(_read(os.path.join(nbase, name, "cpulist")))
    return {"sockets": sockets, "nodes": nodes}


def parse_cpulist(s):
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(out)


def cpu_mask(cpus):
    """llama.cpp's -C form: a hex mask, bit n = CPU n."""
    v = 0
    for c in cpus:
        v |= 1 << c
    return "0x%x" % v


def cpus_for(topo, socket, threads):
    """The CPU set a run with THREADS threads is pinned to: the socket's physical cores
    (one thread each) when they suffice, else all its hardware threads (R25: at most 12)."""
    s = topo["sockets"].get(socket)
    if s is None:
        raise PlanError("no socket %d (sockets: %s)" % (socket, ", ".join(map(str, sorted(topo["sockets"])))))
    if threads <= len(s["physical"]):
        return s["physical"][:threads] if threads < len(s["physical"]) else list(s["physical"])
    if threads <= len(s["all"]):
        return list(s["all"])
    raise PlanError("-t %d is more than socket %d's %d hardware threads (R25: the bench stays on one socket)"
                    % (threads, socket, len(s["all"])))


# ── the plan and its runtime ─────────────────────────────────────────────────────
def _ints(text, what, lo, hi):
    try:
        vals = [int(x) for x in text.split(",") if x.strip() != ""]
    except ValueError:
        raise PlanError("%s: a comma list of whole numbers" % what) from None
    if not vals or any(v < lo or v > hi for v in vals) or len(set(vals)) != len(vals):
        raise PlanError("%s: distinct whole numbers in %d..%d" % (what, lo, hi))
    return vals


def model_path(pins, key):
    return "/models/%s.gguf" % pins["models"][key]["sha256"]


def build_plan(pins, topo, models, threads, numa_modes, depths, depth_threads=6, depth_numa="isolate", socket=0):
    """The ordered runs, cheapest and most useful first, so a bench stopped by its deadline
    keeps what it measured: per model a warm-up (discarded), the sweep (pp512 + tg128 at
    depth 0 per thread count and NUMA mode) and pp4096 at depth 0; then, per depth in
    ascending order and per model, pp512 + tg128 at that depth (DEPTH_THREADS/DEPTH_NUMA).
    pp512/tg128 at depth 0 under the depth configuration come from the sweep, or from a
    run of their own when the sweep does not hold that configuration."""
    for m in models:
        if m not in pins["models"]:
            raise PlanError("unknown model %r (known: %s)" % (m, ", ".join(sorted(pins["models"]))))
    for n in list(numa_modes) + [depth_numa]:
        if n not in ("none", "isolate", "distribute"):
            raise PlanError("NUMA mode %r: none, isolate or distribute" % n)
    if 0 not in depths:
        raise PlanError("--depths must include 0")
    runs = []
    sweep = {(t, n) for t in threads for n in numa_modes}
    dcpus = cpus_for(topo, socket, depth_threads)
    for m in models:
        mp = model_path(pins, m)
        runs.append(_run("warmup-%s" % m, m, depth_threads, dcpus, "none", False,
                         ["-m", mp, "-p", "64", "-n", "8", "-t", str(depth_threads), "-r", "1"],
                         [("pp", 64, 0), ("tg", 8, 0)], discard=True))
        for t in threads:
            for n in numa_modes:
                c = cpus_for(topo, socket, t)
                runs.append(_run("sweep-%s-t%d-%s" % (m, t, n), m, t, c, n, True,
                                 ["-m", mp, "-p", "512", "-n", "128", "-t", str(t), "-r", "1"],
                                 [("pp", 512, 0), ("tg", 128, 0)]))
        tests = [("pp", 4096, 0)]
        args = ["-m", mp, "-p", "4096", "-n", "0", "-t", str(depth_threads), "-r", "1"]
        if (depth_threads, depth_numa) not in sweep:
            tests = [("pp", 512, 0), ("pp", 4096, 0), ("tg", 128, 0)]
            args = ["-m", mp, "-p", "512,4096", "-n", "128", "-t", str(depth_threads), "-r", "1"]
        runs.append(_run("depth-%s-d0" % m, m, depth_threads, dcpus, depth_numa, False, args, tests))
    for d in sorted(x for x in depths if x > 0):
        for m in models:
            runs.append(_run("depth-%s-d%d" % (m, d), m, depth_threads, dcpus, depth_numa, False,
                             ["-m", model_path(pins, m), "-p", "512", "-n", "128", "-d", str(d),
                              "-t", str(depth_threads), "-r", "1"],
                             [("pp", 512, d), ("tg", 128, d)]))
    for r in runs:
        for a in r["args"]:
            if not TOKEN_RE.match(a):
                raise PlanError("unsafe argument %r" % a)
    return runs


def _run(name, model, threads, cpus, numa, numa_required, args, tests, discard=False):
    return {"name": name, "model": model, "threads": threads, "cpus": cpus, "mask": cpu_mask(cpus),
            "numa": numa, "numa_required": numa_required, "args": args, "tests": tests, "discard": discard}


def _rates(model, which):
    lo, hi = model["estimate_tok_s"][which]
    return {"expected": (lo + hi) / 2.0, "pessimistic": float(lo)}


def _attn_ratio(model):
    a = model["arch"]
    return (4.0 * a["layers"] * a["hidden"]) / (2.0 * a["params_b"] * 1e9)


def _kv_ratio(model):
    a = model["arch"]
    return (a["layers"] * a["kv_heads"] * a["head_dim"] * 2 * 2) / float(model["size_bytes"])


def pp_seconds(model, n, depth, rate):
    """Seconds to process N prompt tokens starting at DEPTH, at RATE tok/s on an empty context."""
    if n <= 0:
        return 0.0
    ctx = depth + n / 2.0
    return n / (rate / (1.0 + ctx * _attn_ratio(model)))


def tg_seconds(model, n, depth, rate):
    if n <= 0:
        return 0.0
    ctx = depth + n / 2.0
    return n / (rate / (1.0 + ctx * _kv_ratio(model)))


def run_seconds(pins, run, which, paged=None):
    """Estimated seconds of one llama-bench invocation (WHICH: expected | pessimistic)."""
    model = pins["models"][run["model"]]
    pr, gr = _rates(model, "prompt")[which], _rates(model, "gen")[which]
    s = LOAD_OVERHEAD_S
    if paged is not None and run["model"] not in paged:
        s += model["size_bytes"] / PAGE_IN_BYTES_S
        paged.add(run["model"])
    for kind, n, d in run["tests"]:
        if d > 0:
            s += pp_seconds(model, d, 0, pr)          # the fill, again for each test
        s += pp_seconds(model, n, d, pr) if kind == "pp" else tg_seconds(model, n, d, gr)
    return s


def plan_estimate(pins, runs):
    out = {}
    for which in ("expected", "pessimistic"):
        paged = set()
        per = [run_seconds(pins, r, which, paged) for r in runs]
        out[which] = {"total_s": SYSINFO_S + sum(per), "runs_s": per}
    return out


def plan_tsv(runs):
    """One line per run: name, cpu list, hex mask, NUMA mode, 1 when the run needs --numa,
    then the llama-bench arguments (tab-separated fields, space-separated arguments)."""
    lines = []
    for r in runs:
        lines.append("\t".join([r["name"], ",".join(map(str, r["cpus"])), r["mask"], r["numa"],
                                "1" if r["numa_required"] else "0", " ".join(r["args"])]))
    return "\n".join(lines) + "\n"


def hours(s):
    return s / 3600.0


def describe_plan(pins, runs, est, max_hours):
    out = []
    out.append("The bench measures (llama-bench, -r 1, one hardware thread per physical core of the socket, nice 19):")
    for r, e, p in zip(runs, est["expected"]["runs_s"], est["pessimistic"]["runs_s"]):
        tests = ", ".join("%s%d@d%d" % t for t in r["tests"])
        what = "warm-up, discarded" if r["discard"] else tests
        out.append("  %-34s %-3s -t %-2d cpus %-24s numa %-8s %s  ~%.0f min (pessimistic %.0f)"
                   % (r["name"], r["model"], r["threads"], ",".join(map(str, r["cpus"])), r["numa"], what,
                      e / 60, p / 60))
    out.append("Plus one llama-server start that prints system_info (the AVX = 1 | AVX2 = 0 check).")
    out.append("Estimated runtime: %.1f h expected, %.1f h pessimistic (the design's throughput ranges, §5.1);"
               " the cap is %.1f h (--max-hours)."
               % (hours(est["expected"]["total_s"]), hours(est["pessimistic"]["total_s"]), max_hours))
    return "\n".join(out)


# ── eval estimate ────────────────────────────────────────────────────────────────
def fixture_sizes(fixtures):
    """(standing prefix characters, [conversation characters], transcript characters)."""
    with open(os.path.join(fixtures, "standing.md"), encoding="utf-8") as f:
        standing = f.read()
    with open(os.path.join(fixtures, "tools.json"), encoding="utf-8") as f:
        tools = f.read()
    convs = []
    cdir = os.path.join(fixtures, "conversations")
    for n in sorted(os.listdir(cdir)):
        if n.endswith(".json"):
            with open(os.path.join(cdir, n), encoding="utf-8") as f:
                convs.append(len(json.dumps(json.load(f)["messages"])))
    with open(os.path.join(fixtures, "transcript.json"), encoding="utf-8") as f:
        tr = len(json.dumps(json.load(f)))
    return len(standing) + len(tools), convs, tr


def eval_seconds(pins, key, fixtures, which="expected"):
    model = pins["models"][key]
    pr, gr = _rates(model, "prompt")[which], _rates(model, "gen")[which]
    prefix, convs, tr = fixture_sizes(fixtures)
    s = SERVER_START_S + model["size_bytes"] / PAGE_IN_BYTES_S
    s += pp_seconds(model, prefix / 4.0, 0, pr)                       # the standing prefix, once
    for c in convs:
        s += pp_seconds(model, c / 4.0, prefix / 4.0, pr) + tg_seconds(model, EVAL_GEN_AVG, prefix / 4.0, gr)
    s += pp_seconds(model, prefix / 4.0 + tr / 4.0, 0, pr) + 5 * tg_seconds(model, EVAL_GEN_AVG, prefix / 4.0, gr)
    return s


# ── parsing the bench Job's log ──────────────────────────────────────────────────
def parse_bench(text):
    """The bench container's log (bench-run.sh's @@ markers) as
    {"help": {...}, "taskset": bool, "sysinfo": {...}, "runs": [...], "done": bool, "fatal": str|None}."""
    out = {"help": {}, "taskset": False, "sysinfo": {"lines": [], "rc": None}, "runs": [], "skipped": [],
           "done": False, "fatal": None}
    cur, mode, buf = None, None, []
    lines = text.splitlines()
    for line in lines:
        if line.startswith("@@"):
            if cur is not None and mode == "json":
                cur["json_text"] = "\n".join(buf)
            if cur is not None and mode == "stderr":
                cur["stderr"] = buf
            if mode == "sysinfo":
                out["sysinfo"]["lines"] = buf
            word, _, rest = line[2:].partition(" ")
            mode, buf = None, []
            if word == "HELP":
                out["help"] = {k: v == "1" for k, v in (kv.split("=", 1) for kv in rest.split() if "=" in kv)}
            elif word == "TASKSET":
                out["taskset"] = rest.strip() == "1"
            elif word == "SYSINFO":
                mode = "sysinfo"
            elif word == "SYSINFO_RC":
                out["sysinfo"]["rc"] = int(rest.strip() or "0")
            elif word == "BEGIN":
                cur = {"name": rest.strip(), "json_text": "", "stderr": [], "rc": None, "seconds": None}
                out["runs"].append(cur)
            elif word == "JSON":
                mode = "json"
            elif word == "STDERR":
                mode = "stderr"
            elif word == "END" and cur is not None:
                m = re.search(r"rc=(\d+)", rest)
                cur["rc"] = int(m.group(1)) if m else None
                m = re.search(r"seconds=(\d+)", rest)
                cur["seconds"] = int(m.group(1)) if m else None
                cur = None
            elif word == "SKIP":
                name, _, why = rest.partition(" ")
                out["skipped"].append({"name": name, "why": why.strip()})
            elif word == "DONE":
                out["done"] = True
            elif word == "FATAL":
                out["fatal"] = rest.strip()
            continue
        if mode is not None:
            buf.append(line)
    if cur is not None and mode == "json":
        cur["json_text"] = "\n".join(buf)
    for r in out["runs"]:
        try:
            r["results"] = json.loads(r.pop("json_text") or "[]")
        except json.JSONDecodeError:
            r["results"] = []
            r["parse_error"] = True
    out["avx_check"] = avx_check(out["sysinfo"]["lines"] + [l for r in out["runs"] for l in r.get("stderr", [])])
    return out


def avx_check(lines):
    """'pass' when a system_info line shows AVX = 1 and AVX2 = 0 (or the sandybridge backend
    was loaded and nothing shows AVX2 = 1); 'fail' when AVX2 = 1 or AVX = 0; else 'unknown'."""
    text = "\n".join(lines)
    if re.search(r"\bAVX2 = 1\b", text) or re.search(r"\bAVX = 0\b", text):
        return "fail"
    if re.search(r"\bAVX = 1\b", text) and re.search(r"\bAVX2 = 0\b", text):
        return "pass"
    if "sandybridge" in text:
        return "pass"
    return "unknown"


def bench_rows(parsed, plan_runs=None):
    """One row per measured test: model, threads, numa, test, depth, tokens/s."""
    meta = {r["name"]: r for r in (plan_runs or [])}
    rows = []
    for r in parsed["runs"]:
        p = meta.get(r["name"], {})
        if p.get("discard") or r["name"].startswith("warmup-"):
            continue
        for t in r.get("results") or []:
            n_prompt, n_gen = int(t.get("n_prompt", 0)), int(t.get("n_gen", 0))
            kind = "pp" if n_prompt > 0 and n_gen == 0 else "tg" if n_gen > 0 and n_prompt == 0 else "pp+tg"
            rows.append({"run": r["name"], "model": p.get("model") or _model_of(r["name"]),
                         "threads": int(t.get("n_threads", p.get("threads", 0)) or 0),
                         "numa": p.get("numa"), "cpu_mask": t.get("cpu_mask"),
                         "test": "%s%d" % (kind, n_prompt or n_gen), "depth": int(t.get("n_depth", 0) or 0),
                         "tok_s": float(t.get("avg_ts", 0.0)), "stddev": float(t.get("stddev_ts", 0.0) or 0.0)})
    return rows


def _model_of(name):
    m = re.match(r"^(?:sweep|depth|warmup)-([a-z0-9]+)", name)
    return m.group(1) if m else None


def best_rates(rows, model):
    """The best depth-0 prompt (pp512) and generation (tg128) rates of MODEL, with their config."""
    pp = [r for r in rows if r["model"] == model and r["test"] == "pp512" and r["depth"] == 0]
    tg = [r for r in rows if r["model"] == model and r["test"] == "tg128" and r["depth"] == 0]
    bp = max(pp, key=lambda r: r["tok_s"]) if pp else None
    bg = max(tg, key=lambda r: r["tok_s"]) if tg else None
    return {"prompt_tok_s": bp["tok_s"] if bp else None, "prompt_config": _cfg(bp),
            "gen_tok_s": bg["tok_s"] if bg else None, "gen_config": _cfg(bg)}


def _cfg(r):
    return None if r is None else {"threads": r["threads"], "numa": r["numa"]}


# ── the recommendation (§5.1, R26) ───────────────────────────────────────────────
MIN_GEN = 1.5
MIN_PROMPT = 3.0
CLEARLY_WORSE = 0.15     # 8B's tool-call validity at least 15 points below 4B's


def recommend(rates, evals):
    """('8b' | '4b' | None, [reasons]). 4B when 8B generates below 1.5 tok/s, processes
    prompts below 3 tok/s, or its tool-call validity is clearly worse than 4B's."""
    why = []
    r8 = rates.get("8b") or {}
    if r8.get("gen_tok_s") is None or r8.get("prompt_tok_s") is None:
        return None, ["no 8B throughput measured yet"]
    if r8["gen_tok_s"] < MIN_GEN:
        why.append("8B generates %.2f tok/s, below %.1f" % (r8["gen_tok_s"], MIN_GEN))
    if r8["prompt_tok_s"] < MIN_PROMPT:
        why.append("8B processes prompts at %.2f tok/s, below %.1f" % (r8["prompt_tok_s"], MIN_PROMPT))
    v8 = (evals.get("8b") or {}).get("scores", {}).get("tool_call_validity")
    v4 = (evals.get("4b") or {}).get("scores", {}).get("tool_call_validity")
    if v8 is not None and v4 is not None and v8 < v4 - CLEARLY_WORSE:
        why.append("8B's tool-call validity %.2f is clearly worse than 4B's %.2f" % (v8, v4))
    if why:
        return "4b", why
    if v8 is None:
        return "8b", ["8B meets the throughput thresholds; its tool-call eval has not run yet"]
    return "8b", ["8B meets the throughput thresholds (%.2f tok/s generation, %.2f prompt) and its"
                  " tool-call validity (%.2f) is not clearly worse" % (r8["gen_tok_s"], r8["prompt_tok_s"], v8)]


# ── machine facts ────────────────────────────────────────────────────────────────
def machine_facts(proc="/proc", sysroot="/sys"):
    facts = {}
    try:
        with open(os.path.join(proc, "cpuinfo"), encoding="utf-8", errors="replace") as f:
            info = f.read()
        m = re.search(r"^model name\s*:\s*(.+)$", info, re.M)
        facts["cpu_model"] = m.group(1).strip() if m else None
        m = re.search(r"^flags\s*:\s*(.+)$", info, re.M)
        flags = set(m.group(1).split()) if m else set()
        facts["simd"] = {f: f in flags for f in ("sse4_2", "avx", "avx2", "fma", "f16c", "avx512f", "sha_ni")}
        facts["logical_cpus"] = len(re.findall(r"^processor\s*:", info, re.M))
    except OSError:
        pass
    try:
        with open(os.path.join(proc, "meminfo"), encoding="ascii") as f:
            mem = dict(re.findall(r"^(\w+):\s+(\d+) kB", f.read(), re.M))
        facts["mem_total_gib"] = round(int(mem["MemTotal"]) / 1048576, 1)
        facts["mem_available_gib"] = round(int(mem.get("MemAvailable", 0)) / 1048576, 1)
    except (OSError, KeyError):
        pass
    try:
        topo = topology(sysroot)
        facts["sockets"] = len(topo["sockets"])
        facts["physical_cores"] = sum(len(s["physical"]) for s in topo["sockets"].values())
        facts["numa_nodes"] = {str(k): v for k, v in topo["nodes"].items()}
    except (OSError, PlanError, ValueError):
        pass
    facts["kernel"] = os.uname().release
    return facts


# ── the report (research/agents/bench/<date>.json) ───────────────────────────────
def merge_report(existing, pins, machine=None, bench=None, evals=None, plan_runs=None, today=None):
    """EXISTING (a report from an earlier call the same day, or {}) with what is given
    replaced or added; the recommendation recomputed from everything now in it."""
    rep = dict(existing or {})
    rep["schema"] = 1
    rep["date"] = today or rep.get("date") or datetime.date.today().isoformat()
    rep["design"] = "codeplan/rs4-design.md §5.1, R24-R28 (research Phase 4b step 0)"
    rep["pins"] = {"llama_cpp": pins["llama_cpp"], "python_image": pins["python_image"],
                   "models": {k: {x: v[x] for x in ("name", "role", "repo", "revision", "file", "size_bytes",
                                                    "sha256", "licence")} for k, v in pins["models"].items()}}
    if machine:
        rep["machine"] = machine
    if bench is not None:
        rows = bench_rows(bench, plan_runs)
        rep["bench"] = {"avx_check": bench.get("avx_check"), "sysinfo": bench.get("sysinfo", {}).get("lines", [])[:8],
                        "llama_bench_flags": bench.get("help"), "taskset": bench.get("taskset"),
                        "complete": bool(bench.get("done")) and not bench.get("fatal"),
                        "fatal": bench.get("fatal"), "skipped": bench.get("skipped", []),
                        "seconds": {r["name"]: r.get("seconds") for r in bench.get("runs", [])},
                        "rows": rows,
                        "best": {m: best_rates(rows, m) for m in sorted({r["model"] for r in rows if r["model"]})}}
    if evals:
        ev = dict(rep.get("eval") or {})
        for e in evals:
            ev[e["model_key"]] = e
        rep["eval"] = ev
    rates = (rep.get("bench") or {}).get("best") or {}
    choice, why = recommend(rates, rep.get("eval") or {})
    rep["recommendation"] = {"model": choice, "why": why,
                             "thresholds": {"min_gen_tok_s": MIN_GEN, "min_prompt_tok_s": MIN_PROMPT,
                                            "validity_clearly_worse_by": CLEARLY_WORSE}}
    return rep


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


# ── CLI ──────────────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(prog="benchlib.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("topology")
    t.add_argument("--sys", default="/sys")
    p = sub.add_parser("plan")
    p.add_argument("--models", default="8b,4b")
    p.add_argument("--threads", default="6,12")
    p.add_argument("--numa", default="none,isolate")
    p.add_argument("--depths", default="0,4096,12288")
    p.add_argument("--depth-threads", type=int, default=6)
    p.add_argument("--depth-numa", default="isolate")
    p.add_argument("--socket", type=int, default=0)
    p.add_argument("--sys", default="/sys")
    p.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS)
    p.add_argument("--tsv")
    p.add_argument("--json")
    p.add_argument("--pins", default=PINS)
    e = sub.add_parser("eval-estimate")
    e.add_argument("--models", default="8b,4b")
    e.add_argument("--fixtures", required=True)
    e.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS)
    e.add_argument("--pins", default=PINS)
    b = sub.add_parser("parse-bench")
    b.add_argument("raw")
    b.add_argument("out")
    mc = sub.add_parser("machine")
    mc.add_argument("--proc", default="/proc")
    mc.add_argument("--sys", default="/sys")
    r = sub.add_parser("report")
    r.add_argument("--out", required=True)
    r.add_argument("--bench")
    r.add_argument("--plan")
    r.add_argument("--eval", action="append", default=[])
    r.add_argument("--machine")
    r.add_argument("--date")
    r.add_argument("--pins", default=PINS)
    a = ap.parse_args(argv)

    try:
        if a.cmd == "topology":
            print(json.dumps(topology(a.sys), sort_keys=True))
            return 0
        if a.cmd == "plan":
            pins = load_pins(a.pins)
            models = [m for m in a.models.split(",") if m]
            if not models or len(set(models)) != len(models):
                raise PlanError("--models: a comma list of distinct models (%s)" % ", ".join(sorted(pins["models"])))
            threads = _ints(a.threads, "--threads", 1, 64)
            depths = _ints(a.depths, "--depths", 0, 32768)
            numa = [n for n in a.numa.split(",") if n]
            if not numa or len(set(numa)) != len(numa):
                raise PlanError("--numa: a comma list of distinct modes (none, isolate, distribute)")
            if not 0 < a.max_hours <= 24:
                raise PlanError("--max-hours must be in (0, 24]")
            runs = build_plan(pins, topology(a.sys), models, threads, numa, depths,
                              a.depth_threads, a.depth_numa, a.socket)
            est = plan_estimate(pins, runs)
            print(describe_plan(pins, runs, est, a.max_hours))
            if a.tsv:
                with open(a.tsv, "w", encoding="utf-8") as f:
                    f.write(plan_tsv(runs))
            if a.json:
                write_json(a.json, {"runs": runs, "estimate": est, "max_hours": a.max_hours,
                                    "memory_gi": max(pins["models"][m]["bench_memory_gi"] for m in models)})
            if hours(est["expected"]["total_s"]) > a.max_hours:
                print("Refused: the expected runtime is over the %.1f h cap. Measure less (--models 8b, "
                      "--threads 6, --numa none, --depths 0,4096) or raise --max-hours." % a.max_hours,
                      file=sys.stderr)
                return 2
            return 0
        if a.cmd == "eval-estimate":
            pins = load_pins(a.pins)
            total = {"expected": 0.0, "pessimistic": 0.0}
            for m in [m for m in a.models.split(",") if m]:
                if m not in pins["models"]:
                    raise PlanError("unknown model %r" % m)
                for w in total:
                    s = eval_seconds(pins, m, a.fixtures, w)
                    total[w] += s
                print("  %-3s ~%.0f min expected (pessimistic %.0f)" % (
                    m, eval_seconds(pins, m, a.fixtures) / 60, eval_seconds(pins, m, a.fixtures, "pessimistic") / 60))
            print("Estimated runtime: %.1f h expected, %.1f h pessimistic; the cap is %.1f h (--max-hours)."
                  % (hours(total["expected"]), hours(total["pessimistic"]), a.max_hours))
            if hours(total["expected"]) > a.max_hours:
                print("Refused: over the cap. Evaluate one model (--models 8b) or raise --max-hours.", file=sys.stderr)
                return 2
            return 0
        if a.cmd == "parse-bench":
            with open(a.raw, encoding="utf-8", errors="replace") as f:
                parsed = parse_bench(f.read())
            write_json(a.out, parsed)
            print("parsed %d runs, %d skipped, avx check %s%s" % (
                len(parsed["runs"]), len(parsed["skipped"]), parsed["avx_check"],
                "" if parsed["done"] else " (incomplete)"))
            return 0 if parsed["done"] and not parsed["fatal"] else 1
        if a.cmd == "machine":
            print(json.dumps(machine_facts(a.proc, a.sys), sort_keys=True))
            return 0
        if a.cmd == "report":
            pins = load_pins(a.pins)
            existing = {}
            if os.path.exists(a.out):
                with open(a.out, encoding="utf-8") as f:
                    existing = json.load(f)
            bench = plan_runs = machine = None
            if a.bench:
                with open(a.bench, encoding="utf-8") as f:
                    bench = json.load(f)
            if a.plan:
                with open(a.plan, encoding="utf-8") as f:
                    plan_runs = json.load(f)["runs"]
            if a.machine:
                with open(a.machine, encoding="utf-8") as f:
                    machine = json.load(f)
            evals = []
            for path in a.eval:
                with open(path, encoding="utf-8") as f:
                    evals.append(json.load(f))
            rep = merge_report(existing, pins, machine, bench, evals, plan_runs, a.date)
            write_json(a.out, rep)
            rec = rep["recommendation"]
            print("report: %s; recommendation: %s (%s)" % (a.out, rec["model"] or "none yet", "; ".join(rec["why"])))
            return 0
    except (PlanError, OSError, ValueError, KeyError) as e:
        print("benchlib: %s" % e, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
