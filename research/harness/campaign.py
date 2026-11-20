"""Run a controller campaign: a grid of scenarios x controllers x parameter sets x seeds x
clock offsets, each one runner.run_scenario, written as results.jsonl and manifest.json.

    python -m research.harness.campaign SPEC.yaml [--out DIR] [--jobs N] [--allow-dirty]
                                                  [--max-cpu-hours H]

Spec (YAML):
    scenarios:        [path (relative to the spec file) | inline scenario mapping]
    controllers:      [{code, params?: {k: v}, params_grid?: {k: [v, ...]}}]
    seeds:            [int, ...]
    clock_offsets_s:  [number, ...]       (default [0.0])
    jitter_s:         number               (default 0.0)

A scenario may pin a calibration file and a recipe line of a snapshot (pins.py: keys
`calibration` and `recipe_line_from`); resolve_spec resolves both here, before any run, and
the resolved values stay in the spec next to their pins, so spec_digest covers both.

Each params_grid is expanded to its cartesian product (keys sorted), over params' fixed
values. Every run is one line of results.jsonl, canonical JSON (sorted keys, no spaces),
in the sorted order of (scenario, code, params, seed, clock offset), so the same spec,
code and seeds give a byte-identical file whatever --jobs is. manifest.json names the
code (commit, dirty files, blob SHAs of every contract file read and of the sandbox's own
code, contract.CONTRACT_VERSION), the spec's digest,
the grid, METRICS_VERSION, the library versions and the sha256 of results.jsonl, plus,
when a scenario has a pin, `provenance` (what each pin applied). spec.json beside it holds
the resolved spec: the exact bytes spec_digest hashes.

CPU budget: before anything runs, one short calibration run per (scenario, controller
code) (the scenario cut to CALIBRATION_H) measures CPU seconds (with child processes:
GEKKO's solver) per simulated hour (a scenario's sensors set its message rate, so each is
measured); the estimate is the sum over runs of its (scenario, code) rate x its duration. A campaign over
--max-cpu-hours (default 4) is refused, nothing written. Pool size: --jobs, never above
the CPU limit (the cgroup's /sys/fs/cgroup/cpu.max quota when there is one, else half of
os.cpu_count()), never above the number of runs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import math
import multiprocessing
import os
import sys

import yaml

from . import algorithms_loader, metrics, pins, runner

CALIBRATION_H = 0.05           # 3 simulated minutes per controller code
DEFAULT_MAX_CPU_HOURS = 4.0
SPEC_KEYS = {"scenarios", "controllers", "seeds", "clock_offsets_s", "jitter_s", "description"}


class CampaignError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def load_spec(path, allow_dirty=False, repo_root=None):
    with open(path, encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    return resolve_spec(spec, os.path.dirname(os.path.abspath(path)), allow_dirty=allow_dirty, repo_root=repo_root)


def resolve_spec(spec, base_dir=".", allow_dirty=False, repo_root=None):
    """The spec with scenario files inlined, pins resolved (pins.py: a pin's path is
    relative to the file holding it) and defaults filled in (what the digest covers)."""
    if not isinstance(spec, dict):
        raise CampaignError("the spec must be a mapping")
    bad = sorted(set(spec) - SPEC_KEYS)
    if bad:
        raise CampaignError("unknown spec key(s): " + ", ".join(bad))
    out = {"scenarios": [], "controllers": [], "seeds": [], "clock_offsets_s": [0.0], "jitter_s": 0.0}
    for sc in spec.get("scenarios") or []:
        sc_dir = base_dir
        if isinstance(sc, str):
            path = os.path.join(base_dir, sc)
            sc_dir = os.path.dirname(path)
            with open(path, encoding="utf-8") as f:
                sc = yaml.safe_load(f)
        if not isinstance(sc, dict) or not sc.get("name"):
            raise CampaignError("a scenario must be a mapping with a name")
        try:
            sc = pins.resolve_pins(sc, sc_dir, repo_root or runner.DEFAULT_REPO, allow_dirty=allow_dirty)
        except pins.PinError as e:
            raise CampaignError("scenario %s: %s" % (sc["name"], e)) from None
        out["scenarios"].append(sc)
    if not out["scenarios"]:
        raise CampaignError("the spec names no scenario")
    names = [sc["name"] for sc in out["scenarios"]]
    if len(set(names)) != len(names):
        raise CampaignError("scenario names must be unique")
    for c in spec.get("controllers") or []:
        if not isinstance(c, dict) or set(c) - {"code", "params", "params_grid"} or "code" not in c:
            raise CampaignError("a controller is {code, params?, params_grid?}")
        grid = c.get("params_grid") or {}
        if not isinstance(grid, dict) or any(not isinstance(v, list) or not v for v in grid.values()):
            raise CampaignError("params_grid maps a parameter to a non-empty list")
        out["controllers"].append({"code": c["code"], "params": dict(c.get("params") or {}),
                                   "params_grid": {k: list(grid[k]) for k in sorted(grid)}})
    if not out["controllers"]:
        raise CampaignError("the spec names no controller")
    seeds = spec.get("seeds")
    if not isinstance(seeds, list) or not seeds or any(not isinstance(s, int) or isinstance(s, bool) for s in seeds):
        raise CampaignError("seeds must be a non-empty list of integers")
    out["seeds"] = sorted(set(seeds))
    if "clock_offsets_s" in spec:
        offs = spec["clock_offsets_s"]
        if not isinstance(offs, list) or not offs or any(isinstance(o, bool) or not isinstance(o, (int, float)) for o in offs):
            raise CampaignError("clock_offsets_s must be a non-empty list of numbers")
        out["clock_offsets_s"] = sorted({float(o) for o in offs})
    j = spec.get("jitter_s", 0.0)
    if isinstance(j, bool) or not isinstance(j, (int, float)) or j < 0:
        raise CampaignError("jitter_s must be a number >= 0")
    out["jitter_s"] = float(j)
    if "description" in spec:
        out["description"] = spec["description"]
    return out


def expand(spec):
    """Every run as (scenario name, code, params, seed, clock offset), sorted."""
    runs = []
    for c in spec["controllers"]:
        keys = list(c["params_grid"])
        for values in itertools.product(*(c["params_grid"][k] for k in keys)) if keys else [()]:
            params = dict(c["params"])
            params.update(dict(zip(keys, values)))
            for sc in spec["scenarios"]:
                for seed in spec["seeds"]:
                    for off in spec["clock_offsets_s"]:
                        runs.append((sc["name"], c["code"], canonical(params), seed, off))
    runs = sorted(set(runs))
    return runs


def cpu_limit():
    """CPUs this process may use: the cgroup v2 quota, else half the host's CPUs (>= 1)."""
    try:
        with open("/sys/fs/cgroup/cpu.max", encoding="ascii") as f:
            quota, period = f.read().split()[:2]
        if quota != "max":
            return max(1, int(int(quota) // int(period)))
    except (OSError, ValueError):
        pass
    return max(1, (os.cpu_count() or 2) // 2)


def cpu_seconds():
    """CPU time of this process and its waited-for children (GEKKO runs its solver as a
    child process, which time.process_time() would not count)."""
    t = os.times()
    return t.user + t.system + t.children_user + t.children_system


# ── workers ──────────────────────────────────────────────────────────────────────
_W = {}


def _init(repo_root, allow_dirty, spec):
    _W["loaded"] = algorithms_loader.load(repo_root, allow_dirty=allow_dirty)
    _W["scenarios"] = {sc["name"]: sc for sc in spec["scenarios"]}
    _W["jitter"] = spec["jitter_s"]


def _run(run):
    name, code, params, seed, off = run
    r = runner.run_scenario(copy.deepcopy(_W["scenarios"][name]), {"code": code, "params": json.loads(params)},
                            seed, off, _W["jitter"], loaded=_W["loaded"])
    return canonical(r)


def calibrate(spec, loaded):
    """CPU seconds per simulated hour, per (scenario name, controller code): one short run
    each, since a scenario's sensors (a 3-s publish interval) set its message rate."""
    rates = {}
    for scenario in spec["scenarios"]:
        sc = copy.deepcopy(scenario)
        sc["duration_h"] = min(sc["duration_h"], CALIBRATION_H)
        sc["metrics_from_h"] = 0
        for c in spec["controllers"]:
            key = (scenario["name"], c["code"])
            if key in rates:
                continue
            loaded.check(c["code"], c["params"])
            t0 = cpu_seconds()
            runner.run_scenario(copy.deepcopy(sc), {"code": c["code"], "params": c["params"]},
                                spec["seeds"][0], spec["clock_offsets_s"][0], spec["jitter_s"], loaded=loaded)
            rates[key] = (cpu_seconds() - t0) / sc["duration_h"]
    return rates


def run_campaign(spec, out_dir, repo_root=None, jobs=None, allow_dirty=False,
                 max_cpu_hours=DEFAULT_MAX_CPU_HOURS):
    """Run SPEC (already resolved) into OUT_DIR; returns the manifest."""
    repo_root = repo_root or runner.DEFAULT_REPO
    loaded = algorithms_loader.load(repo_root, allow_dirty=allow_dirty)
    runs = expand(spec)
    durations = {sc["name"]: sc["duration_h"] for sc in spec["scenarios"]}
    for c in spec["controllers"]:                       # refuse before any CPU is spent
        keys = list(c["params_grid"])
        for values in itertools.product(*(c["params_grid"][k] for k in keys)) if keys else [()]:
            p = dict(c["params"])
            p.update(dict(zip(keys, values)))
            loaded.check(c["code"], p)
    for sc in spec["scenarios"]:
        runner.normalise(copy.deepcopy(sc), loaded)
    rates = calibrate(spec, loaded)
    estimate_h = sum(rates[(name, code)] * durations[name] for name, code, _, _, _ in runs) / 3600.0
    if estimate_h > max_cpu_hours:
        raise CampaignError("estimated %.3g CPU-hours for %d runs, over the cap of %.3g "
                            "(--max-cpu-hours)" % (estimate_h, len(runs), max_cpu_hours))
    limit = cpu_limit()
    pool_size = max(1, min(jobs or limit, limit, len(runs)))

    if pool_size == 1:
        _init(repo_root, allow_dirty, spec)
        lines = [_run(r) for r in runs]
    else:
        with multiprocessing.get_context("spawn").Pool(pool_size, initializer=_init,
                                                       initargs=(repo_root, allow_dirty, spec)) as pool:
            lines = pool.map(_run, runs, chunksize=1)

    body = "".join(line + "\n" for line in lines).encode("utf-8")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.jsonl"), "wb") as f:
        f.write(body)
    results = [json.loads(line) for line in lines]
    spec_bytes = canonical(spec).encode("utf-8")
    with open(os.path.join(out_dir, "spec.json"), "wb") as f:
        f.write(spec_bytes)
    manifest = {
        "metrics_version": metrics.METRICS_VERSION,
        "code": loaded.manifest(),
        "spec_digest": hashlib.sha256(spec_bytes).hexdigest(),
        "scenarios": sorted(durations),
        "controllers": spec["controllers"],
        "seeds": spec["seeds"],
        "clock_offsets_s": spec["clock_offsets_s"],
        "jitter_s": spec["jitter_s"],
        "runs": len(runs),
        "invalid_runs": sum(1 for r in results if not r["valid"]),
        "cpu_hours_estimate": round(estimate_h, 4),
        "max_cpu_hours": max_cpu_hours,
        "result_digest": hashlib.sha256(body).hexdigest(),
    }
    prov = {sc["name"]: p for sc in spec["scenarios"] for p in [pins.provenance(sc)] if p}
    if prov:
        manifest["provenance"] = prov
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m research.harness.campaign",
                                 description="Run a controller campaign on the chamber model.")
    ap.add_argument("spec")
    ap.add_argument("--out", default=None, help="output directory (default: research/runs/<spec name>)")
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run although the contract sources or research/ differ from HEAD (recorded in the manifest)")
    ap.add_argument("--max-cpu-hours", type=float, default=DEFAULT_MAX_CPU_HOURS)
    a = ap.parse_args(argv)
    if a.jobs is not None and a.jobs < 1:
        ap.error("--jobs must be >= 1")
    if not math.isfinite(a.max_cpu_hours) or a.max_cpu_hours <= 0:
        ap.error("--max-cpu-hours must be > 0")
    out = a.out or os.path.join(runner.DEFAULT_REPO, "research", "runs",
                                os.path.splitext(os.path.basename(a.spec))[0])
    try:
        spec = load_spec(a.spec, allow_dirty=a.allow_dirty)
        m = run_campaign(spec, out, jobs=a.jobs, allow_dirty=a.allow_dirty, max_cpu_hours=a.max_cpu_hours)
    except (CampaignError, algorithms_loader.LoaderError, runner.ScenarioError, OSError, yaml.YAMLError) as e:
        print("campaign: %s" % e, file=sys.stderr)
        return 2
    print("campaign: %d runs (%d invalid), results in %s, digest %s"
          % (m["runs"], m["invalid_runs"], out, m["result_digest"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
