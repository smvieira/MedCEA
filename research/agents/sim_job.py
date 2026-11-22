"""research/agents/sim_job.py (design R6): the entrypoint of a sim-<cid> Job (python3 -m research.agents.sim_job, cwd = the code bundle root). Runs one campaign
spec (MEDCEA_SIM_SPEC, base64 JSON, or --spec FILE) into --out with the harness, with a CPU
watchdog: process + children CPU seconds, cross-checked against the cgroup's usage_usec when
readable, stop at the cap (cpu_cap_exceeded). Prints exactly one final line

    SIM_RESULT {json}

with {state: done|failed, cpu_hours, cpu_hours_cgroup, manifest, rows (first 50 lines of
results.jsonl, as parsed), error?}; the full results.jsonl stays in --out (a results volume in
the cluster) and manifest.result_digest is the digest of it, so the log copy is checkable
against the volume. Stdlib + the harness.

--estimate (stage 3 of 4b, design R7): the estimate-<id> Job. Reads the spec the same way, runs
research.agents.estimate.estimate_spec (FLC and MPC allowed: this image has their libraries) and prints

    ESTIMATE_RESULT {state: done|failed, cpu_hours, calibration_h, runs, error?, controller_libraries}

under the same watchdog (--max-cpu-hours, default 0.1: the calibration slices are short)."""
import argparse
import base64
import json
import os
import resource
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MARK = "SIM_RESULT "
EST_MARK = "ESTIMATE_RESULT "
EST_CAP_H = 0.1
ROWS_MAX = 50


def cpu_seconds():
    me, ch = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return me.ru_utime + me.ru_stime + ch.ru_utime + ch.ru_stime


def cgroup_seconds(path="/sys/fs/cgroup/cpu.stat"):
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("usage_usec "):
                    return int(line.split()[1]) / 1e6
    except (OSError, ValueError):
        pass
    return None


def emit(obj, mark=MARK):
    sys.stdout.write(mark + json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def spent_hours(base_cg, base_proc):
    p = (cpu_seconds() - base_proc) / 3600.0
    c = cgroup_seconds()
    return p, (None if c is None or base_cg is None else (c - base_cg) / 3600.0)


def main(argv=None, runner=None, clock=time.monotonic, poll=2.0, exit_fn=os._exit):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--max-cpu-hours", type=float, default=None)
    ap.add_argument("--spec", default=None)
    ap.add_argument("--estimate", action="store_true")
    a = ap.parse_args(argv)
    if a.estimate:
        if a.max_cpu_hours is None:
            a.max_cpu_hours = EST_CAP_H
    elif a.out is None or a.max_cpu_hours is None:
        ap.error("--out and --max-cpu-hours are required")
    mark = EST_MARK if a.estimate else MARK
    if a.spec:
        with open(a.spec, "rb") as f:
            raw = f.read()
    else:
        raw = base64.b64decode(os.environ["MEDCEA_SIM_SPEC"])
    spec = json.loads(raw)
    if a.estimate:
        if runner is None:
            def runner(spec, out, jobs, cap):
                from research.agents import estimate
                return estimate.estimate_spec(spec, ROOT)
    elif runner is None:
        from research.harness import campaign

        def runner(spec, out, jobs, cap):
            s = campaign.resolve_spec(spec, repo_root=ROOT)
            return campaign.run_campaign(s, out, repo_root=ROOT, jobs=jobs, max_cpu_hours=cap)
    base_p, base_c = cpu_seconds(), cgroup_seconds()
    done = threading.Event()

    def watchdog():
        while not done.wait(poll):
            p, c = spent_hours(base_c, base_p)
            if max(p, c or 0.0) > a.max_cpu_hours:
                emit({"state": "failed", "error": "cpu_cap_exceeded", "cpu_hours": round(max(p, c or 0.0), 6),
                      "cpu_hours_cgroup": None if c is None else round(c, 6)}, mark)
                exit_fn(3)
                return
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        m = runner(spec, a.out, a.jobs, a.max_cpu_hours)
    except Exception as e:                       # the campaign's own refusals included
        done.set()
        emit({"state": "failed", "error": ("%s: %s" % (type(e).__name__, e))[:200],
              "cpu_hours": round(spent_hours(base_c, base_p)[0], 6)}, mark)
        return 1
    done.set()
    p, c = spent_hours(base_c, base_p)
    if max(p, c or 0.0) > a.max_cpu_hours:
        # the watchdog looks every `poll` seconds: a run that ends between two looks is checked here, and a
        # result over its cap is never reported as done (E48, 22 Nov 2026: 0.001 against 0.0002 was "done")
        emit({"state": "failed", "error": "cpu_cap_exceeded", "cpu_hours": round(max(p, c or 0.0), 6),
              "cpu_hours_cgroup": None if c is None else round(c, 6)}, mark)
        return 3
    if a.estimate:
        emit({"state": "done", "cpu_hours": m["cpu_hours"], "calibration_h": m["calibration_h"], "runs": m["runs"],
              "controller_libraries": m.get("controller_libraries", {})}, mark)
        return 0
    rows = []
    try:
        with open(os.path.join(a.out, "results.jsonl"), encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= ROWS_MAX:
                    break
                rows.append(json.loads(line))
    except OSError:
        pass
    emit({"state": "done", "manifest": m, "rows": rows, "cpu_hours": round(max(p, c or 0.0), 6),
          "cpu_hours_cgroup": None if c is None else round(c, 6), "cpu_hours_process": round(p, 6)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
