"""apps/research-agents/campaigns.py (research Phase 4e, design rs4e 3.1): what the research console reads about a
session's simulation campaigns. Pure functions over a session's trace events and a root directory (the orchestrator's
/runs, PVC research-runs), so they are tested on a temporary tree.

A campaign belongs to a session only through the session's own trace: a gate_pending whose gid is the cid, or a
sim_started naming it (both written by mcp-sim on the server port), so a cid of another session is "no such campaign"
whatever the runs volume holds. Its files are /runs/campaigns/<cid>/{manifest.json, results.jsonl, series/<n>.json.gz}
(the sim Job's --out, apps/research-agents/jobs.py). results.jsonl is served only when its sha256 is the result_digest
the trace recorded for the campaign (sim_finished): a file changed or replaced on the volume answers 409, never other
numbers than the ones the session's record vouches for. Files the trace names that are gone answer 410.

Every reader returns (status, object) as the orchestrator's handlers send it."""
import gzip
import hashlib
import json
import math
import os
import re
import threading

CID = re.compile(r"^c[0-9a-f]{20}$")
# Sizes the orchestrator's pod can hold (its memory limit is 256Mi, apps/research-agents/k8s/agents.yaml): results.jsonl
# of 8 MiB parses to about 55 MB of rows (E58's row shape); a series file is at most about 3.2 MB uncompressed at
# research/harness/series.py's MAX_POINTS and MAX_CHANGES. The design's 64 MiB / 200 MB would OOM-kill the pod, and its
# tracking of every running session with it, before the 413 could answer (review of commit B).
RESULTS_MAX = 8 * 1024 * 1024           # results.jsonl read whole: 413 above
SERIES_MAX = 8 * 1000 * 1000            # a run's series file (gzip): 413 above
SERIES_RAW_MAX = 16 * 1000 * 1000      # … and uncompressed, counted while it is decompressed (a gzip bomb stops here)
SERIES_CHUNK = 1024 * 1024
READ_WAIT_S = 30                        # one file read at a time; a request that waits longer answers 503
_READ = threading.BoundedSemaphore(1)
SERIES_POINTS_MAX = 2000                # the series route's ?points= bound
SERIES_POINTS_MIN = 10
SETTINGS_MAX = 200                      # by_setting rows the console gets (an agent gets mcp_sim.SETTINGS_MAX)
RUNS_PAGE_MAX = 200                     # ?limit= of the runs page
RUNS_PAGE_DEFAULT = 50


def campaigns_of(events):
    """The session's campaigns from its trace, in the order the trace names them first:
    [{cid, gate: {gid, estimate_h, cap_h, runs, state, decided_by?, approved_cap_h?} | None, started_at, finished_at,
    state, cpu_hours, result_digest, spec_sha256}]. state: waiting (a gate not decided), denied, approved (decided,
    not started yet), running (started, not finished), done or failed (the newest sim_finished)."""
    out, order = {}, []

    def get(cid):
        if cid not in out:
            out[cid] = {"cid": cid, "gate": None, "started_at": None, "finished_at": None, "state": None,
                        "cpu_hours": None, "result_digest": None, "spec_sha256": None}
            order.append(cid)
        return out[cid]

    for e in events or []:
        if not isinstance(e, dict):
            continue
        p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        ev = e.get("event")
        if ev == "gate_pending" and CID.match(str(p.get("gid") or "")):
            c = get(p["gid"])
            if c["gate"] is None:
                c["gate"] = {"gid": p["gid"], "estimate_h": p.get("estimate_h"), "cap_h": p.get("cap_h"),
                             "runs": p.get("runs"), "state": "pending"}
                c["spec_sha256"] = c["spec_sha256"] or p.get("spec_sha256")
        elif ev == "gate_decided" and str(p.get("gid") or "") in out and out[p["gid"]]["gate"] is not None:
            g = out[p["gid"]]["gate"]
            if g["state"] == "pending":
                g["state"] = "approved" if p.get("decision") == "approve" else "denied"
                if p.get("by_username"):
                    g["decided_by"] = p.get("by_username")
                if p.get("decision") == "approve" and p.get("approved_cap_h") is not None:
                    g["approved_cap_h"] = p.get("approved_cap_h")
        elif ev == "sim_started" and CID.match(str(p.get("cid") or "")):
            c = get(p["cid"])
            if c["started_at"] is None:
                c["started_at"] = e.get("at")
            c["spec_sha256"] = c["spec_sha256"] or p.get("spec_sha256")
        elif ev == "sim_finished" and str(p.get("cid") or "") in out:
            c = out[p["cid"]]
            c["finished_at"] = e.get("at")
            c["state"] = p.get("state") if p.get("state") in ("done", "failed") else "failed"
            if p.get("cpu_hours") is not None:
                c["cpu_hours"] = p.get("cpu_hours")
            if p.get("result_digest"):
                c["result_digest"] = p.get("result_digest")
    for c in out.values():
        if c["state"] is None:
            if c["started_at"]:
                c["state"] = "running"
            elif c["gate"]:
                c["state"] = {"pending": "waiting"}.get(c["gate"]["state"], c["gate"]["state"])
            else:
                c["state"] = "running"
    return [out[cid] for cid in order]


def campaign_of(events, cid):
    """The campaign entry of cid when this session's trace names it, else None."""
    if not CID.match(str(cid or "")):
        return None
    return next((c for c in campaigns_of(events) if c["cid"] == cid), None)


def one_at_a_time(fn):
    """A reader of the runs volume runs alone (the pod's memory holds one results file and its rows, not several at
    once: ThreadingHTTPServer serves requests concurrently); 503 when another read holds it longer than READ_WAIT_S."""
    def run(*a, **k):
        if not _READ.acquire(timeout=READ_WAIT_S):
            return 503, {"error": "the orchestrator is reading another campaign: try again"}
        try:
            return fn(*a, **k)
        finally:
            _READ.release()
    run.__name__, run.__doc__ = fn.__name__, fn.__doc__
    return run


def _dir(root, cid):
    return os.path.join(root, "campaigns", cid)


def _results(root, entry):
    """(rows, manifest, None) or (None, None, (status, object)): results.jsonl verified against the trace."""
    st = entry["state"]
    if st in ("waiting", "approved", "running"):
        # the entry's own state: an approved gate whose simulation has not started is not "running" (campaigns_of)
        return None, None, (200, {"state": st, "cid": entry["cid"]})
    if st == "denied":
        return None, None, (200, {"state": "denied", "cid": entry["cid"]})
    d = _dir(root, entry["cid"])
    path = os.path.join(d, "results.jsonl")
    want = entry.get("result_digest")
    if not want:
        # finished without a result the trace vouches for (a failed Job): nothing is served
        return None, None, (200, {"state": entry["state"], "cid": entry["cid"],
                                  "error": "the campaign has no recorded result"})
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, None, (410, {"state": "gone", "cid": entry["cid"], "result_digest": want,
                                  "error": "the campaign's files are no longer on the runs volume"})
    if size > RESULTS_MAX:
        return None, None, (413, {"error": "the campaign's results are larger than %d MiB" % (RESULTS_MAX // 1048576)})
    with open(path, "rb") as f:
        body = f.read(RESULTS_MAX + 1)
    if hashlib.sha256(body).hexdigest() != want:
        return None, None, (409, {"error": "results do not match the trace"})
    rows = []
    for line in body.decode("utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    try:
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        manifest = None
    if not isinstance(manifest, dict) or manifest.get("result_digest") != want:
        manifest = None                          # only a manifest that names the same results is shown
    return rows, manifest, None


def _int(q, name, default, lo, hi):
    """A query integer: (value, None) or (None, error)."""
    v = (q.get(name) or [None])[0] if isinstance(q, dict) else None
    if v is None or v == "":
        return default, None
    if not re.match(r"^[0-9]{1,9}$", str(v)):
        return None, "%s must be a whole number" % name
    v = int(v)
    if not lo <= v <= hi:
        return None, "%s is %d to %d" % (name, lo, hi)
    return v, None


def series_info(manifest):
    """{every_s, runs} of a campaign recorded with series, else None."""
    s = (manifest or {}).get("series") if isinstance(manifest, dict) else None
    if not isinstance(s, dict) or not isinstance(s.get("files"), list):
        return None
    return {"every_s": s.get("every_s"), "runs": len(s["files"])}


@one_at_a_time
def read_campaign(root, entry, q, summarise_settings, summarise_row, defaults_of):
    """GET …/campaigns/<cid>?sort=&offset=&limit=: {cid, state, manifest, by_setting (≤ SETTINGS_MAX settings, every
    row of the campaign, not fit to an agent's view), runs: {offset, total, rows: [summarise_row…]}, series}."""
    offset, err = _int(q, "offset", 0, 0, 10 ** 7)
    limit, err2 = _int(q, "limit", RUNS_PAGE_DEFAULT, 1, RUNS_PAGE_MAX)
    if err or err2:
        return 400, {"error": err or err2}
    sort = (q.get("sort") or [None])[0] if isinstance(q, dict) else None
    rows, manifest, refusal = _results(root, entry)
    if refusal:
        return refusal
    try:
        table = summarise_settings(rows, defaults_of, sort or None, max_rows=SETTINGS_MAX)
    except Exception as e:      # mcp_sim.ToolRefused: a sort that is no criterion of this campaign
        if type(e).__name__ == "ToolRefused":
            return 400, {"error": str(e)[:300]}
        raise
    page = rows[offset:offset + limit]
    return 200, {"cid": entry["cid"], "state": entry["state"], "manifest": manifest, "by_setting": table,
                 "runs": {"offset": offset, "total": len(rows), "rows": [summarise_row(r) for r in page]},
                 "series": series_info(manifest)}


def _run_index(n, rows):
    if not re.match(r"^[0-9]{1,7}$", str(n or "")):
        return None
    n = int(n)
    return n if n < len(rows) else None


@one_at_a_time
def read_run(root, entry, n):
    """GET …/campaigns/<cid>/runs/<n>: the full result row n (its line in results.jsonl)."""
    rows, _manifest, refusal = _results(root, entry)
    if refusal:
        return refusal if refusal[0] != 200 else (409, dict(refusal[1], error="the campaign has no results to read"))
    i = _run_index(n, rows)
    if i is None:
        return 404, {"error": "no such run"}
    return 200, rows[i]


def decimate(doc, points):
    """At most `points` samples: per bucket of the samples, one sample with each column's minimum and one with its
    maximum (t the bucket's first and last time), so a peak or a dip is never averaged away; `changes` (command,
    relay, light and cycle switches) stay whole. A document at or under `points` is returned unchanged."""
    cols = doc.get("columns") if isinstance(doc, dict) else None
    if not isinstance(cols, dict) or not isinstance(cols.get("t"), list):
        return doc
    t = cols["t"]
    n = len(t)
    if n <= points:
        return doc
    buckets = max(1, points // 2)
    bounds = [(b * n // buckets, (b + 1) * n // buckets) for b in range(buckets)]
    bounds = [(lo, hi) for lo, hi in bounds if hi > lo]

    def nums(arr, lo, hi):
        return [v for v in arr[lo:hi] if isinstance(v, (int, float)) and not isinstance(v, bool)
                and math.isfinite(v)]

    def pick(obj):
        out = {}
        for k, v in obj.items():
            if isinstance(v, list) and len(v) == n:
                if k == "t":
                    col = []
                    for lo, hi in bounds:
                        col += [v[lo], v[hi - 1]]
                else:
                    col = []
                    for lo, hi in bounds:
                        xs = nums(v, lo, hi)
                        col += [min(xs), max(xs)] if xs else [None, None]
                out[k] = col
            elif isinstance(v, dict):
                out[k] = pick(v)
            else:
                out[k] = v
        return out

    res = dict(doc)
    res["columns"] = pick(cols)
    res["decimated"] = {"from": n, "to": 2 * len(bounds), "rule": "min and max per bucket; changes whole"}
    return res


@one_at_a_time
def read_series(root, entry, n, q):
    """GET …/campaigns/<cid>/runs/<n>/series?points=: research/harness/series.py's document of run n, decimated to at
    most `points` (≤ SERIES_POINTS_MAX); 404 {"error": "no series recorded for this campaign"} without series."""
    points, err = _int(q, "points", SERIES_POINTS_MAX, SERIES_POINTS_MIN, SERIES_POINTS_MAX)
    if err:
        return 400, {"error": err}
    rows, manifest, refusal = _results(root, entry)
    if refusal:
        return refusal if refusal[0] != 200 else (409, dict(refusal[1], error="the campaign has no results to read"))
    if series_info(manifest) is None:
        return 404, {"error": "no series recorded for this campaign"}
    i = _run_index(n, rows)
    if i is None:
        return 404, {"error": "no such run"}
    rel = "series/%d.json.gz" % i
    if rel not in manifest["series"]["files"]:
        return 404, {"error": "no series recorded for this run"}
    path = os.path.join(_dir(root, entry["cid"]), rel)
    try:
        size = os.path.getsize(path)
    except OSError:
        return 410, {"state": "gone", "error": "the run's series is no longer on the runs volume"}
    if size > SERIES_MAX:
        return 413, {"error": "the run's series is larger than %d MB" % (SERIES_MAX // 1000000)}
    raw = _gunzip_bounded(path, SERIES_RAW_MAX)
    if raw is None:
        return 413, {"error": "the run's series is larger than %d MB uncompressed" % (SERIES_RAW_MAX // 1000000)}
    return 200, decimate(json.loads(raw.decode("utf-8")), points)


def _gunzip_bounded(path, limit):
    """The file decompressed, or None as soon as more than `limit` bytes come out (read in SERIES_CHUNK pieces, so no
    more than limit + one piece is ever held)."""
    out, n = [], 0
    with gzip.open(path, "rb") as f:
        while True:
            b = f.read(SERIES_CHUNK)
            if not b:
                return b"".join(out)
            n += len(b)
            if n > limit:
                return None
            out.append(b)

