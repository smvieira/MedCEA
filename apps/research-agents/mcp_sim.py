"""apps/research-agents/mcp_sim.py (research Phase 4a, stage 5): mcp-sim, the simulation tools and the
CPU gate (design R6, R7, OD12).

Tools (names as in the profile): sim.estimate(spec), sim.run(spec), sim.status(cid), sim.results(cid, top).
The server recomputes the estimate itself from the spec (the agent's figure is not an input).
Gate for sim.run, on the recomputed estimate E (CPU-hours) and the session's remaining budget:
  E > 24                      refused (hard maximum per campaign);
  E + calibration > remaining refused (budget);
  E < 2                       starts at once;
  2 <= E <= 24                gate_pending is traced and the call answers "waiting for the supervisor";
                              the same sim.run (or sim.status) reads /gates/<gid>: approved -> start,
                              denied -> refused.
cap_h = min(max(1.25 E + calibration, CAP_FLOOR_H), remaining, approved_cap_h of the decision); the runner gets the cap
and deadline_s = max(DEADLINE_FLOOR_S, ceil(cap_h x 3600 / pool x 1.5)). A handle (cid) is bound to its session: another
session's cid is "no such campaign". The runner is an interface (stage 6 supplies the Job runner):
  start(cid, spec, cap_h, deadline_s)            -> None
  status(cid) -> {state running|done|failed, cpu_hours, manifest?, rows?, error?}
  pool                                           -> worker count (int)
An Estimator has estimate(spec, sid=None) -> {cpu_hours, calibration_h, runs, inprocess}."""
import importlib.util
import math
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_common import McpServer, Tool, ToolRefused, canonical, sha, clean_obj  # noqa: E402

AUTO_BELOW_H = 2.0
MAX_CAMPAIGN_H = 24.0
SESSION_DEFAULT_H = 16.0
CHEAP = ("IF_THEN_ELSE", "PID", "Q_LEARNING")
SPEC_SCHEMA = {"type": "object", "properties": {"spec": {"type": "object"}}, "required": ["spec"]}
CID_SCHEMA = {"type": "object", "properties": {"cid": {"type": "string"}, "top": {"type": "integer"}}, "required": ["cid"]}


PROPOSE_SCHEMA = {"type": "object", "properties": {
    "algorithm_code": {"type": "string"}, "params": {"type": "object"},
    "evidence": {"type": "array", "items": {"type": "string"}}, "rationale": {"type": "string"}},
    "required": ["algorithm_code", "params", "evidence"]}
CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,30}$")


def _load_params(repo_root):
    """schd/cea/algorithms/params.py by path (stdlib only, imports no algorithm; never `import cea`)."""
    path = os.path.join(repo_root, "schd", "cea", "algorithms", "params.py")
    spec = importlib.util.spec_from_file_location("medcea_algorithm_params", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# A Job needs time to start (unpack the bundle, install the wheels) before it computes anything: a small
# campaign's deadline from its cap alone was 1 s, and E48's first run failed "deadline" (22 Nov 2026).
# The CPU cap is enforced by sim_job's watchdog against the cgroup's CPU time, not by this wall clock.
DEADLINE_FLOOR_S = 300
# The Job's own process start (the interpreter, the harness imports) costs CPU the estimate does not
# count: a 3-run campaign estimated 0.0002 CPU-hours and spent 0.001 (E48). The cap never goes below this.
CAP_FLOOR_H = 0.01

class LocalEstimator:
    """In-process estimate (R7) for PID / bang-bang / Q-learning specs with research/harness/campaign.py;
    FLC and MPC import their libraries and cost far more, so they go to an estimate Job (RemoteEstimator)."""
    def __init__(self, repo_root):
        self.repo_root = repo_root

    def estimate(self, spec, sid=None):
        if self.repo_root not in sys.path:
            sys.path.insert(0, self.repo_root)
        from research.agents import estimate
        try:
            out = estimate.estimate_spec(spec, self.repo_root, allow_codes=CHEAP)
        except estimate.EstimateRefused as exc:
            raise ToolRefused(str(exc))
        return dict(out, inprocess=True)


class RemoteEstimator:
    """The estimate Job (R7), through the orchestrator's sim port (8091): POST /internal/estimates, then
    poll GET /internal/estimates/<eid> until done, failed or `timeout_s` (300 s: the tool's timeout).
    `http` has request(method, path, body) -> (status, object)."""
    def __init__(self, http, timeout_s=300, poll_s=3, sleep=time.sleep, clock=time.monotonic):
        self.http, self.timeout_s, self.poll_s, self.sleep, self.clock = http, timeout_s, poll_s, sleep, clock

    def estimate(self, spec, sid=None):
        st, r = self.http.request("POST", "/internal/estimates", {"sid": sid, "spec": spec})
        if st != 200 or not isinstance(r, dict) or not r.get("eid"):
            raise ToolRefused("the estimate could not be started (%s)" % (r or {}).get("error", st))
        eid, t0 = r["eid"], self.clock()
        while True:
            st, r = self.http.request("GET", "/internal/estimates/" + eid)
            r = r if st == 200 and isinstance(r, dict) else {"state": "failed", "error": "the orchestrator did not answer"}
            if r.get("state") == "done":
                return {"cpu_hours": r["cpu_hours"], "calibration_h": r.get("calibration_h", 0), "runs": r.get("runs", 0),
                        "inprocess": False}
            if r.get("state") == "failed":
                raise ToolRefused("estimate refused: %s" % str(r.get("error", "failed"))[:200])
            if self.clock() - t0 > self.timeout_s:
                raise ToolRefused("the estimate Job did not finish within %d s: try a smaller spec" % self.timeout_s)
            self.sleep(self.poll_s)


class SplitEstimator:
    """Stdlib controllers in-process, FLC and MPC (anything else) by the estimate Job."""
    def __init__(self, local, remote):
        self.local, self.remote = local, remote

    def estimate(self, spec, sid=None):
        from research.agents import estimate
        codes = estimate.spec_codes(spec) if isinstance(spec, dict) else None
        if codes is not None and not codes <= set(CHEAP):
            return self.remote.estimate(spec, sid=sid)
        return self.local.estimate(spec, sid=sid)


class RemoteRunner:
    """The runner interface over the orchestrator's sim port (8091): mcp-sim holds no Kubernetes
    rights, the orchestrator creates the sim-<cid> Job. `http` has request(method, path, body)."""
    def __init__(self, http, pool=2):
        self.http, self.pool = http, pool

    def start(self, cid, spec, cap_h, deadline_s, sid=None):
        st, r = self.http.request("POST", "/internal/sims", {"sid": sid, "cid": cid, "spec": spec,
                                                             "cap_h": cap_h, "deadline_s": deadline_s})
        if st != 200:
            raise ToolRefused("the simulation could not be started (%s)" % (r or {}).get("error", st))

    def status(self, cid):
        st, r = self.http.request("GET", "/internal/sims/" + cid)
        return r if st == 200 else {"state": "failed", "error": "the orchestrator did not answer"}


class SimServer:
    def __init__(self, session, estimator, runner, repo_root=None):
        self.session, self.estimator, self.runner = session, estimator, runner
        self.repo_root = repo_root
        self.camps = {}                  # cid -> {sid, spec, est, cap_h, state, gid?}
        self.lock = threading.Lock()
        self.app = McpServer("mcp-sim", "mcp-sim", session, [
            Tool("sim.estimate", "Estimate the CPU-hours of a campaign spec (recomputed by the server).", SPEC_SCHEMA, self.t_estimate),
            Tool("sim.run", "Run a campaign spec; above 2 CPU-hours the supervisor must approve.", SPEC_SCHEMA, self.t_run),
            Tool("sim.status", "State of a campaign handle.", CID_SCHEMA, self.t_status),
            Tool("sim.results", "Metrics and result digest of a finished campaign.", CID_SCHEMA, self.t_results),
            Tool("propose.parameter_set", "Propose a controller parameter set, backed by finished campaigns; "
                 "the supervisor accepts or discards it.", PROPOSE_SCHEMA, self.t_propose)])

    # ── helpers
    def _spec(self, args):
        spec = args.get("spec")
        if not isinstance(spec, dict):
            raise ToolRefused("spec must be an object")
        return spec

    def _est(self, spec, sid=None):
        e = self.estimator.estimate(spec, sid=sid)
        return {"cpu_hours": float(e["cpu_hours"]), "calibration_h": float(e.get("calibration_h", 0)),
                "runs": int(e.get("runs", 0))}

    def _reserved(self, sid):
        with self.lock:
            return sum(c["cap_h"] for c in self.camps.values()
                       if c["sid"] == sid and c["state"] in ("started", "pending") and c.get("cap_h"))

    def _remaining(self, ctx):
        left = (ctx["info"].get("budget_left") or {}).get("cpu_hours", SESSION_DEFAULT_H)
        return max(0.0, min(float(left), SESSION_DEFAULT_H) - self._reserved(ctx["sid"]))

    def _own(self, ctx, cid):
        with self.lock:
            c = self.camps.get(cid)
        if c is None or c["sid"] != ctx["sid"]:
            raise ToolRefused("no such campaign")
        return c

    def _start(self, ctx, cid, c, cap_h):
        pool = max(1, int(getattr(self.runner, "pool", 1)))
        deadline = max(DEADLINE_FLOOR_S, math.ceil(cap_h * 3600 / pool * 1.5))
        c.update(cap_h=cap_h, state="started", deadline_s=deadline)
        self.runner.start(cid, c["spec"], cap_h, deadline, sid=ctx["sid"])
        self.session.trace(ctx["sid"], "sim_started", {"cid": cid, "spec_sha256": c["spec_sha"], "estimate_h": round(c["est"]["cpu_hours"], 6),
                                                       "cap_h": round(cap_h, 6), "deadline_s": deadline})

    # ── tools
    def t_estimate(self, ctx, args):
        e = self._est(self._spec(args), ctx["sid"])
        return {"cpu_hours": round(e["cpu_hours"], 4), "calibration_h": round(e["calibration_h"], 4), "runs": e["runs"],
                "gate": "auto" if e["cpu_hours"] < AUTO_BELOW_H else ("ask" if e["cpu_hours"] <= MAX_CAMPAIGN_H else "refused")}

    def t_run(self, ctx, args):
        spec = self._spec(args)
        digest = sha(canonical(spec))
        cid = "c" + sha(ctx["sid"] + digest)[:20]
        with self.lock:
            known = self.camps.get(cid)
        if known:
            return self._progress(ctx, cid, known)
        est = self._est(spec, ctx["sid"])
        e, cal = est["cpu_hours"], est["calibration_h"]
        if e > MAX_CAMPAIGN_H:
            raise ToolRefused("campaign estimate %.3g CPU-hours is over the %g maximum" % (e, MAX_CAMPAIGN_H))
        remaining = self._remaining(ctx)
        if e + cal > remaining:
            raise ToolRefused("estimate %.3g CPU-hours (with calibration) exceeds the session's remaining %.3g" % (e + cal, remaining))
        cap = min(max(1.25 * e + cal, CAP_FLOOR_H), remaining)
        c = {"sid": ctx["sid"], "spec": spec, "spec_sha": digest, "est": est, "cap_h": cap, "state": "pending"}
        with self.lock:
            self.camps[cid] = c
        if e < AUTO_BELOW_H:
            self._start(ctx, cid, c, cap)
            return {"cid": cid, "state": "started", "estimate_h": round(e, 4), "cap_h": round(cap, 4)}
        self.session.trace(ctx["sid"], "gate_pending", {"gid": cid, "estimate_h": round(e, 6), "cap_h": round(cap, 6),
                                                        "runs": est["runs"], "spec_sha256": digest})
        return {"cid": cid, "state": "waiting for the supervisor", "estimate_h": round(e, 4)}

    def _progress(self, ctx, cid, c):
        if c["state"] == "pending":
            g = self.session.gate(ctx["sid"], cid)
            if g and g.get("state") == "approved":
                approved = (g.get("decision") or {}).get("approved_cap_h")
                cap = c["cap_h"]
                if isinstance(approved, (int, float)) and not isinstance(approved, bool) and approved > 0:
                    cap = min(cap, float(approved))
                self._start(ctx, cid, c, cap)
            elif g and g.get("state") == "denied":
                c["state"] = "denied"
        if c["state"] == "pending":
            return {"cid": cid, "state": "waiting for the supervisor"}
        if c["state"] == "denied":
            raise ToolRefused("the supervisor denied this campaign")
        if c["state"] == "started":
            s = self.runner.status(cid)
            if s["state"] in ("done", "failed"):
                c["state"], c["final"] = s["state"], s
                self.session.trace(ctx["sid"], "sim_finished", {
                    "cid": cid, "state": s["state"], "cpu_hours": round(float(s.get("cpu_hours", 0)), 6),
                    "result_digest": (s.get("manifest") or {}).get("result_digest"), "cap_h": round(c["cap_h"], 6)})
        out = {"cid": cid, "state": c["state"], "cap_h": round(c["cap_h"], 4)}
        if c["state"] == "started":
            out["state"] = "running"
        if c.get("final"):
            out["cpu_hours"] = round(float(c["final"].get("cpu_hours", 0)), 4)
            if c["state"] == "failed":
                out["error"] = str(c["final"].get("error", ""))[:200]
        return out

    def t_status(self, ctx, args):
        cid = args.get("cid")
        return self._progress(ctx, cid, self._own(ctx, cid))

    def t_results(self, ctx, args):
        cid = args.get("cid")
        c = self._own(ctx, cid)
        out = self._progress(ctx, cid, c)
        if c["state"] != "done":
            raise ToolRefused("the campaign is %s, not done" % out["state"])
        top = args.get("top", 10)
        top = top if isinstance(top, int) and not isinstance(top, bool) and 1 <= top <= 10 else 10
        m = c["final"].get("manifest") or {}
        rows = []
        for r in (c["final"].get("rows") or [])[:top]:
            if isinstance(r, dict):
                rows.append({k: r[k] for k in ("scenario", "code", "seed", "valid") if k in r}
                            | {"metrics": {k: v for k, v in (r.get("metrics") or {}).items()
                                           if isinstance(v, (int, float)) and not isinstance(v, bool)}})
        return {"cid": cid, "state": "done", "runs": m.get("runs"), "invalid_runs": m.get("invalid_runs"),
                "result_digest": m.get("result_digest"), "spec_digest": m.get("spec_digest"),
                "cpu_hours": out.get("cpu_hours"), "top": clean_obj(rows)}

    def t_propose(self, ctx, args):
        """A candidate parameter set (research Phase 4a stage 7a). Nothing is written to production: the
        result is the proposal document; the agent loop traces the `proposal` event with its digest and the
        supervisor decides (accept/discard) through the orchestrator. The parameters are validated with
        schd/cea/algorithms/params.py (the controller part of the coupling contract), the evidence must be
        finished campaigns of this session, and their spec and result digests are part of the document."""
        code = args.get("algorithm_code")
        params = args.get("params")
        ev = args.get("evidence")
        if not isinstance(code, str) or not CODE_RE.match(code):
            raise ToolRefused("algorithm_code must be an algorithm code such as PID")
        if not isinstance(params, dict):
            raise ToolRefused("params must be an object")
        if not isinstance(ev, list) or not 1 <= len(ev) <= 5 or not all(isinstance(x, str) for x in ev):
            raise ToolRefused("evidence must name 1 to 5 finished campaigns of this session")
        if not self.repo_root:
            raise ToolRefused("this deployment cannot validate parameter sets")
        problems = _load_params(self.repo_root).validate_params(code, params)
        if problems:
            raise ToolRefused("parameter set refused: %s" % "; ".join(problems)[:300])
        docs = []
        for cid in ev:
            c = self._own(ctx, cid)
            if self._progress(ctx, cid, c)["state"] != "done":
                raise ToolRefused("campaign %s is not done" % cid)
            m = c["final"].get("manifest") or {}
            if not m.get("result_digest") or not m.get("spec_digest"):
                raise ToolRefused("campaign %s has no result digest" % cid)
            docs.append({"cid": cid, "spec_digest": m["spec_digest"], "result_digest": m["result_digest"]})
        rationale = args.get("rationale")
        doc = {"kind": "parameter_set", "algorithm_code": code, "params": clean_obj(params),
               "evidence": docs, "rationale": str(rationale)[:500] if rationale else ""}
        return {"proposal": doc, "proposal_sha256": sha(canonical(doc)), "status": "proposed: waiting for the supervisor"}


def main():
    """The mcp-sim pod (research Phase 4a, 6b1): RS_SESSION_SERVER_URL (research-session :8102),
    RS_ORCH_SIM_URL (the orchestrator's sim port :8091), RS_SIM_POOL, RS_MCP_PORT (8110). The code
    bundle's root is two levels above this file."""
    from orchestrator import Http
    from mcp_common import Session, make_http_server
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    orch = Http(os.environ["RS_ORCH_SIM_URL"], timeout=30)
    srv = SimServer(Session(os.environ["RS_SESSION_SERVER_URL"], "mcp-sim"),
                    SplitEstimator(LocalEstimator(root), RemoteEstimator(orch)),
                    RemoteRunner(orch, pool=int(os.environ.get("RS_SIM_POOL", "2"))), repo_root=root)
    port = int(os.environ.get("RS_MCP_PORT", "8110"))
    sys.stderr.write("mcp-sim: port %d\n" % port)
    make_http_server(srv.app, port=port).serve_forever()


if __name__ == "__main__":
    main()
