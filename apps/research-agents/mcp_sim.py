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
cap_h = min(1.25 E + calibration, remaining, approved_cap_h of the decision); the runner gets the cap
and deadline_s = ceil(cap_h x 3600 / pool x 1.5). A handle (cid) is bound to its session: another
session's cid is "no such campaign". The runner is an interface (stage 6 supplies the Job runner):
  start(cid, spec, cap_h, deadline_s)            -> None
  status(cid) -> {state running|done|failed, cpu_hours, manifest?, rows?, error?}
  pool                                           -> worker count (int)
An Estimator has estimate(spec) -> {cpu_hours, calibration_h, runs, inprocess}."""
import math
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_common import McpServer, Tool, ToolRefused, canonical, sha, clean_obj  # noqa: E402

AUTO_BELOW_H = 2.0
MAX_CAMPAIGN_H = 24.0
SESSION_DEFAULT_H = 16.0
CHEAP = ("IF_THEN_ELSE", "PID", "Q_LEARNING")
SPEC_SCHEMA = {"type": "object", "properties": {"spec": {"type": "object"}}, "required": ["spec"]}
CID_SCHEMA = {"type": "object", "properties": {"cid": {"type": "string"}, "top": {"type": "integer"}}, "required": ["cid"]}


class LocalEstimator:
    """In-process estimate (R7) for PID / bang-bang / Q-learning specs with research/harness/campaign.py;
    FLC and MPC import their libraries and cost far more, so they go to an estimate Job (stage 6)."""
    def __init__(self, repo_root):
        self.repo_root = repo_root

    def estimate(self, spec):
        if self.repo_root not in sys.path:
            sys.path.insert(0, self.repo_root)
        from research.harness import algorithms_loader, campaign, runner
        import copy
        try:
            spec = campaign.resolve_spec(copy.deepcopy(spec), repo_root=self.repo_root)
        except campaign.CampaignError as e:
            raise ToolRefused("spec refused: %s" % e)
        codes = {c["code"] for c in spec["controllers"]}
        if not codes <= set(CHEAP):
            raise ToolRefused("a spec with %s needs an estimate Job: not available in this deployment"
                              % ", ".join(sorted(codes - set(CHEAP))))
        loaded = algorithms_loader.load(self.repo_root)
        runs = campaign.expand(spec)
        for sc in spec["scenarios"]:
            runner.normalise(copy.deepcopy(sc), loaded)
        rates = campaign.calibrate(spec, loaded)
        dur = {sc["name"]: sc["duration_h"] for sc in spec["scenarios"]}
        est = sum(rates[(n, c)] * dur[n] for n, c, _, _, _ in runs) / 3600.0
        cal = sum(r * min(dur[n], campaign.CALIBRATION_H) for (n, _), r in rates.items()) / 3600.0
        return {"cpu_hours": est, "calibration_h": cal, "runs": len(runs), "inprocess": True}


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
    def __init__(self, session, estimator, runner):
        self.session, self.estimator, self.runner = session, estimator, runner
        self.camps = {}                  # cid -> {sid, spec, est, cap_h, state, gid?}
        self.lock = threading.Lock()
        self.app = McpServer("mcp-sim", "mcp-sim", session, [
            Tool("sim.estimate", "Estimate the CPU-hours of a campaign spec (recomputed by the server).", SPEC_SCHEMA, self.t_estimate),
            Tool("sim.run", "Run a campaign spec; above 2 CPU-hours the supervisor must approve.", SPEC_SCHEMA, self.t_run),
            Tool("sim.status", "State of a campaign handle.", CID_SCHEMA, self.t_status),
            Tool("sim.results", "Metrics and result digest of a finished campaign.", CID_SCHEMA, self.t_results)])

    # ── helpers
    def _spec(self, args):
        spec = args.get("spec")
        if not isinstance(spec, dict):
            raise ToolRefused("spec must be an object")
        return spec

    def _est(self, spec):
        e = self.estimator.estimate(spec)
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
        deadline = math.ceil(cap_h * 3600 / pool * 1.5)
        c.update(cap_h=cap_h, state="started", deadline_s=deadline)
        self.runner.start(cid, c["spec"], cap_h, deadline, sid=ctx["sid"])
        self.session.trace(ctx["sid"], "sim_started", {"cid": cid, "spec_sha256": c["spec_sha"], "estimate_h": round(c["est"]["cpu_hours"], 6),
                                                       "cap_h": round(cap_h, 6), "deadline_s": deadline})

    # ── tools
    def t_estimate(self, ctx, args):
        e = self._est(self._spec(args))
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
        est = self._est(spec)
        e, cal = est["cpu_hours"], est["calibration_h"]
        if e > MAX_CAMPAIGN_H:
            raise ToolRefused("campaign estimate %.3g CPU-hours is over the %g maximum" % (e, MAX_CAMPAIGN_H))
        remaining = self._remaining(ctx)
        if e + cal > remaining:
            raise ToolRefused("estimate %.3g CPU-hours (with calibration) exceeds the session's remaining %.3g" % (e + cal, remaining))
        cap = min(1.25 * e + cal, remaining)
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


def main():
    """The mcp-sim pod (research Phase 4a, 6b1): RS_SESSION_SERVER_URL (research-session :8102),
    RS_ORCH_SIM_URL (the orchestrator's sim port :8091), RS_SIM_POOL, RS_MCP_PORT (8110). The code
    bundle's root is two levels above this file."""
    from orchestrator import Http
    from mcp_common import Session, make_http_server
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    srv = SimServer(Session(os.environ["RS_SESSION_SERVER_URL"], "mcp-sim"), LocalEstimator(root),
                    RemoteRunner(Http(os.environ["RS_ORCH_SIM_URL"]), pool=int(os.environ.get("RS_SIM_POOL", "2"))))
    port = int(os.environ.get("RS_MCP_PORT", "8110"))
    sys.stderr.write("mcp-sim: port %d\n" % port)
    make_http_server(srv.app, port=port).serve_forever()


if __name__ == "__main__":
    main()
