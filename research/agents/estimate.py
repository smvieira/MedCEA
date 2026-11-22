"""research/agents/estimate.py (research Phase 4b stage 3; design R7): the CPU estimate of a campaign spec.
One function, two callers: mcp-sim's LocalEstimator (in-process, for the stdlib controllers) and
sim_job --estimate (the estimate-<id> Job, which has FLC's and MPC's libraries). The estimate is the
harness's own: resolve the spec, check every scenario, run one short calibration slice per (scenario,
controller) and extrapolate by the scenario's duration. Raises EstimateRefused with a message fit for a
tool result. Needs the code bundle's root (research/, schd/cea/algorithms/)."""
import copy


class EstimateRefused(Exception):
    pass


def spec_codes(spec):
    """The controller codes a raw spec names (no resolving), or None when it is not shaped like a spec."""
    try:
        return {c["code"] for c in spec["controllers"]}
    except (KeyError, TypeError):
        return None


def estimate_spec(spec, repo_root, allow_codes=None):
    # the caller has the bundle root on sys.path (sim_job runs from it; mcp-sim's LocalEstimator inserts it)
    from research.harness import algorithms_loader, campaign, runner
    try:
        spec = campaign.resolve_spec(copy.deepcopy(spec), repo_root=repo_root)
    except campaign.CampaignError as e:
        raise EstimateRefused("spec refused: %s" % e)
    codes = {c["code"] for c in spec["controllers"]}
    if allow_codes is not None and not codes <= set(allow_codes):
        raise EstimateRefused("a spec with %s needs an estimate Job: not available in this deployment"
                              % ", ".join(sorted(codes - set(allow_codes))))
    loaded = algorithms_loader.load(repo_root)
    libs = getattr(loaded, "libraries", {}) or {}
    for code in sorted(codes & {"FLC", "MPC"}):
        # without its library a controller falls back to bang-bang and would be estimated as one: refuse instead
        if code in libs and not libs[code].get("present"):
            raise EstimateRefused("%s's libraries are not installed here (%s): the estimate would be bang-bang's"
                                  % (code, str(libs[code].get("reason"))[:100]))
    runs = campaign.expand(spec)
    for sc in spec["scenarios"]:
        runner.normalise(copy.deepcopy(sc), loaded)
    rates = campaign.calibrate(spec, loaded)
    dur = {sc["name"]: sc["duration_h"] for sc in spec["scenarios"]}
    est = sum(rates[(n, c)] * dur[n] for n, c, _, _, _ in runs) / 3600.0
    cal = sum(r * min(dur[n], campaign.CALIBRATION_H) for (n, _), r in rates.items()) / 3600.0
    return {"cpu_hours": est, "calibration_h": cal, "runs": len(runs),
            "controller_libraries": {k: bool(v.get("present")) for k, v in libs.items()}}
