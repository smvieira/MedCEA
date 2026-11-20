"""Plant calibration: which chamber constants a dataset can identify, and a step-response
fit for the day it can (design §3, revised by §9 R8 and R12).

PLANT_FIELDS maps every twin_plant.chamber.ChamberParams field to one class, and each
class names what identifying it needs. identifiability(header) gives, per field, a
Verdict(ok, reasons). Lake contract v1 exports AP readings only (no command, no SP
report), so on every dataset of contract v1 no field but the hardware spec is identifiable
and `fit-plant` refuses (exit 3). There is no override flag: an assumption changes visibly
in a scenario's plant.overrides.

fit_step(t, y, t_step, actuator, ...) fits y = y0 + K (1 - exp(-(t - t0) / tau)) after a
step at t0 by variable projection (closed-form least squares of y0 and K for each tau, a
golden-section search over log tau on the residual sum of squares), with an interval for
tau from a residual block bootstrap (10-minute blocks, R12), widened to a delete-a-block
jackknife's and by the residuals' autocorrelation (review of 20 Nov 2026: the bootstrap
alone under-covers when the readings wander). It returns a StepFit or a
Refusal, never a number it cannot stand behind:

- no step inside the data;
- a pre-step baseline under 10 minutes, or one that drifts (slope > K / (20 tau));
- K under 10 x the noise;
- a window after the step shorter than 0.5 tau;
- the interval's half-width over 20 % of tau;
- an ambient change or a door event in the window (from the disturbance log, when given);
- NO_AMBIENT: no ambient series, for an actuator of the coupled_thermal or conditional
  class (R12).

With power_w it also gives C_a = power_w tau / K. Phase 3 applies no plant fit (R8): a
calibration file refuses any `fitted` plant entry.
"""
from __future__ import annotations

import dataclasses
import math
from typing import NamedTuple

from ..twin_plant.chamber import ChamberParams
from . import stats

CLASSES = {
    "spec": ("volume_m3",),
    "ambient": ("ambient_temperature", "ambient_humidity", "ambient_co2"),
    "coupled_thermal": ("tau_air_s", "air_heat_capacity_j_per_k", "leak_ach_per_h", "substrate_air_w_per_k"),
    "excitation": ("heater_w", "cooler_w", "cooler_cop", "humidifier_w", "humidifier_g_per_h", "substrate_heater_w",
                   "air_flow_fan_w", "co2_fan_w", "co2_steriliser_w", "light_red_w", "light_blue_w", "light_uv_w",
                   "lamp_heat_fraction", "fan_air_exchange_per_h", "co2_fan_ach_per_h", "door_open_ach_per_h",
                   "fan_mixing_factor"),
    "substrate": ("substrate_heat_capacity_j_per_k", "substrate_ambient_w_per_k"),
    "conditional": ("co2_production_ml_per_h", "fungi_water_g_per_h"),
    "biology": ("fungi_heat_w", "fungi_ref_temperature", "fungi_q10"),
    "disturbance": ("door_open_extra_heat_w",),
}
PLANT_FIELDS = {f: cls for cls, fields in CLASSES.items() for f in fields}

NEEDS = {
    "spec": "the hardware; never fitted",
    "ambient": "a room sensor (a second SENSE board), never the chamber's own",
    "coupled_thermal": "a heater step of known power plus the room temperature",
    "excitation": "a step of that actuator, with a known power and timing",
    "substrate": "the ground_temperature sensor plus a substrate-heater step",
    "conditional": "a closed-chamber relaxation, the room's CO2 and humidity, the substrate temperature and a "
                   "disturbance log",
    "biology": "literature only in Phase 3",
    "disturbance": "a logged door test",
}

REASONS = {
    "NO_ACTUATOR_DATA": "lake contract v1 exports AP readings only: no command or SP report says when an actuator "
                        "switched",
    "NO_EXCITATION": "no actuator step in the window",
    "NO_AMBIENT": "the room is not measured",
    "NOT_OBSERVED": "ground_temperature has no sensor",
    "SPEC": "a hardware specification, never fitted",
    "LITERATURE": "taken from the literature in Phase 3",
    "CONDITIONAL_REFUSED": "refused by default: needs a closed-chamber relaxation with the room and the substrate "
                           "measured",
}

# Which actuator's step identifies a class (the excitation class: any actuator).
CLASS_ACTUATORS = {"coupled_thermal": ("air_heater",), "substrate": ("substrate_heater",)}
AMBIENT_CLASSES = ("coupled_thermal", "conditional")
ACTUATOR_CLASS = {"air_heater": "coupled_thermal", "substrate_heater": "substrate"}

MIN_BASELINE_S = 600.0
K_NOISE_FACTOR = 10.0
MIN_WINDOW_TAU = 0.5
MAX_CI_HALF = 0.2
DRIFT_FACTOR = 20.0
TAU_MIN_S = 10.0
GOLDEN_ITERS = 60
JACKKNIFE_BLOCKS = 2        # the jackknife deletes 2 bootstrap blocks (20 minutes) at a time


class Verdict(NamedTuple):
    ok: bool
    reasons: tuple


class StepFit(NamedTuple):
    tau_s: float
    y0: float
    K: float
    t0: float
    ci95: tuple
    sigma: float
    n: int
    heat_capacity_j_per_k: float | None


class Refusal(NamedTuple):
    code: str
    why: str


def chamber_fields():
    return [f.name for f in dataclasses.fields(ChamberParams)]


def identifiability(header, rows=None):
    """{field: Verdict} for every ChamberParams field, from a dataset's header (and rows:
    which tags were observed)."""
    events = header.get("actuator_events")
    has_events = isinstance(events, list) and bool(events)
    stepped = {e.get("actuator") for e in events or [] if isinstance(e, dict)} if has_events else set()
    has_ambient = bool(header.get("ambient"))
    tags = {r["tag"] for r in rows} if rows is not None else set((header.get("series") or {}).keys())
    tags = {t.split("/")[0] for t in tags}
    out = {}
    for field in chamber_fields():
        cls = PLANT_FIELDS[field]
        if cls == "spec":
            out[field] = Verdict(False, ("SPEC",))
            continue
        reasons = []
        if not has_events:
            reasons.append("NO_ACTUATOR_DATA")
        wanted = CLASS_ACTUATORS.get(cls)
        if not stepped or (wanted and not set(wanted) & stepped):
            reasons.append("NO_EXCITATION")
        if not has_ambient:
            reasons.append("NO_AMBIENT")
        if cls == "substrate" and "ground_temperature" not in tags:
            reasons.append("NOT_OBSERVED")
        if cls == "biology":
            reasons.append("LITERATURE")
        if cls == "conditional":
            reasons.append("CONDITIONAL_REFUSED")
        out[field] = Verdict(not reasons, tuple(reasons))
    return out


def table(verdicts):
    """The verdicts as report lines."""
    lines = []
    for field in chamber_fields():
        v = verdicts[field]
        lines.append("%-34s %-16s %s" % (field, PLANT_FIELDS[field], "identifiable" if v.ok else
                                         "refused: " + ", ".join(v.reasons)))
    lines.append("")
    for code, text in REASONS.items():
        if any(code in v.reasons for v in verdicts.values()):
            lines.append("%s: %s" % (code, text))
    return lines


# ── the step fit ────────────────────────────────────────────────────────────────────
def _ls(t, y, t0, tau):
    """(ssr, y0, K) of the least-squares y0 + K x, x = 1 - exp(-(t - t0)/tau) after t0."""
    n = len(t)
    exp = math.exp
    xs = [1.0 - exp((t0 - ti) / tau) if ti > t0 else 0.0 for ti in t]
    sx = math.fsum(xs)
    sxx = math.fsum([x * x for x in xs])
    sy = math.fsum(y)
    sxy = math.fsum([x * yi for x, yi in zip(xs, y)])
    det = n * sxx - sx * sx
    if det <= 0:
        return float("inf"), 0.0, 0.0
    K = (n * sxy - sx * sy) / det
    y0 = (sy - K * sx) / n
    syy = math.fsum([yi * yi for yi in y])
    return max(0.0, syy - y0 * sy - K * sxy), y0, K


def _golden(t, y, t0, lo, hi, grid=24, tol=1e-7):
    """tau minimising the SSR over [lo, hi] (a log-tau golden-section search, after a coarse
    grid of GRID + 1 points that picks the bracket)."""
    a, b = math.log(lo), math.log(hi)
    pts = [a + (b - a) * i / grid for i in range(grid + 1)]
    vals = [_ls(t, y, t0, math.exp(g))[0] for g in pts]
    i = min(range(len(pts)), key=lambda j: vals[j])
    a, b = pts[max(0, i - 1)], pts[min(len(pts) - 1, i + 1)]
    g = (math.sqrt(5) - 1) / 2
    c, d = b - g * (b - a), a + g * (b - a)
    fc, fd = _ls(t, y, t0, math.exp(c))[0], _ls(t, y, t0, math.exp(d))[0]
    for _ in range(GOLDEN_ITERS):
        if b - a < tol:
            break
        if fc < fd:
            b, d, fd = d, c, fc
            c = b - g * (b - a)
            fc = _ls(t, y, t0, math.exp(c))[0]
        else:
            a, c, fc = c, d, fd
            d = a + g * (b - a)
            fd = _ls(t, y, t0, math.exp(d))[0]
    return math.exp((a + b) / 2)


# t(0.975, df) for df = 1..30; beyond, 1.96 + 2.4 / df is within 0.002.
_T975 = (12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
         2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042)


def _t975(df):
    return _T975[df - 1] if df <= len(_T975) else 1.96 + 2.4 / df


def _vif(t, resid, max_lag=60):
    """1 + 2 sum rho_k over the residuals' autocorrelation at whole sampling steps (the
    median step), summed while it stays positive: the variance inflation a correlated
    residual gives an estimate made from it. 1 for white residuals."""
    n = len(t)
    steps = sorted(b - a for a, b in zip(t, t[1:]))
    dt = steps[len(steps) // 2] if steps else 0
    var = math.fsum(r * r for r in resid) / n if n else 0
    if dt <= 0 or var <= 0:
        return 1.0
    total = 0.0
    for k in range(1, max_lag + 1):
        num, m, j = 0.0, 0, 0
        for i in range(n):
            while j < n and t[j] - t[i] < k * dt - dt / 2:
                j += 1
            if j < n and abs(t[j] - t[i] - k * dt) <= dt / 2:
                num += resid[i] * resid[j]
                m += 1
        if m < 10:
            break
        rho = num / m / var
        if rho <= 0:
            break
        total += rho
    return 1.0 + 2.0 * total


def _jackknife(t, y, t_step, blocks, order, lo_b, hi_b):
    """The half-width t(0.975, g-1) sd_jack of tau's delete-a-block jackknife over the G
    blocks (None under 3 blocks). A deleted block that leaves no reading after the step, or
    fewer than 10 readings, is skipped."""
    est = []
    for b in order:
        drop = set(blocks[b])
        tt = [ti for i, ti in enumerate(t) if i not in drop]
        yy = [yi for i, yi in enumerate(y) if i not in drop]
        if len(tt) < 10 or tt[-1] <= t_step or tt[0] >= t_step:
            continue
        est.append(_golden(tt, yy, t_step, lo_b, hi_b, grid=8, tol=1e-5))
    g = len(est)
    if g < 3:
        return None
    m = math.fsum(est) / g
    sd = math.sqrt((g - 1) / g * math.fsum((e - m) ** 2 for e in est))
    return _t975(g - 1) * sd


def fit_step(t, y, t_step, actuator, power_w=None, ambient=None, disturbances=None, sigma_noise=None,
             seed_key="fit_step", resamples=100, block_s=stats.BLOCK_S):
    """The first-order step fit of the module docstring. T and Y are equal-length sequences
    (seconds, readings) in time order; AMBIENT is None or [(t, room value)];
    DISTURBANCES [(t, kind)]. Returns StepFit or Refusal."""
    t = [float(x) for x in t]
    y = [float(x) for x in y]
    if len(t) != len(y) or len(t) < 10:
        return Refusal("NOT_ENOUGH_DATA", "fewer than 10 readings")
    if any(not math.isfinite(v) for v in t + y):
        return Refusal("NOT_ENOUGH_DATA", "a reading is not finite")
    if not (t[0] < t_step < t[-1]):
        return Refusal("NO_STEP", "no step inside the data")
    cls = ACTUATOR_CLASS.get(actuator, "excitation")
    if cls in AMBIENT_CLASSES and not ambient:
        return Refusal("NO_AMBIENT", REASONS["NO_AMBIENT"])
    pre = [(ti, yi) for ti, yi in zip(t, y) if ti <= t_step]
    if t_step - t[0] < MIN_BASELINE_S or len(pre) < 3:
        return Refusal("BASELINE", "a pre-step baseline of %.0f s, under %d s" % (t_step - t[0], MIN_BASELINE_S))
    window = t[-1] - t_step
    tau = _golden(t, y, t_step, TAU_MIN_S, max(10 * window, 100 * TAU_MIN_S))
    ssr, y0, K = _ls(t, y, t_step, tau)
    resid = [yi - y0 - K * ((1 - math.exp(-(ti - t_step) / tau)) if ti > t_step else 0.0) for ti, yi in zip(t, y)]
    sigma = sigma_noise if sigma_noise is not None else math.sqrt(ssr / max(1, len(t) - 3))
    if abs(K) < K_NOISE_FACTOR * sigma:
        return Refusal("SMALL_STEP", "the step K = %.3g is under %g x the noise %.3g" % (K, K_NOISE_FACTOR, sigma))
    if window < MIN_WINDOW_TAU * tau:
        return Refusal("SHORT_WINDOW", "%.0f s after the step, under %.1f x tau (%.0f s)" % (window, MIN_WINDOW_TAU,
                                                                                            tau))
    ps = stats.ols_line([p[0] for p in pre], [p[1] for p in pre])[1]
    if abs(ps) > abs(K) / (DRIFT_FACTOR * tau):
        return Refusal("BASELINE", "the baseline drifts (%.3g per s, over K / (20 tau) = %.3g)"
                       % (ps, abs(K) / (DRIFT_FACTOR * tau)))
    if ambient:
        before = [v for ta, v in ambient if ta < t[0]]
        vals = before[-1:] + [v for ta, v in ambient if t[0] <= ta <= t[-1]]
        if vals and max(vals) - min(vals) > abs(K) / K_NOISE_FACTOR:
            return Refusal("AMBIENT_CHANGE", "the room changed by %.3g in the window" % (max(vals) - min(vals)))
    for td, kind in disturbances or []:
        if t[0] <= td <= t[-1]:
            return Refusal("DISTURBANCE", "a %s at %.0f s lies in the window" % (kind, td))
    # residual block bootstrap
    fitted = [yi - r for yi, r in zip(y, resid)]
    blocks = {}
    for i, ti in enumerate(t):
        blocks.setdefault(int((ti - t[0]) // block_s), []).append(i)
    order = sorted(blocks)
    rng = stats.rng_for(seed_key, "tau")
    taus = []
    lo_b, hi_b = max(TAU_MIN_S, tau / 4), tau * 4
    for _ in range(resamples):
        pool = []
        for _b in order:
            pick = blocks[order[int(rng.random() * len(order))]]
            pool.extend(resid[j] for j in pick)
        ys = [f + pool[i % len(pool)] for i, f in enumerate(fitted)]
        taus.append(_golden(t, ys, t_step, lo_b, hi_b, grid=8, tol=1e-5))
    lo, hi = stats.percentile_ci(taus)
    # The residual bootstrap redraws residuals around this fit, which has already absorbed
    # the slow part of a wandering process term, so alone its interval is too narrow when
    # the readings wander (review of 20 Nov 2026: with the live AR(1) magnitude, 5 of 15
    # accepted 2-h fits missed tau). Two corrections, both 1 on white residuals:
    # - the delete-a-block jackknife (JACKKNIFE_BLOCKS x 10-min blocks) refits the readings
    #   themselves without each block, so a stretch whose wander pulled tau shows; the
    #   interval is the union of the bootstrap's and tau +- t(0.975, g-1) sd_jack;
    # - its half-widths are then scaled by sqrt(1 + 2 sum rho_k) of the residuals'
    #   autocorrelation (the variance inflation of a correlated residual).
    # On simulated 2-h steps with the live process term about 96 % of the accepted
    # intervals cover tau and a third are refused WIDE_CI; the protocol's 5-h step is
    # accepted (tests/test_research_calib_plant.py Coverage).
    jblocks = {}
    for i, ti in enumerate(t):
        jblocks.setdefault(int((ti - t[0]) // (JACKKNIFE_BLOCKS * block_s)), []).append(i)
    jk = _jackknife(t, y, t_step, jblocks, sorted(jblocks), lo_b, hi_b)
    if jk is not None:
        lo, hi = min(lo, tau - jk), max(hi, tau + jk)
    f = math.sqrt(_vif(t, resid))
    lo, hi = tau - f * (tau - lo), tau + f * (hi - tau)
    if (hi - lo) / 2 > MAX_CI_HALF * tau:
        return Refusal("WIDE_CI", "tau's 95 %% interval [%.0f, %.0f] s is wider than +-%d %% of %.0f s"
                       % (lo, hi, int(MAX_CI_HALF * 100), tau))
    c_a = power_w * tau / K if power_w is not None and K != 0 else None
    return StepFit(tau, y0, K, t_step, (lo, hi), sigma, len(t), c_a)


def mode_time_constants(p):
    """The two eigen time constants (s) of the air/substrate pair, fans off, door shut:
    (the air mode, the substrate mode). The air mode is the one a heater step on the air
    shows (8277 s at the defaults, against tau_air_s 8760 s)."""
    ca, cs = p.air_heat_capacity_j_per_k, p.substrate_heat_capacity_j_per_k
    g_as, g_sa = p.substrate_air_w_per_k, p.substrate_ambient_w_per_k
    a11 = -1.0 / p.tau_air_s
    a12 = g_as / ca
    a21 = g_as / cs
    a22 = -(g_as + g_sa) / cs
    tr, det = a11 + a22, a11 * a22 - a12 * a21
    disc = math.sqrt(max(0.0, tr * tr / 4 - det))
    l1, l2 = tr / 2 + disc, tr / 2 - disc
    taus = sorted((-1.0 / l1, -1.0 / l2), key=lambda x: abs(x - p.tau_air_s))
    return taus[0], taus[1]
