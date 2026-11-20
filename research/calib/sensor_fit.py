"""The sensor estimators (design §2, revised by §9 R1-R7 and R10).

fit(header, rows, sensor_map, reference, humidity_model) reads one dataset (its header and
rows, as dataset.read gives them) and returns, for each mapped model sensor (a
twin_plant.sensors.default_specs() id), one entry per SensorSpec field:

    {value, source, applied, ...}       an estimate (applied: it changes the model)
    {source, applied: false, why}       a refusal: the default stays

Sources: fitted | fitted_confounded | chosen | datasheet | not_identifiable |
not_enough_data. Every number is rounded to 6 significant digits (stats.sig6) before it is
compared or written, and every interval comes from a block bootstrap (10-minute blocks,
200 resamples) seeded from sha256(<content_sha256>:<field>), so the same dataset gives
the same file.

The rules, in short (the design says why):
- cycles are keyed by measured_at (R1); the cadence, segments and outages come from
  segments.Board (R2); a field needs a segment of 1 h or more and 1000 cycles of its
  sensor (500 pairs for an offset), or it is refused not_enough_data;
- publish_interval_s: the mean of the normal differences of the sensor's cycle times
  (refused when their coefficient of variation is over 0.5); jitter, skipped cycles and
  reboots go under unmodelled;
- start_offset_s: 0 for every sensor, chosen (R4: one cycle, one timestamp);
- latency_s: median(ingested_at - measured_at) - 0.5 s (measured_at is truncated to the
  second), fitted_confounded (it includes the board clock's offset); refused beyond
  1800 s or below -2 s (a wrong clock or time zone);
- quantisation: the largest of 0.01..1 that every value is a multiple of;
- noise_sd (R5): the structure function v_k = Var_trim(y[i+k] - 2y[i] + y[i-k]) / 6
  (trimmed beyond 5 x IQR, the IQR at least 2 lattice steps),
  k = 1..4, fitted as sigma_n^2 + q^2/12 + c k by weighted least squares; refused when
  the lag-1 autocorrelation of the first differences is positive beyond sampling error
  (white noise plus a slow process gives -0.5..0: a positive one is filtered noise, not
  separable from process variation), when the fit is poor (relative residual > 0.25), or
  when the intercept's interval reaches 0; c goes under unmodelled; a significant excess
  of repeated values (binomial test, p < 0.001) and a non-uniform last digit (chi-square,
  p < 0.001) are recorded, never acted on;
- noise_rel_sd: 0 (the fitted noise_sd holds the whole noise) unless the per-decile noise
  grows with the value beyond its bootstrap interval, which is recorded and not applied;
- bias: the reference sensor's tags are 0 (chosen; absolute accuracy unknown); another
  sensor's tag shared with the reference is the median paired difference (pairs share a
  measured_at); a tag no second sensor publishes stays 0, not_identifiable;
- humidity_model (R7, chosen): constant_offset (bias T = dT, bias RH = median dRH; the
  default) or self_heating (self_heating_c = dT, bias T = 0, bias RH = the self-heating
  model's median residual); both models' residuals, slopes and predicted offsets are
  recorded, and validity.air_humidity is the reference's observed range;
- bias_sd (R6): the datasheet accuracy a as a/2 (SHT45 T and RH; the SCD30's CO2 at the
  observed median), source datasheet;
- dropout_p (R3): a (sensor, tag) missing from a cycle in which the sensor published
  another tag, over every such chance; Wilson interval.

A positive estimate whose interval is wider than itself is marked weak and not applied.
"""
from __future__ import annotations

import math

from ..twin_plant import sensors as sensors_mod
from ..twin_plant.chamber import saturation_density
from . import segments, stats

MIN_SEGMENT_S = 3600.0
MIN_EVENTS = 1000
MIN_PAIRS = 500
CV_MAX = 0.5
LATENCY_MAX_S = 1800.0
LATENCY_MIN_S = -2.0
TRUNCATION_S = 0.5
QSTEPS = (100, 50, 25, 10, 5, 2, 1)          # hundredths: 1, 0.5, 0.25, 0.1, 0.05, 0.02, 0.01
LAGS = (1, 2, 3, 4)
REL_RESID_MAX = 0.25
P_FLAG = 0.001
RH_POINTS = (50, 70, 85, 95)
HUMIDITY_MODELS = ("constant_offset", "self_heating")
SOURCES = ("fitted", "fitted_confounded", "chosen", "datasheet", "assumed", "spec", "not_identifiable",
           "not_enough_data")
DICT_FIELDS = ("quantisation", "noise_sd", "noise_rel_sd", "bias", "bias_sd")
SCALAR_FIELDS = ("publish_interval_s", "start_offset_s", "latency_s", "dropout_p", "self_heating_c")
LATENCY_NOTE = "includes the board clock's offset; not separable without a trusted publish time"

# Datasheet accuracy as a/2 (R6). SHT45: +-0.1 C, +-1.0 %RH typical. SCD30 CO2: +-(30 ppm + 3 %).
DATASHEET_BIAS_SD = {"sht45": {"air_temperature": 0.05, "air_humidity": 0.5}}
SCD30_CO2_ACCURACY = (30.0, 0.03)


class FitError(ValueError):
    """A fit that cannot start (a bad map, a sensor the dataset lacks)."""


def entry(value, source, applied=True, **extra):
    e = {"value": stats.sig6(value), "source": source, "applied": bool(applied)}
    for k, v in extra.items():
        if v is not None:
            e[k] = v
    return e


def refused(source, why):
    return {"source": source, "applied": False, "why": why}


def _ci(lo, hi):
    return [stats.sig6(lo), stats.sig6(hi)]


def _weak(e):
    """Mark a positive estimate whose 95 % interval is wider than itself weak, not applied."""
    ci = e.get("ci95")
    if e.get("applied") and ci and e["value"] > 0 and (ci[1] - ci[0]) > e["value"]:
        e["applied"] = False
        e["weak"] = True
        e["why"] = "weak: the 95 %% interval [%s, %s] is wider than the value; the default stays" % (ci[0], ci[1])
    return e


def default_specs():
    return {s.sensor_id: s for s in sensors_mod.default_specs()}


def parse_map(text):
    """'sht45=sht45_1,scd30=scd30_1' -> {model id: lake sensor}."""
    out = {}
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if part.count("=") != 1:
            raise FitError("--map takes model=lake pairs, e.g. sht45=sht45_1,scd30=scd30_1")
        k, v = (x.strip() for x in part.split("="))
        if not k or not v or k in out:
            raise FitError("--map: %r is empty or given twice" % part)
        out[k] = v
    if not out:
        raise FitError("--map names no sensor")
    return out


# ── the fit ─────────────────────────────────────────────────────────────────────────
class _Ctx:
    def __init__(self, board, content_sha256, resamples):
        self.board = board
        self.sha = content_sha256
        self.resamples = resamples
        segs = board.segments
        self.segments = segs
        self.long = [s for s in segs if board.cycles[s[1]]["t"] - board.cycles[s[0]]["t"] >= MIN_SEGMENT_S]
        self.limit = (board.cadence["nominal"] or 0) * segments.NORMAL_FACTOR

    def rng(self, field):
        return stats.rng_for(self.sha, field)

    def block(self, seg_index, t):
        seg0 = self.board.cycles[self.segments[seg_index][0]]["t"]
        return (seg_index, int((t - seg0) // stats.BLOCK_S))


def _boot(ctx, field, blocks, stat):
    """Bootstrap STAT over BLOCKS (a list of per-block sufficient statistics)."""
    rng = ctx.rng(field)
    out = []
    n = len(blocks)
    for _ in range(ctx.resamples):
        idx = stats.resample_blocks(n, rng)
        v = stat([blocks[i] for i in idx])
        if v is not None:
            out.append(v)
    if len(out) < ctx.resamples // 2:
        return None
    return stats.percentile_ci(out)


def _cycle_time(c, sensor):
    return min(v[1] for v in c["s"][sensor].values())


def _sensor_cycles(ctx, sensor):
    """[(segment index, cycle)] of the sensor, every segment."""
    out = []
    for k, seg in enumerate(ctx.segments):
        for c in ctx.board.sensor_cycles(sensor, seg):
            out.append((k, c))
    return out


def _fit_interval(ctx, model, sensor, cycles, unmodelled):
    diffs = []
    skipped = []
    prev = None
    for k, c in cycles:
        t = _cycle_time(c, sensor)
        if prev is not None and prev[0] == k:
            d = t - prev[1]
            if d <= ctx.limit:
                diffs.append((k, t, d))
            else:
                skipped.append(d)
        prev = (k, t)
    if len(diffs) < MIN_EVENTS:
        return refused("not_enough_data", "%d normal cycle differences, %d needed" % (len(diffs), MIN_EVENTS))
    ds = [d for _, _, d in diffs]
    m = stats.mean(ds)
    sd = math.sqrt(stats.variance(ds))
    cv = sd / m if m > 0 else float("inf")
    if not math.isfinite(cv) or cv > CV_MAX:
        return refused("fitted", "no regular schedule: the differences' coefficient of variation is %.3g (over %s)"
                       % (cv, CV_MAX))
    blocks = {}
    for k, t, d in diffs:
        b = blocks.setdefault(ctx.block(k, t), [0, 0.0])
        b[0] += 1
        b[1] += d
    ci = _boot(ctx, "%s.publish_interval_s" % model, list(blocks.values()),
               lambda bs: math.fsum(b[1] for b in bs) / sum(b[0] for b in bs))
    srt = sorted(ds)
    med = stats.median(srt, True)
    unmodelled.append({"what": "publish jitter", "sensor": model, "median_s": stats.sig6(med),
                       "sd_s": stats.sig6(1.4826 * stats.mad(ds)), "mean_s": stats.sig6(m)})
    total = len(diffs) + len(skipped)
    reboots = sum(1 for d in skipped if d >= segments.REBOOT_MIN_S)
    unmodelled.append({"what": "skipped cycles", "sensor": model, "rate": stats.sig6(len(skipped) / total),
                       "skipped": len(skipped), "of": total,
                       "reboot_signature": {"gaps_30_60_s": reboots,
                                            "note": "a board restart shows as one gap of 30-60 s"}})
    if not ci:
        return refused("not_enough_data", "too few 10-minute blocks for an interval")
    return _weak(entry(m, "fitted", ci95=_ci(*ci), n=len(diffs), cv=stats.sig6(cv)))


def _fit_latency(ctx, sensor, cycles):
    ds = []
    for _, c in cycles:
        m_rel = (c["m"] - ctx.board.origin_us) / 1e6
        for v in c["s"][sensor].values():
            ds.append(v[1] - m_rel)
    if len(ds) < MIN_EVENTS:
        return refused("not_enough_data", "%d readings, %d needed" % (len(ds), MIN_EVENTS))
    s = sorted(ds)
    p50 = stats.median(s, True)
    pct = {"p5": stats.sig6(stats.quantile(s, 0.05, True)), "p50": stats.sig6(p50),
           "p95": stats.sig6(stats.quantile(s, 0.95, True))}
    if p50 > LATENCY_MAX_S or p50 < LATENCY_MIN_S:
        e = refused("fitted_confounded", "the median of ingested_at - measured_at is %.6g s: the board's clock or "
                    "its time zone is wrong, and a latency would be silently wrong" % p50)
        e.update(pct)
        return e
    return entry(max(0.0, p50 - TRUNCATION_S), "fitted_confounded", note=LATENCY_NOTE, **pct)


def _values(ctx, sensor, tag):
    out = []
    for seg in ctx.segments:
        out.extend(h for _, h in ctx.board.series(sensor, tag, seg))
    return out


def _fit_quantisation(values):
    if len(values) < MIN_EVENTS:
        return refused("not_enough_data", "%d readings, %d needed" % (len(values), MIN_EVENTS)), None
    for q in QSTEPS:
        if all(v % q == 0 for v in values):
            return entry(q / 100.0, "fitted", n=len(values)), q
    return refused("fitted", "no step of 0.01 or more divides every value"), None   # unreachable: 1 divides all


def _lattice(model, tag, values, unmodelled):
    counts = [0] * 10
    for v in values:
        counts[abs(v) % 10] += 1
    stat, df, p = stats.chi2_uniform(counts)
    if p < P_FLAG:
        unmodelled.append({"what": "the sensor's own resolution is not a clean 0.01 lattice", "sensor": model,
                           "tag": tag, "chi2": stats.sig6(stat), "df": df, "p": stats.sig6(p),
                           "last_digit_counts": counts})


def _structure(vk):
    """(intercept, slope, weights) of the WLS line through v_k = a + c k, w_k = n_k / v_k^2."""
    xs, ys, ws = [], [], []
    for k in LAGS:
        n, v = vk[k]
        if n < 3 or v is None or v <= 0:
            return None
        xs.append(float(k))
        ys.append(v)
        ws.append(n / (v * v))
    a, c = stats.wls_line(xs, ys, ws)
    return a, c


def _vk_from(blocks):
    vk = {}
    for k in LAGS:
        n = sum(b[k][0] for b in blocks)
        s = math.fsum(b[k][1] for b in blocks)
        ss = math.fsum(b[k][2] for b in blocks)
        vk[k] = (n, ((ss - s * s / n) / (n - 1)) / 6.0 if n > 2 else None)
    return vk


def _fit_noise(ctx, model, sensor, tag, q_h, unmodelled):
    """noise_sd of one (sensor, tag) by the structure function (R5)."""
    kmax = max(LAGS)
    d2 = {k: [] for k in LAGS}
    centres = []
    d1 = []
    d1_pairs = []
    for si, seg in enumerate(ctx.segments):
        ser = ctx.board.series(sensor, tag, seg)
        ys = [h / 100.0 for _, h in ser]
        ts = [t for t, _ in ser]
        seg_d1 = [ys[i + 1] - ys[i] for i in range(len(ys) - 1)]
        d1.extend(seg_d1)
        d1_pairs.extend(zip(seg_d1, seg_d1[1:]))
        for i in range(kmax, len(ys) - kmax):
            centres.append((ctx.block(si, ts[i]), ys[i]))
            for k in LAGS:
                d2[k].append(ys[i + k] - 2 * ys[i] + ys[i - k])
    n = len(centres)
    if n < MIN_EVENTS:
        return refused("not_enough_data", "%d usable cycles, %d needed" % (n, MIN_EVENTS)), None
    q = q_h / 100.0
    # lag-1 autocorrelation of the first differences
    m1 = stats.mean(d1)
    den = math.fsum((x - m1) ** 2 for x in d1)
    r1 = (math.fsum((a - m1) * (b - m1) for a, b in d1_pairs) / den) if den > 0 else 0.0
    if r1 > 3.0 / math.sqrt(len(d1)):
        e = refused("not_identifiable",
                    "noise not separable from filtered process variation: the first differences' lag-1 "
                    "autocorrelation is %+.3g (white noise plus a slow process gives -0.5..0)" % r1)
        e["d1_autocorrelation"] = stats.sig6(r1)
        return e, None
    bounds = {k: stats.trim_bounds(d2[k], 2 * q) for k in LAGS}
    trimmed = {k: 0 for k in LAGS}
    blocks = {}
    for idx, (b, _) in enumerate(centres):
        st = blocks.get(b)
        if st is None:
            st = blocks[b] = {k: [0, 0.0, 0.0] for k in LAGS}
        for k in LAGS:
            x = d2[k][idx]
            lo, hi = bounds[k]
            if x < lo or x > hi:
                trimmed[k] += 1
                continue
            s = st[k]
            s[0] += 1
            s[1] += x
            s[2] += x * x
    blist = list(blocks.values())
    vk = _vk_from(blist)
    fit = _structure(vk)
    info = {"d1_autocorrelation": stats.sig6(r1),
            "v_k": [stats.sig6(vk[k][1]) for k in LAGS],
            "trimmed": [trimmed[k] for k in LAGS], "n": n}
    if fit is None:
        return dict(refused("fitted", "a lag's variance is zero: no noise to fit"), **info), None
    a, c = fit
    pred = {k: a + c * k for k in LAGS}
    rel = max(abs(vk[k][1] - pred[k]) / vk[k][1] for k in LAGS)
    info["relative_residual"] = stats.sig6(rel)
    info["lag_ratio"] = [stats.sig6(math.sqrt(vk[k][1] / vk[1][1])) for k in LAGS]
    if rel > REL_RESID_MAX:
        return dict(refused("fitted", "the structure function is not a straight line in the lag (relative "
                            "residual %.3g > %s)" % (rel, REL_RESID_MAX)), **info), None
    sn2 = a - q * q / 12.0

    def stat(bs):
        f = _structure(_vk_from(bs))
        return None if f is None else f[0] - q * q / 12.0
    ci = _boot(ctx, "%s.noise_sd.%s" % (model, tag), blist, stat)
    if ci is None:
        return dict(refused("not_enough_data", "too few 10-minute blocks for an interval"), **info), None
    if ci[0] <= 0 or sn2 <= 0:
        return dict(refused("fitted", "the noise variance's 95 %% interval [%.3g, %.3g] reaches 0: the noise is "
                            "not separable from the quantisation and the process" % (ci[0], ci[1])), **info), None
    if c > 0:
        unmodelled.append({"what": "fast process variation not in the model", "sensor": model, "tag": tag,
                           "variance_per_cycle": stats.sig6(3 * c)})
    sigma = math.sqrt(sn2)
    # stale values: more repeated readings than the noise and the lattice explain
    zeros = sum(1 for x in d1 if abs(x) < q / 2)
    p0 = stats.p_zero_difference(math.sqrt(max(0.0, 2 * sn2 + 3 * max(c, 0.0))), q)
    p = stats.binomial_excess_p(zeros, len(d1), p0)
    info["repeats"] = {"observed": zeros, "of": len(d1), "expected": stats.sig6(p0 * len(d1))}
    if p < P_FLAG:
        unmodelled.append({"what": "repeated values beyond what the noise and the lattice explain",
                           "sensor": model, "tag": tag, "observed": zeros, "expected": stats.sig6(p0 * len(d1)),
                           "of": len(d1), "p": stats.sig6(p)})
    e = entry(sigma, "fitted", ci95=_ci(math.sqrt(ci[0]), math.sqrt(ci[1])), **info)
    return _weak(e), (centres, d2[1], blist, sn2)


def _fit_rel_noise(ctx, model, tag, noise_entry, raw):
    """noise_rel_sd: 0 unless the noise grows with the value (recorded, not applied)."""
    if not noise_entry.get("applied") or raw is None:
        return refused("not_identifiable", "noise_sd %s was not applied: the datasheet noise stays" % tag)
    centres, d21, _, _ = raw
    vals = sorted(abs(v) for _, v in centres)
    edges = [stats.quantile(vals, i / 10.0, True) for i in range(11)]

    def bin_of(v):
        for i in range(10):
            if v <= edges[i + 1]:
                return i
        return 9
    blocks = {}
    for (b, v), x in zip(centres, d21):
        st = blocks.setdefault(b, [[0, 0.0, 0.0, 0.0] for _ in range(10)])
        s = st[bin_of(abs(v))]
        s[0] += 1
        s[1] += x
        s[2] += x * x
        s[3] += abs(v)

    def slope(bs):
        xs, ys = [], []
        for i in range(10):
            n = sum(b[i][0] for b in bs)
            if n < 3:
                continue
            s = math.fsum(b[i][1] for b in bs)
            ss = math.fsum(b[i][2] for b in bs)
            xs.append(math.fsum(b[i][3] for b in bs) / n)
            ys.append(math.sqrt(max(0.0, (ss - s * s / n) / (n - 1) / 6.0)))
        if len(xs) < 3 or max(xs) == min(xs):
            return None
        return stats.ols_line(xs, ys)[1]
    blist = list(blocks.values())
    b = slope(blist)
    ci = _boot(ctx, "%s.noise_rel_sd.%s" % (model, tag), blist, slope)
    if b is None or ci is None:
        return refused("not_identifiable", "heteroscedasticity: the values do not spread over enough bins")
    if ci[0] > 0 or ci[1] < 0:
        e = entry(b, "fitted", applied=False, ci95=_ci(*ci),
                  why="the noise grows with the value, but splitting it from noise_sd is not fitted "
                      "(CALIB_VERSION 1): noise_sd holds the average over the observed range")
        return e
    return entry(0.0, "not_identifiable", ci95=_ci(*ci), why="heteroscedasticity: the slope's 95 % interval "
                 "includes 0, so the fitted noise_sd holds the whole noise")


def _pairs(ctx, ref, other, tag):
    """[(block, t, reference value, other value)] of cycles in which both published TAG."""
    out = []
    for si, seg in enumerate(ctx.segments):
        i0, i1 = seg
        for c in ctx.board.cycles[i0:i1 + 1]:
            a = c["s"].get(ref, {}).get(tag)
            b = c["s"].get(other, {}).get(tag)
            if a is not None and b is not None:
                out.append((ctx.block(si, c["t"]), c["t"], a[0] / 100.0, b[0] / 100.0))
    return out


def _median_ci(ctx, field, keyed):
    """Median of the values with a block-bootstrap interval; KEYED is [(block, value)]."""
    blocks = {}
    for b, v in keyed:
        blocks.setdefault(b, []).append(v)
    blist = list(blocks.values())
    med = stats.median([v for _, v in keyed])
    ci = _boot(ctx, field, blist, lambda bs: stats.median([v for b in bs for v in b]))
    return med, ci


def _rh_pred(rh, t, dt):
    return rh * saturation_density(t) / saturation_density(t + dt)


def _fit_relative(ctx, model, sensor, ref_model, ref_sensor, other_tags, humidity_model, result):
    """bias (and self_heating_c) of a non-reference sensor against the reference."""
    bias = result["bias"]
    rel = {}
    shared = [t for t in other_tags if t in ctx.board.tags_of(ref_sensor)]
    for tag in other_tags:
        if tag not in shared:
            bias[tag] = entry(0.0, "not_identifiable",
                              why="no second sensor publishes %s, so its offset cannot be seen" % tag)
    pairs = {tag: _pairs(ctx, ref_sensor, sensor, tag) for tag in shared}
    for tag in shared:
        if len(pairs[tag]) < MIN_PAIRS:
            bias[tag] = refused("not_enough_data", "%d paired cycles, %d needed" % (len(pairs[tag]), MIN_PAIRS))
    ok = {t for t in shared if len(pairs[t]) >= MIN_PAIRS}
    d = {}
    for tag in sorted(ok):
        med, ci = _median_ci(ctx, "%s.bias.%s" % (model, tag), [(b, y - x) for b, _, x, y in pairs[tag]])
        d[tag] = (med, ci, len(pairs[tag]))
        bias[tag] = entry(med, "fitted", ci95=_ci(*ci) if ci else None, n=len(pairs[tag]),
                          relative_to=ref_model)
    humid = "air_temperature" in ok and "air_humidity" in ok
    if not humid:
        if "self_heating_c" not in result:
            result["self_heating_c"] = refused("not_enough_data",
                                               "self-heating needs paired air_temperature and air_humidity")
        return None
    dT = d["air_temperature"][0]
    # the paired cycles with both tags on both sensors
    both = []
    for si, seg in enumerate(ctx.segments):
        i0, i1 = seg
        for c in ctx.board.cycles[i0:i1 + 1]:
            a, b = c["s"].get(ref_sensor, {}), c["s"].get(sensor, {})
            if all(k in a and k in b for k in ("air_temperature", "air_humidity")):
                both.append((ctx.block(si, c["t"]), a["air_temperature"][0] / 100.0, a["air_humidity"][0] / 100.0,
                             b["air_humidity"][0] / 100.0))
    sh_resid = [(blk, rh_o - _rh_pred(rh_r, t_r, dT)) for blk, t_r, rh_r, rh_o in both]
    sh_med, sh_ci = _median_ci(ctx, "%s.self_heating_residual" % model, sh_resid)
    dRH = d["air_humidity"][0]
    co_resid = stats.median([rh_o - rh_r - dRH for _, _, rh_r, rh_o in both])
    xs = [rh_r for _, _, rh_r, _ in both]
    ys = [rh_o - rh_r for _, _, rh_r, rh_o in both]
    slope_obs = stats.ols_line(xs, ys)[1] if max(xs) > min(xs) else 0.0
    t_med = stats.median([t_r for _, t_r, _, _ in both])
    k = saturation_density(t_med) / saturation_density(t_med + dT)
    rel = {"relative_to": ref_model, "pairs": len(both),
           "dT": {"value": stats.sig6(dT), "ci95": bias["air_temperature"].get("ci95")},
           "dRH": {"value": stats.sig6(dRH), "ci95": bias["air_humidity"].get("ci95")},
           "slope_dRH_vs_RH": {"observed": stats.sig6(slope_obs), "self_heating": stats.sig6(k - 1.0),
                               "constant_offset": 0.0},
           "residual_median": {"self_heating": stats.sig6(sh_med), "constant_offset": stats.sig6(co_resid)},
           "predicted_offset_at_rh": {
               "temperature": stats.sig6(t_med),
               "self_heating": {str(r): stats.sig6(r * k - r + sh_med) for r in RH_POINTS},
               "constant_offset": {str(r): stats.sig6(dRH) for r in RH_POINTS}},
           "humidity_model": humidity_model}
    result["humidity_model"] = {"value": humidity_model, "source": "chosen",
                                "why": "R7: both models are recorded; self-heating explains only part of the "
                                       "slope of dRH against RH, so the choice is the user's"}
    sh = entry(dT, "fitted", applied=humidity_model == "self_heating",
               ci95=bias["air_temperature"].get("ci95"), rh_residual=stats.sig6(sh_med))
    if humidity_model == "self_heating":
        bias["air_temperature"] = entry(0.0, "chosen", why="the self-heating (self_heating_c) carries dT")
        bias["air_humidity"] = entry(sh_med, "fitted", ci95=_ci(*sh_ci) if sh_ci else None, n=len(both),
                                     relative_to=ref_model,
                                     why="the self-heating model's median residual")
    else:
        sh["why"] = "humidity_model constant_offset: the offsets are in bias"
    result["self_heating_c"] = sh
    return rel


def fit(header, rows, sensor_map, reference="sht45", humidity_model="constant_offset",
        resamples=stats.BOOT_RESAMPLES):
    """The sensor fit of one dataset (module docstring). Returns
    {sensors, relative, validity, unmodelled, window, segments, outages, refused_sensors}."""
    specs = default_specs()
    if humidity_model not in HUMIDITY_MODELS:
        raise FitError("--humidity-model must be one of " + ", ".join(HUMIDITY_MODELS))
    for model in sensor_map:
        if model not in specs:
            raise FitError("--map: %s is not a model sensor (%s)" % (model, ", ".join(sorted(specs))))
    if reference not in sensor_map:
        raise FitError("the reference %s is not in --map" % reference)
    lake_sensors = {r["sensor"] for r in rows}
    for model, lake in sensor_map.items():
        if lake not in lake_sensors:
            raise FitError("the dataset has no sensor %s (it has %s)" % (lake, ", ".join(sorted(lake_sensors))))
    board = segments.Board(rows, list(sensor_map.values()))
    ctx = _Ctx(board, header["content_sha256"], resamples)
    unmodelled = []
    out = {}
    relative = {}
    enough = bool(ctx.long)
    for model in sorted(sensor_map, key=lambda m: (m != reference, m)):
        sensor = sensor_map[model]
        spec = specs[model]
        tags = [t for t in spec.tags if t in board.tags_of(sensor)]
        extra = sorted(set(board.tags_of(sensor)) - set(spec.tags))
        if extra:
            raise FitError("sensor %s publishes %s, which the model sensor %s does not"
                           % (sensor, ", ".join(extra), model))
        r = {"quantisation": {}, "noise_sd": {}, "noise_rel_sd": {}, "bias": {}, "bias_sd": {}}
        out[model] = r
        r["start_offset_s"] = entry(0.0, "chosen", why="R4: every sensor of the board shares one cycle and one "
                                    "measured_at; the whole delay is in latency_s")
        cycles = _sensor_cycles(ctx, sensor)
        if not enough:
            why = "no segment of %d s or more (the longest: %.0f s)" % (
                MIN_SEGMENT_S, max(board.cycles[b]["t"] - board.cycles[a]["t"] for a, b in ctx.segments))
            for f in ("publish_interval_s", "latency_s", "dropout_p"):
                r[f] = refused("not_enough_data", why)
            for tag in tags:
                for f in ("quantisation", "noise_sd"):
                    r[f][tag] = refused("not_enough_data", why)
            r["bias_sd"] = _bias_sd(spec, None, tags)
            continue
        r["publish_interval_s"] = _fit_interval(ctx, model, sensor, cycles, unmodelled)
        r["latency_s"] = _fit_latency(ctx, sensor, cycles)
        r["dropout_p"] = _fit_dropout(model, sensor, cycles, tags)
        raw = {}
        for tag in tags:
            values = _values(ctx, sensor, tag)
            qe, q_h = _fit_quantisation(values)
            r["quantisation"][tag] = qe
            if q_h is None:
                r["noise_sd"][tag] = refused("not_enough_data", "the quantisation was not fitted")
                continue
            if q_h == 1:
                _lattice(model, tag, values, unmodelled)
            ne, raw[tag] = _fit_noise(ctx, model, sensor, tag, q_h, unmodelled)
            r["noise_sd"][tag] = ne
            if tag in spec.noise_rel_sd:
                r["noise_rel_sd"][tag] = _fit_rel_noise(ctx, model, tag, ne, raw.get(tag))
        if model == reference:
            for tag in tags:
                r["bias"][tag] = entry(0.0, "chosen", why="the reference: offsets are relative to it; its "
                                       "absolute accuracy is unknown (no reference instrument)")
        else:
            rel = _fit_relative(ctx, model, sensor, reference, sensor_map[reference], tags, humidity_model, r)
            if rel:
                relative[model] = rel
        co2 = _values(ctx, sensor, "co2") if "co2" in tags else []
        r["bias_sd"] = _bias_sd(spec, stats.median(co2) / 100.0 if co2 else None, tags)
        if "self_heating_c" not in r and model != reference:
            r["self_heating_c"] = refused("not_enough_data", "self-heating needs paired air_temperature and "
                                          "air_humidity")
    validity = {}
    ref_sensor = sensor_map[reference]
    if "air_humidity" in board.tags_of(ref_sensor) and enough:
        v = _values(ctx, ref_sensor, "air_humidity")
        validity["air_humidity"] = [stats.sig6(min(v) / 100.0), stats.sig6(max(v) / 100.0)]
    if relative:
        unmodelled.append({"what": "correlated absolute error", "sensor": ",".join(sorted(relative)),
                           "note": "a sensor's absolute temperature and humidity error is correlated with the "
                                   "reference's through the fitted relative offset; not modelled (R6)"})
    refused_sensors = [m for m, r in out.items() if not any(
        e.get("source") in ("fitted", "fitted_confounded") and "value" in e for e in _entries(r))]
    segs = [{"from": board.ts(board.cycles[a]["t"]), "to": board.ts(board.cycles[b]["t"]),
             "events": {sensor_map[m]: sum(1 for c in board.cycles[a:b + 1] if sensor_map[m] in c["s"])
                        for m in sorted(sensor_map)}}
            for a, b in board.segments]
    return {"sensors": out, "relative": relative, "validity": validity, "unmodelled": unmodelled,
            "window": {"from": segments.format_us(board.cycles[0]["m"]),
                       "to": segments.format_us(board.cycles[-1]["m"])},
            "segments": segs, "outages": segments.outage_records(board, header.get("lake", {}).get("cut_at")),
            "cadence": {"nominal_s": board.cadence["nominal"], "skipped_hist": board.cadence["skipped_hist"],
                        "outage_hist": board.cadence["outage_hist"]},
            "refused_sensors": refused_sensors}


def _entries(r):
    for k, v in r.items():
        if k in DICT_FIELDS:
            yield from v.values()
        elif isinstance(v, dict) and "source" in v:
            yield v


def _fit_dropout(model, sensor, cycles, tags):
    if len(cycles) < MIN_EVENTS:
        return refused("not_enough_data", "%d cycles, %d needed" % (len(cycles), MIN_EVENTS))
    trials = len(cycles) * len(tags)
    misses = sum(1 for _, c in cycles for t in tags if t not in c["s"][sensor])
    p = misses / trials
    lo, hi = stats.wilson(misses, trials)
    return _weak(entry(p, "fitted", ci95=_ci(lo, hi), misses=misses, of=trials))


def _bias_sd(spec, co2_median, tags):
    out = {}
    for tag, sd in DATASHEET_BIAS_SD.get(spec.kind, {}).items():
        if tag in tags:
            out[tag] = entry(sd, "datasheet", why="the datasheet accuracy a as a/2 (R6)")
    if spec.kind == "scd30" and "co2" in tags:
        if co2_median is None:
            out["co2"] = refused("not_enough_data", "no CO2 level to take the 3 % part at")
        else:
            a = SCD30_CO2_ACCURACY[0] + SCD30_CO2_ACCURACY[1] * co2_median
            out["co2"] = entry(a / 2.0, "datasheet", at_ppm=stats.sig6(co2_median),
                               why="SCD30 +-(30 ppm + 3 %) at the observed median, as a/2 (R6)")
    return out
