"""Small, deterministic statistics for the fits (standard library only).

- quantile (linear interpolation between order statistics, R's type 7), median, MAD;
- trimmed variance (values beyond 5 x IQR of the quartiles dropped, design §9 R5);
- the Wilson score interval of a proportion;
- a block bootstrap whose only random call is int(rng.random() * n) (design §9 R10),
  from a random.Random seeded by sha256(<content_sha256>:<field>): the same dataset gives
  the same intervals on every machine and Python version;
- weighted least squares of a straight line;
- chi-square and normal tail probabilities (a lattice test, a binomial excess test);
- sig6(): every fitted number and interval bound is rounded to 6 significant digits
  before it is compared or written.
"""
from __future__ import annotations

import hashlib
import math
import random

TRIM_IQR = 5.0
BOOT_RESAMPLES = 200
BLOCK_S = 600.0


def sig6(x):
    """x rounded to 6 significant digits (a float; 0.0 stays 0.0). ValueError for a
    non-finite x: nothing silently wrong is ever written."""
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
        raise ValueError("not a finite number: %r" % (x,))
    if x == 0:
        return 0.0
    return float("%.6g" % x)


def mean(xs):
    xs = list(xs)
    if not xs:
        raise ValueError("mean of nothing")
    return math.fsum(xs) / len(xs)


def variance(xs):
    xs = list(xs)
    if len(xs) < 2:
        raise ValueError("variance needs two values")
    m = mean(xs)
    return math.fsum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def quantile(xs, p, presorted=False):
    s = xs if presorted else sorted(xs)
    if not s:
        raise ValueError("quantile of nothing")
    if not 0.0 <= p <= 1.0:
        raise ValueError("p must be within 0..1")
    h = (len(s) - 1) * p
    lo = int(math.floor(h))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (h - lo) * (s[hi] - s[lo])


def median(xs, presorted=False):
    return quantile(xs, 0.5, presorted)


def mad(xs):
    m = median(xs)
    return median([abs(x - m) for x in xs])


def trim_bounds(xs, floor=0.0):
    """(lo, hi): Q1 - 5 IQR and Q3 + 5 IQR, the IQR taken as at least FLOOR (on a lattice
    coarser than the noise most differences are 0 and the IQR with them)."""
    s = sorted(xs)
    q1, q3 = quantile(s, 0.25, True), quantile(s, 0.75, True)
    iqr = max(q3 - q1, floor)
    return q1 - TRIM_IQR * iqr, q3 + TRIM_IQR * iqr


def wilson(k, n, z=1.959963984540054):
    """The Wilson score interval (95 % by default) of k successes in n trials."""
    if n <= 0:
        raise ValueError("wilson needs n > 0")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    lo = 0.0 if k == 0 else max(0.0, c - h)
    hi = 1.0 if k == n else min(1.0, c + h)
    return lo, hi


def rng_for(content_sha256, field):
    """The bootstrap's random source for one field of one dataset."""
    digest = hashlib.sha256(("calib:%s:%s" % (content_sha256, field)).encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def resample_blocks(nblocks, rng):
    """One bootstrap resample: nblocks block indices drawn with replacement."""
    return [int(rng.random() * nblocks) for _ in range(nblocks)]


def percentile_ci(values, level=0.95):
    s = sorted(values)
    a = (1 - level) / 2
    return quantile(s, a, True), quantile(s, 1 - a, True)


def wls_line(xs, ys, ws):
    """(intercept, slope) of y = a + b x by weighted least squares."""
    sw = math.fsum(ws)
    sx = math.fsum(w * x for w, x in zip(ws, xs))
    sy = math.fsum(w * y for w, y in zip(ws, ys))
    sxx = math.fsum(w * x * x for w, x in zip(ws, xs))
    sxy = math.fsum(w * x * y for w, x, y in zip(ws, xs, ys))
    det = sw * sxx - sx * sx
    if det == 0:
        raise ValueError("wls_line: the x values do not vary")
    b = (sw * sxy - sx * sy) / det
    a = (sy - b * sx) / sw
    return a, b


def ols_line(xs, ys):
    return wls_line(xs, ys, [1.0] * len(xs))


def lag1_autocorrelation(xs):
    xs = list(xs)
    if len(xs) < 3:
        raise ValueError("autocorrelation needs three values")
    m = mean(xs)
    den = math.fsum((x - m) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return math.fsum((xs[i] - m) * (xs[i + 1] - m) for i in range(len(xs) - 1)) / den


# ── tail probabilities ─────────────────────────────────────────────────────────────
def normal_sf(z):
    """P(Z > z) for a standard normal Z."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def normal_cdf(z):
    return 0.5 * math.erfc(-z / math.sqrt(2.0))


def _gamma_p_series(a, x):
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(10000):
        ap += 1
        term *= x / ap
        total += term
        if abs(term) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_q_cf(a, x):
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_sf(x, df):
    """P(X > x) for a chi-square X with df degrees of freedom."""
    if x <= 0:
        return 1.0
    a, y = df / 2.0, x / 2.0
    if y < a + 1:
        return max(0.0, 1.0 - _gamma_p_series(a, y))
    return _gamma_q_cf(a, y)


def chi2_uniform(counts):
    """(statistic, df, p) of a chi-square test that COUNTS are uniform."""
    n = sum(counts)
    k = len(counts)
    if n == 0 or k < 2:
        raise ValueError("chi2_uniform needs counts")
    e = n / k
    stat = math.fsum((c - e) ** 2 / e for c in counts)
    return stat, k - 1, chi2_sf(stat, k - 1)


def binomial_excess_p(k, n, p0):
    """One-sided p-value that k of n exceeds what p0 explains (normal approximation with
    continuity correction; n is in the thousands here)."""
    if n <= 0:
        raise ValueError("binomial_excess_p needs n > 0")
    if p0 <= 0:
        return 0.0 if k > 0 else 1.0
    if p0 >= 1:
        return 1.0
    sd = math.sqrt(n * p0 * (1 - p0))
    return normal_sf((k - 0.5 - n * p0) / sd)


def p_zero_difference(sigma, q):
    """P(two quantised readings are equal) when the difference of the underlying values is
    N(0, sigma^2) and the lattice step q has a uniform phase: E[max(0, 1 - |d| / q)]."""
    if q <= 0:
        return 0.0
    if sigma <= 0:
        return 1.0
    r = q / sigma
    return math.erf(r / math.sqrt(2.0)) - (2.0 / (r * math.sqrt(2 * math.pi))) * (1 - math.exp(-r * r / 2.0))
