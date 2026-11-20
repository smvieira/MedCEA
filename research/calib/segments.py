"""From dataset rows to board cycles, cadence and segments (design §2.1, §9 R1-R3).

R1. A board cycle is keyed by measured_at: the SENSE board stamps one measured_at per
loop pass and every tag of every sensor of that pass carries it. A cycle's time is its
measured_at (the board's clock, whole seconds): the cadence, the gaps, the segments and
the bootstrap blocks are the board's own. ingested_at (the platform's receive time,
microsecond-resolved) is used only for the latency and for the delivery stalls it shows:
the platform sometimes receives a run of cycles late and then at once (a 46 s ingest gap
followed by gaps of 0.01-2 s, every measured_at 3 s apart), so classifying on ingested_at
would call a stall a skipped cycle, keep the catch-up in the normal differences, and bias
the interval low (review of 20 Nov 2026: 2.987 s against the board's 3.0007 s).

R2. Gaps. The nominal interval is the mode of the cycle-time differences, rounded to
0.1 s. A difference up to 3 x nominal is normal; a larger one under 60 s is a skipped
cycle (a board reboot shows as a gap of 30-60 s); one of 60 s or more is an outage. An
outage ends a segment; it never counts as a dropout. Outages are classified from the data
alone (a gap between readings, or the end of the data before the snapshot's cut), never
from holds.

Times are kept as integer microseconds since the epoch (exact), and as seconds relative to
the first cycle (floats) for the arithmetic.
"""
from __future__ import annotations

import collections
import datetime
from decimal import Decimal, InvalidOperation

OUTAGE_S = 60.0
NORMAL_FACTOR = 3.0
REBOOT_MIN_S = 30.0
SKIP_BINS = ((0.0, 10.0), (10.0, 30.0), (30.0, 60.0))
OUTAGE_BINS = ((60.0, 600.0), (600.0, 3600.0), (3600.0, None))

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


class DataError(ValueError):
    """Rows that cannot be read as the fits need them."""


def parse_us(ts):
    """A dataset timestamp (YYYY-MM-DDTHH:MM:SS.ffffffZ) as integer microseconds since the epoch."""
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise DataError("timestamp %r is not in the dataset's form" % (ts,))
    try:
        d = datetime.datetime.fromisoformat(ts[:-1] + "+00:00")
    except ValueError:
        raise DataError("timestamp %r is not in the dataset's form" % (ts,)) from None
    delta = d - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def format_us(us):
    d = _EPOCH + datetime.timedelta(microseconds=us)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hundredths(text):
    """A reading's raw numeric text as an integer number of hundredths; DataError when it
    is not a finite number with at most 2 decimals (the board publishes round(v, 2))."""
    if text is None:
        raise DataError("a reading without a value")
    try:
        d = Decimal(str(text))
    except InvalidOperation:
        raise DataError("value %r is not a number" % (text,)) from None
    if not d.is_finite():
        raise DataError("value %r is not finite" % (text,))
    h = d * 100
    if h != h.to_integral_value():
        raise DataError("value %r has more than 2 decimals: the model rounds to 2" % (text,))
    return int(h)


class Board:
    """The board cycles of the mapped sensors.

    cycles: [{"m": measured_us, "t": seconds (measured_at, relative to origin),
              "i": seconds (earliest ingested_at, relative to origin),
              "s": {sensor: {tag: (hundredths, ingested seconds, raw text)}}}] in measured_at
    order. origin_us: the earliest ingested_at (so every ingested second is >= 0)."""

    def __init__(self, rows, sensors):
        sensors = list(sensors)
        by = {}
        for r in rows:
            if r["sensor"] not in sensors:
                continue
            m = parse_us(r["measured_at"])
            i = parse_us(r["ingested_at"])
            c = by.setdefault(m, {"m": m, "i": i, "s": {}})
            c["i"] = min(c["i"], i)
            tags = c["s"].setdefault(r["sensor"], {})
            if r["tag"] in tags:
                raise DataError("sensor %s published %s twice at %s: a cycle is one measured_at (R1)"
                                % (r["sensor"], r["tag"], r["measured_at"]))
            tags[r["tag"]] = (hundredths(r["value"]), i, r["value"])
        if not by:
            raise DataError("no reading of %s in the dataset" % ", ".join(sensors))
        ms = sorted(by)
        self.origin_us = min(c["i"] for c in by.values())
        self.sensors = sensors
        self.cycles = []
        for m in ms:
            c = by[m]
            s = {sid: {tag: (h, (iu - self.origin_us) / 1e6, raw) for tag, (h, iu, raw) in tags.items()}
                 for sid, tags in c["s"].items()}
            self.cycles.append({"m": m, "t": (m - self.origin_us) / 1e6, "i": (c["i"] - self.origin_us) / 1e6,
                                "s": s})
        self.cadence = cadence([c["t"] for c in self.cycles])
        self.segments = self.cadence["segments"]

    def ts(self, seconds):
        return format_us(self.origin_us + int(round(seconds * 1e6)))

    def tags_of(self, sensor):
        out = []
        for c in self.cycles:
            for tag in c["s"].get(sensor, {}):
                if tag not in out:
                    out.append(tag)
        return sorted(out)

    def sensor_cycles(self, sensor, segment):
        """The cycles of SEGMENT (i0, i1) in which SENSOR published anything."""
        i0, i1 = segment
        return [c for c in self.cycles[i0:i1 + 1] if sensor in c["s"]]

    def series(self, sensor, tag, segment):
        """[(cycle time s, hundredths)] of one tag in one segment, in cycle order."""
        out = []
        for c in self.sensor_cycles(sensor, segment):
            v = c["s"][sensor].get(tag)
            if v is not None:
                out.append((c["t"], v[0]))
        return out


def nominal_interval(diffs):
    """The mode of the differences rounded to 0.1 s (the smaller on a tie)."""
    counts = collections.Counter(round(d, 1) for d in diffs if d > 0)
    if not counts:
        raise DataError("the cycles have no positive time difference")
    best = max(counts.values())
    return min(k for k, v in counts.items() if v == best)


def _hist(values, bins):
    out = []
    for lo, hi in bins:
        n = sum(1 for v in values if v >= lo and (hi is None or v < hi))
        out.append({"from_s": lo, "to_s": hi, "n": n})
    return out


def _skip_bins(limit):
    """SKIP_BINS starting at the normal limit (3 x nominal)."""
    out = []
    for lo, hi in SKIP_BINS:
        lo = max(lo, limit)
        if hi > lo:
            out.append((round(lo, 3), hi))
    return out


def cadence(times):
    """Classify the differences of cycle TIMES (seconds, increasing): nominal, normal
    differences, skipped cycles, outages, and the segments the outages leave (as
    inclusive index ranges)."""
    if len(times) < 2:
        return {"nominal": None, "normal": [], "skipped": [], "outages": [],
                "segments": [(0, len(times) - 1)] if times else [], "skipped_hist": [], "outage_hist": []}
    diffs = [b - a for a, b in zip(times, times[1:])]
    nominal = nominal_interval(diffs)
    limit = NORMAL_FACTOR * nominal
    normal, skipped, outages = [], [], []
    segments, start = [], 0
    for i, d in enumerate(diffs):
        if d >= OUTAGE_S:
            outages.append((i, d))
            segments.append((start, i))
            start = i + 1
        elif d > limit:
            skipped.append((i, d))
        else:
            normal.append((i, d))
    segments.append((start, len(times) - 1))
    return {"nominal": nominal, "normal": normal, "skipped": skipped, "outages": outages,
            "segments": segments,
            "skipped_hist": _hist([d for _, d in skipped], _skip_bins(limit)),
            "outage_hist": _hist([d for _, d in outages], OUTAGE_BINS)}


def outage_records(board, cut_at=None):
    """[{from, to, seconds, why}] of the board's outages, plus the end of the data when the
    snapshot's cut is an outage's length after the last cycle."""
    out = []
    for i, d in board.cadence["outages"]:
        out.append({"from": board.ts(board.cycles[i]["t"]), "to": board.ts(board.cycles[i + 1]["t"]),
                    "seconds": round(d, 3), "why": "gap in the data"})
    if cut_at:
        last = board.origin_us + int(round(board.cycles[-1]["t"] * 1e6))
        cut = parse_us(cut_at)
        if (cut - last) / 1e6 >= OUTAGE_S:
            out.append({"from": format_us(last), "to": format_us(cut), "seconds": round((cut - last) / 1e6, 3),
                        "why": "end of the data before the snapshot's cut"})
    return out
