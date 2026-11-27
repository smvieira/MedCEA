"""A run's chamber time series (research Phase 4e, design rs4e 2.3): what the console plots for one run.

Outside every digest: it is not a spec key, it never enters a result row, pool.map's results,
SIM_RESULT or the trace, and results.jsonl, spec.json, spec_digest and result_digest are the same
bytes with or without it (campaign.run_campaign(..., series_every_s=None), CLI --series-every S,
0 = off). The recorder only reads what the runner already computed; it draws no random number.

SeriesRecorder (one per run) keeps columnar arrays, never the runner's trace=True tick dicts, so its
memory grows with the points, not the ticks:

    t                                   simulated seconds of the sampled tick (3 decimals)
    air_temperature, air_humidity,      the chamber's truth (3 decimals)
    co2, ground_temperature
    loops.<key>.value|state|cmd         per active loop: the value the loop resolved (3 decimals,
                                        null when none), its state (STATE_CODES: 0 ok, 1 fallback,
                                        2 no_data, 3 waiting; null when the loop did not run that tick:
                                        out of phase, or it raised) and the tick's command (CMD_CODES:
                                        0 none, 1 UP, 2 DOWN, 3 OFF)
    relays                              bitmask in chamber.RELAYS order (bit i = RELAYS[i] on)
    light                               1 while the recipe line's light period is on
    energy_wh                           the relays' electrical energy since the start (3 decimals)
    cycle                               the recipe cycle (light period) the tick falls in
    disturbance                         bitmask: 1 door open, 2 extra heat
    extra_heat_w                        W of extra heat in force
    ambient_temperature|humidity|co2    the room the chamber sees (the scenario's ambient changes applied)

A sample is taken at the first tick at or after each multiple of every_s. Command, relay, light and
cycle *changes* are kept whole as [t, kind, index, value] (kind cmd: index = the loop's place in
header.loops, value a CMD_CODE; relay: index into RELAYS, value 0|1; light: index 0; cycle: index 0,
value the cycle), so decimating the samples hides no switch; at most MAX_CHANGES of them, the rest
counted in changes_dropped.

Bound: every_s = max(requested, ceil(duration_s / max_points / 10) * 10) with max_points 5000, so a
9000 h scenario still has at most 5000 points; the recorder never keeps more than max_points samples.

A recorder that raises is stopped by the runner (the run goes on unchanged) and its file carries
`error: {reason, at_s}` with the points it had.

File: canonical JSON (sorted keys, no spaces), gzip with mtime 0, written to <name>.tmp and renamed,
so the same run gives the same bytes whatever the campaign's worker count."""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os

SCHEMA = 1
DEFAULT_EVERY_S = 60.0
MAX_POINTS = 5000
MAX_CHANGES = 100000
DECIMALS = 3
TRUTH = ("air_temperature", "air_humidity", "co2", "ground_temperature")
AMBIENT = ("temperature", "humidity", "co2")
STATE_CODES = {"ok": 0, "fallback": 1, "no_data": 2, "waiting": 3}
CMD_CODES = {None: 0, "": 0, "UP": 1, "DOWN": 2, "OFF": 3}
DISTURBANCE_BITS = {"door_open": 1, "extra_heat": 2}


class SeriesError(ValueError):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def requested_every(value):
    """A requested interval (s) from an argument or an environment value: None or 0 is off (None);
    anything else must be a finite number > 0."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise SeriesError("the series interval must be a number of seconds")
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise SeriesError("the series interval must be a number of seconds") from None
    if not math.isfinite(v) or v < 0:
        raise SeriesError("the series interval must be a number of seconds >= 0 (0 = off)")
    return v or None


def effective_every(requested, duration_s, max_points=MAX_POINTS):
    """The interval a run records at: the requested one, coarsened to a multiple of 10 s when the
    run would otherwise exceed max_points."""
    floor = math.ceil(float(duration_s) / max_points / 10.0) * 10.0 if duration_s > 0 else 0.0
    return max(float(requested), floor)


def _r(v):
    if v is None:
        return None
    v = float(v)
    if not math.isfinite(v):
        return None
    out = round(v, DECIMALS)
    return 0.0 if out == 0 else out        # never -0.0: the bytes would differ for the same value


class SeriesRecorder:
    """One run's series; see the module docstring. The runner calls start() once, then tick() every
    control tick and, when due(t), sample(...); the campaign then calls write(path)."""

    def __init__(self, every_s, header=None, max_points=MAX_POINTS, max_changes=MAX_CHANGES):
        req = requested_every(every_s)
        if req is None:
            raise SeriesError("a recorder needs an interval > 0")
        if not isinstance(max_points, int) or isinstance(max_points, bool) or max_points < 1:
            raise SeriesError("max_points must be an integer >= 1")
        self.requested = req
        self.max_points = max_points
        self.max_changes = int(max_changes)
        self.header = dict(header or {})
        self.every = None
        self.loops = []
        self.next_mark = 0.0
        self.cols = None
        self.changes = ([], [], [], [])     # t, kind, index, value (columnar while recording)
        self.changes_dropped = 0
        self._last_cmd = {}
        self._last_relays = None
        self._last_light = None
        self._last_cycle = None
        self.error = None

    # ── recording
    def start(self, duration_s, metrics_from_s, loops, relays):
        """loops: [(key, lower, upper)] of the active loops in the runner's order; relays: chamber.RELAYS."""
        self.every = effective_every(self.requested, duration_s, self.max_points)
        self.loops = [k for k, _, _ in loops]
        self.relays = tuple(relays)
        self.header.update({
            "schema": SCHEMA, "every_s": self.every, "requested_every_s": self.requested,
            "max_points": self.max_points, "duration_s": _r(duration_s), "metrics_from_s": _r(metrics_from_s),
            "band": {k: [lo, hi] for k, lo, hi in loops}, "loops": list(self.loops), "relays": list(self.relays),
            "codes": {"state": dict(STATE_CODES),
                      "cmd": {"none": 0, "UP": 1, "DOWN": 2, "OFF": 3},
                      "disturbance": dict(DISTURBANCE_BITS)}})
        self.cols = {k: [] for k in ("t",) + TRUTH + ("relays", "light", "energy_wh", "cycle", "disturbance",
                                                      "extra_heat_w")}
        for k in AMBIENT:
            self.cols["ambient_" + k] = []
        self.cols["loops"] = {k: {"value": [], "state": [], "cmd": []} for k in self.loops}
        self.next_mark = 0.0

    def _change(self, t, kind, index, value):
        if len(self.changes[0]) >= self.max_changes:
            self.changes_dropped += 1
            return
        for col, v in zip(self.changes, (_r(t), kind, index, value)):
            col.append(v)

    def _mask(self, relays):
        m = 0
        for i, r in enumerate(self.relays):
            if relays.get(r):
                m |= 1 << i
        return m

    def tick(self, t, loop_cmds, relays, light, cycle):
        """Every control tick: keep command, relay, light and cycle changes whole.
        loop_cmds: {key: command or None} for the loops of this tick."""
        for i, key in enumerate(self.loops):
            code = CMD_CODES.get(loop_cmds.get(key), 0)
            if self._last_cmd.get(key, 0) != code:
                self._change(t, "cmd", i, code)
                self._last_cmd[key] = code
        if self._last_relays is None:
            self._last_relays = {r: 0 for r in self.relays}
        for i, r in enumerate(self.relays):
            v = 1 if relays.get(r) else 0
            if v != self._last_relays[r]:
                self._change(t, "relay", i, v)
                self._last_relays[r] = v
        light = 1 if light else 0
        if light != (self._last_light or 0):
            self._change(t, "light", 0, light)
        self._last_light = light
        if cycle != (self._last_cycle or 0):
            self._change(t, "cycle", 0, int(cycle))
        self._last_cycle = cycle

    def due(self, t):
        return len(self.cols["t"]) < self.max_points and t >= self.next_mark - 1e-9

    def sample(self, t, truth, loop_states, relays, light, energy_wh, cycle, disturbances, ambient):
        """loop_states: {key: (state, value, command)} of the loops that ran this tick; disturbances: the
        runner's {door_open, extra_heat_w}; ambient: {temperature, humidity, co2} in force."""
        if not self.due(t):
            return
        c = self.cols
        c["t"].append(_r(t))
        for k in TRUTH:
            c[k].append(_r(truth.get(k)))
        for key in self.loops:
            st, val, cmd = loop_states.get(key, (None, None, None))
            lc = c["loops"][key]
            lc["value"].append(_r(val))
            lc["state"].append(STATE_CODES.get(st))
            lc["cmd"].append(CMD_CODES.get(cmd, 0))
        c["relays"].append(self._mask(relays))
        c["light"].append(1 if light else 0)
        c["energy_wh"].append(_r(energy_wh))
        c["cycle"].append(int(cycle))
        dist = disturbances or {}
        heat = float(dist.get("extra_heat_w") or 0.0)
        c["disturbance"].append((DISTURBANCE_BITS["door_open"] if dist.get("door_open") else 0)
                                | (DISTURBANCE_BITS["extra_heat"] if heat else 0))
        c["extra_heat_w"].append(_r(heat))
        for k in AMBIENT:
            c["ambient_" + k].append(_r((ambient or {}).get(k)))
        # the next mark above t: a tick that passes several marks (an interval below the tick) samples once
        self.next_mark = (math.floor(t / self.every + 1e-9) + 1) * self.every

    def fail(self, reason, t=None):
        """The runner calls this when recording raised: the series stops there and says why."""
        self.error = {"reason": str(reason)[:300], "at_s": _r(t)}

    # ── output
    def points(self):
        return len(self.cols["t"]) if self.cols else 0

    def document(self):
        if self.cols is None:
            raise SeriesError("the recorder was never started")
        doc = {"header": self.header, "columns": self.cols,
               "changes": [list(x) for x in zip(*self.changes)], "changes_dropped": self.changes_dropped}
        if self.error:
            doc["error"] = self.error
        return doc

    def to_bytes(self):
        return gzip.compress(canonical(self.document()).encode("utf-8"), 9, mtime=0)

    def write(self, path):
        """Write the series (tmp + rename); returns the file's sha256."""
        data = self.to_bytes()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        return hashlib.sha256(data).hexdigest()


def read(path):
    """A written series as its document (gzip + JSON)."""
    with gzip.open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def file_name(n):
    return "%d.json.gz" % int(n)


def files_digest(shas):
    """sha256 over each file's sha256 (hex, one per line) in run order: manifest.series.digest."""
    return hashlib.sha256("".join(s + "\n" for s in shas).encode("ascii")).hexdigest()
