"""One closed-loop scenario: production's 10-s control tick against the chamber model.

The tick is schd/cea/control_logic_thread.py re-expressed with the same pure functions of
schd/cea/loop_resolver.py, in the same order:

    snapshot the readings -> light_on = now < cycle start + light_on_minutes
    for each active loop (the map's order):
        not in_phase -> nothing sent
        resolve(loop, readings, now, started_at) -> AlarmTracker
        decide(loop, resolved, algorithm, last_cmd) -> (command, hold)   [command_map applied]
        a command -> published to control/<actuator>; last_cmd = command
    the light command (ON/OFF with the line's light type), once per zone
    wait 10 s (+ the clock's jitter)

The loop map is loop_resolver.build_default_map for one zone, with the board's actuators
declaring their quantities (edge/templates/esp32-control.json); a loop is active when the
recipe line has its setpoint (loop_resolver.limits). Controllers are built through
ALGORITHM_NAMES with the scenario's parameters; PID's clock and Q-learning's random
source are the scenario's SimClock (simclock.py).

The board: each published message is applied, in publishing order, through the
template's command semantics (`set` of the command's branch, a typed actuator's type
first), so a relay several actuators share (air_flow_fan) ends a tick in the state the
last message gave it, as on the board. A message for an actuator the scenario's board
does not have is ignored, as the firmware ignores it.

Readings: the sensors (twin_plant.sensors) sample the chamber's truth every plant step
(1 s); each message reaches the runner's readings at its arrival time through
loop_resolver.update_readings, keyed (zone, tag, sensor), with the clock's monotonic
time as the receive time.

Cycles: production runs one run_agent per recipe cycle (light_on + light_off minutes):
at each cycle end it publishes all_controllers_off, keeps the stateful controllers'
state (PID, Q_LEARNING: get_state/load_state), closes the controllers (MPC's GEKKO
temp directory), and starts the next cycle with new controller instances, a new
AlarmTracker (control_logic_thread builds one per thread), no last command, empty
readings and a new start grace. Messages that arrived before the boundary belonged to
the old subscriber and are dropped, so the new cycle's first tick sees only what a
fresh subscriber would. With `cycle_restart: true` (default) the runner does the same at
every cycle boundary; the gap between cycles (a database round trip) is not modelled.

A loop whose controller raises is caught per loop, as control_logic_thread does: the
other loops and the light still run that tick; the exceptions are counted per loop
(`errors`) and make the run invalid.

An active loop's input tag must be a truth key of the chamber and published by at least
one configured sensor, or the scenario is refused.

Scenario (dict):
    name, duration_h,
    recipe_type      (default: the catalogue's default_type),
    recipe_line:     {setpoints: {quantity: {lower, upper}}, light_type, light_on_minutes, light_off_minutes},
    initial:         {air_temperature, air_humidity, co2, ground_temperature} (optional each),
    ambient:         {temperature, humidity, co2} (the room; shorthand for plant ambient_*),
    disturbances:    [{at_h, kind: door_open, duration_min}
                      | {at_h, kind: extra_heat, watts, duration_min}
                      | {at_h, kind: ambient, temperature?, humidity?, co2?}  (from then on)],
    plant:           {overrides: {ChamberParams field: number}},
    sensors:         {overrides: {sensor_id: {SensorSpec field: value}}, remove: [sensor_id]},
    actuators:       [actuator] (the board's commands actuators; default: all of the template's),
    loops:           {loop_code: {input: {...}, output?: {...}}}: control_loop rows (as the
                     onboarding wizard saves them) replacing the default map's loop of that
                     quantity, checked by loop_resolver.validate_loops (loop_problems). Without
                     a row the loop is the default map's: rule 'single' over every sensor of
                     the default tag, which gives no_data (ambiguous_source) as soon as two
                     sensors publish the tag (SHT45 and SCD30 both publish air_temperature
                     and air_humidity), exactly as in production,
    zone             (default Z1), metrics_from_h (default 0), cycle_restart (default true).
"""
from __future__ import annotations

import contextlib
import heapq
import io
import math
import os

from ..twin_plant.chamber import RELAYS, TRUTH_KEYS, Chamber, ChamberParams
from ..twin_plant.sensors import SensorBank, default_specs
from . import algorithms_loader, metrics
from .simclock import SimClock

TICK_S = 10.0              # control_logic_thread.py: stop_event.wait(10)
PLANT_STEP_S = 1.0         # the chamber is advanced in steps of at most 1 s between ticks
STATEFUL = ("PID", "Q_LEARNING")   # run_agent.py _STATEFUL_ALGORITHMS: state kept across cycles

SCENARIO_KEYS = {"name", "duration_h", "recipe_type", "recipe_line", "initial", "ambient",
                 "disturbances", "plant", "sensors", "actuators", "zone", "metrics_from_h",
                 "cycle_restart", "description", "loops"}
LINE_KEYS = {"setpoints", "light_type", "light_on_minutes", "light_off_minutes"}
DISTURBANCE_KINDS = {"door_open": {"at_h", "kind", "duration_min"},
                     "extra_heat": {"at_h", "kind", "duration_min", "watts"},
                     "ambient": {"at_h", "kind", "temperature", "humidity", "co2"}}
SENSOR_FIELDS = {"noise_sd", "noise_rel_sd", "quantisation", "bias", "publish_interval_s",
                 "latency_s", "dropout_p", "start_offset_s", "self_heating_c", "bias_sd"}
LIGHT = "light"

DEFAULT_REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))


class ScenarioError(ValueError):
    pass


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v):
    return _num(v) and math.isfinite(v)


# ── the scenario ─────────────────────────────────────────────────────────────────
def normalise(scenario, loaded):
    """The scenario with every default filled in, or ScenarioError."""
    if not isinstance(scenario, dict):
        raise ScenarioError("a scenario must be a mapping")
    unknown = sorted(set(scenario) - SCENARIO_KEYS)
    if unknown:
        raise ScenarioError("unknown scenario key(s): " + ", ".join(unknown))
    s = dict(scenario)
    if not isinstance(s.get("name"), str) or not s["name"]:
        raise ScenarioError("a scenario needs a name")
    if not _num(s.get("duration_h")) or s["duration_h"] <= 0:
        raise ScenarioError("duration_h must be a number > 0")
    s.setdefault("recipe_type", loaded.catalogue.get("default_type"))
    quantities = loaded.quantities(s["recipe_type"])
    s.setdefault("zone", "Z1")
    if not loaded.lr.topic_safe(s["zone"]):
        raise ScenarioError("zone %r cannot be an MQTT topic segment" % s["zone"])
    s.setdefault("metrics_from_h", 0)
    if not _num(s["metrics_from_h"]) or not 0 <= s["metrics_from_h"] < s["duration_h"]:
        raise ScenarioError("metrics_from_h must be within 0..duration_h")
    s.setdefault("cycle_restart", True)
    if not isinstance(s["cycle_restart"], bool):
        raise ScenarioError("cycle_restart must be true or false")

    line = dict(s.get("recipe_line") or {})
    bad = sorted(set(line) - LINE_KEYS)
    if bad:
        raise ScenarioError("unknown recipe_line key(s): " + ", ".join(bad))
    light_types = sorted(loaded.actuators[LIGHT]["types"])
    line.setdefault("light_type", "DARK")
    if line["light_type"] not in light_types:
        raise ScenarioError("light_type must be one of " + ", ".join(light_types))
    for k in ("light_on_minutes", "light_off_minutes"):
        line.setdefault(k, 0)
        if not isinstance(line[k], int) or isinstance(line[k], bool) or line[k] < 0:
            raise ScenarioError("%s must be a whole number >= 0" % k)
    warnings = []
    sp = line.get("setpoints")
    if not isinstance(sp, dict) or not sp:
        raise ScenarioError("recipe_line.setpoints must name at least one quantity")
    # The structural rules of recipe_line_setpoints_trg (recipe_line_setpoints_guard,
    # migration 011), in its order and with its RAISE texts (tests/test_research_contract.py
    # Setpoints compares them): keys of the recipe type, {"lower", "upper"} numbers only,
    # lower <= upper, within the catalogue's min..max (inclusive).
    for code, e in sp.items():
        if code not in quantities:
            raise ScenarioError("recipe_line setpoints: %s is not a quantity of the recipe's type (%s)"
                                % (str(code)[:60], ", ".join(sorted(quantities))))
        if not isinstance(e, dict) or set(e) != {"lower", "upper"} or not (_num(e["lower"]) and _num(e["upper"])):
            raise ScenarioError('recipe_line setpoints: %s must be {"lower": <number>, "upper": <number>}' % code)
        q = quantities[code]
        if e["lower"] > e["upper"]:
            raise ScenarioError("recipe_line setpoints: %s lower %s is above upper %s" % (code, e["lower"], e["upper"]))
        if e["lower"] < q["min"] or e["upper"] > q["max"]:
            raise ScenarioError("recipe_line setpoints: %s must be within %s and %s %s"
                                % (code, q["min"], q["max"], q.get("unit") or ""))
    missing = [c for c, q in quantities.items() if q["required"] and c not in sp]
    if missing:
        warnings.append("recipe line lacks required quantities (a recipe could not be approved): "
                        + ", ".join(missing))
    s["recipe_line"] = line

    commands_actuators = sorted(n for n, d in loaded.actuators.items() if d.get("kind") == "commands")
    s.setdefault("actuators", commands_actuators)
    acts = s["actuators"]
    if not isinstance(acts, list) or any(a not in commands_actuators for a in acts):
        raise ScenarioError("actuators must be a list of " + ", ".join(commands_actuators))

    plant = dict(s.get("plant") or {})
    if set(plant) - {"overrides"}:
        raise ScenarioError("plant takes only overrides")
    overrides = dict(plant.get("overrides") or {})
    for k, v in (s.get("ambient") or {}).items():
        if k not in ("temperature", "humidity", "co2"):
            raise ScenarioError("unknown ambient key %s" % k)
        if "ambient_" + k in overrides:
            raise ScenarioError("ambient.%s and plant.overrides.ambient_%s both given" % (k, k))
        overrides["ambient_" + k] = v
    try:
        s["_plant_params"] = ChamberParams.from_dict(overrides)
    except ValueError as e:
        raise ScenarioError(str(e)) from None

    sens = dict(s.get("sensors") or {})
    if set(sens) - {"overrides", "remove"}:
        raise ScenarioError("sensors takes overrides and remove")
    specs = {sp_.sensor_id: sp_ for sp_ in default_specs()}
    for sid in sens.get("remove") or []:
        if sid not in specs:
            raise ScenarioError("sensors.remove: no sensor %s" % sid)
        del specs[sid]
    for sid, fields in (sens.get("overrides") or {}).items():
        if sid not in specs:
            raise ScenarioError("sensors.overrides: no sensor %s" % sid)
        bad = sorted(set(fields) - SENSOR_FIELDS)
        if bad:
            raise ScenarioError("sensors.overrides.%s: unknown field(s) %s" % (sid, ", ".join(bad)))
        for k, v in fields.items():
            setattr(specs[sid], k, dict(v) if isinstance(v, dict) else v)
    s["_sensor_specs"] = [specs[k] for k in sorted(specs)]
    for spec in s["_sensor_specs"]:
        try:
            spec.validate()
        except ValueError as e:
            raise ScenarioError(str(e)) from None

    dist = []
    for d in s.get("disturbances") or []:
        kind = d.get("kind") if isinstance(d, dict) else None
        if kind not in DISTURBANCE_KINDS:
            raise ScenarioError("disturbance kind must be one of " + ", ".join(sorted(DISTURBANCE_KINDS)))
        bad = sorted(set(d) - DISTURBANCE_KINDS[kind])
        if bad:
            raise ScenarioError("disturbance %s: unknown key(s) %s" % (kind, ", ".join(bad)))
        if not _num(d.get("at_h")) or d["at_h"] < 0:
            raise ScenarioError("disturbance %s needs at_h >= 0" % kind)
        if kind in ("door_open", "extra_heat") and (not _num(d.get("duration_min")) or d["duration_min"] <= 0):
            raise ScenarioError("disturbance %s needs duration_min > 0" % kind)
        if kind == "extra_heat" and not _finite(d.get("watts")):
            raise ScenarioError("disturbance extra_heat needs watts")
        if kind == "ambient" and any(not _finite(d[k]) for k in ("temperature", "humidity", "co2") if k in d):
            raise ScenarioError("disturbance ambient: temperature, humidity and co2 must be finite numbers")
        dist.append(dict(d))
    s["_disturbances"] = sorted(dist, key=lambda d: d["at_h"])
    s["_warnings"] = warnings
    s["_quantities"] = quantities
    return s


def _disturbance_at(disturbances, t):
    """(ambient overrides, disturbances) in force at simulated time t (s)."""
    amb, door, heat = {}, False, 0.0
    for d in disturbances:
        start = d["at_h"] * 3600.0
        if start > t:
            break
        if d["kind"] == "ambient":
            amb.update({k: d[k] for k in ("temperature", "humidity", "co2") if k in d})
        elif t < start + d["duration_min"] * 60.0:
            if d["kind"] == "door_open":
                door = True
            else:
                heat += float(d["watts"])
    return amb, {"door_open": door, "extra_heat_w": heat}


# ── the board ────────────────────────────────────────────────────────────────────
class Board:
    """The CONTROL board's relays, driven through the template's command semantics."""

    def __init__(self, definitions, actuators):
        self.defs = definitions
        self.present = set(actuators) | {LIGHT}
        self.relays = {r: 0 for r in RELAYS}
        self.ignored = 0

    def apply(self, actuator, command, value=None):
        spec = self.defs.get(actuator)
        if actuator not in self.present or spec is None:
            self.ignored += 1
            return False
        if "types" in spec:
            branch = (spec["types"].get(value) or {}).get(command)
        else:
            branch = (spec.get("commands") or {}).get(command)
        if branch is None:
            self.ignored += 1
            return False
        for relay, v in branch["set"].items():
            self.relays[relay] = int(v)
        return True

    def all_off(self):
        """all_controllers_off: every present actuator's OFF branch (each light type's too)."""
        for name in sorted(self.present):
            spec = self.defs[name]
            branches = [spec["commands"]["OFF"]] if "OFF" in (spec.get("commands") or {}) else []
            branches += [t["OFF"] for _, t in sorted((spec.get("types") or {}).items()) if "OFF" in t]
            for b in branches:
                for relay, v in b["set"].items():
                    self.relays[relay] = int(v)


# ── which branch a controller took ───────────────────────────────────────────────
class _Probe:
    """Whether the last compute() fell back. Uses the controller's fallback_count where its
    code keeps one (mpc.py/flc.py since 17 Nov 2026); otherwise wraps the library call
    (FLC: _ctrl.compute, MPC: _m.solve) and notes an exception, and counts a compute with
    no library (FLC _ctrl None, MPC _gekko falsy) as a fallback."""

    def __init__(self, code, algo):
        self.code = code
        self.algo = algo
        self.counter = hasattr(algo, "fallback_count")
        self.raised = False
        if self.counter or code not in algorithms_loader.LIBRARY_CODES:
            return
        target = (getattr(algo, "_ctrl", None), "compute") if code == "FLC" else (getattr(algo, "_m", None), "solve")
        obj, attr = target
        if obj is not None and (code == "FLC" or getattr(algo, "_gekko", None)):
            inner = getattr(obj, attr)

            def wrapped(*a, **k):
                try:
                    return inner(*a, **k)
                except Exception:
                    self.raised = True
                    raise
            setattr(obj, attr, wrapped)

    def before(self):
        self.raised = False
        return self.algo.fallback_count if self.counter else None

    def fell_back(self, mark):
        if self.code not in algorithms_loader.LIBRARY_CODES:
            return False
        if self.counter:
            return self.algo.fallback_count > mark
        if self.code == "FLC" and getattr(self.algo, "_ctrl", None) is None:
            return True
        if self.code == "MPC" and not getattr(self.algo, "_gekko", None):
            return True
        return self.raised


# ── the run ──────────────────────────────────────────────────────────────────────
def run_scenario(scenario, controller, seed, clock_offset_s=0.0, jitter_s=0.0, repo_root=None,
                 allow_dirty=False, trace=False, loaded=None):
    """Run one scenario with one controller; returns the result dict (see campaign.py).

    controller: {code, params}. trace: False (summary only), True (one entry per tick:
    time, truth, each loop's resolved state and command, relays) or "readings" (also the
    readings snapshot each tick decided on, for the parity test)."""
    loaded = loaded or algorithms_loader.load(repo_root or DEFAULT_REPO, allow_dirty=allow_dirty)
    lr = loaded.lr
    code = controller.get("code")
    params = dict(controller.get("params") or {})
    loaded.check(code, params)
    s = normalise(scenario, loaded)
    quantities = s["_quantities"]
    zone = s["zone"]
    line = s["recipe_line"]

    decl = {n: {"quantity": d.get("quantity")} for n, d in loaded.actuators.items()
            if d.get("kind") == "commands" and n in s["actuators"]}
    loops = lr.build_default_map([zone], quantities, {zone: decl})
    rows = s.get("loops") or {}
    if not isinstance(rows, dict):
        raise ScenarioError("loops must map a loop_code to {input, output?}")
    for i, loop in enumerate(loops):
        row = rows.get(loop["loop_code"])
        if row is None:
            continue
        if not isinstance(row, dict) or set(row) - {"input", "output"} or "input" not in row:
            raise ScenarioError("loops.%s must be {input, output?}" % loop["loop_code"])
        loops[i] = lr.loop_from_row({"zone_code": zone, "loop_id": i + 1, "loop_code": loop["loop_code"],
                                     "input": row["input"], "output": row.get("output", loop["output"])},
                                    quantities)
    unknown = sorted(set(rows) - {lp["loop_code"] for lp in loops})
    if unknown:
        raise ScenarioError("loops: no loop %s on this board and recipe type" % ", ".join(unknown))
    errs, _ = lr.validate_loops(loops, quantities)
    if errs:
        raise ScenarioError("; ".join(errs))
    active, inactive = [], {}
    published = {tag for spec in s["_sensor_specs"] for tag in spec.tags}
    for loop in loops:
        lo, hi, why = lr.limits(loop, line)
        if why:
            inactive[loop["loop_code"]] = why
            continue
        tag = loop["input"]["tag"]
        if tag not in TRUTH_KEYS:
            raise ScenarioError("loop %s: the chamber model has no %s (it models %s)"
                                % (loop["loop_code"], tag, ", ".join(TRUTH_KEYS)))
        if tag not in published:
            raise ScenarioError("loop %s: no configured sensor publishes %s" % (loop["loop_code"], tag))
        active.append((loop, lr.state_key(loop, False), lo, hi))

    clock = SimClock(clock_offset_s, jitter_s, seed)
    chamber = Chamber(s["_plant_params"], s.get("initial"), seed)
    bank = SensorBank(s["_sensor_specs"], seed)
    board = Board(loaded.actuators, s["actuators"])
    duration = s["duration_h"] * 3600.0
    metrics_from = s["metrics_from_h"] * 3600.0
    on_s, period_s = line["light_on_minutes"] * 60.0, (line["light_on_minutes"] + line["light_off_minutes"]) * 60.0

    series = {key: metrics.LoopSeries() for _, key, _, _ in active}
    relay_series = metrics.RelaySeries(RELAYS)
    branches = {key: {"library": 0, "fallback": 0, "not_computed": 0} for _, key, _, _ in active}
    commands = {key: {"UP": 0, "DOWN": 0, "OFF": 0, "hold": 0, "none": 0} for _, key, _, _ in active}
    errors = {key: 0 for _, key, _, _ in active}
    first_error = {}
    alarm_counts = {}
    reasons = {}
    ticks = []
    pending = []          # heap of (arrival, sensor, tag, value)
    session = {"algos": {}, "probes": {}, "last_cmd": {}, "readings": {}, "started_at": None,
               "alarms": None}
    persisted = {}
    stderr = io.StringIO()

    def close_algos():
        for algo in session["algos"].values():
            close = getattr(algo, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def new_session(now):
        session["algos"], session["probes"] = {}, {}
        session["alarms"] = lr.AlarmTracker("SIM")
        for loop, key, lo, hi in active:
            algo = loaded.make(code, lo, hi, params)
            if code in STATEFUL and persisted.get(key):
                algo.load_state(persisted[key])
            session["algos"][key] = algo
            session["probes"][key] = _Probe(code, algo)
        session["last_cmd"] = {}
        session["readings"] = {}
        session["started_at"] = now

    def end_session():
        board.all_off()
        for key, algo in session["algos"].items():
            st = algo.get_state()
            if st:
                persisted[key] = st
        close_algos()
        session["algos"] = {}

    def advance_to(t_target):
        while chamber.time_s < t_target - 1e-9:
            dt = min(PLANT_STEP_S, t_target - chamber.time_s)
            amb, dist = _disturbance_at(s["_disturbances"], chamber.time_s)
            chamber.step(dt, board.relays, light_on, amb, dist)
            for tag, sensor, v, arrival in bank.readings_due(chamber.time_s, chamber.truth()):
                heapq.heappush(pending, (arrival, sensor, tag, v))

    def _tick_loop(loop, key, t, now, snap, light_on, entry):
        """One loop's part of a tick, production's try block (control_logic_thread.py)."""
        if not lr.in_phase(loop, light_on):
            return
        r = lr.resolve(loop, snap, now, session["started_at"])
        for ln in session["alarms"].update((zone, loop["loop_code"]), r["alarm"], now,
                                           lr.alarm_detail(r, session["last_cmd"].get(key))):
            if ln.startswith("ALARM "):
                kind = ln.split()[1]
                alarm_counts[kind] = alarm_counts.get(kind, 0) + 1
        probe = session["probes"][key]
        mark = probe.before()
        cmd, hold = lr.decide(loop, r, session["algos"][key], session["last_cmd"].get(key))
        computed = r.get("state") in ("ok", "fallback") and r.get("value") is not None
        if not computed:
            branches[key]["not_computed"] += 1
        elif probe.fell_back(mark):
            branches[key]["fallback"] += 1
            why = getattr(session["algos"][key], "last_fallback", None)
            if why:
                reasons.setdefault(key, why)
        else:
            branches[key]["library"] += 1
        if entry is not None:
            entry["loops"][key] = {"state": r["state"], "value": r["value"], "used": r["used"],
                                   "cmd": cmd, "hold": hold}
        if not cmd:
            commands[key]["none"] += 1
            return
        board.apply(loop["output"]["actuator"], cmd)
        session["last_cmd"][key] = cmd
        commands[key]["hold" if hold else cmd] = commands[key].get("hold" if hold else cmd, 0) + 1
        if t >= metrics_from:
            series[key].command(cmd)

    clock.install(loaded.pid, loaded.q_learning)
    try:
        with contextlib.redirect_stderr(stderr):
            light_on = False
            for tag, sensor, v, arrival in bank.readings_due(0.0, chamber.truth()):
                heapq.heappush(pending, (arrival, sensor, tag, v))
            t = 0.0
            cycle = 0
            new_session(clock.monotonic())
            while t < duration:
                advance_to(t)
                clock.t = t
                now = clock.monotonic()
                if s["cycle_restart"] and period_s > 0 and int(t // period_s) > cycle:
                    cycle = int(t // period_s)
                    end_session()
                    boundary = cycle * period_s
                    while pending and pending[0][0] < boundary:
                        heapq.heappop(pending)          # the old subscriber's, gone with it
                    new_session(now)
                while pending and pending[0][0] <= t:
                    arrival, sensor, tag, v = heapq.heappop(pending)
                    lr.update_readings(session["readings"], (zone, tag, sensor),
                                       {"value": v, "sensor": sensor}, clock.start_offset_s + arrival)
                snap = dict(session["readings"])
                light_on = period_s > 0 and (t % period_s) < on_s
                truth = chamber.truth()
                entry = {"t": t, "truth": truth, "loops": {}} if trace else None
                if trace == "readings":
                    entry["now"] = now
                    entry["started_at"] = session["started_at"]
                    entry["readings"] = sorted([list(k) + list(v) for k, v in snap.items()])

                for loop, key, lo, hi in active:
                    if t >= metrics_from:
                        series[key].sample(truth[loop["input"]["tag"]], lo, hi)
                    try:
                        _tick_loop(loop, key, t, now, snap, light_on, entry)
                    except Exception as e:     # control_logic_thread: one loop never stops the others
                        errors[key] += 1
                        first_error.setdefault(key, "%s: %s" % (type(e).__name__, " ".join(str(e).split())[:200]))
                board.apply(LIGHT, "ON" if light_on else "OFF", line["light_type"])
                if t >= metrics_from:
                    relay_series.sample(board.relays)
                if trace:
                    entry["light_on"] = light_on
                    entry["relays"] = dict(board.relays)
                    ticks.append(entry)
                t += clock.next_interval(TICK_S)
            advance_to(duration)
    finally:
        clock.uninstall()
        close_algos()

    invalid = []
    for key in sorted(errors):
        if errors[key]:
            invalid.append("loop %s raised on %d tick(s) (first: %s)" % (key, errors[key], first_error[key]))
    if code in algorithms_loader.LIBRARY_CODES:
        lib = loaded.libraries.get(code) or {}
        total_fb = sum(b["fallback"] for b in branches.values())
        total_c = sum(b["fallback"] + b["library"] for b in branches.values())
        if total_fb:
            why = next(iter(reasons.values()), None) or lib.get("reason") or "unknown reason"
            invalid.append("%s fell back to bang-bang on %d of %d computed ticks (%s)"
                           % (code, total_fb, total_c, why))
    energy = metrics.energy(chamber.energy_wh())
    loops_out = {}
    for loop, key, lo, hi in active:
        d = {"lower": lo, "upper": hi, "tag": loop["input"]["tag"], "actuator": loop["output"]["actuator"],
             "branches": branches[key], "commands": commands[key], "errors": errors[key]}
        d.update(series[key].result())
        loops_out[key] = d
    messages = [ln for ln in stderr.getvalue().splitlines() if ln.strip()]
    result = {
        "metrics_version": metrics.METRICS_VERSION,
        "scenario": s["name"],
        "recipe_type": s["recipe_type"],
        "controller": {"code": code, "params": dict(sorted(params.items()))},
        "seed": seed,
        "clock_offset_s": float(clock_offset_s),
        "jitter_s": float(jitter_s),
        "duration_h": s["duration_h"],
        "metrics_from_h": s["metrics_from_h"],
        "valid": not invalid,
        "invalid_reasons": invalid,
        "loops": loops_out,
        "inactive_loops": inactive,
        "relays": {r: {"switches": relay_series.switches[r], "energy_wh": energy["per_relay_wh"][r]}
                   for r in RELAYS},
        "energy_total_wh": energy["total_wh"],
        "alarms": dict(sorted(alarm_counts.items())),
        "ignored_messages": board.ignored,
        "warnings": list(s["_warnings"]),
        "controller_messages": {"count": len(messages), "first": messages[:3]},
    }
    if trace:
        result["trace"] = ticks
    return result
