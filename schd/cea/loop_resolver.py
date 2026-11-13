"""cea.loop_resolver — the runner's control loops, without MQTT or a database
(feedback control Phase 2; owner decisions Q8, Q11, Q12, Q20; plan
codeplan/feedback-control-plan.md).

Pure: the standard library only and no relative import, so the offline tests load
this file by path (the host python has no psycopg2, which cea/__init__ pulls in).

A loop is the dict the runner keeps in run_params[0]['control_loops']:

    {"zone_code", "loop_id" (None on the default map), "loop_code",
     "recipe_lower", "recipe_upper",            recipe_line columns of its limits
     "input":  {"tag", "sources": [sensor…] | "*", "rule", "reference"?,
                "fallback"?, "max_age_s"?},
     "output": {"actuator", "mode": "command", "command_map"?}}

Readings are keyed (zone, tag, sensor). A reading topic is
<root>/<unit>/<zone>/sense/<tag>/<sensor> (a board onboarded since Phase 1) or
<root>/<unit>/<zone>/sense/<tag> (a board flashed before it: the payload's "sensor"
when present, else 'default', a reserved sensor id). Both are accepted (Q12).

The default map (Q11, Q20, owner D-a): a zone with active control_loop rows uses
them; a zone with an actuator and no rows gets one loop per quantity with the
internal rule 'single' over every sensor of the tag ("*"): exactly one fresh sensor
is used; two or more give no_data and ALARM ambiguous_source (the reference is the
user's onboarding choice); none give no_data. Substrate reads ground_temperature
(F1); CO2 maps the algorithm's DOWN to fans UP (F11).

no_data never synthesises a command (Q8): the last command is held, with an ALARM
line every ALARM_REPEAT_S; a fallback sensor in use keeps controlling, with an
ALARM line. Alarms are log lines (stderr, the run log) until Phase 9 mails them.
"""
import json
import math
import re

DEFAULT_MAX_AGE_S = 90          # 3 x the SENSE default message_interval (30 s)
MAX_AGE_LIMIT_S = 3600
RULES = ("reference", "mean", "min", "max")
DEFAULT_RULE = "single"         # internal to the default map, never stored
ALL_SOURCES = "*"
RESERVED_SENSOR = "default"
ALARM_REPEAT_S = 300
LIGHT_ACTUATOR = "light"         # the time-based light command's actuator, no loop's
STATE_KEY_MAX = 50              # medcea.algorithm_state.channel varchar(50)
ACTUATOR_RE = re.compile(r"[A-Za-z0-9_]+")
TOPIC_UNSAFE = ("+", "#", "/")

# The four loops of this release, keyed by loop_code: the same table as the
# database's medcea._loop_quantities() (migration 010) and the wizard's QUANTITIES.
# Phase 5 extends all three together (tests/test_loop_resolver.py compares them).
QUANTITIES = {
    "air_temperature": {"tag": "air_temperature",
                        "recipe_lower": "air_temperature_lower_limit",
                        "recipe_upper": "air_temperature_upper_limit"},
    "air_humidity": {"tag": "air_humidity",
                     "recipe_lower": "hr_lower_limit", "recipe_upper": "hr_upper_limit"},
    "co2": {"tag": "co2", "recipe_lower": "co2_lower_limit", "recipe_upper": "co2_upper_limit",
            "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}},
    "substrate_temperature": {"tag": "ground_temperature",
                              "recipe_lower": "substrate_temperature_lower_limit",
                              "recipe_upper": "substrate_temperature_upper_limit"},
}
LIMIT_COLUMNS = tuple(sorted({q[k] for q in QUANTITIES.values() for k in ("recipe_lower", "recipe_upper")}))

ALARM_KINDS = ("fallback_in_use", "no_fresh_data", "ambiguous_source")


# ── topics and readings ──────────────────────────────────────────────────────────
def topic_safe(segment):
    """A unit or zone code usable as one MQTT topic segment of a subscription."""
    return isinstance(segment, str) and segment != "" and not any(c in segment for c in TOPIC_UNSAFE)


def parse_reading_topic(topic, root, unit_code, payload=None):
    """(zone, tag, sensor) of a reading topic of this unit, else None.

    5 segments: sensor = payload["sensor"] when a non-empty str, else 'default'.
    6 segments: sensor = segment 6 (the topic wins over the payload).
    Exact segments only; a tag starting with '_' (_health, _test) is not a reading.
    """
    if not isinstance(topic, str):
        return None
    seg = topic.split("/")
    if len(seg) not in (5, 6):
        return None
    if seg[0] != root or seg[1] != unit_code or seg[3] != "sense":
        return None
    zone, tag = seg[2], seg[4]
    if not zone or not tag or tag.startswith("_"):
        return None
    if len(seg) == 6:
        sensor = seg[5]
        if not sensor:
            return None
    else:
        sensor = None
        if isinstance(payload, dict):
            s = payload.get("sensor")
            if isinstance(s, str) and s != "":
                sensor = s
        sensor = sensor or RESERVED_SENSOR
    return (zone, tag, sensor)


def reading_value(payload):
    """The payload's value as a finite float, else None (bool, str, NaN, inf refused)."""
    if not isinstance(payload, dict):
        return None
    v = payload.get("value")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    v = float(v)
    return v if math.isfinite(v) else None


def update_readings(readings, key, payload, recv_t):
    """Store readings[key] = (value, recv_t), the newest receive time winning.
    recv_t is the runner's own monotonic clock at on_message (the board's
    timestamp is never trusted). False when the value is unusable or older."""
    v = reading_value(payload)
    if v is None:
        return False
    old = readings.get(key)
    if old is not None and recv_t < old[1]:
        return False
    readings[key] = (v, recv_t)
    return True


# ── resolving a loop's process value ─────────────────────────────────────────────
def max_age(loop):
    m = (loop.get("input") or {}).get("max_age_s")
    if isinstance(m, bool) or not isinstance(m, (int, float)) or not m > 0:
        return DEFAULT_MAX_AGE_S
    return m


def _alarm_of(state, reason):
    if state == "fallback":
        return "fallback_in_use"
    if state == "no_data":
        if reason == "waiting":
            return None
        if reason == "ambiguous_source":
            return "ambiguous_source"
        return "no_fresh_data"
    return None


def _result(value, state, used, stale, reason, sensors=None):
    return {"value": value, "state": state, "used": list(used), "stale": list(stale),
            "reason": reason, "alarm": _alarm_of(state, reason), "sensors": list(sensors or [])}


def resolve(loop, readings, now, started_at=None):
    """The loop's process value now: {value, state: ok|fallback|no_data, used,
    stale: [(sensor, age|None)], reason, alarm: kind|None, sensors}.

    Candidates are the readings of the loop's zone with exactly input.tag. A reading
    is fresh while now - t <= max_age_s (90 when absent).
      single (default map, sources "*"): one fresh sensor -> ok; two or more ->
          no_data, reason ambiguous_source (sensors named); none -> no_data
      reference: the reference fresh -> ok; else the fallback fresh -> fallback;
          else no_data
      mean/min/max: over the fresh listed sources; all fresh -> ok, some -> fallback
          (a degraded aggregate raises the fallback alarm), none -> no_data
    reason 'waiting' (no alarm): no source seen yet and now - started_at < max_age_s.
    """
    inp = loop.get("input") or {}
    zone, tag = loop.get("zone_code"), inp.get("tag")
    limit = max_age(loop)
    rule = inp.get("rule")
    sources = inp.get("sources")

    def age(sensor):
        r = readings.get((zone, tag, sensor))
        return None if r is None else now - r[1]

    def fresh(sensor):
        a = age(sensor)
        return a is not None and a <= limit

    def value(sensor):
        return readings[(zone, tag, sensor)][0]

    if sources == ALL_SOURCES:
        seen = sorted(s for (z, t, s) in readings if z == zone and t == tag)
    else:
        seen = [s for s in (sources or []) if (zone, tag, s) in readings]
        sources = list(sources or [])
    grace = (not seen and started_at is not None and now - started_at < limit)

    def no_data(stale, reason=None, sensors=None):
        return _result(None, "no_data", [], stale, "waiting" if grace else (reason or "no_fresh_data"), sensors)

    if sources == ALL_SOURCES:
        live = [s for s in seen if fresh(s)]
        stale = [(s, age(s)) for s in seen if not fresh(s)]
        if len(live) == 1:
            return _result(value(live[0]), "ok", live, stale, None)
        if len(live) > 1:
            return _result(None, "no_data", [], stale, "ambiguous_source", live)
        return no_data(stale)

    stale = [(s, age(s)) for s in sources if not fresh(s)]
    if rule == "reference":
        ref, fb = inp.get("reference"), inp.get("fallback")
        if ref is not None and fresh(ref):
            return _result(value(ref), "ok", [ref], stale, None)
        if fb is not None and fresh(fb):
            return _result(value(fb), "fallback", [fb], stale, "reference_stale")
        return no_data(stale)
    if rule in ("mean", "min", "max"):
        live = [s for s in sources if fresh(s)]
        if not live:
            return no_data(stale)
        vals = [value(s) for s in live]
        v = sum(vals) / len(vals) if rule == "mean" else (min(vals) if rule == "min" else max(vals))
        return _result(v, "ok" if len(live) == len(sources) else "fallback", live, stale,
                       None if len(live) == len(sources) else "partial")
    return no_data(stale, "bad_rule")


def decide(loop, resolved, algo, last_cmd):
    """(command | None, hold). ok/fallback: the algorithm's command on the resolved
    value, through output.command_map. no_data: compute() is NOT called (PID and
    Q-learning keep their state); the last command is held when there is one, else
    nothing is sent. OFF is never synthesised for no_data (Q8)."""
    if resolved.get("state") in ("ok", "fallback") and resolved.get("value") is not None:
        cmd = algo.compute(float(resolved["value"]))
        cmap = (loop.get("output") or {}).get("command_map") or {}
        return cmap.get(cmd, cmd), False
    if last_cmd:
        return last_cmd, True
    return None, False


# ── the default map ──────────────────────────────────────────────────────────────
def default_loop(zone_code, loop_code):
    q = QUANTITIES[loop_code]
    out = {"actuator": loop_code, "mode": "command"}
    if "command_map" in q:
        out["command_map"] = dict(q["command_map"])
    return {"zone_code": zone_code, "loop_id": None, "loop_code": loop_code,
            "recipe_lower": q["recipe_lower"], "recipe_upper": q["recipe_upper"],
            "input": {"tag": q["tag"], "sources": ALL_SOURCES, "rule": DEFAULT_RULE,
                      "max_age_s": DEFAULT_MAX_AGE_S},
            "output": out}


def build_default_map(zone_codes):
    """One loop per quantity per zone (zones sorted, de-duplicated). The legacy
    actuators carry the loop_code's name (edge/templates/esp32-control.json), so
    algorithm_state keys stay the old channel names."""
    zones = sorted({z for z in zone_codes})
    if not zones:
        raise ValueError("the default loop map needs at least one zone")
    return [default_loop(z, code) for z in zones for code in QUANTITIES]


build_legacy_map = build_default_map      # the name runner.md used


def is_default(loop):
    """A default-map loop: no control_loop row (loop_id None) and sources "*"."""
    inp = loop.get("input")
    return loop.get("loop_id") is None and isinstance(inp, dict) and inp.get("sources") == ALL_SOURCES


# ── validation: the database's _loop_problems, without the zone inventory ────────
def _jsonb_text(obj):
    """jsonb's text form of a flat object: keys by length, then bytes."""
    keys = sorted(obj, key=lambda k: (len(k.encode()), k.encode()))
    return "{" + ", ".join(f"{json.dumps(k)}: {json.dumps(obj[k])}" for k in keys) + "}"


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def loop_problems(loop, zone_code):
    """Every reason one table row is refused, in medcea._loop_problems' words and
    order (migration 010), but for the two inventory rules the runner cannot see
    (a sensor on an active SENSE board, an actuator on an active CONTROL board).
    `loop` holds loop_code, recipe_lower, recipe_upper, input, output only. A NULL
    recipe column is not a problem here: limits() makes that loop inactive."""
    if not isinstance(loop, dict):
        return ["a loop must be a JSON object"]
    code = loop.get("loop_code")
    if not isinstance(code, str):
        return ["a loop needs a loop_code"]
    q = QUANTITIES.get(code)
    if q is None:
        return ["loop_code %s is not one of %s" % (code[:60], ", ".join(sorted(QUANTITIES)))]
    pre = code + ": "
    errs = []
    if len(code) + 1 + len(zone_code or "") > STATE_KEY_MAX:
        errs.append(pre + "the runner's state key %s@%s is longer than 50 characters" % (code, zone_code))
    for k in loop:
        if k not in ("loop_code", "recipe_lower", "recipe_upper", "input", "output"):
            errs.append(pre + "unknown key %s" % str(k)[:60])
    for col in ("recipe_lower", "recipe_upper"):
        if loop.get(col) is not None and loop.get(col) != q[col]:
            errs.append(pre + "%s must be %s" % (col, q[col]))

    inp = loop.get("input")
    tag = q["tag"]
    srcs = []
    if not isinstance(inp, dict):
        errs.append(pre + "input must be an object")
    else:
        for k in inp:
            if k not in ("tag", "sources", "rule", "reference", "fallback", "max_age_s"):
                errs.append(pre + "unknown key input.%s" % str(k)[:60])
        if inp.get("tag", None) != tag or not isinstance(inp.get("tag"), str):
            errs.append(pre + "input.tag must be %s" % tag)
        sources = inp.get("sources")
        if not isinstance(sources, list) or len(sources) == 0:
            errs.append(pre + "input.sources must be a non-empty list of sensor names")
        else:
            for s in sources:
                if not isinstance(s, str):
                    errs.append(pre + "input.sources must hold sensor names (strings)")
                    continue
                if s in srcs:
                    errs.append(pre + "sensor %s is listed twice" % s[:60])
                    continue
                srcs.append(s)
                if s == RESERVED_SENSOR:
                    errs.append(pre + "sensor default is reserved for readings without a sensor name "
                                "(a board flashed before Phase 1): re-onboard the board and choose its named sensor")
        rule = inp.get("rule")
        ref = fb = None
        if not isinstance(rule, str) or rule not in RULES:
            errs.append(pre + "input.rule must be one of reference, mean, min, max")
        elif rule == "reference":
            if not isinstance(inp.get("reference"), str):
                errs.append(pre + "rule reference needs input.reference, one of the sources")
            else:
                ref = inp["reference"]
                if ref not in srcs:
                    errs.append(pre + "input.reference %s is not one of the sources" % ref[:60])
            if "fallback" in inp:
                if not isinstance(inp.get("fallback"), str):
                    errs.append(pre + "input.fallback must be a sensor name")
                else:
                    fb = inp["fallback"]
                    if ref is not None and fb == ref:
                        errs.append(pre + "input.fallback must be another sensor than the reference")
                    elif fb not in srcs:
                        errs.append(pre + "input.fallback %s is not one of the sources" % fb[:60])
            if any(y != ref and y != fb for y in srcs):
                errs.append(pre + "with rule reference, input.sources holds only the reference and the fallback")
        elif "reference" in inp or "fallback" in inp:
            errs.append(pre + "rule %s takes no reference or fallback" % rule)
        if "max_age_s" in inp:
            n = inp["max_age_s"]
            if not _num(n) or not math.isfinite(n) or n != int(n) or n < 1 or n > MAX_AGE_LIMIT_S:
                errs.append(pre + "input.max_age_s must be a whole number of seconds from 1 to 3600")

    outp = loop.get("output")
    if not isinstance(outp, dict):
        errs.append(pre + "output must be an object")
        return errs
    for k in outp:
        if k not in ("actuator", "mode", "command_map"):
            errs.append(pre + "unknown key output.%s" % str(k)[:60])
    if outp.get("mode", None) != "command" or not isinstance(outp.get("mode"), str):
        errs.append(pre + "output.mode must be command (level and boost need Phase 3's PWM outputs)")
    if "command_map" in q:
        if outp.get("command_map", None) != q["command_map"]:
            errs.append(pre + "output.command_map must be exactly %s" % _jsonb_text(q["command_map"]))
    elif "command_map" in outp:
        errs.append(pre + "output.command_map is only for co2")
    act = outp.get("actuator")
    if not isinstance(act, str) or not ACTUATOR_RE.fullmatch(act):
        errs.append(pre + "output.actuator must be an actuator name")
    return errs


def _runner_only_problems(row):
    """What the database refuses through its inventory rules (a sensor on an active
    SENSE board, an actuator taking UP/DOWN/OFF on an active CONTROL board), which
    the runner cannot see: a row written past save_zone_loops (as postgres) must
    still fail the run closed. An empty sensor name never matches a reading (a
    6-segment topic needs one, a 5-segment one reads as 'default'); actuator light
    takes the runner's time-based light command every cycle."""
    code = row.get("loop_code")
    pre = "%s: " % code
    errs = []
    inp, outp = row.get("input"), row.get("output")
    if isinstance(inp, dict) and isinstance(inp.get("sources"), list):
        if any(isinstance(x, str) and x == "" for x in inp["sources"]):
            errs.append(pre + "input.sources holds an empty sensor name")
    if isinstance(outp, dict) and outp.get("actuator") == LIGHT_ACTUATOR:
        errs.append(pre + "output.actuator light is reserved for the time-based light command")
    return errs


def validate_loops(loops):
    """(errors, warnings) for a unit's loop map. A table row gets loop_problems();
    a default-map loop must be exactly default_loop(zone, code). Across the map:
    a zone code usable in a topic, one loop per (zone, loop_code) and one loop per
    (zone, actuator) (command mode would fight at the board, F8). Any error fails
    the run at start, before anything is written."""
    errs, warns = [], []
    if not isinstance(loops, list) or not loops:
        return ["no control loops"], warns
    codes, acts = set(), set()
    for lp in loops:
        if not isinstance(lp, dict):
            errs.append("a loop must be a JSON object")
            continue
        zone = lp.get("zone_code")
        code = lp.get("loop_code")
        if not topic_safe(zone):
            errs.append("zone code %r cannot be used in an MQTT topic" % (zone,))
            continue
        where = "zone %s: " % zone
        if is_default(lp):
            if code not in QUANTITIES or lp != default_loop(zone, code):
                errs.append(where + "%s: not the default map's loop" % code)
            elif len(code) + 1 + len(zone) > STATE_KEY_MAX:
                errs.append(where + "%s: the runner's state key %s@%s is longer than 50 characters"
                            % (code, code, zone))
        else:
            row = {k: lp[k] for k in ("loop_code", "recipe_lower", "recipe_upper", "input", "output") if k in lp}
            errs += [where + e for e in loop_problems(row, zone)]
            errs += [where + e for e in _runner_only_problems(row)]
            for col in ("recipe_lower", "recipe_upper"):
                if lp.get(col) is None and isinstance(code, str):
                    warns.append(where + "%s: %s is NULL: the loop is inactive" % (code, col))
        if isinstance(code, str):
            if (zone, code) in codes:
                errs.append(where + "%s: listed twice" % code)
            codes.add((zone, code))
            act = (lp.get("output") or {}).get("actuator") if isinstance(lp.get("output"), dict) else None
            if isinstance(act, str):
                if (zone, act) in acts:
                    errs.append(where + "%s: actuator %s is driven by another loop of the zone" % (code, act))
                acts.add((zone, act))
    return errs, warns


def loop_from_row(row):
    """A control_loop row (dict; input/output jsonb as dicts or JSON text) as a loop."""
    def obj(v):
        return json.loads(v) if isinstance(v, (str, bytes)) else v
    return {"zone_code": row["zone_code"], "loop_id": row.get("loop_id"), "loop_code": row["loop_code"],
            "recipe_lower": row.get("recipe_lower"), "recipe_upper": row.get("recipe_upper"),
            "input": obj(row["input"]), "output": obj(row["output"])}


# ── per run ──────────────────────────────────────────────────────────────────────
def limits(loop, recipe_line):
    """(lower, upper, None) or (None, None, why): a loop whose recipe column is
    NULL, or whose recipe line has no value there, is inactive for the line."""
    cols = (loop.get("recipe_lower"), loop.get("recipe_upper"))
    if None in cols:
        return None, None, "%s has no recipe limit column: inactive" % loop.get("loop_code")
    lo, hi = recipe_line.get(cols[0]), recipe_line.get(cols[1])
    if lo is None or hi is None:
        missing = ", ".join(c for c, v in zip(cols, (lo, hi)) if v is None)
        return None, None, "the recipe line has no %s: inactive" % missing
    return float(lo), float(hi), None


def zones_of(loops):
    return sorted({lp["zone_code"] for lp in loops})


def state_key(loop, multi_zone):
    """algorithm_state.channel: the loop_code (the old channel name) on a unit of one
    zone, loop_code@zone_code on a unit of several."""
    return "%s@%s" % (loop["loop_code"], loop["zone_code"]) if multi_zone else loop["loop_code"]


def command_topic(root, unit, zone, actuator):
    return "%s/%s/%s/control/%s" % (root, unit, zone, actuator)


def light_topic(root, unit, zone):
    return command_topic(root, unit, zone, LIGHT_ACTUATOR)


def stop_topics(root, unit, zones):
    """One <root>/<unit>/<zone>/sense/# per zone (a list, never a str): the
    publisher's 'finished' path turns each into .../control/all_controllers_off."""
    return ["%s/%s/%s/sense/#" % (root, unit, z) for z in sorted(set(zones)) if topic_safe(z)] \
        if topic_safe(unit) else []


def subscribe_topics(root, unit, zones):
    """The zones' sense/# subscriptions (5- and 6-segment readings alike); a unit or
    zone code holding '+', '#' or '/' is skipped (an invalid subscription)."""
    return stop_topics(root, unit, zones)


def command_payload(loop, resolved, cmd, hold, timestamp):
    """The control message: the board dispatches on "tag" (the actuator). No
    "value" key: the board reads "value" as the light type."""
    return {"timestamp": timestamp, "tag": loop["output"]["actuator"], "command": cmd,
            "origin": "loop", "loop": loop["loop_code"], "state": "hold" if hold else resolved["state"],
            "sources": resolved["used"], "process_value": resolved["value"]}


class AlarmTracker:
    """ALARM lines: on a transition, then every ALARM_REPEAT_S while it lasts;
    ALARM_CLEARED when the loop is back to ok (or waiting)."""

    def __init__(self, unit_code, repeat_s=ALARM_REPEAT_S):
        self.unit = unit_code
        self.repeat = repeat_s
        self.active = {}            # key -> (kind, last line time)

    def update(self, key, kind, now, detail=""):
        """Lines to log now (a list, usually empty). key = (zone, loop_code)."""
        zone, loop_code = key
        tail = "unit=%s zone=%s loop=%s" % (self.unit, zone, loop_code)
        lines = []
        cur = self.active.get(key)
        if cur is not None and cur[0] != kind:
            lines.append("ALARM_CLEARED %s %s" % (cur[0], tail))
            del self.active[key]
            cur = None
        if kind is None:
            return lines
        if cur is None or now - cur[1] >= self.repeat:
            lines.append(("ALARM %s %s %s" % (kind, tail, detail)).rstrip())
            self.active[key] = (kind, now)
        return lines


def alarm_detail(resolved, last_cmd=None):
    stale = ",".join("%s(%s)" % (s, "never" if a is None else "%ds" % int(a)) for s, a in resolved["stale"])
    if resolved["alarm"] == "ambiguous_source":
        return "sensors=%s: choose the reference in onboarding" % ",".join(resolved["sensors"])
    if resolved["alarm"] == "fallback_in_use":
        return "using=%s stale=%s" % (",".join(resolved["used"]), stale or "-")
    if resolved["alarm"] == "no_fresh_data":
        return "stale=%s (%s)" % (stale or "-", "holding the last command %s" % last_cmd
                                  if last_cmd is not None else "nothing sent yet")
    return ""
