#!/usr/bin/env python3
"""The onboarding wizard's control-loop picker (feedback control Phase 2, owner
decision Q20; codeplan/feedback-control-plan.md).

A zone's control loops say which sensor each of the four recipe quantities is
controlled on and which actuator it drives. The reference (or the aggregation of
several sensors) is always the person's onboarding choice: a tag published by one
sensor is preselected; a tag published by several is in error (L_CHOOSE) until the
person picks the reference (and optionally a fallback), or mean/min/max over the
sensors they tick, or marks the quantity not controlled. A zone without loop rows
runs on the runner's default map (one fresh sensor per tag is used; several give no
data and ALARM ambiguous_source), decided per zone.

The database is the final judge: medcea.save_zone_loops(zone, loops) (migration
010) replaces the zone's active loops with the list it is sent, every loop the zone
keeps; a code left out is deactivated. The checks here mirror its _loop_problems()
and the save's own (a code twice, one actuator per loop), and edge/src/host/ui/
loops.js mirrors validate() between /* loops-logic:begin */ and :end
(tests/test_loops_ui.py compares them on every fixture in tests/fixtures/loops/).
QUANTITIES is the same table as the database's _loop_quantities() and the runner's
schd/cea/loop_resolver.QUANTITIES (tests/test_loops.py compares all three).

Standard library only and no relative import, so tests load it by path.

The answer the picker gives (the page posts it as a JSON string):

    {"skip": true}                                   Decide later: nothing is saved
    {"skip": false, "stop_all": false, "loops": [...]}   every loop the zone keeps
    {"skip": false, "stop_all": true,  "loops": []}      Stop all (confirmed): the
                                                          zone goes back to the default map

CLI (flash-device.sh's plan_loops; every JSON on stdout):

    spec ROLE --context F [--plan-sources F] [--plan-actuators F]
                                 the picker's spec (ROLE SENSE, CONTROL or ZONE)
    validate --spec F            answer on stdin -> {findings, errors, warnings}; exit 1 on an error
    stale --spec F               STALE<TAB>loop_code<TAB>message, one line per stale loop
    questions --spec F           the terminal's questions: Q<TAB>code<TAB>label / INFO<TAB>text
    options --spec F --code C [--fallback-for X]
                                 OPT<TAB>token<TAB>label lines for one question
    terminal-answer --spec F     "code<TAB>token[<TAB>fallback]" lines on stdin -> the answer
    payload                      answer on stdin -> "skip", or the JSON array to save
    result-text                  save_zone_loops' result on stdin -> one line of words
"""

import copy
import json
import math
import re
import sys

SPEC_VERSION = 1
# The four loops of this release, in the picker's order. Same table as
# medcea._loop_quantities() (migration 010) and schd/cea/loop_resolver.QUANTITIES;
# the actuator is the default one (edge/templates/esp32-control.json, relay8).
QUANTITIES = [
    {"loop_code": "air_temperature", "label": "Air temperature", "tag": "air_temperature",
     "recipe_lower": "air_temperature_lower_limit", "recipe_upper": "air_temperature_upper_limit",
     "actuator": "air_temperature"},
    {"loop_code": "air_humidity", "label": "Air humidity", "tag": "air_humidity",
     "recipe_lower": "hr_lower_limit", "recipe_upper": "hr_upper_limit",
     "actuator": "air_humidity"},
    {"loop_code": "co2", "label": "CO2", "tag": "co2",
     "recipe_lower": "co2_lower_limit", "recipe_upper": "co2_upper_limit",
     "actuator": "co2", "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}},
    {"loop_code": "substrate_temperature", "label": "Substrate temperature", "tag": "ground_temperature",
     "recipe_lower": "substrate_temperature_lower_limit",
     "recipe_upper": "substrate_temperature_upper_limit",
     "actuator": "substrate_temperature"},
]
QMAP = {q["loop_code"]: q for q in QUANTITIES}
RULES = ("reference", "mean", "min", "max")
MODES = ("command",)
MAX_AGE_MIN, MAX_AGE_MAX, MAX_AGE_DEFAULT = 1, 3600, 90
MAX_LOOPS = 16
STATE_KEY_MAX = 50
RESERVED = "default"
INSTANCE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
ACTUATOR_RE = re.compile(r"^[A-Za-z0-9_]+$")
ANSWER_KEYS = ("skip", "stop_all", "loops")
LOOP_KEYS = ("loop_code", "recipe_lower", "recipe_upper", "input", "output")
INPUT_KEYS = ("tag", "sources", "rule", "reference", "fallback", "max_age_s")
OUTPUT_KEYS = ("actuator", "mode", "command_map")
INVENTORY_CODES = ("L_SOURCE", "L_SOURCE_TAG", "L_SOURCE_RESERVED", "L_ACTUATOR", "L_ACTUATOR_KIND")

CODES = {
    "L_SCHEMA": "wrong keys or types, or a page of another version",
    "L_EMPTY": "no loop and no Stop all",
    "L_QUANTITY": "loop_code not one of the four",
    "L_DUP": "a loop_code twice",
    "L_STATE_KEY": "loop_code@zone_code over 50 characters",
    "L_LIMITS": "recipe columns not the quantity's",
    "L_TAG": "input.tag not the quantity's",
    "L_RULE": "rule not reference, mean, min, max",
    "L_RULE_ARGS": "mean/min/max with a reference or fallback",
    "L_CHOOSE": "several sensors and none chosen (Q20)",
    "L_SOURCES_EMPTY": "no sensor",
    "L_SOURCE_RESERVED": "the reserved sensor id default",
    "L_SOURCE": "a sensor the zone does not have",
    "L_SOURCE_TAG": "a sensor not publishing the tag",
    "L_REFERENCE": "reference not one of the sources",
    "L_FALLBACK": "fallback not another source",
    "L_SOURCES_EXTRA": "rule reference with sources besides reference and fallback",
    "L_MAX_AGE": "max_age_s not a whole number from 1 to 3600",
    "L_MODE": "mode other than command",
    "L_COMMAND_MAP": "co2 without its map, or a map on another quantity",
    "L_ACTUATOR": "an actuator the zone does not have",
    "L_ACTUATOR_KIND": "an actuator without every command the loop sends",
    "L_ACTUATOR_SHARED": "two loops on one actuator",
    "W_OLD_BOARD": "a board flashed before Phase 1",
    "W_SENSOR_PROBLEM": "a sensor the database cannot name",
    "W_NOT_CONTROLLED": "a quantity with a sensor and an actuator but no loop",
    "W_STOPPED": "an active loop left out (deactivated)",
    "W_DEFAULT_MAP": "Stop all: the zone goes back to the default map",
    "W_DECIDE_LATER": "Decide later with several sensors on a tag",
}


def sends(q):
    """The commands a loop of quantity q can send the actuator (after its command_map)."""
    if q.get("command_map"):
        return sorted(set(q["command_map"].values()))
    return ["DOWN", "OFF", "UP"]


def instance_of_topic(topic, tag, declared=None):
    """(kind, instance) of one SENSE component tag, as medcea._zone_inventory reads it:
    6 segments <root>/<unit>/<zone>/sense/<tag>/<sensor> -> ("named", sensor);
    5 segments -> ("old", None) (a board flashed before Phase 1: sensor 'default');
    a reserved, malformed or mismatching name -> ("reserved"|"bad"|"mismatch", ...)."""
    seg = topic.split("/") if isinstance(topic, str) else []
    if len(seg) == 5 and seg[3] == "sense" and seg[4] == tag:
        return "old", None
    if len(seg) != 6 or seg[3] != "sense" or seg[4] != tag:
        return "bad", None
    if seg[5] == RESERVED:
        return "reserved", seg[5]
    if not INSTANCE_RE.match(seg[5]):
        return "bad", seg[5]
    if declared is not None and declared != seg[5]:
        return "mismatch", seg[5]
    return "named", seg[5]


def actuators_from_definitions(defs):
    """[{name, kind, commands}] from a CONTROL board's actuator_definitions, as
    _zone_inventory derives them: kind commands|types|unknown, commands sorted."""
    out = []
    for name in sorted((defs or {})):
        d = defs[name] if isinstance(defs[name], dict) else {}
        if isinstance(d.get("commands"), dict):
            out.append({"name": name, "kind": "commands", "commands": sorted(d["commands"])})
        elif isinstance(d.get("types"), dict):
            out.append({"name": name, "kind": "types", "commands": []})
        else:
            out.append({"name": name, "kind": "unknown", "commands": []})
    return out


def _fit(spec, name, q):
    a = next((x for x in spec.get("actuators") or [] if x.get("name") == name), None)
    return a is not None and a.get("kind") == "commands" and all(c in (a.get("commands") or []) for c in sends(q))


def candidates(spec, tag):
    """The zone's sensors publishing tag, in inventory order."""
    return [s["instance"] for s in spec.get("sources") or [] if tag in (s.get("tags") or [])]


# --------------------------------------------------------------- rows ----------
def row_for(spec, code, st):
    """One loop from the picker's state for a quantity: {rule, reference, fallback,
    sensors, max_age_s, actuator}. sources follow the choice (critique 1.6):
    [reference(, fallback)] for rule reference, the ticked sensors for mean/min/max."""
    q = QMAP[code]
    rule = st.get("rule") or "reference"
    inp = {"tag": q["tag"]}
    if rule == "reference":
        ref = st.get("reference")
        fb = st.get("fallback")
        inp["sources"] = [x for x in (ref, fb) if isinstance(x, str) and x]
        inp["rule"] = "reference"
        inp["reference"] = ref if isinstance(ref, str) and ref else None
        if isinstance(fb, str) and fb and fb != ref:
            inp["fallback"] = fb
    else:
        ticked = st.get("sensors") or []
        inp["sources"] = [s for s in candidates(spec, q["tag"]) if s in ticked]
        inp["rule"] = rule
    inp["max_age_s"] = st.get("max_age_s", MAX_AGE_DEFAULT)
    out = {"actuator": st.get("actuator") or q["actuator"], "mode": "command"}
    if q.get("command_map"):
        out["command_map"] = dict(q["command_map"])
    return {"loop_code": code, "recipe_lower": q["recipe_lower"], "recipe_upper": q["recipe_upper"],
            "input": inp, "output": out}


def state_of(row):
    """The picker's state for a stored loop (the inverse of row_for)."""
    inp = row.get("input") if isinstance(row.get("input"), dict) else {}
    out = row.get("output") if isinstance(row.get("output"), dict) else {}
    rule = inp.get("rule") if inp.get("rule") in RULES else "reference"
    srcs = [s for s in inp.get("sources") or [] if isinstance(s, str)]
    return {"rule": rule,
            "reference": inp.get("reference") if rule == "reference" else None,
            "fallback": inp.get("fallback") if rule == "reference" else None,
            "sensors": srcs if rule != "reference" else [],
            "max_age_s": inp.get("max_age_s", MAX_AGE_DEFAULT),
            "actuator": out.get("actuator")}


def _default_state(cands, actuator):
    return {"rule": "reference", "reference": cands[0] if len(cands) == 1 else None,
            "fallback": None, "sensors": list(cands), "max_age_s": MAX_AGE_DEFAULT, "actuator": actuator}


def _stale(spec, row):
    """What of a stored loop the zone will no longer have, or None."""
    code = row.get("loop_code")
    q = QMAP.get(code)
    if q is None:
        return None
    inp = row.get("input") if isinstance(row.get("input"), dict) else {}
    out = row.get("output") if isinstance(row.get("output"), dict) else {}
    cands = candidates(spec, q["tag"])
    missing = [s for s in inp.get("sources") or [] if isinstance(s, str) and s not in cands]
    act = out.get("actuator")
    bad_act = act if not (isinstance(act, str) and _fit(spec, act, q)) else None
    if not missing and bad_act is None:
        return None
    said = []
    if missing:
        said.append("reads %s, which zone %s will no longer have" % (", ".join(missing), spec.get("zone_code")))
    if bad_act is not None:
        said.append("drives %s, which is no longer an actuator of zone %s taking %s"
                    % (bad_act, spec.get("zone_code"), ", ".join(sends(q))))
    return {"loop_code": code, "missing_sources": missing, "missing_actuator": bad_act,
            "message": "%s %s: stop it or choose again" % (code, " and ".join(said))}


def build_spec(role, ctx, plan_sources=None, plan_actuators=None):
    """The picker's spec from zone_loop_context's answer and the board being
    onboarded: a SENSE board's planned sensors replace the zone's (the database
    still holds the old ones until register); a CONTROL board's planned map replaces
    the zone's actuators. ROLE ZONE (--loops-only) takes both from the database."""
    role = (role or "ZONE").upper()
    if role not in ("SENSE", "CONTROL", "ZONE"):
        raise ValueError("role must be SENSE, CONTROL or ZONE")
    spec = {"version": SPEC_VERSION, "role": role,
            "unit_code": ctx.get("unit_code"), "zone_code": ctx.get("zone_code"), "zone_id": ctx.get("zone_id"),
            "busy": ctx.get("busy")}
    problems = []
    if role == "SENSE":
        sources, seen = [], set()
        for s in plan_sources or []:
            inst = s.get("instance")
            if not isinstance(inst, str) or inst == RESERVED or not INSTANCE_RE.match(inst) or inst in seen:
                problems.append("sensor %s cannot be a loop's source: re-name it on the wiring screen" % inst)
                continue
            seen.add(inst)
            sources.append({"instance": inst, "driver": s.get("driver"), "tags": list(s.get("tags") or []),
                            "from": "plan"})
        spec["sources"] = sources
        spec["old_boards"] = []
    else:
        spec["sources"] = [{"instance": s.get("instance"), "driver": s.get("driver"),
                            "tags": list(s.get("tags") or []), "from": "zone"}
                           for s in ctx.get("sensors") or []]
        spec["old_boards"] = [{"component_id": o.get("component_id"), "dns_name": o.get("dns_name"),
                               "driver": o.get("driver"), "tags": list(o.get("tags") or [])}
                              for o in ctx.get("old_boards") or []]
        problems = list(ctx.get("sensor_problems") or [])
    spec["sensor_problems"] = problems
    if role == "CONTROL":
        defs = (plan_actuators or {}).get("actuator_definitions") if isinstance(plan_actuators, dict) else None
        spec["actuators"] = actuators_from_definitions(defs or {})
    else:
        acts, seen = [], set()
        for a in ctx.get("actuators") or []:
            if a.get("actuator") in seen:
                continue
            seen.add(a.get("actuator"))
            acts.append({"name": a.get("actuator"), "kind": a.get("kind"), "commands": list(a.get("commands") or [])})
        spec["actuators"] = acts
    existing = []
    for lp in ctx.get("loops") or []:
        existing.append({k: copy.deepcopy(lp.get(k)) for k in ("loop_id",) + LOOP_KEYS})
    spec["existing"] = existing
    spec["quantities"] = [dict(q, sends=sends(q)) for q in QUANTITIES]
    spec["stale"] = [x for x in (_stale(spec, {k: v for k, v in r.items() if k != "loop_id"}) for r in existing) if x]
    rows = []
    any_existing = bool(existing)
    for q in QUANTITIES:
        code = q["loop_code"]
        cands = candidates(spec, q["tag"])
        fit = [a["name"] for a in spec["actuators"] if _fit(spec, a["name"], q)]
        ex = next((r for r in existing if r.get("loop_code") == code), None)
        row = {"loop_code": code, "candidates": cands, "actuators": fit,
               "default_actuator": q["actuator"] in fit}
        if ex is not None:
            stored = {k: ex[k] for k in LOOP_KEYS}
            row.update(offered=True, ticked=True, existing=True, loop=stored, state=state_of(stored), reason="")
        elif cands and fit:
            act = q["actuator"] if q["actuator"] in fit else fit[0]
            st = _default_state(cands, act)
            row.update(offered=True, ticked=(not any_existing and q["actuator"] in fit), existing=False,
                       loop=row_for(spec, code, st), state=st, reason="")
        else:
            why = []
            if not cands:
                why.append("no sensor publishes %s" % q["tag"])
            if not fit:
                why.append("no actuator takes %s" % ", ".join(sends(q)))
            row.update(offered=False, ticked=False, existing=False, loop=None, state=None,
                       reason=" and ".join(why))
        rows.append(row)
    spec["rows"] = rows
    spec["rules"] = list(RULES)
    spec["modes"] = list(MODES)
    spec["max_age"] = {"min": MAX_AGE_MIN, "max": MAX_AGE_MAX, "default": MAX_AGE_DEFAULT}
    spec["initial"] = defaults(spec)
    return spec


def defaults(spec):
    """The picker's starting answer: every ticked row (stored loops as they are;
    a new row only when the zone has no loop rows, Q20)."""
    return {"skip": False, "stop_all": False,
            "loops": [copy.deepcopy(r["loop"]) for r in spec.get("rows") or [] if r.get("ticked") and r.get("loop")]}


def offered(spec):
    """Whether the picker has anything to show."""
    return any(r.get("offered") for r in spec.get("rows") or []) or bool(spec.get("existing"))


# ------------------------------------------------------------ validate ---------
def _isnum(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _same_map(a, b):
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if sorted(a) != sorted(b):
        return False
    return all(isinstance(a[k], str) and a[k] == b[k] for k in a)


def validate(spec, answer):
    """Every finding {level, code, where, message} on the answer. Mirrored by
    loops.js's validate(); the database re-checks (save_zone_loops)."""
    out = []

    def f(level, code, where, message):
        out.append({"level": level, "code": code, "where": where, "message": message})

    if not isinstance(spec, dict) or spec.get("version") != SPEC_VERSION:
        f("error", "L_SCHEMA", "spec.version", "the page and the wizard are of different versions: reload the page")
        return out
    zone = spec.get("zone_code") or ""
    for o in spec.get("old_boards") or []:
        f("warn", "W_OLD_BOARD", "old_boards.%s" % o.get("component_id"),
          "%s publishes %s without a sensor name (flashed before Phase 1): re-onboard this SENSE board "
          "so its readings carry the sensor name; until then it is no loop's source"
          % (o.get("dns_name") or "a board", ", ".join(o.get("tags") or [])))
    for i, p in enumerate(spec.get("sensor_problems") or []):
        f("warn", "W_SENSOR_PROBLEM", "sensor_problems.%d" % i, str(p))
    if not isinstance(answer, dict):
        f("error", "L_SCHEMA", "answer", "the answer must be a JSON object")
        return out
    for k in answer:
        if k not in ANSWER_KEYS:
            f("error", "L_SCHEMA", "answer", "unknown key %s" % str(k)[:60])
    skip = answer.get("skip", False)
    if not isinstance(skip, bool):
        f("error", "L_SCHEMA", "answer.skip", "skip must be true or false")
        return out
    if skip:
        if len([k for k in answer if k != "skip"]) > 0:
            f("error", "L_SCHEMA", "answer.skip", "Decide later sends nothing else")
            return out
        if not spec.get("existing"):
            for r in spec.get("rows") or []:
                if r.get("offered") and len(r.get("candidates") or []) > 1:
                    f("warn", "W_DECIDE_LATER", "loops.%s" % r["loop_code"],
                      "%s has %d sensors (%s): until one is chosen a run gets no data for it and an alarm"
                      % (r["loop_code"], len(r["candidates"]), ", ".join(r["candidates"])))
        return out
    stop_all = answer.get("stop_all", False)
    if not isinstance(stop_all, bool):
        f("error", "L_SCHEMA", "answer.stop_all", "stop_all must be true or false")
        return out
    loops = answer.get("loops")
    if not isinstance(loops, list):
        f("error", "L_SCHEMA", "answer.loops", "loops must be a list (every loop the zone keeps)")
        return out
    if stop_all and len(loops) > 0:
        f("error", "L_SCHEMA", "answer.stop_all", "Stop all sends no loops")
    if not stop_all and len(loops) == 0:
        f("error", "L_EMPTY", "answer.loops",
          "no loop is ticked: tick at least one, choose Decide later, or Stop all loops")
    if stop_all and len(loops) == 0:
        f("warn", "W_DEFAULT_MAP", "answer.stop_all",
          "every loop of zone %s stops: the zone goes back to the default map (a tag with one sensor "
          "uses it; a tag with several gets no data and an alarm)" % zone)
    if len(loops) > MAX_LOOPS:
        f("error", "L_SCHEMA", "answer.loops", "at most %d loops" % MAX_LOOPS)
    srcs_all = [s.get("instance") for s in spec.get("sources") or []]
    codes, acts = [], {}
    for i, lp in enumerate(loops):
        if not isinstance(lp, dict):
            f("error", "L_SCHEMA", "loops.%d" % i, "a loop must be a JSON object")
            continue
        code = lp.get("loop_code")
        if not isinstance(code, str) or code not in QMAP:
            f("error", "L_QUANTITY", "loops.%d.loop_code" % i,
              "loop_code %s is not one of %s" % (code[:60] if isinstance(code, str) else json.dumps(code), ", ".join(q["loop_code"] for q in QUANTITIES)))
            continue
        w = "loops." + code
        if code in codes:
            f("error", "L_DUP", w + ".loop_code", "%s: listed twice" % code)
            continue
        codes.append(code)
        q = QMAP[code]
        if len(code) + 1 + len(zone) > STATE_KEY_MAX:
            f("error", "L_STATE_KEY", w + ".loop_code",
              "%s: the runner's state key %s@%s is longer than %d characters" % (code, code, zone, STATE_KEY_MAX))
        for k in lp:
            if k not in LOOP_KEYS:
                f("error", "L_SCHEMA", w, "%s: unknown key %s" % (code, str(k)[:60]))
        if lp.get("recipe_lower") != q["recipe_lower"] or lp.get("recipe_upper") != q["recipe_upper"]:
            f("error", "L_LIMITS", w + ".recipe",
              "%s: the limits are the recipe's %s and %s" % (code, q["recipe_lower"], q["recipe_upper"]))
        inp = lp.get("input")
        cands = candidates(spec, q["tag"])
        if not isinstance(inp, dict):
            f("error", "L_SCHEMA", w + ".input", "%s: input must be an object" % code)
        else:
            for k in inp:
                if k not in INPUT_KEYS:
                    f("error", "L_SCHEMA", w + ".input", "%s: unknown key input.%s" % (code, str(k)[:60]))
            if inp.get("tag") != q["tag"]:
                f("error", "L_TAG", w + ".input.tag", "%s: input.tag must be %s" % (code, q["tag"]))
            rule = inp.get("rule")
            if not isinstance(rule, str) or rule not in RULES:
                f("error", "L_RULE", w + ".input.rule", "%s: the rule must be one of %s" % (code, ", ".join(RULES)))
            srcs = inp.get("sources")
            seen = []
            if not isinstance(srcs, list):
                f("error", "L_SCHEMA", w + ".input.sources", "%s: sources must be a list of sensor names" % code)
            else:
                for s in srcs:
                    if not isinstance(s, str):
                        f("error", "L_SCHEMA", w + ".input.sources", "%s: sources must be sensor names" % code)
                        continue
                    if s in seen:
                        f("error", "L_SCHEMA", w + ".input.sources", "%s: sensor %s is listed twice" % (code, s[:60]))
                        continue
                    seen.append(s)
                    if s == RESERVED:
                        f("error", "L_SOURCE_RESERVED", w + ".input.sources." + s,
                          "%s: sensor default is reserved for readings without a sensor name: re-onboard "
                          "that board and choose its named sensor" % code)
                    elif s not in srcs_all:
                        f("error", "L_SOURCE", w + ".input.sources." + s,
                          "%s: sensor %s is not on the SENSE board of zone %s" % (code, s[:60], zone))
                    elif s not in cands:
                        f("error", "L_SOURCE_TAG", w + ".input.sources." + s,
                          "%s: sensor %s does not publish %s" % (code, s, q["tag"]))
            choose = rule == "reference" and inp.get("reference") is None
            if choose:
                f("error", "L_CHOOSE", w + ".input.reference",
                  "%s has %d sensors (%s): choose the one it controls on, or mean/min/max, or mark it not controlled"
                  % (code, len(cands), ", ".join(cands)))
            elif isinstance(srcs, list) and len(srcs) == 0:
                f("error", "L_SOURCES_EMPTY", w + ".input.sources", "%s: tick at least one sensor" % code)
            if rule == "reference" and not choose:
                ref = inp.get("reference")
                if not isinstance(ref, str) or ref not in seen:
                    f("error", "L_REFERENCE", w + ".input.reference",
                      "%s: the reference must be one of the sources" % code)
                if "fallback" in inp:
                    fb = inp.get("fallback")
                    if not isinstance(fb, str) or fb == ref or fb not in seen:
                        f("error", "L_FALLBACK", w + ".input.fallback",
                          "%s: the fallback must be another of the sources than the reference" % code)
                extra = [s for s in seen if s != ref and s != inp.get("fallback")]
                if extra:
                    f("error", "L_SOURCES_EXTRA", w + ".input.sources",
                      "%s: with rule reference the sources are the reference and the fallback only (not %s)"
                      % (code, ", ".join(extra)))
            elif rule in ("mean", "min", "max") and ("reference" in inp or "fallback" in inp):
                f("error", "L_RULE_ARGS", w + ".input.rule", "%s: rule %s takes no reference or fallback" % (code, rule))
            if "max_age_s" in inp:
                n = inp.get("max_age_s")
                if not _isnum(n) or not math.isfinite(n) or n != int(n) or n < MAX_AGE_MIN or n > MAX_AGE_MAX:
                    f("error", "L_MAX_AGE", w + ".input.max_age_s",
                      "%s: max age must be a whole number of seconds from %d to %d" % (code, MAX_AGE_MIN, MAX_AGE_MAX))
        outp = lp.get("output")
        if not isinstance(outp, dict):
            f("error", "L_SCHEMA", w + ".output", "%s: output must be an object" % code)
            continue
        for k in outp:
            if k not in OUTPUT_KEYS:
                f("error", "L_SCHEMA", w + ".output", "%s: unknown key output.%s" % (code, str(k)[:60]))
        mode = outp.get("mode")
        if mode != "command":
            f("error", "L_MODE", w + ".output.mode",
              "%s: the mode is command in this release (level and boost need the PWM outputs of Phase 3)" % code)
        if q.get("command_map"):
            if not _same_map(outp.get("command_map"), q["command_map"]):
                f("error", "L_COMMAND_MAP", w + ".output.command_map",
                  "%s: the command map is fixed: DOWN to UP, UP to OFF, OFF to OFF (the fans)" % code)
        elif "command_map" in outp:
            f("error", "L_COMMAND_MAP", w + ".output.command_map", "%s: a command map is only for co2" % code)
        act = outp.get("actuator")
        if not isinstance(act, str) or not ACTUATOR_RE.match(act):
            f("error", "L_ACTUATOR", w + ".output.actuator", "%s: choose an actuator" % code)
            continue
        a = next((x for x in spec.get("actuators") or [] if x.get("name") == act), None)
        if a is None:
            f("error", "L_ACTUATOR", w + ".output.actuator",
              "%s: actuator %s is not on the CONTROL board of zone %s" % (code, act, zone))
        elif not _fit(spec, act, q):
            f("error", "L_ACTUATOR_KIND", w + ".output.actuator",
              "%s: actuator %s does not take every command the loop sends (%s)" % (code, act, ", ".join(sends(q))))
        if act in acts:
            f("error", "L_ACTUATOR_SHARED", w + ".output.actuator",
              "%s: actuator %s is driven by %s already (one loop per actuator)" % (code, act, acts[act]))
        else:
            acts[act] = code
    if not stop_all:
        for r in spec.get("existing") or []:
            if r.get("loop_code") not in codes:
                f("warn", "W_STOPPED", "loops.%s" % r.get("loop_code"),
                  "%s stops: its loop is deactivated when this is saved" % r.get("loop_code"))
        if len(loops) > 0:
            for r in spec.get("rows") or []:
                if r.get("offered") and r.get("default_actuator") and r["loop_code"] not in codes \
                        and not any(x.get("loop_code") == r["loop_code"] for x in spec.get("existing") or []):
                    f("warn", "W_NOT_CONTROLLED", "loops.%s" % r["loop_code"],
                      "%s is not controlled: the zone has its sensor and actuator, but no loop" % r["loop_code"])
    return out


def summary(findings):
    return {"findings": findings,
            "errors": sum(1 for x in findings if x["level"] == "error"),
            "warnings": sum(1 for x in findings if x["level"] != "error")}


# ------------------------------------------------------------ terminal ---------
def questions(spec):
    """The terminal's way of asking: one question per ticked row with two or more
    sensors and no choice yet, and per stale row; a row with one sensor is said."""
    out = []
    stale = {s["loop_code"]: s for s in spec.get("stale") or []}
    for r in spec.get("rows") or []:
        code = r["loop_code"]
        if not r.get("ticked"):
            continue
        if code in stale:
            out.append(("Q", code, "%s: %s" % (code, stale[code]["message"])))
        elif r.get("existing"):
            out.append(("INFO", "%s keeps its loop (%s)" % (code, describe(r["loop"]))))
        elif len(r.get("candidates") or []) == 1:
            out.append(("INFO", "%s controls on %s, its only sensor" % (code, r["candidates"][0])))
        elif len(r.get("candidates") or []) > 1:
            out.append(("Q", code, "%s has %d sensors (%s): which does it control on?"
                        % (code, len(r["candidates"]), ", ".join(r["candidates"]))))
    for r in spec.get("rows") or []:
        if r.get("offered") and not r.get("ticked"):
            out.append(("INFO", "%s is offered but not controlled (choose it in the browser to add it)"
                        % r["loop_code"]))
    return out


def options(spec, code, fallback_for=None):
    r = next((x for x in spec.get("rows") or [] if x["loop_code"] == code), None)
    if r is None:
        raise ValueError("no row %s" % code)
    cands = r.get("candidates") or []
    if fallback_for is not None:
        out = [("fb:", "no fallback")]
        out += [("fb:%s" % s, "fall back to %s when %s has no fresh reading" % (s, fallback_for))
                for s in cands if s != fallback_for]
        return out
    out = [("ref:%s" % s, "control on %s" % s) for s in cands]
    if len(cands) > 1:
        out += [("mean", "the mean of all %d" % len(cands)), ("min", "the lowest of all %d" % len(cands)),
                ("max", "the highest of all %d" % len(cands))]
    out.append(("off", "stop this loop" if r.get("existing") else "not controlled"))
    return out


def terminal_answer(spec, lines):
    """The answer from the terminal's choices (code<TAB>token[<TAB>fallback token])."""
    chosen = {}
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2 and parts[0]:
            chosen[parts[0]] = parts[1:]
    loops = []
    for r in spec.get("rows") or []:
        code = r["loop_code"]
        if not r.get("ticked"):
            continue
        c = chosen.get(code)
        if c is None:
            loops.append(copy.deepcopy(r["loop"]))
            continue
        tok = c[0]
        if tok == "off":
            continue
        st = dict(r["state"])
        if tok.startswith("ref:"):
            st.update(rule="reference", reference=tok[4:], fallback=None)
            if len(c) > 1 and c[1].startswith("fb:") and c[1][3:]:
                st["fallback"] = c[1][3:]
        elif tok in ("mean", "min", "max"):
            st.update(rule=tok, reference=None, fallback=None, sensors=list(r.get("candidates") or []))
        else:
            raise ValueError("unknown choice %s for %s" % (tok, code))
        if not st.get("actuator"):
            st["actuator"] = QMAP[code]["actuator"]
        loops.append(row_for(spec, code, st))
    if not loops:
        return {"skip": True}
    return {"skip": False, "stop_all": False, "loops": loops}


def describe(lp):
    inp = lp.get("input") or {}
    out = lp.get("output") or {}
    if inp.get("rule") == "reference":
        s = "on %s" % inp.get("reference")
        if inp.get("fallback"):
            s += ", falling back to %s" % inp["fallback"]
    else:
        s = "%s of %s" % (inp.get("rule"), ", ".join(inp.get("sources") or []))
    return "%s, drives %s" % (s, out.get("actuator"))


def result_text(res):
    """save_zone_loops' result in words."""
    def names(k):
        return ", ".join(x.get("loop_code", "?") for x in res.get(k) or [])
    if not res.get("changed"):
        return "control loops unchanged (%s)" % (names("unchanged") or "none")
    parts = []
    for k, word in (("inserted", "created"), ("updated", "updated"), ("unchanged", "unchanged"),
                    ("deactivated", "stopped")):
        if res.get(k):
            parts.append("%s %s" % (word, names(k)))
    return "control loops saved: " + "; ".join(parts)


# ----------------------------------------------------------------- cli ---------
def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _opt(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, args = argv[1], argv[2:]
    try:
        if cmd == "spec":
            if not args:
                print("usage: spec ROLE --context F [--plan-sources F] [--plan-actuators F]", file=sys.stderr)
                return 2
            ctx = _load(_opt(args, "--context"))
            ps = _opt(args, "--plan-sources")
            pa = _opt(args, "--plan-actuators")
            spec = build_spec(args[0], ctx, _load(ps) if ps else None, _load(pa) if pa else None)
            json.dump(spec, sys.stdout)
            print()
            return 0
        if cmd == "validate":
            spec = _load(_opt(args, "--spec"))
            raw = sys.stdin.read()
            try:
                answer = json.loads(raw)
            except ValueError:
                answer = None
                res = summary([{"level": "error", "code": "L_SCHEMA", "where": "answer",
                                "message": "the answer is not JSON"}])
            else:
                res = summary(validate(spec, answer))
            json.dump(res, sys.stdout)
            print()
            return 1 if res["errors"] else 0
        if cmd == "stale":
            spec = _load(_opt(args, "--spec"))
            for s in spec.get("stale") or []:
                print("STALE\t%s\t%s" % (s["loop_code"], s["message"].replace("\t", " ")))
            return 0
        if cmd == "questions":
            spec = _load(_opt(args, "--spec"))
            for q in questions(spec):
                print("\t".join(x.replace("\t", " ") for x in q))
            return 0
        if cmd == "options":
            spec = _load(_opt(args, "--spec"))
            for tok, label in options(spec, _opt(args, "--code"), _opt(args, "--fallback-for")):
                print("OPT\t%s\t%s" % (tok, label))
            return 0
        if cmd == "terminal-answer":
            spec = _load(_opt(args, "--spec"))
            json.dump(terminal_answer(spec, sys.stdin.read().splitlines()), sys.stdout)
            print()
            return 0
        if cmd == "payload":
            answer = json.loads(sys.stdin.read())
            if answer.get("skip"):
                print("skip")
            else:
                print(json.dumps(answer.get("loops") or [], separators=(",", ":")))
            return 0
        if cmd == "result-text":
            print(result_text(json.loads(sys.stdin.read())))
            return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("loops.py %s: %s" % (cmd, e), file=sys.stderr)
        return 2
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
