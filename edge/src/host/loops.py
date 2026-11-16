#!/usr/bin/env python3
"""The onboarding wizard's control-loop picker (feedback control Phase 2, owner
decision Q20; recipe types, migration 011; codeplan/feedback-control-plan.md).

A loop has two halves, each bound by the onboarding of its own board, in either order:
the input (which sensor, and which of its tags, a quantity is controlled on), bound by
a SENSE onboarding, and the output (which actuator it drives), bound by a CONTROL
onboarding. A loop with one half is half-bound: saved, shown, never run. The
quantities are the zone's unit's recipe type's (zone_loop_context's
allowed.quantities: tag = the default sense tag, sense_uoms, commands, command_map,
loopable, required); a row per loopable one.

  SENSE   half input:  per quantity, which (sensor, tag) feeds it: a tag whose UoM is
          one of the quantity's sense_uoms (a tag without a UoM only when it is the
          default tag, with a note). The default tag is preferred; a default tag
          published by one sensor is preselected, by several is in error (L_CHOOSE)
          until the person picks the reference (and optionally a fallback), or
          mean/min/max over the sensors of that tag, or marks it not controlled (Q20).
  CONTROL half output: per quantity, which actuator acts on it: the actuators that
          declare the quantity (actuator_definitions.<a>.quantity), else those taking
          every command it sends.
  ZONE    (--loops-only) both halves.

The database is the final judge: medcea.save_zone_loops(zone, {half, loops})
(migration 011) replaces that half of the zone's loops with the list it is sent; a
code left out loses that half, and a loop left with neither is deactivated. The
checks here mirror its _loop_check() word for word (every message of a database rule
is one of _loop_check's or save_zone_loops' literals: tests/test_loops.py) and add the
picker's own (L_CHOOSE, L_EMPTY, the answer's shape, the warnings). edge/src/host/ui/
loops.js mirrors validate() between /* loops-logic:begin */ and :end
(tests/test_loops_ui.py compares them on every fixture in tests/fixtures/loops/).

Standard library only and no relative import, so tests load it by path.

The answer the picker gives (the page posts it as a JSON string):

    {"skip": true}                                         Decide later: nothing is saved
    {"skip": false, "stop_all": false, "half": H, "loops": [...]}   that half of every loop
    {"skip": false, "stop_all": true,  "half": H, "loops": []}      Stop all (confirmed)

CLI (flash-device.sh's plan_loops; every JSON on stdout):

    spec ROLE --context F [--plan-sources F] [--plan-actuators F]
                                 the picker's spec (ROLE SENSE, CONTROL or ZONE)
    validate --spec F            answer on stdin -> {findings, errors, warnings}; exit 1 on an error
    stale --spec F               STALE<TAB>loop_code<TAB>message, one line per stale loop
    questions --spec F           the terminal's questions: Q<TAB>key<TAB>label / INFO<TAB>text
                                 (key: the loop_code, or <loop_code>:output for an actuator
                                 question of the ZONE picker)
    options --spec F --code KEY [--fallback-for X]
                                 OPT<TAB>token<TAB>label lines for one question
    terminal-answer --spec F     "key<TAB>token[<TAB>fallback]" lines on stdin -> the answer
    payload                      answer on stdin -> "skip", or {"half", "loops"} to save
    result-text                  save_zone_loops' result on stdin -> one line of words
"""

import copy
import json
import math
import re
import sys

SPEC_VERSION = 2
# The loopable quantities of apps/database/recipe_types.yaml (the catalogue migration
# 011 seeds), PLANT's required flags: used only when a context carries no
# allowed.quantities (an offline test, a database before 011). tests/test_loops.py
# keeps it equal to the YAML.
FALLBACK_QUANTITIES = [
    {"loop_code": "air_temperature", "label": "Air temperature", "unit": "°C", "tag": "air_temperature",
     "sense_uoms": ["C"], "commands": ["DOWN", "OFF", "UP"], "phase": "always", "loopable": True,
     "required": True},
    {"loop_code": "air_humidity", "label": "Air humidity", "unit": "%RH", "tag": "air_humidity",
     "sense_uoms": ["RH%"], "commands": ["DOWN", "OFF", "UP"], "phase": "always", "loopable": True,
     "required": True},
    {"loop_code": "co2", "label": "CO₂", "unit": "ppm", "tag": "co2",
     "sense_uoms": ["ppm"], "commands": ["OFF", "UP"], "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"},
     "phase": "always", "loopable": True, "required": True},
    {"loop_code": "substrate_temperature", "label": "Substrate temperature", "unit": "°C",
     "tag": "ground_temperature", "sense_uoms": ["C"], "commands": ["DOWN", "OFF", "UP"], "phase": "always",
     "loopable": True, "required": False},
]
HALVES = {"SENSE": "input", "CONTROL": "output", "ZONE": "both"}
RULES = ("reference", "mean", "min", "max")
MODES = ("command",)
MAX_AGE_MIN, MAX_AGE_MAX, MAX_AGE_DEFAULT = 1, 3600, 90
MAX_LOOPS = 16
STATE_KEY_MAX = 50
RESERVED = "default"
INSTANCE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TAG_RE = re.compile(r"^[a-z][a-z0-9_]*$")
ACTUATOR_RE = re.compile(r"^[A-Za-z0-9_]+$")
ANSWER_KEYS = ("skip", "stop_all", "half", "loops")
LOOP_KEYS = ("loop_code", "input", "output")
INPUT_KEYS = ("tag", "sources", "rule", "reference", "fallback", "max_age_s")
OUTPUT_KEYS = ("actuator", "mode", "command_map")
INVENTORY_CODES = ("L_SOURCE", "L_SOURCE_TAG", "L_SOURCE_RESERVED", "L_UOM", "L_ACTUATOR", "L_ACTUATOR_KIND",
                   "L_ACTUATOR_QUANTITY")
# the picker's own findings: every other code's message is a database literal
PICKER_CODES = ("L_SCHEMA", "L_EMPTY", "L_CHOOSE")

CODES = {
    "L_SCHEMA": "wrong keys or types, or a page of another version",
    "L_EMPTY": "no loop and no Stop all",
    "L_QUANTITY": "loop_code not a quantity of the unit's recipe type",
    "L_NOT_LOOPABLE": "a quantity that is a setpoint only (no loop yet)",
    "L_DUP": "a loop_code twice",
    "L_STATE_KEY": "loop_code@zone_code over 50 characters",
    "L_HALF": "a half this onboarding does not set, or no half at all",
    "L_TAG": "input.tag not a tag name",
    "L_UOM": "a source whose tag is in another unit than the quantity's",
    "L_RULE": "rule not reference, mean, min, max",
    "L_RULE_ARGS": "mean/min/max with a reference or fallback",
    "L_CHOOSE": "several sensors (or tags) and none chosen (Q20)",
    "L_SOURCES_EMPTY": "no sensor",
    "L_SOURCE_RESERVED": "the reserved sensor id default",
    "L_SOURCE": "a sensor the zone does not have",
    "L_SOURCE_TAG": "a sensor not publishing the tag",
    "L_REFERENCE": "reference not one of the sources",
    "L_FALLBACK": "fallback not another source",
    "L_SOURCES_EXTRA": "rule reference with sources besides reference and fallback",
    "L_MAX_AGE": "max_age_s not a whole number from 1 to 3600",
    "L_MODE": "mode other than command",
    "L_COMMAND_MAP": "a map other than the quantity's, or a map on a quantity without one",
    "L_ACTUATOR": "an actuator the zone does not have",
    "L_ACTUATOR_KIND": "an actuator without every command the loop sends",
    "L_ACTUATOR_QUANTITY": "an actuator declaring another quantity",
    "L_ACTUATOR_SHARED": "two loops on one actuator",
    "W_OLD_BOARD": "a board flashed before Phase 1",
    "W_SENSOR_PROBLEM": "a sensor the database cannot name",
    "W_NO_UOM": "a source tag without a UoM (not checked)",
    "W_NOT_CONTROLLED": "a quantity this board could serve, unticked",
    "W_STOPPED": "an active loop's half left out",
    "W_HALF_BOUND": "a loop that waits for its other half",
    "W_DEFAULT_MAP": "Stop all",
    "W_DECIDE_LATER": "Decide later with several sensors on a tag",
}


def sends(q):
    """The commands a loop of quantity q can send the actuator (after its command_map)."""
    if isinstance(q.get("command_map"), dict) and q["command_map"]:
        return sorted(set(q["command_map"].values()))
    return sorted(q.get("commands") or ["DOWN", "OFF", "UP"])


def jsonb_text(obj):
    """jsonb's text form of a flat object of strings: keys by length, then bytes."""
    keys = sorted(obj, key=lambda k: (len(k.encode()), k.encode()))
    return "{" + ", ".join("%s: %s" % (json.dumps(k), json.dumps(obj[k])) for k in keys) + "}"


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
    """[{name, kind, commands, quantity}] from a CONTROL board's actuator_definitions, as
    _zone_inventory derives them: kind commands|types|unknown, commands sorted, the
    declared quantity (a string) or None."""
    out = []
    for name in sorted((defs or {})):
        d = defs[name] if isinstance(defs[name], dict) else {}
        q = d.get("quantity") if isinstance(d.get("quantity"), str) else None
        if isinstance(d.get("commands"), dict):
            out.append({"name": name, "kind": "commands", "commands": sorted(d["commands"]), "quantity": q})
        elif isinstance(d.get("types"), dict):
            out.append({"name": name, "kind": "types", "commands": [], "quantity": q})
        else:
            out.append({"name": name, "kind": "unknown", "commands": [], "quantity": q})
    return out


def quantities_of(ctx):
    """The spec's quantities from zone_loop_context's allowed.quantities (the unit's recipe
    type, every quantity, loopable or not), ordered as the catalogue; the fallback only
    for a context without them (a database before migration 011). An empty object is a
    recipe type with no quantity: no row, as the database would refuse every code."""
    aq = ((ctx or {}).get("allowed") or {}).get("quantities")
    if not isinstance(aq, dict):
        out = copy.deepcopy(FALLBACK_QUANTITIES)
    else:
        out = []
        for code in sorted(aq, key=lambda c: ((aq[c] or {}).get("ordinal", 0), c)):
            d = aq[code] or {}
            q = {"loop_code": code, "label": d.get("label") or code, "unit": d.get("unit") or "",
                 "tag": d.get("tag"), "sense_uoms": list(d.get("sense_uoms") or []),
                 "commands": sorted(d.get("commands") or ["DOWN", "OFF", "UP"]),
                 "phase": d.get("phase") or "always", "loopable": bool(d.get("loopable")),
                 "required": bool(d.get("required"))}
            if isinstance(d.get("command_map"), dict):
                q["command_map"] = dict(d["command_map"])
            out.append(q)
    for q in out:
        q["sends"] = sends(q)
    return out


def qmap(spec):
    return {q["loop_code"]: q for q in spec.get("quantities") or []}


def _source(spec, name):
    for s in spec.get("sources") or []:
        if s.get("instance") == name:
            return s
    return None


def _uom_ok(q, uom):
    return not uom or uom in (q.get("sense_uoms") or [])


def candidates(spec, code, tag):
    """The zone's sensors publishing tag in one of the quantity's units (or with no
    unit), in inventory order."""
    q = qmap(spec).get(code)
    if q is None or not tag:
        return []
    return [s["instance"] for s in spec.get("sources") or []
            if tag in (s.get("tags") or []) and _uom_ok(q, (s.get("uoms") or {}).get(tag))]


def pairs(spec, q):
    """[{instance, tag, uom}] a quantity can read: every tag in one of its units, and a
    tag without a unit only when it is the quantity's default tag; the default tag's
    first, then the rest in inventory order."""
    first, rest = [], []
    for s in spec.get("sources") or []:
        for t in s.get("tags") or []:
            uom = (s.get("uoms") or {}).get(t) or None
            if uom is None and t != q.get("tag"):
                continue
            if not _uom_ok(q, uom):
                continue
            (first if t == q.get("tag") else rest).append({"instance": s.get("instance"), "tag": t, "uom": uom})
    return first + rest


def _actuator(spec, name):
    for a in spec.get("actuators") or []:
        if a.get("name") == name:
            return a
    return None


def _fit(spec, name, q):
    a = _actuator(spec, name)
    return (a is not None and a.get("kind") == "commands"
            and all(c in (a.get("commands") or []) for c in sends(q))
            and (a.get("quantity") is None or a.get("quantity") == q["loop_code"]))


def fits(spec, q):
    """(names, default): the actuators declaring the quantity that take its commands, else
    the undeclared ones taking them; the default is the only declared one, else the one
    named after the quantity (never just any actuator that takes the commands: a co2 fan
    would then be the air temperature's)."""
    code = q["loop_code"]
    ok = [a for a in spec.get("actuators") or [] if a.get("kind") == "commands"
          and all(c in (a.get("commands") or []) for c in sends(q))]
    declared = [a["name"] for a in ok if a.get("quantity") == code]
    if declared:
        return declared, (declared[0] if len(declared) == 1 else None)
    names = [a["name"] for a in ok if a.get("quantity") is None]
    return names, (code if code in names else None)


# --------------------------------------------------------------- rows ----------
def row_for(spec, code, st):
    """One loop from the picker's state for a quantity: {tag, rule, reference, fallback,
    sensors, max_age_s, actuator, input, output}; the spec's half says which halves it
    carries (both: the state's input/output flags). sources follow the choice (critique
    1.6): [reference(, fallback)] for rule reference, the ticked sensors of the tag for
    mean/min/max."""
    q = qmap(spec)[code]
    half = spec.get("half")
    out = {"loop_code": code}
    want_in = half == "input" or (half == "both" and st.get("input") is not False)
    want_out = half == "output" or (half == "both" and st.get("output") is not False)
    if want_in:
        tag = st.get("tag") if isinstance(st.get("tag"), str) and st.get("tag") else None
        rule = st.get("rule") or "reference"
        inp = {"tag": tag}
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
            inp["sources"] = [s for s in candidates(spec, code, tag) if s in ticked]
            inp["rule"] = rule
        inp["max_age_s"] = st.get("max_age_s", MAX_AGE_DEFAULT)
        out["input"] = inp
    if want_out:
        o = {"actuator": st.get("actuator") or None, "mode": "command"}
        if isinstance(q.get("command_map"), dict):
            o["command_map"] = dict(q["command_map"])
        out["output"] = o
    return out


def state_of(row):
    """The picker's state for a stored loop (the inverse of row_for)."""
    inp = row.get("input") if isinstance(row.get("input"), dict) else {}
    out = row.get("output") if isinstance(row.get("output"), dict) else {}
    rule = inp.get("rule") if inp.get("rule") in RULES else "reference"
    srcs = [s for s in inp.get("sources") or [] if isinstance(s, str)]
    return {"tag": inp.get("tag") if isinstance(inp.get("tag"), str) else None,
            "rule": rule,
            "reference": inp.get("reference") if rule == "reference" else None,
            "fallback": inp.get("fallback") if rule == "reference" else None,
            "sensors": srcs if rule != "reference" else [],
            "max_age_s": inp.get("max_age_s", MAX_AGE_DEFAULT),
            "actuator": out.get("actuator") if isinstance(out.get("actuator"), str) else None,
            "input": isinstance(row.get("input"), dict),
            "output": isinstance(row.get("output"), dict)}


def _stale(spec, ex):
    """What of a stored loop the board being onboarded takes away (its half only), or None."""
    code = ex.get("loop_code")
    q = qmap(spec).get(code)
    if q is None:
        return None
    half = spec.get("half")
    missing, bad_act = [], None
    inp = ex.get("input")
    if half in ("input", "both") and isinstance(inp, dict):
        cands = candidates(spec, code, inp.get("tag"))
        missing = [s for s in inp.get("sources") or [] if isinstance(s, str) and s not in cands]
    out = ex.get("output")
    if half in ("output", "both") and isinstance(out, dict):
        act = out.get("actuator")
        if not (isinstance(act, str) and _fit(spec, act, q)):
            bad_act = act
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


def _stored(half, ex):
    """The half (or halves) of a stored loop this picker shows, or None."""
    if ex is None:
        return None
    lp = {"loop_code": ex["loop_code"]}
    if half in ("input", "both") and isinstance(ex.get("input"), dict):
        lp["input"] = copy.deepcopy(ex["input"])
    if half in ("output", "both") and isinstance(ex.get("output"), dict):
        lp["output"] = copy.deepcopy(ex["output"])
    return lp if len(lp) > 1 else None


def build_spec(role, ctx, plan_sources=None, plan_actuators=None):
    """The picker's spec from zone_loop_context's answer and the board being
    onboarded: a SENSE board's planned sensors replace the zone's (the database
    still holds the old ones until register); a CONTROL board's planned map replaces
    the zone's actuators. ROLE ZONE (--loops-only) takes both from the database."""
    role = (role or "ZONE").upper()
    if role not in HALVES:
        raise ValueError("role must be SENSE, CONTROL or ZONE")
    half = HALVES[role]
    spec = {"version": SPEC_VERSION, "role": role, "half": half, "recipe_type": ctx.get("recipe_type"),
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
                            "uoms": dict(s.get("uoms") or {}), "from": "plan"})
        spec["sources"] = sources
        spec["old_boards"] = []
    else:
        spec["sources"] = [{"instance": s.get("instance"), "driver": s.get("driver"),
                            "tags": list(s.get("tags") or []), "uoms": dict(s.get("uoms") or {}), "from": "zone"}
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
            acts.append({"name": a.get("actuator"), "kind": a.get("kind"), "commands": list(a.get("commands") or []),
                         "quantity": a.get("quantity") if isinstance(a.get("quantity"), str) else None})
        spec["actuators"] = acts
    existing = []
    for lp in ctx.get("loops") or []:
        ex = {"loop_id": lp.get("loop_id"), "loop_code": lp.get("loop_code"),
              "input": copy.deepcopy(lp.get("input")) if isinstance(lp.get("input"), dict) else None,
              "output": copy.deepcopy(lp.get("output")) if isinstance(lp.get("output"), dict) else None}
        ex["live"] = ex["input"] is not None and ex["output"] is not None
        existing.append(ex)
    spec["existing"] = existing
    spec["quantities"] = quantities_of(ctx)
    spec["stale"] = [x for x in (_stale(spec, r) for r in existing) if x]
    in_side, out_side = half in ("input", "both"), half in ("output", "both")
    any_in = any(e["input"] is not None for e in existing)
    any_out = any(e["output"] is not None for e in existing)
    rows = []
    for q in spec["quantities"]:
        if not q["loopable"]:
            continue
        code = q["loop_code"]
        ex = next((e for e in existing if e["loop_code"] == code), None)
        prs = pairs(spec, q) if in_side else []
        tags = []
        for p in prs:
            if p["tag"] not in tags:
                tags.append(p["tag"])
        dtag = q["tag"] if q["tag"] in tags else None
        names, dact = fits(spec, q) if out_side else ([], None)
        row = {"loop_code": code, "label": q["label"], "pairs": prs, "tags": tags, "default_tag": dtag,
               "candidates": candidates(spec, code, dtag) if dtag else [], "actuators": names,
               "default_actuator": dact, "existing": ex is not None,
               "live": bool(ex and ex["live"]),
               "has_input": bool(ex and ex["input"] is not None),
               "has_output": bool(ex and ex["output"] is not None)}
        stored = _stored(half, ex)
        if stored is not None:
            row.update(offered=True, ticked=True, loop=stored, state=state_of(stored), reason="")
        else:
            can_in, can_out = bool(prs), bool(names)
            offer = can_in if half == "input" else can_out if half == "output" else (can_in or can_out)
            if offer:
                cands = row["candidates"]
                st = {"tag": dtag, "rule": "reference", "reference": cands[0] if len(cands) == 1 else None,
                      "fallback": None, "sensors": list(cands), "max_age_s": MAX_AGE_DEFAULT, "actuator": dact,
                      "input": can_in, "output": can_out}
                if half == "input":
                    ticked = dtag is not None and (ex is not None or not any_in)
                elif half == "output":
                    ticked = dact is not None and (ex is not None or not any_out)
                else:
                    ticked = dtag is not None and dact is not None and not existing
                row.update(offered=True, ticked=ticked, loop=row_for(spec, code, st), state=st, reason="")
            else:
                why = []
                if in_side and not prs:
                    why.append("no sensor publishes a reading in %s" % " or ".join(q["sense_uoms"] or ["?"]))
                if out_side and not names:
                    why.append("no actuator takes %s" % ", ".join(sends(q)))
                row.update(offered=False, ticked=False, loop=None, state=None, reason=" and ".join(why))
        row["default"] = (dtag is not None if half == "input" else dact is not None if half == "output"
                          else dtag is not None and dact is not None)
        rows.append(row)
    spec["rows"] = rows
    spec["rules"] = list(RULES)
    spec["modes"] = list(MODES)
    spec["max_age"] = {"min": MAX_AGE_MIN, "max": MAX_AGE_MAX, "default": MAX_AGE_DEFAULT}
    spec["initial"] = defaults(spec)
    return spec


def defaults(spec):
    """The picker's starting answer: every ticked row (stored halves as they are; a new
    row as row_for says)."""
    return {"skip": False, "stop_all": False, "half": spec.get("half"),
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


def _show(v):
    return v[:60] if isinstance(v, str) else json.dumps(v)


def _has_half(half, ex):
    if half == "input":
        return ex.get("input") is not None
    if half == "output":
        return ex.get("output") is not None
    return True


def stop_all_text(half, zone):
    if half == "input":
        return ("no sensor of zone %s feeds a loop after this is saved: a loop keeps its actuator and "
                "waits for a sensor (a loop with neither is stopped)" % zone)
    if half == "output":
        return ("no actuator of zone %s is driven by a loop after this is saved: a loop keeps its sensor and "
                "waits for an actuator (a loop with neither is stopped)" % zone)
    return ("every loop of zone %s stops: the zone goes back to the default map (a tag with one sensor "
            "uses it; a tag with several gets no data and an alarm)" % zone)


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
    half = spec.get("half")
    qs = qmap(spec)
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
        if half != "output" and not spec.get("existing"):
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
    if answer.get("half") != half:
        f("error", "L_SCHEMA", "answer.half",
          "the answer sets the %s half, this page the %s half: reload the page" % (_show(answer.get("half")), half))
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
        f("warn", "W_DEFAULT_MAP", "answer.stop_all", stop_all_text(half, zone))
    if len(loops) > MAX_LOOPS:
        f("error", "L_SCHEMA", "answer.loops", "at most %d loops" % MAX_LOOPS)
    loopable = sorted(c for c, q in qs.items() if q.get("loopable"))
    codes, acts, sides = [], {}, {}
    for i, lp in enumerate(loops):
        if not isinstance(lp, dict):
            f("error", "L_SCHEMA", "loops.%d" % i, "a loop must be a JSON object")
            continue
        code = lp.get("loop_code")
        if not isinstance(code, str):
            f("error", "L_QUANTITY", "loops.%d.loop_code" % i, "a loop needs a loop_code")
            continue
        q = qs.get(code)
        if q is None:
            f("error", "L_QUANTITY", "loops.%d.loop_code" % i,
              "loop_code %s is not one of %s" % (code[:60], ", ".join(loopable) or "none"))
            continue
        w = "loops." + code
        if not q.get("loopable"):
            f("error", "L_NOT_LOOPABLE", w + ".loop_code", "%s: a setpoint only, without a feedback loop yet" % code)
            continue
        if code in codes:
            f("error", "L_DUP", w + ".loop_code", "%s: listed twice" % code)
            continue
        codes.append(code)
        if len(code) + 1 + len(zone) > STATE_KEY_MAX:
            f("error", "L_STATE_KEY", w + ".loop_code",
              "%s: the runner's state key %s@%s is longer than %d characters" % (code, code, zone, STATE_KEY_MAX))
        for k in lp:
            if k not in LOOP_KEYS:
                f("error", "L_SCHEMA", w, "%s: unknown key %s" % (code, str(k)[:60]))
        inp = lp.get("input")
        outp = lp.get("output")
        sides[code] = (inp is not None, outp is not None)
        if half == "input" and outp is not None:
            f("error", "L_HALF", w + ".output", "%s: a SENSE onboarding sets the input only" % code)
        elif half == "output" and inp is not None:
            f("error", "L_HALF", w + ".input", "%s: a CONTROL onboarding sets the output only" % code)
        if half == "input" and inp is None:
            f("error", "L_SCHEMA", w + ".input", "%s: input must be an object" % code)
        elif half == "output" and outp is None:
            f("error", "L_SCHEMA", w + ".output", "%s: output must be an object" % code)
        elif half == "both" and inp is None and outp is None:
            f("error", "L_HALF", w, "%s: a loop needs an input or an output" % code)
        if inp is not None:
            _check_input(spec, f, q, code, w, inp, zone)
        if outp is not None:
            _check_output(spec, f, q, code, w, outp, zone, acts)
    if not stop_all:
        for r in spec.get("existing") or []:
            if r.get("loop_code") not in codes and _has_half(half, r):
                if half == "input":
                    msg = ("%s loses its sensor when this is saved: until one is chosen again, a run reads the only fresh sensor of its default tag"
                           % r.get("loop_code"))
                elif half == "output":
                    msg = ("%s loses its actuator when this is saved: until one is chosen again, a run drives the zone's actuator for it, if it has one"
                           % r.get("loop_code"))
                else:
                    msg = "%s stops: its loop is deactivated when this is saved" % r.get("loop_code")
                f("warn", "W_STOPPED", "loops.%s" % r.get("loop_code"), msg)
        if len(loops) > 0:
            for r in spec.get("rows") or []:
                c = r["loop_code"]
                if r.get("offered") and r.get("default") and c not in codes \
                        and not any(x.get("loop_code") == c and _has_half(half, x) for x in spec.get("existing") or []):
                    if half == "input":
                        msg = "%s gets no sensor: this board publishes %s, but it is not ticked" % (c, r["default_tag"])
                    elif half == "output":
                        msg = "%s gets no actuator: this board has %s, but it is not ticked" % (c, r["default_actuator"])
                    else:
                        msg = "%s is not controlled: the zone has its sensor and actuator, but no loop" % c
                    f("warn", "W_NOT_CONTROLLED", "loops.%s" % c, msg)
        for c in codes:
            has_in, has_out = sides[c]
            ex = next((x for x in spec.get("existing") or [] if x.get("loop_code") == c), None)
            if half == "input":
                has_out = bool(ex and ex.get("output") is not None)
            elif half == "output":
                has_in = bool(ex and ex.get("input") is not None)
            if has_in and not has_out:
                f("warn", "W_HALF_BOUND", "loops.%s" % c,
                  "%s waits for its actuator: until a CONTROL board's onboarding chooses one, a run drives the zone's actuator for it, if it has one" % c)
            elif has_out and not has_in:
                f("warn", "W_HALF_BOUND", "loops.%s" % c,
                  "%s waits for its sensor: until a SENSE board's onboarding chooses one, a run reads the only fresh sensor of its default tag" % c)
    return out


def _check_input(spec, f, q, code, w, inp, zone):
    if not isinstance(inp, dict):
        f("error", "L_SCHEMA", w + ".input", "%s: input must be an object" % code)
        return
    for k in inp:
        if k not in INPUT_KEYS:
            f("error", "L_SCHEMA", w + ".input", "%s: unknown key input.%s" % (code, str(k)[:60]))
    tag = inp.get("tag")
    no_tag = tag is None
    if not no_tag and (not isinstance(tag, str) or not TAG_RE.match(tag)):
        f("error", "L_TAG", w + ".input.tag", "%s: input.tag must be a tag name" % code)
        tag = None
    rule = inp.get("rule")
    if not isinstance(rule, str) or rule not in RULES:
        f("error", "L_RULE", w + ".input.rule", "%s: input.rule must be one of reference, mean, min, max" % code)
    srcs = inp.get("sources")
    seen = []
    if not isinstance(srcs, list):
        f("error", "L_SCHEMA", w + ".input.sources", "%s: input.sources must be a non-empty list of sensor names" % code)
    else:
        for s in srcs:
            if not isinstance(s, str):
                f("error", "L_SCHEMA", w + ".input.sources", "%s: input.sources must hold sensor names (strings)" % code)
                continue
            if s in seen:
                f("error", "L_SCHEMA", w + ".input.sources", "%s: sensor %s is listed twice" % (code, s[:60]))
                continue
            seen.append(s)
            src = _source(spec, s)
            if s == RESERVED:
                f("error", "L_SOURCE_RESERVED", w + ".input.sources." + s,
                  "%s: sensor default is reserved for readings without a sensor name (a board flashed before "
                  "Phase 1): re-onboard the board and choose its named sensor" % code)
            elif src is None:
                f("error", "L_SOURCE", w + ".input.sources." + s,
                  "%s: sensor %s is not on an active SENSE board of zone %s" % (code, s[:60], zone))
            elif tag is not None:
                if tag not in (src.get("tags") or []):
                    f("error", "L_SOURCE_TAG", w + ".input.sources." + s, "%s: sensor %s does not publish %s" % (code, s, tag))
                else:
                    uom = (src.get("uoms") or {}).get(tag) or ""
                    if uom and uom not in (q.get("sense_uoms") or []):
                        f("error", "L_UOM", w + ".input.sources." + s,
                          "%s: sensor %s publishes %s in %s, not %s"
                          % (code, s, tag, uom, " or ".join(sorted(q.get("sense_uoms") or []))))
                    elif not uom:
                        f("warn", "W_NO_UOM", w + ".input.sources." + s,
                          "%s: sensor %s publishes %s without a unit, so it is not checked to be in %s"
                          % (code, s, tag, " or ".join(sorted(q.get("sense_uoms") or []))))
    cands = candidates(spec, code, tag) if tag is not None else []
    choose = no_tag or (rule == "reference" and inp.get("reference") is None)
    if no_tag:
        reads = ["%s %s" % (p["instance"], p["tag"]) for p in pairs(spec, q)]
        f("error", "L_CHOOSE", w + ".input.tag",
          "%s can read %s: choose the tag and the sensor it controls on, or mark it not controlled"
          % (code, ", ".join(reads) or "nothing on this board"))
    elif choose:
        f("error", "L_CHOOSE", w + ".input.reference",
          "%s has %d sensors (%s): choose the one it controls on, or mean/min/max, or mark it not controlled"
          % (code, len(cands), ", ".join(cands)))
    elif isinstance(srcs, list) and len(srcs) == 0:
        f("error", "L_SOURCES_EMPTY", w + ".input.sources",
          "%s: input.sources must be a non-empty list of sensor names" % code)
    if rule == "reference" and not choose:
        ref = inp.get("reference")
        if not isinstance(ref, str):
            f("error", "L_REFERENCE", w + ".input.reference",
              "%s: rule reference needs input.reference, one of the sources" % code)
        elif ref not in seen:
            f("error", "L_REFERENCE", w + ".input.reference",
              "%s: input.reference %s is not one of the sources" % (code, ref[:60]))
        fb = None
        if "fallback" in inp:
            fb = inp.get("fallback")
            if not isinstance(fb, str):
                f("error", "L_FALLBACK", w + ".input.fallback", "%s: input.fallback must be a sensor name" % code)
                fb = None
            elif fb == ref:
                f("error", "L_FALLBACK", w + ".input.fallback",
                  "%s: input.fallback must be another sensor than the reference" % code)
            elif fb not in seen:
                f("error", "L_FALLBACK", w + ".input.fallback",
                  "%s: input.fallback %s is not one of the sources" % (code, fb[:60]))
        rs = ref if isinstance(ref, str) else None
        if any(s != rs and s != fb for s in seen):
            f("error", "L_SOURCES_EXTRA", w + ".input.sources",
              "%s: with rule reference, input.sources holds only the reference and the fallback" % code)
    elif rule in ("mean", "min", "max") and ("reference" in inp or "fallback" in inp):
        f("error", "L_RULE_ARGS", w + ".input.rule", "%s: rule %s takes no reference or fallback" % (code, rule))
    if "max_age_s" in inp:
        n = inp.get("max_age_s")
        if not _isnum(n) or not math.isfinite(n) or n != int(n) or n < MAX_AGE_MIN or n > MAX_AGE_MAX:
            f("error", "L_MAX_AGE", w + ".input.max_age_s",
              "%s: input.max_age_s must be a whole number of seconds from 1 to 3600" % code)


def _check_output(spec, f, q, code, w, outp, zone, acts):
    if not isinstance(outp, dict):
        f("error", "L_SCHEMA", w + ".output", "%s: output must be an object" % code)
        return
    for k in outp:
        if k not in OUTPUT_KEYS:
            f("error", "L_SCHEMA", w + ".output", "%s: unknown key output.%s" % (code, str(k)[:60]))
    if outp.get("mode") != "command":
        f("error", "L_MODE", w + ".output.mode",
          "%s: output.mode must be command (level and boost need Phase 3's PWM outputs)" % code)
    if isinstance(q.get("command_map"), dict):
        if not _same_map(outp.get("command_map"), q["command_map"]):
            f("error", "L_COMMAND_MAP", w + ".output.command_map",
              "%s: output.command_map must be exactly %s" % (code, jsonb_text(q["command_map"])))
    elif "command_map" in outp:
        f("error", "L_COMMAND_MAP", w + ".output.command_map",
          "%s: output.command_map is only for a quantity whose catalogue entry has one" % code)
    act = outp.get("actuator")
    if not isinstance(act, str) or not ACTUATOR_RE.match(act):
        f("error", "L_ACTUATOR", w + ".output.actuator", "%s: output.actuator must be an actuator name" % code)
        return
    a = _actuator(spec, act)
    if a is None:
        f("error", "L_ACTUATOR", w + ".output.actuator",
          "%s: actuator %s is not on an active CONTROL board of zone %s" % (code, act, zone))
    elif a.get("kind") != "commands" or not all(c in (a.get("commands") or []) for c in sends(q)):
        f("error", "L_ACTUATOR_KIND", w + ".output.actuator",
          "%s: actuator %s does not take every command the loop sends (%s)" % (code, act, ", ".join(sends(q))))
    elif a.get("quantity") is not None and a.get("quantity") != code:
        f("error", "L_ACTUATOR_QUANTITY", w + ".output.actuator",
          "%s: actuator %s acts on %s, not %s" % (code, act, a.get("quantity"), code))
    if act in acts:
        f("error", "L_ACTUATOR_SHARED", w + ".output.actuator",
          "%s: actuator %s is driven by another loop of the zone" % (code, act))
    else:
        acts[act] = code


def summary(findings):
    return {"findings": findings,
            "errors": sum(1 for x in findings if x["level"] == "error"),
            "warnings": sum(1 for x in findings if x["level"] != "error")}


# ------------------------------------------------------------ terminal ---------
def describe(lp):
    parts = []
    inp = lp.get("input")
    if isinstance(inp, dict):
        if inp.get("rule") == "reference":
            s = "on %s" % inp.get("reference")
            if inp.get("fallback"):
                s += ", falling back to %s" % inp["fallback"]
        else:
            s = "%s of %s" % (inp.get("rule"), ", ".join(inp.get("sources") or []))
        if inp.get("tag"):
            s += " (%s)" % inp["tag"]
        parts.append(s)
    out = lp.get("output")
    if isinstance(out, dict):
        parts.append("drives %s" % out.get("actuator"))
    return ", ".join(parts) or "nothing"


def questions(spec):
    """The terminal's way of asking: per ticked row, a question for a sensor choice the
    picker cannot make (two or more sensors on the default tag, or a stale input) and
    for an actuator choice (two or more and none declared, or a stale output); what is
    decided is said."""
    out = []
    half = spec.get("half")
    stale = {s["loop_code"]: s for s in spec.get("stale") or []}
    for r in spec.get("rows") or []:
        code = r["loop_code"]
        if not r.get("ticked"):
            continue
        st = stale.get(code)
        if half != "output":
            if st and st["missing_sources"]:
                out.append(("Q", code, "%s: %s" % (code, st["message"])))
            elif r.get("has_input"):
                out.append(("INFO", "%s keeps its sensor (%s)" % (code, describe({"input": r["loop"].get("input")}))))
            elif len(r.get("candidates") or []) == 1:
                out.append(("INFO", "%s controls on %s, its only sensor" % (code, r["candidates"][0])))
            elif len(r.get("candidates") or []) > 1:
                out.append(("Q", code, "%s has %d sensors (%s): which does it control on?"
                            % (code, len(r["candidates"]), ", ".join(r["candidates"]))))
        if half != "input":
            key = code if half == "output" else code + ":output"
            if st and st["missing_actuator"] is not None:
                out.append(("Q", key, "%s: %s" % (code, st["message"])))
            elif r.get("has_output"):
                out.append(("INFO", "%s keeps its actuator (%s)" % (code, describe({"output": r["loop"].get("output")}))))
            elif r.get("default_actuator"):
                out.append(("INFO", "%s acts through %s" % (code, r["default_actuator"])))
            elif len(r.get("actuators") or []) > 1:
                out.append(("Q", key, "%s can act through %s: which one?" % (code, ", ".join(r["actuators"]))))
    for r in spec.get("rows") or []:
        if r.get("offered") and not r.get("ticked"):
            out.append(("INFO", "%s is offered but not controlled (choose it in the browser to add it)"
                        % r["loop_code"]))
    return out


def _key(spec, key):
    code, _, suf = (key or "").partition(":")
    side = "output" if suf == "output" or (not suf and spec.get("half") == "output") else "input"
    return code, side


def options(spec, key, fallback_for=None):
    code, side = _key(spec, key)
    r = next((x for x in spec.get("rows") or [] if x["loop_code"] == code), None)
    if r is None:
        raise ValueError("no row %s" % code)
    off = ("off", "stop this loop" if r.get("existing") else "not controlled")
    if side == "output":
        return [("act:%s" % a, "act through %s" % a) for a in r.get("actuators") or []] + [off]
    tag = (r.get("state") or {}).get("tag") or r.get("default_tag")
    cands = candidates(spec, code, tag) if tag else []
    if fallback_for is not None:
        out = [("fb:", "no fallback")]
        out += [("fb:%s" % s, "fall back to %s when %s has no fresh reading" % (s, fallback_for))
                for s in cands if s != fallback_for]
        return out
    out = [("ref:%s" % s, "control on %s" % s) for s in cands]
    if len(cands) > 1:
        out += [("mean", "the mean of all %d" % len(cands)), ("min", "the lowest of all %d" % len(cands)),
                ("max", "the highest of all %d" % len(cands))]
    out.append(off)
    return out


def terminal_answer(spec, lines):
    """The answer from the terminal's choices (key<TAB>token[<TAB>fallback token])."""
    chosen = {}
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2 and parts[0]:
            chosen[_key(spec, parts[0])] = parts[1:]
    loops = []
    for r in spec.get("rows") or []:
        code = r["loop_code"]
        if not r.get("ticked"):
            continue
        cin, cout = chosen.get((code, "input")), chosen.get((code, "output"))
        if (cin and cin[0] == "off") or (cout and cout[0] == "off"):
            continue
        if cin is None and cout is None:
            loops.append(copy.deepcopy(r["loop"]))
            continue
        st = dict(r["state"])
        if cin is not None:
            tok = cin[0]
            if tok.startswith("ref:"):
                st.update(rule="reference", reference=tok[4:], fallback=None)
                if len(cin) > 1 and cin[1].startswith("fb:") and cin[1][3:]:
                    st["fallback"] = cin[1][3:]
            elif tok in ("mean", "min", "max"):
                st.update(rule=tok, reference=None, fallback=None,
                          sensors=candidates(spec, code, st.get("tag") or r.get("default_tag")))
            else:
                raise ValueError("unknown choice %s for %s" % (tok, code))
            if not st.get("tag"):
                st["tag"] = r.get("default_tag")
        if cout is not None:
            if not cout[0].startswith("act:"):
                raise ValueError("unknown choice %s for %s" % (cout[0], code))
            st["actuator"] = cout[0][4:]
        loops.append(row_for(spec, code, st))
    if not loops:
        return {"skip": True}
    return {"skip": False, "stop_all": False, "half": spec.get("half"), "loops": loops}


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


def payload(answer):
    """What save_zone_loops gets: "skip", or {"half", "loops"}."""
    if answer.get("skip"):
        return "skip"
    if answer.get("half") not in ("input", "output", "both"):
        raise ValueError("the answer names no half (input, output or both)")
    return {"half": answer["half"], "loops": answer.get("loops") or []}


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
            p = payload(json.loads(sys.stdin.read()))
            print(p if p == "skip" else json.dumps(p, separators=(",", ":")))
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
