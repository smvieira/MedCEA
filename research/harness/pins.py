"""Snapshot pins in a scenario, resolved before any run (design §4.2, revised by §9 R7, R8).

Two scenario keys pin a scenario to the lake's snapshots, and campaign.resolve_spec
resolves them here, once, in the parent process: workers receive plain values, nothing
fetches or reads a pinned file in a worker, and determinism is untouched.

    calibration:      {path, sha256, extrapolate?: {<tag>: <why>}}
    recipe_line_from: {extract, sha256, snapshot_id, lineage, recipe_id, seq,
                       light?: {light_on_minutes, light_off_minutes, why}}

A path is relative to the file that holds the key (the scenario file's own directory, or
the spec's for an inline scenario) and is kept as written. Each pin gains `resolved`: what
it applied (the calibration's sensor overrides, the recipe line it picked), so the spec's
digest covers both the provenance and the values, and runner.normalise refuses a pin
without it and checks the values are the ones in effect.

calibration: the file's sha256 must match; calibfile.check() holds (schema, sensor model
version, no fitted plant entry, assumed and spec values equal to the defaults); a file
recorded dirty is refused unless the campaign runs with --allow-dirty; each applied value
becomes sensors.overrides[<model>][<field>], merged per tag into the dict fields over the
model's defaults (runner's override replaces whole dicts); a value the scenario sets too is
refused; a sensor the scenario removes is skipped; the scenario's humidity setpoints and
initial humidity must lie in the calibration's validity unless extrapolate names a reason.

recipe_line_from: the extract's sha256, its digests (recomputed offline), snapshot id and
lineage must match; the (recipe_id, seq) line sets recipe_type and recipe_line; a scenario
naming another recipe type, or giving recipe_line too, is refused; a photoperiod under 60
minutes (the recipe files' 1/1 placeholder) needs `light` with a why; the extract's
catalogue (each quantity's min and max) must equal git's recipe_types.yaml.
"""
from __future__ import annotations

import copy
import hashlib
import os
from decimal import Decimal

import yaml

from ..calib import calibfile, extract, pgtext, sensor_fit
from . import algorithms_loader
from ..twin_plant.chamber import ChamberParams

CALIBRATION_KEYS = {"path", "sha256", "extrapolate"}
LINE_FROM_KEYS = {"extract", "sha256", "snapshot_id", "lineage", "recipe_id", "seq", "light"}
LIGHT_KEYS = {"light_on_minutes", "light_off_minutes", "why"}
MIN_PERIOD_MIN = 60


class PinError(ValueError):
    """A pin that cannot be resolved as it says."""


def _read_pinned(base_dir, rel, want, what):
    if not isinstance(rel, str) or not rel:
        raise PinError("%s needs a path" % what)
    if not isinstance(want, str) or len(want) != 64 or any(c not in "0123456789abcdef" for c in want.lower()):
        raise PinError("%s needs sha256: the 64-hex sha256 of the file's bytes" % what)
    path = os.path.join(base_dir, rel)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise PinError("%s %s: %s" % (what, rel, e.strerror or e)) from None
    got = hashlib.sha256(data).hexdigest()
    if got != want.lower():
        raise PinError("%s %s sha256 differs: the file is %s, the pin says %s" % (what, rel, got, want.lower()))
    return data


def _plain(v):
    """A loads_raw value with every number as an int (no fraction or exponent) or a float."""
    if isinstance(v, pgtext.Num):
        s = str(v)
        return int(s) if s.lstrip("-").isdigit() else float(s)
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _int(text, what):
    try:
        return int(str(text))
    except (TypeError, ValueError):
        raise PinError("%s %r is not a whole number" % (what, text)) from None


def resolve_line_from(sc, base_dir, repo_root):
    pin = sc["recipe_line_from"]
    if not isinstance(pin, dict):
        raise PinError("recipe_line_from must be a mapping")
    if "resolved" in pin:
        raise PinError("recipe_line_from.resolved is written by campaign.resolve_spec, never by hand")
    bad = sorted(set(pin) - LINE_FROM_KEYS)
    missing = sorted(LINE_FROM_KEYS - {"light"} - set(pin))
    if bad or missing:
        raise PinError("recipe_line_from: unknown %s, missing %s" % (bad or "-", missing or "-"))
    if "recipe_line" in sc:
        raise PinError("recipe_line and recipe_line_from both given: the pin sets the line")
    data = _read_pinned(base_dir, pin["extract"], pin["sha256"], "recipe_line_from extract")
    doc = yaml.safe_load(data.decode("utf-8"))
    try:
        extract.verify_doc(doc, pin["extract"])
    except extract.ExtractError as e:
        raise PinError(str(e)) from None
    lake = doc["lake"]
    if lake["snapshot_id"] != pin["snapshot_id"]:
        raise PinError("recipe_line_from: the extract is snapshot %s, the pin says %s"
                       % (lake["snapshot_id"], pin["snapshot_id"]))
    if str(lake["lineage"]).lower() != str(pin["lineage"]).lower():
        raise PinError("recipe_line_from: the extract's lineage is %s, the pin says %s"
                       % (lake["lineage"], pin["lineage"]))
    rid, seq = pin["recipe_id"], pin["seq"]
    lines = [r for r in doc["recipe_lines"] if _int(r["recipe_id"], "recipe_id") == rid
             and _int(r["seq"], "seq") == seq]
    if len(lines) != 1:
        raise PinError("recipe_line_from: snapshot %s has no line seq %s of recipe %s" % (lake["snapshot_id"], seq,
                                                                                         rid))
    line = lines[0]
    recipes = [r for r in doc["recipes"] if _int(r["recipe_id"], "recipe_id") == rid]
    if len(recipes) != 1:
        raise PinError("recipe_line_from: snapshot %s has no recipe %s" % (lake["snapshot_id"], rid))
    rtype = recipes[0]["recipe_type"]
    if "recipe_type" in sc and sc["recipe_type"] != rtype:
        raise PinError("recipe_line_from: recipe %s is a %s recipe, the scenario says %s" % (rid, rtype,
                                                                                            sc["recipe_type"]))
    _check_catalogue(doc, repo_root)
    resolved_line = {"setpoints": _plain(pgtext.loads_raw(line["setpoints"])), "light_type": line["light_type"],
                     "light_on_minutes": _int(line["light_on_minutes"], "light_on_minutes"),
                     "light_off_minutes": _int(line["light_off_minutes"], "light_off_minutes")}
    light = pin.get("light")
    override = None
    if light is not None:
        if not isinstance(light, dict) or set(light) != LIGHT_KEYS:
            raise PinError("recipe_line_from.light is {light_on_minutes, light_off_minutes, why}")
        if not isinstance(light["why"], str) or not light["why"].strip():
            raise PinError("recipe_line_from.light needs a why")
        for k in ("light_on_minutes", "light_off_minutes"):
            v = light[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise PinError("recipe_line_from.light.%s must be a whole number >= 0" % k)
        override = {"from": {k: resolved_line[k] for k in ("light_on_minutes", "light_off_minutes")},
                    "to": {k: light[k] for k in ("light_on_minutes", "light_off_minutes")}, "why": light["why"]}
        resolved_line.update(override["to"])
    elif resolved_line["light_on_minutes"] + resolved_line["light_off_minutes"] < MIN_PERIOD_MIN:
        raise PinError("recipe_line_from: line seq %s of recipe %s has a %d + %d minute photoperiod (a placeholder: "
                       "every cycle, and every controller restart, would last that long); give light: "
                       "{light_on_minutes, light_off_minutes, why}"
                       % (seq, rid, resolved_line["light_on_minutes"], resolved_line["light_off_minutes"]))
    sc["recipe_type"] = rtype
    sc["recipe_line"] = resolved_line
    res = {"recipe_type": rtype, "recipe_line": copy.deepcopy(resolved_line),
           "digests": {"recipe_lines": doc["digests"]["recipe_lines"], "catalogue": doc["digests"]["catalogue"]}}
    if override:
        res["light_override"] = override
    pin["resolved"] = res


def _check_catalogue(doc, repo_root):
    with open(os.path.join(repo_root, algorithms_loader.CATALOGUE), encoding="utf-8") as f:
        git = {q["code"]: q for q in yaml.safe_load(f)["quantities"]}
    snap = {}
    for r in doc["catalogue"]:
        if r["kind"] == "quantity":
            snap[r["code"]] = pgtext.loads_raw(r["doc"])
    for code in sorted(set(git) | set(snap)):
        if code not in git or code not in snap:
            raise PinError("the snapshot's catalogue differs from git's for %s (%s)"
                           % (code, "absent from git" if code not in git else "absent from the snapshot"))
        for k in ("min", "max"):
            a, b = snap[code].get(k), git[code].get(k)
            if a is None or b is None or Decimal(str(a)) != Decimal(str(b)):
                raise PinError("the snapshot's catalogue differs from git's for %s: %s %s, git %s" % (code, k, a, b))


# The room's key for a tag the chamber starts from when the scenario gives no initial value
# (Chamber: initial.get(tag, p.ambient_<key>)), and that an ambient disturbance changes.
AMBIENT_OF = {"air_humidity": "humidity", "air_temperature": "temperature", "co2": "co2"}


def _start_and_ambient(sc, tag):
    """[(what, value)] of TAG's start value as the chamber takes it (initial, else the
    room's ambient: scenario ambient, plant.overrides.ambient_*, ChamberParams' default)
    and of every ambient disturbance that sets the room's value."""
    out = []
    key = AMBIENT_OF.get(tag)
    initial = sc.get("initial") or {}
    if tag in initial:
        out.append(("initial %s" % tag, initial[tag]))
    elif key is not None:
        amb = sc.get("ambient") or {}
        ov = (sc.get("plant") or {}).get("overrides") or {}
        if isinstance(amb, dict) and key in amb:
            out.append(("initial %s (ambient.%s)" % (tag, key), amb[key]))
        elif isinstance(ov, dict) and "ambient_" + key in ov:
            out.append(("initial %s (plant.overrides.ambient_%s)" % (tag, key), ov["ambient_" + key]))
        else:
            out.append(("initial %s (the model's ambient_%s)" % (tag, key),
                        getattr(ChamberParams(), "ambient_" + key)))
    if key is not None:
        for d in sc.get("disturbances") or []:
            if isinstance(d, dict) and d.get("kind") == "ambient" and key in d:
                out.append(("ambient disturbance at %s h %s" % (d.get("at_h"), key), d[key]))
    return out


def _validity(sc, validity, extrapolate):
    """Refuse scenario humidity (setpoints, the start value as the chamber takes it, the
    room's value after an ambient disturbance) outside the calibration's range unless
    extrapolate gives a reason (R7)."""
    used = {}
    for tag, rng in sorted(validity.items()):
        lo, hi = rng
        vals = []
        sp = ((sc.get("recipe_line") or {}).get("setpoints") or {}).get(tag)
        if isinstance(sp, dict):
            vals += [("setpoint %s.%s" % (tag, k), sp.get(k)) for k in ("lower", "upper")]
        vals += _start_and_ambient(sc, tag)
        outside = [(w, v) for w, v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)
                   and not lo <= v <= hi]
        if not outside:
            continue
        why = (extrapolate or {}).get(tag)
        if not isinstance(why, str) or not why.strip():
            raise PinError("calibration: %s lie outside the calibration's validity %s [%s, %s]: the offsets were "
                           "fitted there only; give calibration.extrapolate.%s: <why> to run anyway"
                           % (", ".join("%s %s" % (w, v) for w, v in outside), tag, lo, hi, tag))
        used[tag] = why
    for tag in extrapolate or {}:
        if tag not in validity:
            raise PinError("calibration.extrapolate.%s: the calibration has no validity range for %s" % (tag, tag))
    return used


def resolve_calibration(sc, base_dir, allow_dirty=False):
    pin = sc["calibration"]
    if not isinstance(pin, dict):
        raise PinError("calibration must be a mapping {path, sha256, extrapolate?}")
    if "resolved" in pin:
        raise PinError("calibration.resolved is written by campaign.resolve_spec, never by hand")
    bad = sorted(set(pin) - CALIBRATION_KEYS)
    missing = sorted({"path", "sha256"} - set(pin))
    if bad or missing:
        raise PinError("calibration: unknown %s, missing %s" % (bad or "-", missing or "-"))
    extrapolate = pin.get("extrapolate")
    if extrapolate is not None and not isinstance(extrapolate, dict):
        raise PinError("calibration.extrapolate maps a tag to the reason")
    data = _read_pinned(base_dir, pin["path"], pin["sha256"], "calibration")
    doc = yaml.safe_load(data.decode("utf-8"))
    try:
        calibfile.check(doc, pin["path"])
    except calibfile.CalibError as e:
        raise PinError(str(e)) from None
    if doc["code"].get("dirty") and not allow_dirty:
        raise PinError("calibration %s was fitted from a dirty research/ (%s): refit it from a commit, or run the "
                       "campaign with --allow-dirty" % (pin["path"], ", ".join(doc["code"].get("dirty_files") or [])))
    sens = sc.setdefault("sensors", {})
    if not isinstance(sens, dict):
        raise PinError("sensors must be a mapping")
    remove = list(sens.get("remove") or [])
    ov = calibfile.to_overrides(doc, remove=remove, where=pin["path"])
    scen = sens.get("overrides") or {}
    if not isinstance(scen, dict):
        raise PinError("sensors.overrides must be a mapping")
    defaults = sensor_fit.default_specs()
    merged = copy.deepcopy(scen)
    for model, fields in ov["sensors"].items():
        own = scen.get(model) or {}
        out = merged.setdefault(model, {})
        for field, v in fields.items():
            if isinstance(v, dict):
                theirs = own.get(field)
                if theirs is not None and not isinstance(theirs, dict):
                    raise PinError("sensors.overrides.%s.%s must map a tag to a value" % (model, field))
                both = sorted(set(v) & set(theirs or {}))
                if both:
                    raise PinError("sensors.overrides.%s.%s.%s is set in both the calibration and the scenario"
                                   % (model, field, both[0]))
                d = dict(getattr(defaults[model], field))
                d.update(v)
                d.update(theirs or {})
                out[field] = d
            else:
                if field in own:
                    raise PinError("sensors.overrides.%s.%s is set in both the calibration and the scenario"
                                   % (model, field))
                out[field] = v
    sens["overrides"] = merged
    used = _validity(sc, doc["validity"], extrapolate)
    src = doc["source"]
    res = {"name": doc["name"], "calib_version": doc["calib_version"],
           "sensor_model_version": doc["sensor_model_version"],
           "source": {"dataset_content_sha256": src["dataset_content_sha256"],
                      "snapshot_id": src["lake"]["snapshot_id"], "lineage": src["lake"]["lineage"],
                      "digest_measurement": src["lake"]["digest_measurement"]},
           "code": {"commit": doc["code"].get("commit"), "dirty": doc["code"].get("dirty")},
           "sensors": ov["sensors"], "applied": ov["applied"], "not_applied": ov["not_applied"],
           "validity": doc["validity"]}
    if used:
        res["extrapolate"] = used
    plant = {"overrides": dict((sc.get("plant") or {}).get("overrides") or {}),
             "ambient": dict(sc.get("ambient") or {})}
    if plant["overrides"] or plant["ambient"]:
        res["scenario_plant"] = plant
    pin["resolved"] = res


def resolve_pins(sc, base_dir, repo_root, allow_dirty=False):
    """SC with its pins resolved (a copy); SC itself when it has none, so a spec without
    pins hashes exactly as before."""
    if "calibration" not in sc and "recipe_line_from" not in sc:
        return sc
    sc = copy.deepcopy(sc)
    try:
        if "recipe_line_from" in sc:
            resolve_line_from(sc, base_dir, repo_root)
        if "calibration" in sc:
            resolve_calibration(sc, base_dir, allow_dirty)
    except (calibfile.CalibError, extract.ExtractError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise PinError(str(e)) from None
    return sc


def provenance(sc):
    """The manifest's provenance block of one resolved scenario (None without a pin)."""
    out = {}
    cal = sc.get("calibration")
    if cal:
        r = cal["resolved"]
        out["calibration"] = {"path": cal["path"], "sha256": cal["sha256"], "name": r["name"],
                              "calib_version": r["calib_version"], "sensor_model_version": r["sensor_model_version"],
                              "source": r["source"], "code": r["code"], "applied": r["applied"],
                              "not_applied": r["not_applied"], "validity": r["validity"]}
        if "extrapolate" in r:
            out["calibration"]["extrapolate"] = r["extrapolate"]
        if "scenario_plant" in r:
            out["calibration"]["scenario_plant"] = r["scenario_plant"]
    lf = sc.get("recipe_line_from")
    if lf:
        r = lf["resolved"]
        out["setpoints"] = {"extract": lf["extract"], "sha256": lf["sha256"], "snapshot_id": lf["snapshot_id"],
                            "lineage": lf["lineage"], "digests": r["digests"], "recipe_id": lf["recipe_id"],
                            "seq": lf["seq"], "recipe_type": r["recipe_type"]}
        if "light_override" in r:
            out["setpoints"]["light_override"] = r["light_override"]
    return out or None
