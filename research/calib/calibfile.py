"""The calibration file (CALIB_SCHEMA 1): research/calib/calibrations/<name>.yaml.

Canonical YAML (sorted keys, block style), written by dump(): the same dataset, commit and
CALIB_VERSION give the same bytes. A campaign scenario pins the file by its sha256
(campaign.resolve_spec), and to_overrides() turns it into the sensor overrides it applies.

    medcea_calibration: 1
    calib_version, sensor_model_version, name
    source:     dataset_content_sha256, lake {contract_version, snapshot_id, lineage, cut_at,
                digest_measurement {"<k>": hex}, digest_verified}, unit, zone, window,
                segments, outages, cadence                (no holds: design §9 R9)
    code:       commit, dirty, dirty_files, python (major.minor), blobs {path: blob sha}
    sensor_map: {model sensor: lake sensor}
    reference:  {sensor, why}
    sensors:    {model sensor: {field: entry | {tag: entry}}, ...}  (sensor_fit's entries;
                a sensor the dataset did not observe is {source: datasheet, note})
    relative, validity, unmodelled
    plant:      {ChamberParams field: {value, source: assumed | spec, class, refused}}

An entry changes the model only when `applied` is true. Phase 3 refuses a `fitted` plant
entry outright, and an assumed or spec value that is not ChamberParams' default (design §9
R8: change an assumption in a scenario's plant.overrides, where it is visible).
"""
from __future__ import annotations

import copy
import hashlib
import math
import os
import sys

import yaml

from ..harness import algorithms_loader
from ..twin_plant import sensors as sensors_mod
from ..twin_plant.chamber import ChamberParams
from . import CALIB_SCHEMA, CALIB_VERSION, plant_fit, sensor_fit

PLANT_SOURCES = ("assumed", "spec", "fitted")
REFERENCE_WHY = ("better datasheet accuracy; the SCD30 self-heats (a lamp and an MCU on its board); the loops' "
                 "reference (the SCD30 is their fallback). Absolute accuracy unknown: only offsets relative to it "
                 "are identifiable")
NON_FIELDS = ("humidity_model",)
TOP_KEYS = ("medcea_calibration", "calib_version", "sensor_model_version", "name", "source", "code", "sensor_map",
            "reference", "sensors", "relative", "validity", "unmodelled", "plant")
CODE_DIRS = ("research/calib", "research/twin_plant")


class CalibError(ValueError):
    """A calibration file that is not well-formed, or that a campaign may not apply."""


# ── code state ──────────────────────────────────────────────────────────────────────
def code_state(allow_dirty=False):
    """{commit, dirty, dirty_files, python, blobs} of the sandbox's own code (research/),
    refused (CalibError) when research/ differs from HEAD unless allow_dirty (R10)."""
    root = algorithms_loader.SANDBOX_ROOT
    st = algorithms_loader.sandbox_state(root)
    if st["dirty"] and not allow_dirty:
        raise CalibError("research/ differs from HEAD (%s): commit it, or pass --allow-dirty to record it as dirty"
                         % ", ".join(st["dirty_files"]))
    blobs = {rel: algorithms_loader.blob_sha(root, rel) for rel in algorithms_loader.sandbox_files(root)
             if rel.startswith(CODE_DIRS) and rel.endswith(".py")}
    return {"commit": st["commit"], "dirty": bool(st["dirty"]), "dirty_files": list(st["dirty_files"]),
            "python": "%d.%d" % sys.version_info[:2], "blobs": dict(sorted(blobs.items()))}


# ── build ───────────────────────────────────────────────────────────────────────────
def plant_section(header, rows=None):
    verdicts = plant_fit.identifiability(header, rows)
    defaults = ChamberParams().to_dict()
    out = {}
    for field in plant_fit.chamber_fields():
        cls = plant_fit.PLANT_FIELDS[field]
        e = {"value": float(defaults[field]), "source": "spec" if cls == "spec" else "assumed", "class": cls}
        if cls != "spec":
            e["refused"] = list(verdicts[field].reasons)
        out[field] = e
    return out


def build(header, fit, name, sensor_map, reference, code, rows=None):
    """The calibration document from a dataset header and sensor_fit.fit()'s result."""
    lake = header["lake"]
    complete = [s for s in lake["snapshots"] if s.get("complete")]
    specs = sensor_fit.default_specs()
    sens = copy.deepcopy(fit["sensors"])
    for model in specs:
        if model not in sens:
            sens[model] = {"source": "datasheet", "note": "not observed: the model's defaults, unchanged"}
    doc = {
        "medcea_calibration": CALIB_SCHEMA,
        "calib_version": CALIB_VERSION,
        "sensor_model_version": sensors_mod.SENSOR_MODEL_VERSION,
        "name": name,
        "source": {
            "dataset_content_sha256": header["content_sha256"],
            "lake": {"contract_version": lake["contract_version"], "snapshot_id": lake["snapshot_id"],
                     "lineage": lake["lineage"], "cut_at": lake["cut_at"],
                     "digest_measurement": {str(s["id"]): s["digest_measurement"] for s in complete},
                     "digest_verified": bool(lake["snapshots"]) and all(s.get("digest_verified") for s in
                                                                        lake["snapshots"])},
            "unit": header["query"]["p_unit"], "zone": header["query"]["p_zone"],
            "window": fit["window"], "segments": fit["segments"], "outages": fit["outages"],
            "cadence": fit["cadence"],
        },
        "code": code,
        "sensor_map": dict(sensor_map),
        "reference": {"sensor": reference, "why": REFERENCE_WHY},
        "sensors": sens,
        "relative": fit["relative"],
        "validity": fit["validity"],
        "unmodelled": fit["unmodelled"],
        "plant": plant_section(header, rows),
    }
    check(doc)
    return doc


# ── dump / load ─────────────────────────────────────────────────────────────────────
def dumps(doc):
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False, allow_unicode=True, width=4096)


def dump(doc, path):
    data = dumps(doc).encode("utf-8")
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp-%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return hashlib.sha256(data).hexdigest()


def load_bytes(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise CalibError("cannot read %s: %s" % (path, e.strerror or e)) from None
    try:
        doc = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as e:
        raise CalibError("%s is not a YAML calibration file: %s" % (path, e)) from None
    return data, doc


def load(path):
    return load_bytes(path)[1]


# ── checks ──────────────────────────────────────────────────────────────────────────
def _finite_everywhere(obj, where):
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return
    if isinstance(obj, (int, float)):
        if not math.isfinite(obj):
            raise CalibError("%s is not finite" % where)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _finite_everywhere(v, "%s.%s" % (where, k))
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            _finite_everywhere(v, "%s[%d]" % (where, i))
        return
    raise CalibError("%s holds a %s" % (where, type(obj).__name__))


def _check_entry(e, where):
    if not isinstance(e, dict) or e.get("source") not in sensor_fit.SOURCES:
        raise CalibError("%s is not an entry with a known source" % where)
    if not isinstance(e.get("applied"), bool):
        raise CalibError("%s: applied must be true or false" % where)
    if e["applied"] and ("value" not in e or isinstance(e["value"], bool)
                         or not isinstance(e["value"], (int, float))):
        raise CalibError("%s is applied but has no numeric value" % where)


def check(doc, where="calibration"):
    """Schema, versions, sources, finiteness, the plant rules and the sensor bounds (through
    to_overrides). Raises CalibError."""
    if not isinstance(doc, dict) or doc.get("medcea_calibration") != CALIB_SCHEMA:
        raise CalibError("%s is not a calibration file of schema %d" % (where, CALIB_SCHEMA))
    missing = [k for k in TOP_KEYS if k not in doc]
    extra = sorted(set(doc) - set(TOP_KEYS))
    if missing or extra:
        raise CalibError("%s: missing %s, unknown %s" % (where, missing or "-", extra or "-"))
    smv = doc["sensor_model_version"]
    if not isinstance(smv, int) or isinstance(smv, bool) or not 1 <= smv <= sensors_mod.SENSOR_MODEL_VERSION:
        raise CalibError("%s: sensor_model_version %r, but this code's sensor model is version %d"
                         % (where, smv, sensors_mod.SENSOR_MODEL_VERSION))
    if not isinstance(doc["calib_version"], int) or doc["calib_version"] < 1:
        raise CalibError("%s: calib_version must be a whole number >= 1" % where)
    if not isinstance(doc["name"], str) or not doc["name"]:
        raise CalibError("%s: name must be a non-empty string" % where)
    _finite_everywhere(doc, where)
    code = doc["code"]
    if not isinstance(code, dict) or not isinstance(code.get("dirty"), bool):
        raise CalibError("%s: code must record commit, dirty and blobs" % where)
    specs = sensor_fit.default_specs()
    for model, fields in (doc["sensors"] or {}).items():
        if model not in specs:
            raise CalibError("%s: sensors.%s is not a model sensor" % (where, model))
        if "source" in fields:
            if fields["source"] != "datasheet":
                raise CalibError("%s: sensors.%s is either fields or {source: datasheet}" % (where, model))
            continue
        for field, e in fields.items():
            w = "%s: sensors.%s.%s" % (where, model, field)
            if field in NON_FIELDS:
                continue
            if field in sensor_fit.DICT_FIELDS:
                if not isinstance(e, dict):
                    raise CalibError("%s must map a tag to an entry" % w)
                for tag, te in e.items():
                    if tag not in specs[model].tags:
                        raise CalibError("%s.%s: the sensor does not publish %s" % (w, tag, tag))
                    _check_entry(te, "%s.%s" % (w, tag))
            elif field in sensor_fit.SCALAR_FIELDS:
                _check_entry(e, w)
            else:
                raise CalibError("%s is not a SensorSpec field" % w)
    plant = doc["plant"]
    fields = plant_fit.chamber_fields()
    if not isinstance(plant, dict) or sorted(plant) != sorted(fields):
        raise CalibError("%s: plant must name every ChamberParams field exactly" % where)
    to_overrides(doc, where=where)


def to_overrides(doc, remove=(), where="calibration"):
    """{sensors: {model: {field: value | {tag: value}}}, applied: [...], not_applied: [{field,
    why}]}: the sensor overrides the calibration applies (a sensor in REMOVE is skipped),
    after checking that every resulting SensorSpec is valid and that the plant section
    changes nothing (R8). Raises CalibError."""
    specs = sensor_fit.default_specs()
    out, applied, not_applied = {}, [], []
    for model in sorted(doc.get("sensors") or {}):
        fields = doc["sensors"][model]
        if "source" in fields or model in remove:
            if model in remove:
                not_applied.append({"field": model, "why": "the scenario removes this sensor"})
            continue
        ov = {}
        for field in sorted(fields):
            e = fields[field]
            if field in NON_FIELDS:
                continue
            if field in sensor_fit.DICT_FIELDS:
                for tag in sorted(e):
                    te = e[tag]
                    name = "%s.%s.%s" % (model, field, tag)
                    if te.get("applied"):
                        ov.setdefault(field, {})[tag] = te["value"]
                        applied.append(name)
                    else:
                        not_applied.append({"field": name, "why": te.get("why", te.get("source"))})
            else:
                name = "%s.%s" % (model, field)
                if e.get("applied"):
                    ov[field] = e["value"]
                    applied.append(name)
                else:
                    not_applied.append({"field": name, "why": e.get("why", e.get("source"))})
        if ov:
            spec = copy.deepcopy(specs[model])
            for field, v in ov.items():
                if isinstance(v, dict):
                    merged = dict(getattr(spec, field))
                    merged.update(v)
                    setattr(spec, field, merged)
                else:
                    setattr(spec, field, v)
            try:
                spec.validate()
            except ValueError as e:
                raise CalibError("%s: sensors.%s: %s" % (where, model, e)) from None
            out[model] = ov
    defaults = ChamberParams().to_dict()
    for field, e in sorted((doc.get("plant") or {}).items()):
        if not isinstance(e, dict) or e.get("source") not in PLANT_SOURCES:
            raise CalibError("%s: plant.%s needs a source (assumed or spec)" % (where, field))
        if e["source"] == "fitted":
            raise CalibError("%s: plant.%s is fitted: plant fits are applied from a later phase (R8)"
                             % (where, field))
        if field not in defaults:
            raise CalibError("%s: plant.%s is not a ChamberParams field" % (where, field))
        if e.get("value") != defaults[field]:
            raise CalibError("%s: plant.%s is %r, not the model's %s %r: change an assumption in the scenario's "
                             "plant.overrides, where it is visible" % (where, field, e.get("value"),
                                                                       e["source"], defaults[field]))
    return {"sensors": out, "applied": applied, "not_applied": not_applied}


def verify(path):
    """A calibration file offline: canonical bytes, schema and every rule of check().
    Returns the summary lines."""
    data, doc = load_bytes(path)
    check(doc, path)
    if dumps(doc).encode("utf-8") != data:
        raise CalibError("%s is not in canonical form (rewrite it with calibfile.dump)" % path)
    ov = to_overrides(doc, where=path)
    root = algorithms_loader.SANDBOX_ROOT
    blobs = doc["code"].get("blobs") or {}
    same = sum(1 for rel, sha in blobs.items()
               if os.path.exists(os.path.join(root, rel)) and algorithms_loader.blob_sha(root, rel) == sha)
    src = doc["source"]
    return ["calibration %s: %s, sha256 %s" % (path, doc["name"], hashlib.sha256(data).hexdigest()),
            "dataset %s, snapshot %s, lineage %s" % (src["dataset_content_sha256"], src["lake"]["snapshot_id"],
                                                    src["lake"]["lineage"]),
            "%d sensor values applied, %d not applied; plant: %d fields, every one the model's default"
            % (len(ov["applied"]), len(ov["not_applied"]), len(doc["plant"])),
            "code %s%s: %d of %d blobs equal this checkout's files"
            % (doc["code"].get("commit"), " (dirty)" if doc["code"].get("dirty") else "", same, len(blobs))]
