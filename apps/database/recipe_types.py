#!/usr/bin/env python3
"""The recipe-type catalogue (apps/database/recipe_types.yaml): checked and printed as JSON.

  recipe_types.py check            exit 1 with the problems on stderr
  recipe_types.py json             the checked document, canonical JSON (migration 011's
                                   -v recipe_types_b64 is its base64; the Configuration UI
                                   and the Run Monitor serve the same bytes)
  recipe_types.py b64              base64 of `json`, one line

Stdlib + PyYAML. The rules here are the database's CHECKs and migration 011's seed rules;
the migration raises on the same problems, this only says so before a deploy starts.
"""
import base64
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "recipe_types.yaml")
CODE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
QUANTITY_KEYS = {"code", "label", "unit", "sense_uoms", "default_tag", "commands", "command_map",
                 "phase", "loopable", "min", "max"}
TYPE_KEYS = {"code", "label", "legacy_unit_type", "quantities"}
COMMANDS = {"UP", "DOWN", "OFF"}


def load(path=DEFAULT):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def problems(doc):
    out = []
    if not isinstance(doc, dict):
        return ["the file must be a mapping"]
    if doc.get("version") != 1:
        out.append("version must be 1")
    qs = doc.get("quantities")
    ts = doc.get("recipe_types")
    if not isinstance(qs, list) or not qs:
        return out + ["quantities must be a non-empty list"]
    if not isinstance(ts, list) or not ts:
        return out + ["recipe_types must be a non-empty list"]
    codes = []
    for i, q in enumerate(qs):
        where = "quantities[%d]" % i
        if not isinstance(q, dict):
            out.append(where + " must be a mapping")
            continue
        extra = set(q) - QUANTITY_KEYS
        if extra:
            out.append("%s: unknown keys %s" % (where, ", ".join(sorted(extra))))
        c = q.get("code")
        if not isinstance(c, str) or not CODE_RE.match(c) or len(c) > 40:
            out.append(where + ": code must match ^[a-z][a-z0-9_]*$ (at most 40)")
            continue
        where = "quantity " + c
        if c in codes:
            out.append(where + ": listed twice")
        codes.append(c)
        for k in ("label", "unit"):
            if not isinstance(q.get(k), str) or not q.get(k):
                out.append("%s: %s must be text" % (where, k))
        if not (isinstance(q.get("sense_uoms"), list) and q["sense_uoms"]
                and all(isinstance(u, str) and u for u in q["sense_uoms"])):
            out.append(where + ": sense_uoms must be a non-empty list of UoM strings")
        if not isinstance(q.get("default_tag"), str) or not CODE_RE.match(q["default_tag"]):
            out.append(where + ": default_tag must match ^[a-z][a-z0-9_]*$")
        cmds = q.get("commands")
        if not (isinstance(cmds, list) and cmds and set(cmds) <= COMMANDS and len(set(cmds)) == len(cmds)):
            out.append(where + ": commands must be a list of UP, DOWN, OFF")
            cmds = []
        cm = q.get("command_map")
        if cm is not None:
            if not (isinstance(cm, dict) and set(cm) == COMMANDS and set(cm.values()) <= set(cmds)):
                out.append(where + ": command_map maps UP, DOWN and OFF to its commands")
        if q.get("phase") not in ("always", "light_on"):
            out.append(where + ": phase must be always or light_on")
        if not isinstance(q.get("loopable"), bool):
            out.append(where + ": loopable must be true or false")
        lo, hi = q.get("min"), q.get("max")
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (lo, hi)) or not lo < hi:
            out.append(where + ": min and max must be numbers, min below max")
    tcodes, legacy = [], []
    for i, t in enumerate(ts):
        where = "recipe_types[%d]" % i
        if not isinstance(t, dict):
            out.append(where + " must be a mapping")
            continue
        extra = set(t) - TYPE_KEYS
        if extra:
            out.append("%s: unknown keys %s" % (where, ", ".join(sorted(extra))))
        c = t.get("code")
        if not isinstance(c, str) or not TYPE_RE.match(c) or len(c) > 20:
            out.append(where + ": code must match ^[A-Z][A-Z0-9_]*$ (at most 20)")
            continue
        where = "recipe type " + c
        if c in tcodes:
            out.append(where + ": listed twice")
        tcodes.append(c)
        if not isinstance(t.get("label"), str) or not t.get("label"):
            out.append(where + ": label must be text")
        lu = t.get("legacy_unit_type")
        if lu is not None:
            if not isinstance(lu, str) or lu in legacy:
                out.append(where + ": legacy_unit_type must be text, once per file")
            legacy.append(lu)
        tq = t.get("quantities")
        if not isinstance(tq, dict) or not tq:
            out.append(where + ": quantities must map quantity codes to true (required) or false")
            continue
        for k, v in tq.items():
            if k not in codes:
                out.append("%s: %s is not a quantity" % (where, k))
            if not isinstance(v, bool):
                out.append("%s: %s must be true or false" % (where, k))
    if doc.get("default_type") not in tcodes:
        out.append("default_type must name one of the recipe types")
    return out


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main(argv):
    path = os.environ.get("MEDCEA_RECIPE_TYPES", DEFAULT)
    if len(argv) != 2 or argv[1] not in ("check", "json", "b64"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        doc = load(path)
    except (OSError, yaml.YAMLError) as e:
        print("recipe_types: cannot read %s: %s" % (path, e), file=sys.stderr)
        return 1
    errs = problems(doc)
    if errs:
        for e in errs:
            print("recipe_types.yaml: " + e, file=sys.stderr)
        return 1
    if argv[1] == "json":
        print(canonical(doc))
    elif argv[1] == "b64":
        print(base64.b64encode(canonical(doc).encode("utf-8")).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
