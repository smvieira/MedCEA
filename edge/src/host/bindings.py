#!/usr/bin/env python3
"""How a command reaches a piece of equipment.

A CONTROL board's job is to turn "make it warmer" into something physical. On an
ESP32 that is a GPIO level; on a Modbus relay it is a coil write; on a smart plug
it is an HTTP call. The *shape* of the command table is the same in every case —
an actuator, a branch (UP/DOWN/OFF or ON/OFF), and a list of things to set — so
the only part that is device-specific is the ADDRESS: what identifies one
channel, what counts as a legal one, and what the field is called in the file the
device reads.

That is all this module abstracts, and it does it from data rather than code. A
binding is declared in the device template:

    "binding": {
      "kind": "gpio", "field": "pin", "label": "GPIO",
      "descriptions_key": "pin_descriptions", "address_kind": "int",
      "valid_ranges": [[0, 21], [26, 48]],
      "rules": [{"addresses": [26,27,28,29,30,31,32], "level": "error",
                 "message": "GPIO {addr} is wired to the SPI flash."}]
    }

so adding a device family that does not use pin I/O is a new template, not new
Python. A family whose addressing genuinely cannot be described this way (one
needing a live lookup, say) subclasses Binding and registers itself in KINDS.

The rules travel to the browser editor untouched (`to_ui`), so the operator gets
the same warnings the renderer would give, from the same source. Two thin
interpreters over one table beats two tables that drift.
"""

import json
import os
import re

LEVELS = ("error", "warn")


class BindingError(Exception):
    """An address the device could not accept."""


# The ESP32-S3 this platform flashes, kept here as the fallback so a template
# written before bindings existed still renders. New templates declare their own.
DEFAULT_GPIO = {
    "kind": "gpio",
    "field": "pin",
    "label": "GPIO",
    "descriptions_key": "pin_descriptions",
    "address_kind": "int",
    "placeholder": "GPIO",
    "hint": "The pin the relay channel is wired to.",
    "valid_ranges": [[0, 21], [26, 48]],
    "rules": [],
}


def _rules_from_groups(variant):
    """A variant's pin groups, as validation rules.

    A group without a `level` is reference material for the pin table and is
    never flagged — knowing GPIO12 is also a JTAG pin is worth showing and not
    worth refusing.
    """
    return [{"addresses": g.get("pins") or [], "level": g["level"],
             "message": g.get("note", g.get("label", ""))}
            for g in (variant.get("groups") or []) if g.get("level")]


class Binding(object):
    """One device family's addressing scheme, driven by the template."""

    def __init__(self, spec=None):
        spec = dict(DEFAULT_GPIO, **(spec or {}))
        self.spec = spec
        self.kind = spec.get("kind", "gpio")
        self.field = spec.get("field", "pin")
        self.label = spec.get("label", "Address")
        self.descriptions_key = spec.get("descriptions_key", "pin_descriptions")
        self.address_kind = spec.get("address_kind", "int")
        self.placeholder = spec.get("placeholder", self.label)
        self.hint = spec.get("hint", "")
        self.pattern = spec.get("pattern") or ""
        self.unassigned = spec.get("unassigned", ["", "-", None])

        # A family can come in several silicon variants that differ only in
        # which addresses exist and which are spoken for — every ESP32 is
        # addressed by GPIO number, but an S3 has 26-48 and a C3 stops at 21.
        # That is a property of the variant, not of the binding, so selecting
        # one swaps the ranges and the rules and changes nothing else.
        self.variants = spec.get("variants") or {}
        self.variant = (spec.get("variant") or spec.get("default_variant") or "")
        if self.variants and self.variant not in self.variants:
            self.variant = next(iter(self.variants), "")

        v = self.variants.get(self.variant) or {}
        self.valid_ranges = v.get("ranges") or spec.get("valid_ranges") or []
        self.rules = _rules_from_groups(v) if v else (spec.get("rules") or [])
        if self.address_kind not in ("int", "string"):
            raise BindingError("binding address_kind must be 'int' or 'string', "
                               "not %r" % self.address_kind)
        if self.pattern:
            try:
                self._rx = re.compile(self.pattern)
            except re.error as e:
                raise BindingError("binding pattern %r is not a regex: %s"
                                   % (self.pattern, e))
        else:
            self._rx = None

    # -------------------------------------------------------------- address --
    def is_unassigned(self, raw):
        """True for the answers that mean 'this chamber has no such equipment'."""
        return raw in self.unassigned or (isinstance(raw, str) and not raw.strip())

    def normalise(self, raw):
        """One answered address, in the type the device's config file wants.

        Raises BindingError with a message an operator can act on — this is the
        text that ends up next to the field they just typed in.
        """
        if self.address_kind == "int":
            try:
                addr = int(str(raw).strip())
            except (TypeError, ValueError):
                raise BindingError("%s must be a whole number, not %r"
                                   % (self.label, raw))
            if self.valid_ranges and not any(lo <= addr <= hi
                                             for lo, hi in self.valid_ranges):
                raise BindingError("%s %d is not addressable on this device (valid: %s)"
                                   % (self.label, addr, self.ranges_text()))
            return addr
        addr = str(raw).strip()
        if not addr:
            raise BindingError("%s cannot be blank" % self.label)
        if self._rx and not self._rx.match(addr):
            raise BindingError("%r is not a valid %s" % (addr, self.label))
        return addr

    def ranges_text(self):
        return ", ".join("%d-%d" % (lo, hi) for lo, hi in self.valid_ranges)

    # ------------------------------------------------------------ variants --
    def select(self, variant):
        """The same binding, checked against a different silicon variant."""
        if not variant or variant == self.variant:
            return self
        if self.variants and variant not in self.variants:
            raise BindingError(
                "unknown %s variant %r (known: %s)"
                % (self.label, variant, ", ".join(sorted(self.variants)) or "none"))
        return make(dict(self.spec, variant=variant))

    def variant_label(self, variant=None):
        v = self.variants.get(variant or self.variant) or {}
        return v.get("label", variant or self.variant or "")

    def pin_rows(self, variant=None):
        """Every address this variant has, with what else wants it.

        This is the reference table the operator opens from the form. It is
        generated from the same groups the validator reads, so the table cannot
        say a pin is free while validation calls it taken.
        """
        v = self.variants.get(variant or self.variant) or {}
        groups = v.get("groups") or []
        rows = []
        for lo, hi in (v.get("ranges") or self.valid_ranges or []):
            for pin in range(lo, hi + 1):
                tags, level, notes = [], "", []
                for g in groups:
                    if pin not in (g.get("pins") or []):
                        continue
                    tags.append(g.get("label", g.get("id", "")))
                    if g.get("level") == "error":
                        level = "error"
                    elif g.get("level") == "warn" and level != "error":
                        level = "warn"
                    if g.get("level"):
                        notes.append(str(g.get("note", "")).replace("{addr}", str(pin)))
                rows.append({"pin": pin, "types": tags or ["I/O"],
                             "level": level, "notes": notes})
        return rows

    def usable_pins(self, variant=None):
        """Addresses that can actually drive something on this variant."""
        return [r["pin"] for r in self.pin_rows(variant) if r["level"] != "error"]

    def key(self, addr):
        """The address as it appears in the descriptions map.

        Always a string: the board reads this back with the address stringified
        (cea_control does `descriptions.get(str(pin))`), and a JSON object has
        string keys anyway.
        """
        return str(addr)

    # ------------------------------------------------------------ advisories --
    def advise(self, addr):
        """Template-declared cautions about one address: [(level, message)].

        These are not errors in the addressing — they are facts about the
        silicon or the bus that the operator wants before they wire it, not
        after.
        """
        out = []
        for rule in self.rules:
            if not self._matches(rule, addr):
                continue
            level = rule.get("level", "warn")
            if level not in LEVELS:
                level = "warn"
            out.append((level, str(rule.get("message", "")).replace("{addr}", str(addr))))
        return out

    def _matches(self, rule, addr):
        if "addresses" in rule:
            if self.address_kind == "int":
                if addr in [int(a) for a in rule["addresses"]]:
                    return True
            elif str(addr) in [str(a) for a in rule["addresses"]]:
                return True
        for lo, hi in rule.get("ranges") or []:
            if self.address_kind == "int" and lo <= addr <= hi:
                return True
        pat = rule.get("pattern")
        if pat and re.match(pat, str(addr)):
            return True
        return False

    # ---------------------------------------------------------------- emit ---
    def action(self, addr, value):
        """One entry in a branch's action list, in this device's field names."""
        return {self.field: addr, "value": 1 if int(value) else 0}

    def descriptions(self, pins, labels):
        """The address -> equipment-name map the device ships with."""
        return {self.key(addr): labels.get(fid, fid) for fid, addr in pins.items()}

    def to_ui(self):
        """What the browser editor needs to render and check this family.

        Every variant travels, not just the selected one, so switching boards in
        the form is instant and the pin reference is available offline — the
        wizard is often the only thing on that screen.
        """
        return {
            "kind": self.kind, "field": self.field, "label": self.label,
            "descriptions_key": self.descriptions_key,
            "address_kind": self.address_kind, "placeholder": self.placeholder,
            "hint": self.hint, "valid_ranges": self.valid_ranges,
            "pattern": self.pattern, "rules": self.rules,
            "ranges_text": self.ranges_text(),
            "variant": self.variant,
            "variants": self.variants,
            "variant_order": sorted(self.variants),
        }


# A family whose addressing needs real logic registers a subclass here; every
# other family is a template edit and needs no entry.
KINDS = {}


def make(spec):
    spec = spec or {}
    cls = KINDS.get(spec.get("kind"), Binding)
    return cls(spec)


def from_template(tpl, base_dir=None):
    """The binding a template declares, or the ESP32 GPIO one it predates.

    `variants_from` pulls the silicon table out of its own file, because the
    same table serves every template of that family and a reference list is
    something you want to read and correct on its own, not buried inside a
    command table.
    """
    spec = dict(tpl.get("binding") or DEFAULT_GPIO)
    ref = spec.pop("variants_from", None)
    if ref:
        path = os.path.join(base_dir or ".", ref)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except OSError as e:
            raise BindingError("cannot read the variant table %s: %s" % (path, e))
        except ValueError as e:
            raise BindingError("%s is not valid JSON: %s" % (path, e))
        spec.setdefault("variants", data.get("variants") or {})
        if data.get("default"):
            spec.setdefault("default_variant", data["default"])
        spec["esptool_map"] = {k: v for k, v in (data.get("_esptool_map") or {}).items()
                               if not k.startswith("_")}
    return make(spec)


def variant_for_chip(binding, chip):
    """What `esptool chip_id` printed, as a variant id — or "" if unrecognised.

    Matched loosely because esptool prints "ESP32-S3 (QFN56) (revision v0.2)"
    and the table holds "esp32-s3".
    """
    got = str(chip or "").strip().lower()
    if not got:
        return ""
    table = binding.spec.get("esptool_map") or {}
    # Longest key first, so "esp32-s3" wins over a bare "esp32" prefix.
    for key in sorted(table, key=len, reverse=True):
        if got.startswith(key):
            return table[key]
    return ""


# ------------------------------------------------------------- validation ----
# Structural checks. These are family-independent on purpose: "an actuator the
# scheduler cannot switch on" is wrong on a relay board and on a Modbus coil
# alike. Anything device-specific comes from the binding's own rules above.
def validate_config(binding, cfg):
    """Check a rendered actuator config. Returns [{level, message, where}].

    Mirrors what render_actuator_config() would drop and what the board's
    cea_control.py can actually execute, so an operator sees the same verdict in
    the browser that the renderer reaches on its own.
    """
    out = []
    field = binding.field

    def add(level, message, where):
        out.append({"level": level, "message": message, "where": where})

    declared = cfg.get(binding.descriptions_key) or {}
    defs = cfg.get("actuator_definitions") or {}

    used = {}
    for name, spec in defs.items():
        for where, branch in _branches(name, spec):
            for act in branch.get("actions") or []:
                used[str(act.get(field))] = used.get(str(act.get(field)), 0) + 1

    for addr, desc in declared.items():
        label = "%s %s" % (binding.label, addr)
        if not str(desc).strip():
            add("warn", "%s has no equipment name. Setpoint reports will read "
                        "“%s %s”." % (label, binding.label, addr), label)
        try:
            canon = binding.normalise(addr)
        except BindingError as e:
            add("error", str(e), label)
            continue
        for level, msg in binding.advise(canon):
            add(level, msg, label)
        if not used.get(str(addr)):
            add("warn", "Nothing drives %s. The channel ships as a label with no "
                        "command behind it." % label, label)

    if not defs:
        add("error", "No actuators. The board would subscribe and never act.", "config")

    for name, spec in defs.items():
        branches = list(_branches(name, spec))
        if not branches:
            add("error", "Actuator “%s” has no commands at all." % name, name)

        for where, branch in branches:
            acts = branch.get("actions") or []
            if not acts:
                add("error", "“%s” drives no channel. An empty branch is "
                             "dropped at render time." % where, where)
            if not str(branch.get("description", "")).strip():
                add("warn", "“%s” has no description. It is what an operator "
                            "reads in the run log." % where, where)
            seen = {}
            for act in acts:
                addr = act.get(field)
                if addr is None:
                    add("error", "An action in “%s” has no %s."
                        % (where, binding.label), where)
                    continue
                if str(addr) not in declared:
                    add("error", "“%s” drives %s %s, which is not a declared "
                                 "channel. The board reports it with no equipment name."
                        % (where, binding.label, addr), where)
                val = 1 if int(act.get("value", 0)) else 0
                if str(addr) in seen:
                    if seen[str(addr)] != val:
                        add("error", "“%s” sets %s %s to both 0 and 1. The last "
                                     "write wins, silently." % (where, binding.label, addr),
                            where)
                    else:
                        add("warn", "“%s” sets %s %s twice with the same value."
                            % (where, binding.label, addr), where)
                seen[str(addr)] = val

        if "types" in spec:
            for tname, tspec in (spec.get("types") or {}).items():
                w = "%s · %s" % (name, tname)
                if "ON" not in tspec:
                    add("error", "Type “%s” has no ON. A type that cannot be "
                                 "switched on is dropped at render time." % w, w)
                if "OFF" not in tspec:
                    add("warn", "Type “%s” has no OFF, so all_off() cannot park "
                                "it at boot." % w, w)
                on, off = tspec.get("ON"), tspec.get("OFF")
                if on and off:
                    lit = [str(a.get(field)) for a in (on.get("actions") or [])
                           if int(a.get("value", 0))]
                    cleared = {str(a.get(field)): int(a.get("value", 0))
                               for a in (off.get("actions") or [])}
                    stranded = [p for p in lit if cleared.get(p) != 0]
                    if stranded:
                        add("error", "“%s OFF” never clears %s %s, which its own "
                                     "ON energises. The equipment stays on and the board "
                                     "reports success."
                            % (w, binding.label, ", ".join(stranded)), w + " · OFF")
        else:
            cmds = spec.get("commands") or {}
            if "UP" not in cmds:
                add("error", "Actuator “%s” has no UP. The whole actuator is "
                             "dropped at render time, so the scheduler never sees it."
                    % name, name)
            if "OFF" not in cmds:
                add("warn", "Actuator “%s” has no OFF. all_off() cannot park it "
                            "at boot, so a reset leaves its equipment wherever the last "
                            "command left it." % name, name)
    return out


def _branches(name, spec):
    """(where, branch) for every command in an actuator, both kinds."""
    if "types" in spec:
        for tname, tspec in (spec.get("types") or {}).items():
            for cmd, branch in tspec.items():
                yield ("%s · %s · %s" % (name, tname, cmd)), branch
    else:
        for cmd, branch in (spec.get("commands") or {}).items():
            yield ("%s · %s" % (name, cmd)), branch
