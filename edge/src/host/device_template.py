#!/usr/bin/env python3
"""Device templates: what the wizard asks, and what it writes.

A board's program is the same on every device in the fleet; what differs is a
handful of numbers — which GPIO the SCL line is on, which relay drives the
humidifier — plus the slot it was given. Those numbers live in
edge/templates/<role>.json, this module turns them into questions and then into
the files that go on the board.

Everything else is INFERRED and never asked: the MQTT host and port come from
config.env, the topics and the client id from the slot, the hostname (the
board's one name) from the unit, role and zone. Asking an operator to retype a topic is how a board ends up
publishing where nothing is listening.

    drivers    ROLE                what this role can carry
    params     ROLE DRIVER         what to ask for that driver
    functions  ROLE DRIVER         equipment a CONTROL board can drive
    channelmap ROLE DRIVER [VAR]   the whole editable map, as JSON, for the UI
    binding    ROLE [VARIANT]      how this device family addresses a channel
    validate   ROLE [VARIANT]      stdin config -> findings, exit 1 if fatal
    pins       ROLE [VARIANT]      the silicon's pin reference, as a table
    render                         stdin JSON -> the board's files

Which device family the templates come from is CEA_DEVICE_FAMILY (default
esp32). Everything pin-shaped lives behind the template's `binding` block, so a
family that drives Modbus coils or HTTP endpoints is a new template rather than
a fork of this module — see edge/src/host/bindings.py.

The output is line-oriented TSV so flash-device.sh stays the engine and this
stays a table.
"""

import json
import os
import sys

import bindings

TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "templates")

ROLES = ("SENSE", "CONTROL")

# A template file is <family>-<role>.json. The family is the device this
# platform is onboarding, not the role it plays: esp32-control.json and (say)
# modbus-control.json are both CONTROL boards, and everything downstream of
# load() works on either, because what differs between them — how an address is
# written and what counts as a legal one — lives in the template's `binding`
# block rather than in this file. CEA_DEVICE_FAMILY picks one; the default is
# the only family with firmware in this repo.
DEFAULT_FAMILY = "esp32"


class TemplateError(Exception):
    pass


def family():
    return (os.environ.get("CEA_DEVICE_FAMILY") or DEFAULT_FAMILY).strip().lower()


def template_path(role, fam=None):
    return os.path.join(TEMPLATE_DIR, "%s-%s.json" % (fam or family(), role.lower()))


def families():
    """Every family with a template on disk, for an error message worth reading."""
    out = set()
    try:
        for name in os.listdir(TEMPLATE_DIR):
            if name.endswith(".json") and "-" in name:
                out.add(name.rsplit(".", 1)[0].split("-", 1)[0])
    except OSError:
        pass
    return sorted(out)


def load(role):
    role = (role or "").upper()
    if role not in ROLES:
        raise TemplateError("unknown role %r (expected SENSE or CONTROL)" % role)
    fam = family()
    path = template_path(role, fam)
    if not os.path.exists(path):
        known = ", ".join(families()) or "none found"
        raise TemplateError(
            "no %s template for device family %r (looked for %s).\n"
            "Families with a template here: %s.\n"
            "Set CEA_DEVICE_FAMILY to one of those, or add the template."
            % (role, fam, path, known))
    try:
        with open(path, encoding="utf-8") as f:
            tpl = json.load(f)
    except OSError as e:
        raise TemplateError("cannot read the %s template %s: %s" % (role, path, e))
    except ValueError as e:
        raise TemplateError("%s is not valid JSON: %s" % (path, e))
    tpl.setdefault("family", fam)
    return tpl


def binding_for(role):
    """The addressing scheme this role's device family uses."""
    try:
        return bindings.from_template(load(role), TEMPLATE_DIR)
    except bindings.BindingError as e:
        raise TemplateError("the %s template declares an unusable binding: %s"
                            % (role, e))


def driver(role, driver_id):
    for d in load(role).get("drivers", []):
        if d.get("id") == driver_id:
            return d
    raise TemplateError("the %s template has no driver %r" % (role, driver_id))


def _t(*fields):
    return "\t".join(str(f).replace("\t", " ").replace("\n", " ") for f in fields)


# ------------------------------------------------------------------ queries --
def cmd_drivers(role):
    tpl = load(role)
    print(_t("ROLE", tpl["role"], tpl["component_type"],
             "multi" if tpl.get("multi") else "single"))
    for d in tpl.get("drivers", []):
        tags = ",".join(t["tag"] for t in d.get("tags", []))
        print(_t("DRIVER", d["id"], d.get("name", d["id"]),
                 d.get("subtitle", ""), tags))
    for p in tpl.get("device_params", []):
        print(_t("DEVPARAM", p["name"], p.get("kind", "int"), p.get("default", ""),
                 p.get("label", p["name"]), p.get("hint", ""),
                 "1" if p.get("advanced") else "0"))
    for i in tpl.get("inferred", []):
        print(_t("INFERRED", i["name"], i.get("from", ""), i.get("note", "")))
    return 0


def cmd_params(role, driver_id):
    """One PARAM line per question, each followed by its OPTION lines.

    Flat lines rather than an embedded JSON blob: the caller is a bash `while
    read` loop, and handing it JSON means a nested $(python3 -c '...') inside a
    quoted assignment inside a here-doc. That is a quoting bug waiting to
    happen, in a script that writes WiFi passphrases.
    """
    for p in driver(role, driver_id).get("params", []):
        print(_t("PARAM", p["name"], p.get("kind", "int"),
                 _fmt_default(p.get("default")), p.get("label", p["name"]),
                 p.get("hint", ""), "1" if p.get("advanced") else "0"))
        for o in p.get("options", []):
            print(_t("OPTION", p["name"], o["value"], o.get("label", o["value"])))
    return 0


def cmd_functions(role, driver_id):
    d = driver(role, driver_id)
    b = bindings.from_template(load(role), TEMPLATE_DIR)
    print(_t("DRIVERMETA", d["id"], d.get("model", ""), d.get("manufacturer", ""),
             "1" if d.get("active_low", True) else "0", b.label, b.kind))
    for f in d.get("functions", []):
        pin = f.get("default_pin")
        print(_t("FUNC", f["id"], f.get("label", f["id"]),
                 "" if pin is None else pin))
    return 0


def cmd_channelmap(role, driver_id, variant=None):
    """Everything the browser editor needs, as one JSON document on stdout.

    The editor is generic: it renders whatever this prints. That is the whole
    point of the binding block — a device family with no pins gets the same
    editor, correctly labelled and correctly validated, without a line of
    JavaScript changing.
    """
    tpl = load(role)
    d = driver(role, driver_id)
    b = bindings.from_template(tpl, TEMPLATE_DIR)
    if variant:
        b = b.select(variant)
    pins = {f["id"]: f["default_pin"] for f in d.get("functions", [])
            if f.get("default_pin") is not None}
    json.dump({
        "family": tpl.get("family", family()),
        "role": tpl.get("role", role),
        "driver": {"id": d["id"], "name": d.get("name", d["id"]),
                   "active_low": bool(d.get("active_low", True))},
        "binding": b.to_ui(),
        "functions": [{"id": f["id"], "label": f.get("label", f["id"]),
                       "default": f.get("default_pin")}
                      for f in d.get("functions", [])],
        # The reference wiring, already rendered, so the editor opens on a real
        # working table rather than an empty form.
        "reference": render_actuator_config(d, pins, b),
    }, sys.stdout)
    sys.stdout.write("\n")
    return 0


def cmd_binding(role, variant=None):
    b = binding_for(role)
    json.dump(b.select(variant).to_ui() if variant else b.to_ui(), sys.stdout)
    sys.stdout.write("\n")
    return 0


def cmd_validate(role, variant=None):
    """stdin: an actuator config. stdout: its findings. Exit 1 if any is fatal.

    The variant matters: a map that is clean on an S3 can be impossible on a
    C3, whose GPIOs stop at 21 and whose flash sits on 12-17.
    """
    cfg = json.load(sys.stdin)
    b = binding_for(role)
    if variant:
        b = b.select(variant)
    findings = bindings.validate_config(b, cfg)
    json.dump({"findings": findings,
               "errors": sum(1 for f in findings if f["level"] == "error"),
               "warnings": sum(1 for f in findings if f["level"] == "warn")},
              sys.stdout)
    sys.stdout.write("\n")
    return 1 if any(f["level"] == "error" for f in findings) else 0


def cmd_pins(role, variant=None):
    """The silicon's pin reference, as a table. What the form's info panel shows."""
    b = binding_for(role)
    if variant:
        b = b.select(variant)
    v = b.variants.get(b.variant) or {}
    print("%s  (%s)" % (b.variant_label(), b.ranges_text()))
    if v.get("subtitle"):
        print("  %s" % v["subtitle"])
    for key in ("absent_note", "flash_note"):
        if v.get(key):
            print("  %s" % v[key])
    print()
    print("  %-6s %-34s %s" % (b.label.upper(), "TYPE", "STATUS"))
    for r in b.pin_rows():
        mark = {"error": "UNUSABLE", "warn": "caution"}.get(r["level"], "free")
        print("  %-6s %-34s %s" % (r["pin"], ", ".join(r["types"]), mark))
    usable = b.usable_pins()
    print()
    print("  %d of %d addressable pins can drive a relay." % (usable and len(usable) or 0,
                                                              len(b.pin_rows())))
    return 0


def _fmt_default(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    return "" if v is None else v


# ------------------------------------------------------------------- render --
def coerce(kind, raw):
    """Turn one answered prompt into the type the board's code expects.

    Every answer arrives as a string — from `read -r` or from a browser POST —
    and a GPIO number that reaches MicroPython as "5" instead of 5 fails inside
    a driver, a long way from the question that caused it.
    """
    s = str(raw).strip()
    if kind == "bool":
        return s.lower() in ("1", "y", "yes", "true", "t", "on")
    if kind in ("pin", "int", "choice"):
        try:
            return int(s)
        except ValueError:
            raise TemplateError("%r is not a whole number" % raw)
    if kind == "float":
        try:
            return float(s)
        except ValueError:
            raise TemplateError("%r is not a number" % raw)
    return s


def _pyrepr(v):
    """A Python literal for device_cfg.py, via the JSON encoder.

    Not string formatting: a WiFi PSK may hold quotes, backslashes or non-ASCII,
    and every one of those turns a naive substitution into a board that will not
    boot. JSON's true/false/null are the only shapes that differ from Python's.
    """
    if isinstance(v, bool):
        return "True" if v else "False"
    if v is None:
        return "None"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_pyrepr(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (_pyrepr(k), _pyrepr(x))
                               for k, x in v.items()) + "}"
    raise TemplateError("cannot render %r into device_cfg.py" % (v,))


def render_actuator_config(tpl_driver, pins, binding=None):
    """Build the device's actuator config from the assigned channels.

    `pins` maps a function id to an address, or leaves it out entirely when the
    chamber has no such equipment. The address is whatever this device family
    uses — a GPIO on an ESP32, a coil on a Modbus relay — and `binding` is what
    knows the difference; nothing below this line names a pin. Two kinds of
    pruning happen here, and the second one is the one that matters:

    * an action naming an unassigned function is dropped — nothing to drive;
    * a branch whose `needs` are ALL unassigned is dropped WHOLE.

    Without the second rule "turn the UV lamp on" in a chamber with no UV lamp
    survives as the leftover actions from the same branch — turn the red and
    blue lamps off — and the board reports that it did what it was asked. An
    actuator the chamber cannot perform must be absent, so the scheduler can
    tell "cannot" from "did, and nothing happened".
    """
    b = binding or bindings.from_template(load("CONTROL"), TEMPLATE_DIR)
    labels = {f["id"]: f.get("label", f["id"]) for f in tpl_driver.get("functions", [])}
    descriptions = b.descriptions(pins, labels)

    def branch(spec):
        """One command's actions, or None if this chamber cannot perform it."""
        needs = spec.get("needs")
        if needs and not any(fid in pins for fid in needs):
            return None
        actions = [b.action(pins[fid], v)
                   for fid, v in spec.get("set", {}).items() if fid in pins]
        if not actions:
            return None
        return {"description": spec.get("description", ""), "actions": actions}

    defs = {}
    for name, spec in (tpl_driver.get("actuators") or {}).items():
        if spec.get("kind") == "types":
            types = {}
            for tname, tspec in spec.get("types", {}).items():
                built = {}
                for cmd, cspec in tspec.items():
                    got = branch(cspec)
                    if got is not None:
                        built[cmd] = got
                # A type with no ON is a light you can only switch off.
                if "ON" in built:
                    types[tname] = built
            if types:
                defs[name] = {"comment": spec.get("comment", ""), "types": types}
        else:
            cmds = {}
            for cmd, cspec in spec.get("commands", {}).items():
                got = branch(cspec)
                if got is not None:
                    cmds[cmd] = got
            # Same reasoning: an actuator that can only go DOWN is not one the
            # scheduler can control, so it does not go in the table at all.
            if "UP" in cmds:
                defs[name] = {"comment": spec.get("comment", ""), "commands": cmds}

    return {b.descriptions_key: descriptions, "actuator_definitions": defs}


def _normalise_config(b, cfg):
    """Clean an operator-edited table into what the device's code expects.

    The browser sends addresses as strings because HTML fields are strings. The
    board indexes its descriptions by string and its actions by the native type,
    so both conversions happen here rather than being half-done in two places.
    """
    descriptions = {}
    for addr, desc in (cfg.get(b.descriptions_key) or {}).items():
        if b.is_unassigned(addr):
            continue
        descriptions[b.key(b.normalise(addr))] = str(desc)

    defs = {}
    for name, spec in (cfg.get("actuator_definitions") or {}).items():
        name = str(name).strip()
        if not name:
            continue
        out = {"comment": str(spec.get("comment", ""))}
        if "types" in spec:
            types = {}
            for tname, tspec in (spec.get("types") or {}).items():
                tname = str(tname).strip()
                if not tname:
                    continue
                types[tname] = {c: _normalise_branch(b, br) for c, br in tspec.items()}
            out["types"] = types
        else:
            out["commands"] = {c: _normalise_branch(b, br)
                               for c, br in (spec.get("commands") or {}).items()}
        defs[name] = out
    return {b.descriptions_key: descriptions, "actuator_definitions": defs}


def _normalise_branch(b, branch):
    actions = []
    for act in branch.get("actions") or []:
        raw = act.get(b.field, act.get("pin"))
        if b.is_unassigned(raw):
            continue
        actions.append(b.action(b.normalise(raw), act.get("value", 0)))
    return {"description": str(branch.get("description", "")), "actions": actions}


def render(spec):
    """Write everything this board needs into spec['out_dir'].

    Returns the list of filenames written plus the component rows the platform
    database should get, so the caller does not have to re-derive either.
    """
    out_dir = spec["out_dir"]
    role = spec["role"].upper()
    unit = spec.get("unit_code", "")
    zone = spec.get("zone_code", "")
    root = spec.get("topic_root", "medcea")
    base_topic = "%s/%s/%s" % (root, unit, zone)

    cfg = {
        "STATE": spec.get("state", "REGISTERED"),
        "ROLE": role,
        # The board's one name (unit02-c-zone02): DHCP hostname and the
        # device_dns in its payloads. config.py reads HOSTNAME for both.
        "HOSTNAME": spec["hostname"],
        "UNIT_CODE": unit,
        "ZONE_CODE": zone,
        "ZONE_ID": spec.get("zone_id"),
        "WIFI_SSID": spec.get("wifi_ssid", ""),
        "WIFI_PSK": spec.get("wifi_psk", ""),
        "MQTT_HOST": spec.get("mqtt_host", ""),
        "MQTT_PORT": int(spec.get("mqtt_port", 1883)),
        # The board's own broker credential. Only here (and in the provisioned
        # record): the component rows below carry host/port but never this,
        # because the API role can read them.
        "MQTT_USER": spec.get("mqtt_user", ""),
        "MQTT_PASS": spec.get("mqtt_pass", ""),
        "TOPIC_ROOT": root,
        "MAC": spec.get("mac", ""),
        "FIRMWARE": spec.get("firmware", ""),
        "FIRMWARE_SHA256": spec.get("firmware_sha256", ""),
        "FLASHED_AT": spec.get("flashed_at", ""),
    }

    written = []
    components = []

    if role == "SENSE":
        tpl = load("SENSE")
        cfg["MESSAGE_INTERVAL"] = int(spec.get("message_interval", 30))
        sensors = []
        for chosen in spec.get("components", []):
            d = driver("SENSE", chosen["driver"])
            params = {}
            for p in d.get("params", []):
                name = p["name"]
                raw = chosen.get("params", {}).get(name, p.get("default"))
                params[name] = coerce(p.get("kind", "int"), raw)
            tags = [t["tag"] for t in d.get("tags", [])]
            sensors.append({"driver": d["id"], "params": params, "tags": tags})
            components.append({
                "component_type": tpl["component_type"],
                "model": d.get("model", tpl.get("model", "")),
                "manufacturer": d.get("manufacturer", tpl.get("manufacturer", "")),
                "parameters": {
                    "driver": d["id"],
                    "params": params,
                    "topic_base": base_topic + "/sense",
                    "message_interval": cfg["MESSAGE_INTERVAL"],
                    "mqtt": {"host": cfg["MQTT_HOST"], "port": cfg["MQTT_PORT"]},
                    "tags": [{"tag": t["tag"], "UoM": t.get("uom", ""),
                              "topic": "%s/sense/%s" % (base_topic, t["tag"])}
                             for t in d.get("tags", [])],
                },
            })
        if not sensors:
            raise TemplateError("a SENSE board with no sensor would publish nothing")
        cfg["SENSORS"] = sensors

    elif role == "CONTROL":
        tpl = load("CONTROL")
        d = driver("CONTROL", spec.get("driver", "relay8"))
        cfg["POLL_MS"] = int(spec.get("poll_ms", 100))
        cfg["ACTUATOR_CONFIG"] = "actuator_config.json"
        cfg["ACTIVE_LOW"] = bool(d.get("active_low", True))
        b = bindings.from_template(tpl, TEMPLATE_DIR)
        if spec.get("variant"):
            b = b.select(spec["variant"])
        cfg["BINDING"] = b.kind
        cfg["CHIP_VARIANT"] = b.variant

        # Two ways in. Normally the operator assigns one address per piece of
        # equipment and the command table is DERIVED from the template, which is
        # what keeps nine chambers running the same program. The wizard's editor
        # can instead hand back a table it built and the operator adjusted, and
        # that table is then authoritative — re-deriving it would silently throw
        # away the edit they were just shown.
        edited = spec.get("actuator_config")
        if edited:
            if not isinstance(edited, dict) or "actuator_definitions" not in edited:
                raise TemplateError(
                    "actuator_config must be an object with actuator_definitions")
            actuator_cfg = _normalise_config(b, edited)
        else:
            pins = {}
            for fid, raw in (spec.get("functions") or {}).items():
                if b.is_unassigned(raw):
                    continue
                try:
                    pins[fid] = b.normalise(raw)
                except bindings.BindingError as e:
                    raise TemplateError("%s: %s" % (fid, e))
            if not pins:
                raise TemplateError(
                    "a CONTROL board with no assigned %s would drive nothing" % b.label)
            actuator_cfg = render_actuator_config(d, pins, b)

        # The renderer's own verdict, refused rather than shipped. A board that
        # cannot switch an actuator on is not a board with a small problem.
        blocking = [f for f in bindings.validate_config(b, actuator_cfg)
                    if f["level"] == "error"]
        if blocking:
            raise TemplateError(
                "the actuator map has %d error(s) and was not written:\n  %s"
                % (len(blocking), "\n  ".join("%s — %s" % (f["where"], f["message"])
                                              for f in blocking)))
        path = os.path.join(out_dir, "actuator_config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(actuator_cfg, f, indent=2)
            f.write("\n")
        written.append("actuator_config.json")
        components.append({
            "component_type": tpl["component_type"],
            "model": d.get("model", tpl.get("model", "")),
            "manufacturer": d.get("manufacturer", tpl.get("manufacturer", "")),
            "parameters": dict(actuator_cfg, **{
                "driver": d["id"],
                "active_low": cfg["ACTIVE_LOW"],
                "topic_sub": base_topic + "/control/#",
                "topic_pub": base_topic + "/control_setpoint",
                "mqtt": {"host": cfg["MQTT_HOST"], "port": cfg["MQTT_PORT"]},
            }),
        })
    else:
        raise TemplateError("render does not know the role %r" % role)

    lines = [
        "# GENERATED by edge/flash-device.sh - do not edit by hand.",
        "#",
        "# Literals only. The logic that reads them is config.py, which is shipped",
        "# unchanged to every board; re-onboarding rewrites this file and leaves",
        "# that one alone. Editing here is how nine boards ended up with nine",
        "# subtly different programs.",
        "",
    ]
    for k, v in cfg.items():
        lines.append("%-16s = %s" % (k, _pyrepr(v)))
    lines.append("")
    with open(os.path.join(out_dir, "device_cfg.py"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    written.append("device_cfg.py")

    return {"written": written, "components": components,
            "topic_base": base_topic, "config": cfg}


def cmd_render():
    spec = json.load(sys.stdin)
    result = render(spec)
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[1]
    try:
        if cmd == "drivers":
            return cmd_drivers(argv[2])
        if cmd == "params":
            return cmd_params(argv[2], argv[3])
        if cmd == "functions":
            return cmd_functions(argv[2], argv[3])
        if cmd == "channelmap":
            return cmd_channelmap(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
        if cmd == "binding":
            return cmd_binding(argv[2], argv[3] if len(argv) > 3 else None)
        if cmd == "validate":
            return cmd_validate(argv[2], argv[3] if len(argv) > 3 else None)
        if cmd == "pins":
            return cmd_pins(argv[2], argv[3] if len(argv) > 3 else None)
        if cmd == "render":
            return cmd_render()
    except bindings.BindingError as e:
        print(str(e), file=sys.stderr)
        return 1
    except TemplateError as e:
        print(str(e), file=sys.stderr)
        return 1
    except IndexError:
        print("missing argument for %r" % cmd, file=sys.stderr)
        return 2
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
