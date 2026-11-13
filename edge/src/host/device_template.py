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
    actuator-map CONTROL DRIVER [VARIANT]
                                   stdin "<function>\t<pin>" lines -> {"actuator_definitions"}
                                   as render() derives them (the control-loop picker)
    sense-sources SENSE            stdin {"wiring", "variant"} or {"sensors_tsv"} ->
                                   [{instance, driver, tags}] of the components render()
                                   writes (the control-loop picker's planned sensors)

  SENSE wiring (the on-screen wiring screen; the rules are wiring.py's):
    wiring-spec      SENSE [VARIANT] [--initial FILE]   the screen's catalogue, JSON
    validate-wiring  SENSE VARIANT       stdin document -> findings, exit 1 if fatal
    board-templates  SENSE [VARIANT]     saved and shipped boards, TSV
    board-template   SLUG                one board template's wiring document
    save-board-template SLUG --title T [--description D] --by USER [--replace]
                                         stdin document -> edge/board-templates/SLUG.json

Which device family the templates come from is CEA_DEVICE_FAMILY (default
esp32). Everything pin-shaped lives behind the template's `binding` block, so a
family that drives Modbus coils or HTTP endpoints is a new template rather than
a fork of this module — see edge/src/host/bindings.py.

The output is line-oriented TSV so flash-device.sh stays the engine and this
stays a table.
"""

import datetime
import json
import os
import re
import sys
import tempfile

import bindings
import wiring

EDGE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATE_DIR = os.path.join(EDGE_DIR, "templates")

# Board templates: a wiring document with a name. The shipped ones come with
# git; the saved ones are written by the wizard on this host and are tracked in
# git too, so a board someone saved can be reviewed and shared. Not in the
# database: a new table would widen the access policy's skeleton.
SHIPPED_BOARDS_DIR = os.path.join(TEMPLATE_DIR, "boards")
SLUG_RX = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

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


class UsageError(Exception):
    """A command line the CLI cannot act on: exit 2."""


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


def saved_boards_dir():
    return os.environ.get("CEA_BOARD_TEMPLATES_DIR") or os.path.join(EDGE_DIR,
                                                                    "board-templates")


def _t(*fields):
    return "\t".join(str(f).replace("\t", " ").replace("\n", " ") for f in fields)


# ------------------------------------------------------------------ queries --
def cmd_drivers(role):
    tpl = load(role)
    print(_t("ROLE", tpl["role"], tpl["component_type"],
             "multi" if tpl.get("multi") else "single"))
    for d in tpl.get("drivers", []):
        # A wiring-only driver has no pins of its own to ask for: it lives on a
        # bus the wiring screen draws, so the question loop cannot place it.
        if d.get("wiring_only"):
            continue
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
        # TLS (5 Nov 2026): the name in the broker's certificate, verified against the
        # platform CA in mqtt_ca.der, which flash-device.sh copies next to this file.
        "MQTT_TLS_NAME": spec.get("mqtt_tls_name", ""),
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

    if role == "SENSE" and spec.get("wiring") is not None:
        # The wiring screen's document. wiring.py checks it again here and
        # refuses on any error: the board is about to be erased.
        tpl = load("SENSE")
        cfg["MESSAGE_INTERVAL"] = int(spec.get("message_interval", 30))
        try:
            got = wiring.render_sense(
                spec["wiring"], tpl, spec.get("variant"), base_topic=base_topic,
                message_interval=cfg["MESSAGE_INTERVAL"],
                mqtt={"host": cfg["MQTT_HOST"], "port": cfg["MQTT_PORT"]},
                coerce=coerce, base_dir=TEMPLATE_DIR)
        except wiring.WiringError as e:
            raise TemplateError(str(e))
        except bindings.BindingError as e:
            raise TemplateError("the GPIO table is unusable: %s" % e)
        cfg.update(got["cfg"])
        components.extend(got["components"])

    elif role == "SENSE":
        tpl = load("SENSE")
        cfg["MESSAGE_INTERVAL"] = int(spec.get("message_interval", 30))
        sensors = []
        seen = set()
        for i, chosen in enumerate(spec.get("components", [])):
            d = driver("SENSE", chosen["driver"])
            if d.get("wiring_only"):
                raise TemplateError(
                    "%s has no pins of its own: wire it on screen (or with --wiring)"
                    % d["id"])
            params = {}
            for p in d.get("params", []):
                name = p["name"]
                raw = chosen.get("params", {}).get(name, p.get("default"))
                params[name] = coerce(p.get("kind", "int"), raw)
            # The sensor instance: the last segment of its reading topic and the
            # "sensor" of its readings. A legacy SENSORS entry has no id, so the
            # firmware names it by cea_sense.Board.__init__'s rule (its driver,
            # then <driver>_<position> for a repeat); this row says the same.
            inst = d["id"]
            if inst in seen:
                inst = "%s_%d" % (inst, i + 1)
            seen.add(inst)
            tags = [t["tag"] for t in d.get("tags", [])]
            sensors.append({"driver": d["id"], "params": params, "tags": tags})
            components.append({
                "component_type": tpl["component_type"],
                "model": d.get("model", tpl.get("model", "")),
                "manufacturer": d.get("manufacturer", tpl.get("manufacturer", "")),
                "parameters": {
                    "driver": d["id"],
                    "instance": inst,
                    "params": params,
                    "topic_base": base_topic + "/sense",
                    "message_interval": cfg["MESSAGE_INTERVAL"],
                    "mqtt": {"host": cfg["MQTT_HOST"], "port": cfg["MQTT_PORT"]},
                    "tags": [{"tag": t["tag"], "UoM": t.get("uom", ""),
                              "topic": "%s/sense/%s/%s" % (base_topic, t["tag"], inst)}
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


# ------------------------------------------------------------- wiring ----
def _sense_only(role):
    if (role or "").upper() != "SENSE":
        raise UsageError("wiring and board templates are for SENSE boards only")
    return load("SENSE")


def _gpio(tpl):
    try:
        return wiring.gpio_binding(tpl, TEMPLATE_DIR)
    except bindings.BindingError as e:
        raise TemplateError("the GPIO table is unusable: %s" % e)


def _read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise TemplateError("cannot read %s %s: %s" % (what, path, e))
    except ValueError as e:
        raise TemplateError("%s %s is not valid JSON: %s" % (what, path, e))


def board_templates(tpl, variant=None):
    """Every board template, shipped first, each validated.

    `variant` is the chip to check against; without one each template is
    checked against its own board. An invalid template is listed with its
    first error, never hidden: "why is my board greyed out" needs an answer.
    """
    out, seen = [], set()
    for source, d in (("shipped", SHIPPED_BOARDS_DIR), ("saved", saved_boards_dir())):
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".json"))
        except OSError:
            continue
        for name in names:
            slug = name[:-5]
            if slug in seen or not SLUG_RX.match(slug):
                continue
            try:
                rec = _read_json(os.path.join(d, name), "board template")
            except TemplateError as e:
                rec, broken = {}, str(e)
            else:
                broken = None if isinstance(rec, dict) else "not a JSON object"
                rec = rec if isinstance(rec, dict) else {}
            seen.add(slug)
            doc = rec.get("wiring")
            if broken:
                findings = [{"level": "error", "message": broken}]
            else:
                findings = wiring.validate(doc, tpl, variant, TEMPLATE_DIR)
            errs = wiring.errors(findings)
            board = doc.get("board") if isinstance(doc, dict) else None
            out.append({
                "slug": slug, "title": str(rec.get("title") or slug),
                "description": str(rec.get("description") or ""),
                "variant": str(rec.get("variant") or
                               (board.get("variant") if isinstance(board, dict) else "")
                               or ""),
                "source": source, "valid": not errs,
                "first_error": errs[0]["message"] if errs else None,
                "wiring": doc,
            })
    return out


def find_board_template(slug):
    for d in (SHIPPED_BOARDS_DIR, saved_boards_dir()):
        path = os.path.join(d, slug + ".json")
        if SLUG_RX.match(slug or "") and os.path.exists(path):
            rec = _read_json(path, "board template")
            if not isinstance(rec, dict) or not isinstance(rec.get("wiring"), dict):
                raise TemplateError("board template %s has no wiring document" % path)
            return rec
    raise TemplateError("no board template %r" % slug)


def cmd_wiring_spec(role, args):
    """The wiring screen's whole catalogue, as one JSON object.

    It rides in every /api/state poll while the screen is up, so it carries no
    pictures (those come once, from /api/parts) and must stay under 32 KB.
    """
    tpl = _sense_only(role)
    variant, initial = None, None
    i = 0
    while i < len(args):
        if args[i] == "--initial":
            if i + 1 >= len(args):
                raise IndexError
            initial = _read_json(args[i + 1], "initial wiring")
            # The provisioned record and a board template both carry the
            # document under "wiring"; a bare document has a version. Only
            # the document is ever passed on: a record also holds the board's
            # passwords, and the spec goes to the browser.
            if isinstance(initial, dict) and "version" not in initial:
                initial = initial.get("wiring")
            if not isinstance(initial, dict):
                initial = None
            i += 2
        elif args[i].startswith("-"):
            raise TemplateError("unknown option %s" % args[i])
        else:
            variant = args[i]
            i += 1
    gpio = _gpio(tpl)
    variant = variant or gpio.variant
    if variant not in gpio.variants:
        raise TemplateError("unknown chip variant %r (known: %s)"
                            % (variant, ", ".join(sorted(gpio.variants))))
    drivers = []
    for d in tpl.get("drivers", []):
        if not d.get("bus"):
            continue
        drivers.append({
            "id": d["id"], "name": d.get("name", d["id"]),
            "subtitle": d.get("subtitle", ""), "model": d.get("model", ""),
            "manufacturer": d.get("manufacturer", ""), "part": d.get("part", ""),
            "bus": d["bus"], "power": d.get("power") or {},
            "quantities": d.get("quantities") or [],
            # Which quantities a NEW instance starts with switched off. Generic;
            # none ships since Q13 (the SCD30's T/RH are on, told apart from
            # the SHT45's by the sensor instance in the topic).
            "default_off": d.get("default_off") or [],
            "params": [p for p in d.get("params", []) if not p.get("legacy_bus")],
        })
    json.dump({
        "role": "SENSE", "family": tpl.get("family", family()), "variant": variant,
        "variants": [{"id": v, "label": gpio.variant_label(v)}
                     for v in sorted(gpio.variants)],
        "pins": gpio.variants[variant],
        "drivers": drivers,
        "hubs": tpl.get("hubs") or [],
        "boards": tpl.get("boards") or [],
        "templates": board_templates(tpl, variant),
        "initial": initial,
    }, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def cmd_validate_wiring(role, variant):
    """stdin: a wiring document. stdout: its findings. Exit 1 if any is fatal."""
    tpl = _sense_only(role)
    try:
        doc = json.load(sys.stdin)
    except ValueError as e:
        doc = None
        findings = [{"level": "error", "code": "E_SCHEMA", "where": "",
                     "message": "The wiring is not JSON: %s" % e}]
    else:
        try:
            findings = wiring.validate(doc, tpl, variant, TEMPLATE_DIR)
        except bindings.BindingError as e:
            raise TemplateError("the GPIO table is unusable: %s" % e)
    json.dump({"findings": findings,
               "errors": sum(1 for f in findings if f["level"] == "error"),
               "warnings": sum(1 for f in findings if f["level"] == "warn")},
              sys.stdout)
    sys.stdout.write("\n")
    return 1 if any(f["level"] == "error" for f in findings) else 0


def cmd_board_templates(role, variant=None):
    tpl = _sense_only(role)
    # Every field non-empty ("-"): the shell reads these with IFS=$'\t' read,
    # which merges empty fields and shifts the rest one variable left.
    for t in board_templates(tpl, variant):
        print(_t(t["slug"], t["title"].strip() or "-", t["variant"] or "-", t["source"],
                 "1" if t["valid"] else "0", t["first_error"] or "-"))
    return 0


def cmd_board_template(slug):
    json.dump(find_board_template(slug)["wiring"], sys.stdout)
    sys.stdout.write("\n")
    return 0


def cmd_save_board_template(args):
    """Save a wiring as a board template on this host. stdin: the document.

    Refused with nothing written: a bad slug, a shipped slug, an existing saved
    slug without --replace, or a document with any error. The write is atomic
    (temporary file, then link or rename), so a reader never sees half a file.
    """
    if not args or args[0].startswith("-"):
        raise IndexError
    slug, opts, flags = args[0], {}, set()
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("--title", "--description", "--by"):
            if i + 1 >= len(args):
                raise IndexError
            opts[a[2:]] = args[i + 1]
            i += 2
        elif a == "--replace":
            flags.add("replace")
            i += 1
        else:
            raise UsageError("unknown option %s" % a)
    title = (opts.get("title") or "").strip()
    by = (opts.get("by") or "").strip()
    if not title or not by:
        raise UsageError("save-board-template needs --title and --by")
    if not SLUG_RX.match(slug):
        raise TemplateError("%r is not a usable name: a lower-case letter, then 1-40 "
                            "lower-case letters, digits or -" % slug)
    if os.path.exists(os.path.join(SHIPPED_BOARDS_DIR, slug + ".json")):
        raise TemplateError("%s is a shipped board template; choose another name" % slug)
    for text, what in ((title, "title"), (opts.get("description") or "", "description")):
        if any(ord(c) < 32 for c in text) or len(text) > 400:
            raise TemplateError("the %s must be one line of at most 400 characters"
                                % what)
    tpl = _sense_only("SENSE")
    try:
        doc = json.load(sys.stdin)
    except ValueError as e:
        raise TemplateError("the wiring is not JSON: %s" % e)
    doc = wiring.normalise(doc)
    findings = wiring.validate(doc, tpl, None, TEMPLATE_DIR)
    errs = wiring.errors(findings)
    if errs:
        raise TemplateError("the wiring has %d error(s) and was not saved:\n  %s"
                            % (len(errs), "\n  ".join("%s %s — %s"
                                                     % (f["code"], f["where"] or "-",
                                                        f["message"]) for f in errs)))
    d = saved_boards_dir()
    path = os.path.join(d, slug + ".json")
    exists = os.path.exists(path)
    if exists and "replace" not in flags:
        raise TemplateError("a board template %s already exists; tick replace to "
                            "overwrite it" % slug)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = {"slug": slug, "title": title,
           "description": (opts.get("description") or "").strip(),
           "variant": doc["board"]["variant"], "saved_by": by, "saved_at": now}
    if exists:
        # A replacement keeps when the template first appeared; replaced_at says
        # when its wiring last changed. An unreadable old file just starts afresh.
        try:
            with open(path, encoding="utf-8") as f:
                old = json.load(f).get("saved_at")
            if isinstance(old, str) and old:
                rec["saved_at"] = old
        except (OSError, ValueError, AttributeError):
            pass
        rec["replaced_at"] = now
    rec["wiring"] = doc
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".%s." % slug, suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        if exists:
            os.replace(tmp, path)
        else:
            # link() refuses an existing name, so two saves of one new slug
            # cannot overwrite each other.
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise TemplateError("a board template %s was saved meanwhile" % slug)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(path)
    return 0


def cmd_actuator_map(role, driver_id, variant=None):
    """The actuator definitions a CONTROL board gets from one address per function
    (stdin, CONTROL_PINS_TSV's "<function>\t<pin>" lines), exactly as render()
    derives them: the control-loop picker's planned actuators, before the board is
    touched. The channel-map editor's table needs no call: it is already one."""
    if (role or "").upper() != "CONTROL":
        raise UsageError("actuator-map is for CONTROL boards")
    tpl = load("CONTROL")
    d = driver("CONTROL", driver_id)
    b = bindings.from_template(tpl, TEMPLATE_DIR)
    if variant:
        b = b.select(variant)
    pins = {}
    for line in sys.stdin.read().splitlines():
        if not line.strip():
            continue
        fid, _, raw = line.partition("\t")
        if b.is_unassigned(raw):
            continue
        try:
            pins[fid] = b.normalise(raw)
        except bindings.BindingError as e:
            raise TemplateError("%s: %s" % (fid, e))
    cfg = render_actuator_config(d, pins, b) if pins else {"actuator_definitions": {}}
    json.dump({"actuator_definitions": cfg["actuator_definitions"]}, sys.stdout)
    sys.stdout.write("\n")
    return 0


def sense_sources(plan):
    """[{instance, driver, tags}] of the SENSE board render() would write for this
    plan ({"wiring", "variant"}, or {"sensors_tsv"}: the questions' lines). Taken
    from the very components render() returns, so the instance is the last segment
    of each reading topic, as the database (_zone_inventory) and the runner read it."""
    with tempfile.TemporaryDirectory() as d:
        spec = {"out_dir": d, "role": "SENSE", "hostname": "sense-sources",
                "unit_code": "UNIT", "zone_code": "ZONE", "topic_root": "medcea"}
        if plan.get("wiring") is not None:
            spec["wiring"] = plan["wiring"]
            spec["variant"] = plan.get("variant") or None
        else:
            comps, order = {}, []
            for line in (plan.get("sensors_tsv") or "").splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                drv = parts[0]
                if drv not in comps:
                    comps[drv] = {"driver": drv, "params": {}}
                    order.append(drv)
                if len(parts) >= 3 and parts[1]:
                    comps[drv]["params"][parts[1]] = parts[2]
            spec["components"] = [comps[x] for x in order]
        got = render(spec)
    out = []
    for c in got["components"]:
        p = c.get("parameters") or {}
        tags, inst = [], None
        for t in p.get("tags") or []:
            if not isinstance(t, dict) or not isinstance(t.get("topic"), str):
                continue
            inst = t["topic"].rsplit("/", 1)[-1]
            tags.append(t.get("tag"))
        out.append({"instance": inst if inst is not None else p.get("instance"),
                    "driver": p.get("driver"), "tags": tags})
    return out


def cmd_sense_sources(role):
    if (role or "").upper() != "SENSE":
        raise UsageError("sense-sources is for SENSE boards")
    try:
        plan = json.load(sys.stdin)
    except ValueError:
        raise UsageError("sense-sources: stdin is not JSON")
    json.dump(sense_sources(plan), sys.stdout)
    sys.stdout.write("\n")
    return 0


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
        if cmd == "wiring-spec":
            return cmd_wiring_spec(argv[2], argv[3:])
        if cmd == "validate-wiring":
            if len(argv) != 4:
                raise IndexError
            return cmd_validate_wiring(argv[2], argv[3])
        if cmd == "board-templates":
            return cmd_board_templates(argv[2], argv[3] if len(argv) > 3 else None)
        if cmd == "board-template":
            return cmd_board_template(argv[2])
        if cmd == "save-board-template":
            return cmd_save_board_template(argv[2:])
        if cmd == "actuator-map":
            return cmd_actuator_map(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
        if cmd == "sense-sources":
            return cmd_sense_sources(argv[2])
    except UsageError as e:
        print(str(e), file=sys.stderr)
        return 2
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
