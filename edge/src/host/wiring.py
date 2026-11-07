#!/usr/bin/env python3
"""How a SENSE board's sensors are wired, checked and rendered.

The wiring screen edits one document (schema version 1):

    {"version": 1,
     "board":   {"variant": "esp32s3", "part": "esp32-s3-devkitc-1"},
     "buses":   [{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9, "freq": 100000,
                  "impl": "soft", "pullups": "external"}],
     "hubs":    [{"id": "mux0", "kind": "tca9548a", "bus": "i2c0", "addr": 112}],
     "sensors": [{"id": "sht45_1", "driver": "sht4x", "bus": "i2c0", "hub": "mux0",
                  "channel": 0, "addr": 68, "params": {},
                  "tags": [{"q": "temperature", "tag": "air_temperature"}, ...]}],
     "layout":  {"sht45_1": [420, 40]}}

and this module is the verdict on it. ui/wiring.js mirrors validate() so the
operator sees each finding as they drag a wire; the parity test holds the two to
the same (level, code, where) set on every fixture in tests/fixtures/wiring/.
Python is authoritative: render_sense() checks again and raises, so a stale page
or a hand-made POST cannot put a broken bus on a board that was just erased.

What a part can do is data in the SENSE template (a driver's `bus`, `power` and
`quantities`; `hubs`; `boards`), and what a pin is wired to inside the chip is
the same esp32-gpio.json the CONTROL binding reads, through bindings.py, so the
pin table cannot say one thing on the channel map and another here.

A document that is not well formed (E_SCHEMA) is not checked any further: every
later rule reads fields the schema promised, and a list of consequences of one
typo helps nobody.
"""

import os
import re

import bindings

VERSION = 1

ID_RX = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
TAG_RX = re.compile(r"^[a-z][a-z0-9_]{0,47}$")

TOP_KEYS = ("version", "board", "buses", "hubs", "sensors", "layout")
BOARD_KEYS = ("variant", "part")
BUS_KEYS = {
    "i2c": ("id", "kind", "sda", "scl", "freq", "impl", "pullups"),
    # Stage 2. Accepted by the schema so a stage-2 document says "not yet" in
    # words (E_BUS_KIND) rather than "unknown key".
    "rs485": ("id", "kind", "uart", "tx", "rx", "de", "baud", "termination"),
}
HUB_KEYS = ("id", "kind", "bus", "addr")
SENSOR_KEYS = ("id", "driver", "bus", "hub", "channel", "addr", "params", "tags",
               "unit")
TAG_KEYS = ("q", "tag")

# Every bus field that names a GPIO, in the order findings walk them.
PIN_FIELDS = {"i2c": ("sda", "scl"), "rs485": ("tx", "rx", "de")}
# An input-only pin can still receive. Everything else here drives the line.
INPUT_OK = ("rx",)

IMPLS = ("soft", "hw")
PULLUPS = ("external", "internal", "none")
FREQ_MIN, FREQ_MAX, FREQ_DEFAULT = 10000, 1000000, 100000
ADDR_MIN, ADDR_MAX = 0x08, 0x77
CHANNELS = 8


class WiringError(Exception):
    """A document render_sense() refuses to turn into a board."""


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def normalise(doc):
    """The document with every whole-number float made an int (68.0 -> 68).

    JSON does not tell 68 from 68.0, and the browser cannot: JSON.parse gives
    both as 68, so the screen's checks pass a hand-edited "addr": 68.0. Python
    sees a float and would call it E_SCHEMA, failing a wiring the operator was
    shown as clean. A fraction (68.5) stays a float and is still E_SCHEMA, on
    both sides. Returns a copy; the caller's document is not touched."""
    if isinstance(doc, float) and doc.is_integer():
        return int(doc)
    if isinstance(doc, dict):
        return {k: normalise(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [normalise(v) for v in doc]
    return doc


def _hex(a):
    return "0x%02X" % a


def gpio_binding(tpl, base_dir):
    """The ESP32 pin table the template points at, as a bindings.Binding."""
    spec = dict(bindings.DEFAULT_GPIO,
                variants_from=tpl.get("gpio_reference") or "esp32-gpio.json")
    return bindings.from_template({"binding": spec}, base_dir)


def wiring_drivers(tpl):
    """id -> driver, for the drivers that can sit on a shared bus."""
    return {d["id"]: d for d in tpl.get("drivers", []) if d.get("bus")}


def hub_kinds(tpl):
    return {h["id"]: h for h in tpl.get("hubs", [])}


def _path(section, obj, i):
    """Where an object is reported: by its id, or by its index when it has none."""
    oid = obj.get("id") if isinstance(obj, dict) else None
    if isinstance(oid, str) and oid:
        return "%s.%s" % (section, oid)
    return "%s.%d" % (section, i)


# --------------------------------------------------------------- schema ----
def _schema(doc):
    """E_SCHEMA findings, as (where, message). Empty means the shape is right."""
    out = []

    def bad(where, msg):
        out.append((where, msg))

    if not isinstance(doc, dict):
        bad("", "The wiring is not a JSON object.")
        return out
    if doc.get("version") != VERSION or not _int(doc.get("version")):
        bad("", "Wiring version must be %d." % VERSION)
    extra = sorted(k for k in doc if k not in TOP_KEYS)
    if extra:
        bad("", "Unknown key(s) in the wiring: %s." % ", ".join(map(str, extra)))

    board = doc.get("board")
    if not isinstance(board, dict):
        bad("board", "The wiring names no board.")
    else:
        extra = sorted(k for k in board if k not in BOARD_KEYS)
        if extra:
            bad("board", "Unknown key(s) in the board: %s." % ", ".join(extra))
        if not isinstance(board.get("variant"), str) or not board.get("variant"):
            bad("board", "The board has no chip variant.")
        if "part" in board and board["part"] is not None \
                and not isinstance(board["part"], str):
            bad("board", "The board part must be text.")

    if "layout" in doc and not isinstance(doc["layout"], dict):
        bad("", "layout must be an object.")

    seen = set()
    for section in ("buses", "hubs", "sensors"):
        items = doc.get(section, [])
        if items is None:
            items = []
        if not isinstance(items, list):
            bad("", "%s must be a list." % section)
            continue
        for i, obj in enumerate(items):
            where = _path(section, obj, i)
            if not isinstance(obj, dict):
                bad(where, "Each entry in %s must be an object." % section)
                continue
            oid = obj.get("id")
            if not isinstance(oid, str) or not ID_RX.match(oid) or oid == "board":
                bad(where, "%r is not a usable id: a lower-case letter, then up to "
                           "23 letters, digits or _ (\"board\" is taken)." % (oid,))
            elif oid in seen:
                bad(where, "The id %s is used twice." % oid)
            else:
                seen.add(oid)
            {"buses": _schema_bus, "hubs": _schema_hub,
             "sensors": _schema_sensor}[section](obj, where, bad)
    return out


def _schema_bus(b, where, bad):
    kind = b.get("kind")
    if not isinstance(kind, str) or not kind:
        bad(where, "The bus has no kind.")
        return
    keys = BUS_KEYS.get(kind)
    if keys is None:
        return                  # an unknown kind is E_BUS_KIND, said in words later
    extra = sorted(k for k in b if k not in keys)
    if extra:
        bad(where, "Unknown key(s) on a %s bus: %s." % (kind, ", ".join(extra)))
    if kind == "i2c":
        for f in ("sda", "scl"):
            if not _int(b.get(f)):
                bad(where, "The bus needs its %s GPIO as a whole number." % f.upper())
        if "freq" in b and not _int(b["freq"]):
            bad(where, "The bus frequency must be a whole number of Hz.")
        if "impl" in b and b["impl"] not in IMPLS:
            bad(where, "impl must be one of: %s." % ", ".join(IMPLS))
        if "pullups" in b and b["pullups"] not in PULLUPS:
            bad(where, "pullups must be one of: %s." % ", ".join(PULLUPS))
    else:
        for f in ("uart", "tx", "rx", "de", "baud"):
            if f in b and not _int(b[f]):
                bad(where, "%s must be a whole number." % f)
        if "termination" in b and not isinstance(b["termination"], bool):
            bad(where, "termination must be true or false.")


def _schema_hub(h, where, bad):
    if not isinstance(h.get("kind"), str) or not h.get("kind"):
        bad(where, "The hub has no kind.")
    if not isinstance(h.get("bus"), str) or not h.get("bus"):
        bad(where, "The hub is not wired to a bus: drag a wire from the board to it.")
    if not _int(h.get("addr")):
        bad(where, "The hub needs its I2C address as a whole number.")
    extra = sorted(k for k in h if k not in HUB_KEYS)
    if extra:
        bad(where, "Unknown key(s) on a hub: %s." % ", ".join(extra))


def _schema_sensor(s, where, bad):
    if not isinstance(s.get("driver"), str) or not s.get("driver"):
        bad(where, "The sensor names no driver.")
    for f in ("bus", "hub"):
        if s.get(f) is not None and not isinstance(s[f], str):
            bad(where, "%s must be an id or null." % f)
    if not _int(s.get("addr")):
        bad(where, "The sensor needs its address as a whole number.")
    if "params" in s and not isinstance(s["params"], dict):
        bad(where, "params must be an object.")
    if "tags" not in s:
        bad(where, "The sensor has no tags list.")
    extra = sorted(k for k in s if k not in SENSOR_KEYS)
    if extra:
        bad(where, "Unknown key(s) on a sensor: %s." % ", ".join(extra))


# ------------------------------------------------------------- validate ----
def validate(doc, tpl, variant=None, base_dir=None):
    """Every finding for a wiring document: [{level, code, where, message}].

    `variant` is the chip the board is (or will be) checked against; it wins
    over board.variant, because at step 3 the silicon esptool reads is the
    truth and the document only says what the operator expected.
    """
    findings = []
    doc = normalise(doc)

    def add(level, code, where, message):
        findings.append({"level": level, "code": code, "where": where,
                         "message": message})

    schema = _schema(doc)
    if schema:
        for where, msg in schema:
            add("error", "E_SCHEMA", where, msg)
        return _sorted(findings, doc)

    buses = doc.get("buses") or []
    hubs = doc.get("hubs") or []
    sensors = doc.get("sensors") or []
    drivers = wiring_drivers(tpl)
    hkinds = hub_kinds(tpl)

    # -- the board and its chip --------------------------------------------
    gpio = gpio_binding(tpl, base_dir or _template_dir())
    board = doc["board"]
    eff = variant or board["variant"]
    pins_of = None
    if board["variant"] not in gpio.variants:
        add("error", "E_VARIANT", "board",
            "%s is not a chip variant this wizard knows (known: %s)."
            % (board["variant"], ", ".join(sorted(gpio.variants))))
    elif eff not in gpio.variants:
        add("error", "E_VARIANT", "board",
            "%s is not a chip variant this wizard knows." % eff)
    if eff in gpio.variants:
        pins_of = gpio.select(eff)
        part = board.get("part")
        if part:
            offered = [b for b in tpl.get("boards", []) if b.get("part") == part]
            if not offered:
                add("error", "E_VARIANT", "board",
                    "%s is not a board this wizard offers." % part)
            elif eff not in (offered[0].get("variants") or []):
                add("error", "E_VARIANT", "board",
                    "The %s carries %s, not %s."
                    % (offered[0].get("name", part),
                       " or ".join(gpio.variant_label(v)
                                   for v in offered[0].get("variants") or [])
                       or "another chip",
                       gpio.variant_label(eff)))

    # -- buses -------------------------------------------------------------
    bus_by_id = {b["id"]: b for b in buses}
    used_pins = {}
    for b in buses:
        where = "buses." + b["id"]
        kind = b["kind"]
        if kind == "rs485":
            add("error", "E_BUS_KIND", where, "RS485 comes with stage 2.")
        elif kind != "i2c":
            add("error", "E_BUS_KIND", where,
                "A %s bus is not supported; only I2C for now." % kind)
        for f in PIN_FIELDS.get(kind, ()):
            pin = b.get(f)
            if not _int(pin):
                continue
            fw = "%s.%s" % (where, f)
            if pin in used_pins:
                add("error", "E_PIN_DUP", fw,
                    "GPIO%d is already used as %s." % (pin, used_pins[pin]))
            else:
                used_pins[pin] = "%s %s" % (b["id"], f.upper())
            if pins_of is None:
                continue
            if not any(lo <= pin <= hi for lo, hi in pins_of.valid_ranges):
                add("error", "E_PIN_RANGE", fw,
                    "GPIO%d does not exist on the %s (valid: %s)."
                    % (pin, pins_of.variant_label(), pins_of.ranges_text()))
                continue
            errs, warns = _pin_groups(pins_of, pin, f)
            if errs:
                add("error", "E_PIN_GROUP", fw, " ".join(errs))
            if warns:
                add("warn", "W_PIN_GROUP", fw, " ".join(warns))
        if kind == "i2c":
            freq = b.get("freq", FREQ_DEFAULT)
            if not FREQ_MIN <= freq <= FREQ_MAX:
                add("error", "E_BUS_FREQ", where + ".freq",
                    "%d Hz is outside %d..%d Hz." % (freq, FREQ_MIN, FREQ_MAX))
            pull = b.get("pullups", "external")
            if pull == "none":
                add("warn", "W_PULLUPS", where + ".pullups",
                    "No pull-ups on %s: I2C does not work without them. Fit "
                    "2.2 kΩ from SDA and SCL to 3V3." % b["id"])
            elif pull == "internal":
                add("warn", "W_PULLUPS", where + ".pullups",
                    "Internal pull-ups are too weak for a multi-sensor bus; fit "
                    "2.2 kΩ to 3V3.")

    # -- hubs --------------------------------------------------------------
    hub_by_id = {h["id"]: h for h in hubs}
    hub_ok = {}                 # id -> its bus, when the hub sits on a real I2C bus
    for h in hubs:
        where = "hubs." + h["id"]
        kind = hkinds.get(h["kind"])
        if kind is None:
            add("error", "E_DRIVER", where,
                "%s is not a hub this wizard knows." % h["kind"])
        bus = bus_by_id.get(h["bus"])
        if bus is None:
            add("error", "E_BUS_REF", where, "The hub's bus %s does not exist." % h["bus"])
        elif bus["kind"] != "i2c":
            add("error", "E_BUS_KIND", where, "A hub can only sit on an I2C bus.")
        else:
            hub_ok[h["id"]] = h["bus"]
        _addr(add, where, h["addr"], kind and kind.get("addrs"),
              kind and kind.get("name"))
        if kind:
            _power(add, where, kind, kind.get("name", h["kind"]))
        if not any(s.get("hub") == h["id"] for s in sensors):
            add("warn", "W_HUB_UNUSED", where,
                "Nothing is wired to %s. Remove it, or wire a sensor to a channel."
                % h["id"])

    # -- sensors -----------------------------------------------------------
    placed = []                 # (sensor, bus id, hub id or None, channel or None)
    published = {}              # tag name -> where it was first published
    for s in sensors:
        where = "sensors." + s["id"]
        d = drivers.get(s["driver"])
        if d is None:
            add("error", "E_DRIVER", where,
                "%s is not a sensor the wiring screen can place." % s["driver"])
        _addr(add, where, s["addr"], d and d["bus"].get("addrs"), d and d.get("name"))
        if d:
            _power(add, where, d, d.get("name", d["id"]))
        _tags(add, where, s.get("tags"), d, published)

        hub_id, ch = s.get("hub"), s.get("channel")
        if s.get("bus") is None:
            add("error", "E_UNWIRED", where,
                "%s is not wired: drag a wire from the board or hub to it." % s["id"])
            continue
        bus = bus_by_id.get(s["bus"])
        if bus is None:
            add("error", "E_BUS_REF", where, "The sensor's bus %s does not exist." % s["bus"])
            continue
        loc_ok = True
        if hub_id is not None:
            hub = hub_by_id.get(hub_id)
            # A hub that is not there has no channels to check.
            if hub is None:
                add("error", "E_BUS_REF", where, "The sensor's hub %s does not exist." % hub_id)
                loc_ok = False
            elif hub["bus"] != s["bus"]:
                add("error", "E_BUS_REF", where,
                    "The sensor is on %s but its hub %s is on %s."
                    % (s["bus"], hub_id, hub["bus"]))
                loc_ok = False
            elif ch is None:
                add("error", "E_HUB", where + ".channel",
                    "The sensor is behind %s but on no channel." % hub_id)
                loc_ok = False
            elif not _int(ch) or not 0 <= ch < CHANNELS:
                add("error", "E_HUB", where + ".channel",
                    "%r is not a hub channel (0-%d)." % (ch, CHANNELS - 1))
                loc_ok = False
            elif hub_id not in hub_ok:
                loc_ok = False
        elif ch is not None:
            add("error", "E_HUB", where + ".channel",
                "A channel without a hub: wire the sensor to a hub channel, or "
                "clear the channel.")
            loc_ok = False
        if d and bus["kind"] != d["bus"].get("kind"):
            add("error", "E_BUS_KIND", where,
                "%s talks %s, not %s." % (d.get("name", d["id"]),
                                          d["bus"].get("kind"), bus["kind"]))
            loc_ok = False
        if loc_ok:
            placed.append((s, s["bus"], hub_id, ch))

    # -- per bus: speed and addresses ---------------------------------------
    for b in buses:
        if b["kind"] != "i2c":
            continue
        freq = b.get("freq", FREQ_DEFAULT)
        limits = []
        for h in hubs:
            kind = hkinds.get(h["kind"])
            if kind and h["bus"] == b["id"] and kind.get("max_freq"):
                limits.append((kind["max_freq"], kind.get("name", h["kind"])))
        for s in sensors:
            d = drivers.get(s["driver"])
            if d and s.get("bus") == b["id"] and d["bus"].get("max_freq"):
                limits.append((d["bus"]["max_freq"], d.get("name", d["id"])))
        if limits and FREQ_MIN <= freq <= FREQ_MAX:
            low, who = min(limits)
            if freq > low:
                add("error", "E_BUS_FREQ", "buses.%s.freq" % b["id"],
                    "%s runs at %d Hz but %s takes at most %d Hz."
                    % (b["id"], freq, who, low))

        devices = [("hubs." + h["id"], h["addr"], None, None) for h in hubs
                   if h["id"] in hub_ok and hub_ok[h["id"]] == b["id"]]
        devices += [("sensors." + s["id"], s["addr"], hub_id, ch)
                    for s, bus_id, hub_id, ch in placed if bus_id == b["id"]]
        devices = [x for x in devices if ADDR_MIN <= x[1] <= ADDR_MAX]
        for i, (w, a, hub_id, ch) in enumerate(devices):
            for w2, a2, hub2, ch2 in devices[:i]:
                if a != a2:
                    continue
                # A hub's own address is on the root segment, which every channel
                # sees; two channels never see each other.
                if hub_id is not None and hub2 is not None and (hub_id, ch) != (hub2, ch2):
                    continue
                add("error", "E_ADDR_CLASH", w + ".addr",
                    "%s answers %s, like %s on the same segment."
                    % (w.split(".", 1)[1], _hex(a), w2.split(".", 1)[1]))
                break

    if not published:
        add("error", "E_NO_SENSOR", "",
            "No sensor publishes anything: the board would send no readings.")
    return _sorted(findings, doc)


def _pin_groups(binding, pin, field):
    """The error and warning notes for one pin, from the variant's groups."""
    errs, warns = [], []
    for g in (binding.variants.get(binding.variant) or {}).get("groups") or []:
        if pin not in (g.get("pins") or []) or not g.get("level"):
            continue
        if g.get("id") == "input_only" and field in INPUT_OK:
            continue
        note = str(g.get("note", g.get("label", ""))).replace("{addr}", str(pin))
        (errs if g["level"] == "error" else warns).append(note)
    return errs, warns


def _addr(add, where, addr, options, name):
    if not ADDR_MIN <= addr <= ADDR_MAX:
        add("error", "E_ADDR_RANGE", where + ".addr",
            "%s is not a usable I2C address (%s-%s)."
            % (_hex(addr) if addr >= 0 else addr, _hex(ADDR_MIN), _hex(ADDR_MAX)))
    elif options and addr not in options:
        add("error", "E_ADDR_OPTION", where + ".addr",
            "%s answers only %s, not %s."
            % (name, " or ".join(_hex(a) for a in options), _hex(addr)))


def _power(add, where, part, name):
    rails = (part.get("power") or {}).get("rails") or []
    if rails and "3V3" not in rails:
        add("warn", "W_POWER", where,
            "Power %s from %s, not from the board's 3V3." % (name, " or ".join(rails)))


def _tags(add, where, tags, d, published):
    """E_TAG / E_TAG_DUP / W_TAG_OFF for one sensor; records what it publishes."""
    tw = where + ".tags"
    ok = isinstance(tags, list) and all(
        isinstance(t, dict) and set(t) == set(TAG_KEYS) and isinstance(t["q"], str)
        and (t["tag"] is None or isinstance(t["tag"], str)) for t in tags)
    if not ok:
        add("error", "E_TAG", tw,
            "tags must be a list of {q, tag}, tag being a name or null.")
        return
    quantities = [q["q"] for q in d.get("quantities", [])] if d else None
    seen = set()
    for t in tags:
        q, name = t["q"], t["tag"]
        qw = "%s.%s" % (tw, q)
        if quantities is not None and q not in quantities:
            add("error", "E_TAG", qw, "%s does not measure %s." % (d.get("name"), q))
            continue
        if q in seen:
            add("error", "E_TAG", qw, "%s is listed twice." % q)
            continue
        seen.add(q)
        if name is None:
            continue
        if not TAG_RX.match(name):
            add("error", "E_TAG", qw,
                "%r is not a tag name: a lower-case letter, then up to 47 letters, "
                "digits or _." % name)
            continue
        if name in published:
            add("error", "E_TAG_DUP", qw,
                "%s is already published by %s: two sensors on one tag would "
                "interleave one series." % (name, published[name]))
            continue
        published[name] = where.split(".", 1)[1]
    for q in quantities or []:
        if q not in seen:
            add("error", "E_TAG", "%s.%s" % (tw, q),
                "%s is not listed: give it a tag name, or null to switch it off." % q)
    if tags and all(t["tag"] is None for t in tags):
        add("warn", "W_TAG_OFF", where,
            "Every reading of %s is switched off: it is wired but publishes nothing."
            % where.split(".", 1)[1])


def _sorted(findings, doc):
    """Document order of `where`. Cosmetic: tests compare sets."""
    order = {"": 0, "board": 1}
    if isinstance(doc, dict):
        for section in ("buses", "hubs", "sensors"):
            items = doc.get(section)
            if isinstance(items, list):
                for i, obj in enumerate(items):
                    order.setdefault(_path(section, obj, i), len(order))

    # Within one object, in the order the checks walk its fields (sda before
    # scl), which is the order the operator reads them on screen.
    def key(item):
        i, f = item
        head = ".".join(f["where"].split(".")[:2])
        return (order.get(head, len(order)), i)
    return [f for _i, f in sorted(enumerate(findings), key=key)]


def errors(findings):
    return [f for f in findings if f["level"] == "error"]


def _template_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "templates")


# --------------------------------------------------------------- render ----
def render_sense(doc, tpl, variant=None, base_topic="", message_interval=30,
                 mqtt=None, coerce=None, base_dir=None):
    """The board's wiring as device_cfg.py values plus one DB row per sensor.

    Returns {"cfg": {WIRING_VERSION, BUSES, HUBS, SENSORS}, "components": [...]}.
    Raises WiringError on any error finding: nothing is half-written.
    """
    doc = normalise(doc)
    blocking = errors(validate(doc, tpl, variant, base_dir))
    if blocking:
        raise WiringError(
            "the wiring has %d error(s) and was not written:\n  %s"
            % (len(blocking), "\n  ".join("%s %s — %s" % (f["code"], f["where"] or "-",
                                                          f["message"])
                                          for f in blocking)))
    mqtt = mqtt or {}
    drivers = wiring_drivers(tpl)
    buses = {}
    out_buses = []
    for b in doc.get("buses") or []:
        nb = {"id": b["id"], "kind": "i2c", "sda": b["sda"], "scl": b["scl"],
              "freq": b.get("freq", FREQ_DEFAULT), "impl": b.get("impl", "soft")}
        buses[b["id"]] = nb
        out_buses.append(nb)
    hubs = {}
    out_hubs = []
    for h in doc.get("hubs") or []:
        nh = {"id": h["id"], "kind": h["kind"], "bus": h["bus"], "addr": h["addr"]}
        hubs[h["id"]] = nh
        out_hubs.append(nh)

    sensors, components = [], []
    for s in doc.get("sensors") or []:
        d = drivers[s["driver"]]
        params = {}
        given = s.get("params") or {}
        for p in d.get("params", []):
            if p.get("legacy_bus"):
                continue        # the bus is the document's, not the driver's
            raw = given.get(p["name"], p.get("default"))
            params[p["name"]] = coerce(p.get("kind", "int"), raw) if coerce else raw
        uom = {q["q"]: q.get("uom", "") for q in d.get("quantities", [])}
        tags = [[t["q"], t["tag"], uom.get(t["q"], "")]
                for t in s["tags"] if t["tag"] is not None]
        hub_id = s.get("hub")
        sensors.append({"id": s["id"], "driver": d["id"], "bus": s["bus"],
                        "hub": hub_id, "channel": s.get("channel") if hub_id else None,
                        "addr": s["addr"], "params": params, "tags": tags})
        bus = buses[s["bus"]]
        hub = hubs.get(hub_id)
        components.append({
            "component_type": tpl["component_type"],
            "model": d.get("model", tpl.get("model", "")),
            "manufacturer": d.get("manufacturer", tpl.get("manufacturer", "")),
            "parameters": {
                "driver": d["id"],
                "instance": s["id"],
                "addr": s["addr"],
                "wiring": {
                    "bus": {"kind": bus["kind"], "sda": bus["sda"], "scl": bus["scl"],
                            "freq": bus["freq"]},
                    "hub": ({"kind": hub["kind"], "addr": hub["addr"],
                             "channel": s.get("channel")} if hub else None),
                },
                "params": params,
                "topic_base": base_topic + "/sense",
                "message_interval": message_interval,
                "mqtt": {"host": mqtt.get("host", ""), "port": mqtt.get("port")},
                "tags": [{"tag": tag, "UoM": u,
                          "topic": "%s/sense/%s" % (base_topic, tag)}
                         for _q, tag, u in tags],
            },
        })
    return {"cfg": {"WIRING_VERSION": VERSION, "BUSES": out_buses, "HUBS": out_hubs,
                    "SENSORS": sensors},
            "components": components}
