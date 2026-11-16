/* The SENSE wiring screen.
 *
 * The operator draws the board: the ESP32 with one output per I2C bus, hubs
 * hanging off a bus, sensors hanging off a bus or a hub channel. Drawflow
 * (vendor/, MIT) draws the boxes and the wires; everything the platform cares
 * about is the wiring document (schema 1), which value() builds from the
 * drawing and which is all the page ever sends. Drawflow's own export carries
 * every node's HTML, pictures included, and would not fit the answer.
 *
 * The checks between wiring-logic:begin and :end mirror edge/src/host/wiring.py
 * code for code and path for path (tests/test_wiring_ui.py compares them on
 * every fixture). The browser needs a verdict on every drag; the renderer needs
 * one it can refuse on. Python is authoritative — render_sense() re-checks.
 *
 * Drawflow puts node HTML in with innerHTML, so every string that reaches a
 * node goes through esc(), and a picture is an <img> with a data: URI: an
 * image cannot run script.
 *
 *   Wiring.mount({el, spec, initial, parts, onchange})
 *     -> {value, variant, errors, findings, saveAs}
 *   Wiring.logic = {validate, fromDrawflow, toDrawflow}
 */
(function (root) {
  "use strict";

  /* wiring-logic:begin */
  var ID_RX = /^[a-z][a-z0-9_]{0,23}$/, TAG_RX = /^[a-z][a-z0-9_]{0,47}$/;
  // A sensor id ends its reading topic (<base>/sense/<tag>/<id>); "default" is
  // the platform's name for the sensor of a reading that names none.
  var RESERVED_SENSOR_IDS = ["default"];
  var SLUG_RX = /^[a-z][a-z0-9-]{1,40}$/;
  var TOP_KEYS = ["version", "board", "buses", "hubs", "sensors", "layout"];
  var BOARD_KEYS = ["variant", "part"];
  var BUS_KEYS = {
    i2c: ["id", "kind", "sda", "scl", "freq", "impl", "pullups"],
    rs485: ["id", "kind", "uart", "tx", "rx", "de", "baud", "termination"]
  };
  var HUB_KEYS = ["id", "kind", "bus", "addr"];
  var SENSOR_KEYS = ["id", "driver", "bus", "hub", "channel", "addr", "params", "tags", "unit"];
  var PIN_FIELDS = { i2c: ["sda", "scl"], rs485: ["tx", "rx", "de"] };
  // An input-only pin cannot drive these; RX only listens, so it may sit on one.
  var DRIVES = { sda: 1, scl: 1, tx: 1, de: 1 };
  var IMPLS = ["soft", "hw"], PULLUPS = ["external", "internal", "none"];
  var ADDR_LO = 8, ADDR_HI = 119, CHANNELS = 8;
  var FREQ_MIN = 10000, FREQ_MAX = 1000000, FREQ_DEFAULT = 100000;

  function isObj(x) { return x !== null && typeof x === "object" && !Array.isArray(x); }
  function isInt(x) { return typeof x === "number" && isFinite(x) && Math.floor(x) === x; }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function hex(n) { return "0x" + (n < 16 ? "0" : "") + n.toString(16).toUpperCase(); }
  /* The variant's pin table: ranges and groups, as wiring-spec prints it. The
     spec carries the table of the variant it was built for (and, if the host
     ever sends them, every variant's under pins_by_variant). */
  function pinTable(spec, variant) {
    spec = spec || {};
    if (spec.pins_by_variant && spec.pins_by_variant[variant]) return spec.pins_by_variant[variant];
    if (spec.variant === variant && spec.pins) return spec.pins;
    return null;
  }
  function knownVariant(spec, v) {
    var vs = (spec && spec.variants) || [];
    for (var i = 0; i < vs.length; i++) if ((vs[i] && vs[i].id) === v) return true;
    return !!pinTable(spec, v);
  }
  function inRanges(ranges, p) {
    for (var i = 0; i < (ranges || []).length; i++)
      if (p >= ranges[i][0] && p <= ranges[i][1]) return true;
    return false;
  }

  /* Every finding for a wiring document, as wiring.validate() gives it: the
     same codes at the same paths, in the same order of checks. `variant` is the
     chip it is checked against and wins over board.variant. Like the Python, a
     document that is not well formed (E_SCHEMA) is checked no further. */
  function validate(doc, spec, variant) {
    spec = spec || {};
    var out = [];
    function add(level, code, where, message) {
      out.push({ level: level, code: code, where: where, message: message });
    }

    var schema = schemaFindings(doc);
    if (schema.length) {
      schema.forEach(function (x) { add("error", "E_SCHEMA", x[0], x[1]); });
      return sortFindings(out, doc);
    }

    var buses = doc.buses || [], hubs = doc.hubs || [], sensors = doc.sensors || [];
    var drivers = {}, hkinds = {};
    (spec.drivers || []).forEach(function (d) { if (d && d.id && d.bus) drivers[d.id] = d; });
    (spec.hubs || []).forEach(function (x) { if (x && x.id) hkinds[x.id] = x; });

    // -- the board and its chip
    var board = doc.board, eff = variant || board.variant, pins = null;
    function vlabel(v) {
      var x = (spec.variants || []).filter(function (y) { return y.id === v; })[0];
      return (x && x.label) || v;
    }
    if (!knownVariant(spec, board.variant)) {
      add("error", "E_VARIANT", "board", board.variant + " is not a chip variant this wizard knows.");
    } else if (!knownVariant(spec, eff)) {
      add("error", "E_VARIANT", "board", eff + " is not a chip variant this wizard knows.");
    }
    if (knownVariant(spec, eff)) {
      pins = pinTable(spec, eff);
      var part = board.part;
      if (part) {
        var offered = (spec.boards || []).filter(function (b) { return b.part === part; });
        if (!offered.length)
          add("error", "E_VARIANT", "board", part + " is not a board this wizard offers.");
        else if ((offered[0].variants || []).indexOf(eff) < 0)
          add("error", "E_VARIANT", "board", "The " + (offered[0].name || part) + " carries " +
              ((offered[0].variants || []).map(vlabel).join(" or ") || "another chip") + ", not " + vlabel(eff) + ".");
      }
    }

    // -- buses
    var busById = {}, usedPins = {};
    buses.forEach(function (b) { busById[b.id] = b; });
    buses.forEach(function (b) {
      var where = "buses." + b.id, kind = b.kind;
      if (kind === "rs485") add("error", "E_BUS_KIND", where, "RS485 comes with stage 2.");
      else if (kind !== "i2c") add("error", "E_BUS_KIND", where, "A " + kind + " bus is not supported; only I2C for now.");
      (PIN_FIELDS[kind] || []).forEach(function (f) {
        var pin = b[f];
        if (!isInt(pin)) return;
        var fw = where + "." + f;
        if (has(usedPins, pin)) add("error", "E_PIN_DUP", fw, "GPIO" + pin + " is already used as " + usedPins[pin] + ".");
        else usedPins[pin] = b.id + " " + f.toUpperCase();
        if (!pins) return;
        if (!inRanges(pins.ranges, pin)) {
          add("error", "E_PIN_RANGE", fw, "GPIO" + pin + " does not exist on the " + (pins.label || eff) +
              " (valid: " + (pins.ranges || []).map(function (r) { return r[0] + "-" + r[1]; }).join(", ") + ").");
          return;
        }
        var errs = [], warns = [];
        (pins.groups || []).forEach(function (g) {
          if ((g.pins || []).indexOf(pin) < 0 || !g.level) return;
          if (g.id === "input_only" && !DRIVES[f]) return;
          var note = String(g.note != null ? g.note : (g.label || "")).replace(/\{addr\}/g, String(pin));
          (g.level === "error" ? errs : warns).push(note);
        });
        if (errs.length) add("error", "E_PIN_GROUP", fw, errs.join(" "));
        if (warns.length) add("warn", "W_PIN_GROUP", fw, warns.join(" "));
      });
      if (kind === "i2c") {
        var freq = has(b, "freq") ? b.freq : FREQ_DEFAULT;
        if (!(freq >= FREQ_MIN && freq <= FREQ_MAX))
          add("error", "E_BUS_FREQ", where + ".freq", freq + " Hz is outside " + FREQ_MIN + ".." + FREQ_MAX + " Hz.");
        var pull = has(b, "pullups") ? b.pullups : "external";
        if (pull === "none")
          add("warn", "W_PULLUPS", where + ".pullups", "No pull-ups on " + b.id +
              ": I2C does not work without them. Fit 2.2 kΩ from SDA and SCL to 3V3.");
        else if (pull === "internal")
          add("warn", "W_PULLUPS", where + ".pullups",
              "Internal pull-ups are too weak for a multi-sensor bus; fit 2.2 kΩ to 3V3.");
      }
    });

    // -- hubs
    var hubById = {}, hubOk = {};
    hubs.forEach(function (x) { hubById[x.id] = x; });
    hubs.forEach(function (x) {
      var where = "hubs." + x.id, kind = hkinds[x.kind] || null;
      if (!kind) add("error", "E_DRIVER", where, x.kind + " is not a hub this wizard knows.");
      var bus = has(busById, x.bus) ? busById[x.bus] : null;
      if (!bus) add("error", "E_BUS_REF", where, "The hub's bus " + x.bus + " does not exist.");
      else if (bus.kind !== "i2c") add("error", "E_BUS_KIND", where, "A hub can only sit on an I2C bus.");
      else hubOk[x.id] = x.bus;
      addrCheck(add, where, x.addr, kind && kind.addrs, kind && kind.name);
      if (kind) power(add, where, kind, kind.name || x.kind);
      if (!sensors.some(function (s) { return s.hub === x.id; }))
        add("warn", "W_HUB_UNUSED", where, "Nothing is wired to " + x.id +
            ". Remove it, or wire a sensor to a channel.");
    });

    // -- sensors
    var placed = [], published = {}, npub = { n: 0 };
    sensors.forEach(function (s) {
      var where = "sensors." + s.id, d = has(drivers, s.driver) ? drivers[s.driver] : null;
      if (RESERVED_SENSOR_IDS.indexOf(s.id) >= 0)
        add("error", "E_ID_RESERVED", where, s.id + " is reserved: the platform calls the sensor of a reading " +
            "that names none \"" + s.id + "\". Give this sensor another id.");
      if (!d) add("error", "E_DRIVER", where, s.driver + " is not a sensor the wiring screen can place.");
      addrCheck(add, where, s.addr, d && d.bus.addrs, d && d.name);
      if (d) power(add, where, d, d.name || d.id);
      tagChecks(add, where, s.tags, d, published, npub);

      var hubId = has(s, "hub") ? s.hub : null, ch = has(s, "channel") ? s.channel : null;
      if (hubId === undefined) hubId = null;
      if (ch === undefined) ch = null;
      if (!has(s, "bus") || s.bus === null) {
        add("error", "E_UNWIRED", where, s.id + " is not wired: drag a wire from the board or hub to it.");
        return;
      }
      var bus = has(busById, s.bus) ? busById[s.bus] : null;
      if (!bus) { add("error", "E_BUS_REF", where, "The sensor's bus " + s.bus + " does not exist."); return; }
      var locOk = true;
      if (hubId !== null) {
        var hub = has(hubById, hubId) ? hubById[hubId] : null;
        if (!hub) { add("error", "E_BUS_REF", where, "The sensor's hub " + hubId + " does not exist."); locOk = false; }
        else if (hub.bus !== s.bus) {
          add("error", "E_BUS_REF", where, "The sensor is on " + s.bus + " but its hub " + hubId + " is on " + hub.bus + ".");
          locOk = false;
        } else if (ch === null) {
          add("error", "E_HUB", where + ".channel", "The sensor is behind " + hubId + " but on no channel.");
          locOk = false;
        } else if (!isInt(ch) || ch < 0 || ch >= CHANNELS) {
          add("error", "E_HUB", where + ".channel", JSON.stringify(ch) + " is not a hub channel (0-" + (CHANNELS - 1) + ").");
          locOk = false;
        } else if (!has(hubOk, hubId)) {
          locOk = false;
        }
      } else if (ch !== null) {
        add("error", "E_HUB", where + ".channel",
            "A channel without a hub: wire the sensor to a hub channel, or clear the channel.");
        locOk = false;
      }
      if (d && bus.kind !== d.bus.kind) {
        add("error", "E_BUS_KIND", where, (d.name || d.id) + " talks " + d.bus.kind + ", not " + bus.kind + ".");
        locOk = false;
      }
      if (locOk) placed.push({ s: s, bus: s.bus, hub: hubId, ch: ch });
    });

    // -- per bus: speed and addresses
    buses.forEach(function (b) {
      if (b.kind !== "i2c") return;
      var freq = has(b, "freq") ? b.freq : FREQ_DEFAULT, low = null, who = "";
      function see(max, name) {
        if (max && (low === null || max < low || (max === low && name < who))) { low = max; who = name; }
      }
      hubs.forEach(function (x) {
        var k = hkinds[x.kind];
        if (k && x.bus === b.id && k.max_freq) see(k.max_freq, k.name || x.kind);
      });
      sensors.forEach(function (s) {
        var d = has(drivers, s.driver) ? drivers[s.driver] : null;
        if (d && s.bus === b.id && d.bus.max_freq) see(d.bus.max_freq, d.name || d.id);
      });
      if (low !== null && freq >= FREQ_MIN && freq <= FREQ_MAX && freq > low)
        add("error", "E_BUS_FREQ", "buses." + b.id + ".freq",
            b.id + " runs at " + freq + " Hz but " + who + " takes at most " + low + " Hz.");

      var devs = [];
      hubs.forEach(function (x) {
        if (has(hubOk, x.id) && hubOk[x.id] === b.id) devs.push({ w: "hubs." + x.id, a: x.addr, hub: null, ch: null });
      });
      placed.forEach(function (p) {
        if (p.bus === b.id) devs.push({ w: "sensors." + p.s.id, a: p.s.addr, hub: p.hub, ch: p.ch });
      });
      devs = devs.filter(function (x) { return x.a >= ADDR_LO && x.a <= ADDR_HI; });
      devs.forEach(function (x, i) {
        for (var j = 0; j < i; j++) {
          var y = devs[j];
          if (x.a !== y.a) continue;
          // A hub's own address is on the root segment, which every channel
          // sees; two channels never see each other.
          if (x.hub !== null && y.hub !== null && (x.hub !== y.hub || x.ch !== y.ch)) continue;
          add("error", "E_ADDR_CLASH", x.w + ".addr", x.w.split(".")[1] + " answers " + hex(x.a) +
              ", like " + y.w.split(".")[1] + " on the same segment.");
          break;
        }
      });
    });

    if (!npub.n) add("error", "E_NO_SENSOR", "", "No sensor publishes anything: the board would send no readings.");
    return sortFindings(out, doc);
  }

  /* E_SCHEMA findings as [where, message]; empty when the shape is right. */
  function schemaFindings(doc) {
    var out = [];
    function bad(where, msg) { out.push([where, msg]); }
    if (!isObj(doc)) { bad("", "The wiring is not a JSON object."); return out; }
    if (doc.version !== 1) bad("", "Wiring version must be 1.");
    var extra = Object.keys(doc).filter(function (k) { return TOP_KEYS.indexOf(k) < 0; }).sort();
    if (extra.length) bad("", "Unknown key(s) in the wiring: " + extra.join(", ") + ".");
    var board = doc.board;
    if (!isObj(board)) {
      bad("board", "The wiring names no board.");
    } else {
      extra = Object.keys(board).filter(function (k) { return BOARD_KEYS.indexOf(k) < 0; }).sort();
      if (extra.length) bad("board", "Unknown key(s) in the board: " + extra.join(", ") + ".");
      if (typeof board.variant !== "string" || !board.variant) bad("board", "The board has no chip variant.");
      if (has(board, "part") && board.part !== null && typeof board.part !== "string")
        bad("board", "The board part must be text.");
    }
    if (has(doc, "layout") && !isObj(doc.layout)) bad("", "layout must be an object.");
    var seen = {};
    ["buses", "hubs", "sensors"].forEach(function (section) {
      var items = has(doc, section) ? doc[section] : [];
      if (items === null) items = [];
      if (!Array.isArray(items)) { bad("", section + " must be a list."); return; }
      items.forEach(function (o, i) {
        var where = pathOf(section, o, i);
        if (!isObj(o)) { bad(where, "Each entry in " + section + " must be an object."); return; }
        var oid = o.id;
        if (typeof oid !== "string" || !ID_RX.test(oid) || oid === "board")
          bad(where, JSON.stringify(oid === undefined ? null : oid) + " is not a usable id: a lower-case letter, " +
              "then up to 23 letters, digits or _ (\"board\" is taken).");
        else if (has(seen, oid)) bad(where, "The id " + oid + " is used twice.");
        else seen[oid] = true;
        ({ buses: schemaBus, hubs: schemaHub, sensors: schemaSensor })[section](o, where, bad);
      });
    });
    return out;
  }
  function extraKeys(o, keys) {
    return Object.keys(o).filter(function (k) { return keys.indexOf(k) < 0; }).sort();
  }
  function schemaBus(b, where, bad) {
    var kind = b.kind;
    if (typeof kind !== "string" || !kind) { bad(where, "The bus has no kind."); return; }
    var keys = has(BUS_KEYS, kind) ? BUS_KEYS[kind] : null;
    if (!keys) return;            // an unknown kind is E_BUS_KIND, said in words later
    var extra = extraKeys(b, keys);
    if (extra.length) bad(where, "Unknown key(s) on a " + kind + " bus: " + extra.join(", ") + ".");
    if (kind === "i2c") {
      ["sda", "scl"].forEach(function (f) {
        if (!isInt(b[f])) bad(where, "The bus needs its " + f.toUpperCase() + " GPIO as a whole number.");
      });
      if (has(b, "freq") && !isInt(b.freq)) bad(where, "The bus frequency must be a whole number of Hz.");
      if (has(b, "impl") && IMPLS.indexOf(b.impl) < 0) bad(where, "impl must be one of: " + IMPLS.join(", ") + ".");
      if (has(b, "pullups") && PULLUPS.indexOf(b.pullups) < 0)
        bad(where, "pullups must be one of: " + PULLUPS.join(", ") + ".");
    } else {
      ["uart", "tx", "rx", "de", "baud"].forEach(function (f) {
        if (has(b, f) && !isInt(b[f])) bad(where, f + " must be a whole number.");
      });
      if (has(b, "termination") && typeof b.termination !== "boolean") bad(where, "termination must be true or false.");
    }
  }
  function schemaHub(x, where, bad) {
    if (typeof x.kind !== "string" || !x.kind) bad(where, "The hub has no kind.");
    if (typeof x.bus !== "string" || !x.bus) bad(where, "The hub is not wired to a bus: drag a wire from the board to it.");
    if (!isInt(x.addr)) bad(where, "The hub needs its I2C address as a whole number.");
    var extra = extraKeys(x, HUB_KEYS);
    if (extra.length) bad(where, "Unknown key(s) on a hub: " + extra.join(", ") + ".");
  }
  function schemaSensor(s, where, bad) {
    if (typeof s.driver !== "string" || !s.driver) bad(where, "The sensor names no driver.");
    ["bus", "hub"].forEach(function (f) {
      if (has(s, f) && s[f] !== null && typeof s[f] !== "string") bad(where, f + " must be an id or null.");
    });
    if (!isInt(s.addr)) bad(where, "The sensor needs its address as a whole number.");
    if (has(s, "params") && !isObj(s.params)) bad(where, "params must be an object.");
    if (!has(s, "tags")) bad(where, "The sensor has no tags list.");
    var extra = extraKeys(s, SENSOR_KEYS);
    if (extra.length) bad(where, "Unknown key(s) on a sensor: " + extra.join(", ") + ".");
  }

  function addrCheck(add, where, addr, options, name) {
    if (!(addr >= ADDR_LO && addr <= ADDR_HI))
      add("error", "E_ADDR_RANGE", where + ".addr", (addr >= 0 ? hex(addr) : addr) +
          " is not a usable I2C address (" + hex(ADDR_LO) + "-" + hex(ADDR_HI) + ").");
    else if (options && options.length && options.indexOf(addr) < 0)
      add("error", "E_ADDR_OPTION", where + ".addr", name + " answers only " +
          options.map(hex).join(" or ") + ", not " + hex(addr) + ".");
  }
  function power(add, where, part, name) {
    var rails = ((part.power || {}).rails) || [];
    if (rails.length && rails.indexOf("3V3") < 0)
      add("warn", "W_POWER", where, "Power " + name + " from " + rails.join(" or ") + ", not from the board's 3V3.");
  }
  /* E_TAG / E_TAG_DUP / W_TAG_OFF for one sensor; counts what it publishes.
     Two sensors may publish one tag (each reading goes to <tag>/<sensor id>);
     one sensor publishing two of its quantities on one tag is E_TAG_DUP. */
  function tagChecks(add, where, tags, d, published, npub) {
    var tw = where + ".tags";
    var ok = Array.isArray(tags) && tags.every(function (t) {
      return isObj(t) && Object.keys(t).length === 2 && has(t, "q") && has(t, "tag") &&
             typeof t.q === "string" && (t.tag === null || typeof t.tag === "string");
    });
    if (!ok) { add("error", "E_TAG", tw, "tags must be a list of {q, tag}, tag being a name or null."); return; }
    var qs = d ? (d.quantities || []).map(function (q) { return q.q; }) : null, seen = {}, mine = {};
    tags.forEach(function (t) {
      var q = t.q, name = t.tag, qw = tw + "." + q;
      if (qs && qs.indexOf(q) < 0) { add("error", "E_TAG", qw, d.name + " does not measure " + q + "."); return; }
      if (has(seen, q)) { add("error", "E_TAG", qw, q + " is listed twice."); return; }
      seen[q] = true;
      if (name === null) return;
      if (!TAG_RX.test(name)) {
        add("error", "E_TAG", qw, JSON.stringify(name) + " is not a tag name: a lower-case letter, then up to 47 " +
            "letters, digits or _.");
        return;
      }
      if (has(mine, name)) {
        add("error", "E_TAG_DUP", qw, where.split(".").slice(1).join(".") + " already publishes " +
            mine[name] + " as " + name + ": one sensor cannot publish two readings on one tag.");
        return;
      }
      mine[name] = q;
      if (!has(published, name)) published[name] = where.split(".").slice(1).join(".");
      npub.n += 1;
    });
    (qs || []).forEach(function (q) {
      if (!has(seen, q)) add("error", "E_TAG", tw + "." + q, q + " is not listed: give it a tag name, or null to switch it off.");
    });
    if (tags.length && tags.every(function (t) { return t.tag === null; }))
      add("warn", "W_TAG_OFF", where, "Every reading of " + where.split(".").slice(1).join(".") +
          " is switched off: it is wired but publishes nothing.");
  }

  function pathOf(section, o, i) {
    var oid = isObj(o) ? o.id : undefined;
    return section + "." + (typeof oid === "string" && oid ? oid : String(i));
  }
  /* Document order of `where` (cosmetic: the tests compare sets), keeping the
     order the checks walk an object's fields. */
  function sortFindings(out, doc) {
    var order = { "": 0, board: 1 }, n = 2;
    if (isObj(doc)) ["buses", "hubs", "sensors"].forEach(function (sec) {
      if (Array.isArray(doc[sec])) doc[sec].forEach(function (o, i) {
        var k = pathOf(sec, o, i);
        if (!has(order, k)) order[k] = n++;
      });
    });
    return out.map(function (f, i) {
      var head = f.where.split(".").slice(0, 2).join(".");
      return { f: f, k: has(order, head) ? order[head] : n, i: i };
    }).sort(function (a, b) { return a.k - b.k || a.i - b.i; }).map(function (x) { return x.f; });
  }

  /* Drawflow's export (or its live data) -> the wiring document.

     nodeData maps a Drawflow node id to what that node is, and wins over the
     data stored in the export:
       {kind: "board",  board: {variant, part}, buses: [bus...]}  output_k = buses[k-1]
       {kind: "hub",    hub: {id, kind, addr}}                    input_1 = up, output_k = channel k-1
       {kind: "sensor", sensor: {id, driver, addr, params, tags}} input_1
     Which bus and channel something is on comes only from the wires. */
  function fromDrawflow(exportJson, nodeData) {
    var data = (((exportJson || {}).drawflow || {}).Home || {}).data || {};
    nodeData = nodeData || {};
    var ids = Object.keys(data).sort(function (a, b) { return Number(a) - Number(b); });
    function info(id) { return nodeData[id] || (data[id] && data[id].data) || {}; }
    function upstream(id) {
      var n = data[id], c = n && n.inputs && n.inputs.input_1 && n.inputs.input_1.connections;
      if (!c || !c.length) return null;
      var k = Number(String(c[0].input || "").replace("output_", ""));
      return { node: String(c[0].node), k: k };
    }
    var doc = { version: 1, board: null, buses: [], hubs: [], sensors: [], layout: {} };
    var boardId = null, boardBuses = [];
    ids.forEach(function (id) {
      var d = info(id);
      if (d.kind === "board" && boardId === null) {
        boardId = id;
        doc.board = copy(d.board || {});
        boardBuses = (d.buses || []).map(copy);
        doc.buses = boardBuses;
      }
    });
    function busOf(k) { var b = boardBuses[k - 1]; return b ? b.id : null; }
    function pos(id, key) {
      var n = data[id];
      if (n && isFinite(n.pos_x) && isFinite(n.pos_y)) doc.layout[key] = [Math.round(n.pos_x), Math.round(n.pos_y)];
    }
    if (boardId !== null) pos(boardId, "board");
    var hubOfNode = {};
    ids.forEach(function (id) {
      var d = info(id);
      if (d.kind !== "hub") return;
      var x = d.hub || {}, up = upstream(id);
      var h = { id: x.id, kind: x.kind, bus: up && info(up.node).kind === "board" ? busOf(up.k) : null,
                addr: x.addr };
      hubOfNode[id] = h;
      doc.hubs.push(h);
      pos(id, h.id);
    });
    ids.forEach(function (id) {
      var d = info(id);
      if (d.kind !== "sensor") return;
      var s = copy(d.sensor || {}), up = upstream(id), src = up ? info(up.node) : {};
      var out = { id: s.id, driver: s.driver, bus: null, hub: null, channel: null, addr: s.addr,
                  params: s.params || {}, tags: s.tags || [] };
      if (up && src.kind === "board") {
        out.bus = busOf(up.k);
      } else if (up && src.kind === "hub" && hubOfNode[up.node]) {
        out.bus = hubOfNode[up.node].bus;
        out.hub = hubOfNode[up.node].id;
        out.channel = up.k - 1;
      }
      doc.sensors.push(out);
      pos(id, s.id);
    });
    return doc;
  }
  function copy(x) { return x === undefined ? undefined : JSON.parse(JSON.stringify(x)); }

  /* The wiring document -> a Drawflow-shaped graph: board first, then hubs,
     then sensors, each at its layout position or in a three-column layout.
     Node html is left empty: the screen draws its own. */
  function toDrawflow(doc, spec) {
    doc = isObj(doc) ? doc : {};
    var layout = isObj(doc.layout) ? doc.layout : {};
    var data = {}, n = 0;
    var COL = [40, 400, 760], ROW = [0, 0, 0], STEP = [0, 250, 190];
    function node(kind, key, d, ins, outs, col) {
      n += 1;
      var id = String(n), at = layout[key];
      var x, y;
      if (Array.isArray(at) && isFinite(at[0]) && isFinite(at[1])) { x = at[0]; y = at[1]; }
      else { x = COL[col]; y = 30 + ROW[col]; ROW[col] += STEP[col] || 200; }
      var inputs = {}, outputs = {}, i;
      for (i = 1; i <= ins; i++) inputs["input_" + i] = { connections: [] };
      for (i = 1; i <= outs; i++) outputs["output_" + i] = { connections: [] };
      data[id] = { id: Number(id), name: kind, data: d, class: "wr-" + kind, html: "",
                   typenode: false, inputs: inputs, outputs: outputs, pos_x: x, pos_y: y };
      return id;
    }
    function link(from, k, to) {
      data[from].outputs["output_" + k].connections.push({ node: to, output: "input_1" });
      data[to].inputs.input_1.connections.push({ node: from, input: "output_" + k });
    }
    var buses = Array.isArray(doc.buses) ? doc.buses.filter(isObj).map(copy) : [];
    var boardId = node("board", "board", { kind: "board", board: copy(isObj(doc.board) ? doc.board : {}), buses: buses },
                       0, Math.max(buses.length, 1), 0);
    var busK = {};
    buses.forEach(function (b, i) { busK[b.id] = i + 1; });
    var hubNode = {}, hubDefs = {};
    ((spec || {}).hubs || []).forEach(function (h) { if (h && h.id) hubDefs[h.id] = h; });
    (Array.isArray(doc.hubs) ? doc.hubs : []).filter(isObj).forEach(function (h) {
      var nch = (hubDefs[h.kind] && hubDefs[h.kind].channels) || 8;
      var id = node("hub", h.id, { kind: "hub", hub: { id: h.id, kind: h.kind, addr: h.addr } }, 1, nch, 1);
      hubNode[h.id] = id;
      if (busK[h.bus]) link(boardId, busK[h.bus], id);
    });
    (Array.isArray(doc.sensors) ? doc.sensors : []).filter(isObj).forEach(function (s) {
      var id = node("sensor", s.id, { kind: "sensor", sensor: { id: s.id, driver: s.driver, addr: s.addr,
                    params: copy(s.params || {}), tags: copy(s.tags || []) } }, 1, 0, 2);
      if (s.hub != null && hubNode[s.hub] && isInt(s.channel) && data[hubNode[s.hub]].outputs["output_" + (s.channel + 1)])
        link(hubNode[s.hub], s.channel + 1, id);
      else if (s.hub == null && busK[s.bus]) link(boardId, busK[s.bus], id);
    });
    return { drawflow: { Home: { data: data } } };
  }

  var logic = { validate: validate, fromDrawflow: fromDrawflow, toDrawflow: toDrawflow,
                pinTable: pinTable, hex: hex, SLUG_RX: SLUG_RX, TAG_RX: TAG_RX };
  if (typeof module !== "undefined" && module.exports) module.exports = logic;
  /* wiring-logic:end */

  if (typeof document === "undefined") { root.Wiring = { logic: logic }; return; }

  /* ---------------------------------------------------------------- screen --- */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function opt(sel, value, label, selected, disabled) {
    var o = h("option", null, label);
    o.value = String(value);
    if (selected) o.selected = true;
    if (disabled) o.disabled = true;
    sel.appendChild(o);
    return o;
  }
  function field(label, control, note) {
    var w = h("label", "wr-field");
    w.appendChild(h("span", "wr-flabel", label));
    w.appendChild(control);
    if (note) w.appendChild(h("span", "wr-note", note));
    return w;
  }

  function mount(opts) {
    var el = opts.el, spec = opts.spec || {}, onchange = opts.onchange || function () {};
    var parts = (opts.parts && opts.parts.parts) || opts.parts || {};
    var drivers = {}, hubDefs = {};
    (spec.drivers || []).forEach(function (d) { if (d && d.id && d.bus) drivers[d.id] = d; });
    (spec.hubs || []).forEach(function (x) { if (x && x.id) hubDefs[x.id] = x; });
    var variant = spec.variant || "";
    var findings = [], saveProblem = null;

    el.innerHTML = "";
    var wr = h("div", "wr");
    el.appendChild(wr);

    // Without Drawflow the screen is a JSON box checked by the same rules: the
    // run can still go on, and nobody is left with a blank card.
    if (typeof root.Drawflow !== "function") return mountFallback(wr);

    /* ---- top bar: variant, start-from, palette */
    var bar = h("div", "wr-bar");
    var vsel = h("select", "wr-vsel");
    (spec.variants || [{ id: variant, label: variant }]).forEach(function (x) {
      // Only a variant whose pin table travelled with the spec can be checked here.
      opt(vsel, x.id, x.label || x.id, x.id === variant, !pinTable(spec, x.id));
    });
    bar.appendChild(field("Board chip", vsel));
    var tsel = h("select", "wr-tsel");
    opt(tsel, "", "— keep the current drawing —", true);
    opt(tsel, "#blank", "An empty board");
    (spec.templates || []).forEach(function (t, i) {
      opt(tsel, String(i), (t.title || t.slug) + (t.source === "saved" ? " (saved)" : "") +
          (t.valid === false ? " — " + (t.first_error || "has errors") : ""));
    });
    bar.appendChild(field("Start from", tsel));
    wr.appendChild(bar);

    var pal = h("div", "wr-palette");
    pal.appendChild(h("span", "wr-pallabel", "Add"));
    Object.keys(drivers).forEach(function (id) {
      var b = h("button", null, "+ " + (drivers[id].name || id));
      b.type = "button";
      b.title = drivers[id].subtitle || "";
      b.onclick = function () { addSensor(id); };
      pal.appendChild(b);
    });
    Object.keys(hubDefs).forEach(function (id) {
      var b = h("button", null, "+ " + (hubDefs[id].name || id));
      b.type = "button";
      b.onclick = function () { addHub(id); };
      pal.appendChild(b);
    });
    var addBusBtn = h("button", null, "+ I2C bus");
    addBusBtn.type = "button";
    addBusBtn.onclick = function () { addBus(); };
    pal.appendChild(addBusBtn);
    wr.appendChild(pal);

    var body = h("div", "wr-body");
    var canvas = h("div", "wr-canvas");
    var side = h("div", "wr-side");
    body.appendChild(canvas); body.appendChild(side);
    wr.appendChild(body);
    var notice = h("p", "wr-notice");
    notice.hidden = true;
    wr.appendChild(notice);
    var fl = h("ul", "wr-findings");
    wr.appendChild(fl);

    /* ---- save as a board template */
    var fs = h("fieldset", "wr-save");
    var lg = h("legend");
    var saveOn = h("input"); saveOn.type = "checkbox";
    lg.appendChild(saveOn); lg.appendChild(document.createTextNode(" Save as a board template"));
    fs.appendChild(lg);
    var sgrid = h("div", "wr-savegrid");
    var slug = h("input"); slug.type = "text"; slug.placeholder = "sense-hub-two-sht45"; slug.maxLength = 41;
    var title = h("input"); title.type = "text"; title.maxLength = 120;
    var desc = h("input"); desc.type = "text"; desc.maxLength = 400;
    var repl = h("input"); repl.type = "checkbox";
    sgrid.appendChild(field("Name (slug)", slug, "a-z, 0-9 and -"));
    sgrid.appendChild(field("Title", title));
    sgrid.appendChild(field("Description", desc));
    var rl = h("label", "wr-check"); rl.appendChild(repl);
    rl.appendChild(document.createTextNode(" Replace a saved template of that name"));
    sgrid.appendChild(rl);
    fs.appendChild(sgrid);
    wr.appendChild(fs);
    sgrid.hidden = true;
    saveOn.onchange = function () { sgrid.hidden = !saveOn.checked; refresh(); };
    [slug, title, desc].forEach(function (i) { i.oninput = function () { refresh(); }; });
    repl.onchange = function () { refresh(); };

    /* ---- Drawflow */
    var ed = new root.Drawflow(canvas);
    ed.reroute = false;
    ed.curvature = 0.35;
    ed.start();
    var model = {};          // drawflow id -> node data (what the node IS)
    var boardDf = null, allowRemove = false, selected = null;
    var origRemove = ed.removeNodeId.bind(ed);
    // The board is the root of every wire: the Delete key may not take it.
    ed.removeNodeId = function (nid) {
      if (String(nid) === "node-" + boardDf && !allowRemove) return;
      origRemove(nid);
    };
    function live() { return { drawflow: ed.drawflow.drawflow }; }
    function nodeEl(id) { return canvas.querySelector("#node-" + id); }

    function partOf(d) {
      var name = d.kind === "board" ? (d.board || {}).part
               : d.kind === "hub" ? (hubDefs[(d.hub || {}).kind] || {}).part
               : (drivers[(d.sensor || {}).driver] || {}).part;
      return name && parts[name] ? parts[name] : null;
    }
    function titleOf(d) {
      if (d.kind === "board") {
        var b = (spec.boards || []).filter(function (x) { return x.part === (d.board || {}).part; })[0];
        return (b && b.name) || "ESP32 board";
      }
      if (d.kind === "hub") return (hubDefs[d.hub.kind] || {}).name || d.hub.kind;
      return (drivers[d.sensor.driver] || {}).name || d.sensor.driver;
    }
    function nodeHtml(d) {
      var p = partOf(d), pic;
      if (p && p.svg) {
        var sz = (p.meta && p.meta.size) || [], ar = Number(sz[0]) > 0 && Number(sz[1]) > 0
          ? ' style="aspect-ratio:' + Number(sz[0]) + "/" + Number(sz[1]) + '"' : "";
        pic = '<div class="wr-pic"' + ar + '><img alt="' + esc(titleOf(d)) + '" draggable="false" src="' +
              esc("data:image/svg+xml;utf8," + encodeURIComponent(p.svg)) + '"></div>';
      } else {
        pic = '<div class="wr-box">' + esc(titleOf(d)) + "</div>";
      }
      var kind = d.kind === "board" ? "Board" : d.kind === "hub" ? "Hub" : "Sensor";
      return '<div class="wr-nh"><span class="wr-nk">' + esc(kind) + "</span>" + esc(titleOf(d)) + "</div>" +
             pic + '<div class="wr-nf"></div>';
    }
    function busLabel(b) {
      return "I2C " + b.id + " · SDA " + b.sda + " / SCL " + b.scl;
    }
    function labelPorts(id) {
      var d = model[id], e = nodeEl(id);
      if (!d || !e) return;
      function lab(sel, text) {
        var p = e.querySelector(sel);
        if (p) { p.setAttribute("data-label", text); p.title = text; }
      }
      if (d.kind === "board") d.buses.forEach(function (b, i) { lab(".outputs .output_" + (i + 1), busLabel(b)); });
      if (d.kind === "hub") {
        lab(".inputs .input_1", "up");
        var n = (hubDefs[d.hub.kind] || {}).channels || 8;
        for (var c = 0; c < n; c++) lab(".outputs .output_" + (c + 1), "ch" + c);
      }
      if (d.kind === "sensor") lab(".inputs .input_1", String(((drivers[d.sensor.driver] || {}).bus || {}).kind || "i2c").toUpperCase());
      var f = e.querySelector(".wr-nf");
      if (f) f.textContent = d.kind === "board" ? (d.board.variant || "")
        : d.kind === "hub" ? d.hub.id + " · " + (isInt(d.hub.addr) ? hex(d.hub.addr) : "?")
        : d.sensor.id + " · " + (isInt(d.sensor.addr) ? hex(d.sensor.addr) : "?");
    }

    /* Which pads of the picture a port stands for. */
    function padsFor(id, cls) {
      var d = model[id], fns = [];
      if (!d) return fns;
      var k = Number(String(cls).replace(/^(in|out)put_/, ""));
      if (d.kind === "board") {
        var b = d.buses[k - 1];
        if (b) fns = ["GPIO" + b.sda, "GPIO" + b.scl];
      } else if (/^output_/.test(cls)) {
        fns = ["SD" + (k - 1), "SC" + (k - 1)];
      } else {
        fns = ["SDA", "SCL", "VIN", "VCC", "3V3", "GND"];
      }
      return fns;
    }
    function showPads(id, cls) {
      var e = nodeEl(id), p = model[id] && partOf(model[id]);
      if (!e || !p || !p.meta) return;
      var pic = e.querySelector(".wr-pic");
      if (!pic) return;
      var fmap = p.meta.functions || {}, conns = p.meta.connectors || {}, lower = {};
      Object.keys(fmap).forEach(function (k) { lower[k.toLowerCase()] = fmap[k]; });
      padsFor(id, cls).forEach(function (fn) {
        (fmap[fn] || lower[fn.toLowerCase()] || []).forEach(function (cn) {
          var c = conns[cn];
          if (!c || !isFinite(c.fx) || !isFinite(c.fy)) return;
          var dot = h("span", "wr-pad");
          dot.style.left = (Number(c.fx) * 100) + "%";
          dot.style.top = (Number(c.fy) * 100) + "%";
          dot.title = fn;
          pic.appendChild(dot);
        });
      });
    }
    function hidePads() {
      [].slice.call(canvas.querySelectorAll(".wr-pad")).forEach(function (x) { x.remove(); });
    }
    canvas.addEventListener("mouseover", function (ev) {
      var port = ev.target.closest && ev.target.closest(".input, .output");
      if (!port) return;
      var ne = port.closest(".drawflow-node");
      if (!ne) return;
      hidePads();
      var cls = [].slice.call(port.classList).filter(function (c) { return /^(in|out)put_\d+$/.test(c); })[0];
      if (cls) showPads(ne.id.slice(5), cls);
    });
    canvas.addEventListener("mouseout", function (ev) {
      if (ev.target.closest && ev.target.closest(".input, .output")) hidePads();
    });

    function addNode(d, ins, outs, x, y) {
      var id = String(ed.addNode(d.kind, ins, outs, x, y, "wr-" + d.kind, {}, nodeHtml(d)));
      model[id] = d;
      labelPorts(id);
      return id;
    }

    /* ---- build from a document */
    function load(doc) {
      allowRemove = true;
      ed.clear();
      allowRemove = false;
      model = {}; boardDf = null; selected = null;
      doc = isObj(doc) ? copy(doc) : {};
      if (!isObj(doc.board) || typeof doc.board.variant !== "string") doc.board = { variant: variant };
      if (!doc.board.part) {
        var bd = (spec.boards || []).filter(function (b) { return (b.variants || []).indexOf(doc.board.variant) >= 0; })[0];
        if (bd) doc.board.part = bd.part;
      }
      if (!Array.isArray(doc.buses) || !doc.buses.length) doc.buses = [newBus(doc.board.part, [])];
      if (pinTable(spec, doc.board.variant)) variant = doc.board.variant;
      vsel.value = variant;
      doc.board.variant = variant;
      var g = toDrawflow(doc, spec).drawflow.Home.data, map = {};
      Object.keys(g).sort(function (a, b) { return a - b; }).forEach(function (k) {
        var n = g[k];
        var id = addNode(n.data, Object.keys(n.inputs).length, Object.keys(n.outputs).length, n.pos_x, n.pos_y);
        map[k] = id;
        if (n.data.kind === "board") boardDf = id;
      });
      Object.keys(g).forEach(function (k) {
        var outs = g[k].outputs;
        Object.keys(outs).forEach(function (oc) {
          outs[oc].connections.forEach(function (c) {
            ed.addConnection(map[k], map[c.node], oc, c.output);
          });
        });
      });
      renderSide();
      refresh();
    }

    function freeId(prefix) {
      var used = {};
      Object.keys(model).forEach(function (k) {
        var d = model[k];
        if (d.kind === "hub") used[d.hub.id] = 1;
        if (d.kind === "sensor") used[d.sensor.id] = 1;
        if (d.kind === "board") d.buses.forEach(function (b) { used[b.id] = 1; });
      });
      prefix = String(prefix).toLowerCase().replace(/[^a-z0-9_]/g, "_").replace(/^[^a-z]+/, "") || "s";
      prefix = prefix.slice(0, 20);
      for (var i = prefix === "mux" || prefix === "i2c" ? 0 : 1; ; i++)
        if (!used[prefix + i] && !used[prefix + "_" + i]) return prefix === "mux" || prefix === "i2c" ? prefix + i : prefix + "_" + i;
    }
    function busPins() {
      var used = {};
      if (boardDf && model[boardDf]) model[boardDf].buses.forEach(function (b) { used[b.sda] = used[b.scl] = 1; });
      return used;
    }
    function freePins(except) {
      var t = pinTable(spec, variant) || {}, used = busPins(), out = [];
      (t.ranges || []).forEach(function (r) {
        for (var p = r[0]; p <= r[1]; p++) {
          var lv = "";
          (t.groups || []).forEach(function (g) {
            if ((g.pins || []).indexOf(p) >= 0 && g.level === "error") lv = "error";
            else if ((g.pins || []).indexOf(p) >= 0 && g.level === "warn" && lv !== "error") lv = "warn";
          });
          if (lv !== "error" && (!used[p] || except.indexOf(p) >= 0)) out.push({ pin: p, level: lv });
        }
      });
      return out;
    }
    function newBus(part, taken) {
      var bd = (spec.boards || []).filter(function (b) { return b.part === part; })[0];
      var dflt = (bd && bd.i2c_defaults) || {}, sda = dflt.sda, scl = dflt.scl;
      var fp = freePins([]).filter(function (x) { return !x.level; }).map(function (x) { return x.pin; });
      if (taken.indexOf(sda) >= 0 || !isInt(sda)) sda = fp[0];
      if (taken.indexOf(scl) >= 0 || !isInt(scl) || scl === sda) scl = fp.filter(function (p) { return p !== sda; })[0];
      return { id: boardDf ? freeId("i2c") : "i2c0", kind: "i2c", sda: sda, scl: scl,
               freq: 100000, impl: "soft", pullups: "external" };
    }
    function column(kind) {
      var ys = Object.keys(model).filter(function (k) { return model[k].kind === kind; }).map(function (k) {
        var n = ed.drawflow.drawflow.Home.data[k];
        return n ? n.pos_y + (nodeEl(k) ? nodeEl(k).offsetHeight : 180) : 0;
      });
      return ys.length ? Math.max.apply(null, ys) + 30 : 30;
    }
    function addSensor(drv) {
      var d = drivers[drv];
      // A new instance publishes its driver's default tags, except any its
      // driver switches off by default (none ships since Q13: the SCD30's T/RH
      // are on). Two sensors on one tag are told apart by their instance, the
      // last segment of the reading topic.
      var off = d.default_off || [];
      var tags = (d.quantities || []).map(function (q) {
        var on = q.tag && off.indexOf(q.q) < 0;
        return { q: q.q, tag: on ? q.tag : null };
      });
      var id = addNode({ kind: "sensor", sensor: { id: freeId(drv), driver: drv,
                         addr: d.bus.default_addr != null ? d.bus.default_addr : (d.bus.addrs || [])[0],
                         params: defaultParams(d), tags: tags } }, 1, 0, 760, column("sensor"));
      select(id);
      refresh();
    }
    function defaultParams(d) {
      var p = {};
      (d.params || []).forEach(function (x) {
        if (x && x.name && !x.legacy_bus && x.kind !== "pin" && x.default !== undefined) p[x.name] = x.default;
      });
      return p;
    }
    function addHub(kind) {
      var x = hubDefs[kind], taken = {};
      Object.keys(model).forEach(function (k) { if (model[k].kind === "hub") taken[model[k].hub.addr] = 1; });
      // Two hubs on one bus must answer different addresses (A0-A2 jumpers).
      var addrs = [x.default_addr].concat(x.addrs || []).filter(function (a) { return isInt(a) && !taken[a]; });
      var id = addNode({ kind: "hub", hub: { id: freeId("mux"), kind: kind,
                         addr: addrs.length ? addrs[0] : x.default_addr } },
                       1, x.channels || 8, 400, column("hub"));
      select(id);
      refresh();
    }
    function addBus() {
      var d = model[boardDf], taken = [];
      d.buses.forEach(function (b) { taken.push(b.sda, b.scl); });
      d.buses.push(newBus(d.board.part, taken));
      ed.addNodeOutput(boardDf);
      labelPorts(boardDf);
      select(boardDf);
      refresh();
    }

    /* ---- wires: refuse what cannot be built, and say why */
    function say(msg) {
      notice.textContent = msg;
      notice.hidden = !msg;
    }
    ed.on("connectionCreated", function (c) {
      var src = model[c.output_id], dst = model[c.input_id], why = null;
      var inp = ed.drawflow.drawflow.Home.data[c.input_id].inputs[c.input_class].connections;
      if (!src || !dst) why = "That wire joins nothing this screen knows.";
      else if (inp.length > 1) why = "That input already has a wire. Remove it first (click it, then Delete).";
      else if (dst.kind === "hub" && src.kind === "hub") why = "A hub cannot hang off another hub's channel: wire it to a board bus.";
      else if (dst.kind === "hub" && src.kind === "board" &&
               (src.buses[Number(c.output_class.slice(7)) - 1] || {}).kind !== "i2c")
        why = "A hub only hangs off an I2C bus.";
      else if (dst.kind === "sensor") {
        var want = String(((drivers[dst.sensor.driver] || {}).bus || {}).kind || "i2c");
        var have = src.kind === "hub" ? "i2c" : (src.buses[Number(c.output_class.slice(7)) - 1] || {}).kind;
        if (want !== have) why = titleOf(dst) + " talks " + want.toUpperCase() + ", not " + String(have).toUpperCase() + ".";
      }
      if (why) {
        ed.removeSingleConnection(c.output_id, c.input_id, c.output_class, c.input_class);
        say(why);
      } else {
        say("");
      }
      refresh();
    });
    ed.on("connectionRemoved", function () { refresh(); });
    ed.on("nodeMoved", function () { onchange(ctl); });
    ed.on("nodeRemoved", function (id) {
      delete model[String(id)];
      if (selected === String(id)) selected = null;
      renderSide();
      refresh();
    });
    ed.on("nodeSelected", function (id) { selected = String(id); renderSide(); });
    ed.on("nodeUnselected", function () { selected = null; renderSide(); });

    function select(id) { selected = String(id); renderSide(); }

    /* ---- side panel: what the selected node is, or the board's buses */
    function renderSide() {
      side.innerHTML = "";
      var id = selected && model[selected] ? selected : boardDf, d = model[id];
      if (!d) return;
      side.appendChild(h("h3", null, titleOf(d)));
      if (d.kind === "board") return boardPanel(d);
      if (d.kind === "hub") hubPanel(id, d);
      else sensorPanel(id, d);
      var rm = h("button", "wr-remove", "Remove from the board");
      rm.type = "button";
      rm.onclick = function () { ed.removeNodeId("node-" + id); };
      side.appendChild(rm);
    }
    function addrSelect(cur, addrs, onpick) {
      var s = h("select");
      var list = (addrs || []).slice();
      if (isInt(cur) && list.indexOf(cur) < 0) list.unshift(cur);
      list.forEach(function (a) { opt(s, a, hex(a) + " (" + a + ")", a === cur); });
      s.onchange = function () { onpick(Number(s.value)); };
      return s;
    }
    function boardPanel(d) {
      side.appendChild(h("p", "wr-note", "Chip " + d.board.variant + ". Each bus is one output on the board; " +
                         "drag from it to a hub's “up” or to a sensor."));
      d.buses.forEach(function (b, i) {
        var box = h("div", "wr-bus");
        box.appendChild(h("h4", null, "I2C " + b.id));
        ["sda", "scl"].forEach(function (f) {
          var s = h("select"), mine = [b.sda, b.scl];
          var list = freePins(mine);
          if (!list.some(function (x) { return x.pin === b[f]; })) list.unshift({ pin: b[f], level: "error" });
          list.forEach(function (x) {
            opt(s, x.pin, "GPIO" + x.pin + (x.level === "warn" ? " (caution)" : x.level === "error" ? " (not usable)" : ""), x.pin === b[f]);
          });
          s.onchange = function () { b[f] = Number(s.value); labelPorts(boardDf); renderSide(); refresh(); };
          box.appendChild(field(f.toUpperCase(), s));
        });
        var fq = h("select");
        [10000, 50000, 100000, 400000, 1000000].concat(isInt(b.freq) && [10000, 50000, 100000, 400000, 1000000].indexOf(b.freq) < 0 ? [b.freq] : [])
          .forEach(function (f) { opt(fq, f, (f / 1000) + " kHz", f === (isInt(b.freq) ? b.freq : 100000)); });
        fq.onchange = function () { b.freq = Number(fq.value); refresh(); };
        box.appendChild(field("Clock", fq));
        var im = h("select");
        opt(im, "soft", "software (SoftI2C)", b.impl !== "hw");
        opt(im, "hw", "hardware I2C", b.impl === "hw");
        im.onchange = function () { b.impl = im.value; refresh(); };
        box.appendChild(field("Driver", im));
        var pu = h("select");
        [["external", "external 2.2 kΩ"], ["internal", "internal (weak)"], ["none", "none"]].forEach(function (x) {
          opt(pu, x[0], x[1], (b.pullups || "external") === x[0]);
        });
        pu.onchange = function () { b.pullups = pu.value; refresh(); };
        box.appendChild(field("Pull-ups", pu));
        if (d.buses.length > 1) {
          var rm = h("button", "wr-remove", "Remove this bus");
          rm.type = "button";
          rm.onclick = function () {
            d.buses.splice(i, 1);
            ed.removeNodeOutput(boardDf, "output_" + (i + 1));
            labelPorts(boardDf); renderSide(); refresh();
          };
          box.appendChild(rm);
        }
        side.appendChild(box);
      });
    }
    function hubPanel(id, d) {
      var x = hubDefs[d.hub.kind] || {};
      side.appendChild(h("p", "wr-note", d.hub.id + ": wire “up” to a board bus, and sensors to its channels."));
      side.appendChild(field("Address", addrSelect(d.hub.addr, x.addrs, function (a) {
        d.hub.addr = a; labelPorts(id); refresh();
      }), "set by the A0-A2 jumpers"));
    }
    function sensorPanel(id, d) {
      var s = d.sensor, x = drivers[s.driver] || {};
      side.appendChild(h("p", "wr-note", s.id + (x.subtitle ? " — " + x.subtitle : "")));
      side.appendChild(field("Address", addrSelect(s.addr, (x.bus || {}).addrs, function (a) {
        s.addr = a; labelPorts(id); refresh();
      })));
      var tb = h("div", "wr-tags");
      tb.appendChild(h("h4", null, "Published as"));
      (x.quantities || []).forEach(function (q) {
        var t = (s.tags || []).filter(function (y) { return y && y.q === q.q; })[0];
        if (!t) { t = { q: q.q, tag: null }; s.tags.push(t); }
        var row = h("div", "wr-tagrow");
        var on = h("input"); on.type = "checkbox"; on.checked = t.tag !== null;
        var nm = h("input"); nm.type = "text"; nm.value = t.tag || q.tag || ""; nm.disabled = t.tag === null;
        nm.maxLength = 48;
        on.onchange = function () { t.tag = on.checked ? (nm.value || q.tag || q.q) : null; nm.disabled = !on.checked; refresh(); };
        nm.oninput = function () { if (on.checked) { t.tag = nm.value; refresh(); } };
        var lab = h("label", "wr-check"); lab.appendChild(on);
        lab.appendChild(document.createTextNode(" " + q.q + (q.uom ? " (" + q.uom + ")" : "")));
        row.appendChild(lab); row.appendChild(nm);
        tb.appendChild(row);
      });
      side.appendChild(tb);
      (x.params || []).forEach(function (p) {
        if (!p || !p.name || p.legacy_bus || p.kind === "pin") return;
        var cur = (s.params || {})[p.name], c;
        if (p.kind === "choice") {
          c = h("select");
          (p.options || []).forEach(function (o) { opt(c, JSON.stringify(o.value), o.label || o.value, o.value === cur); });
          c.onchange = function () { s.params[p.name] = JSON.parse(c.value); refresh(); };
        } else {
          c = h("input"); c.type = p.kind === "int" ? "number" : "text";
          c.value = cur == null ? "" : String(cur);
          c.oninput = function () {
            s.params[p.name] = p.kind === "int" ? (c.value === "" ? null : Number(c.value)) : c.value;
            refresh();
          };
        }
        side.appendChild(field(p.label || p.name, c, p.hint || ""));
      });
    }

    /* ---- verdict */
    function value() {
      var doc = fromDrawflow(live(), model);
      if (doc.board) doc.board.variant = variant;
      return doc;
    }
    function checkSave() {
      if (!saveOn.checked) return null;
      var sl = slug.value.trim();
      if (!SLUG_RX.test(sl)) return "The template name must be 2-41 characters of a-z, 0-9 and -, starting with a letter.";
      if (!title.value.trim()) return "Give the template a title.";
      var t = (spec.templates || []).filter(function (x) { return x.slug === sl; })[0];
      if (t && t.source !== "saved") return "“" + sl + "” is a template shipped with the platform; choose another name.";
      if (t && !repl.checked) return "A saved template “" + sl + "” exists; tick Replace to overwrite it.";
      return null;
    }
    function refresh() {
      findings = validate(value(), spec, variant);
      saveProblem = checkSave();
      fl.innerHTML = "";
      var shown = findings.slice();
      if (saveProblem) shown.push({ level: "error", code: "SAVE_AS", where: "", message: saveProblem });
      if (!shown.length) fl.appendChild(h("li", "wr-ok", "No problems found."));
      shown.forEach(function (f) {
        var li = h("li", f.level === "error" ? "wr-err" : "wr-warn");
        li.appendChild(h("span", "wr-lvl", f.level === "error" ? "error" : "warning"));
        li.appendChild(h("span", "wr-msg", f.message));
        if (f.where) li.appendChild(h("code", null, f.where));
        fl.appendChild(li);
      });
      onchange(ctl);
    }

    vsel.onchange = function () {
      variant = vsel.value;
      var d = model[boardDf];
      d.board.variant = variant;
      var bd = (spec.boards || []).filter(function (b) { return b.part === d.board.part; })[0];
      if (!bd || (bd.variants || []).indexOf(variant) < 0) {
        var nb = (spec.boards || []).filter(function (b) { return (b.variants || []).indexOf(variant) >= 0; })[0];
        if (nb) d.board.part = nb.part; else delete d.board.part;
      }
      labelPorts(boardDf); renderSide(); refresh();
    };
    tsel.onchange = function () {
      var v = tsel.value;
      tsel.value = "";
      if (v === "") return;
      if (!confirm("Replace the drawing with " + (v === "#blank" ? "an empty board" : "this template") + "?")) return;
      say("");
      load(v === "#blank" ? null : (spec.templates[Number(v)] || {}).wiring);
    };

    var ctl = {
      value: value,
      variant: function () { return variant; },
      findings: function () { return findings.slice(); },
      errors: function () {
        return findings.filter(function (f) { return f.level === "error"; }).length + (saveProblem ? 1 : 0);
      },
      saveAs: function () {
        if (!saveOn.checked || saveProblem) return null;
        return { slug: slug.value.trim(), title: title.value.trim(), description: desc.value.trim(),
                 replace: !!repl.checked };
      }
    };
    load(opts.initial || spec.initial || null);
    return ctl;

    /* ---- no Drawflow: the document as text, checked by the same rules */
    function mountFallback(w) {
      w.appendChild(h("p", "wr-notice", "The wiring screen could not load its drawing library. " +
                      "Edit the wiring as JSON below, or go Back and answer one sensor at a time."));
      var ta = h("textarea", "wr-json");
      ta.rows = 18; ta.spellcheck = false;
      ta.value = JSON.stringify(opts.initial || spec.initial ||
                                { version: 1, board: { variant: variant }, buses: [], hubs: [], sensors: [] }, null, 1);
      w.appendChild(ta);
      var ul = h("ul", "wr-findings");
      w.appendChild(ul);
      var doc = null, parseErr = null;
      function check() {
        try { doc = JSON.parse(ta.value); parseErr = null; } catch (e) { doc = null; parseErr = String(e.message || e); }
        findings = doc ? validate(doc, spec, variant) : [];
        ul.innerHTML = "";
        if (parseErr) ul.appendChild(h("li", "wr-err", "Not JSON: " + parseErr));
        findings.forEach(function (f) {
          ul.appendChild(h("li", f.level === "error" ? "wr-err" : "wr-warn", f.message + (f.where ? " [" + f.where + "]" : "")));
        });
        onchange(fctl);
      }
      var fctl = {
        value: function () { return doc; },
        variant: function () { return isObj(doc) && isObj(doc.board) && doc.board.variant || variant; },
        findings: function () { return findings.slice(); },
        errors: function () { return parseErr ? 1 : findings.filter(function (f) { return f.level === "error"; }).length; },
        saveAs: function () { return null; }
      };
      ta.oninput = check;
      check();
      return fctl;
    }
  }

  root.Wiring = { mount: mount, logic: logic };
})(typeof window !== "undefined" ? window : this);
