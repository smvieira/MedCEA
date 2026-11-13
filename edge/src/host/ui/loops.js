/* The control-loop picker (feedback control Phase 2, owner decision Q20).
 *
 * One row per recipe quantity: whether the zone controls it, on which sensor
 * (the reference, with an optional fallback) or on the mean/min/max of the
 * sensors ticked, how old a reading may be, and which actuator it drives. A tag
 * with one sensor comes preselected; a tag with several stays in error until the
 * person chooses (nothing is preselected), or unticks the quantity.
 *
 * The checks between loops-logic:begin and :end mirror edge/src/host/loops.py's
 * validate() code for code, path for path and word for word
 * (tests/test_loops_ui.py compares them on every fixture in tests/fixtures/loops/).
 * Python is authoritative — flash-device.sh re-checks before the board is
 * touched — and the database's save_zone_loops() is the final judge.
 *
 * Every string reaches the page through textContent, never innerHTML.
 *
 *   Loops.mount({el, spec, onchange}) -> {value, errors, findings, skip}
 *   Loops.logic = {validate, rowFor, stateOf, sends, candidates, QUANTITIES}
 */
(function (root) {
  "use strict";

  /* loops-logic:begin */
  var SPEC_VERSION = 1;
  var QUANTITIES = [
    { loop_code: "air_temperature", label: "Air temperature", tag: "air_temperature",
      recipe_lower: "air_temperature_lower_limit", recipe_upper: "air_temperature_upper_limit",
      actuator: "air_temperature" },
    { loop_code: "air_humidity", label: "Air humidity", tag: "air_humidity",
      recipe_lower: "hr_lower_limit", recipe_upper: "hr_upper_limit",
      actuator: "air_humidity" },
    { loop_code: "co2", label: "CO2", tag: "co2",
      recipe_lower: "co2_lower_limit", recipe_upper: "co2_upper_limit",
      actuator: "co2", command_map: { DOWN: "UP", UP: "OFF", OFF: "OFF" } },
    { loop_code: "substrate_temperature", label: "Substrate temperature", tag: "ground_temperature",
      recipe_lower: "substrate_temperature_lower_limit",
      recipe_upper: "substrate_temperature_upper_limit",
      actuator: "substrate_temperature" }
  ];
  var QMAP = {};
  QUANTITIES.forEach(function (q) { QMAP[q.loop_code] = q; });
  var RULES = ["reference", "mean", "min", "max"];
  var MAX_AGE_MIN = 1, MAX_AGE_MAX = 3600, MAX_AGE_DEFAULT = 90;
  var MAX_LOOPS = 16, STATE_KEY_MAX = 50, RESERVED = "default";
  var ACTUATOR_RX = /^[A-Za-z0-9_]+$/;
  var ANSWER_KEYS = ["skip", "stop_all", "loops"];
  var LOOP_KEYS = ["loop_code", "recipe_lower", "recipe_upper", "input", "output"];
  var INPUT_KEYS = ["tag", "sources", "rule", "reference", "fallback", "max_age_s"];
  var OUTPUT_KEYS = ["actuator", "mode", "command_map"];

  function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function isStr(v) { return typeof v === "string"; }
  function isBool(v) { return v === true || v === false; }

  function sends(q) {
    if (q.command_map) {
      var vals = {};
      Object.keys(q.command_map).forEach(function (k) { vals[q.command_map[k]] = true; });
      return Object.keys(vals).sort();
    }
    return ["DOWN", "OFF", "UP"];
  }
  function candidates(spec, tag) {
    return (spec.sources || []).filter(function (s) { return (s.tags || []).indexOf(tag) >= 0; })
                               .map(function (s) { return s.instance; });
  }
  function findActuator(spec, name) {
    var all = spec.actuators || [];
    for (var i = 0; i < all.length; i++) if (all[i].name === name) return all[i];
    return null;
  }
  function fit(spec, name, q) {
    var a = findActuator(spec, name);
    return a !== null && a.kind === "commands" &&
      sends(q).every(function (c) { return (a.commands || []).indexOf(c) >= 0; });
  }
  function sameMap(a, b) {
    if (!isObj(a) || !isObj(b)) return false;
    var ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
    if (ka.join("\u0000") !== kb.join("\u0000")) return false;
    return ka.every(function (k) { return isStr(a[k]) && a[k] === b[k]; });
  }
  function isWhole(n) { return typeof n === "number" && Number.isInteger(n); }
  function show(v) { return isStr(v) ? v.slice(0, 60) : JSON.stringify(v === undefined ? null : v); }

  function rowFor(spec, code, st) {
    var q = QMAP[code], rule = st.rule || "reference", inp = { tag: q.tag };
    if (rule === "reference") {
      var ref = st.reference, fb = st.fallback;
      inp.sources = [ref, fb].filter(function (x) { return isStr(x) && x !== ""; });
      inp.rule = "reference";
      inp.reference = isStr(ref) && ref !== "" ? ref : null;
      if (isStr(fb) && fb !== "" && fb !== ref) inp.fallback = fb;
    } else {
      var ticked = st.sensors || [];
      inp.sources = candidates(spec, q.tag).filter(function (s) { return ticked.indexOf(s) >= 0; });
      inp.rule = rule;
    }
    inp.max_age_s = has(st, "max_age_s") ? st.max_age_s : MAX_AGE_DEFAULT;
    var out = { actuator: st.actuator || q.actuator, mode: "command" };
    if (q.command_map) out.command_map = JSON.parse(JSON.stringify(q.command_map));
    return { loop_code: code, recipe_lower: q.recipe_lower, recipe_upper: q.recipe_upper, input: inp, output: out };
  }

  function stateOf(row) {
    var inp = isObj(row.input) ? row.input : {}, out = isObj(row.output) ? row.output : {};
    var rule = RULES.indexOf(inp.rule) >= 0 ? inp.rule : "reference";
    var srcs = (Array.isArray(inp.sources) ? inp.sources : []).filter(isStr);
    return { rule: rule,
             reference: rule === "reference" && has(inp, "reference") ? inp.reference : null,
             fallback: rule === "reference" && has(inp, "fallback") ? inp.fallback : null,
             sensors: rule !== "reference" ? srcs : [],
             max_age_s: has(inp, "max_age_s") ? inp.max_age_s : MAX_AGE_DEFAULT,
             actuator: has(out, "actuator") ? out.actuator : null };
  }

  function validate(spec, answer) {
    var out = [];
    function f(level, code, where, message) { out.push({ level: level, code: code, where: where, message: message }); }
    if (!isObj(spec) || spec.version !== SPEC_VERSION) {
      f("error", "L_SCHEMA", "spec.version", "the page and the wizard are of different versions: reload the page");
      return out;
    }
    var zone = spec.zone_code || "";
    (spec.old_boards || []).forEach(function (o) {
      f("warn", "W_OLD_BOARD", "old_boards." + (o.component_id === undefined || o.component_id === null ? "None" : o.component_id),
        (o.dns_name || "a board") + " publishes " + (o.tags || []).join(", ") +
        " without a sensor name (flashed before Phase 1): re-onboard this SENSE board " +
        "so its readings carry the sensor name; until then it is no loop's source");
    });
    (spec.sensor_problems || []).forEach(function (p, i) { f("warn", "W_SENSOR_PROBLEM", "sensor_problems." + i, String(p)); });
    if (!isObj(answer)) {
      f("error", "L_SCHEMA", "answer", "the answer must be a JSON object");
      return out;
    }
    Object.keys(answer).forEach(function (k) {
      if (ANSWER_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", "answer", "unknown key " + k.slice(0, 60));
    });
    var skip = has(answer, "skip") ? answer.skip : false;
    if (!isBool(skip)) { f("error", "L_SCHEMA", "answer.skip", "skip must be true or false"); return out; }
    if (skip) {
      if (Object.keys(answer).filter(function (k) { return k !== "skip"; }).length > 0) {
        f("error", "L_SCHEMA", "answer.skip", "Decide later sends nothing else");
        return out;
      }
      if (!(spec.existing || []).length) {
        (spec.rows || []).forEach(function (r) {
          var c = r.candidates || [];
          if (r.offered && c.length > 1)
            f("warn", "W_DECIDE_LATER", "loops." + r.loop_code,
              r.loop_code + " has " + c.length + " sensors (" + c.join(", ") +
              "): until one is chosen a run gets no data for it and an alarm");
        });
      }
      return out;
    }
    var stopAll = has(answer, "stop_all") ? answer.stop_all : false;
    if (!isBool(stopAll)) { f("error", "L_SCHEMA", "answer.stop_all", "stop_all must be true or false"); return out; }
    var loops = answer.loops;
    if (!Array.isArray(loops)) {
      f("error", "L_SCHEMA", "answer.loops", "loops must be a list (every loop the zone keeps)");
      return out;
    }
    if (stopAll && loops.length > 0) f("error", "L_SCHEMA", "answer.stop_all", "Stop all sends no loops");
    if (!stopAll && loops.length === 0)
      f("error", "L_EMPTY", "answer.loops", "no loop is ticked: tick at least one, choose Decide later, or Stop all loops");
    if (stopAll && loops.length === 0)
      f("warn", "W_DEFAULT_MAP", "answer.stop_all",
        "every loop of zone " + zone + " stops: the zone goes back to the default map (a tag with one sensor " +
        "uses it; a tag with several gets no data and an alarm)");
    if (loops.length > MAX_LOOPS) f("error", "L_SCHEMA", "answer.loops", "at most " + MAX_LOOPS + " loops");
    var srcsAll = (spec.sources || []).map(function (s) { return s.instance; });
    var codes = [], acts = {};
    loops.forEach(function (lp, i) {
      if (!isObj(lp)) { f("error", "L_SCHEMA", "loops." + i, "a loop must be a JSON object"); return; }
      var code = lp.loop_code;
      if (!isStr(code) || !has(QMAP, code)) {
        f("error", "L_QUANTITY", "loops." + i + ".loop_code",
          "loop_code " + show(code) + " is not one of " + QUANTITIES.map(function (q) { return q.loop_code; }).join(", "));
        return;
      }
      var w = "loops." + code;
      if (codes.indexOf(code) >= 0) { f("error", "L_DUP", w + ".loop_code", code + ": listed twice"); return; }
      codes.push(code);
      var q = QMAP[code];
      if (code.length + 1 + zone.length > STATE_KEY_MAX)
        f("error", "L_STATE_KEY", w + ".loop_code",
          code + ": the runner's state key " + code + "@" + zone + " is longer than " + STATE_KEY_MAX + " characters");
      Object.keys(lp).forEach(function (k) {
        if (LOOP_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w, code + ": unknown key " + k.slice(0, 60));
      });
      if (lp.recipe_lower !== q.recipe_lower || lp.recipe_upper !== q.recipe_upper)
        f("error", "L_LIMITS", w + ".recipe",
          code + ": the limits are the recipe's " + q.recipe_lower + " and " + q.recipe_upper);
      var inp = lp.input, cands = candidates(spec, q.tag);
      if (!isObj(inp)) {
        f("error", "L_SCHEMA", w + ".input", code + ": input must be an object");
      } else {
        Object.keys(inp).forEach(function (k) {
          if (INPUT_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w + ".input", code + ": unknown key input." + k.slice(0, 60));
        });
        if (inp.tag !== q.tag) f("error", "L_TAG", w + ".input.tag", code + ": input.tag must be " + q.tag);
        var rule = inp.rule;
        if (!isStr(rule) || RULES.indexOf(rule) < 0)
          f("error", "L_RULE", w + ".input.rule", code + ": the rule must be one of " + RULES.join(", "));
        var srcs = inp.sources, seen = [];
        if (!Array.isArray(srcs)) {
          f("error", "L_SCHEMA", w + ".input.sources", code + ": sources must be a list of sensor names");
        } else {
          srcs.forEach(function (s) {
            if (!isStr(s)) { f("error", "L_SCHEMA", w + ".input.sources", code + ": sources must be sensor names"); return; }
            if (seen.indexOf(s) >= 0) {
              f("error", "L_SCHEMA", w + ".input.sources", code + ": sensor " + s.slice(0, 60) + " is listed twice");
              return;
            }
            seen.push(s);
            if (s === RESERVED)
              f("error", "L_SOURCE_RESERVED", w + ".input.sources." + s,
                code + ": sensor default is reserved for readings without a sensor name: re-onboard " +
                "that board and choose its named sensor");
            else if (srcsAll.indexOf(s) < 0)
              f("error", "L_SOURCE", w + ".input.sources." + s,
                code + ": sensor " + s.slice(0, 60) + " is not on the SENSE board of zone " + zone);
            else if (cands.indexOf(s) < 0)
              f("error", "L_SOURCE_TAG", w + ".input.sources." + s, code + ": sensor " + s + " does not publish " + q.tag);
          });
        }
        var choose = rule === "reference" && (inp.reference === undefined || inp.reference === null);
        if (choose)
          f("error", "L_CHOOSE", w + ".input.reference",
            code + " has " + cands.length + " sensors (" + cands.join(", ") +
            "): choose the one it controls on, or mean/min/max, or mark it not controlled");
        else if (Array.isArray(srcs) && srcs.length === 0)
          f("error", "L_SOURCES_EMPTY", w + ".input.sources", code + ": tick at least one sensor");
        if (rule === "reference" && !choose) {
          var ref = inp.reference;
          if (!isStr(ref) || seen.indexOf(ref) < 0)
            f("error", "L_REFERENCE", w + ".input.reference", code + ": the reference must be one of the sources");
          if (has(inp, "fallback")) {
            var fb = inp.fallback;
            if (!isStr(fb) || fb === ref || seen.indexOf(fb) < 0)
              f("error", "L_FALLBACK", w + ".input.fallback",
                code + ": the fallback must be another of the sources than the reference");
          }
          var extra = seen.filter(function (s) { return s !== ref && s !== inp.fallback; });
          if (extra.length)
            f("error", "L_SOURCES_EXTRA", w + ".input.sources",
              code + ": with rule reference the sources are the reference and the fallback only (not " +
              extra.join(", ") + ")");
        } else if ((rule === "mean" || rule === "min" || rule === "max") && (has(inp, "reference") || has(inp, "fallback"))) {
          f("error", "L_RULE_ARGS", w + ".input.rule", code + ": rule " + rule + " takes no reference or fallback");
        }
        if (has(inp, "max_age_s")) {
          var n = inp.max_age_s;
          if (!isWhole(n) || n < MAX_AGE_MIN || n > MAX_AGE_MAX)
            f("error", "L_MAX_AGE", w + ".input.max_age_s",
              code + ": max age must be a whole number of seconds from " + MAX_AGE_MIN + " to " + MAX_AGE_MAX);
        }
      }
      var outp = lp.output;
      if (!isObj(outp)) { f("error", "L_SCHEMA", w + ".output", code + ": output must be an object"); return; }
      Object.keys(outp).forEach(function (k) {
        if (OUTPUT_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w + ".output", code + ": unknown key output." + k.slice(0, 60));
      });
      if (outp.mode !== "command")
        f("error", "L_MODE", w + ".output.mode",
          code + ": the mode is command in this release (level and boost need the PWM outputs of Phase 3)");
      if (q.command_map) {
        if (!sameMap(outp.command_map, q.command_map))
          f("error", "L_COMMAND_MAP", w + ".output.command_map",
            code + ": the command map is fixed: DOWN to UP, UP to OFF, OFF to OFF (the fans)");
      } else if (has(outp, "command_map")) {
        f("error", "L_COMMAND_MAP", w + ".output.command_map", code + ": a command map is only for co2");
      }
      var act = outp.actuator;
      if (!isStr(act) || !ACTUATOR_RX.test(act)) {
        f("error", "L_ACTUATOR", w + ".output.actuator", code + ": choose an actuator");
        return;
      }
      if (findActuator(spec, act) === null)
        f("error", "L_ACTUATOR", w + ".output.actuator",
          code + ": actuator " + act + " is not on the CONTROL board of zone " + zone);
      else if (!fit(spec, act, q))
        f("error", "L_ACTUATOR_KIND", w + ".output.actuator",
          code + ": actuator " + act + " does not take every command the loop sends (" + sends(q).join(", ") + ")");
      if (has(acts, act))
        f("error", "L_ACTUATOR_SHARED", w + ".output.actuator",
          code + ": actuator " + act + " is driven by " + acts[act] + " already (one loop per actuator)");
      else acts[act] = code;
    });
    if (!stopAll) {
      (spec.existing || []).forEach(function (r) {
        if (codes.indexOf(r.loop_code) < 0)
          f("warn", "W_STOPPED", "loops." + r.loop_code, r.loop_code + " stops: its loop is deactivated when this is saved");
      });
      if (loops.length > 0) {
        (spec.rows || []).forEach(function (r) {
          if (r.offered && r.default_actuator && codes.indexOf(r.loop_code) < 0 &&
              !(spec.existing || []).some(function (x) { return x.loop_code === r.loop_code; }))
            f("warn", "W_NOT_CONTROLLED", "loops." + r.loop_code,
              r.loop_code + " is not controlled: the zone has its sensor and actuator, but no loop");
        });
      }
    }
    return out;
  }

  var logic = { validate: validate, rowFor: rowFor, stateOf: stateOf, sends: sends,
                candidates: candidates, QUANTITIES: QUANTITIES, RULES: RULES,
                MAX_AGE_DEFAULT: MAX_AGE_DEFAULT };
  if (typeof module !== "undefined" && module.exports) module.exports = logic;
  /* loops-logic:end */

  if (typeof document === "undefined") { root.Loops = { logic: logic }; return; }

  /* ---------------------------------------------------------------- screen --- */
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function opt(sel, value, label, selected) {
    var o = h("option", null, label);
    o.value = value;
    if (selected) o.selected = true;
    sel.appendChild(o);
  }
  function copy(v) { return JSON.parse(JSON.stringify(v)); }

  function mount(o) {
    var el = o.el, spec = o.spec || {}, onchange = o.onchange || function () {};
    var rows = {}, skip = false, stopAll = false, findings = [];
    (spec.rows || []).forEach(function (r) {
      rows[r.loop_code] = { r: r, ticked: !!r.ticked, touched: false,
                            st: r.state ? copy(r.state) : null };
    });
    var stale = {};
    (spec.stale || []).forEach(function (s) { stale[s.loop_code] = s; });

    el.innerHTML = "";
    var w = h("div", "lp");
    el.appendChild(w);
    w.appendChild(h("p", "lp-zone", "Zone " + (spec.unit_code || "?") + " / " + (spec.zone_code || "?") +
      (spec.role === "SENSE" ? " — the sensors of the board you are onboarding" :
       spec.role === "CONTROL" ? " — the actuators of the board you are onboarding" : "")));
    if ((spec.existing || []).length === 0)
      w.appendChild(h("p", "lp-note", "This zone has no control loops yet, so it runs on the default map: " +
        "a tag with one sensor uses it, a tag with several gets no data and an alarm. Saving the loops below " +
        "replaces the default map for this zone; a quantity left unticked is then not controlled."));
    else
      w.appendChild(h("p", "lp-note", "Saving replaces this zone's loops with the ticked rows: " +
        "a loop you untick is stopped."));

    var table = h("table", "lp-table");
    var head = h("tr");
    ["Control", "Quantity", "Sensor", "Max age (s)", "Actuator", "Mode"].forEach(function (t) { head.appendChild(h("th", null, t)); });
    var thead = h("thead"); thead.appendChild(head); table.appendChild(thead);
    var tbody = h("tbody"); table.appendChild(tbody);
    w.appendChild(table);

    var bar = h("div", "lp-bar");
    var later = h("button", "lp-later", "Decide later"); later.type = "button";
    var stopBtn = h("button", "lp-stopall", "Stop all loops"); stopBtn.type = "button";
    bar.appendChild(later);
    if ((spec.existing || []).length) bar.appendChild(stopBtn);
    var modeNote = h("span", "lp-modenote");
    bar.appendChild(modeNote);
    w.appendChild(bar);
    var ul = h("ul", "lp-findings");
    w.appendChild(ul);

    later.onclick = function () {
      skip = !skip; if (skip) stopAll = false;
      redraw();
    };
    stopBtn.onclick = function () {
      if (!stopAll && !confirm("Stop every control loop of zone " + spec.zone_code + "?\n\n" +
          "The zone goes back to the default map: a tag with one sensor uses it, a tag with several gets " +
          "no data and an alarm in a run.")) return;
      stopAll = !stopAll; if (stopAll) skip = false;
      redraw();
    };

    function current(code) {
      var x = rows[code];
      if (!x.ticked) return null;
      if (!x.touched && x.r.loop) return copy(x.r.loop);
      return rowFor(spec, code, x.st);
    }
    function value() {
      if (skip) return { skip: true };
      if (stopAll) return { skip: false, stop_all: true, loops: [] };
      var loops = [];
      (spec.rows || []).forEach(function (r) { var l = current(r.loop_code); if (l) loops.push(l); });
      return { skip: false, stop_all: false, loops: loops };
    }
    function touch(code) { rows[code].touched = true; check(); }

    function sensorCell(code, x) {
      var td = h("td", "lp-sensor"), cands = x.r.candidates || [], st = x.st;
      var how = h("select", "lp-rule");
      opt(how, "reference", "on one sensor", st.rule === "reference");
      if (cands.length > 1) {
        opt(how, "mean", "mean of the ticked", st.rule === "mean");
        opt(how, "min", "lowest of the ticked", st.rule === "min");
        opt(how, "max", "highest of the ticked", st.rule === "max");
      } else if (st.rule !== "reference") {
        opt(how, st.rule, st.rule, true);
      }
      how.onchange = function () {
        st.rule = how.value;
        if (st.rule === "reference") { st.sensors = []; }
        else { st.reference = null; st.fallback = null; if (!st.sensors || !st.sensors.length) st.sensors = cands.slice(); }
        touch(code); drawRow(code);
      };
      td.appendChild(how);
      if (st.rule === "reference") {
        var ref = h("select", "lp-ref");
        if (cands.length !== 1 || st.reference !== cands[0]) opt(ref, "", "— choose the sensor —", !st.reference);
        cands.forEach(function (c) { opt(ref, c, c, st.reference === c); });
        if (st.reference && cands.indexOf(st.reference) < 0) opt(ref, st.reference, st.reference + " (gone)", true);
        ref.onchange = function () {
          st.reference = ref.value || null;
          if (st.fallback === st.reference) st.fallback = null;
          touch(code); drawRow(code);
        };
        td.appendChild(ref);
        if (cands.length > 1 || st.fallback) {
          var fb = h("select", "lp-fb");
          opt(fb, "", "no fallback", !st.fallback);
          cands.forEach(function (c) { if (c !== st.reference) opt(fb, c, "fall back to " + c, st.fallback === c); });
          if (st.fallback && cands.indexOf(st.fallback) < 0) opt(fb, st.fallback, st.fallback + " (gone)", true);
          fb.onchange = function () { st.fallback = fb.value || null; touch(code); };
          td.appendChild(fb);
        }
      } else {
        var box = h("div", "lp-ticks");
        cands.forEach(function (c) {
          var lab = h("label"), cb = h("input");
          cb.type = "checkbox"; cb.checked = (st.sensors || []).indexOf(c) >= 0;
          cb.onchange = function () {
            st.sensors = cands.filter(function (s) { return s === c ? cb.checked : (st.sensors || []).indexOf(s) >= 0; });
            touch(code);
          };
          lab.appendChild(cb); lab.appendChild(document.createTextNode(" " + c));
          box.appendChild(lab);
        });
        td.appendChild(box);
      }
      return td;
    }

    var trs = {};
    function drawRow(code) {
      var x = rows[code], r = x.r, q = QMAP[code];
      var tr = trs[code] || h("tr");
      tr.innerHTML = "";
      tr.className = x.ticked ? "lp-on" : "lp-off";
      var tdc = h("td", "lp-tick"), cb = h("input");
      cb.type = "checkbox"; cb.checked = x.ticked; cb.disabled = !r.offered;
      cb.setAttribute("aria-label", "control " + q.label);
      cb.onchange = function () { x.ticked = cb.checked; check(); drawRow(code); };
      tdc.appendChild(cb);
      if (stale[code]) {
        var stop = h("button", "lp-stop", "Stop this loop"); stop.type = "button";
        stop.onclick = function () { x.ticked = false; check(); drawRow(code); };
        if (x.ticked) tdc.appendChild(stop);
      }
      tr.appendChild(tdc);
      var tdq = h("td", "lp-q");
      tdq.appendChild(h("div", "lp-label", q.label));
      tdq.appendChild(h("div", "lp-tag", q.tag + (r.existing ? " · saved" : "")));
      if (stale[code]) tdq.appendChild(h("div", "lp-badge", stale[code].message));
      tr.appendChild(tdq);
      if (!r.offered) {
        var na = h("td", "lp-na", r.reason || "nothing to control");
        na.colSpan = 4; tr.appendChild(na);
      } else if (!x.ticked) {
        var nc = h("td", "lp-na", r.existing ? "stopped when saved" : "not controlled");
        nc.colSpan = 4; tr.appendChild(nc);
      } else {
        tr.appendChild(sensorCell(code, x));
        var tda = h("td"), age = h("input", "lp-age");
        age.type = "number"; age.min = String(MAX_AGE_MIN); age.max = String(MAX_AGE_MAX); age.step = "1";
        age.value = String(x.st.max_age_s);
        age.oninput = function () { x.st.max_age_s = age.value === "" ? null : Number(age.value); touch(code); };
        tda.appendChild(age); tr.appendChild(tda);
        var tdo = h("td"), act = h("select", "lp-act");
        var fits = (r.actuators || []).slice();
        if (x.st.actuator && fits.indexOf(x.st.actuator) < 0) opt(act, x.st.actuator, x.st.actuator + " (cannot)", true);
        fits.forEach(function (n) { opt(act, n, n, x.st.actuator === n); });
        act.onchange = function () { x.st.actuator = act.value; touch(code); };
        tdo.appendChild(act); tr.appendChild(tdo);
        var tdm = h("td"), mode = h("select", "lp-mode");
        opt(mode, "command", "command", true); mode.disabled = true;
        mode.title = "level and boost: Phase 3 (PWM outputs)";
        tdm.appendChild(mode);
        if (q.command_map) tdm.appendChild(h("div", "lp-map", "fans: DOWN→UP, UP→OFF"));
        tr.appendChild(tdm);
      }
      if (!trs[code]) { trs[code] = tr; tbody.appendChild(tr); }
    }

    function redraw() {
      later.textContent = skip ? "Choose now" : "Decide later";
      stopBtn.textContent = stopAll ? "Keep the loops" : "Stop all loops";
      table.hidden = skip || stopAll;
      modeNote.textContent = skip ? "Nothing is saved; the zone's loops stay as they are." :
        stopAll ? "Every loop of this zone stops when saved." : "";
      check();
    }

    function check() {
      findings = validate(spec, value());
      ul.innerHTML = "";
      findings.forEach(function (fd) {
        ul.appendChild(h("li", fd.level === "error" ? "lp-err" : "lp-warn", fd.message));
      });
      onchange(ctl);
    }

    var ctl = {
      value: value,
      findings: function () { return findings.slice(); },
      errors: function () { return findings.filter(function (fd) { return fd.level === "error"; }).length; },
      skip: function () { return skip; }
    };
    (spec.rows || []).forEach(function (r) { drawRow(r.loop_code); });
    redraw();
    return ctl;
  }

  root.Loops = { mount: mount, logic: logic };
})(typeof window !== "undefined" ? window : this);
