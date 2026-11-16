/* The control-loop picker (feedback control Phase 2, owner decision Q20; recipe
 * types, migration 011).
 *
 * One row per loopable quantity of the zone's unit's recipe type. A loop has two
 * halves, each bound by its own board's onboarding, in either order: a SENSE board
 * binds the input (which tag of which sensor, or the mean/min/max of the sensors of
 * one tag, how old a reading may be), a CONTROL board the output (which actuator).
 * A loop with one half ("half-bound") runs on the default for the other. A default
 * tag with one sensor comes preselected; with several it stays in error until the
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
 *   Loops.logic = {validate, rowFor, stateOf, sends, candidates, pairs, qmap, ...}
 */
(function (root) {
  "use strict";

  /* loops-logic:begin */
  var SPEC_VERSION = 2;
  var RULES = ["reference", "mean", "min", "max"];
  var MAX_AGE_MIN = 1, MAX_AGE_MAX = 3600, MAX_AGE_DEFAULT = 90;
  var MAX_LOOPS = 16, STATE_KEY_MAX = 50, RESERVED = "default";
  var ACTUATOR_RX = /^[A-Za-z0-9_]+$/;
  var TAG_RX = /^[a-z][a-z0-9_]*$/;
  var ANSWER_KEYS = ["skip", "stop_all", "half", "loops"];
  var LOOP_KEYS = ["loop_code", "input", "output"];
  var INPUT_KEYS = ["tag", "sources", "rule", "reference", "fallback", "max_age_s"];
  var OUTPUT_KEYS = ["actuator", "mode", "command_map"];

  function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function isStr(v) { return typeof v === "string"; }
  function isBool(v) { return v === true || v === false; }
  function copyOf(v) { return JSON.parse(JSON.stringify(v)); }

  function sends(q) {
    if (isObj(q.command_map) && Object.keys(q.command_map).length) {
      var vals = {};
      Object.keys(q.command_map).forEach(function (k) { vals[q.command_map[k]] = true; });
      return Object.keys(vals).sort();
    }
    return (q.commands && q.commands.length ? q.commands.slice() : ["DOWN", "OFF", "UP"]).sort();
  }
  function jsonbText(obj) {
    var keys = Object.keys(obj).sort(function (a, b) {
      return a.length !== b.length ? a.length - b.length : (a < b ? -1 : a > b ? 1 : 0);
    });
    return "{" + keys.map(function (k) { return JSON.stringify(k) + ": " + JSON.stringify(obj[k]); }).join(", ") + "}";
  }
  function qmap(spec) {
    var m = {};
    (spec.quantities || []).forEach(function (q) { m[q.loop_code] = q; });
    return m;
  }
  function source(spec, name) {
    var all = spec.sources || [];
    for (var i = 0; i < all.length; i++) if (all[i].instance === name) return all[i];
    return null;
  }
  function uomOk(q, uom) { return !uom || (q.sense_uoms || []).indexOf(uom) >= 0; }
  function candidates(spec, code, tag) {
    var q = qmap(spec)[code];
    if (!q || !tag) return [];
    return (spec.sources || []).filter(function (s) {
      return (s.tags || []).indexOf(tag) >= 0 && uomOk(q, (s.uoms || {})[tag]);
    }).map(function (s) { return s.instance; });
  }
  function pairs(spec, q) {
    var first = [], rest = [];
    (spec.sources || []).forEach(function (s) {
      (s.tags || []).forEach(function (t) {
        var uom = (s.uoms || {})[t] || null;
        if (uom === null && t !== q.tag) return;
        if (!uomOk(q, uom)) return;
        (t === q.tag ? first : rest).push({ instance: s.instance, tag: t, uom: uom });
      });
    });
    return first.concat(rest);
  }
  function findActuator(spec, name) {
    var all = spec.actuators || [];
    for (var i = 0; i < all.length; i++) if (all[i].name === name) return all[i];
    return null;
  }
  function sameMap(a, b) {
    if (!isObj(a) || !isObj(b)) return false;
    var ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
    if (ka.join("\u0000") !== kb.join("\u0000")) return false;
    return ka.every(function (k) { return isStr(a[k]) && a[k] === b[k]; });
  }
  function isWhole(n) { return typeof n === "number" && Number.isInteger(n); }
  function show(v) { return isStr(v) ? v.slice(0, 60) : JSON.stringify(v === undefined ? null : v); }
  function hasHalf(half, ex) {
    if (half === "input") return ex.input !== null && ex.input !== undefined;
    if (half === "output") return ex.output !== null && ex.output !== undefined;
    return true;
  }
  function stopAllText(half, zone) {
    if (half === "input")
      return "no sensor of zone " + zone + " feeds a loop after this is saved: a loop keeps its actuator and " +
        "waits for a sensor (a loop with neither is stopped)";
    if (half === "output")
      return "no actuator of zone " + zone + " is driven by a loop after this is saved: a loop keeps its sensor and " +
        "waits for an actuator (a loop with neither is stopped)";
    return "every loop of zone " + zone + " stops: the zone goes back to the default map (a tag with one sensor " +
      "uses it; a tag with several gets no data and an alarm)";
  }

  function rowFor(spec, code, st) {
    var q = qmap(spec)[code], half = spec.half, out = { loop_code: code };
    var wantIn = half === "input" || (half === "both" && st.input !== false);
    var wantOut = half === "output" || (half === "both" && st.output !== false);
    if (wantIn) {
      var tag = isStr(st.tag) && st.tag !== "" ? st.tag : null;
      var rule = st.rule || "reference", inp = { tag: tag };
      if (rule === "reference") {
        var ref = st.reference, fb = st.fallback;
        inp.sources = [ref, fb].filter(function (x) { return isStr(x) && x !== ""; });
        inp.rule = "reference";
        inp.reference = isStr(ref) && ref !== "" ? ref : null;
        if (isStr(fb) && fb !== "" && fb !== ref) inp.fallback = fb;
      } else {
        var ticked = st.sensors || [];
        inp.sources = candidates(spec, code, tag).filter(function (s) { return ticked.indexOf(s) >= 0; });
        inp.rule = rule;
      }
      inp.max_age_s = has(st, "max_age_s") ? st.max_age_s : MAX_AGE_DEFAULT;
      out.input = inp;
    }
    if (wantOut) {
      var o = { actuator: st.actuator || null, mode: "command" };
      if (isObj(q.command_map)) o.command_map = copyOf(q.command_map);
      out.output = o;
    }
    return out;
  }

  function stateOf(row) {
    var inp = isObj(row.input) ? row.input : {}, out = isObj(row.output) ? row.output : {};
    var rule = RULES.indexOf(inp.rule) >= 0 ? inp.rule : "reference";
    var srcs = (Array.isArray(inp.sources) ? inp.sources : []).filter(isStr);
    return { tag: isStr(inp.tag) ? inp.tag : null,
             rule: rule,
             reference: rule === "reference" && has(inp, "reference") ? inp.reference : null,
             fallback: rule === "reference" && has(inp, "fallback") ? inp.fallback : null,
             sensors: rule !== "reference" ? srcs : [],
             max_age_s: has(inp, "max_age_s") ? inp.max_age_s : MAX_AGE_DEFAULT,
             actuator: isStr(out.actuator) ? out.actuator : null,
             input: isObj(row.input),
             output: isObj(row.output) };
  }

  function checkInput(spec, f, q, code, w, inp, zone) {
    if (!isObj(inp)) { f("error", "L_SCHEMA", w + ".input", code + ": input must be an object"); return; }
    Object.keys(inp).forEach(function (k) {
      if (INPUT_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w + ".input", code + ": unknown key input." + k.slice(0, 60));
    });
    var tag = has(inp, "tag") ? inp.tag : null, noTag = tag === null;
    if (!noTag && (!isStr(tag) || !TAG_RX.test(tag))) {
      f("error", "L_TAG", w + ".input.tag", code + ": input.tag must be a tag name");
      tag = null;
    }
    var rule = inp.rule;
    if (!isStr(rule) || RULES.indexOf(rule) < 0)
      f("error", "L_RULE", w + ".input.rule", code + ": input.rule must be one of reference, mean, min, max");
    var srcs = inp.sources, seen = [];
    var units = (q.sense_uoms || []).slice().sort().join(" or ");
    if (!Array.isArray(srcs)) {
      f("error", "L_SCHEMA", w + ".input.sources", code + ": input.sources must be a non-empty list of sensor names");
    } else {
      srcs.forEach(function (s) {
        if (!isStr(s)) { f("error", "L_SCHEMA", w + ".input.sources", code + ": input.sources must hold sensor names (strings)"); return; }
        if (seen.indexOf(s) >= 0) {
          f("error", "L_SCHEMA", w + ".input.sources", code + ": sensor " + s.slice(0, 60) + " is listed twice");
          return;
        }
        seen.push(s);
        var src = source(spec, s);
        if (s === RESERVED)
          f("error", "L_SOURCE_RESERVED", w + ".input.sources." + s,
            code + ": sensor default is reserved for readings without a sensor name (a board flashed before " +
            "Phase 1): re-onboard the board and choose its named sensor");
        else if (src === null)
          f("error", "L_SOURCE", w + ".input.sources." + s,
            code + ": sensor " + s.slice(0, 60) + " is not on an active SENSE board of zone " + zone);
        else if (tag !== null) {
          if ((src.tags || []).indexOf(tag) < 0)
            f("error", "L_SOURCE_TAG", w + ".input.sources." + s, code + ": sensor " + s + " does not publish " + tag);
          else {
            var uom = (src.uoms || {})[tag] || "";
            if (uom && (q.sense_uoms || []).indexOf(uom) < 0)
              f("error", "L_UOM", w + ".input.sources." + s,
                code + ": sensor " + s + " publishes " + tag + " in " + uom + ", not " + units);
            else if (!uom)
              f("warn", "W_NO_UOM", w + ".input.sources." + s,
                code + ": sensor " + s + " publishes " + tag + " without a unit, so it is not checked to be in " + units);
          }
        }
      });
    }
    var cands = tag !== null ? candidates(spec, code, tag) : [];
    var choose = noTag || (rule === "reference" && (inp.reference === undefined || inp.reference === null));
    if (noTag) {
      var reads = pairs(spec, q).map(function (p) { return p.instance + " " + p.tag; });
      f("error", "L_CHOOSE", w + ".input.tag",
        code + " can read " + (reads.join(", ") || "nothing on this board") +
        ": choose the tag and the sensor it controls on, or mark it not controlled");
    } else if (choose) {
      f("error", "L_CHOOSE", w + ".input.reference",
        code + " has " + cands.length + " sensors (" + cands.join(", ") +
        "): choose the one it controls on, or mean/min/max, or mark it not controlled");
    } else if (Array.isArray(srcs) && srcs.length === 0) {
      f("error", "L_SOURCES_EMPTY", w + ".input.sources", code + ": input.sources must be a non-empty list of sensor names");
    }
    if (rule === "reference" && !choose) {
      var ref = inp.reference, fb = null;
      if (!isStr(ref))
        f("error", "L_REFERENCE", w + ".input.reference", code + ": rule reference needs input.reference, one of the sources");
      else if (seen.indexOf(ref) < 0)
        f("error", "L_REFERENCE", w + ".input.reference", code + ": input.reference " + ref.slice(0, 60) + " is not one of the sources");
      if (has(inp, "fallback")) {
        fb = inp.fallback;
        if (!isStr(fb)) {
          f("error", "L_FALLBACK", w + ".input.fallback", code + ": input.fallback must be a sensor name");
          fb = null;
        } else if (fb === ref) {
          f("error", "L_FALLBACK", w + ".input.fallback", code + ": input.fallback must be another sensor than the reference");
        } else if (seen.indexOf(fb) < 0) {
          f("error", "L_FALLBACK", w + ".input.fallback", code + ": input.fallback " + fb.slice(0, 60) + " is not one of the sources");
        }
      }
      var rs = isStr(ref) ? ref : null;
      if (seen.some(function (s) { return s !== rs && s !== fb; }))
        f("error", "L_SOURCES_EXTRA", w + ".input.sources",
          code + ": with rule reference, input.sources holds only the reference and the fallback");
    } else if ((rule === "mean" || rule === "min" || rule === "max") && (has(inp, "reference") || has(inp, "fallback"))) {
      f("error", "L_RULE_ARGS", w + ".input.rule", code + ": rule " + rule + " takes no reference or fallback");
    }
    if (has(inp, "max_age_s")) {
      var n = inp.max_age_s;
      if (!isWhole(n) || n < MAX_AGE_MIN || n > MAX_AGE_MAX)
        f("error", "L_MAX_AGE", w + ".input.max_age_s",
          code + ": input.max_age_s must be a whole number of seconds from 1 to 3600");
    }
  }

  function checkOutput(spec, f, q, code, w, outp, zone, acts) {
    if (!isObj(outp)) { f("error", "L_SCHEMA", w + ".output", code + ": output must be an object"); return; }
    Object.keys(outp).forEach(function (k) {
      if (OUTPUT_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w + ".output", code + ": unknown key output." + k.slice(0, 60));
    });
    if (outp.mode !== "command")
      f("error", "L_MODE", w + ".output.mode",
        code + ": output.mode must be command (level and boost need Phase 3's PWM outputs)");
    if (isObj(q.command_map)) {
      if (!sameMap(outp.command_map, q.command_map))
        f("error", "L_COMMAND_MAP", w + ".output.command_map",
          code + ": output.command_map must be exactly " + jsonbText(q.command_map));
    } else if (has(outp, "command_map")) {
      f("error", "L_COMMAND_MAP", w + ".output.command_map",
        code + ": output.command_map is only for a quantity whose catalogue entry has one");
    }
    var act = outp.actuator;
    if (!isStr(act) || !ACTUATOR_RX.test(act)) {
      f("error", "L_ACTUATOR", w + ".output.actuator", code + ": output.actuator must be an actuator name");
      return;
    }
    var a = findActuator(spec, act), need = sends(q);
    if (a === null)
      f("error", "L_ACTUATOR", w + ".output.actuator",
        code + ": actuator " + act + " is not on an active CONTROL board of zone " + zone);
    else if (a.kind !== "commands" || !need.every(function (c) { return (a.commands || []).indexOf(c) >= 0; }))
      f("error", "L_ACTUATOR_KIND", w + ".output.actuator",
        code + ": actuator " + act + " does not take every command the loop sends (" + need.join(", ") + ")");
    else if (a.quantity !== null && a.quantity !== undefined && a.quantity !== code)
      f("error", "L_ACTUATOR_QUANTITY", w + ".output.actuator",
        code + ": actuator " + act + " acts on " + a.quantity + ", not " + code);
    if (has(acts, act))
      f("error", "L_ACTUATOR_SHARED", w + ".output.actuator",
        code + ": actuator " + act + " is driven by another loop of the zone");
    else acts[act] = code;
  }

  function validate(spec, answer) {
    var out = [];
    function f(level, code, where, message) { out.push({ level: level, code: code, where: where, message: message }); }
    if (!isObj(spec) || spec.version !== SPEC_VERSION) {
      f("error", "L_SCHEMA", "spec.version", "the page and the wizard are of different versions: reload the page");
      return out;
    }
    var zone = spec.zone_code || "", half = spec.half, qs = qmap(spec);
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
      if (half !== "output" && !(spec.existing || []).length) {
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
    if (answer.half !== half) {
      f("error", "L_SCHEMA", "answer.half",
        "the answer sets the " + show(answer.half) + " half, this page the " + half + " half: reload the page");
      return out;
    }
    var loops = answer.loops;
    if (!Array.isArray(loops)) {
      f("error", "L_SCHEMA", "answer.loops", "loops must be a list (every loop the zone keeps)");
      return out;
    }
    if (stopAll && loops.length > 0) f("error", "L_SCHEMA", "answer.stop_all", "Stop all sends no loops");
    if (!stopAll && loops.length === 0)
      f("error", "L_EMPTY", "answer.loops", "no loop is ticked: tick at least one, choose Decide later, or Stop all loops");
    if (stopAll && loops.length === 0) f("warn", "W_DEFAULT_MAP", "answer.stop_all", stopAllText(half, zone));
    if (loops.length > MAX_LOOPS) f("error", "L_SCHEMA", "answer.loops", "at most " + MAX_LOOPS + " loops");
    var loopable = Object.keys(qs).filter(function (c) { return qs[c].loopable; }).sort();
    var codes = [], acts = {}, sides = {};
    loops.forEach(function (lp, i) {
      if (!isObj(lp)) { f("error", "L_SCHEMA", "loops." + i, "a loop must be a JSON object"); return; }
      var code = lp.loop_code;
      if (!isStr(code)) { f("error", "L_QUANTITY", "loops." + i + ".loop_code", "a loop needs a loop_code"); return; }
      var q = has(qs, code) ? qs[code] : null;
      if (q === null) {
        f("error", "L_QUANTITY", "loops." + i + ".loop_code",
          "loop_code " + code.slice(0, 60) + " is not one of " + (loopable.join(", ") || "none"));
        return;
      }
      var w = "loops." + code;
      if (!q.loopable) {
        f("error", "L_NOT_LOOPABLE", w + ".loop_code", code + ": a setpoint only, without a feedback loop yet");
        return;
      }
      if (codes.indexOf(code) >= 0) { f("error", "L_DUP", w + ".loop_code", code + ": listed twice"); return; }
      codes.push(code);
      if (code.length + 1 + zone.length > STATE_KEY_MAX)
        f("error", "L_STATE_KEY", w + ".loop_code",
          code + ": the runner's state key " + code + "@" + zone + " is longer than " + STATE_KEY_MAX + " characters");
      Object.keys(lp).forEach(function (k) {
        if (LOOP_KEYS.indexOf(k) < 0) f("error", "L_SCHEMA", w, code + ": unknown key " + k.slice(0, 60));
      });
      var inp = has(lp, "input") ? lp.input : null, outp = has(lp, "output") ? lp.output : null;
      sides[code] = [inp !== null, outp !== null];
      if (half === "input" && outp !== null)
        f("error", "L_HALF", w + ".output", code + ": a SENSE onboarding sets the input only");
      else if (half === "output" && inp !== null)
        f("error", "L_HALF", w + ".input", code + ": a CONTROL onboarding sets the output only");
      if (half === "input" && inp === null)
        f("error", "L_SCHEMA", w + ".input", code + ": input must be an object");
      else if (half === "output" && outp === null)
        f("error", "L_SCHEMA", w + ".output", code + ": output must be an object");
      else if (half === "both" && inp === null && outp === null)
        f("error", "L_HALF", w, code + ": a loop needs an input or an output");
      if (inp !== null) checkInput(spec, f, q, code, w, inp, zone);
      if (outp !== null) checkOutput(spec, f, q, code, w, outp, zone, acts);
    });
    if (!stopAll) {
      (spec.existing || []).forEach(function (r) {
        if (codes.indexOf(r.loop_code) < 0 && hasHalf(half, r)) {
          var msg = half === "input"
            ? r.loop_code + " loses its sensor when this is saved: until one is chosen again, a run reads the only fresh sensor of its default tag"
            : half === "output"
            ? r.loop_code + " loses its actuator when this is saved: until one is chosen again, a run drives the zone's actuator for it, if it has one"
            : r.loop_code + " stops: its loop is deactivated when this is saved";
          f("warn", "W_STOPPED", "loops." + r.loop_code, msg);
        }
      });
      if (loops.length > 0) {
        (spec.rows || []).forEach(function (r) {
          var c = r.loop_code;
          if (r.offered && r.default && codes.indexOf(c) < 0 &&
              !(spec.existing || []).some(function (x) { return x.loop_code === c && hasHalf(half, x); })) {
            var msg = half === "input"
              ? c + " gets no sensor: this board publishes " + r.default_tag + ", but it is not ticked"
              : half === "output"
              ? c + " gets no actuator: this board has " + r.default_actuator + ", but it is not ticked"
              : c + " is not controlled: the zone has its sensor and actuator, but no loop";
            f("warn", "W_NOT_CONTROLLED", "loops." + c, msg);
          }
        });
      }
      codes.forEach(function (c) {
        var hasIn = sides[c][0], hasOut = sides[c][1], ex = null;
        (spec.existing || []).forEach(function (x) { if (ex === null && x.loop_code === c) ex = x; });
        if (half === "input") hasOut = !!(ex && ex.output !== null && ex.output !== undefined);
        else if (half === "output") hasIn = !!(ex && ex.input !== null && ex.input !== undefined);
        if (hasIn && !hasOut)
          f("warn", "W_HALF_BOUND", "loops." + c,
            c + " waits for its actuator: until a CONTROL board's onboarding chooses one, a run drives the zone's actuator for it, if it has one");
        else if (hasOut && !hasIn)
          f("warn", "W_HALF_BOUND", "loops." + c,
            c + " waits for its sensor: until a SENSE board's onboarding chooses one, a run reads the only fresh sensor of its default tag");
      });
    }
    return out;
  }

  var logic = { validate: validate, rowFor: rowFor, stateOf: stateOf, sends: sends,
                candidates: candidates, pairs: pairs, qmap: qmap, jsonbText: jsonbText, RULES: RULES,
                MAX_AGE_DEFAULT: MAX_AGE_DEFAULT, SPEC_VERSION: SPEC_VERSION };
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
    var half = spec.half, QM = qmap(spec);
    var inSide = half !== "output", outSide = half !== "input";
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
      (spec.recipe_type ? " (" + spec.recipe_type + " recipes)" : "") +
      (half === "input" ? " — which sensor each loop reads, from the board you are onboarding" :
       half === "output" ? " — which actuator each loop drives, on the board you are onboarding" : "")));
    var halfNote = half === "input"
      ? "Each loop's actuator is chosen when the zone's CONTROL board is onboarded; until then a run drives the zone's actuator for it, if it has one."
      : half === "output"
      ? "Each loop's sensor is chosen when the zone's SENSE board is onboarded; until then a run reads the only fresh sensor of its default tag."
      : "A loop with only one half runs on the default for the other until it is chosen.";
    if ((spec.existing || []).length === 0)
      w.appendChild(h("p", "lp-note", "This zone has no control loops yet, so it runs on the default map: " +
        "a tag with one sensor uses it, a tag with several gets no data and an alarm. " + halfNote));
    else
      w.appendChild(h("p", "lp-note", "Saving replaces this part of the zone's loops with the ticked rows: " +
        "a loop you untick loses it. " + halfNote));

    var table = h("table", "lp-table");
    var head = h("tr"), cols = ["Control", "Quantity"];
    if (inSide) cols.push("Sensor", "Max age (s)");
    if (outSide) cols.push("Actuator", "Mode");
    cols.forEach(function (t) { head.appendChild(h("th", null, t)); });
    var thead = h("thead"); thead.appendChild(head); table.appendChild(thead);
    var tbody = h("tbody"); table.appendChild(tbody);
    w.appendChild(table);

    var bar = h("div", "lp-bar");
    var later = h("button", "lp-later", "Decide later"); later.type = "button";
    var stopBtn = h("button", "lp-stopall", "Stop all loops"); stopBtn.type = "button";
    bar.appendChild(later);
    if ((spec.existing || []).some(function (x) { return hasHalf(half, x); })) bar.appendChild(stopBtn);
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
      if (!stopAll && !confirm(stopAllText(half, spec.zone_code))) return;
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
      if (stopAll) return { skip: false, stop_all: true, half: half, loops: [] };
      var loops = [];
      (spec.rows || []).forEach(function (r) { var l = current(r.loop_code); if (l) loops.push(l); });
      return { skip: false, stop_all: false, half: half, loops: loops };
    }
    function touch(code) { rows[code].touched = true; check(); }

    function sensorCell(code, x) {
      var td = h("td", "lp-sensor"), st = x.st, r = x.r;
      if (half === "both") {
        var use = h("select", "lp-use");
        opt(use, "1", "reads a sensor", st.input !== false);
        opt(use, "0", "no sensor yet", st.input === false);
        use.onchange = function () { st.input = use.value === "1"; touch(code); drawRow(code); };
        td.appendChild(use);
        if (st.input === false) return td;
      }
      var tags = (r.tags || []).slice();
      if (st.tag && tags.indexOf(st.tag) < 0) tags.push(st.tag);
      if (tags.length > 1 || !st.tag) {
        var tg = h("select", "lp-tagsel");
        if (!st.tag) opt(tg, "", "— choose the reading —", true);
        tags.forEach(function (t) { opt(tg, t, t === r.default_tag ? t : t + " (another tag)", st.tag === t); });
        tg.onchange = function () {
          st.tag = tg.value || null; st.reference = null; st.fallback = null;
          var c = candidates(spec, code, st.tag);
          if (c.length === 1) st.reference = c[0];
          st.sensors = c.slice();
          touch(code); drawRow(code);
        };
        td.appendChild(tg);
      }
      var cands = st.tag ? candidates(spec, code, st.tag) : [];
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
      (r.pairs || []).forEach(function (p) {
        if (p.tag === st.tag && !p.uom)
          td.appendChild(h("div", "lp-tag", p.instance + " gives " + p.tag + " no unit: it is not checked"));
      });
      return td;
    }

    function actuatorCell(code, x) {
      var td = h("td"), st = x.st, r = x.r;
      var act = h("select", "lp-act");
      var fits = (r.actuators || []).slice();
      if (half === "both") opt(act, "", "no actuator yet", st.output === false);
      else if (!st.actuator) opt(act, "", "— choose the actuator —", true);
      if (st.actuator && fits.indexOf(st.actuator) < 0) opt(act, st.actuator, st.actuator + " (cannot)", st.output !== false);
      fits.forEach(function (n) { opt(act, n, n, st.output !== false && st.actuator === n); });
      act.onchange = function () {
        if (act.value === "" && half === "both") { st.output = false; }
        else { st.output = true; st.actuator = act.value || null; }
        touch(code);
      };
      td.appendChild(act);
      return td;
    }

    var trs = {};
    function drawRow(code) {
      var x = rows[code], r = x.r, q = QM[code] || { label: code, tag: "" };
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
      var state = !r.existing ? "" : r.live ? " · live" :
        r.has_input ? " · waits for its actuator" : r.has_output ? " · waits for its sensor" : "";
      tdq.appendChild(h("div", "lp-tag", (q.tag || "") + state));
      if (stale[code]) tdq.appendChild(h("div", "lp-badge", stale[code].message));
      tr.appendChild(tdq);
      var span = (inSide ? 2 : 0) + (outSide ? 2 : 0);
      if (!r.offered) {
        var na = h("td", "lp-na", r.reason || "nothing to control");
        na.colSpan = span; tr.appendChild(na);
      } else if (!x.ticked) {
        var nc = h("td", "lp-na", r.existing ? "stopped when saved" : "not controlled");
        nc.colSpan = span; tr.appendChild(nc);
      } else {
        if (inSide) {
          tr.appendChild(sensorCell(code, x));
          var tda = h("td"), age = h("input", "lp-age");
          age.type = "number"; age.min = String(MAX_AGE_MIN); age.max = String(MAX_AGE_MAX); age.step = "1";
          age.value = String(x.st.max_age_s);
          age.oninput = function () { x.st.max_age_s = age.value === "" ? null : Number(age.value); touch(code); };
          tda.appendChild(age); tr.appendChild(tda);
        }
        if (outSide) {
          tr.appendChild(actuatorCell(code, x));
          var tdm = h("td"), mode = h("select", "lp-mode");
          opt(mode, "command", "command", true); mode.disabled = true;
          mode.title = "level and boost: Phase 3 (PWM outputs)";
          tdm.appendChild(mode);
          if (isObj(q.command_map)) tdm.appendChild(h("div", "lp-map", "fans: DOWN→UP, UP→OFF"));
          tr.appendChild(tdm);
        }
      }
      if (!trs[code]) { trs[code] = tr; tbody.appendChild(tr); }
    }

    function redraw() {
      later.textContent = skip ? "Choose now" : "Decide later";
      stopBtn.textContent = stopAll ? "Keep the loops" : "Stop all loops";
      table.hidden = skip || stopAll;
      modeNote.textContent = skip ? "Nothing is saved; the zone's loops stay as they are." :
        stopAll ? stopAllText(half, spec.zone_code) : "";
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
