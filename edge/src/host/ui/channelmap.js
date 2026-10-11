/* The channel-map editor.
 *
 * Renders whatever `device_template.py channelmap` prints, and nothing in here
 * knows what a GPIO is. The address field's name, its label, what counts as a
 * legal one and which addresses carry a warning all arrive in spec.binding,
 * which comes from the device template — so a family that drives Modbus coils
 * or HTTP endpoints gets this editor, correctly labelled and correctly checked,
 * with no change to this file.
 *
 * The structural checks below (an actuator with no UP, a type whose OFF leaves
 * its own equipment running) are deliberately duplicated from
 * bindings.validate_config in Python. They are the same rules read from the same
 * template, in two thin interpreters: the browser needs a verdict on every
 * keystroke and the renderer needs one it can refuse on. Python is authoritative
 * — render() re-checks and will not write a table with errors in it.
 *
 *   ChannelMap.mount({el, spec, initial}) -> {value, findings, errors, onchange}
 */
(function (root) {
  "use strict";

  var CMDS = ["UP", "DOWN", "OFF"], TCMDS = ["ON", "OFF"];
  var uid = (function () { var n = 0; return function () { return "cm" + (++n); }; })();

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function el(html) { var d = document.createElement("div"); d.innerHTML = html; return d; }

  /* ------------------------------------------------------------- binding --- */
  function Addr(b, variant) {
    this.b = b || {};
    this.field = this.b.field || "pin";
    this.label = this.b.label || "Address";
    this.key = this.b.descriptions_key || "pin_descriptions";
    this.isInt = (this.b.address_kind || "int") === "int";
    this.rx = this.b.pattern ? new RegExp(this.b.pattern) : null;
    this.variants = this.b.variants || {};
    this.order = this.b.variant_order || Object.keys(this.variants);
    this.setVariant(variant || this.b.variant || "");
  }
  /* Which silicon we are checking against. Changing it swaps the legal range
     and the per-pin rules and touches nothing else — the command table is the
     same table, it is the board underneath that moved. */
  Addr.prototype.setVariant = function (v) {
    var vd = this.variants[v];
    this.variant = vd ? v : "";
    this.groups = (vd && vd.groups) || [];
    this.ranges = (vd && vd.ranges) || this.b.valid_ranges || [];
    this.rules = vd
      ? this.groups.filter(function (g) { return g.level; }).map(function (g) {
          return { addresses: g.pins || [], level: g.level, message: g.note || g.label || "" };
        })
      : (this.b.rules || []);
    this.rangesText = this.ranges.map(function (r) { return r[0] + "-" + r[1]; }).join(", ");
    return this;
  };
  Addr.prototype.meta = function () { return this.variants[this.variant] || {}; };
  /* Every pin this variant has, with whatever else already wants it. Built from
     the same groups the rules come from, so the reference cannot claim a pin is
     free while validation calls it taken. */
  Addr.prototype.pinRows = function () {
    var groups = this.groups, rows = [];
    this.ranges.forEach(function (r) {
      for (var p = r[0]; p <= r[1]; p++) {
        var tags = [], level = "", notes = [];
        groups.forEach(function (g) {
          if ((g.pins || []).indexOf(p) < 0) return;
          tags.push(g.label || g.id || "");
          if (g.level === "error") level = "error";
          else if (g.level === "warn" && level !== "error") level = "warn";
          if (g.level) notes.push(String(g.note || "").replace(/\{addr\}/g, String(p)));
        });
        rows.push({ pin: p, types: tags.length ? tags : ["I/O"], level: level, notes: notes });
      }
    });
    return rows;
  };
  /* The one-line verdict shown beside a channel as it is typed. */
  Addr.prototype.describe = function (raw) {
    var s = this.clean(raw);
    if (s === "") return null;
    var n = this.isInt ? Number(s) : s, hit = null;
    this.pinRows().forEach(function (r) { if (String(r.pin) === String(n)) hit = r; });
    if (!hit) return { types: ["not on this board"], level: "error" };
    return hit;
  };
  /* Keep only what this family could accept, so the field cannot hold a value
     the device would reject — typing letters into a GPIO is not a validation
     error to report later, it is a keystroke to drop now. */
  Addr.prototype.clean = function (raw) {
    var s = String(raw == null ? "" : raw);
    return this.isInt ? s.replace(/[^0-9]/g, "") : s.trim();
  };
  Addr.prototype.problem = function (raw) {
    var s = this.clean(raw);
    if (s === "") return this.label + " cannot be blank.";
    if (this.isInt) {
      var n = Number(s), ok = !this.ranges.length;
      for (var i = 0; i < this.ranges.length; i++)
        if (n >= this.ranges[i][0] && n <= this.ranges[i][1]) { ok = true; break; }
      if (!ok)
        return this.label + " " + n + " does not exist on the " +
               (this.meta().label || "selected board") + " (valid: " + this.rangesText + ").";
    } else if (this.rx && !this.rx.test(s)) {
      return "“" + s + "” is not a valid " + this.label + ".";
    }
    return null;
  };
  Addr.prototype.advise = function (raw) {
    var s = this.clean(raw), n = this.isInt ? Number(s) : s, out = [];
    if (s === "") return out;
    for (var i = 0; i < this.rules.length; i++) {
      var r = this.rules[i], hit = false, j;
      if (r.addresses)
        for (j = 0; j < r.addresses.length; j++)
          if (String(r.addresses[j]) === String(n)) { hit = true; break; }
      if (!hit && r.ranges && this.isInt)
        for (j = 0; j < r.ranges.length; j++)
          if (n >= r.ranges[j][0] && n <= r.ranges[j][1]) { hit = true; break; }
      if (!hit && r.pattern && new RegExp(r.pattern).test(String(n))) hit = true;
      if (hit)
        out.push({ level: r.level === "error" ? "error" : "warn",
                   message: String(r.message || "").replace(/\{addr\}/g, String(n)) });
    }
    return out;
  };

  /* --------------------------------------------------------------- model --- */
  function fromConfig(A, cfg) {
    cfg = cfg || {};
    var descs = cfg[A.key] || {};
    var chans = Object.keys(descs).map(function (a) {
      return { id: uid(), addr: String(a), desc: String(descs[a]) };
    });
    var acts = Object.keys(cfg.actuator_definitions || {}).map(function (name) {
      var spec = cfg.actuator_definitions[name] || {};
      if (spec.types) {
        return { id: uid(), name: name, kind: "types", comment: spec.comment || "",
          types: Object.keys(spec.types).map(function (tn) {
            return { id: uid(), name: tn,
              branches: Object.keys(spec.types[tn]).map(function (c) {
                return mkBranch(A, c, spec.types[tn][c]); }) };
          }) };
      }
      return { id: uid(), name: name, kind: "commands", comment: spec.comment || "",
        commands: Object.keys(spec.commands || {}).map(function (c) {
          return mkBranch(A, c, spec.commands[c]); }) };
    });
    return { channels: chans, actuators: acts };
  }
  function mkBranch(A, cmd, b) {
    b = b || {};
    return { id: uid(), cmd: cmd, description: b.description || "",
      actions: (b.actions || []).map(function (a) {
        return { id: uid(), addr: String(a[A.field] != null ? a[A.field] : ""),
                 value: Number(a.value) ? 1 : 0 };
      }) };
  }
  function branchesOf(a) {
    var out = [];
    if (a.kind === "types")
      a.types.forEach(function (t) { t.branches.forEach(function (b) { out.push({ t: t, b: b }); }); });
    else a.commands.forEach(function (b) { out.push({ t: null, b: b }); });
    return out;
  }

  /* ---------------------------------------------------------------- mount -- */
  function mount(opts) {
    var host = opts.el, spec = opts.spec || {}, A = new Addr(spec.binding);
    var st = fromConfig(A, opts.initial || spec.reference || {});
    var lastFindings = [];
    var api = {
      value: function () { return toConfig(); },
      findings: function () { return lastFindings; },
      errors: function () {
        return lastFindings.filter(function (f) { return f.level === "error"; }).length;
      },
      onchange: opts.onchange || null,
      // The board the map was checked against travels with the map: the shell
      // re-checks it against the chip it actually reads off the silicon, and it
      // cannot do that without knowing what the operator was looking at.
      variant: function () { return A.variant; },
      reset: function (cfg) { st = fromConfig(A, cfg || spec.reference || {}); render(); }
    };

    /* The board bar only exists for a family that HAS silicon variants. A
       Modbus coil has no such thing, and an empty selector would be furniture. */
    var boardHTML = "";
    if (A.order.length) {
      boardHTML =
        '<div class="cm-sec cm-board"><div class="cm-boardrow">' +
          '<label class="cm-blabel" for="cm-variant">Board</label>' +
          '<select id="cm-variant" data-cm-f="variant">' +
            A.order.map(function (id) {
              return '<option value="' + esc(id) + '"' + (id === A.variant ? " selected" : "") +
                     ">" + esc((A.variants[id] || {}).label || id) + "</option>";
            }).join("") + "</select>" +
          '<span class="cm-bnote" data-cm="bnote"></span>' +
          '<button type="button" class="cm-ghost" data-cm-add="ref">Pin reference</button>' +
        '</div><div class="cm-refwrap" data-cm="ref" hidden></div></div>';
    }

    host.classList.add("cm");
    host.innerHTML = boardHTML +
      '<div class="cm-sec"><div class="cm-sechead"><h3>Channels</h3>' +
        '<span class="cm-note">One ' + esc(A.label) + ' per piece of equipment. ' +
        'Deleting one removes it from every command that drove it.</span></div>' +
        '<div class="cm-panel"><div class="cm-chead"><span>' + esc(A.label) +
          "</span><span>Equipment</span><span>Pin type</span><span>Driven by</span>" +
          "<span></span></div>" +
        '<div data-cm="chans"></div>' +
        '<div class="cm-addbar"><button type="button" data-cm-add="chan">+ Add channel</button>' +
        "</div></div></div>" +
      '<div class="cm-sec"><div class="cm-sechead"><h3>Actuators</h3>' +
        '<span class="cm-note">What the scheduler can ask for. Commands take UP/DOWN/OFF; ' +
        "typed actuators pick a recipe first, then ON/OFF.</span></div>" +
        '<div data-cm="acts"></div>' +
        '<div style="display:flex;gap:.4rem;flex-wrap:wrap">' +
          '<button type="button" data-cm-add="cmdact">+ Command actuator</button>' +
          '<button type="button" data-cm-add="typact">+ Typed actuator</button></div></div>' +
      '<div class="cm-sec"><div class="cm-sechead"><h3>Validation</h3></div>' +
        '<div class="cm-panel" data-cm="report"></div></div>' +
      '<div class="cm-sec"><div class="cm-sechead"><h3>Generated file</h3>' +
        '<span class="cm-note">Updates as you type. This is what ships to the device.</span></div>' +
        '<div class="cm-panel"><div class="cm-jhead"><span>actuator_config.json</span></div>' +
        '<pre class="cm-out" data-cm="out"></pre></div>' +
        '<div class="cm-bar"><span class="cm-verdict" data-cm="verdict"></span>' +
        '<span data-cm="stats"></span></div></div>';

    var qChans = host.querySelector('[data-cm="chans"]'),
        qActs = host.querySelector('[data-cm="acts"]'),
        qRep = host.querySelector('[data-cm="report"]'),
        qOut = host.querySelector('[data-cm="out"]'),
        qVer = host.querySelector('[data-cm="verdict"]'),
        qStat = host.querySelector('[data-cm="stats"]');

    /* ------------------------------------------------------------ emit ---- */
    function toConfig() {
      var descs = {}, defs = {};
      st.channels.forEach(function (c) { if (c.addr !== "") descs[c.addr] = c.desc; });
      function br(b) {
        return { description: b.description,
          actions: b.actions.filter(function (a) { return a.addr !== ""; })
            .map(function (a) {
              var o = { value: a.value };
              o[A.field] = A.isInt ? Number(a.addr) : a.addr;
              return o;
            }) };
      }
      st.actuators.forEach(function (a) {
        if (!a.name) return;
        if (a.kind === "types") {
          var types = {};
          a.types.forEach(function (t) {
            if (!t.name) return;
            var m = {}; t.branches.forEach(function (b) { m[b.cmd] = br(b); });
            types[t.name] = m;
          });
          defs[a.name] = { comment: a.comment, types: types };
        } else {
          var cs = {}; a.commands.forEach(function (b) { cs[b.cmd] = br(b); });
          defs[a.name] = { comment: a.comment, commands: cs };
        }
      });
      var out = {}; out[A.key] = descs; out.actuator_definitions = defs;
      return out;
    }

    /* -------------------------------------------------------- validate ---- */
    function validate() {
      var F = [], bad = {}, warn = {}, used = {};
      function add(l, m, w, id) {
        F.push({ level: l, message: m, where: w });
        if (id) (l === "error" ? bad : warn)[id] = 1;
      }
      st.actuators.forEach(function (a) {
        branchesOf(a).forEach(function (x) {
          x.b.actions.forEach(function (ac) {
            if (ac.addr !== "") used[ac.addr] = (used[ac.addr] || 0) + 1;
          });
        });
      });

      var declared = {};
      st.channels.forEach(function (c) {
        var w = A.label + " " + (c.addr || "?") + (c.desc ? " · " + c.desc : "");
        if (c.addr === "") { add("error", "Channel has no " + A.label + ".", w, c.id); return; }
        var p = A.problem(c.addr);
        if (p) add("error", p, w, c.id);
        A.advise(c.addr).forEach(function (r) { add(r.level, r.message, w, c.id); });
        if (!c.desc.trim())
          add("warn", "Channel has no equipment name. Setpoint reports will read “" +
              A.label + " " + c.addr + "”.", w, c.id);
        if (declared[c.addr])
          add("error", A.label + " " + c.addr + " is assigned twice. The later channel " +
              "silently wins.", w, c.id);
        declared[c.addr] = 1;
        if (!used[c.addr])
          add("warn", "Nothing drives " + w + ". The channel ships as a label with no " +
              "command behind it.", w, c.id);
      });

      if (!st.actuators.length)
        add("error", "No actuators. The device would subscribe and never act.", "config");

      var names = {};
      st.actuators.forEach(function (a) {
        var an = a.name || "unnamed";
        if (!a.name.trim())
          add("error", "Actuator has no name. The scheduler addresses it by this tag.", an, a.id);
        else if (names[a.name])
          add("error", "Two actuators are both named “" + a.name + "”. The later one wins.", an, a.id);
        names[a.name] = 1;

        var bs = branchesOf(a);
        if (!bs.length) add("error", "Actuator “" + an + "” has no commands at all.", an, a.id);

        bs.forEach(function (x) {
          var b = x.b, w = an + (x.t ? " · " + (x.t.name || "?") : "") + " · " + b.cmd;
          if (!b.actions.length || b.actions.every(function (ac) { return ac.addr === ""; }))
            add("error", "“" + w + "” drives no channel. An empty branch is dropped at " +
                "render time.", w, b.id);
          if (!b.description.trim())
            add("warn", "“" + w + "” has no description. It is what an operator reads in " +
                "the run log.", w, b.id);
          var seen = {};
          b.actions.forEach(function (ac) {
            if (ac.addr === "") { add("error", "An action in “" + w + "” has no channel selected.", w, ac.id); return; }
            if (!declared[ac.addr])
              add("error", "“" + w + "” drives " + A.label + " " + ac.addr + ", which is not " +
                  "a declared channel. The device reports it with no equipment name.", w, ac.id);
            if (seen[ac.addr] !== undefined) {
              if (seen[ac.addr] !== ac.value)
                add("error", "“" + w + "” sets " + A.label + " " + ac.addr + " to both 0 and 1. " +
                    "The last write wins, silently.", w, ac.id);
              else
                add("warn", "“" + w + "” sets " + A.label + " " + ac.addr + " twice with the " +
                    "same value.", w, ac.id);
            }
            seen[ac.addr] = ac.value;
          });
        });

        if (a.kind === "commands") {
          var have = {}, dupe = {};
          a.commands.forEach(function (b) {
            if (dupe[b.cmd]) add("error", "Actuator “" + an + "” declares " + b.cmd + " twice.", an, b.id);
            dupe[b.cmd] = 1; have[b.cmd] = b;
          });
          if (!have.UP)
            add("error", "Actuator “" + an + "” has no UP. The whole actuator is dropped at " +
                "render time, so the scheduler never sees it.", an, a.id);
          if (!have.OFF)
            add("warn", "Actuator “" + an + "” has no OFF. all_off() cannot park it at boot, " +
                "so a reset leaves its equipment wherever the last command left it.", an, a.id);
        } else {
          if (!a.types.length) add("error", "Typed actuator “" + an + "” has no types.", an, a.id);
          var tn = {};
          a.types.forEach(function (t) {
            var w = an + " · " + (t.name || "unnamed");
            if (!t.name.trim())
              add("error", "A type of “" + an + "” has no name. The scheduler selects it by " +
                  "this value.", w, t.id);
            else if (tn[t.name]) add("error", "“" + an + "” declares type “" + t.name + "” twice.", w, t.id);
            tn[t.name] = 1;
            var have = {}, dupe = {};
            t.branches.forEach(function (b) {
              if (dupe[b.cmd]) add("error", "Type “" + w + "” declares " + b.cmd + " twice.", w, b.id);
              dupe[b.cmd] = 1; have[b.cmd] = b;
            });
            if (!have.ON)
              add("error", "Type “" + w + "” has no ON. A type that cannot be switched on is " +
                  "dropped at render time.", w, t.id);
            if (!have.OFF)
              add("warn", "Type “" + w + "” has no OFF, so all_off() cannot park it at boot.", w, t.id);
            if (have.ON && have.OFF) {
              var lit = have.ON.actions.filter(function (ac) { return ac.value === 1; })
                          .map(function (ac) { return ac.addr; });
              var cleared = {};
              have.OFF.actions.forEach(function (ac) { cleared[ac.addr] = ac.value; });
              var stranded = lit.filter(function (p) { return cleared[p] !== 0; });
              if (stranded.length)
                add("error", "“" + w + " OFF” never clears " + A.label + " " + stranded.join(", ") +
                    ", which its own ON energises. The equipment stays on and the device " +
                    "reports success.", w + " · OFF", have.OFF.id);
            }
          });
        }
      });
      return { findings: F, bad: bad, warn: warn, used: used };
    }

    /* ---------------------------------------------------------- render ---- */
    function addrOptions(sel) {
      var html = "", found = false;
      st.channels.forEach(function (c) {
        if (c.addr === "") return;
        if (c.addr === sel) found = true;
        html += '<option value="' + esc(c.addr) + '"' + (c.addr === sel ? " selected" : "") +
                ">" + esc(c.addr) + " — " + esc(c.desc || "unnamed") + "</option>";
      });
      if (sel !== "" && !found)
        html += '<option value="' + esc(sel) + '" selected>' + esc(sel) +
                " — not a declared channel</option>";
      if (sel === "") html = '<option value="" selected>— pick a channel —</option>' + html;
      return html;
    }
    function actionsHTML(b) {
      var h = '<div class="cm-actions">';
      b.actions.forEach(function (ac) {
        h += '<div class="cm-action">' +
          '<select data-cm-f="addr" data-cm-id="' + ac.id + '">' + addrOptions(ac.addr) + "</select>" +
          '<div class="cm-seg" role="group" aria-label="logical value">' +
            '<button type="button" data-cm-v="0" data-cm-id="' + ac.id + '" aria-pressed="' +
              (ac.value === 0) + '">0 · off</button>' +
            '<button type="button" class="cm-on" data-cm-v="1" data-cm-id="' + ac.id +
              '" aria-pressed="' + (ac.value === 1) + '">1 · on</button></div>' +
          '<button type="button" class="cm-x" data-cm-del="action" data-cm-id="' + ac.id +
            '" aria-label="Remove action">&times;</button></div>';
      });
      return h + '<div><button type="button" class="cm-ghost" data-cm-add="action" data-cm-id="' +
        b.id + '">+ Add channel action</button></div></div>';
    }
    function branchHTML(b, opts) {
      return '<div class="cm-branch">' +
        '<div class="cm-bhead">' +
        '<select class="cm-cmd cm-c-' + esc(b.cmd) + '" data-cm-f="cmd" data-cm-id="' + b.id + '">' +
          opts.map(function (c) { return "<option" + (c === b.cmd ? " selected" : "") + ">" + c + "</option>"; }).join("") +
        "</select>" +
        '<input class="cm-text" data-cm-f="bdesc" data-cm-id="' + b.id + '" value="' +
          esc(b.description) + '" placeholder="What this command does, in an operator’s words">' +
        '<button type="button" class="cm-x" data-cm-del="branch" data-cm-id="' + b.id +
          '" aria-label="Remove command">&times;</button></div>' + actionsHTML(b) + "</div>";
    }

    function render() {
      qChans.innerHTML = st.channels.map(function (c) {
        return '<div class="cm-crow" data-cm-chan="' + c.id + '">' +
          '<input data-cm-f="addr-c" data-cm-id="' + c.id + '" value="' + esc(c.addr) +
            '" placeholder="' + esc(spec.binding && spec.binding.placeholder || A.label) + '">' +
          '<input class="cm-text" data-cm-f="cdesc" data-cm-id="' + c.id + '" value="' +
            esc(c.desc) + '" placeholder="What is wired to this channel">' +
          '<span class="cm-ptype" data-cm-ptype="' + c.id + '"></span>' +
          '<span class="cm-use" data-cm-use="' + esc(c.addr) + '"></span>' +
          '<button type="button" class="cm-x" data-cm-del="chan" data-cm-id="' + c.id +
            '" aria-label="Remove channel">&times;</button></div>';
      }).join("") || '<div class="cm-empty">No channels yet.</div>';

      qActs.innerHTML = st.actuators.map(function (a) {
        var body;
        if (a.kind === "types") {
          body = a.types.map(function (t) {
            return '<div class="cm-type"><div class="cm-thead">' +
              '<input data-cm-f="tname" data-cm-id="' + t.id + '" value="' + esc(t.name) +
                '" placeholder="Recipe name, e.g. RED">' +
              '<button type="button" class="cm-x" data-cm-del="type" data-cm-id="' + t.id +
                '" aria-label="Remove type">&times;</button></div>' +
              '<div class="cm-tbody">' + t.branches.map(function (b) { return branchHTML(b, TCMDS); }).join("") +
              '<div style="padding:.4rem 0 .1rem"><button type="button" class="cm-ghost" ' +
                'data-cm-add="branch" data-cm-id="' + t.id + '">+ Add ON/OFF</button></div>' +
              "</div></div>";
          }).join("") +
          '<div><button type="button" class="cm-ghost" data-cm-add="type" data-cm-id="' + a.id +
            '">+ Add type</button></div>';
        } else {
          body = a.commands.map(function (b) { return branchHTML(b, CMDS); }).join("") +
            '<div style="padding:.4rem 0 .1rem"><button type="button" class="cm-ghost" ' +
              'data-cm-add="branch" data-cm-id="' + a.id + '">+ Add UP/DOWN/OFF</button></div>';
        }
        return '<div class="cm-act"><div class="cm-acthead">' +
          '<input data-cm-f="aname" data-cm-id="' + a.id + '" value="' + esc(a.name) +
            '" placeholder="MQTT tag, e.g. air_temperature">' +
          '<select data-cm-f="kind" data-cm-id="' + a.id + '">' +
            '<option value="commands"' + (a.kind === "commands" ? " selected" : "") + ">UP / DOWN / OFF</option>" +
            '<option value="types"' + (a.kind === "types" ? " selected" : "") + ">Typed (ON / OFF)</option>" +
          "</select>" +
          '<button type="button" class="cm-x" data-cm-del="act" data-cm-id="' + a.id +
            '" aria-label="Remove actuator">&times;</button></div>' +
          '<div class="cm-actbody"><div class="cm-comment">' +
            '<input class="cm-text" data-cm-f="comment" data-cm-id="' + a.id + '" value="' +
              esc(a.comment) + '" placeholder="Comment carried into the file"></div>' +
            body + "</div></div>";
      }).join("") || '<div class="cm-panel cm-empty">No actuators yet.</div>';

      refresh();
    }

    /* The pin reference for the selected board: a grid for shape, then the
       flagged pins spelled out, because "GPIO26-32 are flash" is the thing an
       operator needs in words, not a colour they have to hover to decode. */
    function renderRef() {
      var box = host.querySelector('[data-cm="ref"]');
      if (!box) return;
      var rows = A.pinRows(), m = A.meta();
      var notes = [];
      ["absent_note", "flash_note"].forEach(function (k) { if (m[k]) notes.push(m[k]); });
      var flagged = rows.filter(function (r) { return r.level; });

      box.innerHTML =
        '<div class="cm-refhead">' + esc(m.label || A.variant) +
          (m.subtitle ? ' <span class="cm-note">' + esc(m.subtitle) + "</span>" : "") + "</div>" +
        (notes.length ? '<p class="cm-refnote">' + notes.map(esc).join(" ") + "</p>" : "") +
        '<div class="cm-legend">' +
          '<span><i class="cm-sw cm-free"></i>free</span>' +
          '<span><i class="cm-sw cm-cau"></i>in use by something else</span>' +
          '<span><i class="cm-sw cm-un"></i>cannot drive a relay</span></div>' +
        '<div class="cm-grid">' + rows.map(function (r) {
          return '<span class="cm-chip cm-chip-' + (r.level || "free") + '" title="' +
            esc(r.types.join(", ") + (r.notes.length ? " — " + r.notes.join(" ") : "")) +
            '">' + r.pin + "</span>";
        }).join("") + "</div>" +
        (flagged.length
          ? '<table class="cm-reftab"><thead><tr><th>' + esc(A.label) +
            "</th><th>Type</th><th>Why it matters</th></tr></thead><tbody>" +
            flagged.map(function (r) {
              return '<tr class="cm-row-' + r.level + '"><td>' + r.pin + "</td><td>" +
                esc(r.types.join(", ")) + "</td><td>" + esc(r.notes.join(" ")) + "</td></tr>";
            }).join("") + "</tbody></table>"
          : '<p class="cm-refnote">Every pin on this board is free to drive a relay.</p>');
    }

    /* Rebuild the channel <select>s only. Used while a channel address or name
       is being typed, where a full render() would pull focus out of the field. */
    function syncSelects() {
      host.querySelectorAll('select[data-cm-f="addr"]').forEach(function (s) {
        s.innerHTML = addrOptions(s.value);
      });
      st.channels.forEach(function (c) {
        var u = host.querySelector('[data-cm-chan="' + c.id + '"] .cm-use');
        if (u) u.setAttribute("data-cm-use", c.addr);
      });
    }

    function refresh() {
      var cfg = toConfig(), v = validate();
      lastFindings = v.findings;

      qOut.innerHTML = esc(JSON.stringify(cfg, null, 2))
        .replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span class="cm-k">$1</span>$2')
        .replace(/:\s(-?\d+)/g, ': <span class="cm-n">$1</span>');

      host.querySelectorAll("[data-cm-use]").forEach(function (n) {
        var a = n.getAttribute("data-cm-use"), c = v.used[a] || 0;
        n.textContent = c ? c + (c === 1 ? " action" : " actions") : "unused";
        n.classList.toggle("cm-dead", c === 0 && a !== "");
      });

      /* Pre-validation, shown where the address was typed rather than only in
         the report below: what this pin already is on the selected board. */
      host.querySelectorAll("[data-cm-ptype]").forEach(function (n) {
        var c = chan(n.getAttribute("data-cm-ptype"));
        var d = c ? A.describe(c.addr) : null;
        n.textContent = d ? d.types.join(", ") : "";
        n.title = d && d.notes && d.notes.length ? d.notes.join("\n") : "";
        n.className = "cm-ptype" + (d && d.level ? " cm-ptype-" + d.level : "");
      });

      var bn = host.querySelector('[data-cm="bnote"]');
      if (bn) {
        var m = A.meta(), usable = A.pinRows().filter(function (r) { return r.level !== "error"; });
        bn.textContent = A.rangesText + " · " + usable.length + " of " +
          A.pinRows().length + " can drive a relay";
        bn.title = m.subtitle || "";
      }
      host.querySelectorAll(".cm-cmd").forEach(function (n) {
        n.className = "cm-cmd cm-c-" + n.value;
      });
      host.querySelectorAll("input[data-cm-id],select[data-cm-id]").forEach(function (n) {
        var id = n.getAttribute("data-cm-id");
        n.classList.toggle("cm-bad", !!v.bad[id]);
        n.classList.toggle("cm-warn", !v.bad[id] && !!v.warn[id]);
      });

      var errs = v.findings.filter(function (f) { return f.level === "error"; }),
          warns = v.findings.filter(function (f) { return f.level === "warn"; });
      qRep.innerHTML = v.findings.length
        ? errs.concat(warns).map(function (f) {
            return '<div class="cm-find"><span class="cm-tag ' + f.level + '">' +
              (f.level === "error" ? "Error" : "Warn") + "</span><span>" + esc(f.message) +
              '<span class="cm-where">' + esc(f.where) + "</span></span></div>";
          }).join("")
        : '<div class="cm-clean">Nothing to fix. Every command resolves to a declared ' +
          "channel, and every actuator survives the renderer's pruning.</div>";

      qVer.className = "cm-verdict " + (errs.length ? "bad" : warns.length ? "warn" : "ok");
      qVer.textContent = errs.length
        ? errs.length + (errs.length === 1 ? " error" : " errors") +
          (warns.length ? ", " + warns.length + " warning" + (warns.length === 1 ? "" : "s") : "")
        : warns.length ? warns.length + " warning" + (warns.length === 1 ? "" : "s") + ", no errors"
        : "Valid";
      qStat.textContent = Object.keys(cfg[A.key]).length + " channels · " +
        Object.keys(cfg.actuator_definitions).length + " actuators · " +
        st.actuators.reduce(function (s, a) { return s + branchesOf(a).length; }, 0) + " commands";

      if (api.onchange) api.onchange(api);
    }

    /* ---------------------------------------------------------- events ---- */
    function chan(id) { return st.channels.filter(function (c) { return c.id === id; })[0]; }
    function act(id) { return st.actuators.filter(function (a) { return a.id === id; })[0]; }
    function branch(id) {
      for (var i = 0; i < st.actuators.length; i++) {
        var bs = branchesOf(st.actuators[i]);
        for (var j = 0; j < bs.length; j++) if (bs[j].b.id === id) return bs[j];
      }
      return null;
    }
    function action(id) {
      for (var i = 0; i < st.actuators.length; i++) {
        var bs = branchesOf(st.actuators[i]);
        for (var j = 0; j < bs.length; j++)
          for (var k = 0; k < bs[j].b.actions.length; k++)
            if (bs[j].b.actions[k].id === id) return bs[j].b.actions[k];
      }
      return null;
    }

    host.addEventListener("input", function (e) {
      var n = e.target, f = n.getAttribute && n.getAttribute("data-cm-f");
      if (!f) return;
      var id = n.getAttribute("data-cm-id"), o;
      if (f === "addr-c" || f === "cdesc") {
        o = chan(id); if (!o) return;
        if (f === "addr-c") { o.addr = A.clean(n.value); if (n.value !== o.addr) n.value = o.addr; }
        else o.desc = n.value;
        syncSelects(); refresh(); return;
      }
      if (f === "aname" || f === "comment") {
        o = act(id); if (!o) return;
        o[f === "aname" ? "name" : "comment"] = n.value; refresh(); return;
      }
      if (f === "tname") {
        st.actuators.forEach(function (a) {
          if (a.kind === "types") a.types.forEach(function (t) { if (t.id === id) t.name = n.value; });
        });
        refresh(); return;
      }
      if (f === "bdesc") { o = branch(id); if (o) { o.b.description = n.value; refresh(); } }
    });

    host.addEventListener("change", function (e) {
      var n = e.target, f = n.getAttribute && n.getAttribute("data-cm-f");
      if (!f) return;
      var id = n.getAttribute("data-cm-id"), o;
      if (f === "variant") {
        // The map is deliberately kept as-is. Changing board re-checks the same
        // table against different silicon, and the errors that appear are the
        // point — silently dropping the pins the new chip lacks would hide
        // exactly what the operator needs to see.
        A.setVariant(n.value);
        var open = host.querySelector('[data-cm="ref"]');
        if (open && !open.hidden) renderRef();
        refresh(); return;
      }
      if (f === "addr") { o = action(id); if (o) { o.addr = n.value; refresh(); } return; }
      if (f === "cmd") { o = branch(id); if (o) { o.b.cmd = n.value; refresh(); } return; }
      if (f === "kind") {
        var a = act(id); if (!a || a.kind === n.value) return;
        if (n.value === "types") {
          /* Carry the table over rather than discarding what was typed: UP is
             the nearest thing a typed actuator has to "make it happen". */
          var carried = (a.commands || []).map(function (b) {
            return { id: b.id, cmd: b.cmd === "UP" ? "ON" : "OFF",
                     description: b.description, actions: b.actions };
          });
          a.types = [{ id: uid(), name: "", branches: carried.length ? carried :
            [{ id: uid(), cmd: "ON", description: "", actions: [] },
             { id: uid(), cmd: "OFF", description: "", actions: [] }] }];
          delete a.commands;
        } else {
          var first = (a.types && a.types[0]) || { branches: [] };
          var back = first.branches.map(function (b) {
            return { id: b.id, cmd: b.cmd === "ON" ? "UP" : "OFF",
                     description: b.description, actions: b.actions };
          });
          a.commands = back.length ? back :
            [{ id: uid(), cmd: "UP", description: "", actions: [] },
             { id: uid(), cmd: "OFF", description: "", actions: [] }];
          delete a.types;
        }
        a.kind = n.value; render();
      }
    });

    host.addEventListener("click", function (e) {
      var btn = e.target.closest && e.target.closest("button");
      if (!btn || !host.contains(btn)) return;
      var id = btn.getAttribute("data-cm-id"), o;

      if (btn.hasAttribute("data-cm-v")) {
        e.preventDefault();
        o = action(id); if (!o) return;
        o.value = Number(btn.getAttribute("data-cm-v"));
        btn.parentElement.querySelectorAll("button").forEach(function (x) {
          x.setAttribute("aria-pressed", String(Number(x.getAttribute("data-cm-v")) === o.value));
        });
        refresh(); return;
      }

      var add = btn.getAttribute("data-cm-add");
      if (add) e.preventDefault();
      if (add === "ref") {
        var box = host.querySelector('[data-cm="ref"]');
        if (box) {
          box.hidden = !box.hidden;
          btn.textContent = box.hidden ? "Pin reference" : "Hide reference";
          if (!box.hidden) renderRef();
        }
        return;
      }
      if (add === "chan") {
        st.channels.push({ id: uid(), addr: "", desc: "" }); render();
        var rows = host.querySelectorAll('input[data-cm-f="addr-c"]');
        if (rows.length) rows[rows.length - 1].focus();
        return;
      }
      if (add === "action") { o = branch(id); if (o) { o.b.actions.push({ id: uid(), addr: "", value: 0 }); render(); } return; }
      if (add === "branch") {
        var a = act(id), have = {}, next;
        if (a) {
          a.commands.forEach(function (c) { have[c.cmd] = 1; });
          next = CMDS.filter(function (c) { return !have[c]; })[0] || "OFF";
          a.commands.push({ id: uid(), cmd: next, description: "", actions: [] }); render(); return;
        }
        st.actuators.forEach(function (x) {
          if (x.kind !== "types") return;
          x.types.forEach(function (t) {
            if (t.id !== id) return;
            var h = {}; t.branches.forEach(function (c) { h[c.cmd] = 1; });
            t.branches.push({ id: uid(), cmd: TCMDS.filter(function (c) { return !h[c]; })[0] || "OFF",
                              description: "", actions: [] });
          });
        });
        render(); return;
      }
      if (add === "type") {
        o = act(id);
        if (o) {
          o.types.push({ id: uid(), name: "", branches: [
            { id: uid(), cmd: "ON", description: "", actions: [] },
            { id: uid(), cmd: "OFF", description: "", actions: [] }] });
          render();
        }
        return;
      }
      if (add === "cmdact") {
        st.actuators.push({ id: uid(), name: "", kind: "commands", comment: "", commands: [
          { id: uid(), cmd: "UP", description: "", actions: [] },
          { id: uid(), cmd: "DOWN", description: "", actions: [] },
          { id: uid(), cmd: "OFF", description: "", actions: [] }] });
        render(); return;
      }
      if (add === "typact") {
        st.actuators.push({ id: uid(), name: "", kind: "types", comment: "", types: [
          { id: uid(), name: "", branches: [
            { id: uid(), cmd: "ON", description: "", actions: [] },
            { id: uid(), cmd: "OFF", description: "", actions: [] }] }] });
        render(); return;
      }

      var del = btn.getAttribute("data-cm-del");
      if (del) e.preventDefault();
      if (del === "chan") {
        var gone = chan(id);
        st.channels = st.channels.filter(function (c) { return c.id !== id; });
        /* A deleted channel must not linger as a bare address inside a command. */
        if (gone) st.actuators.forEach(function (a) {
          branchesOf(a).forEach(function (x) {
            x.b.actions = x.b.actions.filter(function (ac) { return ac.addr !== gone.addr; });
          });
        });
        render(); return;
      }
      if (del === "act") { st.actuators = st.actuators.filter(function (a) { return a.id !== id; }); render(); return; }
      if (del === "type") {
        st.actuators.forEach(function (a) {
          if (a.kind === "types") a.types = a.types.filter(function (t) { return t.id !== id; });
        });
        render(); return;
      }
      if (del === "branch") {
        st.actuators.forEach(function (a) {
          if (a.kind === "types") a.types.forEach(function (t) {
            t.branches = t.branches.filter(function (b) { return b.id !== id; });
          });
          else a.commands = a.commands.filter(function (b) { return b.id !== id; });
        });
        render(); return;
      }
      if (del === "action") {
        st.actuators.forEach(function (a) {
          branchesOf(a).forEach(function (x) {
            x.b.actions = x.b.actions.filter(function (ac) { return ac.id !== id; });
          });
        });
        render();
      }
    });

    render();
    return api;
  }

  root.ChannelMap = { mount: mount };
})(window);
