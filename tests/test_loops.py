#!/usr/bin/env python3
"""The onboarding wizard's control-loop picker (feedback control Phase 2, Q20; recipe
types, migration 011), offline: edge/src/host/loops.py's rules on every fixture in
tests/fixtures/loops/ (one per code), every database rule's message a literal of
_loop_check()/save_zone_loops() (migration 011), its defaults per half (SENSE binds the
input, CONTROL the output, --loops-only both; one sensor preselected, several in error
until chosen, stored halves kept, half-bound loops said, stale loops said), the
terminal's questions, the CLI, its fallback quantities against
apps/database/recipe_types.yaml, and device_template.py's sense-sources (with UoMs),
actuator-map (with each actuator's quantity) and channelmap quantities. The JS mirror is
tests/test_loops_ui.py.

    python3 -m unittest tests.test_loops
"""
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.path.join(ROOT, "edge", "src", "host")
LOOPS = os.path.join(HOST, "loops.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "loops")
MIGRATIONS = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")
RESOLVER = os.path.join(ROOT, "schd", "cea", "loop_resolver.py")
RECIPE_TYPES = os.path.join(ROOT, "apps", "database", "recipe_types.yaml")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


lp = load(LOOPS, "loops_t")
lr = load(RESOLVER, "loop_resolver_t")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def contexts():
    with open(os.path.join(FIXTURES, "_contexts.json"), encoding="utf-8") as f:
        return json.load(f)


def fixtures():
    return sorted(glob.glob(os.path.join(FIXTURES, "[!_]*.json")))


def fixture_case(path, ctx=None):
    """(spec, answer, expect) of one fixture: the spec built by loops.build_spec from
    the named context, as plan_loops builds it."""
    ctx = ctx or contexts()
    with open(path, encoding="utf-8") as f:
        fx = json.load(f)
    spec = lp.build_spec(fx["role"], ctx[fx["context"]], fx.get("plan_sources"), fx.get("plan_actuators"))
    spec.update(fx.get("spec_patch") or {})
    answer = spec["initial"] if fx["answer"] == "initial" else fx["answer"]
    return spec, answer, fx["expect"]


def triples(findings):
    return sorted((f["level"], f["code"], f["where"]) for f in findings)


class Fixtures(unittest.TestCase):
    def test_every_fixture(self):
        files = fixtures()
        self.assertGreater(len(files), 20)
        ctx = contexts()
        for path in files:
            with self.subTest(fixture=os.path.basename(path)):
                spec, answer, expect = fixture_case(path, ctx)
                got = lp.validate(spec, answer)
                self.assertEqual(triples(got), sorted(tuple(e) for e in expect))
                for f in got:
                    self.assertTrue(f["message"], f)
                    self.assertIn(f["code"], lp.CODES)

    def test_every_code_has_a_fixture(self):
        seen = set()
        for path in fixtures():
            with open(path, encoding="utf-8") as f:
                seen |= {e[1] for e in json.load(f)["expect"]}
        self.assertEqual(sorted(set(lp.CODES) - seen), [])

    def test_fixtures_are_one_space_json(self):
        for path in fixtures() + [os.path.join(FIXTURES, "_contexts.json")]:
            with self.subTest(path=os.path.basename(path)):
                raw = read(path)
                self.assertEqual(raw, json.dumps(json.loads(raw), indent=1) + "\n")


def fn_body(sql, name):
    """The LAST definition of a function in the migrations (011 replaces 010's)."""
    bodies = re.findall(r"CREATE OR REPLACE FUNCTION %s\(.*?END \$\$;" % re.escape(name), sql, re.S)
    if not bodies:
        raise AssertionError("no %s in the migrations" % name)
    return bodies[-1]


def db_templates():
    """Every string literal of _loop_check() and save_zone_loops() as a regex: a
    format()'s %s matches any text."""
    sql = read(MIGRATIONS)
    out = []
    for name in ("medcea._loop_check", "medcea.save_zone_loops"):
        for lit in re.findall(r"'((?:[^']|'')*)'", fn_body(sql, name)):
            lit = lit.replace("''", "'")
            if len(lit) < 12:
                continue
            out.append(re.compile("^(?:[a-z][a-z0-9_]*: )?%s$" % re.escape(lit).replace("%s", ".+")))
    return out


class Parity(unittest.TestCase):
    """The picker's rules are the database's (migration 011's _loop_check and
    save_zone_loops), and its fallback quantities are recipe_types.yaml's."""

    def test_fallback_is_the_catalogue(self):
        import yaml
        with open(RECIPE_TYPES, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        plant = next(t for t in doc["recipe_types"] if t["code"] == "PLANT")["quantities"]
        want = []
        for q in doc["quantities"]:
            if not q["loopable"] or q["code"] not in plant:
                continue
            d = {"loop_code": q["code"], "label": q["label"], "unit": q["unit"], "tag": q["default_tag"],
                 "sense_uoms": q["sense_uoms"], "commands": sorted(q["commands"]), "phase": q["phase"],
                 "loopable": True, "required": plant[q["code"]]}
            if q.get("command_map"):
                d["command_map"] = q["command_map"]
            want.append(d)
        self.assertEqual(lp.FALLBACK_QUANTITIES, want)

    def test_context_quantities_follow_the_catalogue_order(self):
        qs = lp.quantities_of(contexts()["bench"])
        self.assertEqual([q["loop_code"] for q in qs],
                         ["air_temperature", "air_humidity", "co2", "substrate_temperature", "light_intensity"])
        self.assertEqual([q["loopable"] for q in qs], [True, True, True, True, False])
        self.assertEqual([r["loop_code"] for r in lp.build_spec("ZONE", contexts()["bench"])["rows"]],
                         ["air_temperature", "air_humidity", "co2", "substrate_temperature"])   # no light_intensity row
        self.assertEqual(lp.quantities_of({})[:4], [dict(q, sends=lp.sends(q)) for q in lp.FALLBACK_QUANTITIES])
        self.assertEqual(lp.quantities_of({"allowed": {"quantities": {}}}), [])     # a type with no quantity

    def test_co2_map_is_f11(self):
        q = {x["loop_code"]: x for x in lp.FALLBACK_QUANTITIES}
        self.assertEqual(q["co2"]["command_map"], {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"})
        self.assertEqual(lp.sends(q["co2"]), ["OFF", "UP"])
        self.assertEqual(lp.sends(q["air_humidity"]), ["DOWN", "OFF", "UP"])
        self.assertEqual(q["substrate_temperature"]["tag"], "ground_temperature")   # F1
        self.assertEqual(lp.jsonb_text(q["co2"]["command_map"]), '{"UP": "OFF", "OFF": "OFF", "DOWN": "UP"}')

    def test_rules_as_the_database(self):
        sql = read(MIGRATIONS)
        body = fn_body(sql, "medcea._loop_check")
        self.assertIn("ARRAY['reference', 'mean', 'min', 'max']", body)
        self.assertIn("n < 1 OR n > 3600", body)
        self.assertIn("ARRAY['loop_code', 'input', 'output']", body)
        self.assertIn("ARRAY['tag', 'sources', 'rule', 'reference', 'fallback', 'max_age_s']", body)
        self.assertIn("ARRAY['actuator', 'mode', 'command_map']", body)
        self.assertIn("(inp ->> 'tag') !~ '%s'" % lp.TAG_RE.pattern, body)
        self.assertIn("IF s = 'default' THEN", body)
        self.assertIn("> 50 THEN", body)
        self.assertEqual(list(lp.LOOP_KEYS), ["loop_code", "input", "output"])
        self.assertEqual(list(lp.INPUT_KEYS), ["tag", "sources", "rule", "reference", "fallback", "max_age_s"])
        self.assertEqual(list(lp.OUTPUT_KEYS), ["actuator", "mode", "command_map"])
        self.assertEqual(tuple(lp.RULES), tuple(lr.RULES))
        self.assertEqual((lp.MAX_AGE_MAX, lp.MAX_AGE_DEFAULT, lp.RESERVED, lp.STATE_KEY_MAX),
                         (lr.MAX_AGE_LIMIT_S, lr.DEFAULT_MAX_AGE_S, lr.RESERVED_SENSOR, lr.STATE_KEY_MAX))
        save = fn_body(sql, "medcea.save_zone_loops")
        self.assertIn("is driven by another loop of the zone", save)     # L_ACTUATOR_SHARED
        self.assertIn("listed twice", save)                              # L_DUP
        self.assertIn("jsonb_array_length(lst) > 16", save)              # MAX_LOOPS
        self.assertIn("p_loops ->> 'half' IN ('input', 'output', 'both')", save)
        self.assertEqual(lp.MAX_LOOPS, 16)
        self.assertEqual(sorted(lp.HALVES.values()), ["both", "input", "output"])

    def test_every_rule_message_is_the_databases(self):
        """Every finding of a database rule (all but the picker's own: the answer's shape,
        L_EMPTY, L_CHOOSE, and the warnings) is word for word a literal of _loop_check()
        or save_zone_loops(), %s standing for its values."""
        templates = db_templates()
        ctx = contexts()
        seen = set()
        for path in fixtures():
            spec, answer, _ = fixture_case(path, ctx)
            for f in lp.validate(spec, answer):
                if f["level"] != "error" or f["code"] in ("L_EMPTY", "L_CHOOSE") \
                        or (f["code"] == "L_SCHEMA" and not f["where"].startswith("loops.")):
                    continue
                with self.subTest(fixture=os.path.basename(path), message=f["message"]):
                    self.assertTrue(any(t.match(f["message"]) for t in templates), f["message"])
                seen.add(f["code"])
        mirrored = {c for c in lp.CODES if c.startswith("L_") and c not in ("L_EMPTY", "L_CHOOSE")}
        self.assertEqual(sorted(mirrored - seen), [])

    def test_instance_rule_as_the_database(self):
        inv = fn_body(read(MIGRATIONS), "medcea._zone_inventory")
        self.assertIn("tg.seg[6] !~ '%s'" % lp.INSTANCE_RE.pattern, inv)
        self.assertIn("WHEN tg.seg[6] = 'default' THEN 'reserved'", inv)
        self.assertIn("'quantity', CASE WHEN jsonb_typeof(e.value -> 'quantity') = 'string'", inv)
        self.assertIn("'uoms', s.uoms", inv)


class Instances(unittest.TestCase):
    def test_topics(self):
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/scd30_1", "co2"), ("named", "scd30_1"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2", "co2"), ("old", None))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/default", "co2"), ("reserved", "default"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/SCD", "co2"), ("bad", "SCD"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/scd30_1", "co2", "scd30_2"), ("mismatch", "scd30_1"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/rh/scd30_1", "co2"), ("bad", None))


class SenseSourcesAndActuatorMap(unittest.TestCase):
    """device_template.py's helpers name what render() writes."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, HOST)
        cls.dt = load(os.path.join(HOST, "device_template.py"), "device_template_t")

    def run_dt(self, args, stdin):
        r = subprocess.run([sys.executable, os.path.join(HOST, "device_template.py")] + args,
                           input=stdin, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def rendered_instances(self, comps):
        return [(c["parameters"]["tags"][0]["topic"].rsplit("/", 1)[-1],
                 [t["tag"] for t in c["parameters"]["tags"]],
                 {t["tag"]: t["UoM"] or None for t in c["parameters"]["tags"]}) for c in comps]

    def test_wired_board(self):
        doc = json.loads(read(os.path.join(ROOT, "edge", "templates", "boards",
                                           "sense-hub-bench-sht45-scd30.json")))["wiring"]
        got = self.run_dt(["sense-sources", "SENSE"], json.dumps({"wiring": doc, "variant": "esp32s3"}))
        self.assertEqual([(g["instance"], g["tags"], g["uoms"]) for g in got],
                         [("sht45_1", ["air_temperature", "air_humidity"], {"air_temperature": "C", "air_humidity": "RH%"}),
                          ("scd30_1", ["co2", "air_temperature", "air_humidity"],
                           {"co2": "ppm", "air_temperature": "C", "air_humidity": "RH%"})])
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            comps = self.dt.render({"out_dir": d, "role": "SENSE", "hostname": "x", "unit_code": "UNIT01",
                                    "zone_code": "ZONE01", "wiring": doc, "variant": "esp32s3"})["components"]
        self.assertEqual([(g["instance"], g["tags"], g["uoms"]) for g in got], self.rendered_instances(comps))
        for c in comps:      # the topic's sensor is the component's declared instance
            self.assertEqual(c["parameters"]["instance"], c["parameters"]["tags"][0]["topic"].rsplit("/", 1)[-1])

    def test_legacy_questions(self):
        tsv = "scd30\t\t\nground_temperature\tdata_pin\t17\n"
        got = self.run_dt(["sense-sources", "SENSE"], json.dumps({"sensors_tsv": tsv}))
        self.assertEqual([g["instance"] for g in got], ["scd30", "ground_temperature"])
        self.assertEqual(got[1]["tags"], ["ground_temperature"])
        self.assertEqual(got[1]["uoms"], {"ground_temperature": "C"})

    def reference_pins(self):
        r = subprocess.run([sys.executable, os.path.join(HOST, "device_template.py"), "functions", "CONTROL", "relay8"],
                           capture_output=True, text=True, timeout=60)
        return "".join("%s\t%s\n" % (l.split("\t")[1], l.split("\t")[3]) for l in r.stdout.splitlines()
                       if l.startswith("FUNC\t") and l.split("\t")[3])

    def test_actuator_map_equals_render(self):
        tsv = self.reference_pins()
        got = self.run_dt(["actuator-map", "CONTROL", "relay8"], tsv)
        import tempfile
        pins = dict(l.split("\t") for l in tsv.splitlines())
        with tempfile.TemporaryDirectory() as d:
            comps = self.dt.render({"out_dir": d, "role": "CONTROL", "hostname": "x", "unit_code": "U",
                                    "zone_code": "Z", "functions": pins})["components"]
        self.assertEqual(got["actuator_definitions"], comps[0]["parameters"]["actuator_definitions"])
        acts = {a["name"]: a for a in lp.actuators_from_definitions(got["actuator_definitions"])}
        self.assertEqual((acts["light"]["kind"], acts["light"]["quantity"]), ("types", None))   # never a loop's
        for q in lp.FALLBACK_QUANTITIES:
            a = acts[q["loop_code"]]
            self.assertEqual((a["kind"], a["quantity"]), ("commands", q["loop_code"]))
            self.assertTrue(set(lp.sends(q)) <= set(a["commands"]))

    def test_the_template_declares_quantities(self):
        tpl = json.loads(read(os.path.join(ROOT, "edge", "templates", "esp32-control.json")))
        for d in tpl["drivers"]:
            for name, a in d["actuators"].items():
                with self.subTest(actuator=name):
                    if a["kind"] == "commands":
                        self.assertEqual(a["quantity"], name)
                    else:
                        self.assertNotIn("quantity", a)
        codes = {q["loop_code"] for q in lp.FALLBACK_QUANTITIES}
        self.assertEqual(codes, {a["quantity"] for d in tpl["drivers"] for a in d["actuators"].values()
                                 if a["kind"] == "commands"})

    def test_channelmap_offers_the_loopable_quantities(self):
        spec = self.run_dt(["channelmap", "CONTROL", "relay8"], "")
        self.assertEqual([q["code"] for q in spec["quantities"]], [q["loop_code"] for q in lp.FALLBACK_QUANTITIES])
        self.assertEqual(spec["reference"]["actuator_definitions"]["co2"]["quantity"], "co2")
        self.assertNotIn("quantity", spec["reference"]["actuator_definitions"]["light"])

    def test_an_edited_table_keeps_and_checks_the_quantity(self):
        import bindings
        b = bindings.from_template(self.dt.load("CONTROL"), self.dt.TEMPLATE_DIR)
        cfg = {"pin_descriptions": {"5": "fan"}, "actuator_definitions": {
            "vent": {"comment": "", "quantity": " co2 ",
                     "commands": {"UP": {"description": "up", "actions": [{"pin": "5", "value": 1}]},
                                  "OFF": {"description": "off", "actions": [{"pin": "5", "value": 0}]}}}}}
        out = self.dt._normalise_config(b, cfg)
        self.assertEqual(out["actuator_definitions"]["vent"]["quantity"], "co2")
        self.assertEqual([f for f in bindings.validate_config(b, out) if f["level"] == "error"], [])
        bad = json.loads(json.dumps(out))
        bad["actuator_definitions"]["vent"]["quantity"] = "CO2!"
        self.assertTrue(any("is no quantity code" in f["message"] for f in bindings.validate_config(b, bad)))
        bad = {"pin_descriptions": {"5": "lamp"}, "actuator_definitions": {
            "lamp": {"quantity": "light", "types": {"RED": {
                "ON": {"description": "on", "actions": [{"pin": 5, "value": 1}]},
                "OFF": {"description": "off", "actions": [{"pin": 5, "value": 0}]}}}}}}
        self.assertTrue(any("Only an UP/DOWN/OFF actuator acts on a quantity" in f["message"]
                            for f in bindings.validate_config(b, bad)))
        self.assertNotIn("quantity", self.dt._normalise_config(b, bad)["actuator_definitions"]["lamp"])

    def test_actuator_map_without_a_humidifier(self):
        tsv = "".join(l + "\n" for l in self.reference_pins().splitlines() if not l.startswith("air_humidifier"))
        got = self.run_dt(["actuator-map", "CONTROL", "relay8"], tsv)
        self.assertNotIn("air_humidity", got["actuator_definitions"])


class Defaults(unittest.TestCase):
    def setUp(self):
        self.ctx = contexts()

    def rows(self, spec):
        return {r["loop_code"]: r for r in spec["rows"]}

    def test_one_sensor_is_preselected(self):
        spec = lp.build_spec("ZONE", self.ctx["single"])
        rows = self.rows(spec)
        self.assertEqual(spec["half"], "both")
        self.assertEqual(rows["co2"]["loop"]["input"],
                         {"tag": "co2", "sources": ["scd30"], "rule": "reference", "reference": "scd30", "max_age_s": 90})
        self.assertEqual(rows["co2"]["loop"]["output"],
                         {"actuator": "co2", "mode": "command", "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}})
        self.assertTrue(all(r["ticked"] for r in spec["rows"]))
        self.assertEqual(lp.validate(spec, spec["initial"]), [])

    def test_two_sensors_choose_nothing(self):
        spec = lp.build_spec("ZONE", self.ctx["bench"])
        rh = self.rows(spec)["air_humidity"]
        self.assertEqual(rh["candidates"], ["scd30_1", "sht45_1"])
        self.assertIsNone(rh["loop"]["input"]["reference"])
        self.assertEqual(rh["loop"]["input"]["sources"], [])
        codes = {f["code"] for f in lp.validate(spec, spec["initial"])}
        self.assertEqual(codes, {"L_CHOOSE"})

    def test_the_tag_is_a_choice_in_the_right_unit(self):
        spec = lp.build_spec("ZONE", self.ctx["bench"])
        sub = self.rows(spec)["substrate_temperature"]
        # no ground_temperature on the bench: the air temperature tags (C) are offered, nothing ticked
        self.assertEqual([(p["instance"], p["tag"]) for p in sub["pairs"]],
                         [("scd30_1", "air_temperature"), ("sht45_1", "air_temperature")])
        self.assertEqual((sub["offered"], sub["ticked"], sub["default_tag"]), (True, False, None))
        at = self.rows(spec)["air_temperature"]
        self.assertEqual({p["tag"] for p in at["pairs"]}, {"air_temperature"})       # never RH% or ppm
        self.assertEqual(lp.candidates(spec, "air_temperature", "air_humidity"), [])

    def test_declared_actuators_first(self):
        ctx = json.loads(json.dumps(self.ctx["single"]))
        ctx["actuators"].append({"actuator": "fan2", "kind": "commands", "commands": ["DOWN", "OFF", "UP"],
                                 "quantity": None})
        spec = lp.build_spec("ZONE", ctx)
        rows = self.rows(spec)
        self.assertEqual((rows["co2"]["actuators"], rows["co2"]["default_actuator"]), (["co2"], "co2"))
        ctx["actuators"] = [a for a in ctx["actuators"] if a["actuator"] in ("fan2", "light")]
        rows = self.rows(lp.build_spec("ZONE", ctx))
        # undeclared: fits by its commands, never a default for a quantity it is not named after
        self.assertEqual((rows["co2"]["actuators"], rows["co2"]["default_actuator"]), (["fan2"], None))
        self.assertFalse(rows["co2"]["ticked"])

    def test_no_actuator_no_output_side(self):
        ctx = dict(self.ctx["single"], actuators=[a for a in self.ctx["single"]["actuators"] if a["kind"] != "commands"])
        rows = self.rows(lp.build_spec("ZONE", ctx))
        self.assertTrue(rows["co2"]["offered"])                 # the sensor side alone is offered
        self.assertFalse(rows["co2"]["ticked"])
        rows = self.rows(lp.build_spec("CONTROL", ctx, plan_actuators={"actuator_definitions": {}}))
        self.assertFalse(rows["co2"]["offered"])
        self.assertIn("no actuator", rows["co2"]["reason"])

    def test_sense_half_alone(self):
        plan = [{"instance": "scd30_1", "driver": "scd30", "tags": ["co2", "air_temperature", "air_humidity"],
                 "uoms": {"co2": "ppm", "air_temperature": "C", "air_humidity": "RH%"}}]
        spec = lp.build_spec("SENSE", self.ctx["sense_only"], plan)
        self.assertEqual(spec["half"], "input")
        self.assertEqual([l["loop_code"] for l in spec["initial"]["loops"]], ["air_temperature", "air_humidity", "co2"])
        for l in spec["initial"]["loops"]:
            self.assertEqual(sorted(l), ["input", "loop_code"])
        self.assertEqual({f["code"] for f in lp.validate(spec, spec["initial"])}, {"W_HALF_BOUND"})
        self.assertEqual(lp.payload(spec["initial"])["half"], "input")

    def test_control_half_alone(self):
        acts = {"actuator_definitions": {c: {"quantity": c, "commands": {"UP": {}, "DOWN": {}, "OFF": {}}}
                                         for c in ("air_temperature", "co2")}}
        spec = lp.build_spec("CONTROL", self.ctx["control_only"], plan_actuators=acts)
        self.assertEqual(spec["half"], "output")
        self.assertEqual([(l["loop_code"], sorted(l)) for l in spec["initial"]["loops"]],
                         [("air_temperature", ["loop_code", "output"]), ("co2", ["loop_code", "output"])])
        self.assertEqual({f["code"] for f in lp.validate(spec, spec["initial"])}, {"W_HALF_BOUND"})

    def test_half_bound_rows_are_said_and_completed(self):
        spec = lp.build_spec("ZONE", self.ctx["halfbound"])
        rows = self.rows(spec)
        self.assertEqual((rows["air_humidity"]["has_input"], rows["air_humidity"]["has_output"],
                          rows["air_humidity"]["live"]), (True, False, False))
        self.assertEqual(rows["air_humidity"]["loop"], {"loop_code": "air_humidity",
                                                        "input": self.ctx["halfbound"]["loops"][0]["input"]})
        acts = {"actuator_definitions": {"air_humidity": {"quantity": "air_humidity",
                                                          "commands": {"UP": {}, "DOWN": {}, "OFF": {}}}}}
        spec = lp.build_spec("CONTROL", self.ctx["halfbound"], plan_actuators=acts)
        rows = self.rows(spec)
        # the CONTROL board's output completes the loop the SENSE board bound
        self.assertTrue(rows["air_humidity"]["ticked"])
        self.assertEqual(rows["air_humidity"]["loop"]["output"]["actuator"], "air_humidity")
        hb = [f for f in lp.validate(spec, spec["initial"]) if f["code"] == "W_HALF_BOUND"]
        self.assertNotIn("loops.air_humidity", [f["where"] for f in hb])

    def test_stored_loops_kept_and_new_rows_unticked(self):
        spec = lp.build_spec("ZONE", self.ctx["existing"])
        rows = self.rows(spec)
        self.assertTrue(rows["air_humidity"]["ticked"] and rows["air_humidity"]["existing"])
        stored = {k: self.ctx["existing"]["loops"][0][k] for k in lp.LOOP_KEYS}
        self.assertEqual(rows["air_humidity"]["loop"], stored)
        self.assertTrue(rows["air_humidity"]["live"])
        self.assertTrue(rows["air_temperature"]["offered"])
        self.assertFalse(rows["air_temperature"]["ticked"])    # nothing added without a click
        self.assertEqual([l["loop_code"] for l in spec["initial"]["loops"]], ["air_humidity", "co2"])
        self.assertEqual({f["code"] for f in lp.validate(spec, spec["initial"])}, {"W_NOT_CONTROLLED"})

    def test_stale_is_said_and_kept(self):
        plan = [{"instance": "scd30_1", "driver": "scd30", "tags": ["co2", "air_temperature", "air_humidity"],
                 "uoms": {"co2": "ppm", "air_temperature": "C", "air_humidity": "RH%"}}]
        spec = lp.build_spec("SENSE", self.ctx["existing"], plan)
        self.assertEqual([s["loop_code"] for s in spec["stale"]], ["air_humidity"])
        self.assertEqual(spec["stale"][0]["missing_sources"], ["sht45_1"])
        self.assertIn("sht45_1", spec["stale"][0]["message"])
        self.assertIn("air_humidity", [l["loop_code"] for l in spec["initial"]["loops"]])   # never dropped silently
        self.assertEqual(spec["sources"][0]["from"], "plan")

    def test_sense_plan_drops_reserved_names(self):
        plan = [{"instance": "default", "driver": "scd30", "tags": ["co2"]}]
        spec = lp.build_spec("SENSE", self.ctx["single"], plan)
        self.assertEqual(spec["sources"], [])
        self.assertTrue(spec["sensor_problems"])

    def test_row_for_follows_the_choice(self):
        spec = lp.build_spec("ZONE", self.ctx["bench"])
        st = {"tag": "air_humidity", "rule": "reference", "reference": "sht45_1", "fallback": "scd30_1",
              "max_age_s": 60, "actuator": "air_humidity"}
        self.assertEqual(lp.row_for(spec, "air_humidity", st)["input"],
                         {"tag": "air_humidity", "sources": ["sht45_1", "scd30_1"], "rule": "reference",
                          "reference": "sht45_1", "fallback": "scd30_1", "max_age_s": 60})
        st = {"tag": "air_humidity", "rule": "max", "sensors": ["sht45_1"], "max_age_s": 90, "actuator": "air_humidity"}
        self.assertEqual(lp.row_for(spec, "air_humidity", st)["input"],
                         {"tag": "air_humidity", "sources": ["sht45_1"], "rule": "max", "max_age_s": 90})
        self.assertNotIn("output", lp.row_for(spec, "air_humidity", dict(st, output=False)))
        stored = self.ctx["existing"]["loops"][0]
        row = {k: stored[k] for k in lp.LOOP_KEYS}
        self.assertEqual(lp.row_for(spec, "air_humidity", lp.state_of(row)), row)


class Terminal(unittest.TestCase):
    def test_questions_options_answer(self):
        spec = lp.build_spec("ZONE", contexts()["bench"])
        qs = lp.questions(spec)
        self.assertEqual([q[1] for q in qs if q[0] == "Q"], ["air_temperature", "air_humidity"])
        self.assertIn(("INFO", "co2 controls on scd30_1, its only sensor"), qs)
        self.assertIn(("INFO", "co2 acts through co2"), qs)
        self.assertEqual([o[0] for o in lp.options(spec, "air_humidity")],
                         ["ref:scd30_1", "ref:sht45_1", "mean", "min", "max", "off"])
        self.assertEqual([o[0] for o in lp.options(spec, "air_humidity", "sht45_1")], ["fb:", "fb:scd30_1"])
        ans = lp.terminal_answer(spec, ["air_humidity\tref:sht45_1\tfb:scd30_1", "air_temperature\toff"])
        self.assertEqual(ans["half"], "both")
        self.assertEqual([l["loop_code"] for l in ans["loops"]], ["air_humidity", "co2"])
        self.assertEqual(lp.validate(spec, ans), [f for f in lp.validate(spec, ans) if f["level"] == "warn"])
        self.assertEqual(lp.terminal_answer(spec, ["air_humidity\toff", "air_temperature\toff",
                                                   "co2\toff"]), {"skip": True})

    def test_an_actuator_question(self):
        ctx = json.loads(json.dumps(contexts()["single"]))
        for a in ctx["actuators"]:
            if a["actuator"] == "co2":
                a["quantity"] = None
                a["actuator"] = "fan_a"
        ctx["actuators"].append({"actuator": "fan_b", "kind": "commands", "commands": ["DOWN", "OFF", "UP"],
                                 "quantity": None})
        spec = lp.build_spec("CONTROL", ctx, plan_actuators={"actuator_definitions": {
            n: {"commands": {"UP": {}, "DOWN": {}, "OFF": {}}} for n in ("fan_a", "fan_b")}})
        rows = {r["loop_code"]: r for r in spec["rows"]}
        self.assertEqual((rows["co2"]["actuators"], rows["co2"]["default_actuator"], rows["co2"]["ticked"]),
                         (["fan_a", "fan_b"], None, False))
        # ticked by the person in the browser; in the terminal it is asked
        spec["rows"][2]["ticked"] = True
        self.assertIn(("Q", "co2", "co2 can act through fan_a, fan_b: which one?"), lp.questions(spec))
        self.assertEqual([o[0] for o in lp.options(spec, "co2")], ["act:fan_a", "act:fan_b", "off"])
        ans = lp.terminal_answer(spec, ["co2\tact:fan_b"])
        self.assertEqual(ans["loops"], [{"loop_code": "co2", "output": {
            "actuator": "fan_b", "mode": "command", "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}}}])
        zspec = lp.build_spec("ZONE", ctx)
        self.assertEqual([o[0] for o in lp.options(zspec, "co2:output")], ["act:fan_a", "act:fan_b", "off"])

    def test_result_text(self):
        self.assertEqual(lp.result_text({"changed": True, "inserted": [{"loop_code": "co2"}], "updated": [],
                                         "deactivated": [{"loop_code": "air_humidity"}], "unchanged": []}),
                         "control loops saved: created co2; stopped air_humidity")
        self.assertEqual(lp.result_text({"changed": False, "unchanged": [{"loop_code": "co2"}]}),
                         "control loops unchanged (co2)")


class Cli(unittest.TestCase):
    def run_cli(self, args, stdin=""):
        return subprocess.run([sys.executable, LOOPS] + args, input=stdin, capture_output=True, text=True,
                              timeout=60)

    def test_spec_validate_payload(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ctxf = os.path.join(d, "ctx.json")
            with open(ctxf, "w") as f:
                json.dump(contexts()["bench"], f)
            r = self.run_cli(["spec", "ZONE", "--context", ctxf])
            self.assertEqual(r.returncode, 0, r.stderr)
            spec = json.loads(r.stdout)
            specf = os.path.join(d, "spec.json")
            with open(specf, "w") as f:
                json.dump(spec, f)
            r = self.run_cli(["validate", "--spec", specf], json.dumps(spec["initial"]))
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["errors"], 2)
            r = self.run_cli(["validate", "--spec", specf], '{"skip": true}')
            self.assertEqual(r.returncode, 0)
            r = self.run_cli(["validate", "--spec", specf], "not json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(self.run_cli(["payload"], '{"skip": true}').stdout.strip(), "skip")
            self.assertEqual(json.loads(self.run_cli(["payload"], '{"skip": false, "half": "input", "loops": []}').stdout),
                             {"half": "input", "loops": []})
            r = self.run_cli(["payload"], '{"skip": false, "loops": []}')
            self.assertEqual(r.returncode, 2)               # never a payload without its half
            self.assertIn("no half", r.stderr)


if __name__ == "__main__":
    unittest.main()
