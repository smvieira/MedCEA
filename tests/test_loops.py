#!/usr/bin/env python3
"""The onboarding wizard's control-loop picker (feedback control Phase 2, Q20), offline:
edge/src/host/loops.py's rules on every fixture in tests/fixtures/loops/ (one per code),
its defaults (one sensor preselected, several in error until chosen, stored loops kept,
stale loops said), the terminal's questions, the CLI, and its parity with the two other
copies of the loop table: the database's _loop_quantities()/_loop_problems() (migration
010) and the runner's schd/cea/loop_resolver.py. Also device_template.py's sense-sources
and actuator-map against render(). The JS mirror is tests/test_loops_ui.py.

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
DDL = os.path.join(ROOT, "apps", "database", "medcea_db_ddl.sql")
RESOLVER = os.path.join(ROOT, "schd", "cea", "loop_resolver.py")


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


class Parity(unittest.TestCase):
    """loops.QUANTITIES, the database's _loop_quantities() and the runner's QUANTITIES
    are one table (Phase 5 extends all three together)."""

    def db_table(self):
        m = re.search(r"FUNCTION medcea\._loop_quantities\(\).*?SELECT '(.*?)'::jsonb", read(MIGRATIONS), re.S)
        self.assertIsNotNone(m)
        return json.loads(m.group(1))

    def mine(self):
        out = {}
        for q in lp.QUANTITIES:
            d = {k: q[k] for k in ("tag", "recipe_lower", "recipe_upper")}
            if q.get("command_map"):
                d["command_map"] = q["command_map"]
            out[q["loop_code"]] = d
        return out

    def test_same_table_as_the_database(self):
        self.assertEqual(self.mine(), self.db_table())

    def test_same_table_as_the_runner(self):
        self.assertEqual(self.mine(), lr.QUANTITIES)
        # the runner's default map drives the actuator named after the loop_code; so does
        # the picker's default row
        for q in lp.QUANTITIES:
            d = lr.default_loop("ZONE01", q["loop_code"])
            self.assertEqual(d["output"]["actuator"], q["actuator"])
            self.assertEqual(d["output"].get("command_map"), q.get("command_map"))

    def test_co2_map_is_f11(self):
        self.assertEqual(lp.QMAP["co2"]["command_map"], {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"})
        self.assertEqual(lp.sends(lp.QMAP["co2"]), ["OFF", "UP"])
        self.assertEqual(lp.sends(lp.QMAP["air_humidity"]), ["DOWN", "OFF", "UP"])
        self.assertEqual(lp.QMAP["substrate_temperature"]["tag"], "ground_temperature")   # F1

    def test_rules_and_limits_as_the_database_and_runner(self):
        sql = read(MIGRATIONS)
        body = re.search(r"FUNCTION medcea\._loop_problems\(.*?END \$\$;", sql, re.S).group(0)
        self.assertIn("ARRAY['reference', 'mean', 'min', 'max']", body)
        self.assertIn("n < 1 OR n > 3600", body)
        self.assertIn("ARRAY['loop_code', 'recipe_lower', 'recipe_upper', 'input', 'output']", body)
        self.assertIn("ARRAY['tag', 'sources', 'rule', 'reference', 'fallback', 'max_age_s']", body)
        self.assertIn("ARRAY['actuator', 'mode', 'command_map']", body)
        self.assertIn("IF s = 'default' THEN", body)
        self.assertIn("> 50 THEN", body)
        self.assertEqual(list(lp.LOOP_KEYS), ["loop_code", "recipe_lower", "recipe_upper", "input", "output"])
        self.assertEqual(list(lp.INPUT_KEYS), ["tag", "sources", "rule", "reference", "fallback", "max_age_s"])
        self.assertEqual(list(lp.OUTPUT_KEYS), ["actuator", "mode", "command_map"])
        self.assertEqual(tuple(lp.RULES), tuple(lr.RULES))
        self.assertEqual((lp.MAX_AGE_MAX, lp.MAX_AGE_DEFAULT, lp.RESERVED, lp.STATE_KEY_MAX),
                         (lr.MAX_AGE_LIMIT_S, lr.DEFAULT_MAX_AGE_S, lr.RESERVED_SENSOR, lr.STATE_KEY_MAX))
        save = re.search(r"FUNCTION medcea\.save_zone_loops\(.*?END \$\$;", sql, re.S).group(0)
        self.assertIn("is driven by another loop of the zone", save)     # L_ACTUATOR_SHARED
        self.assertIn("listed twice", save)                              # L_DUP
        self.assertIn("jsonb_array_length(p_loops) > 16", save)          # MAX_LOOPS
        self.assertEqual(lp.MAX_LOOPS, 16)

    def test_instance_rule_as_the_database(self):
        inv = re.search(r"FUNCTION medcea\._zone_inventory\(.*?END \$\$;", read(MIGRATIONS), re.S).group(0)
        self.assertIn("tg.seg[6] !~ '%s'" % lp.INSTANCE_RE.pattern, inv)
        self.assertIn("WHEN tg.seg[6] = 'default' THEN 'reserved'", inv)

    def test_recipe_columns_exist(self):
        block = re.search(r"CREATE TABLE medcea\.recipe_line \((.*?)\n\);", read(DDL), re.S).group(1)
        for q in lp.QUANTITIES:
            for col in (q["recipe_lower"], q["recipe_upper"]):
                self.assertRegex(block, r"\b%s\b" % col)


class Instances(unittest.TestCase):
    def test_topics(self):
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/scd30_1", "co2"), ("named", "scd30_1"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2", "co2"), ("old", None))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/default", "co2"), ("reserved", "default"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/SCD", "co2"), ("bad", "SCD"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/co2/scd30_1", "co2", "scd30_2"), ("mismatch", "scd30_1"))
        self.assertEqual(lp.instance_of_topic("medcea/U/Z/sense/rh/scd30_1", "co2"), ("bad", None))


class SenseSourcesAndActuatorMap(unittest.TestCase):
    """device_template.py's two helpers name what render() writes."""

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
                 [t["tag"] for t in c["parameters"]["tags"]]) for c in comps]

    def test_wired_board(self):
        doc = json.loads(read(os.path.join(ROOT, "edge", "templates", "boards",
                                           "sense-hub-bench-sht45-scd30.json")))["wiring"]
        got = self.run_dt(["sense-sources", "SENSE"], json.dumps({"wiring": doc, "variant": "esp32s3"}))
        self.assertEqual([(g["instance"], g["tags"]) for g in got],
                         [("sht45_1", ["air_temperature", "air_humidity"]),
                          ("scd30_1", ["co2", "air_temperature", "air_humidity"])])
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            comps = self.dt.render({"out_dir": d, "role": "SENSE", "hostname": "x", "unit_code": "UNIT01",
                                    "zone_code": "ZONE01", "wiring": doc, "variant": "esp32s3"})["components"]
        self.assertEqual([(g["instance"], g["tags"]) for g in got], self.rendered_instances(comps))
        for c in comps:      # the topic's sensor is the component's declared instance
            self.assertEqual(c["parameters"]["instance"], c["parameters"]["tags"][0]["topic"].rsplit("/", 1)[-1])

    def test_legacy_questions(self):
        tsv = "scd30\t\t\nground_temperature\tdata_pin\t17\n"
        got = self.run_dt(["sense-sources", "SENSE"], json.dumps({"sensors_tsv": tsv}))
        self.assertEqual([g["instance"] for g in got], ["scd30", "ground_temperature"])
        self.assertEqual(got[1]["tags"], ["ground_temperature"])

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
        self.assertEqual(acts["light"]["kind"], "types")              # never a loop's actuator
        for q in lp.QUANTITIES:
            self.assertEqual(acts[q["actuator"]]["kind"], "commands")
            self.assertTrue(set(lp.sends(q)) <= set(acts[q["actuator"]]["commands"]))

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

    def test_no_actuator_no_row(self):
        ctx = dict(self.ctx["single"], actuators=[a for a in self.ctx["single"]["actuators"] if a["actuator"] != "co2"])
        spec = lp.build_spec("ZONE", ctx)
        rows = self.rows(spec)
        # another actuator could take the commands: offered, never ticked by default
        self.assertTrue(rows["co2"]["offered"])
        self.assertFalse(rows["co2"]["ticked"] or rows["co2"]["default_actuator"])
        self.assertNotIn("co2", [l["loop_code"] for l in spec["initial"]["loops"]])
        self.assertNotIn("W_NOT_CONTROLLED", {f["code"] for f in lp.validate(spec, spec["initial"])})
        ctx = dict(self.ctx["single"], actuators=[a for a in self.ctx["single"]["actuators"] if a["kind"] != "commands"])
        rows = self.rows(lp.build_spec("ZONE", ctx))
        self.assertFalse(rows["co2"]["offered"])
        self.assertIn("no actuator", rows["co2"]["reason"])

    def test_stored_loops_kept_and_new_rows_unticked(self):
        spec = lp.build_spec("ZONE", self.ctx["existing"])
        rows = self.rows(spec)
        self.assertTrue(rows["air_humidity"]["ticked"] and rows["air_humidity"]["existing"])
        stored = {k: self.ctx["existing"]["loops"][0][k] for k in lp.LOOP_KEYS}
        self.assertEqual(rows["air_humidity"]["loop"], stored)
        self.assertTrue(rows["air_temperature"]["offered"])
        self.assertFalse(rows["air_temperature"]["ticked"])    # nothing added without a click
        self.assertEqual([l["loop_code"] for l in spec["initial"]["loops"]], ["air_humidity", "co2"])
        self.assertEqual(lp.validate(spec, spec["initial"]),
                         [f for f in lp.validate(spec, spec["initial"]) if f["code"] == "W_NOT_CONTROLLED"])

    def test_stale_is_said_and_kept(self):
        plan = [{"instance": "scd30_1", "driver": "scd30", "tags": ["co2", "air_temperature", "air_humidity"]}]
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
        st = {"rule": "reference", "reference": "sht45_1", "fallback": "scd30_1", "max_age_s": 60, "actuator": "air_humidity"}
        self.assertEqual(lp.row_for(spec, "air_humidity", st)["input"],
                         {"tag": "air_humidity", "sources": ["sht45_1", "scd30_1"], "rule": "reference",
                          "reference": "sht45_1", "fallback": "scd30_1", "max_age_s": 60})
        st = {"rule": "max", "sensors": ["sht45_1"], "max_age_s": 90, "actuator": "air_humidity"}
        self.assertEqual(lp.row_for(spec, "air_humidity", st)["input"],
                         {"tag": "air_humidity", "sources": ["sht45_1"], "rule": "max", "max_age_s": 90})
        stored = self.ctx["existing"]["loops"][0]
        row = {k: stored[k] for k in lp.LOOP_KEYS}
        self.assertEqual(lp.row_for(spec, "air_humidity", lp.state_of(row)), row)


class Terminal(unittest.TestCase):
    def test_questions_options_answer(self):
        spec = lp.build_spec("ZONE", contexts()["bench"])
        qs = lp.questions(spec)
        self.assertEqual([q[1] for q in qs if q[0] == "Q"], ["air_temperature", "air_humidity"])
        self.assertIn(("INFO", "co2 controls on scd30_1, its only sensor"), qs)
        self.assertEqual([o[0] for o in lp.options(spec, "air_humidity")],
                         ["ref:scd30_1", "ref:sht45_1", "mean", "min", "max", "off"])
        self.assertEqual([o[0] for o in lp.options(spec, "air_humidity", "sht45_1")], ["fb:", "fb:scd30_1"])
        ans = lp.terminal_answer(spec, ["air_humidity\tref:sht45_1\tfb:scd30_1", "air_temperature\toff"])
        self.assertEqual([l["loop_code"] for l in ans["loops"]], ["air_humidity", "co2"])
        self.assertEqual(lp.validate(spec, ans), [f for f in lp.validate(spec, ans) if f["level"] == "warn"])
        self.assertEqual(lp.terminal_answer(spec, ["air_humidity\toff", "air_temperature\toff",
                                                   "co2\toff"]), {"skip": True})

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
            self.assertEqual(json.loads(self.run_cli(["payload"], '{"skip": false, "loops": []}').stdout), [])


if __name__ == "__main__":
    unittest.main()
