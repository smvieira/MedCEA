#!/usr/bin/env python3
"""Feedback control Phase 2, the runner's loops, offline (schd/cea/loop_resolver.py and
schd/cea/get_control_loops.py; owner decisions Q8, Q11, Q12, Q20 per zone).

- ParseTopic: 5- and 6-segment reading topics -> (zone, tag, sensor); 'default' for a
  5-segment topic without payload.sensor; exact segments only.
- Readings: kept per (zone, tag, sensor), newest receive time wins, unusable values
  never stored.
- Resolve: reference/fallback, mean/min/max, max_age_s, the default map's 'single'
  rule (one fresh sensor ok, two -> no_data + ambiguous_source, a stale 'default'
  ignored), F1 (substrate reads ground_temperature), F4 (no substring match), zone
  isolation, the start grace.
- DefaultMap: one loop per quantity per zone, the exact recipe columns, F11's co2 map,
  the same table as the database's _loop_quantities().
- Validate: every rule of the database's _loop_problems but the zone inventory, in its
  words (each runner message matches a literal of the migration's function, and every
  non-inventory literal is produced); one loop per actuator; NULL limit columns warn.
- Limits: a NULL recipe value or column makes the loop inactive.
- Decide: Q8 (no compute and never OFF on no_data; hold the last command).
- Topics, StateKey, Alarms (ALARM, repeat after 300 s, ALARM_CLEARED, ambiguous_source).
- GetControlLoops against a fake connection: table / default / mixed per zone, the
  to_regclass guard, today's error text, fail closed on an invalid row, parameters only.
- Static: the pure module imports only the standard library; the old character loop,
  substring match and tag-from-topic are gone; nothing imports
  get_feedback_control_loop_params.

The cea package is NOT imported (its __init__ needs psycopg2, absent on the host):
a stub package points at schd/cea so the relative import of get_control_loops works.
Run: python3 tests/test_loop_resolver.py
"""
import ast
import importlib
import json
import os
import re
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CEA = os.path.join(ROOT, "schd", "cea")
MIGRATIONS = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")

_pkg = types.ModuleType("cea_t")
_pkg.__path__ = [CEA]
sys.modules["cea_t"] = _pkg
lr = importlib.import_module("cea_t.loop_resolver")
gcl = importlib.import_module("cea_t.get_control_loops")

ROOT_T, UNIT = "medcea", "IAMT01"
CO2_MAP = {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def table_loop(zone="Z01", code="air_humidity", sources=("sht45_1", "scd30_1"), rule="reference",
               reference="sht45_1", fallback="scd30_1", max_age_s=None, actuator=None, **extra):
    q = lr.QUANTITIES[code]
    inp = {"tag": q["tag"], "sources": list(sources), "rule": rule}
    if reference is not None:
        inp["reference"] = reference
    if fallback is not None:
        inp["fallback"] = fallback
    if max_age_s is not None:
        inp["max_age_s"] = max_age_s
    out = {"actuator": actuator or code, "mode": "command"}
    if "command_map" in q:
        out["command_map"] = dict(q["command_map"])
    lp = {"zone_code": zone, "loop_id": 7, "loop_code": code,
          "recipe_lower": q["recipe_lower"], "recipe_upper": q["recipe_upper"], "input": inp, "output": out}
    lp.update(extra)
    return lp


def agg_loop(rule, sources=("a", "b"), **kw):
    return table_loop(sources=sources, rule=rule, reference=None, fallback=None, **kw)


class ParseTopic(unittest.TestCase):
    def p(self, topic, payload=None, unit=UNIT):
        return lr.parse_reading_topic(topic, ROOT_T, unit, payload)

    def test_six_segments(self):
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/air_humidity/sht45_1"), ("Z01", "air_humidity", "sht45_1"))

    def test_five_segments_payload_sensor(self):
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/co2", {"sensor": "scd30_1"}), ("Z01", "co2", "scd30_1"))

    def test_five_segments_default(self):
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/co2", {"value": 1}), ("Z01", "co2", "default"))
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/co2", {"sensor": ""}), ("Z01", "co2", "default"))
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/co2", "not a dict"), ("Z01", "co2", "default"))

    def test_topic_wins_over_payload(self):
        self.assertEqual(self.p("medcea/IAMT01/Z01/sense/co2/scd30_1", {"sensor": "other"}), ("Z01", "co2", "scd30_1"))

    def test_underscore_tags(self):
        for t in ("medcea/IAMT01/Z01/sense/_health", "medcea/IAMT01/Z01/sense/_test",
                  "medcea/IAMT01/Z01/sense/_test/x"):
            self.assertIsNone(self.p(t), t)

    def test_wrong_root_unit_kind(self):
        for t in ("other/IAMT01/Z01/sense/co2", "medcea/IAMT02/Z01/sense/co2",
                  "medcea/IAMT01/Z01/control/co2", "medcea/IAMT01/Z01/control_setpoint/co2"):
            self.assertIsNone(self.p(t), t)

    def test_shapes(self):
        for t in ("medcea/IAMT01/Z01/sense", "medcea/IAMT01/Z01/sense/co2/a/b",
                  "medcea/IAMT01/Z01/sense//a", "medcea/IAMT01/Z01/sense/co2/", "medcea/IAMT01//sense/co2", None):
            self.assertIsNone(self.p(t), t)

    def test_unit_with_space(self):
        self.assertEqual(self.p("medcea/IAM T03/Z01/sense/co2", unit="IAM T03"), ("Z01", "co2", "default"))


class Readings(unittest.TestCase):
    def test_two_sensors_kept_apart_newest_wins(self):
        r = {}
        self.assertTrue(lr.update_readings(r, ("Z01", "air_humidity", "sht45_1"), {"value": 80}, 10.0))
        self.assertTrue(lr.update_readings(r, ("Z01", "air_humidity", "scd30_1"), {"value": 70}, 11.0))
        self.assertEqual(len(r), 2)
        self.assertTrue(lr.update_readings(r, ("Z01", "air_humidity", "sht45_1"), {"value": 81}, 12.0))
        self.assertFalse(lr.update_readings(r, ("Z01", "air_humidity", "sht45_1"), {"value": 1}, 11.5))
        self.assertEqual(r[("Z01", "air_humidity", "sht45_1")], (81.0, 12.0))

    def test_bad_values(self):
        r = {}
        for v in (None, "21", True, float("nan"), float("inf"), [1]):
            self.assertFalse(lr.update_readings(r, ("Z01", "co2", "default"), {"value": v}, 1.0), v)
        self.assertFalse(lr.update_readings(r, ("Z01", "co2", "default"), {}, 1.0))
        self.assertEqual(r, {})


class Resolve(unittest.TestCase):
    def rd(self, *items):
        return {(z, t, s): (v, at) for z, t, s, v, at in items}

    def test_reference_fresh(self):
        r = lr.resolve(table_loop(), self.rd(("Z01", "air_humidity", "sht45_1", 80, 100)), 150)
        self.assertEqual((r["state"], r["value"], r["used"], r["alarm"]), ("ok", 80.0, ["sht45_1"], None))

    def test_reference_stale_fallback_fresh(self):
        r = lr.resolve(table_loop(), self.rd(("Z01", "air_humidity", "sht45_1", 80, 0),
                                             ("Z01", "air_humidity", "scd30_1", 70, 100)), 150)
        self.assertEqual((r["state"], r["value"], r["used"], r["alarm"]), ("fallback", 70.0, ["scd30_1"], "fallback_in_use"))
        self.assertIn(("sht45_1", 150), r["stale"])

    def test_both_stale(self):
        r = lr.resolve(table_loop(), self.rd(("Z01", "air_humidity", "sht45_1", 80, 0),
                                             ("Z01", "air_humidity", "scd30_1", 70, 0)), 500)
        self.assertEqual((r["state"], r["value"], r["alarm"]), ("no_data", None, "no_fresh_data"))

    def test_no_fallback_key(self):
        lp = table_loop(sources=("sht45_1",), fallback=None)
        r = lr.resolve(lp, self.rd(("Z01", "air_humidity", "sht45_1", 80, 0)), 500)
        self.assertEqual(r["state"], "no_data")

    def test_reference_never_seen(self):
        r = lr.resolve(table_loop(), self.rd(("Z01", "air_humidity", "scd30_1", 70, 100)), 150)
        self.assertEqual(r["state"], "fallback")
        self.assertIn(("sht45_1", None), r["stale"])

    def test_age_boundary(self):
        rd = self.rd(("Z01", "air_humidity", "sht45_1", 80, 100))
        self.assertEqual(lr.resolve(table_loop(max_age_s=30), rd, 130)["state"], "ok")
        self.assertEqual(lr.resolve(table_loop(max_age_s=30, fallback=None, sources=("sht45_1",)), rd, 130.001)["state"],
                         "no_data")

    def test_default_max_age(self):
        lp = table_loop(sources=("sht45_1",), fallback=None)
        rd = self.rd(("Z01", "air_humidity", "sht45_1", 80, 0))
        self.assertEqual(lr.resolve(lp, rd, 90)["state"], "ok")
        self.assertEqual(lr.resolve(lp, rd, 90.5)["state"], "no_data")

    def test_aggregates_all_fresh(self):
        rd = self.rd(("Z01", "air_humidity", "a", 70, 100), ("Z01", "air_humidity", "b", 80, 100))
        self.assertEqual(lr.resolve(agg_loop("mean"), rd, 110)["value"], 75.0)
        self.assertEqual(lr.resolve(agg_loop("min"), rd, 110)["value"], 70.0)
        self.assertEqual(lr.resolve(agg_loop("max"), rd, 110)["value"], 80.0)
        self.assertEqual(lr.resolve(agg_loop("max"), rd, 110)["state"], "ok")

    def test_aggregate_partial(self):
        rd = self.rd(("Z01", "air_humidity", "a", 70, 0), ("Z01", "air_humidity", "b", 80, 100))
        r = lr.resolve(agg_loop("mean"), rd, 110)
        self.assertEqual((r["state"], r["value"], r["used"], r["alarm"]), ("fallback", 80.0, ["b"], "fallback_in_use"))

    def test_aggregate_all_stale(self):
        rd = self.rd(("Z01", "air_humidity", "a", 70, 0), ("Z01", "air_humidity", "b", 80, 0))
        self.assertEqual(lr.resolve(agg_loop("mean"), rd, 500)["state"], "no_data")

    def test_default_single_one_fresh(self):
        lp = lr.default_loop("Z01", "air_temperature")
        r = lr.resolve(lp, self.rd(("Z01", "air_temperature", "default", 21, 100)), 110)
        self.assertEqual((r["state"], r["value"], r["used"]), ("ok", 21.0, ["default"]))

    def test_default_single_two_fresh_is_ambiguous(self):
        lp = lr.default_loop("Z01", "air_temperature")
        rd = self.rd(("Z01", "air_temperature", "sht45_1", 21, 100), ("Z01", "air_temperature", "scd30_1", 23, 100))
        r = lr.resolve(lp, rd, 110)
        self.assertEqual((r["state"], r["value"], r["alarm"], r["sensors"]),
                         ("no_data", None, "ambiguous_source", ["scd30_1", "sht45_1"]))
        self.assertIn("choose the reference in onboarding", lr.alarm_detail(r))
        self.assertIn("sensors=scd30_1,sht45_1", lr.alarm_detail(r))

    def test_default_single_one_fresh_one_stale_default(self):
        lp = lr.default_loop("Z01", "air_temperature")
        rd = self.rd(("Z01", "air_temperature", "default", 19, 0), ("Z01", "air_temperature", "sht45_1", 21, 200))
        r = lr.resolve(lp, rd, 210)
        self.assertEqual((r["state"], r["value"], r["used"]), ("ok", 21.0, ["sht45_1"]))

    def test_default_both_topic_forms(self):
        lp = lr.default_loop("Z01", "air_humidity")
        rd = {}
        lr.update_readings(rd, lr.parse_reading_topic("medcea/IAMT01/Z01/sense/air_humidity", "medcea", UNIT, {}),
                           {"value": 80}, 100)
        self.assertEqual(lr.resolve(lp, rd, 110)["state"], "ok")
        rd2 = {}
        lr.update_readings(rd2, lr.parse_reading_topic("medcea/IAMT01/Z01/sense/air_humidity/sht45_1", "medcea", UNIT),
                           {"value": 81}, 100)
        self.assertEqual(lr.resolve(lp, rd2, 110)["value"], 81.0)

    def test_table_loop_ignores_default(self):
        lp = table_loop(sources=("sht45_1",), fallback=None)
        r = lr.resolve(lp, self.rd(("Z01", "air_humidity", "default", 80, 100)), 110)
        self.assertEqual(r["state"], "no_data")

    def test_renamed_tag_never_matches(self):
        """F4: air_temperature_scd30 never feeds air_temperature, and the reverse."""
        rd = self.rd(("Z01", "air_temperature_scd30", "default", 30, 100))
        self.assertEqual(lr.resolve(lr.default_loop("Z01", "air_temperature"), rd, 110)["state"], "no_data")
        lp = dict(lr.default_loop("Z01", "air_temperature"))
        lp["input"] = dict(lp["input"], tag="air_temperature_scd30")
        rd2 = self.rd(("Z01", "air_temperature", "default", 21, 100))
        self.assertEqual(lr.resolve(lp, rd2, 110)["state"], "no_data")

    def test_zone_isolation(self):
        rd = self.rd(("Z02", "air_temperature", "default", 21, 100))
        self.assertEqual(lr.resolve(lr.default_loop("Z01", "air_temperature"), rd, 110)["state"], "no_data")

    def test_substrate_reads_ground_temperature(self):
        """F1."""
        lp = lr.default_loop("Z01", "substrate_temperature")
        self.assertEqual(lr.resolve(lp, self.rd(("Z01", "ground_temperature", "default", 18, 100)), 110)["value"], 18.0)
        self.assertEqual(lr.resolve(lp, self.rd(("Z01", "substrate_temperature", "default", 18, 100)), 110)["state"],
                         "no_data")

    def test_start_grace(self):
        lp = lr.default_loop("Z01", "co2")
        r = lr.resolve(lp, {}, 1010, started_at=1000)
        self.assertEqual((r["state"], r["reason"], r["alarm"]), ("no_data", "waiting", None))
        r = lr.resolve(lp, {}, 1100, started_at=1000)
        self.assertEqual((r["reason"], r["alarm"]), ("no_fresh_data", "no_fresh_data"))
        r = lr.resolve(table_loop(), {}, 1010, started_at=1000)
        self.assertEqual(r["reason"], "waiting")


class DefaultMap(unittest.TestCase):
    def test_two_zones(self):
        m = lr.build_default_map(["Z02", "Z01", "Z02"])
        self.assertEqual(len(m), 8)
        self.assertEqual([l["zone_code"] for l in m], ["Z01"] * 4 + ["Z02"] * 4)
        by = {(l["zone_code"], l["loop_code"]): l for l in m}
        self.assertEqual({c for _, c in by}, {"air_temperature", "air_humidity", "co2", "substrate_temperature"})
        h = by[("Z01", "air_humidity")]
        self.assertEqual((h["recipe_lower"], h["recipe_upper"]), ("hr_lower_limit", "hr_upper_limit"))
        self.assertEqual(by[("Z01", "substrate_temperature")]["input"]["tag"], "ground_temperature")
        self.assertEqual((by[("Z01", "air_temperature")]["recipe_lower"], by[("Z01", "co2")]["recipe_upper"]),
                         ("air_temperature_lower_limit", "co2_upper_limit"))
        for l in m:
            self.assertEqual(l["input"]["sources"], "*")
            self.assertEqual(l["input"]["rule"], "single")
            self.assertEqual(l["input"]["max_age_s"], 90)
            self.assertEqual(l["output"]["actuator"], l["loop_code"])
            self.assertEqual(l["output"]["mode"], "command")
            self.assertIsNone(l["loop_id"])
        self.assertNotIn("light", {l["loop_code"] for l in m})
        with self.assertRaises(ValueError):
            lr.build_default_map([])

    def test_co2_map(self):
        for l in lr.build_default_map(["Z01"]):
            if l["loop_code"] == "co2":
                self.assertEqual(l["output"]["command_map"], CO2_MAP)
            else:
                self.assertNotIn("command_map", l["output"])

    def test_validates(self):
        self.assertEqual(lr.validate_loops(lr.build_default_map(["Z01", "Z02"])), ([], []))

    def test_same_table_as_the_database(self):
        sql = _read(MIGRATIONS)
        m = re.search(r"FUNCTION medcea\._loop_quantities\(\).*?SELECT '(.*?)'::jsonb", sql, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), lr.QUANTITIES)

    def test_recipe_columns_exist(self):
        ddl = _read(os.path.join(ROOT, "apps", "database", "medcea_db_ddl.sql"))
        block = re.search(r"CREATE TABLE medcea\.recipe_line \((.*?)\n\);", ddl, re.S).group(1)
        for col in lr.LIMIT_COLUMNS:
            self.assertRegex(block, r"\b%s\b" % col)
        details = _read(os.path.join(CEA, "get_recipe_line_item_seq_details.py"))
        for col in lr.LIMIT_COLUMNS:
            self.assertIn("'%s'" % col, details)


def _problem_literals():
    """The message literals of medcea._loop_problems (migration 010), '' unescaped."""
    sql = _read(MIGRATIONS)
    body = re.search(r"FUNCTION medcea\._loop_problems\(.*?\$\$(.*?)END \$\$;", sql, re.S).group(1)
    lits = re.findall(r"(?:\(pre \|\| |RETURN ARRAY\[)(?:format\()?'((?:[^']|'')*)'", body)
    return {x.replace("''", "'") for x in lits}


INVENTORY = {"sensor %s is not on an active SENSE board of zone %s", "sensor %s does not publish %s",
             "actuator %s is not on an active CONTROL board of zone %s",
             "actuator %s does not take every command the loop sends (%s)"}


class Validate(unittest.TestCase):
    """Each case: a table row the runner refuses, with the database's own words."""

    def errs(self, lp):
        return lr.validate_loops([lp])[0]

    def assertProblem(self, lp, text):
        e = self.errs(lp)
        self.assertTrue(any(text in x for x in e), (text, e))

    def test_good_rows(self):
        self.assertEqual(lr.validate_loops([table_loop()]), ([], []))
        self.assertEqual(lr.validate_loops([table_loop(code="co2", sources=("scd30_1",), reference="scd30_1",
                                                       fallback=None, max_age_s=60)]), ([], []))
        self.assertEqual(lr.validate_loops([agg_loop("mean", code="substrate_temperature")]), ([], []))

    def test_loop_code(self):
        self.assertProblem(table_loop(loop_code="foo"),
                           "loop_code foo is not one of air_humidity, air_temperature, co2, substrate_temperature")
        self.assertProblem(table_loop(loop_code=None), "a loop needs a loop_code")

    def test_limits_tied_to_loop_code(self):
        self.assertProblem(table_loop(recipe_lower="co2_lower_limit"), "air_humidity: recipe_lower must be hr_lower_limit")
        self.assertProblem(table_loop(recipe_upper="x; DROP TABLE medcea.recipe"),
                           "air_humidity: recipe_upper must be hr_upper_limit")

    def test_tag(self):
        lp = table_loop()
        lp["input"]["tag"] = "air_humidity_scd30"
        self.assertProblem(lp, "air_humidity: input.tag must be air_humidity")
        lp = table_loop(code="substrate_temperature")
        lp["input"]["tag"] = "substrate_temperature"
        self.assertProblem(lp, "input.tag must be ground_temperature")

    def test_sources(self):
        lp = table_loop()
        lp["input"]["sources"] = []
        self.assertProblem(lp, "input.sources must be a non-empty list of sensor names")
        lp["input"]["sources"] = "*"
        self.assertProblem(lp, "input.sources must be a non-empty list of sensor names")
        self.assertProblem(agg_loop("mean", sources=("a", 3)), "input.sources must hold sensor names (strings)")
        self.assertProblem(agg_loop("mean", sources=("a", "a")), "sensor a is listed twice")
        self.assertProblem(agg_loop("mean", sources=("a", "default")), "sensor default is reserved")

    def test_rule(self):
        self.assertProblem(agg_loop("median"), "input.rule must be one of reference, mean, min, max")
        self.assertProblem(agg_loop("single"), "input.rule must be one of reference, mean, min, max")
        self.assertProblem(table_loop(reference=None, fallback=None, sources=("a",)),
                           "rule reference needs input.reference, one of the sources")
        self.assertProblem(table_loop(reference="x"), "input.reference x is not one of the sources")
        self.assertProblem(table_loop(fallback="sht45_1"), "input.fallback must be another sensor than the reference")
        self.assertProblem(table_loop(sources=("sht45_1",), fallback="zz"), "input.fallback zz is not one of the sources")
        lp = table_loop()
        lp["input"]["fallback"] = 3
        self.assertProblem(lp, "input.fallback must be a sensor name")
        self.assertProblem(table_loop(sources=("sht45_1", "scd30_1", "x")),
                           "with rule reference, input.sources holds only the reference and the fallback")
        lp = agg_loop("mean")
        lp["input"]["reference"] = "a"
        self.assertProblem(lp, "rule mean takes no reference or fallback")

    def test_max_age(self):
        for bad in (0, -1, 3601, 1.5, "90", True, float("inf")):
            self.assertProblem(table_loop(max_age_s=bad), "input.max_age_s must be a whole number of seconds from 1 to 3600")
        for good in (1, 3600, 90.0):
            self.assertEqual(self.errs(table_loop(max_age_s=good)), [], good)

    def test_actuator(self):
        for bad in ("a/b", "a+", "#", "", "a\n", 5):
            self.assertProblem(table_loop(actuator=bad if bad != "" else None) if bad != "" else
                               dict(table_loop(), output={"actuator": "", "mode": "command"}),
                               "output.actuator must be an actuator name")

    def test_mode(self):
        for mode in ("level", "boost", None):
            lp = table_loop()
            lp["output"]["mode"] = mode
            self.assertProblem(lp, "output.mode must be command (level and boost need Phase 3's PWM outputs)")

    def test_co2_map(self):
        lp = table_loop(code="co2", sources=("a",), reference="a", fallback=None)
        del lp["output"]["command_map"]
        self.assertProblem(lp, 'co2: output.command_map must be exactly {"UP": "OFF", "OFF": "OFF", "DOWN": "UP"}')
        lp["output"]["command_map"] = {"DOWN": "OFF", "UP": "UP", "OFF": "OFF"}
        self.assertProblem(lp, "output.command_map must be exactly")
        lp = table_loop()
        lp["output"]["command_map"] = CO2_MAP
        self.assertProblem(lp, "air_humidity: output.command_map is only for co2")

    def test_unknown_keys(self):
        lp = table_loop()
        lp["input"]["weights"] = [1]
        lp["output"]["baseline"] = 1
        self.assertProblem(lp, "unknown key input.weights")
        self.assertProblem(lp, "unknown key output.baseline")

    def test_objects(self):
        self.assertProblem(dict(table_loop(), input=[1]), "air_humidity: input must be an object")
        self.assertProblem(dict(table_loop(), output="x"), "air_humidity: output must be an object")

    def test_state_key_length(self):
        z = "Z" * 40
        self.assertProblem(table_loop(zone=z), "the runner's state key air_humidity@%s is longer than 50 characters" % z)

    def test_state_key_length_default_map(self):
        z = "Z" * 40
        e = lr.validate_loops(lr.build_default_map([z]))[0]
        self.assertIn("zone %s: substrate_temperature: the runner's state key substrate_temperature@%s "
                      "is longer than 50 characters" % (z, z), e)
        self.assertEqual(lr.validate_loops(lr.build_default_map(["Z" * 28]))[0], [])

    def test_empty_sensor_name(self):
        # the database refuses it through its inventory rule; the runner must too
        self.assertProblem(agg_loop("mean", sources=("a", "")), "input.sources holds an empty sensor name")

    def test_light_actuator_reserved(self):
        self.assertProblem(table_loop(actuator="light"),
                           "output.actuator light is reserved for the time-based light command")

    def test_duplicates(self):
        e = lr.validate_loops([table_loop(), table_loop()])[0]
        self.assertIn("zone Z01: air_humidity: listed twice", e)
        e = lr.validate_loops([table_loop(), table_loop(code="air_temperature", sources=("a",), reference="a",
                                                        fallback=None, actuator="air_humidity")])[0]
        self.assertIn("zone Z01: air_temperature: actuator air_humidity is driven by another loop of the zone", e)
        self.assertEqual(lr.validate_loops([table_loop(), table_loop(zone="Z02")])[0], [])

    def test_star_only_on_the_default_map(self):
        lp = lr.default_loop("Z01", "co2")
        lp["input"]["rule"] = "mean"
        self.assertTrue(lr.validate_loops([lp])[0])
        lp = lr.default_loop("Z01", "co2")
        lp["output"] = {"actuator": "co2", "mode": "command"}
        self.assertTrue(lr.validate_loops([lp])[0])

    def test_zone_code_topic_safe(self):
        self.assertTrue(lr.validate_loops([table_loop(zone="Z+1")])[0])
        self.assertTrue(lr.validate_loops(lr.build_default_map(["Z#"]))[0])
        self.assertEqual(lr.validate_loops([]), (["no control loops"], []))

    def test_null_limit_column_is_a_warning(self):
        errs, warns = lr.validate_loops([table_loop(recipe_lower=None)])
        self.assertEqual(errs, [])
        self.assertEqual(warns, ["zone Z01: air_humidity: recipe_lower is NULL: the loop is inactive"])

    def test_parity_with_the_migration(self):
        """Every runner message is a literal of _loop_problems (or save_zone_loops'
        two map-wide checks), and every non-inventory literal is produced."""
        lits = _problem_literals()
        self.assertGreater(len(lits), 20)
        sql = _read(MIGRATIONS)
        self.assertIn("'%s: listed twice'", sql)
        self.assertIn("'%s: actuator %s is driven by another loop of the zone'", sql)
        pats = {l: re.compile(re.escape(l).replace("%s", ".*")) for l in lits}
        bad = [
            "x", dict(table_loop(), loop_code=3), dict(table_loop(), loop_code="foo"),
            dict(table_loop(zone="Z" * 40), extra=1, recipe_lower="a", recipe_upper="b", input=[1], output="x"),
            dict(table_loop(), input={"tag": "t", "sources": "x", "rule": "r", "w": 1}),
            dict(table_loop(), input={"tag": "air_humidity", "sources": ["a", 1, "a", "default"], "rule": "reference",
                                      "reference": "q", "fallback": "z", "max_age_s": 0}),
            dict(table_loop(), input={"tag": "air_humidity", "sources": ["a"], "rule": "reference", "fallback": 1}),
            dict(table_loop(), input={"tag": "air_humidity", "sources": ["a", "b"], "rule": "reference",
                                      "reference": "a", "fallback": "a"}),
            dict(table_loop(), input={"tag": "air_humidity", "sources": ["a"], "rule": "mean", "reference": "a"}),
            dict(table_loop(), output={"actuator": "a/b", "mode": "level", "command_map": {}, "x": 1}),
            dict(table_loop(code="co2", sources=("a",), reference="a", fallback=None), output={"actuator": "co2", "mode": "command"}),
        ]
        produced, matched = [], set()
        for lp in bad:
            row = {k: v for k, v in lp.items() if k not in ("zone_code", "loop_id")} if isinstance(lp, dict) else lp
            produced += lr.loop_problems(row, lp.get("zone_code", "Z01") if isinstance(lp, dict) else "Z01")
        for msg in produced:
            m = re.match(r"(?:[a-z_0-9]+: )?(.*)$", msg, re.S)
            text = msg if any(p.fullmatch(msg) for p in pats.values()) else m.group(1)
            hits = [l for l, p in pats.items() if p.fullmatch(text)]
            self.assertTrue(hits, msg)
            matched.update(hits)
        self.assertEqual(lits - INVENTORY - matched, set())


class Limits(unittest.TestCase):
    def test_values(self):
        lp = lr.default_loop("Z01", "air_humidity")
        self.assertEqual(lr.limits(lp, {"hr_lower_limit": 70, "hr_upper_limit": 90}), (70.0, 90.0, None))

    def test_null_recipe_value_inactive(self):
        lp = lr.default_loop("Z01", "substrate_temperature")
        lo, hi, why = lr.limits(lp, {"substrate_temperature_lower_limit": None, "substrate_temperature_upper_limit": 20})
        self.assertEqual((lo, hi), (None, None))
        self.assertIn("substrate_temperature_lower_limit", why)
        self.assertIn("inactive", why)

    def test_null_column_inactive(self):
        lo, hi, why = lr.limits(table_loop(recipe_upper=None), {"hr_lower_limit": 1, "hr_upper_limit": 2})
        self.assertIsNone(lo)
        self.assertIn("inactive", why)


class FakeAlgo:
    def __init__(self, cmd):
        self.cmd, self.calls = cmd, []

    def compute(self, v):
        self.calls.append(v)
        return self.cmd


class Decide(unittest.TestCase):
    def test_ok_mapped(self):
        lp = lr.default_loop("Z01", "co2")
        a = FakeAlgo("DOWN")
        self.assertEqual(lr.decide(lp, {"state": "ok", "value": 1500.0}, a, None), ("UP", False))
        self.assertEqual(lr.decide(lp, {"state": "ok", "value": 300.0}, FakeAlgo("UP"), None), ("OFF", False))
        self.assertEqual(lr.decide(lr.default_loop("Z01", "air_temperature"), {"state": "ok", "value": 30.0},
                                   FakeAlgo("DOWN"), None), ("DOWN", False))

    def test_fallback_computes_on_the_fallback_value(self):
        a = FakeAlgo("UP")
        self.assertEqual(lr.decide(table_loop(), {"state": "fallback", "value": 61.0}, a, "OFF"), ("UP", False))
        self.assertEqual(a.calls, [61.0])

    def test_no_data_holds(self):
        a = FakeAlgo("OFF")
        self.assertEqual(lr.decide(table_loop(), {"state": "no_data", "value": None}, a, "UP"), ("UP", True))
        self.assertEqual(lr.decide(table_loop(), {"state": "no_data", "value": None}, a, None), (None, False))
        self.assertEqual(a.calls, [])

    def test_no_data_never_off(self):
        for last in (None, "UP", "DOWN"):
            cmd, _ = lr.decide(lr.default_loop("Z01", "co2"), {"state": "no_data", "value": None}, FakeAlgo("OFF"), last)
            self.assertNotEqual(cmd, "OFF")


class Topics(unittest.TestCase):
    def test_command_topic_and_payload(self):
        lp = lr.default_loop("Z02", "co2")
        self.assertEqual(lr.command_topic("medcea", "IAMT01", "Z02", "co2"), "medcea/IAMT01/Z02/control/co2")
        r = {"state": "ok", "used": ["default"], "value": 900.0}
        p = lr.command_payload(lp, r, "UP", False, "t")
        self.assertEqual((p["tag"], p["command"], p["state"], p["loop"], p["origin"]), ("co2", "UP", "ok", "co2", "loop"))
        self.assertNotIn("value", p)
        self.assertEqual(lr.command_payload(lp, r, "UP", True, "t")["state"], "hold")

    def test_light_topic_per_zone(self):
        self.assertEqual(lr.light_topic("medcea", "U", "Z03"), "medcea/U/Z03/control/light")

    def test_stop_topics_list(self):
        self.assertEqual(lr.stop_topics("medcea", "IAMT01", ["Z02"]), ["medcea/IAMT01/Z02/sense/#"])
        self.assertEqual(lr.stop_topics("medcea", "IAMT01", ["Z02", "Z01", "Z02"]),
                         ["medcea/IAMT01/Z01/sense/#", "medcea/IAMT01/Z02/sense/#"])

    def test_subscribe_skips_unsafe(self):
        self.assertEqual(lr.subscribe_topics("medcea", "IAM+04", ["Z01"]), [])
        self.assertEqual(lr.subscribe_topics("medcea", "IAMT01", ["Z+", "Z/1", "Z01"]), ["medcea/IAMT01/Z01/sense/#"])
        self.assertEqual(lr.subscribe_topics("medcea", "IAM T03", ["Z01"]), ["medcea/IAM T03/Z01/sense/#"])


class StateKey(unittest.TestCase):
    def test_keys(self):
        lp = lr.default_loop("Z01", "co2")
        self.assertEqual(lr.state_key(lp, False), "co2")
        self.assertEqual(lr.state_key(lp, True), "co2@Z01")


class Alarms(unittest.TestCase):
    def test_transition_repeat_clear(self):
        t = lr.AlarmTracker("IAMT01")
        k = ("Z01", "air_humidity")
        l1 = t.update(k, "fallback_in_use", 0, "using=scd30_1")
        self.assertEqual(l1, ["ALARM fallback_in_use unit=IAMT01 zone=Z01 loop=air_humidity using=scd30_1"])
        self.assertEqual(t.update(k, "fallback_in_use", 100), [])
        self.assertEqual(len(t.update(k, "fallback_in_use", 300)), 1)
        self.assertEqual(t.update(k, "no_fresh_data", 310),
                         ["ALARM_CLEARED fallback_in_use unit=IAMT01 zone=Z01 loop=air_humidity",
                          "ALARM no_fresh_data unit=IAMT01 zone=Z01 loop=air_humidity"])
        self.assertEqual(t.update(k, None, 320), ["ALARM_CLEARED no_fresh_data unit=IAMT01 zone=Z01 loop=air_humidity"])
        self.assertEqual(t.update(k, None, 330), [])

    def test_waiting_is_silent(self):
        t = lr.AlarmTracker("U")
        r = lr.resolve(lr.default_loop("Z01", "co2"), {}, 5, started_at=0)
        self.assertEqual(t.update(("Z01", "co2"), r["alarm"], 5, lr.alarm_detail(r)), [])

    def test_no_fresh_data_detail(self):
        r = lr.resolve(lr.default_loop("Z01", "co2"), {("Z01", "co2", "a"): (1.0, 0)}, 1000, started_at=0)
        self.assertEqual(r["alarm"], "no_fresh_data")
        self.assertIn("(nothing sent yet)", lr.alarm_detail(r))
        self.assertIn("(holding the last command UP)", lr.alarm_detail(r, "UP"))

    def test_ambiguous_line(self):
        t = lr.AlarmTracker("U")
        rd = {("Z01", "co2", "a"): (1.0, 9), ("Z01", "co2", "b"): (2.0, 9)}
        r = lr.resolve(lr.default_loop("Z01", "co2"), rd, 10)
        line = t.update(("Z01", "co2"), r["alarm"], 10, lr.alarm_detail(r))[0]
        self.assertEqual(line, "ALARM ambiguous_source unit=U zone=Z01 loop=co2 sensors=a,b: choose the reference in onboarding")


# ── get_control_loops against a fake connection ─────────────────────────────────
class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.result = None

    def execute(self, sql, params=None):
        self.conn.executed.append((sql, params))
        if "to_regclass" in sql:
            self.result = [(self.conn.has_table,)]
        elif "medcea.control_loop l" in sql:
            if self.conn.denied:
                raise PermissionError("42501 permission denied for table control_loop")
            self.result = list(self.conn.rows)
        elif "component_type = 'ACTUATOR'" in sql:
            self.result = [(z,) for z in self.conn.actuator_zones]
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.result[0]

    def fetchall(self):
        return self.result

    def close(self):
        self.conn.closed_cursors += 1


class FakeConn:
    def __init__(self, has_table=True, rows=(), actuator_zones=(), denied=False):
        self.has_table, self.rows, self.actuator_zones, self.denied = has_table, rows, actuator_zones, denied
        self.executed, self.rollbacks, self.closed_cursors = [], 0, 0

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.rollbacks += 1


def row(lp):
    return (lp["zone_code"], lp["loop_id"], lp["loop_code"], lp["recipe_lower"], lp["recipe_upper"],
            lp["input"], json.dumps(lp["output"]))


class GetControlLoops(unittest.TestCase):
    def test_table(self):
        a, b = table_loop(), table_loop(code="co2", sources=("scd30_1",), reference="scd30_1", fallback=None)
        conn = FakeConn(rows=[row(a), row(b)], actuator_zones=["Z01"])
        res = gcl.get_control_loops(UNIT, conn)
        self.assertEqual(res["source"], "table")
        self.assertEqual([l["loop_code"] for l in res["loops"]], ["air_humidity", "co2"])
        self.assertEqual(res["loops"][1]["output"]["command_map"], CO2_MAP)
        self.assertEqual(conn.rollbacks, 1)
        self.assertTrue(any("not controlled: air_temperature, substrate_temperature" in w for w in res["warnings"]))
        self.assertFalse(any("DEFAULT_LOOP_MAP" in w for w in res["warnings"]))

    def test_no_table(self):
        conn = FakeConn(has_table=False, actuator_zones=["Z02"])
        res = gcl.get_control_loops(UNIT, conn)
        self.assertEqual(res["source"], "default")
        self.assertEqual(res["loops"], lr.build_default_map(["Z02"]))
        self.assertTrue(any("not deployed yet" in w for w in res["warnings"]))
        self.assertFalse(any("medcea.control_loop l" in s for s, _ in conn.executed))
        self.assertEqual(conn.rollbacks, 1)

    def test_no_rows(self):
        res = gcl.get_control_loops(UNIT, FakeConn(actuator_zones=["Z02"]))
        self.assertEqual(res["source"], "default")
        self.assertTrue(any(w.startswith("DEFAULT_LOOP_MAP unit=IAMT01 zones=Z02") for w in res["warnings"]))

    def test_mixed_per_zone(self):
        """Q20 / D-a: a zone with rows uses them; an actuator zone without rows gets
        the default map; onboarding one zone never stops control of its sibling."""
        conn = FakeConn(rows=[row(table_loop(zone="Z01"))], actuator_zones=["Z01", "Z02"])
        res = gcl.get_control_loops(UNIT, conn)
        self.assertEqual(res["source"], "mixed")
        self.assertEqual([(l["zone_code"], l["loop_code"]) for l in res["loops"]],
                         [("Z01", "air_humidity")] + [("Z02", c) for c in lr.QUANTITIES])

    def test_nothing(self):
        with self.assertRaisesRegex(RuntimeError, r"^No active actuator found for unit code: IAMT01$"):
            gcl.get_control_loops(UNIT, FakeConn())

    def test_invalid_row_fails_closed(self):
        lp = table_loop()
        lp["output"]["mode"] = "boost"
        conn = FakeConn(rows=[row(lp)], actuator_zones=["Z01"])
        with self.assertRaisesRegex(RuntimeError, r"invalid .*output\.mode must be command"):
            gcl.get_control_loops(UNIT, conn)
        self.assertEqual(conn.rollbacks, 1)

    def test_permission_error_propagates(self):
        conn = FakeConn(denied=True, actuator_zones=["Z01"])
        with self.assertRaises(PermissionError):
            gcl.get_control_loops(UNIT, conn)
        self.assertEqual(conn.rollbacks, 1)

    def test_parameters_only(self):
        conn = FakeConn(rows=[row(table_loop())], actuator_zones=["Z01"])
        gcl.get_control_loops("IAM'01", conn)
        for sql, params in conn.executed:
            self.assertNotIn("IAM'01", sql)
            if "%s" in sql:
                self.assertEqual(params, ("IAM'01",))
        rows_sql = gcl.SQL_ROWS
        for f in ("u.is_active = 'Y'", "z.is_active = 'Y'", "l.is_active = 'Y'", "u.unit_code = %s"):
            self.assertIn(f, rows_sql)
        for f in ("c.is_active = 'Y'", "component_type = 'ACTUATOR'", "z.is_active = 'Y'"):
            self.assertIn(f, gcl.SQL_ACTUATOR_ZONES)
        src = _read(os.path.join(CEA, "get_control_loops.py"))
        self.assertNotRegex(src, r"execute\(\s*f[\"']")
        self.assertNotRegex(src, r"execute\([^)]*%\s*\(")


class Static(unittest.TestCase):
    def test_pure_module_imports(self):
        tree = ast.parse(_read(os.path.join(CEA, "loop_resolver.py")))
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                self.assertEqual(n.level, 0, "no relative import")
                mods.add(n.module.split(".")[0])
        self.assertLessEqual(mods, {"json", "math", "re"})

    def test_old_patterns_gone(self):
        ctl = _read(os.path.join(CEA, "control_logic_thread.py"))
        self.assertNotIn("ch in topic", ctl)
        self.assertNotIn("split('/')[-1]", ctl)
        self.assertNotIn("'_algorithms' in dir()", ctl)
        agent = _read(os.path.join(CEA, "run_agent.py"))
        self.assertNotIn("for topic in mqtt_topics", agent)
        self.assertNotIn("for topic in [mqtt_topics]", agent)

    def test_old_function_retired(self):
        self.assertFalse(os.path.exists(os.path.join(CEA, "get_feedback_control_loop_params.py")))
        for base in ("schd", "apps", "edge"):
            for dp, _, fs in os.walk(os.path.join(ROOT, base)):
                for f in fs:
                    if f.endswith(".py"):
                        self.assertNotIn("get_feedback_control_loop_params", _read(os.path.join(dp, f)), f)
        init = ast.parse(_read(os.path.join(CEA, "__init__.py")))
        alls = [n for n in init.body if isinstance(n, ast.Assign) and n.targets[0].id == "__all__"][0]
        names = [e.value for e in alls.value.elts if isinstance(e, ast.Constant)]
        self.assertEqual(len(names), len(alls.value.elts), "__all__ holds only names (no module objects)")
        self.assertIn("get_control_loops", names)
        self.assertIn("loop_resolver", names)

    def test_both_run_paths_read_loops_once(self):
        src = _read(os.path.join(ROOT, "schd", "run_recipe.py"))
        self.assertEqual(src.count("loopset = read_control_loops(unit_code, conn)"), 2)
        self.assertEqual(src.count("with_loops("), 3)     # the definition + both paths
        tree = ast.parse(src)
        for fn in [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("run_recipe", "run_recipe_by_id")]:
            loops = [n for n in ast.walk(fn) if isinstance(n, (ast.For, ast.While))]
            for lp in loops:
                self.assertNotIn("read_control_loops", ast.unparse(lp), fn.name)

    def test_legacy_path_marks_a_known_run_failed(self):
        """A loop-read failure on the legacy path: an existing run is marked F, none is created."""
        src = _read(os.path.join(ROOT, "schd", "run_recipe.py"))
        fn = [n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "run_recipe"][0]
        body = ast.unparse(fn)
        self.assertLess(body.index("recipe_run_id = None"), body.index("check_unit_availability("))
        self.assertLess(body.index("check_unit_availability("), body.index("read_control_loops("))
        self.assertLess(body.index("read_control_loops("), body.index("create_recipe_run("))
        self.assertIn("if conn and recipe_run_id is not None:", body)


if __name__ == "__main__":
    unittest.main(verbosity=1)
