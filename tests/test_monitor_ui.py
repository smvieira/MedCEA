"""The Run Monitor's Live Measurements, offline (apps/monitor/html/monitor.html,
feedback control Phase 1).

- The monitor-logic block (pure functions between /* monitor-logic:begin */ and
  /* monitor-logic:end */) runs under node (skipped without node), its TAG_MAP built by
  tagMapFrom() from the real catalogue (apps/database/recipe_types.py json, as the deploy
  serves it at /recipe-types.json; migration 011):
  - tagMapFrom: each quantity's default sense tag → the quantity, its label and unit, in
    the catalogue's order (ground_temperature → substrate_temperature);
  - stepLimits: the step's setpoints[quantity], nulls without one;
  - typeLabel: PLANT/FUNGI by label;
  - orderMeasurements: TAG_MAP order, unknown tags last by name, then zone, then sensor;
    a reading without a tag does not throw;
  - gaugeLabel: a named sensor is always shown, 'default' only beside another sensor of
    the same zone and tag; the zone only when the unit's rows span several zones;
  - esc: a board's tag, sensor, zone or UoM never reaches innerHTML as markup;
  - isStale: older than 10 minutes by the database's receive time; a missing or bad
    date is not stale.
- Static: renderGauge takes the whole reading and puts its label through esc(); the old
  per-tag sort (a.tag.localeCompare) is gone.

Run: python3 tests/test_monitor_ui.py
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "apps", "monitor", "html", "monitor.html")
NODE = shutil.which("node")
RECIPE_TYPES = os.path.join(ROOT, "apps", "database", "recipe_types.py")


def catalogue_json():
    out = subprocess.run(["python3", RECIPE_TYPES, "json"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logic_block():
    m = re.search(r"/\* monitor-logic:begin \*/(.*?)/\* monitor-logic:end \*/", read(PAGE), re.S)
    assert m, "monitor-logic block missing"
    return m.group(1)


def run_node(expr):
    """Evaluate a JSON-producing expression after the logic block."""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(logic_block() + "\nconst DOC = " + catalogue_json() + ";\nTAG_MAP = tagMapFrom(DOC);\n"
                + "console.log(JSON.stringify(" + expr + "));\n")
        path = f.name
    try:
        out = subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


def r(zone, tag, sensor="default", **kw):
    d = {"zone_code": zone, "tag": tag, "sensor": sensor, "value": 1}
    d.update(kw)
    return d


@unittest.skipUnless(NODE, "node not installed")
class MonitorLogicTest(unittest.TestCase):
    def test_order(self):
        rows = [r("Z2", "air_humidity", "sht45_1"), r("Z1", "lux"), r("Z1", "air_humidity", "sht45_1"),
                r("Z1", "co2"), r("Z1", "air_humidity", "scd30"), r("Z1", "air_temperature"),
                r("Z1", None), r("Z1", "ammonia")]
        got = run_node("orderMeasurements(%s).map(m => [m.zone_code, m.tag, m.sensor])" % json.dumps(rows))
        self.assertEqual(got, [
            ["Z1", "air_temperature", "default"],
            ["Z1", "air_humidity", "scd30"], ["Z1", "air_humidity", "sht45_1"],
            ["Z2", "air_humidity", "sht45_1"],
            ["Z1", "co2", "default"],
            ["Z1", None, "default"], ["Z1", "ammonia", "default"], ["Z1", "lux", "default"],
        ])
        # the input is not reordered in place
        self.assertEqual(run_node("(() => { const a = %s; orderMeasurements(a); return a[0].zone_code; })()"
                                  % json.dumps(rows)), "Z2")

    def labels(self, rows):
        return run_node("(() => { const a = %s; const c = labelContext(a); return a.map(m => gaugeLabel(m, c)); })()"
                        % json.dumps(rows))

    def test_label_one_zone(self):
        # a board not yet re-onboarded looks as before Phase 1
        self.assertEqual(self.labels([r("Z1", "air_humidity"), r("Z1", "co2")]), ["Air humidity", "CO₂"])
        # two sensors on one tag: two gauges, each named
        self.assertEqual(self.labels([r("Z1", "air_humidity", "sht45_1"), r("Z1", "air_humidity", "scd30")]),
                         ["Air humidity · sht45_1", "Air humidity · scd30"])
        # a named sensor alone is still named
        self.assertEqual(self.labels([r("Z1", "co2", "scd30")]), ["CO₂ · scd30"])
        # re-onboarded beside its old readings: 'default' is named too, or two gauges read the same
        self.assertEqual(self.labels([r("Z1", "air_humidity"), r("Z1", "air_humidity", "sht45_1")]),
                         ["Air humidity · default", "Air humidity · sht45_1"])
        # an unknown tag is labelled by its name; a missing sensor counts as 'default'
        self.assertEqual(self.labels([{"zone_code": "Z1", "tag": "lux"}]), ["lux"])

    def test_label_zones(self):
        rows = [r("Z1", "air_humidity", "sht45_1"), r("Z2", "air_humidity", "sht45_1"), r("Z2", "co2")]
        self.assertEqual(self.labels(rows), ["Air humidity · Z1 · sht45_1", "Air humidity · Z2 · sht45_1",
                                             "CO₂ · Z2"])
        # 'default' in one zone is not made visible by a sensor of another zone
        self.assertEqual(self.labels([r("Z1", "co2"), r("Z2", "co2", "scd30")]),
                         ["CO₂ · Z1", "CO₂ · Z2 · scd30"])

    def test_tag_map_from_the_catalogue(self):
        got = run_node("TAG_MAP")
        self.assertEqual(list(got), ["air_temperature", "air_humidity", "co2", "ground_temperature", "light_intensity"])
        self.assertEqual(got["ground_temperature"], {"quantity": "substrate_temperature",
                                                     "label": "Substrate temperature", "unit": "°C"})
        self.assertEqual(got["co2"]["unit"], "ppm")
        self.assertEqual(run_node("tagMapFrom(null)"), {})

    def test_step_limits(self):
        step = {"setpoints": {"substrate_temperature": {"lower": 18, "upper": 22.5}, "co2": {"lower": "x", "upper": 9}}}
        self.assertEqual(run_node("stepLimits(%s, TAG_MAP.ground_temperature)" % json.dumps(step)),
                         {"low": 18, "high": 22.5})
        self.assertEqual(run_node("stepLimits(%s, TAG_MAP.co2)" % json.dumps(step)), {"low": None, "high": 9})
        self.assertEqual(run_node("stepLimits(%s, TAG_MAP.air_humidity)" % json.dumps(step)), {"low": None, "high": None})
        self.assertEqual(run_node("[stepLimits(null, TAG_MAP.co2), stepLimits({}, undefined)]"),
                         [{"low": None, "high": None}] * 2)

    def test_type_label(self):
        self.assertEqual(run_node("[typeLabel(DOC, 'FUNGI'), typeLabel(DOC, 'PLANT'), typeLabel(DOC, 'X'), typeLabel(null, null)]"),
                         ["Fungi", "Plants", "X", ""])

    def test_esc(self):
        self.assertEqual(run_node("esc('<img src=x onerror=\"a\">&\\'')"),
                         "&lt;img src=x onerror=&quot;a&quot;&gt;&amp;&#39;")
        self.assertEqual(run_node("[esc(null), esc(undefined), esc(4.5)]"), ["", "", "4.5"])

    def test_stale(self):
        now = "Date.parse('2026-11-13T10:00:00+00:00')"
        got = run_node("[%s].map(t => isStale({db_timestamp: t}, %s))" % (
            "'2026-11-13T09:49:00+00:00', '2026-11-13T09:59:00+00:00', 'not a date', null, undefined", now))
        self.assertEqual(got, [True, False, False, False, False])
        self.assertFalse(run_node("isStale(null, %s)" % now))


class MonitorPageStaticTest(unittest.TestCase):
    def test_render_uses_the_logic(self):
        page = read(PAGE)
        self.assertIn("function renderGauge(m, step, ctx, nowMs)", page)
        self.assertIn("const label = esc(gaugeLabel(m, ctx));", page)
        # the unknown-tag branch: the raw value and the board's UoM are escaped too
        self.assertIn("${value != null ? esc(value) : '—'} ${esc(m.unit_of_measurement)}", page)
        self.assertIn("orderMeasurements(meas).map(m => renderGauge(m, curStep, ctx, nowMs))", page)
        self.assertNotIn("a.tag.localeCompare", page)
        self.assertIn(".gauge-stale{opacity:.45}", page)
        # migration 011: limits from the step's setpoints, never the old limit columns
        self.assertIn("const { low, high } = stepLimits(step, cfg);", page)
        self.assertNotIn("_lower_limit", page)
        self.assertNotIn("hr_lower", page)
        self.assertIn("await catalogueReady;", page)
        self.assertIn("fetch('/recipe-types.json', { cache: 'no-cache' })", page)

    def test_api_returns_setpoints(self):
        api = read(os.path.join(ROOT, "apps", "monitor", "monitor-api.py"))
        self.assertNotIn("_lower_limit", api)
        self.assertEqual(api.count("rl.setpoints"), 2)       # SELECT and GROUP BY

    def test_deploy_serves_the_catalogue(self):
        d = read(os.path.join(ROOT, "apps", "monitor", "deploy.sh"))
        self.assertIn('python3 "$REPO_ROOT/apps/database/recipe_types.py" json > "$_RT_JSON"', d)
        self.assertIn('--from-file=recipe-types.json="$_RT_JSON"', d)


if __name__ == "__main__":
    unittest.main()
