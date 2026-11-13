"""The Run Monitor's Live Measurements, offline (apps/monitor/html/monitor.html,
feedback control Phase 1).

- The monitor-logic block (pure functions between /* monitor-logic:begin */ and
  /* monitor-logic:end */) runs under node (skipped without node):
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
        f.write(logic_block() + "\nconsole.log(JSON.stringify(" + expr + "));\n")
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
            ["Z1", "co2", "default"],
            ["Z1", "air_humidity", "scd30"], ["Z1", "air_humidity", "sht45_1"],
            ["Z2", "air_humidity", "sht45_1"],
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
        self.assertEqual(self.labels([r("Z1", "air_humidity"), r("Z1", "co2")]), ["Humidity", "CO₂"])
        # two sensors on one tag: two gauges, each named
        self.assertEqual(self.labels([r("Z1", "air_humidity", "sht45_1"), r("Z1", "air_humidity", "scd30")]),
                         ["Humidity · sht45_1", "Humidity · scd30"])
        # a named sensor alone is still named
        self.assertEqual(self.labels([r("Z1", "co2", "scd30")]), ["CO₂ · scd30"])
        # re-onboarded beside its old readings: 'default' is named too, or two gauges read the same
        self.assertEqual(self.labels([r("Z1", "air_humidity"), r("Z1", "air_humidity", "sht45_1")]),
                         ["Humidity · default", "Humidity · sht45_1"])
        # an unknown tag is labelled by its name; a missing sensor counts as 'default'
        self.assertEqual(self.labels([{"zone_code": "Z1", "tag": "lux"}]), ["lux"])

    def test_label_zones(self):
        rows = [r("Z1", "air_humidity", "sht45_1"), r("Z2", "air_humidity", "sht45_1"), r("Z2", "co2")]
        self.assertEqual(self.labels(rows), ["Humidity · Z1 · sht45_1", "Humidity · Z2 · sht45_1",
                                             "CO₂ · Z2"])
        # 'default' in one zone is not made visible by a sensor of another zone
        self.assertEqual(self.labels([r("Z1", "co2"), r("Z2", "co2", "scd30")]),
                         ["CO₂ · Z1", "CO₂ · Z2 · scd30"])

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


if __name__ == "__main__":
    unittest.main()
