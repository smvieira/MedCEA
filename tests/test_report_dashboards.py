"""Grafana's provisioned dashboards, static (apps/report/dashboards/*.json; feedback
control Phase 1).

A board may carry two sensors of one quantity (SHT45 and SCD30 both publish
air_humidity), and the views msg_actual_points/v_ap_measurements name each reading's
instance in `sensor` ('default' for a board flashed before Phase 1). A panel that reads
one tag and does not name sensor would mix them: a gauge flipping to whichever sensor
wrote last, an average of a self-heating SCD30 with an SHT45, a table's MAX over both.

- every file is valid JSON with unique panel ids (rows' nested panels included);
- every rawSql that reads msg_actual_points or v_ap_measurements and filters on tag
  names sensor; a time_series one puts it in its series name (`metric`), so each zone and
  sensor is its own series;
- the "Latest Readings" table shows the latest value per zone, device and sensor, not
  a MAX over the time window.

Run: python3 tests/test_report_dashboards.py
"""
import glob
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARDS = sorted(glob.glob(os.path.join(ROOT, "apps", "report", "dashboards", "*.json")))
READINGS = re.compile(r"\bmedcea\.(msg_actual_points|v_ap_measurements)\b")
TAG_FILTER = re.compile(r"\btag\s*(=|IN\b)", re.I)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def panels(doc):
    for p in doc.get("panels", []):
        yield p
        yield from p.get("panels", [])          # a collapsed row keeps its panels inside


def targets(doc):
    for p in panels(doc):
        for t in p.get("targets", []):
            if "rawSql" in t:
                yield p, t


class DashboardTest(unittest.TestCase):
    def test_files_exist(self):
        self.assertTrue(DASHBOARDS)

    def test_valid_json_unique_ids(self):
        for path in DASHBOARDS:
            ids = [p["id"] for p in panels(load(path)) if "id" in p]
            self.assertEqual(len(ids), len(set(ids)), path)

    def test_per_tag_reads_name_the_sensor(self):
        seen = 0
        for path in DASHBOARDS:
            for p, t in targets(load(path)):
                sql = t["rawSql"]
                if not (READINGS.search(sql) and TAG_FILTER.search(sql)):
                    continue
                seen += 1
                where = "%s: panel %s %r" % (os.path.basename(path), p.get("id"), p.get("title"))
                self.assertRegex(sql, r"\bsensor\b", where)
                if t.get("format") == "time_series":
                    self.assertIn("concat_ws(' / ', zone_code, sensor) AS metric", sql, where)
        self.assertGreaterEqual(seen, 7)        # three gauges, three trends, the table

    def test_latest_table_is_the_latest(self):
        doc = load(os.path.join(ROOT, "apps", "report", "dashboards", "iot-monitoring.json"))
        (sql,) = [t["rawSql"] for p, t in targets(doc) if p.get("id") == 20]
        flat = " ".join(sql.split())
        self.assertIn("sensor AS \"Sensor\"", flat)
        self.assertIn("SELECT DISTINCT ON (zone_code, device_dns, sensor, tag)", flat)
        self.assertIn("ORDER BY zone_code, device_dns, sensor, tag, record_timestamp DESC", flat)
        self.assertIn("GROUP BY zone_code, device_dns, sensor", flat)
        # the column overrides still name the pivot's columns
        names = {m["matcher"]["options"] for p in panels(doc) if p.get("id") == 20
                 for m in p["fieldConfig"].get("overrides", []) if m["matcher"]["id"] == "byName"}
        for name in names:
            self.assertIn('"%s"' % name, sql)


if __name__ == "__main__":
    unittest.main()
