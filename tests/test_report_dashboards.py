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

The standard reports (owner decision of 17 Nov 2026: Grafana is the platform's tool for
standard reports; runs per unit, run history, release status, device and zone health):

- every dashboard has a uid and a title of its own, and the four reports exist;
- every rawSql and every query variable reads only what svc_grafana, the datasource's
  login, may SELECT: the set is compiled from the policy (`cli.py --defaults compile
  grants --mode enforce --format json`, run in a scratch_repo() copy), and every
  FROM/JOIN names a schema-qualified object of it (a view of it must also not read a
  table outside it: run_history/run_watch are granted but security_invoker over recipe
  and recipe_line, which svc_grafana may not read, so they are refused here);
- deploy.sh and uninstall.sh take every file in dashboards/ (a glob, not a list), the
  file names are valid ConfigMap keys, and all of them together stay well under the
  256 KiB that kubectl apply's last-applied annotation may hold;
- the provider keeps allowUiUpdates: false and puts them in one folder;
- a variable with All that a query uses in `IN ($var)` has an allValue (a subquery or a
  literal list), since Grafana expands All over no options to `IN ()`, a syntax error
  on an install with no unit or run yet; its objects are checked like any query;
- every read of medcea.measurement in Device and Zone Health is driven by zone_id and
  bounded in time (its only index is (zone_id, measure_timestamp) and the table is never
  pruned), and that dashboard refreshes no more often than every 5 minutes.

Run: python3 tests/test_report_dashboards.py
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import clean_env, scratch_repo  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARDS = sorted(glob.glob(os.path.join(ROOT, "apps", "report", "dashboards", "*.json")))
READINGS = re.compile(r"\bmedcea\.(msg_actual_points|v_ap_measurements)\b")
TAG_FILTER = re.compile(r"\btag\s*(=|IN\b)", re.I)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def panels(doc):
    for p in doc.get("panels", []):
        yield p
        yield from p.get("panels", [])          # a collapsed row keeps its panels inside


def targets(doc):
    for p in panels(doc):
        for t in p.get("targets", []):
            if "rawSql" in t:
                yield p, t


def queries(doc):
    """(where, sql) for every panel rawSql and every query variable."""
    for p, t in targets(doc):
        yield "panel %s %r" % (p.get("id"), p.get("title")), t["rawSql"]
    for v in doc.get("templating", {}).get("list", []):
        if v.get("type") == "query":
            yield "variable %s" % v.get("name"), v["query"]
        if v.get("allValue"):
            yield "variable %s allValue" % v.get("name"), v["allValue"]


REPORTS = {   # file → uid, the standard report set of 17 Nov 2026
    "runs-per-unit.json": "medcea-runs-per-unit",
    "run-history.json": "medcea-run-history",
    "release-status.json": "medcea-release-status",
    "device-zone-health.json": "medcea-device-zone-health",
    "control-loops.json": "medcea-control-loops",       # 21 Nov 2026
}
# Granted to svc_grafana but security_invoker views over tables it may not read.
UNREADABLE_VIEWS = {"medcea.run_history", "medcea.run_watch"}
RELATION = re.compile(r"\b(?:FROM|JOIN)\s+(?:LATERAL\s+)?([A-Za-z_][\w.]*)(\s*\()?", re.I)
EXTRACT = re.compile(r"\b(extract|substring|trim)\s*\(\s*\w+\s+FROM\b", re.I)   # not a relation
QUALIFIED = re.compile(r"\b(medcea|medcea_auth|iam|iam_policy|public|pg_catalog|information_schema)\.(\w+)\b")


def grafana_select_set():
    """The tables and views svc_grafana may SELECT, compiled from defaults.yaml offline."""
    root = scratch_repo()
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(root, "apps", "iam", "compiler", "cli.py"), "--defaults",
             "compile", "grants", "--mode", "enforce", "--format", "json"],
            capture_output=True, text=True, env=clean_env(), check=True).stdout
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return {obj for role, kind, obj, priv in json.loads(out)["privileges"]
            if role == "svc_grafana" and kind == "table" and priv == "SELECT"}


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


class StandardReportsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = {os.path.basename(p): load(p) for p in DASHBOARDS}
        cls.readable = grafana_select_set()

    def test_the_reports_exist(self):
        for name, uid in REPORTS.items():
            self.assertIn(name, self.docs)
            self.assertEqual(self.docs[name]["uid"], uid, name)
            self.assertIn("report", self.docs[name].get("tags", []), name)

    def test_unique_uids_and_titles(self):
        uids = [d.get("uid") for d in self.docs.values()]
        titles = [d.get("title") for d in self.docs.values()]
        self.assertTrue(all(uids) and all(titles))
        self.assertEqual(len(uids), len(set(uids)))
        self.assertEqual(len(titles), len(set(titles)))
        for uid in uids:
            self.assertRegex(uid, r"^[A-Za-z0-9_-]{1,40}$")

    def test_the_datasource_is_the_platform_one(self):
        for name, doc in self.docs.items():
            for p in panels(doc):
                if p.get("type") == "row":
                    continue
                self.assertEqual(p["datasource"]["uid"], "PA68174188487FD5C", (name, p.get("id")))
                for t in p.get("targets", []):
                    self.assertEqual(t["datasource"]["uid"], "PA68174188487FD5C", (name, p.get("id")))

    def test_the_compiled_set(self):
        # what this test checks against; a policy change that moves it is a decision
        self.assertTrue({"medcea.recipe_run", "medcea.recipe_line_cycle_run", "medcea.run_release",
                         "medcea.measurement", "medcea.cea_unit", "medcea.cea_zone",
                         "medcea.msg_actual_points"} <= self.readable, sorted(self.readable))
        for unreadable in ("medcea.recipe", "medcea.recipe_line", "medcea.device"):
            self.assertNotIn(unreadable, self.readable)

    def test_every_query_reads_only_what_svc_grafana_may(self):
        allowed = self.readable - UNREADABLE_VIEWS
        seen = 0
        for name, doc in self.docs.items():
            for where, sql in queries(doc):
                seen += 1
                at = "%s: %s" % (name, where)
                for m in QUALIFIED.finditer(sql):
                    self.assertIn(m.group(0), allowed, at)
                for m in RELATION.finditer(EXTRACT.sub(r"\1(", sql)):
                    if m.group(2):          # a function call: jsonb_array_elements(…)
                        continue
                    self.assertIn(m.group(1), allowed, at)
        self.assertGreaterEqual(seen, 30)

    def test_deploy_ships_every_file(self):
        deploy, uninstall = (read(os.path.join("apps", "report", f)) for f in ("deploy.sh", "uninstall.sh"))
        self.assertIn('for f in "$DASHBOARDS_DIR"/*.json; do echo "--from-file=$(basename "$f")=$f"; done', deploy)
        self.assertIn('for DASHBOARD_FILE in "$DASHBOARDS_DIR"/*.json; do', deploy)
        self.assertIn('for f in "$DASHBOARDS_DIR"/*.json; do', uninstall)
        files = os.listdir(os.path.join(ROOT, "apps", "report", "dashboards"))
        self.assertEqual(sorted(f for f in files if not f.endswith(".json")), [])
        for f in files:
            self.assertRegex(f, r"^[-._a-zA-Z0-9]+$")
        self.assertLess(sum(os.path.getsize(p) for p in DASHBOARDS), 160 * 1024)

    def test_all_never_expands_to_an_empty_list(self):
        used = 0
        for name, doc in self.docs.items():
            sql = " ".join(t["rawSql"] for _, t in targets(doc))
            for v in doc.get("templating", {}).get("list", []):
                if v.get("includeAll") and ("IN ($%s)" % v["name"]) in sql:
                    used += 1
                    self.assertTrue((v.get("allValue") or "").strip(), (name, v["name"]))
        self.assertGreaterEqual(used, 6)    # $unit in the four reports, $recipe and $status

    def test_measurement_reads_are_zone_driven_and_bounded(self):
        doc = self.docs["device-zone-health.json"]
        self.assertEqual(doc["refresh"], "5m")
        reads = 0
        for where, sql in queries(doc):
            for chunk in sql.split("FROM medcea.measurement")[1:]:
                reads += 1
                head = chunk[:400]
                self.assertRegex(head, r"\bm\.zone_id\s*(=|IN\b)", where)
                self.assertRegex(head, r"\$__timeFrom\(\)|\$__timeFilter\(m\.measure_timestamp\)|"
                                       r"m\.measure_timestamp >= now\(\) - interval", where)
        self.assertGreaterEqual(reads, 8)

    def test_the_provider(self):
        provider = read(os.path.join("apps", "report", "k8s", "dashboard-provider.yaml"))
        self.assertIn("allowUiUpdates: false", provider)
        self.assertIn("folder: MedCEA", provider)


class ControlLoopsTest(unittest.TestCase):
    """Control Loops (21 Nov 2026): per quantity, each sensor, the value the loop used, the
    bounds of the recipe step from the cycle's recorded run_params (run_history is not
    readable by svc_grafana), and the command sent with what it does."""

    @classmethod
    def setUpClass(cls):
        cls.doc = load(os.path.join(ROOT, "apps", "report", "dashboards", "control-loops.json"))
        cls.sql = {p.get("title"): [t["rawSql"] for t in p.get("targets", [])] for p in panels(cls.doc)}

    def test_one_block_per_quantity(self):
        (row,) = [p for p in panels(self.doc) if p.get("repeat")]
        self.assertEqual(row["repeat"], "quantity")
        q = [v for v in self.doc["templating"]["list"] if v["name"] == "quantity"][0]
        for code in ("air_temperature", "air_humidity", "co2", "substrate_temperature"):
            self.assertIn(": " + code, q["query"])

    def test_bounds_come_from_the_cycles_recorded_parameters(self):
        flat = " ".join(sum(self.sql.values(), []))
        self.assertIn("FROM medcea.recipe_line_cycle_run c", flat)
        self.assertIn("->'setpoints'->'$quantity'->>'lower'", flat)
        self.assertNotIn("run_history", flat)

    def test_every_sensor_and_the_value_used_are_separate_series(self):
        (ts,) = [p for p in panels(self.doc) if p.get("type") == "timeseries"]
        names = [t["rawSql"] for t in ts["targets"]]
        self.assertIn("concat_ws(' / ', zone_code, sensor) AS metric", names[0])
        self.assertIn("'Value the loop used' AS metric", names[1])
        self.assertIn('"Recipe lower bound"', names[2])

    def test_commands_say_what_they_do(self):
        flat = " ".join(sum(self.sql.values(), []))
        self.assertIn("UP: fresh-air fan on (lowers CO₂)", flat)       # co2's command map: UP lowers it
        self.assertIn("UP: humidifier on (raises humidity)", flat)
        self.assertIn("DOWN: cooling on", flat)
        self.assertIn("(held: no fresh reading)", flat)


if __name__ == "__main__":
    unittest.main()
