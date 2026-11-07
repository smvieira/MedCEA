#!/usr/bin/env python3
"""Board templates (device_template.py board-templates / board-template /
save-board-template), offline: a save -> list -> load round trip in a scratch
CEA_BOARD_TEMPLATES_DIR, and every refusal (bad slug, a shipped slug, an existing
slug without --replace, a document with errors, missing options). Nothing is
written outside the mktemp folder."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "edge", "src", "host", "device_template.py")
SHIPPED = os.path.join(ROOT, "edge", "templates", "boards")
REF_SLUG = "sense-hub-sht45-scd30-lux"
BENCH_SLUG = "sense-hub-bench-sht45-scd30"


def reference():
    with open(os.path.join(SHIPPED, REF_SLUG + ".json"), encoding="utf-8") as f:
        return json.load(f)["wiring"]


class BoardTemplates(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="board-templates-")
        self.saved = os.path.join(self.dir, "saved")       # created by the first save

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_tool(self, args, stdin=""):
        env = dict(os.environ, CEA_BOARD_TEMPLATES_DIR=self.saved)
        return subprocess.run([sys.executable, TOOL] + args, input=stdin, text=True,
                              capture_output=True, env=env, timeout=60)

    def save(self, slug, doc=None, *extra):
        return self.run_tool(["save-board-template", slug, "--title", "Bench board",
                              "--by", "tester"] + list(extra),
                             json.dumps(reference() if doc is None else doc))

    def listing(self, variant=None):
        r = self.run_tool(["board-templates", "SENSE"] + ([variant] if variant else []))
        self.assertEqual(r.returncode, 0, r.stderr)
        return [line.split("\t") for line in r.stdout.splitlines()]

    def test_shipped_reference_is_valid(self):
        rows = self.listing()
        self.assertEqual(rows, [
            [BENCH_SLUG, "Sense board as bench-tested 6 Nov 2026: hub + SHT45 ch7 + SCD30 ch6",
             "esp32s3", "shipped", "1", "-"],
            [REF_SLUG, "Sense board, chamber design map: hub + SHT45 ch0 + SCD30 ch1 + SEN0562 ch2",
             "esp32s3", "shipped", "1", "-"]])
        with open(os.path.join(SHIPPED, REF_SLUG + ".json"), encoding="utf-8") as f:
            rec = json.load(f)
        self.assertEqual(rec["slug"], REF_SLUG)
        self.assertEqual(rec["saved_by"], "medcea")
        self.assertEqual(set(rec), {"slug", "title", "description", "variant", "saved_by",
                                    "saved_at", "wiring"})

    def test_the_bench_template_is_the_tested_wiring(self):
        # The owner's bench test (i2c_hub_test.py rev3, 6 Nov 2026) passed on exactly
        # this: hardware I2C(0), GPIO8/9, 100 kHz, a TCA9548A at 0x70, SHT45 on ch7,
        # SCD30 on ch6 with CO2 only, nothing else on the hub or the root bus.
        got = self.run_tool(["board-template", BENCH_SLUG])
        self.assertEqual(got.returncode, 0, got.stderr)
        doc = json.loads(got.stdout)
        self.assertEqual(doc["buses"], [{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9,
                                         "freq": 100000, "impl": "hw", "pullups": "external"}])
        self.assertEqual(doc["hubs"], [{"id": "mux0", "kind": "tca9548a", "bus": "i2c0", "addr": 0x70}])
        self.assertEqual(sorted((s["driver"], s["hub"], s["channel"], s["addr"]) for s in doc["sensors"]),
                         [("scd30", "mux0", 6, 0x61), ("sht4x", "mux0", 7, 0x44)])
        tags = {s["driver"]: {t["q"]: t["tag"] for t in s["tags"]} for s in doc["sensors"]}
        self.assertEqual(tags["scd30"], {"co2": "co2", "temperature": None, "humidity": None})
        self.assertEqual(tags["sht4x"], {"temperature": "air_temperature", "humidity": "air_humidity"})
        v = self.run_tool(["validate-wiring", "SENSE", "esp32s3"], got.stdout)
        self.assertEqual(json.loads(v.stdout), {"findings": [], "errors": 0, "warnings": 0})

    def test_round_trip(self):
        doc = reference()
        doc["sensors"][2]["tags"][0]["tag"] = "lux"
        r = self.save("bench-one", doc, "--description", "For the bench")
        self.assertEqual(r.returncode, 0, r.stderr)
        path = os.path.join(self.saved, "bench-one.json")
        self.assertEqual(r.stdout.strip(), path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        self.assertEqual(sorted(os.listdir(self.saved)), ["bench-one.json"])   # no temp left
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        self.assertEqual(rec["title"], "Bench board")
        self.assertEqual(rec["description"], "For the bench")
        self.assertEqual(rec["saved_by"], "tester")
        self.assertEqual(rec["variant"], "esp32s3")
        self.assertRegex(rec["saved_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertNotIn("replaced_at", rec)
        self.assertEqual(rec["wiring"], doc)

        rows = self.listing()
        self.assertEqual([r[0] for r in rows], [BENCH_SLUG, REF_SLUG, "bench-one"])
        self.assertEqual(rows[2][3:], ["saved", "1", "-"])

        got = self.run_tool(["board-template", "bench-one"])
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(got.stdout), doc)
        got = self.run_tool(["board-template", REF_SLUG])
        self.assertEqual(json.loads(got.stdout), reference())

        spec = json.loads(self.run_tool(["wiring-spec", "SENSE"]).stdout)
        self.assertEqual([(t["slug"], t["source"]) for t in spec["templates"]],
                         [(BENCH_SLUG, "shipped"), (REF_SLUG, "shipped"), ("bench-one", "saved")])
        self.assertEqual(spec["templates"][2]["wiring"], doc)

    def test_whole_number_floats_are_saved_as_ints(self):
        doc = reference()
        doc["hubs"][0]["addr"] = 112.0
        r = self.save("bench-float", doc)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.saved, "bench-float.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["wiring"], reference())
        with open(os.path.join(self.saved, "bench-float.json"), encoding="utf-8") as f:
            self.assertNotIn("112.0", f.read())

    def test_listing_greys_out_a_template_for_another_chip(self):
        rows = self.listing("esp32")
        self.assertEqual(rows[0][4], "0")
        self.assertIn("ESP32", rows[0][5])

    def test_invalid_file_on_disk_is_listed_not_hidden(self):
        os.makedirs(self.saved)
        with open(os.path.join(self.saved, "hand-made.json"), "w") as f:
            json.dump({"slug": "hand-made", "title": "By hand", "variant": "esp32s3",
                       "wiring": dict(reference(), version=2)}, f)
        with open(os.path.join(self.saved, "garbage.json"), "w") as f:
            f.write("{")
        rows = {r[0]: r for r in self.listing()}
        self.assertEqual(rows["hand-made"][4], "0")
        self.assertIn("version", rows["hand-made"][5])
        self.assertEqual(rows["garbage"][4], "0")

    def test_refusals(self):
        bad_doc = reference()
        bad_doc["sensors"][1]["tags"][1]["tag"] = "air_temperature"     # E_TAG_DUP
        for slug, doc, why in (("Bench", None, "usable name"), ("b", None, "usable name"),
                               ("x" * 42, None, "usable name"), ("bench_one", None, "usable name"),
                               (REF_SLUG, None, "shipped"), ("bench-bad", bad_doc, "E_TAG_DUP")):
            with self.subTest(slug):
                r = self.save(slug, doc)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn(why, r.stderr)
                self.assertFalse(os.path.exists(self.saved) and os.listdir(self.saved))
        r = self.run_tool(["save-board-template", "bench-x", "--title", "T", "--by", "u"], "{")
        self.assertEqual(r.returncode, 1)

    def test_usage(self):
        doc = json.dumps(reference())
        for args in (["save-board-template"], ["save-board-template", "bench-one"],
                     ["save-board-template", "bench-one", "--title", "T"],
                     ["save-board-template", "bench-one", "--by", "u"],
                     ["save-board-template", "bench-one", "--title", "T", "--by", "u", "--force"],
                     ["save-board-template", "bench-one", "--title"],
                     ["board-templates", "CONTROL"], ["board-template"]):
            with self.subTest(args):
                self.assertEqual(self.run_tool(args, doc).returncode, 2)
        self.assertFalse(os.path.exists(self.saved))
        self.assertEqual(self.run_tool(["board-template", "nope"]).returncode, 1)
        self.assertEqual(self.run_tool(["board-template", "../x"]).returncode, 1)

    def test_no_overwrite_without_replace(self):
        self.assertEqual(self.save("bench-one").returncode, 0)
        path = os.path.join(self.saved, "bench-one.json")
        with open(path) as f:
            first = json.load(f)
        first["saved_at"] = "2026-01-02T03:04:05Z"   # as if saved long ago
        with open(path, "w") as f:
            json.dump(first, f)
        doc = reference()
        doc["sensors"][2]["tags"][0]["tag"] = "lux"
        r = self.save("bench-one", doc)
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exists", r.stderr)
        with open(os.path.join(self.saved, "bench-one.json")) as f:
            self.assertEqual(json.load(f)["wiring"], reference())
        r = self.save("bench-one", doc, "--replace")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.saved, "bench-one.json")) as f:
            rec = json.load(f)
        self.assertEqual(rec["wiring"], doc)
        self.assertIn("replaced_at", rec)
        self.assertEqual(rec["saved_at"], "2026-01-02T03:04:05Z")
        self.assertNotEqual(rec["replaced_at"], rec["saved_at"])
        self.assertEqual(sorted(os.listdir(self.saved)), ["bench-one.json"])

    def test_title_must_be_one_line(self):
        r = self.run_tool(["save-board-template", "bench-one", "--title", "a\nb", "--by", "u"],
                          json.dumps(reference()))
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
