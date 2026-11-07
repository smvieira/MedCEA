#!/usr/bin/env python3
"""A SENSE board's wiring (edge/src/host/wiring.py), offline: every fixture in
tests/fixtures/wiring/ gives exactly its (level, code, where) set (the UI's
parity test reads the same files), render_sense() and the render() branch, the
legacy question-loop render byte for byte against the golden taken before the
wiring branch existed, and the CLI (wiring-spec size, validate-wiring exits)."""
import copy
import glob
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.path.join(ROOT, "edge", "src", "host")
TOOL = os.path.join(HOST, "device_template.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "wiring")
LEGACY = os.path.join(FIXTURES, "legacy")
REFERENCE = os.path.join(ROOT, "edge", "templates", "boards", "sense-hub-sht45-scd30-lux.json")
sys.path.insert(0, HOST)

import device_template  # noqa: E402
import wiring  # noqa: E402

CODES = {
    "error": ("E_SCHEMA", "E_VARIANT", "E_DRIVER", "E_PIN_RANGE", "E_PIN_GROUP", "E_PIN_DUP",
              "E_BUS_REF", "E_BUS_KIND", "E_BUS_FREQ", "E_ADDR_RANGE", "E_ADDR_OPTION",
              "E_ADDR_CLASH", "E_HUB", "E_UNWIRED", "E_TAG", "E_TAG_DUP", "E_NO_SENSOR"),
    "warn": ("W_PIN_GROUP", "W_PULLUPS", "W_HUB_UNUSED", "W_TAG_OFF",
             "W_POWER"),
}
# W_POWER needs a part with no 3V3 rail; none ships yet (the SEN0604 is stage 2), so
# it is tested below on a patched template instead of a fixture.
NO_FIXTURE = {"W_POWER"}


def fixtures():
    out = {}
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
        with open(path, encoding="utf-8") as f:
            out[os.path.basename(path)[:-5]] = json.load(f)
    return out


def reference():
    with open(REFERENCE, encoding="utf-8") as f:
        return json.load(f)["wiring"]


def run(args, stdin="", env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([sys.executable, TOOL] + args, input=stdin, text=True,
                          capture_output=True, env=e, timeout=60)


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tpl = device_template.load("SENSE")

    def test_each_fixture_gives_exactly_its_set(self):
        for name, fx in fixtures().items():
            with self.subTest(name):
                self.assertEqual(set(fx), {"variant", "doc", "expect"} | ({"note"} & set(fx)))
                got = {(f["level"], f["code"], f["where"])
                       for f in wiring.validate(fx["doc"], self.tpl, fx["variant"])}
                self.assertEqual(got, {tuple(e) for e in fx["expect"]})

    def test_every_code_has_a_fixture(self):
        seen = {e[1] for fx in fixtures().values() for e in fx["expect"]}
        for level, codes in CODES.items():
            for code in codes:
                if code not in NO_FIXTURE:
                    self.assertIn(code, seen, "no fixture triggers %s" % code)
        # and nothing outside the contract's list
        self.assertLessEqual(seen, set(CODES["error"]) | set(CODES["warn"]))

    def test_levels_match_the_code_prefix(self):
        for fx in fixtures().values():
            for level, code, _w in fx["expect"]:
                self.assertEqual(level, "error" if code.startswith("E_") else "warn", code)

    def test_findings_are_complete_dicts_in_a_stable_order(self):
        for name, fx in fixtures().items():
            a = wiring.validate(fx["doc"], self.tpl, fx["variant"])
            b = wiring.validate(copy.deepcopy(fx["doc"]), self.tpl, fx["variant"])
            self.assertEqual(a, b, name)
            for f in a:
                self.assertEqual(set(f), {"level", "code", "where", "message"})
                self.assertTrue(f["message"].strip(), name)

    def test_named_cases(self):
        fx = fixtures()
        self.assertEqual(fx["ok-reference-board"]["expect"], [])
        self.assertEqual(fx["ok-same-driver-two-channels"]["expect"], [])
        self.assertIn(["error", "E_PIN_GROUP", "buses.i2c0.sda"], fx["gpio8-on-esp32"]["expect"])
        self.assertEqual(fx["ok-reference-board"]["doc"], reference())


class Validate(unittest.TestCase):
    def setUp(self):
        self.tpl = device_template.load("SENSE")

    def codes(self, doc, variant="esp32s3", tpl=None):
        return {(f["code"], f["where"]) for f in wiring.validate(doc, tpl or self.tpl, variant)}

    def test_gpio8_9_pass_on_s3_fail_on_esp32(self):
        doc = reference()
        self.assertEqual(self.codes(doc), set())
        bad = self.codes(doc, "esp32")
        self.assertIn(("E_PIN_GROUP", "buses.i2c0.sda"), bad)
        self.assertIn(("E_PIN_GROUP", "buses.i2c0.scl"), bad)

    def test_rx_may_be_input_only(self):
        # The contract's rule for stage 2: an input-only pin is refused for a line
        # the board drives, never for RX. RS485 itself is still refused (E_BUS_KIND).
        doc = reference()
        doc["board"] = {"variant": "esp32"}
        doc["buses"][0].update(sda=21, scl=22)
        doc["buses"].append({"id": "rs485a", "kind": "rs485", "uart": 1, "tx": 34,
                             "rx": 35, "de": 25})
        got = self.codes(doc, "esp32")
        self.assertIn(("E_PIN_GROUP", "buses.rs485a.tx"), got)
        self.assertNotIn(("E_PIN_GROUP", "buses.rs485a.rx"), got)
        self.assertIn(("E_BUS_KIND", "buses.rs485a"), got)

    def test_power_warning_from_the_template(self):
        tpl = copy.deepcopy(self.tpl)
        for d in tpl["drivers"]:
            if d["id"] == "sen0562":
                d["power"] = {"rails": ["12V"]}
        got = wiring.validate(reference(), tpl, "esp32s3")
        self.assertEqual({(f["level"], f["code"], f["where"]) for f in got},
                         {("warn", "W_POWER", "sensors.lux_1")})
        self.assertIn("12V", got[0]["message"])

    def test_variant_argument_wins_over_the_document(self):
        doc = reference()
        doc["board"] = {"variant": "esp32"}
        self.assertIn(("E_PIN_GROUP", "buses.i2c0.sda"), self.codes(doc, None))
        self.assertEqual(self.codes(doc, "esp32s3"), set())

    def test_a_clash_on_a_hub_address(self):
        doc = reference()
        doc["sensors"][0].update(addr=112, driver="sht4x")
        got = self.codes(doc)
        self.assertIn(("E_ADDR_OPTION", "sensors.sht45_1.addr"), got)
        self.assertIn(("E_ADDR_CLASH", "sensors.sht45_1.addr"), got)

    def test_schema_errors_stop_the_rest(self):
        doc = reference()
        doc["buses"][0]["sda"] = "8"
        doc["sensors"][0]["tags"][0]["tag"] = "Bad"
        self.assertEqual(self.codes(doc), {("E_SCHEMA", "buses.i2c0")})

    def test_template_data(self):
        drv = wiring.wiring_drivers(self.tpl)
        self.assertEqual(sorted(drv), ["scd30", "sen0562", "sht4x"])
        self.assertEqual(drv["sht4x"]["bus"]["addrs"], [68, 69, 70])
        self.assertEqual(drv["scd30"]["bus"]["max_freq"], 100000)
        self.assertTrue(drv["scd30"]["bus"]["clock_stretch"])
        self.assertTrue(all(p.get("legacy_bus") for p in drv["scd30"]["params"]))
        self.assertEqual(drv["sen0562"]["bus"]["addrs"], [35])
        self.assertEqual(self.tpl["hubs"][0]["addrs"], list(range(112, 120)))
        self.assertEqual(self.tpl["boards"][0]["i2c_defaults"], {"sda": 8, "scl": 9})
        for d in drv.values():
            self.assertIn("3V3", d["power"]["rails"])
            for q in d["quantities"]:
                self.assertRegex(q["tag"], wiring.TAG_RX.pattern)


BASE_SPEC = {"role": "SENSE", "unit_code": "UNIT02", "zone_code": "ZONE01", "zone_id": 7,
             "hostname": "unit02-s-zone01", "wifi_ssid": "bench", "wifi_psk": "not-a-secret",
             "mqtt_host": "192.0.2.10", "mqtt_port": 31884, "mqtt_tls_name": "mqtt.medcea",
             "mqtt_user": "unit02-s-zone01", "mqtt_pass": "fixture-pass",
             "topic_root": "medcea", "message_interval": 30, "mac": "aa:bb:cc:dd:ee:ff",
             "firmware": "ESP32_GENERIC_S3.bin", "firmware_sha256": "0" * 64,
             "flashed_at": "20261106120000"}


class Render(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sense-wiring-")
        self.tpl = device_template.load("SENSE")

    def tearDown(self):
        for n in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, n))
        os.rmdir(self.tmp)

    def cfg_text(self):
        with open(os.path.join(self.tmp, "device_cfg.py"), encoding="utf-8") as f:
            return f.read()

    def test_legacy_render_is_byte_identical(self):
        for name in ("scd30_ground", "scd4x"):
            with self.subTest(name):
                with open(os.path.join(LEGACY, name + ".spec.json")) as f:
                    spec = json.load(f)
                spec["out_dir"] = self.tmp
                res = device_template.render(spec)
                res.pop("config")
                with open(os.path.join(LEGACY, name + ".device_cfg.py")) as f:
                    self.assertEqual(self.cfg_text(), f.read())
                with open(os.path.join(LEGACY, name + ".result.json")) as f:
                    self.assertEqual(json.loads(json.dumps(res)), json.load(f))

    def test_legacy_driver_listing_unchanged(self):
        r = run(["drivers", "SENSE"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(LEGACY, "drivers-SENSE.tsv")) as f:
            self.assertEqual(r.stdout, f.read())
        out = "".join(run(["params", "SENSE", d]).stdout
                      for d in ("scd4x", "scd30", "ground_temperature", "water_level"))
        with open(os.path.join(LEGACY, "params-SENSE.tsv")) as f:
            self.assertEqual(out, f.read())

    def test_legacy_refuses_a_wiring_only_driver(self):
        spec = dict(BASE_SPEC, out_dir=self.tmp, components=[{"driver": "sht4x", "params": {}}])
        with self.assertRaises(device_template.TemplateError):
            device_template.render(spec)

    def test_wiring_render(self):
        doc = reference()
        doc["sensors"].append({"id": "sht45_2", "driver": "sht4x", "bus": "i2c0", "hub": "mux0",
                               "channel": 3, "addr": 68, "params": {},
                               "tags": [{"q": "temperature", "tag": "air_temperature_2"},
                                        {"q": "humidity", "tag": None}]})
        spec = dict(BASE_SPEC, out_dir=self.tmp, wiring=doc, variant="esp32s3")
        res = device_template.render(spec)
        cfg = res["config"]
        self.assertEqual(cfg["WIRING_VERSION"], 1)
        self.assertEqual(cfg["BUSES"], [{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9,
                                         "freq": 100000, "impl": "hw"}])
        self.assertEqual(cfg["HUBS"], [{"id": "mux0", "kind": "tca9548a", "bus": "i2c0",
                                        "addr": 112}])
        self.assertEqual(cfg["SENSORS"][0], {
            "id": "sht45_1", "driver": "sht4x", "bus": "i2c0", "hub": "mux0", "channel": 0,
            "addr": 68, "params": {}, "tags": [["temperature", "air_temperature", "C"],
                                               ["humidity", "air_humidity", "RH%"]]})
        self.assertEqual(cfg["SENSORS"][1]["tags"], [["co2", "co2", "ppm"]])
        self.assertEqual(cfg["SENSORS"][1]["params"], {})     # scl/sda are the bus's now
        self.assertEqual(cfg["SENSORS"][3]["tags"], [["temperature", "air_temperature_2", "C"]])
        # one row per instance, the driver twice
        comps = res["components"]
        self.assertEqual([c["parameters"]["instance"] for c in comps],
                         ["sht45_1", "scd30_1", "lux_1", "sht45_2"])
        p = comps[2]["parameters"]
        self.assertEqual(comps[2]["model"], "SEN0562")
        self.assertEqual(comps[2]["manufacturer"], "DFRobot")
        self.assertEqual(p["addr"], 35)
        self.assertEqual(p["wiring"], {"bus": {"kind": "i2c", "sda": 8, "scl": 9, "freq": 100000},
                                       "hub": {"kind": "tca9548a", "addr": 112, "channel": 2}})
        self.assertEqual(p["tags"], [{"tag": "light_intensity", "UoM": "lx",
                                      "topic": "medcea/UNIT02/ZONE01/sense/light_intensity"}])
        self.assertEqual(p["topic_base"], "medcea/UNIT02/ZONE01/sense")
        self.assertEqual(p["mqtt"], {"host": "192.0.2.10", "port": 31884})
        self.assertNotIn("fixture-pass", json.dumps(comps))
        text = self.cfg_text()
        self.assertIn("WIRING_VERSION   = 1\n", text)
        self.assertIn('BUSES            = [{"id": "i2c0"', text)
        self.assertIn('"hub": "mux0", "channel": 0', text)
        compile(text, "device_cfg.py", "exec")

    def test_direct_sensor_has_no_hub(self):
        doc = reference()
        doc["sensors"][2].update(hub=None, channel=None)
        res = device_template.render(dict(BASE_SPEC, out_dir=self.tmp, wiring=doc))
        self.assertEqual(res["config"]["SENSORS"][2]["hub"], None)
        self.assertEqual(res["config"]["SENSORS"][2]["channel"], None)
        self.assertIsNone(res["components"][2]["parameters"]["wiring"]["hub"])

    def test_render_refuses_errors_and_writes_nothing(self):
        for variant, mutate in (("esp32", lambda d: None),
                                ("esp32s3", lambda d: d["sensors"][1]["tags"][1].update(
                                    tag="air_temperature"))):
            doc = reference()
            mutate(doc)
            with self.assertRaises(device_template.TemplateError) as ctx:
                device_template.render(dict(BASE_SPEC, out_dir=self.tmp, wiring=doc,
                                            variant=variant))
            self.assertIn("error", str(ctx.exception))
            self.assertEqual(os.listdir(self.tmp), [])

    def test_render_sense_direct(self):
        got = wiring.render_sense(reference(), self.tpl, "esp32s3", base_topic="r/U/Z")
        self.assertEqual(len(got["components"]), 3)
        self.assertEqual(sorted(got["cfg"]), ["BUSES", "HUBS", "SENSORS", "WIRING_VERSION"])
        with self.assertRaises(wiring.WiringError):
            wiring.render_sense({"version": 1}, self.tpl)

    def test_whole_number_floats_render_as_ints(self):
        # The browser cannot tell 68.0 from 68 (JSON.parse), so neither may Python:
        # the board gets ints, which bytes([1 << ch]) and the drivers need.
        with open(os.path.join(FIXTURES, "ok-whole-number-floats.json"), encoding="utf-8") as f:
            doc = json.load(f)["doc"]
        got = wiring.render_sense(doc, self.tpl, "esp32s3", base_topic="r/U/Z")
        for entry in got["cfg"]["BUSES"] + got["cfg"]["HUBS"] + got["cfg"]["SENSORS"]:
            for k in ("sda", "scl", "freq", "addr", "channel"):
                if entry.get(k) is not None:
                    self.assertIs(type(entry[k]), int, (entry["id"], k))
        self.assertIs(type(got["components"][0]["parameters"]["addr"]), int)
        self.assertEqual(doc["sensors"][0]["addr"], 68.0)   # the caller's copy untouched


class Cli(unittest.TestCase):
    def setUp(self):
        self.saved = tempfile.mkdtemp(prefix="board-templates-")
        self.env = {"CEA_BOARD_TEMPLATES_DIR": self.saved}

    def tearDown(self):
        for n in os.listdir(self.saved):
            os.unlink(os.path.join(self.saved, n))
        os.rmdir(self.saved)

    def test_wiring_spec_shape_and_size(self):
        r = run(["wiring-spec", "SENSE"], env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(len(r.stdout.encode()), 32 * 1024)
        spec = json.loads(r.stdout)
        self.assertEqual(set(spec), {"role", "family", "variant", "variants", "pins", "drivers",
                                     "hubs", "boards", "templates", "initial"})
        self.assertEqual(spec["variant"], "esp32s3")
        self.assertIn({"id": "esp32s3", "label": "ESP32-S3"}, spec["variants"])
        self.assertEqual(spec["pins"]["ranges"], [[0, 21], [26, 48]])
        self.assertEqual([d["id"] for d in spec["drivers"]], ["scd30", "sht4x", "sen0562"])
        self.assertEqual(spec["drivers"][0]["params"], [])
        self.assertEqual(spec["drivers"][0]["default_off"], ["temperature", "humidity"])
        self.assertEqual([(t["slug"], t["source"], t["valid"], t["first_error"])
                          for t in spec["templates"]],
                         [("sense-hub-bench-sht45-scd30", "shipped", True, None),
                          ("sense-hub-sht45-scd30-lux", "shipped", True, None)])
        self.assertIsNone(spec["initial"])
        self.assertNotIn("<svg", r.stdout)

    def test_wiring_spec_variant_and_initial(self):
        r = run(["wiring-spec", "SENSE", "esp32"], env=self.env)
        spec = json.loads(r.stdout)
        self.assertEqual(spec["variant"], "esp32")
        self.assertFalse(spec["templates"][0]["valid"])
        self.assertTrue(spec["templates"][0]["first_error"])
        rec = os.path.join(self.saved, "record.json")
        with open(rec, "w") as f:
            json.dump({"hostname": "x", "wiring": reference()}, f)
        spec = json.loads(run(["wiring-spec", "SENSE", "esp32s3", "--initial", rec],
                              env=self.env).stdout)
        self.assertEqual(spec["initial"], reference())
        # A record from the questions path has "wiring": null; nothing else of it
        # (it holds the board's passwords) may reach the spec, which the browser gets.
        with open(rec, "w") as f:
            json.dump({"hostname": "x", "wifi_psk": "not-for-the-page", "wiring": None}, f)
        r = run(["wiring-spec", "SENSE", "esp32s3", "--initial", rec], env=self.env)
        self.assertIsNone(json.loads(r.stdout)["initial"])
        self.assertNotIn("not-for-the-page", r.stdout)
        self.assertEqual(run(["wiring-spec", "SENSE", "esp99"], env=self.env).returncode, 1)
        self.assertEqual(run(["wiring-spec", "CONTROL"], env=self.env).returncode, 2)

    def test_validate_wiring_exit_codes(self):
        ok = run(["validate-wiring", "SENSE", "esp32s3"], json.dumps(reference()))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout), {"findings": [], "errors": 0, "warnings": 0})
        bad = run(["validate-wiring", "SENSE", "esp32"], json.dumps(reference()))
        self.assertEqual(bad.returncode, 1)
        out = json.loads(bad.stdout)
        self.assertEqual(out["errors"], 3)
        warn_doc = reference()
        warn_doc["buses"][0]["pullups"] = "none"
        w = run(["validate-wiring", "SENSE", "esp32s3"], json.dumps(warn_doc))
        self.assertEqual(w.returncode, 0)
        self.assertEqual(json.loads(w.stdout)["warnings"], 1)
        notjson = run(["validate-wiring", "SENSE", "esp32s3"], "{")
        self.assertEqual(notjson.returncode, 1)
        self.assertEqual(json.loads(notjson.stdout)["findings"][0]["code"], "E_SCHEMA")
        self.assertEqual(run(["validate-wiring", "SENSE"], "{}").returncode, 2)
        self.assertEqual(run(["validate-wiring", "CONTROL", "esp32s3"], "{}").returncode, 2)

    def test_validate_wiring_cli_matches_fixtures(self):
        for name, fx in fixtures().items():
            if fx["variant"] is None:
                continue
            r = run(["validate-wiring", "SENSE", fx["variant"]], json.dumps(fx["doc"]))
            got = {(f["level"], f["code"], f["where"]) for f in json.loads(r.stdout)["findings"]}
            self.assertEqual(got, {tuple(e) for e in fx["expect"]}, name)
            self.assertEqual(r.returncode, 1 if any(e[0] == "error" for e in fx["expect"]) else 0,
                             name)


if __name__ == "__main__":
    unittest.main()
