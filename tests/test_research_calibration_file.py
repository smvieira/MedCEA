#!/usr/bin/env python3
"""The calibration file of research Phase 3 (research/calib/calibfile.py), offline.

- The schema: every top-level key, versions, sources, finiteness; every ChamberParams
  field in the plant section with its class and refusal codes; no holds (design §9 R9).
- The canonical dump: the same dataset and code give the same bytes; verify() refuses a
  file that is not in canonical form.
- to_overrides(): only applied entries change the model; the dict fields carry their
  tags; a sensor the scenario removes is skipped; a value outside SensorSpec's bounds, an
  applied entry without a value, a `fitted` plant entry (R8) and an assumed or spec value
  that is not the default are refused; a sensor_model_version newer than the code's too.
- code_state(): research/ dirty is refused unless allow_dirty (R10), which records it.

Run:  python3 -m unittest tests.test_research_calibration_file
"""
import copy
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml  # noqa: E402

import _rs_synth as S  # noqa: E402
from research.calib import calibfile, plant_fit  # noqa: E402
from research.harness import algorithms_loader  # noqa: E402
from research.twin_plant.chamber import ChamberParams  # noqa: E402
from research.twin_plant.sensors import SENSOR_MODEL_VERSION  # noqa: E402


class File(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rs-calfile-")
        cls.path, cls.sha, cls.doc = S.make_calibration(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_schema(self):
        d = self.doc
        self.assertEqual(sorted(d), sorted(calibfile.TOP_KEYS))
        self.assertEqual((d["medcea_calibration"], d["calib_version"], d["sensor_model_version"]),
                         (1, 1, SENSOR_MODEL_VERSION))
        src = d["source"]
        self.assertEqual(src["lake"]["digest_measurement"], {"1": S.header_for(S.make_rows(hours=1.5))["lake"][
            "snapshots"][0]["digest_measurement"]})
        self.assertTrue(src["lake"]["digest_verified"])
        self.assertEqual((src["unit"], src["zone"]), ("UNIT01", "ZONE01"))
        self.assertNotIn("holds", src)
        self.assertEqual(d["reference"]["sensor"], "sht45")
        self.assertIn("Absolute accuracy unknown", d["reference"]["why"])
        self.assertEqual(d["sensors"]["ds18b20"]["source"], "datasheet")
        self.assertEqual(d["sensor_map"], S.MAP)

    def test_plant_section(self):
        plant = self.doc["plant"]
        defaults = ChamberParams().to_dict()
        self.assertEqual(sorted(plant), sorted(defaults))
        for field, e in plant.items():
            self.assertEqual(e["value"], defaults[field])
            self.assertEqual(e["class"], plant_fit.PLANT_FIELDS[field])
            if e["class"] == "spec":
                self.assertEqual(e["source"], "spec")
            else:
                self.assertEqual(e["source"], "assumed")
                self.assertEqual(e["refused"][:3], ["NO_ACTUATOR_DATA", "NO_EXCITATION", "NO_AMBIENT"])

    def test_canonical_and_verify(self):
        with open(self.path, "rb") as f:
            data = f.read()
        self.assertEqual(calibfile.dumps(yaml.safe_load(data)).encode("utf-8"), data)
        path2, sha2, _ = S.make_calibration(os.path.join(self.tmp, "again"))
        self.assertEqual(sha2, self.sha)
        lines = calibfile.verify(self.path)
        self.assertIn("every one the model's default", lines[2])
        bad = os.path.join(self.tmp, "reordered.yaml")
        with open(bad, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.doc, f, sort_keys=False)
        with self.assertRaisesRegex(calibfile.CalibError, "canonical"):
            calibfile.verify(bad)

    def test_to_overrides(self):
        ov = calibfile.to_overrides(self.doc)
        sht = ov["sensors"]["sht45"]
        self.assertAlmostEqual(sht["publish_interval_s"], 2.988, delta=0.01)
        self.assertEqual(set(sht["noise_sd"]), {"air_temperature", "air_humidity"})
        self.assertEqual(sht["bias_sd"], {"air_temperature": 0.05, "air_humidity": 0.5})
        scd = ov["sensors"]["scd30"]
        self.assertNotIn("co2", scd["noise_sd"])                       # refused: filtered
        self.assertNotIn("self_heating_c", scd)                        # constant_offset
        self.assertAlmostEqual(scd["bias"]["air_temperature"], 2.04, delta=0.02)
        self.assertNotIn("ds18b20", ov["sensors"])
        self.assertIn("scd30.noise_sd.co2", [n["field"] for n in ov["not_applied"]])
        self.assertIn("sht45.latency_s", ov["applied"])
        removed = calibfile.to_overrides(self.doc, remove=["scd30"])
        self.assertEqual(set(removed["sensors"]), {"sht45"})
        self.assertIn({"field": "scd30", "why": "the scenario removes this sensor"}, removed["not_applied"])

    def mutated(self, fn):
        d = copy.deepcopy(self.doc)
        fn(d)
        return d

    def test_refusals(self):
        cases = [
            (lambda d: d.pop("plant"), "missing"),
            (lambda d: d.update(extra=1), "unknown"),
            (lambda d: d.update(sensor_model_version=SENSOR_MODEL_VERSION + 1), "sensor_model_version"),
            (lambda d: d.update(medcea_calibration=2), "schema"),
            (lambda d: d["sensors"]["sht45"]["noise_sd"]["air_temperature"].update(value=float("nan")), "finite"),
            (lambda d: d["sensors"]["sht45"]["noise_sd"]["air_temperature"].update(value=-1.0), "must be >= 0"),
            (lambda d: d["sensors"]["sht45"]["publish_interval_s"].update(value=0.0), "publish_interval_s"),
            (lambda d: d["sensors"]["sht45"]["latency_s"].pop("value"), "no numeric value"),
            (lambda d: d["sensors"]["sht45"]["latency_s"].update(source="guessed"), "known source"),
            (lambda d: d["sensors"]["sht45"]["noise_sd"].update(co2=d["sensors"]["sht45"]["noise_sd"][
                "air_temperature"]), "does not publish"),
            (lambda d: d["sensors"]["sht45"].update(jitter_s={"value": 1.0, "source": "fitted", "applied": True}),
             "not a SensorSpec field"),
            (lambda d: d["plant"]["tau_air_s"].update(source="fitted", value=9000.0), "later phase"),
            (lambda d: d["plant"]["tau_air_s"].update(value=9000.0), "plant.overrides"),
            (lambda d: d["plant"]["volume_m3"].update(value=0.3), "plant.overrides"),
            (lambda d: d["plant"].pop("fungi_q10"), "every ChamberParams field"),
            (lambda d: d["sensors"].update(bme280={}), "not a model sensor"),
        ]
        for fn, why in cases:
            with self.assertRaisesRegex(calibfile.CalibError, why, msg=why):
                calibfile.check(self.mutated(fn))

    def test_weak_and_refused_entries_change_nothing(self):
        d = self.mutated(lambda d: d["sensors"]["sht45"]["latency_s"].update(applied=False, weak=True))
        self.assertNotIn("latency_s", calibfile.to_overrides(d)["sensors"]["sht45"])


class CodeState(unittest.TestCase):
    def test_dirty_needs_the_flag(self):
        st = algorithms_loader.sandbox_state(algorithms_loader.SANDBOX_ROOT)
        code = calibfile.code_state(allow_dirty=True)
        self.assertEqual(code["dirty"], st["dirty"])
        self.assertEqual(code["commit"], st["commit"])
        self.assertRegex(code["python"], r"^\d+\.\d+$")
        self.assertIn("research/calib/sensor_fit.py", code["blobs"])
        self.assertIn("research/twin_plant/sensors.py", code["blobs"])
        self.assertTrue(all(k.startswith(("research/calib/", "research/twin_plant/")) for k in code["blobs"]))
        if st["dirty"]:
            with self.assertRaisesRegex(calibfile.CalibError, "--allow-dirty"):
                calibfile.code_state()
        else:
            self.assertEqual(calibfile.code_state(), code)


if __name__ == "__main__":
    unittest.main()
