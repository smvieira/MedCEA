"""edge/tools/i2c_hub_test.py, the owner's I2C hub bench test (MicroPython, run on the
board with Thonny or mpremote, never by the platform).

Its CONFIG block and the shipped board template sense-hub-bench-sht45-scd30 describe
the same bench wiring: if one moves a sensor to another hub channel or pin, the other
must follow, or the template stops being "the wiring the bench test passed on".
"""

import ast
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "edge", "tools", "i2c_hub_test.py")
BENCH = os.path.join(ROOT, "edge", "templates", "boards", "sense-hub-bench-sht45-scd30.json")


def constants():
    with open(SCRIPT, encoding="utf-8") as f:
        tree = ast.parse(f.read(), SCRIPT)
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


class BenchScriptTest(unittest.TestCase):

    def test_the_script_and_the_bench_template_describe_one_wiring(self):
        c = constants()
        with open(BENCH, encoding="utf-8") as f:
            doc = json.load(f)["wiring"]
        bus, = doc["buses"]
        hub, = doc["hubs"]
        self.assertEqual((c["PIN_SDA"], c["PIN_SCL"], c["I2C_FREQ"]), (bus["sda"], bus["scl"], bus["freq"]))
        self.assertEqual(bus["impl"], "soft" if c["USE_SOFT_I2C"] else "hw")
        self.assertEqual(c["HUB_ADDR"], hub["addr"])
        placed = {s["driver"]: (s["channel"], s["addr"]) for s in doc["sensors"]}
        self.assertEqual(placed.get("sht4x"), (c["SHT45_CH"], c["SHT45_ADDR"]))
        self.assertEqual(placed.get("scd30"), (c["SCD30_CH"], c["SCD30_ADDR"]))
        if c["LUX_CH"] is None:
            self.assertNotIn("sen0562", placed)
        else:
            self.assertEqual(placed.get("sen0562"), (c["LUX_CH"], c["LUX_ADDR"]))

    def test_the_firmware_uses_the_scripts_timeout(self):
        # The board firmware's bus timeout is the one the bench test passed with.
        with open(os.path.join(ROOT, "edge", "src", "app", "cea_bus.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        fw = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and getattr(n.targets[0], "id", None) == "I2C_TIMEOUT_US"]
        self.assertEqual(fw, [constants()["I2C_TIMEOUT_US"]])


if __name__ == "__main__":
    unittest.main()
