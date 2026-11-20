#!/usr/bin/env python3
"""Research Sandbox Phase 1: the chamber model and its sensors (research/twin_plant/).

- StepResponse: heater on from ambient, fans off: the air rises first-order, and the
  time constant fitted to the rise is within 15 % of tau_air_s; Euler at dt 1 s and 10 s agree.
- Energy: each relay's Wh = its power x on-time.
- Humidity: RH stays within 0..100 (humidifier into a cold chamber, a dry room).
- CO2: rises with respiration in a closed chamber, falls with the co2 fan, never < 0,
  respiration grows with substrate temperature (Q10).
- Inputs: from_dict refuses unknown keys and non-numbers; unknown relays, initial keys,
  ambient keys and disturbances are refused; the door raises the exchange.
- Sensors: identical seeds give identical readings, different seeds differ; latency moves
  arrival_t; dropout drops about dropout_p of the messages without shifting later noise;
  publish times follow interval and offset; quantisation; RH clipped.
- Static: both modules import only the standard library.
- Hardening (sensor model v2): a bool, a non-number or a non-finite value in a SensorSpec,
  in a Chamber's initial state, ambient or disturbances is a ValueError, never a TypeError.
- ModelV2: readings_due is byte-identical to 42417c3's sensors.py (loaded from git show)
  over a long trajectory; self_heating_c raises T and recomputes RH at the same vapour
  density without touching the stream; bias_sd draws one constant per (sensor, tag) from a
  stream of its own, deterministic per seed, and leaves the message stream unchanged.

Run: python3 -m unittest tests.test_research_plant
"""
import ast
import importlib.util
import math
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from research.twin_plant import chamber as ch  # noqa: E402
from research.twin_plant import sensors as sn  # noqa: E402


def run(c, seconds, dt, relays, **kw):
    out = []
    t = 0.0
    while t < seconds - 1e-9:
        c.step(dt, relays, False, **kw)
        t += dt
        out.append((t, c.truth()))
    return out


class StepResponse(unittest.TestCase):
    def fit_tau(self, dt):
        p = ch.ChamberParams()
        c = ch.Chamber(p)
        t0 = c.truth()["air_temperature"]
        trace = run(c, 8 * p.tau_air_s, dt, {"air_heater": 1})
        t_inf = trace[-1][1]["air_temperature"]
        # Steady state well above ambient
        self.assertGreater(t_inf - t0, 5.0)
        # Least-squares slope of ln(1 - x) over the first two time constants
        xs, ys = [], []
        for t, tr in trace:
            if t > 2 * p.tau_air_s:
                break
            frac = (tr["air_temperature"] - t0) / (t_inf - t0)
            if 0.02 < frac < 0.95:
                xs.append(t)
                ys.append(math.log(1.0 - frac))
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
        return -1.0 / slope, p.tau_air_s, t_inf

    def test_first_order_tau(self):
        tau, want, _ = self.fit_tau(10.0)
        self.assertLess(abs(tau - want) / want, 0.15, "fitted tau %.0f s, want %.0f s" % (tau, want))

    def test_63_percent_time(self):
        p = ch.ChamberParams()
        c = ch.Chamber(p)
        t0 = c.truth()["air_temperature"]
        trace = run(c, 8 * p.tau_air_s, 10.0, {"air_heater": 1})
        t_inf = trace[-1][1]["air_temperature"]
        t63 = next(t for t, tr in trace if tr["air_temperature"] - t0 >= 0.632 * (t_inf - t0))
        self.assertLess(abs(t63 - p.tau_air_s) / p.tau_air_s, 0.15)

    def test_substep_independent(self):
        a, b = ch.Chamber(ch.ChamberParams()), ch.Chamber(ch.ChamberParams())
        run(a, 3600, 1.0, {"air_heater": 1, "air_humidifier": 1})
        run(b, 3600, 10.0, {"air_heater": 1, "air_humidifier": 1})
        for k in ch.TRUTH_KEYS:
            self.assertAlmostEqual(a.truth()[k], b.truth()[k], places=6, msg=k)

    def test_cooler_cools_and_fan_couples_substrate(self):
        c = ch.Chamber(ch.ChamberParams())
        run(c, 3600, 10.0, {"air_cooler": 1})
        self.assertLess(c.truth()["air_temperature"], 19.0)
        still, mixed = ch.Chamber(ch.ChamberParams()), ch.Chamber(ch.ChamberParams())
        run(still, 1800, 10.0, {"substrate_heater": 1})
        run(mixed, 1800, 10.0, {"substrate_heater": 1, "air_flow_fan": 1})
        # More substrate -> air conductance with the fan: the substrate stays cooler
        self.assertGreater(still.truth()["ground_temperature"], mixed.truth()["ground_temperature"])
        self.assertGreater(still.truth()["ground_temperature"], 20.5)

    def test_rest_state_is_steady(self):
        p = ch.ChamberParams.from_dict({"co2_production_ml_per_h": 0, "fungi_water_g_per_h": 0,
                                        "fungi_heat_w": 0})
        c = ch.Chamber(p)
        before = c.truth()
        run(c, 3600, 10.0, {})
        for k in ch.TRUTH_KEYS:
            self.assertAlmostEqual(before[k], c.truth()[k], places=6, msg=k)


class Initial(unittest.TestCase):
    def test_missing_keys_start_at_the_room(self):
        p = ch.ChamberParams.from_dict({"ambient_temperature": 20.0, "ambient_co2": 420.0})
        c = ch.Chamber(p, initial={"air_temperature": 16.0})
        t = c.truth()
        self.assertEqual(t["air_temperature"], 16.0)
        self.assertEqual(t["ground_temperature"], 20.0)       # the room's, not the initial air's
        self.assertAlmostEqual(t["co2"], 420.0)
        self.assertAlmostEqual(t["air_humidity"], p.ambient_humidity, places=6)
        c = ch.Chamber(p, initial={"air_temperature": 16.0, "ground_temperature": 18.5})
        self.assertEqual(c.truth()["ground_temperature"], 18.5)


class Energy(unittest.TestCase):
    def test_power_times_on_time(self):
        p = ch.ChamberParams()
        c = ch.Chamber(p)
        for _ in range(360):                               # 1 h of heater, at 10 s
            c.step(10.0, {"air_heater": 1, "co2_fan": 1}, True)
        for _ in range(180):                               # 30 min of fan only
            c.step(10.0, {"air_flow_fan": 1, "light_red": 1}, True)
        e = c.energy_wh()
        self.assertEqual(set(e), set(ch.RELAYS))
        self.assertAlmostEqual(e["air_heater"], p.heater_w * 1.0)
        self.assertAlmostEqual(e["co2_fan"], p.co2_fan_w * 1.0)
        self.assertAlmostEqual(e["air_flow_fan"], p.air_flow_fan_w * 0.5)
        self.assertAlmostEqual(e["light_red"], p.light_red_w * 0.5)
        self.assertEqual(e["air_cooler"], 0.0)
        self.assertEqual(e["substrate_heater"], 0.0)

    def test_relays_accept_bools_refuse_others(self):
        c = ch.Chamber(ch.ChamberParams())
        c.step(10, {"air_heater": True}, False)
        self.assertAlmostEqual(c.energy_wh()["air_heater"], 100.0 * 10 / 3600)
        for bad in (2, 0.5, "1", None):
            with self.assertRaises(ValueError):
                c.step(10, {"air_heater": bad}, False)


class Humidity(unittest.TestCase):
    def test_clamped_to_100(self):
        c = ch.Chamber(ch.ChamberParams(), initial={"air_humidity": 95})
        trace = run(c, 6 * 3600, 10.0, {"air_humidifier": 1, "air_cooler": 1})
        for _, tr in trace:
            self.assertGreaterEqual(tr["air_humidity"], 0.0)
            self.assertLessEqual(tr["air_humidity"], 100.0)
        self.assertGreater(trace[-1][1]["air_humidity"], 99.0)

    def test_clamped_at_0(self):
        c = ch.Chamber(ch.ChamberParams(), initial={"air_humidity": 0})
        run(c, 3600, 10.0, {"air_heater": 1, "co2_fan": 1}, ambient={"humidity": 0})
        self.assertGreaterEqual(c.truth()["air_humidity"], 0.0)

    def test_humidifier_raises_fan_lowers(self):
        c = ch.Chamber(ch.ChamberParams(), initial={"air_humidity": 60})
        run(c, 600, 10.0, {"air_humidifier": 1})
        up = c.truth()["air_humidity"]
        self.assertGreater(up, 60.0)
        c2 = ch.Chamber(ch.ChamberParams(), initial={"air_humidity": 90})
        run(c2, 1800, 10.0, {"air_flow_fan": 1})
        self.assertLess(c2.truth()["air_humidity"], 90.0)


class Co2(unittest.TestCase):
    def test_respiration_raises_fan_lowers(self):
        c = ch.Chamber(ch.ChamberParams())
        run(c, 4 * 3600, 10.0, {})
        high = c.truth()["co2"]
        self.assertGreater(high, 800.0)
        run(c, 3600, 10.0, {"co2_fan": 1, "co2_steriliser": 1})
        low = c.truth()["co2"]
        self.assertLess(low, high - 300.0)
        self.assertGreaterEqual(low, 0.0)

    def test_never_negative(self):
        c = ch.Chamber(ch.ChamberParams(), initial={"co2": 0})
        run(c, 600, 10.0, {"co2_fan": 1}, ambient={"co2": 0})
        self.assertGreaterEqual(c.truth()["co2"], 0.0)

    def test_q10(self):
        cold = ch.Chamber(ch.ChamberParams(), initial={"ground_temperature": 10, "air_temperature": 10})
        warm = ch.Chamber(ch.ChamberParams(), initial={"ground_temperature": 30, "air_temperature": 30})
        cold.step(60, {}, False, ambient={"temperature": 10})
        warm.step(60, {}, False, ambient={"temperature": 30})
        rise_cold = cold.truth()["co2"] - 420
        rise_warm = warm.truth()["co2"] - 420
        self.assertAlmostEqual(rise_warm / rise_cold, 4.0, delta=0.1)   # q10 2 over 20 C

    def test_door_raises_exchange(self):
        shut, opened = ch.Chamber(ch.ChamberParams(), initial={"co2": 3000}), \
            ch.Chamber(ch.ChamberParams(), initial={"co2": 3000})
        shut.step(300, {}, False)
        opened.step(300, {}, False, disturbances={"door_open": True})
        self.assertLess(opened.truth()["co2"], shut.truth()["co2"] - 500)


class Inputs(unittest.TestCase):
    def test_from_dict(self):
        p = ch.ChamberParams.from_dict({"heater_w": 50, "tau_air_s": 3600})
        self.assertEqual(p.heater_w, 50.0)
        self.assertEqual(p.volume_m3, 0.216)
        with self.assertRaisesRegex(ValueError, "unknown chamber parameter.*bogus"):
            ch.ChamberParams.from_dict({"bogus": 1})
        for bad in ("10", True, None, float("nan")):
            with self.assertRaises(ValueError):
                ch.ChamberParams.from_dict({"heater_w": bad})
        with self.assertRaises(ValueError):
            ch.ChamberParams.from_dict({"heater_w": -1})
        with self.assertRaises(ValueError):
            ch.ChamberParams.from_dict({"ambient_humidity": 120})

    def test_unknown_inputs_refused(self):
        c = ch.Chamber(ch.ChamberParams())
        with self.assertRaisesRegex(ValueError, "unknown relay"):
            c.step(10, {"air_heeter": 1}, False)
        with self.assertRaisesRegex(ValueError, "unknown ambient"):
            c.step(10, {}, False, ambient={"temp": 20})
        with self.assertRaisesRegex(ValueError, "unknown disturbance"):
            c.step(10, {}, False, disturbances={"window": True})
        with self.assertRaisesRegex(ValueError, "unknown initial"):
            ch.Chamber(ch.ChamberParams(), initial={"temperature": 20})
        with self.assertRaises(ValueError):
            c.step(-1, {}, False)

    def test_truth_keys(self):
        c = ch.Chamber(ch.ChamberParams(), initial={"air_temperature": 18, "air_humidity": 85,
                                                    "co2": 900, "ground_temperature": 17})
        tr = c.truth()
        self.assertEqual(tuple(sorted(tr)), tuple(sorted(ch.TRUTH_KEYS)))
        self.assertAlmostEqual(tr["air_temperature"], 18)
        self.assertAlmostEqual(tr["air_humidity"], 85)
        self.assertAlmostEqual(tr["co2"], 900)
        self.assertAlmostEqual(tr["ground_temperature"], 17)


TRUTH = {"air_temperature": 20.0, "air_humidity": 85.0, "co2": 1000.0, "ground_temperature": 19.0}


def collect(bank, until, step=10.0, truth=TRUTH):
    out = []
    t = 0.0
    while t <= until:
        out.extend(bank.readings_due(t, truth))
        t += step
    return out


class Sensors(unittest.TestCase):
    def test_default_specs(self):
        specs = sn.default_specs()
        by = {s.kind: s for s in specs}
        self.assertEqual(set(by), {"sht45", "scd30", "ds18b20"})
        self.assertEqual(by["sht45"].tags, ("air_temperature", "air_humidity"))
        self.assertIn("co2", by["scd30"].tags)
        self.assertEqual(by["ds18b20"].tags, ("ground_temperature",))
        for s in specs:
            self.assertEqual(s.publish_interval_s, 30.0)

    def test_same_seed_same_readings(self):
        a = collect(sn.SensorBank(sn.default_specs(), seed=7), 600)
        b = collect(sn.SensorBank(sn.default_specs(), seed=7), 600)
        self.assertEqual(a, b)
        self.assertTrue(a)

    def test_different_seed_differs(self):
        a = collect(sn.SensorBank(sn.default_specs(), seed=1), 600)
        b = collect(sn.SensorBank(sn.default_specs(), seed=2), 600)
        self.assertNotEqual([m[2] for m in a], [m[2] for m in b])

    def test_global_random_untouched(self):
        import random
        random.seed(123)
        x = random.random()
        random.seed(123)
        collect(sn.SensorBank(sn.default_specs(), seed=3), 300)
        ch.Chamber(ch.ChamberParams(), seed=3).step(10, {}, False)
        self.assertEqual(random.random(), x)

    def test_publish_times_and_latency(self):
        spec = sn.SensorSpec("s1", "sht45", ("air_temperature",), publish_interval_s=30,
                             latency_s=4.5, start_offset_s=5)
        bank = sn.SensorBank([spec], seed=0)
        msgs = collect(bank, 120)
        self.assertEqual([m[3] for m in msgs], [9.5, 39.5, 69.5, 99.5])
        # A message is returned in the call whose window holds its publish time, even if
        # it arrives after that call's t.
        bank2 = sn.SensorBank([spec], seed=0)
        self.assertEqual(bank2.readings_due(4.9, TRUTH), [])
        got = bank2.readings_due(5.0, TRUTH)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0][3], 9.5)
        self.assertEqual(bank2.readings_due(5.0, TRUTH), [])   # (last_t, t] is empty
        with self.assertRaises(ValueError):
            bank2.readings_due(1.0, TRUTH)

    def test_dropout(self):
        base = sn.SensorSpec("s1", "scd30", ("co2",), noise_sd={"co2": 15})
        lossy = sn.SensorSpec("s1", "scd30", ("co2",), noise_sd={"co2": 15}, dropout_p=0.3)
        full = collect(sn.SensorBank([base], seed=5), 30 * 2000, step=30)
        some = collect(sn.SensorBank([lossy], seed=5), 30 * 2000, step=30)
        lost = 1 - len(some) / len(full)
        self.assertAlmostEqual(lost, 0.3, delta=0.04)
        # The noise of a surviving message does not depend on dropout_p
        full_by_t = {m[3]: m[2] for m in full}
        for m in some:
            self.assertEqual(m[2], full_by_t[m[3]])
        none = sn.SensorSpec("s1", "scd30", ("co2",), dropout_p=1.0)
        self.assertEqual(collect(sn.SensorBank([none], seed=5), 600), [])

    def test_noise_level_and_quantisation(self):
        bank = sn.SensorBank(sn.default_specs(), seed=11)
        msgs = collect(bank, 30 * 3000, step=30)
        co2 = [m[2] for m in msgs if m[0] == "co2"]
        mean = sum(co2) / len(co2)
        sd = math.sqrt(sum((v - mean) ** 2 for v in co2) / (len(co2) - 1))
        self.assertAlmostEqual(mean, 1000.0, delta=2.0)
        self.assertAlmostEqual(sd, 15 + 0.015 * 1000, delta=2.0)     # (30 ppm + 3 %) / 2
        for tag, sid, v, _ in msgs:
            self.assertEqual(round(v, 2), v)
            if sid == "ds18b20":
                # a 12-bit step, then the board's 2-decimal rounding
                self.assertAlmostEqual(v, round(round(v / 0.0625) * 0.0625, 2), places=9)

    def test_rh_clipped(self):
        spec = sn.SensorSpec("s1", "sht45", ("air_humidity",), noise_sd={"air_humidity": 5})
        msgs = collect(sn.SensorBank([spec], seed=0), 30 * 500, step=30,
                       truth={"air_humidity": 99.5})
        self.assertTrue(all(0.0 <= m[2] <= 100.0 for m in msgs))
        self.assertIn(100.0, [m[2] for m in msgs])

    def test_spec_validation(self):
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("x", "bme280", ("air_temperature",))])
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("default", "sht45", ("air_temperature",))])
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("x", "sht45", ("air_temperature",), noise_sd={"co2": 1})])
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("x", "sht45", ("air_temperature",), dropout_p=1.5)])
        s = sn.SensorSpec("x", "sht45", ("air_temperature",))
        with self.assertRaises(ValueError):
            sn.SensorBank([s, s])

    def test_absent_tag_not_published(self):
        spec = sn.SensorSpec("lux", "sen0562", ("light_intensity",))
        self.assertEqual(collect(sn.SensorBank([spec]), 300), [])


class Hardening(unittest.TestCase):
    BAD = (True, False, "1", None, float("nan"), float("inf"), -float("inf"), [1])

    def test_spec_numbers(self):
        for field in ("publish_interval_s", "latency_s", "dropout_p", "start_offset_s", "self_heating_c"):
            for bad in self.BAD:
                s = sn.SensorSpec("x", "sht45", ("air_temperature",))
                setattr(s, field, bad)
                with self.assertRaises(ValueError, msg="%s=%r" % (field, bad)):
                    s.validate()
        for field in ("noise_sd", "noise_rel_sd", "quantisation", "bias", "bias_sd"):
            for bad in self.BAD:
                s = sn.SensorSpec("x", "sht45", ("air_temperature",))
                setattr(s, field, {"air_temperature": bad})
                with self.assertRaises(ValueError, msg="%s=%r" % (field, bad)):
                    s.validate()
            s = sn.SensorSpec("x", "sht45", ("air_temperature",))
            setattr(s, field, [("air_temperature", 1.0)])
            with self.assertRaises(ValueError):
                s.validate()
        with self.assertRaises(ValueError):
            sn.SensorSpec("x", "sht45", ("air_temperature",), bias_sd={"co2": 1}).validate()
        with self.assertRaises(ValueError):
            sn.SensorSpec("x", "sht45", ("air_temperature",), bias_sd={"air_temperature": -1}).validate()
        with self.assertRaises(ValueError):
            sn.SensorSpec("x", "sht45", ("air_temperature",), self_heating_c=25).validate()
        # A NaN interval would make readings_due loop forever: refused before any bank exists
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("x", "sht45", ("air_temperature",), publish_interval_s=float("nan"))])
        sn.SensorSpec("x", "sht45", ("air_temperature",), bias={"air_temperature": -0.5},
                      self_heating_c=-1.0, bias_sd={"air_temperature": 0.1}).validate()

    def test_chamber_inputs(self):
        for bad in self.BAD:
            with self.assertRaises(ValueError, msg=repr(bad)):
                ch.Chamber(ch.ChamberParams(), initial={"air_temperature": bad})
            c = ch.Chamber(ch.ChamberParams())
            with self.assertRaises(ValueError, msg=repr(bad)):
                c.step(10, {}, False, ambient={"temperature": bad})
            with self.assertRaises(ValueError, msg=repr(bad)):
                c.step(10, {}, False, disturbances={"extra_heat_w": bad})
        for bad in (1, "yes", None, float("nan")):
            with self.assertRaises(ValueError):
                ch.Chamber(ch.ChamberParams()).step(10, {}, False, disturbances={"door_open": bad})
        c = ch.Chamber(ch.ChamberParams(), initial={"air_temperature": 18, "co2": 900.5})
        c.step(10, {}, False, ambient={"temperature": 21, "humidity": 40, "co2": 410},
               disturbances={"door_open": False, "extra_heat_w": 5})


BASE_COMMIT = "42417c3"


def old_sensors_module(test):
    """42417c3's research/twin_plant/sensors.py, loaded from git show (skip without it)."""
    if shutil.which("git") is None:
        test.skipTest("git is not installed")
    p = subprocess.run(["git", "-C", ROOT, "show", "%s:research/twin_plant/sensors.py" % BASE_COMMIT],
                       capture_output=True, text=True)
    if p.returncode != 0:
        test.skipTest("commit %s is not in this checkout" % BASE_COMMIT)
    tmp = tempfile.mkdtemp(prefix="rs-sensors-v1-")
    test.addCleanup(shutil.rmtree, tmp)
    path = os.path.join(tmp, "sensors_v1.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(p.stdout)
    spec = importlib.util.spec_from_file_location("sensors_v1_%s" % BASE_COMMIT, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod                 # dataclasses look the module up while defining
    test.addCleanup(sys.modules.pop, spec.name, None)
    spec.loader.exec_module(mod)
    return mod


def specs_of(mod):
    out = mod.default_specs()
    out.append(mod.SensorSpec("lossy", "scd30", ("co2", "air_temperature", "air_humidity"),
                              noise_sd={"co2": 7.0, "air_temperature": 0.3, "air_humidity": 2.0},
                              noise_rel_sd={"co2": 0.02}, quantisation={"co2": 1.0},
                              bias={"air_temperature": 1.5, "air_humidity": -4.0},
                              publish_interval_s=3.02, latency_s=1.2, dropout_p=0.07, start_offset_s=0.4))
    out.append(mod.SensorSpec("fast", "sht45", ("air_temperature", "air_humidity"),
                              noise_sd={"air_temperature": 0.02, "air_humidity": 0.3},
                              quantisation={"air_temperature": 0.01, "air_humidity": 0.01},
                              publish_interval_s=2.988, latency_s=0.8))
    return out


def trajectory(mod, seed, seconds=6 * 3600):
    """Every message of a bank sampling a moving chamber, 1-s plant steps, a heater and a
    humidifier switched on and off."""
    c = ch.Chamber(ch.ChamberParams(), initial={"air_temperature": 16, "air_humidity": 92, "co2": 1500})
    bank = mod.SensorBank(specs_of(mod), seed=seed)
    out = list(bank.readings_due(0.0, c.truth()))
    t = 0
    while t < seconds:
        relays = {"air_heater": int((t // 1800) % 2 == 0), "air_humidifier": int((t // 2700) % 2 == 1),
                  "co2_fan": int((t // 3600) % 3 == 2)}
        c.step(1.0, relays, False)
        t += 1
        out.extend(bank.readings_due(float(t), c.truth()))
    return out


class ModelV2(unittest.TestCase):
    def test_version(self):
        self.assertEqual(sn.SENSOR_MODEL_VERSION, 2)
        self.assertIn("self_heating_c", sn.SensorSpec.__dataclass_fields__)
        self.assertIn("bias_sd", sn.SensorSpec.__dataclass_fields__)

    def test_readings_due_byte_identical_to_version_1(self):
        old = old_sensors_module(self)
        self.assertFalse(hasattr(old, "SENSOR_MODEL_VERSION"))
        for seed in (0, 1, 7):
            a = trajectory(old, seed)
            b = trajectory(sn, seed)
            self.assertGreater(len(a), 20000)
            self.assertEqual(repr(a).encode(), repr(b).encode(), "seed %d" % seed)

    def _one(self, **kw):
        spec = sn.SensorSpec("s", "scd30", ("air_temperature", "air_humidity", "co2"), **kw)
        return sn.SensorBank([spec], seed=3)

    def test_self_heating_humidity_physics(self):
        truth = {"air_temperature": 20.0, "air_humidity": 53.0, "co2": 800.0}
        msgs = {m[0]: m[2] for m in self._one(self_heating_c=2.1).readings_due(0.0, truth)}
        self.assertEqual(msgs["air_temperature"], 22.1)
        rh = 53.0 * ch.saturation_density(20.0) / ch.saturation_density(22.1)
        self.assertEqual(msgs["air_humidity"], round(rh, 2))
        self.assertEqual(msgs["co2"], 800.0)
        # Same water vapour density as the air, only warmer: about -6.6 %RH at 53 %RH
        self.assertAlmostEqual(ch.vapour_density(22.1, rh), ch.vapour_density(20.0, 53.0), places=9)
        self.assertLess(rh - 53.0, -6.0)
        self.assertGreater(rh - 53.0, -7.0)
        # The dependence on RH: proportional, so the offset grows with the humidity
        hi = 90.0 * ch.saturation_density(20.0) / ch.saturation_density(22.1) - 90.0
        self.assertLess(hi, rh - 53.0)
        # Applied before clipping: a negative self-heating near saturation is clipped at 100
        msgs = {m[0]: m[2] for m in self._one(self_heating_c=-3.0).readings_due(0.0, dict(truth, air_humidity=95.0))}
        self.assertEqual(msgs["air_humidity"], 100.0)
        # Humidity without temperature in the truth cannot be corrected: refused
        with self.assertRaises(ValueError):
            sn.SensorBank([sn.SensorSpec("h", "sht45", ("air_humidity",), self_heating_c=1.0)]).readings_due(
                0.0, {"air_humidity": 50.0})

    def test_self_heating_draws_nothing(self):
        noise = {"air_temperature": 0.2, "air_humidity": 1.0, "co2": 10.0}
        truth = {"air_temperature": 20.0, "air_humidity": 53.0, "co2": 800.0}
        a = collect(self._one(noise_sd=noise), 3000, truth=truth)
        b = collect(self._one(noise_sd=noise, self_heating_c=2.0), 3000, truth=truth)
        self.assertEqual(len(a), len(b))
        for x, y in zip(a, b):
            self.assertEqual((x[0], x[1], x[3]), (y[0], y[1], y[3]))
            if x[0] == "air_temperature":
                self.assertAlmostEqual(y[2] - x[2], 2.0, delta=0.011)
            if x[0] == "co2":
                self.assertEqual(x[2], y[2])

    def test_bias_sd_deterministic_and_independent(self):
        noise = {"air_temperature": 0.2, "air_humidity": 1.0, "co2": 10.0}
        bsd = {"air_temperature": 0.1, "co2": 20.0}
        truth = {"air_temperature": 20.0, "air_humidity": 53.0, "co2": 800.0}

        def bank(seed, **kw):
            specs = [sn.SensorSpec("s", "scd30", ("air_temperature", "air_humidity", "co2"),
                                   noise_sd=noise, dropout_p=0.2, **kw),
                     sn.SensorSpec("t", "sht45", ("air_temperature",), noise_sd={"air_temperature": 0.05})]
            return sn.SensorBank(specs, seed=seed)

        b1, b1b, b2 = bank(1, bias_sd=bsd), bank(1, bias_sd=bsd), bank(2, bias_sd=bsd)
        self.assertEqual(b1.drawn_bias(), b1b.drawn_bias())
        self.assertNotEqual(b1.drawn_bias(), b2.drawn_bias())
        self.assertEqual(set(b1.drawn_bias()), {"s"})
        self.assertEqual(set(b1.drawn_bias()["s"]), {"air_temperature", "co2"})
        self.assertEqual(b1.drawn_bias()["s"]["co2"], sn.bias_draw(1, "s", "co2", 20.0))
        # A zero sd draws nothing, like no entry
        self.assertEqual(bank(1, bias_sd={"co2": 0.0}).drawn_bias(), {})

        plain = collect(bank(1), 3000, truth=truth)
        biased = collect(b1, 3000, truth=truth)
        self.assertEqual(collect(bank(1, bias_sd=bsd), 3000, truth=truth), biased)
        # The message stream (dropouts, noise draws, times) is unchanged; only the constant moves
        self.assertEqual([(m[0], m[1], m[3]) for m in plain], [(m[0], m[1], m[3]) for m in biased])
        drawn = b1.drawn_bias()["s"]
        for x, y in zip(plain, biased):
            if x[1] == "s" and x[0] in drawn:
                self.assertAlmostEqual(y[2] - x[2], drawn[x[0]], delta=0.011)
            else:
                self.assertEqual(x[2], y[2])
        # Equal to the version-1 stream when bias_sd is absent
        self.assertEqual(collect(bank(1, bias_sd={}), 3000, truth=truth), plain)


class Static(unittest.TestCase):
    def test_stdlib_only(self):
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        for name in ("chamber.py", "sensors.py", "__init__.py"):
            path = os.path.join(ROOT, "research", "twin_plant", name)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    mods = [node.module]
                else:
                    continue
                for m in mods:
                    self.assertIn(m.split(".")[0], allowed, "%s imports %s" % (name, m))


if __name__ == "__main__":
    unittest.main()
