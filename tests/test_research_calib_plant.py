#!/usr/bin/env python3
"""The plant fit of research Phase 3 (research/calib/plant_fit.py), offline (design §3.4,
revised by §9 R12).

- PLANT_FIELDS covers dataclasses.fields(ChamberParams) exactly, one class each.
- (a) An exact first-order chamber (no substrate coupling, no fungi) with a heater step,
  sampled through SensorBank (SHT45, sd 0.05, step 0.01, latency 2 s, dropout 0.1) with an
  AR(1) process term at the live data's magnitude (snapshot 1's SHT45 air temperature: a
  process variance of 2e-5 C^2 per 3-s cycle, here an AR(1) of sd 0.045 C and 600 s): tau within 2 %, C_a = P tau / K within
  3 %, for tau_air_s 3600, 8760 and 14400 s, at 30-s (seeds 1-3) and 3-s intervals.
- (b) The default (two-mode) chamber: the fitted tau is the air mode's eigen time constant
  (8277 s at the defaults) within 10 %; the bias against tau_air_s is reported, not hidden.
- (c) Every refusal comes back as a Refusal, never a number: no step, no ambient series, a
  short or drifting baseline, a step under 10 x the noise, a short window, a wide interval
  (a strong AR(1) process: the gate refuses it), an ambient change, a door event.
- (d) A contract-v1-shaped dataset (AP readings only): identifiability refuses every
  non-spec field with NO_ACTUATOR_DATA, NO_EXCITATION and NO_AMBIENT, and fit-plant exits 3.

Run:  python3 -m unittest tests.test_research_calib_plant
"""
import dataclasses
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _rs_synth as S  # noqa: E402
from research.calib import plant_fit  # noqa: E402
from research.twin_plant.chamber import Chamber, ChamberParams  # noqa: E402
from research.twin_plant.sensors import SensorBank, SensorSpec  # noqa: E402

EXACT = {"substrate_air_w_per_k": 0, "co2_production_ml_per_h": 0, "fungi_water_g_per_h": 0, "fungi_heat_w": 0}
AMBIENT = [(0.0, 20.0), (40000.0, 20.0)]


def step_data(tau=8760.0, interval=30.0, seed=1, rest=900, step_s=7200, exact=True, ar_sd=0.0, ar_tau=600.0,
              heater_w=None, initial=None):
    """(times, readings) of the air temperature: REST s with everything off, then the heater
    on for STEP_S s; AR_SD adds an AR(1) process term (C) to the truth the sensor reads."""
    over = {"tau_air_s": tau}
    if exact:
        over.update(EXACT)
    if heater_w is not None:
        over["heater_w"] = heater_w
    p = ChamberParams.from_dict(over)
    ch = Chamber(p, initial or {}, seed)
    bank = SensorBank([SensorSpec("sht45_1", "sht45", ("air_temperature",), noise_sd={"air_temperature": 0.05},
                                  quantisation={"air_temperature": 0.01}, publish_interval_s=interval,
                                  dropout_p=0.1, latency_s=2.0)], seed)
    rng = random.Random("ar:%d" % seed)
    phi = math.exp(-1.0 / ar_tau)
    k = ar_sd * math.sqrt(1 - phi * phi)
    x = 0.0
    out = []
    for t in range(rest + step_s + 1):
        if t:
            ch.step(1.0, {"air_heater": 1 if t > rest else 0}, False)
        x = phi * x + k * rng.gauss(0.0, 1.0)
        tr = ch.truth()
        tr["air_temperature"] += x
        out.extend(bank.readings_due(float(t), tr))
    return p, [m[3] for m in out], [m[2] for m in out]


class Fields(unittest.TestCase):
    def test_plant_fields_cover_chamber_params_exactly(self):
        names = [f.name for f in dataclasses.fields(ChamberParams)]
        self.assertEqual(sorted(plant_fit.PLANT_FIELDS), sorted(names))
        self.assertEqual(len(names), sum(len(v) for v in plant_fit.CLASSES.values()))
        self.assertEqual(set(plant_fit.CLASSES), set(plant_fit.NEEDS))
        self.assertEqual(plant_fit.chamber_fields(), names)

    def test_the_classes_of_the_design(self):
        self.assertEqual(plant_fit.PLANT_FIELDS["volume_m3"], "spec")
        self.assertEqual(plant_fit.PLANT_FIELDS["tau_air_s"], "coupled_thermal")
        self.assertEqual(plant_fit.PLANT_FIELDS["co2_production_ml_per_h"], "conditional")
        self.assertEqual(plant_fit.PLANT_FIELDS["fungi_q10"], "biology")
        self.assertEqual(plant_fit.PLANT_FIELDS["door_open_extra_heat_w"], "disturbance")


class ExactFirstOrder(unittest.TestCase):
    def check(self, tau, interval, seed, step_s=7200, resamples=100, ar_sd=0.0):
        p, t, y = step_data(tau, interval, seed, step_s=step_s, ar_sd=ar_sd)
        r = plant_fit.fit_step(t, y, 900.0, "air_heater", power_w=p.heater_w, ambient=AMBIENT,
                               seed_key="t:%s:%s:%s" % (tau, interval, seed), resamples=resamples)
        self.assertIsInstance(r, plant_fit.StepFit, r)
        self.assertAlmostEqual(r.tau_s / tau, 1.0, delta=0.02, msg=(tau, interval, seed, r))
        self.assertAlmostEqual(r.heat_capacity_j_per_k / p.air_heat_capacity_j_per_k, 1.0, delta=0.03)
        self.assertLessEqual(r.ci95[0], r.tau_s)
        self.assertGreaterEqual(r.ci95[1], r.tau_s)
        return r

    def test_30_s_interval(self):
        # a 2-h step; tau 14400 s needs 3 h (2 h is exactly 0.5 tau, which the window rule refuses)
        for tau, step_s in ((3600.0, 7200), (8760.0, 7200), (14400.0, 10800)):
            for seed in (1, 2, 3):
                self.check(tau, 30.0, seed, step_s=step_s)

    def test_3_s_interval(self):
        for tau, step_s in ((3600.0, 7200), (8760.0, 7200), (14400.0, 10800)):
            self.check(tau, 3.0, 1, step_s=step_s, resamples=30)

    def test_with_the_live_process_term_and_the_protocols_step(self):
        """The AR(1) term at the live magnitude wanders enough that a 2-h step gives tau to
        about 10 % only (Coverage: such a fit is refused or its interval says so): the
        step-test protocol's 5-h heater step (design §6) brings it back within 2 %."""
        for tau in (3600.0, 8760.0, 14400.0):
            for seed in (1, 2, 3):
                self.check(tau, 30.0, seed, step_s=18000, resamples=40, ar_sd=0.045)

    def test_deterministic(self):
        p, t, y = step_data(8760.0, 30.0, 2)
        a = plant_fit.fit_step(t, y, 900.0, "air_heater", ambient=AMBIENT, seed_key="d")
        b = plant_fit.fit_step(t, y, 900.0, "air_heater", ambient=AMBIENT, seed_key="d")
        self.assertEqual(a, b)


class Coverage(unittest.TestCase):
    """Review of 20 Nov 2026: with the live process term (AR(1), 0.045 C, 600 s) on 2-h
    steps the residual bootstrap alone accepted intervals that missed tau a third of the
    time. Every accepted interval must now cover the true tau at about the nominal rate
    (here: at most one miss), and the rest be refused, never a confident wrong number."""

    def test_two_hour_steps_under_the_process_term(self):
        accepted, misses, refused = 0, [], []
        for tau in (3600.0, 8760.0):
            for seed in range(1, 9):
                p, t, y = step_data(tau, 30.0, seed, step_s=7200, ar_sd=0.045)
                r = plant_fit.fit_step(t, y, 900.0, "air_heater", power_w=p.heater_w, ambient=AMBIENT,
                                       seed_key="c:%s:%s" % (tau, seed), resamples=60)
                if isinstance(r, plant_fit.Refusal):
                    refused.append((tau, seed, r.code))
                    continue
                accepted += 1
                if not r.ci95[0] <= tau <= r.ci95[1]:
                    misses.append((tau, seed, r.tau_s, r.ci95))
        self.assertGreaterEqual(accepted, 6, refused)
        self.assertLessEqual(len(misses), 1, misses)
        self.assertTrue(all(code in ("WIDE_CI", "BASELINE") for _, _, code in refused), refused)

    def test_white_residuals_are_not_widened(self):
        self.assertAlmostEqual(plant_fit._vif([30.0 * i for i in range(200)],
                                              [(-1) ** i * 0.05 for i in range(200)]), 1.0)
        t = [30.0 * i for i in range(400)]
        x, e = 0.0, []
        import random as _r
        g = _r.Random(3)
        for _ in t:
            x = 0.9 * x + g.random() - 0.5
            e.append(x)
        self.assertGreater(plant_fit._vif(t, e), 5.0)


class ModelStructure(unittest.TestCase):
    def test_default_chamber_gives_the_air_mode(self):
        p, t, y = step_data(8760.0, 30.0, 1, exact=False)
        air, sub = plant_fit.mode_time_constants(p)
        self.assertAlmostEqual(air, 8277, delta=1)
        self.assertGreater(sub, air)
        r = plant_fit.fit_step(t, y, 900.0, "air_heater", ambient=AMBIENT, seed_key="b")
        self.assertIsInstance(r, plant_fit.StepFit, r)
        self.assertAlmostEqual(r.tau_s / air, 1.0, delta=0.10)
        bias = r.tau_s / p.tau_air_s - 1.0          # reported, not hidden: the two-mode chamber's fit
        self.assertLess(abs(bias), 0.15)


class Refusals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p, cls.t, cls.y = step_data(8760.0, 30.0, 1)

    def code(self, *a, **kw):
        kw.setdefault("ambient", AMBIENT)
        kw.setdefault("resamples", 30)
        r = plant_fit.fit_step(*a, **kw)
        self.assertIsInstance(r, plant_fit.Refusal, r)
        return r.code

    def test_no_step(self):
        self.assertEqual(self.code(self.t, self.y, 99999.0, "air_heater"), "NO_STEP")
        self.assertEqual(self.code(self.t, self.y, -5.0, "air_heater"), "NO_STEP")

    def test_no_ambient(self):
        self.assertEqual(self.code(self.t, self.y, 900.0, "air_heater", ambient=None), "NO_AMBIENT")

    def test_short_baseline(self):
        _, t, y = step_data(8760.0, 30.0, 1, rest=300)
        self.assertEqual(self.code(t, y, 300.0, "air_heater"), "BASELINE")

    def test_drifting_baseline(self):
        _, t, y = step_data(8760.0, 30.0, 1, initial={"air_temperature": 16.0})
        self.assertEqual(self.code(t, y, 900.0, "air_heater"), "BASELINE")

    def test_small_step(self):
        _, t, y = step_data(8760.0, 30.0, 1, heater_w=0.1)
        self.assertEqual(self.code(t, y, 900.0, "air_heater"), "SMALL_STEP")

    def test_short_window(self):
        _, t, y = step_data(8760.0, 30.0, 1, step_s=1800)
        self.assertEqual(self.code(t, y, 900.0, "air_heater"), "SHORT_WINDOW")

    def test_strong_process_noise_is_refused(self):
        _, t, y = step_data(8760.0, 30.0, 1, ar_sd=1.5, ar_tau=3600.0)
        self.assertEqual(self.code(t, y, 900.0, "air_heater"), "WIDE_CI")
        _, t, y = step_data(8760.0, 30.0, 2, ar_sd=1.5, ar_tau=3600.0)   # the wander shows as a drift
        self.assertEqual(self.code(t, y, 900.0, "air_heater"), "BASELINE")

    def test_ambient_change(self):
        self.assertEqual(self.code(self.t, self.y, 900.0, "air_heater", ambient=[(0.0, 20.0), (4000.0, 23.0)]),
                         "AMBIENT_CHANGE")

    def test_door_event(self):
        self.assertEqual(self.code(self.t, self.y, 900.0, "air_heater", disturbances=[(3000.0, "door_open")]),
                         "DISTURBANCE")

    def test_never_a_number_from_bad_input(self):
        self.assertEqual(self.code([0, 1], [1, 2], 0.5, "air_heater"), "NOT_ENOUGH_DATA")
        y = list(self.y)
        y[5] = float("nan")
        self.assertEqual(self.code(self.t, y, 900.0, "air_heater"), "NOT_ENOUGH_DATA")


class LakeShape(unittest.TestCase):
    """(d) contract v1: AP readings only."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rs-plant-")
        cls.rows = S.make_rows(hours=1.2)
        cls.path = S.write_dataset(os.path.join(cls.tmp, "ds"), cls.rows)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_every_non_spec_field_refused(self):
        v = plant_fit.identifiability(S.header_for(self.rows), self.rows)
        self.assertEqual(sorted(v), sorted(plant_fit.PLANT_FIELDS))
        for field, verdict in v.items():
            self.assertFalse(verdict.ok, field)
            if plant_fit.PLANT_FIELDS[field] == "spec":
                self.assertEqual(verdict.reasons, ("SPEC",))
                continue
            for code in ("NO_ACTUATOR_DATA", "NO_EXCITATION", "NO_AMBIENT"):
                self.assertIn(code, verdict.reasons, field)
        self.assertIn("NOT_OBSERVED", v["substrate_heat_capacity_j_per_k"].reasons)
        self.assertIn("LITERATURE", v["fungi_q10"].reasons)
        self.assertIn("CONDITIONAL_REFUSED", v["co2_production_ml_per_h"].reasons)

    def test_actuator_events_lift_the_contract_refusal(self):
        h = S.header_for(self.rows)
        h["actuator_events"] = [{"actuator": "air_heater", "at": "x", "state": "ON"}]
        h["ambient"] = {"temperature": "a room series"}
        v = plant_fit.identifiability(h, self.rows)
        self.assertTrue(v["tau_air_s"].ok, v["tau_air_s"])
        self.assertNotIn("NO_ACTUATOR_DATA", v["heater_w"].reasons)
        self.assertIn("NO_EXCITATION", v["substrate_heater_w"].reasons + v["substrate_heat_capacity_j_per_k"].reasons)

    def test_fit_plant_exits_3(self):
        report = os.path.join(self.tmp, "plant.txt")
        p = subprocess.run([sys.executable, "-m", "research.calib", "fit-plant", self.path, "--report", report,
                            "--allow-dirty"], cwd=REPO, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("no plant constant is identifiable", p.stderr)
        for field in plant_fit.PLANT_FIELDS:
            line = next(ln for ln in p.stdout.splitlines() if ln.startswith(field + " "))
            if plant_fit.PLANT_FIELDS[field] != "spec":
                self.assertIn("NO_ACTUATOR_DATA", line)
        self.assertFalse(os.path.exists(report))          # exit 3: nothing written
        self.assertIn("NO_ACTUATOR_DATA: lake contract v1 exports AP readings only", p.stdout)


if __name__ == "__main__":
    unittest.main()
