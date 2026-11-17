#!/usr/bin/env python3
"""The research sandbox's closed-loop simulation harness (RS.3), offline.

- Loader: schd/cea/algorithms and loop_resolver loaded by path (no psycopg2, paho or cea
  in sys.modules), unknown algorithm codes refused (never get_algorithm's silent
  bang-bang), blob SHAs equal to `git hash-object`, a dirty tree refused unless
  allow_dirty (a throwaway git repository in a temp dir).
- SimClock: PID's clock and Q-learning's random source swapped for the run and restored.
- Runner: determinism per seed; PID's result depends on the clock offset modulo its
  10-s PWM window (the aliasing with the 10-s tick) and is fixed for a given offset;
  Q-learning deterministic under its seeded Random; every tick's decision equals
  loop_resolver's resolve/decide on the same readings (parity); the shared
  air_flow_fan ends a tick as the last message left it; co2's command_map; bang-bang
  holds the air temperature in band after settling; FLC/MPC without their libraries
  are marked invalid.
- research/.venv (when it exists): FLC and MPC run their libraries on every computed
  tick, and MPC (after the sign fix) heats a chamber below the band.
- Campaign: grid expansion, byte-identical results.jsonl for one and two workers, the
  CPU-hour cap, the manifest.

Run: cd <repo> && python3 -m unittest tests.test_research_harness
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

import yaml  # noqa: E402

from research.harness import algorithms_loader, campaign, metrics, runner  # noqa: E402
from research.harness.simclock import SimClock  # noqa: E402

SCEN_DIR = os.path.join(REPO, "research", "harness", "scenarios")
CAMPAIGNS = os.path.join(REPO, "research", "harness", "campaigns")
VENV_PY = os.path.join(REPO, "research", ".venv", "bin", "python")


def smoke(**changes):
    with open(os.path.join(SCEN_DIR, "smoke_air_temperature.yaml"), encoding="utf-8") as f:
        sc = yaml.safe_load(f)
    sc.update(changes)
    return sc


def loaded():
    return algorithms_loader.load(REPO, allow_dirty=True)


def run(sc=None, code="IF_THEN_ELSE", params=None, seed=1, offset=0.0, jitter=0.0, trace=False):
    return runner.run_scenario(copy.deepcopy(sc or smoke()), {"code": code, "params": params or {}},
                               seed, offset, jitter, loaded=loaded(), trace=trace)


def digest(result):
    return hashlib.sha256(campaign.canonical(result).encode()).hexdigest()


class Loader(unittest.TestCase):
    def test_no_operational_imports(self):
        L = loaded()
        run(smoke(duration_h=0.05, metrics_from_h=0))
        for name in list(sys.modules):
            self.assertFalse(name == "psycopg2" or name.startswith("psycopg2."), name)
            self.assertFalse(name == "paho" or name.startswith("paho."), name)
            self.assertFalse(name == "cea" or name.startswith("cea."), name)
        self.assertTrue(L.pkg.startswith("medcea_rs_cea_"))
        self.assertEqual(sorted(L.algorithms.ALGORITHM_NAMES),
                         ["FLC", "IF_THEN_ELSE", "MPC", "PID", "Q_LEARNING"])

    def test_unknown_code_refused(self):
        L = loaded()
        with self.assertRaises(algorithms_loader.LoaderError):
            L.make("BANG_BANG", 18, 22)
        with self.assertRaises(algorithms_loader.LoaderError):
            run(code="pid")                 # get_algorithm would upper-case it; the harness does not
        if L.params is not None:
            with self.assertRaises(algorithms_loader.LoaderError):
                L.make("PID", 18, 22, {"kp": -1})
            with self.assertRaises(algorithms_loader.LoaderError):
                L.make("PID", 18, 22, {"gain": 1})

    def test_blob_shas_are_git_hash_object(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        L = loaded()
        for rel in ("apps/database/recipe_types.yaml", "schd/cea/loop_resolver.py",
                    "schd/cea/algorithms/pid.py", "edge/templates/esp32-control.json"):
            out = subprocess.run(["git", "-C", REPO, "hash-object", rel], capture_output=True, text=True)
            self.assertEqual(L.blobs[rel], out.stdout.strip(), rel)

    def test_dirty_tree_refused(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        tmp = tempfile.mkdtemp(prefix="rs-harness-")
        self.addCleanup(shutil.rmtree, tmp)
        for rel in ("schd/cea/algorithms", "schd/cea/loop_resolver.py",
                    algorithms_loader.CATALOGUE, algorithms_loader.CONTROL_TEMPLATE):
            src, dst = os.path.join(REPO, rel), os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy(src, dst)
        git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@example.org",
               "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "x"], check=True)
        state = algorithms_loader.git_state(tmp)
        self.assertFalse(state["dirty"], state)
        with open(os.path.join(tmp, "schd/cea/algorithms/pid.py"), "a", encoding="utf-8") as f:
            f.write("\n# edited\n")
        with self.assertRaisesRegex(algorithms_loader.LoaderError, "pid.py"):
            algorithms_loader.load(tmp)
        L = algorithms_loader.load(tmp, allow_dirty=True)
        self.assertTrue(L.git["dirty"])
        self.assertIn("schd/cea/algorithms/pid.py", L.git["dirty_files"])
        self.assertIn("schd/cea/algorithms/pid.py", L.manifest()["dirty_files"])

    def test_outside_git_counts_as_dirty(self):
        tmp = tempfile.mkdtemp(prefix="rs-harness-")
        self.addCleanup(shutil.rmtree, tmp)
        self.assertTrue(algorithms_loader.git_state(tmp)["dirty"])


class Clock(unittest.TestCase):
    def test_install_and_restore(self):
        L = loaded()
        t0, r0 = L.pid._time, L.q_learning._random
        c = SimClock(5.0, 0.0, 1).install(L.pid, L.q_learning)
        self.assertIs(L.pid._time, c)
        self.assertIs(L.q_learning._random, c.random)
        c.advance(3)
        self.assertEqual(c.monotonic(), 8.0)
        c.uninstall()
        self.assertIs(L.pid._time, t0)
        self.assertIs(L.q_learning._random, r0)

    def test_jitter(self):
        self.assertEqual(SimClock(0, 0, 1).next_interval(), 10.0)
        a, b = SimClock(0, 2.0, 7), SimClock(0, 2.0, 7)
        self.assertEqual(a.next_interval(), b.next_interval())    # seeded
        self.assertTrue(10.0 <= b.next_interval() <= 12.0)


class Runner(unittest.TestCase):
    def test_determinism(self):
        a, b, c = run(seed=3), run(seed=3), run(seed=4)
        self.assertEqual(digest(a), digest(b))
        self.assertNotEqual(digest(a), digest(c))

    def test_pid_depends_on_the_clock_offset(self):
        L = loaded()
        original = L.pid._time
        sc = smoke(duration_h=0.5, metrics_from_h=0,
                   initial={"air_temperature": 20.5, "air_humidity": 85, "co2": 800})
        r0, r0b, r10, r99 = (run(sc, "PID", seed=1, offset=o) for o in (0.0, 0.0, 10.0, 9.99))
        self.assertIs(L.pid._time, original)          # restored after each run
        self.assertEqual(digest(r0), digest(r0b))     # fixed for a given offset
        # Only the offset modulo cycle_time (10 s = the tick) matters ...
        self.assertEqual(r0["loops"], r10["loops"])
        # ... and it decides how often the duty cycle fires: at offset 0 every tick sits at
        # the window's start (fires whenever |output| > 0), at 9.99 only when |output| > 0.999.
        def off(r):
            return sum(r["loops"][k]["commands"]["OFF"] for k in ("air_temperature", "air_humidity"))
        self.assertGreater(off(r99), off(r0))
        self.assertNotEqual(r0["loops"], r99["loops"])

    def test_q_learning_seeded_and_restored(self):
        import random as stdlib_random
        L = loaded()
        sc = smoke(duration_h=0.3, metrics_from_h=0)
        a, b, c = run(sc, "Q_LEARNING", seed=5), run(sc, "Q_LEARNING", seed=5), run(sc, "Q_LEARNING", seed=6)
        self.assertEqual(digest(a), digest(b))
        self.assertNotEqual(digest(a), digest(c))
        self.assertIs(L.q_learning._random, stdlib_random)

    def test_parity_with_loop_resolver(self):
        L = loaded()
        lr = L.lr
        sc = smoke(duration_h=0.3, metrics_from_h=0)
        r = run(sc, "IF_THEN_ELSE", seed=2, trace="readings")
        s = runner.normalise(copy.deepcopy(sc), L)
        q = s["_quantities"]
        decl = {n: {"quantity": d.get("quantity")} for n, d in L.actuators.items() if d.get("kind") == "commands"}
        loops = lr.build_default_map(["Z1"], q, {"Z1": decl})
        for i, lp in enumerate(loops):
            row = sc["loops"].get(lp["loop_code"])
            if row:
                loops[i] = lr.loop_from_row({"zone_code": "Z1", "loop_id": i + 1, "loop_code": lp["loop_code"],
                                             "input": row["input"], "output": lp["output"]}, q)
        algos, last = {}, {}
        for lp in loops:
            lo, hi, why = lr.limits(lp, sc["recipe_line"])
            if not why:
                algos[lp["loop_code"]] = (lp, L.make("IF_THEN_ELSE", lo, hi))
        self.assertEqual(sorted(algos), sorted(r["loops"]))
        checked = 0
        for entry in r["trace"]:
            readings = {(z, t, s_): (v, rt) for z, t, s_, v, rt in entry["readings"]}
            for key, (lp, algo) in algos.items():
                res = lr.resolve(lp, readings, entry["now"], entry["started_at"])
                cmd, hold = lr.decide(lp, res, algo, last.get(key))
                got = entry["loops"][key]
                self.assertEqual((got["state"], got["value"], got["cmd"], got["hold"]),
                                 (res["state"], res["value"], cmd, hold), (entry["t"], key))
                if cmd:
                    last[key] = cmd
                checked += 1
        self.assertGreater(checked, 50)

    def test_shared_air_flow_fan_last_write_wins(self):
        L = loaded()
        b = runner.Board(L.actuators, ["air_temperature", "air_humidity", "co2", "substrate_temperature"])
        b.apply("air_temperature", "DOWN")      # fan 1
        b.apply("air_humidity", "OFF")          # fan 0
        self.assertEqual(b.relays["air_flow_fan"], 0)
        b.apply("air_humidity", "OFF")
        b.apply("air_temperature", "DOWN")
        self.assertEqual(b.relays["air_flow_fan"], 1)
        # In a run: each tick's fan is the one the last fan-setting message (map order) left.
        sc = smoke(duration_h=0.3, metrics_from_h=0, initial={"air_temperature": 24, "air_humidity": 97, "co2": 800})
        r = run(sc, "IF_THEN_ELSE", seed=1, trace=True)
        order = ["air_temperature", "air_humidity", "co2"]
        sets = L.actuators
        fan, seen_conflict = 0, False
        for entry in r["trace"]:
            writes = []
            for key in order:
                cmd = entry["loops"].get(key, {}).get("cmd")
                if cmd:
                    v = sets[key]["commands"][cmd]["set"].get("air_flow_fan")
                    if v is not None:
                        writes.append(v)
            if writes:
                fan = writes[-1]
                seen_conflict |= len(set(writes)) > 1
            self.assertEqual(entry["relays"]["air_flow_fan"], fan, entry["t"])
        self.assertTrue(seen_conflict, "the scenario never had two loops disagree on the fan")

    def test_co2_command_map(self):
        sc = smoke(duration_h=0.1, metrics_from_h=0, initial={"air_temperature": 20, "air_humidity": 85, "co2": 6000})
        r = run(sc, "IF_THEN_ELSE", seed=1, trace=True)
        first = next(e for e in r["trace"] if e["loops"]["co2"]["cmd"])
        # Above the band bang-bang answers DOWN; the co2 command_map sends UP (fans on).
        self.assertEqual(first["loops"]["co2"]["cmd"], "UP")
        self.assertEqual(first["relays"]["co2_fan"], 1)
        self.assertLess(r["trace"][-1]["truth"]["co2"], 6000)
        sc = smoke(duration_h=0.05, metrics_from_h=0, initial={"air_temperature": 20, "air_humidity": 85, "co2": 300})
        r = run(sc, "IF_THEN_ELSE", seed=1, trace=True)
        first = next(e for e in r["trace"] if e["loops"]["co2"]["cmd"])
        self.assertEqual(first["loops"]["co2"]["cmd"], "OFF")     # algorithm UP -> OFF
        self.assertEqual(first["relays"]["co2_fan"], 0)

    def test_bang_bang_settles_in_band(self):
        r = run(seed=1)
        t = r["loops"]["air_temperature"]
        self.assertTrue(r["valid"])
        self.assertGreater(t["samples"], 100)
        self.assertEqual(t["out_of_band"], 0.0)
        self.assertEqual(t["branches"]["fallback"], 0)
        self.assertGreater(r["relays"]["air_heater"]["energy_wh"], 0)
        self.assertAlmostEqual(r["energy_total_wh"], sum(v["energy_wh"] for v in r["relays"].values()))

    def test_default_map_is_ambiguous_with_two_sensors(self):
        # Without a control_loop row the default map's 'single' rule sees SHT45 and SCD30
        # both publishing air_temperature: no_data, ambiguous_source, as in production.
        sc = smoke(duration_h=0.1, metrics_from_h=0)
        del sc["loops"]
        r = run(sc, seed=1)
        self.assertGreater(r["alarms"].get("ambiguous_source", 0), 0)
        self.assertGreater(r["loops"]["air_temperature"]["branches"]["not_computed"], 30)

    def test_flc_mpc_marked_invalid_without_libraries(self):
        L = loaded()
        for code in ("FLC", "MPC"):
            if L.libraries[code]["present"]:
                continue                      # run under research/.venv: covered by Venv
            r = run(smoke(duration_h=0.05, metrics_from_h=0), code, seed=1)
            self.assertFalse(r["valid"], code)
            self.assertIn("fell back to bang-bang", r["invalid_reasons"][0])
            self.assertGreater(sum(v["branches"]["fallback"] for v in r["loops"].values()), 0)
            self.assertEqual(sum(v["branches"]["library"] for v in r["loops"].values()), 0)
        if all(L.libraries[c]["present"] for c in ("FLC", "MPC")):
            self.skipTest("FLC and MPC libraries are present in this interpreter")

    def test_probe_without_fallback_counter(self):
        # Controller code from before the fallback_count attribute: a compute with no
        # library counts as a fallback, a library call that raises too.
        class OldMPC:
            _gekko = None

            def compute(self, v):
                return "UP"
        p = runner._Probe("MPC", OldMPC())
        self.assertTrue(p.fell_back(p.before()))

        class Solver:
            fail = False

            def solve(self, disp=False):
                if self.fail:
                    raise RuntimeError("no solution")

        class OldMPCWithLib:
            _gekko = True

            def __init__(self):
                self._m = Solver()

            def compute(self, v):
                try:
                    self._m.solve()
                    return "UP"
                except Exception:
                    return "OFF"
        a = OldMPCWithLib()
        p = runner._Probe("MPC", a)
        mark = p.before()
        a.compute(1.0)
        self.assertFalse(p.fell_back(mark))
        a._m.fail = True
        mark = p.before()
        a.compute(1.0)
        self.assertTrue(p.fell_back(mark))

    def test_scenario_refusals(self):
        L = loaded()
        bad = [
            smoke(colour="red"),
            smoke(recipe_line={"setpoints": {"air_temperature": {"lower": 22, "upper": 18}}}),
            smoke(recipe_line={"setpoints": {"air_temperature": {"lower": 18, "upper": 99}}}),
            smoke(recipe_line={"setpoints": {"leaf_wetness": {"lower": 1, "upper": 2}}}),
            smoke(recipe_line={"setpoints": {"air_temperature": {"lower": 18, "upper": 22}}, "light_type": "GREEN"}),
            smoke(disturbances=[{"at_h": 0, "kind": "earthquake"}]),
            smoke(actuators=["light"]),
            smoke(loops={"air_temperature": {"input": {"tag": "air_temperature", "sources": ["default"],
                                                       "rule": "mean"}}}),
        ]
        for sc in bad:
            with self.assertRaises((runner.ScenarioError, algorithms_loader.LoaderError)):
                runner.run_scenario(sc, {"code": "IF_THEN_ELSE"}, 1, loaded=L)

    def test_metrics_formulas(self):
        s = metrics.LoopSeries()
        for x in (17.0, 18.2, 20.0, 21.9, 23.0):
            s.sample(x, 18.0, 22.0)
        r = s.result()
        self.assertAlmostEqual(r["rmsd_mid"], ((9 + 3.24 + 0 + 3.61 + 9) / 5) ** 0.5)
        self.assertAlmostEqual(r["out_of_band"], 2 / 5)
        self.assertAlmostEqual(r["boundary_hugging"], 2 / 3)     # 18.2 and 21.9 within 0.4 of an edge
        self.assertAlmostEqual(r["mean_abs_error"], 2 / 5)


class Venv(unittest.TestCase):
    """FLC and MPC for real, in research/.venv (skipped when it does not exist)."""

    def test_flc_and_mpc_use_their_libraries(self):
        if not os.path.exists(VENV_PY):
            self.skipTest("research/.venv does not exist (source research/lib-venv.sh && ensure_research_venv)")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        tmp = tempfile.mkdtemp(prefix="rs-harness-venv-")
        self.addCleanup(shutil.rmtree, tmp)
        # PyYAML comes from the venv itself (research/requirements.txt pins it); nothing of
        # the host's site-packages is borrowed.
        script = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import yaml
from research.harness import algorithms_loader, runner
L = algorithms_loader.load(sys.argv[1], allow_dirty=True)
sc = yaml.safe_load(open(sys.argv[2]))
sc.update(duration_h=0.1, metrics_from_h=0)
out = {"libraries": L.libraries}
for code in ("FLC", "MPC"):
    r = runner.run_scenario(dict(sc), {"code": code, "params": {}}, 1, 0.0, 0.0, loaded=L, trace=True)
    below = [e["loops"]["air_temperature"]["cmd"] for e in r["trace"]
             if e["loops"]["air_temperature"]["value"] is not None
             and e["loops"]["air_temperature"]["value"] < r["loops"]["air_temperature"]["lower"]]
    out[code] = {"valid": r["valid"], "reasons": r["invalid_reasons"],
                 "branches": {k: v["branches"] for k, v in r["loops"].items()},
                 "below_band_cmds": below,
                 "t_first": r["trace"][0]["truth"]["air_temperature"],
                 "t_last": r["trace"][-1]["truth"]["air_temperature"]}
print(json.dumps(out))
"""
        p = subprocess.run([VENV_PY, "-c", script, REPO, os.path.join(SCEN_DIR, "smoke_air_temperature.yaml")],
                           capture_output=True, text=True, env=env, cwd=tmp, timeout=600)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(out["libraries"]["FLC"]["present"], out["libraries"])
        self.assertTrue(out["libraries"]["MPC"]["present"], out["libraries"])
        for code in ("FLC", "MPC"):
            r = out[code]
            self.assertTrue(r["valid"], (code, r["reasons"]))
            for key, b in r["branches"].items():
                self.assertEqual(b["fallback"], 0, (code, key))
                self.assertGreater(b["library"], 0, (code, key))
            # The chamber starts at 16 C under an 18-22 band: a controller that moves toward
            # the band answers UP (heat) there. A DOWN majority is MPC's old inverted sign.
            cmds = r["below_band_cmds"]
            self.assertTrue(cmds, code)
            self.assertGreater(cmds.count("UP"), cmds.count("DOWN"),
                               "%s drives away from the band below it: %s" % (code, cmds))
            self.assertGreater(r["t_last"], r["t_first"], code)

    def test_the_campaign_cli_runs_in_the_venv(self):
        """research/.venv/bin/python -m research.harness.campaign on the shipped smoke spec,
        cut to a short scenario (a copy in a temp dir): exit 0, no invalid run, and no GEKKO
        temp directory left behind by the run."""
        if not os.path.exists(VENV_PY):
            self.skipTest("research/.venv does not exist (source research/lib-venv.sh && ensure_research_venv)")
        tmp = tempfile.mkdtemp(prefix="rs-campaign-venv-")
        self.addCleanup(shutil.rmtree, tmp)
        with open(os.path.join(CAMPAIGNS, "smoke.yaml"), encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        sc = smoke(duration_h=0.05, metrics_from_h=0)
        spec["scenarios"] = [sc]
        spec["seeds"] = [1]
        spec["clock_offsets_s"] = [0]
        spec_path = os.path.join(tmp, "spec.yaml")
        with open(spec_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(spec, f)
        gk = os.path.join(tmp, "gk")
        os.mkdir(gk)
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        env["TMPDIR"] = gk                       # GEKKO's mkdtemp lands here
        p = subprocess.run([VENV_PY, "-m", "research.harness.campaign", spec_path, "--out",
                            os.path.join(tmp, "out"), "--allow-dirty", "--jobs", "1"],
                           cwd=REPO, capture_output=True, text=True, env=env, timeout=900)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertRegex(p.stdout, r"campaign: 9 runs \(0 invalid\)")
        with open(os.path.join(tmp, "out", "manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
        self.assertTrue(m["code"]["controller_libraries"]["MPC"]["present"])
        self.assertEqual(m["code"]["libraries"]["PyYAML"], "6.0.3")
        self.assertEqual(os.listdir(gk), [], "GEKKO temp directories left behind")


class Campaign(unittest.TestCase):
    def spec(self):
        sc = smoke(duration_h=0.1, metrics_from_h=0)
        return campaign.resolve_spec({
            "scenarios": [sc],
            "controllers": [{"code": "IF_THEN_ELSE"},
                            {"code": "PID", "params_grid": {"kp": [0.2, 0.5], "ki": [0.05]}}],
            "seeds": [2, 1],
            "clock_offsets_s": [0, 5],
        })

    def test_expand(self):
        runs = campaign.expand(self.spec())
        self.assertEqual(len(runs), (1 + 2) * 2 * 2)
        self.assertEqual(runs, sorted(runs))
        self.assertIn(("smoke_air_temperature", "PID", '{"ki":0.05,"kp":0.5}', 1, 5.0), runs)

    def test_byte_identical_across_jobs_and_manifest(self):
        spec = self.spec()
        outs = []
        for jobs in (1, 2):
            d = tempfile.mkdtemp(prefix="rs-campaign-")
            self.addCleanup(shutil.rmtree, d)
            m = campaign.run_campaign(spec, d, repo_root=REPO, jobs=jobs, allow_dirty=True)
            with open(os.path.join(d, "results.jsonl"), "rb") as f:
                body = f.read()
            outs.append(body)
            self.assertEqual(m["result_digest"], hashlib.sha256(body).hexdigest())
            self.assertEqual(m["runs"], 12)
            self.assertEqual(m["metrics_version"], metrics.METRICS_VERSION)
            for k in ("commit", "blobs", "libraries", "dirty"):
                self.assertIn(k, m["code"])
            self.assertIn("schd/cea/algorithms/pid.py", m["code"]["blobs"])
            with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["spec_digest"], m["spec_digest"])
        self.assertEqual(outs[0], outs[1])
        lines = outs[0].decode().splitlines()
        self.assertEqual(len(lines), 12)
        self.assertEqual(json.loads(lines[0])["controller"]["code"], "IF_THEN_ELSE")

    def test_cpu_cap_refuses_and_writes_nothing(self):
        d = tempfile.mkdtemp(prefix="rs-campaign-")
        self.addCleanup(shutil.rmtree, d)
        out = os.path.join(d, "out")
        with self.assertRaisesRegex(campaign.CampaignError, "CPU-hours"):
            campaign.run_campaign(self.spec(), out, repo_root=REPO, allow_dirty=True, max_cpu_hours=1e-9)
        self.assertFalse(os.path.exists(out))

    def test_unknown_code_refused_before_running(self):
        spec = self.spec()
        spec["controllers"].append({"code": "PIDX", "params": {}, "params_grid": {}})
        d = tempfile.mkdtemp(prefix="rs-campaign-")
        self.addCleanup(shutil.rmtree, d)
        with self.assertRaises(algorithms_loader.LoaderError):
            campaign.run_campaign(spec, os.path.join(d, "out"), repo_root=REPO, allow_dirty=True)
        self.assertFalse(os.path.exists(os.path.join(d, "out")))

    def test_cpu_limit(self):
        self.assertGreaterEqual(campaign.cpu_limit(), 1)

    def test_cli_refuses_a_dirty_tree_without_the_flag(self):
        state = algorithms_loader.git_state(REPO)
        if not state["dirty"]:
            self.skipTest("the contract sources are clean in this checkout")
        d = tempfile.mkdtemp(prefix="rs-campaign-")
        self.addCleanup(shutil.rmtree, d)
        spec = os.path.join(d, "spec.yaml")
        with open(spec, "w", encoding="utf-8") as f:
            yaml.safe_dump({"scenarios": [os.path.join(SCEN_DIR, "smoke_air_temperature.yaml")],
                            "controllers": [{"code": "IF_THEN_ELSE"}], "seeds": [1]}, f)
        p = subprocess.run([sys.executable, "-m", "research.harness.campaign", spec, "--out", os.path.join(d, "o")],
                           cwd=REPO, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2)
        self.assertIn("differ from HEAD", p.stderr)
        self.assertIn("--allow-dirty", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "o")))


    def test_cap_message_has_significant_digits(self):
        with self.assertRaises(campaign.CampaignError) as cm:
            campaign.run_campaign(self.spec(), os.path.join(tempfile.gettempdir(), "rs-never-written"),
                                  repo_root=REPO, allow_dirty=True, max_cpu_hours=1e-6)
        msg = str(cm.exception)
        self.assertRegex(msg, r"over the cap of 1e-06 ")
        self.assertNotIn("0.00 CPU-hours", msg)
        self.assertFalse(os.path.exists(os.path.join(tempfile.gettempdir(), "rs-never-written")))

    def test_shipped_specs_resolve(self):
        L = loaded()
        for name, runs in (("smoke.yaml", 36), ("fruiting_compare.yaml", 45)):
            spec = campaign.load_spec(os.path.join(CAMPAIGNS, name))
            self.assertEqual(len(campaign.expand(spec)), runs, name)
            self.assertEqual({c["code"] for c in spec["controllers"]}, set(L.codes()), name)
            for sc in spec["scenarios"]:
                runner.normalise(copy.deepcopy(sc), L)
            for c in spec["controllers"]:
                for v in (c["params_grid"] or {None: [None]}).values():
                    for x in v:
                        p = dict(c["params"])
                        if x is not None:
                            p[next(iter(c["params_grid"]))] = x
                        L.check(c["code"], p)


class Manifest(unittest.TestCase):
    """The manifest pins the sandbox's own code too (F12)."""

    def test_sandbox_files_and_contract_version(self):
        L = loaded()
        m = L.manifest()
        self.assertEqual(m["contract_version"], __import__("research.contract", fromlist=["x"]).CONTRACT_VERSION)
        for rel in ("research/harness/runner.py", "research/harness/metrics.py", "research/harness/campaign.py",
                    "research/twin_plant/chamber.py", "research/twin_plant/sensors.py", "research/contract.py",
                    "research/harness/scenarios/smoke_air_temperature.yaml", "research/requirements.txt",
                    "apps/database/medcea_db_migrations.sql"):
            self.assertIn(rel, m["blobs"], rel)
            self.assertEqual(m["blobs"][rel], algorithms_loader.blob_sha(REPO, rel), rel)
        for rel in m["blobs"]:
            self.assertFalse(rel.startswith(("research/.venv/", "research/runs/")) or "__pycache__" in rel, rel)

    def test_a_changed_research_file_is_dirty(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        tmp = tempfile.mkdtemp(prefix="rs-sandbox-")
        self.addCleanup(shutil.rmtree, tmp)
        os.makedirs(os.path.join(tmp, "research", "harness"))
        os.makedirs(os.path.join(tmp, "research", ".venv"))
        os.makedirs(os.path.join(tmp, "research", "runs", "x"))
        for rel in ("research/harness/runner.py", "research/.venv/junk.py", "research/runs/x/results.jsonl"):
            with open(os.path.join(tmp, rel), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
        git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(git + ["add", "research/harness/runner.py"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "x"], check=True)
        saved = algorithms_loader.SANDBOX_ROOT
        algorithms_loader.SANDBOX_ROOT = tmp
        self.addCleanup(setattr, algorithms_loader, "SANDBOX_ROOT", saved)
        st = algorithms_loader.sandbox_state(tmp)
        self.assertFalse(st["dirty"], st)                       # .venv and runs never count
        self.assertEqual(algorithms_loader.sandbox_files(tmp), ["research/harness/runner.py"])
        with open(os.path.join(tmp, "research/harness/runner.py"), "a", encoding="utf-8") as f:
            f.write("# edited\n")
        st = algorithms_loader.sandbox_state(tmp)
        self.assertTrue(st["dirty"])
        self.assertEqual(st["dirty_files"], ["research/harness/runner.py"])
        self.assertEqual(algorithms_loader.sandbox_state("/elsewhere")["dirty_files"],
                         ["sandbox:research/harness/runner.py"])


class Production(unittest.TestCase):
    """Where the runner follows control_logic_thread / run_agent across cycles and errors."""

    def test_one_alarm_tracker_per_cycle(self):
        L = loaded()
        made = []
        orig = L.lr.AlarmTracker

        class Counting(orig):
            def __init__(self, *a, **k):
                made.append(self)
                super().__init__(*a, **k)
        L.lr.AlarmTracker = Counting
        self.addCleanup(setattr, L.lr, "AlarmTracker", orig)
        line = dict(smoke()["recipe_line"], light_on_minutes=1, light_off_minutes=1)
        run(smoke(duration_h=0.2, metrics_from_h=0, recipe_line=line))          # 720 s / 120 s
        self.assertEqual(len(made), 6)
        made.clear()
        run(smoke(duration_h=0.2, metrics_from_h=0, recipe_line=line, cycle_restart=False))
        self.assertEqual(len(made), 1)

    def test_a_restart_drops_messages_from_before_the_boundary(self):
        # The SCD30 publishes at 25 + 30 j s: at 115 s, between the ticks at 110 and 120 and
        # before the boundary at 120 s, which the old subscriber received.
        line = dict(smoke()["recipe_line"], light_on_minutes=1, light_off_minutes=1)
        sc = smoke(duration_h=0.2, metrics_from_h=0, recipe_line=line,
                   sensors={"overrides": {"scd30": {"start_offset_s": 25.0}}})
        r = run(sc, trace="readings", offset=3.0)
        firsts = [e for e in r["trace"] if e["t"] > 0 and e["t"] % 120.0 < 10.0]
        self.assertTrue(firsts)
        for e in firsts:
            boundary = e["t"] - e["t"] % 120.0
            for z, tag, sensor, value, recv in e["readings"]:
                self.assertGreaterEqual(recv - 3.0, boundary - 1e-9, (e["t"], sensor, tag))

    def test_input_tag_without_truth_or_sensor_is_refused(self):
        L = loaded()
        sc = smoke(sensors={"remove": ["sht45", "scd30"]})
        with self.assertRaisesRegex(runner.ScenarioError, "no configured sensor publishes air_temperature"):
            runner.run_scenario(sc, {"code": "IF_THEN_ELSE"}, 1, loaded=L)
        sc = smoke(loops={"air_temperature": {"input": {"tag": "leaf_temperature", "sources": ["sht45"],
                                                        "rule": "reference", "reference": "sht45"}}})
        with self.assertRaises(runner.ScenarioError) as cm:
            runner.run_scenario(sc, {"code": "IF_THEN_ELSE"}, 1, loaded=L)
        self.assertNotIsInstance(cm.exception, KeyError)

    def test_a_raising_loop_is_counted_and_the_others_go_on(self):
        L = loaded()
        orig = L.algorithms.ALGORITHM_NAMES["IF_THEN_ELSE"]

        class Raising(orig):
            def compute(self, v):
                if self.upper_limit == 22.0:          # only the air temperature loop (18-22)
                    raise ValueError("boom\nsecond line")
                return super().compute(v)
        L.algorithms.ALGORITHM_NAMES["IF_THEN_ELSE"] = Raising
        self.addCleanup(L.algorithms.ALGORITHM_NAMES.__setitem__, "IF_THEN_ELSE", orig)
        r = run(smoke(duration_h=0.1, metrics_from_h=0), trace=True)
        self.assertFalse(r["valid"])
        t = r["loops"]["air_temperature"]
        self.assertGreater(t["errors"], 0)
        self.assertEqual(r["loops"]["air_humidity"]["errors"], 0)
        self.assertGreater(r["loops"]["air_humidity"]["commands"]["UP"] + r["loops"]["air_humidity"]["commands"]["OFF"]
                           + r["loops"]["air_humidity"]["commands"]["DOWN"], 0)
        self.assertIn("loop air_temperature raised on %d tick(s) (first: ValueError: boom second line)" % t["errors"],
                      r["invalid_reasons"])
        self.assertEqual(len(r["trace"]), 36)                    # every tick still ran

    def test_mpc_instances_are_closed(self):
        L = loaded()
        if "MPC" not in L.algorithms.ALGORITHM_NAMES:
            self.skipTest("no MPC")
        orig = L.algorithms.ALGORITHM_NAMES["MPC"]
        made, closed = [], []

        class Tracked(orig):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                made.append(self)

            def close(self):
                closed.append(self)
                super().close()
        L.algorithms.ALGORITHM_NAMES["MPC"] = Tracked
        self.addCleanup(L.algorithms.ALGORITHM_NAMES.__setitem__, "MPC", orig)
        line = dict(smoke()["recipe_line"], light_on_minutes=1, light_off_minutes=1)
        run(smoke(duration_h=0.1, metrics_from_h=0, recipe_line=line), code="MPC")
        self.assertTrue(made)
        self.assertEqual(sorted(map(id, closed)), sorted(map(id, made)))
        before = len(closed)
        L._library_presence()
        self.assertEqual(len(closed) - before, 1)               # the probe instance too


if __name__ == "__main__":
    unittest.main()
