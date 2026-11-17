#!/usr/bin/env python3
"""Production controller parity (research sandbox Phase 1, owner decision of 17 Nov 2026).

Offline; the cea package is NOT imported (its __init__ needs psycopg2): a stub package
points at schd/cea, as tests/test_loop_resolver.py does, so only
schd/cea/algorithms/__init__.py runs.

- Params        schd/cea/algorithms/params.py: one schema per ALGORITHM_NAMES code, its
                names and defaults = each class's __init__ (inspect), bounds well formed;
                validate_params catches an unknown code, a non-object, an unknown key, a
                wrong type (bool, string, float for an int), a non-finite value, a value
                out of range (inclusive and exclusive minimum); the defaults validate.
- MpcSign       a fake gekko module (no gekko needed): u > 0.05 -> UP, u < -0.05 -> DOWN,
                inside the deadband OFF (the model x' = (a-1)x + b*u, b > 0).
- MpcCleanup    GEKKO's temp directory: reset() cleans the old model, close() and __del__
                clean once, a failing cleanup is swallowed, no gekko is harmless.
- ControlLogicCloses  control_logic_thread's finally closes every algorithm after its
                state was collected (getattr guard; a failing close() is logged only).
- Fallbacks     MPC without gekko and on a solver exception, FLC without scikit-fuzzy
                and on a compute exception: bang-bang answers, fallback_count,
                last_fallback, FALLBACK_TOTAL, one stderr line then one per 360.
- RealLibraries research/.venv/bin/python, when it exists (else skipped): real GEKKO
                below the band UP, above DOWN, in band OFF; real FLC likewise; no fallback;
                MPC's GEKKO temp directories are gone after reset(), close() and del.
- SchedulerPod  apps/scheduler/k8s/scheduler.yaml installs requirements-controllers.txt
                with --require-hashes --no-deps after the unpinned line; every line is
                pinned with a sha256; the ConfigMap ships the file; the render list is
                unchanged.
- HealthCheck   check_controllers against a fake kubectl (tests/test_health_phase5.py's
                Tree): OK on the pins, WARN on missing/broken/other version, no pod,
                SKIP without the scheduler, read-only, versions only; conf and dispatch.

    python3 -m unittest tests.test_controllers_parity
"""
import contextlib
import importlib
import inspect
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CEA = os.path.join(REPO, "schd", "cea")
VENV_PY = os.path.join(REPO, "research", ".venv", "bin", "python")
sys.path.insert(0, HERE)   # tests/test_health_phase5.py's fake kubectl tree, for HealthCheck

_pkg = types.ModuleType("cea_cp")
_pkg.__path__ = [CEA]
sys.modules.setdefault("cea_cp", _pkg)
algos = importlib.import_module("cea_cp.algorithms")
params = importlib.import_module("cea_cp.algorithms.params")
mpc = importlib.import_module("cea_cp.algorithms.mpc")
flc = importlib.import_module("cea_cp.algorithms.flc")


def read(*p):
    with open(os.path.join(REPO, *p), encoding="utf-8") as f:
        return f.read()


# ── params.py ───────────────────────────────────────────────────────────────────────────
class Params(unittest.TestCase):
    def test_every_code_has_a_schema(self):
        self.assertEqual(set(params.PARAMS), set(algos.ALGORITHM_NAMES))

    def test_schema_matches_each_init(self):
        for code, cls in algos.ALGORITHM_NAMES.items():
            sig = inspect.signature(cls.__init__)
            got = {n: p.default for n, p in sig.parameters.items()
                   if n not in ("self", "lower_limit", "upper_limit")
                   and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)}
            want = {n: s["default"] for n, s in params.PARAMS[code].items()}
            self.assertEqual(got, want, code)
            for n, s in params.PARAMS[code].items():
                self.assertEqual(type(s["default"]).__name__, s["type"], (code, n))
                self.assertIn(s["type"], ("int", "float"))
                self.assertLess(s["min"], s["max"], (code, n))
                for k in ("unit", "meaning"):
                    self.assertTrue(s[k], (code, n, k))
                self.assertEqual(params.validate_params(code, {n: s["default"]}), [], (code, n))

    def test_defaults_validate_and_construct(self):
        for code, cls in algos.ALGORITHM_NAMES.items():
            d = params.defaults(code)
            self.assertEqual(params.validate_params(code, d), [], code)
            self.assertEqual(params.validate_params(code, None), [])
            self.assertEqual(params.validate_params(code, {}), [])
            with contextlib.redirect_stderr(io.StringIO()):
                cls(lower_limit=18.0, upper_limit=22.0, **d)
        self.assertIsNone(params.defaults("NOPE"))

    def test_the_seeded_database_defaults_validate(self):
        # migration 001's control_algorithm.default_params rows
        mig = read("apps", "database", "medcea_db_migrations.sql")
        rows = re.findall(r"\('(IF_THEN_ELSE|PID|FLC|MPC|Q_LEARNING)',.*?'(\{[^']*\})'\)", mig, re.S)
        self.assertEqual({c for c, _ in rows}, set(algos.ALGORITHM_NAMES))
        for code, js in rows:
            self.assertEqual(params.validate_params(code, json.loads(js)), [], code)

    def test_problem_kinds(self):
        v = params.validate_params
        self.assertIn("unknown algorithm code 'BANG'", v("BANG", {})[0])
        self.assertIn("unknown algorithm code None", v(None, {})[0])
        self.assertIn("must be an object", v("PID", [1])[0])
        self.assertIn("unknown parameter 'kq'", v("PID", {"kq": 1})[0])
        self.assertIn("unknown parameter 'x' (known: none)", v("IF_THEN_ELSE", {"x": 1})[0])
        self.assertIn("kp must be a number", v("PID", {"kp": "0.2"})[0])
        self.assertIn("kp must be a number", v("PID", {"kp": True})[0])
        self.assertIn("horizon must be an integer", v("MPC", {"horizon": 6.0})[0])
        self.assertEqual(v("PID", {"kp": 1}), [])            # an int is a number
        self.assertIn("finite", v("PID", {"kp": math.nan})[0])
        self.assertIn("finite", v("PID", {"kp": math.inf})[0])
        self.assertIn("horizon = 0 is outside [1, 60]", v("MPC", {"horizon": 0})[0])
        self.assertIn("is outside (0.0, 0.4]", v("FLC", {"deadband_fraction": 0.0})[0])
        self.assertIn("is outside (0.0, 0.4]", v("FLC", {"deadband_fraction": 0.5})[0])
        self.assertEqual(v("FLC", {"deadband_fraction": 0.4}), [])
        self.assertEqual(v("Q_LEARNING", {"gamma": 0.0}), [])   # inclusive minimum
        self.assertEqual(len(v("PID", {"kp": -1, "ki": "x", "zz": 1})), 3)

    def test_stdlib_only(self):
        import ast
        tree = ast.parse(read("schd", "cea", "algorithms", "params.py"))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, (ast.Import, ast.ImportFrom))


# ── a fake gekko ────────────────────────────────────────────────────────────────────────
class _Var:
    def __init__(self, value=0.0):
        self.value = value
        self.NEWVAL = value

    def dt(self):
        return self

    def _op(self, *_):
        return self

    __add__ = __radd__ = __sub__ = __rsub__ = __mul__ = __rmul__ = __truediv__ = __rtruediv__ = _op

    def __eq__(self, other):
        return self

    __hash__ = object.__hash__


def fake_gekko(u_out=0.0, fail=None, cleanup_fail=None):
    """A gekko module whose solve() sets u.NEWVAL to u_out (or raises fail); cleanup()
    is recorded in mod.cleanups (and raises cleanup_fail when given)."""
    mod = types.ModuleType("gekko")

    class GEKKO:
        def __init__(self, remote=True):
            self.options = types.SimpleNamespace()
            self.time = []
            self.mvs = []

        def Const(self, v):
            return v

        def CV(self, value=0.0, lb=None, ub=None):
            return _Var(value)

        def MV(self, value=0.0, lb=None, ub=None):
            v = _Var(value)
            self.mvs.append(v)
            return v

        def Equation(self, eq):
            return eq

        def solve(self, disp=True):
            if fail:
                raise fail
            for v in self.mvs:
                v.NEWVAL = u_out

        def cleanup(self):
            mod.cleanups.append(self)
            if cleanup_fail:
                raise cleanup_fail

    mod.GEKKO = GEKKO
    mod.cleanups = []        # every GEKKO.cleanup() call, in order
    return mod


@contextlib.contextmanager
def modules(**mods):
    """sys.modules entries for the block; None makes the import fail."""
    saved = {k: sys.modules.get(k, KeyError) for k in mods}
    try:
        for k, v in mods.items():
            sys.modules[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is KeyError:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


class MpcSign(unittest.TestCase):
    def cmd(self, u, sensor=20.0):
        with modules(gekko=fake_gekko(u)):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            out = a.compute(sensor)
        self.assertEqual(a.fallback_count, 0)
        return out

    def test_positive_u_raises_the_reading(self):
        self.assertEqual(self.cmd(1.0), "UP")
        self.assertEqual(self.cmd(0.06), "UP")

    def test_negative_u_lowers_it(self):
        self.assertEqual(self.cmd(-1.0), "DOWN")
        self.assertEqual(self.cmd(-0.06), "DOWN")

    def test_deadband_is_off(self):
        for u in (0.0, 0.05, -0.05, 0.01):
            self.assertEqual(self.cmd(u), "OFF", u)

    def test_the_command_ignores_the_reading_when_the_solver_answers(self):
        # the solver's answer, not bang-bang, decides: 25 is above the band, u > 0 still UP
        self.assertEqual(self.cmd(1.0, sensor=25.0), "UP")


class MpcCleanup(unittest.TestCase):
    """GEKKO(remote=False) makes a temp directory per model that only m.cleanup()
    removes: reset() cleans the old model before building, close() and __del__ once."""

    def test_reset_cleans_the_previous_model(self):
        g = fake_gekko(1.0)
        with modules(gekko=g):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            first = a._m
            a.reset()
            self.assertEqual(g.cleanups, [first])
            self.assertIsNot(a._m, first)
            self.assertEqual(a.compute(20.0), "UP")      # behaviour unchanged after reset
            self.assertEqual(a.fallback_count, 0)

    def test_close_cleans_once(self):
        g = fake_gekko(1.0)
        with modules(gekko=g):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            m = a._m
            a.close()
            a.close()
            a.__del__()
        self.assertEqual(g.cleanups, [m])
        self.assertIsNone(a._m)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(a.compute(15.0), "UP")     # a closed instance answers bang-bang
        self.assertEqual(a.fallback_count, 1)

    def test_del_cleans_an_unclosed_model(self):
        g = fake_gekko(1.0)
        with modules(gekko=g):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            m = a._m
            del a
            import gc
            gc.collect()
        self.assertEqual(g.cleanups, [m])

    def test_a_failing_cleanup_is_swallowed(self):
        g = fake_gekko(1.0, cleanup_fail=OSError("gone"))
        with modules(gekko=g):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            a.reset()
            a.close()
        self.assertEqual(len(g.cleanups), 2)

    def test_without_gekko_close_is_harmless(self):
        with modules(gekko=None):
            a = mpc.MPCAlgorithm(18.0, 22.0)
        a.close()
        a.reset()
        self.assertIsNone(a._m)


# ── control_logic_thread closes its algorithms ─────────────────────────────────────────
class ControlLogicCloses(unittest.TestCase):
    """schd/cea/control_logic_thread.py's finally collects the states, then calls each
    algorithm's close() (guarded): a stub cea package, the stop event already set."""

    def run_thread(self, algo_factory):
        made = []

        def get_algorithm(code, lo, hi, **kw):
            a = algo_factory()
            made.append(a)
            return a
        lr = importlib.import_module("cea_cp.loop_resolver")
        cea = types.ModuleType("cea")
        cea.__path__ = []
        cea.mqtt_publish_control_message = lambda *a, **k: None
        cea.loop_resolver = lr
        alg = types.ModuleType("cea.algorithms")
        alg.get_algorithm = get_algorithm
        ns = {}
        exec(compile(read("schd", "cea", "control_logic_thread.py"), "control_logic_thread.py", "exec"), ns)
        import datetime
        import threading
        stop = threading.Event()
        stop.set()
        loops = [{"zone_code": "Z1", "loop_code": "air_temperature", "loop_id": 1,
                  "input": {"tag": "air_temperature"}, "output": {"actuator": "air_temperature"}},
                 {"zone_code": "Z1", "loop_code": "air_humidity", "loop_id": 2,
                  "input": {"tag": "air_humidity"}, "output": {"actuator": "air_humidity"}}]
        params = [{"light_type": "DARK", "light_on_minutes": 0, "control_algorithm": "MPC",
                   "setpoints": {"air_temperature": {"lower": 18, "upper": 22},
                                 "air_humidity": {"lower": 80, "upper": 90}}}]
        states = {}
        out = io.StringIO()
        with modules(cea=cea, **{"cea.algorithms": alg}), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            ns["control_logic_thread"](None, params, datetime.datetime.now(datetime.timezone.utc), {},
                                       threading.Lock(), stop, loops=loops, unit_code="U1", root="r",
                                       result_states=states)
        return made, states, out.getvalue()

    def test_every_algorithm_is_closed_after_its_state_is_collected(self):
        order = []

        class A:
            def compute(self, v):
                return "OFF"

            def load_state(self, s):
                pass

            def get_state(self):
                order.append("state")
                return {"k": 1}

            def close(self):
                order.append("close")
        made, states, _ = self.run_thread(A)
        self.assertEqual(len(made), 2)
        self.assertEqual(order, ["state", "state", "close", "close"])
        self.assertEqual(set(states), {"air_temperature", "air_humidity"})

    def test_a_failing_close_does_not_stop_the_others(self):
        closed = []

        class A:
            def get_state(self):
                return {}

            def close(self):
                closed.append(self)
                raise RuntimeError("boom")
        made, _, out = self.run_thread(A)
        self.assertEqual(closed, made)
        self.assertEqual(out.count("closing loop"), 2)

    def test_an_algorithm_without_close(self):
        class A:
            def get_state(self):
                return {}
        made, _, out = self.run_thread(A)
        self.assertEqual(len(made), 2)
        self.assertIn("stopped", out)


class Fallbacks(unittest.TestCase):
    def run_quiet(self, fn):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = fn()
        return out, err.getvalue()

    def bang_bang(self, a):
        return [a.compute(v) for v in (15.0, 20.0, 25.0)]

    def test_mpc_without_gekko(self):
        before = mpc.FALLBACK_TOTAL
        with modules(gekko=None):
            a = mpc.MPCAlgorithm(18.0, 22.0)
        out, err = self.run_quiet(lambda: self.bang_bang(a))
        self.assertEqual(out, ["UP", "OFF", "DOWN"])
        self.assertEqual(a.fallback_count, 3)
        self.assertIn("gekko is not installed", a.last_fallback)
        self.assertEqual(mpc.FALLBACK_TOTAL - before, 3)
        lines = err.splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith("WARNING mpc fallback: gekko is not installed"), err)

    def test_mpc_solver_exception(self):
        with modules(gekko=fake_gekko(fail=RuntimeError("@error: Solution Not Found\nline 2"))):
            a = mpc.MPCAlgorithm(18.0, 22.0)
            out, err = self.run_quiet(lambda: self.bang_bang(a))
        self.assertEqual(out, ["UP", "OFF", "DOWN"])
        self.assertEqual(a.fallback_count, 3)
        self.assertEqual(a.last_fallback, "solver failed (RuntimeError: @error: Solution Not Found line 2)")
        self.assertEqual(err.count("WARNING mpc fallback: solver failed"), 1)
        self.assertNotIn("line 2\n", err.replace("line 2)", ""))   # one line per report

    def test_rate_limit_one_line_per_360(self):
        with modules(gekko=None):
            a = mpc.MPCAlgorithm(18.0, 22.0)
        _, err = self.run_quiet(lambda: [a.compute(20.0) for _ in range(721)])
        self.assertEqual(a.fallback_count, 721)
        self.assertEqual(err.count("WARNING mpc fallback:"), 3)   # fallbacks 1, 361, 721
        self.assertIn("fallback 361 of this controller", err)
        # a second instance reports its own first fallback
        with modules(gekko=None):
            b = mpc.MPCAlgorithm(18.0, 22.0)
        _, err = self.run_quiet(lambda: b.compute(20.0))
        self.assertEqual(err.count("WARNING mpc fallback:"), 1)

    def test_flc_without_scikit_fuzzy(self):
        before = flc.FALLBACK_TOTAL
        with modules(skfuzzy=None, numpy=None):
            a = flc.FLCAlgorithm(18.0, 22.0)
        out, err = self.run_quiet(lambda: self.bang_bang(a))
        self.assertEqual(out, ["UP", "OFF", "DOWN"])
        self.assertEqual(a.fallback_count, 3)
        self.assertIn("scikit-fuzzy is not usable", a.last_fallback)
        self.assertEqual(flc.FALLBACK_TOTAL - before, 3)
        self.assertEqual(len(err.splitlines()), 1)
        self.assertTrue(err.startswith("WARNING flc fallback: scikit-fuzzy is not usable"), err)

    def test_flc_compute_exception(self):
        with modules(skfuzzy=None, numpy=None):
            a = flc.FLCAlgorithm(18.0, 22.0)

        class Broken:
            input = {}

            def compute(self):
                raise ValueError("crisp output cannot be calculated")
        a._ctrl = Broken()
        out, err = self.run_quiet(lambda: self.bang_bang(a))
        self.assertEqual(out, ["UP", "OFF", "DOWN"])
        self.assertEqual(a.fallback_count, 3)
        self.assertEqual(a.last_fallback, "compute failed (ValueError: crisp output cannot be calculated)")
        self.assertEqual(err.count("WARNING flc fallback: compute failed"), 1)

    def test_files_import_without_the_libraries(self):
        for f in ("mpc.py", "flc.py"):
            src = read("schd", "cea", "algorithms", f)
            top = [l for l in src.splitlines() if re.match(r"(import|from) ", l)]
            self.assertEqual(sorted(top), sorted(l for l in top if re.match(r"(import (sys|time) as|from \.base)", l)), f)


# ── the real libraries, through research/.venv ─────────────────────────────────────────
REAL = r'''
import json, sys, types, importlib
p = types.ModuleType("cea_rl"); p.__path__ = [sys.argv[1]]; sys.modules["cea_rl"] = p
mpc = importlib.import_module("cea_rl.algorithms.mpc")
flc = importlib.import_module("cea_rl.algorithms.flc")
out = {}
for name, mod, cls in (("mpc", mpc, mpc.MPCAlgorithm), ("flc", flc, flc.FLCAlgorithm)):
    res = []
    for v in (15.0, 17.9, 20.0, 22.1, 25.0):
        a = cls(18.0, 22.0)
        res.append([v, a.compute(v), a.fallback_count, a.last_fallback])
    out[name] = res
print(json.dumps(out))
'''


@unittest.skipUnless(os.path.exists(VENV_PY),
                     "research/.venv is not built (research/lib-venv.sh): the real gekko/scikit-fuzzy test is skipped")
class RealLibraries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = subprocess.run([VENV_PY, "-c", REAL, CEA], capture_output=True, text=True, timeout=600,
                           cwd=REPO, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise AssertionError(p.stderr)
        cls.res = json.loads(p.stdout.strip().splitlines()[-1])

    def check(self, name):
        got = {v: (cmd, n, why) for v, cmd, n, why in self.res[name]}
        for v, (_, n, why) in got.items():
            self.assertEqual(n, 0, (name, v, why))
        self.assertEqual(got[15.0][0], "UP")
        self.assertEqual(got[17.9][0], "UP")
        self.assertEqual(got[20.0][0], "OFF")
        self.assertEqual(got[22.1][0], "DOWN")
        self.assertEqual(got[25.0][0], "DOWN")

    def test_mpc_below_up_above_down_in_band_off(self):
        self.check("mpc")

    def test_flc_agrees(self):
        self.check("flc")

    def test_mpc_temp_directories_are_removed(self):
        code = (r'''
import json, os, sys, types, importlib
p = types.ModuleType("cea_rl"); p.__path__ = [sys.argv[1]]; sys.modules["cea_rl"] = p
mpc = importlib.import_module("cea_rl.algorithms.mpc")
a = mpc.MPCAlgorithm(18.0, 22.0)
first = a._m._path
a.compute(15.0)
a.reset()
second = a._m._path
a.compute(15.0)
a.close()
b = mpc.MPCAlgorithm(18.0, 22.0)
third = b._m._path
del b
print(json.dumps([os.path.exists(first), os.path.exists(second), os.path.exists(third),
                  a.fallback_count]))
''')
        p = subprocess.run([VENV_PY, "-c", code, CEA], capture_output=True, text=True, timeout=600,
                           cwd=REPO, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout.strip().splitlines()[-1]), [False, False, False, 0])


# ── the scheduler pod ──────────────────────────────────────────────────────────────────
PINS = {"gekko": "1.3.3", "networkx": "3.6.1", "numpy": "2.4.6", "packaging": "26.3",
        "scikit-fuzzy": "0.5.0", "scipy": "1.17.1"}


class SchedulerPod(unittest.TestCase):
    def api_command(self):
        import yaml
        doc = next(yaml.safe_load_all(read("apps", "scheduler", "k8s", "scheduler.yaml")))
        c = [c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "api"]
        self.assertEqual(len(c), 1)
        return c[0]["command"][2]

    def test_requirements_are_hash_pinned(self):
        lines = [l for l in read("apps", "scheduler", "requirements-controllers.txt").splitlines()
                 if l.strip() and not l.startswith("#")]
        got = {}
        for l in lines:
            m = re.fullmatch(r"([a-z0-9-]+)==(\S+) --hash=sha256:[0-9a-f]{64}", l)
            self.assertTrue(m, l)
            got[m.group(1)] = m.group(2)
        self.assertEqual(got, PINS)

    def test_installed_after_the_unpinned_line_with_require_hashes(self):
        cmd = self.api_command()
        unpinned = cmd.index("pip install --quiet flask")
        pinned = cmd.index("pip install --quiet --require-hashes --no-deps -r /scripts/requirements-controllers.txt")
        start = cmd.index("python /scripts/scheduler-api.py")
        self.assertLess(unpinned, pinned)
        self.assertLess(pinned, start)
        self.assertIn("pandas", cmd[unpinned:pinned])   # pandas pulls numpy unpinned: the pin wins
        p = subprocess.run(["bash", "-n"], input=cmd, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_the_configmap_ships_the_file(self):
        dep = read("apps", "scheduler", "deploy.sh")
        self.assertIn('--from-file=requirements-controllers.txt="$SCRIPT_DIR/requirements-controllers.txt"', dep)
        m = re.search(r"create configmap scheduler-api .*?--dry-run", dep, re.S)
        self.assertIn("requirements-controllers.txt", m.group(0))
        # no new ${VAR} in the template, so the render list stays as it was
        tpl = "\n".join(l for l in read("apps", "scheduler", "k8s", "scheduler.yaml").splitlines()
                        if not l.lstrip().startswith("#"))   # the comments name SCHEDULER_DOMAIN
        self.assertEqual(sorted(set(re.findall(r"\$\{([A-Z_]+)\}", tpl))),
                         sorted(["IAM_ENFORCE", "NAMESPACE", "PG_SECRET", "PG_SECRET_KEY", "PG_USER",
                                 "PROJECT_NAME", "REPO_ROOT"]))
        self.assertIn("render \"$SCRIPT_DIR/k8s/scheduler.yaml\" NAMESPACE PG_USER PG_SECRET PG_SECRET_KEY "
                      "PROJECT_NAME REPO_ROOT IAM_ENFORCE", dep)

    def test_the_research_venv_pins_the_same_controller_libraries(self):
        # the host's own wheels differ (python 3.14), but gekko and scikit-fuzzy are the same versions
        req = read("research", "requirements.txt") if os.path.exists(os.path.join(REPO, "research", "requirements.txt")) else ""
        if not req:
            self.skipTest("research/requirements.txt is not there")
        for lib in ("gekko", "scikit-fuzzy", "packaging"):
            self.assertIn(f"{lib}=={PINS[lib]} ", req, lib)


# ── the health check ───────────────────────────────────────────────────────────────────
class HealthCheck(unittest.TestCase):
    NAME = "Controller libraries"

    @classmethod
    def setUpClass(cls):
        import test_health_phase5 as h5
        cls.h5 = h5
        cls.t = h5.Tree()
        os.makedirs(cls.t.path("apps", "scheduler"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "scheduler", "requirements-controllers.txt"),
                    cls.t.path("apps", "scheduler", "requirements-controllers.txt"))

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def run_check(self, probe=None, absent=False, pods=("scheduler-1",)):
        h5 = self.h5
        rules = h5.dep_rules("scheduler", list(pods), absent=absent)
        for p in pods:
            rules.append(h5.rule(rf"exec -n medcea {p} -c api -- python3 -c", probe if probe is not None else "1.3.3 0.5.0\n"))
        self.t.scenario(rules)
        r = self.t.fn("check_controllers", f'check_controllers "{self.NAME}" medcea')
        for c in self.t.calls():
            self.assertIn(c["argv"][0], ("get", "exec", "version"), c)
        return r

    def test_ok_on_the_pins_and_versions_only(self):
        r = self.run_check()
        self.assertEqual(r, f"OK|{self.NAME}|pod scheduler-1: gekko 1.3.3, scikit-fuzzy 0.5.0 (the pinned versions)")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)                     # Running, not terminating, pods only
        probe = ex[0]["argv"][-1]
        self.assertIn('ver("gekko")', probe)
        self.assertIn('ver("skfuzzy", ("skfuzzy.control",))', probe)
        self.assertIn("timeout", self.h5.body("check_controllers"))

    def test_missing_and_broken_warn(self):
        r = self.run_check("missing:gekko 0.5.0\n")
        self.assertEqual(r, f"WARN|{self.NAME}|pod scheduler-1: gekko is not installed: MPC runs as bang-bang "
                            "(./apps/scheduler/deploy.sh)")
        r = self.run_check("1.3.3 missing:packaging\n")
        self.assertIn("skfuzzy cannot import packaging: FLC runs as bang-bang", r)
        self.assertTrue(r.startswith("WARN|"))
        r = self.run_check("1.3.3 broken:AttributeError\n")
        self.assertIn("skfuzzy fails to import (AttributeError): FLC runs as bang-bang", r)

    def test_another_version_warns(self):
        r = self.run_check("1.2.0 0.5.0\n")
        self.assertEqual(r, f"WARN|{self.NAME}|pod scheduler-1: gekko 1.2.0 is not the pinned 1.3.3 "
                            "(./apps/scheduler/deploy.sh)")

    def test_never_fails(self):
        for probe in ("", "garbage\n", "missing:gekko missing:skfuzzy\n"):
            r = self.run_check(probe)
            self.assertTrue(r.startswith("WARN|"), (probe, r))
        self.assertIn("cannot read the controller libraries in pod scheduler-1", self.run_check(""))

    def test_no_running_pod_warns_and_no_scheduler_skips(self):
        self.assertEqual(self.run_check(pods=()),
                         f"WARN|{self.NAME}|no Running scheduler pod: its controller libraries cannot be read")
        self.assertEqual(self.run_check(absent=True),
                         f"SKIP|{self.NAME}|the scheduler is not deployed (./apps/scheduler/deploy.sh)")

    def test_wiring(self):
        lines = [l for l in read("health-checks.conf").splitlines() if l.strip() and not l.startswith("#")]
        names = [l.split("|")[0].strip() for l in lines]
        i = names.index("Control loops")
        self.assertEqual([x.strip() for x in lines[i + 1].split("|")[:3]], [self.NAME, "controllers", "$NAMESPACE"])
        self.assertEqual(len(lines), 66)
        src = read("health-check.sh")
        self.assertRegex(src, r'(?m)^        controllers\)  check_controllers "\$name" "\$target" ;;$')
        self.assertIn("${CYAN}controllers${NC}", src)
        self.assertNotIn("_record FAIL", self.h5.body("check_controllers", src))


if __name__ == "__main__":
    unittest.main()
