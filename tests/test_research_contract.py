"""The research sandbox's coupling contract (plan, "Coupling contract").

The sandbox is its own application. Only four interfaces touch the rest of MedCEA:
identity, read-only research data, the metadata production itself uses, and one gateway
for candidates. This test pins the parts Phase 1 has, so a change on either side fails
here until both move in the same commit:

- Quantities: research/contract.py's reviewed table = schd/cea/loop_resolver.QUANTITIES =
  apps/database/recipe_types.yaml's loopable quantities (tag, commands, command_map,
  phase, and their order, which decides who wins a shared relay), and the harness's own
  table (algorithms_loader.Loaded.quantities) is read from the YAML, never copied.
- Actuators: contract.ACTUATORS / LIGHT_TYPES / SHARED_RELAYS = edge/templates/
  esp32-control.json's relay8 actuators; the chamber model knows exactly those relays;
  the runner's Board applies the template's relay sets and the last message wins on a
  shared relay.
- Controllers: every code the harness accepts = ALGORITHM_NAMES; params.py covers each
  and its schema matches the classes' signatures; unknown codes and bad parameters are
  refused by the loader and by a campaign before anything runs.
- Loop rules: research/ defines none of loop_resolver's functions and the runner calls
  them on the loaded module.
- Setpoints: the runner's recipe-line checks are recipe_line_setpoints_guard's (migration
  011, a contract source): the same four rules, in order, with the trigger's RAISE texts.
- Isolation: nothing under research/ imports cea's __init__ (psycopg2, paho) or an
  operational module, starts psql/kubectl, or holds SQL; no import alias, `from`
  import or getattr rebinds a process or import primitive (which the call-name checks
  would miss); a run in a clean interpreter that refuses those imports loads only
  research/ and the two contract code paths.
- research/README.md states the four interfaces.

Offline, deterministic, standard library + PyYAML. Run:
    python3 -m unittest tests.test_research_contract
"""
import ast
import contextlib
import copy
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

import yaml  # noqa: E402

from research import contract  # noqa: E402
from research.harness import algorithms_loader, campaign, runner  # noqa: E402
from research.twin_plant import chamber, sensors  # noqa: E402

RESEARCH = os.path.join(REPO, "research")
SCEN_DIR = os.path.join(RESEARCH, "harness", "scenarios")


def loaded():
    # allow_dirty: the test checks the working copy; the manifest's dirty rule has its own test.
    return algorithms_loader.load(REPO, allow_dirty=True)


def research_py():
    """Every Python file under research/ but the virtualenv and caches."""
    out = []
    for root, dirs, files in os.walk(RESEARCH):
        dirs[:] = sorted(d for d in dirs if d not in (".venv", "__pycache__", "runs"))
        out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
    return out


def parse(path):
    with open(path, encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def rel(path):
    return os.path.relpath(path, REPO)


# ── interface 3: the quantity catalogue ───────────────────────────────────────────────
class Quantities(unittest.TestCase):
    def setUp(self):
        self.L = loaded()
        with open(os.path.join(REPO, "apps/database/recipe_types.yaml"), encoding="utf-8") as f:
            self.yaml = yaml.safe_load(f)

    def test_reviewed_form_matches_the_sources(self):
        self.assertEqual(contract.drift(self.L), [])

    def test_loop_resolver_copy_equals_the_catalogue(self):
        lr = self.L.lr
        self.assertEqual(list(lr.QUANTITIES), [q["code"] for q in self.yaml["quantities"]])
        for q in self.yaml["quantities"]:
            want = {"tag": q["default_tag"], "sense_uoms": q["sense_uoms"], "commands": q["commands"],
                    "phase": q["phase"], "loopable": q["loopable"]}
            if q.get("command_map"):
                want["command_map"] = q["command_map"]
            self.assertEqual(lr.QUANTITIES[q["code"]], want, q["code"])

    def test_loopable_order_is_the_reviewed_order(self):
        codes = [c for c, _ in contract.QUANTITIES]
        self.assertEqual(self.L.lr.loopable(self.L.lr.QUANTITIES), codes)
        self.assertEqual([q["code"] for q in self.yaml["quantities"] if q["loopable"]], codes)

    def test_the_harness_reads_its_table_from_the_catalogue(self):
        lr = self.L.lr
        for t in self.yaml["recipe_types"]:
            got = self.L.quantities(t["code"])
            self.assertEqual(list(got), [q["code"] for q in self.yaml["quantities"] if q["code"] in t["quantities"]])
            for code, e in got.items():
                for k, v in lr.QUANTITIES[code].items():
                    self.assertEqual(e[k], v, (t["code"], code, k))
                q = next(x for x in self.yaml["quantities"] if x["code"] == code)
                self.assertEqual((e["min"], e["max"], e["required"]), (q["min"], q["max"], t["quantities"][code]))
        # A change to the YAML reaches the harness without a code change: no copy is kept.
        changed = copy.deepcopy(self.yaml)
        changed["quantities"][0]["max"] = 59
        self.assertEqual(algorithms_loader._quantities(changed, "FUNGI")["air_temperature"]["max"], 59)

    def test_default_map_on_the_template_board(self):
        """build_default_map over the relay8 board: every loopable quantity gets its own
        actuator, on its default tag, and every command the loop can send (the algorithm's
        UP/DOWN/OFF through command_map) is a command the actuator and the catalogue know."""
        lr = self.L.lr
        for t in self.yaml["recipe_types"]:
            quantities = self.L.quantities(t["code"])
            decl = {n: {"quantity": d.get("quantity")} for n, d in self.L.actuators.items()
                    if d.get("kind") == "commands"}
            loops = lr.build_default_map(["Z1"], quantities, {"Z1": decl})
            self.assertEqual([lp["loop_code"] for lp in loops], [c for c, _ in contract.QUANTITIES])
            errs, _ = lr.validate_loops(loops, quantities)
            self.assertEqual(errs, [])
            for lp in loops:
                code = lp["loop_code"]
                self.assertEqual(lp["output"]["actuator"], code)
                self.assertEqual(lp["input"]["tag"], quantities[code]["tag"])
                cmap = lp["output"].get("command_map") or {}
                sent = {cmap.get(c, c) for c in ("UP", "DOWN", "OFF")}
                self.assertLessEqual(sent, set(quantities[code]["commands"]), code)
                self.assertLessEqual(sent, set(self.L.actuators[code]["commands"]), code)

    def test_the_chamber_models_the_loop_tags(self):
        tags = {e["tag"] for _, e in contract.QUANTITIES}
        self.assertEqual(set(chamber.TRUTH_KEYS), tags)
        published = set()
        for spec in sensors.default_specs():
            published |= set(spec.tags)
        self.assertLessEqual(published, tags | {"light_intensity"})
        self.assertLessEqual(tags, published, "a loop tag no default sensor publishes")


# ── interface 3: the actuator command semantics ──────────────────────────────────────
class Actuators(unittest.TestCase):
    def setUp(self):
        self.L = loaded()

    def test_template_relay_sets(self):
        got = contract.observed(self.L)
        self.assertEqual(got["actuators"], contract.reviewed()["actuators"])
        self.assertEqual(got["light_types"], contract.reviewed()["light_types"])
        self.assertEqual(got["shared_relays"], contract.reviewed()["shared_relays"])

    def test_the_loader_reads_relay8_of_the_template(self):
        with open(os.path.join(REPO, algorithms_loader.CONTROL_TEMPLATE), encoding="utf-8") as f:
            t = json.load(f)
        relay8 = next(d for d in t["drivers"] if d["id"] == algorithms_loader.CONTROL_DRIVER)
        self.assertEqual(self.L.actuators, relay8["actuators"])
        self.assertEqual(runner.LIGHT, self.L.lr.LIGHT_ACTUATOR)
        self.assertIn(runner.LIGHT, self.L.actuators)

    def test_the_chamber_knows_exactly_the_template_relays(self):
        relays = set()
        for d in self.L.actuators.values():
            branches = list((d.get("commands") or {}).values())
            for tb in (d.get("types") or {}).values():
                branches += list(tb.values())
            for b in branches:
                relays |= set(b["set"])
        self.assertEqual(set(chamber.RELAYS), relays)
        self.assertEqual(set(chamber.ChamberParams().relay_power_w()), set(chamber.RELAYS))

    def test_the_board_applies_the_template_and_the_last_message_wins(self):
        names = sorted(n for n, d in self.L.actuators.items() if d.get("kind") == "commands")
        for a in names:
            for cmd, branch in self.L.actuators[a]["commands"].items():
                b = runner.Board(self.L.actuators, names)
                self.assertTrue(b.apply(a, cmd))
                for relay, v in branch["set"].items():
                    self.assertEqual(b.relays[relay], v, (a, cmd, relay))
        # air_flow_fan: air_temperature UP turns it off, air_humidity DOWN on; in the tick's
        # loop order (air_temperature before air_humidity) the humidity loop's message wins.
        b = runner.Board(self.L.actuators, names)
        b.apply("air_temperature", "UP")
        b.apply("air_humidity", "DOWN")
        self.assertEqual(b.relays["air_flow_fan"], 1)
        b.apply("substrate_temperature", "UP")
        self.assertEqual(b.relays["air_flow_fan"], 0)
        for ltype, branches in contract.LIGHT_TYPES.items():
            b = runner.Board(self.L.actuators, names)
            self.assertTrue(b.apply(runner.LIGHT, "ON", ltype))
            for relay, v in branches["ON"].items():
                self.assertEqual(b.relays[relay], v, (ltype, relay))

    def test_a_board_without_an_actuator_ignores_its_messages(self):
        b = runner.Board(self.L.actuators, ["air_temperature"])
        self.assertFalse(b.apply("co2", "UP"))
        self.assertEqual(b.relays["co2_fan"], 0)
        self.assertEqual(b.ignored, 1)


# ── interface 3: the controller contract ─────────────────────────────────────────────
class Controllers(unittest.TestCase):
    def setUp(self):
        self.L = loaded()
        self.names = self.L.algorithms.ALGORITHM_NAMES

    def test_accepted_codes_are_algorithm_names(self):
        self.assertEqual(self.L.codes(), sorted(self.names))
        self.assertEqual(self.L.codes(), list(contract.ALGORITHM_CODES))
        for code in self.names:
            self.L.check(code, None)
        for bad in ("BANG_BANG", "pid", "", None, "LQR"):
            with self.assertRaises(algorithms_loader.LoaderError, msg=repr(bad)):
                self.L.check(bad)

    def test_params_is_production_module(self):
        self.assertIsNotNone(self.L.params, "schd/cea/algorithms/params.py is missing")
        self.assertEqual(os.path.realpath(self.L.params.__file__),
                         os.path.join(REPO, "schd", "cea", "algorithms", "params.py"))
        self.assertEqual(self.L.params.SCHEMA_VERSION, contract.PARAMS_SCHEMA_VERSION)
        self.assertEqual(set(self.L.params.PARAMS), set(self.names))

    def test_schema_matches_the_class_signatures(self):
        base = self.L.algorithms.ControlAlgorithm
        for code, cls in self.names.items():
            self.assertTrue(issubclass(cls, base), code)
            for m in ("compute", "reset", "get_state", "load_state"):
                self.assertTrue(callable(getattr(cls, m, None)), (code, m))
            sig = inspect.signature(cls.__init__)
            got = {n: p.default for n, p in sig.parameters.items()
                   if n not in ("self", "lower_limit", "upper_limit")
                   and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)}
            spec = self.L.params.PARAMS[code]
            self.assertEqual(got, {n: s["default"] for n, s in spec.items()}, code)
            for n, s in spec.items():
                self.assertEqual(type(s["default"]).__name__, s["type"], (code, n))

    def test_the_harness_validates_through_the_schema(self):
        for code in self.names:
            d = self.L.params.defaults(code)
            a = self.L.make(code, 18.0, 22.0, d)
            with contextlib.redirect_stderr(io.StringIO()):     # FLC/MPC fallback lines without the venv
                self.assertIn(a.compute(20.0), ("UP", "DOWN", "OFF"), code)
            with self.assertRaisesRegex(algorithms_loader.LoaderError, "unknown parameter"):
                self.L.make(code, 18.0, 22.0, {"no_such_parameter": 1})
            for n, s in self.L.params.PARAMS[code].items():
                with self.assertRaises(algorithms_loader.LoaderError, msg=(code, n)):
                    self.L.make(code, 18.0, 22.0, {n: s["max"] + 1})

    def test_a_campaign_refuses_an_unknown_code_before_running(self):
        with open(os.path.join(SCEN_DIR, "smoke_air_temperature.yaml"), encoding="utf-8") as f:
            sc = yaml.safe_load(f)
        out = tempfile.mkdtemp(prefix="rs-contract-")
        self.addCleanup(shutil.rmtree, out)
        for c in ({"code": "BANG_BANG"}, {"code": "PID", "params": {"kp": -1}}):
            spec = campaign.resolve_spec({"scenarios": [sc], "controllers": [c], "seeds": [1]})
            with self.assertRaises(algorithms_loader.LoaderError):
                campaign.run_campaign(spec, os.path.join(out, "x"), allow_dirty=True)
            self.assertFalse(os.path.exists(os.path.join(out, "x")))


# ── interface 3: the loop rules are called, not copied ───────────────────────────────
LR_FUNCTIONS = ("resolve", "decide", "limits", "in_phase", "build_default_map", "update_readings",
                "loop_problems", "validate_loops", "default_loop", "loop_from_row", "state_key",
                "parse_reading_topic", "reading_value", "complete_half", "declared_actuators",
                "max_age", "loopable")
RUNNER_CALLS = ("build_default_map", "limits", "resolve", "decide", "in_phase", "update_readings",
                "validate_loops", "loop_from_row", "state_key")


class LoopRules(unittest.TestCase):
    def test_no_redefinition_under_research(self):
        lr_src = parse(os.path.join(REPO, "schd/cea/loop_resolver.py"))
        lr_defs = {n.name for n in lr_src.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")}
        self.assertLessEqual(set(LR_FUNCTIONS), lr_defs)
        for path in research_py():
            for node in ast.walk(parse(path)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertNotIn(node.name, lr_defs, "%s:%d re-defines loop_resolver.%s"
                                     % (rel(path), node.lineno, node.name))
                if isinstance(node, ast.Assign) and not path.endswith(os.path.join("research", "contract.py")):
                    for t in node.targets:
                        self.assertFalse(isinstance(t, ast.Name) and t.id == "QUANTITIES",
                                         "%s:%d keeps a copy of QUANTITIES" % (rel(path), node.lineno))

    def test_the_runner_calls_the_loaded_module(self):
        called = set()
        for node in ast.walk(parse(os.path.join(RESEARCH, "harness", "runner.py"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "lr"):
                called.add(node.func.attr)
        missing = sorted(set(RUNNER_CALLS) - called)
        self.assertEqual(missing, [], "runner.py no longer calls lr.%s" % ", lr.".join(missing))

    # The loader names the contract in the manifest (its version) and pins its sources'
    # blob SHAs; nothing else of contract.py reaches the harness.
    CONTRACT_READERS = {os.path.join("research", "harness", "algorithms_loader.py"):
                        {"CONTRACT_VERSION", "SOURCES"}}

    def test_contract_py_drives_no_simulation(self):
        """The reviewed form is only compared; the harness code never reads it. The loader
        may read contract.CONTRACT_VERSION and contract.SOURCES (manifest, blob SHAs)."""
        for path in research_py():
            if path.endswith(os.path.join("research", "contract.py")):
                continue
            allowed = self.CONTRACT_READERS.get(rel(path))
            tree = parse(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""] + [a.name for a in node.names]
                else:
                    continue
                if allowed is not None and isinstance(node, ast.ImportFrom) and node.level == 2 \
                        and node.module is None and [a.name for a in node.names] == ["contract"] \
                        and node.names[0].asname is None:
                    continue
                self.assertFalse(any(m.split(".")[-1] == "contract" for m in mods),
                                 "%s:%d imports research.contract" % (rel(path), node.lineno))
            if allowed is not None:
                used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                        and isinstance(n.value, ast.Name) and n.value.id == "contract"}
                self.assertLessEqual(used, allowed, "%s reads contract.%s" % (rel(path), sorted(used - allowed)))
                bare = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "contract"
                        and not any(isinstance(p, ast.Attribute) and p.value is n for p in ast.walk(tree))]
                self.assertEqual(bare, [], "%s uses contract other than by attribute" % rel(path))


# ── interface 3: the setpoint rules of a recipe line ─────────────────────────────────
MIGRATIONS = os.path.join(REPO, "apps", "database", "medcea_db_migrations.sql")


def setpoint_guard_raises():
    """The RAISE format strings of recipe_line_setpoints_guard()'s per-setpoint loop (the
    last definition in the migration file), '' unescaped."""
    with open(MIGRATIONS, encoding="utf-8") as f:
        sql = f.read()
    start = sql.rindex("CREATE OR REPLACE FUNCTION medcea.recipe_line_setpoints_guard()")
    body = sql[start:sql.index("END $$;", start)]
    loop = body[body.index("FOR k, v IN SELECT key, value FROM jsonb_each(NEW.setpoints) LOOP"):]
    loop = loop[:loop.index("END LOOP;")]
    return body, [m.replace("''", "'") for m in re.findall(r"RAISE EXCEPTION '((?:[^']|'')*)'", loop)]


def as_regex(fmt):
    return re.compile("^" + ".+?".join(re.escape(p) for p in fmt.split("%")) + "$", re.S)


class Setpoints(unittest.TestCase):
    """The runner's checks of a scenario's recipe_line.setpoints are the trigger's: the same
    four rules in the same order, with its RAISE texts (as tests/test_loops.py does for
    _loop_check)."""

    @classmethod
    def setUpClass(cls):
        cls.body, cls.raises = setpoint_guard_raises()
        with open(os.path.join(RESEARCH, "harness", "runner.py"), encoding="utf-8") as f:
            cls.runner_src = f.read()

    def test_the_trigger_has_the_four_rules(self):
        self.assertEqual(len(self.raises), 4, self.raises)
        for fragment in ("IF NOT qs ? k THEN",
                         "jsonb_typeof(v) IS DISTINCT FROM 'object' OR jsonb_typeof(v -> 'lower') IS DISTINCT FROM 'number'",
                         "OR jsonb_typeof(v -> 'upper') IS DISTINCT FROM 'number'",
                         "WHERE y NOT IN ('lower', 'upper')",
                         "IF lo > hi THEN",
                         "IF lo < (qs -> k ->> 'min')::numeric OR hi > (qs -> k ->> 'max')::numeric THEN"):
            self.assertIn(fragment, self.body)
        self.assertIn("apps/database/medcea_db_migrations.sql", contract.SOURCES)

    def test_the_runner_raises_the_same_texts_in_the_same_order(self):
        positions = []
        for fmt in self.raises:
            py = fmt.replace("%", "%s")
            self.assertIn(py, self.runner_src, "runner.py lacks the trigger's text %r" % fmt)
            positions.append(self.runner_src.index(py))
        self.assertEqual(positions, sorted(positions), "runner.py checks in another order than the trigger")

    def refusal(self, setpoints):
        with open(os.path.join(SCEN_DIR, "smoke_air_temperature.yaml"), encoding="utf-8") as f:
            sc = yaml.safe_load(f)
        sc["recipe_line"]["setpoints"] = setpoints
        try:
            runner.normalise(sc, loaded())
        except runner.ScenarioError as e:
            return str(e)
        return None

    def test_each_refusal_matches_its_raise(self):
        not_quantity, shape, order, bounds = (as_regex(f) for f in self.raises)
        cases = [({"leaf_wetness": {"lower": 1, "upper": 2}}, not_quantity),
                 ({"air_temperature": {"lower": 18}}, shape),
                 ({"air_temperature": {"lower": 18, "upper": 22, "mid": 20}}, shape),
                 ({"air_temperature": {"lower": "18", "upper": 22}}, shape),
                 ({"air_temperature": {"lower": True, "upper": 22}}, shape),
                 ({"air_temperature": [18, 22]}, shape),
                 ({"air_temperature": {"lower": 23, "upper": 22}}, order),
                 ({"air_temperature": {"lower": -100, "upper": 22}}, bounds),
                 ({"co2": {"lower": 500, "upper": 10 ** 9}}, bounds)]
        for sp, rx in cases:
            msg = self.refusal(sp)
            self.assertIsNotNone(msg, sp)
            self.assertRegex(msg, rx, sp)

    def test_what_the_trigger_accepts_the_runner_accepts(self):
        q = loaded().quantities("FUNGI")["air_temperature"]
        for sp in ({"air_temperature": {"lower": 20, "upper": 20}},                  # lower = upper
                   {"air_temperature": {"lower": q["min"], "upper": q["max"]}},       # inclusive bounds
                   {"air_temperature": {"lower": 18.5, "upper": 21.25}}):
            self.assertIsNone(self.refusal(sp), sp)


# ── isolation: no operational import, no database, no cluster ─────────────────────────
THIRD_PARTY_OK = {"yaml", "numpy", "scipy", "skfuzzy", "gekko", "research"}
FORBIDDEN_WORDS = re.compile(r"\b(psql|kubectl|microk8s|helm3?|mosquitto_pub|mosquitto_sub)\b")
SQL = re.compile(r"\b(INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+[a-z_.]+\s+SET|CREATE\s+(TABLE|VIEW|FUNCTION|ROLE)"
                 r"|ALTER\s+(TABLE|ROLE)|DROP\s+(TABLE|VIEW|SCHEMA|DATABASE)|TRUNCATE\s|GRANT\s|SELECT\s.+\sFROM\s)")
URL = re.compile(r"\b(postgres(ql)?|mqtts?)://")


# Forms that would let a call escape the two checks below, which match call names as
# written (import_module, subprocess.run, os.system ...): an alias rebinds the name.
ALIAS_WATCHED = {"os", "subprocess", "importlib", "importlib.util", "builtins", "sys", "runpy"}
OS_EXEC = re.compile(r"^(system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*)$")
DANGEROUS_NAMES = {"import_module", "__import__", "spec_from_file_location", "module_from_spec",
                   "exec_module", "run", "Popen", "call", "check_call", "check_output", "system",
                   "popen", "run_path", "run_module"}


def _rebinds_primitive(v):
    """True for a bare watched module (subprocess, importlib, os, ...) or one of its process
    or import primitives taken as a value (not called)."""
    if isinstance(v, ast.Name):
        return v.id in ALIAS_WATCHED
    if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name):
        mod, attr = v.value.id, v.attr
        return ((mod == "subprocess") or (mod == "os" and bool(OS_EXEC.match(attr)))
                or (mod in ("importlib", "builtins", "runpy") and attr in DANGEROUS_NAMES | {"run_path", "run_module"}))
    return False


def alias_problems(tree):
    """[(lineno, why)] for every import or name form that rebinds a process or import
    primitive under another name, so a literal-name check would not see its calls."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in ("runpy", "ctypes"):
                    out.append((node.lineno, "import %s" % a.name))
                elif a.asname and (a.name in ALIAS_WATCHED or a.name.split(".")[0] in ALIAS_WATCHED):
                    out.append((node.lineno, "import %s as %s" % (a.name, a.asname)))
        elif isinstance(node, ast.ImportFrom) and not node.level:
            mod, names = node.module or "", [a.name for a in node.names]
            if mod in ("subprocess", "builtins", "runpy", "ctypes", "importlib.util", "importlib.machinery"):
                out.append((node.lineno, "from %s import %s" % (mod, ", ".join(names))))
            elif mod == "importlib" and set(names) - {"metadata"}:
                out.append((node.lineno, "from importlib import %s" % ", ".join(names)))
            elif mod == "os" and any(OS_EXEC.match(n) or n == "*" for n in names):
                out.append((node.lineno, "from os import %s" % ", ".join(names)))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            # name = subprocess | subprocess.<anything> | os.system | importlib.import_module:
            # a rebinding the literal call checks would not see (a call's result is fine)
            vals = node.value.elts if isinstance(node.value, (ast.Tuple, ast.List)) else [node.value]
            for v in vals:
                if _rebinds_primitive(v):
                    out.append((node.lineno, "%s rebinds %s" % (type(node).__name__, ast.unparse(v))))
                    break
        elif (isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("vars", "globals", "locals")):
            out.append((node.lineno, "%s()" % node.func.id))
        elif isinstance(node, ast.Name) and node.id == "__import__":
            out.append((node.lineno, "__import__"))
        elif (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "getattr"
              and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
              and node.args[1].value in DANGEROUS_NAMES):
            out.append((node.lineno, "getattr(..., %r)" % node.args[1].value))
    return out


class Isolation(unittest.TestCase):
    def test_alias_check_catches_each_form(self):
        bad = ["run = subprocess.run\nrun(['sh'])", "sp = subprocess\nsp.run(['sh'])",
               "im = importlib.import_module\nim('cea')", "f: object = os.system",
               "vars(subprocess)['run'](['sh'])", "(r := subprocess.Popen)",
               "from importlib import import_module", "import importlib as il",
               "from subprocess import run", "from subprocess import Popen as P",
               "import subprocess as sp", "from os import system", "from os import popen",
               "from os import execvp", "from os import *", "import os as o",
               "from importlib.util import spec_from_file_location", "import runpy",
               "x = __import__('cea')", "f = getattr(subprocess, 'run')", "from builtins import __import__"]
        for src in bad:
            self.assertTrue(alias_problems(ast.parse(src)), src)
        good = ["import os", "import subprocess", "import importlib", "import importlib.metadata",
                "from importlib import metadata", "from os import path", "from os.path import join",
                "from . import contract", "import yaml as y", "getattr(a, '_ctrl', None)",
                "p = os.path.join('a', 'b')", "r = subprocess.run(['git', 'status'])",
                "n = os.cpu_count()", "v = sys.version_info"]
        for src in good:
            self.assertEqual(alias_problems(ast.parse(src)), [], src)

    def test_no_aliased_process_or_import_primitive(self):
        for path in research_py():
            for line, why in alias_problems(parse(path)):
                self.fail("%s:%d %s (an alias escapes the call checks)" % (rel(path), line, why))

    def test_imports_are_stdlib_pyyaml_numeric_or_research(self):
        stdlib = set(sys.stdlib_module_names)
        for path in research_py():
            for node in ast.walk(parse(path)):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    mods = [node.module]
                for m in mods:
                    top = m.split(".")[0]
                    self.assertTrue(top in stdlib or top in THIRD_PARTY_OK,
                                    "%s:%d imports %s" % (rel(path), node.lineno, m))

    def test_dynamic_imports_reach_only_the_contract_code(self):
        allowed = (".algorithms", ".loop_resolver", ".algorithms.params")
        for path in research_py():
            for node in ast.walk(parse(path)):
                if not isinstance(node, ast.Call):
                    continue
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in ("import_module", "__import__", "spec_from_file_location", "exec_module"):
                    self.assertEqual(name, "import_module", "%s:%d %s" % (rel(path), node.lineno, name))
                    arg = node.args[0]
                    ok = (isinstance(arg, ast.BinOp) and isinstance(arg.right, ast.Constant)
                          and arg.right.value in allowed)
                    self.assertTrue(ok, "%s:%d imports %s" % (rel(path), node.lineno, ast.unparse(arg)))
                if (isinstance(f, ast.Attribute) and f.attr in ("insert", "append", "extend")
                        and ast.unparse(f.value) == "sys.path"):
                    self.fail("%s:%d changes sys.path" % (rel(path), node.lineno))

    def test_subprocesses_are_read_only_git(self):
        for path in research_py():
            for node in ast.walk(parse(path)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and ((ast.unparse(node.func.value) == "subprocess")
                             or (ast.unparse(node.func.value) == "os" and OS_EXEC.match(node.func.attr)))):
                    arg = node.args[0] if node.args else None
                    self.assertTrue(isinstance(arg, ast.List) and arg.elts
                                    and isinstance(arg.elts[0], ast.Constant) and arg.elts[0].value == "git",
                                    "%s:%d runs %s" % (rel(path), node.lineno, ast.unparse(node)))

    def test_no_sql_database_or_cluster_in_code(self):
        for path in research_py():
            for node in ast.walk(parse(path)):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    s = node.value
                    self.assertIsNone(SQL.search(s), "%s:%d SQL text %r" % (rel(path), node.lineno, s[:80]))
                    self.assertIsNone(URL.search(s), "%s:%d %r" % (rel(path), node.lineno, s[:80]))
        for root, dirs, files in os.walk(RESEARCH):
            dirs[:] = [d for d in dirs if d not in (".venv", "__pycache__", "runs")]
            for f in files:
                p = os.path.join(root, f)
                self.assertFalse(f.endswith(".sql"), "%s: no SQL in research/ in Phase 1" % rel(p))
                if f.endswith(".sh"):
                    with open(p, encoding="utf-8") as fh:
                        for i, line in enumerate(fh, 1):
                            code = line.split("#", 1)[0]
                            self.assertIsNone(FORBIDDEN_WORDS.search(code), "%s:%d %s" % (rel(p), i, line.strip()))

    def test_a_run_loads_only_research_and_the_contract_code(self):
        """In a clean interpreter that refuses psycopg2, paho, cea and the operational
        packages, a short scenario runs and every repository module it loaded is under
        research/ or is the contract's code (schd/cea/algorithms, loop_resolver)."""
        script = r'''
import importlib.abc, json, os, sys
REPO = sys.argv[1]
BLOCK = ("psycopg2", "psycopg", "paho", "cea", "requests", "sqlalchemy", "asyncpg", "pg8000")
class Refuse(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCK:
            raise ImportError("refused by the contract test: " + name)
        return None
sys.meta_path.insert(0, Refuse())
sys.path.insert(0, REPO)
import yaml
from research.harness import runner
with open(os.path.join(REPO, "research/harness/scenarios/smoke_air_temperature.yaml")) as f:
    sc = yaml.safe_load(f)
sc["duration_h"] = 0.05; sc["metrics_from_h"] = 0
r = runner.run_scenario(sc, {"code": "IF_THEN_ELSE", "params": {}}, 1, allow_dirty=True)
files = sorted({os.path.relpath(os.path.realpath(m.__file__), REPO) for m in list(sys.modules.values())
                if getattr(m, "__file__", None) and os.path.realpath(m.__file__).startswith(REPO + os.sep)})
print(json.dumps({"files": files, "modules": sorted(sys.modules), "valid": r["valid"]}))
'''
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        p = subprocess.run([sys.executable, "-I", "-c", script, REPO], capture_output=True, text=True,
                           timeout=300, env=env, cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(out["valid"])
        for f in out["files"]:
            self.assertTrue(f.startswith("research" + os.sep) or f.startswith("schd/cea/algorithms/")
                            or f == "schd/cea/loop_resolver.py", f)
        for m in out["modules"]:
            self.assertNotIn(m.split(".")[0], ("psycopg2", "paho", "cea"), m)

    def test_the_manifest_names_every_contract_source(self):
        L = loaded()
        self.assertEqual(set(contract.SOURCES) - set(L.blobs), set())
        for path in contract.SOURCES:
            self.assertTrue(os.path.isfile(os.path.join(REPO, path)), path)


# ── research/README.md ────────────────────────────────────────────────────────────────
class Readme(unittest.TestCase):
    def test_states_the_four_interfaces(self):
        with open(os.path.join(RESEARCH, "README.md"), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"^## Coupling contract\n(.*?)(?=^## |\Z)", text, re.M | re.S)
        self.assertIsNotNone(m, "README.md has no '## Coupling contract' section")
        sec = m.group(1)
        items = dict(re.findall(r"^(\d)\. (\w+)", sec, re.M))
        self.assertEqual([items.get(str(i), "").lower() for i in range(1, 5)],
                         [name for name, _ in contract.INTERFACES])
        for word in ("Keycloak", "route table", "medcea.research_*()", "snapshot", "contract version", "recipe_types.yaml",
                     "ALGORITHM_NAMES", "loop_resolver", "esp32-control.json", "gateway", "draft",
                     "Nothing else is shared"):
            self.assertIn(word, sec)


if __name__ == "__main__":
    unittest.main()
