#!/usr/bin/env python3
"""The control-loop picker's page side: the block between /* loops-logic:begin */ and
/* loops-logic:end */ in edge/src/host/ui/loops.js mirrors edge/src/host/loops.py.
Every fixture in tests/fixtures/loops/ is run through both with the spec loops.py builds,
and must give the same findings, message for message; rowFor/stateOf and the table are
compared too. The node tests skip when node is missing. Also the wizard page's wiring of
the prompt kind `loops`, and the catalogue's fixed arguments (the Control loops tile).

    python3 -m unittest tests.test_loops_ui
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.path.join(ROOT, "edge", "src", "host")
UI_JS = os.path.join(HOST, "ui", "loops.js")
SERVER = os.path.join(HOST, "wizard_server.py")
NODE = shutil.which("node")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_loops as TL     # noqa: E402  (same directory; loads loops.py by path)

HARNESS = r"""
const L = module.exports;
let raw = ""; process.stdin.on("data", c => raw += c).on("end", () => {
  const out = JSON.parse(raw).map(c => {
    if (c.op === "validate") return L.validate(c.spec, c.answer);
    if (c.op === "rowFor") return L.rowFor(c.spec, c.code, c.state);
    if (c.op === "stateOf") return L.stateOf(c.row);
    if (c.op === "table") return L.QUANTITIES;
    throw new Error("unknown op " + c.op);
  });
  process.stdout.write(JSON.stringify(out));
});
"""


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logic_block():
    m = re.search(r"/\* loops-logic:begin \*/(.*?)/\* loops-logic:end \*/", read(UI_JS), re.S)
    if not m:
        raise AssertionError("loops.js has no loops-logic block")
    return m.group(1)


@unittest.skipUnless(NODE, "node is not installed")
class LogicParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.js = os.path.join(cls.tmp, "logic.js")
        with open(cls.js, "w", encoding="utf-8") as f:
            f.write("var module = {exports: {}};\n" + logic_block() + "\n" + HARNESS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_js(self, cases):
        r = subprocess.run([NODE, self.js], input=json.dumps(cases), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        return json.loads(r.stdout)

    def test_the_block_needs_no_dom(self):
        self.assertEqual(re.findall(r"\bdocument\.|\bwindow\.|innerHTML", logic_block()), [])

    def test_every_fixture_word_for_word(self):
        files = TL.fixtures()
        ctx = TL.contexts()
        cases, names = [], []
        for path in files:
            spec, answer, expect = TL.fixture_case(path, ctx)
            cases.append({"op": "validate", "spec": spec, "answer": answer})
            names.append((os.path.basename(path), spec, answer, expect))
        for (name, spec, answer, expect), got in zip(names, self.run_js(cases)):
            with self.subTest(fixture=name):
                self.assertEqual(TL.triples(got), sorted(tuple(e) for e in expect))
                self.assertEqual(got, TL.lp.validate(spec, answer))

    def test_table(self):
        self.assertEqual(self.run_js([{"op": "table"}])[0], TL.lp.QUANTITIES)

    def test_row_for_and_state_of(self):
        ctx = TL.contexts()
        spec = TL.lp.build_spec("ZONE", ctx["bench"])
        states = [
            {"rule": "reference", "reference": "sht45_1", "fallback": "scd30_1", "max_age_s": 60, "actuator": "air_humidity"},
            {"rule": "reference", "reference": None, "fallback": None, "max_age_s": 90, "actuator": "air_humidity"},
            {"rule": "reference", "reference": "sht45_1", "fallback": "sht45_1", "max_age_s": 90, "actuator": None},
            {"rule": "mean", "sensors": ["sht45_1", "scd30_1"], "max_age_s": 90, "actuator": "air_humidity"},
            {"rule": "min", "sensors": [], "actuator": "air_humidity"},
        ]
        cases = [{"op": "rowFor", "spec": spec, "code": c, "state": st}
                 for c in ("air_humidity", "co2") for st in states]
        rows = [r["loop"] for r in spec["rows"] if r["loop"]] + [
            {k: l[k] for k in TL.lp.LOOP_KEYS} for l in ctx["existing"]["loops"]]
        cases += [{"op": "stateOf", "row": r} for r in rows]
        got = self.run_js(cases)
        want = [TL.lp.row_for(spec, c["code"], c["state"]) for c in cases if c["op"] == "rowFor"] + \
               [TL.lp.state_of(r) for r in rows]
        self.assertEqual(got, want)


class Page(unittest.TestCase):
    """wizard_server.py's page inlines the picker and wires the prompt kind."""

    def test_the_page(self):
        src = read(SERVER)
        for needle in ('<script>__LOOPS_JS__</script>', '__LOOPS_CSS__', '<div id="ploops" hidden></div>',
                       'p.kind === "loops"', 'ui_asset("loops.js")', 'ui_asset("loops.css")',
                       'Loops.mount(', 'loopCtl.skip()', 'JSON.stringify(loopCtl.value())'):
            self.assertIn(needle, src)
        # the poll calls renderPrompt every tick: the id guard must stay first
        render = src[src.index("function renderPrompt(p)"):]
        self.assertLess(render.index("if (p.id === curId) return;"), render.index('p.kind === "loops"'))
        # Back and send reset the picker like the other editors
        self.assertIn("mapCtl = null; wireCtl = null; loopCtl = null;", src[src.index("function goBack()"):])
        self.assertIn("a picker that cannot send a broken answer", src)
        # without loops.js the question can still be answered: Decide later
        self.assertIn("The loop picker did not load", src)

    def test_the_js_mounts_with_no_innerhtml_of_data(self):
        js = read(UI_JS)
        screen = js[js.index("/* loops-logic:end */"):]
        # innerHTML is only ever cleared, never fed a string
        self.assertEqual({v.strip() for v in re.findall(r'innerHTML\s*=\s*([^;]+);', screen)}, {'""'})
        self.assertIn("module.exports = logic", logic_block())


class CatalogueArgs(unittest.TestCase):
    """The Control loops tile runs flash-device.sh --loops-only; the catalogue passes only
    plain long options, never a request's."""

    def load_server(self):
        sys.path.insert(0, HOST)
        import importlib.util
        spec = importlib.util.spec_from_file_location("wizard_server_t", SERVER)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_shipped_catalogue(self):
        m = self.load_server()
        cat = m.load_catalog(os.path.join(ROOT, "edge", "catalog.json"), ROOT)
        tile = [e for e in cat if e["id"] == "control-loops"]
        self.assertEqual(len(tile), 1)
        self.assertEqual(tile[0]["_args"], ["--loops-only"])
        self.assertTrue(os.path.realpath(tile[0]["_script"]).endswith("edge/flash-device.sh"))
        m.STATE["catalog"] = cat
        self.assertNotIn("_args", json.dumps(m.catalog_public()))      # never shown to the page

    def test_bad_args_make_the_tile_unavailable(self):
        m = self.load_server()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "catalog.json")
            with open(p, "w") as f:
                json.dump({"devices": [
                    {"id": "a", "name": "A", "status": "available", "script": "edge/flash-device.sh",
                     "args": ["--loops-only", "--psk=x"]},
                    {"id": "b", "name": "B", "status": "available", "script": "edge/flash-device.sh",
                     "args": "--loops-only"},
                    {"id": "c", "name": "C", "status": "available", "script": "edge/flash-device.sh"}]}, f)
            cat = {e["id"]: e for e in m.load_catalog(p, ROOT)}
        self.assertEqual(cat["a"]["status"], "unavailable")
        self.assertEqual(cat["b"]["status"], "unavailable")
        self.assertEqual((cat["c"]["status"], cat["c"]["_args"]), ("available", []))
        src = read(SERVER)
        self.assertIn('cmd = [entry["_script"]] + entry.get("_args", []) + ["--ui-spool", d]', src)


if __name__ == "__main__":
    unittest.main()
