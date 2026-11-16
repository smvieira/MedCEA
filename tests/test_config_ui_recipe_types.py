"""The Configuration UI's recipe types and setpoints (migration 011), offline.

- The recipe-types-logic block (pure functions between /* recipe-types-logic:begin */ and
  /* recipe-types-logic:end */ in apps/frontend/html/index.html) runs under node (skipped
  without node) against the real catalogue (apps/database/recipe_types.py json, the bytes
  the deploy serves at /recipe-types.json):
  - rtTypes/rtTypeCode/rtTypeLabel: PLANT and FUNGI, the old unit labels (Greens,
    Mushrooms) mapped, anything else null;
  - rtQuantities: a type's quantities in the catalogue's order, required flags;
  - setpointsFromInputs: an optional quantity left empty is left out, a half-filled or
    reversed or out-of-range one is an error, a required one must be there;
  - setpointsFromV1 / normaliseRecipeImport: a v1 file's limit columns become setpoints
    (substrate only when both are set), a v2 file keeps its own, both are checked against
    the type; recipeExport writes format 2 and never a limit column;
  - setpointsText, typesMatch.
- Static: the page writes setpoints and never a *_limit column; the line modal has no
  limit inputs; the type selects; the deploy serves recipe-types.json beside the page.

Run: python3 tests/test_config_ui_recipe_types.py
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "apps", "frontend", "html", "index.html")
NODE = shutil.which("node")
LIMITS = ("air_temperature_lower_limit", "air_temperature_upper_limit", "co2_lower_limit", "co2_upper_limit",
          "hr_lower_limit", "hr_upper_limit", "substrate_temperature_lower_limit", "substrate_temperature_upper_limit")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block():
    m = re.search(r"/\* recipe-types-logic:begin \*/(.*?)/\* recipe-types-logic:end \*/", read(INDEX), re.S)
    assert m, "recipe-types-logic block missing"
    return m.group(1)


def catalogue():
    return subprocess.run(["python3", os.path.join(ROOT, "apps", "database", "recipe_types.py"), "json"],
                          capture_output=True, text=True, check=True).stdout.strip()


def run_node(expr):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(block() + "\nconst DOC = " + catalogue() + ";\nconsole.log(JSON.stringify(" + expr + "));\n")
        path = f.name
    try:
        out = subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


V1_STEP = {"recipe_item_seq_id": 1, "recipe_item_seq_name": "Spawn run", "cycle_number": 3, "light_type": "DARK",
           "light_on_minutes": 0, "light_off_minutes": 1440,
           "air_temperature_lower_limit": 20, "air_temperature_upper_limit": 24, "co2_lower_limit": 400,
           "co2_upper_limit": 5000, "hr_lower_limit": 85, "hr_upper_limit": 95,
           "substrate_temperature_lower_limit": 22, "substrate_temperature_upper_limit": None, "notes": "n"}
SP = {"air_temperature": {"lower": 20, "upper": 24}, "air_humidity": {"lower": 85, "upper": 95},
      "co2": {"lower": 400, "upper": 5000}}


@unittest.skipUnless(NODE, "node not installed")
class RecipeTypesLogic(unittest.TestCase):
    def test_types(self):
        self.assertEqual(run_node("rtTypes(DOC).map(t => [t.code, t.label, t.legacy])"),
                         [["PLANT", "Plants", "Greens"], ["FUNGI", "Fungi", "Mushrooms"]])
        self.assertEqual(run_node("['PLANT', 'Greens', 'Mushrooms', 'Other', '', null, 'plant'].map(v => rtTypeCode(DOC, v))"),
                         ["PLANT", "PLANT", "FUNGI", None, None, None, None])
        self.assertEqual(run_node("[rtTypeLabel(DOC, 'FUNGI'), rtTypeLabel(DOC, 'X'), rtTypeLabel(DOC, null), rtTypes(null)]"),
                         ["Fungi", "X", "—", []])

    def test_quantities(self):
        q = run_node("rtQuantities(DOC, 'FUNGI')")
        self.assertEqual([x["code"] for x in q],
                         ["air_temperature", "air_humidity", "co2", "substrate_temperature", "light_intensity"])
        self.assertEqual([x["code"] for x in q if x["required"]], ["air_temperature", "air_humidity", "co2"])
        self.assertEqual(q[1]["max"], 100)
        self.assertEqual(run_node("[rtQuantities(DOC, 'NONE'), rtQuantities(null, 'PLANT')]"), [[], []])

    def test_inputs(self):
        ok = {"air_temperature": {"lower": "20", "upper": "24"}, "air_humidity": {"lower": "85", "upper": "95"},
              "co2": {"lower": "400", "upper": "5000"}, "substrate_temperature": {"lower": "", "upper": ""},
              "light_intensity": {"lower": " ", "upper": ""}}
        r = run_node("setpointsFromInputs(%s, rtQuantities(DOC, 'PLANT'))" % json.dumps(ok))
        self.assertEqual(r, {"setpoints": SP, "errors": []})
        bad = dict(ok, co2={"lower": "", "upper": "500"}, air_humidity={"lower": "95", "upper": "85"},
                   air_temperature={"lower": "", "upper": ""}, substrate_temperature={"lower": "-20", "upper": "5"})
        r = run_node("setpointsFromInputs(%s, rtQuantities(DOC, 'PLANT'))" % json.dumps(bad))
        self.assertEqual(r["setpoints"], {})
        self.assertEqual(r["errors"], ["Air temperature is required",
                                       "Air humidity: the lower value is above the upper one",
                                       "CO₂: needs a lower and an upper value",
                                       "Substrate temperature: must be within -10 and 60 °C"])

    def test_v1_import(self):
        self.assertEqual(run_node("setpointsFromV1(%s)" % json.dumps(V1_STEP)), SP)
        n = run_node("normaliseRecipeImport(%s, DOC, 'Mushrooms')" % json.dumps(
            {"recipe_name": "Oyster", "steps": [dict(V1_STEP, recipe_item_seq_id=2), V1_STEP]}))
        self.assertEqual(n["errors"], [])
        self.assertEqual(n["recipe_type"], "FUNGI")
        self.assertEqual([s["recipe_item_seq_id"] for s in n["steps"]], [1, 2])
        self.assertEqual(n["steps"][0], {"recipe_item_seq_id": 1, "recipe_item_seq_name": "Spawn run", "cycle_number": 3,
                                         "light_type": "DARK", "light_on_minutes": 0, "light_off_minutes": 1440,
                                         "setpoints": SP, "notes": "n"})
        for s in n["steps"]:
            self.assertFalse(set(s) & set(LIMITS))
        # no type chosen, a step lacking a field or a required quantity
        n = run_node("normaliseRecipeImport(%s, DOC, null)" % json.dumps(
            {"recipe_name": "X", "steps": [dict(V1_STEP, cycle_number=None, co2_lower_limit=None)]}))
        self.assertEqual(n["errors"], ["choose a recipe type", "Step 1: missing field cycle_number"])
        n = run_node("normaliseRecipeImport(%s, DOC, 'PLANT')" % json.dumps(
            {"recipe_name": "X", "steps": [dict(V1_STEP, co2_lower_limit=None)]}))
        self.assertEqual(n["errors"], ["Step 1: CO₂ is required"])

    def test_v2_import_and_export(self):
        step = {k: V1_STEP[k] for k in ("recipe_item_seq_id", "recipe_item_seq_name", "cycle_number", "light_type",
                                       "light_on_minutes", "light_off_minutes")}
        v2 = {"format": 2, "recipe_name": "B", "recipe_type": "PLANT",
              "steps": [dict(step, setpoints=dict(SP, ammonia={"lower": 1, "upper": 2}))]}
        n = run_node("normaliseRecipeImport(%s, DOC, null)" % json.dumps(v2))
        self.assertEqual(n["errors"], ["Step 1: ammonia is not a quantity of this recipe type"])
        n = run_node("normaliseRecipeImport(%s, DOC, null)" % json.dumps(dict(v2, recipe_type="ROCKS")))
        self.assertIn("recipe_type ROCKS is not a recipe type", n["errors"])
        # a database line (setpoints and the read-only limit columns) exports as format 2
        line = dict(V1_STEP, setpoints=SP, recipe_id=7, timestamp_cre="t", created_by_name="x")
        e = run_node("recipeExport({recipe_name: 'O', recipe_type: 'FUNGI'}, [%s])" % json.dumps(line))
        self.assertEqual(e, {"format": 2, "recipe_name": "O", "recipe_description": None, "recipe_type": "FUNGI",
                             "steps": [{"recipe_item_seq_id": 1, "recipe_item_seq_name": "Spawn run", "cycle_number": 3,
                                        "light_type": "DARK", "light_on_minutes": 0, "light_off_minutes": 1440,
                                        "setpoints": SP, "notes": "n"}]})
        # an export imports back unchanged
        n = run_node("normaliseRecipeImport(%s, DOC, null)" % json.dumps(e))
        self.assertEqual((n["errors"], n["steps"]), ([], e["steps"]))

    def test_text_and_match(self):
        self.assertEqual(run_node("setpointsText(%s, DOC)" % json.dumps(dict(co2=SP["co2"], zz={"lower": 1, "upper": 2},
                                                                            air_temperature=SP["air_temperature"]))),
                         "Air temperature 20–24 °C · CO₂ 400–5000 ppm · zz 1–2")
        self.assertEqual(run_node("[setpointsText({}, DOC), setpointsText(null, null)]"), ["—", "—"])
        self.assertEqual(run_node("[typesMatch({recipe_type: 'PLANT'}, {unit_type: 'PLANT'}),"
                                  " typesMatch({recipe_type: 'PLANT'}, {unit_type: 'FUNGI'}),"
                                  " typesMatch({}, {unit_type: 'FUNGI'}), typesMatch(null, null)]"),
                         [True, False, True, True])


class RecipeTypesStatic(unittest.TestCase):
    def setUp(self):
        self.page = read(INDEX)
        self.script = self.page[self.page.index("/* recipe-types-logic:end */"):]

    def test_no_limit_column_is_written(self):
        """Outside the logic block (LEGACY_LIMITS, the v1 mapping) and the labels of old
        row_change entries, the page names no limit column: the database refuses them."""
        rest = self.page.replace(block(), "")
        labels = re.search(r"const RECIPE_FIELD_LABELS = \{.*?\};", rest, re.S).group(0)
        rest = rest.replace(labels, "")
        for col in LIMITS:
            self.assertNotIn(col, rest, col)
        self.assertIn("data.setpoints = sp.setpoints;", self.page)
        self.assertIn('<div class="fg full" id="rline-setpoints"></div>', self.page)

    def test_type_selects_and_catalogue(self):
        self.assertIn('<select name="unit_type" id="unit-type-select" required>', self.page)
        self.assertIn('<select name="recipe_type" id="recipe-type-select" required>', self.page)
        self.assertNotIn('<option value="Greens">', self.page)
        self.assertIn("fetch('/recipe-types.json', { cache: 'no-cache' })", self.page)
        self.assertIn("recipe_type: src.recipe_type", self.page)            # a copy keeps the type
        self.assertIn("recipe_type: n.recipe_type", self.page)              # an import names it
        self.assertNotIn("recipe_type_id", self.page)

    def test_deploy_serves_the_catalogue(self):
        d = read(os.path.join(ROOT, "apps", "frontend", "deploy.sh"))
        self.assertIn('python3 "$REPO_ROOT/apps/database/recipe_types.py" json > "$_RT_JSON"', d)
        self.assertIn('--from-file=recipe-types.json="$_RT_JSON"', d)
        m = read(os.path.join(ROOT, "apps", "frontend", "k8s", "config-ui.yaml"))
        self.assertIn("mountPath: /usr/share/nginx/html/recipe-types.json\n          subPath: recipe-types.json", m)

    def test_library_files_are_v2(self):
        """apps/frontend/recipes/*.json are format 2, typed, without a limit column, and
        each passes the catalogue's checks (under node when installed)."""
        d = os.path.join(ROOT, "apps", "frontend", "recipes")
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        self.assertTrue(files)
        payloads = []
        for f in files:
            p = json.loads(read(os.path.join(d, f)))
            with self.subTest(f):
                self.assertEqual(p.get("format"), 2)
                self.assertIn(p.get("recipe_type"), ("PLANT", "FUNGI"))
                self.assertFalse(set(json.dumps(p).split('"')) & set(LIMITS))
                self.assertEqual(p["recipe_type"], "FUNGI" if f.startswith("Pleurotus") else "PLANT")
            payloads.append(p)
        if NODE:
            errs = run_node("%s.map(p => normaliseRecipeImport(p, DOC, null).errors)" % json.dumps(payloads))
            self.assertEqual(dict(zip(files, errs)), {f: [] for f in files})
        for u, t in (("UNIT01.json", "FUNGI"), ("UNIT02.json", "PLANT")):
            self.assertEqual(json.loads(read(os.path.join(ROOT, "apps", "frontend", "units", u)))["unit_type"], t)


if __name__ == "__main__":
    unittest.main()
