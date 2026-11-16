#!/usr/bin/env python3
"""Recipe types and metadata-driven setpoints (migration 011; owner decisions of
15 Nov 2026), offline.

- Catalogue: apps/database/recipe_types.yaml passes recipe_types.py check; the checker
  refuses what the migration would (codes, commands, a command map onto a command the
  quantity lacks, a type naming an unknown quantity, the default type); YAML 1.1's
  bare OFF is caught; `b64` is the base64 of `json`.
- Migration011: the last block, its own transaction after 010's COMMIT with the 011
  nonce lib-db-apply.sh reads back (after 010's); recipe_types_b64 passed by db_apply;
  REVOKE right after each CREATE TABLE; the data steps as medcea_owner with the actor
  migration:011, the catalogue owned by medcea_owner before them; the unit type
  pre-flight refuses with the list; the setpoints backfill is proved (round trip) in
  the same transaction; the limit columns read-only by trigger (whatever the columns
  that remain); the guards ENABLE ALWAYS; the definer functions owned by medcea_owner;
  _loop_problems keeps 010's signature; save_zone_loops' two payload forms.
- Policy: the three catalogue tables are master_data members, service_only
  [svc_scheduler], written_by functions; grants.LEGACY_ANON_EXCLUDED and the down
  file's REVOKE list name them.
Run: python3 tests/test_recipe_model.py
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "apps", "database")
sys.path.insert(0, DB)
import recipe_types  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
from compiler import grants, model  # noqa: E402

TABLES = ("control_quantity", "recipe_type", "recipe_type_quantity")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block():
    full = read(os.path.join(DB, "medcea_db_migrations.sql"))
    return full, full[full.index("-- ── Migration 011"):]


def function(sql, name):
    m = re.search(r"CREATE OR REPLACE FUNCTION %s\(.*?\$\$(.*?)\$\$;" % re.escape(name), sql, re.S)
    return m.group(1) if m else None


class Catalogue(unittest.TestCase):
    def setUp(self):
        self.doc = recipe_types.load()

    def test_the_file_is_valid(self):
        self.assertEqual(recipe_types.problems(self.doc), [])
        codes = [q["code"] for q in self.doc["quantities"]]
        self.assertEqual(codes, ["air_temperature", "air_humidity", "co2", "substrate_temperature", "light_intensity"])
        self.assertEqual({t["code"] for t in self.doc["recipe_types"]}, {"PLANT", "FUNGI"})
        self.assertEqual({t["legacy_unit_type"] for t in self.doc["recipe_types"]}, {"Greens", "Mushrooms"})
        lux = next(q for q in self.doc["quantities"] if q["code"] == "light_intensity")
        self.assertEqual((lux["phase"], lux["loopable"]), ("light_on", False))
        for t in self.doc["recipe_types"]:
            self.assertEqual({k for k, v in t["quantities"].items() if v}, {"air_temperature", "air_humidity", "co2"})

    def test_cli(self):
        for cmd in ("check", "json", "b64"):
            r = subprocess.run([sys.executable, os.path.join(DB, "recipe_types.py"), cmd],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        j = subprocess.run([sys.executable, os.path.join(DB, "recipe_types.py"), "json"],
                           capture_output=True, text=True).stdout.strip()
        b = subprocess.run([sys.executable, os.path.join(DB, "recipe_types.py"), "b64"],
                           capture_output=True, text=True).stdout.strip()
        self.assertEqual(base64.b64decode(b).decode("utf-8"), j)
        self.assertEqual(json.loads(j), self.doc)

    def refused(self, mutate, text):
        doc = json.loads(json.dumps(self.doc))
        mutate(doc)
        errs = recipe_types.problems(doc)
        self.assertTrue(any(text in e for e in errs), (text, errs))

    def test_refusals(self):
        self.refused(lambda d: d["quantities"][0].update(code="Air"), "code must match")
        self.refused(lambda d: d["quantities"][0].update(commands=["UP", "SIDEWAYS"]), "commands must be a list")
        self.refused(lambda d: d["quantities"][2].update(commands=["UP"]), "command_map maps")
        self.refused(lambda d: d["quantities"][0].update(min=10, max=10), "min below max")
        self.refused(lambda d: d["quantities"][0].update(phase="dawn"), "phase must be")
        self.refused(lambda d: d["quantities"].append(dict(d["quantities"][0])), "listed twice")
        self.refused(lambda d: d["recipe_types"][0]["quantities"].update(ph=True), "ph is not a quantity")
        self.refused(lambda d: d.update(default_type="ALGAE"), "default_type")
        self.refused(lambda d: d["recipe_types"][1].update(legacy_unit_type="Greens"), "once per file")
        self.refused(lambda d: d["quantities"][0].update(extra=1), "unknown keys extra")

    def test_bare_off_is_caught(self):
        """YAML 1.1 reads a bare OFF as false: the checker says so before a deploy."""
        text = read(recipe_types.DEFAULT).replace('["DOWN", "OFF", "UP"]', "[DOWN, OFF, UP]", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(text)
        try:
            errs = recipe_types.problems(recipe_types.load(f.name))
        finally:
            os.unlink(f.name)
        self.assertTrue(any("commands must be a list" in e for e in errs), errs)


class Migration011(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full, cls.block = block()
        cls.lib = read(os.path.join(DB, "lib-db-apply.sh"))

    def statements(self):
        return re.findall(r"(?m)^(BEGIN|COMMIT);", re.sub(r"\$(\w*)\$.*?\$\1\$", "$$", self.block, flags=re.S))

    def test_last_and_own_transaction(self):
        before = self.full[:self.full.index("-- ── Migration 011")]
        self.assertTrue(before.rstrip().endswith("COMMIT;"))
        self.assertEqual(self.statements(), ["BEGIN", "COMMIT"])
        self.assertTrue(self.block.rstrip().endswith("COMMIT;"))

    def test_nonce(self):
        self.assertIn("VALUES ('011:last_nonce', :'deploy_nonce')", self.block)
        self.assertLess(self.lib.index("key = '010:last_nonce'"), self.lib.index("key = '011:last_nonce'"))
        self.assertIn('-v recipe_types_b64="$rt_b64"', self.lib)
        self.assertIn('rt_b64="$(python3 "$dir/recipe_types.py" b64)"', self.lib)
        self.assertIn(":'recipe_types_b64'", self.block)

    def test_revoke_right_after_create(self):
        for t in TABLES:
            i = self.block.index("CREATE TABLE IF NOT EXISTS medcea.%s (" % t)
            rest = self.block[i:]
            stmt_end = rest.index(");") + 2
            self.assertTrue(rest[stmt_end:].lstrip().startswith("REVOKE ALL ON TABLE medcea.%s FROM PUBLIC, anon, authenticator;" % t), t)

    def test_owner_and_actor_before_data_steps(self):
        b = self.block
        own = b.index("ALTER TABLE %s OWNER TO medcea_owner")
        actor = b.index("SELECT medcea_auth._set_internal_actor('migration:011');")
        role = b.index("SET LOCAL ROLE medcea_owner;")
        self.assertLess(b.index("-- 2. Seed from the YAML"), own)
        self.assertLess(own, actor)
        self.assertLess(actor, role)
        self.assertLess(role, b.index("-- 3. cea_unit.unit_type"))
        self.assertIn("RESET ROLE;", b[b.index("-- 10. Ownership"):])

    def test_unit_type_preflight(self):
        b = self.block[self.block.index("-- 3. cea_unit.unit_type"):self.block.index("-- 4. recipe.recipe_type")]
        self.assertIn("units whose type is no recipe type: %; set each to Greens or Mushrooms", b)
        self.assertLess(b.index("RAISE EXCEPTION"), b.index("ALTER COLUMN unit_type TYPE varchar(20)"))
        self.assertIn("FOREIGN KEY (unit_type) REFERENCES medcea.recipe_type(recipe_type_code)", b)

    def test_recipe_type_column(self):
        b = self.block[self.block.index("-- 4. recipe.recipe_type"):self.block.index("-- 5. recipe_line.setpoints")]
        self.assertIn("ADD COLUMN recipe_type varchar(20)", b)
        self.assertIn("REFERENCES medcea.recipe_type(recipe_type_code)", b)
        self.assertIn("ALTER COLUMN recipe_type SET NOT NULL", b)
        self.assertIn("RAISE WARNING 'migration 011: no single unit type tells the recipe type of %", b)

    def test_setpoints_proof(self):
        b = self.block[self.block.index("-- 5. recipe_line.setpoints"):self.block.index("-- 6. Guards")]
        self.assertIn("ADD COLUMN setpoints jsonb NOT NULL DEFAULT '{}'::jsonb", b)
        backfill, proof, drop = (b.index("UPDATE medcea.recipe_line l SET setpoints"),
                                 b.index("-- the proof"), b.index("DROP NOT NULL"))
        self.assertLess(backfill, proof)
        self.assertLess(proof, drop)
        self.assertIn("do not read back as their limit columns", b)
        for col in ("air_temperature_lower_limit", "hr_upper_limit", "co2_lower_limit", "substrate_temperature_upper_limit"):
            self.assertGreaterEqual(b.count(col), 2, col)   # in the backfill and in the proof
        self.assertIn("IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid = 'medcea.recipe_line'::regclass", b)

    def test_guards(self):
        g = function(self.block, "medcea.recipe_line_setpoints_guard")
        self.assertIn("the limit columns are read-only since migration 011", g)
        self.assertIn("nj ? c", g)   # works whether or not the columns still exist (012)
        self.assertIn("is not a quantity of the recipe''s type", g)
        self.assertIn("lower % is above upper %", g)
        trig = self.block[self.block.index("FOR r IN SELECT * FROM (VALUES"):]
        for rel, name in (("medcea.recipe_line", "recipe_line_setpoints_trg"), ("medcea.recipe", "recipe_type_fixed_trg"),
                          ("medcea.recipe_unit_permission", "recipe_type_match_trg"),
                          ("medcea.schedule", "recipe_type_match_trg"), ("medcea.recipe_run", "recipe_type_match_trg"),
                          ("medcea.approval", "approval_recipe_complete_trg")):
            self.assertIn("('%s', '%s'" % (rel, name), trig)
        self.assertIn("ENABLE ALWAYS TRIGGER", trig)
        m = function(self.block, "medcea.recipe_type_match")
        self.assertIn("medcea_auth.policy_refuse(", m)
        self.assertIn("approve_recipe: recipe % misses required setpoints", function(self.block, "medcea.approval_recipe_complete"))

    def test_loop_functions(self):
        self.assertIn("CREATE OR REPLACE FUNCTION medcea._loop_problems(p_loop jsonb, p_zone_code text, p_sensors jsonb, p_actuators jsonb)",
                      self.block)
        save = function(self.block, "medcea.save_zone_loops")
        self.assertIn("p_loops ->> 'half' IN ('input', 'output', 'both')", save)
        self.assertIn("half := 'both'; lst := p_loops;", save)
        self.assertIn("drops := drops || r.id;", save)
        chk = function(self.block, "medcea._loop_check")
        for t in ("a setpoint only, without a feedback loop yet", "sensor %s publishes %s in %s, not %s",
                  "actuator %s acts on %s, not %s", "a SENSE onboarding sets the input only"):
            self.assertIn(t, chk)
        self.assertIn("'uoms', s.uoms", self.block)
        self.assertIn("'quantity', CASE WHEN jsonb_typeof(e.value -> 'quantity') = 'string'", self.block)

    def test_ownership(self):
        own = self.block[self.block.index("-- 10. Ownership"):]
        for f in ("medcea._recipe_quantities(text)", "medcea.recipe_line_setpoints_guard()", "medcea.recipe_type_match()",
                  "medcea._loop_check(jsonb,text,jsonb,jsonb,jsonb,text)", "medcea.save_zone_loops(integer,jsonb)"):
            self.assertIn("to_regprocedure('%s')" % f, own)

    def test_no_object_in_the_ddl(self):
        ddl = read(os.path.join(DB, "medcea_db_ddl.sql"))
        for t in TABLES:
            self.assertNotIn("medcea.%s " % t, ddl)


class Policy(unittest.TestCase):
    def test_members(self):
        with open(os.path.join(ROOT, "apps", "iam", "policy", "defaults.yaml")) as f:
            p = model.Policy(yaml.safe_load(f))
        members = {m.get("object"): m for m in p.groups["master_data"]["members"]}
        for t in TABLES:
            m = members["medcea." + t]
            self.assertEqual((m["service_only"], m["written_by"]), (["svc_scheduler"], "functions"))

    def test_legacy_anon_excluded(self):
        down = read(os.path.join(DB, "medcea_db_migrations_down_008b.sql"))
        for t in TABLES:
            self.assertIn(t, grants.LEGACY_ANON_EXCLUDED)
            self.assertGreaterEqual(down.count("'%s'" % t), 2, t)


if __name__ == "__main__":
    unittest.main(verbosity=1)
