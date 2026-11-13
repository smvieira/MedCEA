#!/usr/bin/env python3
"""Feedback control Phases 1+2, the database (migration 010), offline: the migration text.

- Migration 010 (apps/database/medcea_db_migrations.sql, the last block): its own
  transaction after 009's COMMIT with the 010 nonce lib-db-apply.sh reads back;
  medcea.control_loop (columns, CHECKs, the partial unique index of one active loop
  per (zone_id, loop_code), REVOKEs right after the CREATE), the busy guard (55006
  while the zone's unit has a run in R or S, ENABLE ALWAYS), stamp_actor_trg and
  row_change_trg attached here (not in 008b's list, which runs before the table
  exists), ownership, catalog guards (re-run safe), and the two views' trailing
  `sensor` column with security_invoker re-stated, in parity with the DDL.
- The engineer's write path (owner decision Q19, version 2c), created INERT:
  medcea.zone_loop_context(integer) and medcea.save_zone_loops(integer, jsonb),
  SECURITY DEFINER with a search_path, REVOKE ALL FROM PUBLIC, no GRANT in the migration;
  policy version 2c names them (master_data, level U: rr_engineer's EXECUTE only, from the
  compiled grants), never the guard or the helpers; their helpers; the validation rules (loop_code tied to the four
  quantities and their recipe_line columns, co2's command map, a commands actuator
  holding every command the loop sends, one loop per actuator, rule reference =>
  sources [reference(, fallback)], max_age_s 1..3600, mode command, 'default' never a
  saved source, the sensor taken from the topic's 6th segment), the order of the
  save's steps (actor 42501, table 55000, locks, 22023 with DETAIL, the no-op before
  the busy check, 55006 with the guard's own text, the writes).
- 008b's approve_change and _lock_row know medcea.control_loop; down_008b and
  grants.LEGACY_ANON_EXCLUDED take anon's blanket grant back from it; the optional
  down_010 undoes 010 in the order 010's step 1 reverses.

No database is needed. Run: python3 tests/test_control_loop_db.py
"""
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "apps", "database")
sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
from compiler import grants, model  # noqa: E402

QUANTITIES = {
    "air_temperature": ("air_temperature", "air_temperature_lower_limit", "air_temperature_upper_limit"),
    "air_humidity": ("air_humidity", "hr_lower_limit", "hr_upper_limit"),
    "co2": ("co2", "co2_lower_limit", "co2_upper_limit"),
    "substrate_temperature": ("ground_temperature", "substrate_temperature_lower_limit",
                              "substrate_temperature_upper_limit"),
}
CO2_MAP = '{"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}'
BUSY = ("'control_loop: unit % has run % in %; change its loops when no run is running or scheduled'")
SENSOR = "COALESCE(NULLIF(msg ->> 'sensor', ''), 'default') AS sensor"
SAVE = "medcea.save_zone_loops(integer,jsonb)"
CONTEXT = "medcea.zone_loop_context(integer)"
HELPERS = ("medcea._loop_quantities()", "medcea._zone_inventory(integer)",
           "medcea._loop_problems(jsonb,text,jsonb,jsonb)")
GUARD = "medcea.control_loop_busy_guard()"


def read(name):
    with open(os.path.join(DB, name)) as f:
        return f.read()


def collapse(text):
    return " ".join(text.split())


def outside_bodies(sql):
    """The SQL text with every dollar-quoted body blanked: what runs at the top level."""
    return re.sub(r"\$(\w*)\$.*?\$\1\$", "$$", sql, flags=re.S)


def statements(sql):
    """Top-level statements (comments dropped, bodies blanked), whitespace-collapsed."""
    text = outside_bodies(re.sub(r"(?m)^\s*--[^\n]*$", "", sql))
    return [collapse(s) for s in text.split(";") if s.strip()]


def function(block, name):
    """The CREATE OR REPLACE FUNCTION statement of `name` (schema-qualified), header and body."""
    i = block.index(f"CREATE OR REPLACE FUNCTION {name}(")
    j = block.index("$$;", block.index("AS $$", i)) + 3
    return block[i:j]


def ddl_view(ddl, view):
    i = ddl.index(f"CREATE VIEW medcea.{view} AS")
    return ddl[ddl.index("SELECT", i):ddl.index(";", i)]


def mig_view(block, view):
    i = block.index(f"CREATE OR REPLACE VIEW medcea.{view} WITH (security_invoker = true) AS")
    return block[block.index("SELECT", i):block.index(";", i)]


class Migration010Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.full = read("medcea_db_migrations.sql")
        start = cls.full.index("-- ── Migration 010")
        cls.block = cls.full[start:]
        cls.before = cls.full[:start]
        cls.lib = read("lib-db-apply.sh")
        cls.ddl = read("medcea_db_ddl.sql")

    def test_last_and_after_009(self):
        self.assertTrue(self.before.rstrip().endswith("COMMIT;"), "010 follows 009's COMMIT")
        self.assertIn("Migration 009", self.before)
        self.assertEqual(self.full.count("Migration 010"), 1)
        self.assertNotIn("Migration 011", self.full)

    def test_its_own_transaction(self):
        st = statements(self.block)
        self.assertEqual(st[0], "BEGIN")
        self.assertEqual(st[1], "SET LOCAL lock_timeout = '5s'")
        self.assertEqual(st[-1], "COMMIT")
        self.assertEqual(st.count("BEGIN"), 1)
        self.assertEqual(st.count("COMMIT"), 1)

    def test_nonce(self):
        self.assertIn("INSERT INTO medcea.platform_setting (key, value) VALUES ('010:last_nonce', :'deploy_nonce')",
                      self.block)
        self.assertIn("key = '010:last_nonce'", self.lib)
        self.assertLess(self.lib.index("key = '008c:last_nonce'"), self.lib.index("key = '010:last_nonce'"))
        self.assertIn("migration 010 did not commit", self.lib)
        nonce_check = self.lib[self.lib.index("key = '010:last_nonce'"):]
        self.assertRegex(nonce_check[:600], r"return 1")
        # psql does not interpolate :'var' inside a dollar-quoted body: the nonce is top level
        for _tag, body in re.findall(r"\$(\w*)\$(.*?)\$\1\$", self.block, re.S):
            self.assertNotRegex(body, r":'[a-z_]+'")

    def table(self):
        i = self.block.index("CREATE TABLE IF NOT EXISTS medcea.control_loop (")
        return self.block[i:self.block.index("\n);", i) + 3]

    def test_columns(self):
        t = self.table()
        body = t[t.index("(") + 1:t.rindex(")")]
        names = []
        depth = 0
        part = ""
        for ch in body:
            depth += {"(": 1, ")": -1}.get(ch, 0)
            if ch == "," and depth == 0:
                names.append(part.split()[0])
                part = ""
            else:
                part += ch
        names.append(part.split()[0])
        stamps = [f"{w}_by_{c}" for w in ("created", "updated") for c in ("sub", "person", "name", "role", "source")]
        self.assertEqual(names, ["loop_id", "zone_id", "loop_code", "recipe_lower", "recipe_upper", "input", "output",
                                 "is_active", "timestamp_cre"] + stamps)
        flat = collapse(t)
        self.assertIn("loop_id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY", flat)
        self.assertIn("REFERENCES medcea.cea_zone(zone_id)", flat)
        self.assertIn("is_active medcea.is_active NOT NULL DEFAULT 'Y' CONSTRAINT control_loop_is_active_chk "
                      "CHECK (is_active IN ('Y', 'N'))", flat)
        self.assertIn("loop_code varchar(50) NOT NULL", flat)
        # stamp types as 008b's B4 adds them; timestamp_cre so _content leaves it out
        self.assertIn("created_by_role varchar(40)", flat)
        self.assertNotIn("created_at", flat)
        self.assertNotIn("CREATE TABLE medcea.control_loop", self.ddl, "the table lives only in the migration")
        self.assertNotIn("control_loop", self.ddl)

    def test_jsonb_checks(self):
        flat = collapse(self.table())
        inp = flat[flat.index("control_loop_input_chk"):flat.index(", output jsonb NOT NULL")]
        out = flat[flat.index("control_loop_output_chk"):flat.index(", is_active medcea.is_active")]
        # a CHECK passes on NULL: both are coalesce(…, false)
        self.assertIn("CHECK (coalesce(", inp)
        self.assertTrue(inp.rstrip(", ").endswith(", false))"), inp[-80:])
        self.assertIn("CHECK (coalesce(", out)
        self.assertTrue(out.rstrip(", ").endswith(", false))"), out[-80:])
        self.assertIn("input ->> 'rule' IN ('reference', 'mean', 'min', 'max')", inp)
        self.assertIn("output ->> 'mode' IN ('command', 'level', 'boost')", out)
        self.assertIn("pg_catalog.jsonb_typeof(input -> 'tag') = 'string'", inp)
        self.assertIn("pg_catalog.jsonb_typeof(output -> 'actuator') = 'string'", out)
        self.assertIn("WHEN pg_catalog.jsonb_typeof(input -> 'sources') = 'array'", inp)
        self.assertIn("""jsonb_path_exists(input, '$.sources[*] ? (@.type() != "string")')""", inp)
        # the casts that would raise on the wrong type are behind a CASE
        self.assertRegex(inp, r"CASE WHEN pg_catalog\.jsonb_typeof\(input -> 'max_age_s'\) = 'number' "
                              r"THEN \(input ->> 'max_age_s'\)::numeric > 0 ELSE false END")

    def test_one_active_index(self):
        m = re.search(r"DO \$\$\s+BEGIN\s+IF pg_catalog\.to_regclass\('medcea\.control_loop_one_active'\) IS NULL THEN\s+"
                      r"CREATE UNIQUE INDEX control_loop_one_active ON medcea\.control_loop \(zone_id, loop_code\) "
                      r"WHERE is_active = 'Y';", self.block)
        self.assertIsNotNone(m)

    def test_revoke_right_after_create(self):
        self.assertRegex(self.block, r"\n\);\nREVOKE ALL ON TABLE medcea\.control_loop FROM PUBLIC, anon, authenticator;\n"
                                     r"REVOKE ALL ON SEQUENCE medcea\.control_loop_loop_id_seq FROM PUBLIC, anon, authenticator;\n")
        self.assertEqual(self.table().count("CREATE TABLE"), 1)
        self.assertLess(self.block.index("CREATE TABLE IF NOT EXISTS medcea.control_loop"),
                        self.block.index("REVOKE ALL ON TABLE medcea.control_loop"))

    def test_busy_guard(self):
        g = function(self.block, "medcea.control_loop_busy_guard")
        self.assertIn("RETURNS trigger", g)
        self.assertIn("SECURITY DEFINER SET search_path = medcea, pg_temp", g)
        self.assertLess(g.index("FOR NO KEY UPDATE"), g.index("medcea._unit_busy("))
        self.assertIn("RAISE EXCEPTION " + BUSY, g)
        self.assertIn("USING ERRCODE = '55006'", g)
        self.assertNotIn("policy_refuse", g)   # structural: both modes
        for w in ("OLD.zone_id", "NEW.zone_id", "RETURN OLD", "RETURN NEW", "ORDER BY z.unit_id"):
            self.assertIn(w, g)
        self.assertIn("REVOKE ALL ON FUNCTION medcea.control_loop_busy_guard() FROM PUBLIC;", self.block)
        flat = collapse(self.block)
        self.assertIn("CREATE TRIGGER control_loop_busy_trg BEFORE INSERT OR UPDATE OR DELETE ON medcea.control_loop "
                      "FOR EACH ROW EXECUTE FUNCTION medcea.control_loop_busy_guard();", flat)
        self.assertIn("AND tgname = 'control_loop_busy_trg' AND tgenabled <> 'A') THEN "
                      "ALTER TABLE medcea.control_loop ENABLE ALWAYS TRIGGER control_loop_busy_trg;", flat)

    def test_unit_busy_is_r_and_s(self):
        i = self.full.index("CREATE OR REPLACE FUNCTION medcea._unit_busy(")
        body = self.full[i:self.full.index("$$;", i)]
        self.assertIn("r.recipe_run_status IN ('R', 'S')", body)

    def test_stamp_and_row_change(self):
        flat = collapse(self.block)
        for trg, fn in (("stamp_actor_trg", "BEFORE INSERT OR UPDATE ON medcea.control_loop "
                                            "FOR EACH ROW EXECUTE FUNCTION medcea.stamp_actor();"),
                        ("row_change_trg", "AFTER INSERT OR UPDATE OR DELETE ON medcea.control_loop "
                                           "FOR EACH ROW EXECUTE FUNCTION medcea.log_row_change('loop_id');")):
            self.assertIn(f"AND tgname = '{trg}') THEN CREATE TRIGGER {trg} {fn}", flat)
            self.assertIn(f"IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = "
                          f"pg_catalog.to_regclass('medcea.control_loop') AND tgname = '{trg}')", flat)
        # 008b's list runs before the table exists (one transaction, before 010): never there
        spec = re.search(r"spec  text\[\]\[\] := ARRAY\[(.*?)\];", self.before, re.S)
        self.assertIsNotNone(spec)
        self.assertNotIn("control_loop", spec.group(1))
        b4 = self.before[self.before.index("B4. Attribution columns"):self.before.index("END $$;",
                                                                                         self.before.index("B4. Attribution"))]
        self.assertNotIn("'control_loop'", b4)
        self.assertNotIn("14 attributed", self.full)
        self.assertEqual(self.full.count("15 attributed tables"), 3)

    def test_rerun_safe(self):
        top = "\n".join(statements(self.block))
        for word in ("ALTER TABLE", "CREATE INDEX", "CREATE UNIQUE INDEX", "CREATE OR REPLACE VIEW", "CREATE TRIGGER",
                     "DROP ", "GRANT ", "CREATE OR REPLACE TRIGGER", "ALTER FUNCTION"):
            self.assertNotIn(word, top, word)
        inserts = [s for s in statements(self.block) if s.startswith("INSERT")]
        self.assertEqual(len(inserts), 1)
        self.assertTrue(inserts[0].startswith("INSERT INTO medcea.platform_setting"))
        self.assertIn("CREATE TABLE IF NOT EXISTS medcea.control_loop", top)
        self.assertNotIn("CREATE OR REPLACE TRIGGER", self.block)
        # step 1 brings a table parked by down_010 back before CREATE TABLE IF NOT EXISTS
        self.assertLess(self.block.index("ALTER TABLE medcea_retired_010.control_loop SET SCHEMA medcea;"),
                        self.block.index("CREATE TABLE IF NOT EXISTS medcea.control_loop"))

    def test_views(self):
        for view in ("msg_actual_points", "v_ap_measurements"):
            with self.subTest(view):
                m, d = collapse(mig_view(self.block, view)), collapse(ddl_view(self.ddl, view))
                self.assertEqual(m, d, "the migration's view and the DDL's are the same text")
                cols = m[len("SELECT "):m.index(" FROM medcea.measurement")]
                self.assertTrue(cols.endswith(", msg, " + SENSOR), cols[-120:])
                self.assertEqual(m.count("sensor"), 2)
                guard = self.block[self.block.rindex("IF pg_catalog.to_regclass('medcea." + view + "') IS NOT NULL",
                                                     0, self.block.index("CREATE OR REPLACE VIEW medcea." + view)):
                                   self.block.index("CREATE OR REPLACE VIEW medcea." + view)]
                self.assertIn("attname = 'sensor' AND NOT attisdropped", guard)
                self.assertIn(f"pg_catalog.to_regclass('medcea.{view}')", guard)
                self.assertNotIn(f"'medcea.{view}'::regclass", guard)
                # no other column moved: the DDL's list before sensor is the one pg_dump wrote
                self.assertIn(", msg FROM", d.replace(", " + SENSOR, ""))
        # every other medcea view is untouched by 010
        self.assertEqual(len(re.findall(r"CREATE OR REPLACE VIEW medcea\.", self.block)), 2)

    def test_review_targets(self):
        i = self.full.index("CREATE OR REPLACE FUNCTION medcea.approve_change(")
        body = self.full[i:self.full.index("END $$;", i)]
        allowed = re.search(r"IF p_target NOT IN \(([^)]*)\) THEN", body)
        self.assertIn("'medcea.control_loop'", allowed.group(1))
        i = self.full.index("CREATE OR REPLACE FUNCTION medcea_auth._lock_row(")
        body = self.full[i:self.full.index("END $$;", i)]
        self.assertIn("WHEN 'medcea.control_loop' THEN 'loop_id'", body)

    def test_ownership(self):
        flat = collapse(self.block)
        self.assertIn("IF (SELECT relowner FROM pg_catalog.pg_class WHERE oid = pg_catalog.to_regclass('medcea.control_loop')) "
                      "<> 'medcea_owner'::regrole THEN ALTER TABLE medcea.control_loop OWNER TO medcea_owner;", flat)
        own = flat[flat.index("8. Ownership"):]
        for sig in (GUARD, SAVE, CONTEXT) + HELPERS:
            self.assertIn(f"pg_catalog.to_regprocedure('{sig}')", own, sig)
        self.assertIn("IF (SELECT proowner FROM pg_catalog.pg_proc WHERE oid = f) <> 'medcea_owner'::regrole THEN "
                      "EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO medcea_owner', f);", own)

    def test_header_follows_q19(self):
        head = self.block[:self.block.index("BEGIN;")]
        self.assertNotIn("master_data C/U", head)
        self.assertIn("save_zone_loops()", head)
        self.assertIn("version 2c", head)
        comment = re.search(r"COMMENT ON TABLE medcea\.control_loop IS '(.*?)';", self.block, re.S).group(1)
        self.assertNotIn("Written by engineers (master_data)", comment)
        self.assertIn("save_zone_loops()", comment)


class LoopFunctionsTest(unittest.TestCase):
    """The two functions of policy version 2c and their helpers, created inert by 010."""

    @classmethod
    def setUpClass(cls):
        full = read("medcea_db_migrations.sql")
        cls.block = full[full.index("-- ── Migration 010"):]
        cls.save = function(cls.block, "medcea.save_zone_loops")
        cls.context = function(cls.block, "medcea.zone_loop_context")
        cls.problems = function(cls.block, "medcea._loop_problems")
        cls.inventory = function(cls.block, "medcea._zone_inventory")
        cls.quantities = function(cls.block, "medcea._loop_quantities")
        cls.guard = function(cls.block, "medcea.control_loop_busy_guard")
        cls.ddl = read("medcea_db_ddl.sql")

    def test_created_inert(self):
        flat = collapse(self.block)
        for name in ("save_zone_loops", "zone_loop_context"):
            f = collapse(function(self.block, "medcea." + name))
            self.assertIn("LANGUAGE plpgsql", f)
            self.assertIn("SECURITY DEFINER SET search_path = medcea, pg_temp AS $$", f)
        self.assertIn("LANGUAGE plpgsql STABLE SECURITY DEFINER", collapse(self.context))
        self.assertNotIn("STABLE", collapse(self.save)[:200])
        for f in (self.problems, self.inventory, self.quantities):
            head = collapse(f[:f.index("AS $$")])
            self.assertNotIn("SECURITY DEFINER", head)
            self.assertIn("SET search_path = ", head)
            self.assertIn("pg_temp", head)
        for sig in ("medcea.save_zone_loops(integer, jsonb)", "medcea.zone_loop_context(integer)",
                    "medcea._loop_problems(jsonb, text, jsonb, jsonb)", "medcea._zone_inventory(integer)",
                    "medcea._loop_quantities()", "medcea.control_loop_busy_guard()"):
            self.assertIn(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC;", flat, sig)
        # each REVOKE right after its function
        for m in re.finditer(r"CREATE OR REPLACE FUNCTION (medcea\.[a-z_]+)\(", self.block):
            end = self.block.index("$$;", self.block.index("AS $$", m.start())) + 3
            self.assertTrue(self.block[end:].lstrip().startswith(f"REVOKE ALL ON FUNCTION {m.group(1)}("), m.group(1))
        self.assertNotRegex(self.block, r"\bGRANT\b")

    def test_named_by_the_policy_2c(self):
        """Version 2c names the two entry points (master_data, level U): engineer alone gets
        EXECUTE on each; the guard and the helpers stay unnamed and ungranted."""
        p = model.load_defaults()
        declared = set(grants.declared_functions(p))
        privs = grants.privileges(p)
        for sig in (SAVE, CONTEXT):
            self.assertIn(sig, declared, sig)
            self.assertEqual([tuple(x) for x in privs if x[2] == sig],
                             [("rr_engineer", "function", sig, "EXECUTE")], sig)
        for sig in (GUARD,) + HELPERS:
            self.assertNotIn(sig, declared, sig)
            self.assertFalse([x for x in privs if x[2] == sig], sig)
        with open(os.path.join(ROOT, "tests", "iam-grants.golden.json")) as f:
            golden = json.load(f)
        named = [x for x in golden["privileges"] if "zone_loop" in json.dumps(x)]
        self.assertEqual(sorted(map(tuple, named)),
                         sorted(("rr_engineer", "function", sig, "EXECUTE") for sig in (SAVE, CONTEXT)))
        for k, v in golden.items():
            if k != "privileges":
                self.assertNotIn("zone_loop", json.dumps(v), k)
        self.assertEqual([f for f in grants.NOT_BUILT if "loop" in f], [])

    def test_creatable_before_the_table(self):
        self.assertNotRegex(self.block, r"control_loop%(ROW)?TYPE")
        self.assertNotIn("SETOF medcea.control_loop", self.block)
        for m in re.finditer(r"CREATE OR REPLACE FUNCTION (medcea\.[a-z_]+)\(", self.block):
            f = function(self.block, m.group(1))
            body = f[f.index("AS $$"):]
            if "medcea.control_loop " in body or "medcea.control_loop\n" in body:
                self.assertIn("LANGUAGE plpgsql", f[:f.index("AS $$")], m.group(1))

    def test_actor_first_hard_42501(self):
        for name, f in (("save_zone_loops", self.save), ("zone_loop_context", self.context)):
            with self.subTest(name):
                actor = f.index("medcea_auth.request_actor()")
                person = f.index("coalesce(btrim(a.person), '') = ''")
                self.assertLess(actor, person)
                first = f[person:f.index("END IF;", person)]
                self.assertIn("a.source = 'token' OR a.source LIKE 'person via %'", first)
                self.assertIn("ERRCODE = '42501'", first)
                self.assertIn("RAISE EXCEPTION", first)
                self.assertNotIn("policy_refuse", f)
                self.assertIn("medcea_auth.policy_holds(a.role, 'master_data', 'U')", f)

    def test_save_order(self):
        s = self.save
        order = [s.index("medcea_auth.request_actor()"),
                 s.index("policy_holds(a.role, 'master_data', 'U')"),
                 s.index("pg_catalog.to_regclass('medcea.control_loop') IS NULL"),
                 s.index("FOR SHARE"),
                 s.index("FOR NO KEY UPDATE"),
                 s.index("medcea._zone_inventory("),
                 s.index("medcea._loop_problems("),
                 s.index("DETAIL = array_to_json(errs)::text"),
                 s.index("'changed', false"),
                 s.index("medcea._unit_busy("),
                 s.index("UPDATE medcea.control_loop SET is_active = 'N'"),
                 s.index("INSERT INTO medcea.control_loop")]
        self.assertEqual(order, sorted(order))
        self.assertIn("USING ERRCODE = '55000'", s[order[2]:order[3]])
        self.assertIn("USING ERRCODE = '22023', DETAIL = array_to_json(errs)::text", s)
        self.assertIn("'save_zone_loops: ' || array_to_string(errs, '; ')", s)

    def test_busy_text_is_the_guards(self):
        self.assertIn("RAISE EXCEPTION " + BUSY, self.save)
        busy = self.save[self.save.index("RAISE EXCEPTION " + BUSY):]
        self.assertIn("USING ERRCODE = '55006'", busy[:400])
        self.assertEqual(self.block.count(BUSY), 2)

    def test_replace_all(self):
        s = collapse(self.save)
        # absent codes deactivated, changed ones updated in place, new ones inserted
        self.assertIn("IF l IS NULL THEN drops := drops || r.id;", s)
        self.assertIn("(r.lo, r.up, r.inp, r.outp) IS DISTINCT FROM (l ->> 'recipe_lower', l ->> 'recipe_upper', "
                      "l -> 'input', l -> 'output')", s)
        self.assertIn("WHERE cl.zone_id = p_zone_id AND cl.is_active = 'Y' ORDER BY cl.loop_id FOR UPDATE", s)
        self.assertIn("jsonb_typeof(p_loops) IS DISTINCT FROM 'array'", s)
        self.assertIn("'%s: listed twice'", s)
        self.assertIn("'%s: actuator %s is driven by another loop of the zone'", s)
        self.assertNotIn("DELETE", s)
        for k in ("'inserted'", "'updated'", "'deactivated'", "'unchanged'", "'changed', true"):
            self.assertIn(k, s)

    def test_quantities(self):
        q = collapse(self.quantities)
        for code, (tag, lo, up) in QUANTITIES.items():
            self.assertIn(f'"{code}": {{"tag": "{tag}", "recipe_lower": "{lo}", "recipe_upper": "{up}"', q)
            for col in (lo, up):
                # the columns exist in recipe_line, and the runner reads them
                rl = self.ddl[self.ddl.index("CREATE TABLE medcea.recipe_line ("):]
                self.assertRegex(rl[:rl.index(");")], rf"\n    {col} integer")
                with open(os.path.join(ROOT, "schd", "cea", "get_recipe_line_item_seq_details.py")) as f:
                    self.assertIn(col, f.read())
        self.assertIn('"command_map": ' + CO2_MAP, q)
        self.assertEqual(q.count("command_map"), 1)
        self.assertEqual(len(re.findall(r'"([a-z0-9_]+)": \{"tag"', q)), 4)

    def test_rules(self):
        p = collapse(self.problems)
        self.assertIn("medcea._loop_quantities()", p)
        # loop_code, limits and tag tied to the quantity
        self.assertIn("(p_loop -> 'recipe_lower') IS DISTINCT FROM (q -> 'recipe_lower')", p)
        self.assertIn("(p_loop -> 'recipe_upper') IS DISTINCT FROM (q -> 'recipe_upper')", p)
        self.assertIn("(inp -> 'tag') IS DISTINCT FROM (q -> 'tag')", p)
        self.assertIn("'loop_code %s is not one of %s'", p)
        self.assertIn("is longer than 50 characters", p)
        # rules, reference => sources = [reference(, fallback)]
        self.assertIn("ARRAY['reference', 'mean', 'min', 'max']", p)
        self.assertIn("with rule reference, input.sources holds only the reference and the fallback", p)
        self.assertIn("y IS DISTINCT FROM ref AND y IS DISTINCT FROM fb", p)
        self.assertIn("takes no reference or fallback", p)
        self.assertIn("input.fallback must be another sensor than the reference", p)
        # max_age_s an integer 1..3600
        self.assertIn("IF n <> trunc(n) OR n < 1 OR n > 3600 THEN", p)
        # 'default' is reserved, never a saved source
        self.assertIn("IF s = 'default' THEN", p)
        self.assertIn("sensor default is reserved", p)
        # mode command only (the table's CHECK keeps level/boost for later phases)
        self.assertIn("""(outp -> 'mode') IS DISTINCT FROM '"command"'::jsonb""", p)
        self.assertNotIn("'level'", p)
        # co2 exactly its map, the others none
        self.assertIn("IF q ? 'command_map' THEN IF (outp -> 'command_map') IS DISTINCT FROM (q -> 'command_map')", p)
        self.assertIn("output.command_map is only for co2", p)
        # a commands actuator holding every command the loop sends
        self.assertIn("need := ARRAY(SELECT DISTINCT v FROM jsonb_each_text(q -> 'command_map') m(c, v) ORDER BY v);", p)
        self.assertIn("need := ARRAY['DOWN', 'OFF', 'UP'];", p)
        self.assertIn("e ->> 'kind' = 'commands'", p)
        self.assertIn("(e -> 'commands') ?& need", p)
        self.assertIn("'^[A-Za-z0-9_]+$'", p)
        # unknown keys refused at each level
        for keys in ("ARRAY['loop_code', 'recipe_lower', 'recipe_upper', 'input', 'output']",
                     "ARRAY['tag', 'sources', 'rule', 'reference', 'fallback', 'max_age_s']",
                     "ARRAY['actuator', 'mode', 'command_map']"):
            self.assertIn(keys, p)
        # a cast or array function only behind its type check (nested IF, not AND/OR)
        self.assertIn("IF jsonb_typeof(inp -> 'sources') IS DISTINCT FROM 'array' THEN", p)
        self.assertIn("ELSIF jsonb_array_length(inp -> 'sources') = 0 THEN", p)
        self.assertIn("IF jsonb_typeof(inp -> 'max_age_s') IS DISTINCT FROM 'number' THEN", p)
        # the context advertises the same rules
        c = collapse(self.context)
        self.assertIn("""'rules', '["reference", "mean", "min", "max"]'::jsonb""", c)
        self.assertIn("""'modes', '["command"]'::jsonb""", c)
        self.assertIn("""'max_age_s', '{"min": 1, "max": 3600, "default": 90}'::jsonb""", c)

    def test_sensor_from_the_topic(self):
        inv = collapse(self.inventory)
        self.assertIn("string_to_array(t ->> 'topic', '/') AS seg", inv)
        self.assertIn("WHEN cardinality(tg.seg) = 5 AND tg.seg[4] = 'sense' AND tg.seg[5] = tg.tag THEN 'old'", inv)
        self.assertIn("WHEN tg.seg[6] = 'default' THEN 'reserved'", inv)
        self.assertIn("WHEN tg.declared IS NOT NULL AND tg.declared <> tg.seg[6] THEN 'mismatch'", inv)
        self.assertIn("CASE WHEN jsonb_typeof(comp.p -> 'instance') = 'string' THEN comp.p ->> 'instance' END AS declared", inv)
        self.assertIn("FROM cls x WHERE x.kind = 'named' GROUP BY x.inst HAVING count(DISTINCT x.component_id) = 1", inv)
        self.assertIn("FROM cls x WHERE x.kind = 'old' GROUP BY x.component_id", inv)
        # never p ->> 'instance' alone as the name (a board flashed before Phase 1 has it, with 5-segment topics)
        self.assertNotIn("'instance', j.p ->> 'instance'", inv)
        self.assertIn("upper(d.device_type) = 'SENSE'", inv)
        self.assertIn("upper(d.device_type) = 'CONTROL'", inv)
        self.assertIn("'actuator_definitions'", inv)
        self.assertIn("WHEN jsonb_typeof(e.value -> 'commands') = 'object' THEN 'commands'", inv)
        c = collapse(self.context)
        for k in ("'sensors', inv.sensors", "'old_boards', inv.old_boards", "'sensor_problems', inv.problems",
                  "'actuators', inv.actuators", "'deployed', dep", "'busy'"):
            self.assertIn(k, c)
        self.assertIn("IF dep THEN", c)
        self.assertNotIn("created_by_name", c)   # no person names


class DownTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.down_b = read("medcea_db_migrations_down_008b.sql")
        cls.down = read("medcea_db_migrations_down_010.sql")
        full = read("medcea_db_migrations.sql")
        cls.block = full[full.index("-- ── Migration 010"):]

    def test_anon_excluded(self):
        self.assertIn("control_loop", grants.LEGACY_ANON_EXCLUDED)
        loop = re.search(r"FOREACH t IN ARRAY ARRAY\[([^\]]*)\] LOOP\s+IF pg_catalog.to_regclass", self.down_b)
        self.assertIn("'control_loop'", loop.group(1))
        seq = re.search(r"AND t\.relname IN \(([^)]*)\) LOOP", self.down_b)
        self.assertIn("'control_loop'", seq.group(1))
        # guarded, never a top-level REVOKE (the table may not exist yet)
        self.assertNotRegex(self.down_b, r"(?m)^REVOKE ALL ON medcea\.control_loop")

    def test_down_010(self):
        self.assertNotRegex(self.down, r"(?m)^(BEGIN|COMMIT);")
        flat = collapse(self.down)
        self.assertIn("DROP TRIGGER IF EXISTS control_loop_busy_trg ON medcea.control_loop;", flat)
        drop = re.search(r"DROP FUNCTION IF EXISTS (.*?);", flat).group(1)
        made = set(re.findall(r"CREATE OR REPLACE FUNCTION (medcea\.[a-z_]+)\(", self.block))
        self.assertEqual({x.split("(")[0].strip() for x in re.split(r",\s*(?=medcea\.)", drop)}, made)
        self.assertIn("ALTER TABLE medcea.control_loop SET SCHEMA medcea_retired_010;", flat)
        self.assertIn("ALTER TABLE medcea_retired_010.control_loop SET SCHEMA medcea;", self.block)
        self.assertLess(self.down.index("is granted (policy version 2c)"), self.down.index("DROP FUNCTION"))
        self.assertLess(self.down.index("DROP TRIGGER"), self.down.index("DROP FUNCTION"))
        code = re.sub(r"(?m)^\s*--[^\n]*$", "", self.down)
        self.assertNotIn("DROP TABLE", code)
        self.assertNotIn("DROP VIEW", code)


if __name__ == "__main__":
    unittest.main()
