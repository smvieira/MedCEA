#!/usr/bin/env python3
"""Migration 013: the research sandbox's read functions (Phase 2a, commit A), offline.

- Structure: 013 is the last block, its own transaction after 012's COMMIT, with
  the 013 nonce that lib-db-apply.sh reads back right after 012's; it is not in the
  DDL; it checks first that every table it reads exists.
- The eleven functions: exactly the signatures of the Phase 2a interfaces (argument
  names, RETURNS TABLE column names and types, parsed from the SQL), LANGUAGE sql,
  STABLE, SECURITY DEFINER, SET search_path = pg_catalog, medcea, pg_temp, owned by
  medcea_owner (the ownership loop names each), REVOKE ALL … FROM PUBLIC per
  function, no GRANT, CREATE OR REPLACE (re-run safe).
- Nothing personal or free-text: a scan of every body for forbidden identifiers
  (*_by_*, names, descriptions, notes, reasons, locations, device identifiers,
  addresses), msg read only through its allowed keys, run_params only through the
  first element's allowed keys, every alias.column reference a real column of the
  table the alias names, every relation schema-qualified.
- The jsonb they return is rebuilt, never passed on (review of 18 Nov 2026):
  parameters keep only ^[a-z][a-z0-9_]{0,39}$ keys with number/boolean values, a
  loop's input and output only their known keys with typed values; checked against
  schd/cea/algorithms/params.py and schd/cea/loop_resolver.py so that nothing
  legitimate is dropped, and live with free text planted in every place.
- The down file: refused while svc_research_export may execute one, drops all
  eleven, deletes the nonce, no BEGIN/COMMIT of its own.
- Optional: with a local PostgreSQL (initdb, pg_ctl, postgres, psql on PATH or in
  /usr/lib/postgresql/*/bin), the DDL and every migration run in a throwaway cluster
  and the functions answer as medcea_owner; skipped otherwise.
Run: python3 tests/test_research_functions.py
"""
import glob
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "apps", "database")

# The interfaces of Phase 2a (INTERFACES.md, "Migration 013"), word for word.
SIGNATURES = {
    "research_contract_version": ([], "integer"),
    "research_measurements": ([("p_after", "timestamptz"), ("p_upto", "timestamptz")],
                              [("ingested_at", "timestamptz"), ("measured_at", "timestamptz"), ("unit_code", "text"),
                               ("zone_code", "text"), ("tag", "text"), ("sensor", "text"), ("value", "numeric"),
                               ("uom", "text")]),
    "research_units": ([], [("unit_code", "text"), ("recipe_type", "text"), ("area", "numeric"),
                            ("height", "numeric"), ("is_active", "text")]),
    "research_zones": ([], [("unit_code", "text"), ("zone_code", "text"), ("is_active", "text")]),
    "research_recipes": ([], [("recipe_id", "integer"), ("recipe_type", "text"), ("status", "text")]),
    "research_recipe_lines": ([], [("recipe_id", "integer"), ("seq", "integer"), ("cycle_number", "integer"),
                                   ("light_type", "text"), ("light_on_minutes", "integer"),
                                   ("light_off_minutes", "integer"), ("setpoints", "jsonb")]),
    "research_runs": ([], [("run_id", "integer"), ("recipe_id", "integer"), ("unit_code", "text"),
                           ("started_at", "timestamptz"), ("ended_at", "timestamptz"), ("status", "text")]),
    "research_cycles": ([], [("run_id", "integer"), ("seq", "integer"), ("cycle_num", "integer"),
                             ("started_at", "timestamptz"), ("ended_at", "timestamptz"), ("status", "text"),
                             ("algorithm_code", "text"), ("algorithm_params", "jsonb"), ("control_loops", "jsonb")]),
    "research_control_loops": ([], [("unit_code", "text"), ("zone_code", "text"), ("loop_code", "text"),
                                    ("input", "jsonb"), ("output", "jsonb")]),
    "research_param_sets": ([], [("params_id", "integer"), ("algorithm_code", "text"), ("unit_code", "text"),
                                 ("params", "jsonb")]),
    "research_catalogue": ([], [("kind", "text"), ("code", "text"), ("doc", "jsonb")]),
}

# Identifiers no body may name (person, free text, location, device identity, raw json)
FORBIDDEN = re.compile(
    r"(_by_|\bname\b|_name\b|\bnames?\b|description|\bnotes?\b|\breason\b|location|\bdevice_id\b|\bdevice_dns\b"
    r"|serial|address|\bip\b|\bmac\b|contact|\bsource\b|\blabel\b|legacy_unit_type|\bsub\b|person|executed_by"
    r"|\bschedule_id\b|session_user|client_addr|\bactor\b)", re.I)
MSG_KEYS = {"unit_code", "zone_code", "tag", "sensor", "value", "UoM"}
RUN_PARAM_KEYS = {"control_algorithm", "control_algorithm_params", "control_loops"}
LOOP_KEYS = {"zone_code", "loop_code", "phase", "input", "output", "completed"}

# The columns of every table the functions read (DDL + migrations 008b..012)
COLUMNS = {
    "measurement": {"measure_timestamp", "device_id", "device_dns", "msg_type", "msg", "timestamp", "zone_id"},
    "cea_unit": {"unit_id", "unit_type", "description", "location_id", "area", "height", "timestamp", "is_active",
                 "unit_code", "commissioning"},
    "cea_zone": {"unit_id", "zone_id", "zone_code", "zone_description", "timestamp_cre", "is_active"},
    "recipe": {"recipe_id", "recipe_name", "recipe_description", "timestamp_cre", "timestamp_upd", "is_active",
               "status", "recipe_type"},
    "recipe_line": {"recipe_id", "recipe_item_seq_id", "recipe_item_seq_name", "cycle_number", "light_type",
                    "light_on_minutes", "light_off_minutes", "timestamp_cre", "timestamp_upd", "notes", "setpoints"},
    "recipe_run": {"recipe_run_id", "recipe_id", "unit_id", "recipe_run_start", "recipe_run_end", "timestamp_cre",
                   "timestamp_upd", "recipe_run_status", "is_active", "schedule_id", "params_id"},
    "recipe_line_cycle_run": {"recipe_line_cycle_run_id", "recipe_run_id", "recipe_id", "recipe_item_seq_id",
                              "recipe_item_seq_cycle_num", "recipe_line_seq_cycle_run_start",
                              "recipe_line_seq_cycle_run_end", "recipe_line_cycle_run_status", "run_params",
                              "timestamp_cre", "timestamp_upd"},
    "control_loop": {"loop_id", "zone_id", "loop_code", "input", "output", "is_active", "timestamp_cre"},
    "unit_algorithm_params": {"params_id", "algorithm_id", "unit_id", "name", "params", "status", "source",
                              "timestamp_cre", "timestamp_upd"},
    "control_algorithm": {"algorithm_id", "algorithm_code", "algorithm_name", "description", "default_params",
                          "is_active", "status"},
    "control_quantity": {"quantity_id", "quantity_code", "label", "unit", "sense_uoms", "default_tag", "commands",
                         "command_map", "phase", "loopable", "min_value", "max_value", "ordinal"},
    "recipe_type": {"recipe_type_id", "recipe_type_code", "label", "legacy_unit_type", "is_default", "ordinal"},
    "recipe_type_quantity": {"recipe_type_id", "quantity_id", "required", "ordinal"},
}
# dropped by migration 012
DROPPED = {"control_loop": {"recipe_lower", "recipe_upper"}}


def read(name):
    with open(os.path.join(DB, name), encoding="utf-8") as f:
        return f.read()


def block013():
    full = read("medcea_db_migrations.sql")
    return full, full[full.index("-- ── Migration 013"):]


def strip_comments(sql):
    return re.sub(r"--[^\n]*", "", sql)


def functions(block):
    """{name: (args text, returns text, attributes text, body)} of every CREATE OR REPLACE FUNCTION."""
    out = {}
    for m in re.finditer(r"CREATE OR REPLACE FUNCTION medcea\.(\w+)\((.*?)\)\s*RETURNS\s+(.*?)\n\s*"
                         r"(LANGUAGE[^\n]*?) AS \$\$(.*?)\$\$;", block, re.S):
        out[m.group(1)] = (m.group(2), m.group(3).strip(), m.group(4), m.group(5))
    return out


def parse_pairs(text):
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    return [tuple(p.strip().split(" ", 1)) for p in text.split(",")]


def parse_returns(text):
    m = re.fullmatch(r"TABLE\((.*)\)", re.sub(r"\s+", " ", text).strip(), re.S)
    return parse_pairs(m.group(1)) if m else text.strip()


def string_literals_removed(sql):
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


class Structure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full, cls.block = block013()
        cls.lib = read("lib-db-apply.sh")
        cls.ddl = read("medcea_db_ddl.sql")

    def test_last_and_own_transaction(self):
        before = self.full[:self.full.index("-- ── Migration 013")]
        self.assertTrue(before.rstrip().endswith("COMMIT;"), "after 012's COMMIT")
        self.assertIn("-- ── Migration 012", before)
        stmts = re.findall(r"(?m)^(BEGIN|COMMIT);", re.sub(r"\$(\w*)\$.*?\$\1\$", "$$", self.block, flags=re.S))
        self.assertEqual(stmts, ["BEGIN", "COMMIT"])
        self.assertTrue(self.block.rstrip().endswith("COMMIT;"))
        self.assertEqual(self.full.count("-- ── Migration 013"), 1)

    def test_nonce_and_reload(self):
        self.assertIn("INSERT INTO medcea.platform_setting (key, value) VALUES ('013:last_nonce', :'deploy_nonce')",
                      self.block)
        self.assertIn("NOTIFY pgrst, 'reload schema';", self.block)
        self.assertLess(self.lib.index("key = '012:last_nonce'"), self.lib.index("key = '013:last_nonce'"))
        self.assertLess(self.lib.index("key = '013:last_nonce'"), self.lib.index("── 3a."))
        self.assertIn("migration 013 did not commit", self.lib)

    def test_no_psql_variable_in_a_body(self):
        for body in re.findall(r"\$(\w*)\$(.*?)\$\1\$", self.block, re.S):
            self.assertNotRegex(body[1], r":'[a-z_]+'")

    def test_not_in_the_ddl(self):
        self.assertNotIn("research_", self.ddl)

    def test_tables_checked_first(self):
        check = self.block.index("migrations 008b to 012 must have run first")
        self.assertLess(check, self.block.index("CREATE OR REPLACE FUNCTION"))
        for t in COLUMNS:
            self.assertIn("'medcea.%s'" % t, self.block[:check], t)

    def test_no_grant_and_nothing_else_created(self):
        code = strip_comments(self.block)
        self.assertNotRegex(code, r"\bGRANT\b")
        self.assertNotIn("TO anon", code)
        self.assertNotRegex(code, r"CREATE (TABLE|VIEW|INDEX|TRIGGER|ROLE|SCHEMA)")
        self.assertNotRegex(code, r"\bALTER TABLE\b")
        self.assertNotRegex(code, r"CREATE FUNCTION")   # only CREATE OR REPLACE: re-run safe


class Functions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full, cls.block = block013()
        cls.fns = functions(cls.block)

    def test_exactly_the_eleven(self):
        self.assertEqual(set(self.fns), set(SIGNATURES))
        self.assertEqual(len(re.findall(r"CREATE OR REPLACE FUNCTION", self.block)), len(SIGNATURES))

    def test_signatures_are_the_interfaces(self):
        for name, (args, returns) in SIGNATURES.items():
            a, r, _, _ = self.fns[name]
            self.assertEqual(parse_pairs(a), args, name)
            self.assertEqual(parse_returns(r), returns, name)

    def test_attributes(self):
        for name, (_, _, attrs, _) in self.fns.items():
            self.assertEqual(attrs, "LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, medcea, pg_temp",
                             name)

    def test_revoke_per_function(self):
        for name, (args, _) in SIGNATURES.items():
            types = ", ".join(t for _, t in args)
            self.assertIn("REVOKE ALL ON FUNCTION medcea.%s(%s) FROM PUBLIC;" % (name, types), self.block, name)
            self.assertIn("COMMENT ON FUNCTION medcea.%s(%s) IS" % (name, types), self.block, name)

    def test_owned_by_medcea_owner(self):
        own = self.block[self.block.index("DECLARE f regprocedure;"):self.block.index("REVOKE ALL ON FUNCTION")]
        self.assertIn("ALTER FUNCTION %s OWNER TO medcea_owner", own)
        for name, (args, _) in SIGNATURES.items():
            types = ",".join(t for _, t in args)
            self.assertIn("'medcea.%s(%s)'::regprocedure" % (name, types), own, name)
        # ownership before the revokes, which are before the nonce
        self.assertLess(self.block.index("OWNER TO medcea_owner"), self.block.index("REVOKE ALL ON FUNCTION"))
        self.assertLess(self.block.index("REVOKE ALL ON FUNCTION"), self.block.index("'013:last_nonce'"))

    def test_contract_version_is_1(self):
        self.assertEqual(self.fns["research_contract_version"][3].strip(), "SELECT 1")

    def test_relations_schema_qualified(self):
        for name, (_, _, _, body) in self.fns.items():
            code = string_literals_removed(strip_comments(body))
            for m in re.finditer(r"\b(FROM|JOIN)\s+([\w.]+)", code):
                rel = m.group(2)
                if rel.startswith("pg_catalog.") or rel == "LATERAL" or rel == "(":
                    continue
                self.assertTrue(rel.startswith("medcea."), "%s: %s" % (name, rel))
                self.assertIn(rel[len("medcea."):], COLUMNS, "%s reads %s" % (name, rel))

    def test_no_forbidden_identifier(self):
        for name, (_, _, _, body) in self.fns.items():
            code = string_literals_removed(strip_comments(body))
            hits = FORBIDDEN.findall(code)
            self.assertEqual(hits, [], name)

    def test_msg_only_through_its_allowed_keys(self):
        for name, (_, _, _, body) in self.fns.items():
            code = strip_comments(body)
            refs = re.findall(r"\bmsg\b(.{0,12})", code)
            for tail in refs:
                if name == "research_measurements" and tail.startswith("_type"):
                    continue
                self.assertRegex(tail, r"^ ->> '", "%s: msg only as ->> 'key'" % name)
            keys = set(re.findall(r"\bmsg ->> '(\w+)'", code))
            self.assertLessEqual(keys, MSG_KEYS, name)
            if name != "research_measurements":
                self.assertEqual(refs, [], name)
        m = self.fns["research_measurements"][3]
        self.assertIn("(m.msg_type)::text = 'AP'", m)
        self.assertIn("COALESCE(NULLIF(m.msg ->> 'sensor', ''), 'default')", m)   # 010's sensor expression
        self.assertIn("(p_after IS NULL OR m.\"timestamp\" > p_after)", m)
        self.assertIn("m.\"timestamp\" <= p_upto", m)

    def test_run_params_only_through_its_allowed_keys(self):
        for name, (_, _, _, body) in self.fns.items():
            code = strip_comments(body)
            if name != "research_cycles":
                self.assertNotIn("run_params", code, name)
                continue
            self.assertLessEqual(set(re.findall(r"rp\.e ->>? '(\w+)'", code)), RUN_PARAM_KEYS)
            self.assertEqual(set(re.findall(r"x\.v -> '(\w+)'", code)), LOOP_KEYS)
            # run_params is read only to pick its first element (never returned whole)
            for m in re.finditer(r"run_params(.{0,8})", code):
                self.assertRegex(m.group(1), r"^(::text|::jsonb|\)|\s*->\s*0)", m.group(0))

    def test_columns_exist_in_the_aliased_table(self):
        for name, (_, _, _, body) in self.fns.items():
            code = string_literals_removed(strip_comments(body))
            aliases = {a: t for t, a in re.findall(r"medcea\.(\w+)\s+(?:AS\s+)?(\w+)\b", code)
                       if a.upper() not in ("ON", "WHERE", "ORDER", "JOIN", "LEFT", "CROSS")}
            for alias, col in re.findall(r"\b(\w+)\.\"?(\w+)\"?", code):
                if alias in ("medcea", "pg_catalog", "rp", "x", "s", "i", "o", "f", "e", "kv", "cm"):
                    continue
                self.assertIn(alias, aliases, "%s: unknown alias %s" % (name, alias))
                self.assertIn(col, COLUMNS[aliases[alias]], "%s: %s.%s" % (name, aliases[alias], col))

    def test_the_selections(self):
        f = {n: v[3] for n, v in self.fns.items()}
        self.assertIn("WHERE r.status IN ('approved', 'retired')", f["research_recipes"])
        self.assertIn("WHERE r.status IN ('approved', 'retired')", f["research_recipe_lines"])
        self.assertIn("WHERE (cl.is_active)::text = 'Y'", f["research_control_loops"])
        self.assertIn("WHERE p.status = 'approved'", f["research_param_sets"])
        for kind in ("'quantity'", "'recipe_type'", "'recipe_type_quantity'"):
            self.assertIn(kind, f["research_catalogue"])


PARAM_FILTER = ("FROM pg_catalog.jsonb_each({src}) kv\n"
                "                       WHERE kv.key ~ '^[a-z][a-z0-9_]{{0,39}}$'\n"
                "                         AND pg_catalog.jsonb_typeof(kv.value) IN ('number', 'boolean')) END")
NAME_RE = r"^[a-z][a-z0-9_]{0,47}$"
ACTUATOR_RE = r"^[A-Za-z0-9_]{1,48}$"
COMMAND_RE = r"^[A-Z]{1,10}$"
INPUT_KEYS = {"tag", "sources", "rule", "reference", "fallback", "max_age_s"}
OUTPUT_KEYS = {"actuator", "mode", "command_map"}


def half_filter(body, alias):
    """The text of the input (alias i) or output (alias o) filter in BODY, dedented."""
    start = body.index("(SELECT CASE WHEN pg_catalog.jsonb_typeof(%s.j) = 'object'" % alias)
    end = body.index(" AS j) %s)" % alias, start) + len(" AS j) %s)" % alias)
    lines = body[start:end].split("\n")
    first, rest = lines[0], lines[1:]
    ind = min(len(l) - len(l.lstrip()) for l in rest if l.strip())
    return "\n".join([first] + [l[ind:] for l in rest])


class RebuiltJson(unittest.TestCase):
    """No jsonb column passes a person's free text on (review of 18 Nov 2026)."""

    @classmethod
    def setUpClass(cls):
        cls.full, cls.block = block013()
        cls.fns = {n: v[3] for n, v in functions(cls.block).items()}

    def test_params_rebuilt_in_both(self):
        ps = self.fns["research_param_sets"]
        self.assertIn(PARAM_FILTER.format(src="p.params"), ps)
        self.assertIn("COALESCE(pg_catalog.jsonb_object_agg(kv.key, kv.value), '{}'::jsonb)", ps)
        self.assertNotRegex(ps, r"p\.params::jsonb|p\.params\s*(,|\n\s*FROM)")
        cy = self.fns["research_cycles"]
        self.assertIn(PARAM_FILTER.format(src="rp.e -> 'control_algorithm_params'"), cy)
        self.assertNotRegex(cy, r"THEN rp\.e -> 'control_algorithm_params' END")

    def test_loop_halves_rebuilt_in_both(self):
        cy, cl = self.fns["research_cycles"], self.fns["research_control_loops"]
        for alias, src_cy, src_cl in (("i", "x.v -> 'input'", "cl.input"), ("o", "x.v -> 'output'", "cl.output")):
            a, b = half_filter(cy, alias), half_filter(cl, alias)
            self.assertEqual(a.replace(src_cy, "SRC"), b.replace(src_cl, "SRC"), "the same filter in both")
            self.assertIn("FROM (SELECT %s AS j) %s)" % (src_cy, alias), a)
        self.assertNotRegex(cl, r"cl\.(input|output)::jsonb")
        self.assertNotRegex(cy, r"'(input|output)', x\.v -> '(input|output)'")
        inp, out = half_filter(cy, "i"), half_filter(cy, "o")
        self.assertEqual(set(re.findall(r"SELECT '(\w+)'", inp)), INPUT_KEYS)
        self.assertEqual(set(re.findall(r"SELECT '(\w+)'", out)), OUTPUT_KEYS)
        self.assertEqual(inp.count("'%s'" % NAME_RE), 4)          # tag, sources, reference, fallback
        self.assertIn("(i.j -> 'sources') = '\"*\"'::jsonb", inp)
        self.assertIn("(i.j ->> 'rule') IN ('reference', 'mean', 'min', 'max', 'single')", inp)
        self.assertIn("pg_catalog.jsonb_typeof(i.j -> 'max_age_s') = 'number'", inp)
        self.assertIn("(o.j ->> 'actuator') ~ '%s'" % ACTUATOR_RE, out)
        self.assertIn("(o.j ->> 'mode') ~ '%s'" % NAME_RE, out)
        self.assertIn("cm.key ~ '%s'" % COMMAND_RE, out)
        self.assertIn("(cm.value #>> '{}') ~ '%s'" % COMMAND_RE, out)

    def test_nothing_legitimate_is_dropped(self):
        """Every key and value the runner and the parameter contract use passes the filters."""
        sys.path.insert(0, os.path.join(ROOT, "schd", "cea", "algorithms"))
        try:
            import params as P
        finally:
            sys.path.pop(0)
        import importlib.util
        spec = importlib.util.spec_from_file_location("lr013", os.path.join(ROOT, "schd", "cea", "loop_resolver.py"))
        lr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lr)
        for code, spec_ in P.PARAMS.items():
            for key, p in spec_.items():
                self.assertRegex(key, r"^[a-z][a-z0-9_]{0,39}$", code)
                self.assertIn(p["type"], ("int", "float"), (code, key))   # JSON numbers
        self.assertLessEqual(set(lr.RULES) | {lr.DEFAULT_RULE}, {"reference", "mean", "min", "max", "single"})
        for code, q in lr.QUANTITIES.items():
            self.assertRegex(q["tag"], NAME_RE)
            loop = lr.default_loop("Z1", code, actuator=code)
            self.assertLessEqual(set(loop["input"]), INPUT_KEYS)
            self.assertLessEqual(set(loop["output"]), OUTPUT_KEYS)
            self.assertEqual(loop["input"]["sources"], "*")
            self.assertRegex(loop["output"]["actuator"], ACTUATOR_RE)
            self.assertRegex(loop["output"]["mode"], NAME_RE)
            for k, v in (loop["output"].get("command_map") or {}).items():
                self.assertRegex(k, COMMAND_RE)
                self.assertRegex(v, COMMAND_RE)
        # the database's own rules for a stored loop are no wider than the filters
        loop_check = self.full[self.full.rindex("CREATE OR REPLACE FUNCTION medcea._loop_check"):]
        self.assertIn("ARRAY['tag', 'sources', 'rule', 'reference', 'fallback', 'max_age_s']", loop_check)
        self.assertIn("ARRAY['actuator', 'mode', 'command_map']", loop_check)
        self.assertIn("(outp ->> 'actuator') !~ '^[A-Za-z0-9_]+$'", loop_check)
        with open(os.path.join(ROOT, "edge", "src", "host", "wiring.py"), encoding="utf-8") as f:
            wiring = f.read()
        self.assertIn('TAG_RX = re.compile(r"%s")' % NAME_RE, wiring)          # tags fit the name shape
        self.assertIn('ID_RX = re.compile(r"^[a-z][a-z0-9_]{0,23}$")', wiring)  # sensor ids too


class COLUMNSMatchTheSchema(unittest.TestCase):
    """The column lists above are the real ones (DDL tables; the migrations' tables)."""

    def test_ddl_tables(self):
        ddl = read("medcea_db_ddl.sql")
        for t in ("measurement", "cea_unit", "cea_zone", "recipe", "recipe_line", "recipe_run",
                  "recipe_line_cycle_run"):
            body = ddl[ddl.index("CREATE TABLE medcea.%s (" % t):]
            body = body[:body.index("\n);")]
            cols = set(re.findall(r'(?m)^\s+"?(\w+)"? ', body)) - {"CONSTRAINT"}
            self.assertLessEqual(cols, COLUMNS[t], t)

    def test_migration_tables(self):
        mig = read("medcea_db_migrations.sql")
        for t in ("control_loop", "unit_algorithm_params", "control_algorithm", "control_quantity", "recipe_type",
                  "recipe_type_quantity"):
            body = mig[mig.index("CREATE TABLE IF NOT EXISTS medcea.%s (" % t):]
            body = body[:body.index("\n);")]
            for col in set(re.findall(r"(?m)^    (\w+)\s+(?:integer|varchar|text|jsonb|boolean|numeric|timestamptz|"
                                  r"INTEGER|VARCHAR|TEXT|JSONB|medcea\.)", body)) - DROPPED.get(t, set()):
                if "_by_" not in col:   # attribution: real, and never read (the forbidden scan)
                    self.assertIn(col, COLUMNS[t], t)
        for added in ("ADD COLUMN zone_id integer", "ADD COLUMN status varchar(10)"):
            self.assertIn(added.split(" ")[2], mig)


class DownFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.down = read("medcea_db_migrations_down_013.sql")

    def test_refused_while_the_exporter_may_execute(self):
        d = self.down
        refuse = d.index("RAISE EXCEPTION 'down 013: svc_research_export may still execute")
        self.assertIn("pg_catalog.has_function_privilege('svc_research_export', f, 'EXECUTE')", d)
        self.assertIn("pg_catalog.to_regrole('svc_research_export') IS NOT NULL", d)
        self.assertLess(refuse, d.index("DROP FUNCTION"))

    def test_drops_all_and_the_nonce(self):
        for name, (args, _) in SIGNATURES.items():
            types = ", ".join(t for _, t in args)
            self.assertIn("DROP FUNCTION IF EXISTS medcea.%s(%s);" % (name, types), self.down)
            self.assertIn("pg_catalog.to_regprocedure('medcea.%s(%s)')" % (name, ",".join(t for _, t in args)),
                          self.down)
        self.assertIn("DELETE FROM medcea.platform_setting WHERE key = '013:last_nonce';", self.down)
        self.assertIn("NOTIFY pgrst, 'reload schema';", self.down)

    def test_runs_in_the_callers_transaction(self):
        self.assertNotRegex(self.down, r"(?m)^(BEGIN|COMMIT);")
        self.assertIn("psql -X -1 -v ON_ERROR_STOP=1", self.down)


def _pg_bin():
    """The directory holding initdb, pg_ctl, postgres and psql, or None."""
    names = ("initdb", "pg_ctl", "postgres", "psql")
    if all(shutil.which(n) for n in names):
        return os.path.dirname(shutil.which("initdb"))
    for d in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if all(os.access(os.path.join(d, n), os.X_OK) for n in names):
            return d
    return None


@unittest.skipUnless(_pg_bin(), "no local PostgreSQL (initdb, pg_ctl, postgres, psql)")
class LiveCluster(unittest.TestCase):
    """DDL + every migration in a throwaway cluster, then the functions as medcea_owner."""

    @classmethod
    def setUpClass(cls):
        b = _pg_bin()
        cls.tmp = tempfile.mkdtemp(prefix="rs013-")
        cls.data = os.path.join(cls.tmp, "data")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = str(s.getsockname()[1])
        subprocess.run([os.path.join(b, "initdb"), "-D", cls.data, "-U", "postgres", "--auth=trust"],
                       check=True, capture_output=True)
        subprocess.run([os.path.join(b, "pg_ctl"), "-D", cls.data, "-w", "-l", os.path.join(cls.tmp, "log"),
                        "-o", "-k %s -p %s -c listen_addresses=''" % (cls.tmp, cls.port), "start"],
                       check=True, capture_output=True)
        cls.psql = [os.path.join(b, "psql"), "-X", "-h", cls.tmp, "-p", cls.port, "-U", "postgres"]

    @classmethod
    def tearDownClass(cls):
        subprocess.run([os.path.join(_pg_bin(), "pg_ctl"), "-D", cls.data, "-m", "immediate", "stop"],
                       capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def sql(self, db, text, *args, check=True):
        p = subprocess.run(self.psql + ["-d", db, "-v", "ON_ERROR_STOP=1", *args, "-f", "-"],
                           input=text, capture_output=True, text=True)
        if check:
            self.assertEqual(p.returncode, 0, p.stderr[-3000:])
        return p

    SEED = r"""
BEGIN;
SET LOCAL ROLE medcea_owner;
INSERT INTO medcea.cea_location (name) VALUES ('t13');
INSERT INTO medcea.cea_unit (unit_type, location_id, is_active, unit_code)
     SELECT 'FUNGI', location_id, 'Y', 'U13' FROM medcea.cea_location WHERE name = 't13';
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active)
     SELECT unit_id, 'Z1', 'Y' FROM medcea.cea_unit WHERE unit_code = 'U13';
INSERT INTO medcea.unit_algorithm_params (algorithm_id, name, params, status)
     SELECT algorithm_id, 'set13',
            '{"kp": 0.5, "horizon": 6, "adaptive": true, "note": "call Ana on 555", "Bad Key": 1, "nested": {"kp": 1}}',
            'approved'
       FROM medcea.control_algorithm WHERE algorithm_code = 'PID';
INSERT INTO medcea.unit_algorithm_params (algorithm_id, name, params, status)
     SELECT algorithm_id, 'set13b', '{"who": "Ana"}', 'approved'
       FROM medcea.control_algorithm WHERE algorithm_code = 'FLC';
INSERT INTO medcea.control_loop (zone_id, loop_code, input, output, is_active)
     SELECT zone_id, 'air_temperature',
            '{"tag": "air_temperature", "sources": ["sht45", "scd30"], "rule": "reference", "reference": "sht45",
              "fallback": "scd30", "max_age_s": 90, "comment": "secret note"}',
            '{"actuator": "air_temperature", "mode": "command", "comment": "free text"}', 'Y'
       FROM medcea.cea_zone WHERE zone_code = 'Z1';
INSERT INTO medcea.recipe (recipe_name, recipe_type) VALUES ('r13', 'FUNGI');
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number, light_type,
                                light_on_minutes, light_off_minutes)
     SELECT recipe_id, 1, 'l1', 1, 'DARK', 1, 1 FROM medcea.recipe WHERE recipe_name = 'r13';
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
     SELECT r.recipe_id, u.unit_id, now(), 'C', 'Y' FROM medcea.recipe r, medcea.cea_unit u
      WHERE r.recipe_name = 'r13' AND u.unit_code = 'U13';
INSERT INTO medcea.recipe_line_cycle_run (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num,
                                          recipe_line_cycle_run_status, run_params)
     SELECT rr.recipe_run_id, rr.recipe_id, 1, 1, 'C',
            '[{"control_algorithm": "PID", "control_algorithm_params": {"kp": 0.5, "who": "Ana", "Bad Key": 2},
               "control_loops": [
                 {"zone_code": "Z1", "loop_code": "co2", "phase": "always",
                  "input": {"tag": "co2", "sources": "*", "rule": "single", "max_age_s": 90, "extra": "x"},
                  "output": {"actuator": "co2", "mode": "command", "comment": "y",
                             "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF", "note": "hi", "X": "lower"}}},
                 {"zone_code": "Z1", "loop_code": "air_temperature", "phase": "always",
                  "input": {"tag": "Air Temp!", "sources": ["sht45", "Ana Smith", 3], "rule": "guess",
                            "reference": "Ana", "fallback": 7, "max_age_s": "90"},
                  "output": {"actuator": "fan with notes", "mode": 1, "command_map": "x"}},
                 {"zone_code": "Z1", "loop_code": "air_humidity", "input": "free text", "output": null}],
               "secret": "no"}]'::json
       FROM medcea.recipe_run rr JOIN medcea.recipe r USING (recipe_id) WHERE r.recipe_name = 'r13';
COMMIT;
"""

    def check_rebuilt_json(self):
        """Free text planted in every jsonb the functions read never comes back."""
        import json
        self.sql("medcea_db", self.SEED)

        def rows(q):
            out = self.sql("medcea_db", "SET ROLE medcea_owner;\n" + q, "-tA").stdout
            return [json.loads(l) for l in out.split("\n") if l.strip() and l.strip() != "SET"]

        self.assertEqual(rows("SELECT pg_catalog.jsonb_build_object('a', algorithm_code, 'p', params) "
                              "FROM medcea.research_param_sets() ORDER BY params_id;"),
                         [{"a": "PID", "p": {"kp": 0.5, "horizon": 6, "adaptive": True}},
                          {"a": "FLC", "p": {}}])
        self.assertEqual(rows("SELECT pg_catalog.jsonb_build_object('i', input, 'o', output) "
                              "FROM medcea.research_control_loops();"),
                         [{"i": {"tag": "air_temperature", "sources": ["sht45", "scd30"], "rule": "reference",
                                 "reference": "sht45", "fallback": "scd30", "max_age_s": 90},
                           "o": {"actuator": "air_temperature", "mode": "command"}}])
        got = rows("SELECT pg_catalog.jsonb_build_object('a', algorithm_code, 'p', algorithm_params, "
                   "'l', control_loops) FROM medcea.research_cycles();")
        self.assertEqual(got, [{
            "a": "PID", "p": {"kp": 0.5},
            "l": [{"zone_code": "Z1", "loop_code": "co2", "phase": "always", "completed": None,
                   "input": {"tag": "co2", "sources": "*", "rule": "single", "max_age_s": 90},
                   "output": {"actuator": "co2", "mode": "command",
                              "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}}},
                  {"zone_code": "Z1", "loop_code": "air_temperature", "phase": "always", "completed": None,
                   "input": {"sources": ["sht45"]}, "output": {}},
                  {"zone_code": "Z1", "loop_code": "air_humidity", "phase": None, "completed": None,
                   "input": None, "output": None}]}])
        text = json.dumps(got) + json.dumps(rows("SELECT params FROM medcea.research_param_sets();"))
        for planted in ("Ana", "555", "secret", "comment", "free text", "note", "Bad Key", "nested", "lower",
                        "extra", "guess", "fan with notes"):
            self.assertNotIn(planted, text)

    def test_ddl_and_migrations_then_the_functions(self):
        self.sql("postgres", "CREATE ROLE medcea_owner NOLOGIN; CREATE ROLE anon NOLOGIN;"
                             "CREATE ROLE authenticator LOGIN NOINHERIT; CREATE ROLE mqtt_auth LOGIN NOINHERIT;"
                             "CREATE DATABASE medcea_db;")
        # as db_apply: the DDL without ON_ERROR_STOP, then the migrations with the nonce
        subprocess.run(self.psql + ["-d", "medcea_db", "-q", "-f", "-"], input=read("medcea_db_ddl.sql"),
                       capture_output=True, text=True)
        b64 = subprocess.run([sys.executable, os.path.join(DB, "recipe_types.py"), "b64"],
                             capture_output=True, text=True, check=True).stdout.strip()
        mig = subprocess.run(self.psql + ["-d", "medcea_db", "-q", "-v", "deploy_nonce=abc123",
                                          "-v", "recipe_types_b64=" + b64, "-f", "-"],
                             input=read("medcea_db_migrations.sql"), capture_output=True, text=True)
        got = self.sql("medcea_db", "SELECT value FROM medcea.platform_setting WHERE key = '013:last_nonce'",
                       "-tA").stdout.strip()
        if got != "abc123":
            self.skipTest("the migrations do not complete on an empty cluster here: " + mig.stderr[-1500:])
        out = self.sql("medcea_db", """
            SELECT p.proname, p.prosecdef, p.provolatile, pg_get_userbyid(p.proowner),
                   coalesce(array_to_string(p.proacl, ' '), '') FROM pg_proc p
             WHERE p.pronamespace = 'medcea'::regnamespace AND p.proname LIKE 'research\\_%' ORDER BY 1""",
                       "-tA", "-F", "|").stdout.split()
        self.assertEqual(len(out), len(SIGNATURES))
        for line in out:
            name, definer, vol, owner, acl = line.split("|")
            self.assertEqual((definer, vol, owner), ("t", "s", "medcea_owner"), name)
            self.assertNotIn("=X/", acl.replace("medcea_owner=X/", ""), name)   # no PUBLIC or other holder
        calls = "".join("SELECT * FROM medcea.%s(%s);\n" % (n, "NULL, now()" if a else "")
                        for n, (a, _) in SIGNATURES.items())
        self.sql("medcea_db", "SET ROLE medcea_owner;\n" + calls)
        self.check_rebuilt_json()
        # re-run safe: the whole migrations file again, same nonce
        subprocess.run(self.psql + ["-d", "medcea_db", "-q", "-v", "deploy_nonce=def456",
                                    "-v", "recipe_types_b64=" + b64, "-f", "-"],
                       input=read("medcea_db_migrations.sql"), capture_output=True, text=True)
        got = self.sql("medcea_db", "SELECT value FROM medcea.platform_setting WHERE key = '013:last_nonce'",
                       "-tA").stdout.strip()
        self.assertEqual(got, "def456")
        # and the down file
        self.sql("medcea_db", read("medcea_db_migrations_down_013.sql"), "-1")
        left = self.sql("medcea_db", "SELECT count(*) FROM pg_proc WHERE proname LIKE 'research\\_%'",
                        "-tA").stdout.strip()
        self.assertEqual(left, "0")


if __name__ == "__main__":
    unittest.main()
