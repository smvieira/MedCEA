#!/usr/bin/env python3
"""tests/test_research_db.py — the research sandbox's own database (Phase 2a, apps/research/).

Offline (stdlib unittest):
  Sql        the DDL and grants as text: the staging tables have exactly the columns of
             migration 013's read functions (the interface); every lake table but the
             staging ones, and vault.reservation, is append-only through ENABLE ALWAYS
             triggers; every SECURITY DEFINER function pins its search_path and loses
             PUBLIC's EXECUTE; grants.sql grants exactly what the interface says.
  LakeApiSql db/lake_api.sql as text (Phase 2b): the two roles and rs_lake_api's three
             settings and connection limit, every lake_api function STABLE, SECURITY
             DEFINER, search_path pg_catalog, pg_temp, PUBLIC's EXECUTE revoked; no column
             that names a person; measurements reads snapshot_id <= the snapshot and
             refuses (22023) what it must; holds() only ranges; the lineage rule; the
             digest check uses _set_digest's text rules; the asserts cover the reader.
  Deploy     apps/research/deploy.sh and uninstall.sh in a scratch tree against a fake
             kubectl/helm, policy source and cli.py: the unknown-option refusal, each
             skip line, the full path in order, no secret in any argv (the fakes log argv),
             passwords only as SCRAM verifiers, the grant check failing the deploy.
  Reserve    apps/research/reserve.sh: argument checks before the log and lock, list,
             add against a fake Keycloak (curl) and psql: --by enabled with qa, refused
             otherwise, the typed confirmation.
  Chart      the values keys exist in bitnamicharts/postgresql 18.4.0's own values.yaml at
             the paths used (the cached chart; skipped without it), and `helm template`
             renders no NetworkPolicy with them (skipped without helm)
  RealPostgres  the DDL, grants, close_snapshot, the reservation and the append-only
             refusals on a throwaway PostgreSQL, when initdb/pg_ctl/psql are found
             (PATH, or MEDCEA_TEST_PG_BIN; MEDCEA_TEST_PG_SHARE for initdb -L); skipped
             otherwise.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import REPO, clean_env, scratch_repo  # noqa: E402

APP = os.path.join(REPO, "apps", "research")
DDL = os.path.join(APP, "db", "medcea_research_ddl.sql")
GRANTS = os.path.join(APP, "db", "grants.sql")
ASSERT = os.path.join(APP, "db", "assert_grants.sql")
LAKE_API = os.path.join(APP, "db", "lake_api.sql")

# The interface (INTERFACES.md, migration 013): function → columns and types.
STAGES = {
    "measurements": [("ingested_at", "timestamptz"), ("measured_at", "timestamptz"), ("unit_code", "text"),
                     ("zone_code", "text"), ("tag", "text"), ("sensor", "text"), ("value", "numeric"),
                     ("uom", "text")],
    "units": [("unit_code", "text"), ("recipe_type", "text"), ("area", "numeric"), ("height", "numeric"),
              ("is_active", "text")],
    "zones": [("unit_code", "text"), ("zone_code", "text"), ("is_active", "text")],
    "recipes": [("recipe_id", "integer"), ("recipe_type", "text"), ("status", "text")],
    "recipe_lines": [("recipe_id", "integer"), ("seq", "integer"), ("cycle_number", "integer"),
                     ("light_type", "text"), ("light_on_minutes", "integer"), ("light_off_minutes", "integer"),
                     ("setpoints", "jsonb")],
    "runs": [("run_id", "integer"), ("recipe_id", "integer"), ("unit_code", "text"),
             ("started_at", "timestamptz"), ("ended_at", "timestamptz"), ("status", "text")],
    "cycles": [("run_id", "integer"), ("seq", "integer"), ("cycle_num", "integer"),
               ("started_at", "timestamptz"), ("ended_at", "timestamptz"), ("status", "text"),
               ("algorithm_code", "text"), ("algorithm_params", "jsonb"), ("control_loops", "jsonb")],
    "control_loops": [("unit_code", "text"), ("zone_code", "text"), ("loop_code", "text"), ("input", "jsonb"),
                      ("output", "jsonb")],
    "param_sets": [("params_id", "integer"), ("algorithm_code", "text"), ("unit_code", "text"),
                   ("params", "jsonb")],
    "catalogue": [("kind", "text"), ("code", "text"), ("doc", "jsonb")],
}
LAKE = {"measurements": "measurement"}   # every other set keeps its name
APPEND_ONLY = ["lake.snapshot"] + ["lake." + LAKE.get(s, s) for s in STAGES] + ["vault.reservation"]

SECRETS = {"RESEARCH_DB_PASS": "rsSuperPass0123456789", "RS_EXPORT_WRITER_DB_PASS": "rsWriterPass0123456789",
           "RS_BACKUP_DB_PASS": "rsBackupPass0123456789", "RS_LAKE_API_DB_PASS": "rsLakeApiPass0123456789",
           "RS_SESSION_DB_PASS": "rsSessionPass0123456789"}
DOCKERHUB = {"DOCKERHUB_USER": "someone", "DOCKERHUB_PAT": "dckr_pat_SECRET0123456789"}
KC_SECRET = "kcDeployerSecret0123456789"


def read(p):
    with open(p) as f:
        return f.read()


def sql_code(text):
    return "\n".join(l.split("--", 1)[0] for l in text.splitlines())


def functions(text):
    """(name, header) of every CREATE OR REPLACE FUNCTION: the header up to the body's $$."""
    out = []
    for m in re.finditer(r"CREATE OR REPLACE FUNCTION ([a-z_]+\.[a-z_]+)\((.*?)\$\$", text, re.S):
        out.append((m.group(1), m.group(0)))
    return out


class Sql(unittest.TestCase):
    def setUp(self):
        self.ddl = sql_code(read(DDL))
        self.grants = sql_code(read(GRANTS))

    def test_stage_tables_are_the_interface(self):
        for name, cols in STAGES.items():
            m = re.search(r"CREATE TABLE IF NOT EXISTS lake\.stage_%s \((.*?)\);" % name, self.ddl, re.S)
            self.assertIsNotNone(m, name)
            got = [tuple(c.split()) for c in " ".join(m.group(1).split()).split(", ")]
            self.assertEqual(got, cols, name)

    def test_lake_tables_copy_the_stage_tables(self):
        for name in STAGES:
            lake = LAKE.get(name, name)
            self.assertRegex(self.ddl, r"CREATE TABLE IF NOT EXISTS lake\.%s \(\s*snapshot_id bigint NOT NULL "
                                       r"REFERENCES lake\.snapshot \(snapshot_id\), LIKE lake\.stage_%s\);" % (lake, name))

    def test_append_only_everywhere_but_staging(self):
        m = re.search(r"FOREACH t IN ARRAY ARRAY\[('lake\.snapshot'.*?)\] LOOP(.*?)END LOOP", self.ddl, re.S)
        self.assertIsNotNone(m)
        listed = re.findall(r"'([a-z_.]+)'", m.group(1))
        self.assertEqual(sorted(listed), sorted(APPEND_ONLY))
        self.assertFalse([t for t in listed if ".stage_" in t])
        body = m.group(2)
        self.assertIn("BEFORE UPDATE OR DELETE ON %s", body)
        self.assertIn("FOR EACH ROW EXECUTE FUNCTION lake.refuse_change()", body)
        self.assertIn("BEFORE TRUNCATE ON %s", body)
        self.assertIn("ENABLE ALWAYS TRIGGER append_only_row", body)
        self.assertIn("ENABLE ALWAYS TRIGGER append_only_truncate", body)
        refuse = self.ddl[self.ddl.index("CREATE OR REPLACE FUNCTION lake.refuse_change()"):]
        self.assertIn("RAISE EXCEPTION", refuse[:refuse.index("END $$")])
        # no lake table is created without being in the list
        made = set(re.findall(r"CREATE TABLE IF NOT EXISTS ((?:lake|vault)\.[a-z_]+)", self.ddl))
        self.assertEqual({t for t in made if ".stage_" not in t}, set(APPEND_ONLY))

    def test_definer_functions_pin_search_path_and_revoke_public(self):
        fns = functions(self.ddl)
        names = {n for n, _ in fns}
        self.assertTrue({"lake.latest_cut", "lake.close_snapshot", "vault.reserve", "vault.reserved_rows_in",
                         "lake._set_digest", "lake.refuse_change"} <= names, names)
        for name, header in fns:
            self.assertIn("SET search_path = pg_catalog", header, name)
            self.assertRegex(self.ddl, r"REVOKE ALL ON FUNCTION %s\([^)]*\) FROM PUBLIC;" % re.escape(name), name)
            if name != "lake.refuse_change":
                self.assertIn("SECURITY DEFINER", header, name)
        self.assertIn("SET TimeZone = 'UTC'", dict(fns)["lake.close_snapshot"])   # stable digests
        # the digest pins its own row text form, whoever calls it
        self.assertIn("SET TimeZone = 'UTC' SET DateStyle = 'ISO, YMD'", dict(fns)["lake._set_digest"])
        self.assertIn("ALTER DEFAULT PRIVILEGES FOR ROLE rs_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", self.ddl)
        # created as rs_owner (owns everything), back to postgres at the end
        self.assertLess(self.ddl.index("SET ROLE rs_owner;"), self.ddl.index("CREATE TABLE"))
        self.assertTrue(self.ddl.rstrip().endswith("RESET ROLE;"))

    def test_the_measurement_digest_is_bounded(self):
        # no one string_agg over every staged measurement: a first export or a backlog would
        # need it all in memory at once (the pod has 2Gi); one hour of ingest at a time
        body = self.ddl[self.ddl.index("FUNCTION lake._set_digest"):]
        body = body[:body.index("END $$")]
        meas = body[body.index("IF p_stage = 'stage_measurements' THEN"):body.index("RETURN;")]
        self.assertIn("FOR h IN SELECT pg_catalog.date_trunc('hour', m.ingested_at) AS hour, pg_catalog.count(*) AS c",
                      meas)
        self.assertIn("GROUP BY 1 ORDER BY 1 NULLS LAST LOOP", meas)
        self.assertIn("x.ingested_at >= h.hour AND x.ingested_at < h.hour + interval '1 hour'", meas)
        self.assertIn("ORDER BY x::text COLLATE \"C\"", meas)
        self.assertIn("pg_catalog.to_char(h.hour, 'YYYY-MM-DD\"T\"HH24\":00:00Z\"')", meas)
        self.assertIn("|| '|' || h.c::text || '|' || hd", meas)
        self.assertIn("pg_catalog.array_to_string(lines, E'\\n')", meas)
        self.assertEqual(meas.count("string_agg"), 1)   # inside the hour's SELECT only
        # the general path (EXECUTE format over any stage table) is never reached for measurements
        self.assertLess(body.index("RETURN;"), body.index("EXECUTE pg_catalog.format("))
        self.assertIn("CREATE INDEX IF NOT EXISTS stage_measurements_ingested_at_idx ON lake.stage_measurements "
                      "(ingested_at);", self.ddl)
        # the definition is written down where the function is
        raw = read(DDL)
        head = raw[raw.index("-- _set_digest(stage table)"):raw.index("FUNCTION lake._set_digest")]
        self.assertIn("<H as YYYY-MM-DDTHH:00:00Z>|<rows in H>|<sha256 hex", head)

    def test_refusals_are_the_interfaces(self):
        cs = self.ddl[self.ddl.index("FUNCTION lake.close_snapshot"):]
        cs = cs[:cs.index("END $$")]
        self.assertIn("ARRAY[1]", cs)
        self.assertIn("p_previous IS DISTINCT FROM v_latest", cs)
        self.assertEqual(cs.count("ERRCODE = '22023'"), cs.count("RAISE EXCEPTION"))
        self.assertIn("pg_advisory_xact_lock", cs)
        rs = self.ddl[self.ddl.index("FUNCTION vault.reserve"):]
        rs = rs[:rs.index("END $$")]
        self.assertIn("already exported: it is no longer held out", rs)
        self.assertIn("'^[A-Za-z0-9_-]+$'", rs)
        self.assertIn("< 10", rs)
        self.assertIn("p_to <= p_from", rs)
        self.assertIn("pg_advisory_xact_lock", rs)   # the same lock as close_snapshot
        self.assertEqual(rs.count("ERRCODE = '22023'"), rs.count("RAISE EXCEPTION"))

    def test_roles_and_schemas(self):
        self.assertIn("CREATE ROLE rs_owner NOLOGIN", self.ddl)
        self.assertRegex(self.ddl, r"ALTER ROLE rs_owner\s+NOLOGIN")
        for s in ("lake", "vault", "sim", "agent_trace", "registry"):
            self.assertRegex(self.ddl, r"CREATE SCHEMA IF NOT EXISTS %s\s+AUTHORIZATION rs_owner;" % s)
        self.assertIn("CREATE DATABASE medcea_research OWNER rs_owner", self.ddl)
        self.assertIn("\\connect medcea_research", self.ddl)

    def test_grants_exactly(self):
        grants = [" ".join(g.split()) for g in re.findall(r"\bGRANT\b.*?;", self.grants, re.S)]
        stage = ", ".join("lake.stage_" + s for s in STAGES)
        self.assertEqual(grants, [
            "GRANT CONNECT ON DATABASE medcea_research TO rs_export_writer, rs_backup;",
            "GRANT CONNECT ON DATABASE medcea_research TO rs_lake_api;",
            "GRANT CONNECT ON DATABASE medcea_research TO rs_session;",
            "GRANT USAGE ON SCHEMA lake TO rs_export_writer;",
            "GRANT INSERT ON %s TO rs_export_writer;" % stage,
            "GRANT EXECUTE ON FUNCTION lake.close_snapshot(timestamptz, timestamptz, integer), lake.latest_cut() "
            "TO rs_export_writer;",
            "GRANT pg_read_all_data TO rs_backup;",
            "GRANT USAGE ON SCHEMA lake_api TO rs_lake_reader;",
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA lake_api TO rs_lake_reader;",
            "GRANT rs_lake_reader TO rs_lake_api;",
            "GRANT USAGE ON SCHEMA agent_trace TO rs_session;",
            "GRANT EXECUTE ON FUNCTION agent_trace.open_session(text, text, text, text, uuid, text, text, text, text, "
            "text, text[], jsonb, text, text, timestamptz), agent_trace.append_event(text, text, text, text, jsonb, "
            "text), agent_trace.put_blob(text, text, bytea), agent_trace.checkpoint(text, jsonb), "
            "agent_trace.use_claim(text, inet), agent_trace.revoke(text, text, uuid), "
            "agent_trace.session_status(text), agent_trace.events(text, bigint) TO rs_session;"])
        self.assertNotRegex(self.grants, r"TO\s+PUBLIC")
        flat = " ".join(self.grants.split())
        for line in ("REVOKE ALL ON DATABASE medcea_research FROM PUBLIC;",
                     "REVOKE ALL ON DATABASE medcea_research FROM rs_export_writer, rs_backup, rs_lake_api, "
                     "rs_lake_reader, rs_session;",
                     "REVOKE ALL ON SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api FROM PUBLIC, "
                     "rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;"):
            self.assertIn(line, flat)
        for kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
            self.assertIn("REVOKE ALL ON ALL %s IN SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api "
                          "FROM PUBLIC, rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;" % kind, flat)
        self.assertNotRegex(self.ddl, r"\bGRANT\b")   # the DDL grants nothing
        self.assertNotRegex(sql_code(read(LAKE_API)), r"\bGRANT\b")   # nor lake_api.sql
        # only the reader's schema and its functions; the lake's own grant lines are unchanged
        self.assertLess(self.grants.index("GRANT pg_read_all_data TO rs_backup;"),
                        self.grants.index("GRANT USAGE ON SCHEMA lake_api TO rs_lake_reader;"))

    def test_assert_is_read_only(self):
        a = re.sub(r"'[^']*'", "''", sql_code(read(ASSERT)))
        self.assertIn("BEGIN READ ONLY;", a)
        self.assertNotRegex(a, r"\b(INSERT|UPDATE|DELETE|GRANT|REVOKE|ALTER|CREATE|DROP)\b")



# The reader's interface (S4 of the Phase 2b spec): function → (arguments, columns).
LAKE_API_FUNCTIONS = {
    "lake_api.snapshots": ("", ["snapshot_id", "cut_at", "previous_cut_at", "created_at", "contract_version",
                                '"rows"', "digests", "lineage"]),
    "lake_api.measurements": ("p_snapshot bigint, p_unit text, p_zone text, p_tag text DEFAULT NULL, "
                              "p_from timestamptz DEFAULT NULL, p_to timestamptz DEFAULT NULL, "
                              "p_sensor text DEFAULT NULL, p_limit integer DEFAULT 50000",
                              ["snapshot_id", "ingested_at", "measured_at", "unit_code", "zone_code", "tag",
                               "sensor", "value", "uom"]),
    "lake_api.units": ("p_snapshot bigint", ["snapshot_id", "unit_code", "recipe_type", "area", "height", "is_active"]),
    "lake_api.zones": ("p_snapshot bigint", ["snapshot_id", "unit_code", "zone_code", "is_active"]),
    "lake_api.recipes": ("p_snapshot bigint", ["snapshot_id", "recipe_id", "recipe_type", "status"]),
    "lake_api.recipe_lines": ("p_snapshot bigint", ["snapshot_id", "recipe_id", "seq", "cycle_number", "light_type",
                                                    "light_on_minutes", "light_off_minutes", "setpoints"]),
    "lake_api.catalogue": ("p_snapshot bigint", ["snapshot_id", "kind", "code", "doc"]),
    "lake_api.holds": ("", ["unit_code", "zone_code", "from_at", "to_at"]),
}
# Words that would name a person (decision P): no column, parameter or reference of the reader.
PERSON_WORDS = ("by_username", "by_sub", "reason", "username", "email", "person", "created_by", "updated_by",
                "executed_by", "description", "note", "name", "ip_address", "mac", "serial", "device")


def lineage(measurement_digests):
    """The lineage rule, written once more from the spec: L_0 = '',
    L_N = sha256_hex(L_{N-1} + '\n' + digests.measurement)."""
    out, prev = [], ""
    for d in measurement_digests:
        prev = hashlib.sha256((prev + "\n" + d).encode()).hexdigest()
        out.append(prev)
    return out


class LakeApiSql(unittest.TestCase):
    def setUp(self):
        self.raw = read(LAKE_API)
        self.sql = sql_code(self.raw)
        self.fns = dict(functions(self.sql))

    def body(self, name):
        h = self.fns[name]
        rest = self.sql[self.sql.index(h) + len(h):]
        return rest[:rest.index("$$")]

    def test_roles_and_settings(self):
        self.assertIn("CREATE ROLE rs_lake_reader NOLOGIN NOINHERIT;", self.sql)
        self.assertIn("CREATE ROLE rs_lake_api LOGIN NOINHERIT;", self.sql)
        flat = " ".join(self.sql.split())
        self.assertIn("ALTER ROLE rs_lake_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION "
                      "NOBYPASSRLS;", flat)
        self.assertIn("ALTER ROLE rs_lake_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION "
                      "NOBYPASSRLS CONNECTION LIMIT 10;", flat)
        for setting in ("statement_timeout = '30s'", "default_transaction_read_only = on", "temp_file_limit = '256MB'"):
            self.assertIn("ALTER ROLE rs_lake_api SET %s;" % setting, self.sql)
        # and what the asserts look for is exactly how PostgreSQL stores them
        assert_sql = read(ASSERT)
        for stored in ("statement_timeout=30s", "default_transaction_read_only=on", "temp_file_limit=256MB"):
            self.assertIn("'%s'" % stored, assert_sql)
        self.assertNotRegex(self.sql, r"\bPASSWORD\b")   # deploy.sh sets it, as a SCRAM verifier

    def test_schema_owned_and_made_by_rs_owner(self):
        self.assertIn("CREATE SCHEMA IF NOT EXISTS lake_api AUTHORIZATION rs_owner;", self.sql)
        self.assertIn("ALTER SCHEMA lake_api OWNER TO rs_owner;", self.sql)
        self.assertLess(self.sql.index("SET ROLE rs_owner;"), self.sql.index("CREATE OR REPLACE FUNCTION"))
        self.assertTrue(self.sql.rstrip().endswith("RESET ROLE;"))
        self.assertNotIn("\\connect", self.sql)   # deploy.sh connects it to medcea_research

    def test_the_interface(self):
        got = {n: h for n, h in self.fns.items() if n.startswith("lake_api.")}
        self.assertEqual(set(got), set(LAKE_API_FUNCTIONS))
        for name, (args, cols) in LAKE_API_FUNCTIONS.items():
            with self.subTest(name):
                h = " ".join(got[name].split())
                self.assertIn("FUNCTION %s(%s)" % (name, args), h)
                m = re.search(r"RETURNS TABLE \((.*?)\) LANGUAGE", h)
                self.assertEqual([c.split()[0] for c in m.group(1).split(", ")], cols)
        # runs, cycles, control loops and parameter sets are not exposed (O3)
        for t in ("lake.runs", "lake.cycles", "lake.control_loops", "lake.param_sets"):
            self.assertNotIn(t, self.sql)

    def test_every_function_is_a_pinned_stable_definer(self):
        for name, header in self.fns.items():
            with self.subTest(name):
                h = " ".join(header.split())
                self.assertIn("STABLE SECURITY DEFINER", h)
                self.assertIn("SET search_path = pg_catalog, pg_temp", h)
                self.assertRegex(self.sql, r"REVOKE ALL ON FUNCTION %s\([^)]*\) FROM PUBLIC;" % re.escape(name))
                body = self.body(name)
                # every relation qualified: lake., vault. or pg_catalog. only
                for rel in re.findall(r"(?<!DISTINCT )\b(?:FROM|JOIN)\s+([a-z_][a-z_.]*)", body):
                    if rel in ("o", "chain", "lake", "vault"):
                        continue
                    self.assertRegex(rel, r"^(lake|vault|pg_catalog)\.", (name, rel))

    def test_no_person(self):
        code = re.sub(r"'[^']*'", "''", self.sql)   # messages may say anything
        for w in PERSON_WORDS:
            self.assertNotRegex(code, r"\b%s\b" % w, w)
        holds = self.body("lake_api.holds")
        self.assertIn("SELECT r.unit_code, r.zone_code, r.from_at, r.to_at", holds)

    def test_measurements(self):
        b = self.body("lake_api.measurements")
        self.assertIn("m.snapshot_id <= p_snapshot", b)
        self.assertIn("pg_catalog.lower(m.unit_code) = pg_catalog.lower(p_unit)", b)   # the index
        self.assertIn("pg_catalog.lower(m.zone_code) = pg_catalog.lower(p_zone)", b)
        self.assertIn("(p_from IS NULL OR m.measured_at > p_from)", b)
        self.assertIn("(p_to IS NULL OR m.measured_at <= p_to)", b)
        self.assertIn("ORDER BY m.measured_at DESC", b)
        self.assertIn("LIMIT p_limit", b)
        self.assertEqual(b.count("RAISE EXCEPTION"), 3)
        self.assertEqual(b.count("ERRCODE = '22023'"), 3)
        self.assertIn("RAISE EXCEPTION 'no snapshot %'", b)
        self.assertIn("p_limit < 1 OR p_limit > 50000", b)
        self.assertIn("p_unit IS NULL OR p_zone IS NULL", b)
        # the index it relies on
        self.assertIn("ON lake.measurement (pg_catalog.lower(unit_code), pg_catalog.lower(zone_code), measured_at)",
                      read(DDL))

    def test_small_sets_read_exactly_one_snapshot(self):
        for n in ("units", "zones", "recipes", "recipe_lines", "catalogue"):
            b = self.body("lake_api." + n)
            self.assertRegex(b, r"FROM lake\.%s [a-z] WHERE [a-z]\.snapshot_id = p_snapshot" % n, n)

    def test_lineage(self):
        b = self.body("lake_api.snapshots")
        self.assertIn("WITH RECURSIVE", b)
        self.assertIn("pg_catalog.row_number() OVER (ORDER BY s.snapshot_id)", b)
        self.assertIn("coalesce(s.digests ->> 'measurement', '') AS md", b)
        self.assertIn("pg_catalog.convert_to('' || E'\\n' || o.md, 'UTF8')", b)          # L_0 = ''
        self.assertIn("pg_catalog.convert_to(chain.lin || E'\\n' || o.md, 'UTF8')", b)   # L_N
        self.assertIn("ORDER BY s.snapshot_id", b)
        self.assertIn("L_N = hex(sha256(utf8(L_{N-1} || E'\\n' || digests->>'measurement')))", self.raw)
        # the notebook helper recomputes it with the same rule
        sys.path.insert(0, os.path.join(REPO, "k8s", "workbench", "examples"))
        import medcea_data
        rows = [{"snapshot_id": 3, "digests": {"measurement": "c" * 64}},
                {"snapshot_id": 1, "digests": {"measurement": hashlib.sha256(b"").hexdigest()}},
                {"snapshot_id": 2, "digests": {"measurement": "b" * 64}}]
        want = lineage([hashlib.sha256(b"").hexdigest(), "b" * 64, "c" * 64])
        self.assertEqual(medcea_data.lineage_chain(rows), {1: want[0], 2: want[1], 3: want[2]})
        self.assertEqual(want[0], hashlib.sha256(("\n" + hashlib.sha256(b"").hexdigest()).encode()).hexdigest())

    def test_the_digest_check_uses_the_digests_rules(self):
        h = " ".join(self.fns["lake.snapshot_digest_check"].split())
        self.assertIn('RETURNS TABLE ("set" text, recorded text, recomputed text, ok boolean)', h)
        self.assertIn("SET TimeZone = 'UTC' SET DateStyle = 'ISO, YMD'", h)
        b = self.body("lake.snapshot_digest_check")
        ddl = sql_code(read(DDL))
        # the same sets in the same order as close_snapshot's
        cs = ddl[ddl.index("FUNCTION lake.close_snapshot"):]
        for arr in ("sets CONSTANT text[] := ARRAY[", "stages CONSTANT text[] := ARRAY["):
            want = cs[cs.index(arr):cs.index("];", cs.index(arr))]
            got = b[b.index(arr):b.index("];", b.index(arr))]
            self.assertEqual(" ".join(got.split()), " ".join(want.split()))
        # a row's text is the staging columns' record form, in attnum order, snapshot_id left out
        self.assertIn("pg_catalog.format('x.%I', a.attname), ', ' ORDER BY a.attnum", b)
        self.assertIn("a.attrelid = pg_catalog.to_regclass('lake.' || stages[i]) AND a.attnum > 0 AND NOT "
                      "a.attisdropped", " ".join(b.split()))
        self.assertEqual(b.count("SELECT ROW(%s)::text AS t"), 2)
        self.assertEqual(b.count("ORDER BY r.t COLLATE \"C\""), 2)
        # per hour of ingest, the line format of _set_digest
        sd = ddl[ddl.index("FUNCTION lake._set_digest"):]
        for piece in ("pg_catalog.date_trunc('hour', m.ingested_at) AS hour, pg_catalog.count(*) AS c",
                      "GROUP BY 1 ORDER BY 1 NULLS LAST LOOP",
                      "coalesce(pg_catalog.to_char(h.hour, 'YYYY-MM-DD\"T\"HH24\":00:00Z\"'), 'none')",
                      "|| '|' || h.c::text || '|' ||"):
            self.assertIn(piece, " ".join(sd.split()))
            self.assertIn(piece, " ".join(b.split()))
        self.assertIn("ok := recorded IS NOT DISTINCT FROM recomputed;", b)
        self.assertIn("RAISE EXCEPTION 'no snapshot %'", b)

    def test_asserts_cover_the_reader(self):
        a = read(ASSERT)
        for line in ("'rs_lake_api is not LOGIN NOINHERIT'", "', not 10'", "'rs_lake_reader can log in'",
                     "'rs_lake_api is a member of '", "'rs_lake_api is not a member of rs_lake_reader'",
                     "'rs_lake_api lacks its setting '", "' holds column privilege '",
                     "'rs_lake_reader lacks USAGE on schema lake_api'", "'rs_lake_reader lacks EXECUTE on '",
                     "' is not SECURITY DEFINER'", "' does not pin search_path = pg_catalog, pg_temp'",
                     "'search_path=pg_catalog, pg_temp'"):
            self.assertIn(line, a)
        self.assertIn("'registry', 'lake_api')", a)   # in the six-schema checks (PUBLIC, ownership)
        # the reader holds nothing on any relation of the database, nothing outside lake_api
        self.assertIn("WHERE NOT (lk.rolname = 'rs_lake_reader' AND n.nspname = 'lake_api' AND a.privilege_type = "
                      "'EXECUTE')", " ".join(a.split()))
        self.assertIn("WHERE NOT (lk.rolname = 'rs_lake_reader' AND n.nspname = 'lake_api' AND a.privilege_type = "
                      "'USAGE')", " ".join(a.split()))


# ── fakes ─────────────────────────────────────────────────────────────────────
STUB_KUBECTL = r"""#!/usr/bin/env bash
# argv to the log (one line per call); stdin of applies and execs to numbered files
a="$*"; echo "kubectl ${a//$'\n'/ }" >> "$STUB_LOG"   # one line per call
n=$(ls "$STUB_DIR" | grep -c '^in-' || true)
save() { cat > "$STUB_DIR/in-$(printf %03d "$n")-$1"; }
case "$*" in
  "get namespace "*) [[ -z "${STUB_NO_NS:-}" ]]; exit $? ;;
  "get statefulset research-postgresql "*) [[ -n "${STUB_STS:-}" ]]; exit $? ;;
  "get pod research-postgresql-0 "*) printf %s "${STUB_PHASE-Running}" ;;
  "get networkpolicy "*)
    [[ -z "${STUB_NETPOL_RC:-}" ]] || exit "$STUB_NETPOL_RC"
    if [[ -n "${STUB_NETPOL_JSON:-}" ]]; then printf '%s' "$STUB_NETPOL_JSON"; else echo '{"items": []}'; fi ;;
  "port-forward "*) exec sleep 30 ;;
  "apply "*) save apply ;;
  "exec -i "*)
    save exec
    f="$(ls "$STUB_DIR"/in-*-exec | tail -n1)"
    if grep -q "assert_grants.sql" "$f"; then printf '%s' "${STUB_ASSERT_OUT:-}"
    elif grep -q "FROM vault.reservation r ORDER BY" "$f"; then printf '%s' "${STUB_LIST_OUT:-}"
    elif grep -q "vault.reserve(" "$f"; then
        if [[ -n "${STUB_RESERVE_ERR:-}" ]]; then echo "psql:<stdin>:3: ERROR:  $STUB_RESERVE_ERR" >&2; exit 3; fi
        echo 7
    fi ;;
esac
exit 0
"""
STUB_MK8S = r"""#!/usr/bin/env bash
case "$1" in
  kubectl) shift; exec "$(dirname "$0")/kubectl" "$@" ;;
  helm3)
    echo "helm3 ${*:2}" >> "$STUB_LOG"
    case "$2" in
      registry) cat > /dev/null ;;
      upgrade) prev=""; for a in "$@"; do [[ "$prev" == -f ]] && cp "$a" "$STUB_DIR/values.yaml" && stat -c %a "$a" > "$STUB_DIR/values.mode"; prev="$a"; done ;;
      status) [[ -n "${STUB_RELEASE:-}" ]] || exit 1 ;;
    esac ;;
esac
exit 0
"""
# curl as Keycloak answers: the token endpoint, the admin probe, users and role mappings
STUB_CURL = r"""#!/usr/bin/env python3
import json, os, sys, urllib.parse
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write("curl " + " ".join(args) + "\n")
url = next(a for a in args if a.startswith("http"))
out = args[args.index("-o") + 1] if "-o" in args else None
wfmt = "-w" in args
users = json.loads(os.environ.get("STUB_KC_USERS", "{}"))
p = urllib.parse.urlparse(url)
q = urllib.parse.parse_qs(p.query)
code, body = 404, "{}"
if p.path.endswith("/protocol/openid-connect/token"):
    sys.stdin.read()
    code, body = 200, json.dumps({"access_token": "tok"})
elif p.path == "/admin/realms/master/users":
    code, body = 200, "[]"
elif p.path.endswith("/users") and "username" in q:
    u = users.get(q["username"][0])
    code, body = 200, json.dumps([{"id": u["id"], "username": q["username"][0], "enabled": u["enabled"]}] if u else [])
elif "/role-mappings/realm/composite" in p.path:
    uid = p.path.split("/users/")[1].split("/")[0]
    roles = next((u["roles"] for u in users.values() if u["id"] == uid), [])
    code, body = 200, json.dumps([{"name": r} for r in roles])
if out and out != "/dev/null":
    open(out, "w").write(body)
elif not out:
    sys.stdout.write(body)
if wfmt:
    sys.stdout.write(str(code))
sys.exit(0 if code == 200 or wfmt or "-f" not in " ".join(args) else 22)
"""


class Tree(unittest.TestCase):
    """A scratch tree with apps/research, the real libraries but a fake cluster."""

    def setUp(self):
        self.root = scratch_repo("medcea-research-")
        shutil.copytree(APP, os.path.join(self.root, "apps", "research"), ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(os.path.join(REPO, "infra", "pg-scram.py"), os.path.join(self.root, "infra", "pg-scram.py"))
        self.log = os.path.join(self.root, "calls.log")
        self.stub = os.path.join(self.root, "stub")
        self.bin = os.path.join(self.root, "bin")
        os.makedirs(self.stub)
        os.makedirs(self.bin)
        for name, text in (("kubectl", STUB_KUBECTL), ("mk8s", STUB_MK8S), ("curl", STUB_CURL)):
            with open(os.path.join(self.bin, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(self.bin, name), 0o755)
        with open(os.path.join(self.root, "infra", "lib-mk8s.sh"), "w") as f:
            f.write('MK8S="%s/mk8s"; KUBECTL="%s/kubectl"\n' % (self.bin, self.bin))
        with open(os.path.join(self.root, "infra", "lib-policy-source.sh"), "w") as f:
            f.write('policy_source_init() { echo "init $*" >> "$STUB_LOG"; }\n'
                    'policy_source_finish() { echo "finish $*" >> "$STUB_LOG"; }\n'
                    'policy_db_state() { echo "policy_db_state $1" >> "$STUB_LOG"; echo "${STUB_PS_STATE:-version-3}"; }\n')
        # the snapshot reader (Phase 2b), run by deploy.sh last and by uninstall.sh first
        shutil.copytree(os.path.join(REPO, "apps", "lake-api"), os.path.join(self.root, "apps", "lake-api"))
        os.makedirs(os.path.join(self.root, "apps", "research", "db"), exist_ok=True)
        with open(os.path.join(self.root, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write('import os, sys\nopen(os.environ["STUB_LOG"], "a").write("cli " + " ".join(sys.argv[1:]) + "\\n")\n'
                    'if sys.argv[1:2] == ["pod-zone"]:\n'
                    '    z = os.environ.get("STUB_POD_ZONE", "")\n'
                    '    print(z) if z else None\n'
                    '    sys.exit(0 if z else int(os.environ.get("STUB_POD_ZONE_RC", "1")))\n'
                    'sys.exit(int(os.environ.get("STUB_ZONE_RC", "0")))\n')
        self.write_config()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, **extra):
        conf = dict(DOMAIN="medcea", NAMESPACE="medcea", PROJECT_NAME="medcea", KEYCLOAK_REALM="medcea",
                    RESEARCH_ENABLED="true", RESEARCH_NAMESPACE="medcea-research", RESEARCH_DB_STORAGE="10Gi",
                    KC_DEPLOYER_SECRET=KC_SECRET, **dict(SECRETS, **DOCKERHUB))
        conf.update(extra)
        with open(os.path.join(self.root, "config.env"), "w") as f:
            for k, v in conf.items():
                f.write('%s="%s"\n' % (k, v))

    def run_script(self, script, *args, stdin=None, **env):
        e = clean_env(**dict({"STUB_LOG": self.log, "STUB_DIR": self.stub,
                              "PATH": self.bin + ":" + os.environ["PATH"]}, **env))
        for k in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG", "MEDCEA_CONFIRMED", "RESEARCH_ENABLED"):
            if k not in env:
                e.pop(k, None)
        r = subprocess.run(["bash", os.path.join(self.root, "apps", "research", script)] + list(args),
                           env=e, capture_output=True, text=True, timeout=120,
                           input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        if os.path.exists(self.log):
            os.remove(self.log)
        r.out = r.stdout + r.stderr
        argv = "\n".join(calls)
        for v in list(SECRETS.values()) + [DOCKERHUB["DOCKERHUB_PAT"], KC_SECRET]:
            self.assertNotIn(v, argv, "a secret in an argv")
            self.assertNotIn(v, r.out, "a secret printed")
        return r, calls

    def inputs(self, kind):
        return [read(os.path.join(self.stub, f)) for f in sorted(os.listdir(self.stub)) if f.endswith("-" + kind)]

    def no_log_no_lock(self):
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))


class Deploy(Tree):
    def test_syntax(self):
        for s in ("deploy.sh", "uninstall.sh", "reserve.sh"):
            subprocess.run(["bash", "-n", os.path.join(APP, s)], check=True)

    def test_unknown_options_exit_2_before_log_and_lock(self):
        for script, args in (("deploy.sh", ["--x"]), ("deploy.sh", ["--help", "x"]),
                             ("uninstall.sh", ["--purge"]), ("uninstall.sh", ["--purge-data", "x"])):
            r, calls = self.run_script(script, *args)
            self.assertEqual(r.returncode, 2, (script, args, r.out))
            self.assertIn("unknown arguments", r.stderr)
            self.no_log_no_lock()
            self.assertEqual(calls, [])
        r, calls = self.run_script("deploy.sh", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipped: RESEARCH_ENABLED is not true", r.stdout)
        self.no_log_no_lock()

    def test_switched_off(self):
        self.write_config(RESEARCH_ENABLED="false")
        r, calls = self.run_script("deploy.sh")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: RESEARCH_ENABLED is not true", r.stdout)
        self.assertFalse([c for c in calls if c.startswith(("init", "cli", "helm3"))], calls)
        r, calls = self.run_script("deploy.sh", STUB_STS="1")   # installed: left alone, said so
        self.assertEqual(r.returncode, 0)
        self.assertIn("still installed", r.out)
        self.assertFalse([c for c in calls if "delete" in c or c.startswith("helm3")], calls)

    def test_no_research_zone(self):
        r, calls = self.run_script("deploy.sh", STUB_ZONE_RC="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: the applied access policy has no research zone yet", r.stdout)
        self.assertEqual(calls[:2], ["init medcea", "cli has-zone research"])
        self.assertEqual(calls[-1], "finish medcea research")
        self.assertFalse([c for c in calls if c.startswith("helm3")])

    def test_broken_policy_refuses(self):
        r, calls = self.run_script("deploy.sh", STUB_ZONE_RC="2")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cli.py has-zone research exit 2", r.out)
        self.assertNotIn("finish medcea research", calls)

    def test_no_applied_version(self):
        for st in ("none", "empty"):
            r, calls = self.run_script("deploy.sh", STUB_PS_STATE=st)
            self.assertEqual(r.returncode, 0, r.out)
            self.assertIn("skipped: no version of the access policy is applied yet (state %s)" % st, r.stdout)
            self.assertEqual(calls[-1], "finish medcea research")
        r, _ = self.run_script("deploy.sh", STUB_PS_STATE="partial")
        self.assertEqual(r.returncode, 1)

    def test_no_namespace(self):
        r, calls = self.run_script("deploy.sh", STUB_NO_NS="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("skipped: namespace medcea-research does not exist yet: run ./deploy-infra.sh", r.stdout)
        self.assertEqual(calls[-1], "finish medcea research")
        self.assertFalse([c for c in calls if c.startswith("helm3") or c.startswith("kubectl apply")])

    def test_missing_password(self):
        for k in ("RS_BACKUP_DB_PASS", "RS_LAKE_API_DB_PASS", "RS_SESSION_DB_PASS"):
            self.write_config(**{k: ""})
            r, calls = self.run_script("deploy.sh")
            self.assertEqual(r.returncode, 1)
            self.assertIn("%s is empty in config.env" % k, r.out)
            self.assertFalse([c for c in calls if c.startswith("helm3")])

    def test_the_reader_fails_the_deploy(self):
        # lake-api's exit code is the research deploy's, and research's finish waits for it
        r, calls = self.run_script("deploy.sh", STUB_POD_ZONE="platform")
        self.assertEqual(r.returncode, 1, r.out)
        self.assertIn("it lives only in the research zone", r.out)
        self.assertNotIn("finish medcea research", calls)
        self.assertNotIn("finish medcea lake-api", calls)

    def test_full_path(self):
        r, calls = self.run_script("deploy.sh")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertEqual(calls[-1], "finish medcea research")
        # the snapshot reader last, under this log and lock: it skips until the policy has its pod
        self.assertEqual(calls[-5:-1], ["init medcea", "cli pod-zone lake-api",
                                        "kubectl get deployment lake-api -n medcea-research", "finish medcea lake-api"])
        self.assertIn("[lake-api]", r.stdout)
        self.assertIn("skipped: the applied access policy has no lake-api pod yet", r.stdout)
        self.assertEqual(len([f for f in os.listdir(os.path.join(self.root, "logs"))]), 1)   # one log
        helm = [c for c in calls if c.startswith("helm3")]
        self.assertTrue(helm[0].startswith("helm3 registry login registry-1.docker.io -u someone --password-stdin"))
        up = helm[1]
        self.assertTrue(up.startswith("helm3 upgrade --install research-postgresql "
                                      "oci://registry-1.docker.io/bitnamicharts/postgresql --version 18.4.0 "
                                      "--namespace medcea-research -f "), up)
        self.assertIn("--wait", up)
        self.assertNotIn("--set", up)
        self.assertEqual(read(os.path.join(self.stub, "values.mode")).strip(), "600")
        values = read(os.path.join(self.stub, "values.yaml"))
        for s in ("fullnameOverride: research-postgresql", "existingSecret: research-postgresql-auth",
                  "priorityClassName: medcea-research-low", "size: 10Gi", "  enabled: false"):
            self.assertIn(s, values)
        self.assertNotIn("${", values)
        self.assertNotIn("cpu: 1", values.split("limits:")[1].split("persistence")[0])   # no CPU limit
        # order: auth Secret → helm → DDL → lake_api.sql → agent_trace.sql → passwords → grants → role Secrets → assert
        order = [c for c in calls if c.startswith(("helm3 upgrade", "kubectl apply", "kubectl exec"))]
        kinds = []
        for c in order:
            kinds.append("helm" if c.startswith("helm3") else c.split()[1])
        self.assertEqual(kinds, ["apply", "helm", "exec", "exec", "exec", "exec", "exec", "apply", "apply", "exec"])
        self.assertIn("kubectl apply -n medcea-research -f -", calls)
        self.assertEqual(calls.count("kubectl apply -n medcea -f -"), 2)
        applies = self.inputs("apply")
        self.assertIn('postgres-password: "%s"' % SECRETS["RESEARCH_DB_PASS"], applies[0])
        self.assertIn("name: research-export-writer", applies[1])
        self.assertIn('username: "rs_export_writer"', applies[1])
        self.assertIn('password: "%s"' % SECRETS["RS_EXPORT_WRITER_DB_PASS"], applies[1])
        self.assertIn("name: research-backup", applies[2])
        self.assertIn('username: "rs_backup"', applies[2])
        for a in applies[1:]:
            self.assertNotIn("medcea/db-role", sql_code(a.replace("#", "--")))   # never deleted by the database purge
        execs = self.inputs("exec")
        self.assertIn("CREATE DATABASE medcea_research", execs[0])
        self.assertEqual(execs[1], read(LAKE_API))
        self.assertEqual(execs[2], read(os.path.join(APP, "db", "agent_trace.sql")))
        pw = execs[3]
        self.assertTrue(pw.startswith("SET log_statement = 'none';"), pw)
        self.assertEqual(len(re.findall(r"\\set pw 'SCRAM-SHA-256\$4096:", pw)), 4)
        self.assertIn("ALTER ROLE rs_export_writer PASSWORD :'pw';", pw)
        self.assertIn("ALTER ROLE rs_backup PASSWORD :'pw';", pw)
        self.assertIn("ALTER ROLE rs_lake_api PASSWORD :'pw';", pw)
        for v in SECRETS.values():
            self.assertNotIn(v, "\n".join(execs))
        self.assertIn("ALTER ROLE rs_session PASSWORD :'pw';", pw)
        self.assertIn("GRANT pg_read_all_data TO rs_backup", execs[4])
        self.assertIn("GRANT rs_lake_reader TO rs_lake_api", execs[4])
        self.assertIn("assert_grants.sql", execs[5])
        ex = [c for c in calls if c.startswith("kubectl exec")]
        self.assertTrue(all(" -n medcea-research research-postgresql-0 " in c for c in ex), ex)
        self.assertIn(" postgres -q -v ON_ERROR_STOP=1 -f -", ex[0])
        self.assertIn(" medcea_research -q -v ON_ERROR_STOP=1 -f -", ex[1])   # lake_api.sql in the database
        self.assertIn(" medcea_research -q -v ON_ERROR_STOP=1 -f -", ex[2])   # agent_trace.sql
        self.assertIn(" postgres -q", ex[3])
        self.assertIn(" medcea_research -q", ex[4])
        self.assertIn(" medcea_research -qtA", ex[5])

    def test_the_chart_networkpolicy_is_off(self):
        # chart 18.4.0 has no top-level networkPolicy key: the switches are per component
        values = read(os.path.join(APP, "k8s", "values.yaml"))
        doc = yaml_load(values)
        self.assertNotIn("networkPolicy", doc)
        self.assertIs(doc["primary"]["networkPolicy"]["enabled"], False)
        self.assertIs(doc["readReplicas"]["networkPolicy"]["enabled"], False)

    def test_only_compiled_netpols_after_the_install(self):
        def item(name, labels):
            return {"metadata": dict({"name": name}, **({"labels": labels} if labels is not None else {}))}
        ok = json.dumps({"items": [item("rs-default-deny", {"medcea/rs-netpol": "true"}),
                                   item("rs-dns", {"medcea/rs-netpol": "true"})]})
        r, calls = self.run_script("deploy.sh", STUB_NETPOL_JSON=ok)
        self.assertEqual(r.returncode, 0, r.out)
        get = [c for c in calls if c.startswith("kubectl get networkpolicy")]
        self.assertEqual(get, ["kubectl get networkpolicy -n medcea-research -o json"])
        # read right after helm, before the database is touched
        self.assertLess(calls.index(next(c for c in calls if c.startswith("helm3 upgrade"))), calls.index(get[0]))
        self.assertLess(calls.index(get[0]), calls.index(next(c for c in calls if c.startswith("kubectl exec"))))
        bad = json.dumps({"items": [item("rs-dns", {"medcea/rs-netpol": "true"}),
                                    item("research-postgresql", {"app.kubernetes.io/managed-by": "Helm"}),
                                    item("allow-all", None), item("rs-x", {"medcea/rs-netpol": "false"})]})
        r, calls = self.run_script("deploy.sh", STUB_NETPOL_JSON=bad)
        self.assertEqual(r.returncode, 1)
        self.assertIn("NetworkPolicy research-postgresql, allow-all, rs-x in medcea-research is not labelled "
                      "medcea/rs-netpol=true: it admits more than the research zone allows", r.out)
        self.assertFalse([c for c in calls if c.startswith("kubectl exec")])
        self.assertNotIn("finish medcea research", calls)
        for env in ({"STUB_NETPOL_RC": "1"}, {"STUB_NETPOL_JSON": "not json"}):
            r, calls = self.run_script("deploy.sh", **env)
            self.assertEqual(r.returncode, 1, env)
            self.assertIn("NetworkPolicies of medcea-research", r.out)
            self.assertFalse([c for c in calls if c.startswith("kubectl exec")])

    def test_a_grant_drift_fails_the_deploy(self):
        r, calls = self.run_script("deploy.sh", STUB_ASSERT_OUT="rs_export_writer holds SELECT on lake.measurement\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("rs_export_writer holds SELECT on lake.measurement", r.out)
        self.assertIn("not the ones db/grants.sql states", r.out)
        self.assertNotIn("finish medcea research", calls)

    def test_uninstall(self):
        r, calls = self.run_script("uninstall.sh", STUB_RELEASE="1")
        self.assertEqual(r.returncode, 0, r.out)
        # the snapshot reader first (it logs in to the database removed below)
        rm = "kubectl delete deployment,service,secret -n medcea-research -l app=lake-api --ignore-not-found"
        self.assertIn(rm, calls)
        self.assertLess(calls.index(rm), calls.index("kubectl delete secret research-export-writer research-backup "
                                                     "-n medcea --ignore-not-found"))
        self.assertIn("kubectl delete secret research-export-writer research-backup -n medcea --ignore-not-found", calls)
        self.assertIn("helm3 uninstall research-postgresql -n medcea-research --wait", calls)
        self.assertFalse([c for c in calls if "pvc" in c])
        self.assertLess(calls.index("kubectl delete secret research-export-writer research-backup -n medcea --ignore-not-found"),
                        calls.index("helm3 uninstall research-postgresql -n medcea-research --wait"))
        self.assertTrue(os.path.isdir(os.path.join(self.root, "logs")))
        self.assertTrue([f for f in os.listdir(os.path.join(self.root, "logs")) if f.startswith("app-research-uninstall-")])
        r, calls = self.run_script("uninstall.sh", "--purge-data")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertFalse([c for c in calls if c.startswith("helm3 uninstall")])   # no release: nothing to uninstall
        self.assertIn("kubectl delete pvc -n medcea-research -l app.kubernetes.io/instance=research-postgresql --ignore-not-found",
                      calls)
        self.assertIn("kubectl delete secret research-postgresql-auth -n medcea-research --ignore-not-found", calls)
        r, calls = self.run_script("uninstall.sh", "--purge-data", STUB_NO_NS="1")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertFalse([c for c in calls if "pvc" in c or c.startswith("helm3")])

    def test_logging_and_lock_order(self):
        for s in ("deploy.sh", "uninstall.sh", "reserve.sh"):
            t = "\n".join(l for l in read(os.path.join(APP, s)).splitlines() if not l.lstrip().startswith("#"))
            self.assertLess(t.index("medcea_log "), t.index("medcea_lock"), s)
        t = read(os.path.join(APP, "deploy.sh"))
        self.assertTrue(t.rstrip().endswith('policy_source_finish "$NAMESPACE" research'))
        self.assertIn('policy_source_init "$NAMESPACE" || exit $?', t)


KC_USERS = {"qa1": {"id": "11111111-2222-3333-4444-555555555555", "enabled": True, "roles": ["qa", "auditor"]},
            "eng1": {"id": "21111111-2222-3333-4444-555555555555", "enabled": True, "roles": ["engineer"]},
            "qaoff": {"id": "31111111-2222-3333-4444-555555555555", "enabled": False, "roles": ["qa"]}}
ADD = ["add", "--by", "qa1", "--unit", "UNIT01", "--from", "2026-12-01", "--to", "2026-12-08T00:00Z",
       "--reason", "held out for the fruiting benchmark"]


class Reserve(Tree):
    def run_add(self, args=ADD, **env):
        env = dict({"STUB_KC_USERS": json.dumps(KC_USERS), "MEDCEA_CONFIRMED": "1"}, **env)
        return self.run_script("reserve.sh", *args, **env)

    def test_usage_errors_before_log_and_lock(self):
        bad = [[], ["drop"], ["list", "x"], ["add"],
               ["add", "--unit", "U1", "--from", "2026-12-01", "--to", "2026-12-02", "--reason", "long enough reason"],
               [a if a != "UNIT01" else "UNIT 01" for a in ADD],
               [a if a != "UNIT01" else "--bootstrap" for a in ADD],
               ADD + ["--zone", "z;1"],
               [a if a != "2026-12-01" else "yesterday" for a in ADD],
               [a if a != "2026-12-01" else "2026-13-45" for a in ADD],
               [a if a != "2026-12-08T00:00Z" else "2026-11-30" for a in ADD],
               [a if a != "held out for the fruiting benchmark" else "  short   " for a in ADD],
               [a if a != "held out for the fruiting benchmark" else "two\nlines of reason" for a in ADD],
               ADD + ["--extra", "x"], ADD[:-1]]
        for args in bad:
            r, calls = self.run_script("reserve.sh", *args)
            self.assertEqual(r.returncode, 2, (args, r.out))
            self.assertEqual(calls, [], args)
            self.no_log_no_lock()
        r, _ = self.run_script("reserve.sh", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("reserve.sh add --by", r.stdout)

    def test_list_is_read_only(self):
        r, calls = self.run_script("reserve.sh", "list",
                                   STUB_LIST_OUT="3|UNIT01|*|2026-12-01T00:00:00Z|2026-12-08T00:00:00Z|qa1|2026-11-18T10:00:00Z|why\n")
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("UNIT01", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".medcea.lock")))   # no lock for list
        sql = self.inputs("exec")[0]
        self.assertIn("BEGIN READ ONLY;", sql)
        self.assertNotRegex(sql, r"\b(INSERT|UPDATE|DELETE|reserve\()")
        r, _ = self.run_script("reserve.sh", "list")
        self.assertIn("No reservations", r.stdout)
        r, _ = self.run_script("reserve.sh", "list", STUB_PHASE="Pending")
        self.assertEqual(r.returncode, 2)
        self.assertIn("./apps/research/deploy.sh first", r.out)

    def test_add(self):
        r, calls = self.run_add()
        self.assertEqual(r.returncode, 0, r.out)
        self.assertIn("Reservation #7 made", r.out)
        self.assertTrue(os.path.exists(os.path.join(self.root, ".medcea.lock")))
        ex = [c for c in calls if c.startswith("kubectl exec")]
        self.assertEqual(len(ex), 1)
        for v in ("-v unit=UNIT01", "-v zone= ", "-v from_at=2026-12-01 ", "-v to_at=2026-12-08T00:00Z",
                  "-v reason=held out for the fruiting benchmark", "-v by_username=qa1",
                  "-v by_sub=11111111-2222-3333-4444-555555555555", " medcea_research "):
            self.assertIn(v, ex[0])
        sql = self.inputs("exec")[0]
        self.assertIn("SET ROLE rs_owner;", sql)
        self.assertIn("vault.reserve(:'unit', NULLIF(:'zone', '')", sql)
        self.assertNotIn("UNIT01", sql)   # values only as psql variables
        self.assertTrue([c for c in calls if c.startswith("kubectl port-forward svc/keycloak 18094:80 -n medcea")])
        # the deployer's secret went to curl on stdin, never argv (checked by run_script)
        self.assertTrue([c for c in calls if c.startswith("curl") and "role-mappings/realm/composite" in c])

    def test_add_refusals(self):
        for by, want in (("eng1", "does not hold the realm role qa"), ("qaoff", "disabled account"),
                         ("nobody", "no account 'nobody'")):
            args = [a if a != "qa1" else by for a in ADD]
            r, calls = self.run_add(args)
            self.assertEqual(r.returncode, 1, (by, r.out))
            self.assertIn(want, r.out)
            self.assertFalse([c for c in calls if c.startswith("kubectl exec")], by)
        r, calls = self.run_add(STUB_RESERVE_ERR="reserve: unit UNIT01 (every zone) from x to y is already exported: it is no longer held out")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exported: it is no longer held out", r.out)
        self.assertIn("Nothing was written", r.out)

    def test_add_needs_a_confirmation(self):
        env = {"STUB_KC_USERS": json.dumps(KC_USERS)}
        r, calls = self.run_script("reserve.sh", *ADD, **env)   # no terminal, no MEDCEA_CONFIRMED
        self.assertEqual(r.returncode, 1)
        self.assertIn("No terminal to confirm on", r.out)
        self.assertFalse([c for c in calls if c.startswith("kubectl exec")])


# ── the chart itself ──────────────────────────────────────────────────────────
CHART = os.path.expanduser("~/.cache/helm/repository/postgresql-18.4.0.tgz")


def yaml_load(text):
    import yaml
    return yaml.safe_load(text)


@unittest.skipUnless(os.path.isfile(CHART), "bitnamicharts/postgresql 18.4.0 not in the helm cache")
class Chart(unittest.TestCase):
    """The values keys we set exist in the chart, at those paths (helm ignores an unknown key)."""

    def chart_values(self):
        import tarfile
        with tarfile.open(CHART) as tf:
            return yaml_load(tf.extractfile("postgresql/values.yaml").read().decode())

    def test_the_switches_are_the_charts(self):
        cv = self.chart_values()
        self.assertNotIn("networkPolicy", cv)   # no top-level switch: a key there is dead
        for comp in ("primary", "readReplicas"):
            self.assertIn("enabled", cv[comp]["networkPolicy"], comp)
            self.assertIs(cv[comp]["networkPolicy"]["enabled"], True, comp)   # what we turn off
        ours = yaml_load(read(os.path.join(APP, "k8s", "values.yaml")).replace("${RESEARCH_DB_STORAGE}", "10Gi"))

        def paths(d, pre=()):
            for k, v in d.items():
                if isinstance(v, dict) and v:
                    yield from paths(v, pre + (k,))
                else:
                    yield pre + (k,)
        for p in paths(ours):
            node = cv
            for k in p[:-1]:
                self.assertIsInstance(node.get(k), dict, "values.yaml key %s is not the chart's" % ".".join(p))
                node = node[k]
                if node == {}:   # a free map in the chart (resources: {}): anything below is the API's
                    break
            else:
                self.assertIn(p[-1], node, "values.yaml key %s is not the chart's" % ".".join(p))

    @unittest.skipUnless(shutil.which("helm"), "no helm on PATH")
    def test_no_networkpolicy_rendered(self):
        values = read(os.path.join(APP, "k8s", "values.yaml")).replace("${RESEARCH_DB_STORAGE}", "10Gi")
        for extra in ([], ["--set", "architecture=replication"]):
            r = subprocess.run(["helm", "template", "research-postgresql", CHART, "--namespace", "medcea-research",
                                "-f", "-"] + extra, input=values, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                self.skipTest("helm template failed offline: " + r.stderr[-200:])
            self.assertIn("kind: StatefulSet", r.stdout)
            self.assertNotIn("kind: NetworkPolicy", r.stdout, extra)
            # and the chart would make one without our switches
            r2 = subprocess.run(["helm", "template", "research-postgresql", CHART, "--namespace", "medcea-research"]
                                + extra, capture_output=True, text=True, timeout=120)
            self.assertIn("kind: NetworkPolicy", r2.stdout)


# ── a real PostgreSQL ─────────────────────────────────────────────────────────
def pg_bin():
    d = os.environ.get("MEDCEA_TEST_PG_BIN")
    if d:
        return d if all(os.access(os.path.join(d, b), os.X_OK) for b in ("initdb", "pg_ctl", "psql")) else None
    p = shutil.which("initdb")
    if p and shutil.which("pg_ctl") and shutil.which("psql"):
        return os.path.dirname(p)
    return None


def _record_text(row):
    """PostgreSQL's record output: a field with a space, comma, quote, backslash or
    parenthesis is double-quoted (none of the test values needs escaping inside)."""
    out = []
    for v in row:
        out.append('"%s"' % v if (v == "" or re.search(r'[\s,"\\()]', v)) else v)
    return "(" + ",".join(out) + ")"


def measurement_digest(rows):
    """lake._set_digest's definition for stage_measurements (the DDL's comment): per hour
    of ingested_at (UTC), the line <hour>|<count>|<sha256 of the sorted row texts>; the
    digest is sha256 of the lines, oldest hour first, joined with newlines."""
    hours = {}
    for r in rows:
        hours.setdefault(r[0][:13], []).append(_record_text(r).encode())
    lines = []
    for h in sorted(hours):
        body = b"\n".join(sorted(hours[h]))
        lines.append("%sT%s:00:00Z|%d|%s" % (h[:10], h[11:13], len(hours[h]), hashlib.sha256(body).hexdigest()))
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


@unittest.skipUnless(pg_bin(), "no initdb/pg_ctl/psql (set MEDCEA_TEST_PG_BIN)")
class RealPostgres(unittest.TestCase):
    UNIT_ZONE = "11111111-2222-3333-4444-555555555555"

    @classmethod
    def setUpClass(cls):
        cls.bin = pg_bin()
        cls.dir = tempfile.mkdtemp(prefix="medcea-rspg-")
        cls.sock = tempfile.mkdtemp(prefix="rspg", dir="/tmp")   # a socket path must stay short
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = str(s.getsockname()[1])
        cmd = [os.path.join(cls.bin, "initdb"), "-D", os.path.join(cls.dir, "data"), "-U", "postgres", "-A", "trust",
               "--no-sync"]
        if os.environ.get("MEDCEA_TEST_PG_SHARE"):
            cmd += ["-L", os.environ["MEDCEA_TEST_PG_SHARE"]]
        subprocess.run(cmd, check=True, capture_output=True)
        subprocess.run([os.path.join(cls.bin, "pg_ctl"), "-D", os.path.join(cls.dir, "data"), "-w", "-l",
                        os.path.join(cls.dir, "log"), "-o", "-k %s -p %s -c listen_addresses=''" % (cls.sock, cls.port),
                        "start"], check=True, capture_output=True)
        for _ in range(2):   # re-run safe
            cls.psql("postgres", read(DDL), check=True)
            cls.psql("medcea_research", read(LAKE_API), check=True)
            cls.psql("medcea_research", read(os.path.join(APP, "db", "agent_trace.sql")), check=True)
            cls.psql("medcea_research", read(GRANTS), check=True)

    @classmethod
    def tearDownClass(cls):
        subprocess.run([os.path.join(cls.bin, "pg_ctl"), "-D", os.path.join(cls.dir, "data"), "-m", "immediate",
                        "stop"], capture_output=True)
        shutil.rmtree(cls.dir, ignore_errors=True)
        shutil.rmtree(cls.sock, ignore_errors=True)

    @classmethod
    def psql(cls, db, sql, user="postgres", check=False):
        r = subprocess.run([os.path.join(cls.bin, "psql"), "-X", "-h", cls.sock, "-p", cls.port, "-U", user, "-d", db,
                            "-qtA", "-v", "ON_ERROR_STOP=1", "-f", "-"], input=sql, capture_output=True, text=True,
                           env=dict(os.environ, PGTZ="UTC"))
        if check and r.returncode != 0:
            raise AssertionError(r.stderr)
        return r

    def q(self, sql, user="postgres"):
        r = self.psql("medcea_research", sql, user=user, check=True)
        return r.stdout.strip()

    def refused(self, sql, want, user="postgres"):
        r = self.psql("medcea_research", sql, user=user)
        self.assertNotEqual(r.returncode, 0, sql)
        self.assertIn(want, r.stderr, sql)
        return r.stderr

    def test_01_grants_as_stated(self):
        self.assertEqual(self.q(read(ASSERT)), "")
        self.assertEqual(self.q("SELECT has_table_privilege('rs_export_writer', 'lake.measurement', 'SELECT')"), "f")
        self.assertEqual(self.q("SELECT has_table_privilege('rs_backup', 'lake.measurement', 'SELECT')"), "t")
        self.assertEqual(self.q("SELECT has_function_privilege('rs_export_writer', 'vault.reserve(text,text,timestamptz,"
                                "timestamptz,text,text,uuid)', 'EXECUTE')"), "f")
        # a role of nobody's may not even connect
        self.psql("postgres", "DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rs_nobody') "
                              "THEN CREATE ROLE rs_nobody LOGIN; END IF; END$$;", check=True)
        r = self.psql("medcea_research", "SELECT 1", user="rs_nobody")
        self.assertIn("permission denied for database", r.stderr)
        # a drifted grant is what the assert reports, then put back
        self.q("GRANT SELECT ON lake.measurement TO rs_export_writer")
        self.assertIn("rs_export_writer holds SELECT on lake.measurement", self.q(read(ASSERT)))
        self.q("REVOKE SELECT ON lake.measurement FROM rs_export_writer")
        self.q("GRANT EXECUTE ON FUNCTION vault.reserved_rows_in(bigint) TO PUBLIC")
        self.assertIn("PUBLIC may execute vault.reserved_rows_in(bigint)", self.q(read(ASSERT)))
        self.q("REVOKE EXECUTE ON FUNCTION vault.reserved_rows_in(bigint) FROM PUBLIC")
        self.assertEqual(self.q(read(ASSERT)), "")

    def test_02_export_reservation_and_refusals(self):
        w = "rs_export_writer"
        self.assertEqual(self.q("SELECT lake.latest_cut() IS NULL", user=w), "t")
        # a reservation before the first export: UNIT01, every zone, 1 Dec 10:00-11:00
        rid = self.q("SET ROLE rs_owner; SELECT vault.reserve('UNIT01', NULL, '2026-12-01 10:00Z', '2026-12-01 11:00Z', "
                     "'benchmark hold-out window', 'qa1', '%s')" % self.UNIT_ZONE)
        self.assertRegex(rid, r"^\d+$")
        stage = """
BEGIN;
INSERT INTO lake.stage_measurements VALUES
 ('2026-12-01 09:59Z', '2026-12-01 09:59Z', 'UNIT01', 'Z1', 'air_temperature', 's1', 20.5, 'C'),
 ('2026-12-01 10:30Z', '2026-12-01 10:30Z', 'UNIT01', 'Z1', 'air_temperature', 's1', 21.0, 'C'),
 ('2026-12-01 10:31Z', '2026-12-01 10:31Z', 'unit01', 'Z2', 'co2', 'default', 900, 'ppm'),
 ('2026-12-01 11:00Z', '2026-12-01 11:00Z', 'UNIT01', 'Z1', 'air_temperature', 's1', 21.5, 'C'),
 ('2026-12-01 10:30Z', '2026-12-01 10:30Z', 'UNIT02', 'Z1', 'air_temperature', 's1', 19.0, 'C');
INSERT INTO lake.stage_zones VALUES ('U1', 'Z1', 'Y');
INSERT INTO lake.stage_catalogue VALUES ('quantity', 'co2', '{"unit": "ppm"}');
SELECT lake.close_snapshot('2026-12-01 12:00Z', NULL, 1);
COMMIT;"""
        sid = self.q(stage, user=w)
        self.assertRegex(sid, r"^\d+$")
        rows, digests = self.q("SELECT rows, digests FROM lake.snapshot WHERE snapshot_id = %s" % sid).split("|")
        rows, digests = json.loads(rows), json.loads(digests)
        self.assertEqual(rows["measurement"], 3)
        self.assertEqual(rows["held_out"], 2)
        self.assertEqual(rows["zones"], 1)
        self.assertEqual(rows["units"], 0)
        self.assertEqual(digests["units"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(digests["zones"], hashlib.sha256(b"(U1,Z1,Y)").hexdigest())
        # the measurements per hour of ingest: 09h, 10h (UNIT02; UNIT01 held out), 11h
        self.assertEqual(digests["measurement"], measurement_digest([
            ("2026-12-01 09:59:00+00", "2026-12-01 09:59:00+00", "UNIT01", "Z1", "air_temperature", "s1", "20.5", "C"),
            ("2026-12-01 10:30:00+00", "2026-12-01 10:30:00+00", "UNIT02", "Z1", "air_temperature", "s1", "19.0", "C"),
            ("2026-12-01 11:00:00+00", "2026-12-01 11:00:00+00", "UNIT01", "Z1", "air_temperature", "s1", "21.5", "C")]))
        self.assertEqual(sorted(rows), sorted([LAKE.get(s, s) for s in STAGES] + ["held_out"]))
        self.assertEqual(self.q("SELECT count(*) FROM lake.measurement WHERE measured_at >= '2026-12-01 10:00Z' "
                                "AND measured_at < '2026-12-01 11:00Z' AND lower(unit_code) = 'unit01'"), "0")
        self.assertEqual(self.q("SELECT vault.reserved_rows_in(%s)" % sid), "0")
        self.assertEqual(self.q("SELECT count(*) FROM lake.stage_measurements"), "0")   # staging emptied
        self.assertEqual(self.q("SELECT lake.latest_cut() = '2026-12-01 12:00Z'", user=w), "t")
        self.assertEqual(self.q("SELECT count(*) FROM lake.zones WHERE snapshot_id = %s" % sid), "1")
        # the writer reads nothing and deletes nothing
        self.refused("SELECT count(*) FROM lake.measurement", "permission denied", user=w)
        self.refused("DELETE FROM lake.stage_units", "permission denied", user=w)
        self.refused("SELECT count(*) FROM vault.reservation", "permission denied", user=w)

        # close_snapshot refusals (22023)
        cs = "BEGIN; %s SELECT lake.close_snapshot(%s); COMMIT;"
        self.refused(cs % ("", "'2026-12-02Z', NULL, 1"), "is not the latest snapshot's", user=w)
        self.refused(cs % ("", "'2026-12-02Z', '2026-12-01 12:00Z', 2"), "contract version 2 is not one", user=w)
        self.refused(cs % ("", "'2026-12-01 11:00Z', '2026-12-01 12:00Z', 1"), "must be later than", user=w)
        self.refused(cs % ("INSERT INTO lake.stage_measurements VALUES ('2026-12-01 11:59Z', '2026-12-01 11:59Z', "
                           "'UNIT02', 'Z1', 't', 's', 1, 'C');", "'2026-12-02Z', '2026-12-01 12:00Z', 1"),
                     "outside", user=w)
        self.refused("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT lake.close_snapshot('2026-12-02Z', "
                     "'2026-12-01 12:00Z', 1); COMMIT;", "READ COMMITTED", user=w)
        self.assertEqual(self.q("SELECT count(*) FROM lake.snapshot"), "1")
        # a second snapshot accumulates
        sid2 = self.q("BEGIN; INSERT INTO lake.stage_measurements VALUES ('2026-12-01 13:00Z', '2026-12-01 13:00Z', "
                      "'UNIT02', 'Z1', 'co2', 'default', 800, 'ppm'); SELECT lake.close_snapshot('2026-12-02Z', "
                      "'2026-12-01 12:00Z', 1); COMMIT;", user=w)
        self.assertEqual(self.q("SELECT previous_cut_at = '2026-12-01 12:00Z', rows->>'measurement' FROM lake.snapshot "
                                "WHERE snapshot_id = %s" % sid2), "t|1")
        # several rows in one hour, two hours, and a session whose TimeZone and DateStyle
        # differ: the function pins its own, so the digest is the definition's
        sid3 = self.q("BEGIN; SET LOCAL TimeZone = 'America/New_York'; SET LOCAL DateStyle = 'SQL, DMY'; "
                      "INSERT INTO lake.stage_measurements VALUES "
                      "('2026-12-02 00:10Z', '2026-12-02 00:10Z', 'UNIT02', 'Z1', 'co2', 'default', 810, 'ppm'), "
                      "('2026-12-02 00:05Z', '2026-12-02 00:05Z', 'UNIT02', 'Z1', 'co2', 'default', 805, 'ppm'), "
                      "('2026-12-02 00:59:59.5Z', '2026-12-02 00:59:59.5Z', 'UNIT02', 'Z2', 'co2', 'b', 1.25, 'ppm'), "
                      "('2026-12-02 02:00Z', '2026-12-02 02:00Z', 'UNIT02', 'Z1', 'co2', 'default', 820, 'ppm'); "
                      "SELECT lake.close_snapshot('2026-12-03Z', '2026-12-02Z', 1); COMMIT;", user=w)
        rows3, dig3 = self.q("SELECT rows->>'measurement', digests->>'measurement' FROM lake.snapshot "
                             "WHERE snapshot_id = %s" % sid3).split("|")
        self.assertEqual(rows3, "4")
        self.assertEqual(dig3, measurement_digest([
            ("2026-12-02 00:10:00+00", "2026-12-02 00:10:00+00", "UNIT02", "Z1", "co2", "default", "810", "ppm"),
            ("2026-12-02 00:05:00+00", "2026-12-02 00:05:00+00", "UNIT02", "Z1", "co2", "default", "805", "ppm"),
            ("2026-12-02 00:59:59.5+00", "2026-12-02 00:59:59.5+00", "UNIT02", "Z2", "co2", "b", "1.25", "ppm"),
            ("2026-12-02 02:00:00+00", "2026-12-02 02:00:00+00", "UNIT02", "Z1", "co2", "default", "820", "ppm")]))
        # an export with no measurements digests the empty string, as before
        sid4 = self.q("BEGIN; SELECT lake.close_snapshot('2026-12-04Z', '2026-12-03Z', 1); COMMIT;", user=w)
        self.assertEqual(self.q("SELECT digests->>'measurement' FROM lake.snapshot WHERE snapshot_id = %s" % sid4),
                         hashlib.sha256(b"").hexdigest())

        # reserve refusals
        rv = "SET ROLE rs_owner; SELECT vault.reserve(%s);"
        exported = self.refused(rv % ("'UNIT02', NULL, '2026-12-01Z', '2026-12-02Z', 'benchmark hold-out window', "
                                      "'qa1', '%s'" % self.UNIT_ZONE), "already exported: it is no longer held out")
        self.assertIn("22023", self.psql("medcea_research", "\\set VERBOSITY verbose\n" + rv % (
            "'UNIT02', 'z1', '2026-12-01Z', '2026-12-02Z', 'benchmark hold-out window', 'qa1', '%s'" % self.UNIT_ZONE)).stderr)
        self.assertTrue(exported)
        # another zone of the same unit, never exported: allowed
        self.assertRegex(self.q(rv % ("'UNIT02', 'Z9', '2026-12-01Z', '2026-12-02Z', 'benchmark hold-out window', "
                                      "'qa1', '%s'" % self.UNIT_ZONE)), r"^\d+$")
        for args, want in (("'UNIT 1', NULL, '2027-01-01Z', '2027-01-02Z', 'a long enough reason', 'qa1', '%s'",
                            "is not a unit code"),
                           ("'UNIT03', NULL, '2027-01-02Z', '2027-01-01Z', 'a long enough reason', 'qa1', '%s'",
                            "must end after it starts"),
                           ("'UNIT03', NULL, '2027-01-01Z', '2027-01-02Z', 'too short', 'qa1', '%s'",
                            "at least 10 characters"),
                           ("'UNIT03', NULL, '2027-01-01Z', now() + interval '2 years', 'a long enough reason', 'qa1', '%s'",
                            "more than a year from now"),
                           ("'UNIT03', 'z/1', '2027-01-01Z', '2027-01-02Z', 'a long enough reason', 'qa1', '%s'",
                            "is not a zone code")):
            self.refused(rv % (args % self.UNIT_ZONE), want)

    def test_03_append_only_for_everyone(self):
        stmts = ["UPDATE lake.measurement SET value = 0", "DELETE FROM lake.measurement",
                 "TRUNCATE lake.measurement", "UPDATE lake.snapshot SET rows = '{}'", "DELETE FROM lake.snapshot",
                 "TRUNCATE lake.snapshot CASCADE", "DELETE FROM vault.reservation", "TRUNCATE vault.reservation",
                 "UPDATE vault.reservation SET reason = 'changed afterwards'", "DELETE FROM lake.zones"]
        for prefix in ("", "SET ROLE rs_owner;", "SET session_replication_role = replica;"):
            for s in stmts:
                self.refused(prefix + s, "is append-only")
        n = self.q("SELECT count(*) FROM lake.measurement")
        self.assertNotEqual(n, "0")
        enabled = self.q("SELECT string_agg(DISTINCT tgenabled::text, '') FROM pg_trigger WHERE tgname LIKE 'append_only_%'")
        self.assertEqual(enabled, "A")
        self.assertEqual(self.q("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'append_only_%'"), str(2 * (len(APPEND_ONLY) + 7)))   # + agent_trace's seven

    def test_04_the_snapshot_reader(self):
        """After test_02's snapshots: lineage, the digest check's parity with close_snapshot,
        the reader's rights and refusals (Phase 2b)."""
        api = "rs_lake_api"
        read_as = "SET ROLE rs_lake_reader; "
        snaps = [l.split("|") for l in self.q(read_as + "SELECT snapshot_id, digests->>'measurement', lineage "
                                              "FROM lake_api.snapshots()", user=api).splitlines()]
        self.assertGreaterEqual(len(snaps), 4)
        self.assertEqual([x[2] for x in snaps], lineage([x[1] for x in snaps]))
        sys.path.insert(0, os.path.join(REPO, "k8s", "workbench", "examples"))
        import medcea_data
        chain = medcea_data.lineage_chain([{"snapshot_id": int(x[0]), "digests": {"measurement": x[1]}} for x in snaps])
        self.assertEqual([chain[int(x[0])] for x in snaps], [x[2] for x in snaps])
        # every snapshot's digests recompute from the lake rows with close_snapshot's rules,
        # whatever the session's TimeZone and DateStyle
        for sid, _, _ in snaps:
            out = self.q("SET TimeZone = 'Asia/Kolkata'; SET DateStyle = 'SQL, DMY'; "
                         "SELECT \"set\", ok FROM lake.snapshot_digest_check(%s)" % sid)
            got = dict(l.split("|") for l in out.splitlines())
            self.assertEqual(sorted(got), sorted(LAKE.get(x, x) for x in STAGES))
            self.assertEqual(set(got.values()), {"t"}, (sid, out))
        self.refused("SELECT * FROM lake.snapshot_digest_check(999999)", "no snapshot 999999")
        # measurements: up to the snapshot, case-insensitive unit and zone, the window, the limit
        first, last = snaps[0][0], snaps[-1][0]
        n_first = self.q(read_as + "SELECT count(*) FROM lake_api.measurements(%s, 'unit02', 'z1')" % first, user=api)
        n_last = self.q(read_as + "SELECT count(*) FROM lake_api.measurements(%s, 'unit02', 'z1')" % last, user=api)
        self.assertEqual(n_first, "1")
        self.assertGreater(int(n_last), int(n_first))
        self.assertEqual(self.q(read_as + "SELECT count(*) FROM lake_api.measurements(%s, 'UNIT02', 'Z1', 'co2', "
                                          "'2026-12-02 00:05Z', '2026-12-02 02:00Z')" % last, user=api), "2")
        self.assertEqual(self.q(read_as + "SELECT max(snapshot_id) <= %s FROM lake_api.measurements(%s, 'UNIT02', "
                                          "'Z1')" % (first, first), user=api), "t")
        self.assertEqual(self.q(read_as + "SELECT count(*) FROM lake_api.measurements(%s, 'UNIT02', 'Z1', p_limit => 1)"
                                % last, user=api), "1")
        for call, want in (("999999, 'UNIT02', 'Z1'", "no snapshot 999999"),
                           ("%s, NULL, 'Z1'" % last, "a unit and a zone are required"),
                           ("%s, 'UNIT02', 'Z1', p_limit => 0" % last, "between 1 and 50000"),
                           ("%s, 'UNIT02', 'Z1', p_limit => 50001" % last, "between 1 and 50000")):
            self.refused(read_as + "SELECT * FROM lake_api.measurements(%s)" % call, want, user=api)
        # the held-out range never reached the reader
        self.assertEqual(self.q(read_as + "SELECT count(*) FROM lake_api.measurements(%s, 'UNIT01', 'Z1', NULL, "
                                          "'2026-12-01 10:00Z', '2026-12-01 10:59:59Z')" % last, user=api), "0")
        self.assertEqual(self.q(read_as + "SELECT count(*) FROM lake_api.zones(%s)" % first, user=api), "1")
        holds = self.q(read_as + "SELECT * FROM lake_api.holds() LIMIT 1", user=api)
        self.assertEqual(len(holds.split("|")), 4)
        self.assertNotIn("qa1", self.q(read_as + "SELECT * FROM lake_api.holds()", user=api))
        # rights: NOINHERIT, so nothing without the role; the reader no table; read-only, bounded
        self.refused("SELECT * FROM lake_api.holds()", "permission denied", user=api)
        self.refused(read_as + "SELECT count(*) FROM lake.measurement", "permission denied", user=api)
        self.refused(read_as + "SELECT count(*) FROM vault.reservation", "permission denied", user=api)
        self.refused(read_as + "SELECT * FROM lake.snapshot_digest_check(1)", "permission denied", user=api)
        self.refused(read_as + "SELECT lake.latest_cut()", "permission denied", user=api)
        self.refused("CREATE TABLE lake_api.x (a int)", "read-only transaction", user=api)
        self.assertEqual(self.q("SHOW statement_timeout; SHOW default_transaction_read_only; SHOW temp_file_limit",
                                user=api).split(), ["30s", "on", "256MB"])
        # a drift is what the asserts report
        self.q("GRANT SELECT ON lake.measurement TO rs_lake_reader")
        self.assertIn("rs_lake_reader holds SELECT on lake.measurement", self.q(read(ASSERT)))
        self.q("REVOKE SELECT ON lake.measurement FROM rs_lake_reader")
        self.q("ALTER ROLE rs_lake_api RESET temp_file_limit")
        self.assertIn("rs_lake_api lacks its setting temp_file_limit=256MB", self.q(read(ASSERT)))
        self.q("ALTER ROLE rs_lake_api SET temp_file_limit = '256MB'")
        self.assertEqual(self.q(read(ASSERT)), "")


if __name__ == "__main__":
    unittest.main()
