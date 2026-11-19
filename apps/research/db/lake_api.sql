-- apps/research/db/lake_api.sql — the snapshot reader's side of medcea_research (research
-- sandbox Phase 2b, commit A; codeplan/research-sandbox-plan.md "Phase 2b", owner
-- decisions O2-O4 and O20 of 19 Nov 2026).
--
-- Run by apps/research/deploy.sh as postgres in pod research-postgresql-0, connected to
-- medcea_research, SQL on stdin, after db/medcea_research_ddl.sql and before
-- db/grants.sql (which grants what is created here; db/assert_grants.sql checks it):
--     psql -X -U postgres -d medcea_research -v ON_ERROR_STOP=1 -f - < lake_api.sql
-- Re-run safe: roles and the schema are created only when missing, their attributes and
-- settings restated on every run, every function CREATE OR REPLACE.
--
-- Roles (cluster-wide, in the research PostgreSQL only):
--   rs_lake_reader  NOLOGIN NOINHERIT: EXECUTE on the lake_api functions and USAGE on
--                   schema lake_api, nothing else (db/grants.sql). PostgREST's anonymous
--                   role: lake-api has no identity (owner decision O2: network-gated).
--   rs_lake_api     LOGIN NOINHERIT, a member of rs_lake_reader only (PostgREST's
--                   authenticator, which SET ROLEs to it). CONNECTION LIMIT 10;
--                   statement_timeout 30s, default_transaction_read_only on,
--                   temp_file_limit 256MB. Its password is set by deploy.sh as a SCRAM
--                   verifier (RS_LAKE_API_DB_PASS), never here.
--
-- Schema lake_api (owner rs_owner): every function is STABLE, SECURITY DEFINER, owned by
-- rs_owner, SET search_path = pg_catalog, pg_temp (every name qualified), PUBLIC's
-- EXECUTE revoked. What a notebook may read, through lake-api (PostgREST):
--   snapshots()                    every snapshot with its lineage (below)
--   measurements(snapshot, unit, zone, tag, from, to, sensor, limit)
--                                  readings exported up to that snapshot
--   units|zones|recipes|recipe_lines|catalogue(snapshot)
--                                  the rows of exactly that snapshot
--   holds()                        held-out ranges only: never who or why (O4)
-- Runs, cycles, control loops and parameter sets are not exposed (O3: decided at Phase 3).
-- Nothing here names a person: the lake holds none (owner decision P).
--
-- Lineage. A snapshot's measurement digest covers only the rows it added (its
-- increment), so "measurements as of snapshot N" is bound by a chain over every snapshot
-- up to N, in snapshot_id order:
--     L_0 = ''      L_N = hex(sha256(utf8(L_{N-1} || E'\n' || digests->>'measurement')))
-- computed on read (lake.snapshot is append-only, so no stored column). medcea_data.py
-- recomputes it from snapshots() with the same rule.
--
-- lake.snapshot_digest_check(snapshot) (schema lake, no grant: health runs it as postgres)
-- recomputes a snapshot's per-set digests from the lake rows with exactly
-- lake._set_digest's text rules and says, per set, whether they still match.

SET client_min_messages = warning;

-- ── Roles ─────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_lake_reader') THEN
        CREATE ROLE rs_lake_reader NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_lake_api') THEN
        CREATE ROLE rs_lake_api LOGIN NOINHERIT;
    END IF;
END $$;
ALTER ROLE rs_lake_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE rs_lake_api    LOGIN   NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 10;
ALTER ROLE rs_lake_api SET statement_timeout = '30s';
ALTER ROLE rs_lake_api SET default_transaction_read_only = on;
ALTER ROLE rs_lake_api SET temp_file_limit = '256MB';

-- ── Schema ────────────────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS lake_api AUTHORIZATION rs_owner;
ALTER SCHEMA lake_api OWNER TO rs_owner;
COMMENT ON SCHEMA lake_api IS
    'Research sandbox: the snapshot reader (lake-api, PostgREST). Read functions only; no person.';

-- Everything below is created by, and so owned by, rs_owner.
SET ROLE rs_owner;

-- ── snapshots() ───────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION lake_api.snapshots()
    RETURNS TABLE (snapshot_id bigint, cut_at timestamptz, previous_cut_at timestamptz, created_at timestamptz,
                   contract_version integer, "rows" jsonb, digests jsonb, lineage text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE o AS (
        SELECT s.snapshot_id AS sid,
               pg_catalog.row_number() OVER (ORDER BY s.snapshot_id) AS rn,
               coalesce(s.digests ->> 'measurement', '') AS md
          FROM lake.snapshot s
    ), chain AS (
        SELECT o.rn, o.sid,
               pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to('' || E'\n' || o.md, 'UTF8')), 'hex') AS lin
          FROM o WHERE o.rn = 1
        UNION ALL
        SELECT o.rn, o.sid,
               pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(chain.lin || E'\n' || o.md, 'UTF8')), 'hex')
          FROM chain JOIN o ON o.rn = chain.rn + 1
    )
    SELECT s.snapshot_id, s.cut_at, s.previous_cut_at, s.created_at, s.contract_version, s.rows, s.digests, chain.lin
      FROM lake.snapshot s JOIN chain ON chain.sid = s.snapshot_id
     ORDER BY s.snapshot_id
$$;
REVOKE ALL ON FUNCTION lake_api.snapshots() FROM PUBLIC;

-- ── measurements(…) ───────────────────────────────────────────────────────────
-- The readings exported up to snapshot p_snapshot (snapshot_id <= p_snapshot: measurements
-- accumulate, each snapshot adds the rows ingested since the one before) of one unit and
-- zone (case-insensitive, the index measurement_unit_zone_at_idx), optionally one tag and
-- one sensor, measured_at in (p_from, p_to], newest first, at most p_limit rows.
-- Refusals (22023): no such snapshot, no unit or zone, a limit outside 1..50000.
CREATE OR REPLACE FUNCTION lake_api.measurements(p_snapshot bigint, p_unit text, p_zone text,
                                                 p_tag text DEFAULT NULL, p_from timestamptz DEFAULT NULL,
                                                 p_to timestamptz DEFAULT NULL, p_sensor text DEFAULT NULL,
                                                 p_limit integer DEFAULT 50000)
    RETURNS TABLE (snapshot_id bigint, ingested_at timestamptz, measured_at timestamptz, unit_code text,
                   zone_code text, tag text, sensor text, value numeric, uom text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
    IF p_snapshot IS NULL OR NOT EXISTS (SELECT 1 FROM lake.snapshot s WHERE s.snapshot_id = p_snapshot) THEN
        RAISE EXCEPTION 'no snapshot %', coalesce(p_snapshot::text, 'NULL') USING ERRCODE = '22023';
    END IF;
    IF p_unit IS NULL OR p_zone IS NULL THEN
        RAISE EXCEPTION 'measurements: a unit and a zone are required' USING ERRCODE = '22023';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 50000 THEN
        RAISE EXCEPTION 'measurements: the limit must be between 1 and 50000, not %', coalesce(p_limit::text, 'NULL')
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        SELECT m.snapshot_id, m.ingested_at, m.measured_at, m.unit_code, m.zone_code, m.tag, m.sensor, m.value, m.uom
          FROM lake.measurement m
         WHERE m.snapshot_id <= p_snapshot
           AND pg_catalog.lower(m.unit_code) = pg_catalog.lower(p_unit)
           AND pg_catalog.lower(m.zone_code) = pg_catalog.lower(p_zone)
           AND (p_tag IS NULL OR m.tag = p_tag)
           AND (p_sensor IS NULL OR m.sensor = p_sensor)
           AND (p_from IS NULL OR m.measured_at > p_from)
           AND (p_to IS NULL OR m.measured_at <= p_to)
         ORDER BY m.measured_at DESC
         LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION lake_api.measurements(bigint, text, text, text, timestamptz, timestamptz, text, integer) FROM PUBLIC;

-- ── The small sets of one snapshot ────────────────────────────────────────────
-- Each snapshot holds a whole copy of these: the rows of exactly p_snapshot.
CREATE OR REPLACE FUNCTION lake_api.units(p_snapshot bigint)
    RETURNS TABLE (snapshot_id bigint, unit_code text, recipe_type text, area numeric, height numeric, is_active text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT u.snapshot_id, u.unit_code, u.recipe_type, u.area, u.height, u.is_active
      FROM lake.units u WHERE u.snapshot_id = p_snapshot ORDER BY u.unit_code COLLATE "C"
$$;
REVOKE ALL ON FUNCTION lake_api.units(bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION lake_api.zones(p_snapshot bigint)
    RETURNS TABLE (snapshot_id bigint, unit_code text, zone_code text, is_active text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT z.snapshot_id, z.unit_code, z.zone_code, z.is_active
      FROM lake.zones z WHERE z.snapshot_id = p_snapshot ORDER BY z.unit_code COLLATE "C", z.zone_code COLLATE "C"
$$;
REVOKE ALL ON FUNCTION lake_api.zones(bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION lake_api.recipes(p_snapshot bigint)
    RETURNS TABLE (snapshot_id bigint, recipe_id integer, recipe_type text, status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.snapshot_id, r.recipe_id, r.recipe_type, r.status
      FROM lake.recipes r WHERE r.snapshot_id = p_snapshot ORDER BY r.recipe_id
$$;
REVOKE ALL ON FUNCTION lake_api.recipes(bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION lake_api.recipe_lines(p_snapshot bigint)
    RETURNS TABLE (snapshot_id bigint, recipe_id integer, seq integer, cycle_number integer, light_type text,
                   light_on_minutes integer, light_off_minutes integer, setpoints jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT l.snapshot_id, l.recipe_id, l.seq, l.cycle_number, l.light_type, l.light_on_minutes,
           l.light_off_minutes, l.setpoints
      FROM lake.recipe_lines l WHERE l.snapshot_id = p_snapshot ORDER BY l.recipe_id, l.seq
$$;
REVOKE ALL ON FUNCTION lake_api.recipe_lines(bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION lake_api.catalogue(p_snapshot bigint)
    RETURNS TABLE (snapshot_id bigint, kind text, code text, doc jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.snapshot_id, c.kind, c.code, c.doc
      FROM lake.catalogue c WHERE c.snapshot_id = p_snapshot ORDER BY c.kind COLLATE "C", c.code COLLATE "C"
$$;
REVOKE ALL ON FUNCTION lake_api.catalogue(bigint) FROM PUBLIC;

-- ── holds(): the held-out ranges, never who or why ───────────────────────────
CREATE OR REPLACE FUNCTION lake_api.holds()
    RETURNS TABLE (unit_code text, zone_code text, from_at timestamptz, to_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.unit_code, r.zone_code, r.from_at, r.to_at
      FROM vault.reservation r ORDER BY r.from_at, r.unit_code COLLATE "C", r.zone_code COLLATE "C"
$$;
REVOKE ALL ON FUNCTION lake_api.holds() FROM PUBLIC;

-- ── lake.snapshot_digest_check(snapshot) ──────────────────────────────────────
-- set, recorded (lake.snapshot.digests), recomputed (from the lake rows of that snapshot),
-- ok, one row per set. The recomputation is lake._set_digest's: a row's text is the
-- record output of its staging columns (snapshot_id left out, attnum order), which equals
-- the staging row's x::text; rows sorted bytewise (COLLATE "C"); TimeZone UTC and
-- DateStyle ISO pinned; measurements per hour of ingested_at. 22023: no such snapshot.
CREATE OR REPLACE FUNCTION lake.snapshot_digest_check(p_snapshot bigint)
    RETURNS TABLE ("set" text, recorded text, recomputed text, ok boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' SET DateStyle = 'ISO, YMD' AS $$
DECLARE
    sets CONSTANT text[] := ARRAY['measurement', 'units', 'zones', 'recipes', 'recipe_lines', 'runs',
                                  'cycles', 'control_loops', 'param_sets', 'catalogue'];
    stages CONSTANT text[] := ARRAY['stage_measurements', 'stage_units', 'stage_zones', 'stage_recipes',
                                    'stage_recipe_lines', 'stage_runs', 'stage_cycles', 'stage_control_loops',
                                    'stage_param_sets', 'stage_catalogue'];
    v_digests jsonb;
    v_cols    text;
    v_hex     text;
    v_hd      text;
    v_lines   text[];
    h         record;
    i         integer;
BEGIN
    SELECT s.digests INTO v_digests FROM lake.snapshot s WHERE s.snapshot_id = p_snapshot;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no snapshot %', coalesce(p_snapshot::text, 'NULL') USING ERRCODE = '22023';
    END IF;
    FOR i IN 1 .. pg_catalog.array_length(sets, 1) LOOP
        SELECT pg_catalog.string_agg(pg_catalog.format('x.%I', a.attname), ', ' ORDER BY a.attnum)
          INTO v_cols
          FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = pg_catalog.to_regclass('lake.' || stages[i]) AND a.attnum > 0 AND NOT a.attisdropped;
        IF sets[i] = 'measurement' THEN
            v_lines := '{}';
            FOR h IN SELECT pg_catalog.date_trunc('hour', m.ingested_at) AS hour, pg_catalog.count(*) AS c
                       FROM lake.measurement m WHERE m.snapshot_id = p_snapshot
                      GROUP BY 1 ORDER BY 1 NULLS LAST LOOP
                EXECUTE pg_catalog.format(
                    'SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to('
                    'coalesce(pg_catalog.string_agg(r.t, E''\n'' ORDER BY r.t COLLATE "C"), ''''), ''UTF8'')), ''hex'') '
                    'FROM (SELECT ROW(%s)::text AS t FROM lake.measurement x WHERE x.snapshot_id = $1 '
                    'AND CASE WHEN $2::timestamptz IS NULL THEN x.ingested_at IS NULL '
                    'ELSE x.ingested_at >= $2 AND x.ingested_at < $2 + interval ''1 hour'' END) r', v_cols)
                    INTO v_hd USING p_snapshot, h.hour;
                v_lines := v_lines || (coalesce(pg_catalog.to_char(h.hour, 'YYYY-MM-DD"T"HH24":00:00Z"'), 'none')
                                       || '|' || h.c::text || '|' || v_hd);
            END LOOP;
            v_hex := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                         pg_catalog.array_to_string(v_lines, E'\n'), 'UTF8')), 'hex');
        ELSE
            EXECUTE pg_catalog.format(
                'SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to('
                'coalesce(pg_catalog.string_agg(r.t, E''\n'' ORDER BY r.t COLLATE "C"), ''''), ''UTF8'')), ''hex'') '
                'FROM (SELECT ROW(%s)::text AS t FROM lake.%I x WHERE x.snapshot_id = $1) r', v_cols, sets[i])
                INTO v_hex USING p_snapshot;
        END IF;
        "set" := sets[i];
        recorded := v_digests ->> sets[i];
        recomputed := v_hex;
        ok := recorded IS NOT DISTINCT FROM recomputed;
        RETURN NEXT;
    END LOOP;
END $$;
REVOKE ALL ON FUNCTION lake.snapshot_digest_check(bigint) FROM PUBLIC;

RESET ROLE;
