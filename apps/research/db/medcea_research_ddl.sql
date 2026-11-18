-- apps/research/db/medcea_research_ddl.sql — the research sandbox's own database
-- (research sandbox Phase 2a; plan codeplan/research-sandbox-plan.md, "Phase 2a").
--
-- Run by apps/research/deploy.sh as postgres in pod research-postgresql-0 (the
-- research namespace's own PostgreSQL, never the platform's rdbms), connected to the
-- maintenance database `postgres`, SQL on stdin:
--     psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -f - < medcea_research_ddl.sql
-- then db/grants.sql against medcea_research. Re-run safe: every object is created only
-- when missing (CREATE … IF NOT EXISTS, CREATE OR REPLACE), ownership and role
-- attributes are restated on every run.
--
-- Roles (cluster-wide, in the research PostgreSQL only):
--   rs_owner          NOLOGIN, owns the database, the five schemas and everything in them
--   rs_export_writer  LOGIN: the exporter (apps/research-export/): INSERT on lake.stage_*,
--                     EXECUTE lake.close_snapshot and lake.latest_cut (db/grants.sql)
--   rs_backup         LOGIN, pg_read_all_data: the nightly backup's pg_dump (db/grants.sql)
-- Their passwords are set by deploy.sh as SCRAM verifiers in a log_statement=none
-- session, never here.
--
-- Schemas: lake (snapshots of the operational data, append-only), vault (held-out
-- reservations, append-only), sim, agent_trace, registry (created empty in 2a).
--
-- The lake is append-only and a snapshot is a high-water mark (owner decision S,
-- 18 Nov 2026): the exporter stages rows (INSERT only), and lake.close_snapshot moves
-- them into the lake in one transaction, minus every reserved (held-out) range, with
-- per-set row counts and sha256 digests in lake.snapshot. Nothing can UPDATE, DELETE
-- or TRUNCATE a lake table or vault.reservation, rs_owner included: the triggers are
-- ENABLE ALWAYS (session_replication_role=replica does not bypass them). A superuser
-- can still disable a trigger; that is outside what a database can prevent.

SET client_min_messages = warning;

-- ── Roles ─────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_owner') THEN
        CREATE ROLE rs_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_export_writer') THEN
        CREATE ROLE rs_export_writer LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_backup') THEN
        CREATE ROLE rs_backup LOGIN;
    END IF;
END $$;
ALTER ROLE rs_owner         NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE rs_export_writer LOGIN   NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
-- INHERIT: pg_read_all_data reaches rs_backup only through inheritance
ALTER ROLE rs_backup        LOGIN   NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT   NOREPLICATION NOBYPASSRLS;

-- ── Database ──────────────────────────────────────────────────────────────────
SELECT 'CREATE DATABASE medcea_research OWNER rs_owner'
 WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'medcea_research') \gexec
ALTER DATABASE medcea_research OWNER TO rs_owner;

\connect medcea_research
SET client_min_messages = warning;

-- ── Schemas ───────────────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS lake        AUTHORIZATION rs_owner;
CREATE SCHEMA IF NOT EXISTS vault       AUTHORIZATION rs_owner;
CREATE SCHEMA IF NOT EXISTS sim         AUTHORIZATION rs_owner;
CREATE SCHEMA IF NOT EXISTS agent_trace AUTHORIZATION rs_owner;
CREATE SCHEMA IF NOT EXISTS registry    AUTHORIZATION rs_owner;
ALTER SCHEMA lake        OWNER TO rs_owner;
ALTER SCHEMA vault       OWNER TO rs_owner;
ALTER SCHEMA sim         OWNER TO rs_owner;
ALTER SCHEMA agent_trace OWNER TO rs_owner;
ALTER SCHEMA registry    OWNER TO rs_owner;
COMMENT ON SCHEMA sim         IS 'Research sandbox: simulation results (empty until a later phase).';
COMMENT ON SCHEMA agent_trace IS 'Research sandbox: agent traces (empty until a later phase).';
COMMENT ON SCHEMA registry    IS 'Research sandbox: model and candidate registry (empty until a later phase).';

-- Everything below is created by, and so owned by, rs_owner.
SET ROLE rs_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE rs_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- ── lake: staging (one table per operational read function, exactly its columns) ──
-- medcea.research_*() of migration 013 → lake.stage_<name>. The exporter INSERTs here
-- (\copy … FROM STDIN) and lake.close_snapshot empties them; no trigger, no key.
CREATE TABLE IF NOT EXISTS lake.stage_measurements (
    ingested_at timestamptz, measured_at timestamptz, unit_code text, zone_code text,
    tag text, sensor text, value numeric, uom text);
-- the per-hour digest reads one hour at a time (lake._set_digest)
CREATE INDEX IF NOT EXISTS stage_measurements_ingested_at_idx ON lake.stage_measurements (ingested_at);
CREATE TABLE IF NOT EXISTS lake.stage_units (
    unit_code text, recipe_type text, area numeric, height numeric, is_active text);
CREATE TABLE IF NOT EXISTS lake.stage_zones (
    unit_code text, zone_code text, is_active text);
CREATE TABLE IF NOT EXISTS lake.stage_recipes (
    recipe_id integer, recipe_type text, status text);
CREATE TABLE IF NOT EXISTS lake.stage_recipe_lines (
    recipe_id integer, seq integer, cycle_number integer, light_type text,
    light_on_minutes integer, light_off_minutes integer, setpoints jsonb);
CREATE TABLE IF NOT EXISTS lake.stage_runs (
    run_id integer, recipe_id integer, unit_code text, started_at timestamptz,
    ended_at timestamptz, status text);
CREATE TABLE IF NOT EXISTS lake.stage_cycles (
    run_id integer, seq integer, cycle_num integer, started_at timestamptz,
    ended_at timestamptz, status text, algorithm_code text, algorithm_params jsonb,
    control_loops jsonb);
CREATE TABLE IF NOT EXISTS lake.stage_control_loops (
    unit_code text, zone_code text, loop_code text, input jsonb, output jsonb);
CREATE TABLE IF NOT EXISTS lake.stage_param_sets (
    params_id integer, algorithm_code text, unit_code text, params jsonb);
CREATE TABLE IF NOT EXISTS lake.stage_catalogue (
    kind text, code text, doc jsonb);

-- ── lake: snapshots ───────────────────────────────────────────────────────────
-- rows / digests: one key per lake table (measurement, units, zones, recipes,
-- recipe_lines, runs, cycles, control_loops, param_sets, catalogue) → its row count /
-- sha256 hex; rows also has held_out, the staged measurements a reservation kept out.
CREATE TABLE IF NOT EXISTS lake.snapshot (
    snapshot_id      bigserial PRIMARY KEY,
    cut_at           timestamptz NOT NULL,
    previous_cut_at  timestamptz,
    created_at       timestamptz NOT NULL DEFAULT pg_catalog.now(),
    contract_version integer NOT NULL,
    rows             jsonb NOT NULL,
    digests          jsonb NOT NULL,
    CONSTRAINT snapshot_cut_after_previous CHECK (previous_cut_at IS NULL OR cut_at > previous_cut_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS snapshot_cut_at_key ON lake.snapshot (cut_at);
COMMENT ON TABLE lake.snapshot IS
    'One row per export: a high-water mark (cut_at) over the operational ingest time, with per-set row counts and sha256 digests. Append-only.';

-- Measurements accumulate (each snapshot adds the rows ingested in (previous_cut_at, cut_at]);
-- the small sets are copied whole into every snapshot.
CREATE TABLE IF NOT EXISTS lake.measurement (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_measurements);
CREATE INDEX IF NOT EXISTS measurement_snapshot_idx ON lake.measurement (snapshot_id);
CREATE INDEX IF NOT EXISTS measurement_unit_zone_at_idx
    ON lake.measurement (pg_catalog.lower(unit_code), pg_catalog.lower(zone_code), measured_at);
CREATE TABLE IF NOT EXISTS lake.units (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_units);
CREATE TABLE IF NOT EXISTS lake.zones (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_zones);
CREATE TABLE IF NOT EXISTS lake.recipes (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_recipes);
CREATE TABLE IF NOT EXISTS lake.recipe_lines (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_recipe_lines);
CREATE TABLE IF NOT EXISTS lake.runs (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_runs);
CREATE TABLE IF NOT EXISTS lake.cycles (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_cycles);
CREATE TABLE IF NOT EXISTS lake.control_loops (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_control_loops);
CREATE TABLE IF NOT EXISTS lake.param_sets (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_param_sets);
CREATE TABLE IF NOT EXISTS lake.catalogue (
    snapshot_id bigint NOT NULL REFERENCES lake.snapshot (snapshot_id), LIKE lake.stage_catalogue);
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['units', 'zones', 'recipes', 'recipe_lines', 'runs', 'cycles',
                             'control_loops', 'param_sets', 'catalogue'] LOOP
        EXECUTE pg_catalog.format('CREATE INDEX IF NOT EXISTS %I ON lake.%I (snapshot_id)', t || '_snapshot_idx', t);
    END LOOP;
END $$;

-- ── vault: held-out reservations ──────────────────────────────────────────────
-- A reservation keeps a unit's (or one zone's) measurements with measured_at in
-- [from_at, to_at) out of every snapshot from then on: lake.close_snapshot drops them
-- while moving staged rows in. Made only by a qa person through apps/research/reserve.sh
-- (vault.reserve, as rs_owner); never changed or removed (append-only).
CREATE TABLE IF NOT EXISTS vault.reservation (
    reservation_id bigserial PRIMARY KEY,
    unit_code      text NOT NULL,
    zone_code      text,
    from_at        timestamptz NOT NULL,
    to_at          timestamptz NOT NULL,
    reason         text NOT NULL,
    by_username    text NOT NULL,
    by_sub         uuid NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT reservation_unit_code_chk CHECK (unit_code ~ '^[A-Za-z0-9_-]+$'),
    CONSTRAINT reservation_zone_code_chk CHECK (zone_code IS NULL OR zone_code ~ '^[A-Za-z0-9_-]+$'),
    CONSTRAINT reservation_range_chk     CHECK (to_at > from_at),
    CONSTRAINT reservation_reason_chk    CHECK (pg_catalog.length(pg_catalog.btrim(reason)) >= 10),
    CONSTRAINT reservation_by_chk        CHECK (pg_catalog.btrim(by_username) <> '')
);
COMMENT ON TABLE vault.reservation IS
    'Held-out ranges (zone NULL = every zone of the unit; measured_at in [from_at, to_at)). Written by vault.reserve only. Append-only.';

-- ── Append-only, for the owner too ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION lake.refuse_change() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only: % refused', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
REVOKE ALL ON FUNCTION lake.refuse_change() FROM PUBLIC;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['lake.snapshot', 'lake.measurement', 'lake.units', 'lake.zones',
                             'lake.recipes', 'lake.recipe_lines', 'lake.runs', 'lake.cycles',
                             'lake.control_loops', 'lake.param_sets', 'lake.catalogue',
                             'vault.reservation'] LOOP
        EXECUTE pg_catalog.format('CREATE OR REPLACE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON %s '
                                  'FOR EACH ROW EXECUTE FUNCTION lake.refuse_change()', t);
        EXECUTE pg_catalog.format('CREATE OR REPLACE TRIGGER append_only_truncate BEFORE TRUNCATE ON %s '
                                  'FOR EACH STATEMENT EXECUTE FUNCTION lake.refuse_change()', t);
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ALWAYS TRIGGER append_only_row', t);
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ALWAYS TRIGGER append_only_truncate', t);
    END LOOP;
END $$;

-- ── lake.latest_cut, lake.close_snapshot ──────────────────────────────────────
-- The cut of the newest snapshot (cuts only grow), NULL before the first one.
CREATE OR REPLACE FUNCTION lake.latest_cut() RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT pg_catalog.max(s.cut_at) FROM lake.snapshot s
$$;
REVOKE ALL ON FUNCTION lake.latest_cut() FROM PUBLIC;

-- _set_digest(stage table) → its row count and a sha256 hex digest of its rows. A row's
-- text is its record output form (x::text) under TimeZone UTC and DateStyle ISO, both
-- pinned by the function's own SET clauses so the session cannot move a digest; rows
-- are sorted bytewise (COLLATE "C").
--   The small sets: sha256 of the sorted row texts joined with newlines (the empty set
--   digests the empty string).
--   stage_measurements, which a first export or a backlog can make large, is digested
--   per hour of ingested_at (UTC), so no one aggregate holds more than an hour of rows
--   (the pod has 2Gi): for each hour H holding rows, oldest first, the line
--       <H as YYYY-MM-DDTHH:00:00Z>|<rows in H>|<sha256 hex of H's sorted row texts joined with newlines>
--   and the digest is sha256 of those lines joined with newlines (no rows: the empty
--   string, as for a small set). A row without an ingest time (close_snapshot refuses
--   those before it digests) would form the last line, "none|<rows>|<hex>".
CREATE OR REPLACE FUNCTION lake._set_digest(p_stage text, OUT n bigint, OUT digest text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path = pg_catalog SET TimeZone = 'UTC' SET DateStyle = 'ISO, YMD' AS $$
DECLARE
    h     record;
    hd    text;
    lines text[] := '{}';
BEGIN
    IF p_stage IS NULL OR p_stage !~ '^stage_[a-z_]+$' THEN
        RAISE EXCEPTION '_set_digest: % is not a staging table', p_stage USING ERRCODE = '22023';
    END IF;
    IF p_stage = 'stage_measurements' THEN
        n := 0;
        FOR h IN SELECT pg_catalog.date_trunc('hour', m.ingested_at) AS hour, pg_catalog.count(*) AS c
                   FROM lake.stage_measurements m GROUP BY 1 ORDER BY 1 NULLS LAST LOOP
            SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                       coalesce(pg_catalog.string_agg(x::text, E'\n' ORDER BY x::text COLLATE "C"), ''), 'UTF8')), 'hex')
              INTO hd
              FROM lake.stage_measurements x
             WHERE CASE WHEN h.hour IS NULL THEN x.ingested_at IS NULL
                        ELSE x.ingested_at >= h.hour AND x.ingested_at < h.hour + interval '1 hour' END;
            lines := lines || (coalesce(pg_catalog.to_char(h.hour, 'YYYY-MM-DD"T"HH24":00:00Z"'), 'none')
                               || '|' || h.c::text || '|' || hd);
            n := n + h.c;
        END LOOP;
        digest := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                      pg_catalog.array_to_string(lines, E'\n'), 'UTF8')), 'hex');
        RETURN;
    END IF;
    EXECUTE pg_catalog.format(
        'SELECT pg_catalog.count(*), pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to('
        'coalesce(pg_catalog.string_agg(x::text, E''\n'' ORDER BY x::text COLLATE "C"), ''''), ''UTF8'')), ''hex'') '
        'FROM lake.%I x', p_stage)
        INTO n, digest;
END $$;
REVOKE ALL ON FUNCTION lake._set_digest(text) FROM PUBLIC;

-- close_snapshot(cut, previous, contract) → the new snapshot_id. The exporter calls it
-- last, in the same READ COMMITTED transaction that staged the rows. Refusals (22023):
-- a contract version this database does not know; p_previous not the latest snapshot's
-- cut (another export ran in between: start again from lake.latest_cut()); a cut not
-- after it; a staged measurement whose ingest time is outside (previous, cut]; another
-- isolation level (it must see a reservation committed while the rows were staged).
CREATE OR REPLACE FUNCTION lake.close_snapshot(p_cut_at timestamptz, p_previous timestamptz, p_contract integer)
    RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog SET TimeZone = 'UTC' AS $$
DECLARE
    known_contracts CONSTANT integer[] := ARRAY[1];
    sets CONSTANT text[] := ARRAY['measurement', 'units', 'zones', 'recipes', 'recipe_lines', 'runs',
                                  'cycles', 'control_loops', 'param_sets', 'catalogue'];
    stages CONSTANT text[] := ARRAY['stage_measurements', 'stage_units', 'stage_zones', 'stage_recipes',
                                    'stage_recipe_lines', 'stage_runs', 'stage_cycles', 'stage_control_loops',
                                    'stage_param_sets', 'stage_catalogue'];
    v_latest  timestamptz;
    v_bad     bigint;
    v_held    bigint;
    v_rows    jsonb := '{}';
    v_digests jsonb := '{}';
    v_id      bigint;
    d         record;
    i         integer;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'close_snapshot: run it in a READ COMMITTED transaction, not %',
            pg_catalog.current_setting('transaction_isolation') USING ERRCODE = '22023';
    END IF;
    -- one export or reservation at a time (vault.reserve takes the same lock)
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.lake'));
    IF p_contract IS NULL OR NOT (p_contract = ANY (known_contracts)) THEN
        RAISE EXCEPTION 'close_snapshot: contract version % is not one this research database knows (%)',
            coalesce(p_contract::text, 'NULL'), pg_catalog.array_to_string(known_contracts, ', ')
            USING ERRCODE = '22023';
    END IF;
    v_latest := lake.latest_cut();
    IF p_previous IS DISTINCT FROM v_latest THEN
        RAISE EXCEPTION 'close_snapshot: the previous cut % is not the latest snapshot''s (%): another export ran; start again from lake.latest_cut()',
            coalesce(p_previous::text, 'NULL'), coalesce(v_latest::text, 'none yet')
            USING ERRCODE = '22023';
    END IF;
    IF p_cut_at IS NULL OR (v_latest IS NOT NULL AND p_cut_at <= v_latest) THEN
        RAISE EXCEPTION 'close_snapshot: the cut % must be later than the previous cut %',
            coalesce(p_cut_at::text, 'NULL'), coalesce(v_latest::text, 'none yet')
            USING ERRCODE = '22023';
    END IF;
    SELECT pg_catalog.count(*) INTO v_bad FROM lake.stage_measurements m
     WHERE m.ingested_at IS NULL OR m.ingested_at > p_cut_at
        OR (p_previous IS NOT NULL AND m.ingested_at <= p_previous);
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'close_snapshot: % staged measurement(s) have an ingest time outside (%, %]',
            v_bad, coalesce(p_previous::text, 'the beginning'), p_cut_at USING ERRCODE = '22023';
    END IF;

    -- held out: never reaches the lake
    DELETE FROM lake.stage_measurements m
     WHERE EXISTS (SELECT 1 FROM vault.reservation r
                    WHERE pg_catalog.lower(r.unit_code) = pg_catalog.lower(m.unit_code)
                      AND (r.zone_code IS NULL OR pg_catalog.lower(r.zone_code) = pg_catalog.lower(m.zone_code))
                      AND m.measured_at >= r.from_at AND m.measured_at < r.to_at);
    GET DIAGNOSTICS v_held = ROW_COUNT;

    FOR i IN 1 .. pg_catalog.array_length(sets, 1) LOOP
        SELECT * INTO d FROM lake._set_digest(stages[i]);
        v_rows := v_rows || pg_catalog.jsonb_build_object(sets[i], d.n);
        v_digests := v_digests || pg_catalog.jsonb_build_object(sets[i], d.digest);
    END LOOP;
    v_rows := v_rows || pg_catalog.jsonb_build_object('held_out', v_held);

    INSERT INTO lake.snapshot (cut_at, previous_cut_at, contract_version, rows, digests)
    VALUES (p_cut_at, p_previous, p_contract, v_rows, v_digests)
    RETURNING snapshot_id INTO v_id;

    FOR i IN 1 .. pg_catalog.array_length(sets, 1) LOOP
        EXECUTE pg_catalog.format('INSERT INTO lake.%I SELECT $1, x.* FROM lake.%I x', sets[i], stages[i]) USING v_id;
        EXECUTE pg_catalog.format('DELETE FROM lake.%I', stages[i]);
    END LOOP;
    RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION lake.close_snapshot(timestamptz, timestamptz, integer) FROM PUBLIC;

-- ── vault.reserve, vault.reserved_rows_in ─────────────────────────────────────
-- reserve(unit, zone|NULL, from, to, reason, by username, by sub) → reservation_id.
-- Called by apps/research/reserve.sh as rs_owner (no grant to anyone else), after it
-- resolved the qa person in Keycloak. Refusals (22023): a unit or zone code outside
-- [A-Za-z0-9_-]; to not after from; a range ending more than a year from now; a reason
-- shorter than 10 characters; no username or sub; a range that overlaps measurements
-- already in the lake for that unit (and zone): those are exported, no longer held out.
CREATE OR REPLACE FUNCTION vault.reserve(p_unit text, p_zone text, p_from timestamptz, p_to timestamptz,
                                         p_reason text, p_by_username text, p_by_sub uuid)
    RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_zone text := NULLIF(pg_catalog.btrim(p_zone), '');
    v_id   bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.lake'));
    IF p_unit IS NULL OR p_unit !~ '^[A-Za-z0-9_-]+$' THEN
        RAISE EXCEPTION 'reserve: % is not a unit code (letters, digits, _ and - only)',
            coalesce(p_unit, 'NULL') USING ERRCODE = '22023';
    END IF;
    IF v_zone IS NOT NULL AND v_zone !~ '^[A-Za-z0-9_-]+$' THEN
        RAISE EXCEPTION 'reserve: % is not a zone code (letters, digits, _ and - only)', v_zone USING ERRCODE = '22023';
    END IF;
    IF p_from IS NULL OR p_to IS NULL OR p_to <= p_from THEN
        RAISE EXCEPTION 'reserve: the range must end after it starts (from %, to %)',
            coalesce(p_from::text, 'NULL'), coalesce(p_to::text, 'NULL') USING ERRCODE = '22023';
    END IF;
    IF p_to > pg_catalog.now() + interval '1 year' THEN
        RAISE EXCEPTION 'reserve: the range ends at %, more than a year from now', p_to USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NULL OR pg_catalog.length(pg_catalog.btrim(p_reason)) < 10 THEN
        RAISE EXCEPTION 'reserve: the reason must be at least 10 characters' USING ERRCODE = '22023';
    END IF;
    IF coalesce(pg_catalog.btrim(p_by_username), '') = '' OR p_by_sub IS NULL THEN
        RAISE EXCEPTION 'reserve: who reserves it (username and Keycloak sub) is required' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM lake.measurement m
                WHERE pg_catalog.lower(m.unit_code) = pg_catalog.lower(p_unit)
                  AND (v_zone IS NULL OR pg_catalog.lower(m.zone_code) = pg_catalog.lower(v_zone))
                  AND m.measured_at >= p_from AND m.measured_at < p_to) THEN
        RAISE EXCEPTION 'reserve: unit % % from % to % is already exported: it is no longer held out',
            p_unit, coalesce('zone ' || v_zone, '(every zone)'), p_from, p_to USING ERRCODE = '22023';
    END IF;
    INSERT INTO vault.reservation (unit_code, zone_code, from_at, to_at, reason, by_username, by_sub)
    VALUES (p_unit, v_zone, p_from, p_to, pg_catalog.btrim(p_reason), pg_catalog.btrim(p_by_username), p_by_sub)
    RETURNING reservation_id INTO v_id;
    RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION vault.reserve(text, text, timestamptz, timestamptz, text, text, uuid) FROM PUBLIC;

-- The measurement rows of a snapshot that fall inside any reservation. Health
-- (rsexport) requires 0: close_snapshot drops them and reserve refuses a range already
-- exported, so anything else means the lake was written around them.
CREATE OR REPLACE FUNCTION vault.reserved_rows_in(p_snapshot bigint) RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT pg_catalog.count(*) FROM lake.measurement m
     WHERE m.snapshot_id = p_snapshot
       AND EXISTS (SELECT 1 FROM vault.reservation r
                    WHERE pg_catalog.lower(r.unit_code) = pg_catalog.lower(m.unit_code)
                      AND (r.zone_code IS NULL OR pg_catalog.lower(r.zone_code) = pg_catalog.lower(m.zone_code))
                      AND m.measured_at >= r.from_at AND m.measured_at < r.to_at)
$$;
REVOKE ALL ON FUNCTION vault.reserved_rows_in(bigint) FROM PUBLIC;

RESET ROLE;
