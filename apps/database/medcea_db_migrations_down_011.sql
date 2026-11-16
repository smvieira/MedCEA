-- medcea_db_migrations_down_011.sql — undo migration 011 (recipe types and
-- metadata-driven setpoints) before a `git revert` of that work, while migration
-- 012 has not run (012 drops the limit columns this file writes back). Never run
-- by a deploy. Run by hand, as postgres, in one transaction:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_011.sql
--
-- Revert order: no run in R or S; this file → git revert → ./apps/database/deploy.sh
-- (010 re-creates its own _loop_quantities, _zone_inventory, _loop_problems,
-- zone_loop_context and save_zone_loops bodies) → the consumers' deploys; the
-- policy's recipe-types version is rolled back last (apply.sh --rollback-to): the
-- reverted grants no longer name the catalogue, which this file parks.
--
--   1. refused while a run is in R or S, while migration 012 has run (no limit
--      columns), while a recipe line holds a setpoint 010's columns cannot hold
--      (light_intensity) or lacks one of the six NOT NULL limits, and while a unit's
--      type has no legacy label; half-bound control loops are refused too (010's
--      table needs both halves): bind or deactivate them first
--   2. the 011 triggers and functions
--   3. recipe_line: the limit columns written back from setpoints, NOT NULL again,
--      setpoints dropped; recipe.recipe_type dropped; cea_unit.unit_type back to the
--      Greens/Mushrooms domain
--   4. control_loop: the recipe columns written back for the four loop codes, input
--      and output NOT NULL with 010's CHECKs, the catalogue foreign key dropped
--   5. the views without setpoints (as the DDL has them, security_invoker)
--   6. the catalogue parked in schema medcea_retired_011 (no grants), with its rows:
--      011 moves nothing back, it seeds the tables again from recipe_types.yaml
--   7. 011:last_nonce removed; PostgREST reloads its schema cache

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE bad text;
BEGIN
    IF EXISTS (SELECT 1 FROM medcea.recipe_run WHERE recipe_run_status IN ('R', 'S')) THEN
        RAISE EXCEPTION 'down 011: a run is in R or S; end it first';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid = 'medcea.recipe_line'::regclass
                                                       AND attname = 'air_temperature_lower_limit' AND NOT attisdropped) THEN
        RAISE EXCEPTION 'down 011: migration 012 has dropped the limit columns; this file cannot undo 011 any more';
    END IF;
    SELECT string_agg(format('%s/%s', recipe_id, recipe_item_seq_id), ', ') INTO bad FROM medcea.recipe_line
     WHERE setpoints ? 'light_intensity'
        OR NOT (setpoints ? 'air_temperature' AND setpoints ? 'air_humidity' AND setpoints ? 'co2')
        OR EXISTS (SELECT 1 FROM jsonb_object_keys(setpoints) k
                    WHERE k NOT IN ('air_temperature', 'air_humidity', 'co2', 'substrate_temperature', 'light_intensity'))
        OR EXISTS (SELECT 1 FROM jsonb_each(setpoints) e
                    WHERE (e.value ->> 'lower')::numeric <> trunc((e.value ->> 'lower')::numeric)
                       OR (e.value ->> 'upper')::numeric <> trunc((e.value ->> 'upper')::numeric));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'down 011: recipe lines whose setpoints 010''s integer limit columns cannot hold: %', bad;
    END IF;
    SELECT string_agg(u.unit_code, ', ') INTO bad FROM medcea.cea_unit u
     LEFT JOIN medcea.recipe_type t ON t.recipe_type_code = u.unit_type
     WHERE t.legacy_unit_type IS NULL;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'down 011: units whose type has no legacy label: %', bad;
    END IF;
    SELECT string_agg(loop_id::text, ', ') INTO bad FROM medcea.control_loop
     WHERE is_active = 'Y' AND (input IS NULL OR output IS NULL);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'down 011: half-bound control loops %: bind or deactivate them first', bad;
    END IF;
END $$;

-- 2. triggers and functions
DROP TRIGGER IF EXISTS recipe_line_setpoints_trg ON medcea.recipe_line;
DROP TRIGGER IF EXISTS recipe_type_fixed_trg ON medcea.recipe;
DROP TRIGGER IF EXISTS recipe_type_match_trg ON medcea.recipe_unit_permission;
DROP TRIGGER IF EXISTS recipe_type_match_trg ON medcea.schedule;
DROP TRIGGER IF EXISTS recipe_type_match_trg ON medcea.recipe_run;
DROP TRIGGER IF EXISTS approval_recipe_complete_trg ON medcea.approval;
DROP FUNCTION IF EXISTS medcea.recipe_line_setpoints_guard();
DROP FUNCTION IF EXISTS medcea.recipe_type_fixed();
DROP FUNCTION IF EXISTS medcea.recipe_type_match();
DROP FUNCTION IF EXISTS medcea.approval_recipe_complete();
DROP FUNCTION IF EXISTS medcea._recipe_quantities(text);
DROP FUNCTION IF EXISTS medcea._unit_quantities(integer);
DROP FUNCTION IF EXISTS medcea._loop_check(jsonb, text, jsonb, jsonb, jsonb, text);

-- 3. recipe_line, recipe, cea_unit
SELECT medcea_auth._set_internal_actor('migration:down-011');
SET LOCAL ROLE medcea_owner;
UPDATE medcea.recipe_line SET
    air_temperature_lower_limit = (setpoints #>> '{air_temperature,lower}')::numeric,
    air_temperature_upper_limit = (setpoints #>> '{air_temperature,upper}')::numeric,
    hr_lower_limit = (setpoints #>> '{air_humidity,lower}')::numeric,
    hr_upper_limit = (setpoints #>> '{air_humidity,upper}')::numeric,
    co2_lower_limit = (setpoints #>> '{co2,lower}')::numeric,
    co2_upper_limit = (setpoints #>> '{co2,upper}')::numeric,
    substrate_temperature_lower_limit = (setpoints #>> '{substrate_temperature,lower}')::numeric,
    substrate_temperature_upper_limit = (setpoints #>> '{substrate_temperature,upper}')::numeric;
RESET ROLE;
ALTER TABLE medcea.recipe_line
    ALTER COLUMN air_temperature_lower_limit SET NOT NULL, ALTER COLUMN air_temperature_upper_limit SET NOT NULL,
    ALTER COLUMN co2_lower_limit SET NOT NULL, ALTER COLUMN co2_upper_limit SET NOT NULL,
    ALTER COLUMN hr_lower_limit SET NOT NULL, ALTER COLUMN hr_upper_limit SET NOT NULL;

-- 5 (before the column drops). the views as the DDL has them
DROP VIEW IF EXISTS medcea.run_history;
DROP VIEW IF EXISTS medcea.run_watch;
CREATE VIEW medcea.run_history WITH (security_invoker = true) AS
 SELECT r.recipe_id, r.recipe_name, r.recipe_description, rl.recipe_item_seq_name, rl.recipe_item_seq_id,
    rl.cycle_number, rlcr.recipe_item_seq_cycle_num, rlcr.recipe_line_seq_cycle_run_start,
    COALESCE(rlcr.recipe_line_seq_cycle_run_end, rlcr.recipe_line_seq_cycle_run_start) AS recipe_line_seq_cycle_run_end,
    rl.air_temperature_lower_limit, rl.air_temperature_upper_limit, rl.light_type, rl.light_on_minutes,
    rl.light_off_minutes, rl.co2_lower_limit, rl.co2_upper_limit, rl.hr_lower_limit, rl.hr_upper_limit,
    rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit, rr.recipe_run_id, rr.unit_id
   FROM (((medcea.recipe r
     JOIN medcea.recipe_line rl ON ((r.recipe_id = rl.recipe_id)))
     JOIN medcea.recipe_run rr ON ((rr.recipe_id = r.recipe_id)))
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON (((rr.recipe_run_id = rlcr.recipe_run_id) AND (rl.recipe_id = rlcr.recipe_id) AND (rl.recipe_item_seq_id = rlcr.recipe_item_seq_id))))
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;
CREATE VIEW medcea.run_watch WITH (security_invoker = true) AS
 SELECT r.recipe_id, r.recipe_name, r.recipe_description, rl.recipe_item_seq_name, rl.recipe_item_seq_id,
    rl.cycle_number, rlcr.recipe_item_seq_cycle_num, rlcr.recipe_line_seq_cycle_run_start,
    rlcr.recipe_line_seq_cycle_run_end,
    rl.air_temperature_lower_limit, rl.air_temperature_upper_limit, rl.light_type, rl.light_on_minutes,
    rl.light_off_minutes, rl.co2_lower_limit, rl.co2_upper_limit, rl.hr_lower_limit, rl.hr_upper_limit,
    rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit, rr.recipe_run_id, rr.unit_id
   FROM (((medcea.recipe r
     JOIN medcea.recipe_line rl ON ((r.recipe_id = rl.recipe_id)))
     JOIN medcea.recipe_run rr ON ((rr.recipe_id = r.recipe_id)))
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON (((rr.recipe_run_id = rlcr.recipe_run_id) AND (rl.recipe_id = rlcr.recipe_id) AND (rl.recipe_item_seq_id = rlcr.recipe_item_seq_id))))
  WHERE ((rr.recipe_run_status)::text <> 'C'::text)
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;
ALTER VIEW medcea.run_history OWNER TO medcea_owner;
ALTER VIEW medcea.run_watch OWNER TO medcea_owner;
REVOKE ALL ON medcea.run_history, medcea.run_watch FROM PUBLIC, anon, authenticator;

ALTER TABLE medcea.recipe_line DROP COLUMN setpoints;
ALTER TABLE medcea.recipe DROP COLUMN recipe_type;
ALTER TABLE medcea.cea_unit DROP CONSTRAINT IF EXISTS cea_unit_recipe_type_fkey;
DO $$
DECLARE m text;
BEGIN
    SELECT string_agg(format('WHEN %L THEN %L', t.recipe_type_code, t.legacy_unit_type), ' ')
      INTO m FROM medcea.recipe_type t WHERE t.legacy_unit_type IS NOT NULL;
    EXECUTE format('ALTER TABLE medcea.cea_unit ALTER COLUMN unit_type TYPE medcea.unit_type USING '
                   '(CASE unit_type %s END)::medcea.unit_type', m);
END $$;

-- 4. control_loop
ALTER TABLE medcea.control_loop DROP CONSTRAINT IF EXISTS control_loop_quantity_fkey;
ALTER TABLE medcea.control_loop DROP CONSTRAINT IF EXISTS control_loop_half_chk;
DO $$
DECLARE def text;
BEGIN
    SET LOCAL ROLE medcea_owner;
    UPDATE medcea.control_loop SET
        recipe_lower = CASE loop_code WHEN 'air_temperature' THEN 'air_temperature_lower_limit'
                                      WHEN 'air_humidity' THEN 'hr_lower_limit' WHEN 'co2' THEN 'co2_lower_limit'
                                      WHEN 'substrate_temperature' THEN 'substrate_temperature_lower_limit' END,
        recipe_upper = CASE loop_code WHEN 'air_temperature' THEN 'air_temperature_upper_limit'
                                      WHEN 'air_humidity' THEN 'hr_upper_limit' WHEN 'co2' THEN 'co2_upper_limit'
                                      WHEN 'substrate_temperature' THEN 'substrate_temperature_upper_limit' END
     WHERE is_active = 'Y';
    RESET ROLE;
    -- inactive half-bound rows: both halves needed by 010's NOT NULL; an empty object
    -- breaks 010's CHECK, so they are given the active row shape's minimum
    UPDATE medcea.control_loop SET input = coalesce(input, '{"tag": "x", "sources": ["x"], "rule": "mean"}'::jsonb),
                                   output = coalesce(output, '{"actuator": "x", "mode": "command"}'::jsonb)
     WHERE input IS NULL OR output IS NULL;
    FOREACH def IN ARRAY ARRAY['input', 'output'] LOOP
        EXECUTE format('ALTER TABLE medcea.control_loop ALTER COLUMN %I SET NOT NULL', def);
    END LOOP;
    SELECT pg_catalog.pg_get_constraintdef(oid) INTO def FROM pg_catalog.pg_constraint
     WHERE conrelid = 'medcea.control_loop'::regclass AND conname = 'control_loop_input_chk';
    IF def LIKE 'CHECK (((input IS NULL) OR %' THEN
        ALTER TABLE medcea.control_loop DROP CONSTRAINT control_loop_input_chk;
        EXECUTE 'ALTER TABLE medcea.control_loop ADD CONSTRAINT control_loop_input_chk CHECK ('
                || substr(def, length('CHECK (((input IS NULL) OR ') + 1, length(def) - length('CHECK (((input IS NULL) OR ') - 2)
                || ')';
    END IF;
    SELECT pg_catalog.pg_get_constraintdef(oid) INTO def FROM pg_catalog.pg_constraint
     WHERE conrelid = 'medcea.control_loop'::regclass AND conname = 'control_loop_output_chk';
    IF def LIKE 'CHECK (((output IS NULL) OR %' THEN
        ALTER TABLE medcea.control_loop DROP CONSTRAINT control_loop_output_chk;
        EXECUTE 'ALTER TABLE medcea.control_loop ADD CONSTRAINT control_loop_output_chk CHECK ('
                || substr(def, length('CHECK (((output IS NULL) OR ') + 1, length(def) - length('CHECK (((output IS NULL) OR ') - 2)
                || ')';
    END IF;
END $$;

-- 6. the catalogue parked
CREATE SCHEMA IF NOT EXISTS medcea_retired_011 AUTHORIZATION medcea_owner;
REVOKE ALL ON SCHEMA medcea_retired_011 FROM PUBLIC;
ALTER TABLE medcea.recipe_type_quantity SET SCHEMA medcea_retired_011;
ALTER TABLE medcea.control_quantity SET SCHEMA medcea_retired_011;
ALTER TABLE medcea.recipe_type SET SCHEMA medcea_retired_011;

-- 7.
DELETE FROM medcea.platform_setting WHERE key = '011:last_nonce';
NOTIFY pgrst, 'reload schema';
