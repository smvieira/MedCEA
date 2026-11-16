-- medcea_db_migrations_down_012.sql — undo migration 012 (the eight recipe_line
-- limit columns and control_loop.recipe_lower/recipe_upper dropped) before a
-- `git revert` of that work, and before medcea_db_migrations_down_011.sql, which
-- refuses while the columns are gone. Never run by a deploy (a deploy with 012
-- still in the migration file drops them again). Run by hand, as postgres, in one
-- transaction:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_012.sql
--
-- Revert order: no run in R or S; this file → git revert of 012 → ./apps/database/deploy.sh;
-- to undo 011 as well, run down_011 next (before reverting 011).
--
--   1. refused while a run is in R or S, and while a setpoint of the four legacy
--      quantities is not a whole number (the columns were integers)
--   2. the eight columns added back (nullable, integer: 011's read-only state) and
--      written from setpoints as medcea_owner with the actor migration:down012,
--      with recipe_line_setpoints_trg (which refuses writes to them) disabled for
--      this transaction only; row_digest leaves the eight keys out, so no approved
--      recipe's digest moves
--   3. control_loop.recipe_lower/recipe_upper added back (empty: down_011 fills
--      them for the active loops)
--   4. the views as 011 left them (the columns, then setpoints)
--   5. 012:last_nonce removed; PostgREST reloads its schema cache

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE bad integer;
BEGIN
    IF EXISTS (SELECT 1 FROM medcea.recipe_run WHERE recipe_run_status IN ('R', 'S')) THEN
        RAISE EXCEPTION 'down 012: a run is in R or S; end it first';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid = 'medcea.recipe_line'::regclass
                                                   AND attname = 'air_temperature_lower_limit' AND NOT attisdropped) THEN
        RAISE EXCEPTION 'down 012: recipe_line already has its limit columns; nothing to undo';
    END IF;
    SELECT count(*) INTO bad FROM medcea.recipe_line l, jsonb_each(l.setpoints) e(k, v)
     WHERE e.k IN ('air_temperature', 'air_humidity', 'co2', 'substrate_temperature')
       AND ((v ->> 'lower')::numeric <> trunc((v ->> 'lower')::numeric)
         OR (v ->> 'upper')::numeric <> trunc((v ->> 'upper')::numeric));
    IF bad > 0 THEN
        RAISE EXCEPTION 'down 012: % setpoint(s) are not whole numbers, which the integer limit columns cannot hold; round them first', bad;
    END IF;
END $$;

-- 2. recipe_line
ALTER TABLE medcea.recipe_line
    ADD COLUMN air_temperature_lower_limit integer, ADD COLUMN air_temperature_upper_limit integer,
    ADD COLUMN co2_lower_limit integer, ADD COLUMN co2_upper_limit integer,
    ADD COLUMN hr_lower_limit integer, ADD COLUMN hr_upper_limit integer,
    ADD COLUMN substrate_temperature_lower_limit integer, ADD COLUMN substrate_temperature_upper_limit integer;

DO $$
DECLARE was "char";
BEGIN
    SELECT tgenabled INTO was FROM pg_catalog.pg_trigger
     WHERE tgrelid = 'medcea.recipe_line'::regclass AND tgname = 'recipe_line_setpoints_trg';
    ALTER TABLE medcea.recipe_line DISABLE TRIGGER recipe_line_setpoints_trg;
    PERFORM medcea_auth._set_internal_actor('migration:down012');
    SET LOCAL ROLE medcea_owner;
    UPDATE medcea.recipe_line SET
        air_temperature_lower_limit = (setpoints #>> '{air_temperature,lower}')::numeric,
        air_temperature_upper_limit = (setpoints #>> '{air_temperature,upper}')::numeric,
        hr_lower_limit = (setpoints #>> '{air_humidity,lower}')::numeric,
        hr_upper_limit = (setpoints #>> '{air_humidity,upper}')::numeric,
        co2_lower_limit = (setpoints #>> '{co2,lower}')::numeric,
        co2_upper_limit = (setpoints #>> '{co2,upper}')::numeric,
        substrate_temperature_lower_limit = (setpoints #>> '{substrate_temperature,lower}')::numeric,
        substrate_temperature_upper_limit = (setpoints #>> '{substrate_temperature,upper}')::numeric
     WHERE setpoints ?| ARRAY['air_temperature', 'air_humidity', 'co2', 'substrate_temperature'];
    RESET ROLE;
    IF was = 'A' THEN
        ALTER TABLE medcea.recipe_line ENABLE ALWAYS TRIGGER recipe_line_setpoints_trg;
    ELSE
        ALTER TABLE medcea.recipe_line ENABLE TRIGGER recipe_line_setpoints_trg;
    END IF;
END $$;

-- 3. control_loop
ALTER TABLE medcea.control_loop
    ADD COLUMN IF NOT EXISTS recipe_lower varchar(64) CONSTRAINT control_loop_recipe_lower_chk CHECK (recipe_lower ~ '^[a-z][a-z0-9_]*$'),
    ADD COLUMN IF NOT EXISTS recipe_upper varchar(64) CONSTRAINT control_loop_recipe_upper_chk CHECK (recipe_upper ~ '^[a-z][a-z0-9_]*$');

-- 4. the views
DROP VIEW IF EXISTS medcea.run_watch;
DROP VIEW IF EXISTS medcea.run_history;
CREATE VIEW medcea.run_history WITH (security_invoker = true) AS
 SELECT r.recipe_id, r.recipe_name, r.recipe_description, rl.recipe_item_seq_name, rl.recipe_item_seq_id,
    rl.cycle_number, rlcr.recipe_item_seq_cycle_num, rlcr.recipe_line_seq_cycle_run_start,
    COALESCE(rlcr.recipe_line_seq_cycle_run_end, rlcr.recipe_line_seq_cycle_run_start) AS recipe_line_seq_cycle_run_end,
    rl.air_temperature_lower_limit, rl.air_temperature_upper_limit, rl.light_type, rl.light_on_minutes,
    rl.light_off_minutes, rl.co2_lower_limit, rl.co2_upper_limit, rl.hr_lower_limit, rl.hr_upper_limit,
    rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit, rr.recipe_run_id, rr.unit_id,
    rl.setpoints
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
    rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit, rr.recipe_run_id, rr.unit_id,
    rl.setpoints
   FROM (((medcea.recipe r
     JOIN medcea.recipe_line rl ON ((r.recipe_id = rl.recipe_id)))
     JOIN medcea.recipe_run rr ON ((rr.recipe_id = r.recipe_id)))
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON (((rr.recipe_run_id = rlcr.recipe_run_id) AND (rl.recipe_id = rlcr.recipe_id) AND (rl.recipe_item_seq_id = rlcr.recipe_item_seq_id))))
  WHERE ((rr.recipe_run_status)::text <> 'C'::text)
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;
ALTER VIEW medcea.run_history OWNER TO medcea_owner;
ALTER VIEW medcea.run_watch OWNER TO medcea_owner;
-- the next database deploy grants what the policy compiles
REVOKE ALL ON medcea.run_history, medcea.run_watch FROM PUBLIC, anon, authenticator;

-- 5. the nonce
DELETE FROM medcea.platform_setting WHERE key = '012:last_nonce';
NOTIFY pgrst, 'reload schema';
