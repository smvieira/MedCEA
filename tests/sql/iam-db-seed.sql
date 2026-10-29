-- tests/sql/iam-db-seed.sql — seed data for the throwaway instance of
-- tests/iam-db-fixture.sh, loaded on top of production's schema and medcea data
-- BEFORE migration 008b, so 008b meets the cases it must handle:
--   • parameter-set copy (_resolve_algorithm mirror): empty default_params, the
--     IF_THEN_ELSE fallback, a schedule whose algorithm differs from its
--     assignment's, an assignment with allowed=false, a non-object algorithm_params
--   • a board moved between zones with telemetry before and after the move, and
--     a reading from an unregistered board (cea-un-*), for the zone backfill
--   • unit codes containing a space and '+', for the code CHECK listing
--   • an existing board credential (serial backfill)
--   • two iam_policy.history events appended with 008a's function
--   • for the runner (tests/iam-runner.sh, IAM plan 2.4): an ACTUATOR on the CONTROL
--     board of IAMT01/Z02, so a run on IAMT01 starts its agent; recipe IAMTEST-R0,
--     one 0-minute line of two cycles, assigned to IAMT01 (a run ends at once); and
--     an operator (UUID aaaaaaaa-…) assigned to IAMT01/Z02 for assigned_run
-- Everything is named IAMT* / iamt*, on its own site. Statements run one by one
-- (autocommit), so the slot history and the readings get distinct timestamps.
\set ON_ERROR_STOP on

-- the code CHECKs are added only once no code violates them, and production may
-- have them by now: drop them here so 008b meets a database from before they
-- existed (it lists the bad codes below and leaves the CHECKs out while they exist)
ALTER TABLE medcea.cea_unit DROP CONSTRAINT IF EXISTS cea_unit_code_chk;
ALTER TABLE medcea.cea_zone DROP CONSTRAINT IF EXISTS cea_zone_code_chk;
-- likewise 008b's one-shot data steps: production has run them by now, so clear
-- their markers and the first apply grandfathers this seed's definitions and
-- parameter sets, as on a database from before 008b (the step skips anything that
-- already has an approval with the same digest, i.e. production's own)
DELETE FROM medcea.platform_setting WHERE key IN ('008b:definitions_grandfathered', '008b:params_grandfathered');

INSERT INTO medcea.cea_location (name, description, is_active) VALUES ('IAMTEST site', 'tests/iam-db-fixture.sh', 'Y')
RETURNING location_id AS loc \gset
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
VALUES ('Mushrooms', 'iamtest unit 1', :loc, 'Y', 'IAMT01') RETURNING unit_id AS u1 \gset
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
VALUES ('Mushrooms', 'iamtest unit 2', :loc, 'Y', 'IAMT02') RETURNING unit_id AS u2 \gset
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
VALUES ('Other', 'iamtest: a space in the code', :loc, 'Y', 'IAM T03') RETURNING unit_id AS u3 \gset
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
VALUES ('Other', 'iamtest: a + in the code', :loc, 'Y', 'IAM+04') RETURNING unit_id AS u4 \gset
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) VALUES (:u1, 'Z01', 'Y') RETURNING zone_id AS z1a \gset
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) VALUES (:u1, 'Z02', 'Y') RETURNING zone_id AS z1b \gset
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) VALUES (:u2, 'Z01', 'Y') RETURNING zone_id AS z2a \gset
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) VALUES (:u4, 'Z01', 'Y') RETURNING zone_id AS z4 \gset

-- a SENSE board placed in IAMT01/Z01, read, moved to IAMT02/Z01, read again
INSERT INTO medcea.device (zone_id, device_type, serial_number, dns_name, is_active)
VALUES (:z1a, 'SENSE', 'iamt-aa:bb:cc:00:00:01', 'iamt01-s-z01', 'Y') RETURNING device_id AS dmove \gset
SELECT pg_sleep(0.05);
INSERT INTO medcea.measurement (measure_timestamp, device_id, device_dns, msg_type, msg)
VALUES (clock_timestamp(), 'iamt-aa:bb:cc:00:00:01', 'iamt01-s-z01', 'AP', '{"tag": "air_temperature", "value": 21, "seed": "before move"}');
SELECT pg_sleep(0.05);
UPDATE medcea.device SET zone_id = :z2a, dns_name = 'iamt02-s-z01' WHERE device_id = :dmove;
SELECT pg_sleep(0.05);
INSERT INTO medcea.measurement (measure_timestamp, device_id, device_dns, msg_type, msg)
VALUES (clock_timestamp(), 'iamt-aa:bb:cc:00:00:01', 'iamt02-s-z01', 'AP', '{"tag": "air_temperature", "value": 22, "seed": "after move"}');
-- an unregistered board's reading stays without a zone
INSERT INTO medcea.measurement (measure_timestamp, device_id, device_dns, msg_type, msg)
VALUES (clock_timestamp(), 'iamt-ff:ff:ff:00:00:09', 'cea-un-000009', 'AP', '{"tag": "air_temperature", "value": 0, "seed": "unregistered"}');
-- a CONTROL board with a credential from before 008b (no serial on the credential)
INSERT INTO medcea.device (zone_id, device_type, serial_number, dns_name, is_active)
VALUES (:z1b, 'CONTROL', 'iamt-aa:bb:cc:00:00:02', 'iamt01-c-z02', 'Y') RETURNING device_id AS dctl \gset
INSERT INTO medcea.mqtt_credential (username, password_hash, device_id, role, topic_base)
VALUES ('iamt01-c-z02', '$7$101$c2VlZHNhbHQ=$c2VlZGhhc2g=', :dctl, 'CONTROL', 'medcea/IAMT01/Z02');
-- its relay: get_feedback_control_loop_params finds a unit's actuators
INSERT INTO medcea.component (component_id, device_id, component_type, model, parameters, is_active)
VALUES (nextval('medcea.component_component_id_seq'), :dctl, 'ACTUATOR', 'iamt-relay',
        '{"pin_descriptions": {}, "seed": "tests/sql/iam-db-seed.sql"}', 'Y');

-- recipes and their lines
INSERT INTO medcea.recipe (recipe_name, recipe_description) VALUES ('IAMTEST-R1', 'iamtest recipe 1') RETURNING recipe_id AS r1 \gset
INSERT INTO medcea.recipe (recipe_name, recipe_description) VALUES ('IAMTEST-R2', 'iamtest recipe 2') RETURNING recipe_id AS r2 \gset
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number,
    air_temperature_lower_limit, air_temperature_upper_limit, light_type, light_on_minutes, light_off_minutes,
    co2_lower_limit, co2_upper_limit, hr_lower_limit, hr_upper_limit)
VALUES (:r1, 1, 'IAMT step 1', 1, 18, 24, 'BLUE', 60, 60, 400, 1200, 70, 90),
       (:r2, 1, 'IAMT step 1', 1, 18, 24, 'RED', 60, 60, 400, 1200, 70, 90);
-- R0: a run of it finishes at once (two cycles of 0 + 0 minutes)
INSERT INTO medcea.recipe (recipe_name, recipe_description) VALUES ('IAMTEST-R0', 'iamtest: 0-minute runner recipe') RETURNING recipe_id AS r0 \gset
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number,
    air_temperature_lower_limit, air_temperature_upper_limit, light_type, light_on_minutes, light_off_minutes,
    co2_lower_limit, co2_upper_limit, hr_lower_limit, hr_upper_limit)
VALUES (:r0, 1, 'IAMT zero', 2, 18, 24, 'BLUE', 0, 0, 400, 1200, 70, 90);

-- assignments (recipe x unit) and schedules
SELECT algorithm_id AS pid FROM medcea.control_algorithm WHERE algorithm_code = 'PID' \gset
SELECT algorithm_id AS flc FROM medcea.control_algorithm WHERE algorithm_code = 'FLC' \gset
-- R1/U1: no algorithm (IF_THEN_ELSE fallback, whose default_params are {}), params given
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_id, algorithm_params)
VALUES (:r1, :u1, true, NULL, '{"x": 1}');
-- R1/U2: PID, not allowed — its params are still merged into the schedule's
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_id, algorithm_params)
VALUES (:r1, :u2, false, :pid, '{"kp": 2}');
-- R0/U1: IF_THEN_ELSE with its own parameters (a set of its own, for the runner)
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_id, algorithm_params)
VALUES (:r0, :u1, true, NULL, '{"iamt_runner": 0}');
-- R2/U1: params that are not a JSON object: listed and skipped
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_id, algorithm_params)
VALUES (:r2, :u1, true, :pid, '[1, 2]');
-- S1 on U1/R1: nothing inline -> IF_THEN_ELSE, {} || {"x": 1}
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
VALUES (:u1, :r1, '0 6 * * *', 'iamtest: inherits the assignment');
-- S2 on U2/R1: FLC, while the assignment says PID -> FLC defaults || {"kp": 2} || own
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description, algorithm_id, algorithm_params)
VALUES (:u2, :r1, '0 7 * * *', 'iamtest: algorithm differs from the assignment', :flc, '{"deadband_fraction": 0.2}');

-- the runner's operator, as before unit assignments (IAM 2.8): IAMT01/Z02. Harmless and
-- unused: the seed runs before this tree's migrations, so iam_policy.user_unit does not
-- exist yet here; tests/runner/iam_runner_flow.py assigns the operator unit IAMT01, and
-- tests/iam-db.sh W4 assigns its own operators.
INSERT INTO iam_policy.user_zone (person_sub, zone_id) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', :z1b);

-- the policy history, appended as 008a does
SELECT iam_policy.append_history('fixture_seed', '{"n": 1}', 'tests/sql/iam-db-seed.sql');
SELECT iam_policy.append_history('fixture_seed', '{"n": 2}', 'tests/sql/iam-db-seed.sql');

-- 008b added recipe.status with DEFAULT 'approved' for the rows it found, then
-- 'draft' for new ones. Inserted after 008b (production has it by now), the seed's
-- recipes are drafts; make them what they would have been, as the owner (whom the
-- status guard exempts), so the first apply grandfathers them.
BEGIN;
SELECT medcea_auth._set_internal_actor('migration:008') WHERE pg_catalog.to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL;
SET LOCAL ROLE medcea_owner;
UPDATE medcea.recipe SET status = 'approved'
 WHERE recipe_name LIKE 'IAMTEST-%' AND status = 'draft';
COMMIT;
