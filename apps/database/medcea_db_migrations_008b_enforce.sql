-- medcea_db_migrations_008b_enforce.sql — the IAM_DB_ROLES=true half of
-- migration 008b (IAM plan 2.2/2.3). Applied by apps/database/lib-db-apply.sh
-- (step 6) inside the mode bundle's single transaction, before
-- `cli.py compile grants --mode enforce` (revokes, the compiled grants,
-- memberships, LOGIN, CONNECT, row-level security and the I9/I10/I15
-- assertions). Idempotent and guarded: a steady-state deploy takes no strong
-- lock. Its inverse is medcea_db_migrations_down_008b.sql.
--
--   triggers   iam_* on the regulated and definition tables (draft_only,
--              immutability, new-run defaults, the Q-table guard, assign_only,
--              existing_slot). Named iam_* so they fire before stamp_actor_trg
--              and status_guard_trg (alphabetical), and so the down file finds them.
--   settings   register_mqtt_credential v1 is no longer anon's (grants.py
--              revokes everything from anon anyway); log_statement = 'all' for
--              postgres in this database (break-glass is logged; the deploy
--              sessions turn it off for themselves, so no password reaches the log)
--   retention  the minimum log retention as a CHECK on scheduler_config
--   demotion   an approved definition with no approval or grandfather record,
--              or whose digest no longer matches its last one, becomes a draft
-- Never applied before PostgREST's JWT and pre-request (2b), the services'
-- own roles (2.5), the functions in their code (2.4) and the access service
-- (2.7) are in place: apps/database/deploy.sh refuses IAM_DB_ROLES=true until then.

SET LOCAL lock_timeout = '5s';

-- ── triggers ────────────────────────────────────────────────────────────────
DO $$
DECLARE
    spec text[][] := ARRAY[
        -- table,                  trigger,                  timing/events,                                  function(args)
        ['recipe',                 'iam_draft_only_trg',     'BEFORE UPDATE',                                 'medcea.reject_non_draft_update()'],
        ['control_algorithm',      'iam_draft_only_trg',     'BEFORE UPDATE',                                 'medcea.reject_non_draft_update()'],
        ['unit_algorithm_params',  'iam_draft_only_trg',     'BEFORE UPDATE',                                 'medcea.reject_non_draft_update()'],
        ['recipe_line',            'iam_draft_only_trg',     'BEFORE INSERT OR UPDATE OR DELETE',             'medcea.reject_non_draft_update()'],
        ['recipe_run',             'iam_immutable_trg',      'BEFORE UPDATE OR DELETE',                       'medcea.immutable_row(''owner_exempt'')'],
        ['recipe_run',             'iam_new_run_trg',        'BEFORE INSERT',                                 'medcea.new_run_defaults()'],
        ['recipe_line_cycle_run',  'iam_immutable_trg',      'BEFORE INSERT OR UPDATE OR DELETE',             'medcea.immutable_row(''insert_too'')'],
        ['measurement',            'iam_immutable_trg',      'BEFORE UPDATE OR DELETE',                       'medcea.immutable_row(''no_owner'')'],
        ['algorithm_state',        'iam_state_guard_trg',    'BEFORE UPDATE OR DELETE',                       'medcea.algorithm_state_guard()'],
        ['recipe_unit_permission', 'iam_assign_only_trg',    'BEFORE INSERT OR UPDATE',                       'medcea.assign_only()'],
        ['device',                 'iam_existing_slot_trg',  'BEFORE INSERT OR UPDATE',                       'medcea.existing_slot()']];
    i integer;
BEGIN
    FOR i IN 1 .. array_length(spec, 1) LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = pg_catalog.to_regclass('medcea.' || spec[i][1]) AND tgname = spec[i][2]) THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER %I %s ON medcea.%I FOR EACH ROW EXECUTE FUNCTION %s',
                                      spec[i][2], spec[i][3], spec[i][1], spec[i][4]);
        END IF;
    END LOOP;
END $$;
-- regulated records are not truncated either
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['recipe_run', 'recipe_line_cycle_run', 'measurement'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                        WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t) AND tgname = 'iam_no_truncate_trg') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER iam_no_truncate_trg BEFORE TRUNCATE ON medcea.%I '
                                      'FOR EACH STATEMENT EXECUTE FUNCTION medcea.refuse_change()', t);
        END IF;
    END LOOP;
END $$;

-- ── settings ────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF pg_catalog.to_regprocedure('medcea.register_mqtt_credential(text, text, integer, text, text)') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION medcea.register_mqtt_credential(text, text, integer, text, text) FROM anon;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
                    WHERE s.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
                      AND s.setrole = 'postgres'::regrole AND 'log_statement=all' = ANY (s.setconfig)) THEN
        EXECUTE pg_catalog.format('ALTER ROLE postgres IN DATABASE %I SET log_statement = %L', current_database(), 'all');
    END IF;
END $$;

-- ── retention ───────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'medcea.scheduler_config'::regclass AND conname = 'scheduler_config_retention_chk') THEN
        ALTER TABLE medcea.scheduler_config ADD CONSTRAINT scheduler_config_retention_chk CHECK (
            key NOT IN ('log_compress_days', 'log_delete_days') OR
            CASE WHEN value ~ '^\d{1,9}$' THEN
                 (key = 'log_compress_days' AND value::int >= 1) OR
                 (key = 'log_delete_days' AND value::int >= 30)
            ELSE false END) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = 'medcea.scheduler_config'::regclass AND conname = 'scheduler_config_retention_chk'
                  AND NOT convalidated) THEN
        IF EXISTS (SELECT 1 FROM medcea.scheduler_config
                    WHERE key IN ('log_compress_days', 'log_delete_days')
                      AND NOT CASE WHEN value ~ '^\d{1,9}$' THEN
                                   (key = 'log_compress_days' AND value::int >= 1) OR
                                   (key = 'log_delete_days' AND value::int >= 30) ELSE false END) THEN
            RAISE WARNING 'scheduler_config holds a retention below the minimum (log_compress_days >= 1, log_delete_days >= 30); the CHECK stays NOT VALID until it is changed through propose_setting() and approve_change()';
        ELSE
            ALTER TABLE medcea.scheduler_config VALIDATE CONSTRAINT scheduler_config_retention_chk;
        END IF;
    END IF;
END $$;

-- ── demotion ────────────────────────────────────────────────────────────────
-- as the owner: the guards (draft_only, the status guard) let only the owner do this
SELECT medcea_auth._set_internal_actor('system:deploy');
SET LOCAL ROLE medcea_owner;
DO $$
DECLARE
    r    record;
    l    text := '';
BEGIN
    PERFORM medcea_auth._owner_write(true);
    FOR r IN
        SELECT 'medcea.recipe' AS target, recipe_id AS id FROM medcea.recipe WHERE status = 'approved'
        UNION ALL SELECT 'medcea.control_algorithm', algorithm_id FROM medcea.control_algorithm WHERE status = 'approved'
        UNION ALL SELECT 'medcea.unit_algorithm_params', params_id FROM medcea.unit_algorithm_params WHERE status = 'approved'
    LOOP
        IF NOT medcea_auth._is_approved(r.target, jsonb_build_array(r.id)) THEN
            EXECUTE pg_catalog.format('UPDATE %s SET status = ''draft'' WHERE %I = $1', r.target::regclass,
                CASE r.target WHEN 'medcea.recipe' THEN 'recipe_id' WHEN 'medcea.control_algorithm' THEN 'algorithm_id'
                              ELSE 'params_id' END) USING r.id;
            l := l || pg_catalog.format(' %s %s;', r.target, r.id);
        END IF;
    END LOOP;
    PERFORM medcea_auth._owner_write(false);
    IF l <> '' THEN
        RAISE WARNING 'IAM_DB_ROLES=true: approved definitions without a matching approval are drafts again:%', l;
    END IF;
END $$;
RESET ROLE;
