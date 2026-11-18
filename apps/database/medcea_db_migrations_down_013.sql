-- medcea_db_migrations_down_013.sql — undo migration 013 (the research sandbox's
-- read functions medcea.research_*()) before a `git revert` of that work. Never
-- run by a deploy (a deploy with 013 still in the migration file creates them
-- again). Run by hand, as postgres, in one transaction:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_013.sql
--
-- Revert order: the research export stopped and the policy version that names
-- these functions (group research_export, svc_research_export) rolled back and
-- its grants gone (./apps/database/deploy.sh after it); then this file → git
-- revert of 013 → ./apps/database/deploy.sh.
--
--   1. refused while svc_research_export may execute any of the eleven functions
--      (the policy still grants them: a dropped function would break its grants
--      bundle and the exporter)
--   2. the eleven functions dropped (nothing else depends on them)
--   3. 013:last_nonce removed; PostgREST reloads its schema cache

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE f regprocedure; held text[] := '{}';
BEGIN
    IF pg_catalog.to_regrole('svc_research_export') IS NOT NULL THEN
        FOREACH f IN ARRAY ARRAY[pg_catalog.to_regprocedure('medcea.research_contract_version()'),
                                 pg_catalog.to_regprocedure('medcea.research_measurements(timestamptz,timestamptz)'),
                                 pg_catalog.to_regprocedure('medcea.research_units()'),
                                 pg_catalog.to_regprocedure('medcea.research_zones()'),
                                 pg_catalog.to_regprocedure('medcea.research_recipes()'),
                                 pg_catalog.to_regprocedure('medcea.research_recipe_lines()'),
                                 pg_catalog.to_regprocedure('medcea.research_runs()'),
                                 pg_catalog.to_regprocedure('medcea.research_cycles()'),
                                 pg_catalog.to_regprocedure('medcea.research_control_loops()'),
                                 pg_catalog.to_regprocedure('medcea.research_param_sets()'),
                                 pg_catalog.to_regprocedure('medcea.research_catalogue()')] LOOP
            IF f IS NOT NULL AND pg_catalog.has_function_privilege('svc_research_export', f, 'EXECUTE') THEN
                held := held || f::text;
            END IF;
        END LOOP;
    END IF;
    IF cardinality(held) > 0 THEN
        RAISE EXCEPTION 'down 013: svc_research_export may still execute %; roll back the policy version that grants them and run ./apps/database/deploy.sh first', held;
    END IF;
END $$;

DROP FUNCTION IF EXISTS medcea.research_contract_version();
DROP FUNCTION IF EXISTS medcea.research_measurements(timestamptz, timestamptz);
DROP FUNCTION IF EXISTS medcea.research_units();
DROP FUNCTION IF EXISTS medcea.research_zones();
DROP FUNCTION IF EXISTS medcea.research_recipes();
DROP FUNCTION IF EXISTS medcea.research_recipe_lines();
DROP FUNCTION IF EXISTS medcea.research_runs();
DROP FUNCTION IF EXISTS medcea.research_cycles();
DROP FUNCTION IF EXISTS medcea.research_control_loops();
DROP FUNCTION IF EXISTS medcea.research_param_sets();
DROP FUNCTION IF EXISTS medcea.research_catalogue();

DELETE FROM medcea.platform_setting WHERE key = '013:last_nonce';

NOTIFY pgrst, 'reload schema';
