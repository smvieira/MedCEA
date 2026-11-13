-- medcea_db_migrations_down_010.sql — undo migration 010 (feedback control
-- Phases 1+2: medcea.control_loop, its guard and functions) before a `git revert`
-- of that work. Never run by a deploy. Run by hand, as postgres, in one
-- transaction:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_010.sql
--
-- Revert order: the policy back first (version 2c's functions, then 2a's member:
-- apply.sh --rollback-to), no run in R or S, then this file → git revert →
-- ./apps/database/deploy.sh. Run it before a full down_008b (-v full=1), which
-- drops medcea._unit_busy() that the guard calls.
--
--   1. refused while a role but the owner may execute save_zone_loops() or
--      zone_loop_context() (the policy's version 2c still names them: the reverted
--      grants would assert functions that no longer exist)
--   2. the guard trigger, then the two functions, their helpers and the guard
--   3. medcea.control_loop parked in schema medcea_retired_010 (no grants), with
--      its rows, identity sequence, index and attribution triggers: the reverted
--      YAML has no member for it and I15 refuses an unclassified relation of
--      medcea, which would roll the reverted deploy's whole bundle back; 010
--      moves it back if it is re-applied
--   4. kept on purpose: the views' sensor column (harmless; dropping it needs
--      DROP VIEW and the grants again), 010:last_nonce (the reverted deploy does
--      not read it), approve_change's and _lock_row's control_loop entries (008b
--      is re-created by the reverted deploy)
--   5. PostgREST reloads its schema cache

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['medcea.save_zone_loops(integer,jsonb)', 'medcea.zone_loop_context(integer)'] LOOP
        IF pg_catalog.to_regprocedure(f) IS NOT NULL
           AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
                        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
                        WHERE p.oid = pg_catalog.to_regprocedure(f) AND a.grantee <> p.proowner
                          AND a.privilege_type = 'EXECUTE') THEN
            RAISE EXCEPTION '% is granted (policy version 2c): roll the policy back first', f
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.control_loop') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS control_loop_busy_trg ON medcea.control_loop;
    END IF;
END $$;

DROP FUNCTION IF EXISTS medcea.save_zone_loops(integer, jsonb), medcea.zone_loop_context(integer),
    medcea._loop_problems(jsonb, text, jsonb, jsonb), medcea._zone_inventory(integer), medcea._loop_quantities(),
    medcea.control_loop_busy_guard();

DO $$
DECLARE g text;
BEGIN
    IF pg_catalog.to_regclass('medcea.control_loop') IS NOT NULL THEN
        IF pg_catalog.to_regnamespace('medcea_retired_010') IS NULL THEN
            CREATE SCHEMA medcea_retired_010 AUTHORIZATION medcea_owner;
            REVOKE ALL ON SCHEMA medcea_retired_010 FROM PUBLIC;
        END IF;
        ALTER TABLE medcea.control_loop SET SCHEMA medcea_retired_010;
        -- no grants: every grantee but the owner loses the table
        FOR g IN SELECT DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident(r.rolname) END
                   FROM pg_catalog.pg_class c
                  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
                   LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
                  WHERE c.oid = 'medcea_retired_010.control_loop'::regclass AND a.grantee <> c.relowner LOOP
            EXECUTE pg_catalog.format('REVOKE ALL ON TABLE medcea_retired_010.control_loop FROM %s', g);
        END LOOP;
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
