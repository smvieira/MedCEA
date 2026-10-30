-- apps/access/rollback-2.7.sql — take back what IAM 2.7 granted outside schema iam, and
-- park what the pre-2.7 access_db.sql cannot hold. Run once, as postgres, in one
-- transaction, AFTER the access proxy has been narrowed to admin and the code reverted,
-- and BEFORE the reverted ./apps/access/deploy.sh (spec 7.4, step 2). Keep it from the
-- 2.7 tree:
--
--   git show <2.7 commit>:apps/access/rollback-2.7.sql | kubectl exec -i -n medcea rdbms-postgresql-0 -- \
--     sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -'
--
-- 1. access_svc keeps nothing in medcea, medcea_auth and iam_policy (the audit histories,
--    user_unit, the master data, set_actor, revoke_person_mqtt): the reverted grants.py
--    leaves access_svc out of its revokes there (it was deferred until 2.7), so nothing
--    else would take them back. Its grants IN schema iam stay: the reverted access_db.sql
--    re-grants what it needs there.
-- 2. The managed roles (rr_*, svc_*, iam_svc) keep nothing in schema iam: the reverted
--    grants.py defers iam again and would never revoke them.
-- 3. Nobody executes the 2.7 iam.* functions (the reverted access-api calls none of them).
-- 4. The mail_settings account decisions move, with their data and ids, to schema
--    iam_retired_27 (no grants): the reverted access_db.sql re-creates the kind CHECK
--    without 'mail_settings' and would fail on them. Re-applying 2.7's access_db.sql moves
--    them back. The policy chain gets account_decisions_parked with their ids.
--
-- What stays, harmless: the 2.7 columns, the iam functions (EXECUTE revoked), the
-- append-only triggers on the iam histories, iam.mail_settings_pending, and schema iam
-- owned by medcea_owner (the reverted medcea_db_owner.sql leaves it). Withdrawn decisions
-- stay too: the status CHECK is not one the reverted file re-creates. Statements only: no
-- BEGIN/COMMIT here (psql -1).

SET LOCAL lock_timeout = '5s';

-- ── 1. access_svc outside schema iam ────────────────────────────────────────
DO $$
DECLARE s text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'access_svc') THEN
        RETURN;
    END IF;
    FOREACH s IN ARRAY ARRAY['medcea', 'medcea_auth', 'iam_policy'] LOOP
        IF pg_catalog.to_regnamespace(s) IS NOT NULL THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES    IN SCHEMA %I FROM access_svc', s);
            EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM access_svc', s);
            EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM access_svc', s);
            EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA %I FROM access_svc', s);
        END IF;
    END LOOP;
END $$;

-- ── 2. the managed roles in schema iam; 3. the 2.7 functions ────────────────
DO $$
DECLARE
    r record;
    f regprocedure;
BEGIN
    IF pg_catalog.to_regnamespace('iam') IS NULL THEN
        RETURN;
    END IF;
    FOR r IN SELECT rolname FROM pg_catalog.pg_roles
              WHERE rolname LIKE 'rr\_%' OR rolname LIKE 'svc\_%' OR rolname = 'iam_svc' LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES    IN SCHEMA iam FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA iam FROM %I', r.rolname);
    END LOOP;
    -- every grantee but the owner, PUBLIC included
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'iam'::regnamespace
                AND p.proname IN ('record_decision', 'withdraw_decision', 'confirm_decision', 'refuse_decision',
                                  'review_decision', 'create_review', 'sign_off_review', '_check_rules',
                                  '_lock_decision', '_later_unit_decision') LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        FOR r IN SELECT DISTINCT a.grantee::regrole::text AS g
                   FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(p.proacl) a
                  WHERE p.oid = f AND a.grantee <> 0 AND a.grantee <> p.proowner LOOP
            EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %s', f, r.g);
        END LOOP;
    END LOOP;
END $$;

-- ── 4. park the mail_settings decisions ─────────────────────────────────────
DO $$
DECLARE
    ids bigint[];
BEGIN
    IF pg_catalog.to_regclass('iam.account_decision') IS NULL THEN
        RETURN;
    END IF;
    SELECT coalesce(array_agg(d.decision_id ORDER BY d.decision_id), '{}') INTO ids
      FROM iam.account_decision d WHERE d.kind = 'mail_settings';
    IF cardinality(ids) = 0 THEN
        RETURN;
    END IF;
    CREATE SCHEMA IF NOT EXISTS iam_retired_27 AUTHORIZATION postgres;
    REVOKE ALL ON SCHEMA iam_retired_27 FROM PUBLIC;
    IF pg_catalog.to_regclass('iam_retired_27.account_decision') IS NULL THEN
        CREATE TABLE iam_retired_27.account_decision (LIKE iam.account_decision);
        REVOKE ALL ON iam_retired_27.account_decision FROM PUBLIC;
    END IF;
    INSERT INTO iam_retired_27.account_decision SELECT * FROM iam.account_decision d WHERE d.kind = 'mail_settings';
    -- the freeze trigger refuses DELETE for everyone: off for this one statement,
    -- inside this transaction, and back to ALWAYS before anything else can run
    ALTER TABLE iam.account_decision DISABLE TRIGGER account_decision_freeze_trg;
    DELETE FROM iam.account_decision d WHERE d.kind = 'mail_settings';
    ALTER TABLE iam.account_decision ENABLE ALWAYS TRIGGER account_decision_freeze_trg;
    -- a staged settings row belongs to one of them; the old code never reads it
    IF pg_catalog.to_regclass('iam.mail_settings_pending') IS NOT NULL THEN
        IF pg_catalog.to_regclass('iam_retired_27.mail_settings_pending') IS NULL THEN
            CREATE TABLE iam_retired_27.mail_settings_pending (LIKE iam.mail_settings_pending);
            REVOKE ALL ON iam_retired_27.mail_settings_pending FROM PUBLIC;
        END IF;
        INSERT INTO iam_retired_27.mail_settings_pending SELECT * FROM iam.mail_settings_pending;
        DELETE FROM iam.mail_settings_pending;
    END IF;
    IF pg_catalog.to_regprocedure('iam_policy.append_history(text, jsonb, text)') IS NOT NULL THEN
        PERFORM medcea_auth._set_internal_actor('system:rollback-27');
        PERFORM iam_policy.append_history('account_decisions_parked',
            jsonb_build_object('decision_ids', to_jsonb(ids), 'schema', 'iam_retired_27'),
            'apps/access/rollback-2.7.sql: the pre-2.7 access_db.sql does not know kind mail_settings');
    END IF;
    RAISE WARNING 'rollback-2.7: mail_settings decisions % parked in schema iam_retired_27; 2.7''s access_db.sql moves them back', ids;
END $$;
