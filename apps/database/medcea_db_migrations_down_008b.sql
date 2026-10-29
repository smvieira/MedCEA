-- medcea_db_migrations_down_008b.sql — IAM_DB_ROLES=false (IAM plan Phase 2
-- rollback). Every database deploy with IAM_DB_ROLES=false applies it, inside
-- the mode bundle's single transaction (apps/database/lib-db-apply.sh step 6),
-- followed by `cli.py compile grants --mode additive`. It can also be run by
-- hand, as postgres, in one transaction; it records the switch itself:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_008b.sql
--
-- Before a `git revert` of the Phase 2 code, run it once more with -v full=1
-- (section 4): the reverted code expects postgres-owned tables and no 008b
-- triggers. The new columns stay; the new tables move, with their data, to
-- schema medcea_retired_008b (no grants), out of reach of the reverted code's
-- blanket anon grant on schema medcea. Re-applying 008b moves them back.
--
--   1. undo the enforce part: iam_* triggers, row-level security, the
--      retention CHECK, log_statement, memberships, CONNECT, LOGIN of the
--      managed roles (rr_*, svc_*, iam_svc: NOLOGIN again), and every grant
--      of anon, authenticator and mqtt_auth in medcea, medcea_auth, iam_policy
--   2. the legacy grants (old apps/database/deploy.sh step 5), with explicit
--      REVOKEs after the blanket grant for what is not the API's
--   3. the flag (medcea.platform_setting and the database setting) and an
--      enforcement_disabled event when the chain's last IAM_DB_ROLES event is
--      not already one
-- Every statement is idempotent and guarded by a catalog check, so a
-- steady-state false deploy takes no strong lock. Schema iam and access_svc
-- are not touched (IAM Phase 2.7). Statements only: no BEGIN/COMMIT here.

SET LOCAL lock_timeout = '5s';

-- ── 1. undo the enforce part ────────────────────────────────────────────────
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT t.tgrelid::regclass AS rel, t.tgname FROM pg_catalog.pg_trigger t
              JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
             WHERE c.relnamespace = 'medcea'::regnamespace AND NOT t.tgisinternal AND t.tgname LIKE 'iam\_%' LOOP
        EXECUTE pg_catalog.format('DROP TRIGGER %I ON %s', r.tgname, r.rel);
    END LOOP;
    -- row-level security: every table that has it in medcea (grants.rls objects)
    FOR r IN SELECT c.oid::regclass AS rel, c.relrowsecurity, c.relforcerowsecurity FROM pg_catalog.pg_class c
              WHERE c.relnamespace = 'medcea'::regnamespace AND (c.relrowsecurity OR c.relforcerowsecurity) LOOP
        EXECUTE pg_catalog.format('ALTER TABLE %s DISABLE ROW LEVEL SECURITY', r.rel);
        IF r.relforcerowsecurity THEN
            EXECUTE pg_catalog.format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', r.rel);
        END IF;
    END LOOP;
    FOR r IN SELECT p.polrelid::regclass AS rel, p.polname FROM pg_catalog.pg_policy p
              JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
             WHERE c.relnamespace = 'medcea'::regnamespace AND p.polname LIKE 'iam\_%' LOOP
        EXECUTE pg_catalog.format('DROP POLICY %I ON %s', r.polname, r.rel);
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = 'medcea.scheduler_config'::regclass AND conname = 'scheduler_config_retention_chk') THEN
        ALTER TABLE medcea.scheduler_config DROP CONSTRAINT scheduler_config_retention_chk;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
                WHERE s.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
                  AND s.setrole = 'postgres'::regrole
                  AND EXISTS (SELECT 1 FROM unnest(s.setconfig) x WHERE x LIKE 'log\_statement=%')) THEN
        EXECUTE pg_catalog.format('ALTER ROLE postgres IN DATABASE %I RESET log_statement', current_database());
    END IF;
    -- memberships: every rr_ role loses its members (authenticator -> rr_*,
    -- rr_admin_login -> rr_admin); authenticator keeps anon only
    FOR r IN SELECT pg_catalog.pg_get_userbyid(m.roleid) AS role, pg_catalog.pg_get_userbyid(m.member) AS member
               FROM pg_catalog.pg_auth_members m
              WHERE pg_catalog.pg_get_userbyid(m.roleid) LIKE 'rr\_%' LOOP
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', r.role, r.member);
    END LOOP;
    -- CONNECT: back to PUBLIC (the enforce bundle revoked it and granted it per
    -- login role); mqtt_auth gets its legacy grant again in section 2
    FOR r IN SELECT rolname FROM pg_catalog.pg_roles
              WHERE rolname LIKE 'rr\_%' OR rolname LIKE 'svc\_%' OR rolname IN ('iam_svc', 'authenticator') LOOP
        EXECUTE pg_catalog.format('REVOKE CONNECT ON DATABASE %I FROM %I', current_database(), r.rolname);
    END LOOP;
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO PUBLIC', current_database());
    -- the managed roles (rr_*, rr_admin_login, svc_*, iam_svc) cannot log in
    -- again: enforce made the service roles and rr_admin_login LOGIN, and the
    -- PUBLIC CONNECT above would let them back in with their enforce-mode
    -- grants. Through deploy.sh `grants --mode additive` does this too; run by
    -- hand, this is what stops them. Guarded, so a steady state writes nothing.
    FOR r IN SELECT rolname FROM pg_catalog.pg_roles
              WHERE (rolname LIKE 'rr\_%' OR rolname LIKE 'svc\_%' OR rolname = 'iam_svc') AND rolcanlogin LOOP
        EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN', r.rolname);
    END LOOP;
END $$;
REVOKE ALL ON ALL TABLES    IN SCHEMA medcea, medcea_auth, iam_policy FROM anon, authenticator, mqtt_auth;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA medcea, medcea_auth, iam_policy FROM anon, authenticator, mqtt_auth;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA medcea, medcea_auth, iam_policy FROM anon, authenticator, mqtt_auth;
REVOKE ALL ON SCHEMA medcea, medcea_auth, iam_policy FROM anon, authenticator, mqtt_auth;

-- ── 2. the legacy grants ────────────────────────────────────────────────────
GRANT USAGE ON SCHEMA medcea TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA medcea TO anon;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA medcea TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA medcea
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA medcea
  GRANT USAGE, SELECT                  ON SEQUENCES TO anon;
GRANT anon TO authenticator;
DO $$ BEGIN
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO mqtt_auth', current_database());
END $$;
-- Append-only history (migration 006): the blanket grant above includes it, so
-- take writes back. Its trigger runs SECURITY DEFINER and still appends.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON medcea.device_slot_history FROM anon;
-- MQTT credentials (migration 007): hashes are not for the API role. It may
-- only call register_mqtt_credential (SECURITY DEFINER). The broker sidecar
-- reads them as mqtt_auth.
REVOKE ALL ON medcea.mqtt_credential FROM anon;
GRANT USAGE ON SCHEMA medcea TO mqtt_auth;
GRANT SELECT ON medcea.mqtt_credential, medcea.device TO mqtt_auth;
-- Platform settings (migration 008a) are service_only in the access policy.
REVOKE ALL ON medcea.platform_setting FROM anon;
-- register_mqtt_credential v1: the edge wizard's call before Phase 2b (moved
-- here from migration 007, so a migration re-run cannot re-grant it)
GRANT EXECUTE ON FUNCTION medcea.register_mqtt_credential(text, text, integer, text, text) TO anon;
-- PostgREST's pre-request: anon keeps it in both modes, so a rolled-back
-- database does not refuse PostgREST once db-pre-request is wired (2b); the
-- function is a no-op while the database setting medcea.iam_db_roles is not true.
-- Pooled sessions keep the old setting: deploy.sh restarts config-api on a flip
-- (by hand after running this file: kubectl rollout restart deployment/config-api).
GRANT USAGE ON SCHEMA medcea_auth TO anon;
GRANT EXECUTE ON FUNCTION medcea_auth.pre_request() TO anon;
-- 008b's tables are not the API's (the blanket grant reached them), nor their
-- identity sequences. grants.LEGACY_ANON_EXCLUDED is this list.
DO $$
DECLARE s regclass; t text;
BEGIN
    -- guarded: after a full down they are parked in medcea_retired_008b (section 4)
    FOREACH t IN ARRAY ARRAY['approval', 'pending_change', 'run_release', 'algorithm_state_event', 'row_change',
                             'unit_algorithm_params', 'mqtt_service_credential', 'mqtt_service_acl'] LOOP
        IF pg_catalog.to_regclass('medcea.' || t) IS NOT NULL THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON medcea.%I FROM anon', t);
        END IF;
    END LOOP;
    FOR s IN SELECT d.objid::regclass FROM pg_catalog.pg_depend d
              JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
              JOIN pg_catalog.pg_class sq ON sq.oid = d.objid AND sq.relkind = 'S'   -- not the toast tables
             WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.refclassid = 'pg_catalog.pg_class'::regclass
               AND d.deptype IN ('a', 'i') AND t.relnamespace = 'medcea'::regnamespace
               AND t.relname IN ('mqtt_credential', 'platform_setting', 'approval', 'pending_change', 'run_release',
                                 'algorithm_state_event', 'row_change', 'unit_algorithm_params',
                                 'mqtt_service_credential', 'mqtt_service_acl') LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SEQUENCE %s FROM anon', s);
    END LOOP;
END $$;
-- The scheduler used to grant itself these (scheduler-api.py, before 2a).
REVOKE ALL ON medcea.schedule FROM authenticator;
REVOKE ALL ON SEQUENCE medcea.schedule_schedule_id_seq FROM authenticator;

-- ── 3. the flag and the event ───────────────────────────────────────────────
INSERT INTO medcea.platform_setting (key, value) VALUES ('iam_db_roles', 'false')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
                    WHERE s.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
                      AND s.setrole = 0 AND 'medcea.iam_db_roles=false' = ANY (s.setconfig)) THEN
        EXECUTE pg_catalog.format('ALTER DATABASE %I SET medcea.iam_db_roles = %L', current_database(), 'false');
    END IF;
    IF (medcea_auth.request_actor()).sub IS NULL THEN
        PERFORM medcea_auth._set_internal_actor('system:rollback');
    END IF;
    IF (SELECT h.event FROM iam_policy.history h WHERE h.payload ->> 'switch' = 'IAM_DB_ROLES'
         ORDER BY h.event_id DESC LIMIT 1) IS DISTINCT FROM 'enforcement_disabled' THEN
        PERFORM iam_policy.append_history('enforcement_disabled', '{"switch": "IAM_DB_ROLES"}'::jsonb,
                                          'medcea_db_migrations_down_008b.sql');
    END IF;
END $$;

-- ── 4. full: before a git revert of the Phase 2 code only ───────────────────
\if :{?full}
-- the managed roles keep nothing: the reverted code does not know them, and
-- their compiled grants (writes on regulated tables included) would outlive
-- the triggers and functions that made those grants safe
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT rolname FROM pg_catalog.pg_roles
              WHERE rolname LIKE 'rr\_%' OR rolname LIKE 'svc\_%' OR rolname = 'iam_svc' LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES    IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA medcea, medcea_auth, iam_policy FROM %I', r.rolname);
        EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM %I', current_database(), r.rolname);
    END LOOP;
END $$;
DO $$
DECLARE r record;
BEGIN
    -- 008b's always-on triggers
    FOR r IN SELECT t.tgrelid::regclass AS rel, t.tgname FROM pg_catalog.pg_trigger t
              JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
             WHERE NOT t.tgisinternal
               AND ((c.relnamespace = 'medcea'::regnamespace
                     AND t.tgname IN ('stamp_actor_trg', 'status_guard_trg', 'row_change_trg', 'measurement_zone_trg',
                                      'algorithm_state_event_trg', 'algorithm_state_before_trg',
                                      'device_serial_change_trg', 'mqtt_service_acl_root_trg',
                                      'schedule_retired_guard_trg'))
                 OR (c.relnamespace = 'medcea'::regnamespace AND c.relname IN
                        ('approval', 'pending_change', 'run_release', 'algorithm_state_event', 'row_change',
                         'device_slot_history') AND t.tgname LIKE '%\_no\_truncate')
                 OR (c.relnamespace = 'medcea'::regnamespace AND c.relname IN
                        ('approval', 'pending_change', 'run_release', 'algorithm_state_event', 'row_change',
                         'device_slot_history') AND t.tgname LIKE '%\_append\_only')
                 OR (c.oid = 'iam_policy.user_zone'::regclass AND t.tgname = 'user_zone_audit_trg')) LOOP
        EXECUTE pg_catalog.format('DROP TRIGGER %I ON %s', r.tgname, r.rel);
    END LOOP;
    -- 008a's append-only triggers go back to plain ENABLE
    FOR r IN SELECT t.tgrelid::regclass AS rel, t.tgname FROM pg_catalog.pg_trigger t
              WHERE t.tgrelid IN ('iam_policy.history'::regclass, 'iam_policy.export_log'::regclass)
                AND t.tgenabled = 'A' LOOP
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE TRIGGER %I', r.rel, r.tgname);
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'cea_unit_code_chk' AND conrelid = 'medcea.cea_unit'::regclass) THEN
        ALTER TABLE medcea.cea_unit DROP CONSTRAINT cea_unit_code_chk;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'cea_zone_code_chk' AND conrelid = 'medcea.cea_zone'::regclass) THEN
        ALTER TABLE medcea.cea_zone DROP CONSTRAINT cea_zone_code_chk;
    END IF;
    -- views back to the owner's rights
    FOR r IN SELECT c.oid::regclass AS rel FROM pg_catalog.pg_class c
              WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind = 'v'
                AND 'security_invoker=true' = ANY (c.reloptions) LOOP
        EXECUTE pg_catalog.format('ALTER VIEW %s RESET (security_invoker)', r.rel);
    END LOOP;
END $$;

-- 008b's functions (the 008a ones and the two register_mqtt_credential
-- versions' v1 stay; v1's body is migration 007's again).
DROP FUNCTION IF EXISTS medcea.stamp_actor(), medcea.guard_control_columns(), medcea.schedule_retired_guard(), medcea.log_row_change(),
    medcea.stamp_measurement_zone(), medcea.device_serial_change(), medcea.mqtt_service_acl_root(),
    medcea.log_algorithm_state(), medcea.algorithm_state_before(), medcea.refuse_change(),
    medcea.reject_non_draft_update(), medcea.immutable_row(), medcea.new_run_defaults(),
    medcea.algorithm_state_guard(), medcea.assign_only(), medcea.existing_slot(),
    medcea._approve_definition(text, integer, text, text), medcea.approve_recipe(integer),
    medcea.approve_algorithm(integer), medcea.approve_params(integer), medcea.approve_change(text, bigint, text),
    medcea.propose_setting(text, jsonb), medcea.propose_commissioning(integer, boolean, text),
    medcea._check_run_params(integer, integer, integer), medcea._check_run_params(integer, integer, integer, integer),
    medcea._check_assigned_run(medcea.recipe_run, text, text, text),
    medcea.start_run(integer), medcea.set_run_status(integer, text), medcea.finish_run(integer, text),
    medcea.record_cycle(integer, jsonb), medcea.release_run(integer), medcea.retire_schedule(integer),
    medcea.retire_algorithm_state(integer, text, text), medcea.register_mqtt_credential(integer, text, text),
    iam_policy.log_user_zone(), iam_policy.log_export(text[], text[]);
CREATE OR REPLACE FUNCTION medcea.register_mqtt_credential(
    p_username text, p_password_hash text, p_device_id integer, p_role text, p_topic_base text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    IF p_password_hash !~ '^\$7\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$' THEN
        RAISE EXCEPTION 'password_hash must be a mosquitto $7$ hash, not a password';
    END IF;
    IF p_username ~ '[:\s]' OR p_topic_base ~ '\s' OR p_username = '' THEN
        RAISE EXCEPTION 'username/topic_base cannot be empty or contain ":" or whitespace';
    END IF;
    DELETE FROM medcea.mqtt_credential WHERE device_id = p_device_id AND username <> p_username;
    INSERT INTO medcea.mqtt_credential (username, password_hash, device_id, role, topic_base)
    VALUES (p_username, p_password_hash, p_device_id, upper(p_role), p_topic_base)
    ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, device_id = EXCLUDED.device_id,
           role = EXCLUDED.role, topic_base = EXCLUDED.topic_base,
           active = true, updated_at = now();
END $$;
CREATE OR REPLACE FUNCTION medcea.log_device_slot() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE ev varchar(10);
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, to_zone_id, to_device_type, to_dns_name)
        VALUES (NEW.device_id, 'placed', NEW.serial_number, NEW.zone_id, NEW.device_type, NEW.dns_name);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, from_zone_id, from_device_type, from_dns_name)
        VALUES (OLD.device_id, 'removed', OLD.serial_number, OLD.zone_id, OLD.device_type, OLD.dns_name);
        RETURN OLD;
    END IF;
    IF NEW.serial_number IS DISTINCT FROM OLD.serial_number THEN
        ev := 'replaced';
    ELSIF NEW.zone_id IS DISTINCT FROM OLD.zone_id
       OR NEW.device_type IS DISTINCT FROM OLD.device_type THEN
        ev := 'moved';
    ELSIF NEW.dns_name IS DISTINCT FROM OLD.dns_name THEN
        ev := 'renamed';
    ELSE
        RETURN NEW;
    END IF;
    INSERT INTO medcea.device_slot_history
        (device_id, event, serial_number, from_serial,
         from_zone_id, from_device_type, from_dns_name,
         to_zone_id, to_device_type, to_dns_name)
    VALUES (NEW.device_id, ev, NEW.serial_number, OLD.serial_number,
            OLD.zone_id, OLD.device_type, OLD.dns_name,
            NEW.zone_id, NEW.device_type, NEW.dns_name);
    RETURN NEW;
END $$;
-- append_history back to 008a's body (the actor is the database login)
CREATE OR REPLACE FUNCTION iam_policy.append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    v_id      bigint;
    v_at      timestamptz := now();
    v_name    text := 'db:' || session_user;
    v_version int;
    v_prev    text;
BEGIN
    IF coalesce(btrim(p_event), '') = '' THEN
        RAISE EXCEPTION 'append_history: event is required';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'append_history needs READ COMMITTED (is %): a transaction snapshot could miss the head',
            current_setting('transaction_isolation');
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    IF jsonb_typeof(p_payload -> 'version') = 'number' THEN
        v_version := (p_payload ->> 'version')::int;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam_policy.history'));
    SELECT h.hash INTO v_prev FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    v_id := nextval(pg_get_serial_sequence('iam_policy.history', 'event_id'));
    INSERT INTO iam_policy.history
        (event_id, at, actor_sub, actor_person, actor_name, event, version, reason, payload, prev_hash, hash)
    VALUES (v_id, v_at, NULL, NULL, v_name, p_event, v_version, p_reason, p_payload, v_prev,
            encode(sha256(convert_to(iam_policy.history_record(
                v_id, v_at, NULL, NULL, v_name, p_event, v_version, p_reason, p_payload, v_prev), 'UTF8')), 'hex'));
    RETURN v_id;
END $$;
-- the actor store and the medcea_auth functions 008b added (pre_request stays:
-- anon may still execute it, and it is a no-op while the setting is false)
DROP FUNCTION IF EXISTS medcea_auth.set_actor(text, text, text, text), medcea_auth.set_system_actor(text, text, bigint),
    medcea_auth.my_zones(), medcea_auth._authors(text, jsonb), medcea_auth._lock_row(text, jsonb), medcea_auth._approver(text),
    medcea_auth._is_approved(text, jsonb), medcea_auth.row_digest(text, jsonb), medcea_auth._content(jsonb, boolean),
    medcea_auth.policy_refuse(text), medcea_auth.enforcing(), medcea_auth._set_internal_actor(text),
    medcea_auth.request_actor(), medcea_auth._is_owner_write(), medcea_auth._owner_write(boolean),
    medcea_auth._actor_put(text, text, text, text, text, text, bigint), medcea_auth._actor_store(),
    medcea_auth._actor_ok(), medcea_auth._own_role(jsonb), medcea_auth.platform_roles(),
    medcea_auth._token_clients(), medcea_auth.policy_holds(text, text, text), medcea_auth.object_group(text);
-- everything in medcea back to postgres (008a's medcea_auth and iam_policy stay
-- with medcea_owner, as 008a made them)
DO $$
DECLARE r record;
BEGIN
    ALTER SCHEMA medcea OWNER TO postgres;
    FOR r IN SELECT c.oid::regclass AS rel, c.relkind FROM pg_catalog.pg_class c
              WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                AND c.relowner <> 'postgres'::regrole
                AND NOT (c.relkind = 'S' AND EXISTS (
                         SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.objid = c.oid AND d.classid = 'pg_catalog.pg_class'::regclass
                            AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')))
              ORDER BY c.relkind = 'S', c.oid LOOP
        EXECUTE pg_catalog.format('ALTER %s %s OWNER TO postgres',
            CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE'
                           WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END, r.rel);
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS f FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'medcea'::regnamespace AND p.proowner <> 'postgres'::regrole LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO postgres', r.f);
    END LOOP;
    FOR r IN SELECT t.oid::regtype AS typ FROM pg_catalog.pg_type t
              WHERE t.typnamespace = 'medcea'::regnamespace AND t.typtype = 'd' AND t.typowner <> 'postgres'::regrole LOOP
        EXECUTE pg_catalog.format('ALTER DOMAIN %s OWNER TO postgres', r.typ);
    END LOOP;
END $$;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE medcea_owner GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
-- 008b's tables leave schema medcea: the reverted deploy.sh grants anon
-- everything in medcea on its first run, which would open the broker's service
-- hashes (mqtt_service_credential) and the audit tables (approval, row_change,
-- ..., whose append-only triggers are gone) to PostgREST. Parked in a schema
-- nobody but the superuser may use; 008b moves them back if it is re-applied.
-- The *_by_* and params_id columns stay in their medcea tables.
CREATE SCHEMA IF NOT EXISTS medcea_retired_008b AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA medcea_retired_008b FROM PUBLIC;
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['unit_algorithm_params', 'approval', 'pending_change', 'run_release',
                             'algorithm_state_event', 'row_change', 'mqtt_service_credential', 'mqtt_service_acl'] LOOP
        IF pg_catalog.to_regclass('medcea.' || t) IS NOT NULL THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON medcea.%I FROM PUBLIC, anon, authenticator, mqtt_auth', t);
            EXECUTE pg_catalog.format('ALTER TABLE medcea.%I SET SCHEMA medcea_retired_008b', t);
        END IF;
    END LOOP;
    RAISE WARNING 'medcea_db_migrations_down_008b.sql -v full=1: 008b''s triggers and functions are gone and medcea is postgres''s again; its tables (approval, row_change, unit_algorithm_params, mqtt_service_*, ...) are parked with their data in schema medcea_retired_008b, and its columns (*_by_*, params_id, status, ...) stay — drop them by hand once nothing is needed';
END $$;
\endif
