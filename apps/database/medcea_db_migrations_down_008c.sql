-- medcea_db_migrations_down_008c.sql — undo migration 008c (IAM Phase 4,
-- slice 4.1) before a `git revert` of that slice. Never run by a deploy.
-- Run by hand, as postgres, in one transaction:
--
--   kubectl exec -i -n medcea rdbms-postgresql-0 -- sh -c \
--     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -' \
--     < apps/database/medcea_db_migrations_down_008c.sql
--
-- Revert order: this file → git revert → ./apps/database/deploy.sh (the old
-- _approver, pre_request and grants) → ./deploy-infra.sh (the old routes and
-- NetworkPolicies). Between the last two the User Manager's widening check
-- answers 503 for a grant, an activation or a role change into qa, qp, admin or
-- auditor (docs/manual admin: "IAM 4.1 deploy order").
--
--   1. refused once a policy version exists (slice 4.2a or later): revert those
--      slices first; their rollback keeps the versions
--   2. the four medcea.*_policy wrappers first, so no definer function in the
--      schema PostgREST exposes outlives the rest
--   3. the freeze trigger on the six tables
--   4. every 008c function in iam_policy; append_history back to 008b's
--      writer body first (it was 008c's filter in front of _append_history),
--      so iam-api's mqtt_credential_issued keeps working
--   5. iam_svc's EXECUTE on iam._changed_since (the function stays: the reverted
--      access_db.sql does not know it, it has no other grant, and the reverted
--      grants assert nothing about it)
--   6. skeleton, version_diff and approval_evidence parked in schema
--      iam_policy_retired_008c (no grants): the reverted YAML does not name them,
--      and I15 refuses any relation of iam_policy that is not a member, which
--      would roll the reverted deploy's whole bundle back; 008c moves them back
--      if it is re-applied
--   7. kept on purpose: entry in its new shape (empty; the reverted YAML still
--      names iam_policy.entry), the new version/waiver/resource_group columns,
--      the CHECKs and one_open (harmless while empty), medcea_auth._person_actor
--      (the reverted 008b re-creates a self-contained _account_actor; the
--      orphan has no grants) and medcea_auth._rpc_client (no grants; the
--      reverted pre_request no longer calls it)
--   8. PostgREST reloads its schema cache

SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF pg_catalog.to_regclass('iam_policy.version') IS NOT NULL AND EXISTS (SELECT 1 FROM iam_policy.version) THEN
        RAISE EXCEPTION 'policy versions exist (slice 4.2a or later): revert those slices first; their rollback keeps the versions';
    END IF;
END $$;

DROP FUNCTION IF EXISTS medcea.approve_policy(integer, text, text, text, text), medcea.return_policy(integer, text),
    medcea.confirm_policy(integer, text, text), medcea.dispute_policy(integer, text);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['version', 'entry', 'waiver', 'skeleton', 'version_diff', 'approval_evidence'] LOOP
        IF pg_catalog.to_regclass('iam_policy.' || t) IS NOT NULL THEN
            EXECUTE pg_catalog.format('DROP TRIGGER IF EXISTS freeze_policy_trg ON iam_policy.%I', t);
            EXECUTE pg_catalog.format('DROP TRIGGER IF EXISTS freeze_policy_truncate_trg ON iam_policy.%I', t);
        END IF;
    END LOOP;
END $$;

-- append_history: 008b B16's writer body again (iam_svc keeps its EXECUTE)
CREATE OR REPLACE FUNCTION iam_policy.append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    v_id      bigint;
    v_at      timestamptz := now();
    a         record;
    v_sub     uuid;
    v_person  text;
    v_name    text;
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
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        v_name := 'db:' || session_user;
    ELSIF a.sub ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        v_sub := a.sub::uuid; v_person := a.person; v_name := a.name;
    ELSE
        v_person := a.person; v_name := a.sub;
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
    VALUES (v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev,
            encode(sha256(convert_to(iam_policy.history_record(
                v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev), 'UTF8')), 'hex'));
    RETURN v_id;
END $$;

DROP FUNCTION IF EXISTS
    iam_policy._begin(text, integer), iam_policy._edge_ok(text, text, text, text), iam_policy._accepted(),
    iam_policy.freeze_policy(), iam_policy._changed_since(text, text, double precision),
    iam_policy._authors(integer), iam_policy.entries_digest(integer), iam_policy._put_rows(integer, jsonb, jsonb),
    iam_policy._evidence(integer, text),
    iam_policy.new_draft(text, text, double precision, jsonb, jsonb),
    iam_policy.save_entry(integer, text, text, jsonb, text, jsonb, double precision),
    iam_policy.submit(integer, text, double precision), iam_policy.withdraw(integer, text, double precision),
    iam_policy._qa(text), iam_policy.approve(integer, text, text, text, text), iam_policy.return_version(integer, text),
    iam_policy.confirm_applied(integer, text, text), iam_policy.dispute_applied(integer, text),
    iam_policy.why_not(integer), iam_policy.audit_versions(), iam_policy._system(), iam_policy._system_as(text[]),
    iam_policy._sync_skeleton(jsonb, text), iam_policy._accept_skeleton(text, jsonb, text, text, jsonb),
    iam_policy._propose_skeleton(text, jsonb, text, jsonb, text, uuid, text, text),
    iam_policy._build_version(text, jsonb, jsonb, integer, integer, text),
    iam_policy._mark_applied(integer, jsonb, text, uuid, text, text), iam_policy._mark_reverted(integer, integer, text),
    iam_policy._withdraw_open(text), iam_policy._record(text, jsonb), iam_policy._append_history(text, jsonb, text);

DO $$
BEGIN
    IF pg_catalog.to_regprocedure('iam._changed_since(text,text,double precision)') IS NOT NULL
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'iam_svc') THEN
        REVOKE ALL ON FUNCTION iam._changed_since(text, text, double precision) FROM iam_svc;
    END IF;
END $$;

DO $$
DECLARE t text;
BEGIN
    IF pg_catalog.to_regclass('iam_policy.version') IS NOT NULL THEN
        ALTER TABLE iam_policy.version DROP CONSTRAINT IF EXISTS version_skeleton_digest_fkey;
        ALTER TABLE iam_policy.version DROP CONSTRAINT IF EXISTS version_approved_skeleton_fkey;
    END IF;
    CREATE SCHEMA IF NOT EXISTS iam_policy_retired_008c AUTHORIZATION postgres;
    REVOKE ALL ON SCHEMA iam_policy_retired_008c FROM PUBLIC;
    FOREACH t IN ARRAY ARRAY['skeleton', 'version_diff', 'approval_evidence'] LOOP
        IF pg_catalog.to_regclass('iam_policy.' || t) IS NOT NULL THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON iam_policy.%I FROM PUBLIC', t);
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.%I SET SCHEMA iam_policy_retired_008c', t);
        END IF;
    END LOOP;
    -- the managed roles' grants on the parked tables go with them (the reverted
    -- grants bundle revokes only inside its own schemas)
    FOR t IN SELECT DISTINCT a.grantee::regrole::text FROM pg_catalog.pg_class c
               CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
              WHERE c.relnamespace = 'iam_policy_retired_008c'::regnamespace AND a.grantee <> 0 AND a.grantee <> c.relowner LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA iam_policy_retired_008c FROM %I', t);
    END LOOP;
    RAISE WARNING 'medcea_db_migrations_down_008c.sql: the policy wrappers, the freeze trigger and 008c''s functions are gone; skeleton, version_diff and approval_evidence are parked in schema iam_policy_retired_008c; now git revert slice 4.1, then ./apps/database/deploy.sh and ./deploy-infra.sh';
END $$;

NOTIFY pgrst, 'reload schema';
