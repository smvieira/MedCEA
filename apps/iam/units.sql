-- apps/iam/units.sql — one unit (de)assignment for apps/iam/units.sh (IAM 2.8).
-- Variables: assign (true|false), sub (Keycloak id = token sub), username, person (person_id or ''),
-- units (comma-separated unit_ids), reason. Run in one transaction (psql -1, READ COMMITTED, which
-- iam_policy.append_history needs), as postgres. No BEGIN/COMMIT, so tests/iam-db.sh can embed it.
-- Prints action|unit_code|decision_id, where action is assigned/removed/unchanged.
--
-- The iam_policy.user_unit row and its iam.account_decision commit together or not at all; the
-- row's trigger (user_unit_audit_trg) appends unit_assigned/unit_removed to the policy hash chain
-- as system:deploy. Idempotent: a unit already assigned (assign) or not assigned (remove) writes
-- nothing — no decision, no chain event. An assignment is a widening: in effect at once and
-- recorded pending_qa (the bootstrap exception; IAM 2.7's confirm screen confirms or refuses it).
-- A removal is a narrowing: applied.
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
\if :assign
WITH want AS (SELECT u.unit_id, u.unit_code FROM medcea.cea_unit u
               WHERE u.unit_id = ANY (pg_catalog.string_to_array(:'units', ',')::int[])),
     ins AS (INSERT INTO iam_policy.user_unit (person_sub, unit_id)
             SELECT :'sub'::uuid, w.unit_id FROM want w
             ON CONFLICT DO NOTHING RETURNING unit_id),
     dec AS (INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id,
                                               widens, status, reason, made_by_sub, made_by_person, made_by_name)
             SELECT 'unit_assign', :'sub', :'username', NULLIF(:'person', ''), i.unit_id,
                    true, 'pending_qa', :'reason', NULL, NULL, 'system:deploy' FROM ins i
             RETURNING unit_id, decision_id)
SELECT CASE WHEN d.decision_id IS NULL THEN 'unchanged' ELSE 'assigned' END, w.unit_code,
       coalesce(d.decision_id::text, '-')
  FROM want w LEFT JOIN dec d USING (unit_id) ORDER BY w.unit_code;
\else
WITH want AS (SELECT u.unit_id, u.unit_code FROM medcea.cea_unit u
               WHERE u.unit_id = ANY (pg_catalog.string_to_array(:'units', ',')::int[])),
     del AS (DELETE FROM iam_policy.user_unit a USING want w
              WHERE a.person_sub = :'sub'::uuid AND a.unit_id = w.unit_id RETURNING a.unit_id),
     dec AS (INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id,
                                               widens, status, reason, made_by_sub, made_by_person, made_by_name)
             SELECT 'unit_remove', :'sub', :'username', NULLIF(:'person', ''), d.unit_id,
                    false, 'applied', :'reason', NULL, NULL, 'system:deploy' FROM del d
             RETURNING unit_id, decision_id)
SELECT CASE WHEN d.decision_id IS NULL THEN 'unchanged' ELSE 'removed' END, w.unit_code,
       coalesce(d.decision_id::text, '-')
  FROM want w LEFT JOIN dec d USING (unit_id) ORDER BY w.unit_code;
\endif
