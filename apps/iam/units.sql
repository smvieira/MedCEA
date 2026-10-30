-- apps/iam/units.sql — one unit (de)assignment for apps/iam/units.sh (IAM 2.8).
-- Variables: assign (true|false), bootstrap (true|false, optional: units.sh assign --bootstrap),
-- sub (Keycloak id = token sub), username, person (person_id or ''), units (comma-separated
-- unit_ids), reason, and who ran it (IAM 2.7, units.sh --by): by_sub (that account's Keycloak
-- id), by_person (its person_id, or its id when it has none), by_name (its username). Run in
-- one transaction (psql -1, READ COMMITTED, which iam_policy.append_history needs), as
-- postgres. No BEGIN/COMMIT, so tests/iam-db.sh can embed it.
-- Prints action|unit_code|decision_id, where action is proposed/waiting/assigned (assign),
-- removed/withdrawn (remove) or unchanged.
--
-- assign: a widening, so it waits for qa. Only the unit_assign decision is written (pending_qa);
-- iam_policy.user_unit gets the row when a qa person confirms it (iam.confirm_decision), and a
-- refusal applies nothing. A unit already assigned is unchanged; one whose latest unit decision
-- is a waiting unit_assign is reported as waiting, with that decision, and nothing is written.
-- --bootstrap (units.sh allows it only while no qa account but the --by one is enabled, so
-- nobody else could ever confirm): the pre-change behaviour — the user_unit row too, in effect
-- before any check, made_by_name 'system:deploy (bootstrap, by <username>)'; a refusal removes it.
-- remove: a narrowing. An assigned unit is deleted and recorded applied; a unit not assigned
-- whose latest unit decision is a waiting unit_assign has that decision withdrawn (status
-- withdrawn, the --by account as the withdrawer, account_decision_withdrawn on the chain).
-- Idempotent: anything else writes nothing — no decision, no chain event.
--
-- The user_unit row's trigger (user_unit_audit_trg) appends unit_assigned/unit_removed to the
-- policy hash chain as system:deploy. The decision names its maker: made_by_sub/made_by_person
-- are the --by account, made_by_name 'system:deploy (by <username>)', so a qa person who ran
-- units.sh cannot confirm it (not_own_author, IAM 2.7). Each (user, unit) is locked first, with
-- the key iam.confirm_decision and iam.refuse_decision take, so a check never interleaves with a
-- change of the same assignment. iam.freeze_record() lets only medcea_owner close a decision,
-- so the withdrawal runs under SET LOCAL ROLE medcea_owner (the owner of schemas iam and
-- iam_policy), and RESET ROLE follows it.
\if :{?by_sub}
\else
DO $$ BEGIN RAISE EXCEPTION 'units.sql needs -v by_sub, by_person and by_name (apps/iam/units.sh --by <username>)'; END $$;
\endif
\if :{?bootstrap}
\else
\set bootstrap false
\endif
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam.user_unit'), pg_catalog.hashtext(:'sub' || ':' || u))
  FROM pg_catalog.unnest(pg_catalog.string_to_array(:'units', ',')::int[]) u \g /dev/null
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
-- st: per unit, whether it is assigned and the waiting unit_assign that is its latest unit decision
\if :assign
WITH want AS (SELECT u.unit_id, u.unit_code FROM medcea.cea_unit u
               WHERE u.unit_id = ANY (pg_catalog.string_to_array(:'units', ',')::int[])),
     st AS (SELECT w.unit_id, w.unit_code,
                   EXISTS (SELECT 1 FROM iam_policy.user_unit a
                            WHERE a.person_sub = :'sub'::uuid AND a.unit_id = w.unit_id) AS assigned,
                   (SELECT CASE WHEN l.kind = 'unit_assign' AND l.status = 'pending_qa' THEN l.decision_id END
                      FROM iam.account_decision l
                     WHERE l.keycloak_user_id = :'sub' AND l.unit_id = w.unit_id
                       AND l.kind IN ('unit_assign', 'unit_remove')
                     ORDER BY l.decision_id DESC LIMIT 1) AS waiting
              FROM want w),
     ins AS (INSERT INTO iam_policy.user_unit (person_sub, unit_id)
             SELECT :'sub'::uuid, s.unit_id FROM st s
              WHERE :bootstrap AND NOT s.assigned AND s.waiting IS NULL
             ON CONFLICT DO NOTHING RETURNING unit_id),
     dec AS (INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id,
                                               widens, status, reason, made_by_sub, made_by_person, made_by_name)
             SELECT 'unit_assign', :'sub', :'username', NULLIF(:'person', ''), s.unit_id,
                    true, 'pending_qa', :'reason', :'by_sub', :'by_person',
                    CASE WHEN :bootstrap THEN 'system:deploy (bootstrap, by ' ELSE 'system:deploy (by ' END
                        || :'by_name' || ')'
               FROM st s
              WHERE NOT s.assigned AND s.waiting IS NULL
                AND (NOT :bootstrap OR s.unit_id IN (SELECT i.unit_id FROM ins i))
             RETURNING unit_id, decision_id)
SELECT CASE WHEN s.assigned THEN 'unchanged' WHEN s.waiting IS NOT NULL THEN 'waiting'
            WHEN d.decision_id IS NULL THEN 'unchanged'
            WHEN :bootstrap THEN 'assigned' ELSE 'proposed' END, s.unit_code,
       coalesce(coalesce(d.decision_id, s.waiting)::text, '-')
  FROM st s LEFT JOIN dec d USING (unit_id) ORDER BY s.unit_code;
\else
WITH want AS (SELECT u.unit_id, u.unit_code FROM medcea.cea_unit u
               WHERE u.unit_id = ANY (pg_catalog.string_to_array(:'units', ',')::int[])),
     st AS (SELECT w.unit_id, w.unit_code,
                   EXISTS (SELECT 1 FROM iam_policy.user_unit a
                            WHERE a.person_sub = :'sub'::uuid AND a.unit_id = w.unit_id) AS assigned,
                   (SELECT CASE WHEN l.kind = 'unit_assign' AND l.status = 'pending_qa' THEN l.decision_id END
                      FROM iam.account_decision l
                     WHERE l.keycloak_user_id = :'sub' AND l.unit_id = w.unit_id
                       AND l.kind IN ('unit_assign', 'unit_remove')
                     ORDER BY l.decision_id DESC LIMIT 1) AS waiting
              FROM want w),
     del AS (DELETE FROM iam_policy.user_unit a USING st s
              WHERE s.assigned AND a.person_sub = :'sub'::uuid AND a.unit_id = s.unit_id RETURNING a.unit_id),
     dec AS (INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id,
                                               widens, status, reason, made_by_sub, made_by_person, made_by_name)
             SELECT 'unit_remove', :'sub', :'username', NULLIF(:'person', ''), d.unit_id,
                    false, 'applied', :'reason', :'by_sub', :'by_person',
                    'system:deploy (by ' || :'by_name' || ')' FROM del d
             RETURNING unit_id, decision_id)
SELECT CASE WHEN d.decision_id IS NULL THEN 'unchanged' ELSE 'removed' END, s.unit_code,
       coalesce(d.decision_id::text, '-')
  FROM st s LEFT JOIN dec d USING (unit_id)
 WHERE s.assigned OR s.waiting IS NULL ORDER BY s.unit_code;
-- a waiting assignment that is not in effect: withdrawn (the units removed above now have an
-- applied unit_remove as their latest decision, so they are not picked up here)
SET LOCAL ROLE medcea_owner;
WITH want AS (SELECT u.unit_id, u.unit_code FROM medcea.cea_unit u
               WHERE u.unit_id = ANY (pg_catalog.string_to_array(:'units', ',')::int[])),
     wd AS (UPDATE iam.account_decision x
               SET status = 'withdrawn', withdrawn_by_sub = :'by_sub', withdrawn_by_person = :'by_person',
                   withdrawn_by_name = 'system:deploy (by ' || :'by_name' || ')', withdrawn_at = now(),
                   withdraw_reason = :'reason'
             WHERE x.keycloak_user_id = :'sub' AND x.kind = 'unit_assign' AND x.status = 'pending_qa'
               AND x.unit_id IN (SELECT w.unit_id FROM want w)
               AND NOT EXISTS (SELECT 1 FROM iam_policy.user_unit a
                                WHERE a.person_sub = :'sub'::uuid AND a.unit_id = x.unit_id)
               AND NOT EXISTS (SELECT 1 FROM iam.account_decision l
                                WHERE l.keycloak_user_id = x.keycloak_user_id AND l.unit_id = x.unit_id
                                  AND l.kind IN ('unit_assign', 'unit_remove') AND l.decision_id > x.decision_id)
            RETURNING x.decision_id, x.kind, x.keycloak_user_id, x.unit_id),
     ev AS (SELECT wd.decision_id, wd.unit_id,
                   iam_policy.append_history('account_decision_withdrawn',
                       pg_catalog.jsonb_build_object('decision_id', wd.decision_id, 'kind', wd.kind,
                                                     'keycloak_user_id', wd.keycloak_user_id, 'unit_id', wd.unit_id),
                       :'reason') AS event_id
              FROM wd)
SELECT 'withdrawn', (SELECT w.unit_code FROM want w WHERE w.unit_id = e.unit_id), e.decision_id::text
  FROM ev e ORDER BY 2;
RESET ROLE;
\endif
