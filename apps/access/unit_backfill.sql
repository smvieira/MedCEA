-- apps/access/unit_backfill.sql — a pending_qa decision for every unit assignment that
-- has none (IAM 2.7). Run by apps/access/deploy.sh after access_db.sql, as postgres, in
-- one transaction (psql -1 -tA); tests/iam-db-fixture.sh (step purge-access) runs it too.
--
-- After ./apps/access/uninstall.sh --purge-data the assignments (iam_policy.user_unit, the
-- database component's) survive while their decisions (schema iam) are gone, so qa would
-- have nothing to confirm or refuse. Each gets a pending_qa unit_assign as a bootstrap row
-- without a maker or subject person, in effect before the check like a units.sh --bootstrap
-- row: confirming it needs the attestation (spec 2.5 rule 6) and inserts nothing,
-- refusing it removes the unit. (Assignments that were still waiting for qa had no
-- user_unit row, so they went with schema iam and are not backfilled.) The username is
-- the account id: the deploy does not call Keycloak. Nothing happens while iam_policy
-- does not exist yet (a fresh install deploys this component before the database
-- component). Prints backfilled|decision|account|unit.
SELECT pg_catalog.to_regclass('iam_policy.user_unit') IS NOT NULL AS have_units \gset
\if :have_units
WITH orphan AS (
    SELECT uu.person_sub, uu.unit_id FROM iam_policy.user_unit uu
     WHERE NOT EXISTS (SELECT 1 FROM iam.account_decision d
                        WHERE d.keycloak_user_id = uu.person_sub::text AND d.unit_id = uu.unit_id
                          AND d.kind IN ('unit_assign', 'unit_remove'))),
     ins AS (
    INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id,
                                      widens, status, reason, made_by_sub, made_by_person, made_by_name)
    SELECT 'unit_assign', o.person_sub::text, o.person_sub::text, NULL, o.unit_id, true, 'pending_qa',
           'unit assignment without a decision (schema iam was purged); recorded by apps/access/deploy.sh for qa',
           NULL, NULL, 'system:deploy (backfill)'
      FROM orphan o ORDER BY o.person_sub, o.unit_id
    RETURNING decision_id, keycloak_user_id, unit_id)
SELECT 'backfilled|' || decision_id || '|' || keycloak_user_id || '|' || unit_id FROM ins ORDER BY decision_id;
\endif
