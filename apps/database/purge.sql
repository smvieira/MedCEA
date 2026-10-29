-- apps/database/purge.sql — drop the platform's database roles (IAM plan 3.6).
-- Run as postgres in database postgres, after DROP DATABASE medcea_db, by
-- apps/database/uninstall.sh --purge-data and by tests/iam-db-fixture.sh purge.
-- Takes :'roles', a comma-separated list: `cli.py db-roles --names` plus
-- medcea_owner, authenticator and anon. Roles are instance-wide, so a role
-- that still owns or holds something in another database (the keycloak
-- database never grants to these) makes DROP ROLE fail loudly instead of
-- being skipped; access_svc is dropped by apps/access/uninstall.sh.
-- (psql does not interpolate :'roles' inside a dollar-quoted body, hence \gexec)
SELECT pg_catalog.format('DROP ROLE IF EXISTS %I', btrim(r))
  FROM pg_catalog.unnest(pg_catalog.string_to_array(:'roles', ',')) r
 WHERE btrim(r) <> ''
\gexec
