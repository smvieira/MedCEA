-- tests/sql/iam-db-catalog.sql — a sorted, line-per-fact snapshot of everything
-- IAM Phase 2a changes in the catalog, for tests/iam-db-fixture.sh to diff
-- between applies (read-only). One line per fact, '|'-separated, first field the kind:
--   acl       grantee|kind|object|privilege   (relations, sequences, functions, schemas, the database)
--   colacl    table.column|acl                (must stay empty)
--   owner     kind|object|owner
--   reloption object|option
--   rls       table|enabled|forced
--   policy    table|name|roles|cmd
--   trigger   table|name|enabled              (O origin, A always, D disabled)
--   defacl    role|schema|kind|acl
--   dbsetting role|setting                    (pg_db_role_setting for this database)
--   member    role|member|inherit|set
--   role      name|login|inherit|super        (platform roles only: not pg_*)
--   constraint table|name|validated           (008b's CHECKs)
-- Object names are schema-qualified with quote_ident, so the session's
-- search_path cannot change a line. Run: psql -X -tA -q -f this-file
\pset footer off
WITH ns AS (SELECT oid, nspname FROM pg_namespace WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')),
rel AS (SELECT c.*, quote_ident(n.nspname) || '.' || quote_ident(c.relname) AS q FROM pg_class c JOIN ns n ON n.oid = c.relnamespace),
fn AS (SELECT p.*, quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ')' AS q
         FROM pg_proc p JOIN ns n ON n.oid = p.pronamespace),
lines(l) AS (
    SELECT 'acl|' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || '|'
           || CASE r.relkind WHEN 'S' THEN 'sequence' ELSE 'table' END || '|' || r.q || '|' || a.privilege_type
      FROM rel r CROSS JOIN LATERAL aclexplode(r.relacl) a
     WHERE r.relkind IN ('r', 'v', 'm', 'p', 'f', 'S') AND a.grantee <> r.relowner
    UNION ALL
    SELECT 'acl|' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || '|function|' || f.q || '|' || a.privilege_type
      FROM fn f CROSS JOIN LATERAL aclexplode(coalesce(f.proacl, acldefault('f', f.proowner))) a
     WHERE a.grantee <> f.proowner
    UNION ALL
    SELECT 'acl|' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || '|schema|' || n.nspname || '|' || a.privilege_type
      FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
     WHERE n.oid IN (SELECT oid FROM ns) AND a.grantee <> n.nspowner
    UNION ALL
    SELECT 'acl|' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || '|database|' || d.datname || '|' || a.privilege_type
      FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
     WHERE d.datname = current_database() AND a.grantee <> d.datdba
    UNION ALL
    SELECT 'colacl|' || r.q || '.' || quote_ident(at.attname) || '|' || at.attacl::text
      FROM rel r JOIN pg_attribute at ON at.attrelid = r.oid WHERE at.attacl IS NOT NULL
    UNION ALL
    SELECT 'owner|' || CASE r.relkind WHEN 'S' THEN 'sequence' WHEN 'v' THEN 'view' WHEN 'i' THEN 'index' ELSE 'table' END
           || '|' || r.q || '|' || pg_get_userbyid(r.relowner)
      FROM rel r WHERE r.relkind IN ('r', 'v', 'm', 'p', 'f', 'S')
    UNION ALL
    SELECT 'owner|function|' || f.q || '|' || pg_get_userbyid(f.proowner) FROM fn f
    UNION ALL
    SELECT 'owner|schema|' || n.nspname || '|' || pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.oid IN (SELECT oid FROM ns)
    UNION ALL
    SELECT 'secdef|' || f.q || '|' || f.prosecdef || '|' || coalesce(array_to_string(f.proconfig, ','), '') FROM fn f
    UNION ALL
    SELECT 'reloption|' || r.q || '|' || o FROM rel r CROSS JOIN LATERAL unnest(r.reloptions) o
    UNION ALL
    SELECT 'rls|' || r.q || '|' || r.relrowsecurity || '|' || r.relforcerowsecurity
      FROM rel r WHERE r.relrowsecurity OR r.relforcerowsecurity
    UNION ALL
    SELECT 'policy|' || r.q || '|' || p.polname || '|' || coalesce((SELECT string_agg(pg_get_userbyid(x), ',' ORDER BY pg_get_userbyid(x))
                                                               FROM unnest(p.polroles) x), '') || '|' || p.polcmd::text
      FROM pg_policy p JOIN rel r ON r.oid = p.polrelid
    UNION ALL
    SELECT 'trigger|' || r.q || '|' || t.tgname || '|' || t.tgenabled::text
      FROM pg_trigger t JOIN rel r ON r.oid = t.tgrelid WHERE NOT t.tgisinternal
    UNION ALL
    SELECT 'defacl|' || pg_get_userbyid(d.defaclrole) || '|' || coalesce(n.nspname, '*') || '|' || d.defaclobjtype::text || '|' || d.defaclacl::text
      FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
    UNION ALL
    SELECT 'dbsetting|' || coalesce(pg_get_userbyid(nullif(s.setrole, 0)), '*') || '|' || c
      FROM pg_db_role_setting s CROSS JOIN LATERAL unnest(s.setconfig) c
     WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
    UNION ALL
    SELECT 'member|' || pg_get_userbyid(m.roleid) || '|' || pg_get_userbyid(m.member) || '|' || m.inherit_option || '|' || m.set_option
      FROM pg_auth_members m
     WHERE pg_get_userbyid(m.roleid) !~ '^pg_' AND pg_get_userbyid(m.member) !~ '^pg_'
    UNION ALL
    SELECT 'role|' || rolname || '|' || rolcanlogin || '|' || rolinherit || '|' || rolsuper
      FROM pg_roles WHERE rolname !~ '^pg_'
    UNION ALL
    SELECT 'constraint|' || r.q || '|' || c.conname || '|' || c.convalidated
      FROM pg_constraint c JOIN rel r ON r.oid = c.conrelid
     WHERE c.conname IN ('cea_unit_code_chk', 'cea_zone_code_chk', 'scheduler_config_retention_chk')
)
SELECT l FROM lines ORDER BY l COLLATE "C";
