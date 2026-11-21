-- apps/research/db/assert_grants.sql — the grants of medcea_research as db/grants.sql
-- states them, checked from the catalog (read-only; run by apps/research/deploy.sh last,
-- connected to medcea_research). Prints one line per problem, nothing when all holds:
--   rs_export_writer holds exactly INSERT on the ten lake.stage_* tables, USAGE on
--   schema lake, CONNECT on the database, EXECUTE on lake.close_snapshot and
--   lake.latest_cut, no column privilege, no membership, owns nothing, no attribute;
--   rs_backup is a member of pg_read_all_data and of nothing else;
--   PUBLIC holds nothing on the database, the six schemas, their relations or functions;
--   rs_owner cannot log in and owns every relation and function of the six schemas;
--   rs_lake_api (Phase 2b) is LOGIN NOINHERIT, CONNECTION LIMIT 10, a member of
--   rs_lake_reader and of nothing else, with its three settings (statement_timeout 30s,
--   default_transaction_read_only on, temp_file_limit 256MB), CONNECT only;
--   rs_lake_reader cannot log in, holds nothing on any table, sequence or column,
--   USAGE on schema lake_api only and EXECUTE only on the lake_api functions (all of
--   them); every lake_api function is SECURITY DEFINER with search_path
--   pg_catalog, pg_temp (and, as above, owned by rs_owner, not executable by PUBLIC);
--   rs_session (research Phase 4a) is LOGIN NOINHERIT, CONNECTION LIMIT 5, statement_timeout
--   10s, a member of nothing, CONNECT only, USAGE on schema agent_trace only, EXECUTE on
--   exactly the eleven agent_trace writers and readers and on nothing else, no privilege on
--   any relation or column; every agent_trace function is SECURITY DEFINER with search_path
--   pg_catalog, pg_temp, and nobody but rs_owner and rs_session holds EXECUTE on one.
BEGIN READ ONLY;
WITH sch AS (
    SELECT n.oid, n.nspname FROM pg_catalog.pg_namespace n
     WHERE n.nspname IN ('public', 'lake', 'vault', 'sim', 'agent_trace', 'registry', 'lake_api')
), w AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_export_writer'
), b AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_backup'
), o AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_owner'
), la AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_lake_api'
), lr AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_lake_reader'
), lake_roles AS (
    SELECT r.oid, r.rolname FROM pg_catalog.pg_roles r WHERE r.rolname IN ('rs_lake_api', 'rs_lake_reader')
), want_setting(setting) AS (
    VALUES ('statement_timeout=30s'), ('default_transaction_read_only=on'), ('temp_file_limit=256MB')
), lake_fn AS (
    SELECT p.oid, 'lake_api.' || p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')' AS sig,
           p.prosecdef, p.proconfig, p.proacl
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'lake_api'
), ss AS (
    SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'rs_session'
), at_fn AS (
    SELECT p.oid, 'agent_trace.' || p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')' AS sig,
           p.proname, p.prosecdef, p.proconfig, p.proacl
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'agent_trace'
), want_ss(proname) AS (
    VALUES ('open_session'), ('append_event'), ('put_blob'), ('checkpoint'), ('use_claim'), ('revoke'),
           ('session_status'), ('events'), ('set_expect'), ('session_state'), ('active_sessions')
), want_rel(relname) AS (
    SELECT 'stage_' || x FROM pg_catalog.unnest(ARRAY['measurements', 'units', 'zones', 'recipes', 'recipe_lines',
                                                      'runs', 'cycles', 'control_loops', 'param_sets', 'catalogue']) x
), want_fn(sig) AS (
    VALUES ('lake.close_snapshot(timestamp with time zone, timestamp with time zone, integer)'), ('lake.latest_cut()')
), rel_acl AS (
    SELECT s.nspname, c.relname, a.grantee, a.privilege_type
      FROM pg_catalog.pg_class c JOIN sch s ON s.oid = c.relnamespace,
           LATERAL pg_catalog.aclexplode(c.relacl) a
), fn AS (
    SELECT p.oid, s.nspname,
           s.nspname || '.' || p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')' AS sig,
           p.proacl, p.proowner
      FROM pg_catalog.pg_proc p JOIN sch s ON s.oid = p.pronamespace
), fn_acl AS (
    SELECT f.sig, a.grantee, a.privilege_type
      FROM fn f, LATERAL pg_catalog.aclexplode(f.proacl) a
), problems(line) AS (
    -- rs_export_writer on relations: exactly INSERT on the stage tables
    SELECT 'rs_export_writer holds ' || r.privilege_type || ' on ' || r.nspname || '.' || r.relname
      FROM rel_acl r WHERE r.grantee = (SELECT oid FROM w)
       AND NOT (r.nspname = 'lake' AND r.privilege_type = 'INSERT' AND r.relname IN (SELECT relname FROM want_rel))
    UNION ALL
    SELECT 'rs_export_writer lacks INSERT on lake.' || x.relname
      FROM want_rel x
     WHERE NOT EXISTS (SELECT 1 FROM rel_acl r WHERE r.grantee = (SELECT oid FROM w) AND r.nspname = 'lake'
                          AND r.relname = x.relname AND r.privilege_type = 'INSERT')
    UNION ALL
    -- column privileges: none for rs_export_writer or PUBLIC
    SELECT 'column privilege ' || a.privilege_type || ' on ' || s.nspname || '.' || c.relname || '.' || att.attname
           || ' for ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE 'rs_export_writer' END
      FROM pg_catalog.pg_attribute att
      JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
      JOIN sch s ON s.oid = c.relnamespace,
           LATERAL pg_catalog.aclexplode(att.attacl) a
     WHERE a.grantee = 0 OR a.grantee = (SELECT oid FROM w)
    UNION ALL
    -- PUBLIC on relations
    SELECT 'PUBLIC holds ' || r.privilege_type || ' on ' || r.nspname || '.' || r.relname
      FROM rel_acl r WHERE r.grantee = 0
    UNION ALL
    -- functions: no default (NULL acl = EXECUTE to PUBLIC), no PUBLIC, rs_export_writer exactly the two
    SELECT 'PUBLIC may execute ' || f.sig FROM fn f WHERE f.proacl IS NULL
    UNION ALL
    SELECT 'PUBLIC may execute ' || x.sig FROM fn_acl x WHERE x.grantee = 0
    UNION ALL
    SELECT 'rs_export_writer holds ' || x.privilege_type || ' on ' || x.sig
      FROM fn_acl x WHERE x.grantee = (SELECT oid FROM w) AND x.sig NOT IN (SELECT sig FROM want_fn)
    UNION ALL
    SELECT 'rs_export_writer lacks EXECUTE on ' || x.sig
      FROM want_fn x
     WHERE NOT EXISTS (SELECT 1 FROM fn_acl a WHERE a.sig = x.sig AND a.grantee = (SELECT oid FROM w)
                          AND a.privilege_type = 'EXECUTE')
    UNION ALL
    -- schemas
    SELECT 'PUBLIC holds ' || a.privilege_type || ' on schema ' || s.nspname
      FROM pg_catalog.pg_namespace n JOIN sch s ON s.oid = n.oid,
           LATERAL pg_catalog.aclexplode(n.nspacl) a WHERE a.grantee = 0
    UNION ALL
    SELECT 'rs_export_writer holds ' || a.privilege_type || ' on schema ' || s.nspname
      FROM pg_catalog.pg_namespace n JOIN sch s ON s.oid = n.oid,
           LATERAL pg_catalog.aclexplode(n.nspacl) a
     WHERE a.grantee = (SELECT oid FROM w) AND NOT (s.nspname = 'lake' AND a.privilege_type = 'USAGE')
    UNION ALL
    SELECT 'rs_export_writer lacks USAGE on schema lake'
     WHERE NOT pg_catalog.has_schema_privilege('rs_export_writer', 'lake', 'USAGE')
    UNION ALL
    -- the database
    SELECT 'PUBLIC holds the default privileges on database medcea_research (CONNECT, TEMP)'
      FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database() AND d.datacl IS NULL
    UNION ALL
    SELECT 'PUBLIC holds ' || a.privilege_type || ' on database ' || d.datname
      FROM pg_catalog.pg_database d, LATERAL pg_catalog.aclexplode(d.datacl) a
     WHERE d.datname = pg_catalog.current_database() AND a.grantee = 0
    UNION ALL
    SELECT 'rs_export_writer holds ' || a.privilege_type || ' on database ' || d.datname
      FROM pg_catalog.pg_database d, LATERAL pg_catalog.aclexplode(d.datacl) a
     WHERE d.datname = pg_catalog.current_database() AND a.grantee = (SELECT oid FROM w)
       AND a.privilege_type <> 'CONNECT'
    UNION ALL
    -- memberships and attributes
    SELECT 'rs_export_writer is a member of ' || r.rolname
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
     WHERE m.member = (SELECT oid FROM w)
    UNION ALL
    SELECT 'rs_backup is a member of ' || r.rolname
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
     WHERE m.member = (SELECT oid FROM b) AND r.rolname <> 'pg_read_all_data'
    UNION ALL
    SELECT 'rs_backup lacks pg_read_all_data'
     WHERE NOT pg_catalog.pg_has_role('rs_backup', 'pg_read_all_data', 'USAGE')
    UNION ALL
    SELECT r.rolname || ' has a superuser, createdb, createrole, replication or bypassrls attribute'
      FROM pg_catalog.pg_roles r
     WHERE r.rolname IN ('rs_owner', 'rs_export_writer', 'rs_backup')
       AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
    UNION ALL
    SELECT 'rs_owner can log in' FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_owner' AND r.rolcanlogin
    UNION ALL
    SELECT 'role ' || x || ' is missing'
      FROM pg_catalog.unnest(ARRAY['rs_owner', 'rs_export_writer', 'rs_backup']) x
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = x)
    UNION ALL
    -- ownership
    SELECT s.nspname || '.' || c.relname || ' is not owned by rs_owner'
      FROM pg_catalog.pg_class c JOIN sch s ON s.oid = c.relnamespace
     WHERE s.nspname <> 'public' AND c.relowner IS DISTINCT FROM (SELECT oid FROM o)
    UNION ALL
    SELECT f.sig || ' is not owned by rs_owner'
      FROM fn f WHERE f.nspname <> 'public' AND f.proowner IS DISTINCT FROM (SELECT oid FROM o)
    UNION ALL
    SELECT 'schema ' || n.nspname || ' is not owned by rs_owner'
      FROM pg_catalog.pg_namespace n JOIN sch s ON s.oid = n.oid
     WHERE s.nspname <> 'public' AND n.nspowner IS DISTINCT FROM (SELECT oid FROM o)
    UNION ALL
    SELECT 'schema ' || x || ' is missing'
      FROM pg_catalog.unnest(ARRAY['lake', 'vault', 'sim', 'agent_trace', 'registry', 'lake_api']) x
     WHERE NOT EXISTS (SELECT 1 FROM sch s WHERE s.nspname = x)
    UNION ALL
    -- ── the snapshot reader (Phase 2b) ──
    SELECT 'role ' || x || ' is missing'
      FROM pg_catalog.unnest(ARRAY['rs_lake_api', 'rs_lake_reader']) x
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = x)
    UNION ALL
    SELECT 'rs_lake_api is not LOGIN NOINHERIT'
      FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_lake_api' AND (NOT r.rolcanlogin OR r.rolinherit)
    UNION ALL
    SELECT 'rs_lake_api has connection limit ' || r.rolconnlimit || ', not 10'
      FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_lake_api' AND r.rolconnlimit <> 10
    UNION ALL
    SELECT 'rs_lake_reader can log in' FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_lake_reader' AND r.rolcanlogin
    UNION ALL
    SELECT r.rolname || ' has a superuser, createdb, createrole, replication or bypassrls attribute'
      FROM pg_catalog.pg_roles r
     WHERE r.rolname IN ('rs_lake_api', 'rs_lake_reader')
       AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
    UNION ALL
    SELECT 'rs_lake_api is a member of ' || r.rolname
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
     WHERE m.member = (SELECT oid FROM la) AND r.rolname <> 'rs_lake_reader'
    UNION ALL
    SELECT 'rs_lake_api is not a member of rs_lake_reader'
     WHERE EXISTS (SELECT 1 FROM la) AND EXISTS (SELECT 1 FROM lr)
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                        WHERE m.member = (SELECT oid FROM la) AND m.roleid = (SELECT oid FROM lr))
    UNION ALL
    SELECT 'rs_lake_reader is a member of ' || r.rolname
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
     WHERE m.member = (SELECT oid FROM lr)
    UNION ALL
    SELECT 'rs_lake_api lacks its setting ' || x.setting
      FROM want_setting x
     WHERE EXISTS (SELECT 1 FROM la)
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting d, LATERAL pg_catalog.unnest(d.setconfig) c
                        WHERE d.setrole = (SELECT oid FROM la) AND d.setdatabase = 0 AND c = x.setting)
    UNION ALL
    -- anything on any relation or column of this database (not only the six schemas)
    SELECT lk.rolname || ' holds ' || a.privilege_type || ' on ' || n.nspname || '.' || c.relname
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
           LATERAL pg_catalog.aclexplode(c.relacl) a JOIN lake_roles lk ON lk.oid = a.grantee
    UNION ALL
    SELECT lk.rolname || ' holds column privilege ' || a.privilege_type || ' on ' || c.relname || '.' || att.attname
      FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid = att.attrelid,
           LATERAL pg_catalog.aclexplode(att.attacl) a JOIN lake_roles lk ON lk.oid = a.grantee
    UNION ALL
    SELECT lk.rolname || ' holds ' || a.privilege_type || ' on schema ' || n.nspname
      FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(n.nspacl) a JOIN lake_roles lk ON lk.oid = a.grantee
     WHERE NOT (lk.rolname = 'rs_lake_reader' AND n.nspname = 'lake_api' AND a.privilege_type = 'USAGE')
    UNION ALL
    SELECT 'rs_lake_reader lacks USAGE on schema lake_api'
     WHERE EXISTS (SELECT 1 FROM lr) AND EXISTS (SELECT 1 FROM sch WHERE nspname = 'lake_api')
       AND NOT pg_catalog.has_schema_privilege('rs_lake_reader', 'lake_api', 'USAGE')
    UNION ALL
    SELECT lk.rolname || ' holds ' || a.privilege_type || ' on ' || n.nspname || '.' || p.proname
           || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')'
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
           LATERAL pg_catalog.aclexplode(p.proacl) a JOIN lake_roles lk ON lk.oid = a.grantee
     WHERE NOT (lk.rolname = 'rs_lake_reader' AND n.nspname = 'lake_api' AND a.privilege_type = 'EXECUTE')
    UNION ALL
    SELECT 'rs_lake_reader lacks EXECUTE on ' || f.sig
      FROM lake_fn f
     WHERE EXISTS (SELECT 1 FROM lr)
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(f.proacl) a
                        WHERE a.grantee = (SELECT oid FROM lr) AND a.privilege_type = 'EXECUTE')
    UNION ALL
    SELECT lk.rolname || ' holds ' || a.privilege_type || ' on database ' || d.datname
      FROM pg_catalog.pg_database d, LATERAL pg_catalog.aclexplode(d.datacl) a JOIN lake_roles lk ON lk.oid = a.grantee
     WHERE d.datname = pg_catalog.current_database()
       AND NOT (lk.rolname = 'rs_lake_api' AND a.privilege_type = 'CONNECT')
    UNION ALL
    SELECT f.sig || ' is not SECURITY DEFINER' FROM lake_fn f WHERE NOT f.prosecdef
    UNION ALL
    SELECT f.sig || ' does not pin search_path = pg_catalog, pg_temp'
      FROM lake_fn f WHERE NOT ('search_path=pg_catalog, pg_temp' = ANY (coalesce(f.proconfig, '{}')))
    UNION ALL
    -- ── the agent trace (research Phase 4a) ──
    SELECT 'role rs_session is missing' WHERE NOT EXISTS (SELECT 1 FROM ss)
    UNION ALL
    SELECT 'rs_session is not LOGIN NOINHERIT'
      FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_session' AND (NOT r.rolcanlogin OR r.rolinherit)
    UNION ALL
    SELECT 'rs_session has connection limit ' || r.rolconnlimit || ', not 5'
      FROM pg_catalog.pg_roles r WHERE r.rolname = 'rs_session' AND r.rolconnlimit <> 5
    UNION ALL
    SELECT 'rs_session has a superuser, createdb, createrole, replication or bypassrls attribute'
      FROM pg_catalog.pg_roles r
     WHERE r.rolname = 'rs_session'
       AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
    UNION ALL
    SELECT 'rs_session is a member of ' || r.rolname
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
     WHERE m.member = (SELECT oid FROM ss)
    UNION ALL
    SELECT 'rs_session lacks its setting statement_timeout=10s'
     WHERE EXISTS (SELECT 1 FROM ss)
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting d, LATERAL pg_catalog.unnest(d.setconfig) c
                        WHERE d.setrole = (SELECT oid FROM ss) AND d.setdatabase = 0 AND c = 'statement_timeout=10s')
    UNION ALL
    SELECT 'rs_session holds ' || a.privilege_type || ' on ' || n.nspname || '.' || c.relname
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
           LATERAL pg_catalog.aclexplode(c.relacl) a
     WHERE a.grantee = (SELECT oid FROM ss)
    UNION ALL
    SELECT 'rs_session holds column privilege ' || a.privilege_type || ' on ' || c.relname || '.' || att.attname
      FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid = att.attrelid,
           LATERAL pg_catalog.aclexplode(att.attacl) a
     WHERE a.grantee = (SELECT oid FROM ss)
    UNION ALL
    SELECT 'rs_session holds ' || a.privilege_type || ' on schema ' || n.nspname
      FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(n.nspacl) a
     WHERE a.grantee = (SELECT oid FROM ss) AND NOT (n.nspname = 'agent_trace' AND a.privilege_type = 'USAGE')
    UNION ALL
    SELECT 'rs_session lacks USAGE on schema agent_trace'
     WHERE EXISTS (SELECT 1 FROM ss) AND EXISTS (SELECT 1 FROM sch WHERE nspname = 'agent_trace')
       AND NOT pg_catalog.has_schema_privilege('rs_session', 'agent_trace', 'USAGE')
    UNION ALL
    SELECT 'rs_session holds ' || a.privilege_type || ' on database ' || d.datname
      FROM pg_catalog.pg_database d, LATERAL pg_catalog.aclexplode(d.datacl) a
     WHERE d.datname = pg_catalog.current_database() AND a.grantee = (SELECT oid FROM ss)
       AND a.privilege_type <> 'CONNECT'
    UNION ALL
    SELECT 'rs_session holds ' || a.privilege_type || ' on ' || n.nspname || '.' || p.proname
           || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')'
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
           LATERAL pg_catalog.aclexplode(p.proacl) a
     WHERE a.grantee = (SELECT oid FROM ss)
       AND NOT (n.nspname = 'agent_trace' AND a.privilege_type = 'EXECUTE'
                AND p.proname IN (SELECT proname FROM want_ss))
    UNION ALL
    SELECT 'rs_session lacks EXECUTE on agent_trace.' || w.proname
      FROM want_ss w
     WHERE EXISTS (SELECT 1 FROM ss)
       AND NOT EXISTS (SELECT 1 FROM at_fn f, LATERAL pg_catalog.aclexplode(f.proacl) a
                        WHERE f.proname = w.proname AND a.grantee = (SELECT oid FROM ss)
                          AND a.privilege_type = 'EXECUTE')
    UNION ALL
    SELECT f.sig || ' is held by ' || pg_catalog.pg_get_userbyid(a.grantee)
      FROM at_fn f, LATERAL pg_catalog.aclexplode(f.proacl) a
     WHERE a.grantee <> 0 AND a.grantee <> (SELECT oid FROM ss) AND a.grantee <> (SELECT oid FROM o)
    UNION ALL
    SELECT f.sig || ' is not SECURITY DEFINER' FROM at_fn f WHERE NOT f.prosecdef
    UNION ALL
    SELECT f.sig || ' does not pin search_path = pg_catalog, pg_temp'
      FROM at_fn f WHERE NOT ('search_path=pg_catalog, pg_temp' = ANY (coalesce(f.proconfig, '{}')))
    UNION ALL
    SELECT 'agent_trace.' || x || ' is missing'
      FROM pg_catalog.unnest(ARRAY['append_event', 'verify_chain', 'head']) x
     WHERE EXISTS (SELECT 1 FROM sch WHERE nspname = 'agent_trace')
       AND NOT EXISTS (SELECT 1 FROM at_fn f WHERE f.proname = x)
)
SELECT line FROM problems ORDER BY line;
COMMIT;
