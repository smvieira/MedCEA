-- apps/research/db/grants.sql — who may do what in medcea_research (research sandbox
-- Phase 2a; the snapshot reader since Phase 2b). Run by apps/research/deploy.sh as
-- postgres, connected to medcea_research, after db/medcea_research_ddl.sql and
-- db/lake_api.sql and db/agent_trace.sql; then db/assert_grants.sql checks the result.
--
-- Written by hand on purpose: the research database is outside the platform's access
-- policy (plan §8); nothing compiles these grants. Re-run safe: everything is revoked
-- first, then exactly this is granted.
--
--   rs_export_writer  CONNECT; USAGE on schema lake; INSERT on the ten lake.stage_*
--                     tables; EXECUTE lake.close_snapshot and lake.latest_cut. Nothing
--                     else: it cannot read the lake, the staging tables or the vault.
--   rs_backup         CONNECT; pg_read_all_data (pg_dump of the whole database).
--   rs_lake_api       CONNECT; a member of rs_lake_reader (lake-api's PostgREST logs in
--                     as it and SET ROLEs to rs_lake_reader; NOINHERIT, so it holds
--                     nothing of its own).
--   rs_lake_reader    USAGE on schema lake_api; EXECUTE on the lake_api functions (each
--                     SECURITY DEFINER, owned by rs_owner). Nothing on any table.
--   rs_session        CONNECT; USAGE on schema agent_trace; EXECUTE on the agent_trace writers
--                     and readers listed below (open_session in both forms, append_event,
--                     put_blob, checkpoint, use_claim, revoke, session_status, events,
--                     set_expect, session_state, active_sessions, sessions_of), nothing on any table;
--                     verify_chain, head and the internals have no grantee (research Phase 4a).
--   rs_owner          owns everything (no grant needed); vault.reserve runs as it.
--   PUBLIC            nothing: no CONNECT or TEMP, nothing on any schema (public
--                     included), no EXECUTE on any function.

SET client_min_messages = warning;

REVOKE ALL ON DATABASE medcea_research FROM PUBLIC;
REVOKE ALL ON DATABASE medcea_research FROM rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;
GRANT CONNECT ON DATABASE medcea_research TO rs_export_writer, rs_backup;
GRANT CONNECT ON DATABASE medcea_research TO rs_lake_api;
GRANT CONNECT ON DATABASE medcea_research TO rs_session;

REVOKE ALL ON SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api
    FROM PUBLIC, rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;
REVOKE ALL ON ALL TABLES    IN SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api
    FROM PUBLIC, rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api
    FROM PUBLIC, rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public, lake, vault, sim, agent_trace, registry, lake_api
    FROM PUBLIC, rs_export_writer, rs_backup, rs_lake_api, rs_lake_reader, rs_session;
ALTER DEFAULT PRIVILEGES FOR ROLE rs_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA lake TO rs_export_writer;
GRANT INSERT ON lake.stage_measurements, lake.stage_units, lake.stage_zones, lake.stage_recipes,
                lake.stage_recipe_lines, lake.stage_runs, lake.stage_cycles, lake.stage_control_loops,
                lake.stage_param_sets, lake.stage_catalogue
   TO rs_export_writer;
GRANT EXECUTE ON FUNCTION lake.close_snapshot(timestamptz, timestamptz, integer), lake.latest_cut()
   TO rs_export_writer;

GRANT pg_read_all_data TO rs_backup;

GRANT USAGE ON SCHEMA lake_api TO rs_lake_reader;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA lake_api TO rs_lake_reader;
GRANT rs_lake_reader TO rs_lake_api;

GRANT USAGE ON SCHEMA agent_trace TO rs_session;
GRANT EXECUTE ON FUNCTION
    agent_trace.open_session(text, text, text, text, uuid, text, text, text, text, text, text[], jsonb, text, text, timestamptz),
    agent_trace.open_session(text, text, text, text, uuid, text, text, text, text, text, text[], jsonb, text, text, timestamptz, text),
    agent_trace.append_event(text, text, text, text, jsonb, text),
    agent_trace.put_blob(text, text, bytea),
    agent_trace.checkpoint(text, jsonb),
    agent_trace.use_claim(text, inet),
    agent_trace.revoke(text, text, uuid),
    agent_trace.session_status(text),
    agent_trace.events(text, bigint),
    agent_trace.set_expect(text, inet),
    agent_trace.session_state(text),
    agent_trace.active_sessions(),
    agent_trace.sessions_of(text, bigint, integer)
   TO rs_session;
