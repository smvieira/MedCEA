-- apps/research/db/grants.sql — who may do what in medcea_research (research sandbox
-- Phase 2a). Run by apps/research/deploy.sh as postgres, connected to medcea_research,
-- after db/medcea_research_ddl.sql; then db/assert_grants.sql checks the result.
--
-- Written by hand on purpose: the research database is outside the platform's access
-- policy (plan §8); nothing compiles these grants. Re-run safe: everything is revoked
-- first, then exactly this is granted.
--
--   rs_export_writer  CONNECT; USAGE on schema lake; INSERT on the ten lake.stage_*
--                     tables; EXECUTE lake.close_snapshot and lake.latest_cut. Nothing
--                     else: it cannot read the lake, the staging tables or the vault.
--   rs_backup         CONNECT; pg_read_all_data (pg_dump of the whole database).
--   rs_owner          owns everything (no grant needed); vault.reserve runs as it.
--   PUBLIC            nothing: no CONNECT or TEMP, nothing on any schema (public
--                     included), no EXECUTE on any function.

SET client_min_messages = warning;

REVOKE ALL ON DATABASE medcea_research FROM PUBLIC;
REVOKE ALL ON DATABASE medcea_research FROM rs_export_writer, rs_backup;
GRANT CONNECT ON DATABASE medcea_research TO rs_export_writer, rs_backup;

REVOKE ALL ON SCHEMA public, lake, vault, sim, agent_trace, registry FROM PUBLIC, rs_export_writer, rs_backup;
REVOKE ALL ON ALL TABLES    IN SCHEMA public, lake, vault, sim, agent_trace, registry FROM PUBLIC, rs_export_writer, rs_backup;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, lake, vault, sim, agent_trace, registry FROM PUBLIC, rs_export_writer, rs_backup;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public, lake, vault, sim, agent_trace, registry FROM PUBLIC, rs_export_writer, rs_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE rs_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA lake TO rs_export_writer;
GRANT INSERT ON lake.stage_measurements, lake.stage_units, lake.stage_zones, lake.stage_recipes,
                lake.stage_recipe_lines, lake.stage_runs, lake.stage_cycles, lake.stage_control_loops,
                lake.stage_param_sets, lake.stage_catalogue
   TO rs_export_writer;
GRANT EXECUTE ON FUNCTION lake.close_snapshot(timestamptz, timestamptz, integer), lake.latest_cut()
   TO rs_export_writer;

GRANT pg_read_all_data TO rs_backup;
