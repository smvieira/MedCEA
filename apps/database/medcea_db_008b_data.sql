-- medcea_db_008b_data.sql — migration 008b's one-shot data steps (IAM plan 2.1).
-- Run by apps/database/lib-db-apply.sh (step 4b) in one transaction (-1,
-- ON_ERROR_STOP) as postgres, after medcea_db_owner.sql; the writes are made
-- as medcea_owner (SET LOCAL ROLE), so the guards that exempt the owner let
-- them through. Skipped, with a WARNING, while IAM_DB_ROLES=true: the enforce
-- triggers would refuse them, and grandfathering must never happen after the
-- switch.
--
--   1. grandfather, once (marker 008b:definitions_grandfathered): every recipe
--      and control algorithm that 008b found in use (status approved) gets an
--      approval row with action 'grandfather' and its current digest;
--   2. parameter sets: copy the inline algorithm_params of recipe_unit_permission
--      and schedule into medcea.unit_algorithm_params, mirroring
--      scheduler-api.py _resolve_algorithm() exactly:
--        assignment p:  alg = p.algorithm_id, else IF_THEN_ELSE
--                       params = (algorithm defaults, '{}' counting as none) || p.algorithm_params
--        schedule s:    alg = s.algorithm_id, else p.algorithm_id, else IF_THEN_ELSE
--                       defaults = s's algorithm's, else p's, else {} ('{}' counting as none)
--                       params = defaults || p.algorithm_params || s.algorithm_params
--                       (p's params are merged whatever p.allowed is, and even when
--                       p names another algorithm)
--      A set with the same (algorithm, unit, params) is reused; otherwise a new
--      one is named rup:r<recipe>/u<unit> or schedule:<id> (#<hash8> appended
--      when that name is taken). A row whose referenced set no longer matches
--      its inline columns (an inline edit after the copy) gets a new set.
--      First run only (marker 008b:params_grandfathered): new sets are
--      'approved' with a 'grandfather' approval, for exactly the ids INSERT
--      returned. Later runs: 'draft', attributed to whoever last edited the
--      source row (and logged in medcea.row_change under that name), no approval.
--      A non-object jsonb in any input is listed and its row skipped.
-- The inline columns stay until IAM Phase 2.4 (migration 008c drops them).

SELECT medcea_auth.enforcing() AS iam_enforcing \gset
\if :iam_enforcing
DO $$ BEGIN
    RAISE WARNING 'IAM_DB_ROLES=true: migration 008b data steps skipped (grandfathering and the parameter-set copy run only before the switch)';
END $$;
\else

SELECT medcea_auth._set_internal_actor('migration:008');
SET LOCAL ROLE medcea_owner;

-- ── 1. grandfather the definitions in use ───────────────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM medcea.platform_setting WHERE key = '008b:definitions_grandfathered') THEN
        RETURN;
    END IF;
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note,
                                 approved_by_sub, approved_by_name, approved_by_source, last_change_id)
    SELECT 'medcea.recipe', jsonb_build_array(r.recipe_id),
           medcea_auth.row_digest('medcea.recipe', jsonb_build_array(r.recipe_id)), 'recipes', 'grandfather',
           'in use before migration 008b', 'migration:008', 'migration:008', 'migration',
           (SELECT x.last_change FROM medcea_auth._authors('medcea.recipe', jsonb_build_array(r.recipe_id)) x)
      FROM medcea.recipe r WHERE r.status = 'approved'
    UNION ALL
    SELECT 'medcea.control_algorithm', jsonb_build_array(a.algorithm_id),
           medcea_auth.row_digest('medcea.control_algorithm', jsonb_build_array(a.algorithm_id)), 'controllers', 'grandfather',
           'in use before migration 008b', 'migration:008', 'migration:008', 'migration',
           (SELECT x.last_change FROM medcea_auth._authors('medcea.control_algorithm', jsonb_build_array(a.algorithm_id)) x)
      FROM medcea.control_algorithm a WHERE a.status = 'approved';
    INSERT INTO medcea.platform_setting (key, value) VALUES ('008b:definitions_grandfathered', now()::text);
END $$;

-- ── 2. parameter sets ───────────────────────────────────────────────────────
SELECT NOT EXISTS (SELECT 1 FROM medcea.platform_setting WHERE key = '008b:params_grandfathered') AS params_first_run \gset

CREATE TEMPORARY TABLE _uap_src ON COMMIT DROP AS
WITH ite AS (SELECT algorithm_id FROM medcea.control_algorithm WHERE algorithm_code = 'IF_THEN_ELSE'),
rup AS (
    SELECT 'rup'::text AS kind, p.recipe_id, p.unit_id, NULL::integer AS schedule_id, p.params_id AS cur_params_id,
           coalesce(p.algorithm_id, (SELECT algorithm_id FROM ite)) AS algorithm_id,
           ca.default_params AS d1, NULL::jsonb AS d2, p.algorithm_params AS p1, NULL::jsonb AS p2,
           'rup:r' || p.recipe_id || '/u' || p.unit_id AS base_name,
           p.updated_by_sub AS by_sub, p.updated_by_person AS by_person, p.updated_by_name AS by_name,
           p.updated_by_role AS by_role, p.updated_by_source AS by_source
      FROM medcea.recipe_unit_permission p
      LEFT JOIN medcea.control_algorithm ca ON ca.algorithm_id = coalesce(p.algorithm_id, (SELECT algorithm_id FROM ite))
     WHERE p.algorithm_id IS NOT NULL OR p.algorithm_params IS NOT NULL),
sch AS (
    SELECT 'schedule'::text, s.recipe_id, s.unit_id, s.schedule_id, s.params_id,
           coalesce(s.algorithm_id, p.algorithm_id, (SELECT algorithm_id FROM ite)),
           ca_s.default_params, ca_p.default_params, p.algorithm_params, s.algorithm_params,
           'schedule:' || s.schedule_id,
           s.updated_by_sub, s.updated_by_person, s.updated_by_name, s.updated_by_role, s.updated_by_source
      FROM medcea.schedule s
      LEFT JOIN medcea.recipe_unit_permission p ON p.unit_id = s.unit_id AND p.recipe_id = s.recipe_id
      LEFT JOIN medcea.control_algorithm ca_s ON ca_s.algorithm_id = s.algorithm_id
      LEFT JOIN medcea.control_algorithm ca_p ON ca_p.algorithm_id = p.algorithm_id)
SELECT * FROM rup UNION ALL SELECT * FROM sch;

DO $$
DECLARE l text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM medcea.control_algorithm WHERE algorithm_code = 'IF_THEN_ELSE') THEN
        RAISE WARNING 'migration 008b: no IF_THEN_ELSE algorithm; parameter sets are not copied';
        DELETE FROM _uap_src;
        RETURN;
    END IF;
    SELECT string_agg(base_name, ', ') INTO l FROM _uap_src
     WHERE (d1 IS NOT NULL AND jsonb_typeof(d1) <> 'object') OR (d2 IS NOT NULL AND jsonb_typeof(d2) <> 'object')
        OR (p1 IS NOT NULL AND jsonb_typeof(p1) <> 'object') OR (p2 IS NOT NULL AND jsonb_typeof(p2) <> 'object')
        OR algorithm_id IS NULL;
    IF l IS NOT NULL THEN
        RAISE WARNING 'migration 008b: not copied into a parameter set (algorithm_params or default_params is not a JSON object, or no algorithm): %', l;
        DELETE FROM _uap_src
         WHERE (d1 IS NOT NULL AND jsonb_typeof(d1) <> 'object') OR (d2 IS NOT NULL AND jsonb_typeof(d2) <> 'object')
            OR (p1 IS NOT NULL AND jsonb_typeof(p1) <> 'object') OR (p2 IS NOT NULL AND jsonb_typeof(p2) <> 'object')
            OR algorithm_id IS NULL;
    END IF;
END $$;

CREATE TEMPORARY TABLE _uap_plan ON COMMIT DROP AS
SELECT s.*,
       coalesce(nullif(s.d1, '{}'::jsonb), nullif(s.d2, '{}'::jsonb), '{}'::jsonb)
         || coalesce(s.p1, '{}'::jsonb)
         || coalesce(s.p2, '{}'::jsonb) AS params,
       NULL::integer AS new_params_id
  FROM _uap_src s;

-- the reused set, if one already has exactly this content
UPDATE _uap_plan pl SET new_params_id = (
    SELECT u.params_id FROM medcea.unit_algorithm_params u
     WHERE u.algorithm_id = pl.algorithm_id AND u.unit_id IS NOT DISTINCT FROM pl.unit_id AND u.params = pl.params
       AND u.status <> 'retired'
     ORDER BY (u.params_id = pl.cur_params_id) DESC, u.params_id LIMIT 1);
-- rows already pointing at a matching set need nothing
DELETE FROM _uap_plan WHERE new_params_id IS NOT NULL AND new_params_id IS NOT DISTINCT FROM cur_params_id;

CREATE TEMPORARY TABLE _uap_new ON COMMIT DROP AS
SELECT DISTINCT ON (algorithm_id, unit_id, params) algorithm_id, unit_id, params, kind,
       base_name, by_sub, by_person, by_name, by_role, by_source
  FROM _uap_plan WHERE new_params_id IS NULL
 ORDER BY algorithm_id, unit_id, params, kind, base_name;
UPDATE _uap_new SET base_name = base_name || '#' || left(encode(sha256(convert_to(params::text, 'UTF8')), 'hex'), 8)
 WHERE EXISTS (SELECT 1 FROM medcea.unit_algorithm_params u WHERE u.name = _uap_new.base_name);
CREATE TEMPORARY TABLE _uap_ins (params_id integer, algorithm_id integer, unit_id integer, params jsonb) ON COMMIT DROP;

\if :params_first_run
-- first run: what was in use is grandfathered as approved
WITH ins AS (
    INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params, status, source)
    SELECT algorithm_id, unit_id, base_name, params, 'approved', 'migration 008b: copied from ' || base_name
      FROM _uap_new
    ON CONFLICT (name) DO NOTHING
    RETURNING params_id, algorithm_id, unit_id, params)
INSERT INTO _uap_ins SELECT * FROM ins;
INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note,
                             approved_by_sub, approved_by_name, approved_by_source, last_change_id)
SELECT 'medcea.unit_algorithm_params', jsonb_build_array(i.params_id),
       medcea_auth.row_digest('medcea.unit_algorithm_params', jsonb_build_array(i.params_id)), 'controllers', 'grandfather',
       'in use before migration 008b', 'migration:008', 'migration:008', 'migration',
       (SELECT x.last_change FROM medcea_auth._authors('medcea.unit_algorithm_params', jsonb_build_array(i.params_id)) x)
  FROM _uap_ins i;
INSERT INTO medcea.platform_setting (key, value) VALUES ('008b:params_grandfathered', now()::text)
ON CONFLICT (key) DO NOTHING;
\else
-- later runs: an inline edit made after the copy becomes a draft set,
-- attributed to whoever made it (stamping and the change log are bypassed for
-- this one insert, and the change is logged under that person instead)
RESET ROLE;
SET LOCAL session_replication_role = replica;
SET LOCAL ROLE medcea_owner;
WITH ins AS (
    INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params, status, source,
        created_by_sub, created_by_person, created_by_name, created_by_role, created_by_source,
        updated_by_sub, updated_by_person, updated_by_name, updated_by_role, updated_by_source)
    SELECT algorithm_id, unit_id, base_name, params, 'draft', 'migration 008b: inline parameters of ' || base_name,
           coalesce(by_sub, 'migration:008'), by_person, coalesce(by_name, 'migration:008'), by_role, coalesce(by_source, 'migration'),
           coalesce(by_sub, 'migration:008'), by_person, coalesce(by_name, 'migration:008'), by_role, coalesce(by_source, 'migration')
      FROM _uap_new
    ON CONFLICT (name) DO NOTHING
    RETURNING params_id, algorithm_id, unit_id, params)
INSERT INTO _uap_ins SELECT * FROM ins;
INSERT INTO medcea.row_change (target, row_key, op, new_values, actor_sub, actor_person, actor_name, actor_role, actor_source)
SELECT 'medcea.unit_algorithm_params', jsonb_build_array(i.params_id), 'I',
       medcea_auth._content(to_jsonb(u), false),
       u.created_by_sub, u.created_by_person, u.created_by_name, u.created_by_role, u.created_by_source
  FROM _uap_ins i JOIN medcea.unit_algorithm_params u ON u.params_id = i.params_id;
RESET ROLE;
SET LOCAL session_replication_role = origin;
SET LOCAL ROLE medcea_owner;
\endif

-- point every source row at its set (an owner write: the control-column guard lets it through)
UPDATE _uap_plan pl SET new_params_id = (
    SELECT u.params_id FROM medcea.unit_algorithm_params u
     WHERE u.algorithm_id = pl.algorithm_id AND u.unit_id IS NOT DISTINCT FROM pl.unit_id AND u.params = pl.params
       AND u.status <> 'retired'
     ORDER BY u.params_id DESC LIMIT 1)
 WHERE pl.new_params_id IS NULL;
UPDATE medcea.recipe_unit_permission p SET params_id = pl.new_params_id
  FROM _uap_plan pl
 WHERE pl.kind = 'rup' AND pl.recipe_id = p.recipe_id AND pl.unit_id = p.unit_id
   AND pl.new_params_id IS NOT NULL AND p.params_id IS DISTINCT FROM pl.new_params_id;
UPDATE medcea.schedule s SET params_id = pl.new_params_id
  FROM _uap_plan pl
 WHERE pl.kind = 'schedule' AND pl.schedule_id = s.schedule_id
   AND pl.new_params_id IS NOT NULL AND s.params_id IS DISTINCT FROM pl.new_params_id;

DO $$
DECLARE n integer; d integer;
BEGIN
    SELECT count(*) INTO n FROM _uap_ins;
    SELECT count(*) INTO d FROM _uap_plan WHERE new_params_id IS NULL;
    IF n > 0 THEN
        RAISE WARNING 'migration 008b: % new parameter set(s) from inline algorithm_params', n;
    END IF;
    IF d > 0 THEN
        RAISE WARNING 'migration 008b: % assignment/schedule row(s) left without a parameter set (name clash); see medcea.unit_algorithm_params', d;
    END IF;
END $$;

RESET ROLE;
\endif
