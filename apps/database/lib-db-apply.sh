#!/usr/bin/env bash
# apps/database/lib-db-apply.sh — apply the platform database (schema, migrations,
# ownership, migration 008b's data steps, passwords and the IAM_DB_ROLES bundle).
#
#   db_apply NS POD MODE      MODE: false | true (IAM_DB_ROLES)
#                             DBA_SERVICE_LOGINS (env, optional): comma-separated login
#                             roles that may log in while MODE is false (IAM Phase 2.5)
#
# Needs: KUBECTL, REPO_ROOT, PROJECT_NAME, CEA_DB. Optional: DBPW_<role> (plaintext
# passwords: DBPW_authenticator, DBPW_mqtt_auth, DBPW_svc_ingest, … — each sent only as
# a SCRAM verifier, on stdin, in a log_statement='none' session). Sourced by
# apps/database/deploy.sh and tests/iam-db-fixture.sh, so the throwaway instance gets
# exactly what production gets. Takes no lock itself: its callers hold medcea_lock.
#
# psql always runs inside the pod, as postgres, with the password read from
# $POSTGRES_PASSWORD_FILE there; SQL and secrets go on stdin (no /tmp files, no
# password in an argument). Every session sets client_min_messages=warning
# (production's POSTGRESQL_CLIENT_MIN_MESSAGES=error would hide the listings 008b
# prints as WARNINGs) and lock_timeout=5s (a busy table fails the deploy instead of
# stalling ingest; re-run it).
#
#   0  role shells: medcea_owner, anon (NOLOGIN), authenticator, mqtt_auth (LOGIN NOINHERIT)
#   1  CREATE DATABASE if missing; then dba_iam_flag: is schema iam (apps/access) compiled?
#   2  medcea_db_ddl.sql (no ON_ERROR_STOP; "already exists" filtered, as before)
#   3  medcea_db_migrations.sql with -v deploy_nonce; 008b must have committed it
#   3a recipe_recipe_id_seq fix (was deploy.sh step 4)
#   4  medcea_db_owner.sql (iam too, IAM 2.7)       (-1, ON_ERROR_STOP)
#   4a the policy's compiled functions              (-1, ON_ERROR_STOP)
#   4b medcea_db_008b_data.sql                      (-1, ON_ERROR_STOP; skipped while enforcing)
#   4c medcea_db_008b_index.sql                     (autocommit; CONCURRENTLY, batched backfill)
#   5  passwords of authenticator and mqtt_auth
#   6  the mode bundle, one transaction (-1, ON_ERROR_STOP):
#        false: medcea_db_migrations_down_008b.sql + grants --mode additive
#        true:  medcea_db_migrations_008b_enforce.sql + grants --mode enforce
#      then the settings (mqtt_topic_root, iam_db_roles, the database setting, the
#      enforcement_* event on a transition) and the grants assertions, last.
#   Every `compile grants` call (4a, 6) gets dba_iam_flag's answer: schema iam and
#   access_svc compiled like the rest, or --without-iam when the access component
#   is absent (IAM 2.7).

_DBA_GREEN='\033[0;32m'; _DBA_YELLOW='\033[0;33m'; _DBA_NC='\033[0m'
_dba_log()  { echo -e "${_DBA_GREEN}[database]${_DBA_NC} $*"; }
_dba_warn() { echo -e "${_DBA_YELLOW}[database] $*${_DBA_NC}" >&2; }

# _dba_psql DB [psql args...] — SQL on stdin
_dba_psql() {
    local db="$1"; shift
    $KUBECTL exec -i -n "$_DBA_NS" "$_DBA_POD" -- \
        env PGOPTIONS="-c client_min_messages=warning -c lock_timeout=5s" \
        sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -U postgres -d "$0" "$@"' "$db" "$@"
}

# _dba_scram ROLE — the verifier of DBPW_<ROLE>, or nothing
_dba_scram() {
    local var="DBPW_$1"
    [[ -n "${!var:-}" ]] || return 0
    printf '%s' "${!var}" | python3 "$REPO_ROOT/infra/pg-scram.py"
}

# Print WARNING lines of psql output; fail on ERROR lines when $2 says so.
_dba_report() {
    local out="$1"
    grep -E '^(psql:[^ ]* )?WARNING:|^WARNING:' <<<"$out" | sed 's/^psql:[^ ]* //' >&2 || true
}

# dba_iam_flag NS POD DB — how `cli.py compile grants` treats schema iam (IAM 2.7):
#   prints nothing          schema iam, role access_svc and the 2.7 functions exist:
#                           iam is compiled like the rest
#   prints --without-iam    schema iam is absent (no access component, or after
#                           access --purge-data / database --purge-data); a leftover
#                           role access_svc is left alone and holds nothing compiled
#   exit 3, message         a half-present access component: schema iam without role
#                           access_svc, or without iam.confirm_decision (the IAM 2.7
#                           access deploy has not run): run ./apps/access/deploy.sh first
#   exit 1                  the query failed: callers abort or FAIL, never default
# Used by db_apply, health-check.sh (iamgrants) and tests/iam-db.sh. Reads only.
dba_iam_flag() {
    local row s r f
    _DBA_NS="$1"; _DBA_POD="$2"
    row="$(_dba_psql "$3" -tAq -v ON_ERROR_STOP=1 -F'|' -c "SELECT pg_catalog.to_regnamespace('iam') IS NOT NULL,
               EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'access_svc'),
               pg_catalog.to_regprocedure('iam.confirm_decision(integer,text)') IS NOT NULL" </dev/null)" \
        || { echo "dba_iam_flag: cannot read schema iam and role access_svc in '$3'" >&2; return 1; }
    IFS='|' read -r s r f <<<"$(tr -d '[:space:]' <<<"$row")"
    if [[ ! "$s|$r|$f" =~ ^[tf]\|[tf]\|[tf]$ ]]; then
        echo "dba_iam_flag: unexpected answer from '$3': $row" >&2
        return 1
    fi
    if [[ "$s" == f ]]; then
        echo "--without-iam"
    elif [[ "$r" == f ]]; then
        echo "schema iam exists but role access_svc does not: run ./apps/access/deploy.sh first (IAM 2.7)" >&2
        return 3
    elif [[ "$f" == f ]]; then
        echo "schema iam has no iam.confirm_decision: run ./apps/access/deploy.sh first (IAM 2.7)" >&2
        return 3
    fi
    return 0
}

db_apply() {
    local ns="$1" pod="$2" mode="$3" out nonce got grants_mode down_or_enforce verifier r flag
    local iam_flag=()
    _DBA_NS="$ns"; _DBA_POD="$pod"
    [[ "$mode" == "false" || "$mode" == "true" ]] || { echo "db_apply: MODE must be false or true" >&2; return 2; }
    [[ "$PROJECT_NAME" =~ ^[a-z][a-z0-9-]{1,30}$ ]] || { echo "db_apply: PROJECT_NAME is not ^[a-z][a-z0-9-]{1,30}$" >&2; return 2; }
    local dir="$REPO_ROOT/apps/database"

    # ── 0. role shells ────────────────────────────────────────────────────────
    _dba_log "Role shells (medcea_owner, anon, authenticator, mqtt_auth)..."
    _dba_psql postgres -q -v ON_ERROR_STOP=1 -f - <<'SQL' || return 1
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'medcea_owner') THEN CREATE ROLE medcea_owner NOLOGIN; END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticator') THEN CREATE ROLE authenticator LOGIN NOINHERIT; END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mqtt_auth') THEN CREATE ROLE mqtt_auth LOGIN NOINHERIT; END IF;
END $$;
-- PostgREST resolves the medcea tables unqualified. Never on postgres: Keycloak
-- connects as postgres and has its own tables in public (CLAUDE.md).
ALTER ROLE authenticator SET search_path TO medcea, public;
SQL

    # ── 1. database ───────────────────────────────────────────────────────────
    if [[ "$(_dba_psql postgres -tAq -c "SELECT 1 FROM pg_database WHERE datname = '$CEA_DB'" | tr -d '[:space:]')" != "1" ]]; then
        _dba_log "Creating database '$CEA_DB'..."
        _dba_psql postgres -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$CEA_DB\" ENCODING 'UTF8' TEMPLATE template0;" || return 1
    else
        _dba_log "Database '$CEA_DB' already exists."
    fi

    # ── 1a. schema iam: compiled, or --without-iam (before anything is written) ─
    flag="$(dba_iam_flag "$ns" "$pod" "$CEA_DB")" || return 1
    if [[ -n "$flag" ]]; then
        iam_flag=("$flag")
        _dba_log "Schema iam is absent (no access component): the grants are compiled $flag."
    fi

    # ── 2. DDL ────────────────────────────────────────────────────────────────
    # plain SQL (pg_dump --schema-only); on a re-run every CREATE fails with
    # "already exists" and is skipped
    _dba_log "Applying schema (medcea_db_ddl.sql; 'already exists' errors are expected and suppressed)..."
    _dba_psql "$CEA_DB" -q -f - < "$dir/medcea_db_ddl.sql" 2>&1 \
        | grep "ERROR:" | grep -v "already exists" | grep -v "multiple primary keys" >&2 || true

    # ── 3. migrations ─────────────────────────────────────────────────────────
    nonce="$(openssl rand -hex 8)"
    _dba_log "Applying post-DDL migrations (008b nonce ${nonce})..."
    # no ON_ERROR_STOP, as before: earlier migrations rely on "already exists" being
    # skipped; 008b is one transaction, and the nonce below says whether it committed
    out="$(_dba_psql "$CEA_DB" -q -v deploy_nonce="$nonce" -f - < "$dir/medcea_db_migrations.sql" 2>&1 || true)"
    grep -v 'NOTICE' <<<"$out" | grep -E 'ERROR|WARNING' | sed 's/^psql:[^ ]* //' >&2 || true
    got="$(_dba_psql "$CEA_DB" -tAq -c "SELECT value FROM medcea.platform_setting WHERE key = '008b:last_nonce'" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$got" != "$nonce" ]]; then
        echo "ERROR: migration 008b did not commit (its nonce is '${got:-none}', not $nonce); the errors are above" >&2
        return 1
    fi

    # ── 3a. recipe_id sequence (tables created without one) ───────────────────
    _dba_psql "$CEA_DB" -q -v ON_ERROR_STOP=1 -f - <<'SQL' || return 1
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT FROM pg_class WHERE relname = 'recipe_recipe_id_seq'
    AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'medcea')
  ) THEN
    CREATE SEQUENCE medcea.recipe_recipe_id_seq;
    ALTER TABLE medcea.recipe ALTER COLUMN recipe_id SET DEFAULT nextval('medcea.recipe_recipe_id_seq');
    PERFORM setval('medcea.recipe_recipe_id_seq', COALESCE((SELECT MAX(recipe_id) FROM medcea.recipe), 0) + 1, false);
  END IF;
END$$;
SQL

    # ── 4. ownership ──────────────────────────────────────────────────────────
    _dba_log "Ownership: medcea, medcea_auth, iam_policy and iam belong to medcea_owner..."
    _dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - < "$dir/medcea_db_owner.sql" || return 1

    # ── 4a. the compiled functions (policy_holds, object_group, pre_request, …) ─
    # before the data steps, which digest rows through object_group(); the bundle
    # re-creates them in step 6 from the same policy
    _dba_log "Compiled policy functions..."
    python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile grants --mode additive --part functions "${iam_flag[@]}" \
        | _dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - >/dev/null || return 1

    # ── 4b/4c. 008b data steps ────────────────────────────────────────────────
    _dba_log "Migration 008b data (grandfathering, parameter sets)..."
    out="$(_dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - < "$dir/medcea_db_008b_data.sql" 2>&1)" \
        || { echo "$out" >&2; return 1; }
    _dba_report "$out"
    _dba_log "Migration 008b telemetry (zone index, zone backfill)..."
    out="$(_dba_psql "$CEA_DB" -q -v ON_ERROR_STOP=1 -f - < "$dir/medcea_db_008b_index.sql" 2>&1)" \
        || { echo "$out" >&2; return 1; }
    _dba_report "$out"

    # ── 5. passwords of the roles PostgREST and the broker log in as ──────────
    # DBPW_authenticator is whatever config-api logs in with right now: the caller
    # decides (apps/database/deploy.sh by pgrst_db_auth_pass: POSTGRES_PASS for the
    # legacy config-api, Secret db-authenticator for the JWT one, IAM plan 2b). The
    # switch itself is apps/frontend/deploy.sh's (infra/lib-postgrest.sh), which sets
    # this password in the same step as the manifest. anon never logs in.
    {
        echo "SET log_statement = 'none';"
        for r in authenticator mqtt_auth; do
            verifier="$(_dba_scram "$r")"
            [[ -n "$verifier" ]] || continue
            printf "\\\\set pw '%s'\n" "$verifier"
            printf "ALTER ROLE %s PASSWORD :'pw';\n" "$r"
        done
    } | _dba_psql "$CEA_DB" -q -v ON_ERROR_STOP=1 -f - >/dev/null || return 1

    # ── 6. the mode bundle ────────────────────────────────────────────────────
    if [[ "$mode" == "true" ]]; then
        grants_mode=enforce; down_or_enforce="$dir/medcea_db_migrations_008b_enforce.sql"
    else
        grants_mode=additive; down_or_enforce="$dir/medcea_db_migrations_down_008b.sql"
    fi
    _dba_log "IAM_DB_ROLES=$mode: $(basename "$down_or_enforce") + grants --mode $grants_mode, one transaction..."
    local body asserts
    local logins=()
    [[ "$grants_mode" == additive && -n "${DBA_SERVICE_LOGINS:-}" ]] && logins=(--service-logins "$DBA_SERVICE_LOGINS")
    body="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile grants --mode "$grants_mode" --part body "${logins[@]}" "${iam_flag[@]}")" || return 1
    asserts="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile grants --mode "$grants_mode" --part assert "${iam_flag[@]}")" || return 1
    out="$({
        echo "SET log_statement = 'none';"
        printf "\\\\set root '%s'\n" "$PROJECT_NAME"
        printf "\\\\set mode '%s'\n" "$mode"
        while read -r r _; do
            verifier="$(_dba_scram "$r")"
            [[ -n "$verifier" ]] && printf "\\\\set pw_%s '%s'\n" "$r" "$verifier"
        done < <(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" db-roles --passwords)
        echo "SELECT medcea_auth._set_internal_actor('system:deploy');"
        cat "$down_or_enforce"
        echo "$body"
        _dba_settings_sql
        echo "$asserts"
    } | _dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" || {
        grep -v 'NOTICE' <<<"$out" | sed 's/^psql:[^ ]* //' >&2
        echo "ERROR: the IAM_DB_ROLES=$mode bundle was rolled back (nothing in it was applied)" >&2
        return 1
    }
    _dba_report "$out"
    _dba_log "IAM_DB_ROLES=$mode applied; grants match the policy."
}

# The settings block of the bundle. psql variables are interpolated in plain
# statements only, so the values reach the DO block through set_config().
_dba_settings_sql() {
    cat <<'SQL'
-- settings: the MQTT topic root and IAM_DB_ROLES, in the table (triggers read
-- it through medcea_auth.enforcing()) and as the database setting
-- medcea.iam_db_roles (pre_request() reads it; new sessions see it)
INSERT INTO medcea.platform_setting (key, value) VALUES ('mqtt_topic_root', :'root')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
INSERT INTO medcea.platform_setting (key, value) VALUES ('iam_db_roles', :'mode')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
SELECT pg_catalog.set_config('medcea.deploy_mode', :'mode', true);
DO $$
DECLARE
    m     text := current_setting('medcea.deploy_mode');
    last  text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
                    WHERE s.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
                      AND s.setrole = 0 AND ('medcea.iam_db_roles=' || m) = ANY (s.setconfig)) THEN
        EXECUTE pg_catalog.format('ALTER DATABASE %I SET medcea.iam_db_roles = %L', current_database(), m);
    END IF;
    SELECT h.event INTO last FROM iam_policy.history h
     WHERE h.payload ->> 'switch' = 'IAM_DB_ROLES' ORDER BY h.event_id DESC LIMIT 1;
    IF last IS DISTINCT FROM (CASE m WHEN 'true' THEN 'enforcement_enabled' ELSE 'enforcement_disabled' END) THEN
        PERFORM iam_policy.append_history(CASE m WHEN 'true' THEN 'enforcement_enabled' ELSE 'enforcement_disabled' END,
                                          '{"switch": "IAM_DB_ROLES"}'::jsonb, 'deploy');
    END IF;
END $$;
SQL
}
