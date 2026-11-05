#!/usr/bin/env bash
# apps/database/lib-db-apply.sh — apply the platform database (schema, migrations,
# ownership, migration 008b's data steps, passwords and the IAM_DB_ROLES bundle).
#
#   db_apply NS POD MODE      MODE: false | true (IAM_DB_ROLES)
#                             DBA_SERVICE_LOGINS (env, optional): comma-separated login
#                             roles that may log in while MODE is false (IAM Phase 2.5)
#   dba_record_switch NS POD DB SWITCH MODE
#                             appends enforcement_enabled/_disabled {switch: SWITCH} to
#                             the hash chain when MODE differs from SWITCH's last event
#                             (deploy-infra.sh, IAM_ENFORCE; IAM 2.6); "skip" before 008a/b
#   dba_retire_person_mqtt NS POD DB DIGEST MODE
#                             ends MQTT person credentials the policy no longer backs
#                             (deploy-infra.sh, before dba_record_switch IAM_MQTT_PERSON;
#                             IAM 3.5); prints the count, "skip" before 008b
#   dba_record_event NS POD DB EVENT PAYLOAD_JSON REASON
#                             appends one event as system:deploy (deploy-infra.sh:
#                             break_glass_seen, IAM 3.3; account_seeded and the policy
#                             break-glass, IAM 4.2a). break_glass_seen, break_glass_ended
#                             and account_seeded go through iam_policy._record once
#                             _system_as exists (the 4.2a bodies); "skip-4.1" while only
#                             the 4.1 _record exists (the caller warns or queues);
#                             before 008c append_history (account_seeded: "skip", the
#                             caller queues); "skip" before 008a/b
#
#   IAM Phase 4, slice 4.2a — the pieces of db_apply that apps/iam/apply.sh reuses:
#   dba_compiled_functions NS POD [--without-iam]
#                             step 4a: the policy's compiled functions, one transaction
#                             (the factory policy on medcea-iamtest only, as db_apply)
#   dba_mode_live NS POD DB   prints true|false from medcea.platform_setting.iam_db_roles;
#                             3 while it is unset (no 008b), 1 when it cannot ask
#   dba_service_logins NS     the comma list of login roles that may log in while
#                             IAM_DB_ROLES=false (IAM 2.5; moved from apps/database/
#                             deploy.sh); reads only the presence of each password
#                             variable, never its value
#   dba_policy_bundle NS POD MODE PRE_SQL POST_SQL [--with-functions]
#                             step 6: one transaction (MODE false|true|auto; auto reads
#                             dba_mode_live and refuses, 3, when config.env differs):
#                             actor (DBA_ACTOR, default system:deploy), READ COMMITTED
#                             asserted, PRE_SQL, [the compiled functions], the down or
#                             enforce file, the grants body, the settings, POST_SQL,
#                             the asserts last. db_apply passes /dev/null twice.
#                             DBA_IAM_FLAG / DBA_SERVICE_LOGINS (env), when set, are used
#                             instead of asking dba_iam_flag / dba_service_logins.
#                             DBA_STAGED / DBA_STAGED_BY / DBA_STAGED_SHA256 (env, IAM
#                             4.5, apps/iam/apply.sh only): compile from that staged
#                             host file instead (_dba_src)
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
#      (1a: schema iam must also have iam._changed_since, IAM 4.1: the compiled grants name it)
#   2  medcea_db_ddl.sql (no ON_ERROR_STOP; "already exists" filtered, as before)
#   3  medcea_db_migrations.sql with -v deploy_nonce; 008b and 008c (IAM 4.1, the
#      access policy's versions) must both have committed it
#   3a recipe_recipe_id_seq fix (was deploy.sh step 4)
#   4  medcea_db_owner.sql (iam too, IAM 2.7)       (-1, ON_ERROR_STOP)
#   4a the policy's compiled functions              (-1, ON_ERROR_STOP)
#   4b medcea_db_008b_data.sql                      (-1, ON_ERROR_STOP; skipped while enforcing)
#   4c medcea_db_008b_index.sql                     (autocommit; CONCURRENTLY, batched backfill)
#   5  passwords of authenticator and mqtt_auth
#   6  the mode bundle, one transaction (-1, ON_ERROR_STOP; dba_policy_bundle):
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
# With -f - the pod reads the whole script before psql starts (in memory, never a file):
# a psql that stops early (ON_ERROR_STOP on the first statement) with input still unsent
# left `kubectl exec -i` hanging, or exiting 0 without the error (IAM 4.2a fixture P22).
# Without -f - stdin may be a terminal, so it is passed through untouched.
_dba_psql() {
    local db="$1"; shift
    local run='PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -U postgres -d "$0" "$@"'
    case " $* " in
        *" -f - "*) run='sql="$(cat; echo .)"; PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"; export PGPASSWORD
printf %s "${sql%.}" | psql -X -U postgres -d "$0" "$@"' ;;
    esac
    $KUBECTL exec -i -n "$_DBA_NS" "$_DBA_POD" -- \
        env PGOPTIONS="-c client_min_messages=warning -c lock_timeout=5s" \
        sh -c "$run" "$db" "$@"
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
#                           access deploy has not run), or without iam._changed_since
#                           (the IAM 4.1 access deploy has not run): run
#                           ./apps/access/deploy.sh first
#   exit 1                  the query failed: callers abort or FAIL, never default
# Used by db_apply, health-check.sh (iamgrants) and tests/iam-db.sh. Reads only.
dba_iam_flag() {
    local row s r f c
    _DBA_NS="$1"; _DBA_POD="$2"
    row="$(_dba_psql "$3" -tAq -v ON_ERROR_STOP=1 -F'|' -c "SELECT pg_catalog.to_regnamespace('iam') IS NOT NULL,
               EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'access_svc'),
               pg_catalog.to_regprocedure('iam.confirm_decision(integer,text)') IS NOT NULL,
               pg_catalog.to_regprocedure('iam._changed_since(text,text,double precision)') IS NOT NULL" </dev/null)" \
        || { echo "dba_iam_flag: cannot read schema iam and role access_svc in '$3'" >&2; return 1; }
    IFS='|' read -r s r f c <<<"$(tr -d '[:space:]' <<<"$row")"
    if [[ ! "$s|$r|$f|$c" =~ ^[tf]\|[tf]\|[tf]\|[tf]$ ]]; then
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
    elif [[ "$c" == f ]]; then
        echo "schema iam has no iam._changed_since: run ./apps/access/deploy.sh first (IAM 4.1)" >&2
        return 3
    fi
    return 0
}

db_apply() {
    local ns="$1" pod="$2" mode="$3" out nonce got grants_mode down_or_enforce verifier r flag
    local iam_flag=() src=() MEDCEA_POLICY_STAGED_SHA256=""
    _dba_src "$ns" || return $?
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
    # 008c (IAM 4.1) is a second transaction after 008b's, with the same nonce
    got="$(_dba_psql "$CEA_DB" -tAq -c "SELECT value FROM medcea.platform_setting WHERE key = '008c:last_nonce'" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$got" != "$nonce" ]]; then
        echo "ERROR: migration 008c did not commit (its nonce is '${got:-none}', not $nonce); the errors are above" >&2
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
    dba_compiled_functions "$ns" "$pod" "${iam_flag[@]}" || return 1

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

    # ── 6. the mode bundle (dba_policy_bundle, also apps/iam/apply.sh's) ───────
    DBA_IAM_FLAG="$flag" DBA_SERVICE_LOGINS="${DBA_SERVICE_LOGINS:-}" \
        dba_policy_bundle "$ns" "$pod" "$mode" /dev/null /dev/null || return 1
}

# _dba_src NS — sets the caller's `src` array: where the grants are compiled from (IAM
# Phase 4). The throwaway fixture namespace always compiles the factory policy, which its
# probes expect; every other namespace the source rule's (compiler/source.py: the
# applied version, else defaults.yaml).
# IAM 4.5 (design §14.8.4.1): DBA_STAGED names the staged host file of the version
# apps/iam/apply.sh applies (its mode-700 stage, header-checked by cli.py and pinned by
# sha256), which then replaces both. It is honoured only for the run that holds the lock
# (DBA_STAGED_BY = MEDCEA_LOCK_HELD, medcea_lock_verify), so a variable exported in an
# operator's shell compiles nothing: it is refused (2), never silently ignored, and never
# falls back to the host file of the previous version. The sha256 reaches cli.py as
# MEDCEA_POLICY_STAGED_SHA256, exported into the caller's own local of that name, so it
# lives as long as the caller's compile.
_dba_src() {
    local ns="$1"
    src=()
    [[ "$ns" == medcea-iamtest ]] && src=(--defaults)
    if [[ -n "${DBA_STAGED:-}" ]]; then
        if [[ -z "${MEDCEA_LOCK_HELD:-}" || "${DBA_STAGED_BY:-}" != "$MEDCEA_LOCK_HELD" ]] \
           || ! declare -F medcea_lock_verify >/dev/null || ! medcea_lock_verify; then
            echo "DBA_STAGED is set, but not by the run that holds the deploy lock: unset DBA_STAGED (only apps/iam/apply.sh sets it, for its bundle)" >&2
            return 2
        fi
        [[ "${DBA_STAGED_SHA256:-}" =~ ^[0-9a-f]{64}$ && -r "$DBA_STAGED" ]] \
            || { echo "DBA_STAGED needs a readable file and DBA_STAGED_SHA256 (64 hex characters)" >&2; return 2; }
        export MEDCEA_POLICY_STAGED_SHA256="$DBA_STAGED_SHA256"
    fi
    [[ -n "${DBA_STAGED:-}" ]] && src=(--staged "$DBA_STAGED")
    return 0
}

# dba_compiled_functions NS POD [--without-iam] — step 4a: the policy's compiled
# functions (policy_holds, object_group, pre_request, role_widening, …) in one
# transaction, from the namespace's source (_dba_src). Before the data steps, which
# digest rows through object_group().
# Design §14.4.8 wrote this as `NS POD [--defaults]`. Built differently on purpose: the
# source is not a caller's option but follows from NS (_dba_src, the one rule db_apply and
# dba_policy_bundle share), so no caller can compile a production namespace from the
# factory file past the source rule (--defaults only for medcea-iamtest, CLAUDE.md); the
# one argument a caller does choose is §14.4.8's `<iam flag>`, i.e. --without-iam.
dba_compiled_functions() {
    local ns="$1" pod="$2" a src=() iam_flag=() MEDCEA_POLICY_STAGED_SHA256=""
    shift 2
    for a in "$@"; do
        case "$a" in
            --without-iam) iam_flag=(--without-iam) ;;
            *) echo "dba_compiled_functions: unknown argument $a" >&2; return 2 ;;
        esac
    done
    _dba_src "$ns" || return $?
    _DBA_NS="$ns"; _DBA_POD="$pod"
    _dba_log "Compiled policy functions..."
    python3 "$REPO_ROOT/apps/iam/compiler/cli.py" "${src[@]}" compile grants --mode additive --part functions "${iam_flag[@]}" \
        | _dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - >/dev/null || return 1
}

# dba_mode_live NS POD DB — the database's own IAM_DB_ROLES (medcea.platform_setting
# iam_db_roles): prints true or false. 3 while it is unset (migration 008b not applied),
# 1 when the database cannot be asked. Reads only.
dba_mode_live() {
    local v
    _DBA_NS="$1"; _DBA_POD="$2"
    v="$(_dba_psql "$3" -tAq -v ON_ERROR_STOP=1 -c "SELECT CASE WHEN pg_catalog.to_regclass('medcea.platform_setting') IS NULL THEN 'unset'
               ELSE coalesce((SELECT s.value FROM medcea.platform_setting s WHERE s.key = 'iam_db_roles'), 'unset') END" </dev/null)" \
        || { echo "dba_mode_live: cannot read medcea.platform_setting in '$3'" >&2; return 1; }
    v="$(tr -d '[:space:]' <<<"$v")"
    case "$v" in
        true|false) echo "$v" ;;
        unset) echo "dba_mode_live: the database records no IAM_DB_ROLES (migration 008b not applied): ./apps/database/deploy.sh" >&2; return 3 ;;
        *) echo "dba_mode_live: unexpected iam_db_roles '$v' in '$3'" >&2; return 1 ;;
    esac
}

# dba_service_logins NS — who may log in while IAM_DB_ROLES=false (IAM Phase 2.5), as a
# comma list on stdout (nothing under IAM_DB_ROLES=true: every login role logs in).
# IAM_DB_SERVICE_ROLES=true: every login role whose password variable config.env sets
# (its presence only: `cli.py db-roles --passwords`, so the caller, apply.sh too, never
# needs the value; the services move to them as they are deployed next,
# infra/lib-db-roles.sh). false: only the roles a live client still uses, so turning the
# flag off never locks out a service that has not been deployed back onto postgres yet;
# the next deploy after it has been makes the role NOLOGIN. Needs infra/lib-db-roles.sh
# (db_clients_live, db_client_role, db_role_can_login) for the false case.
dba_service_logins() {
    local ns="$1" cli="$REPO_ROOT/apps/iam/compiler/cli.py" _sl=() _live=() _cu _c _u _role _var
    local -A _pwvar=()
    [[ "${IAM_DB_ROLES:-false}" == "true" ]] && return 0
    if [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]]; then
        while read -r _role _var; do _pwvar[$_role]="$_var"; done < <(python3 "$cli" db-roles --passwords)
        while read -r _role; do
            _var="${_pwvar[$_role]:-}"
            [[ -n "$_var" && -n "${!_var:+x}" ]] && _sl+=("$_role")
        done < <(python3 "$cli" db-roles --logins)
    else
        # an array, not `while read < <(…)`: db_role_can_login's kubectl exec -i
        # would read the rest of the list as its stdin
        mapfile -t _live < <(db_clients_live "$ns")
        for _cu in "${_live[@]}"; do
            read -r _c _u <<<"$_cu"
            _role="$(db_client_role "$_c")"
            if [[ "$_u" == "$_role" ]] || { [[ "$_u" == "?" ]] && db_role_can_login "$ns" "$_role"; }; then
                _sl+=("$_role")
                _dba_warn "IAM_DB_SERVICE_ROLES=false, but $_c still logs in as $_role: the role keeps its login until $_c is deployed back onto postgres; run this deploy again after that"
            fi
        done
    fi
    (IFS=,; echo "${_sl[*]}")
}

# dba_policy_bundle NS POD MODE PRE_SQL POST_SQL [--with-functions] — step 6 of db_apply
# and apps/iam/apply.sh's bundle (IAM 4.2a): one `psql -1` transaction, in order:
#   SET log_statement = 'none'; the \set lines (root, mode, pw_<role> for each DBPW_<role>
#   set by the caller — apply.sh sets none; the body guards its password lines); the
#   actor (DBA_ACTOR, default system:deploy); READ COMMITTED asserted (F-24); PRE_SQL;
#   [--with-functions: the compiled functions]; the down (false) or enforce (true) file;
#   the grants body (--service-logins under additive); the settings; POST_SQL; the
#   grants asserts, last. PRE_SQL and POST_SQL are host files concatenated onto stdin,
#   never paths inside the pod. MODE false|true, or auto: the database's own mode, refused
#   (3) when config.env's IAM_DB_ROLES says otherwise. Returns 1 when the bundle rolled
#   back (nothing in it applied), 2 on a usage error.
dba_policy_bundle() {
    local ns="$1" pod="$2" mode="$3" pre="${4:-}" post="${5:-}" withfn=false
    local src=() iam_flag=() flag live cfg grants_mode down_or_enforce body asserts fns="" out r verifier sl
    local actor="${DBA_ACTOR:-system:deploy}" logins=() MEDCEA_POLICY_STAGED_SHA256=""
    if [[ $# -eq 6 && "$6" == --with-functions ]]; then withfn=true
    elif [[ $# -ne 5 ]]; then echo "dba_policy_bundle: NS POD MODE PRE_SQL POST_SQL [--with-functions]" >&2; return 2; fi
    [[ -r "$pre" && -r "$post" ]] || { echo "dba_policy_bundle: cannot read $pre or $post" >&2; return 2; }
    [[ "$actor" =~ ^system:[a-z0-9:_-]+$ ]] || { echo "dba_policy_bundle: DBA_ACTOR must be system:<name>, not '$actor'" >&2; return 2; }
    _DBA_NS="$ns"; _DBA_POD="$pod"
    _dba_src "$ns" || return 2
    case "$mode" in
        true|false) ;;
        auto)
            live="$(dba_mode_live "$ns" "$pod" "$CEA_DB")" || return $?
            cfg="${IAM_DB_ROLES:-false}"
            if [[ "$live" != "$cfg" ]]; then
                echo "config.env says IAM_DB_ROLES=$cfg, the database records $live: run ./apps/database/deploy.sh first" >&2
                return 3
            fi
            mode="$live" ;;
        *) echo "dba_policy_bundle: MODE must be false, true or auto" >&2; return 2 ;;
    esac
    if [[ -n "${DBA_IAM_FLAG+x}" ]]; then
        flag="$DBA_IAM_FLAG"
    else
        flag="$(dba_iam_flag "$ns" "$pod" "$CEA_DB")" || return $?
    fi
    [[ -n "$flag" ]] && iam_flag=("$flag")
    local dir="$REPO_ROOT/apps/database"
    if [[ "$mode" == "true" ]]; then
        grants_mode=enforce; down_or_enforce="$dir/medcea_db_migrations_008b_enforce.sql"
    else
        grants_mode=additive; down_or_enforce="$dir/medcea_db_migrations_down_008b.sql"
    fi
    _dba_log "IAM_DB_ROLES=$mode: $(basename "$down_or_enforce") + grants --mode $grants_mode, one transaction..."
    if [[ "$grants_mode" == additive ]]; then
        if [[ -n "${DBA_SERVICE_LOGINS+x}" ]]; then sl="$DBA_SERVICE_LOGINS"; else sl="$(dba_service_logins "$ns")" || return 1; fi
        [[ -n "$sl" ]] && logins=(--service-logins "$sl")
    fi
    body="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" "${src[@]}" compile grants --mode "$grants_mode" --part body "${logins[@]}" "${iam_flag[@]}")" || return 1
    asserts="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" "${src[@]}" compile grants --mode "$grants_mode" --part assert "${iam_flag[@]}")" || return 1
    if [[ "$withfn" == true ]]; then
        # step 4a's SQL (dba_compiled_functions), inside the transaction
        fns="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" "${src[@]}" compile grants --mode additive --part functions "${iam_flag[@]}")" || return 1
    fi
    out="$({
        echo "SET log_statement = 'none';"
        printf "\\\\set root '%s'\n" "$PROJECT_NAME"
        printf "\\\\set mode '%s'\n" "$mode"
        while read -r r _; do
            verifier="$(_dba_scram "$r")"
            [[ -n "$verifier" ]] && printf "\\\\set pw_%s '%s'\n" "$r" "$verifier"
        done < <(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" db-roles --passwords)
        echo "SELECT medcea_auth._set_internal_actor('$actor');"
        _dba_isolation_sql
        cat "$pre"
        [[ "$withfn" == true ]] && echo "$fns"
        cat "$down_or_enforce"
        echo "$body"
        _dba_settings_sql
        # the enforce file sets system:deploy for its demotion step: POST (apply.sh's
        # _mark_applied) runs as this bundle's actor again
        [[ -s "$post" ]] && echo "SELECT medcea_auth._set_internal_actor('$actor');"
        cat "$post"
        echo "$asserts"
    } | _dba_psql "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" || {
        grep -v 'NOTICE' <<<"$out" | sed 's/^psql:[^ ]* //' >&2
        echo "ERROR: the IAM_DB_ROLES=$mode policy bundle was rolled back (nothing in it was applied)" >&2
        return 1
    }
    _dba_report "$out"
    _dba_log "IAM_DB_ROLES=$mode applied; grants match the policy."
}

# The bundle's isolation assert (F-24): the hash chain's writer needs READ COMMITTED, and
# a database or role default of another level would otherwise fail deep inside.
_dba_isolation_sql() {
    cat <<'SQL'
DO $iso$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'the policy bundle needs READ COMMITTED (is %)', pg_catalog.current_setting('transaction_isolation');
    END IF;
END $iso$;
SQL
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

# dba_record_switch NS POD DB SWITCH MODE — an enforcement switch that is not the
# database's own (IAM_ENFORCE) into the hash chain, on a transition only, with the same
# events and reason as IAM_DB_ROLES' block above. Prints "skip" while
# iam_policy.append_history or _set_internal_actor is missing; returns psql's status.
dba_record_switch() {
    _DBA_NS="$1"; _DBA_POD="$2"
    [[ "$5" == "false" || "$5" == "true" ]] || { echo "dba_record_switch: MODE must be false or true" >&2; return 2; }
    _dba_psql "$3" -q -tA -1 -v ON_ERROR_STOP=1 -v sw="$4" -v mode="$5" <<'SQL'
SELECT pg_catalog.to_regprocedure('iam_policy.append_history(text,jsonb,text)') IS NOT NULL
   AND pg_catalog.to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL AS ready \gset
\if :ready
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
SELECT pg_catalog.set_config('medcea.sw', :'sw', true), pg_catalog.set_config('medcea.sw_mode', :'mode', true) \g /dev/null
DO $$
DECLARE
    sw    text := current_setting('medcea.sw');
    ev    text := CASE current_setting('medcea.sw_mode') WHEN 'true' THEN 'enforcement_enabled' ELSE 'enforcement_disabled' END;
    last  text;
BEGIN
    SELECT h.event INTO last FROM iam_policy.history h
     WHERE h.payload ->> 'switch' = sw ORDER BY h.event_id DESC LIMIT 1;
    IF last IS DISTINCT FROM ev THEN
        PERFORM iam_policy.append_history(ev, pg_catalog.jsonb_build_object('switch', sw), 'deploy');
    END IF;
END $$;
\else
\echo skip
\endif
SQL
}

# dba_retire_person_mqtt NS POD DB DIGEST MODE — MQTT person credentials (iam-api, IAM 3.5)
# are bound to the mqtt.json they were issued under: every active one whose
# mqtt_credential_issued event names another digest than DIGEST is set inactive, and
# every active one when MODE (IAM_MQTT_PERSON) differs from that switch's last event in
# the chain, so a narrowed policy or a true -> false -> true round trip never brings an
# old credential back. Call it before dba_record_switch records MODE. Appends
# mqtt_credentials_retired {count, reason, mqtt_digest} when it ended any. Prints the
# count, or "skip" while the tables or append_history are missing.
dba_retire_person_mqtt() {
    _DBA_NS="$1"; _DBA_POD="$2"
    [[ "$5" == "false" || "$5" == "true" ]] || { echo "dba_retire_person_mqtt: MODE must be false or true" >&2; return 2; }
    [[ "$4" =~ ^[0-9a-f]{16,128}$ ]] || { echo "dba_retire_person_mqtt: DIGEST must be the mqtt.json digest" >&2; return 2; }
    _dba_psql "$3" -q -tA -1 -v ON_ERROR_STOP=1 -v dg="$4" \
        -v ev="$([[ "$5" == true ]] && echo enforcement_enabled || echo enforcement_disabled)" <<'SQL'
SELECT pg_catalog.to_regclass('medcea.mqtt_service_credential') IS NOT NULL
   AND pg_catalog.to_regprocedure('iam_policy.append_history(text,jsonb,text)') IS NOT NULL
   AND pg_catalog.to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL AS ready \gset
\if :ready
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
SELECT (SELECT h.event FROM iam_policy.history h WHERE h.payload ->> 'switch' = 'IAM_MQTT_PERSON'
         ORDER BY h.event_id DESC LIMIT 1) IS DISTINCT FROM :'ev' AS switched \gset
WITH r AS (
    UPDATE medcea.mqtt_service_credential c SET active = false
     WHERE c.active
       AND (:'switched'::boolean
            OR NOT EXISTS (SELECT 1 FROM iam_policy.history h
                            WHERE h.event = 'mqtt_credential_issued'
                              AND h.payload ->> 'username' = c.username
                              AND h.payload ->> 'mqtt_digest' = :'dg'))
    RETURNING 1)
SELECT pg_catalog.count(*) AS n FROM r \gset
SELECT :n > 0 AS any \gset
\if :any
SELECT iam_policy.append_history('mqtt_credentials_retired',
         pg_catalog.jsonb_build_object('count', :n, 'mqtt_digest', :'dg',
             'reason', CASE WHEN :'switched'::boolean THEN 'IAM_MQTT_PERSON switched'
                            ELSE 'the MQTT policy changed (mqtt.json digest)' END),
         'deploy') \g /dev/null
\endif
\echo :n
\else
\echo skip
\endif
SQL
}

# dba_record_event NS POD DB EVENT PAYLOAD_JSON REASON — one event in the hash chain as
# system:deploy, for what only a deploy can see (a break-glass setting it finds on a
# running pod, a policy break-glass, an account it seeded). The three events _record
# owns (break_glass_seen, break_glass_ended, account_seeded) go through
# iam_policy._record once iam_policy._system_as exists (the IAM 4.2a bodies: _record
# fills the version and, for account_seeded, checks the content hash and records each
# fact once); REASON becomes the payload's reason unless it names one. With only the
# 4.1 _record (it refuses system:deploy) it prints "skip-4.1" and returns 0: the caller
# warns or queues. Before 008c, break_glass_seen/_ended use append_history as before and
# account_seeded prints "skip" (the caller queues it). Every other event goes through
# append_history. Prints "skip" while append_history or _set_internal_actor is missing.
dba_record_event() {
    _DBA_NS="$1"; _DBA_POD="$2"
    [[ "$4" =~ ^[a-z][a-z0-9_]{2,62}$ ]] || { echo "dba_record_event: EVENT must be a snake_case name" >&2; return 2; }
    _dba_record_event_sql | _dba_psql "$3" -q -tA -1 -v ON_ERROR_STOP=1 -v ev="$4" -v payload="$5" -v why="$6"
}

# _dba_record_event_sql — dba_record_event's SQL (psql variables ev, payload, why); also
# run inside a rolled-back probe by tests/iam-db.sh (P24)
_dba_record_event_sql() {
    cat <<'SQL'
SELECT pg_catalog.to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL AS actor_ok,
       :'ev' IN ('break_glass_seen', 'break_glass_ended', 'account_seeded') AS policy_event,
       :'ev' = 'account_seeded' AS seed_event,
       pg_catalog.to_regprocedure('iam_policy._system_as(text[])') IS NOT NULL AS system_as,
       pg_catalog.to_regprocedure('iam_policy._record(text,jsonb)') IS NOT NULL AS record_41,
       pg_catalog.to_regprocedure('iam_policy.append_history(text,jsonb,text)') IS NOT NULL AS writer \gset
SELECT :'policy_event'::boolean AND :'system_as'::boolean AND :'actor_ok'::boolean AS via_record,
       :'policy_event'::boolean AND :'record_41'::boolean AND NOT :'system_as'::boolean AS only_41,
       :'writer'::boolean AND :'actor_ok'::boolean AS ready \gset
\if :via_record
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
SELECT iam_policy._record(:'ev', CASE WHEN p ? 'reason' OR coalesce(pg_catalog.btrim(:'why'), '') = '' THEN p
                                      ELSE p || pg_catalog.jsonb_build_object('reason', :'why') END)
  FROM (SELECT :'payload'::jsonb AS p) x \g /dev/null
\elif :only_41
\echo skip-4.1
\elif :seed_event
\echo skip
\elif :ready
SELECT medcea_auth._set_internal_actor('system:deploy') \g /dev/null
SELECT iam_policy.append_history(:'ev', :'payload'::jsonb, :'why') \g /dev/null
\else
\echo skip
\endif
SQL
}
