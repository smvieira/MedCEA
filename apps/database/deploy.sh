#!/usr/bin/env bash
# apps/database/deploy.sh — MedCEA database schema deployment
#
# Deploys (apps/database/lib-db-apply.sh, db_apply):
#   - role shells (medcea_owner, anon, authenticator, mqtt_auth) and medcea_db
#   - the schema (medcea_db_ddl.sql) and the post-DDL migrations, 008b included
#   - ownership of medcea, medcea_auth and iam_policy by medcea_owner
#   - migration 008b's one-shot data steps (grandfathering, parameter sets,
#     measurement.zone_id) while IAM_DB_ROLES=false
#   - the IAM_DB_ROLES bundle, one transaction:
#       false (default): medcea_db_migrations_down_008b.sql (today's grants: the
#                        API role anon on the medcea tables) + grants.py additive
#                        (the per-role grants of the access policy on NOLOGIN roles)
#       true:            medcea_db_migrations_008b_enforce.sql + grants.py enforce
#                        (per-role grants, RLS, guard triggers; anon holds nothing)
#     ending in assertions that roll it back when the catalog differs from the policy
#   - platform settings (medcea.platform_setting: the MQTT topic root, IAM_DB_ROLES)
#   - Secrets db-<role> with each database role's credentials (label medcea/db-role=true)
#
# Idempotent: safe to re-run against an existing database. Rollback of Phase 2:
# IAM_DB_ROLES=false in config.env, then ./apps/database/deploy.sh, which then
# restarts config-api: pre_request() reads the database setting
# medcea.iam_db_roles, which only new sessions see, and PostgREST keeps pooled
# sessions for up to 30 min. By hand: kubectl rollout restart deployment/config-api.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"
source "$SCRIPT_DIR/lib-db-apply.sh"
source "$REPO_ROOT/infra/lib-postgrest.sh"   # pgrst_live_mode: which password authenticator gets
source "$REPO_ROOT/infra/lib-db-roles.sh"    # db_clients_live, db_role_secret (IAM Phase 2.5)
NAMESPACE="${NAMESPACE:-medcea}"
PG_RELEASE="${PG_RELEASE:-rdbms}"
CEA_DB="${POSTGRES_DB:-medcea_db}"
IAM_DB_ROLES="${IAM_DB_ROLES:-false}"
CLI="$REPO_ROOT/apps/iam/compiler/cli.py"
# Role mqtt_auth (Mosquitto auth sidecar) logs in with this password.
if [[ -z "${MQTT_AUTH_DB_PASS:-}" ]]; then
    echo "ERROR: MQTT_AUTH_DB_PASS is not set in config.env — run ./deploy-infra.sh first (it generates it)." >&2
    exit 1
fi
if [[ "$IAM_DB_ROLES" != "true" && "$IAM_DB_ROLES" != "false" ]]; then
    echo "ERROR: IAM_DB_ROLES must be true or false, not '$IAM_DB_ROLES'." >&2
    exit 1
fi

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[database]${NC} $*"; }
warn() { echo -e "${YELLOW}[database] $*${NC}" >&2; }

# ── Find postgres pod ─────────────────────────────────────────────────────────
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=$PG_RELEASE" \
    -o jsonpath='{.items[0].metadata.name}' || true)
# stderr is kept and failure tolerated on purpose: under set -e a failing lookup
# used to exit right here, silently, before the error below could explain it.

if [[ -z "$PG_POD" ]]; then
    echo "ERROR: No PostgreSQL pod found (instance=$PG_RELEASE, namespace=$NAMESPACE)" >&2
    exit 1
fi
log "PostgreSQL pod: $PG_POD"

# ── Guard: IAM_DB_ROLES=true only once everything that calls the database is ready ─
# kubectl reads only; nothing is written before this passes.
if [[ "$IAM_DB_ROLES" == "true" ]]; then
    refuse=()
    [[ "${IAM_POSTGREST_JWT:-false}" == "true" ]] || refuse+=("IAM_POSTGREST_JWT is not true (PostgREST must verify tokens first)")
    if [[ -z "${AUTHENTICATOR_DB_PASS:-}" || "${AUTHENTICATOR_DB_PASS:-}" == "${POSTGRES_PASS:-}" ]]; then
        refuse+=("AUTHENTICATOR_DB_PASS is empty or equals POSTGRES_PASS (authenticator would SET ROLE to every rr_ role with the superuser's password)")
    fi
    # contract C1 of 2b: the env names and Secret keys of config-api-jwt.yaml
    _env="$($KUBECTL get deployment config-api -n "$NAMESPACE" -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}={.value}{.valueFrom.secretKeyRef.name}/{.valueFrom.secretKeyRef.key}{"\n"}{end}' 2>/dev/null || true)"
    grep -qx 'PGRST_DB_PRE_REQUEST=medcea_auth.pre_request/' <<<"$_env" || refuse+=("config-api has no PGRST_DB_PRE_REQUEST=medcea_auth.pre_request (2b: IAM_POSTGREST_JWT=true, ./apps/frontend/deploy.sh)")
    grep -qx 'PGRST_JWT_SECRET=medcea-jwks/jwks-sig.json' <<<"$_env" || refuse+=("config-api's PGRST_JWT_SECRET is not Secret medcea-jwks key jwks-sig.json (2b)")
    grep -qx 'AUTHENTICATOR_PASSWORD=db-authenticator/password' <<<"$_env" || refuse+=("config-api does not log in with Secret db-authenticator (2b)")
    grep -qx 'PGRST_JWT_AUD=medcea-api/' <<<"$_env" || refuse+=("config-api has no PGRST_JWT_AUD=medcea-api (2b)")
    [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]] || refuse+=("IAM_DB_SERVICE_ROLES is not true (every service must run on its own role first, 2.5)")
    # every database client on its own role (a client that is not deployed is skipped)
    _seen=""
    mapfile -t _live < <(db_clients_live "$NAMESPACE")
    for _cu in "${_live[@]}"; do
        read -r _c _u <<<"$_cu"
        _seen+="$_c "
        [[ "$_u" == "$(db_client_role "$_c")" ]] \
            || refuse+=("$_c logs in as ${_u/#\?/an unreadable user}, not $(db_client_role "$_c") (2.5: IAM_DB_SERVICE_ROLES=true, then deploy it again)")
    done
    for _c in scheduler node-red; do   # the two that write regulated data must exist
        [[ " $_seen " == *" $_c "* ]] || refuse+=("$_c is not deployed, or could not be read (2.5)")
    done
    for _var in $(python3 "$CLI" db-roles --passwords | awk '{print $2}'); do
        [[ -n "${!_var:-}" ]] || refuse+=("$_var is empty (run ./deploy-infra.sh, which runs infra/configure.sh)")
    done
    if [[ ${#refuse[@]} -gt 0 ]]; then
        echo "ERROR: IAM_DB_ROLES=true refused; nothing was changed:" >&2
        for r in "${refuse[@]}"; do echo "  - $r" >&2; done
        cat >&2 <<'EOF'
  Flipped now, this would break (IAM plan Phase 2a, spec §16):
    - the config UI and the edge wizard (PostgREST without JWT secret and pre-request: anon holds nothing)
    - the scheduler, the runner and its startup recovery (recipe_run, cycles and Q-tables are written
      through functions only; 2.4)
    - the scheduler's PUT /api/algorithms on approved algorithms (draft_only)
    - services still on postgres pass every grant, but every statement is logged (log_statement=all)
    - Node-RED, Grafana and the monitor keep working only while they run as the superuser
  Set IAM_DB_ROLES=false (the default) and re-run.
EOF
        exit 1
    fi
fi

# ── Passwords: the generated ones, as DBPW_<role> for db_apply ───────────────
# authenticator's password follows what config-api runs now, never config.env
# alone (IAM plan 2b): legacy config-api logs in with POSTGRES_PASS, the JWT one
# with Secret db-authenticator, which apps/frontend/deploy.sh owns while it runs
# (it switches the manifest and the password together, infra/lib-postgrest.sh).
# Before config-api exists the flag decides. Refused only while two pod templates
# are live (the password would match one of them); a single unready pod — e.g.
# after --purge-data dropped authenticator — is its template's mode, and this
# deploy is what makes it ready again. The choice is pgrst_db_auth_pass, which
# tests/iam-postgrest.sh exercises against live config-api modes.
pgrst_db_auth_pass "$NAMESPACE" "${IAM_POSTGREST_JWT:-false}" || exit 1
DBPW_authenticator="$_PGRST_DB_AUTH_PASS"
DBPW_mqtt_auth="${MQTT_AUTH_DB_PASS}"
_missing=()
while read -r _role _var; do
    [[ "$_role" == "authenticator" ]] && continue
    if [[ -n "${!_var:-}" ]]; then
        printf -v "DBPW_${_role}" '%s' "${!_var}"
    else
        _missing+=("$_var")
    fi
done < <(python3 "$CLI" db-roles --passwords)
if [[ ${#_missing[@]} -gt 0 ]]; then
    warn "no password for ${_missing[*]} (run ./deploy-infra.sh, which generates them): those roles stay NOLOGIN without one"
fi

# ── Service logins (IAM Phase 2.5): who may log in while IAM_DB_ROLES=false ──
# IAM_DB_SERVICE_ROLES=true: every login role with a password (the services move
# to them as they are deployed next, infra/lib-db-roles.sh). false: only the roles
# a live client still uses, so turning the flag off never locks out a service that
# has not been deployed back onto postgres yet; the next deploy after it has been
# makes the role NOLOGIN. Under IAM_DB_ROLES=true every login role logs in anyway.
DBA_SERVICE_LOGINS=""
if [[ "$IAM_DB_ROLES" != "true" ]]; then
    _sl=()
    if [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]]; then
        while read -r _role; do
            _v="DBPW_$_role"; [[ -n "${!_v:-}" ]] && _sl+=("$_role")
        done < <(python3 "$CLI" db-roles --logins)
    else
        # an array, not `while read < <(…)`: db_role_can_login's kubectl exec -i
        # would read the rest of the list as its stdin
        mapfile -t _live < <(db_clients_live "$NAMESPACE")
        for _cu in "${_live[@]}"; do
            read -r _c _u <<<"$_cu"
            _role="$(db_client_role "$_c")"
            if [[ "$_u" == "$_role" ]] || { [[ "$_u" == "?" ]] && db_role_can_login "$NAMESPACE" "$_role"; }; then
                _sl+=("$_role")
                warn "IAM_DB_SERVICE_ROLES=false, but $_c still logs in as $_role: the role keeps its login until $_c is deployed back onto postgres; run this deploy again after that"
            fi
        done
    fi
    DBA_SERVICE_LOGINS="$(IFS=,; echo "${_sl[*]}")"
    [[ -z "$DBA_SERVICE_LOGINS" ]] || log "Roles that may log in (IAM_DB_SERVICE_ROLES=${IAM_DB_SERVICE_ROLES:-false}): ${DBA_SERVICE_LOGINS//,/, }"
fi

# ── Apply ─────────────────────────────────────────────────────────────────────
log "Deploying database '$CEA_DB' with IAM_DB_ROLES=$IAM_DB_ROLES..."
# The mode a new session sees now (empty on a first deploy): read-only.
_DBA_NS="$NAMESPACE"; _DBA_POD="$PG_POD"
PREV_DB_ROLES="$(_dba_psql "$CEA_DB" -tAq -c "SELECT coalesce(current_setting('medcea.iam_db_roles', true), '')" 2>/dev/null \
                 | tr -d '[:space:]' || true)"
db_apply "$NAMESPACE" "$PG_POD" "$IAM_DB_ROLES"

# ── Unit assignments (IAM 2.8): a warning, never a refusal ───────────────────
# Under IAM_DB_ROLES=true an operator sees the telemetry and runs of their units
# only (own_unit) and starts runs only there. A missing assignment fails closed,
# so this does not block a re-deploy; the database cannot ask Keycloak who the
# operators are, so it checks only that anyone has a unit (per account:
# apps/iam/units.sh list). The apply above created iam_policy.user_unit.
if [[ "$IAM_DB_ROLES" == "true" ]]; then
    _uu="$(_dba_psql "$CEA_DB" -tAq -c "SELECT count(*) FROM iam_policy.user_unit" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "${_uu:-0}" =~ ^[1-9] ]] || warn "IAM_DB_ROLES=true and no unit is assigned to anyone: operators see no telemetry or runs and can start none. Assign them: apps/iam/units.sh assign <user> <UNIT>... (check: apps/iam/units.sh list)"
fi

# ── A mode flip reaches PostgREST only through new sessions ──────────────────
# pre_request() reads medcea.iam_db_roles, an ALTER DATABASE setting that open
# sessions never see; config-api's pool keeps them up to 30 min. Without a
# restart, a rollback (true -> false) leaves pooled sessions trying SET ROLE
# rr_* after the memberships are gone, and false -> true leaves them as anon.
if [[ "${PREV_DB_ROLES:-false}" != "$IAM_DB_ROLES" ]] && [[ -n "$PREV_DB_ROLES" || "$IAM_DB_ROLES" == "true" ]]; then
    if $KUBECTL get deployment/config-api -n "$NAMESPACE" >/dev/null 2>&1; then
        log "IAM_DB_ROLES changed (${PREV_DB_ROLES:-unset} -> $IAM_DB_ROLES): restarting config-api for fresh sessions..."
        $KUBECTL rollout restart deployment/config-api -n "$NAMESPACE" >/dev/null
        $KUBECTL rollout status deployment/config-api -n "$NAMESPACE" --timeout=3m \
            || warn "config-api did not roll out within 3 min; check: $KUBECTL get pods -n $NAMESPACE"
    else
        log "IAM_DB_ROLES changed (${PREV_DB_ROLES:-unset} -> $IAM_DB_ROLES); config-api is not deployed, nothing to restart."
    fi
fi

# ── Secrets: one per database role; each service reads its own (2.5, infra/lib-db-roles.sh) ──
log "Writing Secrets db-<role> (label medcea/db-role=true)..."
while read -r _role _var; do
    [[ -n "${!_var:-}" ]] || continue
    # the JWT config-api reads this one at start: apps/frontend/deploy.sh owns it
    # then (written here only when it is missing, from AUTHENTICATOR_DB_PASS)
    [[ "$_role" == authenticator && "$_PGRST_DB_WRITE_SECRET" != true ]] && continue
    SECRET_NAME="$(db_role_secret "$_role")" DB_ROLE="$_role" DB_PASS="${!_var}" \
        render "$SCRIPT_DIR/k8s/db-role-secret.yaml" SECRET_NAME DB_ROLE DB_PASS \
        | $KUBECTL apply -n "$NAMESPACE" -f - >/dev/null
done < <(python3 "$CLI" db-roles --passwords)

log "Schema deployed successfully."
echo ""
echo -e "  ${BOLD}Database deployed${NC}"
echo -e "  DB:  ${CEA_DB}  (pod: ${PG_POD})   IAM_DB_ROLES=${IAM_DB_ROLES}"
echo ""
