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
    _env="$($KUBECTL get deployment config-api -n "$NAMESPACE" -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null || true)"
    grep -qx 'PGRST_DB_PRE_REQUEST=medcea_auth.pre_request' <<<"$_env" || refuse+=("config-api has no PGRST_DB_PRE_REQUEST=medcea_auth.pre_request (2b)")
    grep -q '^PGRST_JWT_SECRET=' <<<"$_env" || refuse+=("config-api has no PGRST_JWT_SECRET (2b)")
    for _dep in scheduler monitor dbmgmt; do
        _u="$($KUBECTL get deployment "$_dep" -n "$NAMESPACE" -o jsonpath='{range .spec.template.spec.containers[*].env[?(@.name=="PG_USER")]}{.value}{"\n"}{end}' 2>/dev/null || true)"
        if [[ -z "$_u" ]] || grep -qx 'postgres' <<<"$_u"; then
            refuse+=("deployment $_dep still connects as postgres, or could not be read (2.5)")
        fi
    done
    _nr="$($KUBECTL exec -n "$NAMESPACE" deployment/node-red -- cat /data/flows.json 2>/dev/null || true)"
    if [[ -z "$_nr" ]] || grep -Eq '"user" *: *"postgres"' <<<"$_nr"; then
        refuse+=("Node-RED's database connection still uses postgres, or its flows could not be read (2.5)")
    fi
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
# authenticator keeps POSTGRES_PASS until Phase 2b switches config-api's URI to
# AUTHENTICATOR_DB_PASS in the same step.
DBPW_authenticator="${POSTGRES_PASS}"
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

# ── Apply ─────────────────────────────────────────────────────────────────────
log "Deploying database '$CEA_DB' with IAM_DB_ROLES=$IAM_DB_ROLES..."
# The mode a new session sees now (empty on a first deploy): read-only.
_DBA_NS="$NAMESPACE"; _DBA_POD="$PG_POD"
PREV_DB_ROLES="$(_dba_psql "$CEA_DB" -tAq -c "SELECT coalesce(current_setting('medcea.iam_db_roles', true), '')" 2>/dev/null \
                 | tr -d '[:space:]' || true)"
db_apply "$NAMESPACE" "$PG_POD" "$IAM_DB_ROLES"

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

# ── Secrets: one per database role, for 2.5 (nothing mounts them in 2a) ──────
log "Writing Secrets db-<role> (label medcea/db-role=true)..."
_secret_for() {   # role -> Secret name
    case "$1" in
        svc_*)          echo "db-${1//_/-}" ;;
        iam_svc)        echo "db-iam-svc" ;;
        rr_admin_login) echo "db-rr-admin-login" ;;
        authenticator)  echo "db-authenticator" ;;
        *)              echo "db-${1//_/-}" ;;
    esac
}
while read -r _role _var; do
    [[ -n "${!_var:-}" ]] || continue
    SECRET_NAME="$(_secret_for "$_role")" DB_ROLE="$_role" DB_PASS="${!_var}" \
        render "$SCRIPT_DIR/k8s/db-role-secret.yaml" SECRET_NAME DB_ROLE DB_PASS \
        | $KUBECTL apply -n "$NAMESPACE" -f - >/dev/null
done < <(python3 "$CLI" db-roles --passwords)

log "Schema deployed successfully."
echo ""
echo -e "  ${BOLD}Database deployed${NC}"
echo -e "  DB:  ${CEA_DB}  (pod: ${PG_POD})   IAM_DB_ROLES=${IAM_DB_ROLES}"
echo ""
