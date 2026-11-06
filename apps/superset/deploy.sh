#!/usr/bin/env bash
# apps/superset/deploy.sh — Apache Superset 6.1.0 for data analysis (stage B of the
# decision record "Superset for data analysis"; owner decisions of 6 Nov 2026).
#
#   ./apps/superset/deploy.sh               the full deploy (deploy-apps.sh --all runs it)
#   ./apps/superset/deploy.sh --gate-only   only who may sign in, and only when the live
#                                           role mapping drifted from the applied policy
#
# Superset is installed automatically (D4), but only once the applied access policy
# has a superset tool block (stage C): until then this prints
#   skipped: Superset is not in the applied access policy yet (stage C)
# and exits 0, so deploy-apps.sh --all and install.sh stay green. Under IAM_GATES=false
# it is skipped too: there is no pre-policy Superset. If the policy loses Superset (or
# IAM_GATES turns false) while it runs, it is stopped (its Deployment deleted; the
# metadata database, Secret and ConfigMap stay), never left open.
#
# Deploys, in order: the metadata database `superset` owned by the login role
# superset_meta (psql in the PostgreSQL pod, on stdin, a SCRAM verifier only,
# log_statement none) → Secret superset-secrets (server-side apply) and ConfigMap
# superset-config (superset_config.py, medcea_security.py, bootstrap.py,
# requirements.txt) → the init Job (db upgrade, init, bootstrap.py: the connection
# "MedCEA" as svc_superset) → the web Deployment, Service and Ingress at
# https://$SUPERSET_DOMAIN → the portal card.
#
# Who may sign in: `policy_tool superset` (cli.py compile superset), the mapping
# {realm role: Alpha+sql_lab | Gamma+MedCEA Viewer}; medcea_security.py refuses anyone
# else with a 403 before a Superset user exists. The data connection logs in as
# svc_superset only, never postgres: this refuses otherwise (db_client, IAM 2.5).
# No Redis, no Celery worker (D2); dependencies from a hash-checked init container (D3);
# sessions 5 min idle, 1 h at most (D6). Uninstall: ./apps/superset/uninstall.sh
# [--purge-data] (D5: only that script drops the metadata database).
#
# Needs config.env: SUPERSET_SECRET_KEY, SUPERSET_META_DB_PASS (infra/configure.sh),
# SUPERSET_CLIENT_SECRET (deploy-infra.sh, Keycloak client superset), SVC_SUPERSET_DB_PASS.
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
_MODE=full
case "$*" in
    "") ;;
    --gate-only) _MODE=scoped ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/superset/deploy.sh [--gate-only])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-superset-deploy   # logs/app-superset-deploy-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ "$_MODE" == scoped ]] && echo "mode: gate-only"

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-wait.sh"
NAMESPACE="${NAMESPACE:-medcea}"
source "$REPO_ROOT/infra/lib-policy-source.sh"   # where every compile reads the policy (IAM Phase 4)
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)
SUPERSET_DOMAIN="${SUPERSET_DOMAIN:-superset.$DOMAIN}"
PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.$DOMAIN}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[superset]${NC} $*"; }
warn() { echo -e "${YELLOW}[superset] $*${NC}" >&2; }
die()  { echo -e "${RED}[superset] ERROR: $*${NC}" >&2; exit 1; }

_deployed() { $KUBECTL get deployment superset -n "$NAMESPACE" >/dev/null 2>&1; }

# Superset no longer in the policy (or IAM_GATES=false) while it runs: closed, not open.
# The Deployment goes (not a scale to 0): deploy-infra re-enables the card and health
# checks the mapping whenever deployment/superset exists. The data stays.
_stop() {
    $KUBECTL delete deployment superset -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
    source "$REPO_ROOT/infra/lib-portal.sh"
    portal_card disable "https://$SUPERSET_DOMAIN"
}

# The role mapping from the applied policy: SUPERSET_ROLES_MAPPING (canonical JSON), or
# rc 5 (not in the policy), 3 (IAM_GATES=false), 1 (the policy does not compile).
_mapping() {
    local out rc=0
    source "$REPO_ROOT/infra/lib-policy-tools.sh"
    out="$(policy_tool superset)" || rc=$?
    (( rc == 0 )) || return $rc
    SUPERSET_ROLES_MAPPING="$(_check_mapping "$out")" \
        || die "the compiled role mapping is not one Superset accepts (python3 apps/iam/compiler/cli.py compile superset)"
}
# medcea_security.py's own validator (its Flask-free part), so the deploy and the pod
# accept exactly the same mappings; prints the canonical JSON.
_check_mapping() {
    MAPPING="$1" python3 -c '
import json, os, sys
src = open(sys.argv[1]).read().split("\nfrom flask import", 1)[0]
ns = {}
exec(compile(src, sys.argv[1], "exec"), ns)
print(json.dumps(ns["parse_roles_mapping"](os.environ["MAPPING"]), sort_keys=True, separators=(",", ":")))
' "$SCRIPT_DIR/medcea_security.py" 2>/dev/null
}
# The live mapping (Secret superset-secrets on stdin, never printed) equals $1?
_live_mapping_is() {
    $KUBECTL get secret superset-secrets -n "$NAMESPACE" -o jsonpath='{.data.SUPERSET_ROLES_MAPPING}' 2>/dev/null \
        | base64 -d 2>/dev/null \
        | WANT="$1" python3 -c '
import json, os, sys
try:
    print(json.loads(sys.stdin.read()) == json.loads(os.environ["WANT"]))
except Exception:
    print(False)'
}

_SECRET_VARS=(NAMESPACE SUPERSET_SECRET_KEY SUPERSET_META_DB_PASS SUPERSET_CLIENT_SECRET SUPERSET_ROLES_MAPPING)
_render_secret() { render "$SCRIPT_DIR/k8s/superset-secret.yaml" "${_SECRET_VARS[@]}"; }
_CM_FILES=(superset_config.py medcea_security.py bootstrap.py requirements.txt)
# sha256 of what the pods read at start only: the Secret as rendered and the ConfigMap's files
_checksum() {
    { _render_secret; for f in "${_CM_FILES[@]}"; do printf '%s\n' "$f"; cat "$SCRIPT_DIR/$f"; done; } \
        | sha256sum | cut -d' ' -f1
}
_POD_VARS=(NAMESPACE KEYCLOAK_DOMAIN KEYCLOAK_REALM SUPERSET_DOMAIN PORTAL_DOMAIN PLATFORM_IP
           SUPERSET_CONFIG_CHECKSUM PG_SECRET PG_SECRET_KEY SUPERSET_DB_USER POSTGRES_DB)
_apply_cm() {
    local f args=()
    for f in "${_CM_FILES[@]}"; do args+=(--from-file="$f=$SCRIPT_DIR/$f"); done
    $KUBECTL create configmap superset-config -n "$NAMESPACE" "${args[@]}" --dry-run=client -o yaml \
        | $KUBECTL label --local -f - app=superset -o yaml | $KUBECTL apply -f - >/dev/null
}
_apply_secret() {
    _render_secret | $KUBECTL apply --server-side --field-manager=medcea-superset --force-conflicts -f - >/dev/null
}
_apply_web() {
    render "$SCRIPT_DIR/k8s/superset.yaml" "${_POD_VARS[@]}" | $KUBECTL apply -f -
}
_need_secrets() {
    local v missing=()
    for v in SUPERSET_SECRET_KEY SUPERSET_META_DB_PASS SUPERSET_CLIENT_SECRET; do
        [[ -n "${!v:-}" ]] || missing+=("$v")
    done
    (( ${#missing[@]} == 0 )) \
        || die "${missing[*]} empty in config.env: run ./deploy-infra.sh (it generates them and creates the Keycloak client superset), then deploy again"
    (( ${#SUPERSET_SECRET_KEY} >= 32 )) || die "SUPERSET_SECRET_KEY is shorter than 32 characters"
}
# The data connection's login: svc_superset, never postgres.
_db_login() {
    source "$REPO_ROOT/infra/lib-db-roles.sh"   # db_client (IAM 2.5)
    db_client "$NAMESPACE" svc_superset
    [[ "$DBC_USER" == "svc_superset" ]] \
        || die "Superset's data connection would log in as $DBC_USER, not svc_superset: set IAM_DB_SERVICE_ROLES=true and run ./apps/database/deploy.sh first (see the warning above)"
    PG_SECRET="$DBC_SECRET"; PG_SECRET_KEY="$DBC_SECRET_KEY"; SUPERSET_DB_USER="$DBC_USER"
}

# =============================================================================
# --gate-only (scoped): only the role mapping, only on drift
# =============================================================================
if [[ "$_MODE" == scoped ]]; then
    if ! _deployed; then
        echo "  SUPERSET_DOMAIN (superset): not deployed (./apps/superset/deploy.sh installs it)"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    _rc=0; _mapping || _rc=$?
    case $_rc in
        0) ;;
        3|5) _stop
             echo "  SUPERSET_DOMAIN (superset): re-rendered (stopped, Deployment deleted: Superset is not in the applied access policy, or IAM_GATES=false)"
             policy_source_finish "$NAMESPACE" superset
             exit 0 ;;
        *) die "cannot compile Superset's role mapping from the access policy (python3 apps/iam/compiler/cli.py check)" ;;
    esac
    if [[ "$(_live_mapping_is "$SUPERSET_ROLES_MAPPING")" == True ]]; then
        echo "  SUPERSET_DOMAIN (superset): unchanged"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    _need_secrets
    _db_login
    SUPERSET_CONFIG_CHECKSUM="$(_checksum)"
    _apply_cm       # the checksum names these files: the pod must mount them
    _apply_secret
    _apply_web >/dev/null
    $KUBECTL scale deployment superset -n "$NAMESPACE" --replicas=1 >/dev/null
    $KUBECTL rollout status deployment/superset -n "$NAMESPACE" --timeout=12m
    echo "  SUPERSET_DOMAIN (superset): re-rendered (role mapping)"
    policy_source_finish "$NAMESPACE" superset
    exit 0
fi

# =============================================================================
# 0. In the applied policy?
# =============================================================================
_rc=0; _mapping || _rc=$?
case $_rc in
    0) ;;
    5|3)
        if (( _rc == 3 )); then
            warn "skipped: IAM_GATES=false, and Superset has no pre-policy sign-in"
        else
            log "skipped: Superset is not in the applied access policy yet (stage C)"
        fi
        if _deployed; then
            _stop
            warn "the running Superset was stopped (Deployment deleted; its database is kept) and its portal card disabled"
        fi
        policy_source_finish "$NAMESPACE" superset
        exit 0 ;;
    *) die "cannot compile Superset's role mapping from the access policy (python3 apps/iam/compiler/cli.py check)" ;;
esac
log "Sign-in roles (compiled): $SUPERSET_ROLES_MAPPING"
_need_secrets
_db_login

# Dashboards as code arrive with stage C: a bundle must carry databases/MedCEA.yaml
# with bootstrap.py's DB_UUID (a bundle without it silently drops every dataset and
# chart), and the importers need a user holding can_write (dashboards/README.md).
_extra="$(find "$SCRIPT_DIR/dashboards" -type f ! -name README.md -print -quit 2>/dev/null || true)"
[[ -z "$_extra" ]] || die "apps/superset/dashboards/ holds ${_extra#"$SCRIPT_DIR/"}: importing dashboards is not built yet (stage C)"

# =============================================================================
# 1. Metadata database: superset, owned by superset_meta
# =============================================================================
log "Metadata database 'superset' (owner superset_meta)..."
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -n "$PG_POD" ]] || die "PostgreSQL is not running (./deploy-infra.sh)"
_META_SCRAM="$(printf '%s' "$SUPERSET_META_DB_PASS" | python3 "$REPO_ROOT/infra/pg-scram.py")"
# The verifier only, on stdin, in a session that logs no statement. Instance-wide
# objects outside the platform database: no grant in medcea_db, and the database deploy
# never compiles them (as Keycloak's database).
{
    echo "SET log_statement = 'none';"
    printf "\\\\set pw '%s'\n" "$_META_SCRAM"
    cat <<'SQL'
SELECT 'CREATE ROLE superset_meta' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'superset_meta') \gexec
ALTER ROLE superset_meta WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 20 PASSWORD :'pw';
SELECT 'CREATE DATABASE superset OWNER superset_meta' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'superset') \gexec
ALTER DATABASE superset OWNER TO superset_meta;
REVOKE ALL ON DATABASE superset FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE superset TO superset_meta;
SQL
} | _DBA_NS="$NAMESPACE" _DBA_POD="$PG_POD" _dba_psql postgres -q -v ON_ERROR_STOP=1 -f - >/dev/null \
    || die "could not create the metadata database (psql in $PG_POD)"
unset _META_SCRAM

# =============================================================================
# 2. Secret and ConfigMap
# =============================================================================
log "Secret superset-secrets and ConfigMap superset-config..."
_apply_cm
_apply_secret
SUPERSET_CONFIG_CHECKSUM="$(_checksum)"

# =============================================================================
# 3. Init Job: db upgrade, init, bootstrap.py
# =============================================================================
log "Init Job (db upgrade, init, the MedCEA connection and roles)..."
$KUBECTL delete job superset-init -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
render "$SCRIPT_DIR/k8s/superset-init.yaml" "${_POD_VARS[@]}" | $KUBECTL apply -f - >/dev/null
_deadline=$(( SECONDS + 1260 ))
while :; do
    _st="$($KUBECTL get job superset-init -n "$NAMESPACE" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || true)"
    [[ "$_st" == 1/* ]] && break
    if [[ "$_st" == */1 || $SECONDS -ge $_deadline ]]; then
        warn "the init Job failed (or took over 21 min); its last lines:"
        $KUBECTL logs job/superset-init -n "$NAMESPACE" --all-containers --tail=40 >&2 2>/dev/null || true
        die "Superset's init Job did not complete; the running Superset (if any) is unchanged"
    fi
    sleep 5
done
log "  init Job complete."

# =============================================================================
# 4. Web Deployment, Service, Ingress
# =============================================================================
log "Deploying Superset..."
_apply_web
$KUBECTL scale deployment superset -n "$NAMESPACE" --replicas=1 >/dev/null
$KUBECTL rollout status deployment/superset -n "$NAMESPACE" --timeout=12m
wait_for_http "https://$SUPERSET_DOMAIN/health" 180 "Superset" || exit 1

# =============================================================================
# 5. Portal card (the MedCEA Dashboard view)
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$SUPERSET_DOMAIN"

log ""
log "Superset deployed: https://$SUPERSET_DOMAIN"

# The last command of the success path: ends an open policy break-glass for superset (IAM 4.2a)
policy_source_finish "$NAMESPACE" superset
