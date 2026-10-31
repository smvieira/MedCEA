#!/usr/bin/env bash
# apps/iam/deploy.sh — the access policy (codeplan IAM plan) and its service, iam-api
#
# 1. Checks the policy (apps/iam/policy/defaults.yaml) against its own invariants and
#    lists which roles each signed-in host admits. It is not the gate itself:
#    deploy-apps.sh runs components alphabetically, so frontend's gates are compiled
#    before this runs — what stops a broken policy is `cli.py compile`, which every gate
#    goes through and which refuses to compile from a policy that violates its invariants.
# 2. Deploys iam-api (IAM 3.5): ConfigMap iam-api-code (iam-api.py and infra/mqtt-passwd.py),
#    Deployment iam-api and Service iam-mqttx (:8085, the MQTT Explorer's credential
#    endpoint, reached only through its oauth2-proxy). It logs in as iam_svc and never
#    as postgres: until IAM_DB_SERVICE_ROLES=true and the database deploy has let iam_svc
#    log in, and until migration 008b's person-credential tables exist, iam-api is not
#    deployed — a warning while IAM_MQTT_PERSON=false (a default install), an error
#    while it is true (the Explorer would have no credential endpoint).
#    IAM_MQTT_PERSON is read live from /iam/settings.json (./deploy-infra.sh), so the
#    switch needs no redeploy here; while it is false POST answers 409. The guide's
#    enable recipe still runs this deploy right after setting the switch, before
#    ./deploy-infra.sh, so a missing iam-api stops it before the broker changes.
#
# Phase 4 adds the Policy UI, apply.sh and the bootstrap of version 1 here.
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[iam]${NC} $*"; }
die() { echo -e "${RED}[iam] $*${NC}" >&2; exit 1; }
skip_api() {   # iam-api cannot be deployed yet: fatal only while the Explorer depends on it
    [[ "${IAM_MQTT_PERSON:-false}" == "true" ]] && die "$*"
    echo -e "\033[0;33m[iam] iam-api not deployed: $* (needed before IAM_MQTT_PERSON=true).\033[0m" >&2
    exit 0
}

log "Checking the access policy..."
if ! python3 "$SCRIPT_DIR/compiler/cli.py" check; then
    die "The access policy violates its invariants — fix apps/iam/policy/defaults.yaml."
fi

log "Roles each signed-in host admits (policy; [status] = enforced today?):"
python3 "$SCRIPT_DIR/compiler/cli.py" hosts | sed 's/^/  /'

[[ -f "$REPO_ROOT/config.env" ]] || die "config.env not found at $REPO_ROOT/config.env"
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"      # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"    # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-db-roles.sh"  # db_client; _dba_psql
NAMESPACE="${NAMESPACE:-medcea}"
MQTTX_DOMAIN="${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}"

# =============================================================================
# iam-api (IAM 3.5)
# =============================================================================
log "Checking the database for iam-api..."
_POD="$(_dbr_pg_pod "$NAMESPACE")" || _POD=""
[[ -n "$_POD" ]] || skip_api "no PostgreSQL pod in $NAMESPACE: run ./deploy-infra.sh first."
_READY="$(_DBA_NS="$NAMESPACE" _DBA_POD="$_POD" _dba_psql "${POSTGRES_DB:-medcea_db}" -tAq \
    -c "SELECT pg_catalog.to_regclass('medcea.mqtt_service_credential') IS NOT NULL
               AND pg_catalog.to_regclass('iam.account_decision') IS NOT NULL" 2>/dev/null | tr -d '[:space:]')" || _READY=""
[[ "$_READY" == "t" ]] \
    || skip_api "medcea.mqtt_service_credential or iam.account_decision is missing: run ./apps/database/deploy.sh and ./apps/access/deploy.sh first."

# The one service that mints MQTT credentials never runs as postgres: the policy's
# limits on the person tables hold only for iam_svc.
db_client "$NAMESPACE" iam_svc
[[ "$DBC_USER" == "iam_svc" ]] \
    || skip_api "iam-api would log in as $DBC_USER, not iam_svc: set IAM_DB_SERVICE_ROLES=true and run ./apps/database/deploy.sh first (see the warning above)."

log "Creating ConfigMap iam-api-code..."
$KUBECTL create configmap iam-api-code -n "$NAMESPACE" \
    --from-file=iam-api.py="$SCRIPT_DIR/iam-api.py" \
    --from-file=mqtt_passwd.py="$REPO_ROOT/infra/mqtt-passwd.py" \
    --dry-run=client -o yaml | $KUBECTL apply -f -

log "Deploying iam-api (Service iam-mqttx :8085)..."
PG_USER="$DBC_USER" PG_SECRET="$DBC_SECRET" PG_SECRET_KEY="$DBC_SECRET_KEY" PROJECT_NAME="${PROJECT_NAME:-medcea}" \
IAM_ENFORCE="${IAM_ENFORCE:-false}" \
    render "$SCRIPT_DIR/k8s/iam.yaml" NAMESPACE POSTGRES_DB PG_USER PG_SECRET PG_SECRET_KEY PROJECT_NAME MQTTX_DOMAIN IAM_ENFORCE \
  | $KUBECTL apply -f -
# The code is a subPath mount, which kubelet never refreshes in place.
$KUBECTL rollout restart deployment/iam-api -n "$NAMESPACE"
$KUBECTL rollout status deployment/iam-api -n "$NAMESPACE" --timeout=3m

_HEALTH="$($KUBECTL exec -n "$NAMESPACE" deployment/iam-api -- \
    python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8085/healthz", timeout=5).read().decode())' 2>/dev/null)" \
    || die "iam-api does not answer /healthz (kubectl -n $NAMESPACE logs deployment/iam-api)."
log "  /healthz: $_HEALTH"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); sys.exit(0 if d.get("mqtt_digest") else 1)' "$_HEALTH" \
    || echo -e "\033[0;33m[iam] no valid /iam/mqtt.json yet: run ./deploy-infra.sh (the Explorer's POST answers 503 until then).\033[0m" >&2

log ""
log "iam-api deployed: the MQTT Explorer's credential endpoint (IAM_MQTT_PERSON=${IAM_MQTT_PERSON:-false}, read live)."
