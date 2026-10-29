#!/usr/bin/env bash
# apps/scheduler/deploy.sh — Recipe Schedule Manager
#
# Deploys:
#   1. a read-only check that migration 008b's functions are there (retire_schedule, start_run)
#   2. scheduler-api  (Flask + APScheduler, port 8082)
#   3. scheduler-ui   (nginx SPA, port 80)
#   4. oauth2-proxy on $SCHEDULER_DOMAIN (Keycloak SSO, any platform role)
#   5. Updates portal card (Scheduling — "Coming soon" → live link)
#
# Idempotent: safe to re-run.

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
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"
source "$REPO_ROOT/infra/lib-wait.sh"
NAMESPACE="${NAMESPACE:-medcea}"
SCHEDULER_DOMAIN="${SCHEDULER_DOMAIN:-scheduler.$DOMAIN}"
if [[ -z "${MQTT_SCHEDULER_PASS:-}" ]]; then
    echo "ERROR: MQTT_SCHEDULER_PASS is not set in config.env — run ./deploy-infra.sh first." >&2
    exit 1
fi

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[scheduler]${NC} $*"; }

# =============================================================================
# 1. Database schema — owned by apps/database/deploy.sh (migration 008b)
# =============================================================================
# medcea.schedule, medcea.scheduler_config and the run functions come from
# migration 008b; the scheduler runs no DDL. This API retires schedules through
# medcea.retire_schedule() and starts runs through medcea.start_run() (IAM plan
# 2.4), so it refuses to deploy onto a database without them. Read-only check.
PG_RELEASE="${PG_RELEASE:-rdbms}"
CEA_DB="${POSTGRES_DB:-medcea_db}"
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=$PG_RELEASE" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$PG_POD" ]]; then
    echo "ERROR: no PostgreSQL pod (instance=$PG_RELEASE, namespace=$NAMESPACE) — run ./deploy-infra.sh, then ./apps/database/deploy.sh" >&2
    exit 1
fi
_HAVE_FNS=$($KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- \
    env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" \
    sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -tA -U postgres -d "$0"' "$CEA_DB" \
    <<<"SELECT to_regprocedure('medcea.retire_schedule(integer)') IS NOT NULL AND to_regprocedure('medcea.start_run(integer)') IS NOT NULL;" \
    2>/dev/null || true)
if [[ "$_HAVE_FNS" != "t" ]]; then
    echo "ERROR: database $CEA_DB has no medcea.retire_schedule()/medcea.start_run() — run ./apps/database/deploy.sh first" >&2
    exit 1
fi

# =============================================================================
# 2. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap scheduler-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-file=default.conf="$SCRIPT_DIR/k8s/nginx.conf" | $KUBECTL apply -f -

# =============================================================================
# 3. HTML ConfigMap  (substitute $PORTAL_DOMAIN and embed background image)
# =============================================================================
log "Creating HTML ConfigMap..."
_BG_STYLE=""
for _BG_FILE in "$REPO_ROOT/apps/portal/bg.jpg" "$REPO_ROOT/apps/portal/bg.png" "$REPO_ROOT/apps/frontend/images/cea-background.png"; do
    if [[ -f "$_BG_FILE" ]]; then
        _MIME="image/png"; [[ "$_BG_FILE" == *.jpg ]] && _MIME="image/jpeg"
        _BG_STYLE="background-image:url('data:${_MIME};base64,$(base64 -w0 "$_BG_FILE")');"
        log "  Embedding background image: $_BG_FILE"
        break
    fi
done
_BG_TMP=$(mktemp)
echo -n "${_BG_STYLE}" > "$_BG_TMP"
python3 -c "
import sys
html  = open(sys.argv[1]).read()
style = open(sys.argv[2]).read()
html  = html.replace('\$PORTAL_DOMAIN', sys.argv[3])
html  = html.replace('__BG_STYLE__', style)
sys.stdout.write(html)
" "$SCRIPT_DIR/html/scheduler.html" "$_BG_TMP" "${PORTAL_DOMAIN}" \
  | $KUBECTL create configmap scheduler-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml > /tmp/scheduler-html-cm.yaml
rm -f "$_BG_TMP"
$KUBECTL replace -f /tmp/scheduler-html-cm.yaml 2>/dev/null || $KUBECTL create -f /tmp/scheduler-html-cm.yaml
rm -f /tmp/scheduler-html-cm.yaml

# =============================================================================
# 4. Python API ConfigMap
# =============================================================================
log "Creating API script ConfigMap..."
$KUBECTL create configmap scheduler-api -n "$NAMESPACE" \
  --from-file=scheduler-api.py="$SCRIPT_DIR/scheduler-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 5. Deployment
# =============================================================================
log "Deploying scheduler..."
# The broker's "scheduler" service account; the pod gets it as MQTT_USER/MQTT_PASS.
$KUBECTL create secret generic scheduler-secrets -n "$NAMESPACE" \
  --from-literal=MQTT_USER=scheduler --from-literal=MQTT_PASS="$MQTT_SCHEDULER_PASS" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
# The plain Ingress from before the SSO gate: its host now belongs to the proxy.
$KUBECTL delete ingress scheduler -n "$NAMESPACE" --ignore-not-found
render "$SCRIPT_DIR/k8s/scheduler.yaml" NAMESPACE POSTGRES_PASS PROJECT_NAME REPO_ROOT IAM_ENFORCE | $KUBECTL apply -f -

log "Restarting scheduler to pick up new ConfigMaps..."
$KUBECTL rollout restart deployment/scheduler -n "$NAMESPACE"
log "Waiting for scheduler rollout..."
$KUBECTL rollout status deployment/scheduler -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 5b. Sign-in: oauth2-proxy owns $SCHEDULER_DOMAIN (any platform role)
# =============================================================================
log "Deploying scheduler-oauth2-proxy (Keycloak SSO)..."
_VALUES=$(mktemp /tmp/scheduler-oauth2proxy-values-XXXXXX.yaml)
ALLOWED_GROUPS="$(policy_groups SCHEDULER_DOMAIN)"
gate_error_page scheduler-oauth2-proxy SCHEDULER_DOMAIN "$ALLOWED_GROUPS"
APP_SERVICE=scheduler render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE ALLOWED_GROUPS > "$_VALUES"
deploy_oauth2_proxy scheduler-oauth2-proxy scheduler "${SCHEDULER_CLIENT_SECRET:-}" "${SCHEDULER_COOKIE_SECRET:-}" "$SCHEDULER_DOMAIN" "$_VALUES"
rm -f "$_VALUES"
$KUBECTL rollout status deployment/scheduler-oauth2-proxy -n "$NAMESPACE" --timeout=4m
wait_for_http "https://$SCHEDULER_DOMAIN/" 120 "Scheduler" || exit 1

# =============================================================================
# 6. Portal card
# =============================================================================
# The card is part of the portal page deploy-infra.sh renders. The regex patch
# that used to be here looked for a disabled "Scheduling" card that page no longer
# contains, so it never changed anything; removed. portal_card below re-enables
# the card if apps/scheduler/uninstall.sh greyed it out.
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$SCHEDULER_DOMAIN"

log ""
log "Scheduler deployed!"
log "  UI: https://$SCHEDULER_DOMAIN"
