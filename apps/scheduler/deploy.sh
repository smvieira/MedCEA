#!/usr/bin/env bash
# apps/scheduler/deploy.sh — Recipe Schedule Manager
#
# Deploys:
#   1. medcea.schedule table migration
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
# 1. Database schema — owned by the app, not by this script
# =============================================================================
# medcea.schedule, its algorithm_* columns, medcea.scheduler_config and their
# grants are created by _ensure_schema() in scheduler-api.py at every start.
# The psql heredoc that used to sit here never ran: `kubectl exec` without -i
# does not pass stdin, so it was a silent no-op. Removed so there is one owner.

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
render "$SCRIPT_DIR/k8s/scheduler.yaml" NAMESPACE POSTGRES_PASS PROJECT_NAME REPO_ROOT | $KUBECTL apply -f -

log "Restarting scheduler to pick up new ConfigMaps..."
$KUBECTL rollout restart deployment/scheduler -n "$NAMESPACE"
log "Waiting for scheduler rollout..."
$KUBECTL rollout status deployment/scheduler -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 5b. Sign-in: oauth2-proxy owns $SCHEDULER_DOMAIN (any platform role)
# =============================================================================
log "Deploying scheduler-oauth2-proxy (Keycloak SSO)..."
_VALUES=$(mktemp /tmp/scheduler-oauth2proxy-values-XXXXXX.yaml)
APP_SERVICE=scheduler render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE > "$_VALUES"
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
