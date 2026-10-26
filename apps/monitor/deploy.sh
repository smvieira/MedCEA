#!/usr/bin/env bash
# apps/monitor/deploy.sh — Run Monitor Dashboard
#
# Deploys:
#   1. nginx ConfigMap (proxy /api/ → localhost:8082)
#   2. HTML ConfigMap  (monitor.html with background image)
#   3. API ConfigMap   (monitor-api.py)
#   4. Deployment: nginx:1.27-alpine + python:3.11-slim
#   5. Service, and oauth2-proxy on $MONITOR_DOMAIN (Keycloak SSO, any platform role)
#   6. Updates portal card (Run Monitor)
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
MONITOR_DOMAIN="${MONITOR_DOMAIN:-monitor.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[monitor]${NC} $*"; }

# =============================================================================
# 1. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap monitor-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-file=default.conf="$SCRIPT_DIR/k8s/nginx.conf" | $KUBECTL apply -f -

# =============================================================================
# 2. HTML ConfigMap (substitute $MONITOR_DOMAIN and embed background image)
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
sys.stdout.write(html.replace('__BG_STYLE__', style))
" "$SCRIPT_DIR/html/monitor.html" "$_BG_TMP" \
  | $KUBECTL create configmap monitor-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml > /tmp/monitor-html-cm.yaml
rm -f "$_BG_TMP"
$KUBECTL replace -f /tmp/monitor-html-cm.yaml 2>/dev/null || $KUBECTL create -f /tmp/monitor-html-cm.yaml
rm -f /tmp/monitor-html-cm.yaml

# =============================================================================
# 3. API ConfigMap
# =============================================================================
log "Creating API script ConfigMap..."
$KUBECTL create configmap monitor-api -n "$NAMESPACE" \
  --from-file=monitor-api.py="$SCRIPT_DIR/monitor-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 4. Deployment + Service + Ingress
# =============================================================================
log "Deploying monitor..."
# The plain Ingress from before the SSO gate: its host now belongs to the proxy.
$KUBECTL delete ingress monitor -n "$NAMESPACE" --ignore-not-found
render "$SCRIPT_DIR/k8s/monitor.yaml" NAMESPACE POSTGRES_PASS | $KUBECTL apply -f -

log "Restarting monitor to pick up new ConfigMaps..."
$KUBECTL rollout restart deployment/monitor -n "$NAMESPACE"
log "Waiting for monitor rollout..."
$KUBECTL rollout status deployment/monitor -n "$NAMESPACE" --timeout=3m

log "Deploying monitor-oauth2-proxy (Keycloak SSO)..."
_VALUES=$(mktemp /tmp/monitor-oauth2proxy-values-XXXXXX.yaml)
APP_SERVICE=monitor render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE > "$_VALUES"
deploy_oauth2_proxy monitor-oauth2-proxy monitor "${MONITOR_CLIENT_SECRET:-}" "${MONITOR_COOKIE_SECRET:-}" "$MONITOR_DOMAIN" "$_VALUES"
rm -f "$_VALUES"
$KUBECTL rollout status deployment/monitor-oauth2-proxy -n "$NAMESPACE" --timeout=4m
wait_for_http "https://$MONITOR_DOMAIN/" 120 "Run Monitor" || exit 1

# =============================================================================
# 5. Portal card
# =============================================================================
# The card is part of the portal page deploy-infra.sh renders. The regex patch
# that used to be here looked for a disabled "Run Monitor" card that page no longer
# contains, so it never changed anything; removed. portal_card below re-enables
# the card if apps/monitor/uninstall.sh greyed it out.
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$MONITOR_DOMAIN"

log ""
log "Monitor deployed!"
log "  UI: https://$MONITOR_DOMAIN"
