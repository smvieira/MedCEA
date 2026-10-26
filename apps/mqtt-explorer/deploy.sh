#!/usr/bin/env bash
# apps/mqtt-explorer/deploy.sh — MQTT Explorer (browser MQTT tool)
#
# Deploys:
#   1. HTML ConfigMap (index.html, with the topic root and the broker's
#      "mqtt-explorer" service account filled in)
#   2. Deployment + Service (nginx serving the page)
#   3. mqttx-oauth2-proxy on $MQTTX_DOMAIN (Keycloak SSO, any platform role),
#      which also routes /mqtt to the broker's WebSocket listener
#   4. Portal card
#
# The page connects to wss://$MQTTX_DOMAIN/mqtt — through its own sign-in —
# and the broker checks the service account on top. That account's password is
# in the page, which is why the page is only served after sign-in.
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
MQTTX_DOMAIN="${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[mqtt-explorer]${NC} $*"; }

if [[ -z "${MQTT_EXPLORER_PASS:-}" ]]; then
    echo "ERROR: MQTT_EXPLORER_PASS is not set in config.env — run ./deploy-infra.sh first." >&2
    exit 1
fi

# =============================================================================
# 1. Page
# =============================================================================
log "Creating HTML ConfigMap..."
sed -e "s|__TOPIC_ROOT__|${PROJECT_NAME:-medcea}|g" \
    -e "s|__MQTT_USER__|mqtt-explorer|g" \
    -e "s|__MQTT_PASS__|${MQTT_EXPLORER_PASS}|g" \
    "$SCRIPT_DIR/html/index.html" \
  | $KUBECTL create configmap mqtt-explorer-html -n "$NAMESPACE" \
      --from-file=index.html=/dev/stdin --dry-run=client -o yaml \
  | $KUBECTL apply -f -

# =============================================================================
# 2. Deployment + Service
# =============================================================================
log "Deploying mqtt-explorer..."
# Leftovers: the mqttx-web resources of an older name, and the plain Ingress
# deploy-infra.sh used to create — its host now belongs to the proxy.
$KUBECTL delete deployment/mqttx-web service/mqttx-web ingress/mqttx-web \
  -n "$NAMESPACE" --ignore-not-found >/dev/null
$KUBECTL delete ingress mqtt-explorer -n "$NAMESPACE" --ignore-not-found
render "$SCRIPT_DIR/k8s/mqtt-explorer.yaml" NAMESPACE | $KUBECTL apply -n "$NAMESPACE" -f -
# The page is a subPath mount, which kubelet never refreshes in place.
$KUBECTL rollout restart deployment/mqtt-explorer -n "$NAMESPACE"
$KUBECTL rollout status deployment/mqtt-explorer -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 3. Sign-in (and the broker WebSocket at /mqtt)
# =============================================================================
log "Deploying mqttx-oauth2-proxy (Keycloak SSO)..."
_VALUES=$(mktemp /tmp/mqttx-oauth2proxy-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/oauth2-proxy-values.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE > "$_VALUES"
deploy_oauth2_proxy mqttx-oauth2-proxy mqtt-explorer "${MQTTX_CLIENT_SECRET:-}" "${MQTTX_COOKIE_SECRET:-}" "$MQTTX_DOMAIN" "$_VALUES"
rm -f "$_VALUES"
$KUBECTL rollout status deployment/mqttx-oauth2-proxy -n "$NAMESPACE" --timeout=4m
wait_for_http "https://$MQTTX_DOMAIN/" 120 "MQTT Explorer" || exit 1

# =============================================================================
# 4. Portal card
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$MQTTX_DOMAIN"

log ""
log "MQTT Explorer deployed!"
log "  UI: https://$MQTTX_DOMAIN   (broker: wss://$MQTTX_DOMAIN/mqtt as mqtt-explorer)"
