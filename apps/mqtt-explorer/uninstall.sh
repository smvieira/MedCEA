#!/usr/bin/env bash
# apps/mqtt-explorer/uninstall.sh — remove what apps/mqtt-explorer/deploy.sh
# installed: the sign-in proxy, the page's Deployment, Service and ConfigMap.
# The broker and its "mqtt-explorer" service account are infrastructure and stay.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-portal.sh"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
MQTTX_DOMAIN="${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[mqtt-explorer]${NC} $*"; }

portal_card disable "https://$MQTTX_DOMAIN"

log "Removing mqttx-oauth2-proxy (owns the $MQTTX_DOMAIN ingress)..."
$MK8S helm3 uninstall mqttx-oauth2-proxy -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true

log "Removing Deployment, Service, Ingress and ConfigMap..."
$KUBECTL delete deployment,service mqtt-explorer -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete ingress mqtt-explorer -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap mqtt-explorer-html -n "$NAMESPACE" --ignore-not-found

log "MQTT Explorer removed."
