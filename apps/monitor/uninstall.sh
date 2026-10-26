#!/usr/bin/env bash
# apps/monitor/uninstall.sh — remove what apps/monitor/deploy.sh installed:
# the Run Monitor Deployment, Service, Ingress and its three ConfigMaps.
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
MONITOR_DOMAIN="${MONITOR_DOMAIN:-monitor.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[monitor]${NC} $*"; }

portal_card disable "https://$MONITOR_DOMAIN"

log "Removing monitor-oauth2-proxy (owns the $MONITOR_DOMAIN ingress)..."
$MK8S helm3 uninstall monitor-oauth2-proxy -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true

log "Removing Deployment, Service, Ingress and ConfigMaps..."
$KUBECTL delete deployment,service,ingress monitor -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap monitor-nginx monitor-html monitor-api -n "$NAMESPACE" --ignore-not-found

log "Monitor removed."
