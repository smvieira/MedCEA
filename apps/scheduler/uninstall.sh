#!/usr/bin/env bash
# apps/scheduler/uninstall.sh — remove what apps/scheduler/deploy.sh installed:
# the Recipe Schedule Manager Deployment, Service, Ingress and its ConfigMaps.
#
# Kept: the medcea.schedule table and its rows (database data; removed only by
# apps/database/uninstall.sh --purge-data).
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-portal.sh"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
SCHEDULER_DOMAIN="${SCHEDULER_DOMAIN:-scheduler.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[scheduler]${NC} $*"; }

portal_card disable "https://$SCHEDULER_DOMAIN"

log "Removing scheduler-oauth2-proxy (owns the $SCHEDULER_DOMAIN ingress)..."
$MK8S helm3 uninstall scheduler-oauth2-proxy -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true
$MK8S kubectl delete configmap scheduler-oauth2-proxy-templates -n "$NAMESPACE" --ignore-not-found >/dev/null  # its 403 page
$KUBECTL delete secret scheduler-secrets -n "$NAMESPACE" --ignore-not-found

log "Removing Deployment, Service, Ingress and ConfigMaps..."
$KUBECTL delete deployment,service,ingress scheduler -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap scheduler-nginx scheduler-html scheduler-api -n "$NAMESPACE" --ignore-not-found

log "Scheduler removed (schedule data kept in the database)."
