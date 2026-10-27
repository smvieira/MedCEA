#!/usr/bin/env bash
# apps/frontend/uninstall.sh — remove what apps/frontend/deploy.sh installed:
# the System Configuration UI (config-ui + config-api/PostgREST + its
# oauth2-proxy) and the Database Management portal (dbmgmt).
#
# Kept on purpose: the portal-nginx ConfigMap and the images mount deploy.sh
# adds to the portal Deployment. The portal (infra) mounts them, so removing
# them would stop the portal from starting; they only add the background image.
# Database contents are untouched (see apps/database/uninstall.sh).
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
CONFIG_DOMAIN="config.$DOMAIN"
DBMGMT_DOMAIN="${DBMGMT_DOMAIN:-dbmgmt.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[frontend]${NC} $*"; }

log "Disabling portal cards..."
portal_card disable "https://$CONFIG_DOMAIN"
portal_card disable "https://$DBMGMT_DOMAIN"

log "Removing config-oauth2-proxy (owns the $CONFIG_DOMAIN ingress)..."
$MK8S helm3 uninstall config-oauth2-proxy -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true
log "Removing dbmgmt-oauth2-proxy (owns the $DBMGMT_DOMAIN ingress)..."
$MK8S helm3 uninstall dbmgmt-oauth2-proxy -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true

log "Removing Deployments, Services, Ingresses and ConfigMaps..."
$KUBECTL delete deployment config-api config-ui dbmgmt -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete service    config-api config-ui dbmgmt -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete ingress    config-ui dbmgmt -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap  config-ui-nginx config-ui-html recipe-fileserver \
                           dbmgmt-nginx dbmgmt-html dbmgmt-api -n "$NAMESPACE" --ignore-not-found

log "Frontend removed."
