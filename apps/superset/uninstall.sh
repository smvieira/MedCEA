#!/usr/bin/env bash
# apps/superset/uninstall.sh — the inverse of apps/superset/deploy.sh.
#
#   ./apps/superset/uninstall.sh                removes the Deployment, the init Job, the
#                                               Service, the Ingress, Secret superset-secrets
#                                               and ConfigMap superset-config (all labelled
#                                               app=superset) and disables the portal card;
#                                               the metadata database is kept
#   ./apps/superset/uninstall.sh --purge-data   also DROP DATABASE superset and DROP ROLE
#                                               superset_meta: every dashboard, chart,
#                                               saved query and Superset user is gone
#
# Owner decision D5 (6 Nov 2026): the metadata database is dropped only through this
# script's own flag; deploy-apps.sh --uninstall --purge-data passes the flag to the
# database component only, so it never reaches here. Never touches the platform
# database, svc_superset (apps/database owns that role) or the Keycloak client
# superset (deploy-infra.sh's). ConfigMap cea-ca and Secret cea-tls are infrastructure.
# The wheel cache SUPERSET_WHEEL_DIR on the host (three public, hash-pinned wheels) stays:
# delete the folder by hand if Superset is gone for good. The Job and ConfigMap
# superset-wheels, if a failed download left them behind, go with the app=superset objects.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
_PURGE=false
case "$*" in
    "") ;;
    --purge-data) _PURGE=true ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/superset/uninstall.sh [--purge-data])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-superset-uninstall   # logs/app-superset-uninstall-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
SUPERSET_DOMAIN="${SUPERSET_DOMAIN:-superset.$DOMAIN}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[superset]${NC} $*"; }

source "$REPO_ROOT/infra/lib-portal.sh"
portal_card disable "https://$SUPERSET_DOMAIN"

log "Removing Superset (Deployment, init Job, Service, Ingress, Secret, ConfigMap)..."
$KUBECTL delete deployment,job,service,ingress,secret,configmap -n "$NAMESPACE" -l app=superset --ignore-not-found

if [[ "$_PURGE" != true ]]; then
    log "Kept the metadata database 'superset' (dashboards, charts, saved queries, users); pass --purge-data to drop it."
    exit 0
fi

PG_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$PG_POD" ]]; then
    echo -e "${YELLOW}[superset] PostgreSQL is not running: nothing to drop.${NC}"
    exit 0
fi
source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # _dba_psql: psql in the pod, SQL on stdin
log "Dropping database 'superset' and role superset_meta..."
# WITH (FORCE) ends any session still connected (PostgreSQL 13+); the role goes after
# the database it owns.
printf '%s\n' 'DROP DATABASE IF EXISTS superset WITH (FORCE);' 'DROP ROLE IF EXISTS superset_meta;' \
    | _DBA_NS="$NAMESPACE" _DBA_POD="$PG_POD" _dba_psql postgres -q -v ON_ERROR_STOP=1 -f -
log "Superset's metadata database is gone."
