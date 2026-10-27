#!/usr/bin/env bash
# apps/access/uninstall.sh — remove what apps/access/deploy.sh installed.
#
#   ./apps/access/uninstall.sh                 service, proxy, Ingress, ConfigMaps,
#                                              Secret; the request records are kept
#   ./apps/access/uninstall.sh --purge-data    also DROP SCHEMA iam and role access_svc
#
# The request and decision history is an access-control record (Annex 11), so it
# is only dropped with the explicit flag, like the database component's data.
# Keycloak's 'access' client and the realm roles are infrastructure and stay.
# Users already approved keep their accounts and roles.
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
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[access]${NC} $*"; }

portal_card disable "https://$ACCESS_DOMAIN"

log "Removing access-oauth2-proxy..."
$MK8S helm3 uninstall access-oauth2-proxy -n "$NAMESPACE" 2>/dev/null || true

log "Removing Deployment, Services, Ingress, ConfigMaps and Secret..."
$KUBECTL delete deployment access -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete service access-public access-admin access-profile -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete ingress access-public -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap access-api access-html access-templates -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete secret access-secrets -n "$NAMESPACE" --ignore-not-found

if [[ "${1:-}" != "--purge-data" ]]; then
    log "Kept schema iam (access requests and their history; --purge-data drops it)."
    exit 0
fi

PG_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$PG_POD" ]]; then
    log "PostgreSQL is not running — nothing to drop."
    exit 0
fi
_psql() { $KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- env PGPASSWORD="$POSTGRES_PASS" \
              psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" "$@"; }

# database/uninstall.sh --purge-data runs before this one (reverse alphabetical
# order) and may already have dropped medcea_db with the schema in it.
if [[ "$(_psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'")" == "1" ]]; then
    log "Dropping schema iam..."
    _psql -d "$POSTGRES_DB" -c "DROP SCHEMA IF EXISTS iam CASCADE;" \
          -c "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'access_svc') THEN DROP OWNED BY access_svc; END IF; END \$\$;"
fi
_psql -d postgres -c "DROP ROLE IF EXISTS access_svc;"
log "Schema iam and role access_svc dropped."
