#!/usr/bin/env bash
# apps/database/uninstall.sh — the platform database (medcea_db).
#
#   ./apps/database/uninstall.sh                 does nothing: the data is kept
#   ./apps/database/uninstall.sh --purge-data    DROP DATABASE medcea_db, the
#                                                PostgREST roles anon/authenticator,
#                                                mqtt_auth and medcea_owner
#
# Uninstalling the apps must not silently destroy recorded runs, recipes and
# device registrations, so dropping them is a separate, explicit flag (and
# deploy-apps.sh asks for the project name before passing it). PostgreSQL itself
# is infrastructure and keeps running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
PG_USER="${POSTGRES_USER:-postgres}"
PG_PASS="${POSTGRES_PASS}"
CEA_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[database]${NC} $*"; }

if [[ "${1:-}" != "--purge-data" ]]; then
    log "Kept database '$CEA_DB' and its data (pass --purge-data to drop it)."
    exit 0
fi

PG_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$PG_POD" ]]; then
    echo -e "${YELLOW}[database] PostgreSQL is not running — nothing to drop.${NC}"
    exit 0
fi

log "Dropping database '$CEA_DB' and roles anon, authenticator, mqtt_auth, medcea_owner..."
# WITH (FORCE) ends any session still connected (PostgreSQL 13+). The roles go
# after the database because its default privileges reference anon.
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- env PGPASSWORD="$PG_PASS" \
    psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS \"$CEA_DB\" WITH (FORCE);" \
    -c "DROP ROLE IF EXISTS authenticator;" \
    -c "DROP ROLE IF EXISTS anon;" \
    -c "DROP ROLE IF EXISTS mqtt_auth;" \
    -c "DROP ROLE IF EXISTS medcea_owner;"

log "Database '$CEA_DB' dropped."
