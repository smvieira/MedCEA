#!/usr/bin/env bash
# apps/database/uninstall.sh — the platform database (medcea_db).
#
#   ./apps/database/uninstall.sh                 does nothing: the data is kept
#   ./apps/database/uninstall.sh --purge-data    DROP DATABASE medcea_db, then every
#                                                database role the platform created
#                                                (purge.sql: `cli.py db-roles --names` —
#                                                rr_*, rr_admin_login, svc_*, iam_svc,
#                                                mqtt_auth — plus medcea_owner,
#                                                authenticator and anon) and the
#                                                Secrets db-<role> (label medcea/db-role)
#
# Roles are instance-wide: they are dropped only after the database that holds
# their grants is gone. The keycloak database is never touched; access_svc is
# dropped by apps/access/uninstall.sh.
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

# A JWT config-api (IAM_POSTGREST_JWT=true) logs in with Secret db-authenticator,
# which this deletes with the role: a warning, not a refusal, because the
# uninstall order removes frontend first and a standalone purge is deliberate.
source "$REPO_ROOT/infra/lib-postgrest.sh"   # pgrst_template_mode
if [[ "$(pgrst_template_mode "$NAMESPACE" 2>/dev/null || true)" == jwt ]]; then
    echo -e "${YELLOW}[database] config-api still runs with token verification and logs in as authenticator;${NC}" >&2
    echo -e "${YELLOW}           after this purge it cannot connect until ./apps/database/deploy.sh has run again${NC}" >&2
    echo -e "${YELLOW}           (it rewrites the Secret from AUTHENTICATOR_DB_PASS); then ./apps/frontend/deploy.sh${NC}" >&2
    echo -e "${YELLOW}           restarts config-api on it. Or ./apps/frontend/uninstall.sh first.${NC}" >&2
fi

_ROLES="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" db-roles --names | paste -sd, -),medcea_owner,authenticator,anon"
log "Dropping database '$CEA_DB', then roles ${_ROLES//,/, }..."
# WITH (FORCE) ends any session still connected (PostgreSQL 13+). The roles go
# after the database because its grants and default privileges reference them.
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- env PGPASSWORD="$PG_PASS" \
    psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS \"$CEA_DB\" WITH (FORCE);"
{ printf "\\set roles '%s'\n" "$_ROLES"; cat "$SCRIPT_DIR/purge.sql"; } \
    | $KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- env PGPASSWORD="$PG_PASS" \
        psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d postgres -f -
$KUBECTL delete secret -n "$NAMESPACE" -l medcea/db-role=true --ignore-not-found >/dev/null

log "Database '$CEA_DB', its roles and the db-<role> Secrets dropped."
