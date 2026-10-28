#!/usr/bin/env bash
# apps/database/deploy.sh — MedCEA database schema deployment
#
# Deploys:
#   - Creates medcea_db (if not present)
#   - Applies schema via psql from medcea_db_ddl.sql (plain-SQL schema dump)
#   - Applies post-DDL migrations (idempotent ALTER / CREATE IF NOT EXISTS)
#   - Configures search_path for Grafana/PostgREST access
#   - Grants anon role access for PostgREST
#   - Records platform settings (medcea.platform_setting: the MQTT topic root)
#
# Idempotent: safe to re-run against an existing database.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
PG_RELEASE="${PG_RELEASE:-rdbms}"
PG_USER="${POSTGRES_USER:-postgres}"
PG_PASS="${POSTGRES_PASS}"
CEA_DB="${POSTGRES_DB:-medcea_db}"
DDL_FILE="$SCRIPT_DIR/medcea_db_ddl.sql"
# Role mqtt_auth (Mosquitto auth sidecar) is created below with this password.
if [[ -z "${MQTT_AUTH_DB_PASS:-}" ]]; then
    echo "ERROR: MQTT_AUTH_DB_PASS is not set in config.env — run ./deploy-infra.sh first (it generates it)." >&2
    exit 1
fi

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[database]${NC} $*"; }

# ── Find postgres pod ─────────────────────────────────────────────────────────
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=$PG_RELEASE" \
    -o jsonpath='{.items[0].metadata.name}' || true)
# stderr is kept and failure tolerated on purpose: under set -e a failing lookup
# used to exit right here, silently, before the error below could explain it.

if [[ -z "$PG_POD" ]]; then
    echo "ERROR: No PostgreSQL pod found (instance=$PG_RELEASE, namespace=$NAMESPACE)" >&2
    exit 1
fi
log "PostgreSQL pod: $PG_POD"

# ── 1. Create database (if not exists) ───────────────────────────────────────
log "Ensuring database '$CEA_DB' exists..."
DB_EXISTS=$($KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
    env PGPASSWORD="$PG_PASS" psql -U "$PG_USER" -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='$CEA_DB'" 2>/dev/null | tr -d '[:space:]')
if [[ "$DB_EXISTS" != "1" ]]; then
    log "Creating database '$CEA_DB'..."
    $KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
        env PGPASSWORD="$PG_PASS" psql -U "$PG_USER" -d postgres -c \
        "CREATE DATABASE $CEA_DB ENCODING 'UTF8' TEMPLATE template0;" 2>/dev/null || true
else
    log "Database '$CEA_DB' already exists."
fi

# ── 2. Apply schema via psql ─────────────────────────────────────────────────
# medcea_db_ddl.sql is plain SQL (pg_dump --schema-only output), so the schema
# name can be read and edited. psql runs without ON_ERROR_STOP: on a re-run every
# CREATE fails with "already exists" and is skipped, as pg_restore used to.
log "Copying DDL to pod..."
$KUBECTL cp "$DDL_FILE" "$NAMESPACE/$PG_POD:/tmp/medcea_db_ddl.sql"

log "Applying schema (psql — 'already exists' errors are expected and suppressed)..."
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
    env PGPASSWORD="$PG_PASS" psql -q \
        -U "$PG_USER" -d "$CEA_DB" \
        -f /tmp/medcea_db_ddl.sql 2>&1 \
    | grep "ERROR:" \
    | grep -v "already exists" \
    | grep -v "multiple primary keys" || true

$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- rm /tmp/medcea_db_ddl.sql

# ── 3. Apply post-DDL migrations ─────────────────────────────────────────────
MIGRATIONS_FILE="$SCRIPT_DIR/medcea_db_migrations.sql"
if [[ -f "$MIGRATIONS_FILE" ]]; then
    log "Applying post-DDL migrations..."
    $KUBECTL cp "$MIGRATIONS_FILE" "$NAMESPACE/$PG_POD:/tmp/medcea_db_migrations.sql"
    $KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
        env PGPASSWORD="$PG_PASS" psql -U "$PG_USER" -d "$CEA_DB" \
        -f /tmp/medcea_db_migrations.sql 2>&1 | grep -v "^NOTICE" || true
    $KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- rm /tmp/medcea_db_migrations.sql
    log "Migrations applied."
fi

# ── 4. Roles + post-DDL configuration ────────────────────────────────────────
log "Configuring roles and search_path..."
_ROLES_SQL=$(mktemp /tmp/cea_roles_XXXXXX.sql)
cat > "$_ROLES_SQL" << SQLEOF
-- anon: unauthenticated PostgREST role
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN;
  END IF;
END\$\$;

-- authenticator: PostgREST login role
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticator') THEN
    CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD '$PG_PASS';
  ELSE
    ALTER ROLE authenticator PASSWORD '$PG_PASS';
  END IF;
END\$\$;

-- mqtt_auth: the Mosquitto auth sidecar (k8s/mosquitto/mqtt-auth-sync.py).
-- SELECT on mqtt_credential and device only (grants below); the password is
-- MQTT_AUTH_DB_PASS, generated once by deploy-infra.sh into config.env and
-- handed to the pod through the Secret mosquitto-service-auth.
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mqtt_auth') THEN
    CREATE ROLE mqtt_auth NOINHERIT LOGIN PASSWORD '$MQTT_AUTH_DB_PASS';
  ELSE
    ALTER ROLE mqtt_auth PASSWORD '$MQTT_AUTH_DB_PASS';
  END IF;
END\$\$;
GRANT CONNECT ON DATABASE $CEA_DB TO mqtt_auth;

-- search_path: PostgREST authenticator sees medcea schema tables directly.
-- NOTE: Do NOT set this on postgres — Keycloak uses postgres and has tables
-- in public; putting medcea first causes its schema resolution to break.
ALTER ROLE authenticator SET search_path TO medcea, public;

-- Ensure recipe_id sequence exists (idempotent fix for tables created without one)
DO \$\$
BEGIN
  IF NOT EXISTS (
    SELECT FROM pg_class WHERE relname = 'recipe_recipe_id_seq'
    AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'medcea')
  ) THEN
    CREATE SEQUENCE medcea.recipe_recipe_id_seq;
    ALTER TABLE medcea.recipe ALTER COLUMN recipe_id SET DEFAULT nextval('medcea.recipe_recipe_id_seq');
    PERFORM setval('medcea.recipe_recipe_id_seq', COALESCE((SELECT MAX(recipe_id) FROM medcea.recipe), 0) + 1, false);
  END IF;
END\$\$;
SQLEOF
$KUBECTL cp "$_ROLES_SQL" "$NAMESPACE/$PG_POD:/tmp/cea_roles.sql"
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
    env PGPASSWORD="$PG_PASS" psql -U "$PG_USER" -d "$CEA_DB" -f /tmp/cea_roles.sql
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- rm /tmp/cea_roles.sql
rm -f "$_ROLES_SQL"

# ── 5. Grant anon + authenticator access (PostgREST) ─────────────────────────
log "Granting PostgREST role access to medcea schema..."
_GRANTS_SQL=$(mktemp /tmp/cea_grants_XXXXXX.sql)
cat > "$_GRANTS_SQL" << 'SQLEOF'
GRANT USAGE ON SCHEMA medcea TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA medcea TO anon;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA medcea TO anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA medcea
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA medcea
  GRANT USAGE, SELECT                  ON SEQUENCES TO anon;
GRANT anon TO authenticator;
-- Append-only history (migration 006): the blanket grant above includes it, so
-- take writes back. Its trigger runs SECURITY DEFINER and still appends.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON medcea.device_slot_history FROM anon;
-- MQTT credentials (migration 007): hashes are not for the API role. It may
-- only call register_mqtt_credential (SECURITY DEFINER). The broker sidecar
-- reads them as mqtt_auth.
REVOKE ALL ON medcea.mqtt_credential FROM anon;
GRANT USAGE ON SCHEMA medcea TO mqtt_auth;
GRANT SELECT ON medcea.mqtt_credential, medcea.device TO mqtt_auth;
-- Platform settings (migration 008a) are service_only in the access policy.
REVOKE ALL ON medcea.platform_setting FROM anon;
SQLEOF
$KUBECTL cp "$_GRANTS_SQL" "$NAMESPACE/$PG_POD:/tmp/cea_grants.sql"
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- \
    env PGPASSWORD="$PG_PASS" psql -U "$PG_USER" -d "$CEA_DB" -f /tmp/cea_grants.sql
$KUBECTL exec -n "$NAMESPACE" "$PG_POD" -- rm /tmp/cea_grants.sql
rm -f "$_GRANTS_SQL"

# ── 6. Platform settings ─────────────────────────────────────────────────────
# The MQTT topic root is PROJECT_NAME; the database reads it from here (Phase 2
# register_mqtt_credential) rather than from a literal. Passed as a psql
# variable, so the value is quoted by psql, not by this script.
log "Recording platform settings (mqtt_topic_root=$PROJECT_NAME)..."
$KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- \
    env PGPASSWORD="$PG_PASS" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$CEA_DB" \
        -v root="$PROJECT_NAME" -f - <<'SQLEOF'
INSERT INTO medcea.platform_setting (key, value) VALUES ('mqtt_topic_root', :'root')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
SQLEOF

log "Schema deployed successfully."
echo ""
echo -e "  ${BOLD}Database deployed${NC}"
echo -e "  DB:  ${CEA_DB}  (pod: ${PG_POD})"
echo ""
