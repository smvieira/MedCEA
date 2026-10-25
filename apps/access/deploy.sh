#!/usr/bin/env bash
# apps/access/deploy.sh — self-service access requests and the User Manager
#
# Deploys:
#   1. Schema iam + role access_svc in medcea_db (access_db.sql)
#   2. Secret access-secrets (DB password, Keycloak client secret)
#   3. ConfigMaps: the service, its two pages, the e-mail templates
#   4. Deployment access + Services access-public / access-admin + public Ingress
#   5. access-oauth2-proxy (Keycloak client 'access', realm role admin only)
#   6. Portal card (User Manager)
#
# Keycloak's side — realm roles, the 'access' client with its service account,
# the groups mapper and ACCESS_DOMAIN in the certificate — is deploy-infra.sh's.
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
NAMESPACE="${NAMESPACE:-medcea}"
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"   # older config.env files lack it
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[access]${NC} $*"; }

if [[ -z "${ACCESS_CLIENT_SECRET:-}" || -z "${ACCESS_COOKIE_SECRET:-}" ]]; then
    log "ERROR: ACCESS_CLIENT_SECRET / ACCESS_COOKIE_SECRET are not set."
    log "       Run ./deploy-infra.sh to create the 'access' Keycloak client first."
    exit 1
fi

# =============================================================================
# 1. Database: schema iam and role access_svc
# =============================================================================
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' || true)
[[ -n "$PG_POD" ]] || { echo "ERROR: No PostgreSQL pod found in namespace $NAMESPACE" >&2; exit 1; }

# The access_svc password is generated once and kept in the Secret, like the
# cookie secrets in deploy-infra.sh: a new one each run would only churn.
_DB_PW="$($KUBECTL get secret access-secrets -n "$NAMESPACE" -o jsonpath='{.data.PG_PASSWORD}' 2>/dev/null | base64 -d || true)"
[[ -n "$_DB_PW" ]] || _DB_PW="$(openssl rand -hex 20)"

log "Applying schema iam (access requests, append-only history)..."
# The password goes in on stdin as a psql variable, not on the command line,
# so it is not visible in the pod's process list.
if ! _OUT=$({ printf '\\set access_pw %s\n' "$_DB_PW"; cat "$SCRIPT_DIR/access_db.sql"; } \
        | $KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- \
            env PGPASSWORD="$POSTGRES_PASS" psql -q -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB" -f - 2>&1); then
    echo "$_OUT" >&2
    echo "ERROR: applying access_db.sql failed" >&2
    exit 1
fi
grep -v 'NOTICE' <<<"$_OUT" || true

# One-time carry-over: installs from before the User Manager owned e-mail had
# SMTP_USER / SMTP_PASS in config.env. Copy them in while the UI settings are
# still empty; from then on the UI is the only place they are changed.
if [[ -n "${SMTP_USER:-}" && -n "${SMTP_PASS:-}" ]]; then
    { printf '\\set u %s\n\\set p %s\n' "$SMTP_USER" "${SMTP_PASS// /}"
      echo "UPDATE iam.mail_settings SET smtp_user = :'u', smtp_pass = :'p', updated_by = 'config.env (one-time import)', updated_at = now()"
      echo " WHERE id = 1 AND smtp_user = '' AND smtp_pass = '';"; } \
      | $KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- \
          env PGPASSWORD="$POSTGRES_PASS" psql -q -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB" -f - >/dev/null \
      && log "E-mail settings: SMTP_USER/SMTP_PASS from config.env imported if the User Manager had none (manage them there now)."
fi

# =============================================================================
# 2. Secret
# =============================================================================
log "Writing Secret access-secrets..."
$KUBECTL create secret generic access-secrets -n "$NAMESPACE" \
  --from-literal=PG_PASSWORD="$_DB_PW" \
  --from-literal=KC_CLIENT_SECRET="$ACCESS_CLIENT_SECRET" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null

# =============================================================================
# 3. ConfigMaps
# =============================================================================
log "Creating ConfigMaps (service, pages, e-mail templates)..."
$KUBECTL create configmap access-api -n "$NAMESPACE" \
  --from-file=access-api.py="$SCRIPT_DIR/access-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -
_HTML_DIR="$(mktemp -d)"
for _p in register.html admin.html; do
    render "$SCRIPT_DIR/html/$_p" PORTAL_DOMAIN > "$_HTML_DIR/$_p"
done
cp "$SCRIPT_DIR/html/profile.html" "$SCRIPT_DIR/html/user-menu.js" "$_HTML_DIR/"
$KUBECTL create configmap access-html -n "$NAMESPACE" --from-file="$_HTML_DIR" \
  --dry-run=client -o yaml | $KUBECTL apply -f -
rm -rf "$_HTML_DIR"
$KUBECTL create configmap access-templates -n "$NAMESPACE" --from-file="$SCRIPT_DIR/templates" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 4. Deployment, Services, public Ingress
# =============================================================================
log "Deploying access service..."
# Signed-in hosts and their Keycloak clients: the user menu's sign-out and
# change-password links need the client each host logs in with.
HOST_CLIENTS="${PORTAL_DOMAIN}=portal,${CONFIG_DOMAIN:-config.$DOMAIN}=config,${ACCESS_DOMAIN}=access"
render "$SCRIPT_DIR/k8s/access.yaml" NAMESPACE POSTGRES_DB KEYCLOAK_REALM KEYCLOAK_DOMAIN ACCESS_DOMAIN PORTAL_DOMAIN HOST_CLIENTS \
  | $KUBECTL apply -f -
$KUBECTL rollout restart deployment/access -n "$NAMESPACE"

# =============================================================================
# 5. oauth2-proxy for the User Manager (admins only)
# =============================================================================
log "Deploying access-oauth2-proxy (realm role admin only)..."
_AOP_VALUES=$(mktemp /tmp/access-oauth2proxy-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/oauth2-proxy-values.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE > "$_AOP_VALUES"
$MK8S helm3 upgrade --install access-oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$REPO_ROOT/k8s/oauth2-proxy/values-common.yaml" \
  --values "$_AOP_VALUES" \
  --set configuration.clientID="access" \
  --set configuration.clientSecret="$ACCESS_CLIENT_SECRET" \
  --set configuration.cookieSecret="$ACCESS_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.hostname="$ACCESS_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$ACCESS_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  --timeout 5m
rm -f "$_AOP_VALUES"
$KUBECTL rollout restart deployment/access-oauth2-proxy -n "$NAMESPACE"

log "Waiting for rollouts..."
$KUBECTL rollout status deployment/access -n "$NAMESPACE" --timeout=4m
$KUBECTL rollout status deployment/access-oauth2-proxy -n "$NAMESPACE" --timeout=4m

# =============================================================================
# 6. Portal card
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$ACCESS_DOMAIN"

log ""
log "Access requests deployed!"
log "  Register:     the Request access tab of the platform login page (https://$PORTAL_DOMAIN/#register)"
log "  User Manager: https://$ACCESS_DOMAIN/            (realm role admin)"
log "  E-mail:       User Manager → E-mail settings (Gmail app password, templates)"
