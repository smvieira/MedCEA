#!/usr/bin/env bash
# apps/frontend/deploy.sh — Frontend deployments
#
# Deploys:
#   1. System Configuration UI (PostgREST + nginx SPA — Devices/Units/Recipes/Permissions)
#   2. Database Management portal (nginx SPA + Python export API)
#
# Idempotent: safe to re-run.


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"
# shellcheck source=/dev/null
source "$REPO_ROOT/infra/lib-wait.sh"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"  # deploy_oauth2_proxy — one SSO gate per host
APP_DIR="$SCRIPT_DIR"   # the app directory, as the k8s/ templates call it (hostPath mounts)
NAMESPACE="${NAMESPACE:-medcea}"
CONFIG_DOMAIN="config.$DOMAIN"
DBMGMT_DOMAIN="${DBMGMT_DOMAIN:-dbmgmt.$DOMAIN}"
PGADMIN_URL="https://${PGADMIN_DOMAIN}"
PORTAL_URL="https://${PORTAL_DOMAIN}"

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[frontend]${NC} $*"; }


# =============================================================================
# 1. config-api (PostgREST)
# =============================================================================
log "Deploying config-api (PostgREST)..."

render "$SCRIPT_DIR/k8s/config-api.yaml" NAMESPACE POSTGRES_PASS | $KUBECTL apply -n "$NAMESPACE" -f -

# =============================================================================
# 3. config-ui nginx ConfigMap
# =============================================================================
log "Creating nginx config..."

render "$SCRIPT_DIR/k8s/config-ui-nginx.yaml" NAMESPACE | $KUBECTL apply -n "$NAMESPACE" -f -

# =============================================================================
# 4. config-ui HTML ConfigMap
# =============================================================================
log "Creating config UI HTML..."

# Onboarding runs on the platform host, not in the cluster: it needs the USB
# port. apps/edge-wizard publishes it at https://$ONBOARD_DOMAIN through the
# ingress, so the link is a name on the platform certificate like every other
# service (and HTTPS is what lets the wizard's copy buttons use the clipboard).
_EDGE_WIZARD_URL="https://${ONBOARD_DOMAIN:-onboard-device.$DOMAIN}/"
log "Onboarding wizard link: $_EDGE_WIZARD_URL"

# Full RP-initiated logout: without client_id and post_logout_redirect_uri,
# Keycloak shows a confirmation page and leaves the SSO session alive, so the
# next visit signs straight back in without asking.
_KEYCLOAK_LOGOUT_URL=$(python3 -c "
import urllib.parse, sys
inner = 'https://%s/realms/%s/protocol/openid-connect/logout?client_id=config&post_logout_redirect_uri=%s' % (
    sys.argv[1], sys.argv[2], urllib.parse.quote('https://%s/' % sys.argv[3], safe=''))
print(urllib.parse.quote(inner, safe=''))
" "$KEYCLOAK_DOMAIN" "$KEYCLOAK_REALM" "$CONFIG_DOMAIN")

sed -e "s|\$PORTAL_DOMAIN|$PORTAL_DOMAIN|g" \
    -e "s|\$EDGE_WIZARD_URL|$_EDGE_WIZARD_URL|g" \
    -e "s|\$KEYCLOAK_LOGOUT_URL|$_KEYCLOAK_LOGOUT_URL|g" "$SCRIPT_DIR/html/index.html" \
  | $KUBECTL create configmap config-ui-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml | $KUBECTL apply -f -


# =============================================================================
# 5. Recipe file-server script ConfigMap
# =============================================================================
render "$SCRIPT_DIR/k8s/recipe-fileserver.yaml" NAMESPACE | $KUBECTL apply -n "$NAMESPACE" -f -

# =============================================================================
# 6. config-ui Deployment + Service + Ingress
# =============================================================================
log "Deploying config-ui..."

RECIPES_HOST_PATH="$SCRIPT_DIR/recipes"
mkdir -p "$RECIPES_HOST_PATH"

render "$SCRIPT_DIR/k8s/config-ui.yaml" NAMESPACE RECIPES_HOST_PATH APP_DIR | $KUBECTL apply -n "$NAMESPACE" -f -

# =============================================================================
# 6b. Config UI authentication
# =============================================================================
# $CONFIG_DOMAIN used to be served by a plain Ingress with no authentication at
# all — the whole device inventory, every recipe, and the onboarding entry point
# were readable by anyone who could reach the host. It is now fronted by its own
# oauth2-proxy, the same shape portal already uses, and that proxy owns the
# hostname. Two Ingresses for one host is undefined behaviour in nginx-ingress,
# so the plain config-ui Ingress is deliberately gone rather than left disabled.
if [[ -z "${CONFIG_OAUTH2_PROXY_SECRET:-}" || -z "${CONFIG_COOKIE_SECRET:-}" ]]; then
    log "ERROR: CONFIG_OAUTH2_PROXY_SECRET / CONFIG_COOKIE_SECRET are not set."
    log "       Run ./deploy-infra.sh to create the 'config' Keycloak client first."
    exit 1
fi

# Remove any pre-existing unauthenticated Ingress from an earlier deploy.
$KUBECTL delete ingress config-ui -n "$NAMESPACE" --ignore-not-found

# The shared role-gated values (k8s/oauth2-proxy/values-app.yaml): any of the
# four platform roles, the same rule as the portal. Before, any Keycloak
# account got in, role or not. upstreams live inside configuration.content
# there: the content block overrides the configuration.upstreams helm value.
_CFG_VALUES=$(mktemp /tmp/config-oauth2proxy-values-XXXXXX.yaml)
APP_SERVICE=config-ui render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE > "$_CFG_VALUES"
deploy_oauth2_proxy config-oauth2-proxy config "$CONFIG_OAUTH2_PROXY_SECRET" "$CONFIG_COOKIE_SECRET" "$CONFIG_DOMAIN" "$_CFG_VALUES"
rm -f "$_CFG_VALUES"

# =============================================================================
# 7. Wait for rollouts
# =============================================================================
log "Waiting for config-api rollout..."
$KUBECTL rollout status deployment/config-api -n "$NAMESPACE" --timeout=3m

log "Waiting for config-ui rollout..."
$KUBECTL rollout restart deployment/config-ui -n "$NAMESPACE"
# config-ui restarts alongside its oauth2-proxy, and the old replica can sit in
# Terminating past the 3m default while the proxy settles — which failed the whole
# component for something that completed moments later. Give it longer, and if it
# still has not finished, say what to look at rather than just timing out.
if ! $KUBECTL rollout status deployment/config-ui -n "$NAMESPACE" --timeout=6m; then
    echo "  config-ui did not finish rolling out. Current state:" >&2
    $KUBECTL get pods -l app=config-ui -n "$NAMESPACE" >&2 || true
    exit 1
fi

# (No portal patch here: the System Configuration card is part of the page
# deploy-infra.sh renders; the old "enable a disabled card" patch matched nothing.)

# =============================================================================
# 1. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap dbmgmt-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-file=default.conf="$SCRIPT_DIR/k8s/dbmgmt-nginx.conf" | $KUBECTL apply -f -

# =============================================================================
# 2. HTML SPA ConfigMap
# =============================================================================
log "Creating HTML ConfigMap..."
sed -e "s|\${PORTAL_URL}|$PORTAL_URL|g" -e "s|\${PGADMIN_URL}|$PGADMIN_URL|g" "$SCRIPT_DIR/html/dbmgmt.html" \
  | $KUBECTL create configmap dbmgmt-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 3. Python API ConfigMap
# =============================================================================
log "Creating Python API ConfigMap..."
$KUBECTL create configmap dbmgmt-api -n "$NAMESPACE" \
  --from-file=server.py="$SCRIPT_DIR/html/dbmgmt-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

log "Deploying dbmgmt..."
# The plain Ingress from before the SSO gate: its host now belongs to the proxy.
$KUBECTL delete ingress dbmgmt -n "$NAMESPACE" --ignore-not-found
render "$SCRIPT_DIR/k8s/dbmgmt.yaml" NAMESPACE POSTGRES_PASS APP_DIR REPO_ROOT | $KUBECTL apply -f -

log "Waiting for dbmgmt rollout..."
$KUBECTL rollout restart deployment/dbmgmt -n "$NAMESPACE"
$KUBECTL rollout status deployment/dbmgmt -n "$NAMESPACE" --timeout=120s

log "Deploying dbmgmt-oauth2-proxy (Keycloak SSO)..."
_DB_VALUES=$(mktemp /tmp/dbmgmt-oauth2proxy-values-XXXXXX.yaml)
APP_SERVICE=dbmgmt render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE > "$_DB_VALUES"
deploy_oauth2_proxy dbmgmt-oauth2-proxy dbmgmt "${DBMGMT_CLIENT_SECRET:-}" "${DBMGMT_COOKIE_SECRET:-}" "$DBMGMT_DOMAIN" "$_DB_VALUES"
rm -f "$_DB_VALUES"
$KUBECTL rollout status deployment/dbmgmt-oauth2-proxy -n "$NAMESPACE" --timeout=4m

# =============================================================================
# 5. Portal: nginx config, images mount and background (card is in the infra page)
# =============================================================================
log "Configuring portal nginx (images location)..."
$KUBECTL create configmap portal-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-file=default.conf="$SCRIPT_DIR/k8s/portal-nginx.conf" | $KUBECTL apply -f -

log "Patching portal deployment (images volume)..."
if ! $KUBECTL get deployment portal -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -q "images"; then
    $KUBECTL patch deployment portal -n "$NAMESPACE" --type=json -p='[
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"portal-nginx","configMap":{"name":"portal-nginx"}}},
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"images","hostPath":{"path":"'"$SCRIPT_DIR"'/images","type":"Directory"}}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"portal-nginx","mountPath":"/etc/nginx/conf.d/default.conf","subPath":"default.conf","readOnly":true}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"images","mountPath":"/usr/share/nginx/html/images","readOnly":true}}
    ]'
fi

log "Updating portal background..."
$KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' > /tmp/portal_current.html

python3 - /tmp/portal_current.html /tmp/portal_updated.html << 'PYEOF'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
html = open(src).read()

# Set background image (replace whatever style is on #bg div)
html = re.sub(
    r'<div id="bg"[^>]*>',
    '<div id="bg" style="background-image:url(\'/images/cea-background.png\');">',
    html, count=1
)

open(dst, 'w').write(html)
PYEOF

$KUBECTL create configmap portal-html -n "$NAMESPACE" \
    --from-file=index.html=/tmp/portal_updated.html \
    --dry-run=client -o yaml | $KUBECTL apply -f -

$KUBECTL rollout restart deployment/portal -n "$NAMESPACE"

# Re-enable the card if apps/frontend/uninstall.sh greyed it out (infra/lib-portal.sh).
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$CONFIG_DOMAIN"
portal_card enable "https://$DBMGMT_DOMAIN"

echo ""

echo ""
echo -e "  ${BOLD}Frontend deployed${NC}"
# A finished rollout is not a served page: the ingress still has to pick up the
# new pod. Verify before claiming the component deployed.
wait_for_http "https://$CONFIG_DOMAIN/" 120 "Config UI" || exit 1

# The Devices tab links to the onboarding wizard, which runs on the host rather
# than in the cluster (it needs the USB port). apps/edge-wizard deploys it and
# sorts before this component; a stopped daemon would otherwise show up as
# "refused to connect" only when somebody clicks the button.
if ! curl -s -o /dev/null -m 5 --cacert "$REPO_ROOT/.ca/ca.crt" "$_EDGE_WIZARD_URL" 2>/dev/null; then
    log "WARNING: the onboarding wizard is not answering at $_EDGE_WIZARD_URL"
    log "         The 'Onboard Device' button on the Devices tab will not work."
    log "         Install or restart it with: ./apps/edge-wizard/deploy.sh"
    log "         Status and logs:  systemctl --user status cea-edge-wizard"
fi
wait_for_http "https://$DBMGMT_DOMAIN/" 120 "DB Mgmt"   || exit 1

echo -e "  Config UI:  https://$CONFIG_DOMAIN"
echo -e "  DB Mgmt:    https://${DBMGMT_DOMAIN}"
echo ""
