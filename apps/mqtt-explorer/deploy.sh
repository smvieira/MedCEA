#!/usr/bin/env bash
# apps/mqtt-explorer/deploy.sh — MQTT Explorer (browser MQTT tool)
#
# Deploys:
#   1. HTML ConfigMap (index.html, with the topic root and the mode: under
#      IAM_MQTT_PERSON=true the page asks iam-api for a personal credential;
#      under false the broker's shared "mqtt-explorer" account is filled in)
#   2. Deployment + Service (nginx serving the page)
#   3. mqttx-oauth2-proxy on $MQTTX_DOMAIN (Keycloak SSO, the roles the policy
#      compiles: engineer), which also routes /mqtt to the broker's WebSocket
#      listener and /_mqtt-credential to iam-api (Service iam-mqttx)
#   4. Portal card
#
# The page connects to wss://$MQTTX_DOMAIN/mqtt — through its own sign-in — and
# the broker checks a credential on top: the person's own, short-lived one
# (IAM_MQTT_PERSON=true; this deploy refuses until iam-mqttx answers in person mode
# and the broker runs it), or the shared account, whose password is then in the
# page, which is why the page is only served after sign-in.
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

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"
source "$REPO_ROOT/infra/lib-wait.sh"
NAMESPACE="${NAMESPACE:-medcea}"
MQTTX_DOMAIN="${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[mqtt-explorer]${NC} $*"; }

case "${IAM_MQTT_PERSON:-false}" in
    true)
        _MODE=person
        # The page would get no credential: iam-api must answer in person mode, and the
        # broker must have been restarted with per-listener auth (./deploy-infra.sh).
        # iam-api reads the switch from its /iam mount, which the kubelet refreshes about
        # a minute after deploy-infra: wait up to 150 s.
        _OK=false
        for _ in $(seq 1 30); do
            _H="$($KUBECTL exec -n "$NAMESPACE" deployment/iam-api -- python3 -c \
                'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8085/healthz", timeout=5).read().decode())' 2>/dev/null)" || _H=""
            if python3 -c 'import json, sys; d = json.loads(sys.argv[1]); sys.exit(0 if d.get("mode") is True and d.get("mqtt_digest") else 1)' "$_H" 2>/dev/null; then
                _OK=true; break
            fi
            [[ -n "$_H" ]] || break          # no iam-api at all: no point waiting
            sleep 5
        done
        if [[ "$_OK" != true ]]; then
            echo "ERROR: IAM_MQTT_PERSON=true, but iam-api (Service iam-mqttx) does not answer in person mode — run ./apps/iam/deploy.sh and ./deploy-infra.sh first." >&2
            exit 1
        fi
        if [[ "$($KUBECTL get deployment mosquitto -n "$NAMESPACE" -o jsonpath='{.spec.template.metadata.annotations.medcea/mqtt-mode}' 2>/dev/null)" != "true" ]]; then
            echo "ERROR: IAM_MQTT_PERSON=true, but the broker still runs the shared account — run ./deploy-infra.sh first." >&2
            exit 1
        fi ;;
    false)
        _MODE=legacy
        if [[ -z "${MQTT_EXPLORER_PASS:-}" ]]; then
            echo "ERROR: MQTT_EXPLORER_PASS is not set in config.env — run ./deploy-infra.sh first." >&2
            exit 1
        fi ;;
    *)  echo "ERROR: IAM_MQTT_PERSON='${IAM_MQTT_PERSON}' must be \"true\" or \"false\"." >&2; exit 1 ;;
esac

# =============================================================================
# 1. Page
# =============================================================================
log "Creating HTML ConfigMap (mode: $_MODE)..."
if [[ "$_MODE" == person ]]; then _MQ_USER=""; _MQ_PASS=""; else _MQ_USER=mqtt-explorer; _MQ_PASS="$MQTT_EXPLORER_PASS"; fi
sed -e "s|__TOPIC_ROOT__|${PROJECT_NAME:-medcea}|g" \
    -e "s|__MQTT_MODE__|${_MODE}|g" \
    -e "s|__MQTT_USER__|${_MQ_USER}|g" \
    -e "s|__MQTT_PASS__|${_MQ_PASS}|g" \
    "$SCRIPT_DIR/html/index.html" \
  | $KUBECTL create configmap mqtt-explorer-html -n "$NAMESPACE" \
      --from-file=index.html=/dev/stdin --dry-run=client -o yaml \
  | $KUBECTL apply -f -

# =============================================================================
# 2. Deployment + Service
# =============================================================================
log "Deploying mqtt-explorer..."
# Leftovers: the mqttx-web resources of an older name, and the plain Ingress
# deploy-infra.sh used to create — its host now belongs to the proxy.
$KUBECTL delete deployment/mqttx-web service/mqttx-web ingress/mqttx-web \
  -n "$NAMESPACE" --ignore-not-found >/dev/null
$KUBECTL delete ingress mqtt-explorer -n "$NAMESPACE" --ignore-not-found
render "$SCRIPT_DIR/k8s/mqtt-explorer.yaml" NAMESPACE | $KUBECTL apply -n "$NAMESPACE" -f -
# The page is a subPath mount, which kubelet never refreshes in place.
$KUBECTL rollout restart deployment/mqtt-explorer -n "$NAMESPACE"
$KUBECTL rollout status deployment/mqtt-explorer -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 3. Sign-in (and the broker WebSocket at /mqtt)
# =============================================================================
log "Deploying mqttx-oauth2-proxy (Keycloak SSO)..."
_VALUES=$(mktemp /tmp/mqttx-oauth2proxy-values-XXXXXX.yaml)
ALLOWED_GROUPS="$(policy_groups MQTTX_DOMAIN)"
gate_error_page mqttx-oauth2-proxy MQTTX_DOMAIN "$ALLOWED_GROUPS"
render "$SCRIPT_DIR/k8s/oauth2-proxy-values.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$_VALUES"
deploy_oauth2_proxy mqttx-oauth2-proxy mqtt-explorer "${MQTTX_CLIENT_SECRET:-}" "${MQTTX_COOKIE_SECRET:-}" "$MQTTX_DOMAIN" "$_VALUES"
rm -f "$_VALUES"
$KUBECTL rollout status deployment/mqttx-oauth2-proxy -n "$NAMESPACE" --timeout=4m
wait_for_http "https://$MQTTX_DOMAIN/" 120 "MQTT Explorer" || exit 1

# =============================================================================
# 4. Portal card
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$MQTTX_DOMAIN"

log ""
log "MQTT Explorer deployed!"
if [[ "$_MODE" == person ]]; then
    log "  UI: https://$MQTTX_DOMAIN   (broker: wss://$MQTTX_DOMAIN/mqtt with each person's own credential)"
else
    log "  UI: https://$MQTTX_DOMAIN   (broker: wss://$MQTTX_DOMAIN/mqtt as mqtt-explorer)"
fi
