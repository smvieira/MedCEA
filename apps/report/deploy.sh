#!/usr/bin/env bash
# apps/report/deploy.sh — Grafana dashboard provisioning
#
# Deploys:
#   - grafana-dashboard-provider  ConfigMap  → /etc/grafana/provisioning/dashboards/
#   - grafana-dashboards          ConfigMap  → /var/lib/grafana/dashboards/
#   - Mounts both into the Grafana deployment (idempotent)
#   - Pushes dashboard JSON via Grafana API for immediate effect
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
# shellcheck source=/dev/null
source "$REPO_ROOT/infra/lib-wait.sh"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
GRAFANA_URL="https://${GRAFANA_DOMAIN:-grafana.$DOMAIN}"
# Grafana is behind TLS from the platform CA now; every curl below must trust it
# or the dashboard push fails on certificate verification rather than on content.
CA_ARGS=(); [[ -f "$REPO_ROOT/.ca/ca.crt" ]] && CA_ARGS=(--cacert "$REPO_ROOT/.ca/ca.crt")
DASHBOARDS_DIR="$SCRIPT_DIR/dashboards"

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[report]${NC} $*"; }

# ── 1. Dashboard provider ConfigMap ──────────────────────────────────────────
log "Creating dashboard provider ConfigMap..."
$KUBECTL create configmap grafana-dashboard-provider \
    -n "$NAMESPACE" \
    --from-file=provider.yaml="$SCRIPT_DIR/k8s/dashboard-provider.yaml" \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# ── 2. Dashboard JSON ConfigMaps (one per .json file in dashboards/) ──────────
log "Creating dashboard JSON ConfigMap..."
$KUBECTL create configmap grafana-dashboards \
    -n "$NAMESPACE" \
    $(for f in "$DASHBOARDS_DIR"/*.json; do echo "--from-file=$(basename "$f")=$f"; done) \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# ── 3. Patch Grafana deployment to mount ConfigMaps (skip if already mounted) ─
if ! $KUBECTL get deployment grafana -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.volumes[*].name}' 2>/dev/null \
        | grep -q "dashboard-provider"; then
    log "Patching Grafana deployment to mount dashboards..."
    $KUBECTL patch deployment grafana -n "$NAMESPACE" --type=json -p='[
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"dashboard-provider","configMap":{"name":"grafana-dashboard-provider"}}},
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"dashboards","configMap":{"name":"grafana-dashboards"}}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"dashboard-provider","mountPath":"/etc/grafana/provisioning/dashboards","readOnly":true}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"dashboards","mountPath":"/var/lib/grafana/dashboards","readOnly":true}}
    ]'
    log "Waiting for Grafana rollout..."
    $KUBECTL rollout status deployment/grafana -n "$NAMESPACE" --timeout=90s
else
    log "Grafana deployment already has dashboard mounts — updating ConfigMap only."
    # Trigger a rolling restart so Grafana re-reads the updated ConfigMap
    $KUBECTL rollout restart deployment/grafana -n "$NAMESPACE"
    $KUBECTL rollout status deployment/grafana -n "$NAMESPACE" --timeout=90s
fi

# ── 4. Push each dashboard via Grafana API (immediate effect) ─────────────────
# `rollout status` returns when the Deployment reports available, which is not the
# same as Grafana serving HTTP through the ingress — the endpoint needs to pick up
# the new pod, and Grafana still has to finish starting. Pushing immediately after
# the rollout raced that and got a 502 from nginx, failing a deploy whose work had
# actually succeeded. Wait for Grafana to answer before pushing anything.
log "Waiting for Grafana to answer..."
wait_for_http "${GRAFANA_URL}/api/health" 120 "Grafana" || exit 1

log "Pushing dashboards to Grafana API..."
for DASHBOARD_FILE in "$DASHBOARDS_DIR"/*.json; do
    DASHBOARD_NAME="$(basename "$DASHBOARD_FILE" .json)"
    DASHBOARD_JSON="$(cat "$DASHBOARD_FILE")"

    # Retry on 5xx: a healthy Grafana can still briefly 502 through the ingress
    # while endpoints settle. 4xx is a real rejection and is not retried.
    for _try in 1 2 3 4 5; do
        HTTP_CODE=$(curl -s -o /tmp/grafana_push_response.json -w "%{http_code}" "${CA_ARGS[@]}" \
            -u "admin:${ADMIN_PASS}" \
            -H "Content-Type: application/json" \
            -X POST "${GRAFANA_URL}/api/dashboards/db" \
            -d "{\"dashboard\": ${DASHBOARD_JSON}, \"overwrite\": true, \"message\": \"Deployed via deploy-apps.sh\"}")
        [[ "$HTTP_CODE" =~ ^5 ]] || break
        sleep $(( _try * 2 ))
    done

    if [[ "$HTTP_CODE" =~ ^2 ]]; then
        URL=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('url',''))" < /tmp/grafana_push_response.json 2>/dev/null || true)
        log "  ✓ ${DASHBOARD_NAME} → ${GRAFANA_URL}${URL}"
    else
        echo "  ✗ Failed to push ${DASHBOARD_NAME} (HTTP ${HTTP_CODE})" >&2
        cat /tmp/grafana_push_response.json >&2
        exit 1
    fi
done

echo ""
echo -e "  ${BOLD}Reports deployed${NC}"
echo -e "  Grafana:  ${GRAFANA_URL}"
echo ""
