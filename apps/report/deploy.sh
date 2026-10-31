#!/usr/bin/env bash
# apps/report/deploy.sh — Grafana dashboard provisioning
#
# Deploys:
#   - grafana-dashboard-provider  ConfigMap  → /etc/grafana/provisioning/dashboards/
#   - grafana-dashboards          ConfigMap  → /var/lib/grafana/dashboards/
#   - Mounts both into the Grafana deployment (idempotent)
#   - Checks, as Grafana's break-glass admin, that each dashboard is provisioned
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
source "$SCRIPT_DIR/lib-grafana-admin.sh"   # grafana_admin_cfg: the break-glass login, off argv
if [[ -z "${GRAFANA_BREAKGLASS_PASS:-}" ]]; then
    echo "ERROR: GRAFANA_BREAKGLASS_PASS is empty in config.env — run ./deploy-infra.sh first (IAM 3.1)." >&2
    exit 1
fi

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

# ── 4. Check each dashboard is provisioned (as the break-glass admin) ─────────
# The provider has allowUiUpdates: false (IAM 3.1: dashboards change only through
# git and this deploy), and Grafana then refuses an API save of a provisioned
# dashboard too, so nothing is pushed: the restarted pod loads the files at start.
# `rollout status` returns when the Deployment reports available, which is not the
# same as Grafana serving HTTP through the ingress, so wait for it to answer first.
log "Waiting for Grafana to answer..."
wait_for_http "${GRAFANA_URL}/api/health" 120 "Grafana" || exit 1

log "Checking the provisioned dashboards..."
for DASHBOARD_FILE in "$DASHBOARDS_DIR"/*.json; do
    DASHBOARD_NAME="$(basename "$DASHBOARD_FILE" .json)"
    UID_="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("uid",""))' "$DASHBOARD_FILE")"
    if [[ -z "$UID_" ]]; then
        echo "  ✗ ${DASHBOARD_NAME} has no uid; a provisioned dashboard needs one" >&2
        exit 1
    fi
    # Retry: provisioning runs shortly after start, and the ingress may still 502.
    for _try in 1 2 3 4 5 6; do
        HTTP_CODE=$(curl -s -o /tmp/grafana_dashboard_check.json -w "%{http_code}" "${CA_ARGS[@]}" \
            -K <(grafana_admin_cfg) "${GRAFANA_URL}/api/dashboards/uid/${UID_}")
        [[ "$HTTP_CODE" == 401 || "$HTTP_CODE" =~ ^2 ]] && break
        sleep $(( _try * 2 ))
    done

    if [[ "$HTTP_CODE" =~ ^2 ]] && python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["meta"].get("provisioned") else 1)' \
            < /tmp/grafana_dashboard_check.json 2>/dev/null; then
        URL=$(python3 -c "import json,sys; print(json.load(sys.stdin)['meta'].get('url',''))" < /tmp/grafana_dashboard_check.json 2>/dev/null || true)
        log "  ✓ ${DASHBOARD_NAME} → ${GRAFANA_URL}${URL}"
    elif [[ "$HTTP_CODE" == 401 ]]; then
        echo "  ✗ Grafana refused the break-glass login (HTTP 401): run ./deploy-infra.sh, which sets GRAFANA_BREAKGLASS_PASS on Grafana" >&2
        exit 1
    else
        echo "  ✗ ${DASHBOARD_NAME} is not provisioned (HTTP ${HTTP_CODE})" >&2
        cat /tmp/grafana_dashboard_check.json >&2
        exit 1
    fi
done
rm -f /tmp/grafana_dashboard_check.json

echo ""
echo -e "  ${BOLD}Reports deployed${NC}"
echo -e "  Grafana:  ${GRAFANA_URL}"
echo ""
