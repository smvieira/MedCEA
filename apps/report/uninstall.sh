#!/usr/bin/env bash
# apps/report/uninstall.sh — remove what apps/report/deploy.sh installed: the
# Grafana dashboard provider + dashboards ConfigMaps, the mounts it patched into
# the Grafana Deployment, and the dashboards themselves.
#
# Order matters: the mounts come out of the Grafana Deployment BEFORE the
# ConfigMaps are deleted. A pod that mounts a missing ConfigMap never starts, so
# the reverse order would leave Grafana down at its next restart.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
GRAFANA_URL="https://${GRAFANA_DOMAIN:-grafana.$DOMAIN}"
CA_ARGS=(); [[ -f "$REPO_ROOT/.ca/ca.crt" ]] && CA_ARGS=(--cacert "$REPO_ROOT/.ca/ca.crt")
DASHBOARDS_DIR="$SCRIPT_DIR/dashboards"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[report]${NC} $*"; }

# JSON-patch "remove" ops for the volumes and mounts deploy.sh added, highest
# index first so earlier removals do not shift the later ones.
_PATCH="$($KUBECTL get deployment grafana -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    spec = json.load(sys.stdin)["spec"]["template"]["spec"]
except Exception:
    print("[]"); sys.exit()
names = {"dashboard-provider", "dashboards"}
ops = []
for i, m in reversed(list(enumerate(spec["containers"][0].get("volumeMounts", [])))):
    if m["name"] in names: ops.append({"op": "remove", "path": "/spec/template/spec/containers/0/volumeMounts/%d" % i})
for i, v in reversed(list(enumerate(spec.get("volumes", [])))):
    if v["name"] in names: ops.append({"op": "remove", "path": "/spec/template/spec/volumes/%d" % i})
print(json.dumps(ops))
' 2>/dev/null || echo "[]")"

if [[ "$_PATCH" != "[]" ]]; then
    log "Removing dashboard mounts from the Grafana Deployment..."
    $KUBECTL patch deployment grafana -n "$NAMESPACE" --type=json -p="$_PATCH"
    $KUBECTL rollout status deployment/grafana -n "$NAMESPACE" --timeout=3m
fi

# Grafana runs without persistence, so the new pod already starts without these
# dashboards. Delete them by uid as well, for when persistence is enabled.
for f in "$DASHBOARDS_DIR"/*.json; do
    uid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("uid",""))' "$f" 2>/dev/null || true)"
    [[ -n "$uid" ]] || continue
    curl -s -o /dev/null "${CA_ARGS[@]}" -u "admin:${ADMIN_PASS}" \
        -X DELETE "${GRAFANA_URL}/api/dashboards/uid/${uid}" || true
done

log "Removing dashboard ConfigMaps..."
$KUBECTL delete configmap grafana-dashboard-provider grafana-dashboards -n "$NAMESPACE" --ignore-not-found

log "Reports removed."
