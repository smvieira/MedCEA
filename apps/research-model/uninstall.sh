#!/usr/bin/env bash
# apps/research-model/uninstall.sh — the inverse of apps/research-model/deploy.sh (research Phase 4b, stage 1):
# removes Deployments and Services model-gateway and research-llm, ConfigMap model-gateway-code, Secret model-gateway-keys, its script ConfigMap, the claim and the static volume from
# $RESEARCH_GW_NAMESPACE. Kept: the model file in RESEARCH_MODEL_DIR (about 2.5 GB; remove it by hand, or
# ./install.sh --uninstall-all), the namespace and its NetworkPolicies. Idempotent.
#
#   ./apps/research-model/uninstall.sh

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
case "$*" in
    "") ;;
    --help|-h) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-model/uninstall.sh)" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-model-uninstall
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
GW_NS="${RESEARCH_GW_NAMESPACE:-${RESEARCH_NAMESPACE}-gw}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[research-model]${NC} $*"; }

if $KUBECTL get namespace "$GW_NS" >/dev/null 2>&1; then
    log "Removing model-gateway and research-llm from $GW_NS..."
    $KUBECTL delete deployment,service model-gateway -n "$GW_NS" --ignore-not-found
    $KUBECTL delete configmap model-gateway-code -n "$GW_NS" --ignore-not-found
    $KUBECTL delete secret model-gateway-keys -n "$GW_NS" --ignore-not-found
    $KUBECTL delete deployment,service research-llm -n "$GW_NS" --ignore-not-found
    $KUBECTL delete configmap research-llm-script -n "$GW_NS" --ignore-not-found
    $KUBECTL delete pvc research-models -n "$GW_NS" --ignore-not-found
else
    log "Namespace $GW_NS does not exist: nothing to remove there."
fi
$KUBECTL delete pv "${GW_NS}-research-models" --ignore-not-found
log "Removed. The model file in RESEARCH_MODEL_DIR is untouched."
