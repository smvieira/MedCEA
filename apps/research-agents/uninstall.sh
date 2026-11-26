#!/usr/bin/env bash
# apps/research-agents/uninstall.sh — the inverse of apps/research-agents/deploy.sh (research Phase 4a,
# 6b1): removes the orchestrator, mcp-sim, mcp-lake and every agent/simulation Job from
# $RESEARCH_AGENTS_NAMESPACE, research-session and its two Secrets from $RESEARCH_GW_NAMESPACE, the
# copies of medcea-iam-lib, medcea-jwks and research-code, and the wheel PersistentVolumes and claims.
# Kept: the namespaces and their NetworkPolicies, the host wheel folders, the claim research-runs (the
# campaigns' outputs; --purge-data deletes it) and everything in the research database (agent_trace is
# append-only and never touched here). ./apps/research/uninstall.sh runs this before lake-api's, so the
# sessions stop before the database goes. Idempotent.
#
#   ./apps/research-agents/uninstall.sh [--purge-data]

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
PURGE=0
case "$*" in
    "") ;;
    --purge-data) PURGE=1 ;;
    --help|-h) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-agents/uninstall.sh [--purge-data])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-agents-uninstall
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
GW_NS="${RESEARCH_GW_NAMESPACE:-${RESEARCH_NAMESPACE}-gw}"
AG_NS="${RESEARCH_AGENTS_NAMESPACE:-${RESEARCH_NAMESPACE}-agents}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[research-agents]${NC} $*"; }

if $KUBECTL get namespace "$AG_NS" >/dev/null 2>&1; then
    log "Removing the orchestrator, mcp-sim, mcp-lake and the Jobs from $AG_NS..."
    $KUBECTL delete jobs --all -n "$AG_NS" --ignore-not-found --wait=false
    $KUBECTL delete deployment,service -n "$AG_NS" -l app.kubernetes.io/part-of=medcea-research --ignore-not-found
    $KUBECTL delete rolebinding,role,serviceaccount research-orchestrator -n "$AG_NS" --ignore-not-found
    $KUBECTL delete configmap research-code medcea-iam-lib medcea-jwks -n "$AG_NS" --ignore-not-found
    $KUBECTL delete pvc research-wheels -n "$AG_NS" --ignore-not-found
    if [[ "$PURGE" == 1 ]]; then
        log "--purge-data: deleting the claim research-runs (the campaigns' outputs)..."
        $KUBECTL delete pvc research-runs -n "$AG_NS" --ignore-not-found
    else
        log "The claim research-runs is kept (--purge-data deletes it)."
    fi
else
    log "Namespace $AG_NS does not exist: nothing to remove there."
fi
if $KUBECTL get namespace "$GW_NS" >/dev/null 2>&1; then
    log "Removing research-session and its Secrets from $GW_NS..."
    $KUBECTL delete deployment,service -n "$GW_NS" -l app.kubernetes.io/part-of=medcea-research --ignore-not-found
    $KUBECTL delete secret research-session-key research-session-db -n "$GW_NS" --ignore-not-found
    $KUBECTL delete configmap research-code medcea-iam-lib medcea-jwks -n "$GW_NS" --ignore-not-found
    $KUBECTL delete pvc research-wheels -n "$GW_NS" --ignore-not-found
else
    log "Namespace $GW_NS does not exist: nothing to remove there."
fi
$KUBECTL delete pv "${GW_NS}-research-wheels" "${AG_NS}-research-wheels" --ignore-not-found
log "Removed. The wheel folders on the host, the namespaces and the research database (agent_trace included) are untouched."
