#!/usr/bin/env bash
# apps/lake-api/uninstall.sh — the inverse of apps/lake-api/deploy.sh: removes the
# Deployment, the Service and Secret lake-api-auth (label app=lake-api) from the research
# namespace. Never the research database, its roles or its snapshots
# (./apps/research/uninstall.sh, which runs this first). Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
case "$*" in
    "") ;;
    --help|-h) echo "usage: ./apps/lake-api/uninstall.sh (removes lake-api; the research database and its snapshots stay)"; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/lake-api/uninstall.sh)" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-lake-api-uninstall   # logs/app-lake-api-uninstall-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[lake-api]${NC} $*"; }

if ! $KUBECTL get namespace "$RESEARCH_NAMESPACE" >/dev/null 2>&1; then
    log "Namespace $RESEARCH_NAMESPACE does not exist: no lake-api to remove."
    exit 0
fi
log "Removing lake-api (Deployment, Service, Secret lake-api-auth) from $RESEARCH_NAMESPACE..."
$KUBECTL delete deployment,service,secret -n "$RESEARCH_NAMESPACE" -l app=lake-api --ignore-not-found
log "lake-api removed. The research database keeps every snapshot."
