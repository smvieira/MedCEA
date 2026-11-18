#!/usr/bin/env bash
# apps/research-export/uninstall.sh — remove what apps/research-export/deploy.sh installed:
# CronJob research-export, its Jobs and pods (label app=research-export), ConfigMap
# research-export-script.
#
# The research database and every snapshot in it stay (./apps/research/uninstall.sh
# --purge-data drops them); so do the Secrets db-svc-research-export (the database
# deploy's) and research-export-writer (./apps/research/deploy.sh's).
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
case "$*" in
    "") ;;
    --help|-h) echo "usage: ./apps/research-export/uninstall.sh (removes CronJob research-export; the snapshots stay)"; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-export/uninstall.sh)" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-export-uninstall   # logs/app-research-export-uninstall-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[research-export]${NC} $*"; }

log "Removing CronJob research-export, its Jobs and ConfigMap research-export-script..."
$KUBECTL delete cronjob research-export -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete job -n "$NAMESPACE" -l app=research-export --ignore-not-found
$KUBECTL delete configmap research-export-script -n "$NAMESPACE" --ignore-not-found

log "Research export removed. The research database keeps every snapshot."
