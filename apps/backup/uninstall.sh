#!/usr/bin/env bash
# apps/backup/uninstall.sh — remove what apps/backup/deploy.sh installed: CronJob
# medcea-backup, its Jobs and pods, ConfigMap medcea-backup-script.
#
# BACKUP_DIR and every backup in it stay on the host, on purpose: they are the
# copy that survives an uninstall. Delete them by hand when they are no longer
# wanted (they hold secrets: Keycloak's database, people's homes).
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-backup-uninstall   # logs/app-backup-uninstall-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$SCRIPT_DIR/lib-backup.sh"
NAMESPACE="${NAMESPACE:-medcea}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[backup]${NC} $*"; }

log "Removing CronJob medcea-backup, its Jobs and ConfigMap medcea-backup-script..."
$KUBECTL delete cronjob medcea-backup -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete job -n "$NAMESPACE" -l app=medcea-backup --ignore-not-found
$KUBECTL delete configmap medcea-backup-script -n "$NAMESPACE" --ignore-not-found

log "Backups removed. The backups themselves are kept in $(backup_dir) (delete them by hand when no longer wanted)."
