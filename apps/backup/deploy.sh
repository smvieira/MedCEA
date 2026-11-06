#!/usr/bin/env bash
# apps/backup/deploy.sh — nightly backups of the platform's data (decision of
# 1 November 2026).
#
# Deploys:
#   1. BACKUP_DIR on the host (config.env; default /var/backups/$PROJECT_NAME),
#      created mode 700 for the account that runs this deploy (sudo when its parent
#      is not writable). The backups hold secrets: Keycloak's database with its
#      credential hashes and client secrets, pgAdmin's storage inside the platform
#      database's dumps, people's homes with their git tokens.
#   2. ConfigMap medcea-backup-script (apps/backup/backup-job.sh)
#   3. CronJob medcea-backup (apps/backup/k8s/backup-cronjob.yaml), daily at 02:30 UTC:
#      pg_dump (custom format) of $POSTGRES_DB and keycloak (and superset when it exists), the roles without their
#      passwords, and a tar of every AI workbench home (claim-*), Node-RED's /data
#      and Grafana's volume; one dated folder per run with MANIFEST, SHA256SUMS and a
#      final OK; folders older than BACKUP_KEEP_DAYS (default 14) are deleted.
#
# It needs the infrastructure first: the image and Secret of rdbms-postgresql (the
# job runs pg_dump from the server's own image, already on the node). No portal
# card: the host command is ./apps/backup/backups.sh (now, list, verify,
# restore-help), and ./guide.sh → Backups asks for it. health-check.sh "Backups"
# (backupage) reads the newest OK marker. ./apps/backup/uninstall.sh leaves
# BACKUP_DIR and every backup in it.
#
# Idempotent: safe to re-run (a changed BACKUP_DIR or BACKUP_KEEP_DAYS takes effect
# at the next run; the old folder is left where it is).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-backup-deploy   # logs/app-backup-deploy-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$SCRIPT_DIR/lib-backup.sh"
NAMESPACE="${NAMESPACE:-medcea}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[backup]${NC} $*"; }
warn() { echo -e "${YELLOW}[backup] WARNING:${NC} $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

BACKUP_DIR="$(backup_dir)"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
[[ "$BACKUP_DIR" =~ ^/[A-Za-z0-9._/-]+$ && "$BACKUP_DIR" != */../* && "$BACKUP_DIR" != */.. && "$BACKUP_DIR" != */./* ]] \
    || die "BACKUP_DIR='$BACKUP_DIR' must be an absolute path of letters, digits and . _ - / (config.env)."
BACKUP_DIR="${BACKUP_DIR%/}"
[[ -n "$BACKUP_DIR" ]] || die "BACKUP_DIR must not be /."
[[ "$BACKUP_KEEP_DAYS" =~ ^[1-9][0-9]{0,3}$ ]] \
    || die "BACKUP_KEEP_DAYS='$BACKUP_KEEP_DAYS' must be a whole number of days, 1 or more (config.env)."

# Where microk8s-hostpath keeps the volumes: its storage class's pvDir, else the default.
STORAGE_DIR="$($KUBECTL get storageclass microk8s-hostpath -o jsonpath='{.parameters.pvDir}' 2>/dev/null || true)"
STORAGE_DIR="${STORAGE_DIR:-/var/snap/microk8s/common/default-storage}"
case "$BACKUP_DIR/" in
    "$STORAGE_DIR"/*) die "BACKUP_DIR=$BACKUP_DIR is inside the volumes' directory $STORAGE_DIR: the job would copy its own backups." ;;
esac
case "$STORAGE_DIR/" in
    "$BACKUP_DIR"/*) die "BACKUP_DIR=$BACKUP_DIR contains the volumes' directory $STORAGE_DIR." ;;
esac

# =============================================================================
# 1. The host folder
# =============================================================================
BACKUP_UID="$(id -u)"; BACKUP_GID="$(id -g)"
if [[ ! -d "$BACKUP_DIR" ]]; then
    log "Creating $BACKUP_DIR (mode 700, owner $(id -un))..."
    if ! install -d -m 700 "$BACKUP_DIR" 2>/dev/null; then
        sudo -p "[sudo] password for %u (to create $BACKUP_DIR for the backups): " \
            install -d -m 700 -o "$BACKUP_UID" -g "$BACKUP_GID" "$BACKUP_DIR"
    fi
fi
[[ "$(stat -L -c %u "$BACKUP_DIR")" == "$BACKUP_UID" ]] \
    || die "$BACKUP_DIR belongs to uid $(stat -L -c %u "$BACKUP_DIR"), not to $(id -un). Make it yours (sudo chown $(id -un): $BACKUP_DIR) or choose another BACKUP_DIR, then re-run."
chmod 700 "$BACKUP_DIR"
if [[ -d "$STORAGE_DIR" ]]; then
    if [[ "$(df -P "$BACKUP_DIR" | awk 'NR==2 {print $1}')" == "$(df -P "$STORAGE_DIR" | awk 'NR==2 {print $1}')" ]]; then
        warn "$BACKUP_DIR is on the same disk as the data ($STORAGE_DIR): a disk failure takes both. Point BACKUP_DIR at another disk, or copy the folders off this host (manual: Backup and restore)."
    fi
else
    warn "$STORAGE_DIR does not exist on this host: the job will find no volumes to copy (is hostpath-storage enabled?)."
fi

# =============================================================================
# 2. What the job runs, and with which image
# =============================================================================
BACKUP_IMAGE="$($KUBECTL get statefulset rdbms-postgresql -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="postgresql")].image}' 2>/dev/null || true)"
[[ -n "$BACKUP_IMAGE" ]] || die "no StatefulSet rdbms-postgresql in $NAMESPACE: run ./deploy-infra.sh first."
# The name only: the Secret's data is never read here.
$KUBECTL get secret rdbms-postgresql -n "$NAMESPACE" -o name >/dev/null 2>&1 \
    || die "no Secret rdbms-postgresql in $NAMESPACE: run ./deploy-infra.sh first."

log "Creating ConfigMap medcea-backup-script..."
$KUBECTL create configmap medcea-backup-script -n "$NAMESPACE" \
    --from-file=backup-job.sh="$SCRIPT_DIR/backup-job.sh" --dry-run=client -o yaml \
  | $KUBECTL apply -f -

# =============================================================================
# 3. The CronJob
# =============================================================================
log "Deploying CronJob medcea-backup (daily 02:30 UTC, image $BACKUP_IMAGE)..."
render "$SCRIPT_DIR/k8s/backup-cronjob.yaml" NAMESPACE BACKUP_DIR BACKUP_KEEP_DAYS BACKUP_IMAGE \
    BACKUP_UID BACKUP_GID STORAGE_DIR POSTGRES_DB \
  | $KUBECTL apply -f -

log ""
log "Backups deployed."
log "  Folder:   $BACKUP_DIR (mode 700, $(id -un)); $(df -hP "$BACKUP_DIR" | awk 'NR==2 {print $4}') free"
log "  Schedule: daily 02:30 UTC; folders older than $BACKUP_KEEP_DAYS days are deleted after a good run"
log "  Run one now: ./apps/backup/backups.sh now    List: ./apps/backup/backups.sh list"
