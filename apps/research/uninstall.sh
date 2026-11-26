#!/usr/bin/env bash
# apps/research/uninstall.sh — the inverse of apps/research/deploy.sh.
#
#   ./apps/research/uninstall.sh                runs ./apps/lake-api/uninstall.sh first
#                                               (the snapshot reader logs in to this
#                                               database), then removes Secrets research-export-writer and
#                                               research-backup from $NAMESPACE (first, so
#                                               the exporter and the backup stop connecting)
#                                               and the Helm release research-postgresql; its
#                                               volume (the lake, the vault's reservations)
#                                               and Secret research-postgresql-auth are kept,
#                                               so a later deploy finds the same data
#   ./apps/research/uninstall.sh --purge-data   also deletes the volume
#                                               (data-research-postgresql-0) and Secret
#                                               research-postgresql-auth: every snapshot and
#                                               every reservation is gone, and with
#                                               the volume every role of the research
#                                               PostgreSQL (rs_owner, rs_export_writer,
#                                               rs_backup, rs_lake_api, rs_lake_reader)
#
# deploy-apps.sh --uninstall --purge-data passes the flag to the database component only,
# so it never reaches here: purging the research data is this script's own flag. Never
# touches the research namespace itself, its NetworkPolicies, quota or PriorityClass
# (infra/deploy-research-namespace.sh's: ./deploy-infra.sh --reset or --uninstall), nor
# the platform database. Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
_PURGE=false
case "$*" in
    "") ;;
    --purge-data) _PURGE=true ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research/uninstall.sh [--purge-data])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-uninstall   # logs/app-research-uninstall-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
RS_RELEASE=research-postgresql

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[research]${NC} $*"; }

# The agent machinery first (research Phase 4a, R3): its sessions stop before the database goes;
# then the snapshot reader, which logs in to the database removed below.
bash "$REPO_ROOT/apps/research-agents/uninstall.sh"
bash "$REPO_ROOT/apps/lake-api/uninstall.sh"

log "Removing Secrets research-export-writer and research-backup from $NAMESPACE..."
$KUBECTL delete secret research-export-writer research-backup -n "$NAMESPACE" --ignore-not-found >/dev/null

if ! $KUBECTL get namespace "$RESEARCH_NAMESPACE" >/dev/null 2>&1; then
    log "Namespace $RESEARCH_NAMESPACE does not exist: no research database to remove."
    exit 0
fi

if $MK8S helm3 status "$RS_RELEASE" -n "$RESEARCH_NAMESPACE" >/dev/null 2>&1; then
    log "Removing the Helm release $RS_RELEASE from $RESEARCH_NAMESPACE..."
    $MK8S helm3 uninstall "$RS_RELEASE" -n "$RESEARCH_NAMESPACE" --wait
else
    log "No Helm release $RS_RELEASE in $RESEARCH_NAMESPACE."
fi

if [[ "$_PURGE" != true ]]; then
    log "Kept the research database's volume (snapshots, reservations) and Secret research-postgresql-auth; pass --purge-data to delete them."
    exit 0
fi

log "Deleting the research database's volume and Secret research-postgresql-auth..."
$KUBECTL delete pvc -n "$RESEARCH_NAMESPACE" -l "app.kubernetes.io/instance=$RS_RELEASE" --ignore-not-found
$KUBECTL delete secret research-postgresql-auth -n "$RESEARCH_NAMESPACE" --ignore-not-found >/dev/null
log "The research data is gone."
