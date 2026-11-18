#!/usr/bin/env bash
# apps/research-export/deploy.sh — the nightly export from the operational database into
# the research sandbox's database (research sandbox Phase 2a, codeplan/research-sandbox-plan.md;
# owner decisions P, F and S of 18 Nov 2026).
#
# Deploys, in the platform namespace:
#   1. ConfigMap research-export-script (apps/research-export/export-job.sh)
#   2. CronJob research-export (k8s/cronjob.yaml), daily at 03:00 UTC (after the backup):
#      reads medcea.research_*() as svc_research_export (Secret db-svc-research-export),
#      writes one snapshot into medcea_research as rs_export_writer (Secret
#      research-export-writer, which ./apps/research/deploy.sh writes), in one research
#      transaction. The image is research-postgresql's own (psql of its version).
#
# Skipped (exit 0, a "skipped:" line; a CronJob already there is removed, the research
# database and its snapshots are kept) while:
#   - RESEARCH_ENABLED is not true (config.env; opt-in)
#   - the applied access policy has no research zone (cli.py has-zone research): commit A
#     of Phase 2a, or before the skeleton version that adds it is applied
#   - no version of the access policy is applied yet
#   - StatefulSet research-postgresql is not in RESEARCH_NAMESPACE (./apps/research/deploy.sh)
#   - IAM_DB_SERVICE_ROLES is not true (the connection is svc_research_export)
# Under all of those the login is svc_research_export or nothing: a fallback to postgres
# is refused (db_client), like Superset's and iam-api's.
#
# Run one now: microk8s kubectl -n <namespace> create job --from=cronjob/research-export
# research-export-now-<n>. Uninstall: ./apps/research-export/uninstall.sh (the research
# database keeps every snapshot). Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
case "$*" in
    "") ;;
    --help|-h)
        echo "usage: ./apps/research-export/deploy.sh"
        echo "Deploys CronJob research-export (the nightly snapshot into the research database)."
        echo "Skips while RESEARCH_ENABLED is not true, the applied access policy has no research zone,"
        echo "or ./apps/research/deploy.sh has not run."
        exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-export/deploy.sh)" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-export-deploy   # logs/app-research-export-deploy-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
NAMESPACE="${NAMESPACE:-medcea}"
source "$REPO_ROOT/infra/lib-policy-source.sh"   # where every policy read comes from (IAM Phase 4)
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-$NAMESPACE-research}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[research-export]${NC} $*"; }
warn() { echo -e "${YELLOW}[research-export] $*${NC}" >&2; }
die()  { echo -e "${RED}[research-export] ERROR: $*${NC}" >&2; exit 1; }

[[ "$RESEARCH_NAMESPACE" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
    || die "RESEARCH_NAMESPACE='$RESEARCH_NAMESPACE' is not a Kubernetes namespace name (config.env)"
[[ "$POSTGRES_DB" =~ ^[a-z_][a-z0-9_]*$ ]] || die "POSTGRES_DB='$POSTGRES_DB' is not a plain database name (config.env)"

_deployed() { $KUBECTL get cronjob research-export -n "$NAMESPACE" >/dev/null 2>&1; }
# Removes the CronJob, its Jobs and its ConfigMap: what uninstall.sh removes. The research
# database and every snapshot in it stay.
_stop() {
    $KUBECTL delete cronjob research-export -n "$NAMESPACE" --ignore-not-found >/dev/null
    $KUBECTL delete job -n "$NAMESPACE" -l app=research-export --ignore-not-found >/dev/null
    $KUBECTL delete configmap research-export-script -n "$NAMESPACE" --ignore-not-found >/dev/null
}
_skip() {   # _skip MESSAGE: the line, the running export removed, exit 0
    log "skipped: $1"
    if _deployed; then
        _stop
        warn "the CronJob research-export was removed (the research database keeps its snapshots)"
    fi
    policy_source_finish "$NAMESPACE" research-export
    exit 0
}

# =============================================================================
# 0. Is the export wanted, and allowed?
# =============================================================================
[[ "${RESEARCH_ENABLED:-false}" == "true" ]] \
    || _skip "RESEARCH_ENABLED is not true (config.env), so the research sandbox is not installed"

_rc=0; python3 "$REPO_ROOT/apps/iam/compiler/cli.py" has-zone research >/dev/null || _rc=$?
case $_rc in
    0) ;;
    1) _skip "the applied access policy has no research zone yet (it comes with an approved skeleton version: ./apps/iam/apply.sh --status)" ;;
    *) die "cannot read the research zone from the access policy: it does not load or fails its checks (./apps/iam/apply.sh --status)" ;;
esac

# Only from an applied version (as apps/superset/deploy.sh): write-mode policy_source_init
# leaves no state behind, so it is asked here.
_PS_DIR="$(mktemp -d)"
_ST="$(policy_db_state "$NAMESPACE" "$_PS_DIR/state.json")" || _ST=""
rm -rf "$_PS_DIR"
case "$_ST" in
    version-*) ;;
    none|empty) _skip "no version of the access policy is applied yet (state $_ST): run ./apps/research-export/deploy.sh once ./apps/iam/deploy.sh has applied version 1 (./apps/iam/apply.sh --status)" ;;
    "") die "cannot read the policy versions (./apps/iam/apply.sh --status)" ;;
    *)  die "the access policy's versions are in state $_ST (./apps/iam/apply.sh --status)" ;;
esac

# The research database: its image is the job's, so psql matches the server.
EXPORT_IMAGE="$($KUBECTL get statefulset research-postgresql -n "$RESEARCH_NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="postgresql")].image}' 2>/dev/null || true)"
[[ -n "$EXPORT_IMAGE" ]] || _skip "./apps/research/deploy.sh has not run (no StatefulSet research-postgresql in $RESEARCH_NAMESPACE)"

[[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]] \
    || _skip "the research export needs IAM_DB_SERVICE_ROLES=true (its connection is svc_research_export)"

# The writer's Secret, by name only (its data is never read here).
$KUBECTL get secret research-export-writer -n "$NAMESPACE" -o name >/dev/null 2>&1 \
    || die "no Secret research-export-writer in $NAMESPACE: run ./apps/research/deploy.sh (it writes it), then this again"

# The operational login: svc_research_export, never postgres.
source "$REPO_ROOT/infra/lib-db-roles.sh"   # db_client (IAM 2.5)
db_client "$NAMESPACE" svc_research_export
[[ "$DBC_USER" == "svc_research_export" ]] \
    || die "the export would log in as $DBC_USER, not svc_research_export: run ./apps/database/deploy.sh with IAM_DB_SERVICE_ROLES=true first (see the warning above)"
OP_DB_USER="$DBC_USER"; OP_SECRET="$DBC_SECRET"; OP_SECRET_KEY="$DBC_SECRET_KEY"

# =============================================================================
# 1. The script, 2. the CronJob
# =============================================================================
log "Creating ConfigMap research-export-script..."
$KUBECTL create configmap research-export-script -n "$NAMESPACE" \
    --from-file=export-job.sh="$SCRIPT_DIR/export-job.sh" --dry-run=client -o yaml \
  | $KUBECTL apply -f -

log "Deploying CronJob research-export (daily 03:00 UTC, image $EXPORT_IMAGE)..."
render "$SCRIPT_DIR/k8s/cronjob.yaml" NAMESPACE RESEARCH_NAMESPACE EXPORT_IMAGE POSTGRES_DB \
    OP_DB_USER OP_SECRET OP_SECRET_KEY \
  | $KUBECTL apply -f -

log ""
log "Research export deployed: $OP_DB_USER reads $POSTGRES_DB, rs_export_writer writes medcea_research in $RESEARCH_NAMESPACE."
log "  Schedule: daily 03:00 UTC (one snapshot per run; health check \"Research export\")"
log "  Run one now: microk8s kubectl -n $NAMESPACE create job --from=cronjob/research-export research-export-now-\$(date +%s)"
policy_source_finish "$NAMESPACE" research-export
