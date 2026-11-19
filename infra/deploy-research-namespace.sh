#!/usr/bin/env bash
#
# infra/deploy-research-namespace.sh — the research sandbox's zone (Phase 2a).
#
# Creates RESEARCH_NAMESPACE (label medcea/zone=research) and what keeps it away from
# production:
#   - PriorityClass medcea-research-low (value -100, not the default, never preempts):
#     research pods are evicted first under memory pressure;
#   - ResourceQuota research-quota and LimitRange research-limits (k8s/research/; the
#     sizing table is in quota.yaml): no default CPU limit, a default memory limit;
#   - the zone's NetworkPolicies, compiled from the applied access policy
#     (pa_rsnetpol in infra/lib-policy-artefacts.sh): deny all ingress and egress, DNS
#     to kube-dns, and per pod of the zone only its compiled sources and hops.
# Nothing else runs here: the research database is ./apps/research/deploy.sh.
#
# Only while RESEARCH_ENABLED is true (config.env) and the applied access policy has the
# research zone (an approved skeleton version); otherwise one "skipped" line and nothing
# changes. RESEARCH_ENABLED=false with the namespace still present: a warning naming how
# to remove it, nothing removed.
#
#   ./infra/deploy-research-namespace.sh                the above (deploy-infra.sh runs it)
#   ./infra/deploy-research-namespace.sh --policy-only  the zone's NetworkPolicies only,
#                                                       re-rendered when they drifted:
#                                                       "rsnetpol: unchanged|re-rendered|not deployed"
#
# Logs to logs/deploy-research-namespace-<ts>.log (unless a parent logs) and takes the
# deploy lock (unless a parent holds it).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the repository, as in deploy-policy.sh
REPO_ROOT="$SCRIPT_DIR"

_MODE=full
case "$*" in
    --help|-h) sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    --policy-only) _MODE=scoped ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./infra/deploy-research-namespace.sh [--policy-only])" >&2; exit 2 ;;
esac
set -euo pipefail

cd "$REPO_ROOT"
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log deploy-research-namespace   # unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-infra.sh
[[ "$_MODE" == scoped ]] && echo "mode: policy-only"
[[ -f config.env ]] || { echo "ERROR: config.env not found in $REPO_ROOT (run ./deploy-infra.sh first)." >&2; exit 1; }
# shellcheck source=/dev/null
source config.env

case ":$PATH:" in *:/snap/bin:*) ;; *) PATH="$PATH:/snap/bin" ;; esac
if microk8s status --timeout 5 >/dev/null 2>&1; then MK8S="microk8s"; else MK8S="sudo microk8s"; fi
KUBECTL="$MK8S kubectl"
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; NC='\033[0m'
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"

source "$REPO_ROOT/infra/lib-render.sh"
source "$REPO_ROOT/infra/lib-policy-source.sh"
source "$REPO_ROOT/infra/lib-policy-artefacts.sh"   # pa_rsnetpol, _pa_rs_zone, _pa_line

log()  { echo -e "${GREEN}[research-namespace]${NC} $*"; }
warn() { echo -e "${YELLOW}[research-namespace] WARNING:${NC} $*" >&2; }
die()  { echo -e "${RED}[research-namespace] ERROR:${NC} $*" >&2; exit 1; }

_rns_valid() { [[ "$RESEARCH_NAMESPACE" =~ ^[a-z][a-z0-9-]{1,52}$ && "$RESEARCH_NAMESPACE" != "$NAMESPACE" ]]; }
_rns_present() { [[ "$($KUBECTL get namespace "$RESEARCH_NAMESPACE" -o name 2>/dev/null || true)" == "namespace/$RESEARCH_NAMESPACE" ]]; }

# Switched off: no policy read, nothing changed. A namespace left from earlier is named.
if [[ "${RESEARCH_ENABLED:-false}" != "true" ]]; then
    if [[ "$_MODE" == scoped ]]; then
        _pa_line rsnetpol "not deployed"
    else
        log "skipped: RESEARCH_ENABLED is not true (config.env), so the research namespace is not deployed"
    fi
    if _rns_valid && _rns_present; then
        warn "RESEARCH_ENABLED is not true, but namespace $RESEARCH_NAMESPACE is still there and is left as it is (its network policies stay as they were). To remove it and everything in it, the research database and its volume included (./apps/research/uninstall.sh first, if it is deployed):
       $KUBECTL delete namespace $RESEARCH_NAMESPACE
       $KUBECTL delete priorityclass medcea-research-low"
        # research Phase 2b: the AI workbench may live there (the access policy places it)
        if [[ "$($KUBECTL get deployment hub -n "$RESEARCH_NAMESPACE" -o name 2>/dev/null || true)" == deployment.apps/hub ]]; then
            warn "the AI workbench runs in $RESEARCH_NAMESPACE too (its hub and people's homes, claim-<name>): it keeps running, and deleting the namespace takes it with it. Move it back first (an access policy that places it in the platform namespace, then ./infra/deploy-workbench.sh --move), or copy the homes off (./apps/backup/backups.sh restore-help, part C)."
        fi
    fi
    exit 0
fi

_rns_valid || die "RESEARCH_NAMESPACE='$RESEARCH_NAMESPACE' must match ^[a-z][a-z0-9-]{1,52}\$ and differ from NAMESPACE='$NAMESPACE' (config.env)."

# Write mode, as every compiling entry script: the skeleton gate, break-glass, the host file.
policy_source_init "$NAMESPACE" || exit $?

if ! _pa_rs_zone; then
    if [[ "$_MODE" == scoped ]]; then
        _pa_line rsnetpol "not deployed"
    else
        log "skipped: the applied access policy has no research zone yet; it comes with an approved skeleton version (./apps/iam/apply.sh --status)"
    fi
    _rns_present && warn "namespace $RESEARCH_NAMESPACE exists, but the applied access policy has no research zone: its network policies are left as they are."
    policy_source_finish "$NAMESPACE" deploy-research-namespace
    exit 0
fi

if [[ "$_MODE" == scoped ]]; then
    pa_rsnetpol scoped
else
    log "namespace $RESEARCH_NAMESPACE (zone research), PriorityClass medcea-research-low, quota and limits"
    render "$REPO_ROOT/k8s/research/namespace.yaml" RESEARCH_NAMESPACE | $KUBECTL apply -f -
    render "$REPO_ROOT/k8s/research/priorityclass.yaml" | $KUBECTL apply -f -
    render "$REPO_ROOT/k8s/research/quota.yaml" RESEARCH_NAMESPACE | $KUBECTL apply -f -
    render "$REPO_ROOT/k8s/research/limitrange.yaml" RESEARCH_NAMESPACE | $KUBECTL apply -f -
    pa_rsnetpol full
fi

# The last command of the success path: ends an open policy break-glass for this script (IAM 4.2a)
policy_source_finish "$NAMESPACE" deploy-research-namespace
