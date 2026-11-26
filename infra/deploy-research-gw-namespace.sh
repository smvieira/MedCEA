#!/usr/bin/env bash
#
# infra/deploy-research-gw-namespace.sh — the research sandbox's research-gw zone (research Phase 4a, design rs4 R2).
#
# Creates RESEARCH_GW_NAMESPACE (label medcea/zone=research-gw, Pod Security baseline, a default
# ServiceAccount that mounts no token), its ResourceQuota and LimitRange (k8s/research-gw/), and the zone's
# NetworkPolicies compiled from the applied access policy (pa_zonenetpol in
# infra/lib-policy-artefacts.sh: default-deny, DNS for the pods that need it, and per pod only its
# compiled sources and hops). Nothing else runs here: the pods are ./apps/research-agents/deploy.sh.
#
# Only while RESEARCH_ENABLED is true (config.env) and the applied access policy has the research-gw zone
# (an approved skeleton version); otherwise one "skipped" line and nothing changes.
#
#   ./infra/deploy-research-gw-namespace.sh                the above (deploy-infra.sh runs it, after the research namespace)
#   ./infra/deploy-research-gw-namespace.sh --policy-only  the zone's NetworkPolicies only, re-rendered when they drifted:
#                                                      "gwnetpol: unchanged|re-rendered|not deployed"
#
# Logs to logs/deploy-research-gw-namespace-<ts>.log (unless a parent logs) and takes the deploy lock
# (unless a parent holds it).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$SCRIPT_DIR"

_MODE=full
case "$*" in
    --help|-h) sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    --policy-only) _MODE=scoped ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./infra/deploy-research-gw-namespace.sh [--policy-only])" >&2; exit 2 ;;
esac
set -euo pipefail

cd "$REPO_ROOT"
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log deploy-research-gw-namespace   # unless a parent logs
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
source "$REPO_ROOT/infra/lib-policy-artefacts.sh"   # pa_zonenetpol, _pa_zone_has, _pa_line, zone_namespace
source "$REPO_ROOT/infra/lib-research-zone-namespace.sh"

log()  { echo -e "${GREEN}[research-gw-namespace]${NC} $*"; }
warn() { echo -e "${YELLOW}[research-gw-namespace] WARNING:${NC} $*" >&2; }
die()  { echo -e "${RED}[research-gw-namespace] ERROR:${NC} $*" >&2; exit 1; }

rzn_run research-gw
