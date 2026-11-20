#!/usr/bin/env bash
# apps/research/calibrate.sh — calibrate the research sandbox's models from the lake's
# snapshots (research sandbox Phase 3; codeplan/rs3-design.md §1.2, §9 R15).
#
#   ./apps/research/calibrate.sh snapshots
#   ./apps/research/calibrate.sh fetch --snapshot N --expect-lineage HEX --unit U --zone Z --out DIR
#   ./apps/research/calibrate.sh verify FILE
#   ./apps/research/calibrate.sh --help
#
# A host wrapper around python3 -m research.calib (research/calib/cli.py: its own --help
# lists every command). For snapshots and fetch, the two commands that read the lake, it
# resolves lake-api's address on this host as ./apps/lake-api/deploy.sh does (the Running
# pod's IP in $RESEARCH_NAMESPACE, else the Service's ClusterIP: the research zone admits
# the node) and exports MEDCEA_LAKE=http://<ip>:3000. Every other command passes straight
# through and needs neither config.env nor the cluster.
#
# Read-only: it reads lake-api (GETs of the lake_api functions) and writes only the folder
# --out names. It takes no deploy lock (it changes no cluster state and not config.env)
# and logs to logs/research-calibrate-<ts>.log.
#
# Exit codes: python3 -m research.calib's (0 done, 2 refused or failed, 3 not identifiable),
# and 2 here when, for snapshots or fetch, RESEARCH_ENABLED is not true or no lake-api
# runs. Uses research/.venv/bin/python when it exists, else python3. Relative paths
# (--out, FILE) are relative to where you run it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
_usage() { sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case "${1:-}" in
    --help|-h) _usage; exit 0 ;;
    "") _usage >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log research-calibrate   # logs/research-calibrate-<ts>.log

PY=python3
[[ -x "$REPO_ROOT/research/.venv/bin/python" ]] && PY="$REPO_ROOT/research/.venv/bin/python"

case "$1" in
    snapshots|fetch) ;;
    *) PYTHONPATH="$REPO_ROOT" exec "$PY" -m research.calib "$@" ;;
esac

die2() { echo "ERROR: $*" >&2; exit 2; }

[[ -f "$REPO_ROOT/config.env" ]] || die2 "config.env not found at $REPO_ROOT/config.env (snapshots and fetch read the lake from the platform host)"
source "$REPO_ROOT/config.env"
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
[[ "${RESEARCH_ENABLED:-false}" == "true" ]] || die2 "RESEARCH_ENABLED is not true: the research sandbox is off (./medcea.sh → Infrastructure → Turn the research sandbox on or off)"
[[ "$RESEARCH_NAMESPACE" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
    || die2 "RESEARCH_NAMESPACE='$RESEARCH_NAMESPACE' is not a Kubernetes namespace name (config.env)"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)

_pods="$($KUBECTL get pod -n "$RESEARCH_NAMESPACE" -l app=lake-api --field-selector=status.phase=Running \
          -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
[[ -n "$_pods" ]] || die2 "the lake reader is not running (./apps/lake-api/deploy.sh)"
_ip="$($KUBECTL get pod -n "$RESEARCH_NAMESPACE" -l app=lake-api --field-selector=status.phase=Running \
          -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)"
if [[ ! "$_ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
    _ip="$($KUBECTL get service lake-api -n "$RESEARCH_NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
fi
[[ "$_ip" =~ ^[0-9a-fA-F.:]+$ ]] || die2 "cannot read lake-api's address in $RESEARCH_NAMESPACE (pod IP or Service ClusterIP)"
[[ "$_ip" == *:* ]] && _ip="[$_ip]"

export MEDCEA_LAKE="http://$_ip:3000"
echo "lake-api: $MEDCEA_LAKE" >&2
PYTHONPATH="$REPO_ROOT" exec "$PY" -m research.calib "$@"
