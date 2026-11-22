#!/usr/bin/env bash
# apps/research-model/deploy.sh — the research sandbox's local model server (research Phase 4b, stage 1;
# codeplan/rs4-design.md 5.2, 5.5; owner decisions of 21 Nov 2026: Qwen3-4B-Instruct-2507 Q4_K_M, context
# 4096, the llama.cpp server image of apps/research-model/pins.json by digest).
#
#   ./apps/research-model/deploy.sh          ./deploy-apps.sh --all runs it (it skips unless switched on)
#   ./apps/research-model/deploy.sh --help
#
# Then model-gateway (stage 2; gateway.py, ConfigMap model-gateway-code, k8s/gateway.yaml). Deploys Deployment and Service research-llm into $RESEARCH_GW_NAMESPACE: llama-server on CPU, one slot,
# greedy, thinking-free instruct model, no secret and no internet. The model file lives in
# RESEARCH_MODEL_DIR (default /var/lib/<project>/research-models, mode 700 for the deploying account) and
# reaches the pod as a static read-only PersistentVolume; if it is not there yet, this script fetches it
# through apps/research-model/bench.sh fetch (the one fetch-and-verify path: Range resume, sha256 against
# the pin, rename only once it matches). An init container checks the pin again at every pod start.
#
# Prints one line and exits 0 (deploy-apps.sh and install.sh stay green) while
#   skipped: RESEARCH_ENABLED is not true
#   skipped: RESEARCH_LOCAL_MODEL is not true
#   skipped: the applied access policy has no research-llm pod yet
#   skipped: no version of the access policy is applied yet (state ...)
#   skipped: namespace <ns> does not exist yet
# A running research-llm is left alone by a skip, and named.
#
# Then refuses unless the research-gw zone's compiled NetworkPolicies are live and equal (never an open
# pod), fetches the model if missing, applies the volume, the script and the Deployment, and waits for it.
#
# Needs config.env: RESEARCH_ENABLED, RESEARCH_LOCAL_MODEL, RESEARCH_NAMESPACE, RESEARCH_GW_NAMESPACE
# (default ${RESEARCH_NAMESPACE}-gw), optional RESEARCH_MODEL_DIR. Run it as the deploying account, not
# root. Idempotent. Uninstall: ./apps/research-model/uninstall.sh (the model file is kept).

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
SCRIPT_DIR="$REPO_ROOT"   # what infra/lib-policy-artefacts.sh calls the repository
case "$*" in
    "") ;;
    --help|-h) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-model/deploy.sh [--help])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-model-deploy   # unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"    # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR...
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
source "$REPO_ROOT/infra/lib-policy-source.sh"
policy_source_init "$NAMESPACE" || exit $?
source "$REPO_ROOT/infra/lib-policy-artefacts.sh"   # zone_namespace, _pa_zonenetpol_equal
GW_NS="$(zone_namespace research-gw)"
RESEARCH_GW_NAMESPACE="$GW_NS"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[research-model]${NC} $*"; }
warn() { echo -e "${YELLOW}[research-model] $*${NC}" >&2; }
die()  { echo -e "${RED}[research-model] ERROR: $*${NC}" >&2; exit 1; }

[[ "$GW_NS" =~ ^[a-z][a-z0-9-]{1,52}$ ]] || die "'$GW_NS' is not a valid research namespace name (config.env)"
[[ "$GW_NS" != "$NAMESPACE" && "$GW_NS" != "$RESEARCH_NAMESPACE" ]] \
    || die "RESEARCH_NAMESPACE, RESEARCH_GW_NAMESPACE and NAMESPACE must all differ (config.env)"

_skip() {   # _skip MESSAGE: the line, a running research-llm named, exit 0
    log "skipped: $1"
    if $KUBECTL get deployment research-llm -n "$GW_NS" -o name 2>/dev/null | grep -q .; then
        warn "research-llm is still running in $GW_NS (left alone): ./apps/research-model/uninstall.sh removes it"
    fi
    policy_source_finish "$NAMESPACE" research-model
    exit 0
}

# ── Skips ─────────────────────────────────────────────────────────────────────
[[ "${RESEARCH_ENABLED:-false}" == "true" ]] || _skip "RESEARCH_ENABLED is not true"
[[ "${RESEARCH_LOCAL_MODEL:-false}" == "true" ]] || _skip "RESEARCH_LOCAL_MODEL is not true"

_zrc=0
_zone="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" pod-zone research-llm)" || _zrc=$?
case "$_zrc:$_zone" in
    0:research-gw) ;;
    0:*) die "the access policy puts research-llm in the ${_zone:-?} zone: it lives only in research-gw (python3 apps/iam/compiler/cli.py check)" ;;
    1:*) _skip "the applied access policy has no research-llm pod yet" ;;
    *)   die "the applied access policy cannot be read (cli.py pod-zone research-llm exit $_zrc): ./apps/iam/apply.sh --status says why" ;;
esac

_PS_DIR="$(mktemp -d)"
_ST="$(policy_db_state "$NAMESPACE" "$_PS_DIR/state.json")" || _ST=""
rm -rf "$_PS_DIR"
case "$_ST" in
    version-*) ;;
    none|empty) _skip "no version of the access policy is applied yet (state $_ST): run ./apps/research-model/deploy.sh once ./apps/iam/deploy.sh has applied version 1 (./apps/iam/apply.sh --status)" ;;
    "") die "cannot read the access policy's state from the database (policy_db_state failed)" ;;
    *)  die "the access policy's state in the database is '$_ST': ./apps/iam/apply.sh --status" ;;
esac

$KUBECTL get namespace "$GW_NS" >/dev/null 2>&1 \
    || _skip "namespace $GW_NS does not exist yet: run ./deploy-infra.sh (or ./infra/deploy-research-gw-namespace.sh)"

# ── Preconditions ─────────────────────────────────────────────────────────────
# Never an open pod: the zone's compiled policy live and equal to the compile.
_nrc=0
_pa_zonenetpol_equal research-gw || _nrc=$?
case "$_nrc" in
    0) ;;
    1) die "the research-gw zone's NetworkPolicies in $GW_NS are not the compiled ones: run ./infra/deploy-research-gw-namespace.sh (or ./deploy-infra.sh), then this again" ;;
    *) die "cannot compare the research-gw zone's NetworkPolicies with the compile (exit $_nrc)" ;;
esac
$KUBECTL get networkpolicy -n "$GW_NS" -o name 2>/dev/null | grep -q . \
    || die "no NetworkPolicy in $GW_NS: the compiled default-deny must be live first (./infra/deploy-research-gw-namespace.sh)"

# ── The pins (apps/research-model/pins.json; the owner's choice of 21 Nov 2026 is model "4b") ──
PINS="$APP_DIR/pins.json"
MODEL_KEY=4b
_pin() { python3 -c 'import json, sys; p = json.load(open(sys.argv[1])); k = sys.argv[3:]; print(p["models"][k[0]][k[1]] if k[0] in p["models"] else p[k[0]][k[1]])' "$PINS" - "$@"; }
LLAMA_IMAGE_SERVER="$(_pin llama_cpp image_server)"
MODEL_SHA256="$(_pin "$MODEL_KEY" sha256)"
MODEL_FILE="$(_pin "$MODEL_KEY" file)"
[[ "$LLAMA_IMAGE_SERVER" =~ ^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$ ]] || die "apps/research-model/pins.json has no llama.cpp server image pinned by digest"
[[ "$MODEL_SHA256" =~ ^[0-9a-f]{64}$ && "$MODEL_FILE" =~ ^[A-Za-z0-9._-]+\.gguf$ ]] || die "apps/research-model/pins.json has no usable pin for model $MODEL_KEY"
MODEL_ALIAS="$(printf '%s' "${MODEL_FILE%.gguf}" | tr 'A-Z' 'a-z')-${MODEL_SHA256:0:12}"
LLM_CTX=4096      # owner decision of 21 Nov 2026: local sessions are capped at about 4k tokens
LLM_THREADS=6     # what the Deployment requests (llm.yaml); the pod passes its own request on to llama-server (downward API)

# ── The model folder and the file ─────────────────────────────────────────────
MODEL_DIR="${RESEARCH_MODEL_DIR:-/var/lib/${PROJECT_NAME:-medcea}/research-models}"
if [[ ! "$MODEL_DIR" =~ ^/[A-Za-z0-9._/-]+$ || "$MODEL_DIR" == */../* || "$MODEL_DIR" == */.. || "$MODEL_DIR" == */./* ]]; then
    die "RESEARCH_MODEL_DIR='$MODEL_DIR' must be an absolute path of letters, digits and . _ - /"
fi
MODEL_DIR="${MODEL_DIR%/}"
[[ -n "$MODEL_DIR" ]] || die "RESEARCH_MODEL_DIR must not be /"
[[ "$(id -u)" != 0 ]] || die "Run this as the deploying account, not root: the model folder belongs to it and the pod runs as its owner, never root."

if [[ ! -f "$MODEL_DIR/$MODEL_SHA256.gguf" ]]; then
    log "The model ($MODEL_FILE, $(_pin "$MODEL_KEY" size_bytes) bytes) is not in $MODEL_DIR: fetching it with bench.sh fetch (resumes, checks the pinned sha256)..."
    bash "$APP_DIR/bench.sh" fetch --models "$MODEL_KEY" || die "the fetch did not finish: ./apps/research-model/bench.sh fetch --models $MODEL_KEY resumes it"
    [[ -f "$MODEL_DIR/$MODEL_SHA256.gguf" ]] || die "$MODEL_DIR/$MODEL_SHA256.gguf is still missing after the fetch"
fi
MODEL_UID="$(stat -L -c %u "$MODEL_DIR")"; MODEL_GID="$(stat -L -c %g "$MODEL_DIR")"
[[ "$MODEL_UID" != 0 ]] || die "$MODEL_DIR belongs to root: the pod would run as root. sudo chown $(id -un): $MODEL_DIR"

# ── The volume, the script and the Deployment ─────────────────────────────────
MODEL_PV="${GW_NS}-research-models"
LLM_SCRIPT_SHA256="$(sha256sum "$APP_DIR/container/llm-serve.sh" | cut -d' ' -f1)"
log "ConfigMap research-llm-script in $GW_NS..."
python3 -c '
import json, sys
print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "research-llm-script", "namespace": sys.argv[2],
      "labels": {"app": "research-llm"}}, "data": {"llm-serve.sh": open(sys.argv[1]).read()}}))' \
    "$APP_DIR/container/llm-serve.sh" "$GW_NS" | $KUBECTL apply -f - >/dev/null

log "research-llm in $GW_NS ($MODEL_ALIAS, context $LLM_CTX, $LLM_THREADS CPUs)..."
render "$APP_DIR/k8s/llm.yaml" RESEARCH_GW_NAMESPACE LLAMA_IMAGE_SERVER MODEL_PV MODEL_DIR MODEL_UID MODEL_GID MODEL_SHA256 \
    MODEL_FILE MODEL_ALIAS LLM_CTX LLM_SCRIPT_SHA256 | $KUBECTL apply -f - >/dev/null
$KUBECTL rollout status deployment/research-llm -n "$GW_NS" --timeout=10m \
    || die "research-llm did not become ready: microk8s kubectl -n $GW_NS logs deployment/research-llm (init container: -c verify)"

# ── The model gateway (stage 2): the one way a session reaches the model ──────
GATEWAY_IMAGE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["python_image"])' "$PINS")"
[[ "$GATEWAY_IMAGE" =~ ^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$ ]] || die "apps/research-model/pins.json has no python image pinned by digest"
GATEWAY_CODE_SHA256="$(cat "$APP_DIR/gateway.py" "$REPO_ROOT/apps/research-agents/mcp_common.py" | sha256sum | cut -d' ' -f1)"
log "ConfigMap model-gateway-code and model-gateway in $GW_NS..."
python3 -c '
import json, sys
print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "model-gateway-code", "namespace": sys.argv[1],
      "labels": {"app": "model-gateway"}}, "data": {"gateway.py": open(sys.argv[2]).read(), "mcp_common.py": open(sys.argv[3]).read()}}))' \
    "$GW_NS" "$APP_DIR/gateway.py" "$REPO_ROOT/apps/research-agents/mcp_common.py" | $KUBECTL apply -f - >/dev/null
render "$APP_DIR/k8s/gateway.yaml" RESEARCH_GW_NAMESPACE GATEWAY_IMAGE MODEL_ALIAS MODEL_SHA256 LLM_CTX GATEWAY_CODE_SHA256 | $KUBECTL apply -f - >/dev/null
$KUBECTL rollout status deployment/model-gateway -n "$GW_NS" --timeout=5m \
    || die "model-gateway did not become ready: microk8s kubectl -n $GW_NS logs deployment/model-gateway"

log "Done: research-llm runs $MODEL_ALIAS in $GW_NS (Service research-llm:8080) behind model-gateway (Service :8120), both admitted only to the pods the policy names."
policy_source_finish "$NAMESPACE" research-model
