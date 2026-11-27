#!/usr/bin/env bash
# apps/research-console/deploy.sh — the research console (research Phase 4e; codeplan/rs4e-design.md §1, §4,
# §9; owner decisions OD-4e-1, -2, -9 of 27 Nov 2026).
#
#   ./apps/research-console/deploy.sh               ./apps/research/deploy.sh runs it after research-agents
#   ./apps/research-console/deploy.sh --gate-only   only the sign-in gate, only when it drifted (apply.sh's rollout)
#   ./apps/research-console/deploy.sh --help
#
# A web page at https://$RESEARCH_CONSOLE_DOMAIN (default agents.$DOMAIN) for supervising agent sessions:
#   1. ConfigMap research-console-html in $RESEARCH_AGENTS_NAMESPACE: the page (apps/research-console/html)
#      and MANIFEST.json (apps/research-console/page.py; its Sign out address is research_console_logout_url),
#      server-side applied; its sha256 is the ConfigMap's medcea/console-sha256 and the pod's medcea/html-sha256;
#   2. Deployment and Service research-console (k8s/console.yaml): console.py from the research-code bundle
#      (./apps/research-agents/deploy.sh builds it), the agents zone's wheels; no token, no Secret, no egress;
#   3. research-console-oauth2-proxy in $NAMESPACE (k8s/values-console.yaml through app_gate: the roles the
#      policy compiles for RESEARCH_CONSOLE_DOMAIN, the 403 page): / to the console, /api/ straight to the
#      orchestrator's person port; the browser holds only the proxy's cookie;
#   4. the portal's Agent campaigns card enabled (portal_card).
#
# Prints one line and exits 0 (deploy-apps.sh and install.sh stay green) while
#   skipped: RESEARCH_ENABLED is not true
#   skipped: the applied access policy has no research console yet
#   skipped: no version of the access policy is applied yet (state ...)
#   skipped: namespace <ns> does not exist yet
#   skipped: no research-orchestrator yet (./apps/research-agents/deploy.sh)
# A running console is left alone by a skip, and named.
#
# Then refuses unless the research-agents zone's compiled NetworkPolicies are live and equal (never an open
# pod), the code bundle holds console.py, and config.env has the client and cookie secrets (./deploy-infra.sh
# writes both once the policy has the host). --gate-only prints `RESEARCH_CONSOLE_DOMAIN
# (research-console-oauth2-proxy): unchanged | re-rendered (...) | not deployed` and changes nothing else.
#
# Needs config.env: RESEARCH_ENABLED, RESEARCH_CONSOLE_DOMAIN, RESEARCH_CONSOLE_CLIENT_SECRET,
# RESEARCH_CONSOLE_COOKIE_SECRET, RESEARCH_NAMESPACE, RESEARCH_AGENTS_NAMESPACE (default
# ${RESEARCH_NAMESPACE}-agents). Idempotent. Uninstall: ./apps/research-console/uninstall.sh.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
SCRIPT_DIR="$REPO_ROOT"   # what infra/lib-policy-artefacts.sh calls the repository
_MODE=full
case "$*" in
    "") ;;
    --gate-only) _MODE=scoped ;;
    --help|-h) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-console/deploy.sh [--gate-only | --help])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-console-deploy   # unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from apps/research/deploy.sh
[[ "$_MODE" == scoped ]] && echo "mode: gate-only"

[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"           # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"         # render FILE VAR...
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"   # app_gate, research_console_logout_url
source "$REPO_ROOT/infra/lib-wait.sh"           # wait_for_http
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
source "$REPO_ROOT/infra/lib-policy-source.sh"
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)
source "$REPO_ROOT/infra/lib-policy-artefacts.sh"   # zone_namespace, _pa_zonenetpol_equal
AG_NS="$(zone_namespace research-agents)"
RESEARCH_AGENTS_NAMESPACE="$AG_NS"
RESEARCH_CONSOLE_DOMAIN="${RESEARCH_CONSOLE_DOMAIN:-agents.$DOMAIN}"
RELEASE=research-console-oauth2-proxy

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[research-console]${NC} $*"; }
warn() { echo -e "${YELLOW}[research-console] $*${NC}" >&2; }
die()  { echo -e "${RED}[research-console] ERROR: $*${NC}" >&2; exit 1; }

[[ "$AG_NS" =~ ^[a-z][a-z0-9-]{1,52}$ ]] || die "'$AG_NS' is not a valid research namespace name (config.env)"
[[ "$AG_NS" != "$NAMESPACE" && "$AG_NS" != "$RESEARCH_NAMESPACE" ]] \
    || die "RESEARCH_NAMESPACE, RESEARCH_AGENTS_NAMESPACE and NAMESPACE must all differ (config.env)"
[[ "$RESEARCH_CONSOLE_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] \
    || die "RESEARCH_CONSOLE_DOMAIN='$RESEARCH_CONSOLE_DOMAIN' is not a host name (config.env)"

# Does the applied access policy have the console's host? 0 yes, 1 no; anything else dies.
_hrc=0
python3 "$REPO_ROOT/apps/iam/compiler/cli.py" has-host RESEARCH_CONSOLE_DOMAIN >/dev/null || _hrc=$?
case "$_hrc" in
    0|1) ;;
    *) die "the applied access policy cannot be read (cli.py has-host RESEARCH_CONSOLE_DOMAIN exit $_hrc): ./apps/iam/apply.sh --status says why" ;;
esac

# The sign-in gate, shared by the full deploy and --gate-only. Its values name the research-agents
# namespace (both upstreams are there): APP_GATE_VARS adds it to app_gate's render list.
_gate() {
    APP_GATE_VARS=RESEARCH_AGENTS_NAMESPACE app_gate "$_MODE" "$RELEASE" research-console "${RESEARCH_CONSOLE_CLIENT_SECRET:-}" "${RESEARCH_CONSOLE_COOKIE_SECRET:-}" \
        RESEARCH_CONSOLE_DOMAIN "$RESEARCH_CONSOLE_DOMAIN" "$APP_DIR/k8s/values-console.yaml"
}

if [[ "$_MODE" == scoped ]]; then
    if [[ "$_hrc" == 1 ]]; then
        if $KUBECTL get deployment "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
            echo "  RESEARCH_CONSOLE_DOMAIN ($RELEASE): not in the applied access policy; the running proxy is left as it is (./apps/research-console/uninstall.sh removes it)"
        else
            echo "  RESEARCH_CONSOLE_DOMAIN ($RELEASE): not deployed (the applied access policy has no research console yet)"
        fi
    else
        _gate
    fi
    policy_source_finish "$NAMESPACE" research-console
    exit 0
fi

_skip() {   # _skip MESSAGE: the line, a running console named, exit 0
    log "skipped: $1"
    if $KUBECTL get deployment research-console -n "$AG_NS" -o name 2>/dev/null | grep -q . \
       || $KUBECTL get deployment "$RELEASE" -n "$NAMESPACE" -o name 2>/dev/null | grep -q .; then
        warn "the research console is still running (left alone): ./apps/research-console/uninstall.sh removes it"
    fi
    policy_source_finish "$NAMESPACE" research-console
    exit 0
}

# ── Skips ─────────────────────────────────────────────────────────────────────
[[ "${RESEARCH_ENABLED:-false}" == "true" ]] || _skip "RESEARCH_ENABLED is not true"
[[ "$_hrc" == 0 ]] || _skip "the applied access policy has no research console yet"

_zrc=0
_zone="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" pod-zone research-console)" || _zrc=$?
[[ "$_zrc:$_zone" == "0:research-agents" ]] \
    || die "the access policy must put the pod research-console in the research-agents zone (cli.py pod-zone research-console: '${_zone:-}', exit $_zrc)"

_PS_DIR="$(mktemp -d)"
_ST="$(policy_db_state "$NAMESPACE" "$_PS_DIR/state.json")" || _ST=""
rm -rf "$_PS_DIR"
case "$_ST" in
    version-*) ;;
    none|empty) _skip "no version of the access policy is applied yet (state $_ST): run ./apps/research-console/deploy.sh once ./apps/iam/deploy.sh has applied version 1 (./apps/iam/apply.sh --status)" ;;
    "") die "cannot read the access policy's state from the database (policy_db_state failed)" ;;
    *)  die "the access policy's state in the database is '$_ST': ./apps/iam/apply.sh --status" ;;
esac

$KUBECTL get namespace "$AG_NS" >/dev/null 2>&1 \
    || _skip "namespace $AG_NS does not exist yet: run ./deploy-infra.sh (or ./infra/deploy-research-agents-namespace.sh)"
$KUBECTL get deployment research-orchestrator -n "$AG_NS" >/dev/null 2>&1 \
    || _skip "no research-orchestrator yet (./apps/research-agents/deploy.sh)"

# ── Preconditions ─────────────────────────────────────────────────────────────
# Never an open pod: the zone's compiled policy (with ra-research-console) live and equal to the compile.
_nrc=0
_pa_zonenetpol_equal research-agents || _nrc=$?
case "$_nrc" in
    0) ;;
    1) die "the research-agents zone's NetworkPolicies in $AG_NS are not the compiled ones: run ./infra/deploy-research-agents-namespace.sh (or ./deploy-infra.sh), then this again" ;;
    *) die "cannot compare the research-agents zone's NetworkPolicies with the compile (exit $_nrc)" ;;
esac
$KUBECTL get networkpolicy -n "$AG_NS" -o name 2>/dev/null | grep -q . \
    || die "no NetworkPolicy in $AG_NS: the compiled default-deny must be live first (./infra/deploy-research-agents-namespace.sh)"
[[ -n "${RESEARCH_CONSOLE_CLIENT_SECRET:-}" && -n "${RESEARCH_CONSOLE_COOKIE_SECRET:-}" ]] \
    || die "RESEARCH_CONSOLE_CLIENT_SECRET or RESEARCH_CONSOLE_COOKIE_SECRET is empty in config.env: run ./deploy-infra.sh (it creates client research-console once the policy has the host)"

# The code bundle research-agents' deploy built must hold console.py (the console runs it).
RS_CODE_COMMIT="$($KUBECTL get configmap research-code -n "$AG_NS" -o jsonpath='{.metadata.annotations.medcea/code-commit}' 2>/dev/null)" || RS_CODE_COMMIT=""
RS_BUNDLE_SHA256="$($KUBECTL get configmap research-code -n "$AG_NS" -o jsonpath='{.metadata.annotations.medcea/code-sha256}' 2>/dev/null)" || RS_BUNDLE_SHA256=""
[[ "$RS_CODE_COMMIT" =~ ^[0-9a-f]{40}$ && "$RS_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "no code bundle (ConfigMap research-code) in $AG_NS: run ./apps/research-agents/deploy.sh"
git -C "$REPO_ROOT" cat-file -e "$RS_CODE_COMMIT:apps/research-console/console.py" 2>/dev/null \
    || die "the code bundle in $AG_NS (commit ${RS_CODE_COMMIT:0:12}) has no apps/research-console/console.py: run ./apps/research-agents/deploy.sh from this checkout"

CONSOLE_IMAGE="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["python_image"])' "$REPO_ROOT/apps/research-model/pins.json")"
[[ "$CONSOLE_IMAGE" =~ ^python:[0-9.]+-slim@sha256:[0-9a-f]{64}$ ]] || die "apps/research-model/pins.json has no python_image pinned by digest"

# ── 1. The page ───────────────────────────────────────────────────────────────
SIGNOUT="$(research_console_logout_url)" || die "cannot build the console's Sign out address (research_console_logout_url)"
CONSOLE_HTML_SHA256="$(python3 "$APP_DIR/page.py" sha "$SIGNOUT")" || die "the console's page does not build (apps/research-console/page.py, above)"
log "ConfigMap research-console-html in $AG_NS (manifest ${CONSOLE_HTML_SHA256:0:12})..."
python3 "$APP_DIR/page.py" configmap "$AG_NS" "$SIGNOUT" \
    | $KUBECTL apply --server-side --force-conflicts --field-manager=medcea-research-console -f - >/dev/null \
    || die "ConfigMap research-console-html could not be written"

# ── 2. The page server ────────────────────────────────────────────────────────
log "research-console in $AG_NS..."
render "$APP_DIR/k8s/console.yaml" RESEARCH_AGENTS_NAMESPACE CONSOLE_IMAGE CONSOLE_HTML_SHA256 RS_CODE_COMMIT RS_BUNDLE_SHA256 \
    | $KUBECTL apply -f -
$KUBECTL rollout status deployment/research-console -n "$AG_NS" --timeout=5m \
    || die "research-console did not become ready: microk8s kubectl -n $AG_NS logs deployment/research-console (init container: -c unpack)"

# ── 3. The sign-in gate (its Ingress owns the host) ───────────────────────────
$KUBECTL delete ingress research-console -n "$NAMESPACE" --ignore-not-found >/dev/null
log "Deploying $RELEASE (Keycloak SSO; / to the console, /api/ to the orchestrator)..."
_gate
$KUBECTL rollout status "deployment/$RELEASE" -n "$NAMESPACE" --timeout=4m
wait_for_http "https://$RESEARCH_CONSOLE_DOMAIN/" 120 "Research console" || exit 1

# ── 4. The portal card ────────────────────────────────────────────────────────
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$RESEARCH_CONSOLE_DOMAIN"

log "Done: https://$RESEARCH_CONSOLE_DOMAIN (the page from $AG_NS, the API straight to research-orchestrator:8090)."
policy_source_finish "$NAMESPACE" research-console
