#!/usr/bin/env bash
# apps/research-console/uninstall.sh — the inverse of apps/research-console/deploy.sh (research Phase 4e):
# the portal's Agent campaigns card greyed out, research-console-oauth2-proxy and its 403 page from
# $NAMESPACE, then Deployment, Service and ConfigMap research-console-html (-l app=research-console) from
# $RESEARCH_AGENTS_NAMESPACE. The orchestrator, its API (the medcea-agent CLI keeps working), every recorded
# session, the Keycloak client and the namespace stay. ./apps/research/uninstall.sh runs it first.
# Idempotent.
#
#   ./apps/research-console/uninstall.sh

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
case "$*" in
    "") ;;
    --help|-h) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/research-console/uninstall.sh)" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-research-console-uninstall
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from apps/research/uninstall.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-portal.sh"
NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
AG_NS="${RESEARCH_AGENTS_NAMESPACE:-${RESEARCH_NAMESPACE}-agents}"
RESEARCH_CONSOLE_DOMAIN="${RESEARCH_CONSOLE_DOMAIN:-agents.$DOMAIN}"
RELEASE=research-console-oauth2-proxy

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[research-console]${NC} $*"; }

portal_card disable "https://$RESEARCH_CONSOLE_DOMAIN"

log "Removing $RELEASE (owns the $RESEARCH_CONSOLE_DOMAIN ingress)..."
$MK8S helm3 uninstall "$RELEASE" -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true
$KUBECTL delete configmap "$RELEASE-templates" -n "$NAMESPACE" --ignore-not-found >/dev/null   # its 403 page

if $KUBECTL get namespace "$AG_NS" >/dev/null 2>&1; then
    log "Removing research-console and its page from $AG_NS..."
    $KUBECTL delete deployment,service,configmap -l app=research-console -n "$AG_NS" --ignore-not-found
else
    log "Namespace $AG_NS does not exist: nothing to remove there."
fi
log "Research console removed. The orchestrator's API, the recorded sessions and Keycloak client research-console stay."
