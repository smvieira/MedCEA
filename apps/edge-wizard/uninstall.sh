#!/usr/bin/env bash
# apps/edge-wizard/uninstall.sh — remove what apps/edge-wizard/deploy.sh
# installed: the onboard ingress (Service, Endpoints, Ingress) and the
# cea-edge-wizard user service.
#
# Kept on purpose: edge/.venv (a download cache, which flash-device.sh also
# uses; install.sh --uninstall-all removes it) and linger (a per-user setting
# other services may rely on).
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] && source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"

UNIT=cea-edge-wizard
UNIT_FILE="$HOME/.config/systemd/user/$UNIT.service"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[edge-wizard]${NC} $*"; }

log "Removing the ingress..."
$KUBECTL delete ingress,service,endpoints edge-wizard -n "$NAMESPACE" --ignore-not-found

log "Stopping and removing the $UNIT user service..."
systemctl --user disable --now "$UNIT" >/dev/null 2>&1 || true
rm -f "$UNIT_FILE"
systemctl --user daemon-reload >/dev/null 2>&1 || true

log "Onboarding wizard removed."
echo ""
