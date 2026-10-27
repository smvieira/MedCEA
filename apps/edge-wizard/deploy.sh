#!/usr/bin/env bash
# apps/edge-wizard/deploy.sh — Device onboarding wizard (host service)
#
# The Devices tab's "Onboard Device" button opens edge/wizard-daemon.sh at
# https://$ONBOARD_DOMAIN/. It runs on the host, not in the
# cluster, because onboarding is over USB. This makes it part of the install:
#   1. edge/.venv — the esptool/mpremote toolchain (edge/lib-venv.sh)
#   2. systemd --user unit cea-edge-wizard, from `wizard-daemon.sh --install-unit`
#   3. enable + restart — restart, not just start: a --reset recreates the
#      Keycloak client with a new secret that a running daemon would not see
#   4. linger, so it starts at boot and survives logout
#   5. https://$ONBOARD_DOMAIN — Service + Endpoints (the host) + Ingress, so the
#      config UI links to a name over the platform certificate rather than to
#      http://<ip>:8088 (which also kept the browser clipboard API unavailable)
#
# Sorts before frontend, whose deploy checks that the wizard answers.
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-wait.sh"   # wait_for_http
source "$REPO_ROOT/edge/lib-venv.sh"    # ensure_edge_venv
source "$REPO_ROOT/infra/lib-mk8s.sh"   # $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh" # render FILE VAR...
NAMESPACE="${NAMESPACE:-medcea}"
EDGE_WIZARD_PORT="${EDGE_WIZARD_PORT:-8088}"
ONBOARD_DOMAIN="${ONBOARD_DOMAIN:-onboard-device.$DOMAIN}"

UNIT=cea-edge-wizard
UNIT_FILE="$HOME/.config/systemd/user/$UNIT.service"
PORT="$EDGE_WIZARD_PORT"
URL="https://$ONBOARD_DOMAIN/"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[edge-wizard]${NC} $*"; }
warn() { echo -e "${YELLOW}[edge-wizard]${NC} $*"; }

[[ -n "${EDGE_WIZARD_SECRET:-}" ]] || {
    echo "ERROR: EDGE_WIZARD_SECRET is not set in config.env — run ./deploy-infra.sh first." >&2
    exit 1
}

# No user manager to talk to (cron, a bare `su`): say what to run instead of
# failing the whole app install over the one host-side piece.
if ! systemctl --user show-environment >/dev/null 2>&1; then
    warn "No systemd user session here, so the wizard service cannot be installed."
    warn "From a normal login on this machine, run: ./apps/edge-wizard/deploy.sh"
    exit 0   # the ingress would only point at nothing, so leave it for that run
fi

log "Building the provisioning toolchain (edge/.venv)..."
ensure_edge_venv

log "Installing the $UNIT user service..."
mkdir -p "$(dirname "$UNIT_FILE")"
"$REPO_ROOT/edge/wizard-daemon.sh" --install-unit > "$UNIT_FILE"
systemctl --user daemon-reload
systemctl --user enable "$UNIT" >/dev/null 2>&1
systemctl --user restart "$UNIT"

# Without linger the user manager, and this service with it, stops at logout
# and does not start at boot until someone logs in.
if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]]; then
    log "Enabling linger so the wizard runs at boot and after logout..."
    loginctl enable-linger "$USER" 2>/dev/null \
        || sudo -p "[sudo] password for %u (keep the onboarding wizard running after logout): " \
               loginctl enable-linger "$USER" \
        || warn "Could not enable linger — the wizard stops when you log out. Run: sudo loginctl enable-linger $USER"
fi

log "Waiting for the wizard to answer..."
if ! wait_for_http "http://127.0.0.1:$PORT/" 60 "Onboarding wizard"; then
    journalctl --user -u "$UNIT" -n 20 --no-pager >&2 || true
    exit 1
fi

log "Publishing it at $URL..."
render "$SCRIPT_DIR/k8s/ingress.yaml" NAMESPACE PLATFORM_IP EDGE_WIZARD_PORT ONBOARD_DOMAIN \
    | $KUBECTL apply -f -
wait_for_http "$URL" 60 "Onboarding wizard (ingress)" || exit 1

echo ""
echo -e "  ${BOLD}Onboarding wizard deployed${NC}"
echo -e "  Wizard:   $URL   (the Devices tab's Onboard Device button)
  Direct:   http://${PLATFORM_IP}:$PORT/   (the daemon itself, without the ingress)"
echo -e "  Service:  systemctl --user status $UNIT"
