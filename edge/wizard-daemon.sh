#!/usr/bin/env bash
#
# edge/wizard-daemon.sh — the always-on device onboarding service.
#
# Same wizard as `flash-device.sh --ui`, but long-lived: it holds the Keycloak
# session and starts a flash run when an operator presses Start. That is what
# lets the config UI link to a URL that is always there, instead of one that
# only exists while somebody happens to be running the script by hand.
#
# It has to run on the host rather than in the cluster because onboarding is
# over USB, and /dev/ttyACM0 belongs to the host. Run it as a user in the
# dialout group — see edge/README.md.
#
#   ./edge/wizard-daemon.sh                 # foreground
#   systemctl --user start cea-edge-wizard  # see the unit file below
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

case "${1:-}" in
  -h|--help)
    cat <<'EOF'
Usage: ./edge/wizard-daemon.sh [--port N] [--bind ADDR] [--install-unit]

Serves the device onboarding wizard continuously, behind a Keycloak login.

  --port N          default $EDGE_WIZARD_PORT or 8088
  --bind ADDR       default 0.0.0.0
  --install-unit    print a systemd --user unit file and exit
  -h, --help        this message

Requires EDGE_WIZARD_SECRET in config.env (created by ./deploy-infra.sh).
EOF
    exit 0 ;;
esac

PORT=""; BIND="0.0.0.0"
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:-}"; shift 2 ;;
    --bind) BIND="${2:-}"; shift 2 ;;
    --install-unit)
      cat <<EOF
# Save as ~/.config/systemd/user/cea-edge-wizard.service then:
#   systemctl --user daemon-reload
#   systemctl --user enable --now cea-edge-wizard
#   loginctl enable-linger $(id -un)     # so it survives logout
[Unit]
Description=CEA edge device onboarding wizard
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_ROOT
ExecStart=$SCRIPT_DIR/wizard-daemon.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

set -e
cd "$REPO_ROOT"
# shellcheck source=/dev/null
[ -f config.env ] && source config.env
PORT="${PORT:-${EDGE_WIZARD_PORT:-8088}}"
ONBOARD_DOMAIN="${ONBOARD_DOMAIN:-${DOMAIN:+onboard-device.$DOMAIN}}"

[ -n "${EDGE_WIZARD_SECRET:-}" ] || {
  echo "EDGE_WIZARD_SECRET is not set in config.env." >&2
  echo "Run ./deploy-infra.sh to create the 'edge-wizard' Keycloak client." >&2
  exit 1
}
[ -x "$SCRIPT_DIR/.venv/bin/python" ] || {
  echo "edge/.venv is missing — run ./edge/flash-device.sh once to build it." >&2
  exit 1
}

# Warn at startup rather than at the moment someone plugs a board in. This is
# the group set the service will actually have — a stale one here is invisible
# until a flash fails, because usermod does not affect a running process.
if ! id -nG | tr ' ' '\n' | grep -qx dialout; then
    echo "WARNING: $(id -un) is not in the dialout group in THIS process." >&2
    echo "         Flashing will fail with 'not writable'. Fix on the host:" >&2
    echo "             sudo usermod -aG dialout $(id -un)" >&2
    echo "             sudo systemctl restart user@$(id -u)" >&2
    echo "         (restarting the service alone is not enough — it respawns" >&2
    echo "          from user@.service, which holds the old group set)" >&2
fi

SPOOL="$(mktemp -d "${TMPDIR:-/tmp}/cea-wizard-daemon.XXXXXX")"
chmod 700 "$SPOOL"
trap 'rm -rf "$SPOOL"' EXIT INT TERM HUP

_lan="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
_ts="$(tailscale ip -4 2>/dev/null | head -1 || true)"
HOST_ARGS=()
for h in ${_lan:+$_lan} ${_ts:+$_ts} 127.0.0.1 localhost; do HOST_ARGS+=(--allowed-host "$h:$PORT"); done
# The name the config UI links to, forwarded here by the ingress (apps/edge-wizard).
[ -n "${ONBOARD_DOMAIN:-}" ] && HOST_ARGS+=(--allowed-host "https://$ONBOARD_DOMAIN")

ROLE_ARGS=()
[ -n "${EDGE_WIZARD_ROLE:-}" ] && ROLE_ARGS=(--required-role "$EDGE_WIZARD_ROLE")

echo "CEA edge onboarding wizard on port $PORT — sign in with Keycloak realm ${KEYCLOAK_REALM:-medcea}"
echo "  runs act as the person who presses Start"
[ -n "${ONBOARD_DOMAIN:-}" ] && echo "  https://$ONBOARD_DOMAIN/"
for h in ${_lan:+$_lan} ${_ts:+$_ts} 127.0.0.1; do echo "  http://$h:$PORT/"; done

# The secret goes in the environment of this one process, not on its command
# line: argv is readable by every account on the host (/proc/<pid>/cmdline), and
# wizard_server pops it, so the flash runs it starts do not inherit it either.
EDGE_WIZARD_SECRET="$EDGE_WIZARD_SECRET" exec python3 "$SCRIPT_DIR/src/host/wizard_server.py" \
  --dir "$SPOOL" --token unused --port "$PORT" --bind "$BIND" \
  --daemon --repo-root "$REPO_ROOT" \
  --onboard-url "https://${CONFIG_DOMAIN:-config.example.invalid}/#devices" \
  --auth keycloak \
  --issuer "https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM:-medcea}" \
  --client-id "${EDGE_WIZARD_CLIENT:-edge-wizard}" \
  --oidc-insecure "${ROLE_ARGS[@]}" "${HOST_ARGS[@]}"
