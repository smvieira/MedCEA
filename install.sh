#!/bin/bash
# =============================================================================
# install.sh — the one entry point: install, update and uninstall MedCEA
# =============================================================================
# Runs the existing scripts in order and adds nothing they do not already do:
#   install    deploy-infra.sh → deploy-apps.sh --all → health-check.sh
#   uninstall  deploy-apps.sh --uninstall / deploy-infra.sh --reset / --uninstall
# Each of those also works on its own. Run from anywhere; it changes to the
# repository root because every script reads config.env relative to it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
    cat <<'EOF'
Usage: ./install.sh [option]

Install / update
  (no option)            Install or update everything: infrastructure, then the
                         applications, then a health check. Asks for any missing
                         settings first. Safe to re-run: finished steps are
                         skipped or updated in place.
  --configure            Review every setting (current values as defaults), then install.
  --infra-only           Only the infrastructure (MicroK8s, Postgres, Keycloak, Grafana,
                         Node-RED, portal, AI workbench).
  --apps-only            Only the applications (database schema, onboarding wizard,
                         config UI, scheduler, monitor, reports, Node-RED flows).
                         Needs the infrastructure.

Uninstall
  --uninstall-apps [component ...]
                         Remove application components — all, or the ones named
                         (database edge-wizard frontend monitor node-red report scheduler).
                         The infrastructure keeps running; database contents are kept.
      --purge-data       ...and drop the database medcea_db with all its data.
  --uninstall-infra      Remove every platform service, every application and ALL data
                         (the whole namespace). Keeps MicroK8s, so reinstalling is fast.
  --uninstall-all        Total uninstall: everything above plus MicroK8s itself, the
                         onboarding wizard service, edge/.venv, logs and credentials
                         files. Asks before deleting config.env and the platform CA.

  -h, --help             Show this help.

Each uninstall lists what it removes and asks you to type a word to confirm.
EOF
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

cd "$SCRIPT_DIR" || exit 1

MODE="install"; CONFIGURE=""; PURGE=""; declare -a COMPONENTS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --configure)        CONFIGURE="--configure" ;;
        --infra-only)       MODE="infra" ;;
        --apps-only)        MODE="apps" ;;
        --uninstall-apps)   MODE="uninstall-apps" ;;
        --purge-data)       PURGE="--purge-data" ;;
        --uninstall-infra)  MODE="uninstall-infra" ;;
        --uninstall-all)    MODE="uninstall-all" ;;
        -*)                 echo -e "${RED}Unknown option: $1${NC} (see ./install.sh --help)" >&2; exit 1 ;;
        *)  [[ "$MODE" == "uninstall-apps" ]] || { echo -e "${RED}Unexpected argument: $1${NC}" >&2; exit 1; }
            COMPONENTS+=("$1") ;;
    esac
    shift
done
[[ -n "$PURGE" && "$MODE" != "uninstall-apps" ]] && { echo -e "${RED}--purge-data goes with --uninstall-apps.${NC}" >&2; exit 1; }
[[ -n "$CONFIGURE" && "$MODE" != "install" && "$MODE" != "infra" ]] && { echo -e "${RED}--configure goes with an install.${NC}" >&2; exit 1; }

# One deploy at a time; the stages below inherit the lock (infra/lib-lock.sh).
source "$SCRIPT_DIR/infra/lib-lock.sh"
medcea_lock

# deploy-infra.sh leaves the credentials box to us (see infra/lib-credentials.sh).
export MEDCEA_INSTALLER=1

stage() { echo ""; echo -e "${GREEN}${BOLD}━━━━ $* ━━━━${NC}"; }

# with_mk8s_group CMD... — run CMD with the microk8s group active. On a fresh
# install bootstrap-infra.sh has just added the user to the group, but this
# session predates that, so every plain `microk8s` call would fail (or need
# sudo). sg starts CMD in the group straight away, keeping the environment and
# the terminal. A no-op when the session already has the group.
with_mk8s_group() {
    local me; me="$(id -un)"
    if id -nG | tr ' ' '\n' | grep -qx microk8s \
       || ! getent group microk8s | cut -d: -f4 | tr ',' '\n' | grep -qx "$me" \
       || ! command -v sg >/dev/null 2>&1; then
        "$@"
        return
    fi
    sg microk8s -c "$(printf '%q ' "$@")"
}

# run_stage LABEL LOG_PREFIX COMMAND... — stop with directions if it fails.
run_stage() {
    local label="$1" prefix="$2"; shift 2
    stage "$label"
    "$@"; local rc=$?
    if [[ $rc -ne 0 ]]; then
        local log; log="$(ls -t logs/"$prefix"-*.log 2>/dev/null | head -1)"
        echo ""
        echo -e "${RED}${BOLD}Stopped: \"$label\" failed (exit $rc).${NC}"
        [[ -n "$log" ]] && echo -e "  Log: ${BOLD}$log${NC}"
        echo "  Fix the cause and run ./install.sh again — finished steps are skipped or updated in place."
        exit "$rc"
    fi
}

# confirm WORD — for the uninstall options; requires a terminal.
confirm() {
    [[ -t 0 ]] || { echo -e "${RED}Refusing to uninstall without a terminal to confirm on.${NC}" >&2; exit 1; }
    local ans
    read -r -p "Type '$1' to confirm: " ans || exit 1
    [[ "$ans" == "$1" ]] || { echo "Aborted."; exit 0; }
    export MEDCEA_CONFIRMED=1
}

# workbench_homes NS — before an uninstall that deletes the namespace: list each AI
# workbench home it would delete and how to keep it (infra/lib-workbench-homes.sh).
# Never asks for sudo: without the microk8s group it tries `sudo -n` and otherwise
# prints a short warning.
workbench_homes() {
    source "$SCRIPT_DIR/infra/lib-workbench-homes.sh"
    command -v microk8s >/dev/null 2>&1 || return 0
    local k="sudo -n microk8s kubectl"
    microk8s status --timeout 5 >/dev/null 2>&1 && k="microk8s kubectl"
    KUBECTL="$k" workbench_homes_warn "${1:-medcea}"
}

ask_delete() {   # ask_delete "question" → 0 = delete, 1 = keep (the default)
    local ans
    read -r -p "$1 (y/N): " ans || return 1
    [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

finish_with_credentials() {
    source "$SCRIPT_DIR/infra/lib-credentials.sh"
    # Certificate trust steps first, so the credentials box stays the last thing on screen.
    local ip portal
    ip="$( (source ./config.env; echo "$PLATFORM_IP") 2>/dev/null)"
    portal="$( (source ./config.env; echo "$PORTAL_DOMAIN") 2>/dev/null)"
    show_ca_trust "$SCRIPT_DIR/.ca/ca.crt" "$ip" "$portal"
    local f; f="$(latest_credentials "$SCRIPT_DIR")"
    [[ -n "$f" ]] && show_credentials "$f"
}

case "$MODE" in
# -----------------------------------------------------------------------------
install)
    run_stage "1/3  Infrastructure" deploy-infra ./deploy-infra.sh $CONFIGURE
    run_stage "2/3  Applications"   deploy-apps  with_mk8s_group ./deploy-apps.sh --all
    stage "3/3  Health check"
    with_mk8s_group ./health-check.sh || echo -e "${YELLOW}Some checks failed — see above. Services that are still starting usually pass a minute later: ./health-check.sh${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}MedCEA is installed.${NC} Start at the service portal: https://$( (source ./config.env; echo "$PORTAL_DOMAIN") 2>/dev/null)"
    finish_with_credentials
    ;;
infra)
    run_stage "Infrastructure" deploy-infra ./deploy-infra.sh $CONFIGURE
    echo -e "${YELLOW}The applications are not installed yet: ./install.sh --apps-only${NC}"
    finish_with_credentials
    ;;
apps)
    [[ -f config.env ]] || { echo -e "${RED}No config.env — install the infrastructure first: ./install.sh${NC}" >&2; exit 1; }
    run_stage "Applications" deploy-apps with_mk8s_group ./deploy-apps.sh --all
    ;;
# -----------------------------------------------------------------------------
uninstall-apps)
    # deploy-apps.sh lists what goes, validates the names and asks (including
    # the project name for --purge-data).
    run_stage "Uninstall applications" uninstall-apps with_mk8s_group ./deploy-apps.sh --uninstall $PURGE "${COMPONENTS[@]}"
    ;;
uninstall-infra)
    NS="$( (source ./config.env; echo "$NAMESPACE") 2>/dev/null)"; NS="${NS:-medcea}"
    echo -e "${RED}${BOLD}This permanently removes, from namespace '$NS':${NC}"
    echo "  - every platform service: Postgres, Keycloak, Grafana, Node-RED, OAuth2 proxies,"
    echo "    pgAdmin, portal, MQTT broker and explorer, AI workbench"
    echo "  - every application (config UI, scheduler, monitor, reports, flows)"
    echo "  - ALL data: the database, Keycloak users, Grafana settings, workbench homes"
    echo "    (each person's notebooks; not backed up)"
    echo "  Kept: MicroK8s (cached images make reinstalling fast), config.env, the platform CA."
    echo ""
    workbench_homes "$NS"
    confirm reset
    run_stage "Uninstall infrastructure" deploy-infra-reset ./deploy-infra.sh --reset
    echo -e "Reinstall with: ${BOLD}./install.sh${NC}"
    ;;
uninstall-all)
    echo -e "${RED}${BOLD}TOTAL UNINSTALL — this permanently removes:${NC}"
    echo "  - every platform service, application and ALL data (the AI workbench homes, each"
    echo "    person's notebooks, included; not backed up)"
    echo "  - MicroK8s (and Juju, if an old install left it), all cluster data and ~/.kube"
    echo "  - the onboarding wizard user service (cea-edge-wizard), edge/.venv"
    echo "  - the MedCEA block in /etc/hosts (name-based domain)"
    echo "  - logs/ and credentials-*.txt"
    echo "  You will be asked separately about config.env and the platform CA (.ca/)."
    echo "  Kept: edge/provisioned/ (the board provisioning audit trail) and edge/firmware/ (download cache)."
    echo "  Not touched: Tailscale, packages installed by the prerequisite check, dialout group membership."
    echo ""
    workbench_homes "$( (source ./config.env; echo "$NAMESPACE") 2>/dev/null)"
    confirm uninstall
    run_stage "Remove MicroK8s and everything in it" deploy-infra ./deploy-infra.sh --uninstall

    stage "Remove host files"
    if systemctl --user cat cea-edge-wizard >/dev/null 2>&1; then
        systemctl --user disable --now cea-edge-wizard >/dev/null 2>&1 || true
        rm -f "$HOME/.config/systemd/user/cea-edge-wizard.service"
        systemctl --user daemon-reload >/dev/null 2>&1 || true
        echo "  removed the cea-edge-wizard user service"
    fi
    rm -rf edge/.venv && echo "  removed edge/.venv"
    rm -f credentials-*.txt && echo "  removed credentials files"
    rm -rf logs && echo "  removed logs/"
    if [[ -d .ca ]] && ask_delete "Delete the platform CA (.ca/)? Clients that trust it must trust the new one after a reinstall."; then
        rm -rf .ca && echo "  removed .ca/"
    fi
    if [[ -f config.env ]] && ask_delete "Delete config.env (all settings and passwords)?"; then
        # guide.sh's backups (config.env.guide-*.bak) and any temp file it left are full
        # copies of config.env, passwords included.
        rm -f config.env config.env.bak config.env.guide-*.bak config.env.guide.* && echo "  removed config.env (and guide.sh's backups of it)"
    fi
    echo ""
    echo -e "${GREEN}Total uninstall complete.${NC} Reinstall with: ${BOLD}./install.sh${NC}"
    ;;
esac
