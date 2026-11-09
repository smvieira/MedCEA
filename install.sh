#!/bin/bash
# =============================================================================
# install.sh — the one entry point: install, update and uninstall MedCEA
# =============================================================================
# Runs the existing scripts in order and adds nothing they do not already do:
#   install    deploy-infra.sh → deploy-apps.sh --all [→ deploy-infra.sh] → health-check.sh
#              (the second deploy-infra.sh only while IAM_DB_SERVICE_ROLES is true:
#              Grafana and pgAdmin onto their own database roles)
#   uninstall  deploy-apps.sh --uninstall / deploy-infra.sh --reset / --uninstall
# Each of those also works on its own. Run from anywhere; it changes to the
# repository root because every script reads config.env relative to it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
    local comps
    comps="$(find "$SCRIPT_DIR/apps" -mindepth 2 -maxdepth 2 -name uninstall.sh -printf '%h\n' 2>/dev/null | xargs -n1 basename 2>/dev/null | sort | tr '\n' ' ')"
    comps="${comps% }"
    cat <<EOF
Usage: ./install.sh [option]

Install / update
  (no option)            Install or update everything: infrastructure, then the
                         applications, then a health check. Asks for any missing
                         settings first. Safe to re-run: finished steps are
                         skipped or updated in place. While IAM_DB_SERVICE_ROLES is
                         true (a new config.env's default) the infrastructure is
                         deployed once more after the applications, so Grafana and
                         pgAdmin move onto their own database roles.
  --configure            Review every setting (current values as defaults), then install.
  --infra-only           Only the infrastructure (MicroK8s, Postgres, Keycloak, Grafana,
                         Node-RED, portal, AI workbench).
  --break-glass "<reason>"
                         With an install: policy break-glass for this run (IAM 4.2a). Needs
                         an exported MEDCEA_POLICY_FILE; compiles its matrix and waivers
                         (never the skeleton). Asks for the typed word break-glass once;
                         deploy-infra and deploy-apps each record it (two events). Without
                         this option an exported MEDCEA_POLICY_FILE is ignored.
  --apps-only            Only the applications (database schema, User Manager, iam-api,
                         onboarding wizard, config UI, scheduler, monitor, reports,
                         Node-RED flows, MQTT Explorer, nightly backup). Needs the
                         infrastructure. The backup step asks for sudo once when
                         BACKUP_DIR's parent is not writable (it creates the folder).

Uninstall
  --uninstall-apps [component ...]
                         Remove application components — all, or the ones named
                         ($comps).
                         The infrastructure keeps running; database contents are kept.
      --purge-data       ...and drop the database medcea_db with all its data.
  --uninstall-infra      Remove every platform service, every application and ALL data
                         (the whole namespace). Keeps MicroK8s, so reinstalling is fast.
  --uninstall-all        Total uninstall: everything above plus MicroK8s itself, the
                         onboarding wizard service, edge/.venv, Superset's wheel cache,
                         logs and credentials files. Asks before deleting config.env and
                         the platform CA.

  -h, --help             Show this help.

Each uninstall lists what it removes and asks you to type a word to confirm.
EOF
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

cd "$SCRIPT_DIR" || exit 1

MODE="install"; CONFIGURE=""; PURGE=""; BREAK_GLASS=""; declare -a COMPONENTS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --configure)        CONFIGURE="--configure" ;;
        --break-glass)      [[ -n "${2:-}" && "${2:-}" != -* ]] || { echo -e "${RED}--break-glass needs a reason: --break-glass \"<reason>\"${NC}" >&2; exit 1; }
                            BREAK_GLASS="$2"; shift ;;
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
[[ -n "$BREAK_GLASS" && "$MODE" != "install" && "$MODE" != "infra" && "$MODE" != "apps" ]] && { echo -e "${RED}--break-glass goes with an install.${NC}" >&2; exit 1; }
if [[ -n "$BREAK_GLASS" ]]; then
    [[ -n "${MEDCEA_POLICY_FILE:-}" ]] || { echo -e "${RED}--break-glass needs MEDCEA_POLICY_FILE (export MEDCEA_POLICY_FILE=<your policy file>)${NC}" >&2; exit 1; }
    [[ -r "$MEDCEA_POLICY_FILE" ]] || { echo -e "${RED}MEDCEA_POLICY_FILE=$MEDCEA_POLICY_FILE cannot be read${NC}" >&2; exit 1; }
fi

# One deploy at a time; the stages below inherit the lock (infra/lib-lock.sh).
source "$SCRIPT_DIR/infra/lib-lock.sh"
medcea_lock

# deploy-infra.sh leaves the credentials box to us (see infra/lib-credentials.sh).
export MEDCEA_INSTALLER=1

# Policy break-glass (IAM 4.2a, design §14.4.6): asked once here, for both stages; each
# stage records its own break_glass_seen. Without --break-glass an exported override is
# dropped, so it never reaches a deploy by accident.
declare -a APPS_BG=()
if [[ -n "$BREAK_GLASS" ]]; then
    ( : <>/dev/tty ) 2>/dev/null || { echo -e "${RED}break-glass needs a person at the terminal to type the word break-glass: nothing was changed${NC}" >&2; exit 1; }
    {
        echo -e "${RED}BREAK-GLASS requested${NC}: compile $MEDCEA_POLICY_FILE in every stage of this install"
        echo "  reason: $BREAK_GLASS"
        echo "  this changes the matrix and waivers every compile of this run reads; it is recorded"
        echo "  (it never changes the skeleton: a widening git skeleton is refused under break-glass too)"
        echo -n "Type break-glass to go on: "
    } >/dev/tty
    _bg_word=""; read -r _bg_word </dev/tty || _bg_word=""
    [[ "$_bg_word" == break-glass ]] || { echo -e "${RED}break-glass not confirmed: nothing was changed${NC}" >&2; exit 1; }
    export MEDCEA_POLICY_BREAK_GLASS="$BREAK_GLASS" MEDCEA_POLICY_BREAK_GLASS_ASKED="$MEDCEA_LOCK_HELD"
    APPS_BG=(--break-glass "$BREAK_GLASS")
else
    if [[ -n "${MEDCEA_POLICY_FILE:-}${MEDCEA_POLICY_BREAK_GLASS:-}" ]]; then
        echo -e "${YELLOW}MEDCEA_POLICY_FILE / MEDCEA_POLICY_BREAK_GLASS are ignored without --break-glass \"<reason>\"${NC}" >&2
    fi
    unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS MEDCEA_POLICY_BREAK_GLASS_ASKED
fi

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

# data_volumes NS — before an uninstall that deletes the namespace: list each AI
# workbench home and Grafana's volume it would delete, and how to keep them
# (infra/lib-data-volumes.sh).
# Never asks for sudo: without the microk8s group it tries `sudo -n` and otherwise
# prints a short warning.
data_volumes() {
    source "$SCRIPT_DIR/infra/lib-data-volumes.sh"
    command -v microk8s >/dev/null 2>&1 || return 0
    local k="sudo -n microk8s kubectl"
    microk8s status --timeout 5 >/dev/null 2>&1 && k="microk8s kubectl"
    # In a subshell with config.env, so backup_dir() sees the BACKUP_DIR configure.sh asked for.
    ( [[ -f config.env ]] && source ./config.env
      KUBECTL="$k" data_volumes_warn "${1:-medcea}" )
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

# cfg_switch KEY — the value of KEY's one active line in config.env, unquoted; nothing when
# config.env is missing or KEY has zero or several active lines.
cfg_switch() {
    local k="$1" hits
    [[ -f config.env ]] || return 0
    hits="$(grep -cE "^[[:space:]]*(export[[:space:]]+)?${k}=" config.env 2>/dev/null)" || true
    [[ "$hits" == 1 ]] || return 0
    grep -E "^[[:space:]]*(export[[:space:]]+)?${k}=" config.env | sed -E "s/^[^=]*=//; s/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/^[\"']//; s/[\"']$//"
}

# One line after a fresh install: a new config.env has the sign-in gates, network
# policies and the services' own database logins on, but token checks, database roles
# and enforcement off (each has its own rollback). config.env is read the way medcea.sh reads it — never sourced: each switch
# must be one active line, literally "true" or "false"; anything else is not counted.
# Never fails the install.
iam_switches_hint() {
    local k off=0
    [[ -f config.env ]] || return 0
    for k in IAM_GATES IAM_NETPOL IAM_POSTGREST_JWT IAM_DB_SERVICE_ROLES IAM_DB_ROLES IAM_ENFORCE IAM_MQTT_PERSON; do
        [[ "$(cfg_switch "$k")" == false ]] && off=$(( off + 1 ))
    done
    (( off )) && echo -e "${YELLOW}$off IAM switch(es) still false. To turn on the rest in order: ./medcea.sh → IAM switches → \"Bring IAM to full enforcement\".${NC}"
    return 0
}

# One line when the applications stage skipped Superset because IAM_DB_SERVICE_ROLES is
# not true (Superset stage C, A2b: its data connection is svc_superset, never postgres).
# Read from the newest deploy-apps log, which holds apps/superset/deploy.sh's skip line;
# the fix is that switch's recipe, then the Superset deploy. A new config.env has the switch
# true, but a reinstall that kept its config.env (or an older install) keeps false, so the
# hint stays for those. Never fails the install.
superset_skip_hint() {
    local log
    log="$(ls -t logs/deploy-apps-*.log 2>/dev/null | head -1)"
    [[ -n "$log" ]] || return 0
    if grep -qF "skipped: Superset needs IAM_DB_SERVICE_ROLES=true" "$log" 2>/dev/null; then
        echo -e "${YELLOW}Still to do: Superset was skipped, it needs IAM_DB_SERVICE_ROLES=true. Turn it on (./medcea.sh → IAM switches → IAM_DB_SERVICE_ROLES, or \"Bring IAM to full enforcement\"), then ./apps/superset/deploy.sh.${NC}"
    # The version-N guard: the iam deploy's bootstrap waited (apply.sh --bootstrap rc 2), and
    # nothing later in the install deploys Superset again.
    elif grep -qF "skipped: no version of the access policy is applied yet" "$log" 2>/dev/null; then
        echo -e "${YELLOW}Still to do: Superset was skipped, no version of the access policy is applied yet. Once ./apps/iam/deploy.sh has applied version 1 (./apps/iam/apply.sh --status), run ./apps/superset/deploy.sh.${NC}"
    fi
    return 0
}

# --apps-only under IAM_DB_SERVICE_ROLES=true: the full install runs deploy-infra once more
# after the applications (Grafana and pgAdmin onto their roles); this mode does not run the
# infrastructure, so it says so instead. Never fails.
service_roles_infra_hint() {
    [[ "$(cfg_switch IAM_DB_SERVICE_ROLES)" == true ]] || return 0
    echo -e "${YELLOW}Still to do, unless ./deploy-infra.sh has run since this database deploy: ./deploy-infra.sh, so Grafana and pgAdmin move onto their own database roles (IAM_DB_SERVICE_ROLES is true; health-check dbclients names any client still on postgres).${NC}"
    return 0
}

# remove_wheel_cache — Superset's wheel cache, which deploy-infra.sh created (a cache:
# unlike BACKUP_DIR it holds nothing that is not on PyPI). Only its *.whl files are deleted,
# then the folder and /var/lib/<project> with rmdir, so a SUPERSET_WHEEL_DIR pointed at a
# folder holding anything else keeps it (said so). sudo for what the account may not
# remove: the parent is root's. Never fails the uninstall.
remove_wheel_cache() {
    local d parent prompt
    d="$( ( [[ -f config.env ]] && source ./config.env
            source "$SCRIPT_DIR/apps/superset/lib-superset.sh"
            superset_wheel_dir ) 2>/dev/null)" || return 0
    [[ -n "$d" && -d "$d" ]] || return 0
    parent="/var/lib/$( ( [[ -f config.env ]] && source ./config.env; echo "${PROJECT_NAME:-medcea}") 2>/dev/null)"
    prompt="[sudo] password for %u (to remove Superset's wheel cache $d): "
    find "$d" -maxdepth 1 -type f -name '*.whl' -delete 2>/dev/null \
        || sudo -p "$prompt" find "$d" -maxdepth 1 -type f -name '*.whl' -delete || true
    if [[ -n "$(ls -A "$d" 2>/dev/null)" ]]; then
        echo -e "  ${YELLOW}kept $d: it holds more than Superset's wheels${NC}"
        return 0
    fi
    if rmdir "$d" 2>/dev/null || sudo -p "$prompt" rmdir "$d"; then
        echo "  removed Superset's wheel cache $d"
    else
        echo -e "  ${YELLOW}could not remove $d${NC}"
        return 0
    fi
    if [[ "$(dirname "$d")" == "$parent" && -d "$parent" ]] && [[ -z "$(ls -A "$parent" 2>/dev/null)" ]]; then
        { rmdir "$parent" 2>/dev/null || sudo -p "$prompt" rmdir "$parent"; } \
            && echo "  removed $parent (empty)"
    fi
    return 0
}

# One line when deploy-infra added this account to dialout but could not restart
# its user service manager (a desktop run): the onboarding wizard's process still
# lacks the group, so it cannot open the USB port until a reboot. Never fails.
usb_group_hint() {
    local gid pid
    gid="$(getent group dialout 2>/dev/null | cut -d: -f3)"
    [[ -n "$gid" ]] || return 0
    id -nG "$(id -un)" 2>/dev/null | tr ' ' '\n' | grep -qx dialout || return 0
    pid="$(systemctl --user show -p MainPID --value cea-edge-wizard 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
    awk '/^Groups:/ { for (i = 2; i <= NF; i++) print $i }' "/proc/$pid/status" 2>/dev/null | grep -qx "$gid" && return 0
    echo -e "${YELLOW}The onboarding wizard does not have group dialout yet, so it cannot open a board's USB port. Reboot the host once (or, signed out of the desktop, from SSH: sudo systemctl restart user@$(id -u)).${NC}"
    return 0
}

case "$MODE" in
# -----------------------------------------------------------------------------
install)
    run_stage "1/3  Infrastructure" deploy-infra ./deploy-infra.sh $CONFIGURE
    run_stage "2/3  Applications"   deploy-apps  with_mk8s_group ./deploy-apps.sh --all "${APPS_BG[@]}"
    # config.env is read only now: the first stage creates or completes it.
    if [[ "$(cfg_switch IAM_DB_SERVICE_ROLES)" == true ]]; then
        # The switch's enable recipe (medcea.sh): the database deploy in the applications
        # stage has just let the service roles log in, and Grafana and pgAdmin, deployed by
        # the first stage before that, are still on postgres. Under the same lock and
        # MEDCEA_INSTALLER (the credentials box stays last); with --break-glass this run
        # records its break_glass_seen too. A failure stops here like any stage.
        echo ""
        echo "IAM_DB_SERVICE_ROLES is true: the infrastructure runs once more, so Grafana and pgAdmin move onto their own database roles (svc_grafana, rr_admin_login) now that the database lets them log in."
        run_stage "2/3  Infrastructure again (Grafana and pgAdmin onto their database roles)" deploy-infra with_mk8s_group ./deploy-infra.sh
    fi
    stage "3/3  Health check"
    with_mk8s_group ./health-check.sh || echo -e "${YELLOW}Some checks failed — see above. Services that are still starting usually pass a minute later: ./health-check.sh${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}MedCEA is installed.${NC} Start at the service portal: https://$( (source ./config.env; echo "$PORTAL_DOMAIN") 2>/dev/null)"
    iam_switches_hint || true      # before the box, which stays the last thing on screen
    superset_skip_hint || true
    usb_group_hint || true
    finish_with_credentials
    ;;
infra)
    run_stage "Infrastructure" deploy-infra ./deploy-infra.sh $CONFIGURE
    echo -e "${YELLOW}The applications are not installed yet: ./install.sh --apps-only${NC}"
    finish_with_credentials
    ;;
apps)
    [[ -f config.env ]] || { echo -e "${RED}No config.env — install the infrastructure first: ./install.sh${NC}" >&2; exit 1; }
    run_stage "Applications" deploy-apps with_mk8s_group ./deploy-apps.sh --all "${APPS_BG[@]}"
    superset_skip_hint || true
    service_roles_infra_hint || true
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
    echo "  - ALL data: the database, Keycloak users, Grafana's volume (the dashboards Editors"
    echo "    made in the browser), workbench homes (each person's notebooks); copied only by"
    echo "    the nightly backup, if deployed: BACKUP_DIR is kept"
    echo "  Kept: MicroK8s (cached images make reinstalling fast), config.env, the platform CA."
    echo ""
    data_volumes "$NS"
    confirm reset
    run_stage "Uninstall infrastructure" deploy-infra-reset ./deploy-infra.sh --reset
    echo -e "Reinstall with: ${BOLD}./install.sh${NC}"
    ;;
uninstall-all)
    echo -e "${RED}${BOLD}TOTAL UNINSTALL — this permanently removes:${NC}"
    echo "  - every platform service, application and ALL data (the AI workbench homes, each"
    echo "    person's notebooks, and Grafana's volume, Editors' own dashboards, included;"
    echo "    copied only by the nightly backup, if deployed: BACKUP_DIR is kept)"
    echo "  - MicroK8s (and Juju, if an old install left it), all cluster data and ~/.kube"
    echo "  - the onboarding wizard user service (cea-edge-wizard), edge/.venv"
    echo "  - Superset's wheel cache (SUPERSET_WHEEL_DIR; and /var/lib/<project> when that is left empty)"
    echo "  - the MedCEA block in /etc/hosts (name-based domain)"
    echo "  - logs/ and credentials-*.txt"
    echo "  You will be asked separately about config.env and the platform CA (.ca/)."
    echo "  Kept: edge/provisioned/ (the board provisioning audit trail) and edge/firmware/ (download cache)."
    echo "  Not touched: Tailscale, packages installed by the prerequisite check, dialout group membership."
    echo ""
    data_volumes "$( (source ./config.env; echo "$NAMESPACE") 2>/dev/null)"
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
    remove_wheel_cache
    rm -f credentials-*.txt && echo "  removed credentials files"
    rm -rf logs && echo "  removed logs/"
    if [[ -d .ca ]] && ask_delete "Delete the platform CA (.ca/)? Clients that trust it must trust the new one after a reinstall."; then
        rm -rf .ca && echo "  removed .ca/"
    fi
    if [[ -f config.env ]] && ask_delete "Delete config.env (all settings and passwords)?"; then
        # medcea.sh's backups (config.env.guide-*.bak) and any temp file it left are full
        # copies of config.env, passwords included.
        rm -f config.env config.env.bak config.env.guide-*.bak config.env.guide.* && echo "  removed config.env (and medcea.sh's backups of it)"
    fi
    echo ""
    echo -e "${GREEN}Total uninstall complete.${NC} Reinstall with: ${BOLD}./install.sh${NC}"
    ;;
esac
