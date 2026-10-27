#!/usr/bin/env bash
# deploy-apps.sh — Interactive installer for MedCEA application content
#
# Discovers all component deploy scripts under apps/<component>/deploy.sh
# and lets the user toggle which ones to run before confirming.
#
# Usage:
#   ./deploy-apps.sh           # interactive checkbox menu
#   ./deploy-apps.sh --all     # install all without prompting
#   ./deploy-apps.sh --uninstall [--purge-data] [component ...]
#   ./deploy-apps.sh --help

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="$REPO_ROOT/apps"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
else
    BOLD=''; GREEN=''; YELLOW=''; CYAN=''; RED=''; DIM=''; NC=''
fi

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<EOF
Usage: ./deploy-apps.sh [--all | --uninstall [--purge-data] [component ...] | --help]

  (no args)   Interactive checkbox menu — toggle components, then confirm
  --all       Install all components without prompting
  --uninstall Remove app components (all, or the ones named) by running each
              apps/<component>/uninstall.sh. Infrastructure keeps running and
              database contents are kept.
  --purge-data  With --uninstall of database (or of everything): also drop
              medcea_db and its roles. Asks for the project name to confirm.
  --help      Show this message

Components: $(find "$APPS_DIR" -mindepth 2 -maxdepth 2 -name deploy.sh -printf '%h\n' | xargs -n1 basename | sort | tr '\n' ' ')
EOF
    exit 0
fi

INSTALL_ALL=false
[[ "${1:-}" == "--all" ]] && INSTALL_ALL=true
UNINSTALL=false
PURGE_DATA=false
declare -a UNINSTALL_ONLY=()
if [[ "${1:-}" == "--uninstall" ]]; then
    UNINSTALL=true
    shift
    for _a in "$@"; do
        case "$_a" in
            --purge-data) PURGE_DATA=true ;;
            -*) echo "Unknown option: $_a (see --help)" >&2; exit 1 ;;
            *)  UNINSTALL_ONLY+=("$_a") ;;
        esac
    done
fi

# One deploy at a time; the component scripts inherit the lock (infra/lib-lock.sh).
source "$REPO_ROOT/infra/lib-lock.sh"
medcea_lock

# Host packages (curl, python3, ...) — the same check deploy-infra.sh runs, for
# when apps are deployed on their own. Before logging, so the prompt is not teed.
source "$REPO_ROOT/infra/lib-prereqs.sh"
check_prereqs

# ---------------------------------------------------------------------------
# Uninstall — each component's apps/<component>/uninstall.sh, in reverse
# install order (install is alphabetical, so database goes last: the apps that
# use it are gone before it is dropped).
# ---------------------------------------------------------------------------
if $UNINSTALL; then
    declare -a TARGETS=()
    while IFS= read -r _u; do
        TARGETS+=("$(basename "$(dirname "$_u")")")
    done < <(find "$APPS_DIR" -mindepth 2 -maxdepth 2 -name "uninstall.sh" | sort -r)
    if [[ ${#UNINSTALL_ONLY[@]} -gt 0 ]]; then
        for _c in "${UNINSTALL_ONLY[@]}"; do
            [[ -f "$APPS_DIR/$_c/uninstall.sh" ]] \
                || { echo -e "${RED}Unknown component '$_c'. Components with an uninstall: ${TARGETS[*]}${NC}" >&2; exit 1; }
        done
        declare -a _kept=()
        for _c in "${TARGETS[@]}"; do
            printf '%s\n' "${UNINSTALL_ONLY[@]}" | grep -qx "$_c" && _kept+=("$_c")
        done
        TARGETS=("${_kept[@]}")
    fi
    _db=false; printf '%s\n' "${TARGETS[@]}" | grep -qx database && _db=true
    if $PURGE_DATA && ! $_db; then
        echo -e "${RED}--purge-data only applies when 'database' is uninstalled too.${NC}" >&2; exit 1
    fi

    echo -e "${BOLD}This removes these app components:${NC} ${TARGETS[*]}"
    echo "  Infrastructure (Postgres, Keycloak, Grafana, Node-RED, portal, ...) keeps running."
    if $PURGE_DATA; then
        echo -e "  ${RED}--purge-data: database '${POSTGRES_DB:-medcea_db}' and ALL its data are dropped permanently.${NC}"
    elif $_db; then
        echo "  Database contents are kept (add --purge-data to drop them)."
    fi
    # install.sh asks once and sets MEDCEA_CONFIRMED; standalone use asks here.
    if [[ "${MEDCEA_CONFIRMED:-}" != "1" ]]; then
        [[ -t 0 ]] || { echo -e "${RED}Refusing to uninstall without a terminal to confirm on.${NC}" >&2; exit 1; }
        read -r -p "Type 'apps' to confirm: " _ok || exit 1
        [[ "$_ok" == "apps" ]] || { echo "Aborted."; exit 0; }
        if $PURGE_DATA; then
            source "$REPO_ROOT/config.env"
            read -r -p "Type the project name ('$PROJECT_NAME') to drop the database: " _ok || exit 1
            [[ "$_ok" == "$PROJECT_NAME" ]] || { echo "Aborted."; exit 0; }
        fi
    fi

    LOG_DIR="$REPO_ROOT/logs"; mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/uninstall-apps-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "Log: $LOG_FILE"

    FAILED=()
    for component in "${TARGETS[@]}"; do
        echo ""
        echo -e "${YELLOW}━━━ Removing: $component ━━━${NC}"
        _args=(); [[ "$component" == "database" ]] && $PURGE_DATA && _args=(--purge-data)
        if bash "$APPS_DIR/$component/uninstall.sh" "${_args[@]}"; then
            echo -e "${GREEN}✓ $component removed${NC}"
        else
            echo -e "${RED}✗ $component FAILED${NC}"; FAILED+=("$component")
        fi
    done
    echo ""
    if [[ ${#FAILED[@]} -gt 0 ]]; then
        echo -e "${RED}Failed: ${FAILED[*]} — see $LOG_FILE. Re-running is safe.${NC}"; exit 1
    fi
    echo -e "${GREEN}Apps removed. Reinstall with: ./install.sh --apps-only${NC}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Logging — tee all output to logs/deploy-apps-<timestamp>.log
# ---------------------------------------------------------------------------
LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/deploy-apps-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Log: $LOG_FILE"

# ---------------------------------------------------------------------------
# Discover components (subdirectories that contain a deploy.sh)
# ---------------------------------------------------------------------------
declare -a COMPONENTS=()
declare -a LABELS=()

while IFS= read -r deploy_script; do
    component="$(basename "$(dirname "$deploy_script")")"
    COMPONENTS+=("$component")
    label="${component//-/ }"
    label="$(echo "$label" | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2); print}')"
    LABELS+=("$label")
done < <(find "$APPS_DIR" -mindepth 2 -maxdepth 2 -name "deploy.sh" | sort)

if [[ ${#COMPONENTS[@]} -eq 0 ]]; then
    echo "No components found. Add apps/<component>/deploy.sh to register a component."
    exit 0
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║         MedCEA — App Installer           ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ---------------------------------------------------------------------------
# Selection: checkbox toggle loop
# ---------------------------------------------------------------------------
declare -a SELECTED=()

if $INSTALL_ALL; then
    SELECTED=("${COMPONENTS[@]}")
else
    # Initialise all to unchecked (0=off, 1=on)
    declare -a CHECKED=()
    for _ in "${COMPONENTS[@]}"; do CHECKED+=(0); done

    _print_menu() {
        echo -e "${CYAN}Select components to install:${NC}"
        echo ""
        for i in "${!COMPONENTS[@]}"; do
            local num=$((i + 1))
            if [[ "${CHECKED[$i]}" -eq 1 ]]; then
                echo -e "  ${GREEN}[x]${NC} ${BOLD}${num}.${NC} ${LABELS[$i]}"
            else
                echo -e "  ${DIM}[ ]${NC} ${BOLD}${num}.${NC} ${LABELS[$i]}"
            fi
        done
        echo ""
        echo -e "  ${YELLOW}a${NC}  Select all    ${YELLOW}n${NC}  Select none"
        echo -e "  ${YELLOW}↵${NC}  Install selected components"
        echo -e "  ${YELLOW}q${NC}  Quit"
        echo ""
        echo -en "${CYAN}Toggle [number / a / n / Enter to confirm]:${NC} "
    }

    while true; do
        _print_menu
        read -r input
        input="${input,,}"

        case "$input" in
            q)
                echo "Aborted."
                exit 0
                ;;
            a)
                for i in "${!CHECKED[@]}"; do CHECKED[$i]=1; done
                ;;
            n)
                for i in "${!CHECKED[@]}"; do CHECKED[$i]=0; done
                ;;
            "")
                # Enter — confirm selection
                for i in "${!COMPONENTS[@]}"; do
                    [[ "${CHECKED[$i]}" -eq 1 ]] && SELECTED+=("${COMPONENTS[$i]}")
                done
                if [[ ${#SELECTED[@]} -eq 0 ]]; then
                    echo -e "${YELLOW}Nothing selected. Pick at least one component.${NC}"
                    echo ""
                    SELECTED=()
                    continue
                fi
                break
                ;;
            *)
                # Accept space-separated numbers for toggling multiple at once
                valid=true
                for token in $input; do
                    if [[ "$token" =~ ^[0-9]+$ ]] && \
                       [[ "$token" -ge 1 ]] && \
                       [[ "$token" -le "${#COMPONENTS[@]}" ]]; then
                        idx=$((token - 1))
                        CHECKED[$idx]=$(( 1 - CHECKED[$idx] ))  # flip
                    else
                        echo -e "${RED}  '$token' is not a valid choice — ignored${NC}"
                        valid=false
                    fi
                done
                ;;
        esac
        echo ""
    done
fi

# ---------------------------------------------------------------------------
# Confirmation summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Components to install:${NC}"
for c in "${SELECTED[@]}"; do
    echo -e "  ${GREEN}•${NC} $c"
done
echo ""

if ! $INSTALL_ALL; then
    echo -n "Proceed? [Y/n] "
    read -r confirm
    confirm="${confirm,,}"
    if [[ "$confirm" == "n" || "$confirm" == "no" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
FAILED=()

for component in "${SELECTED[@]}"; do
    deploy_script="$APPS_DIR/$component/deploy.sh"
    if [[ ! -f "$deploy_script" ]]; then
        echo -e "${RED}ERROR: $deploy_script not found — skipping${NC}"
        FAILED+=("$component")
        continue
    fi

    echo ""
    echo -e "${GREEN}━━━ Installing: $component ━━━${NC}"
    if bash "$deploy_script"; then
        echo -e "${GREEN}✓ $component installed${NC}"
    else
        echo -e "${RED}✗ $component FAILED${NC}"
        FAILED+=("$component")
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}━━━ Summary ━━━${NC}"
for component in "${SELECTED[@]}"; do
    if printf '%s\n' "${FAILED[@]}" | grep -qx "$component" 2>/dev/null; then
        echo -e "  ${RED}✗ $component${NC}"
    else
        echo -e "  ${GREEN}✓ $component${NC}"
    fi
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}${#FAILED[@]} component(s) failed. Check output above.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}All done.${NC}"
