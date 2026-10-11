#!/usr/bin/env bash
# deploy-apps.sh — Interactive installer for MedCEA application content
#
# Discovers all component deploy scripts under apps/<component>/deploy.sh
# and lets the user toggle which ones to run before confirming.
#
# Usage:
#   ./deploy-apps.sh           # interactive checkbox menu
#   ./deploy-apps.sh --all     # install all without prompting
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
Usage: ./deploy-apps.sh [--all | --help]

  (no args)   Interactive checkbox menu — toggle components, then confirm
  --all       Install all components without prompting
  --help      Show this message
EOF
    exit 0
fi

INSTALL_ALL=false
[[ "${1:-}" == "--all" ]] && INSTALL_ALL=true

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
