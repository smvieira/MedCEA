#!/usr/bin/env bash
# infra/lib-banner.sh — the MedCEA logo: a potted herb, the MedCEA wordmark and its tagline,
# a mushroom (the two crops MedCEA grows).
#
#   medcea_banner full      the coloured drawing deploy-infra.sh prints at the start of a
#                           deploy (install.sh runs deploy-infra); ./medcea.sh prints it once
#                           at the start of the plain mode when stdout is a terminal
#   medcea_banner compact   six lines, 65 columns, no colour: the top of ./medcea.sh's main
#                           menu in the dialog mode, when the terminal has room for it
#
# full uses the caller's GREEN, YELLOW and NC (ANSI defaults when they are unset); when
# the caller's NC is empty (no colour: NO_COLOR, not a terminal) the drawing has none.
# A function library: it defines functions only and prints nothing when sourced.

medcea_banner() {   # medcea_banner full|compact
    case "${1:-full}" in
        full)    _medcea_banner_full ;;
        compact) _medcea_banner_compact ;;
        *)       echo "medcea_banner: full or compact, not '$1'" >&2; return 2 ;;
    esac
}

_medcea_banner_full() {
    # Herb on the left, mushroom on the right: the two crops MedCEA grows.
    # Strings are $'...' so the backslashes and the backtick in the "d" stay literal;
    # printf %s prints them uninterpreted (echo -e would read \c, \b, ... as escapes).
    local -a plant=(
        $'   .--.  .--.'
        $'  (    \\/    )'
        $'   \'--.||.--\''
        $' .--.  ||  .--.'
        $'(    \\_||_/    )'
        $' \'--.__||__.--\''
        $'       ||'
        $'   ____||____'
        $'   \\        /'
        $'    \\______/'
    )
    local -a title=(
        ''
        ''
        $' __  __            _   ____  _____     _'
        $'|  \\/  |  ___   __| | / ___|| ____|   / \\'
        $'| |\\/| | / _ \\ / _` || |    |  _|    / _ \\'
        $'| |  | ||  __/| (_| || |___ | |___  / ___ \\'
        $'|_|  |_| \\___| \\__,_| \\____||_____|/_/   \\_\\'
        ''
        $' Controlled Environment Agriculture for Medicinal Plants and Fungi'
        ''
    )
    local -a mush=(
        ''
        ''
        $'      .-~~~~-.'
        $'   .-\' o   .  \'-.'
        $'  /  .    O   o  \\'
        $' (  o   .     .   )'
        $'  \'-.__________.-\''
        $'       |    |'
        $'       |    |'
        $'    ,,,|____|,,,'
    )
    local GREEN="${GREEN-\033[0;32m}" YELLOW="${YELLOW-\033[0;33m}" NC="${NC-\033[0m}"
    local B='\033[1m' CY='\033[0;36m' RD='\033[0;31m' i pc tc mc
    [[ -z "$NC" ]] && { B=''; CY=''; RD=''; }
    echo ""
    for i in "${!plant[@]}"; do
        pc="$GREEN"; (( i >= 7 )) && pc="$YELLOW"        # leaves / pot
        tc="$B$GREEN"; [[ "${title[$i]}" == *Medicinal* ]] && tc="$CY"
        mc="$RD"; (( i >= 7 )) && mc="$NC"; (( i == 9 )) && mc="$GREEN"  # cap / stem / grass
        printf " ${pc}%-16s${NC}  ${tc}%-44s${NC}  ${mc}%s${NC}\n" "${plant[$i]}" "${title[$i]}" "${mush[$i]}"
    done
    echo ""
}

_medcea_banner_compact() {   # the owner-approved variation (9 Nov 2026), printed as it is
    cat <<'MEDCEA_BANNER'
  .--.  .--.    __  __          _  ___  ___    _       .-~~~~-.
 (    \/    )  |  \/  | ___  __| |/ __|| __|  /_\   .' o  .  O '.
  '--.||.--'   | |\/| |/ -_)/ _` | (__ | _|  / _ \ (____________)
   ___||___    |_|  |_|\___|\__,_|\___||___|/_/ \_\     |    |
   \______/    Controlled Environment Agriculture   ,,,|____|,,,
               for Medicinal Plants and Fungi
MEDCEA_BANNER
}
