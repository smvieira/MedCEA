#!/usr/bin/env bash
# guide.sh — a question-and-answer guide to the MedCEA commands
#
#   ./guide.sh [--dry-run] [--help]
#
# Walks a tree of menus — area (install, infrastructure, applications, operators and
# units, IAM switches, health and tests, edge devices, policy) → action → the questions
# that action needs — then shows the exact command, what it changes, whether it takes
# the deploy lock or needs sudo, and runs it once you confirm: [Y/n] for a read-only
# command, [y/N] for one that changes something, and the word yes typed in full for a
# destructive one (an uninstall, --purge-data, --reset, --bootstrap, erasing a board).
# Answers are checked the way the target script checks them (unit codes, uuids, component
# names on disk); the --by username is remembered for the session.
#
# IAM switches (IAM_GATES, IAM_NETPOL, IAM_ENFORCE, IAM_POSTGREST_JWT,
# IAM_DB_SERVICE_ROLES, IAM_DB_ROLES) and WORKBENCH_ENABLED: shows the current value (the
# one active line in config.env; zero or several active lines are refused), the ordered
# recipe for enabling or rolling back with its preconditions, then sets the value (that
# one line, a backup config.env.guide-<timestamp>.bak next to it, the diff shown) and runs
# the steps in order, stopping at the first that fails. After a recipe that completed it
# offers to delete the backup (it holds every password); ./install.sh --uninstall-all
# deletes any that are left together with config.env.
#
# --dry-run  run nothing and change nothing: print each command, and each config.env
#            change, that would have been made. Every question and confirmation is
#            still asked.
#
# Never asks for a password or a secret: the commands it runs prompt for their own.
# Runs every command with this terminal, so their own prompts work. The commands take
# the deploy lock themselves; a switch recipe takes it once for all its steps (refused
# while another deploy runs), so config.env cannot change under a running deploy, and
# exports MEDCEA_LOCK_HELD so its steps skip their own. Ctrl-C during a recipe stops it
# and says whether config.env was already changed and how to restore it. Answers are
# read from stdin; end of input (Ctrl-D) leaves the guide. MEDCEA_GUIDE_CONFIG=FILE
# reads FILE instead of ./config.env, with --dry-run only (for tests).
#
# Exit 0 on quit; 1 when input ends; 2 for a usage error; 130 after Ctrl-C in a recipe.
# Run from anywhere:  ./guide.sh --dry-run

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n "2,$(grep -n '^# Run from anywhere' "$0" | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# No set -e: a command that fails is reported and the guide goes on.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; NC=''
fi
warn() { echo -e "${YELLOW}[guide] $*${NC}" >&2; }
die()  { local c="$1"; shift; echo -e "${RED}[guide] $*${NC}" >&2; exit "$c"; }
bye()  { echo "Bye."; exit 0; }

DRY_RUN=false
for a in "$@"; do
    case "$a" in
        --dry-run) DRY_RUN=true ;;
        -h|--help) sed -n "2,$(grep -n '^# Run from anywhere' "$0" | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die 2 "unknown argument '$a'  (./guide.sh --help)" ;;
    esac
done

# Every MedCEA script runs from the repository root (config.env is read from there).
cd "$SCRIPT_DIR" || die 2 "cannot cd to $SCRIPT_DIR"

CFG="config.env"
if [[ -n "${MEDCEA_GUIDE_CONFIG:-}" ]]; then
    # The commands it runs read ./config.env, so editing another file and then deploying
    # would deploy something else than what was shown.
    $DRY_RUN || die 2 "MEDCEA_GUIDE_CONFIG works with --dry-run only (the commands read ./config.env)"
    CFG="$MEDCEA_GUIDE_CONFIG"
fi

# ── Answers ──────────────────────────────────────────────────────────────────
# Every helper leaves its result in a global (ANSWER, PICK, LIST, COMPS) instead of
# printf -v into a caller's name, which a helper's own local of the same name would
# swallow (CLAUDE.md). End of input dies: a re-asking loop on a closed stdin would spin.

# A value spliced in as a positional argument never starts with '-': units.sh (and
# flash-device.sh) would read it as an option (a "unit code" --bootstrap would skip the
# guide's typed-yes guard).
UNIT_RE='^[A-Za-z0-9][A-Za-z0-9_-]*$'              # apps/iam/units.sh, no leading -
UNIT_HINT="a unit code is letters, digits, _ and -, starting with a letter or digit"
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
USER_RE='^[A-Za-z0-9][A-Za-z0-9._@+-]*$'            # a Keycloak username, no spaces, no leading -
USER_HINT="letters, digits and . _ @ + -, starting with a letter or digit"
NS_RE='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'             # a Kubernetes namespace
POD_RE='^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'
DB_RE='^[A-Za-z_][A-Za-z0-9_]*$'
INT_RE='^[1-9][0-9]{0,4}$'
IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
BY_USER=""                                          # --by, remembered for the session

ask() {   # ask PROMPT [DEFAULT] → ANSWER (trimmed; DEFAULT when empty)
    local prompt="$1" def="${2-}"
    if [[ -n "$def" ]]; then printf '%s [%s]: ' "$prompt" "$def"; else printf '%s: ' "$prompt"; fi
    if ! IFS= read -r ANSWER; then
        echo
        die 1 "input ended (EOF); leaving the guide"
    fi
    ANSWER="${ANSWER%$'\r'}"
    ANSWER="${ANSWER#"${ANSWER%%[![:space:]]*}"}"
    ANSWER="${ANSWER%"${ANSWER##*[![:space:]]}"}"
    [[ -z "$ANSWER" && -n "$def" ]] && ANSWER="$def"
    return 0
}

ask_match() {   # ask_match PROMPT REGEX HINT [DEFAULT] [optional] → ANSWER ("" if optional and empty)
    local prompt="$1" re="$2" hint="$3" def="${4-}" optional="${5-}"
    while :; do
        ask "$prompt" "$def"
        [[ -z "$ANSWER" && -n "$optional" ]] && return 0
        [[ "$ANSWER" =~ $re ]] && return 0
        warn "'$ANSWER': $hint"
    done
}

ask_text() {   # ask_text PROMPT → ANSWER: free text, "" allowed, no control characters
    while :; do
        ask "$1"
        [[ "$ANSWER" != *[[:cntrl:]]* ]] && return 0
        warn "no control characters, please"
    done
}

ask_yn() {   # ask_yn PROMPT y|n → status 0 for yes
    local q="$1" d="$2" hint="y/N"
    [[ "$d" == y ]] && hint="Y/n"
    while :; do
        ask "$q [$hint]"
        case "${ANSWER,,}" in
            "")     [[ "$d" == y ]]; return ;;
            y|yes)  return 0 ;;
            n|no)   return 1 ;;
            *)      warn "answer y or n" ;;
        esac
    done
}

ask_list() {   # ask_list PROMPT REGEX HINT min|opt → LIST (words, duplicates kept out)
    local prompt="$1" re="$2" hint="$3" need="$4" w ok
    local -a words
    while :; do
        ask "$prompt"
        LIST=(); ok=1
        read -ra words <<<"$ANSWER"
        for w in "${words[@]}"; do
            if [[ "$w" =~ $re ]]; then
                in_list "$w" "${LIST[@]}" || LIST+=("$w")
            else
                warn "'$w': $hint"; ok=0
            fi
        done
        if (( ok )) && [[ "$need" == min && ${#LIST[@]} -eq 0 ]]; then
            warn "at least one, please"; ok=0
        fi
        (( ok )) && return 0
    done
}

in_list() { local x="$1" y; shift; for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done; return 1; }

menu() {   # menu TITLE "label|purpose"... → PICK (1..N, or b)
    local title="$1"; shift
    local -a items=("$@")
    local n=${#items[@]} i label purpose
    echo
    echo -e "${BOLD}${title}${NC}"
    for (( i = 0; i < n; i++ )); do
        label="${items[i]%%|*}"; purpose="${items[i]#*|}"
        printf '  %2d) %s\n' $(( i + 1 )) "$label"
        [[ "$purpose" != "${items[i]}" && -n "$purpose" ]] && printf '      %s\n' "$purpose"
    done
    echo "   b) back    q) quit"
    while :; do
        ask "Choice"
        case "${ANSWER,,}" in
            q|quit) bye ;;
            b|back) PICK=b; return 0 ;;
        esac
        if [[ "$ANSWER" =~ ^[0-9]{1,3}$ ]] && (( 10#$ANSWER >= 1 && 10#$ANSWER <= n )); then
            PICK=$(( 10#$ANSWER )); return 0
        fi
        warn "not a choice: '$ANSWER' — type a number from 1 to $n, b or q"
    done
}

ask_by() {   # the --by username: your own Keycloak account, remembered for the session
    echo "  --by is YOUR Keycloak username: recorded as the decision's maker, so you cannot confirm it yourself."
    ask_match "Your Keycloak username (--by)" "$USER_RE" "$USER_HINT" "$BY_USER"
    BY_USER="$ANSWER"
}

pick_components() {   # pick_components deploy|uninstall → COMPS (empty = all)
    local kind="$1" f c w i ok
    local -a avail=() words
    for f in apps/*/"$kind".sh; do
        [[ -f "$f" ]] || continue
        c="${f#apps/}"; avail+=("${c%%/*}")
    done
    echo "  Components with apps/<name>/$kind.sh:"
    for (( i = 0; i < ${#avail[@]}; i++ )); do printf '    %2d) %s\n' $(( i + 1 )) "${avail[i]}"; done
    while :; do
        ask "Names or numbers, separated by spaces (Enter = all)"
        COMPS=(); ok=1
        [[ -z "$ANSWER" ]] && return 0
        read -ra words <<<"$ANSWER"
        for w in "${words[@]}"; do
            if [[ "$w" =~ ^[0-9]{1,3}$ ]] && (( 10#$w >= 1 && 10#$w <= ${#avail[@]} )); then w="${avail[10#$w - 1]}"; fi
            if in_list "$w" "${avail[@]}"; then
                in_list "$w" "${COMPS[@]}" || COMPS+=("$w")
            else
                warn "unknown component '$w' (no apps/$w/$kind.sh)"; ok=0
            fi
        done
        (( ok )) && return 0
    done
}

pick_one_component() {   # pick_one_component deploy|uninstall → ANSWER (name) or status 1 for back
    local kind="$1" f c
    local -a avail=() items=()
    for f in apps/*/"$kind".sh; do
        [[ -f "$f" ]] || continue
        c="${f#apps/}"; c="${c%%/*}"; avail+=("$c"); items+=("$c|$(component_purpose "$c")")
    done
    menu "Which component?" "${items[@]}"
    [[ "$PICK" == b ]] && return 1
    ANSWER="${avail[PICK - 1]}"
}

component_purpose() {
    case "$1" in
        access)        echo "Access requests and the User Manager" ;;
        database)      echo "medcea_db: schema, migrations, roles, grants, the IAM_DB_ROLES bundle" ;;
        edge-wizard)   echo "Device onboarding wizard (host service) at the onboard address" ;;
        frontend)      echo "System Configuration UI, config-api (PostgREST) and Database Management" ;;
        iam)           echo "Policy check only (Phase 0): deploys nothing" ;;
        monitor)       echo "Run Monitor dashboard" ;;
        mqtt-explorer) echo "Browser MQTT Explorer" ;;
        node-red)      echo "Node-RED palette packages and platform flows" ;;
        report)        echo "Grafana dashboards" ;;
        scheduler)     echo "Recipe Schedule Manager" ;;
        *)             echo "" ;;
    esac
}

# ── config.env, read without sourcing it ─────────────────────────────────────
# Sourcing would run its expressions (tailscale ip …) and put every password in this
# shell; the guide only needs a few literal values.

cfg_check_one() {   # cfg_check_one KEY [quiet] → CFG_LINE, CFG_VAL; status 1 (with a reason) unless exactly one active line
    local key="$1" quiet="${2-}" raw
    local -a hits
    CFG_LINE=""; CFG_VAL=""
    if [[ ! -f "$CFG" ]]; then
        [[ -n "$quiet" ]] || warn "$CFG not found: install first (./install.sh), which creates it"
        return 1
    fi
    mapfile -t hits < <(grep -nE "^[[:space:]]*(export[[:space:]]+)?${key}=" "$CFG")
    if (( ${#hits[@]} == 0 )); then
        [[ -n "$quiet" ]] || warn "$CFG has no active $key= line. Copy it from config.env.example ($(grep -E "^${key}=" config.env.example 2>/dev/null || echo "$key=\"false\"")), then come back."
        return 1
    fi
    if (( ${#hits[@]} > 1 )); then
        local lines="" h
        for h in "${hits[@]}"; do lines+="${h%%:*} "; done
        [[ -n "$quiet" ]] || warn "$key is set on ${#hits[@]} active lines of $CFG (lines ${lines% }). The last one wins when a script sources it, so editing one could leave the other in force. Keep one line (comment out the others), then come back."
        return 1
    fi
    CFG_LINE="${hits[0]%%:*}"
    raw="${hits[0]#*:}"; raw="${raw#*"${key}"=}"
    raw="${raw%%[[:space:]]#*}"                      # a trailing comment
    raw="${raw%"${raw##*[![:space:]]}"}"
    raw="${raw#\"}"; raw="${raw%\"}"; raw="${raw#\'}"; raw="${raw%\'}"
    CFG_VAL="$raw"
}

cfg_literal() {   # cfg_literal KEY DEFAULT → ANSWER: KEY's value, one $VAR resolved, else DEFAULT
    local key="$1" def="$2" ref
    if cfg_check_one "$key" quiet; then
        ANSWER="$CFG_VAL"
        if [[ "$ANSWER" =~ ^\$\{?([A-Z_][A-Z0-9_]*)\}?$ ]]; then
            ref="${BASH_REMATCH[1]}"
            if cfg_check_one "$ref" quiet && [[ "$CFG_VAL" != *'$'* ]]; then ANSWER="$CFG_VAL"; else ANSWER="$def"; fi
        fi
        [[ "$ANSWER" == *'$'* || -z "$ANSWER" ]] && ANSWER="$def"
    else
        ANSWER="$def"
    fi
}

CFG_BACKUP=""
cfg_set() {   # cfg_set KEY VALUE: replace that one line; first call backs config.env up
    local key="$1" val="$2" line prefix newline tmp
    cfg_check_one "$key" || return 1
    line="$(sed -n "${CFG_LINE}p" "$CFG")"
    prefix="${line%%"${key}"=*}"                      # keeps leading space or "export "
    newline="${prefix}${key}=\"${val}\""
    if [[ -z "$CFG_BACKUP" ]]; then
        CFG_BACKUP="${CFG}.guide-$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$CFG" "$CFG_BACKUP" || { warn "could not back up $CFG"; CFG_BACKUP=""; return 1; }
        chmod 600 "$CFG_BACKUP"
        echo "  Backup: $CFG_BACKUP"
    fi
    tmp="$(mktemp "${CFG}.guide.XXXXXX")" || return 1
    if NEWLINE="$newline" awk -v n="$CFG_LINE" 'NR == n { print ENVIRON["NEWLINE"]; next } { print }' "$CFG" >"$tmp" \
       && cat "$tmp" >"$CFG"; then                    # cat keeps the file's mode and owner
        rm -f "$tmp"
    else
        rm -f "$tmp"; warn "could not write $CFG"; return 1
    fi
    # -U0: only the changed line, never its neighbours (they may be passwords)
    diff -U0 "$CFG_BACKUP" "$CFG" | sed '1,2d; s/^/    /'
    return 0
}

# ── The deploy lock, held for a whole switch recipe ──────────────────────────
# A recipe edits config.env and then deploys; a deploy already running elsewhere would
# read the new value halfway through (each apps/<c>/deploy.sh sources config.env), and
# configure.sh would write back what it read before. So the recipe takes the lock before
# its first step, as every script that changes config.env does, and exports
# MEDCEA_LOCK_HELD so its steps skip their own (infra/lib-lock.sh). Not medcea_lock
# itself: that exits on refusal, and the guide reports and goes on. The guide starts no
# background job while it holds the lock (a job would inherit fd 9).

GUIDE_LOCKED=false
guide_lock() {   # guide_lock → status 0 holding the lock; 1 with the reason printed
    [[ -n "${MEDCEA_LOCK_HELD:-}" ]] && return 0          # a parent holds it for us
    if ! source infra/lib-lock.sh 2>/dev/null || [[ -z "${MEDCEA_LOCK_FILE:-}" ]]; then
        warn "cannot read infra/lib-lock.sh: run the guide from a complete MedCEA tree"
        return 1
    fi
    exec 9>>"$MEDCEA_LOCK_FILE" || { warn "cannot open $MEDCEA_LOCK_FILE"; return 1; }
    if ! flock -n 9; then
        local pid holder who
        IFS=$'\t' read -r pid holder <"$MEDCEA_LOCK_FILE" 2>/dev/null
        exec 9>&-
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            who="PID $pid, $holder"
        else   # the file names a run that has ended: a child it left, or a run under sudo
            who="its holder is not named; find it with: fuser -v $MEDCEA_LOCK_FILE (sudo for a run under sudo)"
        fi
        warn "another MedCEA deploy is running ($who). Wait for it to finish, then come back."
        return 1
    fi
    local term
    term="$(tty 2>/dev/null)" || term="none"
    printf '%s\tstarted %s, terminal %s: %s\n' "$$" "$(date '+%F %T')" "${term#/dev/}" "./guide.sh (switch recipe)" >"$MEDCEA_LOCK_FILE"
    export MEDCEA_LOCK_HELD=$$
    GUIDE_LOCKED=true
}
guide_unlock() {
    $GUIDE_LOCKED || return 0
    exec 9>&-
    unset MEDCEA_LOCK_HELD
    GUIDE_LOCKED=false
}

# ── Planning and running one command ─────────────────────────────────────────
# Each action sets these, then calls plan_run:
#   CMD=(…)      the command, one word per element (run as an array: no eval); an
#                element that is exactly && separates commands run one after the other,
#                each only when the one before it exited 0
#   PIPE=(…)     optional: CMD's output is piped into it (read-only formatting only)
#   EFFECT       what it changes, in one line
#   LOCK         yes | no — takes the deploy lock (infra/lib-lock.sh)
#   SUDO         no | mk8s (sudo only without the microk8s group) | free text
#   LEVEL        read ([Y/n]) | change ([y/N]) | destroy (type yes)
#   CONFIRM_WORD with LEVEL=destroy: a second word to type after yes (the project name
#                for --purge-data, as deploy-apps.sh asks it)
#   NOTES=(…)    extra lines shown before the confirmation
#   CFG_NEEDED   yes when the command refuses without config.env

reset_plan() { CMD=(); PIPE=(); EFFECT=""; LOCK=no; SUDO=no; LEVEL=read; CONFIRM_WORD=""; NOTES=(); CFG_NEEDED=no; }

qwords() {   # qwords WORD… → the words as they would be typed (printf %q), space-separated
    local out
    out="$(printf '%q ' "$@")"
    printf '%s' "${out% }"
}

cmd_text() {   # CMD (&& CMD…) (| PIPE) as it would be typed
    local out="" w
    local -a seg=()
    for w in "${CMD[@]}" "&&"; do
        if [[ "$w" == "&&" ]]; then
            [[ -n "$out" ]] && out+=" && "
            out+="$(qwords "${seg[@]}")"; seg=()
        else
            seg+=("$w")
        fi
    done
    (( ${#PIPE[@]} )) && out+=" | $(qwords "${PIPE[@]}")"
    printf '%s' "$out"
}

sudo_text() {
    case "$SUDO" in
        no)   echo "no" ;;
        mk8s) if id -nG 2>/dev/null | grep -qw microk8s; then
                  echo "no (this session is in group microk8s)"
              else
                  echo "yes: this session is not in group microk8s, so its microk8s calls go through sudo (it asks for your password)"
              fi ;;
        *)    echo "$SUDO" ;;
    esac
}

confirm_level() {   # confirm_level → status 0 to go ahead
    case "$LEVEL" in
        read)    ask_yn "Run it?" y ;;
        change)  ask_yn "Run it?" n ;;
        destroy) echo -e "${RED}${BOLD}This is destructive.${NC}"
                 ask "Type yes to go ahead (anything else cancels)"
                 [[ "$ANSWER" == yes ]] || return 1
                 [[ -z "$CONFIRM_WORD" ]] && return 0
                 ask "Type the project name ('$CONFIRM_WORD') to drop the data (anything else cancels)"
                 [[ "$ANSWER" == "$CONFIRM_WORD" ]] ;;
    esac
}

LAST_RC=0
run_array() {   # runs CMD (&& CMD…) (| PIPE) with this terminal; LAST_RC
    local w
    local -a seg=()
    echo -e "${CYAN}\$ $(cmd_text)${NC}"
    if (( ${#PIPE[@]} )); then
        "${CMD[@]}" | "${PIPE[@]}"; LAST_RC=$?
    else
        LAST_RC=0
        for w in "${CMD[@]}" "&&"; do
            if [[ "$w" != "&&" ]]; then seg+=("$w"); continue; fi
            "${seg[@]}"; LAST_RC=$?; seg=()
            (( LAST_RC == 0 )) || break
        done
    fi
    if (( LAST_RC == 0 )); then echo -e "${GREEN}Finished: exit code 0.${NC}"
    else echo -e "${RED}Failed: exit code $LAST_RC.${NC}"; fi
}

plan_run() {
    local n kind
    case "$LEVEL" in read) kind="read-only" ;; change) kind="changes the platform" ;; *) kind="DESTRUCTIVE" ;; esac
    echo
    echo -e "${BOLD}Command${NC}"
    echo "  $(cmd_text)"
    echo "  Kind:        $kind"
    echo "  Changes:     $EFFECT"
    case "$LOCK" in
        yes) echo "  Deploy lock: takes it (refused while another deploy runs)" ;;
        no)  echo "  Deploy lock: no" ;;
        *)   echo "  Deploy lock: $LOCK" ;;
    esac
    echo "  sudo:        $(sudo_text)"
    for n in "${NOTES[@]}"; do echo "  - $n"; done
    [[ "$CFG_NEEDED" == yes && ! -f "$CFG" ]] && warn "this command needs config.env, which does not exist yet: run ./install.sh first"
    if ! confirm_level; then echo "Cancelled; nothing was run."; return 0; fi
    if $DRY_RUN; then echo "[dry run] not executed: $(cmd_text)"; return 0; fi
    run_array
}

# ── The catalogue ────────────────────────────────────────────────────────────
# To add a command: write an a_* function that asks its values (ask, ask_match, ask_yn,
# ask_list, pick_components), fills the plan fields above and ends with plan_run; then
# add one "function|label|one-line purpose" entry to its area's array (AREA_*). A
# function that returns 10 means "back" (no "back to the menu / quit" question after).
# A config.env switch: one case per direction in recipe() and an entry calling
# switch_flow KEY in AREA_SWITCHES.

# ── Install and uninstall ──
a_install() {
    CMD=(./install.sh)
    ask_yn "Review every setting in config.env first (--configure)?" n && CMD+=(--configure)
    EFFECT="cluster and config.env (asks only empty required values); the credentials box comes last"
    LOCK=yes; LEVEL=change; SUDO="maybe: a first install, MicroK8s and the /etc/hosts block ask for your sudo password"
    NOTES=("Runs ./deploy-infra.sh, then ./deploy-apps.sh --all, then ./health-check.sh; safe to re-run.")
    plan_run
}
a_install_infra() {
    CMD=(./install.sh --infra-only)
    ask_yn "Review every setting in config.env first (--configure)?" n && CMD+=(--configure)
    EFFECT="cluster and config.env (missing values only)"
    LOCK=yes; LEVEL=change; SUDO="maybe: MicroK8s and the /etc/hosts block ask for your sudo password"
    NOTES=("Afterwards run the applications: ./install.sh --apps-only")
    plan_run
}
a_install_apps() {
    CMD=(./install.sh --apps-only)
    EFFECT="cluster and database (every application component)"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_uninstall_apps() {
    pick_components uninstall
    CMD=(./install.sh --uninstall-apps "${COMPS[@]}")
    EFFECT="removes ${COMPS[*]:-every application component}; the infrastructure keeps running"
    if (( ${#COMPS[@]} == 0 )) || in_list database "${COMPS[@]}"; then
        if ask_yn "Also DROP the database medcea_db with ALL its data (--purge-data)?" n; then
            CMD+=(--purge-data); EFFECT+="; DROPS medcea_db, its roles and Secrets (all data)"
        fi
    else
        echo "  (--purge-data is offered only when database is among the components)"
    fi
    LOCK=yes; LEVEL=destroy; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("install.sh then asks you to type 'apps' (and the project name with --purge-data)."
           "Reinstall: ./install.sh --apps-only")
    plan_run
}
a_uninstall_infra() {
    CMD=(./install.sh --uninstall-infra)
    EFFECT="removes every platform service, every application and ALL data (the whole namespace, PVCs included); keeps MicroK8s, config.env and .ca/"
    LOCK=yes; LEVEL=destroy; SUDO=mk8s
    NOTES=("install.sh then asks you to type 'reset'." "Reinstall: ./install.sh")
    plan_run
}
a_uninstall_all() {
    CMD=(./install.sh --uninstall-all)
    EFFECT="removes MicroK8s and all cluster data, ~/.kube, the /etc/hosts block, the wizard service, edge/.venv, logs/ and credentials files; asks about .ca/ and config.env (with guide.sh's backups of it)"
    LOCK=yes; LEVEL=destroy; SUDO="yes (snap remove, /etc/hosts)"
    NOTES=("install.sh then asks you to type 'uninstall'. edge/provisioned/ and edge/firmware/ are kept.")
    plan_run
}

# ── Infrastructure ──
a_infra_deploy() {
    CMD=(./deploy-infra.sh)
    EFFECT="cluster (Postgres, Keycloak, Mosquitto, Grafana, Node-RED, proxies, IAM ConfigMaps and NetworkPolicies, workbench), config.env (missing values, generated secrets), /etc/hosts"
    LOCK=yes; LEVEL=change; SUDO="maybe: MicroK8s, containerd registry login and the /etc/hosts block ask for your sudo password"
    NOTES=("Run it after pulling IAM changes and after rotating or removing a realm key."
           "Follow with the applications: ./deploy-apps.sh --all")
    plan_run
}
a_infra_configure() {
    CMD=(./deploy-infra.sh --configure)
    EFFECT="config.env (every setting asked, current values as defaults), then the cluster"
    LOCK=yes; LEVEL=change; SUDO="maybe: as ./deploy-infra.sh"
    plan_run
}
a_configure_only() {
    CMD=(./infra/configure.sh)
    ask_yn "Only the required values that are still empty (--missing)?" n && CMD+=(--missing)
    EFFECT="config.env only (generates missing database passwords; may offer apt-get for host prerequisites); deploys nothing"
    LOCK=yes; LEVEL=change; SUDO="maybe: only to install missing host packages"
    NOTES=("Enter keeps a line as it is, expressions included. Passwords: letters, digits and . _ ~ - only.")
    plan_run
}
a_workbench() {
    CMD=(./infra/deploy-workbench.sh)
    EFFECT="cluster (the JupyterHub Helm release)"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Needs WORKBENCH_SECRET in config.env (written by ./deploy-infra.sh)."
           "Who may sign in, and who is hub administrator, come from the access policy (IAM_GATES=false: any realm account); a policy that does not compile stops the deploy and leaves the running hub as it is.")
    plan_run
}
a_workbench_switch() { switch_flow WORKBENCH_ENABLED; }
a_infra_reset() {
    CMD=(./deploy-infra.sh --reset)
    EFFECT="uninstalls every Helm release and deletes the namespace with ALL its data (PVCs: database, Keycloak users, Grafana, workbench homes); keeps MicroK8s"
    if ask_yn "Also blank the generated secrets in config.env (--secrets)?" n; then
        CMD+=(--secrets); EFFECT+="; blanks generated secrets in config.env"
    fi
    LOCK=yes; LEVEL=destroy; SUDO=mk8s
    NOTES=("deploy-infra.sh then asks you to type 'reset'." "Afterwards both: ./deploy-infra.sh && ./deploy-apps.sh --all")
    plan_run
}
a_infra_uninstall() {
    CMD=(./deploy-infra.sh --uninstall)
    EFFECT="removes MicroK8s (and Juju), all cluster data, ~/.kube and the /etc/hosts block; keeps config.env, .ca/, edge/.venv, logs"
    LOCK=yes; LEVEL=destroy; SUDO="yes (snap remove, /etc/hosts)"
    NOTES=("deploy-infra.sh then asks you to type 'yes'. Reinstalling is slow (images are pulled again).")
    plan_run
}
a_infra_help() {
    CMD=(./deploy-infra.sh --help)
    EFFECT="nothing (prints the usage)"
    plan_run
}

# ── Applications ──
a_apps_menu() {
    CMD=(./deploy-apps.sh)
    EFFECT="cluster and database (the components you tick)"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Its own menu: numbers toggle, a = all, n = none, Enter = confirm, q = quit.")
    plan_run
}
a_apps_all() {
    CMD=(./deploy-apps.sh --all)
    EFFECT="cluster and database (every component, alphabetical order)"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_apps_one() {
    pick_one_component deploy || return 10
    local c="$ANSWER"
    CMD=("./apps/$c/deploy.sh")
    EFFECT="$(component_purpose "$c")"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    case "$c" in
        access)    NOTES=("Order: ./deploy-infra.sh first. Runs ./apps/database/deploy.sh itself when access_svc lacks its grants.") ;;
        database)  NOTES=("Behaviour comes from config.env (IAM_DB_ROLES, IAM_DB_SERVICE_ROLES); restarts config-api when IAM_DB_ROLES changed.") ;;
        frontend)  NOTES=("IAM_POSTGREST_JWT in config.env decides config-api's mode; a switch costs config-api up to ~15 s, by design.") ;;
        scheduler) NOTES=("Refuses until the database deploy has created retire_schedule and start_run.") ;;
        iam)       LEVEL=read; EFFECT="nothing (checks the policy and lists the hosts)" ;;
        edge-wizard) SUDO="no (a systemd user service); mk8s for the Ingress" ;;
    esac
    plan_run
}
a_apps_uninstall() {
    pick_components uninstall
    CMD=(./deploy-apps.sh --uninstall)
    EFFECT="removes ${COMPS[*]:-every application component} (reverse alphabetical order); the infrastructure keeps running"
    if (( ${#COMPS[@]} == 0 )) || in_list database "${COMPS[@]}"; then
        if ask_yn "Also DROP the database medcea_db with ALL its data (--purge-data)?" n; then
            CMD+=(--purge-data); EFFECT+="; DROPS medcea_db, its roles and Secrets (all data)"
        fi
    fi
    CMD+=("${COMPS[@]}")
    LOCK=yes; LEVEL=destroy; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("deploy-apps.sh then asks you to type 'apps' (and the project name with --purge-data).")
    plan_run
}
a_apps_uninstall_one() {
    pick_one_component uninstall || return 10
    local c="$ANSWER"
    CMD=("./apps/$c/uninstall.sh")
    EFFECT="removes what ./apps/$c/deploy.sh created"
    LOCK=yes; LEVEL=destroy; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("No confirmation of its own: this guide's is the only one.")
    case "$c" in
        database)
            EFFECT="nothing without --purge-data (data kept)"
            if ask_yn "DROP the database medcea_db, every platform role and the db-<role> Secrets (--purge-data)?" n; then
                CMD+=(--purge-data); EFFECT="DROPS medcea_db, every platform database role and the db-<role> Secrets (all data)"
                purge_word
                NOTES+=("Warns, does not refuse, while config-api runs JWT: config-api will not connect until the database and frontend deploys run again.")
            fi ;;
        access)
            if ask_yn "Also DROP schema iam (requests, decisions, histories) and role access_svc (--purge-data)?" n; then
                CMD+=(--purge-data); EFFECT+="; DROPS schema iam and role access_svc"
                purge_word
                NOTES+=("Unit assignments in iam_policy.user_unit stay in effect without their decisions; waiting ones are lost. The next access deploy records survivors again as pending_qa.")
            fi ;;
        iam) LEVEL=change; EFFECT="nothing (Phase 0 deploys nothing)" ;;
    esac
    plan_run
}
purge_word() {   # --purge-data: yes, then the project name, as deploy-apps.sh asks it
    cfg_literal PROJECT_NAME medcea
    CONFIRM_WORD="$ANSWER"
    NOTES+=("--purge-data: after yes you type the project name ('$CONFIRM_WORD'), as ./deploy-apps.sh --uninstall asks it.")
}
a_apps_list() {
    CMD=(./deploy-apps.sh --help)
    EFFECT="nothing (prints the usage and the components found)"
    plan_run
}

# ── Operators and units ──
a_units_list() {
    ask_match "One account only? Keycloak username (Enter = everyone)" "$USER_RE" "$USER_HINT" "" optional
    CMD=(./apps/iam/units.sh list)
    [[ -n "$ANSWER" ]] && CMD+=("$ANSWER")
    EFFECT="nothing (lists units in effect and units waiting for qa)"
    LOCK=yes; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Takes the deploy lock and port-forwards Keycloak on 18091.")
    plan_run
}
units_tail() {   # --by, --reason; shared by assign and remove
    ask_by
    CMD+=(--by "$BY_USER")
    ask_text "Reason to record (Enter = the default reason)"
    [[ -n "$ANSWER" ]] && CMD+=(--reason "$ANSWER")
}
a_units_assign() {
    local who
    ask_match "Operator's Keycloak username" "$USER_RE" "$USER_HINT"; who="$ANSWER"
    ask_list "Unit codes, separated by spaces (e.g. UNIT01 UNIT02; case does not matter)" "$UNIT_RE" "$UNIT_HINT" min
    CMD=(./apps/iam/units.sh assign "$who" "${LIST[@]}")
    units_tail
    [[ "${BY_USER,,}" == "${who,,}" ]] && warn "--by is the account being changed: units.sh only warns, but nobody should propose their own widening"
    EFFECT="database: one iam.account_decision per unit, waiting for qa; NOT in effect until a qa person other than you confirms it in the User Manager's Decisions tab"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    echo "  --bootstrap puts the units in effect at once, before any check. units.sh refuses it"
    echo "  while another enabled qa person could confirm instead."
    if ask_yn "Use --bootstrap (only when nobody else could ever confirm)?" n; then
        CMD+=(--bootstrap); LEVEL=destroy
        EFFECT="database: the units are IN EFFECT AT ONCE (iam_policy.user_unit); their decisions still wait for qa, and a refusal removes them"
    fi
    NOTES=("Needs ./apps/database/deploy.sh and ./apps/access/deploy.sh to have run.")
    plan_run
}
a_units_remove() {
    local who
    ask_match "Keycloak username whose units go" "$USER_RE" "$USER_HINT"; who="$ANSWER"
    ask_list "Unit codes to remove, separated by spaces" "$UNIT_RE" "$UNIT_HINT" min
    CMD=(./apps/iam/units.sh remove "$who" "${LIST[@]}")
    units_tail
    EFFECT="database: the units go at once (a narrowing, reviewed later); one still waiting for qa is withdrawn instead"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Under IAM_DB_ROLES=true the operator stops seeing those units' telemetry and runs at once.")
    plan_run
}
a_units_remove_sub() {
    local sub
    echo "  For an account Keycloak no longer has: './apps/iam/units.sh list' prints its id."
    ask_match "Keycloak user id (uuid)" "$UUID_RE" "a uuid looks like 8-4-4-4-12 hex digits"; sub="${ANSWER,,}"
    ask_list "Unit codes to remove, separated by spaces" "$UNIT_RE" "$UNIT_HINT" min
    CMD=(./apps/iam/units.sh remove --sub "$sub" "${LIST[@]}")   # --sub before the codes
    units_tail
    EFFECT="database: the units go at once; one still waiting for qa is withdrawn"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}

# ── IAM switches ──
a_sw_gates()   { switch_flow IAM_GATES; }
a_sw_netpol()  { switch_flow IAM_NETPOL; }
a_sw_enforce() { switch_flow IAM_ENFORCE; }
a_sw_jwt()     { switch_flow IAM_POSTGREST_JWT; }
a_sw_svc()     { switch_flow IAM_DB_SERVICE_ROLES; }
a_sw_dbroles() { switch_flow IAM_DB_ROLES; }
a_rollback_27() {
    # Shown, never run: it needs a 2.7 commit, a git revert and psql in the PostgreSQL pod.
    local ns db
    cfg_literal NAMESPACE medcea; ns="$ANSWER"
    [[ "$ns" =~ $NS_RE ]] || ns="medcea"
    cfg_literal POSTGRES_DB medcea_db; db="$ANSWER"
    [[ "$db" =~ $DB_RE ]] || db="medcea_db"
    echo
    echo -e "${BOLD}IAM 2.7 rollback — the steps, in order (this guide runs none of them)${NC}"
    echo "  1. Narrow the User Manager to realm role admin:  IAM_GATES=false ./apps/access/deploy.sh"
    echo "  2. git revert the 2.7 commits."
    echo "  3. As postgres, once, in one transaction: apps/access/rollback-2.7.sql from the 2.7 tree"
    echo "     (namespace and database from $CFG; the password is read inside the pod, as in the file's header):"
    echo "       git show <2.7 commit>:apps/access/rollback-2.7.sql | microk8s kubectl exec -i -n $ns rdbms-postgresql-0 -- \\"
    # shellcheck disable=SC2016  # $(cat …) and $POSTGRES_PASSWORD_FILE are for the pod's sh, printed literally
    echo '         sh -c '\''PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d '"$db"' -f -'\'
    echo "     It parks mail_settings decisions in schema iam_retired_27 and revokes the 2.7 privileges outside iam."
    echo "  4. ./apps/access/deploy.sh   (the reverted one)"
    echo "  5. ./deploy-infra.sh"
    echo "  6. ./apps/database/deploy.sh"
    echo "  See CLAUDE.md, 'apps/access/ account decisions (IAM 2.7)'."
    return 0
}

# recipe KEY enable|rollback → PRE (checklist), STEPS ("set KEY VALUE" | "run word…"),
# AFTER (notes), REFUSE (a reason not to start). Every switch's recipe lives here.
dep_switch() {   # dep_switch KEY → DEP (true|false); status 1 with REFUSE set
    # A switch another recipe's order depends on: exactly one active line, literally true
    # or false. A duplicate or an expression is not read as "not true" (the order would
    # then be wrong and the deploy refuse after config.env was already changed).
    DEP=""
    if ! cfg_check_one "$1"; then
        REFUSE="this recipe's order depends on $1, which must be on exactly one active line of $CFG."
        return 1
    fi
    case "$CFG_VAL" in
        true|false) DEP="$CFG_VAL" ;;
        *) REFUSE="this recipe's order depends on $1, which is '$CFG_VAL' on line $CFG_LINE of $CFG: write it as \"true\" or \"false\", then come back."
           return 1 ;;
    esac
}

recipe() {
    local key="$1" dir="$2" dbroles="" jwt="" svc=""
    PRE=(); STEPS=(); AFTER=(); REFUSE=""
    case "$key:$dir" in
        IAM_POSTGREST_JWT:rollback|IAM_DB_SERVICE_ROLES:rollback)
            dep_switch IAM_DB_ROLES || return 0; dbroles="$DEP" ;;
        IAM_DB_ROLES:enable)
            dep_switch IAM_POSTGREST_JWT || return 0; jwt="$DEP"
            dep_switch IAM_DB_SERVICE_ROLES || return 0; svc="$DEP" ;;
    esac
    case "$key:$dir" in
        IAM_GATES:enable)
            STEPS=("set IAM_GATES true" "run ./deploy-infra.sh" "run ./deploy-apps.sh --all")
            AFTER=("The User Manager widens beyond admin only once every access pod proves it enforces (the access deploy checks)."
                   "Grafana's role setting comes from the policy again (Editor: engineer; Viewer: roles holding R on dashboards; others cannot sign in); the grafana_* roles are retired."
                   "The AI workbench admits the roles the policy compiles; the hub admin cannot open others' servers. It is redeployed by ./deploy-infra.sh (WORKBENCH_ENABLED=true)."
                   "Device onboarding admits the policy's roles (engineer, maintenance) and pgAdmin admin; ./deploy-apps.sh --all restarts the onboarding wizard and refuses while a flash run is active."
                   "Verify: tests/iam-hosts.sh (Grafana's role setting, the AI workbench, the wizard and pgAdmin included), tests/iam-workbench.sh and ./health-check.sh (Grafana roles, AI Workbench gate, Onboarding roles, pgAdmin roles)") ;;
        IAM_GATES:rollback)
            STEPS=("run env IAM_GATES=false ./apps/access/deploy.sh" "set IAM_GATES false"
                   "run ./deploy-infra.sh" "run ./deploy-apps.sh --all")
            AFTER=("Every gate goes back to operator, qa, auditor, admin; the User Manager to admin only. Each deploy warns while false."
                   "Node-RED and the MQTT Explorer keep their compiled list (engineer): they reach telemetry and device control. Node-RED's editor keeps its rights from the policy (adminAuth)."
                   "Accounts holding production_manager, maintenance, qc, qp, engineer, bio_scientist or control_scientist lose the portal and every other gated host until IAM_GATES is true again."
                   "Grafana goes back to any enabled account (at least Viewer); the grafana_* roles are re-created, so Editor/Admin only for the built-in accounts that still exist."
                   "The AI workbench goes back to any realm account, with ADMIN_USER as hub admin (it still cannot open others' servers, and removing a hub user still keeps the home)."
                   "Device onboarding goes back to EDGE_WIZARD_ROLE (empty: any signed-in account may erase and flash a board); pgAdmin stays admin only.") ;;
        IAM_NETPOL:enable)
            PRE=("Every caller of an application pod is listed under network: in apps/iam/policy/defaults.yaml (an unlisted caller times out).")
            STEPS=("set IAM_NETPOL true" "run ./deploy-infra.sh")
            AFTER=("Verify: tests/iam-network.sh (takes the deploy lock).") ;;
        IAM_NETPOL:rollback)
            STEPS=("set IAM_NETPOL false" "run ./deploy-infra.sh")
            AFTER=("At once, without a deploy: microk8s kubectl -n <namespace> delete netpol -l medcea/iam-netpol=true (lasts until the next ./deploy-infra.sh while IAM_NETPOL=true).") ;;
        IAM_ENFORCE:enable)
            PRE=("The IAM 2.6 code is deployed with IAM_ENFORCE still false (./deploy-infra.sh, ./apps/database/deploy.sh, then ./deploy-apps.sh --all since the last pull)."
                 "IAM_DB_ROLES is true (./guide.sh IAM_DB_ROLES): only the database functions check an operator's assigned_run (execute, stop, status, trigger); without it an operator can stop another unit's run (health-check iamenforce FAILs)."
                 "A report-only soak is over: the services' 'medcea_iam: would refuse' lines from real people are all intended policy (each becomes a 401/403)."
                 "Enabled accounts hold the roles the work needs (production_manager: runs and schedules; engineer: recipes, devices, algorithms); admin keeps no access to recipes, runs or exports."
                 "Every operator has a unit in effect (./apps/iam/units.sh list, run before this guide: it takes the deploy lock), or the Monitor and the scheduler show them no runs or telemetry.")
            STEPS=("run python3 tests/iam-routes-diff.py --strict" "set IAM_ENFORCE true" "run ./deploy-infra.sh")
            AFTER=("Services read it from ConfigMap medcea-iam-lib per request: live within about a minute (kubelet sync), no restart. Refusals are 401/403/503 from then on."
                   "The pods' IAM_ENFORCE copy (used only when /iam/ is missing, and then it lets everything through) stays false until each app's next deploy: ./health-check.sh FAILs (iamenforce) until then, so redeploy them when no run is active (./deploy-apps.sh --all)."
                   "Verify: tests/iam-check.sh (every pod 'enforce', a forged request 'refused' 401), ./health-check.sh, tests/iam-signin.sh (takes the deploy lock).") ;;
        IAM_ENFORCE:rollback)
            STEPS=("set IAM_ENFORCE false" "run ./deploy-infra.sh")
            AFTER=("Services log 'would refuse' and let the request through again within about a minute. The access Admin port and dbmgmt enforce whatever this says."
                   "The pods' copy stays true until each app's next deploy; it only fails closed when /iam/ is missing.") ;;
        IAM_POSTGREST_JWT:enable)
            PRE=("AUTHENTICATOR_DB_PASS in config.env is set and differs from POSTGRES_PASS (the frontend deploy refuses otherwise).")
            STEPS=("run ./deploy-infra.sh" "set IAM_POSTGREST_JWT true" "run ./apps/frontend/deploy.sh")
            AFTER=("config-api serves nothing for 0 to ~15 s during the switch, by design."
                   "After rotating or removing a realm key, run ./deploy-infra.sh again.") ;;
        IAM_POSTGREST_JWT:rollback)
            if [[ "$dbroles" == true ]]; then
                STEPS=("set IAM_DB_ROLES false" "run ./apps/database/deploy.sh")
                AFTER=("IAM_DB_ROLES is true, so it goes back to false first (config-api refuses legacy mode while the database enforces).")
            fi
            STEPS+=("set IAM_POSTGREST_JWT false" "run ./apps/frontend/deploy.sh")
            AFTER+=("config-api serves nothing for 0 to ~15 s during the switch, by design."
                    "Any git revert only after this: a reverted deploy breaks a config-api still in JWT mode.") ;;
        IAM_DB_SERVICE_ROLES:enable)
            STEPS=("set IAM_DB_SERVICE_ROLES true" "run ./deploy-apps.sh --all" "run ./deploy-infra.sh")
            AFTER=("Verify: ./health-check.sh shows dbclients OK."
                   "A statement a service's grants do not cover is now 'permission denied' (intended); pgAdmin can only read.") ;;
        IAM_DB_SERVICE_ROLES:rollback)
            [[ "$dbroles" == true ]] && REFUSE="IAM_DB_ROLES is true, and it requires IAM_DB_SERVICE_ROLES=true: roll back IAM_DB_ROLES first."
            STEPS=("set IAM_DB_SERVICE_ROLES false" "run ./deploy-apps.sh --all" "run ./deploy-infra.sh" "run ./apps/database/deploy.sh")
            AFTER=("The last database deploy makes the service roles NOLOGIN again.") ;;
        IAM_DB_ROLES:enable)
            [[ "$jwt" == true ]] || REFUSE="IAM_POSTGREST_JWT is '${jwt:-unset}': enable it first (this guide, IAM_POSTGREST_JWT → enable)."
            [[ -z "$REFUSE" && "$svc" != true ]] && REFUSE="IAM_DB_SERVICE_ROLES is '${svc:-unset}': enable it first, and check dbclients OK in ./health-check.sh."
            PRE=("Operators have their units, confirmed by qa: ./apps/iam/units.sh list shows no enabled operator without a unit (without one they see nothing and start nothing)."
                 "Every database client logs in as its own role: ./health-check.sh shows dbclients OK."
                 "AUTHENTICATOR_DB_PASS is set and differs from POSTGRES_PASS.")
            STEPS=("set IAM_DB_ROLES true" "run ./apps/database/deploy.sh")
            AFTER=("If the database deploy refuses, it says 'nothing was changed' but config.env already says true: restore it as shown."
                   "The deploy restarts config-api itself.") ;;
        IAM_DB_ROLES:rollback)
            STEPS=("set IAM_DB_ROLES false" "run ./apps/database/deploy.sh")
            AFTER=("The deploy restarts config-api. health-check iamdbroles WARNs while false, by design."
                   "While IAM_ENFORCE is true, nothing checks an operator's assigned_run any more (health-check iamenforce FAILs): roll IAM_ENFORCE back too unless this is brief."
                   "While false, nobody can retire a Q-table from the Config UI (config-api runs every token as anon, which may execute no function). If one must start cold meanwhile: medcea.retire_algorithm_state in psql in the PostgreSQL pod, which records no person."
                   "Before a git revert of the Phase 2 code, also run medcea_db_migrations_down_008b.sql with -v full=1 as postgres (by hand; see CLAUDE.md).") ;;
        WORKBENCH_ENABLED:enable)
            STEPS=("set WORKBENCH_ENABLED true" "run ./deploy-infra.sh")
            AFTER=("About 2 GB of images. To redeploy only the workbench later: ./infra/deploy-workbench.sh") ;;
        WORKBENCH_ENABLED:rollback)
            STEPS=("set WORKBENCH_ENABLED false" "run ./deploy-infra.sh")
            AFTER=("This does not remove a workbench that is already running; later deploys only skip it.") ;;
        *) REFUSE="no recipe for $key $dir" ;;
    esac
}

switch_purpose() {
    case "$1" in
        IAM_GATES)            echo "Each sign-in gate, Grafana's role setting, the AI workbench's hub, the onboarding wizard and pgAdmin admit the roles the policy compiles for their host (false: the pre-policy lists; Node-RED and the MQTT Explorer keep theirs)." ;;
        IAM_NETPOL)           echo "One NetworkPolicy per application pod: only its listed callers can connect." ;;
        IAM_ENFORCE)          echo "Python services refuse what the route table does not allow (false: they only log 'would refuse')." ;;
        IAM_POSTGREST_JWT)    echo "config-api (PostgREST) verifies the person's token (Phase 2b)." ;;
        IAM_DB_SERVICE_ROLES) echo "Each database client logs in as its own role instead of postgres (Phase 2.5)." ;;
        IAM_DB_ROLES)         echo "The database enforces per-role grants, RLS and guard triggers (Phase 2a)." ;;
        WORKBENCH_ENABLED)    echo "deploy-infra.sh also deploys the AI workbench (JupyterHub)." ;;
    esac
}

step_text() {   # step_text STEP → how it reads in the recipe
    local -a w
    read -ra w <<<"$1"
    case "${w[0]}" in
        set) local old=""
             cfg_check_one "${w[1]}" quiet && old="$CFG_VAL"
             printf 'config.env: %s="%s"   (line %s, now "%s")' "${w[1]}" "${w[2]}" "${CFG_LINE:-?}" "$old" ;;
        run) qwords "${w[@]:1}" ;;
    esac
}

switch_flow() {   # switch_flow KEY: current value → enable|roll back → recipe → run
    local key="$1" cur dir target i s n_set=0
    local -a w
    echo
    echo -e "${BOLD}${key}${NC}: $(switch_purpose "$key")"
    cfg_check_one "$key" || { echo "Nothing was changed."; return 0; }
    cur="$CFG_VAL"
    echo "  Now: ${key}=\"${cur}\"   ($CFG line $CFG_LINE)"
    menu "$key: what do you want to do?" \
        "Enable (set ${key}=true)|$( [[ "$cur" == true ]] && echo 'already true: re-runs the deploys' || echo 'the enable recipe')" \
        "Roll back (set ${key}=false)|$( [[ "$cur" == false ]] && echo 'already false: re-runs the deploys' || echo 'the rollback recipe')"
    [[ "$PICK" == b ]] && return 10
    if (( PICK == 1 )); then dir=enable; target=true; else dir=rollback; target=false; fi
    recipe "$key" "$dir"
    if [[ -n "$REFUSE" ]]; then
        warn "$REFUSE"
        echo "Nothing was changed."
        return 0
    fi
    # Every key the recipe sets must be one clean line before anything is touched.
    for s in "${STEPS[@]}"; do
        read -ra w <<<"$s"
        if [[ "${w[0]}" == set ]]; then
            cfg_check_one "${w[1]}" || { echo "Nothing was changed."; return 0; }
            n_set=$(( n_set + 1 ))
        fi
    done
    echo
    echo -e "${BOLD}Recipe: $key → $target${NC}"
    if (( ${#PRE[@]} )); then
        echo "  Before you start, check:"
        for s in "${PRE[@]}"; do echo "    [ ] $s"; done
    fi
    echo "  Steps, in order (stops at the first that fails):"
    for (( i = 0; i < ${#STEPS[@]}; i++ )); do
        printf '    %d. %s\n' $(( i + 1 )) "$(step_text "${STEPS[i]}")"
    done
    if (( ${#AFTER[@]} )); then
        echo "  Notes:"
        for s in "${AFTER[@]}"; do echo "    - $s"; done
    fi
    echo "  Every step takes the deploy lock; deploys use sudo only without the microk8s group (deploy-infra may ask for it)."
    if (( ${#PRE[@]} )); then
        ask_yn "Is every item in 'Before you start' true?" n || { echo "Do those first. Nothing was changed."; return 0; }
    fi
    ask_yn "Run these ${#STEPS[@]} steps?" n || { echo "Cancelled. Nothing was changed."; return 0; }

    if ! $DRY_RUN; then
        guide_lock || { echo "Nothing was changed."; return 0; }
        # Ctrl-C reaches the step's command too, which stops; the guide then reports
        # instead of dying with config.env changed and nothing said (switch_failed).
        RECIPE_SIG=""
        trap 'RECIPE_SIG="Ctrl-C (SIGINT)"' INT
        trap 'RECIPE_SIG=SIGTERM' TERM
        trap 'RECIPE_SIG=SIGHUP' HUP
    fi
    CFG_BACKUP=""
    for (( i = 0; i < ${#STEPS[@]}; i++ )); do
        read -ra w <<<"${STEPS[i]}"
        echo
        echo -e "${BOLD}Step $(( i + 1 ))/${#STEPS[@]}${NC}: $(step_text "${STEPS[i]}")"
        if $DRY_RUN; then
            if [[ "${w[0]}" == set ]]; then
                cfg_check_one "${w[1]}" quiet
                echo "[dry run] would set $CFG line $CFG_LINE: ${w[1]}=\"$CFG_VAL\" → ${w[1]}=\"${w[2]}\"  ($CFG not touched)"
            else
                echo "[dry run] would run: $(qwords "${w[@]:1}")"
            fi
            continue
        fi
        if [[ "${w[0]}" == set ]]; then
            cfg_set "${w[1]}" "${w[2]}"; LAST_RC=$?
        else
            reset_plan; CMD=("${w[@]:1}")
            run_array
        fi
        if [[ -n "$RECIPE_SIG" ]]; then
            switch_failed "$i" "$LAST_RC" "$RECIPE_SIG"
            recipe_end
            exit 130
        fi
        (( LAST_RC == 0 )) || { switch_failed "$i" "$LAST_RC"; recipe_end; return 0; }
    done
    echo
    if $DRY_RUN; then echo -e "${GREEN}[dry run] recipe shown; nothing was run or changed.${NC}"; return 0; fi
    recipe_end
    echo -e "${GREEN}All ${#STEPS[@]} steps done: ${key}=\"${target}\".${NC}"
    if [[ -n "$CFG_BACKUP" && -f "$CFG_BACKUP" ]]; then
        echo "  $CFG_BACKUP is a full copy of the old config.env, passwords included; the only change is shown above."
        if ask_yn "Delete that backup now?" y; then
            rm -f -- "$CFG_BACKUP" && echo "  Deleted $CFG_BACKUP."
        else
            echo "  Kept. ./install.sh --uninstall-all deletes it together with config.env."
        fi
    fi
    return 0
}

recipe_end() {   # after a real recipe: the lock and the signal traps go
    trap - INT TERM HUP
    guide_unlock
}

switch_failed() {   # switch_failed INDEX RC [WHY]
    local i="$1" rc="$2" why="${3-}"
    echo
    if [[ -n "$why" ]]; then
        echo -e "${RED}Stopped by $why during step $(( i + 1 )) (exit code $rc): $(step_text "${STEPS[i]}")${NC}"
        echo "  That step may not have finished; the steps after it were not run."
    else
        echo -e "${RED}Step $(( i + 1 )) failed (exit code $rc): $(step_text "${STEPS[i]}")${NC}"
        echo "  The steps after it were not run."
    fi
    if [[ -n "$CFG_BACKUP" ]]; then
        echo -e "  ${YELLOW}config.env has already been changed.${NC} Fix the cause and run this recipe again"
        echo "  (each step is safe to repeat), or put the old file back with:"
        echo "      cp -p $(printf '%q' "$CFG_BACKUP") $(printf '%q' "$CFG")"
        echo "  Restoring config.env does not undo the steps that already ran."
    else
        echo "  config.env was not changed."
    fi
}

# ── Health and tests ──
a_health() {
    CMD=(./health-check.sh)
    ask_yn "Show detail for passing checks too (--verbose)?" n && CMD+=(--verbose)
    ask_match "Per-check timeout in seconds (Enter = 8)" "$INT_RE" "a whole number of seconds, 1 or more" "" optional
    [[ -n "$ANSWER" ]] && CMD+=(--timeout "$ANSWER")
    while :; do
        ask_text "Check list file (Enter = health-checks.conf)"
        [[ -z "$ANSWER" ]] && break
        [[ -f "$ANSWER" ]] && { CMD+=(--config "$ANSWER"); break; }
        warn "no such file: $ANSWER"
    done
    EFFECT="nothing (OK/WARN/FAIL per check; exit 1 on any FAIL)"
    SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("iamdbroles WARNs while IAM_DB_ROLES=false, by design.")
    plan_run
}
a_routes_diff() {
    CMD=(python3 tests/iam-routes-diff.py)
    EFFECT="nothing (offline: compiled route table vs the routes each service serves)"
    plan_run
}
a_policy_tests() {
    CMD=(python3 tests/test_policy.py)
    EFFECT="nothing (offline policy unit tests)"
    plan_run
}
a_iam_check() {
    CMD=(tests/iam-check.sh)
    EFFECT="nothing (pod mounts; a forged request inside each pod, which must be logged as refused)"
    SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_iam_hosts() {
    CMD=(tests/iam-hosts.sh)
    EFFECT="nothing (each host's live gate, 403 page, pod freshness and scopes against the policy)"
    SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_iam_schema() {
    CMD=(tests/iam-schema.sh)
    EFFECT="nothing (route-table copies, schemas, grants, hash chain; the chain probe is rolled back)"
    SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_iam_db() {
    local ns db s
    cfg_literal NAMESPACE medcea; ns="$ANSWER"
    cfg_literal POSTGRES_DB medcea_db; db="$ANSWER"
    echo "  Read-only (default_transaction_read_only); tests/iam-db.sh's own default is the throwaway fixture."
    ask_match "Namespace of the PostgreSQL pod" "$NS_RE" "a Kubernetes namespace: lower-case letters, digits and -" "$ns"; ns="$ANSWER"
    ask_match "PostgreSQL pod" "$POD_RE" "a pod name: lower-case letters, digits, - and ." "rdbms-postgresql-0"; local pod="$ANSWER"
    ask_match "Database" "$DB_RE" "letters, digits and _" "$db"; db="$ANSWER"
    ask_match "Mode (auto reads the database's setting)" '^(auto|false|true|legacy)$' "auto, false, true or legacy" "auto"; local mode="$ANSWER"
    CMD=(tests/iam-db.sh --namespace "$ns" --pod "$pod" --db "$db" --mode "$mode")
    ask_list "Sections, separated by spaces (Enter = catalog matrix prerequest actor writes drift)" \
        '^(catalog|matrix|prerequest|actor|writes|drift)$' "one of catalog matrix prerequest actor writes drift" opt
    for s in "${LIST[@]}"; do CMD+=(--section "$s"); done
    EFFECT="nothing (read-only session; write sections skipped)"
    SUDO=mk8s
    plan_run
}
a_iam_db_probes() {
    local s
    CMD=(tests/iam-db.sh --write-probes)
    ask_match "Mode" '^(auto|false|true|legacy)$' "auto, false, true or legacy" "auto"
    CMD+=(--mode "$ANSWER")
    ask_list "Sections, separated by spaces (Enter = the default set)" \
        '^(catalog|matrix|prerequest|actor|writes|access|drift)$' "one of catalog matrix prerequest actor writes access drift" opt
    for s in "${LIST[@]}"; do CMD+=(--section "$s"); done
    EFFECT="the throwaway fixture only (namespace medcea-iamtest; every probe rolled back)"
    LEVEL=change; SUDO=mk8s
    NOTES=("Needs a fixture that is up, loaded and applied: first 'Build the throwaway database and keep it' (Health and tests). 'Build and test the throwaway database' (run) deletes its fixture when it ends, so it leaves nothing to probe."
           "Refused against any other namespace. Afterwards: 'Delete the throwaway database'.")
    plan_run
}
a_iam_signin() {
    CMD=(tests/iam-signin.sh)
    EFFECT="Keycloak: one throwaway account per role (test-<role>-<hex>), deleted on exit; login events stay"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_iam_workbench() {
    CMD=(tests/iam-workbench.sh)
    EFFECT="Keycloak: two throwaway accounts (test-admin-/test-bio-<hex>), deleted on exit; cluster: one notebook server and its home volume, deleted on exit; the throwaway admin stays a hub user"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Needs WORKBENCH_ENABLED=true and IAM_GATES=true. Starts one notebook server (the first start pulls the image).")
    plan_run
}
a_iam_network() {
    CMD=(tests/iam-network.sh)
    EFFECT="cluster: a busybox probe pod, deleted on exit"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Meaningful only with IAM_NETPOL=true.")
    plan_run
}
a_iam_access() {
    CMD=(tests/iam-access.sh)
    EFFECT="Keycloak: 4 throwaway accounts, deleted on exit; database: their decisions stay in append-only iam.account_decision"
    LOCK=yes; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    echo "  --with-review creates THIS QUARTER'S access review as test-qa2: permanent, one per quarter."
    if ask_yn "Add --with-review (never on a platform whose qa has yet to make this quarter's review)?" n; then
        CMD+=(--with-review); LEVEL=destroy
        EFFECT+="; a PERMANENT access review for this quarter"
    fi
    NOTES=("Run after ./apps/access/deploy.sh. It leaves permanent append-only records.")
    plan_run
}
a_fixture_run() {
    CMD=(tests/iam-db-fixture.sh run)
    EFFECT="cluster: creates namespace medcea-iamtest, runs the whole IAM Phase 2 sequence there and deletes it on exit; production is only read"
    LOCK="yes, while it reads production (load)"; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}
a_fixture_keep() {
    ask_match "Database deploy mode to apply in the fixture" '^(false|true)$' "false or true" "false"
    CMD=(tests/iam-db-fixture.sh up "&&" tests/iam-db-fixture.sh load "&&" tests/iam-db-fixture.sh apply "$ANSWER")
    EFFECT="cluster: creates namespace medcea-iamtest with production's schema and medcea data (read-only from production) and KEEPS it; production is only read"
    LOCK="yes, while it reads production (load)"; LEVEL=change; SUDO=mk8s; CFG_NEEDED=yes
    NOTES=("Each command runs only if the one before it succeeded."
           "Then: 'Database write probes (fixture only)'. When done: 'Delete the throwaway database'.")
    [[ "$ANSWER" == true ]] && NOTES+=("The full run applies true only after the services step; if apply true refuses here, use false.")
    plan_run
}
a_fixture_down() {
    CMD=(tests/iam-db-fixture.sh down)
    EFFECT="deletes namespace medcea-iamtest (the fixture only, never production)"
    LEVEL=destroy; SUDO=mk8s; CFG_NEEDED=yes
    plan_run
}

# ── Edge devices ──
a_flash() {
    local erase=true
    CMD=(./edge/flash-device.sh)
    echo "  Plug the ESP32 in over USB first. WiFi name and passphrase are asked by the script itself."
    if ask_yn "Bench board with no platform identity (--unregistered: WiFi only, no slot, no database)?" n; then
        CMD+=(--unregistered)
        EFFECT="the board's flash; no database row, no sign-in"
    else
        CFG_NEEDED=yes
        menu "Role of the board" "Ask me in the wizard|" "SENSE|sensors: publishes telemetry" "CONTROL|relays: switches equipment"
        [[ "$PICK" == b ]] && return 10
        (( PICK == 2 )) && CMD+=(--role SENSE)
        (( PICK == 3 )) && CMD+=(--role CONTROL)
        # flash-device.sh matches these exactly (awk $2==u), unlike units.sh
        echo "  Unit and zone codes here are matched exactly: type them as the Units tab shows them (case matters)."
        ask_match "Restrict the slot menu to one unit code, exact case (Enter = any)" "$UNIT_RE" "$UNIT_HINT" "" optional
        [[ -n "$ANSWER" ]] && CMD+=(--unit "$ANSWER")
        ask_match "Restrict the slot menu to one zone code, exact case (Enter = any)" "$UNIT_RE" "$UNIT_HINT" "" optional
        [[ -n "$ANSWER" ]] && CMD+=(--zone "$ANSWER")
        ask_yn "Also ask the advanced template parameters (--advanced)?" n && CMD+=(--advanced)
        ask_yn "Flash and configure, but do NOT write the device row (--no-register)?" n && CMD+=(--no-register)
        flash_ui_question
        EFFECT="the board's flash, medcea.device/component rows and its MQTT credential, edge/provisioned/<hostname>.json"
        NOTES+=("A registered run signs you in to Keycloak (device code, or the --ui link).")
    fi
    while :; do
        ask_text "Serial port (Enter = autodetect /dev/ttyUSB*, /dev/ttyACM*)"
        [[ -z "$ANSWER" ]] && break
        if [[ "$ANSWER" =~ ^/dev/[A-Za-z0-9._/-]+$ && -e "$ANSWER" ]]; then CMD+=(--port "$ANSWER"); break; fi
        warn "no such device: $ANSWER"
    done
    ask_yn "Use only firmware already in edge/firmware/ (--offline)?" n && CMD+=(--offline)
    if ask_yn "Skip erasing the flash (--no-erase; only for a board you erased once already)?" n; then
        CMD+=(--no-erase); erase=false
    fi
    if $erase; then LEVEL=destroy; EFFECT="ERASES the board's flash; then $EFFECT"; else LEVEL=change; fi
    id -nG 2>/dev/null | grep -qw dialout || NOTES+=("This session is not in group dialout: the serial port may be refused.")
    SUDO=no
    plan_run
}
flash_ui_question() {   # --ui only when its port is free (it cannot move under Keycloak)
    # flash-device.sh --ui binds 8088 unless --ui-port; Keycloak's redirect URI for
    # client edge-wizard is registered on EDGE_WIZARD_PORT, where the cea-edge-wizard
    # service also listens.
    local port busy=""
    cfg_literal EDGE_WIZARD_PORT 8088; port="$ANSWER"
    [[ "$port" =~ $INT_RE ]] || port=8088
    if systemctl --user is-active --quiet cea-edge-wizard 2>/dev/null; then
        busy="the cea-edge-wizard service (./apps/edge-wizard/deploy.sh) is running and listens on it"
    elif command -v ss >/dev/null 2>&1 && [[ -n "$(ss -ltnH "sport = :$port" 2>/dev/null)" ]]; then
        busy="something already listens on it"
    fi
    if [[ -n "$busy" ]]; then
        cfg_literal ONBOARD_DOMAIN ""
        echo "  --ui is not offered: it needs port $port (Keycloak's redirect URI is fixed to it), and $busy."
        echo "  For a browser, use the always-on wizard instead: ${ANSWER:+https://$ANSWER, }the link in the Config UI's Devices tab."
        return 0
    fi
    echo "  --ui serves this run's wizard on port $port, which must stay free (the cea-edge-wizard service uses it too)."
    if ask_yn "Also serve the wizard in a browser (--ui; open the printed link with ?t=)?" n; then
        CMD+=(--ui)
        [[ "$port" != 8088 ]] && CMD+=(--ui-port "$port")
    fi
    return 0
}
a_flash_help() {
    CMD=(./edge/flash-device.sh --help)
    EFFECT="nothing (prints every option)"
    plan_run
}
a_wizard_service() {
    CMD=(./apps/edge-wizard/deploy.sh)
    EFFECT="host: the cea-edge-wizard systemd user service, linger, edge/.venv; cluster: its Service, Endpoints and Ingress"
    LOCK=yes; LEVEL=change; SUDO="mk8s (the Ingress); the user service needs none"; CFG_NEEDED=yes
    NOTES=("Needs EDGE_WIZARD_SECRET in config.env (written by ./deploy-infra.sh).")
    plan_run
}
a_wizard_unit() {
    CMD=(./edge/wizard-daemon.sh --install-unit)
    EFFECT="nothing (prints the systemd user unit; writes nothing)"
    CFG_NEEDED=yes
    plan_run
}

# ── Policy (read-only compiler commands, no cluster) ──
POLICY_CLI=(python3 apps/iam/compiler/cli.py)
a_pol_check() {
    CMD=("${POLICY_CLI[@]}" check)
    EFFECT="nothing (exit 1 on a violated invariant)"
    plan_run
}
a_pol_hosts() {
    CMD=("${POLICY_CLI[@]}" hosts)
    EFFECT="nothing"
    plan_run
}
a_pol_proxy() {
    local -a hosts items=()
    local h
    mapfile -t hosts < <("${POLICY_CLI[@]}" hosts 2>/dev/null | awk '$1 ~ /^[A-Z_]+_DOMAIN$/ { print $1 }')
    if (( ${#hosts[@]} == 0 )); then
        warn "'cli.py hosts' listed no host (is the policy valid? try Policy → check)"; return 0
    fi
    for h in "${hosts[@]}"; do items+=("$h|"); done
    menu "Which host?" "${items[@]}"
    [[ "$PICK" == b ]] && return 10
    CMD=("${POLICY_CLI[@]}" compile proxy "${hosts[PICK - 1]}")
    EFFECT="nothing (prints the allowed_groups that host's gate gets)"
    plan_run
}
a_pol_routes() {
    CMD=("${POLICY_CLI[@]}" compile routes)
    PIPE=(python3 -m json.tool)
    EFFECT="nothing (the route table as in ConfigMap medcea-iam-lib, pretty-printed)"
    plan_run
}
a_pol_dbroles() {
    menu "Which list?" "--names|the database roles the policy manages" \
        "--passwords|each role and its config.env password VARIABLE (names, not passwords)" \
        "--logins|the login roles"
    [[ "$PICK" == b ]] && return 10
    local -a f=(--names --passwords --logins)
    CMD=("${POLICY_CLI[@]}" db-roles "${f[PICK - 1]}")
    EFFECT="nothing"
    plan_run
}
a_pol_grants() {
    ask_match "Mode" '^(additive|enforce|verify)$' "additive, enforce or verify" "verify"
    CMD=("${POLICY_CLI[@]}" compile grants --mode "$ANSWER")
    ask_yn "Leave schema iam and access_svc out (--without-iam)?" n && CMD+=(--without-iam)
    EFFECT="nothing (prints SQL; runs none)"
    NOTES=("Never pipe it into psql by hand: ./apps/database/deploy.sh applies it.")
    plan_run
}
a_pol_netpol() {
    local s
    cfg_literal NAMESPACE medcea
    ask_match "Namespace" "$NS_RE" "a Kubernetes namespace: lower-case letters, digits and -" "$ANSWER"
    CMD=("${POLICY_CLI[@]}" compile netpol --namespace "$ANSWER")
    ask_list "Node IP address(es), separated by spaces (Enter = none)" "$IPV4_RE" "an IPv4 address like 192.168.1.10" opt
    for s in "${LIST[@]}"; do CMD+=(--node-ip "$s"); done
    EFFECT="nothing (prints the NetworkPolicies as JSON; ./deploy-infra.sh applies the real ones)"
    plan_run
}

# Areas: "function|label|purpose". The order is the menu's.
AREA_INSTALL=(
    "a_install|Install or update everything|Infrastructure, then every application, then a health check."
    "a_install_infra|Infrastructure only|MicroK8s, Postgres, Keycloak, Grafana, Node-RED, portal, AI workbench."
    "a_install_apps|Applications only|Database schema, wizard, config UI, scheduler, monitor, reports, flows, access."
    "a_uninstall_apps|Uninstall applications|All, or the ones you name; infrastructure keeps running; data kept unless purged."
    "a_uninstall_infra|Uninstall the infrastructure|Every service, every application and ALL data; keeps MicroK8s."
    "a_uninstall_all|Uninstall everything|All of the above plus MicroK8s, the wizard service, logs and credentials files."
)
AREA_INFRA=(
    "a_infra_deploy|Deploy or update the infrastructure|./deploy-infra.sh: after a pull, a config change or a realm key rotation."
    "a_infra_configure|Review every setting, then deploy|./deploy-infra.sh --configure."
    "a_configure_only|Edit settings only, no deploy|./infra/configure.sh: config.env by question and answer."
    "a_workbench|Redeploy only the AI workbench|./infra/deploy-workbench.sh (JupyterHub)."
    "a_workbench_switch|Turn the AI workbench on or off|WORKBENCH_ENABLED in config.env, then ./deploy-infra.sh."
    "a_infra_reset|Reset: wipe the namespace, keep MicroK8s|./deploy-infra.sh --reset: every service and ALL data."
    "a_infra_uninstall|Remove MicroK8s entirely|./deploy-infra.sh --uninstall: all cluster data."
    "a_infra_help|Show deploy-infra.sh's help|Read-only."
)
AREA_APPS=(
    "a_apps_menu|Pick components from a menu|./deploy-apps.sh (its own checkbox menu)."
    "a_apps_all|Install or update every component|./deploy-apps.sh --all."
    "a_apps_one|Deploy one component|./apps/<component>/deploy.sh."
    "a_apps_uninstall|Uninstall components|./deploy-apps.sh --uninstall: all, or the ones you name."
    "a_apps_uninstall_one|Uninstall one component directly|./apps/<component>/uninstall.sh (no confirmation of its own)."
    "a_apps_list|List the components|./deploy-apps.sh --help."
)
AREA_UNITS=(
    "a_units_list|List operators and their units|Units in effect and units waiting for qa."
    "a_units_assign|Assign units to an operator|Proposes it; a qa person other than you confirms it."
    "a_units_remove|Remove units from an account|At once; one still waiting for qa is withdrawn."
    "a_units_remove_sub|Remove units of a deleted account|By its Keycloak id (units.sh list prints it)."
)
AREA_SWITCHES=(
    "a_sw_gates|IAM_GATES — sign-in gates from the policy|Each oauth2-proxy, Grafana's role setting, the AI workbench, the onboarding wizard and pgAdmin admit the roles the policy compiles for their host."
    "a_sw_netpol|IAM_NETPOL — NetworkPolicies per pod|Only each application pod's listed callers can connect."
    "a_sw_enforce|IAM_ENFORCE — services refuse|Python services refuse instead of logging 'would refuse'."
    "a_sw_jwt|IAM_POSTGREST_JWT — config-api verifies tokens|Phase 2b: PostgREST checks the person's token."
    "a_sw_svc|IAM_DB_SERVICE_ROLES — own database roles|Phase 2.5: each client logs in as its own role, not postgres."
    "a_sw_dbroles|IAM_DB_ROLES — the database enforces|Phase 2a: per-role grants, RLS, guard triggers."
    "a_rollback_27|IAM 2.7 rollback (shows the steps)|Account decisions back out; shown, not run."
)
AREA_HEALTH=(
    "a_health|Health check|Every service and IAM control: OK / WARN / FAIL."
    "a_routes_diff|Route table vs code (offline)|python3 tests/iam-routes-diff.py."
    "a_policy_tests|Policy unit tests (offline)|python3 tests/test_policy.py."
    "a_iam_check|IAM mounts and forged requests|tests/iam-check.sh (read-only)."
    "a_iam_hosts|Live gates vs the policy|tests/iam-hosts.sh (read-only)."
    "a_iam_schema|Route-table copies, schemas, hash chain|tests/iam-schema.sh (read-only)."
    "a_iam_db|Database IAM checks, read-only|tests/iam-db.sh against production."
    "a_iam_db_probes|Database write probes (fixture only)|tests/iam-db.sh --write-probes, every probe rolled back."
    "a_iam_signin|Sign-in test, one account per role|tests/iam-signin.sh: throwaway Keycloak accounts."
    "a_iam_network|NetworkPolicy test|tests/iam-network.sh: a throwaway probe pod."
    "a_iam_access|Account decisions test|tests/iam-access.sh: throwaway accounts, permanent decision records."
    "a_fixture_run|Build and test the throwaway database|tests/iam-db-fixture.sh run: the whole sequence, then deletes namespace medcea-iamtest."
    "a_fixture_keep|Build the throwaway database and keep it|tests/iam-db-fixture.sh up, load, apply: for the write probes."
    "a_fixture_down|Delete the throwaway database|tests/iam-db-fixture.sh down."
    "a_iam_workbench|Workbench: admin cannot open others' servers|tests/iam-workbench.sh: throwaway accounts, takes the deploy lock."
)
AREA_EDGE=(
    "a_flash|Flash and register a board|./edge/flash-device.sh: an ESP32 over USB into a unit/zone slot."
    "a_flash_help|Show flash-device.sh's options|Read-only."
    "a_wizard_service|Install or update the browser wizard service|./apps/edge-wizard/deploy.sh."
    "a_wizard_unit|Print the wizard's systemd unit|./edge/wizard-daemon.sh --install-unit (writes nothing)."
)
AREA_POLICY=(
    "a_pol_check|Check the policy's invariants|cli.py check."
    "a_pol_hosts|Who each host admits|cli.py hosts."
    "a_pol_proxy|One host's allowed_groups|cli.py compile proxy <HOST_VAR>."
    "a_pol_routes|The compiled route table|cli.py compile routes (pretty-printed)."
    "a_pol_dbroles|Database roles the policy manages|cli.py db-roles."
    "a_pol_grants|The grants SQL|cli.py compile grants (printed, never run)."
    "a_pol_netpol|The NetworkPolicies|cli.py compile netpol (printed, never applied)."
)
AREAS=(
    "AREA_INSTALL|Install and uninstall|Install, update or remove the whole platform."
    "AREA_INFRA|Infrastructure|deploy-infra.sh and its settings: cluster services, workbench, reset."
    "AREA_APPS|Applications|deploy-apps.sh and the components under apps/."
    "AREA_UNITS|Operators and units|Which units an operator works in (apps/iam/units.sh)."
    "AREA_SWITCHES|IAM switches (enable / roll back)|Turn an IAM phase on or back off, in the documented order."
    "AREA_HEALTH|Health and tests|Health check, IAM checks and tests."
    "AREA_EDGE|Edge devices|Flash and register ESP32 boards; the onboarding wizard."
    "AREA_POLICY|Policy (read-only)|What apps/iam/policy/defaults.yaml compiles to."
)

after_action() {
    while :; do
        ask "Back to the menu (b) or quit (q)" "b"
        case "${ANSWER,,}" in
            b|back) return 0 ;;
            q|quit) bye ;;
            *) warn "type b or q" ;;
        esac
    done
}

run_area() {   # run_area ARRAY_NAME TITLE
    local -n _guide_area="$1"
    local title="$2" e fn rc
    local -a labels=()
    for e in "${_guide_area[@]}"; do labels+=("${e#*|}"); done
    while :; do
        menu "$title" "${labels[@]}"
        [[ "$PICK" == b ]] && return 0
        e="${_guide_area[PICK - 1]}"; fn="${e%%|*}"
        reset_plan
        "$fn"; rc=$?
        (( rc == 10 )) || after_action
    done
}

# ── Main ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}MedCEA guide${NC} — answer the questions; every command is shown before it runs."
$DRY_RUN && echo -e "${YELLOW}Dry run: nothing is run and config.env is not changed.${NC}"
[[ -f "$CFG" ]] || warn "$CFG not found: most commands need it. Install first (Install and uninstall → 1)."
declare -a AREA_LABELS=()
for e in "${AREAS[@]}"; do AREA_LABELS+=("${e#*|}"); done
while :; do
    menu "What do you want to do?" "${AREA_LABELS[@]}"
    [[ "$PICK" == b ]] && bye
    e="${AREAS[PICK - 1]}"; title="${e#*|}"
    run_area "${e%%|*}" "${title%%|*}"
done
