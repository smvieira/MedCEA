#!/bin/bash
# =============================================================================
# configure.sh — fill config.env by question and answer
# =============================================================================
# Called by deploy-infra.sh before anything is installed; runnable on its own.
#
#   ./infra/configure.sh            ask every question, current values as defaults
#   ./infra/configure.sh --missing  ask only the required values that are empty
#                                   (a no-op on a complete config.env)
#
# Creates config.env from config.env.example if it does not exist. Pressing
# Enter keeps the current value AND the current line, so derived values such as
# DOMAIN="$(tailscale ip -4 ...).nip.io" stay expressions unless you change them.
#
# Run it from the repository root, like every other script (config.env is read
# relative to the working directory). CONFIG_FILE overrides the path.

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-config.env}"
EXAMPLE_FILE="$SCRIPT_DIR/../config.env.example"
MODE="all"
[[ "${1:-}" == "--missing" ]] && MODE="missing"

# Values the deploy cannot start without and that nothing generates for you.
REQUIRED=(PROJECT_NAME DOMAIN ADMIN_USER ADMIN_PASS POSTGRES_PASS DOCKERHUB_USER DOCKERHUB_PAT)

die() { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }

# --- config.env access --------------------------------------------------------

# The value as the deploy will see it, i.e. after the shell has expanded it.
cfg_get() {
    ( source "./$CONFIG_FILE" >/dev/null 2>&1; printf '%s' "${!1}" )
}

# Replace KEY's line in place (or append it), double-quoted with the four
# characters that are special inside double quotes escaped. awk takes the line
# through ENVIRON because -v would interpret backslashes in it.
cfg_set() {
    local key="$1" val="$2"
    val="${val//\\/\\\\}"; val="${val//\"/\\\"}"; val="${val//\$/\\\$}"; val="${val//\`/\\\`}"
    if grep -q "^${key}=" "$CONFIG_FILE"; then
        CFG_KEY="$key" CFG_LINE="${key}=\"${val}\"" awk '
            !done && index($0, ENVIRON["CFG_KEY"] "=") == 1 { print ENVIRON["CFG_LINE"]; done = 1; next }
            { print }' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && cat "$CONFIG_FILE.tmp" > "$CONFIG_FILE"
        rm -f "$CONFIG_FILE.tmp"
    else
        printf '%s="%s"\n' "$key" "$val" >> "$CONFIG_FILE"
    fi
}

# Write only when the answer differs from what the line already evaluates to,
# so accepting a default never flattens an expression into a literal.
cfg_update() {
    [[ "$2" == "$(cfg_get "$1")" ]] || cfg_set "$1" "$2"
}

# Should this question be asked in the current mode?
wanted() {
    [[ "$MODE" == "all" ]] || [[ -z "$(cfg_get "$1")" ]]
}

# --- prompts ------------------------------------------------------------------

# ask VAR "Question" "default" — dies on EOF instead of looping on empty input.
ask() {
    local __var="$1" __q="$2" __def="$3" __ans
    if [[ -n "$__def" ]]; then
        read -r -p "$(echo -e "  ${BOLD}${__q}${NC} [${__def}]: ")" __ans || die "input closed"
    else
        read -r -p "$(echo -e "  ${BOLD}${__q}${NC}: ")" __ans || die "input closed"
    fi
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

ask_yn() {
    local __ans
    while true; do
        ask __ans "$1 (y/n)" "$2"
        case "${__ans,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
        esac
    done
}

section() { echo ""; echo -e "${YELLOW}── $* ──${NC}"; }
info()    { echo -e "  $*"; }
link()    { echo -e "    ${CYAN}$*${NC}"; }

gen_password() {
    local p
    p="$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 20)"
    [[ ${#p} -eq 20 ]] || p="$(openssl rand -hex 10)"
    printf '%s' "$p"
}

# Passwords are spliced unencoded into YAML strings, a postgres:// URL,
# `helm --set`, a pgpass line and a curl form body. Each of those breaks on a
# different punctuation character (: @ / , & + " \), so the safe set is narrow.
PASS_RE='^[A-Za-z0-9._~-]{8,64}$'

# ask_password VAR "Label" — hidden input, typed twice; Enter generates one
# (or keeps the current one, when there is a current one).
ask_password() {
    local __var="$1" __label="$2" __cur __a __b
    __cur="$(cfg_get "$__var")"
    while true; do
        if [[ -n "$__cur" ]]; then
            read -r -s -p "$(echo -e "  ${BOLD}${__label}${NC} [Enter = keep current]: ")" __a || die "input closed"
        else
            read -r -s -p "$(echo -e "  ${BOLD}${__label}${NC} [Enter = generate one]: ")" __a || die "input closed"
        fi
        echo ""
        if [[ -z "$__a" ]]; then
            if [[ -n "$__cur" ]]; then return; fi
            __a="$(gen_password)"
            cfg_set "$__var" "$__a"
            info "${GREEN}Generated:${NC} ${BOLD}${__a}${NC}  (saved in $CONFIG_FILE — note it down)"
            return
        fi
        if [[ ! "$__a" =~ $PASS_RE ]]; then
            info "${RED}8-64 characters from A-Z a-z 0-9 . _ ~ - only${NC} (other punctuation breaks the URLs and YAML it is written into)."
            continue
        fi
        read -r -s -p "$(echo -e "  ${BOLD}Repeat ${__label}${NC}: ")" __b || die "input closed"
        echo ""
        [[ "$__a" == "$__b" ]] || { info "${RED}They do not match — try again.${NC}"; continue; }
        cfg_set "$__var" "$__a"
        return
    done
}

# --- Tailscale ----------------------------------------------------------------

# missing | daemon (installed, service not running) | login (running, not
# connected to a tailnet) | up
tailscale_state() {
    command -v tailscale >/dev/null 2>&1 || { echo missing; return; }
    tailscale ip -4 >/dev/null 2>&1 && { echo up; return; }
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet tailscaled || { echo daemon; return; }
    elif tailscale status 2>&1 | grep -q "failed to connect"; then
        echo daemon; return
    fi
    echo login
}

tailscale_help() {
    info "Tailscale gives this machine a fixed 100.x.y.z address you can reach from your laptop"
    info "or phone, at home or away, without opening router ports. A LAN IP works too, but only"
    info "on the local network, and it changes if the router hands out a new one."
    echo ""
    case "$1" in
        missing)
            info "${BOLD}Tailscale is not installed.${NC} To set it up:"
            info "1. Create a free account (Google, Microsoft, GitHub or e-mail login):"
            link "https://login.tailscale.com/start"
            info "2. Install it on this machine (official install script, asks for sudo):"
            link "curl -fsSL https://tailscale.com/install.sh | sh"
            info "   Other methods: https://tailscale.com/download/linux"
            info "3. Connect it, then open the URL it prints and log in:"
            link "sudo tailscale up" ;;
        daemon)
            info "${BOLD}Tailscale is installed but its service is not running.${NC} Start it, then connect:"
            link "sudo systemctl enable --now tailscaled"
            link "sudo tailscale up" ;;
        login)
            info "${BOLD}Tailscale is running but not connected to a tailnet.${NC} Connect it, then open"
            info "the URL it prints and log in:"
            link "sudo tailscale up" ;;
    esac
    echo ""
    info "Afterwards:"
    info "- Install Tailscale on every device that should open the platform, with the same account:"
    link "https://tailscale.com/download"
    info "- Turn off key expiry for this server, or it drops off the tailnet after 180 days:"
    link "https://login.tailscale.com/admin/machines  → this machine → ⋯ → Disable key expiry"
}

# Do the step tailscale_help describes for this state. Returns non-zero if it failed.
tailscale_fix() {
    case "$1" in
        missing) curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up ;;
        daemon)  sudo systemctl enable --now tailscaled && sudo tailscale up ;;
        login)   sudo tailscale up ;;
    esac
}

# Runs on every invocation, complete config or not. USE_TAILSCALE records
# whether DOMAIN depends on Tailscale: "true" means a stopped Tailscale would
# change or strand DOMAIN, so it is fatal; "false" means LAN-only on purpose,
# so it is not raised again; empty means not decided yet.
FORCE_DOMAIN=""
check_tailscale() {
    local want state ts_ip choice fix_label
    want="$(cfg_get USE_TAILSCALE)"
    state="$(tailscale_state)"

    if [[ "$state" == "up" ]]; then
        ts_ip="$(tailscale ip -4 2>/dev/null | head -1)"
        echo -e "${GREEN}Tailscale is connected (${ts_ip}).${NC}"
        if [[ -z "$want" ]]; then
            [[ "$(cfg_get DOMAIN)" == "${ts_ip}.nip.io" ]] && cfg_set USE_TAILSCALE "true"
        fi
        return
    fi
    if [[ "$want" == "false" ]]; then
        info "Tailscale: not used (USE_TAILSCALE=false). To switch: ./deploy-infra.sh --configure"
        return
    fi
    if [[ ! -t 0 ]]; then
        if [[ "$want" == "true" ]]; then
            die "DOMAIN uses this machine's Tailscale IP, but Tailscale is not up ($state).
       Start it (sudo tailscale up), or run ./infra/configure.sh in a terminal to switch to the LAN IP."
        fi
        echo -e "${YELLOW}Tailscale is not set up ($state) — continuing with the LAN IP. Run ./infra/configure.sh for instructions.${NC}"
        return
    fi

    while true; do
        echo ""
        echo -e "${YELLOW}── Tailscale ──${NC}"
        [[ "$want" == "true" ]] && info "${RED}DOMAIN was set to this machine's Tailscale IP, and Tailscale is not up now.${NC}"
        tailscale_help "$state"
        case "$state" in
            missing) fix_label="install and connect it now (runs the commands above)" ;;
            daemon)  fix_label="start and connect it now (runs the commands above)" ;;
            login)   fix_label="connect it now (runs sudo tailscale up)" ;;
        esac
        echo ""
        info "  Enter) check again (after doing the steps in another terminal)"
        info "  a)     ${fix_label}"
        info "  s)     continue without Tailscale (LAN only)"
        ask choice "Choice" ""
        case "${choice,,}" in
            a) tailscale_fix "$state" || info "${RED}That did not finish — see the output above.${NC}" ;;
            s) cfg_set USE_TAILSCALE "false"
               # A domain built on the Tailscale IP is now unreachable; ask again.
               [[ "$want" == "true" ]] && FORCE_DOMAIN=1
               return ;;
        esac
        state="$(tailscale_state)"
        if [[ "$state" == "up" ]]; then
            ts_ip="$(tailscale ip -4 2>/dev/null | head -1)"
            echo -e "${GREEN}Tailscale is connected (${ts_ip}).${NC}"
            # The domain question offers this IP; ask it when DOMAIN does not use it yet.
            [[ "$(cfg_get DOMAIN)" == "${ts_ip}.nip.io" ]] || FORCE_DOMAIN=1
            return
        fi
    done
}

# --- preconditions ------------------------------------------------------------

[[ -f "$EXAMPLE_FILE" ]] || die "config.env.example not found next to infra/ — run from the repository root."

if [[ ! -s "$CONFIG_FILE" ]]; then
    cp "$EXAMPLE_FILE" "$CONFIG_FILE"
    MODE="all"
    echo -e "${GREEN}Created $CONFIG_FILE from config.env.example.${NC}"
else
    # The template is the base: its layout, comments and variables, with every
    # value the existing config.env already has carried over line for line.
    # Variables added to the template since config.env was made appear with
    # their defaults; keys only config.env has (appended by older deploys) are
    # kept at the end. Nothing is written when the result would be identical.
    awk '
        FNR == NR { if (match($0, /^[A-Za-z_][A-Za-z0-9_]*=/)) { k = substr($0, 1, RLENGTH - 1); if (!(k in old)) { old[k] = $0; order[++n] = k } } next }
        match($0, /^[A-Za-z_][A-Za-z0-9_]*=/) { k = substr($0, 1, RLENGTH - 1); seen[k] = 1; print ((k in old) ? old[k] : $0); next }
        { print }
        END {
            hdr = 0
            for (i = 1; i <= n; i++) if (!(order[i] in seen)) {
                if (!hdr) { print ""; print "# --- Kept from the previous config.env (not in config.env.example) ---"; hdr = 1 }
                print old[order[i]]
            }
        }' "$CONFIG_FILE" "$EXAMPLE_FILE" > "$CONFIG_FILE.merged"
    if cmp -s "$CONFIG_FILE.merged" "$CONFIG_FILE"; then
        rm -f "$CONFIG_FILE.merged"
    else
        cp -p "$CONFIG_FILE" "$CONFIG_FILE.bak" && chmod 600 "$CONFIG_FILE.bak"
        cat "$CONFIG_FILE.merged" > "$CONFIG_FILE"
        rm -f "$CONFIG_FILE.merged"
        echo -e "${GREEN}Rebased $CONFIG_FILE on config.env.example, keeping your values${NC} (previous copy: $CONFIG_FILE.bak)."
    fi
fi
# It is about to hold every platform password.
chmod 600 "$CONFIG_FILE"

check_tailscale

if [[ "$MODE" == "missing" ]]; then
    MISSING=()
    for v in "${REQUIRED[@]}"; do [[ -n "$(cfg_get "$v")" ]] || MISSING+=("$v"); done
    [[ ${#MISSING[@]} -eq 0 && -z "$FORCE_DOMAIN" ]] && exit 0
fi

if [[ ! -t 0 ]]; then
    die "$CONFIG_FILE is incomplete (${MISSING[*]:-run interactively}) and there is no terminal to ask on.
       Run ./infra/configure.sh in a terminal, or fill config.env by hand (see config.env.example)."
fi

if [[ -e "$(dirname "$CONFIG_FILE")/.$(basename "$CONFIG_FILE").swp" ]]; then
    echo -e "${YELLOW}Warning: $CONFIG_FILE seems to be open in vim (.swp file). Saving there later will undo these answers.${NC}"
fi

echo ""
echo -e "${GREEN}MedCEA configuration${NC} — press Enter to accept the value in [brackets]."
[[ "$MODE" == "missing" ]] && echo "Only the required values that are still empty are asked: ${MISSING[*]}"

# --- 1. Project identity ------------------------------------------------------
if wanted PROJECT_NAME; then
    section "Project"
    info "One name used as the MQTT topic root, Kubernetes namespace and Keycloak realm."
    info "Changing it after boards are flashed means reflashing them."
    while true; do
        ask _v "Project name" "$(cfg_get PROJECT_NAME)"
        [[ "$_v" =~ ^[a-z][a-z0-9-]{1,30}$ ]] && break
        info "${RED}Lowercase, starts with a letter, 2-31 characters from a-z 0-9 -.${NC}"
    done
    cfg_update PROJECT_NAME "$_v"
fi

# --- 2. Domain ----------------------------------------------------------------
if wanted DOMAIN || [[ -n "$FORCE_DOMAIN" ]]; then
    section "Domain"
    info "Every web UI is served at <service>.<DOMAIN>, e.g. keycloak.<DOMAIN>."
    info "nip.io resolves <anything>.<IP>.nip.io to <IP>, so no DNS setup is needed."
    _ts_ip="$(tailscale ip -4 2>/dev/null | head -1)"
    _lan_ip="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    _cur="$(cfg_get DOMAIN)"
    [[ -n "$_ts_ip" ]] && info "With the Tailscale IP, the platform is reachable from every device on your tailnet."
    info "Changing DOMAIN after deployment means re-running ./deploy-infra.sh (certificates and SSO redirects use it)."
    echo ""
    _opts=(); _vals=()
    # After "continue without Tailscale", the current Tailscale-based domain is not an option.
    [[ "$(cfg_get USE_TAILSCALE)" == "false" && -z "$_ts_ip" && "$_cur" =~ ^100\. ]] && _cur=""
    [[ -n "$_cur" ]]    && { _opts+=("keep current      ${_cur}");       _vals+=("$_cur"); }
    [[ -n "$_ts_ip" ]]  && { _opts+=("Tailscale IP      ${_ts_ip}.nip.io"); _vals+=("${_ts_ip}.nip.io"); }
    [[ -n "$_lan_ip" ]] && { _opts+=("LAN IP            ${_lan_ip}.nip.io (local network only)"); _vals+=("${_lan_ip}.nip.io"); }
    _opts+=("custom domain     (you provide DNS or /etc/hosts entries)"); _vals+=("")
    for i in "${!_opts[@]}"; do info "  $((i+1))) ${_opts[$i]}"; done
    while true; do
        ask _c "Choice" "1"
        [[ "$_c" =~ ^[0-9]+$ ]] && (( _c >= 1 && _c <= ${#_opts[@]} )) && break
    done
    _v="${_vals[$((_c-1))]}"
    while [[ -z "$_v" || ! "$_v" =~ ^[a-zA-Z0-9.-]+$ ]]; do
        ask _v "Domain (e.g. medcea.lab.example.org)" ""
    done
    cfg_update DOMAIN "$_v"
    if [[ -n "$_ts_ip" && "$(cfg_get DOMAIN)" == "${_ts_ip}.nip.io" ]]; then
        cfg_set USE_TAILSCALE "true"
    else
        cfg_set USE_TAILSCALE "false"
    fi
fi

# --- 3. Administrator ---------------------------------------------------------
if wanted ADMIN_USER || wanted ADMIN_PASS; then
    section "Administrator"
    info "The platform admin: Keycloak console, Grafana, Node-RED and the portal."
    info "Grafana's demo users (developer, viewer) get the same password unless you set GRAFANA_*_PASS."
fi
if wanted ADMIN_USER; then
    while true; do
        ask _v "Admin username" "$(cfg_get ADMIN_USER)"
        [[ "$_v" =~ ^[a-z][a-z0-9._-]{1,30}$ ]] && break
        info "${RED}Lowercase letters, digits, . _ - (starting with a letter).${NC}"
    done
    cfg_update ADMIN_USER "$_v"
fi
wanted ADMIN_PASS && ask_password ADMIN_PASS "Admin password"

# --- 4. PostgreSQL ------------------------------------------------------------
if wanted POSTGRES_PASS; then
    section "PostgreSQL"
    info "Superuser password of the platform database. You rarely type it — generating one is fine."
    ask_password POSTGRES_PASS "Postgres password"
fi
if [[ "$MODE" == "all" ]]; then
    while true; do
        ask _v "Database volume size" "$(cfg_get STORAGE_SIZE)"
        [[ "$_v" =~ ^[0-9]+(Mi|Gi|Ti)$ ]] && break
        info "${RED}A Kubernetes quantity such as 10Gi or 500Mi.${NC}"
    done
    cfg_update STORAGE_SIZE "$_v"
fi

# --- 5. Docker Hub ------------------------------------------------------------
if wanted DOCKERHUB_USER || wanted DOCKERHUB_PAT; then
    section "Docker Hub"
    info "Needed to pull the Bitnami Helm charts (PostgreSQL, OAuth2 Proxy), which Docker Hub"
    info "only serves to logged-in users, and to stay under the anonymous image-pull rate limit."
    info "A free account is enough."
    echo ""
    info "1. No account yet? Sign up (free):"
    link "https://app.docker.com/signup"
    info "2. Your username is your Docker ID — shown top-right after logging in, and at:"
    link "https://app.docker.com/settings/general"
    info "   Use the username, not your e-mail address: token logins reject the e-mail."
    info "3. Create an access token at:"
    link "https://app.docker.com/settings/personal-access-tokens"
    info "   → Generate new token → description \"medcea\", any expiry,"
    info "     Access permissions: ${BOLD}Public Repo Read-only${NC} (the platform only pulls)."
    info "   → Copy the token (it starts with dckr_pat_). Docker shows it only once."
    echo ""
    while true; do
        ask _u "Docker Hub username" "$(cfg_get DOCKERHUB_USER)"
        [[ "$_u" == *@* ]] && { info "${RED}That is an e-mail address — enter your Docker ID instead.${NC}"; continue; }
        [[ -n "$_u" ]] && break
    done
    _cur_pat="$(cfg_get DOCKERHUB_PAT)"
    while true; do
        if [[ -n "$_cur_pat" ]]; then
            read -r -s -p "$(echo -e "  ${BOLD}Docker Hub access token${NC} [Enter = keep current]: ")" _p || die "input closed"
            _p="${_p:-$_cur_pat}"
        else
            read -r -s -p "$(echo -e "  ${BOLD}Docker Hub access token${NC} (dckr_pat_...): ")" _p || die "input closed"
        fi
        echo ""
        [[ -n "$_p" ]] || continue
        # The registry's token endpoint answers 200 for valid credentials and
        # 401 otherwise, which checks the pair without touching the cluster.
        _code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -u "${_u}:${_p}" \
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:bitnamicharts/postgresql:pull" 2>/dev/null)"
        case "$_code" in
            200) info "${GREEN}Docker Hub accepted the credentials.${NC}"; break ;;
            401) info "${RED}Docker Hub rejected that username/token pair.${NC}"
                 ask_yn "Try again" "y" && continue
                 break ;;
            *)   info "${YELLOW}Could not reach Docker Hub to check them (HTTP ${_code:-none}) — saving as entered.${NC}"
                 break ;;
        esac
    done
    cfg_update DOCKERHUB_USER "$_u"
    cfg_update DOCKERHUB_PAT "$_p"
fi

# --- 6. Optional settings (full run only) -------------------------------------
if [[ "$MODE" == "all" ]]; then
    section "Other settings"
    _tz="$(cfg_get NODE_RED_TZ)"
    _sys_tz="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
    # The example ships Europe/London; offer the machine's zone instead of it.
    [[ "$_tz" == "Europe/London" && -n "$_sys_tz" ]] && _tz="$_sys_tz"
    info "Timezone for Node-RED flows and schedules (tz database name)."
    while true; do
        ask _v "Timezone" "$_tz"
        [[ -f "/usr/share/zoneinfo/$_v" ]] && break
        info "${RED}Unknown timezone. Examples: Europe/Lisbon, Europe/London, UTC.${NC}"
    done
    cfg_update NODE_RED_TZ "$_v"

    echo ""
    info "AI workbench (JupyterHub): per-user notebooks behind Keycloak, about 2 GB of images."
    _def="y"; [[ "$(cfg_get WORKBENCH_ENABLED)" == "false" ]] && _def="n"
    if ask_yn "Deploy the AI workbench" "$_def"; then
        cfg_update WORKBENCH_ENABLED "true"
    else
        cfg_update WORKBENCH_ENABLED "false"
    fi
fi

# --- Summary ------------------------------------------------------------------
section "Saved to $CONFIG_FILE"
for v in PROJECT_NAME DOMAIN USE_TAILSCALE ADMIN_USER POSTGRES_DB STORAGE_SIZE DOCKERHUB_USER NODE_RED_TZ WORKBENCH_ENABLED; do
    printf '  %-18s %s\n' "$v" "$(cfg_get "$v")"
done
for v in ADMIN_PASS POSTGRES_PASS DOCKERHUB_PAT; do
    if [[ -n "$(cfg_get "$v")" ]]; then printf '  %-18s %s\n' "$v" "(set)"; else printf '  %-18s %s\n' "$v" "(empty)"; fi
done
info "Service secrets (OAuth clients, cookies) are generated during deployment."
info "Re-run any time: ./infra/configure.sh   (or ./deploy-infra.sh --configure)"
echo ""
