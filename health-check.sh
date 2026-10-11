#!/bin/bash
# health-check.sh — MedCEA deployment health checker
#
# Usage:
#   ./health-check.sh [OPTIONS]
#
# Options:
#   -c, --config FILE    Check config file (default: health-checks.conf in same dir)
#   -v, --verbose        Show detailed output for all checks, including passing ones
#   -t, --timeout SECS   Timeout per check in seconds (default: 8)
#   -h, --help           Show this help
#
# The config file lists services to check (see health-checks.conf for format).
# Variable references like $DOMAIN in targets are expanded from config.env.

# Colors (defined early for --help)
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/health-checks.conf"
VERBOSE=false
TIMEOUT=8

# Auto-detect kubectl: prefer microk8s (no sudo needed if user is in microk8s group)
if command -v microk8s &>/dev/null && microk8s kubectl version --client &>/dev/null 2>&1; then
    KUBECTL="microk8s kubectl"
elif command -v kubectl &>/dev/null; then
    KUBECTL="kubectl"
else
    KUBECTL="sudo microk8s kubectl"
fi

# =============================================================================
# --help
# =============================================================================
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo ""
    echo -e "${BOLD}health-check.sh${NC} — MedCEA deployment health checker"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./health-check.sh [OPTIONS]"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo "  -c, --config FILE    Check config file (default: health-checks.conf)"
    echo "  -v, --verbose        Show detail for passing checks too"
    echo "  -t, --timeout SECS   Per-check timeout in seconds (default: 8)"
    echo "  -h, --help           Show this help"
    echo ""
    echo -e "${GREEN}Config file format (health-checks.conf):${NC}"
    echo "  # comment"
    echo "  Service Name  | type  | target            | [options]"
    echo ""
    echo "  Types:"
    echo -e "  ${CYAN}k8s${NC}    Kubernetes workload: NAMESPACE/KIND/NAME"
    echo -e "         e.g. medcea/deployment/keycloak"
    echo -e "              medcea/statefulset/rdbms-postgresql"
    echo ""
    echo -e "  ${CYAN}http${NC}   HTTP GET check: URL (\$VARs from config.env are expanded)"
    echo -e "         options: skip_tls       skip TLS certificate verification"
    echo -e "                  expect=CODE    e.g. expect=302, expect=30x, expect=2xx"
    echo ""
    echo -e "  ${CYAN}tcp${NC}    TCP port: HOST:PORT"
    echo -e "         e.g. localhost:31883"
    echo ""
    echo -e "  ${CYAN}juju${NC}   [unused] Juju model/app status — kept for older configs; Juju was"
    echo -e "         removed with Kubeflow, so these checks report SKIP."
    echo -e "         e.g. kubeflow            (all apps in model 'kubeflow')"
    echo -e "              kubeflow/dex-auth   (specific app within model)"
    echo ""
    exit 0
fi

# =============================================================================
# Parse args
# =============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --config|-c) CONFIG_FILE="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --timeout|-t) TIMEOUT="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}" >&2; exit 1 ;;
    esac
done

# =============================================================================
# Load config.env for variable expansion in targets
# =============================================================================
if [[ -f "${SCRIPT_DIR}/config.env" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/config.env" 2>/dev/null || true
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}ERROR: Config file not found: $CONFIG_FILE${NC}" >&2
    exit 1
fi

# =============================================================================
# Helpers
# =============================================================================
_trim() {
    local s="${1#"${1%%[![:space:]]*}"}"
    echo "${s%"${s##*[![:space:]]}"}"
}

PASS=0; FAIL=0; WARN=0; SKIP=0
# Each entry: "STATUS|Name|detail message"
_RESULTS=()

_record() {
    local status="$1" name="$2" msg="$3"
    _RESULTS+=("${status}|${name}|${msg}")
    case "$status" in
        OK)   (( PASS++ )) ;;
        WARN) (( WARN++ )) ;;
        FAIL) (( FAIL++ )) ;;
        SKIP) (( SKIP++ )) ;;
    esac
}

# =============================================================================
# Check: Kubernetes workload readiness
# target: NAMESPACE/KIND/NAME
# =============================================================================
check_k8s() {
    local name="$1" target="$2"
    local ns kind res

    ns="$(  echo "$target" | cut -d/ -f1)"
    kind="$( echo "$target" | cut -d/ -f2)"
    res="$(  echo "$target" | cut -d/ -f3)"

    if [[ -z "$ns" || -z "$kind" || -z "$res" ]]; then
        _record FAIL "$name" "Invalid k8s target '${target}' — expected NAMESPACE/KIND/NAME"
        return
    fi

    # Fail fast if namespace doesn't exist
    if ! $KUBECTL get namespace "$ns" &>/dev/null 2>&1; then
        _record FAIL "$name" "Namespace '${ns}' does not exist"
        return
    fi

    # Get ready/desired replica counts before checking rollout status
    local ready total
    ready="$($KUBECTL get "${kind}/${res}" -n "$ns" \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "")"
    total="$($KUBECTL get "${kind}/${res}" -n "$ns" \
        -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "")"
    ready="${ready:-0}"; total="${total:-?}"

    # rollout status is the authoritative pass/fail signal
    local out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL rollout status "${kind}/${res}" \
        -n "$ns" --timeout="${TIMEOUT}s" 2>&1) || exit_code=$?

    local label="${kind}/${res} (${ns})"
    if [[ $exit_code -eq 0 ]]; then
        _record OK "$name" "${label}: ${ready}/${total} ready"
    else
        _record FAIL "$name" "${label}: ${ready}/${total} ready — ${out}"
    fi
}

# =============================================================================
# Check: HTTP endpoint
# options (comma-separated): skip_tls, expect=CODE
# =============================================================================
check_http() {
    local name="$1" url="$2" options="$3"
    local curl_args=(-s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT")
    # The platform serves its own CA-signed certificates. Trust that CA here, so
    # a health check verifies the chain instead of blindly skipping TLS.
    [[ -f "$SCRIPT_DIR/.ca/ca.crt" ]] && curl_args+=(--cacert "$SCRIPT_DIR/.ca/ca.crt")
    local expect="2xx"

    IFS=',' read -ra opts <<< "$options"
    for opt in "${opts[@]}"; do
        opt="$(_trim "$opt")"
        case "$opt" in
            skip_tls)    curl_args+=(-k) ;;
            expect=*)    expect="${opt#expect=}" ;;
        esac
    done

    local http_code exit_code=0
    http_code=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || exit_code=$?

    # Normalize: empty response from curl error
    [[ -z "$http_code" || "$http_code" == "000" ]] && http_code="000"

    # Match expected pattern
    local ok=false
    case "$expect" in
        2xx) [[ "$http_code" =~ ^2 ]] && ok=true ;;
        3xx) [[ "$http_code" =~ ^3 ]] && ok=true ;;
        30x) [[ "$http_code" =~ ^30 ]] && ok=true ;;
        4xx) [[ "$http_code" =~ ^4 ]] && ok=true ;;
        *)   [[ "$http_code" == "$expect" ]] && ok=true ;;
    esac

    if [[ "$http_code" == "000" ]]; then
        _record FAIL "$name" "No response (timeout/refused) — ${url}"
    elif $ok; then
        _record OK "$name" "HTTP ${http_code} — ${url}"
    else
        _record WARN "$name" "HTTP ${http_code} (expected ${expect}) — ${url}"
    fi
}

# =============================================================================
# Check: TCP port reachability
# target: HOST:PORT
# =============================================================================
check_tcp() {
    local name="$1" target="$2"
    local host="${target%:*}"
    local port="${target##*:}"

    if [[ -z "$host" || -z "$port" ]]; then
        _record FAIL "$name" "Invalid tcp target '${target}' — expected HOST:PORT"
        return
    fi

    if timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null; then
        _record OK "$name" "TCP ${host}:${port} reachable"
    else
        _record FAIL "$name" "TCP ${host}:${port} unreachable"
    fi
}

# =============================================================================
# Check: Juju model/application unit status
# target: MODEL_NAME or MODEL_NAME/APP_NAME
#   MODEL_NAME       — checks all applications in that Juju model
#   MODEL_NAME/APP   — checks a specific application within that model
# =============================================================================
check_juju() {
    local name="$1" target="$2"
    local model app=""

    if [[ "$target" == */* ]]; then
        model="${target%%/*}"
        app="${target#*/}"
    else
        model="$target"
    fi

    if ! command -v juju &>/dev/null; then
        _record SKIP "$name" "juju command not found — skipping"
        return
    fi

    local raw exit_code=0
    if [[ -n "$app" ]]; then
        raw=$(timeout "$TIMEOUT" juju status -m "$model" "$app" --format json 2>&1) || exit_code=$?
    else
        raw=$(timeout "$TIMEOUT" juju status -m "$model" --format json 2>&1) || exit_code=$?
    fi

    if [[ $exit_code -ne 0 || -z "$raw" ]]; then
        _record FAIL "$name" "juju status -m '${model}' failed: ${raw}"
        return
    fi

    # Parse unit statuses via python3 (always available on Ubuntu)
    # Note: use -c to avoid heredoc/pipe stdin conflict (both can't be stdin at once)
    local summary
    summary=$(printf '%s' "$raw" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    print(f"parse error: {e}")
    sys.exit(0)
ok = blocked = maintenance = 0
issues = []
for app_name, app_data in d.get("applications", {}).items():
    for unit_name, unit_data in app_data.get("units", {}).items():
        ws  = unit_data.get("workload-status", {}).get("current", "unknown")
        js  = unit_data.get("juju-status",    {}).get("current", "unknown")
        msg = unit_data.get("workload-status", {}).get("message", "")
        if ws in ("error", "blocked") or js in ("error", "failed"):
            blocked += 1
            issues.append(f"{unit_name}: {ws}/{js}" + (f" ({msg})" if msg else ""))
        elif ws in ("maintenance", "waiting", "allocating") or js in ("allocating", "rebooting"):
            maintenance += 1
            issues.append(f"{unit_name}: {ws}/{js}")
        else:
            ok += 1
total = ok + blocked + maintenance
detail = f"{total} units: {ok} OK"
if maintenance: detail += f", {maintenance} not-ready"
if blocked: detail += f", {blocked} blocked/error"
if issues: detail += " — " + "; ".join(issues[:3]) + ("..." if len(issues) > 3 else "")
if not d.get("applications"):
    detail = "no applications found"
    print(f"WARN:{detail}")
elif blocked:
    print(f"FAIL:{detail}")
elif maintenance:
    print(f"WARN:{detail}")
else:
    print(f"OK:{detail}")
') || true

    local status_flag="${summary%%:*}"
    local detail="${summary#*:}"
    local label="model:${model}${app:+/}${app}"

    case "$status_flag" in
        OK)   _record OK   "$name" "juju ${label}: ${detail}" ;;
        FAIL) _record FAIL "$name" "juju ${label}: ${detail}" ;;
        WARN) _record WARN "$name" "juju ${label}: ${detail}" ;;
        *)    _record WARN "$name" "juju ${label}: ${summary}" ;;
    esac
}

# =============================================================================
# Print a single result line
# =============================================================================
COL_NAME=28

_print_result() {
    local status="$1" name="$2" msg="$3"
    local label
    case "$status" in
        OK)   label="${GREEN}[  OK  ]${NC}" ;;
        WARN) label="${YELLOW}[ WARN ]${NC}" ;;
        FAIL) label="${RED}[ FAIL ]${NC}"  ;;
        SKIP) label="${DIM}[ SKIP ]${NC}"  ;;
    esac

    if [[ "$status" != "OK" ]] || $VERBOSE; then
        printf "  %b  %-${COL_NAME}s  %b%s%b\n" "$label" "$name" "$DIM" "$msg" "$NC"
    else
        printf "  %b  %s\n" "$label" "$name"
    fi
}

# =============================================================================
# Main: read config, run checks, print results
# =============================================================================
echo ""
echo -e "  ${BOLD}MedCEA Health Check${NC}  $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  ${DIM}Config: ${CONFIG_FILE}  |  Timeout: ${TIMEOUT}s${NC}"
echo ""

while IFS='|' read -r name type target options || [[ -n "$name" ]]; do
    # Skip comments and blank lines
    name="$(_trim "$name")"
    [[ "$name" =~ ^# ]] && continue
    [[ -z "$name" ]] && continue

    type="$(    _trim "$type")"
    target="$(  _trim "$target")"
    options="$( _trim "${options:-}")"

    # Expand $VAR references sourced from config.env
    # Using printf '%s' to avoid issues with backslashes in URLs
    target="$(eval printf '%s' "\"${target}\"" 2>/dev/null || echo "$target")"

    case "$type" in
        k8s)  check_k8s  "$name" "$target" ;;
        http) check_http "$name" "$target" "$options" ;;
        tcp)  check_tcp  "$name" "$target" ;;
        juju) check_juju "$name" "$target" ;;
        "")   continue ;;  # blank type (trailing whitespace only line)
        *)    _record WARN "$name" "Unknown check type '${type}'" ;;
    esac

    # Print result immediately as each check completes
    last="${_RESULTS[-1]}"
    IFS='|' read -r _s _n _m <<< "$last"
    _print_result "$_s" "$_n" "$_m"

done < "$CONFIG_FILE"

# =============================================================================
# Summary
# =============================================================================
TOTAL=$(( PASS + WARN + FAIL + SKIP ))
echo ""
echo -n "  "
if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All ${TOTAL} checks passed.${NC}"
elif [[ $FAIL -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}${PASS} OK, ${WARN} warning(s), 0 failures${NC}${DIM} — ${TOTAL} checks${NC}"
else
    echo -e "${RED}${BOLD}${FAIL} failure(s)${NC}, ${YELLOW}${WARN} warning(s)${NC}, ${GREEN}${PASS} OK${NC}${DIM} — ${TOTAL} checks${NC}"
fi
echo ""

# Exit non-zero if any failures
[[ $FAIL -eq 0 ]]
