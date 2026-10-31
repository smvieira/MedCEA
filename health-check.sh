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
    echo -e "  ${CYAN}iamchain${NC} the access policy history's hash chain: DATABASE"
    echo -e "         e.g. \$POSTGRES_DB   (iam_policy.verify_chain(); SKIP before migration 008a)"
    echo ""
    echo -e "  ${CYAN}iamdbroles${NC} IAM_DB_ROLES (Phase 2): DATABASE"
    echo -e "         WARN while it is false (the database still serves the pre-policy grants),"
    echo -e "         so a default install does not print \"All checks passed\" — on purpose"
    echo ""
    echo -e "  ${CYAN}dbclients${NC} which role each database client logs in as (IAM_DB_SERVICE_ROLES, Phase 2.5)"
    echo -e "         WARN while a client disagrees with the flag (deploy it again)"
    echo ""
    echo -e "  ${CYAN}iamgrants${NC} the database's grants equal the compiled policy: DATABASE"
    echo -e "         (cli.py compile grants --mode verify, in a read-only transaction; drift is a FAIL;"
    echo -e "         --without-iam while schema iam is absent, from dba_iam_flag; a stale"
    echo -e "         medcea_auth.role_widening digest is drift too)"
    echo ""
    echo -e "  ${CYAN}iamdecisions${NC} account decisions waiting for qa (IAM 2.7): DATABASE"
    echo -e "         SKIP without schema iam or role access_svc; FAIL without iam.confirm_decision"
    echo -e "         (./apps/access/deploy.sh) or when access_svc may not execute it"
    echo -e "         (./apps/database/deploy.sh); WARN on a decision pending for over 7 days"
    echo -e "         or a pending mail settings change"
    echo ""
    echo -e "  ${CYAN}postgrest${NC} config-api verifies tokens (IAM_POSTGREST_JWT, Phase 2b): NAMESPACE"
    echo -e "         true: config-api's env is the JWT template's, its key checksum matches"
    echo -e "         Secret medcea-jwks, every key id there is still published by the realm"
    echo -e "         (else FAIL: run ./deploy-infra.sh), and a forged token gets 401; false: WARN"
    echo ""
    echo -e "  ${CYAN}iamenforce${NC} the Python services enforce the route table (IAM_ENFORCE, IAM 2.6): NAMESPACE"
    echo -e "         FAIL when ConfigMap medcea-iam-lib disagrees with config.env (./deploy-infra.sh),"
    echo -e "         and on IAM_ENFORCE=true with IAM_DB_ROLES=false (assigned_run unchecked) or a pod copy"
    echo -e "         still false (fails open without /iam/); WARN on a pod copy still true, or while false"
    echo ""
    echo -e "  ${CYAN}iammqtt${NC} the MQTT Explorer's personal credentials (IAM_MQTT_PERSON, IAM 3.5): NAMESPACE"
    echo -e "         FAIL when config.env, the broker (pod annotation, sidecar, conf), the Explorer page"
    echo -e "         and iam-api disagree on the mode; under true also when the shared mqtt-explorer"
    echo -e "         account or a person credential is in the 1883 file, another name is in the"
    echo -e "         WebSocket file, or IAM_DB_ROLES is false; WARN while false, or when the broker's"
    echo -e "         sidecar last read the database over 5 minutes ago. Usernames only, never a hash"
    echo ""
    echo -e "  ${CYAN}grafanarole${NC} Grafana's role setting is the access policy's (IAM 3.1): NAMESPACE"
    echo -e "         FAIL when the live role path differs from the compiled one (./deploy-infra.sh),"
    echo -e "         strict is not true or Grafana may grant Grafana Admin; WARN while IAM_GATES=false"
    echo -e "         (any enabled account is at least Viewer); SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}iamworkbench${NC} the AI workbench's gate is the access policy's (IAM 3.2): NAMESPACE"
    echo -e "         FAIL when the hub's deployed allowed_groups/admin_groups differ from the compiled"
    echo -e "         ones, allow_all or admin_users is set, admin_access, delete_pvc or auth_state is on,"
    echo -e "         the notebooks' NetworkPolicy allows private addresses, or the hub pod runs older"
    echo -e "         values (./infra/deploy-workbench.sh); WARN while IAM_GATES=false; SKIP while"
    echo -e "         WORKBENCH_ENABLED is not true or there is no hub"
    echo ""
    echo -e "  ${CYAN}onboardroles${NC} the onboarding wizard admits the access policy's roles (IAM 3.4): -"
    echo -e "         FAIL when the running daemon's --required-role differs from policy_tool edge-wizard"
    echo -e "         (./apps/edge-wizard/deploy.sh) or is missing while IAM_GATES=true; WARN while"
    echo -e "         IAM_GATES=false; SKIP when no daemon runs (the http check reports it)"
    echo ""
    echo -e "  ${CYAN}pgadminroles${NC} pgAdmin admits the access policy's roles (IAM 3.4): NAMESPACE"
    echo -e "         FAIL when the deployment's OAUTH2_ADDITIONAL_CLAIMS differs from policy_tool pgadmin"
    echo -e "         (./deploy-infra.sh); WARN while IAM_GATES=false; SKIP without the deployment"
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
# Check: the access policy's hash-chained history
# target: DATABASE (iam_policy.verify_chain(), migration 008a). Runs as postgres
# inside the PostgreSQL pod; the password is read there, never on a command line.
# =============================================================================
check_iamchain() {
    local name="$1" db="$2" out exit_code=0
    # The SQL comes from the here-document, not the loop's stdin (the config file).
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT CASE WHEN to_regprocedure('iam_policy.verify_chain()') IS NULL THEN 'absent' ELSE 'present' END;
SELECT ok, events, first_bad_event, detail FROM iam_policy.verify_chain();
SQL
) || exit_code=$?
    if grep -qx absent <<<"$out"; then   # stderr may come first: match the line
        _record SKIP "$name" "iam_policy.verify_chain() not in ${db} yet (migration 008a: ./apps/database/deploy.sh)"
        return
    fi
    out="$(grep -E '^[tf]\|' <<<"$out" || tail -1 <<<"$out")"
    local ok events bad detail
    IFS='|' read -r ok events bad detail <<<"$out"
    if [[ $exit_code -ne 0 || ( "$ok" != "t" && "$ok" != "f" ) ]]; then
        _record FAIL "$name" "verify_chain() did not run: ${out:0:120}"
    elif [[ "$ok" == "t" ]]; then
        _record OK "$name" "hash chain intact, ${events} event(s)"
    else
        _record FAIL "$name" "hash chain broken at event ${bad}: ${detail}"
    fi
}

# =============================================================================
# Check: IAM_DB_ROLES (Phase 2) — the mode the database records, against config.env
# =============================================================================
check_iamdbroles() {
    local name="$1" db="$2" out
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -U postgres -d "$0" -tA' "$db" 2>&1 <<'SQL'
SELECT 'mode=' || coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'unset');
SQL
) || true
    local mode
    mode="$(grep -o 'mode=[a-z]*' <<<"$out" | head -1 | cut -d= -f2)"
    if [[ -z "$mode" ]]; then
        _record FAIL "$name" "could not read medcea.platform_setting: ${out:0:120}"
    elif [[ "$mode" == "unset" ]]; then
        _record SKIP "$name" "IAM_DB_ROLES not recorded yet (migration 008b: ./apps/database/deploy.sh)"
    elif [[ "$mode" != "${IAM_DB_ROLES:-false}" ]]; then
        _record FAIL "$name" "the database records IAM_DB_ROLES=$mode, config.env says ${IAM_DB_ROLES:-false} (./apps/database/deploy.sh)"
    elif [[ "$mode" == "false" ]]; then
        _record WARN "$name" "IAM_DB_ROLES=false: per-role database grants are compiled but not in force (IAM Phase 2)"
    else
        _record OK "$name" "IAM_DB_ROLES=true: per-role grants, RLS and guard triggers in force"
    fi
}

# =============================================================================
# Check: IAM_DB_SERVICE_ROLES (Phase 2.5) — which role each database client logs in as
# =============================================================================
check_dbclients() {
    local name="$1" cu c u want on_role=() off=() unreadable=()
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-db-roles.sh"
    local live=()
    mapfile -t live < <(db_clients_live "$NAMESPACE" 2>/dev/null)
    if [[ ${#live[@]} -eq 0 ]]; then
        _record SKIP "$name" "no database client is deployed"; return
    fi
    for cu in "${live[@]}"; do
        read -r c u <<<"$cu"
        want="$(db_client_role "$c")"
        if [[ "$u" == "?" ]]; then unreadable+=("$c")
        elif [[ "$u" == "$want" ]]; then on_role+=("$c")
        else off+=("$c")
        fi
    done
    if [[ ${#unreadable[@]} -gt 0 ]]; then
        _record WARN "$name" "cannot read the database user of: ${unreadable[*]}"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" && ${#off[@]} -gt 0 ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES=true, still on postgres: ${off[*]} (deploy them again; Grafana and pgAdmin: ./deploy-infra.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" && ${#on_role[@]} -gt 0 ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES=false, still on their own role: ${on_role[*]} (deploy them again, then ./apps/database/deploy.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]]; then
        _record OK "$name" "all ${#on_role[@]} on their own role (IAM Phase 2.5)"
    else
        _record OK "$name" "all ${#off[@]} on postgres (IAM_DB_SERVICE_ROLES=false)"
    fi
}

# =============================================================================
# Check: the database's grants equal the compiled access policy (read-only)
# =============================================================================
check_iamgrants() {
    local name="$1" db="$2" sql out exit_code=0 flag rc=0
    # --without-iam exactly when the database deploy would compile it so (IAM 2.7):
    # the one helper decides, and an unreadable answer is a FAIL, never a default.
    # (dba_iam_flag, apps/database/lib-db-apply.sh, in a child bash that timeout bounds)
    out="$(timeout "$TIMEOUT" bash -c 'REPO_ROOT="$0"; KUBECTL="$1"; source "$0/apps/database/lib-db-apply.sh"
                                       dba_iam_flag "$2" rdbms-postgresql-0 "$3"' \
                "$SCRIPT_DIR" "$KUBECTL" "$NAMESPACE" "$db" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record FAIL "$name" "cannot tell whether schema iam is compiled (exit $rc): $(tail -1 <<<"$out" | cut -c1-160)"; return
    fi
    flag="$(grep -x -- '--without-iam' <<<"$out" || true)"
    sql="$(python3 "${SCRIPT_DIR}/apps/iam/compiler/cli.py" compile grants --mode verify $flag 2>&1)" || {
        _record FAIL "$name" "cli.py compile grants failed: ${sql:0:120}"; return; }
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA' "$db" \
        2>&1 <<<"$sql") || exit_code=$?
    if grep -q 'medcea.platform_setting" does not exist\|function medcea_auth' <<<"$out" && [[ $exit_code -ne 0 ]]; then
        _record SKIP "$name" "migration 008b not applied yet (./apps/database/deploy.sh)"
    elif [[ $exit_code -eq 0 ]] && grep -q 'grants verified' <<<"$out"; then
        _record OK "$name" "database grants equal the compiled policy${flag:+ ($flag: no access component)}"
    else
        _record FAIL "$name" "grant drift: $(grep -m1 -E 'ERROR|DETAIL' <<<"$out" | cut -c1-200)"
    fi
}

# =============================================================================
# Check: account decisions waiting for qa (IAM 2.7) — read-only, no Keycloak
# target: DATABASE. Drift between Keycloak and the decisions is not computed here
# (that would mint admin tokens): the User Manager's Decisions tab shows it.
# =============================================================================
check_iamdecisions() {
    local name="$1" db="$2" out exit_code=0
    # each step only after the guards before it, so no query names a missing object
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT pg_catalog.to_regnamespace('iam') IS NOT NULL AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'access_svc') AS present,
       pg_catalog.to_regprocedure('iam.confirm_decision(integer,text)') IS NOT NULL AS built \gset
\if :present
\if :built
SELECT 'exec|' || CASE WHEN pg_catalog.has_function_privilege('access_svc', 'iam.confirm_decision(integer,text)', 'EXECUTE')
                       THEN 't' ELSE 'f' END;   -- text || boolean is 'true', not 't'
SELECT 'stale|' || count(*) || '|' || coalesce(min(decision_id)::text, '-')
  FROM iam.account_decision WHERE status = 'pending_qa' AND made_at < now() - interval '7 days';
SELECT 'mail|' || count(*) || '|' || coalesce(min(decision_id)::text, '-')
  FROM iam.account_decision WHERE status = 'pending_qa' AND kind = 'mail_settings';
SELECT 'pending|' || count(*) FROM iam.account_decision WHERE status = 'pending_qa';
\else
SELECT 'state|unbuilt';
\endif
\else
SELECT 'state|absent';
\endif
SQL
) || exit_code=$?
    local state can_exec stale stale_id mail mail_id pending
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    can_exec="$(grep -m1 '^exec|' <<<"$out" | cut -d'|' -f2)"
    IFS='|' read -r _ stale stale_id <<<"$(grep -m1 '^stale|' <<<"$out")"
    IFS='|' read -r _ mail mail_id <<<"$(grep -m1 '^mail|' <<<"$out")"
    pending="$(grep -m1 '^pending|' <<<"$out" | cut -d'|' -f2)"
    if [[ "$state" == absent ]]; then
        _record SKIP "$name" "schema iam or role access_svc absent (./apps/access/deploy.sh installs them)"
    elif [[ "$state" == unbuilt ]]; then
        _record FAIL "$name" "schema iam has no iam.confirm_decision: run ./apps/access/deploy.sh (IAM 2.7)"
    elif [[ $exit_code -ne 0 || -z "$can_exec" || -z "$pending" ]]; then
        _record FAIL "$name" "could not read the account decisions: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"
    elif [[ "$can_exec" != t ]]; then
        _record FAIL "$name" "access_svc may not execute iam.confirm_decision: run ./apps/database/deploy.sh"
    elif [[ "$stale" -gt 0 ]]; then
        _record WARN "$name" "${stale} decision(s) waiting for qa for over 7 days (oldest #${stale_id}): User Manager → Decisions"
    elif [[ "$mail" -gt 0 ]]; then
        _record WARN "$name" "a mail settings change waits for qa (decision #${mail_id}): the realm still sends with the old account"
    else
        _record OK "$name" "${pending} decision(s) waiting for qa, none older than 7 days"
    fi
}

# =============================================================================
# Check: config-api verifies tokens (IAM plan Phase 2b) — read-only
# target: NAMESPACE (default $NAMESPACE)
# =============================================================================
check_postgrest() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" envs mode want problems=() sum ann b64 realm ip code
    envs="$(timeout "$TIMEOUT" $KUBECTL get deployment config-api -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}={.value}{.valueFrom.secretKeyRef.name}/{.valueFrom.secretKeyRef.key}{"\n"}{end}' 2>&1)" \
        || { _record FAIL "$name" "cannot read deployment config-api: ${envs:0:120}"; return; }
    mode=legacy; grep -q '^PGRST_JWT_SECRET=' <<<"$envs" && mode=jwt
    want=legacy; [[ "${IAM_POSTGREST_JWT:-false}" == "true" ]] && want=jwt
    if [[ "$mode" != "$want" ]]; then
        _record FAIL "$name" "config-api runs $mode, config.env says IAM_POSTGREST_JWT=${IAM_POSTGREST_JWT:-false} (./apps/frontend/deploy.sh)"
        return
    fi
    if [[ "$mode" == legacy ]]; then
        _record WARN "$name" "IAM_POSTGREST_JWT=false: config-api does not verify tokens (IAM Phase 2b)"
        return
    fi
    # contract C1 (apps/frontend/k8s/config-api-jwt.yaml)
    local line
    for line in 'PGRST_JWT_SECRET=medcea-jwks/jwks-sig.json' 'AUTHENTICATOR_PASSWORD=db-authenticator/password' \
                'PGRST_JWT_AUD=medcea-api/' 'PGRST_JWT_ROLE_CLAIM_KEY=.medcea_pgrst_role/' \
                'PGRST_DB_PRE_REQUEST=medcea_auth.pre_request/'; do
        grep -qxF "$line" <<<"$envs" || problems+=("env ${line%%=*} is not ${line#*=}")
    done
    grep -q '^PGRST_DB_URI=postgres://authenticator:\$(AUTHENTICATOR_PASSWORD)@' <<<"$envs" \
        || problems+=("PGRST_DB_URI does not take AUTHENTICATOR_PASSWORD")
    sum="$($KUBECTL get secret medcea-jwks -n "$ns" -o jsonpath='{.data.jwks-sig\.json}' 2>/dev/null | base64 -d 2>/dev/null | sha256sum | cut -c1-64)"
    ann="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/jwks-checksum}' 2>/dev/null)"
    [[ -n "$ann" && "$ann" == "$sum" ]] || problems+=("config-api runs other keys than Secret medcea-jwks (./deploy-infra.sh rolls it)")
    # the pod's password is read at start: the template names the Secret version it was made for
    ann="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/auth-secret-version}' 2>/dev/null)"
    sum="$($KUBECTL get secret db-authenticator -n "$ns" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null)"
    [[ -n "$ann" && "$ann" == "$sum" ]] || problems+=("Secret db-authenticator changed since config-api started (./apps/frontend/deploy.sh)")
    # every key id we hand out must still be published by the realm
    ip="$($KUBECTL get svc keycloak -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
    realm="$(curl -s -m "$TIMEOUT" "http://${ip}/realms/${KEYCLOAK_REALM:-medcea}/protocol/openid-connect/certs" 2>/dev/null)"
    local k stale=""
    for k in jwks-sig.json jwks.json; do
        b64="$($KUBECTL get secret medcea-jwks -n "$ns" -o jsonpath="{.data.${k//./\\.}}" 2>/dev/null)"
        stale+="$(REALM="$realm" python3 -c '
import json, os, sys
try:
    live = {k.get("kid") for k in json.loads(os.environ["REALM"])["keys"]}
    ours = {k.get("kid") for k in json.loads(sys.stdin.read())["keys"]}
except Exception:
    print(" unreadable(" + sys.argv[1] + ")"); sys.exit()
gone = sorted(x for x in ours - live if x)
print("".join(" %s:%s" % (sys.argv[1], g) for g in gone) or ("" if ours else " empty(" + sys.argv[1] + ")"))
' "$k" < <(base64 -d <<<"$b64" 2>/dev/null))"
    done
    [[ -z "$stale" ]] || problems+=("key ids the realm no longer publishes or unreadable:${stale} (./deploy-infra.sh)")
    # a forged token must be refused, never served as anon
    ip="$($KUBECTL get svc config-api -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
    code="$(curl -s -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -H 'Authorization: Bearer x.y.z' "http://${ip}:3000/cea_unit?limit=1" 2>/dev/null)"
    [[ "$code" == 401 ]] || problems+=("a forged Bearer token got HTTP ${code:-no answer}, not 401")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "config-api verifies tokens; keys current; forged token refused"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Check: the Python services enforce the route table (IAM_ENFORCE, IAM 2.6) — read-only
# target: NAMESPACE (default $NAMESPACE). Reads the ConfigMap and the deployments only:
# the NetworkPolicies admit no host traffic to scheduler, monitor or dbmgmt.
# =============================================================================
check_iamenforce() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" json mode want dc v stale=()
    want=false; [[ "${IAM_ENFORCE:-false}" == "true" ]] && want=true
    json="$(timeout "$TIMEOUT" $KUBECTL get configmap medcea-iam-lib -n "$ns" -o jsonpath='{.data.settings\.json}' 2>/dev/null)"
    mode="$(python3 -c 'import json, sys; print(str(json.load(sys.stdin).get("enforce") is True).lower())' <<<"$json" 2>/dev/null)"
    if [[ -z "$mode" ]]; then
        _record FAIL "$name" "ConfigMap medcea-iam-lib missing or unreadable (./deploy-infra.sh)"
        return
    fi
    if [[ "$mode" != "$want" ]]; then
        _record FAIL "$name" "ConfigMap says enforce=$mode, config.env IAM_ENFORCE=${IAM_ENFORCE:-false} (./deploy-infra.sh)"
        return
    fi
    # the pods' copy, used only when /iam/ is missing (dbmgmt fails closed without it anyway);
    # an empty copy is false, as the services read it
    for dc in scheduler:api monitor:api config-ui:recipe-fileserver access:api; do
        v="$(timeout "$TIMEOUT" $KUBECTL get deployment "${dc%%:*}" -n "$ns" \
            -o jsonpath="{.spec.template.spec.containers[?(@.name==\"${dc#*:}\")].env[?(@.name==\"IAM_ENFORCE\")].value}" 2>/dev/null)" \
            || continue                                     # not deployed
        [[ "$v" == "true" ]] || v=false
        [[ "$v" == "$want" ]] || stale+=("${dc%%:*}")
    done
    # assigned_run (an operator's execute/stop/status/trigger) is checked only by the
    # database functions under IAM_DB_ROLES=true: no route-level check by decision
    if [[ "$want" == "true" && "${IAM_DB_ROLES:-false}" != "true" ]]; then
        _record FAIL "$name" "IAM_ENFORCE=true with IAM_DB_ROLES=false: operators can start and stop other units' runs (./guide.sh IAM_DB_ROLES, or IAM_ENFORCE back to false)"
    elif [[ ${#stale[@]} -gt 0 && "$want" == "true" ]]; then
        _record FAIL "$name" "pod IAM_ENFORCE copy still false: ${stale[*]} (without /iam/ they let every request through: redeploy them, no run active)"
    elif [[ ${#stale[@]} -gt 0 ]]; then
        _record WARN "$name" "pod IAM_ENFORCE copy differs: ${stale[*]} (redeploy them; the copy is used only when /iam/ is missing)"
    elif [[ "$want" == "false" ]]; then
        _record WARN "$name" "IAM_ENFORCE=false: services only log what they would refuse (IAM 2.6)"
    else
        _record OK "$name" "services refuse what the route table does not allow; every pod agrees"
    fi
}

# =============================================================================
# Check: the MQTT Explorer's personal credentials (IAM_MQTT_PERSON, IAM 3.5) — read-only
# target: NAMESPACE. Every part must follow config.env: the broker pod's annotation
# medcea/mqtt-mode, the sidecar's MQTT_PERSON_CREDENTIALS, the conf (per_listener_settings),
# the page's data-mqtt-mode (ConfigMap mqtt-explorer-html) and iam-api's /healthz mode
# (through kubectl exec: its NetworkPolicy admits no host traffic but the kubelet's).
# Reads the broker's files' usernames (cut -d: -f1) and status.json, never a hash.
# =============================================================================
check_iammqtt() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" want ann env conf page api users ws st problems=() warns=()
    want=false; [[ "${IAM_MQTT_PERSON:-false}" == "true" ]] && want=true
    ann="$(timeout "$TIMEOUT" $KUBECTL get deployment mosquitto -n "$ns" \
        -o jsonpath='{.spec.template.metadata.annotations.medcea/mqtt-mode}' 2>/dev/null)" \
        || { _record FAIL "$name" "no Mosquitto deployment in $ns"; return; }
    env="$($KUBECTL get deployment mosquitto -n "$ns" \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="mqtt-auth-sync")].env[?(@.name=="MQTT_PERSON_CREDENTIALS")].value}' 2>/dev/null)"
    conf=false
    $KUBECTL get configmap mosquitto-config -n "$ns" -o jsonpath='{.data.mosquitto\.conf}' 2>/dev/null \
        | grep -qx 'per_listener_settings true' && conf=true
    [[ "${ann:-false}" == "$want" ]] || problems+=("broker pod annotation says ${ann:-false} (./deploy-infra.sh)")
    [[ "${env:-false}" == "$want" ]] || problems+=("broker sidecar runs ${env:-false} (./deploy-infra.sh)")
    [[ "$conf" == "$want" ]] || problems+=("broker conf per_listener_settings is $conf (./deploy-infra.sh)")
    page="$($KUBECTL get configmap mqtt-explorer-html -n "$ns" -o jsonpath='{.data.index\.html}' 2>/dev/null \
        | sed -n 's/.*data-mqtt-mode="\([a-z_]*\)".*/\1/p' | head -1)"
    if [[ -n "$page" || "$want" == true ]]; then
        [[ "$page" == "$([[ "$want" == true ]] && echo person || echo legacy)" ]] \
            || problems+=("the Explorer page is in mode '${page:-pre-3.5}' (./apps/mqtt-explorer/deploy.sh)")
    fi
    if [[ "$want" == true ]]; then
        api="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/iam-api -- python3 -c \
            'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8085/healthz", timeout=5).read().decode())' 2>/dev/null)"
        case "$(python3 -c 'import json, sys; d = json.loads(sys.argv[1]); print(str(d.get("mode") is True).lower() + ("" if d.get("mqtt_digest") else "-nodoc"))' "$api" 2>/dev/null)" in
            true) ;;
            true-nodoc) problems+=("iam-api has no valid mqtt.json (./deploy-infra.sh)") ;;
            false) problems+=("iam-api still reads IAM_MQTT_PERSON=false (./deploy-infra.sh; it follows within a minute)") ;;
            *) problems+=("iam-mqttx does not answer (./apps/iam/deploy.sh)") ;;
        esac
        [[ "${IAM_DB_ROLES:-false}" == "true" ]] || problems+=("IAM_DB_ROLES=false: the broker cannot read person credentials (mqtt_auth's grants)")
        users="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd 2>/dev/null)"
        ws="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd-ws 2>/dev/null)"
        grep -qx 'mqtt-explorer' <<<"$users"$'\n'"$ws" && problems+=("the shared mqtt-explorer account is still in a password file")
        grep -q '^explorer-' <<<"$users" && problems+=("a person credential is in the 1883 file")
        [[ -n "$ws" ]] || problems+=("no WebSocket password file (passwd-ws)")
        [[ -n "$ws" ]] && grep -qv '^explorer-' <<<"$ws" && problems+=("a name outside explorer- is in the WebSocket file")
    fi
    st="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cat /mosquitto/auth/status.json 2>/dev/null)"
    if [[ -n "$st" ]]; then
        python3 -c 'import datetime, json, sys
d = json.loads(sys.argv[1]).get("last_db_ok")
t = datetime.datetime.strptime(d, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) if d else None
sys.exit(0 if t and (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() < 300 else 1)' "$st" 2>/dev/null \
            || warns+=("the broker's sidecar has not read the database for over 5 minutes (it keeps the last set; person writes are dropped)")
    fi
    if [[ ${#problems[@]} -gt 0 ]]; then
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    elif [[ "$want" == false ]]; then
        $KUBECTL get deployment iam-api -n "$ns" >/dev/null 2>&1 \
            || warns+=("iam-api is not deployed (./apps/iam/deploy.sh, needed before the switch)")
        _record WARN "$name" "IAM_MQTT_PERSON=false: the Explorer uses the shared mqtt-explorer account (read and send on the whole topic root, also on the LAN port 31883)${warns:+; ${warns[*]}}"
    elif [[ ${#warns[@]} -gt 0 ]]; then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "personal credentials on the WebSocket listener only; broker, page and iam-api agree"
    fi
}

# =============================================================================
# Check: Grafana's role setting is the policy's (IAM 3.1) — read-only
# target: NAMESPACE (default $NAMESPACE). Compares the deployment's env with
# policy_grafana (infra/lib-oauth2-proxy.sh), the function deploy-infra renders.
# =============================================================================
check_grafanarole() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" envs path strict assign problems=()
    envs="$(timeout "$TIMEOUT" $KUBECTL get deployment grafana -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[?(@.name=="grafana")].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)" \
        || { _record SKIP "$name" "no Grafana deployment in $ns"; return; }
    path="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=//p' <<<"$envs")"
    strict="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=//p' <<<"$envs")"
    assign="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN=//p' <<<"$envs")"
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        _record WARN "$name" "IAM_GATES=false: Grafana admits any enabled account, at least as Viewer (pre-3.1 setting)"
        return
    fi
    local GRAFANA_ROLE_PATH="" GRAFANA_ROLE_STRICT=""
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh" || ! REPO_ROOT="$SCRIPT_DIR" policy_grafana 2>/dev/null; then
        _record FAIL "$name" "cannot compile Grafana's role setting (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    [[ "$path" == "$GRAFANA_ROLE_PATH" ]] || problems+=("the live role path is not the compiled one (./deploy-infra.sh)")
    [[ "$strict" == "true" ]] || problems+=("role_attribute_strict is '${strict}', not true: a role without a setting still signs in")
    [[ "$assign" == "false" ]] || problems+=("allow_assign_grafana_admin is '${assign}', not false")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "Editor/Viewer from the access policy; others refused; Grafana Admin only break-glass"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Check: the AI workbench's gate is the policy's (IAM 3.2) — read-only
# target: NAMESPACE. Reads the values helm deployed (Secret hub, values.yaml) on
# stdin — they hold the client secret, so only the verdict fields are printed —
# and compares them with policy_workbench (infra/lib-oauth2-proxy.sh).
# =============================================================================
check_iamworkbench() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" live problems=()
    if [[ "${WORKBENCH_ENABLED:-true}" != "true" ]]; then
        _record SKIP "$name" "WORKBENCH_ENABLED is not true"; return
    fi
    live="$(timeout "$TIMEOUT" $KUBECTL get secret hub -n "$ns" -o jsonpath='{.data.values\.yaml}' 2>/dev/null \
        | base64 -d 2>/dev/null | python3 -c '
import json, sys, yaml
try:
    v = yaml.safe_load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(v, dict):
    sys.exit(1)
c = (v.get("hub") or {}).get("config") or {}
a, g = c.get("Authenticator") or {}, c.get("GenericOAuthenticator") or {}
np = ((v.get("singleuser") or {}).get("networkPolicy") or {})
eg = np.get("egressAllowRules") or {}
out = {"allow_all": a.get("allow_all"), "admin_users": sorted(a.get("admin_users") or []),
       "existing": a.get("allow_existing_users"), "auth_state": a.get("enable_auth_state"),
       "allowed": sorted(g.get("allowed_groups") or []), "admins": sorted(g.get("admin_groups") or []),
       "key": g.get("auth_state_groups_key"), "admin_access": (c.get("JupyterHub") or {}).get("admin_access"),
       "delete_pvc": (c.get("KubeSpawner") or {}).get("delete_pvc"),
       "netpol": np.get("enabled"), "private": eg.get("privateIPs"), "metadata": eg.get("cloudMetadataServer")}
for k, x in out.items():
    print(f"{k}\t{json.dumps(x)}")')" || { _record SKIP "$name" "no hub Secret in $ns (workbench not deployed)"; return; }
    declare -A L=()
    local k x
    while IFS=$'\t' read -r k x; do L[$k]="$x"; done <<<"$live"
    [[ "${L[admin_access]}" == false ]] || problems+=("admin_access is ${L[admin_access]}: a hub admin can open others' servers")
    [[ "${L[delete_pvc]}" == false ]] || problems+=("delete_pvc is ${L[delete_pvc]}: removing a hub user deletes the home")
    [[ "${L[auth_state]}" != true ]] || problems+=("enable_auth_state is true: a hub admin can read people's Keycloak tokens")
    [[ "${L[existing]}" != true ]] || problems+=("allow_existing_users is true: every user in the hub database gets in")
    [[ "${L[netpol]}" == true && "${L[private]}" == false && "${L[metadata]}" == false ]] \
        || problems+=("the notebooks' NetworkPolicy is off or allows private addresses")
    local tmpl pod
    tmpl="$($KUBECTL get deployment hub -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.checksum/secret}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$ns" -l component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.checksum/secret}{"\n"}{end}' 2>/dev/null | sort -u)"
    [[ -n "$tmpl" && "$pod" == "$tmpl" ]] || problems+=("the running hub pod does not carry the deployed values (rollout pending?)")
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        if [[ ${#problems[@]} -eq 0 ]]; then
            _record WARN "$name" "IAM_GATES=false: the workbench admits any realm account (pre-3.2 sign-in)"
        else
            local IFS=';'; _record FAIL "$name" "${problems[*]}"
        fi
        return
    fi
    local WORKBENCH_ALLOWED_GROUPS="" WORKBENCH_ADMIN_GROUPS="" WORKBENCH_ALLOW_ALL="" WORKBENCH_ADMIN_USERS="" WORKBENCH_403_MESSAGE=""
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh" || ! REPO_ROOT="$SCRIPT_DIR" policy_workbench 2>/dev/null; then
        _record FAIL "$name" "cannot compile the workbench's gate (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    local want_allowed want_admins
    want_allowed="$(python3 -c 'import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))' "$WORKBENCH_ALLOWED_GROUPS")"
    want_admins="$(python3 -c 'import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))' "$WORKBENCH_ADMIN_GROUPS")"
    [[ "${L[allow_all]}" == false ]] || problems+=("allow_all is ${L[allow_all]}")
    [[ "${L[admin_users]}" == "[]" ]] || problems+=("admin_users is set: OAuthenticator admits them whatever the policy says")
    [[ "${L[allowed]}" == "$want_allowed" ]] || problems+=("allowed_groups ${L[allowed]} is not the compiled $want_allowed (./infra/deploy-workbench.sh)")
    [[ "${L[admins]}" == "$want_admins" ]] || problems+=("admin_groups ${L[admins]} is not the compiled $want_admins")
    [[ "${L[key]}" == '"oauth_user.groups"' ]] || problems+=("auth_state_groups_key is ${L[key]}")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "admits $want_allowed from the access policy; hub admins $want_admins without admin_access"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Check: the onboarding wizard's roles are the policy's (IAM 3.4) — read-only
# Compares the running daemon's --required-role (argv: a role list, no secret)
# with policy_tool edge-wizard (infra/lib-policy-tools.sh), the list
# edge/wizard-daemon.sh passes.
# =============================================================================
check_onboardroles() {
    local name="$1" argv have want
    argv="$(pgrep -af '[w]izard_server.py .*--daemon' | head -1)"
    if [[ -z "$argv" ]]; then
        _record SKIP "$name" "no onboarding wizard daemon runs (systemctl --user status cea-edge-wizard)"
        return
    fi
    have="$(sed -n 's/.* --required-role \([^ ]*\).*/\1/p' <<<"$argv")"
    # shellcheck source=/dev/null
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
            || ! want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool edge-wizard 2>/dev/null)"; then
        _record FAIL "$name" "cannot compile the onboarding roles (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        if [[ "$have" == "$want" ]]; then
            _record WARN "$name" "IAM_GATES=false: the wizard admits ${want:-any signed-in account} (EDGE_WIZARD_ROLE, pre-policy)"
        else
            _record FAIL "$name" "the wizard admits ${have:-any signed-in account}, EDGE_WIZARD_ROLE says ${want:-any} (./apps/edge-wizard/deploy.sh)"
        fi
    elif [[ -z "$have" ]]; then
        _record FAIL "$name" "the wizard runs without --required-role: any signed-in account may erase a board (./apps/edge-wizard/deploy.sh)"
    elif [[ "$have" != "$want" ]]; then
        _record FAIL "$name" "the wizard admits $have, the policy compiles $want (./apps/edge-wizard/deploy.sh, no run active)"
    else
        _record OK "$name" "admits $want from the access policy"
    fi
}

# =============================================================================
# Check: pgAdmin's sign-in roles are the policy's (IAM 3.4) — read-only
# target: NAMESPACE. PGADMIN_CONFIG_OAUTH2_CONFIG also holds the client secret:
# it reaches python on stdin, which prints only OAUTH2_ADDITIONAL_CLAIMS.
# =============================================================================
check_pgadminroles() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" have want same
    timeout "$TIMEOUT" $KUBECTL get deployment pgadmin -n "$ns" >/dev/null 2>&1 \
        || { _record SKIP "$name" "no pgAdmin deployment in $ns"; return; }
    have="$($KUBECTL get deployment pgadmin -n "$ns" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="PGADMIN_CONFIG_OAUTH2_CONFIG")].value}' 2>/dev/null \
        | python3 -c '
import ast, sys
try:
    print(repr(ast.literal_eval(sys.stdin.read())[0].get("OAUTH2_ADDITIONAL_CLAIMS")))
except Exception:
    print("unreadable")')"
    # shellcheck source=/dev/null
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
            || ! want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool pgadmin 2>/dev/null)"; then
        _record FAIL "$name" "cannot compile pgAdmin's roles (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    same="$(python3 -c 'import ast, sys; print(ast.literal_eval(sys.argv[1]) == ast.literal_eval(sys.argv[2]))' "$have" "$want" 2>/dev/null)"
    if [[ "$same" != True ]]; then
        _record FAIL "$name" "OAUTH2_ADDITIONAL_CLAIMS is $have, the policy compiles $want (./deploy-infra.sh)"
    elif [[ "${IAM_GATES:-true}" == "false" ]]; then
        _record WARN "$name" "IAM_GATES=false: pgAdmin keeps the pre-policy $want"
    else
        _record OK "$name" "admits $want from the access policy (checked at sign-in only)"
    fi
}

# =============================================================================
# Check: the flows Node-RED runs against git (IAM 3.3, waiver W1's control) — read-only
# target: NAMESPACE. Reads /data/flows.json as dbclients does; apps/node-red/flows_diff.py
# prints ids, types, names and key names, never a value (the ingest password is in it).
# FAIL: a git node missing or changed, or no flows; WARN: nodes or keys outside git.
# =============================================================================
check_noderedflows() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" out rc
    timeout "$TIMEOUT" $KUBECTL get deployment node-red -n "$ns" >/dev/null 2>&1 \
        || { _record SKIP "$name" "no Node-RED deployment in $ns"; return; }
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-node-red.sh"
    out="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/node-red -- cat /data/flows.json 2>/dev/null \
        | python3 -I "$SCRIPT_DIR/apps/node-red/flows_diff.py" diff --git "$SCRIPT_DIR/apps/node-red/flows" \
            --values <(nr_flow_values "$ns") 2>/dev/null)"; rc=$?
    out="$(sed 's/^\(OK\|WARN\|FAIL\|UNREADABLE\) //' <<<"$out" | paste -sd ';' | cut -c1-300)"
    case "$rc" in
        0) _record OK   "$name" "$out" ;;
        1) _record WARN "$name" "$out (review them; W1 covers only flows from git)" ;;
        2) [[ "$out" == *deploy.sh* ]] || out+=" — ./apps/node-red/deploy.sh puts git's flows back; or commit the change to git"
           _record FAIL "$name" "$out" ;;
        *) _record FAIL "$name" "cannot read Node-RED's flows ($out)" ;;
    esac
}

# =============================================================================
# Check: Node-RED's editor rights are the policy's (IAM 3.3) — read-only
# target: NAMESPACE. adminAuth on, ConfigMap node-red-auth = `cli.py compile node-red`,
# the running settings.js = k8s/node-red/settings.js, the OIDC module installed, and the
# admin API refuses an unauthenticated call from the host (401). IAM_GATES=false changes
# nothing: Node-RED keeps its compiled rights.
# =============================================================================
check_noderedauth() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" auth live want sum tmpl pod ip code problems=()
    auth="$(timeout "$TIMEOUT" $KUBECTL get deployment node-red -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[*].env[?(@.name=="NR_ADMIN_AUTH")]}{.value}{end}' 2>/dev/null)" \
        || { _record SKIP "$name" "no Node-RED deployment in $ns"; return; }
    if [[ "$auth" != "on" ]]; then
        _record FAIL "$name" "adminAuth is '${auth:-not set}': any pod and anyone the proxy admits has full editor rights (./deploy-infra.sh)"
        return
    fi
    live="$($KUBECTL get configmap node-red-auth -n "$ns" -o jsonpath='{.data.permissions\.json}' 2>/dev/null)"
    if ! want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile node-red 2>/dev/null)"; then
        problems+=("cannot compile the editor rights (python3 apps/iam/compiler/cli.py check)")
    elif [[ "$(python3 -c 'import json, sys; print(json.loads(sys.argv[1]) == json.loads(sys.argv[2]))' "$live" "$want" 2>/dev/null)" != True ]]; then
        problems+=("ConfigMap node-red-auth is not the compiled policy (./deploy-infra.sh)")
    fi
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-node-red.sh"
    sum="$(nr_settings_checksum)"
    tmpl="$($KUBECTL get deployment node-red -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/settings-checksum}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$ns" -l app.kubernetes.io/name=node-red --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.medcea/settings-checksum}{"\n"}{end}' 2>/dev/null | sort -u)"
    [[ "$tmpl" == "$sum" && "$pod" == "$sum" ]] || problems+=("the running settings.js is not k8s/node-red/settings.js (./deploy-infra.sh)")
    timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/node-red -- \
        test -f /opt/nr-auth/node_modules/passport-openidconnect/package.json 2>/dev/null \
        || problems+=("the OIDC module is missing (init container nr-auth: npm registry?): the editor refuses everyone")
    ip="$($KUBECTL get svc node-red -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
    code="$(curl -s -o /dev/null -m "$TIMEOUT" -w '%{http_code}' "http://${ip}:1880/flows" 2>/dev/null)"
    [[ "$code" == 401 ]] || problems+=("GET /flows without a token answered ${code:-nothing}, not 401")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "adminAuth on; editor rights from the access policy; the admin API refuses anonymous calls"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
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
        iamchain) check_iamchain "$name" "$target" ;;
        iamdbroles) check_iamdbroles "$name" "$target" ;;
        iamgrants)  check_iamgrants "$name" "$target" ;;
        iamdecisions) check_iamdecisions "$name" "$target" ;;
        dbclients)  check_dbclients "$name" ;;
        postgrest)  check_postgrest "$name" "$target" ;;
        iamenforce)   check_iamenforce "$name" "$target" ;;
        iammqtt)      check_iammqtt "$name" "$target" ;;
        grafanarole)  check_grafanarole "$name" "$target" ;;
        iamworkbench) check_iamworkbench "$name" "$target" ;;
        noderedflows) check_noderedflows "$name" "$target" ;;
        noderedauth)  check_noderedauth "$name" "$target" ;;
        onboardroles) check_onboardroles "$name" ;;
        pgadminroles) check_pgadminroles "$name" "$target" ;;
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
