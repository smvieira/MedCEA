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
