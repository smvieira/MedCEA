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
    echo -e "         e.g. localhost:5432"
    echo ""
    echo -e "  ${CYAN}mqtttls${NC} the boards' broker port: HOST:PORT answers TLS with a certificate that"
    echo -e "         verifies against the platform CA (.ca/ca.crt) for mqtt.\$DOMAIN, and the"
    echo -e "         plain port 31883 is closed; e.g. localhost:31884"
    echo ""
    echo -e "  ${CYAN}apparmor${NC} the stacked-peer rules in MicroK8s's container AppArmor profile"
    echo -e "         (infra/lib-apparmor.sh): units installed, rules loaded, no signal denial"
    echo -e "         inside a container since, no host profile attached inside one; no target"
    echo ""
    echo -e "  ${CYAN}pvc${NC}    a PersistentVolumeClaim is Bound: NAMESPACE/NAME"
    echo -e "         e.g. medcea/grafana; WARN when it is missing or not Bound (the service"
    echo -e "         then keeps nothing across a restart, or does not start)"
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
    echo -e "  ${CYAN}iampolicy${NC} the applied access policy version (IAM 4.2a): DATABASE"
    echo -e "         SKIP before migration 008c or without kubectl; FAIL when PostgreSQL cannot be read,"
    echo -e "         no version is applied yet (./apps/iam/deploy.sh bootstraps it), state/policy-applied.yaml"
    echo -e "         is absent or differs from the database (header or body), the git skeleton widens over"
    echo -e "         the accepted one, an earlier accept widened, an apply did not record its end, a policy"
    echo -e "         break-glass is still open, audit_versions() finds anything, the chain is broken, or a"
    echo -e "         waiver's review date has passed; WARN on queued account facts, an apply in progress,"
    echo -e "         a narrowing git skeleton, git lagging the applied matrix, a waiver due within 30 days"
    echo ""
    echo -e "  ${CYAN}iamartefacts${NC} the live route table, MQTT rows and sign-in gates are the applied"
    echo -e "         version's compile (IAM 4.2a): NAMESPACE. SKIP without ConfigMap medcea-iam-lib;"
    echo -e "         FAIL on a digest or gate that differs (the message names the deploy); WARN while the"
    echo -e "         User Manager's gate is admin-only; hosts whose proxy is not deployed are counted"
    echo ""
    echo -e "  ${CYAN}iamdecisions${NC} account decisions waiting for qa (IAM 2.7): DATABASE"
    echo -e "         SKIP without schema iam or role access_svc; FAIL without iam.confirm_decision"
    echo -e "         (./apps/access/deploy.sh) or when access_svc may not execute it"
    echo -e "         (./apps/database/deploy.sh); WARN on a decision pending for over 7 days"
    echo -e "         or a pending mail settings change"
    echo ""
    echo -e "  ${CYAN}iampending${NC} configuration changes waiting for qa: DATABASE"
    echo -e "         SKIP before the approval functions exist (./apps/database/deploy.sh);"
    echo -e "         WARN on a pending change (commissioning proposal, log setting, review of"
    echo -e "         a commissioning end) waiting for over 7 days: Config UI → Approvals"
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
    echo -e "         FAIL when the hub's deployed allowed_groups differ from the compiled ones, hub"
    echo -e "         role workbench-admin's scopes are not exactly the decided ones or its members not"
    echo -e "         the compiled ones, anyone can hold the built-in admin role (admin_groups,"
    echo -e "         admin_users, admin role members), allow_all is set, delete_pvc or auth_state is"
    echo -e "         on, the notebooks' NetworkPolicy allows private addresses, or the hub pod runs"
    echo -e "         older values (./infra/deploy-workbench.sh); WARN while IAM_GATES=false; SKIP"
    echo -e "         while WORKBENCH_ENABLED is not true or there is no hub"
    echo ""
    echo -e "  ${CYAN}onboardroles${NC} the onboarding wizard admits the access policy's roles (IAM 3.4): -"
    echo -e "         FAIL when the running daemon's --required-role differs from policy_tool edge-wizard"
    echo -e "         (./apps/edge-wizard/deploy.sh) or is missing while IAM_GATES=true; WARN while"
    echo -e "         IAM_GATES=false; SKIP when no daemon runs (the http check reports it)"
    echo ""
    echo -e "  ${CYAN}pgadminroles${NC} pgAdmin admits the access policy's roles (IAM 3.4): NAMESPACE"
    echo -e "         FAIL when OAUTH2_ADDITIONAL_CLAIMS in Secret pgadmin-config differs from policy_tool"
    echo -e "         pgadmin, or the deployment still holds the OAuth2 config or default password as plain"
    echo -e "         env (./deploy-infra.sh); WARN while IAM_GATES=false; SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}supersetroles${NC} Superset admits the access policy's roles (Superset stages B, C): NAMESPACE"
    echo -e "         FAIL when SUPERSET_ROLES_MAPPING in Secret superset-secrets differs from policy_tool"
    echo -e "         superset (or the policy has no superset tool, or gives no role a setting), a running"
    echo -e "         pod was started with another Secret or ConfigMap (medcea/config-checksum), a secret"
    echo -e "         is a plain env value in the deployment or a ReplicaSet, the secret key is empty or"
    echo -e "         the default, the connection is not svc_superset, or the image has no digest; WARN"
    echo -e "         while IAM_GATES=false or IAM_DB_SERVICE_ROLES is not true; SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}backupage${NC} the nightly backup (apps/backup): NAMESPACE"
    echo -e "         OK while the newest OK marker in BACKUP_DIR is at most 26 h old, WARN beyond,"
    echo -e "         FAIL beyond 72 h; SKIP without CronJob medcea-backup, and on its first day"
    echo ""
    echo -e "  ${CYAN}manual${NC} the portal serves the manual the repository builds now (/manual/): NAMESPACE"
    echo -e "         OK when ConfigMap portal-manual's medcea/manual-sha256 = its own content = a fresh"
    echo -e "         docs/manual/build.py --out --standalone (a temp file); WARN when it lags or is missing (./medcea.sh"
    echo -e "         → Infrastructure → Publish the manual to the portal), or the portal does not mount it;"
    echo -e "         FAIL when build.py refuses or the content differs from its annotation; SKIP without the portal"
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

# logs/health-check-<ts>.log (read-only, no lock; infra/lib-log.sh)
REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-log.sh"; REPO_ROOT="$SCRIPT_DIR" medcea_log health-check

# =============================================================================
# Load config.env for variable expansion in targets
# =============================================================================
if [[ -f "${SCRIPT_DIR}/config.env" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/config.env" 2>/dev/null || true
fi

# backup_dir, backup_newest_ok, backup_age_status (check backupage); read-only
source "${SCRIPT_DIR}/apps/backup/lib-backup.sh"
# aa_status (check apparmor); read-only
source "${SCRIPT_DIR}/infra/lib-apparmor.sh"

# Every policy compile below reads what the deploys compiled (IAM Phase 4): an inherited
# MEDCEA_POLICY_FILE (break-glass) or a parent's "already verified" marker is dropped
# first, so a check never trusts a source it was handed; read-only, writes nothing.
source "${SCRIPT_DIR}/infra/lib-policy-source.sh"
policy_source_init "${NAMESPACE:-medcea}" --read-only
# its state document (check iampolicy) lives in a mktemp -d directory that is ours to remove
[[ -n "${POLICY_SOURCE_STATE_FILE:-}" ]] && trap 'rm -rf "$(dirname "$POLICY_SOURCE_STATE_FILE")"' EXIT

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
# Check: a PersistentVolumeClaim is Bound — read-only
# target: NAMESPACE/NAME. WARN, not FAIL: the workload's own check says whether it
# runs; this says whether what people saved in it survives (Grafana since 1 Nov 2026).
# Also WARNs when the volume's hostPath root on this host is not 0700:
# microk8s-hostpath makes it 0777, and Grafana's init container closes it at each start.
# =============================================================================
check_pvc() {
    local name="$1" target="$2" ns claim out phase size
    ns="${target%%/*}"; claim="${target#*/}"
    if [[ -z "$ns" || -z "$claim" || "$claim" == "$target" ]]; then
        _record FAIL "$name" "Invalid pvc target '${target}' — expected NAMESPACE/NAME"
        return
    fi
    if ! out="$(timeout "$TIMEOUT" $KUBECTL get pvc "$claim" -n "$ns" \
            -o jsonpath='{.status.phase} {.status.capacity.storage}' 2>&1)"; then
        _record WARN "$name" "no PVC ${claim} in ${ns}: nothing it should hold survives a restart (./deploy-infra.sh)"
        return
    fi
    read -r phase size <<<"$out"
    if [[ "$phase" == Bound ]]; then
        local pv path mode
        pv="$(timeout "$TIMEOUT" $KUBECTL get pvc "$claim" -n "$ns" -o jsonpath='{.spec.volumeName}' 2>/dev/null)" || pv=""
        path=""
        [[ -n "$pv" ]] && { path="$(timeout "$TIMEOUT" $KUBECTL get pv "$pv" -o jsonpath='{.spec.hostPath.path}' 2>/dev/null)" || path=""; }
        mode=""
        [[ -n "$path" ]] && mode="$(stat -c %a "$path" 2>/dev/null)" || true
        if [[ -n "$mode" && "$mode" != 700 ]]; then
            _record WARN "$name" "pvc/${claim} (${ns}): Bound, but ${path} is mode ${mode}, not 700: any local account may replace its files (restart the workload: ./deploy-infra.sh)"
        else
            _record OK "$name" "pvc/${claim} (${ns}): Bound, ${size:-?}${mode:+, root mode $mode}"
        fi
    else
        _record WARN "$name" "pvc/${claim} (${ns}) is ${phase:-in no phase}, not Bound"
    fi
}

# =============================================================================
# Check: the nightly backup is recent — read-only
# target: NAMESPACE. SKIP before apps/backup is deployed (no CronJob medcea-backup);
# otherwise the age of the newest OK marker in BACKUP_DIR on this host (the job hands
# each folder to the account that deployed it): WARN over 26 h, FAIL over 72 h. With
# no complete backup yet, the CronJob's own age stands in (SKIP on its first day).
# =============================================================================
# =============================================================================
# Check: the AppArmor rules for containers (infra/lib-apparmor.sh) — read-only
# SKIP without AppArmor or MicroK8s; FAIL when the units are missing, the profile lacks
# the rules, the last run failed, a signal was denied inside a container since the
# rules were loaded, or a host profile (mosquitto) is attached inside a container.
# =============================================================================
check_apparmor() {
    local name="$1" res
    res="$(aa_status)"
    _record "${res%%|*}" "$name" "${res#*|}"
}

check_backupage() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" created created_epoch dir newest res
    if ! created="$(timeout "$TIMEOUT" $KUBECTL get cronjob medcea-backup -n "$ns" \
            -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)" || [[ -z "$created" ]]; then
        _record SKIP "$name" "no CronJob medcea-backup in ${ns} (./apps/backup/deploy.sh)"
        return
    fi
    dir="$(backup_dir)"
    if [[ ! -d "$dir" || ! -r "$dir" || ! -x "$dir" ]]; then
        _record FAIL "$name" "cannot read ${dir} (BACKUP_DIR): run this as the account that ran ./apps/backup/deploy.sh, which creates it"
        return
    fi
    created_epoch="$(date -u -d "$created" +%s 2>/dev/null || echo 0)"
    newest="$(backup_newest_ok "$dir")"
    res="$(backup_age_status "$(date -u +%s)" "${newest#* }" "$created_epoch" "${newest%% *}")"
    _record "${res%%|*}" "$name" "${res#*|}"
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
        elif [[ "$u" == "-" ]]; then :   # no connection (Node-RED without flows: noderedflows reports it)
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
# Check: the applied access policy version (IAM 4.2a, design §14.4.14) — read-only
# target: DATABASE (informational: the state document is the one policy_source_init
# --read-only read at the top for $POSTGRES_DB, POLICY_SOURCE_STATE_FILE, bounded by
# TIMEOUT). apps/iam/apply_check.py health judges it: the host file (line 1, line 2 and the
# whole body against the database's rows), the skeleton gate against git, every unreviewed
# accept recomputed, the apply events, break-glass, audit_versions(), the chain, waivers,
# the seed queue. "An apply is running" = a holder of .medcea.lock (_lock_holders) whose
# command line is apps/iam/apply.sh: health never runs flock. The worst line wins; the
# detail lists every WARN and FAIL, 160 characters each. --policy-port: what iam-api's
# /healthz on :8083 answers (IAM 4.3; read in the pod, no secret in it): absent without the
# port (a bootstrap version is then OK while unconfirmed), true once the Policy UI runs —
# then an unconfirmed bootstrap WARNs, another applied version FAILs, another skeleton WARNs.
# =============================================================================
check_iampolicy() {
    local name="$1" out rc=0 lvl msg worst="" ok="" skip="" details=() holders tmo
    if [[ -z "${POLICY_SOURCE_STATE_FILE:-}" || ! -s "${POLICY_SOURCE_STATE_FILE:-}" ]]; then
        if [[ "${POLICY_SOURCE_VERDICT:-skip}" == fail ]]; then
            _record FAIL "$name" "cannot read the applied policy: ${POLICY_SOURCE_DETAIL:0:160}"
        else
            _record SKIP "$name" "${POLICY_SOURCE_DETAIL:-no usable kubectl}"
        fi
        return
    fi
    # The lock's holders only when they matter: scanning every /proc/<pid>/fd takes seconds
    # on a busy host, and only an unfinished apply_started asks whether an apply is running.
    holders=""
    if grep -q '"apply_started"' "$POLICY_SOURCE_STATE_FILE" 2>/dev/null; then
        holders="$(_lock_holders 2>/dev/null | paste -sd ' ')"
    fi
    tmo=$(( TIMEOUT > 30 ? TIMEOUT : 30 ))
    local live="" port=absent
    live="$(timeout "$TIMEOUT" $KUBECTL exec -n "${NAMESPACE:-medcea}" deployment/iam-api -c iam-api -- python3 -c \
        'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8083/healthz", timeout=5).read().decode())' 2>/dev/null)" || live=""
    if python3 -c 'import json, sys; sys.exit(0 if json.loads(sys.argv[1]).get("policy_port") is True else 1)' "$live" 2>/dev/null; then
        port=true
    else
        live=""
    fi
    out="$(timeout "$tmo" python3 "$SCRIPT_DIR/apps/iam/apply_check.py" health --state "$POLICY_SOURCE_STATE_FILE" \
        --host-file "$SCRIPT_DIR/state/policy-applied.yaml" --holders "$holders" --policy-port "$port" --live "$live" 2>&1)" || rc=$?
    while IFS='|' read -r lvl msg; do
        case "$lvl" in
            FAIL) worst=FAIL; details+=("${msg:0:160}") ;;
            WARN) [[ "$worst" == FAIL ]] || worst=WARN; details+=("${msg:0:160}") ;;
            OK)   ok="${msg:0:160}" ;;
            SKIP) skip="${msg:0:160}" ;;
        esac
    done <<<"$out"
    if [[ $rc -ne 0 || -z "$worst$ok$skip" ]]; then
        _record FAIL "$name" "apply_check.py health failed (exit $rc): $(tail -n1 <<<"$out" | cut -c1-160)"
    elif [[ -n "$worst" ]]; then
        local IFS=';'; _record "$worst" "$name" "${details[*]}"
    elif [[ -n "$ok" ]]; then
        _record OK "$name" "$ok"
    elif [[ "${POLICY_SOURCE_VERDICT:-}" == fail ]]; then
        # state none, yet the read-only init failed it: a host file without any policy version
        _record FAIL "$name" "${POLICY_SOURCE_DETAIL:0:160}"
    else
        _record SKIP "$name" "$skip"
    fi
}

# =============================================================================
# Check: the live policy artefacts are the applied version's compile (IAM 4.2a) — read-only
# target: NAMESPACE. (a) ConfigMap medcea-iam-lib: annotation medcea/routes-digest and
# routes.json's digest = cli.py compile routes; (b) medcea/mqtt-digest and mqtt.json's digest
# = cli.py compile mqtt; (c) every HOST → release of network.proxies (the compiled policy):
# ConfigMap <release> absent → "not deployed" (counted); else its oauth2_proxy.cfg
# allowed_groups (no secret in it) = policy_groups HOST (lib-oauth2-proxy.sh, which renders
# the IAM_GATES=false lists too). The User Manager's admin-only fallback (["admin"] while
# the compile differs: not every access pod proved it enforces) is a WARN. The tool hosts
# (Grafana, workbench, Node-RED, wizard, pgAdmin) keep their own checks.
# =============================================================================
check_iamartefacts() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" cm rc=0 cli="$SCRIPT_DIR/apps/iam/compiler/cli.py"
    local want_r want_m probs=() warns=() gates=0 absent=0 host rel live want owner line
    local -A LIVE=() OWNER=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    cm="$(timeout "$TIMEOUT" $KUBECTL get configmap medcea-iam-lib -n "$ns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' <<<"$cm"; then
            _record SKIP "$name" "no ConfigMap medcea-iam-lib in $ns yet (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot read ConfigMap medcea-iam-lib: $(tail -n1 <<<"$cm" | cut -c1-160)"
        fi
        return
    fi
    _digest() { python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' 2>/dev/null; }
    want_r="$(python3 "$cli" compile routes 2>/dev/null | _digest)"
    want_m="$(python3 "$cli" compile mqtt 2>/dev/null | _digest)"
    if [[ -z "$want_r" || -z "$want_m" ]]; then
        unset -f _digest
        _record FAIL "$name" "the applied policy does not compile (python3 apps/iam/compiler/cli.py check)"; return
    fi
    unset -f _digest
    # (a), (b): one line per mismatch, never a value but the digests
    while IFS= read -r line; do
        [[ -n "$line" ]] && probs+=("$line")
    done < <(python3 -c '
import json, sys
cm, wr, wm = json.load(sys.stdin), sys.argv[1], sys.argv[2]
ann, data = cm["metadata"].get("annotations") or {}, cm.get("data") or {}
def dig(key):
    try:
        return json.loads(data.get(key) or "")["digest"]
    except Exception:
        return ""
for what, a, k, want in (("routes", "medcea/routes-digest", "routes.json", wr), ("mqtt", "medcea/mqtt-digest", "mqtt.json", wm)):
    have_a, have_d = ann.get(a, ""), dig(k)
    if have_a != want or have_d != want:
        print("%s: annotation %s, %s %s, the applied version compiles %s (./deploy-infra.sh)"
              % (what, have_a[:12] or "-", k, have_d[:12] or "-", want[:12]))
' "$want_r" "$want_m" <<<"$cm" 2>&1)
    # (c) the gates: HOST release, from the compiled policy
    local proxies
    proxies="$(python3 -c 'import sys
sys.path.insert(0, sys.argv[1])
from compiler import model
for h, r in (model.load().data.get("network", {}).get("proxies") or {}).items():
    print(h, r)' "$SCRIPT_DIR/apps/iam" 2>/dev/null)" || { _record FAIL "$name" "cannot read network.proxies from the applied policy"; return; }
    while IFS=$'\t' read -r host owner; do OWNER[$host]="${owner%% --*}"; done \
        < <(python3 "$SCRIPT_DIR/apps/iam/apply_check.py" owners 2>/dev/null)
    rc=0
    # shellcheck disable=SC2046  # one release name per word
    cm="$(timeout "$TIMEOUT" $KUBECTL get configmap $(awk '{print $2}' <<<"$proxies") -n "$ns" --ignore-not-found -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record FAIL "$name" "cannot read the sign-in proxies' ConfigMaps: $(tail -n1 <<<"$cm" | cut -c1-160)"; return
    fi
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"
    # pa_live_groups: the one reader of a proxy's live gate, shared with the scoped modes (IAM 4.2b)
    while IFS=$'\t' read -r rel live; do [[ -n "$rel" ]] && LIVE[$rel]="$live"; done < <(pa_live_groups <<<"$cm" 2>/dev/null)
    while read -r host rel; do
        [[ -n "$host" ]] || continue
        if [[ -z "${LIVE[$rel]+x}" ]]; then absent=$((absent + 1)); continue; fi
        gates=$((gates + 1))
        if [[ ( "$host" == ACCESS_DOMAIN || "$host" == POLICY_DOMAIN ) && "${IAM_GATES:-true}" == false ]]; then
            want="admin"
        else
            want="$(policy_groups "$host" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | sort -u | paste -sd ' ')"
        fi
        live="${LIVE[$rel]}"
        if [[ -z "$want" ]]; then
            probs+=("gate $host: policy_groups compiles nothing (python3 apps/iam/compiler/cli.py check)")
        elif [[ "$live" == "$want" ]]; then
            :
        elif [[ "$host" == ACCESS_DOMAIN && "$live" == admin ]]; then
            warns+=("the User Manager's gate is admin-only: not every access pod proved it enforces (./apps/access/deploy.sh)")
        elif [[ "$host" == POLICY_DOMAIN && "$live" == admin ]]; then
            warns+=("the Policy UI's gate is admin-only: not every iam-api pod proved it enforces (./apps/iam/deploy.sh)")
        elif [[ "$live" == "-" ]]; then
            probs+=("gate $host ($rel) has no allowed_groups: anyone signed in gets in (${OWNER[$host]:-./deploy-infra.sh})")
        else
            probs+=("gate $host ($rel) admits [$live], the applied version compiles [$want] (${OWNER[$host]:-./deploy-infra.sh})")
        fi
    done <<<"$proxies"
    if ((${#probs[@]})); then
        local IFS=';'; _record FAIL "$name" "${probs[*]}${warns:+;${warns[*]}}"
    elif ((${#warns[@]})); then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "routes, mqtt and $gates gates equal the applied version's compile; $absent hosts not deployed"
    fi
}

# =============================================================================
# Check: the platform manual the portal serves is the one the repository builds (3 Nov 2026)
# — read-only. target: NAMESPACE. ConfigMap portal-manual (infra/lib-manual.sh) carries the
# page gzipped and medcea/manual-sha256; the check rebuilds the page into a mktemp file
# (docs/manual/build.py --out --standalone, as infra/lib-manual.sh builds it; the working
# tree is not touched) and compares three digests:
# the annotation, the ConfigMap's own content (gunzipped) and the fresh build. A lag is a
# WARN with the fix; a ConfigMap whose content is not what its annotation says, or a manual
# that no longer builds, is a FAIL. The portal Deployment must mount the ConfigMap (WARN).
# =============================================================================
check_manual() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rc=0 tmp out
    local fix="./medcea.sh → Infrastructure → Publish the manual to the portal"
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    # Files, not variables: the ConfigMap is ~210 KiB of JSON, over the 128 KiB a single
    # command-line argument may hold.
    tmp="$(mktemp -d)"
    timeout "$TIMEOUT" $KUBECTL get deployment portal -n "$ns" -o json >"$tmp/dep.json" 2>"$tmp/err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' "$tmp/err"; then
            _record SKIP "$name" "no portal deployment in $ns yet (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot read deployment portal: $(tail -n1 "$tmp/err" | cut -c1-160)"
        fi
        rm -rf "$tmp"; return
    fi
    timeout "$TIMEOUT" $KUBECTL get configmap portal-manual -n "$ns" -o json >"$tmp/cm.json" 2>"$tmp/err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' "$tmp/err"; then
            _record WARN "$name" "the manual is not published: /manual/ answers 404 ($fix)"
        else
            _record FAIL "$name" "cannot read ConfigMap portal-manual: $(tail -n1 "$tmp/err" | cut -c1-160)"
        fi
        rm -rf "$tmp"; return
    fi
    if ! out="$(timeout $(( TIMEOUT > 30 ? TIMEOUT : 30 )) python3 "$SCRIPT_DIR/docs/manual/build.py" --out "$tmp/index.html" --standalone 2>&1)"; then
        rm -rf "$tmp"
        _record FAIL "$name" "docs/manual/build.py refuses to build the manual: $(grep -m1 'build:' <<<"$out" | cut -c1-160)"
        return
    fi
    out="$(python3 -c '
import base64, gzip, hashlib, json, sys
d = sys.argv[1]
cm, dep = json.load(open(d + "/cm.json")), json.load(open(d + "/dep.json"))
want = hashlib.sha256(open(d + "/index.html", "rb").read()).hexdigest()
meta = cm.get("metadata") or {}
ann = (meta.get("annotations") or {})
have_a, commit = ann.get("medcea/manual-sha256", ""), ann.get("medcea/manual-commit", "?")
try:
    have_c = hashlib.sha256(gzip.decompress(base64.b64decode((cm.get("binaryData") or {})["index.html.gz"]))).hexdigest()
except Exception:
    have_c = ""
mounted = any((v.get("configMap") or {}).get("name") == "portal-manual"
              for v in ((dep.get("spec") or {}).get("template") or {}).get("spec", {}).get("volumes") or [])
if not have_c or have_c != have_a:
    print("FAIL|ConfigMap portal-manual holds %s, its annotation says %s: republish it" % (have_c[:12] or "no readable page", have_a[:12] or "-"))
elif have_a != want:
    print("WARN|the portal serves the manual of %s (%s), the repository builds %s" % (commit, have_a[:12], want[:12]))
elif not mounted:
    print("WARN|the manual is published (%s) but the portal does not mount it yet: ./deploy-infra.sh" % want[:12])
else:
    print("OK|the portal serves the manual the repository builds (%s, commit %s)" % (want[:12], commit))
' "$tmp" 2>&1)" || out="FAIL|cannot compare the manual's digests: $(tail -n1 <<<"$out" | cut -c1-120)"
    rm -rf "$tmp"
    case "${out%%|*}" in
        OK)   _record OK "$name" "${out#*|}" ;;
        WARN) if [[ "$out" == *"repository builds"* ]]; then _record WARN "$name" "${out#*|} ($fix)"
              else _record WARN "$name" "${out#*|}"; fi ;;
        *)    _record FAIL "$name" "${out#*|}" ;;
    esac
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
# Check: configuration changes waiting for qa (Approvals tab) — read-only
# target: DATABASE. An open medcea.pending_change is one medcea._pending_open()
# says no approval, return or withdrawal closed (the queue's own rule): a waiting
# commissioning "on" or log setting, or the review of an "off" that applied at once.
# =============================================================================
check_iampending() {
    local name="$1" db="$2" out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
-- the argument type first: to_regprocedure() may raise on a type that does not exist
SELECT pg_catalog.to_regclass('medcea.pending_change') IS NOT NULL AS has_table \gset
\if :has_table
SELECT pg_catalog.to_regprocedure('medcea._pending_open(medcea.pending_change)') IS NOT NULL AS built \gset
\else
SELECT false AS built \gset
\endif
\if :built
SELECT 'stale|' || count(*) || '|' || coalesce(min(x.change_id)::text, '-') || '|'
       || count(*) FILTER (WHERE x.target = 'medcea.cea_unit')
  FROM medcea.pending_change x
 WHERE medcea._pending_open(x) AND coalesce(x.applied_at, x.proposed_at) < now() - interval '7 days';
SELECT 'pending|' || count(*) FROM medcea.pending_change x WHERE medcea._pending_open(x);
\else
SELECT 'state|unbuilt';
\endif
SQL
) || exit_code=$?
    local state stale stale_id stale_comm pending
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    IFS='|' read -r _ stale stale_id stale_comm <<<"$(grep -m1 '^stale|' <<<"$out")"
    pending="$(grep -m1 '^pending|' <<<"$out" | cut -d'|' -f2)"
    if [[ "$state" == unbuilt ]]; then
        _record SKIP "$name" "no approval functions yet (./apps/database/deploy.sh)"
    elif [[ $exit_code -ne 0 || -z "$pending" || -z "$stale" ]]; then
        _record FAIL "$name" "could not read the pending changes: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"
    elif [[ "$stale" -gt 0 ]]; then
        _record WARN "$name" "${stale} change(s) waiting for qa for over 7 days (oldest #${stale_id}; ${stale_comm} commissioning): Config UI → Approvals"
    else
        _record OK "$name" "${pending} change(s) waiting for qa, none older than 7 days"
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
        _record FAIL "$name" "IAM_ENFORCE=true with IAM_DB_ROLES=false: operators can start and stop other units' runs (./medcea.sh IAM_DB_ROLES, or IAM_ENFORCE back to false)"
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
# Reads the broker's files' usernames (cut -d: -f1) and status.json, never a hash. The
# shared mqtt-explorer account was removed (1 Nov 2026): it FAILs in either mode if a
# password file still names it (a broker not redeployed since), and under false the page
# must be in mode "off" (no credential).
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
        [[ "$page" == "$([[ "$want" == true ]] && echo person || echo off)" ]] \
            || problems+=("the Explorer page is in mode '${page:-pre-3.5}' (./apps/mqtt-explorer/deploy.sh)")
    fi
    users="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd 2>/dev/null)"
    grep -qx 'mqtt-explorer' <<<"$users" && problems+=("the removed shared mqtt-explorer account is still in the broker's password file (./deploy-infra.sh)")
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
        ws="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd-ws 2>/dev/null)"
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
        _record WARN "$name" "IAM_MQTT_PERSON=false: the MQTT Explorer has no broker credential (no shared account any more); set it true with ./medcea.sh${warns:+; ${warns[*]}}"
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
lr = (v.get("hub") or {}).get("loadRoles") or {}
wa, ad = lr.get("workbench-admin") or {}, lr.get("admin") or {}
np = ((v.get("singleuser") or {}).get("networkPolicy") or {})
eg = np.get("egressAllowRules") or {}
out = {"allow_all": a.get("allow_all"), "admin_users": sorted(a.get("admin_users") or []),
       "existing": a.get("allow_existing_users"), "auth_state": a.get("enable_auth_state"),
       "allowed": sorted(g.get("allowed_groups") or []), "admin_groups": sorted(g.get("admin_groups") or []),
       "key": g.get("auth_state_groups_key"),
       "role_scopes": sorted(wa.get("scopes") or []), "role_groups": sorted(wa.get("groups") or []),
       "role_users": sorted(wa.get("users") or []),
       "builtin_admins": ad.get("users") if isinstance(ad.get("users"), list) else "unpinned",
       "delete_pvc": (c.get("KubeSpawner") or {}).get("delete_pvc"),
       "netpol": np.get("enabled"), "private": eg.get("privateIPs"), "metadata": eg.get("cloudMetadataServer"),
       "egress": json.dumps(np.get("egress") or [], sort_keys=True, separators=(",", ":"))}
for k, x in out.items():
    print(f"{k}\t{json.dumps(x)}")')" || { _record SKIP "$name" "no hub Secret in $ns (workbench not deployed)"; return; }
    declare -A L=()
    local k x
    while IFS=$'\t' read -r k x; do L[$k]="$x"; done <<<"$live"
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"; then
        _record FAIL "$name" "cannot read infra/lib-oauth2-proxy.sh"; return
    fi
    # Hub administration is the custom role workbench-admin (values.yaml hub.loadRoles);
    # JupyterHub's built-in admin role carries tokens and access:servers (a token minted
    # for a person opens their server) and nobody may hold it. admin_access is deprecated
    # since JupyterHub 2.0 and does nothing, so it is not checked.
    [[ "${L[admin_users]}" == "[]" ]] || problems+=("admin_users is set: they are admitted whatever the policy says and get the built-in admin role")
    [[ "${L[admin_groups]}" == "[]" ]] || problems+=("admin_groups is set: its members get the built-in admin role (tokens, access:servers)")
    [[ "${L[builtin_admins]}" == "[]" ]] || problems+=("the built-in admin role's members are ${L[builtin_admins]}, not pinned to [] (stored admin flags survive)")
    local want_scopes forbidden
    want_scopes="$(python3 -c 'import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))' "$WORKBENCH_ADMIN_ROLE_SCOPES")"
    forbidden="$(python3 -c '
import json, sys
bad = set(json.loads(sys.argv[2]))
print(" ".join(s for s in json.loads(sys.argv[1]) if s.split("!")[0] in bad))' "${L[role_scopes]}" "$WORKBENCH_ADMIN_ROLE_FORBIDDEN")"
    [[ -z "$forbidden" ]] || problems+=("workbench-admin holds $forbidden: a hub admin can open others' servers")
    [[ "${L[role_scopes]}" == "$want_scopes" ]] || problems+=("workbench-admin's scopes ${L[role_scopes]} are not the decided $want_scopes")
    [[ "${L[delete_pvc]}" == false ]] || problems+=("delete_pvc is ${L[delete_pvc]}: removing a hub user deletes the home")
    [[ "${L[auth_state]}" != true ]] || problems+=("enable_auth_state is true: a hub admin can read people's Keycloak tokens")
    [[ "${L[existing]}" != true ]] || problems+=("allow_existing_users is true: every user in the hub database gets in")
    [[ "${L[netpol]}" == true && "${L[private]}" == false && "${L[metadata]}" == false ]] \
        || problems+=("the notebooks' NetworkPolicy is off or allows private addresses")
    # The notebooks' platform hops (IAM 3.2b): exactly the compiled ones, and none
    # unless IAM_POSTGREST_JWT and IAM_DB_ROLES are true (policy_workbench_egress).
    local WORKBENCH_EGRESS="" want_egress
    if REPO_ROOT="$SCRIPT_DIR" policy_workbench_egress 2>/dev/null; then
        want_egress="$(python3 -c 'import json, sys; print(json.dumps(json.dumps(json.loads(sys.argv[1]), sort_keys=True, separators=(",", ":"))))' "$WORKBENCH_EGRESS")"
        [[ "${L[egress]}" == "$want_egress" ]] \
            || problems+=("the notebooks' egress hops are not the compiled ones for this IAM_POSTGREST_JWT/IAM_DB_ROLES (./infra/deploy-workbench.sh)")
    else
        problems+=("cannot compile the notebooks' egress hops (python3 apps/iam/compiler/cli.py check)")
    fi
    local tmpl pod
    tmpl="$($KUBECTL get deployment hub -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.checksum/secret}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$ns" -l component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.checksum/secret}{"\n"}{end}' 2>/dev/null | sort -u)"
    [[ -n "$tmpl" && "$pod" == "$tmpl" ]] || problems+=("the running hub pod does not carry the deployed values (rollout pending?)")
    # workbench-admin's members are policy_workbench's in either mode: the compiled admin
    # groups (IAM_GATES=true) or ADMIN_USER by name (IAM_GATES=false).
    local WORKBENCH_ALLOWED_GROUPS="" WORKBENCH_ADMIN_GROUPS="" WORKBENCH_ALLOW_ALL="" WORKBENCH_HUBADMIN_USERS="" WORKBENCH_403_MESSAGE=""
    if ! REPO_ROOT="$SCRIPT_DIR" policy_workbench 2>/dev/null; then
        _record FAIL "$name" "cannot compile the workbench's gate (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    local sorted_json='import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))'
    local want_admins want_hubadmins
    want_admins="$(python3 -c "$sorted_json" "$WORKBENCH_ADMIN_GROUPS")"
    want_hubadmins="$(python3 -c "$sorted_json" "$WORKBENCH_HUBADMIN_USERS")"
    [[ "${L[role_groups]}" == "$want_admins" ]] || problems+=("workbench-admin's groups ${L[role_groups]} are not the compiled $want_admins")
    [[ "${L[role_users]}" == "$want_hubadmins" ]] || problems+=("workbench-admin's users ${L[role_users]} are not $want_hubadmins")
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        if [[ ${#problems[@]} -eq 0 ]]; then
            _record WARN "$name" "IAM_GATES=false: the workbench admits any realm account (pre-3.2 sign-in); hub administrator $want_hubadmins (workbench-admin)"
        else
            local IFS=';'; _record FAIL "$name" "${problems[*]}"
        fi
        return
    fi
    local want_allowed
    want_allowed="$(python3 -c "$sorted_json" "$WORKBENCH_ALLOWED_GROUPS")"
    [[ "${L[allow_all]}" == false ]] || problems+=("allow_all is ${L[allow_all]}")
    [[ "${L[allowed]}" == "$want_allowed" ]] || problems+=("allowed_groups ${L[allowed]} is not the compiled $want_allowed (./infra/deploy-workbench.sh)")
    [[ "${L[key]}" == '"oauth_user.groups"' ]] || problems+=("auth_state_groups_key is ${L[key]}")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "admits $want_allowed from the access policy; hub administrators $want_admins hold workbench-admin (no tokens, no access:servers), nobody the built-in admin role"
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
# target: NAMESPACE. The OAuth2 config is in Secret pgadmin-config with the client
# secret: it reaches python on stdin, which prints only OAUTH2_ADDITIONAL_CLAIMS.
# A Deployment that still carries PGADMIN_CONFIG_OAUTH2_CONFIG or
# PGADMIN_DEFAULT_PASSWORD as a literal value (from before the Secret) FAILs;
# only the variables' names are printed.
# =============================================================================
check_pgadminroles() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" have want same literal oauth passfile
    timeout "$TIMEOUT" $KUBECTL get deployment pgadmin -n "$ns" >/dev/null 2>&1 \
        || { _record SKIP "$name" "no pgAdmin deployment in $ns"; return; }
    # The Deployment and every ReplicaSet it kept: an old one still holds its pod
    # template, plain env values included. "?" = unreadable, never a variable name.
    literal="$(timeout "$TIMEOUT" $KUBECTL get deployment,replicaset -n "$ns" -l app=pgadmin -o json 2>/dev/null \
        | python3 -c '
import json, sys
try:
    items, held = json.load(sys.stdin)["items"], []
    if not any(o["kind"] == "Deployment" for o in items):
        raise ValueError("no deployment")
    for o in items:
        env = o["spec"]["template"]["spec"]["containers"][0].get("env", [])
        names = [e["name"] for e in env if "value" in e
                 and e["name"] in ("PGADMIN_CONFIG_OAUTH2_CONFIG", "PGADMIN_DEFAULT_PASSWORD")]
        if names:
            held.append("%s/%s (%s)" % (o["kind"].lower(), o["metadata"]["name"], ", ".join(names)))
    print("; ".join(held))
except Exception:
    print("?")')"
    if [[ "$literal" == "?" ]]; then
        _record FAIL "$name" "cannot read pgAdmin's deployment and ReplicaSets in $ns"
        return
    elif [[ -n "$literal" ]]; then
        _record FAIL "$name" "pgAdmin's secrets are plain env values in $literal, not from Secret pgadmin-config (./deploy-infra.sh)"
        return
    fi
    if ! timeout "$TIMEOUT" $KUBECTL get secret pgadmin-config -n "$ns" >/dev/null 2>&1; then
        _record FAIL "$name" "Secret pgadmin-config is missing in $ns (./deploy-infra.sh)"
        return
    fi
    have="$($KUBECTL get secret pgadmin-config -n "$ns" -o jsonpath='{.data.oauth2-config}' 2>/dev/null \
        | base64 -d 2>/dev/null | python3 -c '
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
    # libpq skips a passfile its user cannot read: the server entry then fails with
    # "no password supplied" (the file was root's until 1 Nov 2026). The pod says
    # which; no answer means kubectl could not reach the container at all.
    elif passfile="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/pgadmin -c pgadmin -- \
            sh -c 'test -r /pgpassfile && echo readable || echo unreadable' 2>/dev/null)"; [[ "$passfile" != readable ]]; then
        if [[ "$passfile" == unreadable ]]; then
            _record FAIL "$name" "pgAdmin's user cannot read /pgpassfile: its database server entry cannot connect (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot reach pgAdmin's container (still starting? kubectl -n $ns get pods -l app=pgadmin)"
        fi
    # Each e-mail in the pod's PGADMIN_OAUTH2_SERVER_USERS must be an OAuth2 user
    # owning "IoT Postgres" (the postStart hook loads them). Read-only: python's
    # sqlite3 in the pod on pgAdmin's own database, opened mode=ro; prints e-mails
    # and counts, nothing else. "?" = unreadable.
    elif oauth="$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$ns" deployment/pgadmin -c pgadmin -- \
            /venv/bin/python3 - /var/lib/pgadmin/pgadmin4.db 2>/dev/null <<'PY'
import os, sqlite3, sys
try:
    want = sorted({u for u in os.environ.get("PGADMIN_OAUTH2_SERVER_USERS", "").split(",") if u})
    db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    have = {u.lower(): n for u, n in db.execute(
        "SELECT u.username, (SELECT count(*) FROM server s WHERE s.user_id = u.id"
        " AND s.name = 'IoT Postgres') FROM \"user\" u WHERE u.auth_source = 'oauth2'")}
    if not want:
        print("empty")
    else:
        bad = ["%s (no OAuth2 user)" % e for e in want if e not in have]
        bad += ["%s (no IoT Postgres entry)" % e for e in want if have.get(e) == 0]
        # its password file, where pgAdmin resolves "PassFile" (preprocess_username)
        folder = lambda e: (("pga_user_" + e) if e[:1].isdigit() else e).replace("@", "_")
        bad += ["%s (no password file)" % e for e in want if have.get(e) and not os.access(
            os.path.join(os.path.dirname(sys.argv[1]), "storage", folder(e), "pgpassfile"), os.R_OK)]
        print(("missing " + "; ".join(bad)) if bad else "ok %d" % len(want))
except Exception:
    print("?")
PY
)"; [[ "$oauth" == "?" || -z "$oauth" ]]; then
        _record FAIL "$name" "cannot read pgAdmin's users and servers in its pod (still starting? kubectl -n $ns logs deployment/pgadmin)"
    elif [[ "$oauth" == missing* ]]; then
        _record FAIL "$name" "pgAdmin's postStart hook did not give ${oauth#missing } its server (kubectl -n $ns logs deployment/pgadmin | grep oauth2-servers; ./deploy-infra.sh)"
    elif [[ "${IAM_GATES:-true}" == "false" ]]; then
        _record WARN "$name" "IAM_GATES=false: pgAdmin keeps the pre-policy $want"
    elif [[ "$oauth" == empty ]]; then
        _record WARN "$name" "admits $want, but PGADMIN_OAUTH2_SERVER_USERS is empty: no OAuth2 user has the IoT Postgres entry (./deploy-infra.sh)"
    else
        _record OK "$name" "admits $want from the access policy (checked at sign-in only); ${oauth#ok } OAuth2 user(s) have the IoT Postgres entry"
    fi
}

# =============================================================================
# Check: Superset's sign-in roles are the policy's (Superset stages B and C) — read-only
# target: NAMESPACE. Superset signs people in itself; the role each platform role gets
# (AUTH_ROLES_MAPPING) is SUPERSET_ROLES_MAPPING in Secret superset-secrets, next to
# its secret key and passwords, so the Deployment, its ReplicaSets and the Secret
# reach python on stdin, which prints only verdicts, variable names and the mapping
# (role names, no secret). SKIP without the Deployment: apps/superset/deploy.sh skips
# while the applied policy gives no role a Superset setting, and while
# IAM_DB_SERVICE_ROLES is not true (its connection is svc_superset).
# The pod reads the mapping as a secretKeyRef env, at start only (F10): so a running
# pod's medcea/config-checksum must equal superset_config_checksum
# (apps/superset/lib-superset.sh, the deploy's own function) of the live Secret and
# ConfigMap, or it still admits what an older Secret said.
# FAIL: a secret as a plain env value (in the Deployment or a ReplicaSet it kept, by
# name or because the value equals one of the Secret's), the Secret missing, its
# SUPERSET_SECRET_KEY empty or Superset's default, the mapping not policy_tool
# superset's (or the policy no longer has a superset tool, or gives no role a setting),
# a running pod started with another Secret or ConfigMap, the connection user not
# svc_superset, an image not pinned by digest; WARN while IAM_GATES=false, while
# IAM_DB_SERVICE_ROLES is not true (the next deploy stops it) and with no running pod.
# =============================================================================
check_supersetroles() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" doc have=() line want rc=0 same sum pods
    if ! timeout "$TIMEOUT" $KUBECTL get deployment superset -n "$ns" >/dev/null 2>&1; then
        if [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" ]]; then
            _record SKIP "$name" "no Superset deployment in $ns: it needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)"
        else
            _record SKIP "$name" "no Superset deployment in $ns (./apps/superset/deploy.sh installs it once the applied access policy gives a role a Superset setting)"
        fi
        return
    fi
    doc="$( { timeout "$TIMEOUT" $KUBECTL get deployment,replicaset -n "$ns" -l app=superset -o json 2>/dev/null || echo null
              echo
              timeout "$TIMEOUT" $KUBECTL get secret superset-secrets -n "$ns" -o json 2>/dev/null || echo null; } \
        | python3 -c '
import base64, json, re, sys
SECRET_NAMES = {"SUPERSET_SECRET_KEY", "SUPERSET_META_DB_PASS", "SUPERSET_CLIENT_SECRET", "SVC_SUPERSET_DB_PASS"}
DEFAULT_KEYS = {"CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET", "CHANGE_ME_SECRET_KEY", "thisISaSECRET_1234"}
text, dec, objs, i = sys.stdin.read(), json.JSONDecoder(), [], 0
try:
    while len(objs) < 2:
        while i < len(text) and text[i].isspace():
            i += 1
        o, i = dec.raw_decode(text, i)
        objs.append(o)
    lst, sec = objs
    if not lst or not any(o.get("kind") == "Deployment" for o in lst.get("items", [])):
        raise ValueError("no deployment")
except Exception:
    print("unreadable"); sys.exit(0)
data = {}
if sec:
    try:
        data = {k: base64.b64decode(v).decode() for k, v in (sec.get("data") or {}).items()}
    except Exception:
        print("unreadable"); sys.exit(0)
else:
    print("nosecret")
values = {v for k, v in data.items() if k != "SUPERSET_ROLES_MAPPING" and len(v) >= 8}
held, dbuser, images = [], [], set()
for o in lst["items"]:
    spec = o["spec"]["template"]["spec"]
    names = []
    for c in spec.get("initContainers", []) + spec.get("containers", []):
        images.add(c.get("image", ""))
        for e in c.get("env", []):
            if "value" not in e:
                continue
            if e["name"] in SECRET_NAMES or e["name"] == "SUPERSET_ROLES_MAPPING" \
                    or re.search(r"(?i)pass|secret|token", e["name"]) or e["value"] in values:
                names.append(e["name"])
            if o["kind"] == "Deployment" and e["name"] == "SUPERSET_DB_USER":
                dbuser.append(e["value"])
    if names:
        held.append("%s/%s (%s)" % (o["kind"].lower(), o["metadata"]["name"], ", ".join(sorted(set(names)))))
if held:
    print("plain " + "; ".join(held))
if sec:
    k = data.get("SUPERSET_SECRET_KEY", "")
    print("key " + ("empty" if not k else "default" if k in DEFAULT_KEYS else "short" if len(k) < 32 else "ok"))
    try:
        m = json.loads(data["SUPERSET_ROLES_MAPPING"])
        assert isinstance(m, dict)
        print("mapping " + json.dumps({r: sorted(v) for r, v in m.items()}, sort_keys=True))
    except Exception:
        print("mapping ?")
print("dbuser " + (dbuser[0] if dbuser else "-"))
bad = sorted(x for x in images if "@sha256:" not in x)
print("unpinned " + " ".join(bad) if bad else "pinned")
')"
    mapfile -t have <<<"$doc"
    _ssr_get() { local l; for l in "${have[@]}"; do [[ "$l" == "$1 "* ]] && { echo "${l#"$1" }"; return; }; done; }
    if [[ "$doc" == unreadable || -z "$doc" ]]; then
        _record FAIL "$name" "cannot read Superset's deployment, ReplicaSets or Secret superset-secrets in $ns"
        return
    elif [[ -n "$(_ssr_get plain)" ]]; then
        _record FAIL "$name" "Superset's secrets are plain env values in $(_ssr_get plain), not from Secret superset-secrets (./apps/superset/deploy.sh)"
        return
    elif printf '%s\n' "${have[@]}" | grep -qx nosecret; then
        _record FAIL "$name" "Secret superset-secrets is missing in $ns (./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get key)" != ok ]]; then
        _record FAIL "$name" "Superset's SUPERSET_SECRET_KEY is $(_ssr_get key) in Secret superset-secrets (./deploy-infra.sh generates it, then ./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get dbuser)" != svc_superset ]]; then
        _record FAIL "$name" "Superset's connection logs in as $(_ssr_get dbuser), not svc_superset (./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get unpinned)" != "" ]]; then
        _record FAIL "$name" "Superset's image is not pinned by digest: $(_ssr_get unpinned)"
        return
    fi
    # shellcheck source=/dev/null
    declare -F policy_tool >/dev/null || REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
        || { _record FAIL "$name" "cannot load infra/lib-policy-tools.sh"; return; }
    want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool superset 2>/dev/null)" || rc=$?
    case "$rc" in
        0) ;;
        3) _record WARN "$name" "IAM_GATES=false: Superset has no pre-policy setting; it runs with $(_ssr_get mapping) (./apps/superset/uninstall.sh, or IAM_GATES=true)"
           return ;;
        5) _record FAIL "$name" "Superset is deployed, but the applied access policy has no superset tool, or no role is given a setting: it still admits $(_ssr_get mapping) (./apps/superset/deploy.sh --gate-only stops it)"
           return ;;
        *) _record FAIL "$name" "cannot compile Superset's roles (python3 apps/iam/compiler/cli.py check)"
           return ;;
    esac
    same="$(python3 -c 'import json, sys
try:
    a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
    print({r: sorted(v) for r, v in a.items()} == {r: sorted(v) for r, v in b.items()})
except Exception:
    print(False)' "$(_ssr_get mapping)" "$want" 2>/dev/null)"
    if [[ "$same" != True ]]; then
        _record FAIL "$name" "AUTH_ROLES_MAPPING is $(_ssr_get mapping), the policy compiles $want (./apps/superset/deploy.sh --gate-only)"
        return
    fi
    # The running pods against the live Secret and ConfigMap (F10): the deploy's own checksum.
    # shellcheck source=/dev/null
    declare -F superset_config_checksum >/dev/null || source "$SCRIPT_DIR/apps/superset/lib-superset.sh" \
        || { _record FAIL "$name" "cannot load apps/superset/lib-superset.sh"; return; }
    sum="$(KUBECTL="timeout $TIMEOUT $KUBECTL" superset_config_checksum "$ns")" || sum=""
    pods="$(KUBECTL="timeout $TIMEOUT $KUBECTL" superset_web_pods "$ns")" || pods="?"
    if [[ -z "$sum" || "$pods" == "?" ]]; then
        _record FAIL "$name" "cannot compare the running Superset with Secret superset-secrets and ConfigMap superset-config in $ns"
    elif [[ -z "$pods" ]]; then
        _record WARN "$name" "no running Superset pod in $ns (kubectl -n $ns get pod -l app=superset)"
    elif [[ -n "$(awk -v s="$sum" '$2 != s {print $1}' <<<"$pods")" ]]; then
        _record FAIL "$name" "pod $(awk -v s="$sum" '$2 != s {print $1; exit}' <<<"$pods") was started with another Secret or ConfigMap (medcea/config-checksum): it may still admit an older mapping (./apps/superset/deploy.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES is not true: the next ./apps/superset/deploy.sh (or --gate-only) stops Superset, whose connection is svc_superset"
    else
        _record OK "$name" "maps $(python3 -c 'import json,sys; print(", ".join(sorted(json.loads(sys.argv[1]))))' "$want" 2>/dev/null) from the access policy (checked at sign-in only); connection svc_superset"
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
# Check: the boards' MQTT port is TLS only (5 Nov 2026)
# target: HOST:PORT of the TLS NodePort (31884). FAIL when it does not answer TLS with a
# certificate the platform CA signed for mqtt.$DOMAIN (what each board checks), or when
# the plain NodePort 31883, closed that day, answers again.
# =============================================================================
check_mqtttls() {
    local name="$1" target="$2" host port ca out
    host="${target%:*}"; port="${target##*:}"
    ca="$SCRIPT_DIR/.ca/ca.crt"
    if [[ ! -r "$ca" ]]; then
        _record FAIL "$name" "the platform CA $ca is unreadable (run as the account that deploys)"
        return
    fi
    if timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/31883" 2>/dev/null; then
        _record FAIL "$name" "the plain MQTT port ${host}:31883 answers: boards must come in over TLS only (./deploy-infra.sh)"
        return
    fi
    out="$(timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" -servername "mqtt.${DOMAIN}" \
            -verify_hostname "mqtt.${DOMAIN}" -CAfile "$ca" -verify_return_error </dev/null 2>&1 || true)"
    if grep -q "Verify return code: 0 (ok)" <<<"$out"; then
        _record OK "$name" "TLS on ${host}:${port}, certificate mqtt.${DOMAIN} from the platform CA; plain 31883 closed"
    elif [[ -z "$out" ]] || grep -qi "connect:errno\|Connection refused\|connect error" <<<"$out"; then
        _record FAIL "$name" "nothing answers on ${host}:${port} (Mosquitto's TLS listener, ./deploy-infra.sh)"
    else
        _record FAIL "$name" "${host}:${port}: $(grep -m1 -i "verify error\|Verify return code\|error" <<<"$out" | tr -s ' ' | cut -c1-110)"
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
        mqtttls) check_mqtttls "$name" "$target" ;;
        pvc)  check_pvc  "$name" "$target" ;;
        juju) check_juju "$name" "$target" ;;
        iamchain) check_iamchain "$name" "$target" ;;
        iamdbroles) check_iamdbroles "$name" "$target" ;;
        iamgrants)  check_iamgrants "$name" "$target" ;;
        iampolicy)    check_iampolicy "$name" "$target" ;;
        iamartefacts) check_iamartefacts "$name" "$target" ;;
        iamdecisions) check_iamdecisions "$name" "$target" ;;
        iampending)   check_iampending "$name" "$target" ;;
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
        supersetroles) check_supersetroles "$name" "$target" ;;
        apparmor)     check_apparmor "$name" ;;
        backupage)    check_backupage "$name" "$target" ;;
        manual)       check_manual "$name" "$target" ;;
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
