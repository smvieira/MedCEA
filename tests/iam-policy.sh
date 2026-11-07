#!/usr/bin/env bash
# tests/iam-policy.sh — IAM 4.4's drafting and approval on the running platform, with real
# tokens (design §14.7.8, the live default-mode test of §12): a change version is drafted,
# edited by two admins, refused while the checker is red, submitted, refused to the wrong
# approvers, approved by a qa person who is none of its authors with the diff they hashed,
# and withdrawn. With --apply or --change (IAM 4.5, design §14.8.11) the approved version is
# applied for real by ./apps/iam/apply.sh instead of withdrawn.
#
#   tests/iam-policy.sh              drafted, approved, withdrawn: nothing is applied
#   tests/iam-policy.sh --apply      a true no-op version (the cell back at its applied levels)
#                                    applied; it stays the applied version (nothing to restore)
#   tests/iam-policy.sh --change     the harmless narrowing applied, then rolled back to the
#                                    version applied before the run (--rollback-to), and
#                                    test-qa confirms the rollback in the Policy UI
#
# Needs IAM_POSTGREST_JWT=true and IAM_DB_ROLES=true (approvals go through config-api), an
# applied version, and no open change or skeleton version (it refuses, naming
# ./apps/iam/apply.sh --withdraw-open). Creates four throwaway accounts in realm
# $KEYCLOAK_REALM — test-admin-<hex> and test-admin2-<hex> (admin), test-qa-<hex> (qa, its own
# person_id) and test-qa2-<hex> (qa, with test-admin2's person_id) — each with a verified
# test-…@$PROJECT_NAME.invalid and a random password, and under --apply/--change a fifth,
# test-admin3-<hex> (admin, no password, test-qa's person_id, written directly in Keycloak: the
# User Manager refuses it). tests/iam_policy_flow.py signs each in to the Policy UI the way a
# browser does; every reason and note starts with "test:".
#   0   /api/me per role (tabs and acts), Who can…, Service identities, Break-glass served
#   1   admin drafts from applied (the checker's verdict recorded at creation)
#   2   admin saves one harmless cell (a narrowing, chosen offline with the checker) and back
#   3   admin2 saves it again (a co-author)
#   4   admin2 makes a red save; submit → 409 with the checker's errors; admin2 reverts it
#   5   admin submits
#   6   admin's token on approve → 403 (route table)
#   7   test-qa2 (admin2's person) approves → 403 "you are an author"
#   8   iam_svc with set_actor calling medcea.approve_policy in the PostgreSQL pod → 42501
#   9   test-qa approves with a wrong diff digest → 409 from iam-api, the version still submitted
#   10  test-qa fetches the diff, hashes it, approves → approved, with that digest and the
#       accepted skeleton
#   11  the chain holds `approved` with its evidence, and verifies
#   12  admin withdraws → withdrawn (default mode only)
# --apply and --change, before any account is created: the nine checks apply.sh verifies
# against (iamgrants, iamenforce, grafanarole, iamworkbench, onboardroles, pgadminroles,
# noderedauth, iamartefacts, supersetroles) must not FAIL (apply.sh N refuses an apply onto a failing
# platform), else exit 2 naming them; under --change the applied version must be one
# --rollback-to may return to (a bootstrap or rollback version confirmed and not disputed).
# Before step 1 the flow's guard compiles the version that would be applied and stops with
# exit 2 when a target outside routes and grants-* would change. After step 11:
#   14  test-admin3 (an enabled admin with the approver's person_id) exists:
#       apply.sh <v> --check-only --by test-admin-<hex> → exit 1 naming I17
#   15  test-admin3 disabled → --check-only passes (a disabled admin is accepted, OA-b)
#   16  MEDCEA_CONFIRMED=1 apply.sh <v> --by test-admin-<hex> (inherits the lock) → applied
#   17  --apply: no target listed changed, nothing rolled or upgraded, no MQTT credential
#       retired, the applied event (chain_head_before, jwk, apply_log_sha256, changed []),
#       state/policy-applied.yaml's header, iam-api's /healthz applied_version within 60 s;
#       --change: the routes digest moved and the role lost the narrowing's table privileges
#   18  --change: apply.sh --rollback-to <applied before the run> → a rollback version
#       applied, the privileges and the routes digest back
#   19  --change: test-qa confirms the rollback in the Policy UI (token path)
#   13  health shows no new FAIL (under --apply/--change the nine checks too)
# Its trap, in this order: (1) a version this run created that is still open is withdrawn with
# test-admin's token; if that fails, MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --withdraw-open
# --by test-admin-<hex> (the run holds the lock, which apply.sh inherits); (2) under --change, a
# version this run applied that is still the applied one is rolled back to the one applied
# before the run (apply.sh --rollback-to, "test: iam-policy.sh aborted") before any account is
# deleted, since --by must resolve; an apply left unfinished (exit 3) is finished first with
# --resume, under --apply too; (3) a rollback of this run still unconfirmed is confirmed by
# test-qa; (4) only then the accounts are deleted; (5) what is left (an open version, a version
# still applied, a rollback waiting for a qa confirm) is reported. The versions, their events
# and the approval evidence stay (append-only), naming the deleted test accounts.
#
# Takes the deploy lock (it creates accounts). Passwords reach Keycloak, the flow and psql on
# stdin only; usernames only are printed. Run from the repository root after
# ./apps/database/deploy.sh and ./apps/iam/deploy.sh (IAM 4.4; --apply and --change after
# Deploy IAM 4.5). Exit 1 on any failure, 2 on setup, a refused precondition or the guard.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,72p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
MODE=default
case "$*" in
    "") ;;
    --apply) MODE=apply ;;
    --change) MODE=change ;;
    *) echo "Usage: tests/iam-policy.sh [--apply | --change] (--help)" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-log.sh; medcea_log iam-policy   # logs/iam-policy-<ts>.log, unless a parent logs
[[ -f config.env ]] || { echo "config.env not found — run ./deploy-infra.sh first." >&2; exit 2; }
set -a   # the flow reads the host names, the namespace and iam_svc's password from the environment
# shellcheck disable=SC1091
source config.env
set +a
NAMESPACE="${NAMESPACE:-medcea}"
POLICY_DOMAIN="${POLICY_DOMAIN:-policy.$DOMAIN}"; export POLICY_DOMAIN
if [[ "${IAM_POSTGREST_JWT:-false}" != true || "${IAM_DB_ROLES:-false}" != true ]]; then
    echo "Approvals need IAM_POSTGREST_JWT=true and IAM_DB_ROLES=true: nothing to test (./guide.sh)." >&2
    exit 2
fi
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh
source infra/lib-policy-source.sh; policy_source_init "$NAMESPACE" --read-only   # compile what the deploys compiled
export NAMESPACE POSTGRES_DB
# the flow is a child process and cannot call the mk8s function: hand it the command mk8s runs
if declare -f mk8s | grep -q sudo; then FLOW_KUBECTL="sudo microk8s kubectl"; else FLOW_KUBECTL="microk8s kubectl"; fi

KC_PORT=18094
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"

# psql as postgres in the database, read-only; the password is read inside the pod. SQL on stdin.
db() {
    $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- env PGOPTIONS="-c default_transaction_read_only=on" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' \
        "$POSTGRES_DB" 2>&1
}
status_of() {   # VERSION → its status, or "" when it cannot be read
    local s
    s="$(db <<<"SELECT status FROM iam_policy.version WHERE version = $1")" || s=""
    [[ "$s" =~ ^[a-z_]+$ ]] && echo "$s"
}
is_open() { case "$1" in draft|submitted|approved) return 0 ;; esac; return 1; }
applied_now() {   # → the applied version's number, or "" when it cannot be read
    local a
    a="$(db <<<"SELECT version FROM iam_policy.version WHERE status = 'applied'")" || a=""
    [[ "$a" =~ ^[0-9]+$ ]] && echo "$a"
}
last_apply_event() {   # VERSION → the latest apply event filed under it (lib-policy-source.sh's set)
    db <<<"SELECT event FROM iam_policy.history WHERE version = $1
             AND event IN ('apply_started', 'applied', 'bootstrap_applied', 'apply_reverted', 'partial_apply', 'apply_deferred')
           ORDER BY event_id DESC LIMIT 1"
}
needs_confirm() {   # VERSION → 0 when it is a rollback still waiting for a qa confirm
    [[ "$(db <<<"SELECT kind = 'rollback' AND confirmed_at IS NULL AND disputed_at IS NULL
                   FROM iam_policy.version WHERE version = $1")" == t ]]
}
flow() { KUBECTL="$FLOW_KUBECTL" python3 tests/iam_policy_flow.py "$@" <<<"$ACCOUNTS"; }
apply_sh() {   # ARGS… → APPLY_OUT (also printed, indented), APPLY_RC; MEDCEA_CONFIRMED=1, the lock inherited
    APPLY_OUT="$(MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh "$@" 2>&1)"; APPLY_RC=$?
    sed 's/^/        /' <<<"$APPLY_OUT"
}
resume() {   # finishes an apply or rollback left at exit 3 (as test-admin, still resolvable)
    echo "  ....  finishing the unfinished apply (apply.sh --resume)"
    apply_sh --resume --by "$ADMIN_USER_T"
}

CREATED=()
PF_PID=""
ACCOUNTS=""
ADMIN_USER_T=""
PRE_APPLIED=""   # the version applied before the run: --change rolls back to it
APPLIED_V=""     # this run's version, once apply.sh was run on it
ROLLBACK_V=""    # this run's rollback version (--change)
WORK="$(mktemp -d)"; chmod 700 "$WORK"
cleanup() {
    local id code n=0 v="" s a
    [[ -s "$WORK/out.json" ]] && v="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("version") or "")' "$WORK/out.json" 2>/dev/null)"
    if [[ "$v" =~ ^[0-9]+$ ]]; then
        s="$(status_of "$v")"
        # (1) the run's version is still open: the throwaway admin withdraws it in the Policy UI,
        # else the host's withdraw, under this run's lock (apply.sh inherits it)
        if [[ -z "$s" ]] || is_open "$s"; then
            flow withdraw || true
            s="$(status_of "$v")"
        fi
        if [[ -z "$s" ]] || is_open "$s"; then
            echo "  ....  withdrawing version $v from the host (apply.sh --withdraw-open)"
            MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --withdraw-open --by "$ADMIN_USER_T" \
                --reason "test: iam-policy.sh aborted" || true
            s="$(status_of "$v")"
        fi
    fi
    # (2) an apply this run left unfinished is finished; under --change the run's version, while
    # it is still the applied one, is rolled back before any account is deleted (--by resolves)
    if [[ -n "$APPLIED_V" ]]; then
        a="$(applied_now)"
        if [[ -n "$a" ]] && [[ "$(last_apply_event "$a")" =~ ^(apply_started|partial_apply)$ ]]; then
            resume
        fi
        if [[ "$MODE" == change && -n "$PRE_APPLIED" && "$(applied_now)" == "$APPLIED_V" ]]; then
            echo "  ....  rolling version $APPLIED_V back to version $PRE_APPLIED (apply.sh --rollback-to)"
            apply_sh --rollback-to "$PRE_APPLIED" --by "$ADMIN_USER_T" --reason "test: iam-policy.sh aborted"
            (( APPLY_RC == 3 )) && resume
            a="$(applied_now)"
            [[ -n "$a" && "$a" != "$APPLIED_V" ]] && needs_confirm "$a" && ROLLBACK_V="$a"
        fi
    fi
    # (3) a rollback of this run still waiting: test-qa confirms it
    if [[ -n "$ROLLBACK_V" ]] && needs_confirm "$ROLLBACK_V"; then
        flow confirm "$ROLLBACK_V" || true
    fi
    # (4) only then the accounts
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the User Manager${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    # (5) what is left
    if [[ "$v" =~ ^[0-9]+$ ]] && { [[ -z "$s" ]] || is_open "$s"; }; then
        echo -e "${RED}  version $v is still ${s:-unreadable}: withdraw it (./apps/iam/apply.sh --withdraw-open --by <you> --reason \"<why>\")${NC}" >&2
    fi
    if [[ -n "$APPLIED_V" ]]; then
        a="$(applied_now)"
        if [[ -n "$a" ]] && [[ "$(last_apply_event "$a")" =~ ^(apply_started|partial_apply)$ ]]; then
            echo -e "${RED}  version $a's apply is not finished: ./apps/iam/apply.sh --resume --by <you>${NC}" >&2
        fi
        if [[ "$MODE" == change && "$a" == "$APPLIED_V" ]]; then
            echo -e "${RED}  version $APPLIED_V (the test's narrowing) is still applied: ./apps/iam/apply.sh --rollback-to $PRE_APPLIED --by <you> --reason \"<why>\"${NC}" >&2
        fi
    fi
    if [[ -n "$ROLLBACK_V" ]] && needs_confirm "$ROLLBACK_V"; then
        echo -e "${RED}  rollback version $ROLLBACK_V waits for a qa confirm (Policy UI, Confirm tab)${NC}" >&2
    fi
    rm -rf "$WORK"
    [[ -n "${POLICY_SOURCE_STATE_FILE:-}" ]] && rm -rf "$(dirname "$POLICY_SOURCE_STATE_FILE")"
    kc_admin_done
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# one version in flight: refuse before anything is created
OPEN_NOW="$(db <<<"SELECT version || ' (' || kind || ', ' || status || ')' FROM iam_policy.version
                    WHERE kind IN ('change', 'skeleton') AND status IN ('draft', 'submitted', 'approved')")" \
    || { echo "Cannot read iam_policy.version: $OPEN_NOW" >&2; exit 2; }
if [[ -n "$OPEN_NOW" ]]; then
    echo "Version $OPEN_NOW is open: take it through or withdraw it first" \
         "(./apps/iam/apply.sh --withdraw-open --by <you> --reason \"<why>\")." >&2
    exit 2
fi

# health: the policy checks (step 13) and, under --apply/--change, the nine checks apply.sh
# verifies against (design §14.8.6 step 9), whose FAILs before the run refuse it
HC="$WORK/health.conf"
HC_NAMES=("Access policy history" "Access policy version" "Policy artefacts" "Database grants")
printf '%s\n' '# tests/iam-policy.sh step 13' \
    'Access policy history    | iamchain     | $POSTGRES_DB |' \
    'Access policy version    | iampolicy    | $POSTGRES_DB |' \
    'Policy artefacts         | iamartefacts | $NAMESPACE   |' \
    'Database grants          | iamgrants    | $POSTGRES_DB |' > "$HC"
HC8="$WORK/apply.conf"
HC8_NAMES=("Database grants" "Service enforcement" "Grafana roles" "AI Workbench gate"
           "Onboarding roles" "pgAdmin roles" "Node-RED editor rights" "Policy artefacts" "Superset roles")
printf '%s\n' '# tests/iam-policy.sh: the checks of apply.sh step 9' \
    'Database grants          | iamgrants    | $POSTGRES_DB |' \
    'Service enforcement      | iamenforce   | $NAMESPACE   |' \
    'Grafana roles            | grafanarole  | $NAMESPACE   |' \
    'AI Workbench gate        | iamworkbench | $NAMESPACE   |' \
    'Onboarding roles         | onboardroles |              |' \
    'pgAdmin roles            | pgadminroles | $NAMESPACE   |' \
    'Node-RED editor rights   | noderedauth  | $NAMESPACE   |' \
    'Policy artefacts         | iamartefacts | $NAMESPACE   |' \
    'Superset roles           | supersetroles | $NAMESPACE  |' > "$HC8"
if [[ "$MODE" != default ]]; then
    tail -n +2 "$HC8" | grep -vF 'Database grants' | grep -vF 'Policy artefacts' >> "$HC"
    HC_NAMES+=("Service enforcement" "Grafana roles" "AI Workbench gate" "Onboarding roles" "pgAdmin roles" "Node-RED editor rights"
               "Superset roles")
fi
health_fails() {   # CONF NAME… → the names of the FAILing checks, one per line, sorted
    local conf="$1" out name
    shift
    out="$(./health-check.sh -c "$conf" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
    for name in "$@"; do
        grep -qF "[ FAIL ]  $name" <<<"$out" && echo "$name"
    done | sort -u
}

if [[ "$MODE" != default ]]; then
    # apply.sh N refuses an apply onto a platform already failing one of its checks (step 6b)
    PRE_FAILS="$(health_fails "$HC8" "${HC8_NAMES[@]}")"
    if [[ -n "$PRE_FAILS" ]]; then
        echo "These checks FAIL before the run: $(paste -sd, <<<"$PRE_FAILS"). apply.sh refuses an apply" \
             "onto a failing platform: fix them first (./health-check.sh)." >&2
        exit 2
    fi
    PRE_APPLIED="$(applied_now)"
    [[ -n "$PRE_APPLIED" ]] || { echo "Cannot read the applied version (./apps/iam/apply.sh --status)." >&2; exit 2; }
    if [[ "$MODE" == change ]]; then
        # --rollback-to needs the version it returns to confirmed when it is a bootstrap or rollback
        PRE_OK="$(db <<<"SELECT kind || '|' || (kind IN ('change', 'skeleton')
                          OR (confirmed_at IS NOT NULL AND disputed_at IS NULL))
                    FROM iam_policy.version WHERE version = $PRE_APPLIED")"
        if [[ "$PRE_OK" != *'|true' ]]; then
            echo "Version $PRE_APPLIED (${PRE_OK%%|*}) is applied but not confirmed by qa (or disputed):" \
                 "--change could not roll back to it. Have a qa person confirm it in the Policy UI first." >&2
            exit 2
        fi
    fi
fi

$KUBECTL port-forward svc/keycloak "$KC_PORT:80" -n "$NAMESPACE" &>/dev/null 9>&- &
PF_PID=$!
for _ in $(seq 1 12); do
    kc_admin_select && break
    sleep 2
done
[[ -n "$KC_ADMIN_MODE" ]] || { echo "Cannot reach Keycloak's admin API (port-forward on $KC_PORT)." >&2; exit 2; }

echo -e "${BOLD}Drafting and approval in the Policy UI${NC} (https://$POLICY_DOMAIN, realm $R)"
SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
ADMIN_USER_T="test-admin-$SUFFIX"
ACCOUNTS="{\"cacert\": null, \"out\": \"$WORK/out.json\", \"users\": {"
[[ -f .ca/ca.crt ]] && ACCOUNTS="{\"cacert\": \"$REPO_ROOT/.ca/ca.crt\", \"out\": \"$WORK/out.json\", \"users\": {"
for spec in admin:admin:admin admin2:admin:admin2 qa:qa:qa qa2:qa:admin2; do   # key:role:whose person_id
    IFS=: read -r key role pkey <<<"$spec"
    user="test-$key-$SUFFIX"
    pass="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    pid="test-person-$pkey-$SUFFIX"
    body="$(U="$user" P="$pass" E="$user@${PROJECT_NAME}.invalid" ROLE="$role" PID="$pid" python3 -c '
import json, os
e = os.environ
print(json.dumps({"username": e["U"], "enabled": True, "emailVerified": True,
    "email": e["E"], "firstName": "Test", "lastName": e["ROLE"],
    "attributes": {"person_id": [e["PID"]]},
    "credentials": [{"type": "password", "value": e["P"], "temporary": False}]}))')"
    code="$(_kc_send POST "realms/$R/users" "$body")"
    id="$(_kc_user_id "$R" "$user")"
    [[ -n "$id" ]] && CREATED+=("$id")
    [[ "$code" == 201 && -n "$id" ]] || { echo -e "${RED}Could not create $user (HTTP $code).${NC}" >&2; exit 1; }
    code="$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$(_kc_get "realms/$R/roles/$role")]")"
    [[ "$code" == 204 ]] || { echo -e "${RED}Could not give $user the role $role (HTTP $code).${NC}" >&2; exit 1; }
    ACCOUNTS+="$(K="$key" ID="$id" U="$user" P="$pass" PID="$pid" ROLE="$role" python3 -c '
import json, os
e = os.environ
print(json.dumps(e["K"]) + ": " + json.dumps({"id": e["ID"], "username": e["U"], "password": e["P"],
                                               "person_id": e["PID"], "role": e["ROLE"]}))'),"
done
ACCOUNTS="${ACCOUNTS%,}}}"
echo "Created ${#CREATED[@]} test account(s): test-<admin|admin2|qa|qa2>-$SUFFIX (qa2 shares admin2's person_id)"
echo ""

# ── IAM 4.5: the approved version applied for real (--apply, --change; design §14.8.11) ──
SAYS_WHAT="Drafting and approval"; SAYS_WHO="IAM 4.4"
[[ "$MODE" != default ]] && { SAYS_WHAT="Drafting, approval and applying"; SAYS_WHO="IAM 4.5"; }
STEP_FAILS=0
sok()  { printf '  PASS  %-4s %s\n' "$1" "$2"; }
sbad() { printf '  FAIL  %-4s %s\n' "$1" "$2"; STEP_FAILS=$((STEP_FAILS + 1)); }
routes_digest() {   # the medcea/routes-digest annotation of ConfigMap medcea-iam-lib
    $KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
print(json.load(sys.stdin)["metadata"].get("annotations", {}).get("medcea/routes-digest", ""))' 2>/dev/null
}
privs() {   # → "t"/"f" per privilege the flow listed as lost ("lost" in out.json), space-separated
    local sql
    sql="$(python3 -c '
import json, sys
q = lambda x: chr(39) + str(x).replace(chr(39), chr(39) * 2) + chr(39)
for g, o, p in json.load(open(sys.argv[1])).get("lost") or []:
    print("SELECT has_table_privilege(%s, %s, %s);" % (q(g), q(o), q(p)))' "$WORK/out.json")"
    [[ -n "$sql" ]] && db <<<"$sql" | paste -sd ' '
}
payload_problems() {   # PAYLOAD MODE → what the applied event lacks, comma-separated ("" = complete)
    python3 -c '
import json, re, sys
try:
    p = json.loads(sys.argv[1])
except ValueError:
    print("no applied event"); sys.exit(0)
h, j, e = p.get("chain_head_before") or {}, p.get("jwk") or {}, []
if not (isinstance(h.get("id"), int) and re.fullmatch("[0-9a-f]{64}", str(h.get("hash")))):
    e.append("chain_head_before %s" % h)
if not all(j.get(k) for k in ("kid", "n", "e")):
    e.append("jwk")
if not re.fullmatch("[0-9a-f]{64}", str(p.get("apply_log_sha256"))):
    e.append("apply_log_sha256")
ch = p.get("changed")
if sys.argv[2] == "apply" and ch != []:
    e.append("changed %s (want [])" % ch)
if sys.argv[2] == "change" and "routes" not in (ch or []):
    e.append("changed %s (want routes)" % ch)
print(", ".join(e))' "$1" "$2"
}
iamapi_applied() {   # iam-api's /healthz on :8083, read in the pod: its applied_version
    $KUBECTL exec -n "$NAMESPACE" deployment/iam-api -c iam-api -- python3 -c \
        'import json, urllib.request; print(json.loads(urllib.request.urlopen("http://127.0.0.1:8083/healthz", timeout=5).read()).get("applied_version"))' \
        2>/dev/null
}

apply_steps() {
    local v user id code body pl a n before after r_before
    v="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("version") or "")' "$WORK/out.json" 2>/dev/null)"
    [[ "$v" =~ ^[0-9]+$ ]] || { sbad 14 "the flow left no approved version"; return 1; }

    # 14 — I17: an enabled admin with the approver's (test-qa's) person_id, written directly
    user="test-admin3-$SUFFIX"
    body="$(U="$user" E="$user@${PROJECT_NAME}.invalid" PID="test-person-qa-$SUFFIX" python3 -c '
import json, os
e = os.environ
print(json.dumps({"username": e["U"], "enabled": True, "emailVerified": True, "email": e["E"],
    "firstName": "Test", "lastName": "admin3", "attributes": {"person_id": [e["PID"]]}}))')"
    code="$(_kc_send POST "realms/$R/users" "$body")"
    id="$(_kc_user_id "$R" "$user")"
    [[ -n "$id" ]] && CREATED+=("$id")
    if [[ "$code" != 201 || -z "$id" ]] \
            || [[ "$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$(_kc_get "realms/$R/roles/admin")]")" != 204 ]]; then
        sbad 14 "could not create $user as an admin with test-qa's person_id (HTTP $code)"
        return 1
    fi
    echo "  ....       created $user (admin, test-qa's person_id, no password): 5 test accounts"
    apply_sh "$v" --check-only --by "$ADMIN_USER_T"
    (( APPLY_RC == 1 )) && grep -q 'I17' <<<"$APPLY_OUT" \
        && sok 14 "apply.sh $v --check-only refuses: an enabled admin shares the approver's person (I17)" \
        || sbad 14 "apply.sh $v --check-only with $user enabled: exit $APPLY_RC, want 1 naming I17"

    # 15 — disabled, the same check passes (a disabled admin is accepted, OA-b); read-modify-write
    body="$(_kc_get "realms/$R/users/$id" | python3 -c '
import json, sys
u = json.load(sys.stdin); u["enabled"] = False; print(json.dumps(u))')"
    code="$(_kc_send PUT "realms/$R/users/$id" "$body")"
    apply_sh "$v" --check-only --by "$ADMIN_USER_T"
    [[ "$code" == 204 ]] && (( APPLY_RC == 0 )) \
        && sok 15 "$user disabled: apply.sh $v --check-only passes" \
        || sbad 15 "$user disabled (HTTP $code): apply.sh $v --check-only exit $APPLY_RC, want 0"
    (( APPLY_RC == 0 )) || return 1   # never apply what the check refuses

    # 16 — applied, MEDCEA_CONFIRMED=1 under this run's lock
    before="$(db <<<'SELECT max(event_id) FROM iam_policy.history')"
    r_before="$(routes_digest)"
    if [[ "$MODE" == change ]]; then
        a="$(privs)"
        [[ -n "$a" && "$a" != *f* ]] || { sbad 16 "the role does not hold the narrowing's privileges before the apply ($a)"; return 1; }
    fi
    APPLIED_V="$v"
    apply_sh "$v" --by "$ADMIN_USER_T"
    a="$(applied_now)"
    if (( APPLY_RC == 0 )) && [[ "$a" == "$v" ]]; then
        sok 16 "apply.sh $v --by $ADMIN_USER_T applied version $v"
    else
        sbad 16 "apply.sh $v: exit $APPLY_RC, the applied version is ${a:-unreadable}"
        return 1
    fi

    # 17 — what the apply did
    pl="$(db <<<"SELECT payload FROM iam_policy.history WHERE version = $v AND event = 'applied' ORDER BY event_id DESC LIMIT 1")"
    a="$(payload_problems "$pl" "$MODE")"
    [[ -z "$a" ]] && sok 17 "the applied event carries chain_head_before, jwk, apply_log_sha256 and its changed list" \
        || sbad 17 "the applied event: $a"
    if [[ "$MODE" == apply ]]; then
        grep -qE '^[[:space:]]+[A-Za-z0-9_./-]+[[:space:]]+changed[[:space:]]*$' <<<"$APPLY_OUT" \
            && sbad 17 "step 6 lists a changed target for a no-op version" \
            || sok 17 "step 6 lists no changed target"
        grep -qEi 'rollout restart|helm upgrade|re-rendered' <<<"$APPLY_OUT" \
            && sbad 17 "the no-op apply rolled or re-rendered something" \
            || sok 17 "nothing rolled, upgraded or re-rendered"
        n="$(db <<<"SELECT count(*) FROM iam_policy.history WHERE event_id > ${before:-0} AND event = 'mqtt_credentials_retired'")"
        [[ "$n" == 0 ]] && sok 17 "no MQTT credential retired" || sbad 17 "MQTT credentials retired: ${n:-unreadable} event(s)"
        head -1 state/policy-applied.yaml 2>/dev/null | grep -q "version=$v kind=change " \
            && sok 17 "state/policy-applied.yaml is version $v (kind change)" \
            || sbad 17 "state/policy-applied.yaml's header is not version=$v kind=change"
        for _ in $(seq 1 12); do
            a="$(iamapi_applied)"
            [[ "$a" == "$v" ]] && break
            sleep 5
        done
        [[ "$a" == "$v" ]] && sok 17 "iam-api's /healthz says applied_version $v" \
            || sbad 17 "iam-api's /healthz says applied_version ${a:-unreadable} after 60 s, want $v"
        (( STEP_FAILS == 0 ))
        return
    fi
    after="$(routes_digest)"
    [[ -n "$after" && "$after" != "$r_before" ]] && sok 17 "the routes digest moved (${r_before:0:12} → ${after:0:12})" \
        || sbad 17 "the routes digest did not move (${r_before:0:12} → ${after:0:12})"
    a="$(privs)"
    [[ -n "$a" && "$a" != *t* ]] && sok 17 "the role lost the narrowing's table privileges ($(python3 -c '
import json, sys
print(", ".join("%s %s %s" % tuple(x) for x in json.load(open(sys.argv[1])).get("lost") or []))' "$WORK/out.json"))" \
        || sbad 17 "the role still holds a privilege the narrowing removes ($a)"

    # 18 — rolled back to the version applied before the run
    apply_sh --rollback-to "$PRE_APPLIED" --by "$ADMIN_USER_T" --reason "test: iam-policy.sh --change"
    a="$(applied_now)"
    [[ -n "$a" && "$a" != "$v" ]] && needs_confirm "$a" && ROLLBACK_V="$a"
    after="$(routes_digest)"
    if (( APPLY_RC == 0 )) && [[ -n "$ROLLBACK_V" ]]; then
        sok 18 "apply.sh --rollback-to $PRE_APPLIED: rollback version $ROLLBACK_V applied"
    else
        sbad 18 "apply.sh --rollback-to $PRE_APPLIED: exit $APPLY_RC, the applied version is ${a:-unreadable}"
        return 1
    fi
    a="$(privs)"
    [[ -n "$a" && "$a" != *f* && "$after" == "$r_before" ]] && sok 18 "the privileges and the routes digest are back" \
        || sbad 18 "after the rollback: privileges ($a), routes digest ${after:0:12} (want ${r_before:0:12})"

    # 19 — test-qa confirms the rollback in the Policy UI (token path)
    flow confirm "$ROLLBACK_V" && ! needs_confirm "$ROLLBACK_V" \
        && sok 19 "test-qa confirmed rollback version $ROLLBACK_V" \
        || sbad 19 "rollback version $ROLLBACK_V is not confirmed"
    (( STEP_FAILS == 0 ))
}

# 13's baseline: the checks' FAILs before the run
BEFORE="$(health_fails "$HC" "${HC_NAMES[@]}")"

if [[ "$MODE" == default ]]; then
    flow run
else
    flow run "--$MODE"
fi
rc=$?
(( rc == 2 )) && exit 2   # the guard: nothing was drafted
if [[ "$MODE" != default && $rc -eq 0 ]]; then
    apply_steps || rc=1
fi

AFTER="$(health_fails "$HC" "${HC_NAMES[@]}")"
NEW="$(comm -13 <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | sed '/^$/d')"
if [[ -z "$NEW" ]]; then
    echo "  PASS  13   health shows no new FAIL${BEFORE:+ (already failing before: $(paste -sd, <<<"$BEFORE"))}"
else
    echo "  FAIL  13   new health FAIL: $(paste -sd, <<<"$NEW")"
    rc=1
fi
echo ""
if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}${SAYS_WHAT} behave as ${SAYS_WHO} says.${NC}"
else
    echo -e "${RED}${BOLD}${SAYS_WHAT} do not behave as ${SAYS_WHO} says.${NC}"
fi
exit $rc
