#!/usr/bin/env bash
# tests/iam-policy.sh — IAM 4.4's drafting and approval on the running platform, with real
# tokens (design §14.7.8, the live default-mode test of §12): a change version is drafted,
# edited by two admins, refused while the checker is red, submitted, refused to the wrong
# approvers, approved by a qa person who is none of its authors with the diff they hashed,
# and withdrawn. Nothing is applied (apply.sh <version> is IAM 4.5).
#
#   tests/iam-policy.sh
#
# Needs IAM_POSTGREST_JWT=true and IAM_DB_ROLES=true (approvals go through config-api), an
# applied version, and no open change or skeleton version (it refuses, naming
# ./apps/iam/apply.sh --withdraw-open). Creates four throwaway accounts in realm
# $KEYCLOAK_REALM — test-admin-<hex> and test-admin2-<hex> (admin), test-qa-<hex> (qa, its own
# person_id) and test-qa2-<hex> (qa, with test-admin2's person_id) — each with a verified
# test-…@$PROJECT_NAME.invalid and a random password. tests/iam_policy_flow.py signs each in to
# the Policy UI the way a browser does; every reason and note starts with "test:".
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
#   12  admin withdraws → withdrawn
#   13  health (iamchain, iampolicy, iamartefacts, iamgrants) shows no new FAIL
# Its trap, in this order: (1) a version this run created that is still open is withdrawn with
# test-admin's token; (2) if that fails, MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --withdraw-open
# --by test-admin-<hex> (the run holds the lock, which apply.sh inherits); (3) only then the
# accounts are deleted; (4) what was left open, if anything, is reported. The version, its
# events and the approval evidence stay (append-only), naming the deleted test accounts.
#
# Takes the deploy lock (it creates accounts). Passwords reach Keycloak, the flow and psql on
# stdin only; usernames only are printed. Run from the repository root after
# ./apps/database/deploy.sh and ./apps/iam/deploy.sh (IAM 4.4). Exit 1 on any failure, 2 on setup.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
[[ $# -eq 0 ]] || { echo "Usage: tests/iam-policy.sh (--help)" >&2; exit 2; }

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

CREATED=()
PF_PID=""
ACCOUNTS=""
ADMIN_USER_T=""
WORK="$(mktemp -d)"; chmod 700 "$WORK"
cleanup() {
    local id code n=0 v="" s
    [[ -s "$WORK/out.json" ]] && v="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("version") or "")' "$WORK/out.json" 2>/dev/null)"
    if [[ "$v" =~ ^[0-9]+$ ]]; then
        s="$(status_of "$v")"
        # (1) the run's version is still open: the throwaway admin withdraws it in the Policy UI
        if [[ -z "$s" ]] || is_open "$s"; then
            KUBECTL="$FLOW_KUBECTL" python3 tests/iam_policy_flow.py withdraw <<<"$ACCOUNTS" || true
            s="$(status_of "$v")"
        fi
        # (2) the host's withdraw, under this run's lock (apply.sh inherits it)
        if [[ -z "$s" ]] || is_open "$s"; then
            echo "  ....  withdrawing version $v from the host (apply.sh --withdraw-open)"
            MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --withdraw-open --by "$ADMIN_USER_T" \
                --reason "test: iam-policy.sh aborted" || true
            s="$(status_of "$v")"
        fi
    fi
    # (3) only then the accounts
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the User Manager${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    # (4) what was left open
    if [[ "$v" =~ ^[0-9]+$ ]] && { [[ -z "$s" ]] || is_open "$s"; }; then
        echo -e "${RED}  version $v is still ${s:-unreadable}: withdraw it (./apps/iam/apply.sh --withdraw-open --by <you> --reason \"<why>\")${NC}" >&2
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

# 13's baseline: the policy checks' FAILs before the run
HC="$WORK/health.conf"
printf '%s\n' '# tests/iam-policy.sh step 13' \
    'Access policy history    | iamchain     | $POSTGRES_DB |' \
    'Access policy version    | iampolicy    | $POSTGRES_DB |' \
    'Policy artefacts         | iamartefacts | $NAMESPACE   |' \
    'Database grants          | iamgrants    | $POSTGRES_DB |' > "$HC"
health_fails() {   # → the names of the FAILing checks, one per line, sorted
    local out name
    out="$(./health-check.sh -c "$HC" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
    for name in "Access policy history" "Access policy version" "Policy artefacts" "Database grants"; do
        grep -qF "[ FAIL ]  $name" <<<"$out" && echo "$name"
    done | sort -u
}
BEFORE="$(health_fails)"

KUBECTL="$FLOW_KUBECTL" python3 tests/iam_policy_flow.py run <<<"$ACCOUNTS"
rc=$?

AFTER="$(health_fails)"
NEW="$(comm -13 <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | sed '/^$/d')"
if [[ -z "$NEW" ]]; then
    echo "  PASS  13   health shows no new FAIL${BEFORE:+ (already failing before: $(paste -sd, <<<"$BEFORE"))}"
else
    echo "  FAIL  13   new health FAIL: $(paste -sd, <<<"$NEW")"
    rc=1
fi
echo ""
if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Drafting and approval behave as IAM 4.4 says.${NC}"
else
    echo -e "${RED}${BOLD}Drafting and approval do not behave as IAM 4.4 says.${NC}"
fi
exit $rc
