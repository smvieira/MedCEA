#!/usr/bin/env bash
# tests/iam-access.sh — IAM 2.7's account decisions on the running platform, with real
# tokens (spec 8.3): a widening waits for qa and a qa person applies it; a person_id
# change waits and its subject cannot confirm it; a deactivation applies at once and ends
# the person's sessions; I17 refuses an admin's person on a qa account; a forged
# cross-site POST changes nothing.
#
#   tests/iam-access.sh [--with-review]
#
# Creates four throwaway accounts in realm $KEYCLOAK_REALM — test-admin-<hex>,
# test-qa-<hex>, test-qa2-<hex> and test-operator-<hex>, each with its own person_id, a
# verified test-…@$PROJECT_NAME.invalid and a random password — and deletes them on exit,
# also on Ctrl-C or failure. tests/iam_access_flow.py signs each in the way a browser
# does and calls the User Manager's API with its session. The decisions it makes stay in
# iam.account_decision (append-only), naming the deleted test accounts; one it leaves
# pending is withdrawn before exit. --with-review also creates this quarter's access
# review as test-qa2 (permanent, and one per quarter: never on a production platform whose
# qa has yet to make this quarter's).
#
# Takes the deploy lock (it creates accounts). Calls the Keycloak admin API as the deploy
# scripts do (infra/lib-keycloak-admin.sh). Run from the repository root after
# ./apps/access/deploy.sh. Exit 1 on any failure.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
WITH_REVIEW=false
for a in "$@"; do
    case "$a" in
        --with-review) WITH_REVIEW=true ;;
        *) echo "unknown option $a (--help)" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
set -a   # the flow reads the host names from the environment
# shellcheck disable=SC1091
source config.env
set +a
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"; export ACCESS_DOMAIN
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh

KC_PORT=18092
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"

CREATED=()        # Keycloak user ids, deleted on exit
PF_PID=""
OUT=""
cleanup() {
    local id code n=0
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the Keycloak console${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    kc_admin_done
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
    [[ -n "$OUT" ]] && rm -f "$OUT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

$KUBECTL port-forward svc/keycloak "$KC_PORT:80" -n "$NAMESPACE" &>/dev/null 9>&- &
PF_PID=$!
for _ in $(seq 1 12); do
    kc_admin_select && break
    sleep 2
done
if [[ -z "$KC_ADMIN_MODE" ]]; then
    echo "Cannot reach Keycloak's admin API (port-forward on $KC_PORT)." >&2
    exit 2
fi

echo -e "${BOLD}Account decisions through the User Manager${NC} (realm $R, https://$ACCESS_DOMAIN)"
SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
USERS_JSON="{"
for spec in admin:admin qa:qa qa2:qa operator:operator; do
    key="${spec%%:*}"; role="${spec#*:}"
    user="test-$key-$SUFFIX"
    pass="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    pid="test-$user"
    body="$(U="$user" P="$pass" E="$user@${PROJECT_NAME}.invalid" ROLE="$role" PID="$pid" python3 -c '
import json, os
print(json.dumps({"username": os.environ["U"], "enabled": True, "emailVerified": True,
    "email": os.environ["E"], "firstName": "Test", "lastName": os.environ["ROLE"],
    "attributes": {"person_id": [os.environ["PID"]]},
    "credentials": [{"type": "password", "value": os.environ["P"], "temporary": False}]}))')"
    code="$(_kc_send POST "realms/$R/users" "$body")"
    id="$(_kc_user_id "$R" "$user")"
    [[ -n "$id" ]] && CREATED+=("$id")
    if [[ "$code" != 201 || -z "$id" ]]; then
        echo -e "${RED}Could not create $user (HTTP $code).${NC}" >&2
        exit 1
    fi
    rolerep="$(_kc_get "realms/$R/roles/$role")"
    code="$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$rolerep]")"
    if [[ "$code" != 204 ]]; then
        echo -e "${RED}Could not give $user the role $role (HTTP $code).${NC}" >&2
        exit 1
    fi
    USERS_JSON+="$(K="$key" ID="$id" U="$user" P="$pass" PID="$pid" python3 -c '
import json, os
e = os.environ
print(json.dumps(e["K"]) + ": " + json.dumps({"id": e["ID"], "username": e["U"], "password": e["P"], "person_id": e["PID"]}))'),"
done
USERS_JSON="${USERS_JSON%,}}"
echo "Created ${#CREATED[@]} test account(s): test-<admin|qa|qa2|operator>-$SUFFIX"
echo ""

CACERT=null; [[ -f .ca/ca.crt ]] && CACERT="\"$REPO_ROOT/.ca/ca.crt\""
OUT="$(mktemp)"
python3 tests/iam_access_flow.py <<<"{\"users\": $USERS_JSON, \"cacert\": $CACERT, \"with_review\": $WITH_REVIEW, \"out\": \"$OUT\"}"
rc=$?

# step 7: the deactivated operator has no Keycloak session left (POST /users/{id}/logout)
OP_ID="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("operator_id", ""))' "$OUT" 2>/dev/null)"
if [[ -n "$OP_ID" ]]; then
    n="$(_kc_get "realms/$R/users/$OP_ID/sessions" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))' 2>/dev/null)"
    if [[ "$n" == 0 ]]; then
        echo "  PASS  7    the deactivated operator holds no Keycloak session"
    else
        echo "  FAIL  7    the deactivated operator still holds ${n:-?} Keycloak session(s)"
        rc=1
    fi
fi
echo ""
if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Account decisions behave as IAM 2.7 says.${NC}"
else
    echo -e "${RED}${BOLD}Account decisions do not behave as IAM 2.7 says.${NC}"
fi
exit $rc
