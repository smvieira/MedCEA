#!/usr/bin/env bash
# tests/iam-signin.sh — every platform role signs in to every gated host, and gets in
# exactly where the access policy says (IAM plan, Phase 1 tests; the per-role matrix
# moved here from Phase 0).
#
# Creates one throwaway account per role in realm $KEYCLOAK_REALM — test-<role>-<random>,
# with a first and last name, test-…@$PROJECT_NAME.invalid (verified), its own person_id
# and a random password, so Keycloak asks for nothing before signing in — and deletes them
# all on exit, also on Ctrl-C or failure. tests/iam_signin_flow.py then signs each one in
# the way a browser does (host → Keycloak's form → the proxy's callback), so this tests the
# real gates, sessions and 403 pages without changing any proxy setting. Where an account
# gets in, it also calls one read-only API per service behind the host, and the services'
# logs must hold a "would refuse" (enforcing: "refused") line for exactly the calls the
# route table refuses, and every service must refuse one path in no table (a hook that
# never loaded fails) (medcea_iam.check(), IAM plan 1.2). One more account,
# test-none-<random>, holds no platform role and must be refused everywhere, Grafana
# included (IAM 3.1: an enabled account without a role no longer reaches it); Grafana's
# role and Explore are checked against the policy (iam_signin_flow.py).
#
# Takes the deploy lock (it creates accounts). Calls the Keycloak admin API as the deploy
# scripts do (infra/lib-keycloak-admin.sh). Each sign-in is a Keycloak login event in the
# test account's name. Run from the repository root:  tests/iam-signin.sh
# Exit 1 on any mismatch.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

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
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh

KC_PORT=18089
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"

CREATED=()        # Keycloak user ids, deleted on exit
PF_PID=""
cleanup() {
    local id code n=0
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the User Manager${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    kc_admin_done
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
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

echo -e "${BOLD}Sign-in per role${NC} (realm $R, Keycloak admin API as $KC_ADMIN_MODE)"
SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
ROLES="$(python3 -c '
import sys; sys.path.insert(0, "apps/iam")
from compiler import model
print(" ".join(model.load().roles))')"

USERS_JSON="["
for role in $ROLES none; do
    user="test-${role//_/-}-$SUFFIX"
    pass="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    body="$(U="$user" P="$pass" E="$user@${PROJECT_NAME}.invalid" ROLE="$role" python3 -c '
import json, os
print(json.dumps({"username": os.environ["U"], "enabled": True, "emailVerified": True,
    "email": os.environ["E"], "firstName": "Test", "lastName": os.environ["ROLE"],
    "attributes": {"person_id": ["test-" + os.environ["U"]]},
    "credentials": [{"type": "password", "value": os.environ["P"], "temporary": False}]}))')"
    code="$(_kc_send POST "realms/$R/users" "$body")"
    id="$(_kc_user_id "$R" "$user")"
    [[ -n "$id" ]] && CREATED+=("$id")
    if [[ "$code" != 201 || -z "$id" ]]; then
        echo -e "${RED}Could not create $user (HTTP $code).${NC}" >&2
        exit 1
    fi
    code=204
    if [[ "$role" != none ]]; then   # none: an enabled account without a platform role
        rolerep="$(_kc_get "realms/$R/roles/$role")"
        code="$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$rolerep]")"
    fi
    if [[ "$code" != 204 ]]; then
        echo -e "${RED}Could not give $user the role $role (HTTP $code) — is it a realm role?${NC}" >&2
        exit 1
    fi
    USERS_JSON+="$(U="$user" P="$pass" ROLE="$role" python3 -c '
import json, os; print(json.dumps({"role": os.environ["ROLE"], "username": os.environ["U"], "password": os.environ["P"]}))'),"
done
USERS_JSON="${USERS_JSON%,}]"
echo "Created ${#CREATED[@]} test account(s): test-<role>-$SUFFIX"
echo ""

CACERT=null; [[ -f .ca/ca.crt ]] && CACERT="\"$REPO_ROOT/.ca/ca.crt\""
PROBES="$(mktemp)"; LOGS="$(mktemp)"
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 tests/iam_signin_flow.py <<<"{\"users\": $USERS_JSON, \"cacert\": $CACERT, \"probes_out\": \"$PROBES\"}"
rc=$?
echo ""
sleep 2   # the services flush each line, but give the log pipeline a moment
for dc in scheduler:api monitor:api dbmgmt:api config-ui:recipe-fileserver access:api; do
    $KUBECTL logs -n "$NAMESPACE" "deployment/${dc%%:*}" -c "${dc#*:}" --since-time="$T0" 2>/dev/null
done > "$LOGS"
python3 tests/iam_signin_flow.py --compare "$PROBES" "$LOGS" || rc=1
rm -f "$PROBES" "$LOGS"
echo ""
if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Every role gets in exactly where the policy says, and every service's check agrees.${NC}"
else
    echo -e "${RED}${BOLD}Sign-in does not match the policy.${NC}"
fi
exit $rc
