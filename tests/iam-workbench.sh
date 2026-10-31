#!/usr/bin/env bash
# tests/iam-workbench.sh — the AI workbench's hub administrator cannot enter another person's
# server, and losing access reaches the hub (IAM plan 3.2).
#
# Creates two throwaway accounts in realm $KEYCLOAK_REALM — test-admin-<random> (admin) and
# test-bio-<random> (bio_scientist), each with a random password, verified e-mail and
# person_id — and deletes them on exit, also on Ctrl-C or failure. tests/iam_workbench_flow.py
# signs them in the way a browser does and checks, through the hub's own API:
#   W1 bio starts its own server; W2 admin is a hub admin (admin page, user list), bio not;
#   W3 admin's requests to bio's server never answer 200 there; W4 a token the admin mints
#   for bio does not open bio's server; W9 bio's user model shows the admin no stored token;
#   W5 admin stops bio's server; W6 admin removes hub user bio, and its home volume is kept.
# Then W7: bio's realm role is removed and a fresh sign-in gets the hub's 403 naming the
# roles; W8: bio's account is disabled and a fresh sign-in does not get in. (A session
# already open lasts until the hub cookie's hour runs out: cookie_max_age_days.)
#
# Cleanup also deletes bio's home volume (the one PVC W1 created, found by the hub's
# username annotation). The throwaway admin stays a hub user without a home: a hub admin
# cannot remove itself. Takes the deploy lock (it creates accounts and deletes a PVC).
# Run from the repository root:  tests/iam-workbench.sh      Exit 1 on any failure.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
set -a   # the flow reads WORKBENCH_DOMAIN from the environment
# shellcheck disable=SC1091
source config.env
set +a
if [[ "${WORKBENCH_ENABLED:-true}" != "true" ]]; then
    echo "WORKBENCH_ENABLED is not true: no workbench to test." >&2
    exit 2
fi
if [[ "${IAM_GATES:-true}" == "false" ]]; then
    echo "IAM_GATES=false: the workbench admits any account; W2 and W7 assume the policy's gate." >&2
    exit 2
fi
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh

KC_PORT=18092
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"

CREATED=()        # Keycloak user ids, deleted on exit
BIO_NAME=""
PF_PID=""
cleanup() {
    local id code n=0 pvc
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the User Manager${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    if [[ -n "$BIO_NAME" ]]; then
        for pvc in $(bio_pvcs); do
            $KUBECTL delete pvc "$pvc" -n "$NAMESPACE" --wait=false >/dev/null && echo "Deleted the test home volume $pvc."
        done
    fi
    kc_admin_done
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# PVCs KubeSpawner made for BIO_NAME (annotation hub.jupyter.org/username)
bio_pvcs() {
    $KUBECTL get pvc -n "$NAMESPACE" -o json 2>/dev/null | U="$BIO_NAME" python3 -c '
import json, os, sys
for i in json.load(sys.stdin).get("items", []):
    m = i["metadata"]
    if os.environ["U"] in ((m.get("annotations") or {}).get("hub.jupyter.org/username"),
                           (m.get("labels") or {}).get("hub.jupyter.org/username")):
        print(m["name"])'
}

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

echo -e "${BOLD}AI workbench administration${NC} (https://$WORKBENCH_DOMAIN, realm $R)"
SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
declare -A IDS=()
ACCOUNTS="{"
for pair in admin:admin bio:bio_scientist; do
    key="${pair%%:*}" role="${pair#*:}"
    user="test-$key-$SUFFIX"
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
    IDS[$key]="$id"
    code="$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$(_kc_get "realms/$R/roles/$role")]")"
    if [[ "$code" != 204 ]]; then
        echo -e "${RED}Could not give $user the role $role (HTTP $code).${NC}" >&2
        exit 1
    fi
    ACCOUNTS+="$(K="$key" U="$user" P="$pass" python3 -c '
import json, os; print(json.dumps(os.environ["K"]) + ": " + json.dumps({"username": os.environ["U"], "password": os.environ["P"]}))'),"
done
BIO_NAME="test-bio-$SUFFIX"
CACERT=null; [[ -f .ca/ca.crt ]] && CACERT="\"$REPO_ROOT/.ca/ca.crt\""
ACCOUNTS+="\"cacert\": $CACERT}"
echo "Created test-admin-$SUFFIX and $BIO_NAME"
echo ""

rc=0
python3 tests/iam_workbench_flow.py run <<<"$ACCOUNTS" || rc=1

pvcs="$(bio_pvcs)"
if [[ -n "$pvcs" ]]; then
    echo -e "  PASS   W6 the home volume of the removed hub user is kept: $pvcs"
else
    echo -e "  FAIL   W6 no home volume left for $BIO_NAME (delete_pvc false?)"; rc=1
fi

code="$(_kc_send DELETE "realms/$R/users/${IDS[bio]}/role-mappings/realm" "[$(_kc_get "realms/$R/roles/bio_scientist")]")"
[[ "$code" == 204 ]] || { echo -e "${RED}Could not remove bio's role (HTTP $code).${NC}" >&2; exit 1; }
python3 tests/iam_workbench_flow.py refused W7 <<<"$ACCOUNTS" || rc=1

code="$(_kc_send POST "realms/$R/users/${IDS[bio]}/role-mappings/realm" "[$(_kc_get "realms/$R/roles/bio_scientist")]")"
rep="$(_kc_get "realms/$R/users/${IDS[bio]}" | python3 -c 'import json, sys; u = json.load(sys.stdin); u["enabled"] = False; print(json.dumps(u))')"
code2="$(_kc_send PUT "realms/$R/users/${IDS[bio]}" "$rep")"
[[ "$code" == 204 && "$code2" == 204 ]] || { echo -e "${RED}Could not disable bio (HTTP $code/$code2).${NC}" >&2; exit 1; }
python3 tests/iam_workbench_flow.py refused W8 <<<"$ACCOUNTS" || rc=1

echo ""
if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}The hub administrator administers, never enters; lost access reaches the hub.${NC}"
else
    echo -e "${RED}${BOLD}The AI workbench's administration does not match the policy.${NC}"
fi
exit $rc
