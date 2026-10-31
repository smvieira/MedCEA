#!/usr/bin/env bash
# tests/iam-mqtt.sh — the MQTT Explorer's personal credentials, live (IAM plan 3.5).
#
# Needs IAM_MQTT_PERSON=true. Creates three throwaway accounts in realm $KEYCLOAK_REALM —
# test-engineer-, test-operator- and test-admin-<random>, each with a random password,
# verified e-mail and person_id — and deletes them on exit, also on Ctrl-C or failure.
# M6 leaves an applied account decision (append-only, as tests/iam-access.sh's do).
#   M1  the operator is refused: the Explorer's gate, or 403 on POST /_mqtt-credential
#   M2  the engineer gets a credential: explorer-<user>-<6 hex>, the compiled rows
#   M3  within 20 s it is in passwd-ws and not in passwd (the broker's 1883 file)
#   M4  it connects on the WebSocket listener (9001) and is refused on 1883 (CONNACK 4/5)
#   M5  the shared mqtt-explorer account is refused on both listeners
#   M8  acl-ws holds a write row only for a unit flagged for commissioning without a run
#       in R (compared with the database, read-only)
#   M10 415 without JSON, 403 from another Origin
#   M6  the admin deactivates the engineer in the User Manager; within 20 s the credential
#       leaves passwd-ws and is refused on 9001
#   M7  the engineer's old session gets no new credential (re-issue guard)
# MQTT clients run in a throwaway pod (python:3.12-alpine, raw MQTT 3.1.1 over TCP and
# WebSocket); the credential reaches it on stdin, never in argv, and is kept in a mode-600
# temporary file deleted on exit. Usernames only are printed. Takes the deploy lock.
# Run from the repository root:  tests/iam-mqtt.sh      Exit 1 on any failure, 2 on setup.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -f config.env ]] || { echo "config.env not found — run ./deploy-infra.sh first." >&2; exit 2; }
set -a   # the flow reads MQTTX_DOMAIN, ACCESS_DOMAIN and PROJECT_NAME from the environment
# shellcheck disable=SC1091
source config.env
set +a
[[ "${IAM_MQTT_PERSON:-false}" == "true" ]] || { echo "IAM_MQTT_PERSON is not true: nothing to test (./guide.sh)." >&2; exit 2; }
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh
NAMESPACE="${NAMESPACE:-medcea}"

KC_PORT=18093
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"

CREATED=()
PF_PID=""
WORK="$(mktemp -d)"; chmod 700 "$WORK"
cleanup() {
    local id code n=0
    for id in "${CREATED[@]}"; do
        code="$(_kc_send DELETE "realms/$R/users/$id")"
        [[ "$code" == 204 || "$code" == 404 ]] && n=$((n + 1)) \
            || echo -e "${RED}  could not delete test account $id (HTTP $code) — remove it in the User Manager${NC}" >&2
    done
    [[ ${#CREATED[@]} -gt 0 ]] && echo "Deleted $n of ${#CREATED[@]} test account(s)."
    rm -rf "$WORK"
    kc_admin_done
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM

FAILS=0
pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAILS=$((FAILS + 1)); }

$KUBECTL port-forward svc/keycloak "$KC_PORT:80" -n "$NAMESPACE" &>/dev/null 9>&- &
PF_PID=$!
for _ in $(seq 1 12); do
    kc_admin_select && break
    sleep 2
done
[[ -n "$KC_ADMIN_MODE" ]] || { echo "Cannot reach Keycloak's admin API (port-forward on $KC_PORT)." >&2; exit 2; }

echo -e "${BOLD}MQTT Explorer personal credentials${NC} (https://$MQTTX_DOMAIN, realm $R)"
SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
ACCOUNTS="{"
for role in engineer operator admin; do
    user="test-$role-$SUFFIX"
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
    [[ "$code" == 201 && -n "$id" ]] || { echo -e "${RED}Could not create $user (HTTP $code).${NC}" >&2; exit 1; }
    code="$(_kc_send POST "realms/$R/users/$id/role-mappings/realm" "[$(_kc_get "realms/$R/roles/$role")]")"
    [[ "$code" == 204 ]] || { echo -e "${RED}Could not give $user the role $role (HTTP $code).${NC}" >&2; exit 1; }
    ACCOUNTS+="$(K="$role" U="$user" P="$pass" I="$id" python3 -c '
import json, os; print(json.dumps(os.environ["K"]) + ": " + json.dumps({"username": os.environ["U"], "password": os.environ["P"], "id": os.environ["I"]}))'),"
done
CACERT=null; [[ -f .ca/ca.crt ]] && CACERT="\"$REPO_ROOT/.ca/ca.crt\""
ACCOUNTS+="\"cacert\": $CACERT, \"out\": \"$WORK/cred.json\"}"
echo "Created test-engineer-, test-operator- and test-admin-$SUFFIX"
echo ""

python3 tests/iam_mqtt_flow.py issue <<<"$ACCOUNTS" || FAILS=$((FAILS + 1))
[[ -s "$WORK/cred.json" ]] || { echo -e "${RED}No credential issued; the remaining cases need one.${NC}"; exit 1; }
CRED_USER="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["username"])' "$WORK/cred.json")"

sync_users() {   # sync_users FILE → the usernames in the broker's FILE (never a hash)
    $KUBECTL exec -n "$NAMESPACE" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 "/mosquitto/auth/$1" 2>/dev/null
}
in_file() { sync_users "$1" | grep -qx -- "$2"; }

ok=false
for _ in $(seq 1 10); do in_file passwd-ws "$CRED_USER" && { ok=true; break; }; sleep 2; done
$ok && pass "M3a $CRED_USER is in passwd-ws within 20 s" || fail "M3a $CRED_USER is not in passwd-ws after 20 s"
in_file passwd "$CRED_USER" && fail "M3b $CRED_USER is in passwd (1883)" || pass "M3b $CRED_USER is not in passwd (1883)"

# probe CASES → one line per case "name rc" from a throwaway pod; the credentials are on stdin
probe() {
    local cases="$1" pod="iam-mqtt-probe-$SUFFIX-$RANDOM"
    { cat <<'PY'
import base64, json, os, socket, struct, sys
def pkt(user, pw):
    def s(b): return struct.pack('!H', len(b)) + b
    vh = s(b'MQTT') + bytes([4, 0xC2]) + struct.pack('!H', 30)
    body = vh + s(b'iam-mqtt-probe') + s(user.encode()) + s(pw.encode())
    n, enc = len(body), b''
    while True:
        d, n = n % 128, n // 128
        enc += bytes([d | (0x80 if n else 0)])
        if not n: break
    return b'\x10' + enc + body
def tcp(host, user, pw):
    c = socket.create_connection((host, 1883), 5); c.sendall(pkt(user, pw)); r = c.recv(4); c.close()
    return r[3] if len(r) == 4 and r[0] == 0x20 else -1
def ws(host, user, pw):
    c = socket.create_connection((host, 9001), 5)
    key = base64.b64encode(os.urandom(16)).decode()
    c.sendall(('GET /mqtt HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
               'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n' % (host, key)).encode())
    head = b''
    while b'\r\n\r\n' not in head: head += c.recv(1)
    if b' 101 ' not in head.split(b'\r\n')[0]: return -2
    p, mask = pkt(user, pw), os.urandom(4)
    frame = bytes([0x82]) + (bytes([0x80 | len(p)]) if len(p) < 126 else bytes([0x80 | 126]) + struct.pack('!H', len(p)))
    c.sendall(frame + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(p)))
    h = c.recv(2); data = c.recv(h[1] & 0x7f); c.close()
    return data[3] if len(data) == 4 and data[0] == 0x20 else -1
cfg = json.loads(sys.stdin.readline())
for name, kind, host, user, pw in cfg['cases']:
    try: rc = (tcp if kind == 'tcp' else ws)(host, user, pw)
    except Exception: rc = -3
    print(name, rc, flush=True)
PY
    } > "$WORK/probe.py"
    # script and credentials both on stdin: the script as one Python literal line, then the cases
    $KUBECTL run "$pod" -n "$NAMESPACE" --rm -i --restart=Never --quiet --image=python:3.12-alpine \
        --command -- python3 -c 'import sys; src = sys.stdin.readline(); exec(compile(eval(src), "probe", "exec"))' \
        < <(python3 -c 'import sys; print(repr(open(sys.argv[1]).read()))' "$WORK/probe.py"; printf '%s\n' "$cases") 2>/dev/null
}

CASES="$(M="mosquitto.$NAMESPACE.svc.cluster.local" W="mosquitto-ws.$NAMESPACE.svc.cluster.local" \
    EX="${MQTT_EXPLORER_PASS:-x}" python3 -c '
import json, os, sys
c = json.load(open(sys.argv[1]))
u, p, ex = c["username"], c["password"], os.environ["EX"]
print(json.dumps({"cases": [["M4a", "ws", os.environ["W"], u, p], ["M4b", "tcp", os.environ["M"], u, p],
                            ["M5a", "tcp", os.environ["M"], "mqtt-explorer", ex], ["M5b", "ws", os.environ["W"], "mqtt-explorer", ex]]}))' \
    "$WORK/cred.json")"
OUT="$(probe "$CASES")"
rc_of() { awk -v n="$1" '$1 == n {print $2}' <<<"$OUT"; }
[[ "$(rc_of M4a)" == 0 ]] && pass "M4a $CRED_USER connects on the WebSocket listener" || fail "M4a WebSocket CONNACK $(rc_of M4a), not 0"
[[ "$(rc_of M4b)" =~ ^[45]$ ]] && pass "M4b $CRED_USER is refused on 1883 (CONNACK $(rc_of M4b))" || fail "M4b 1883 CONNACK $(rc_of M4b), not 4/5"
[[ "$(rc_of M5a)" =~ ^[45]$ ]] && pass "M5a the shared mqtt-explorer account is refused on 1883" || fail "M5a 1883 CONNACK $(rc_of M5a) for mqtt-explorer"
[[ "$(rc_of M5b)" =~ ^[45]$ ]] && pass "M5b the shared mqtt-explorer account is refused on 9001" || fail "M5b 9001 CONNACK $(rc_of M5b) for mqtt-explorer"

# M8 — write rows only for flagged units without a running run (database read-only)
source apps/database/lib-db-apply.sh
ELIGIBLE="$(_DBA_NS="$NAMESPACE" _DBA_POD=rdbms-postgresql-0 _dba_psql "$POSTGRES_DB" -tAq -c "
    SELECT u.unit_code FROM medcea.cea_unit u WHERE u.commissioning
       AND NOT EXISTS (SELECT 1 FROM medcea.recipe_run r WHERE r.unit_id = u.unit_id AND r.recipe_run_status = 'R')
     ORDER BY 1" 2>/dev/null)"
WROTE="$($KUBECTL exec -n "$NAMESPACE" deployment/mosquitto -c mqtt-auth-sync -- \
    awk -v u="user $CRED_USER" '$0 == u {on = 1; next} /^user / {on = 0} on && $2 == "write" {split($3, t, "/"); print t[2]}' \
    /mosquitto/auth/acl-ws 2>/dev/null | sort -u)"
[[ "$WROTE" == "$(sort -u <<<"$ELIGIBLE" | sed '/^$/d')" ]] \
    && pass "M8 write rows only for units flagged for commissioning without a running run (${WROTE:-none})" \
    || fail "M8 write rows for '${WROTE//$'\n'/ }', flagged and idle: '${ELIGIBLE//$'\n'/ }'"

python3 tests/iam_mqtt_flow.py checks <<<"$ACCOUNTS" || FAILS=$((FAILS + 1))
python3 tests/iam_mqtt_flow.py deactivate <<<"$ACCOUNTS" || FAILS=$((FAILS + 1))
ok=false
for _ in $(seq 1 10); do in_file passwd-ws "$CRED_USER" || { ok=true; break; }; sleep 2; done
$ok && pass "M6b $CRED_USER left passwd-ws within 20 s of the deactivation" || fail "M6b $CRED_USER is still in passwd-ws after 20 s"
OUT="$(probe "$(python3 -c 'import json, sys; print(json.dumps({"cases": [["M6c", "ws", sys.argv[2]] + [json.load(open(sys.argv[1]))[k] for k in ("username", "password")]]}))' \
    "$WORK/cred.json" "mosquitto-ws.$NAMESPACE.svc.cluster.local")")"
[[ "$(rc_of M6c)" =~ ^[45]$ ]] && pass "M6c the deactivated person's credential is refused on 9001" || fail "M6c 9001 CONNACK $(rc_of M6c) after deactivation"

echo ""
if (( FAILS )); then echo -e "${RED}$FAILS failure(s)${NC}"; exit 1; fi
echo -e "${GREEN}All passed${NC}"
