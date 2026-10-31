#!/usr/bin/env bash
# tests/iam-postgrest.sh — IAM Phase 2b against the throwaway instance: config-api
# verifying tokens, deployed by infra/lib-postgrest.sh exactly as apps/frontend/deploy.sh
# does it, in namespace medcea-iamtest only.
#
#   tests/iam-postgrest.sh --namespace medcea-iamtest --mode false|true --dir DIR
#   tests/iam-postgrest.sh --namespace medcea-iamtest --flip --dir DIR
#   tests/iam-postgrest.sh --namespace medcea-iamtest --keys --dir DIR   (Secret medcea-jwks only)
#
# Called by tests/iam-db-fixture.sh (`postgrest MODE`, `pgrst-flip`) after `apply MODE`,
# with the fixture's DIR ($IAMTEST_DIR: the role passwords, mode 600). MODE is the
# database's IAM_DB_ROLES. The realm is a throwaway RSA key made here
# (tests/iam_postgrest_flow.py keygen, DIR/pgrst-*.pem, mode 600, shredded on exit),
# published as Secret medcea-jwks the way deploy-infra.sh does (infra/jwks-sig.py).
# authenticator's passwords are the fixture's: AUTHENTICATOR_DB_PASS = its
# `authenticator` line, the legacy POSTGRES_PASS = its `authenticator_legacy` line.
#
# --mode M (cases):
#   P1–P11, P15  tests/iam_postgrest_flow.py against config-api's ClusterIP: anon and
#                refusals, signatures, audience, expiry, algorithm confusion, the role
#                claim, attribution of writes, azp/role/typ refusals, the readiness probe
#   P17          (true) a notebook token (azp workbench-notebook) only reads: PATCH and
#                POST /rpc are 403 'may only read' for a role that may write, GET is served
#   P16          the same through nginx:1.27-alpine with config-ui-nginx-jwt.yaml:
#                forged Authorization, identity headers and cookie never reach SQL
#                (a probe RPC medcea.iamtest_whoami(), created here, dropped on exit)
#   R16          PUT /scheduler-api/algorithms/<id> through that nginx reaches the
#                scheduler (an echo stand-in, Service scheduler) with the proxy's
#                X-Forwarded-Access-Token, which the scheduler's token check reads
#   P12 (gate)   neither pgrst_deploy's output nor any pod log holds a password or the
#                signature of any token this run made; a failure stops the run
#   P13          authenticator logs in with AUTHENTICATOR_DB_PASS, not the legacy one
#   P14          a new realm key: pgrst_roll_if_changed rolls config-api, the new key is
#                served and the removed one refused; then the first key again
# --flip: absent -> legacy -> jwt -> jwt with a new AUTHENTICATOR_DB_PASS (a new pod,
#   which still logs in after its sessions are cut) -> back -> legacy (a patched
#   annotation included) -> jwt -> legacy -> jwt with a broken Secret key (restored:
#   legacy, its password, served), with a steady load: no gap between two served
#   requests longer than FLIP_MAX_OUTAGE (20 s) during each switch, and no failed
#   request once its rollout has finished. Every switch changes authenticator's
#   password, and PostgREST exits on a refused password, so the old pod dies at its
#   next new connection after the ALTER and nothing serves until the new pod passes
#   its readiness probe (5 s delay, 5 s period): an outage of up to ~15 s is expected.
#   Between the switches, pgrst_db_auth_pass (the password apps/database/deploy.sh
#   gives authenticator) is checked against each live mode, a JWT config-api whose
#   Secret is gone, a stalled rollout (refused) and a single unready pod after
#   authenticator lost its password (its template's mode: the purge recovery).
# Both delete config-api, the nginx pod and the probe RPC on exit, so the fixture's
# later steps (cycle, purge) meet the database as db_apply left it. Exit 1 on any FAIL.

set -uo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
NS=""; MODE=""; DIR=""; FLIP=false; KEYS=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --dir) DIR="$2"; shift 2 ;;
        --flip) FLIP=true; shift ;;
        --keys) KEYS=true; shift ;;
        *) echo "unknown argument $1 (--help)" >&2; exit 2 ;;
    esac
done
# Hard-coded: this script deletes config-api and rewrites authenticator's password.
[[ "$NS" == "medcea-iamtest" ]] || { echo "refused: only namespace medcea-iamtest" >&2; exit 2; }
[[ "$FLIP" == true || "$KEYS" == true || "$MODE" == false || "$MODE" == true ]] || { echo "--mode false|true, --flip or --keys" >&2; exit 2; }
[[ -n "$DIR" && -f "$DIR/passwords" ]] || { echo "--dir must hold the fixture's passwords (tests/iam-db-fixture.sh up)" >&2; exit 2; }

source infra/lib-mk8s.sh
source infra/lib-render.sh
source infra/lib-lock.sh; medcea_lock   # inherited from tests/iam-db-fixture.sh
source apps/database/lib-db-apply.sh
source infra/lib-postgrest.sh

[[ "$($KUBECTL get namespace "$NS" -o jsonpath='{.metadata.labels.medcea/test}' 2>/dev/null)" == iam-db ]] \
    || { echo "refused: namespace $NS has no label medcea/test=iam-db" >&2; exit 2; }

POD=pg; DB=medcea_db
EXTRA_SECRETS=()
FLIP_MAX_OUTAGE="${FLIP_MAX_OUTAGE:-20}"   # seconds without a served request a switch may cost
FLOW=(python3 "$REPO_ROOT/tests/iam_postgrest_flow.py")
RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-9s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-9s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

# the fixture's passwords, never printed (kubectl and psql get them on stdin)
_pw() { awk -v r="$1" '$1 == r {print $2}' "$DIR/passwords"; }
AUTHENTICATOR_DB_PASS="$(_pw authenticator)"
POSTGRES_PASS="$(_pw authenticator_legacy)"   # the legacy config-api's: a fixture-only value
[[ -n "$AUTHENTICATOR_DB_PASS" && -n "$POSTGRES_PASS" ]] \
    || { echo "no authenticator / authenticator_legacy password in $DIR/passwords (re-run tests/iam-db-fixture.sh up)" >&2; exit 2; }

fx() {   # psql in the fixture pod as postgres; SQL on stdin
    $KUBECTL exec -i -n "$NS" "$POD" -- env PGOPTIONS="-c client_min_messages=warning" \
        sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -U postgres -d "$0" "$@"' "$DB" "$@"
}
login_as_authenticator() {   # PASSWORD (stdin to the pod) -> 0 when it logs in over TCP
    local out
    out="$(printf '%s\n' "$1" | $KUBECTL exec -i -n "$NS" "$POD" -- sh -c \
        'read -r PGPASSWORD; export PGPASSWORD; exec psql -X -h 127.0.0.1 -U authenticator -d medcea_db -tAc "SELECT session_user"' 2>&1)"
    [[ "$out" == authenticator ]]
}

cleanup() {
    $KUBECTL delete pod pgrst-nginx pgrst-scheduler-stub -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
    $KUBECTL delete service scheduler -n "$NS" --ignore-not-found >/dev/null 2>&1
    $KUBECTL delete deployment config-api -n "$NS" --ignore-not-found >/dev/null 2>&1
    $KUBECTL delete service config-api -n "$NS" --ignore-not-found >/dev/null 2>&1
    fx -q -c "DROP FUNCTION IF EXISTS medcea.iamtest_whoami();" >/dev/null 2>&1
    [[ -n "${LOAD_PID:-}" ]] && kill "$LOAD_PID" 2>/dev/null
    local f
    for f in "$DIR"/pgrst-*.pem; do [[ -f "$f" ]] && shred -u "$f" 2>/dev/null; done
}
trap cleanup EXIT

# Secret medcea-jwks from key NAME, as deploy-infra.sh writes it
publish_key() {
    local name="$1" tmp
    tmp="$(mktemp -d "$DIR/jwks-XXXX")"; chmod 700 "$tmp"
    python3 infra/jwks-sig.py < "$DIR/$name.jwks.json" > "$tmp/jwks-sig.json" || { rm -rf "$tmp"; return 1; }
    $KUBECTL create secret generic medcea-jwks -n "$NS" --from-file=jwks.json="$DIR/$name.jwks.json" \
        --from-file=jwks-sig.json="$tmp/jwks-sig.json" --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
    local rc=$?; rm -rf "$tmp"; return $rc
}

api_base() { echo "http://$($KUBECTL get svc config-api -n "$NS" -o jsonpath='{.spec.clusterIP}'):3000"; }
wait_served() {   # BASE — GET / answers 200 within 60 s
    local i
    for i in $(seq 1 30); do
        [[ "$("${FLOW[@]}" get "$1" / | cut -d' ' -f1)" == 200 ]] && return 0
        sleep 2
    done
    return 1
}

# P12: a run's secrets in a text (deploy output or logs)
leaks() {   # TEXT -> prints what leaked (role names / "a token signature"), nothing when clean
    local text="$1" r p
    while read -r r p; do
        [[ -n "$p" ]] && grep -qF -- "$p" <<<"$text" && echo "password of $r"
    done < "$DIR/passwords"
    for p in ${EXTRA_SECRETS[@]+"${EXTRA_SECRETS[@]}"}; do
        grep -qF -- "$p" <<<"$text" && echo "a password made by this run"
    done
    [[ -s "$DIR/token-sigs" ]] && grep -qF -f "$DIR/token-sigs" <<<"$text" && echo "a token signature"
    return 0
}
pod_logs() {
    $KUBECTL logs -n "$NS" -l app=config-api --all-containers --prefix --tail=-1 2>&1
    $KUBECTL logs -n "$NS" pgrst-nginx 2>/dev/null
    $KUBECTL logs -n "$NS" "$POD" 2>&1
}

setup_keys() {
    [[ -f "$DIR/pgrst-a.pem" ]] || "${FLOW[@]}" keygen "$DIR" pgrst-a || return 1
    publish_key pgrst-a
}

seed() {
    fx -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
-- a unit of its own (IAMP01), on its own site
INSERT INTO medcea.cea_location (name, description, is_active)
SELECT 'IAMP site', 'tests/iam-postgrest.sh', 'Y' WHERE NOT EXISTS (SELECT 1 FROM medcea.cea_location WHERE name = 'IAMP site');
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
SELECT 'Other', 'iam-postgrest', l.location_id, 'Y', 'IAMP01' FROM medcea.cea_location l
 WHERE l.name = 'IAMP site' AND NOT EXISTS (SELECT 1 FROM medcea.cea_unit WHERE unit_code = 'IAMP01');
-- the probe RPC: who PostgREST runs as, and the headers/cookies SQL would see.
-- Test-only; dropped on exit (it would fail the next bundle's catalog assertions).
CREATE OR REPLACE FUNCTION medcea.iamtest_whoami() RETURNS json LANGUAGE sql AS $$
    SELECT json_build_object('current_user', current_user, 'session_user', session_user,
        'headers', nullif(current_setting('request.headers', true), '')::json,
        'cookies', nullif(current_setting('request.cookies', true), '')::json)
$$;
GRANT EXECUTE ON FUNCTION medcea.iamtest_whoami() TO PUBLIC;
NOTIFY pgrst, 'reload schema';
SQL
}

# ── cases ─────────────────────────────────────────────────────────────────────
run_cases() {
    local out base nginx_ip i
    step "config-api with token verification (database IAM_DB_ROLES=$MODE)"
    setup_keys || { fail setup "keygen / Secret medcea-jwks"; return; }
    seed || { fail setup "seed IAMP01 and the probe RPC"; return; }
    out="$(pgrst_deploy true "$NS" "$POD" "$DB" 2>&1)"
    local rc=$? all_out="$out"
    sed 's/^/        /' <<<"$out"
    [[ $rc -eq 0 ]] && pass deploy "pgrst_deploy true" || { fail deploy "pgrst_deploy true (exit $rc)"; return; }
    [[ "$(pgrst_live_mode "$NS")" == jwt ]] && pass deploy "live mode jwt" || fail deploy "live mode is $(pgrst_live_mode "$NS")"
    base="$(api_base)"
    wait_served "$base" || { fail deploy "config-api does not answer GET /"; return; }
    fx -q -c "NOTIFY pgrst, 'reload schema';" >/dev/null; sleep 2

    # P16's nginx: the JWT conf, rendered into this namespace
    NAMESPACE="$NS" render apps/frontend/k8s/config-ui-nginx-jwt.yaml NAMESPACE | $KUBECTL apply -n "$NS" -f - >/dev/null
    $KUBECTL delete pod pgrst-nginx pgrst-scheduler-stub -n "$NS" --ignore-not-found >/dev/null
    FIXTURE_NS="$NS" render tests/k8s/iam-postgrest-nginx.yaml FIXTURE_NS | $KUBECTL apply -f - >/dev/null
    $KUBECTL wait --for=condition=Ready pod/pgrst-scheduler-stub -n "$NS" --timeout=180s >/dev/null \
        || fail R16 "the scheduler stand-in did not become ready"
    if $KUBECTL wait --for=condition=Ready pod/pgrst-nginx -n "$NS" --timeout=120s >/dev/null; then
        nginx_ip="$($KUBECTL get pod pgrst-nginx -n "$NS" -o jsonpath='{.status.podIP}')"
    else
        fail P16 "the nginx pod did not become ready"; nginx_ip=""
    fi

    "${FLOW[@]}" cases "$MODE" "$base" "$DIR" pgrst-a "${nginx_ip:+http://$nginx_ip}" || FAILS=$((FAILS + 1))

    # P13: authenticator's password is the JWT one now
    login_as_authenticator "$AUTHENTICATOR_DB_PASS" && pass P13 "authenticator logs in with AUTHENTICATOR_DB_PASS" \
        || fail P13 "authenticator cannot log in with AUTHENTICATOR_DB_PASS"
    login_as_authenticator "$POSTGRES_PASS" && fail P13 "authenticator still logs in with the legacy password" \
        || pass P13 "the legacy password no longer logs authenticator in"

    # P14: rotation — the realm drops key a for key b
    [[ -f "$DIR/pgrst-b.pem" ]] || "${FLOW[@]}" keygen "$DIR" pgrst-b
    publish_key pgrst-b
    out="$(pgrst_roll_if_changed "$NS" 2>&1)"; all_out+=$'\n'"$out"
    grep -q 'config-api rolled: realm keys changed' <<<"$out" && pass P14 "pgrst_roll_if_changed: $out" \
        || fail P14 "no roll after the key change: ${out:-nothing}"
    $KUBECTL rollout status deployment/config-api -n "$NS" --timeout=3m >/dev/null || fail P14 "rollout after the roll"
    [[ "$(_pgrst_annotation "$NS")" == "$(jwks_checksum "$NS")" ]] && pass P14 "annotation = checksum of jwks-sig.json" \
        || fail P14 "annotation differs from the checksum"
    out="$(pgrst_roll_if_changed "$NS" 2>&1)"
    [[ -z "$out" ]] && pass P14 "unchanged keys: no second roll" || fail P14 "rolled again: $out"
    wait_served "$base" || fail P14 "config-api does not answer after the roll"
    "${FLOW[@]}" rotated "$base" "$DIR" pgrst-b pgrst-a || FAILS=$((FAILS + 1))
    publish_key pgrst-a && pgrst_roll_if_changed "$NS" >/dev/null \
        && $KUBECTL rollout status deployment/config-api -n "$NS" --timeout=3m >/dev/null || fail P14 "back to key a"

    # P12 (hard gate): no secret in the deploy output or any pod log
    local leaked
    leaked="$( { leaks "$all_out"; leaks "$(pod_logs)"; } | sort -u | paste -sd, -)"
    if [[ -n "$leaked" ]]; then
        fail P12 "secrets in the output or logs: $leaked — stopping"
        exit 1
    fi
    pass P12 "no password and no token signature in pgrst_deploy's output or any pod log"
}

# ── flip ──────────────────────────────────────────────────────────────────────
env_names() {
    $KUBECTL get deployment config-api -n "$NS" -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'
}
load_mark() { wc -l < "$DIR/flip-load" 2>/dev/null || echo 0; }
# flip-load: one "EPOCH CODE" line per request
load_bad_since() {   # LINE — failed requests after that line of the load log
    tail -n +"$(( $1 + 1 ))" "$DIR/flip-load" | awk '$2 != "200"' | wc -l
}
# FROM TO — the longest time without a served request between those lines (the
# last 200 before a failure to the first 200 after it, or to the window's end)
load_outage() {
    sed -n "$1,$2p" "$DIR/flip-load" | awk '
        $2 == "200" { if (bad && last != "") { g = $1 - last; if (g > max) max = g }; last = $1; bad = 0; next }
        { bad = 1; end = $1 }
        END { if (bad && last != "") { g = end - last; if (g > max) max = g }; printf "%.1f\n", max + 0 }'
}
switch() {   # MODE LABEL — pgrst_deploy; 2 s after it, 3 s of load must be all 200
    local mode="$1" label="$2" out rc before after
    before="$(load_mark)"
    out="$(pgrst_deploy "$mode" "$NS" "$POD" "$DB" 2>&1)"; rc=$?
    sed 's/^/        /' <<<"$out"
    ALL_OUT+="$out"$'\n'
    [[ $rc -eq 0 ]] && pass flip "$label" || { fail flip "$label (exit $rc)"; return 1; }
    # kube-proxy drops the old pod's endpoint a moment after the rollout reports done
    sleep 2
    after="$(load_mark)"
    sleep 3
    local during after_bad outage
    during="$(sed -n "$(( before + 1 )),${after}p" "$DIR/flip-load" | awk '$2 != "200"' | wc -l)"
    outage="$(load_outage "$(( before > 0 ? before : 1 ))" "$after")"
    after_bad="$(load_bad_since "$after")"
    SWITCH_FAILS=$(( SWITCH_FAILS + during ))
    [[ "$after_bad" -eq 0 ]] && pass flip "$label: none failed after the rollout" \
        || fail flip "$label: $after_bad failed request(s) after the rollout finished"
    # the outage is bounded by the new pod's start (see the header), not zero
    if awk -v o="$outage" -v m="$FLIP_MAX_OUTAGE" 'BEGIN { exit !(o <= m) }'; then
        pass flip "$label: longest gap ${outage} s, $during failed request(s) during the switch (<= ${FLIP_MAX_OUTAGE} s)"
    else
        fail flip "$label: config-api served nothing for ${outage} s during the switch (> ${FLIP_MAX_OUTAGE} s), $during failed request(s)"
    fi
}

# pgrst_db_auth_pass against the live config-api: LABEL FLAG WANT_LIVE WANT_WRITE —
# the mode it reports, whether it would write the Secret, and that its password
# logs authenticator in (it is what apps/database/deploy.sh would set)
db_pass_case() {
    local label="$1" flag="$2" want_live="$3" want_write="$4" out
    out="$(pgrst_db_auth_pass "$NS" "$flag" 2>&1 >/dev/null)"   # warnings only
    pgrst_db_auth_pass "$NS" "$flag" 2>/dev/null || { fail S2 "$label: refused (${_PGRST_DB_LIVE:-?})"; return; }
    ALL_OUT+="$out"$'\n'
    [[ "$_PGRST_DB_LIVE" == "$want_live" && "$_PGRST_DB_WRITE_SECRET" == "$want_write" ]] \
        && pass S2 "$label: live $want_live, writes the Secret: $want_write" \
        || fail S2 "$label: live $_PGRST_DB_LIVE, writes the Secret: $_PGRST_DB_WRITE_SECRET (want $want_live/$want_write)"
    login_as_authenticator "$_PGRST_DB_AUTH_PASS" && pass S2 "$label: the chosen password is the one authenticator has" \
        || fail S2 "$label: the database deploy would give authenticator a password config-api does not use"
    _PGRST_DB_AUTH_PASS=""
}

run_flip() {
    local base st names out ALL_OUT="" SWITCH_FAILS=0
    step "config-api switches (database IAM_DB_ROLES=false)"
    pgrst_db_enforcing "$NS" "$POD" "$DB" && { fail flip "the database enforces IAM_DB_ROLES: run after apply false"; return; }
    setup_keys || { fail setup "keygen / Secret medcea-jwks"; return; }

    # from nothing: the first deploy creates config-api in legacy mode
    $KUBECTL delete deployment config-api -n "$NS" --ignore-not-found >/dev/null
    out="$(pgrst_deploy false "$NS" "$POD" "$DB" 2>&1)" && pass flip "absent -> legacy" || fail flip "absent -> legacy: $out"
    ALL_OUT+="$out"$'\n'
    base="$(api_base)"
    wait_served "$base" && pass flip "legacy config-api serves GET /" || { fail flip "legacy config-api does not answer"; return; }
    st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1")"
    [[ "$st" == "200 -" ]] && pass flip "legacy, no token: 200" || fail flip "legacy, no token: $st"

    # a steady anonymous load (served by both templates while the database is false)
    : > "$DIR/flip-load"
    ( while :; do printf '%s %s\n' "$(date +%s.%N)" "$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$base/cea_unit?limit=1")" >> "$DIR/flip-load"; sleep 0.2; done ) 9>&- &
    LOAD_PID=$!
    sleep 2

    switch true "legacy -> jwt" || return
    names="$(env_names)"
    grep -qx PGRST_JWT_SECRET <<<"$names" && grep -qx AUTHENTICATOR_PASSWORD <<<"$names" \
        && pass flip "jwt: C1 env present" || fail flip "jwt: C1 env missing"
    st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1" "$DIR" pgrst-a)"
    [[ "$st" == "200 -" ]] && pass flip "jwt, valid token: 200" || fail flip "jwt, valid token: $st"
    db_pass_case "jwt" true jwt false

    # a rotated AUTHENTICATOR_DB_PASS while config-api already runs jwt: the Secret's
    # new version must start a new pod (the env is read at start), which keeps
    # logging in once its sessions are cut (a pool reconnect)
    local gen0 gen1 orig_auth="$AUTHENTICATOR_DB_PASS"
    gen0="$($KUBECTL get deployment config-api -n "$NS" -o jsonpath='{.metadata.generation}')"
    AUTHENTICATOR_DB_PASS="$(openssl rand -hex 16)"; EXTRA_SECRETS+=("$AUTHENTICATOR_DB_PASS")
    switch true "jwt -> jwt, new AUTHENTICATOR_DB_PASS" || return
    gen1="$($KUBECTL get deployment config-api -n "$NS" -o jsonpath='{.metadata.generation}')"
    [[ "$gen1" != "$gen0" ]] && pass flip "new password: a new pod template (generation $gen0 -> $gen1)" \
        || fail flip "new password: config-api was not restarted (generation $gen1)"
    [[ "$($KUBECTL get deployment config-api -n "$NS" -o jsonpath='{.spec.template.metadata.annotations.medcea/auth-secret-version}')" \
       == "$($KUBECTL get secret db-authenticator -n "$NS" -o jsonpath='{.metadata.resourceVersion}')" ]] \
        && pass flip "new password: the pod names the Secret version it read" || fail flip "new password: auth-secret-version stale"
    fx -q -tA -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = 'authenticator'" >/dev/null
    sleep 3
    wait_served "$base" && st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1")" || st="no answer"
    [[ "$st" == "200 -" ]] && pass flip "new password: after its sessions were cut, config-api logs in again" \
        || fail flip "new password: config-api cannot log in after a reconnect: $st"
    AUTHENTICATOR_DB_PASS="$orig_auth"
    switch true "jwt -> jwt, AUTHENTICATOR_DB_PASS back" || return

    # the database deploy's choice while the JWT config-api's Secret is gone (a purge
    # deletes it): config.env's password, and the Secret is written again
    $KUBECTL delete secret db-authenticator -n "$NS" >/dev/null
    db_pass_case "jwt, Secret db-authenticator gone" true jwt true
    SECRET_NAME=db-authenticator DB_ROLE=authenticator DB_PASS="$AUTHENTICATOR_DB_PASS" \
        render apps/database/k8s/db-role-secret.yaml SECRET_NAME DB_ROLE DB_PASS | $KUBECTL apply -n "$NS" -f - >/dev/null

    # an annotation a roll patched in (not in kubectl apply's record) must go too
    $KUBECTL patch deployment config-api -n "$NS" --type=merge \
        -p '{"spec":{"template":{"metadata":{"annotations":{"medcea/jwks-checksum":"patched"}}}}}' >/dev/null
    $KUBECTL rollout status deployment/config-api -n "$NS" --timeout=3m >/dev/null
    switch false "jwt -> legacy" || return
    names="$(env_names)"
    if grep -Eqx 'PGRST_JWT_.*|PGRST_DB_PRE_REQUEST|AUTHENTICATOR_PASSWORD' <<<"$names"; then
        fail flip "legacy still has $(grep -Ex 'PGRST_JWT_.*|PGRST_DB_PRE_REQUEST|AUTHENTICATOR_PASSWORD' <<<"$names" | paste -sd, -)"
    else
        pass flip "legacy: no PGRST_JWT_*, PGRST_DB_PRE_REQUEST or AUTHENTICATOR_PASSWORD"
    fi
    [[ -z "$(_pgrst_annotation "$NS")" ]] && pass flip "legacy: no jwks-checksum annotation (patched one removed)" \
        || fail flip "legacy keeps the jwks-checksum annotation"
    [[ -z "$($KUBECTL get deployment config-api -n "$NS" -o jsonpath='{.spec.template.metadata.annotations.medcea/auth-secret-version}')" ]] \
        && pass flip "legacy: no auth-secret-version annotation" || fail flip "legacy keeps the auth-secret-version annotation"
    st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1")"
    [[ "$st" == "200 -" ]] && pass flip "legacy, no token: 200" || fail flip "legacy, no token: $st"
    st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1" "$DIR" pgrst-a)"
    [[ "$st" == "500 PGRST300" ]] && pass flip "legacy, Bearer: 500 PGRST300" || fail flip "legacy, Bearer: $st"
    login_as_authenticator "$POSTGRES_PASS" && pass flip "legacy: authenticator on the legacy password" \
        || fail flip "legacy: authenticator cannot log in with the legacy password"
    db_pass_case "legacy (IAM_POSTGREST_JWT=true not applied yet)" true legacy true

    switch true "legacy -> jwt (again)" || return
    switch false "jwt -> legacy (again)" || return

    # a Secret key that disappears under the new pod: CreateContainerConfigError before
    # the password changes; pgrst_deploy must put legacy back
    local rc
    # The key is removed BEFORE the JWT Deployment reaches the API server (the apply
    # is intercepted on its stdin), so no new pod can ever read the intact Secret.
    out="$(
        _break_kubectl() {
            if [[ " $* " == *" apply "* && ! -f "$DIR/flip-broke" ]]; then
                local doc; doc="$(cat)"
                if grep -q 'PGRST_JWT_SECRET' <<<"$doc"; then
                    mk8s kubectl patch secret medcea-jwks -n "$NS" --type=json -p '[{"op":"remove","path":"/data/jwks-sig.json"}]' >/dev/null
                    touch "$DIR/flip-broke"
                fi
                # printf, not a here-string: the Secret's apply carries a password
                printf '%s\n' "$doc" | mk8s kubectl "$@"
                return
            fi
            mk8s kubectl "$@"
        }
        rm -f "$DIR/flip-broke"
        KUBECTL=_break_kubectl
        pgrst_deploy true "$NS" "$POD" "$DB" 2>&1
    )"; rc=$?
    sed 's/^/        /' <<<"$out"
    ALL_OUT+="$out"$'\n'
    [[ $rc -ne 0 ]] && pass flip "broken Secret key: pgrst_deploy fails" || fail flip "broken Secret key: pgrst_deploy succeeded"
    $KUBECTL rollout status deployment/config-api -n "$NS" --timeout=3m >/dev/null
    [[ "$(pgrst_live_mode "$NS")" == legacy ]] && pass flip "broken Secret key: config-api back to legacy" \
        || fail flip "broken Secret key: live mode $(pgrst_live_mode "$NS")"
    login_as_authenticator "$POSTGRES_PASS" && pass flip "broken Secret key: authenticator on the legacy password" \
        || fail flip "broken Secret key: the legacy password was not restored"
    st="$("${FLOW[@]}" get "$base" "/cea_unit?limit=1")"
    [[ "$st" == "200 -" ]] && pass flip "broken Secret key: served, no token 200" || fail flip "broken Secret key: $st"
    publish_key pgrst-a

    kill "$LOAD_PID" 2>/dev/null; LOAD_PID=""
    echo "        $(wc -l < "$DIR/flip-load") requests, ${SWITCH_FAILS} failed during the switches"

    # a stalled rollout (two templates live): the database deploy refuses
    $KUBECTL set image deployment/config-api -n "$NS" postgrest=postgrest/postgrest:v0.0.0-iamtest-missing >/dev/null
    sleep 5
    if pgrst_db_auth_pass "$NS" false 2>/dev/null; then
        fail S2 "two templates live: pgrst_db_auth_pass chose ${_PGRST_DB_LIVE} instead of refusing"
    else
        [[ "$_PGRST_DB_LIVE" == rolling ]] && pass S2 "two templates live: refused (rolling)" || fail S2 "refused, but as ${_PGRST_DB_LIVE}"
    fi
    _PGRST_DB_AUTH_PASS=""
    $KUBECTL rollout undo deployment/config-api -n "$NS" >/dev/null
    $KUBECTL rollout status deployment/config-api -n "$NS" --timeout=3m >/dev/null || fail S2 "config-api did not recover from the stalled rollout"

    # one template whose only pod cannot log in (what --purge-data leaves): its mode,
    # not "rolling", and the password it chooses makes config-api ready again
    PGRST_NEW_AUTH_PASS="$(openssl rand -hex 16)" pgrst_set_auth_password "$NS" "$POD" "$DB"
    fx -q -tA -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = 'authenticator'" >/dev/null
    $KUBECTL delete pod -n "$NS" -l app=config-api --wait=false >/dev/null
    local i unready=false
    for i in $(seq 1 30); do
        sleep 2
        if [[ "$($KUBECTL get deployment config-api -n "$NS" -o jsonpath='{.status.availableReplicas}')" == "" ]] \
           && grep -qE 'running|CrashLoopBackOff|terminated' <<<"$($KUBECTL get pods -n "$NS" -l app=config-api -o jsonpath='{.items[*].status.containerStatuses[0].state}')"; then
            unready=true; break
        fi
    done
    # PostgREST exits on a refused password: running unready or crash-looping
    [[ "$unready" == true ]] || fail S2 "the config-api pod never ran unready or crash-looped on a wrong password"
    if pgrst_db_auth_pass "$NS" false 2>/dev/null; then
        [[ "$_PGRST_DB_LIVE" == legacy && "$_PGRST_DB_AUTH_PASS" == "$POSTGRES_PASS" ]] \
            && pass S2 "a single unready legacy pod (purge recovery): legacy, POSTGRES_PASS" \
            || fail S2 "a single unready legacy pod: chose ${_PGRST_DB_LIVE}, or another password"
    else
        fail S2 "a single unready legacy pod: refused as ${_PGRST_DB_LIVE} (the database deploy could never recover it)"
    fi
    PGRST_NEW_AUTH_PASS="${_PGRST_DB_AUTH_PASS:-$POSTGRES_PASS}" pgrst_set_auth_password "$NS" "$POD" "$DB"
    _PGRST_DB_AUTH_PASS=""
    $KUBECTL delete pod -n "$NS" -l app=config-api --wait=false >/dev/null   # skip the crash loop's restart back-off
    wait_served "$base" && pass S2 "after the database deploy's password: config-api ready again" \
        || fail S2 "config-api stayed unready after the password was restored"
    local leaked
    leaked="$( { leaks "$ALL_OUT"; leaks "$(pod_logs)"; } | sort -u | paste -sd, -)"
    [[ -z "$leaked" ]] && pass P12 "no secret in the switches' output or the pod logs" \
        || { fail P12 "secrets in the output or logs: $leaked"; exit 1; }
}

if [[ "$KEYS" == true ]]; then
    setup_keys || { fail setup "keygen / Secret medcea-jwks"; exit 1; }
    pass setup "Secret medcea-jwks from a throwaway key"
    exit 0
elif [[ "$FLIP" == true ]]; then
    run_flip
else
    run_cases
fi

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}iam-postgrest: passed.${NC}"
else
    echo -e "${RED}${BOLD}iam-postgrest: $FAILS failure(s).${NC}"
    exit 1
fi
