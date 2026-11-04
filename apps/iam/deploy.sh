#!/usr/bin/env bash
# apps/iam/deploy.sh — the access policy (codeplan IAM plan) and its service, iam-api
#
# 1. Checks the policy (apps/iam/policy/defaults.yaml) against its own invariants and
#    lists which roles each signed-in host admits. It is not the gate itself:
#    deploy-apps.sh runs components alphabetically, so frontend's gates are compiled
#    before this runs — what stops a broken policy is `cli.py compile`, which every gate
#    goes through and which refuses to compile from a policy that violates its invariants.
# 2. Deploys iam-api (IAM 3.5): ConfigMap iam-api-code (iam-api.py and infra/mqtt-passwd.py),
#    Deployment iam-api and Service iam-mqttx (:8085, the MQTT Explorer's credential
#    endpoint, reached only through its oauth2-proxy). It logs in as iam_svc and never
#    as postgres: until IAM_DB_SERVICE_ROLES=true and the database deploy has let iam_svc
#    log in, and until migration 008b's person-credential tables exist, iam-api is not
#    deployed — a warning while IAM_MQTT_PERSON=false (a default install), an error
#    while it is true (the Explorer would have no credential endpoint).
#    IAM_MQTT_PERSON is read live from /iam/settings.json (./deploy-infra.sh), so the
#    switch needs no redeploy here; while it is false POST answers 409. The guide's
#    enable recipe still runs this deploy right after setting the switch, before
#    ./deploy-infra.sh, so a missing iam-api stops it before the broker changes.
#
# 3. IAM Phase 4, slice 4.2a: version 1 of the access policy, once (design §10, §14.4.11):
#    while iam_policy.version is empty it runs ./apps/iam/apply.sh --bootstrap --by
#    ${MEDCEA_POLICY_BOOTSTRAP_BY:-$ADMIN_USER} (the factory file, applied at once, nothing
#    re-rendered); an apply that was committed but did not record its end is finished with
#    apply.sh --resume. Reached on every iam deploy, also when iam-api is skipped below.
# 4. IAM Phase 4, slice 4.3: the Policy UI (design §14.6). iam-api's second port :8083
#    (policy_api.py, policy.html; Service iam-admin :80 → 8083), the compiler it composes
#    versions with (ConfigMap iam-compiler, server-side applied), and POLICY_DOMAIN's
#    sign-in proxy iam-oauth2-proxy, proof-gated like the User Manager's: admin only until
#    every Ready iam-api pod answers /healthz on 8083 with policy_port and enforce_always,
#    then the roles the policy compiles for POLICY_DOMAIN. --gate-only re-renders only
#    that proxy, and only when it drifted.
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# --gate-only (IAM 4.2b): only the sign-in gate, and only when it drifted from the
# applied policy; no restart, no other apply. Anything else is refused.
_MODE=full
case "$*" in
    "") ;;
    --gate-only) _MODE=scoped ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/iam/deploy.sh [--gate-only])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-iam-deploy   # logs/app-iam-deploy-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ "$_MODE" == scoped ]] && echo "mode: gate-only"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[iam]${NC} $*"; }
die() { echo -e "${RED}[iam] $*${NC}" >&2; exit 1; }
warn() { echo -e "\033[0;33mWARNING: [iam] $*${NC}" >&2; }
skip_api() {   # iam-api cannot be deployed yet: fatal only while the Explorer depends on it
    [[ "${IAM_MQTT_PERSON:-false}" == "true" ]] && die "$*"
    echo -e "\033[0;33m[iam] iam-api not deployed: $* (needed before IAM_MQTT_PERSON=true).\033[0m" >&2
    policy_source_finish "$NAMESPACE" iam
    exit 0
}

[[ -f "$REPO_ROOT/config.env" ]] || die "config.env not found at $REPO_ROOT/config.env"
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"      # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"    # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-db-roles.sh"  # db_client; _dba_psql
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"   # policy_groups, gate_error_page, deploy_oauth2_proxy, pa_gate_state
source "$REPO_ROOT/infra/lib-wait.sh"           # wait_for_http
NAMESPACE="${NAMESPACE:-medcea}"
POLICY_DOMAIN="${POLICY_DOMAIN:-policy.$DOMAIN}"   # older config.env files lack it
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"
# How long the gate waits for every Ready iam-api pod to prove it enforces (tests shorten it).
IAM_PROOF_TIMEOUT="${IAM_PROOF_TIMEOUT:-60}"
source "$REPO_ROOT/infra/lib-policy-source.sh"   # where every compile reads the policy (IAM Phase 4)
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)

# The Policy UI's sign-in gate (IAM 4.3), shared by the full deploy and --gate-only: the
# User Manager's proof-gated pattern (apps/access/deploy.sh _gate). /healthz on :8083 is
# answered before the check; a Ready pod answering anything else (an old pod without the
# port) is waited for, and the Ready pods are listed again each round.
_PROVE='
import json, sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:8083/healthz", timeout=5) as r:
        d = json.load(r)
except Exception as e:
    print("unreachable: %s" % e); sys.exit(1)
ok = d.get("policy_port") is True and d.get("enforce_always") is True
print("policy_port" if ok else "answered %s" % json.dumps(d)[:200]); sys.exit(0 if ok else 1)'
_PROOF_DETAIL=""
_prove_all() {   # → 0 when at least one pod is Ready and every Ready pod proves it
    local listing line p ready out n=0 bad=() pods=()
    listing="$($KUBECTL get pods -n "$NAMESPACE" -l app=iam-api \
        -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>&1)" \
        || { _PROOF_DETAIL="cannot list the iam-api pods: ${listing:0:120}"; return 1; }
    mapfile -t pods <<<"$listing"
    for line in "${pods[@]}"; do
        read -r p ready <<<"$line"
        [[ -n "$p" && "$ready" == True ]] || continue
        n=$((n + 1))
        out="$($KUBECTL exec -n "$NAMESPACE" "$p" -c iam-api -- python3 -c "$_PROVE" 2>&1)" || bad+=("$p: ${out:0:160}")
    done
    if [[ $n -eq 0 ]]; then _PROOF_DETAIL="no Ready iam-api pod"; return 1; fi
    _PROOF_DETAIL="${bad[*]:-}"
    [[ ${#bad[@]} -eq 0 ]]
}
_gate() {
    local proven=0 deadline values
    log "Proving every Ready iam-api pod enforces on :8083 (up to ${IAM_PROOF_TIMEOUT} s)..."
    deadline=$((SECONDS + IAM_PROOF_TIMEOUT))
    while :; do
        if _prove_all; then proven=1; break; fi
        (( SECONDS < deadline )) || break
        sleep 3
    done
    if [[ "${IAM_GATES:-true}" == false || $proven != 1 ]]; then
        ALLOWED_GROUPS='["admin"]'
    else
        ALLOWED_GROUPS="$(policy_groups POLICY_DOMAIN)"
    fi
    log "Deploying iam-oauth2-proxy (POLICY_DOMAIN admits $ALLOWED_GROUPS)..."
    values=$(mktemp /tmp/iam-oauth2-proxy-values-XXXXXX.yaml)
    gate_error_page iam-oauth2-proxy POLICY_DOMAIN "$ALLOWED_GROUPS"
    APP_SERVICE=iam-admin render "$REPO_ROOT/k8s/oauth2-proxy/values-app.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE ALLOWED_GROUPS > "$values"
    if [[ "$_MODE" == scoped ]]; then
        OAUTH2_PROXY_NO_RESTART=1 deploy_oauth2_proxy iam-oauth2-proxy policy "${POLICY_CLIENT_SECRET:-}" "${POLICY_COOKIE_SECRET:-}" "$POLICY_DOMAIN" "$values"
    else
        deploy_oauth2_proxy iam-oauth2-proxy policy "${POLICY_CLIENT_SECRET:-}" "${POLICY_COOKIE_SECRET:-}" "$POLICY_DOMAIN" "$values"
    fi
    rm -f "$values"
    $KUBECTL rollout status deployment/iam-oauth2-proxy -n "$NAMESPACE" --timeout=4m
    [[ $proven == 1 ]] || die "the Policy UI's gate stays admin-only: not every iam-api pod proved it enforces (${_PROOF_DETAIL}).
       Check the pod (kubectl logs deployment/iam-api -n $NAMESPACE) and run this script again."
}
if [[ "$_MODE" == scoped ]]; then
    _WANT='["admin"]'
    [[ "${IAM_GATES:-true}" == false ]] || _WANT="$(policy_groups POLICY_DOMAIN)"
    _rc=0
    pa_gate_state iam-oauth2-proxy POLICY_DOMAIN "$_WANT" || _rc=$?
    case $_rc in
        0) log "POLICY_DOMAIN (iam-oauth2-proxy): unchanged" ;;
        3) log "POLICY_DOMAIN (iam-oauth2-proxy): not deployed (./apps/iam/deploy.sh installs it)" ;;
        4) die "cannot read iam-oauth2-proxy's live gate" ;;
        *) _gate
           log "POLICY_DOMAIN (iam-oauth2-proxy): re-rendered ($PA_DRIFT)" ;;
    esac
    policy_source_finish "$NAMESPACE" iam
    exit 0
fi

log "Checking the access policy..."
if ! python3 "$SCRIPT_DIR/compiler/cli.py" check; then
    die "The access policy violates its invariants — fix apps/iam/policy/defaults.yaml."
fi

log "Roles each signed-in host admits (policy; [status] = enforced today?):"
python3 "$SCRIPT_DIR/compiler/cli.py" hosts | sed 's/^/  /'

# =============================================================================
# IAM Phase 4 slice 4.2a: version 1 of the access policy, once (design §10, §14.4.11)
# =============================================================================
log "Policy versions..."
_PS_DIR="$(mktemp -d)"; trap 'rm -rf "$_PS_DIR"' EXIT
_ST="$(policy_db_state "$NAMESPACE" "$_PS_DIR/state.json")" || die "cannot read the policy versions"
case "$_ST" in
  none)        warn "policy bootstrap waits for ./apps/database/deploy.sh (no migration 008c yet)" ;;
  unreachable) die "PostgreSQL is not Ready (the init above would have refused)" ;;
  version-*)
    if [[ "$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("last_apply_event") or {}).get("event",""))' "$_PS_DIR/state.json")" == apply_started ]]; then
      warn "version ${_ST#version-} was committed but its apply did not record its end: finishing it (apply.sh --resume)"
      MEDCEA_CONFIRMED=1 "$SCRIPT_DIR/apply.sh" --resume --by "${MEDCEA_POLICY_BOOTSTRAP_BY:-$ADMIN_USER}" \
        || die "the apply of version ${_ST#version-} is still not finished: ./apps/iam/apply.sh --resume --by <you>"
    fi
    log "  applied: ${_ST#version-} (./apps/iam/apply.sh --status)" ;;
  partial)     die "policy versions exist but none is applied: ./apps/iam/apply.sh --status" ;;
  empty)
    rc=0
    MEDCEA_CONFIRMED=1 "$SCRIPT_DIR/apply.sh" --bootstrap --by "${MEDCEA_POLICY_BOOTSTRAP_BY:-$ADMIN_USER}" || rc=$?
    case $rc in
      0) unset MEDCEA_POLICY_SOURCE_DONE; policy_source_init "$NAMESPACE" || exit $? ;;   # re-read: version 1, host file verified
      2) warn "policy bootstrap waits (see above); health shows 'no applied version' until a later ./apps/iam/deploy.sh" ;;
      3) die "version 1 is committed but not finished: ./apps/iam/apply.sh --resume --by <you>" ;;
      130) die "the policy bootstrap was interrupted before its commit: nothing was changed" ;;
      *) die "the policy bootstrap refused or failed (see above; it says whether anything was changed)" ;;
    esac ;;
esac

MQTTX_DOMAIN="${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}"

# =============================================================================
# iam-api (IAM 3.5)
# =============================================================================
log "Checking the database for iam-api..."
_POD="$(_dbr_pg_pod "$NAMESPACE")" || _POD=""
[[ -n "$_POD" ]] || skip_api "no PostgreSQL pod in $NAMESPACE: run ./deploy-infra.sh first."
_READY="$(_DBA_NS="$NAMESPACE" _DBA_POD="$_POD" _dba_psql "${POSTGRES_DB:-medcea_db}" -tAq \
    -c "SELECT pg_catalog.to_regclass('medcea.mqtt_service_credential') IS NOT NULL
               AND pg_catalog.to_regclass('iam.account_decision') IS NOT NULL" 2>/dev/null | tr -d '[:space:]')" || _READY=""
[[ "$_READY" == "t" ]] \
    || skip_api "medcea.mqtt_service_credential or iam.account_decision is missing: run ./apps/database/deploy.sh and ./apps/access/deploy.sh first."

# The one service that mints MQTT credentials never runs as postgres: the policy's
# limits on the person tables hold only for iam_svc.
db_client "$NAMESPACE" iam_svc
[[ "$DBC_USER" == "iam_svc" ]] \
    || skip_api "iam-api would log in as $DBC_USER, not iam_svc: set IAM_DB_SERVICE_ROLES=true and run ./apps/database/deploy.sh first (see the warning above)."

log "Creating ConfigMap iam-api-code..."
$KUBECTL create configmap iam-api-code -n "$NAMESPACE" \
    --from-file=iam-api.py="$SCRIPT_DIR/iam-api.py" \
    --from-file=policy_api.py="$SCRIPT_DIR/policy_api.py" \
    --from-file=policy.html="$SCRIPT_DIR/html/policy.html" \
    --from-file=mqtt_passwd.py="$REPO_ROOT/infra/mqtt-passwd.py" \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# The compiler the Policy UI composes versions with (IAM 4.3): apps/iam/compiler/*.py and the
# factory policy, about 340 KiB — over the 256 KiB a client-side apply's last-applied
# annotation holds, so server-side (as infra/lib-manual.sh). Keys compiler__<f>.py and
# policy__defaults.yaml, laid out as compiler/ and policy/ under /opt/iam by `items`.
log "Applying ConfigMap iam-compiler (server-side)..."
_IAM_CM="$(mktemp -d)"
python3 "$SCRIPT_DIR/compiler_cm.py" "$SCRIPT_DIR" "$NAMESPACE" "$_IAM_CM" || { rm -rf "$_IAM_CM"; die "cannot build ConfigMap iam-compiler (above)"; }
IAM_COMPILER_SHA256="$(cat "$_IAM_CM/sha256")"
IAM_COMPILER_ITEMS="$(cat "$_IAM_CM/items.json")"
$KUBECTL apply --server-side --field-manager=medcea-iam --force-conflicts -f - < "$_IAM_CM/configmap.json" >/dev/null
rm -rf "$_IAM_CM"

log "Deploying iam-api (Service iam-mqttx :8085, Service iam-admin :80 → 8083)..."
PG_USER="$DBC_USER" PG_SECRET="$DBC_SECRET" PG_SECRET_KEY="$DBC_SECRET_KEY" PROJECT_NAME="${PROJECT_NAME:-medcea}" \
IAM_ENFORCE="${IAM_ENFORCE:-false}" IAM_COMPILER_SHA256="$IAM_COMPILER_SHA256" IAM_COMPILER_ITEMS="$IAM_COMPILER_ITEMS" \
    render "$SCRIPT_DIR/k8s/iam.yaml" NAMESPACE POSTGRES_DB PG_USER PG_SECRET PG_SECRET_KEY PROJECT_NAME MQTTX_DOMAIN IAM_ENFORCE \
        POLICY_DOMAIN ACCESS_DOMAIN IAM_COMPILER_SHA256 IAM_COMPILER_ITEMS \
  | $KUBECTL apply -f -
# The code is a subPath mount, which kubelet never refreshes in place.
$KUBECTL rollout restart deployment/iam-api -n "$NAMESPACE"
$KUBECTL rollout status deployment/iam-api -n "$NAMESPACE" --timeout=3m

_HEALTH="$($KUBECTL exec -n "$NAMESPACE" deployment/iam-api -- \
    python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8085/healthz", timeout=5).read().decode())' 2>/dev/null)" \
    || die "iam-api does not answer /healthz (kubectl -n $NAMESPACE logs deployment/iam-api)."
log "  /healthz: $_HEALTH"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); sys.exit(0 if d.get("mqtt_digest") else 1)' "$_HEALTH" \
    || echo -e "\033[0;33m[iam] no valid /iam/mqtt.json yet: run ./deploy-infra.sh (the Explorer's POST answers 503 until then).\033[0m" >&2

# The Policy UI's sign-in gate (IAM 4.3), proof-gated (above), then its portal card.
_gate
wait_for_http "https://$POLICY_DOMAIN/" 120 "Policy UI" || exit 1
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$POLICY_DOMAIN"

policy_source_finish "$NAMESPACE" iam   # ends an open policy break-glass for iam (IAM 4.2a)
log ""
log "iam-api deployed: the MQTT Explorer's credential endpoint (IAM_MQTT_PERSON=${IAM_MQTT_PERSON:-false}, read live)"
log "  and the Policy UI at https://$POLICY_DOMAIN/ (admits $ALLOWED_GROUPS)."
