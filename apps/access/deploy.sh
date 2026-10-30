#!/usr/bin/env bash
# apps/access/deploy.sh — self-service access requests and the User Manager
#
# Deploys, in this order (IAM 2.7, invariant W: the access proxy admits more than
# admin only while every serving access pod enforces its route table):
#   0. Preflight: ConfigMap medcea-iam-lib must carry IAM 2.7's route table
#      (widening, the user_manager group) and library (allows, http_check(enforce=)),
#      and the host's gate must compile. Nothing is changed before this passes.
#   1. Schema iam + role access_svc in medcea_db (access_db.sql, one transaction),
#      then a pending_qa decision for every unit assignment that has none (the state
#      after access --purge-data; unit_backfill.sql)
#   2. access_svc's grants: compiled by the database deploy, which runs here when
#      access_svc lacks them (a fresh access_svc, or the first deploy of 2.7)
#   3. Secret access-secrets (DB password, Keycloak client secret) and ConfigMaps:
#      the service, its pages, the e-mail templates
#   4. Deployment access + Services access-public / access-admin + public Ingress,
#      rolled out and waited for
#   5. Proof: every Ready access pod answers /healthz on the Admin port with
#      enforce_always (waited for up to 60 s)
#   6. access-oauth2-proxy (Keycloak client 'access'): the roles compiled for
#      ACCESS_DOMAIN once 5 has passed, realm role admin otherwise; a failed proof
#      deploys the admin-only gate and exits 1
#   7. Portal card (User Manager)
#
# Keycloak's side — realm roles, the 'access' client with its service account,
# the groups mapper and ACCESS_DOMAIN in the certificate — is deploy-infra.sh's.
# Order after pulling IAM 2.7: ./deploy-infra.sh, then this script.
#
# Narrow the gate to admin (rollback step 0, or an emergency):
#   IAM_GATES=false ./apps/access/deploy.sh
# (the command line overrides config.env's IAM_GATES for this script only; do not
# edit config.env for it — ./deploy-infra.sh would put every host on its old list)
# There is no switch that stops the Admin port enforcing: behind a widened gate it
# would fail open.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
# IAM_GATES given on the command line wins over config.env's (which says true):
# it is how rollback step 0 narrows this gate without changing every other host's.
_GATES_OVERRIDE="${IAM_GATES-}"
source "$REPO_ROOT/config.env"
[[ -z "$_GATES_OVERRIDE" ]] || IAM_GATES="$_GATES_OVERRIDE"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"  # policy_groups / gate_error_page / gate_helm_args
NAMESPACE="${NAMESPACE:-medcea}"
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"   # older config.env files lack it
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"
# How long step 5 waits for every Ready pod to prove it enforces (tests shorten it).
ACCESS_PROOF_TIMEOUT="${ACCESS_PROOF_TIMEOUT:-60}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[access]${NC} $*"; }
warn() { echo -e "${YELLOW}[access] $*${NC}" >&2; }
die() { echo -e "${RED}[access] ERROR: $*${NC}" >&2; exit 1; }

if [[ -z "${ACCESS_CLIENT_SECRET:-}" || -z "${ACCESS_COOKIE_SECRET:-}" ]]; then
    log "ERROR: ACCESS_CLIENT_SECRET / ACCESS_COOKIE_SECRET are not set."
    log "       Run ./deploy-infra.sh to create the 'access' Keycloak client first."
    exit 1
fi

# =============================================================================
# 0. Preflight (reads only)
# =============================================================================
# The access service enforces its route table whatever IAM_ENFORCE says (IAM 2.7),
# so it must never start against an older table: routes it serves would be
# missing (refused), and GET / would still be iam_users, which qp may not read.
log "Preflight: IAM 2.7's route table and library in ConfigMap medcea-iam-lib..."
_PREFLIGHT_DIR="$(mktemp -d)"
trap 'rm -rf "$_PREFLIGHT_DIR"' EXIT
$KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.data.routes\.json}' \
    > "$_PREFLIGHT_DIR/routes.json" 2>/dev/null || true
$KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.data.medcea_iam\.py}' \
    > "$_PREFLIGHT_DIR/medcea_iam.py" 2>/dev/null || true
if ! _MISSING="$(python3 - "$_PREFLIGHT_DIR/routes.json" "$_PREFLIGHT_DIR/medcea_iam.py" <<'PY'
import json, re, sys
missing = []
try:
    with open(sys.argv[1]) as f:
        t = json.load(f)
except (OSError, ValueError):
    t = None
if not isinstance(t, dict):
    missing.append("routes.json")
else:
    if "widening" not in t:
        missing.append("routes.json: widening")
    groups = {r.get("group") for s in t.get("services", {}).values() for r in s.get("routes", {}).values()}
    if "user_manager" not in groups:
        missing.append("routes.json: group user_manager")
try:
    with open(sys.argv[2]) as f:
        lib = f.read()
except OSError:
    lib = ""
if not re.search(r"^def allows\(", lib, re.M):
    missing.append("medcea_iam.py: allows()")
if not re.search(r"^def http_check\([^)]*\benforce\b", lib, re.M):
    missing.append("medcea_iam.py: http_check(enforce=)")
print(", ".join(missing))
sys.exit(1 if missing else 0)
PY
)"; then
    die "ConfigMap medcea-iam-lib is older than IAM 2.7 (missing: ${_MISSING:-unreadable}).
       Run ./deploy-infra.sh first (IAM 2.7). Nothing was changed."
fi
# The compiled gate, before anything changes: a policy that does not compile
# stops the deploy here, not after the new pod is serving.
if [[ "${IAM_GATES:-true}" == "false" ]]; then
    _COMPILED_GROUPS='["admin"]'
else
    _COMPILED_GROUPS="$(policy_groups ACCESS_DOMAIN)" \
        || die "the access policy does not compile a gate for ACCESS_DOMAIN. Nothing was changed."
fi

PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' || true)
[[ -n "$PG_POD" ]] || { echo "ERROR: No PostgreSQL pod found in namespace $NAMESPACE" >&2; exit 1; }

# _psql [psql args] — as postgres in the PostgreSQL pod, ON_ERROR_STOP; SQL on stdin
_psql() {
    $KUBECTL exec -i -n "$NAMESPACE" "$PG_POD" -- \
        env PGPASSWORD="$POSTGRES_PASS" psql -X -q -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB" "$@"
}

# =============================================================================
# 1. Database: schema iam and role access_svc
# =============================================================================
# The access_svc password is generated once and kept in the Secret, like the
# cookie secrets in deploy-infra.sh: a new one each run would only churn.
_DB_PW="$($KUBECTL get secret access-secrets -n "$NAMESPACE" -o jsonpath='{.data.PG_PASSWORD}' 2>/dev/null | base64 -d || true)"
[[ -n "$_DB_PW" ]] || _DB_PW="$(openssl rand -hex 20)"

log "Applying schema iam (access requests, account decisions, append-only histories), one transaction..."
# The password goes in on stdin as a psql variable, not on the command line,
# so it is not visible in the pod's process list.
# log_statement='none' first: with IAM_DB_ROLES=true postgres's statements are
# logged in this database (break-glass), and these sessions carry passwords.
# -1: a failure part-way leaves nothing half-applied, and the triggers the file
# replaces are never missing, or in ORIGIN mode, in between (IAM 2.7).
if ! _OUT=$({ echo "SET log_statement = 'none';"; printf '\\set access_pw %s\n' "$_DB_PW"; cat "$SCRIPT_DIR/access_db.sql"; } \
        | _psql -1 -f - 2>&1); then
    echo "$_OUT" >&2
    echo "ERROR: applying access_db.sql failed (rolled back: nothing in it was applied)" >&2
    exit 1
fi
grep -v 'NOTICE' <<<"$_OUT" || true

# One-time carry-over: installs from before the User Manager owned e-mail had
# SMTP_USER / SMTP_PASS in config.env. Copy them in while the UI settings are
# still empty; from then on the UI is the only place they are changed, and since
# IAM 2.7 a change there waits for a qa person (kind mail_settings).
if [[ -n "${SMTP_USER:-}" && -n "${SMTP_PASS:-}" ]]; then
    { echo "SET log_statement = 'none';"; printf '\\set u %s\n\\set p %s\n' "$SMTP_USER" "${SMTP_PASS// /}"
      echo "UPDATE iam.mail_settings SET smtp_user = :'u', smtp_pass = :'p', updated_by = 'config.env (one-time import)', updated_at = now()"
      echo " WHERE id = 1 AND smtp_user = '' AND smtp_pass = '';"; } \
      | _psql -f - >/dev/null \
      && log "E-mail settings: SMTP_USER/SMTP_PASS from config.env imported if the User Manager had none (manage them there now)."
fi

# Unit assignments without a decision (the state after access --purge-data): each
# gets a pending_qa decision for qa (unit_backfill.sql says why and how).
log "Unit assignments without a decision..."
_BACKFILL="$(_psql -1 -tA -f - < "$SCRIPT_DIR/unit_backfill.sql" 2>&1)" \
    || { echo "$_BACKFILL" >&2; die "recording the unit assignments without a decision failed (rolled back)"; }
mapfile -t _BF_ROWS < <(grep '^backfilled|' <<<"$_BACKFILL" || true)
if [[ ${#_BF_ROWS[@]} -gt 0 ]]; then
    warn "Unit assignments without a decision, now pending_qa (a qa person confirms or refuses them in the Decisions tab):"
    for _row in "${_BF_ROWS[@]}"; do
        IFS='|' read -r _ _d _s _u <<<"$_row"
        warn "  decision #$_d: account $_s, unit #$_u"
    done
fi

# =============================================================================
# 2. access_svc's grants (compiled by the database deploy)
# =============================================================================
# The grants in schema iam and access_svc's come from the access policy, and only
# the database deploy applies them. A fresh access_svc (first install, or after
# --purge-data) or the first deploy of IAM 2.7 holds none: the new code would fail
# every write and the Decisions tab. So it runs here, before the new pod; the
# deploy lock is inherited (MEDCEA_LOCK_HELD). If it fails, nothing below runs:
# the running pod keeps serving behind the gate it has.
_grants_held() {
    local v
    v="$(_psql -tA -c "SELECT CASE WHEN pg_catalog.to_regprocedure('iam.record_decision(text,text,text,text,text,text,text,text,bigint)') IS NULL
                                 THEN 'nofunction'
                                 ELSE pg_catalog.has_function_privilege('access_svc',
                                      'iam.record_decision(text,text,text,text,text,text,text,text,bigint)', 'EXECUTE')::text END" 2>&1)" \
        || { echo "$v" >&2; die "could not read access_svc's privileges"; }
    [[ "$v" == nofunction ]] && die "access_db.sql did not create iam.record_decision (is this IAM 2.7's apps/access?)"
    [[ "$v" == true ]]
}
if _grants_held; then
    log "access_svc holds its compiled grants."
else
    log "access_svc lacks its compiled grants: running ./apps/database/deploy.sh..."
    "$REPO_ROOT/apps/database/deploy.sh" \
        || die "./apps/database/deploy.sh failed; the access service and its gate were not changed."
    _grants_held || die "access_svc still lacks EXECUTE on iam.record_decision after the database deploy."
fi

# =============================================================================
# 3. Secret and ConfigMaps
# =============================================================================
log "Writing Secret access-secrets..."
$KUBECTL create secret generic access-secrets -n "$NAMESPACE" \
  --from-literal=PG_PASSWORD="$_DB_PW" \
  --from-literal=KC_CLIENT_SECRET="$ACCESS_CLIENT_SECRET" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null

log "Creating ConfigMaps (service, pages, e-mail templates)..."
$KUBECTL create configmap access-api -n "$NAMESPACE" \
  --from-file=access-api.py="$SCRIPT_DIR/access-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -
_HTML_DIR="$(mktemp -d)"
for _p in register.html admin.html; do
    render "$SCRIPT_DIR/html/$_p" PORTAL_DOMAIN > "$_HTML_DIR/$_p"
done
cp "$SCRIPT_DIR/html/profile.html" "$SCRIPT_DIR/html/user-menu.js" "$_HTML_DIR/"
$KUBECTL create configmap access-html -n "$NAMESPACE" --from-file="$_HTML_DIR" \
  --dry-run=client -o yaml | $KUBECTL apply -f -
rm -rf "$_HTML_DIR"
$KUBECTL create configmap access-templates -n "$NAMESPACE" --from-file="$SCRIPT_DIR/templates" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 4. Deployment, Services, public Ingress
# =============================================================================
log "Deploying access service..."
# Signed-in hosts and their Keycloak clients: the user menu's sign-out and
# change-password links need the client each host logs in with.
HOST_CLIENTS="${PORTAL_DOMAIN}=portal,${CONFIG_DOMAIN:-config.$DOMAIN}=config,${ACCESS_DOMAIN}=access"
HOST_CLIENTS+=",${MONITOR_DOMAIN:-monitor.$DOMAIN}=monitor,${SCHEDULER_DOMAIN:-scheduler.$DOMAIN}=scheduler"
HOST_CLIENTS+=",${DBMGMT_DOMAIN:-dbmgmt.$DOMAIN}=dbmgmt,${MQTTX_DOMAIN:-mqtt-explorer.$DOMAIN}=mqtt-explorer"
render "$SCRIPT_DIR/k8s/access.yaml" NAMESPACE POSTGRES_DB KEYCLOAK_REALM KEYCLOAK_DOMAIN ACCESS_DOMAIN PORTAL_DOMAIN HOST_CLIENTS IAM_ENFORCE \
  | $KUBECTL apply -f -
$KUBECTL rollout restart deployment/access -n "$NAMESPACE"
log "Waiting for the access rollout..."
$KUBECTL rollout status deployment/access -n "$NAMESPACE" --timeout=4m

# =============================================================================
# 5. Proof: every Ready pod enforces
# =============================================================================
# /healthz on the Admin port is answered before check() and reports the code's
# version and that it enforces always. A Ready pod answering anything else (an old
# pod still terminating) is waited for; the Ready pods are listed again each round.
_PROVE='
import json, sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=5) as r:
        d = json.load(r)
except Exception as e:
    print("unreachable: %s" % e); sys.exit(1)
ok = d.get("ok") is True and d.get("access_version") == "2.7" and d.get("enforce_always") is True
print("enforce_always" if ok else "answered %s" % json.dumps(d)[:200]); sys.exit(0 if ok else 1)'
_PROOF_DETAIL=""
_prove_all() {   # → 0 when at least one pod is Ready and every Ready pod proves it
    local listing line p ready out n=0 bad=() pods=()
    listing="$($KUBECTL get pods -n "$NAMESPACE" -l app=access \
        -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>&1)" \
        || { _PROOF_DETAIL="cannot list the access pods: ${listing:0:120}"; return 1; }
    mapfile -t pods <<<"$listing"
    for line in "${pods[@]}"; do
        read -r p ready <<<"$line"
        [[ -n "$p" && "$ready" == True ]] || continue
        n=$((n + 1))
        out="$($KUBECTL exec -n "$NAMESPACE" "$p" -c api -- python3 -c "$_PROVE" 2>&1)" || bad+=("$p: ${out:0:160}")
    done
    if [[ $n -eq 0 ]]; then _PROOF_DETAIL="no Ready access pod"; return 1; fi
    _PROOF_DETAIL="${bad[*]:-}"
    [[ ${#bad[@]} -eq 0 ]]
}
log "Proving every Ready access pod enforces its route table (up to ${ACCESS_PROOF_TIMEOUT} s)..."
_ENFORCING_PROVEN=0
_DEADLINE=$((SECONDS + ACCESS_PROOF_TIMEOUT))
while :; do
    if _prove_all; then _ENFORCING_PROVEN=1; break; fi
    (( SECONDS < _DEADLINE )) || break
    sleep 3
done
if [[ $_ENFORCING_PROVEN == 1 ]]; then
    log "Every Ready access pod answers /healthz with enforce_always."
else
    warn "Not every Ready access pod proved it enforces: ${_PROOF_DETAIL}"
fi

# =============================================================================
# 6. oauth2-proxy for the User Manager
# =============================================================================
# Widened to the compiled roles (admin, qa, qp, auditor) only after step 5. Under
# IAM_GATES=false, or without the proof, realm role admin alone: this host's
# pre-policy list, never the portal's (policy_groups' IAM_GATES=false list).
if [[ "${IAM_GATES:-true}" == false || "$_ENFORCING_PROVEN" != 1 ]]; then
    ALLOWED_GROUPS='["admin"]'
else
    ALLOWED_GROUPS="$_COMPILED_GROUPS"
fi
log "Deploying access-oauth2-proxy (admits $ALLOWED_GROUPS)..."
_AOP_VALUES=$(mktemp /tmp/access-oauth2proxy-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/oauth2-proxy-values.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$_AOP_VALUES"
# The 403 page names exactly the roles this gate admits.
gate_error_page access-oauth2-proxy ACCESS_DOMAIN "$ALLOWED_GROUPS"
mapfile -t _AOP_GATE_ARGS < <(gate_helm_args access-oauth2-proxy)
$MK8S helm3 upgrade --install access-oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$REPO_ROOT/k8s/oauth2-proxy/values-common.yaml" \
  --values "$_AOP_VALUES" \
  --set configuration.clientID="access" \
  --set configuration.clientSecret="$ACCESS_CLIENT_SECRET" \
  --set configuration.cookieSecret="$ACCESS_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.hostname="$ACCESS_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$ACCESS_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  "${_AOP_GATE_ARGS[@]}" \
  --timeout 5m
rm -f "$_AOP_VALUES"
$KUBECTL rollout restart deployment/access-oauth2-proxy -n "$NAMESPACE"
$KUBECTL rollout status deployment/access-oauth2-proxy -n "$NAMESPACE" --timeout=4m

if [[ $_ENFORCING_PROVEN != 1 ]]; then
    die "the User Manager's gate stays admin-only: not every access pod proved it enforces (${_PROOF_DETAIL}).
       Check the pod (kubectl logs deployment/access -n $NAMESPACE) and run this script again."
fi

# =============================================================================
# 7. Portal card
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$ACCESS_DOMAIN"

log ""
log "Access requests deployed!"
log "  Register:     the Request access tab of the platform login page (https://$PORTAL_DOMAIN/#register)"
log "  User Manager: https://$ACCESS_DOMAIN/            (admits $ALLOWED_GROUPS; each role sees the tabs its routes allow)"
log "  Decisions:    a grant, a widening role change, an activation and a person_id change wait for a qa person"
log "  E-mail:       User Manager → E-mail settings (Gmail app password, templates; a settings change waits for qa)"
