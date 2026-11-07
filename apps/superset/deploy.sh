#!/usr/bin/env bash
# apps/superset/deploy.sh — Apache Superset 6.1.0 for data analysis (decision record
# "Superset for data analysis"; owner decisions D1–D8 of 6 Nov 2026, N1–N11 of 7 Nov).
#
#   ./apps/superset/deploy.sh               the full deploy (deploy-apps.sh --all runs it)
#   ./apps/superset/deploy.sh --gate-only   only who may sign in, and only on drift: the
#                                           live role mapping differs from the applied
#                                           policy, or a running pod was started with
#                                           another Secret or ConfigMap. While the wheel
#                                           cache is incomplete (the restart installs from
#                                           it) exit 4 (deferred) if the running Superset
#                                           admits only what the policy still gives,
#                                           else it is stopped (closed, never left open)
#
# Superset is installed automatically (D4), but only once the applied access policy
# has a superset tool block that gives some role a setting: until then this prints
#   skipped: Superset is not in the applied access policy, or no role is given a setting
# and exits 0, so deploy-apps.sh --all and install.sh stay green. Under IAM_GATES=false
# it is skipped too: there is no pre-policy Superset. So it is while
# IAM_DB_SERVICE_ROLES is not true (its data connection is svc_superset, never
# postgres: a fresh install has the switch false). If the policy loses Superset (or
# IAM_GATES or IAM_DB_SERVICE_ROLES turns false) while it runs, it is stopped (its
# Deployment deleted; the metadata database, Secret and ConfigMap stay), never left open.
#
# Deploys, in order: the wheel cache SUPERSET_WHEEL_DIR (N10: Job superset-wheels
# downloads a missing pinned wheel from PyPI; the pods install from the cache only), first,
# so a failed download changes nothing the pods read → the metadata database `superset`
# owned by the login role superset_meta (psql in the PostgreSQL pod, on stdin, a SCRAM
# verifier only, log_statement none) → Secret superset-secrets (server-side apply) and
# ConfigMap superset-config (superset_config.py, medcea_security.py, bootstrap.py,
# requirements.txt) → the init Job (db upgrade, init, bootstrap.py: the connection
# "MedCEA" as svc_superset) → the web Deployment, Service and Ingress at
# https://$SUPERSET_DOMAIN → the portal card.
#
# Who may sign in: `policy_tool superset` (cli.py compile superset), the mapping
# {realm role: Alpha+sql_lab | Gamma+MedCEA Viewer}; medcea_security.py refuses anyone
# else with a 403 before a Superset user exists. The data connection logs in as
# svc_superset only, never postgres: this refuses otherwise (db_client, IAM 2.5).
# No Redis, no Celery worker (D2); dependencies from a hash-checked init container (D3)
# out of the host's wheel cache (N10); sessions 5 min idle, 1 h at most (D6); sign-out
# through the platform's one-hop chain (N4, superset_logout_return). Uninstall:
# ./apps/superset/uninstall.sh [--purge-data] (D5: only that script drops the metadata
# database; the wheel cache stays).
#
# Needs config.env: SUPERSET_SECRET_KEY, SUPERSET_META_DB_PASS (infra/configure.sh),
# SUPERSET_CLIENT_SECRET (deploy-infra.sh, Keycloak client superset), SVC_SUPERSET_DB_PASS;
# IAM_DB_SERVICE_ROLES=true; SUPERSET_WHEEL_DIR (default /var/lib/$PROJECT_NAME/superset-wheels).
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
_MODE=full
case "$*" in
    "") ;;
    --gate-only) _MODE=scoped ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./apps/superset/deploy.sh [--gate-only])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log app-superset-deploy   # logs/app-superset-deploy-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ "$_MODE" == scoped ]] && echo "mode: gate-only"

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-render.sh"  # render FILE VAR... — manifests are in k8s/
source "$REPO_ROOT/infra/lib-wait.sh"
source "$SCRIPT_DIR/lib-superset.sh"     # the config checksum and the wheel cache, shared with health-check.sh
NAMESPACE="${NAMESPACE:-medcea}"
source "$REPO_ROOT/infra/lib-policy-source.sh"   # where every compile reads the policy (IAM Phase 4)
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)
SUPERSET_DOMAIN="${SUPERSET_DOMAIN:-superset.$DOMAIN}"
PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.$DOMAIN}"
WORKBENCH_DOMAIN="${WORKBENCH_DOMAIN:-ai-workbench.$DOMAIN}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[superset]${NC} $*"; }
warn() { echo -e "${YELLOW}[superset] $*${NC}" >&2; }
die()  { echo -e "${RED}[superset] ERROR: $*${NC}" >&2; exit 1; }

_deployed() { $KUBECTL get deployment superset -n "$NAMESPACE" >/dev/null 2>&1; }

# Superset no longer in the policy (or IAM_GATES=false, or IAM_DB_SERVICE_ROLES not
# true) while it runs: closed, not open.
# The Deployment goes (not a scale to 0): deploy-infra re-enables the card and health
# checks the mapping whenever deployment/superset exists. The data stays.
_stop() {
    $KUBECTL delete deployment superset -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
    source "$REPO_ROOT/infra/lib-portal.sh"
    portal_card disable "https://$SUPERSET_DOMAIN"
}

# The role mapping from the applied policy: SUPERSET_ROLES_MAPPING (canonical JSON), or
# rc 5 (not in the policy, or its group gives no role a setting yet), 3 (IAM_GATES=false),
# 1 (the policy does not compile).
_mapping() {
    local out rc=0
    source "$REPO_ROOT/infra/lib-policy-tools.sh"
    out="$(policy_tool superset)" || rc=$?
    (( rc == 0 )) || return $rc
    SUPERSET_ROLES_MAPPING="$(_check_mapping "$out")" \
        || die "the compiled role mapping is not one Superset accepts (python3 apps/iam/compiler/cli.py compile superset)"
}
# medcea_security.py's own validator (its Flask-free part), so the deploy and the pod
# accept exactly the same mappings; prints the canonical JSON.
_check_mapping() {
    MAPPING="$1" python3 -c '
import json, os, sys
src = open(sys.argv[1]).read().split("\nfrom flask import", 1)[0]
ns = {}
exec(compile(src, sys.argv[1], "exec"), ns)
print(json.dumps(ns["parse_roles_mapping"](os.environ["MAPPING"]), sort_keys=True, separators=(",", ":")))
' "$SCRIPT_DIR/medcea_security.py" 2>/dev/null
}
# The live mapping (Secret superset-secrets on stdin, never printed) against $1, the
# compiled one: "equal"; "within" when every role it maps the compiled one maps the same
# way (the policy only adds roles); "other" otherwise, or when it cannot be read.
_live_mapping_vs() {
    $KUBECTL get secret superset-secrets -n "$NAMESPACE" -o jsonpath='{.data.SUPERSET_ROLES_MAPPING}' 2>/dev/null \
        | base64 -d 2>/dev/null \
        | WANT="$1" python3 -c '
import json, os, sys
try:
    live, want = json.loads(sys.stdin.read()), json.loads(os.environ["WANT"])
    norm = lambda m: {r: sorted(v) for r, v in m.items()}
    live, want = norm(live), norm(want)
    print("equal" if live == want else "within" if all(want.get(r) == v for r, v in live.items()) else "other")
except Exception:
    print("other")'
}
# Every running web pod was started with the Secret and ConfigMap as they are now
# (medcea/config-checksum = superset_config_checksum, the comparison health supersetroles
# makes)? The mapping is a secretKeyRef env, read at start only, so a Secret applied by a
# re-render that did not finish is not yet what the pod admits. No running pod is
# current: one that starts reads the live Secret. Unreadable is not current.
_pods_current() {
    local sum pods
    sum="$(superset_config_checksum "$NAMESPACE")" || return 1
    pods="$(superset_web_pods "$NAMESPACE")" || return 1
    [[ -z "$(awk -v s="$sum" '$2 != s' <<<"$pods")" ]]
}

_SECRET_VARS=(NAMESPACE SUPERSET_SECRET_KEY SUPERSET_META_DB_PASS SUPERSET_CLIENT_SECRET SUPERSET_ROLES_MAPPING)
_render_secret() { render "$SCRIPT_DIR/k8s/superset-secret.yaml" "${_SECRET_VARS[@]}"; }
_CM_FILES=(superset_config.py medcea_security.py bootstrap.py requirements.txt)
# sha256 of what the pods read at start only, read back from the cluster after the
# Secret and the ConfigMap were applied: superset_config_checksum (lib-superset.sh), the
# function health-check.sh's supersetroles recomputes a running pod's annotation with.
_checksum() {
    superset_config_checksum "$NAMESPACE" \
        || die "cannot read back Secret superset-secrets and ConfigMap superset-config in $NAMESPACE"
}
_POD_VARS=(NAMESPACE KEYCLOAK_DOMAIN KEYCLOAK_REALM SUPERSET_DOMAIN PORTAL_DOMAIN PLATFORM_IP
           SUPERSET_CONFIG_CHECKSUM PG_SECRET PG_SECRET_KEY SUPERSET_DB_USER POSTGRES_DB
           MEDCEA_LOGOUT_RETURN SUPERSET_WHEEL_DIR SUPERSET_WHEEL_UID SUPERSET_WHEEL_GID)
_WHEEL_VARS=(NAMESPACE SUPERSET_WHEEL_DIR SUPERSET_WHEEL_UID SUPERSET_WHEEL_GID)
_apply_cm() {
    local f args=()
    for f in "${_CM_FILES[@]}"; do args+=(--from-file="$f=$SCRIPT_DIR/$f"); done
    $KUBECTL create configmap superset-config -n "$NAMESPACE" "${args[@]}" --dry-run=client -o yaml \
        | $KUBECTL label --local -f - app=superset -o yaml | $KUBECTL apply -f - >/dev/null
}
_apply_secret() {
    _render_secret | $KUBECTL apply --server-side --field-manager=medcea-superset --force-conflicts -f - >/dev/null
}
_apply_web() {
    render "$SCRIPT_DIR/k8s/superset.yaml" "${_POD_VARS[@]}" | $KUBECTL apply -f -
}
# Where Keycloak's end-session returns (N4): infra/lib-oauth2-proxy.sh, the address
# deploy-infra.sh registers on client superset.
_logout_return() {
    source "$REPO_ROOT/infra/lib-oauth2-proxy.sh"
    MEDCEA_LOGOUT_RETURN="$(superset_logout_return)" && [[ "$MEDCEA_LOGOUT_RETURN" == https://* ]] \
        || die "cannot build Superset's sign-out return address (superset_logout_return, infra/lib-oauth2-proxy.sh)"
}
# The wheel cache (N10): SUPERSET_WHEEL_DIR, never inside or around the volumes' directory
# (the nightly backup copies that; a PVC is no place for host state). Sets SUPERSET_WHEEL_DIR
# and the uid/gid the init containers read it as: its owner. The *_ok forms return 1 with
# WHEELS_WHY set, for --gate-only, where a cache problem is a deferral or a stop, never a
# failure apply.sh would revert the version for; the full deploy dies with the same text.
_wheel_dir_ok() {
    local storage d
    if ! d="$(superset_wheel_dir 2>/dev/null)"; then
        WHEELS_WHY="$(superset_wheel_dir 2>&1 >/dev/null)"; return 1
    fi
    SUPERSET_WHEEL_DIR="$d"
    storage="$($KUBECTL get storageclass microk8s-hostpath -o jsonpath='{.parameters.pvDir}' 2>/dev/null || true)"
    storage="${storage:-/var/snap/microk8s/common/default-storage}"
    case "$SUPERSET_WHEEL_DIR/" in
        "$storage"/*) WHEELS_WHY="SUPERSET_WHEEL_DIR=$SUPERSET_WHEEL_DIR is inside the volumes' directory $storage: choose another folder (config.env)."; return 1 ;;
    esac
    case "$storage/" in
        "$SUPERSET_WHEEL_DIR"/*) WHEELS_WHY="SUPERSET_WHEEL_DIR=$SUPERSET_WHEEL_DIR contains the volumes' directory $storage: choose another folder (config.env)."; return 1 ;;
    esac
}
_wheel_dir() { _wheel_dir_ok || die "$WHEELS_WHY"; }
_wheel_owner_ok() {
    if ! { SUPERSET_WHEEL_UID="$(stat -L -c %u "$SUPERSET_WHEEL_DIR" 2>/dev/null)" \
           && SUPERSET_WHEEL_GID="$(stat -L -c %g "$SUPERSET_WHEEL_DIR" 2>/dev/null)"; }; then
        WHEELS_WHY="cannot read the owner of $SUPERSET_WHEEL_DIR"; return 1
    fi
    if [[ "$SUPERSET_WHEEL_UID" == 0 ]]; then
        WHEELS_WHY="$SUPERSET_WHEEL_DIR belongs to root: the init containers run as its owner, never root. Make it the deploying account's (sudo chown \$(id -un): $SUPERSET_WHEEL_DIR), then re-run."
        return 1
    fi
}
_wheel_owner() { _wheel_owner_ok || die "$WHEELS_WHY"; }
# Full deploy only, before anything changes: the folder, mode 700, the deploying account's.
_own_wheel_dir() {
    local uid gid
    uid="$(id -u)"; gid="$(id -g)"
    (( uid != 0 )) || die "run ./apps/superset/deploy.sh as the deploying account, not root: the wheel cache and the init containers take its uid"
    if [[ ! -d "$SUPERSET_WHEEL_DIR" ]]; then
        log "Creating the wheel cache $SUPERSET_WHEEL_DIR (mode 700, owner $(id -un))..."
        if ! install -d -m 700 "$SUPERSET_WHEEL_DIR" 2>/dev/null; then
            sudo -p "[sudo] password for %u (to create $SUPERSET_WHEEL_DIR for Superset's wheels): " \
                install -d -m 700 -o "$uid" -g "$gid" "$SUPERSET_WHEEL_DIR"
        fi
    fi
    [[ "$(stat -L -c %u "$SUPERSET_WHEEL_DIR")" == "$uid" ]] \
        || die "$SUPERSET_WHEEL_DIR belongs to uid $(stat -L -c %u "$SUPERSET_WHEEL_DIR"), not to $(id -un). Make it yours (sudo chown $(id -un): $SUPERSET_WHEEL_DIR) or choose another SUPERSET_WHEEL_DIR, then re-run."
    chmod 700 "$SUPERSET_WHEEL_DIR"
    _wheel_owner
}
# Full deploy only, before anything the pods read changes: every pinned wheel in the
# cache; a missing one is downloaded by Job superset-wheels (PyPI, --require-hashes),
# which reads requirements.txt from a ConfigMap of its own, superset-wheels (never
# superset-config: the pods' checksum covers that), and the cache is checked again
# afterwards. Both are deleted once it is complete.
_fill_wheels() {
    local missing st deadline
    missing="$(superset_wheels_missing "$SUPERSET_WHEEL_DIR" "$SCRIPT_DIR/requirements.txt")" \
        || die "cannot read the wheel cache $SUPERSET_WHEEL_DIR"
    if [[ -z "$missing" ]]; then
        log "  wheel cache complete ($SUPERSET_WHEEL_DIR)."
        return 0
    fi
    log "  downloading into the wheel cache (PyPI, hash-checked): ${missing//$'\n'/ }"
    $KUBECTL delete job superset-wheels -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
    $KUBECTL create configmap superset-wheels -n "$NAMESPACE" --from-file="requirements.txt=$SCRIPT_DIR/requirements.txt" \
        --dry-run=client -o yaml | $KUBECTL label --local -f - app=superset component=wheels -o yaml \
        | $KUBECTL apply -f - >/dev/null
    render "$SCRIPT_DIR/k8s/superset-wheels.yaml" "${_WHEEL_VARS[@]}" | $KUBECTL apply -f - >/dev/null
    deadline=$(( SECONDS + 660 ))
    while :; do
        st="$($KUBECTL get job superset-wheels -n "$NAMESPACE" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || true)"
        [[ "$st" == 1/* ]] && break
        if [[ "$st" == */1 || $SECONDS -ge $deadline ]]; then
            warn "the wheel Job failed (or took over 11 min); its last lines:"
            $KUBECTL logs job/superset-wheels -n "$NAMESPACE" --tail=20 >&2 2>/dev/null || true
            die "Superset's wheels could not be downloaded (PyPI reachable?); the running Superset (if any) is unchanged"
        fi
        sleep 5
    done
    $KUBECTL delete job,configmap superset-wheels -n "$NAMESPACE" --ignore-not-found >/dev/null
    missing="$(superset_wheels_missing "$SUPERSET_WHEEL_DIR" "$SCRIPT_DIR/requirements.txt")" \
        || die "cannot read the wheel cache $SUPERSET_WHEEL_DIR"
    [[ -z "$missing" ]] || die "the wheel Job finished, but $SUPERSET_WHEEL_DIR still lacks: ${missing//$'\n'/ }"
    log "  wheel cache complete ($SUPERSET_WHEEL_DIR)."
}
# --gate-only: never downloads. A re-render restarts the pod, whose init container
# installs from the cache only (as its owner, never root), so the scoped path checks it
# before anything changes. Returns 1 with WHEELS_WHY set; never dies.
_wheels_ready() {
    local missing
    _wheel_dir_ok || return 1
    if [[ ! -d "$SUPERSET_WHEEL_DIR" ]]; then
        WHEELS_WHY="the wheel cache $SUPERSET_WHEEL_DIR does not exist"; return 1
    fi
    if ! missing="$(superset_wheels_missing "$SUPERSET_WHEEL_DIR" "$SCRIPT_DIR/requirements.txt")"; then
        WHEELS_WHY="the wheel cache $SUPERSET_WHEEL_DIR cannot be read (run this as its owner)"; return 1
    fi
    if [[ -n "$missing" ]]; then
        WHEELS_WHY="the wheel cache $SUPERSET_WHEEL_DIR lacks ${missing//$'\n'/ }"; return 1
    fi
    _wheel_owner_ok
}
# Its data connection is svc_superset, which the platform gives a login only under
# IAM_DB_SERVICE_ROLES=true (IAM 2.5): false (a fresh install's default) is a skip, not
# a fault. Under true a postgres fallback in _db_login is one (a missing Secret or
# password), and dies.
_service_roles_on() { [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]]; }
_need_secrets() {
    local v missing=()
    for v in SUPERSET_SECRET_KEY SUPERSET_META_DB_PASS SUPERSET_CLIENT_SECRET; do
        [[ -n "${!v:-}" ]] || missing+=("$v")
    done
    (( ${#missing[@]} == 0 )) \
        || die "${missing[*]} empty in config.env: run ./deploy-infra.sh (it generates them and creates the Keycloak client superset), then deploy again"
    (( ${#SUPERSET_SECRET_KEY} >= 32 )) || die "SUPERSET_SECRET_KEY is shorter than 32 characters"
}
# The data connection's login: svc_superset, never postgres.
_db_login() {
    source "$REPO_ROOT/infra/lib-db-roles.sh"   # db_client (IAM 2.5)
    db_client "$NAMESPACE" svc_superset
    [[ "$DBC_USER" == "svc_superset" ]] \
        || die "Superset's data connection would log in as $DBC_USER, not svc_superset: set IAM_DB_SERVICE_ROLES=true and run ./apps/database/deploy.sh first (see the warning above)"
    PG_SECRET="$DBC_SECRET"; PG_SECRET_KEY="$DBC_SECRET_KEY"; SUPERSET_DB_USER="$DBC_USER"
}

# =============================================================================
# --gate-only (scoped): only the role mapping, only on drift
# =============================================================================
if [[ "$_MODE" == scoped ]]; then
    if ! _deployed; then
        echo "  SUPERSET_DOMAIN (superset): not deployed (./apps/superset/deploy.sh installs it)"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    _rc=0; _mapping || _rc=$?
    case $_rc in
        0) ;;
        3|5) _stop
             echo "  SUPERSET_DOMAIN (superset): re-rendered (stopped, Deployment deleted: Superset is not in the applied access policy, no role is given a setting, or IAM_GATES=false)"
             policy_source_finish "$NAMESPACE" superset
             exit 0 ;;
        *) die "cannot compile Superset's role mapping from the access policy (python3 apps/iam/compiler/cli.py check)" ;;
    esac
    if ! _service_roles_on; then
        _stop
        echo "  SUPERSET_DOMAIN (superset): re-rendered (stopped, Deployment deleted: IAM_DB_SERVICE_ROLES is not true, and Superset's data connection is svc_superset)"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    # unchanged only when the Secret holds the compiled mapping AND every running pod
    # was started with it: a re-render that applied the Secret but whose rollout did not
    # finish (a signal, a rollout timeout, a full deploy that died after the Secret) is
    # drift, so a retry or ./apps/iam/apply.sh --resume converges instead of a no-op
    _live="$(_live_mapping_vs "$SUPERSET_ROLES_MAPPING")" || _live=other   # no Secret: kubectl fails
    if [[ "$_live" == equal ]] && _pods_current; then
        echo "  SUPERSET_DOMAIN (superset): unchanged"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    if ! _wheels_ready; then   # the restart installs from the cache: decided before anything changes
        # Deferred (exit 4: apply.sh records apply_deferred and drops supersetroles from
        # step 9) only when what runs admits nothing the policy no longer gives: the
        # Secret maps a subset of the compiled roles the same way and every pod runs it.
        # A narrowing, a changed role, or a pod on an unknown configuration fails closed.
        if [[ "$_live" == within ]] && _pods_current; then
            warn "SUPERSET_DOMAIN (superset): deferred — $WHEELS_WHY, so a restart could not install its packages; Superset keeps its old role mapping, which the policy only adds to. Run ./apps/superset/deploy.sh (it fills the cache), then this again (or ./apps/iam/apply.sh --resume)."
            exit 4
        fi
        _stop
        echo "  SUPERSET_DOMAIN (superset): re-rendered (stopped, Deployment deleted: $WHEELS_WHY, and the running Superset may admit roles the applied policy no longer gives it; ./apps/superset/deploy.sh fills the cache and starts it again)"
        policy_source_finish "$NAMESPACE" superset
        exit 0
    fi
    _need_secrets
    _db_login
    _logout_return
    _apply_cm       # the checksum covers these files: the pod must mount them
    _apply_secret
    SUPERSET_CONFIG_CHECKSUM="$(_checksum)"
    _apply_web >/dev/null
    $KUBECTL scale deployment superset -n "$NAMESPACE" --replicas=1 >/dev/null
    $KUBECTL rollout status deployment/superset -n "$NAMESPACE" --timeout=12m
    _pods_current || die "re-rendered, but a running Superset pod still carries another configuration (kubectl -n $NAMESPACE get pod -l app=superset): run this again"
    echo "  SUPERSET_DOMAIN (superset): re-rendered (role mapping)"
    policy_source_finish "$NAMESPACE" superset
    exit 0
fi

# =============================================================================
# 0. In the applied policy?
# =============================================================================
_rc=0; _mapping || _rc=$?
case $_rc in
    0) ;;
    5|3)
        if (( _rc == 3 )); then
            warn "skipped: IAM_GATES=false, and Superset has no pre-policy sign-in"
        else
            log "skipped: Superset is not in the applied access policy, or no role is given a setting"
        fi
        if _deployed; then
            _stop
            warn "the running Superset was stopped (Deployment deleted; its database is kept) and its portal card disabled"
        fi
        policy_source_finish "$NAMESPACE" superset
        exit 0 ;;
    *) die "cannot compile Superset's role mapping from the access policy (python3 apps/iam/compiler/cli.py check)" ;;
esac
if ! _service_roles_on; then
    log "skipped: Superset needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)"
    if _deployed; then
        _stop
        warn "the running Superset was stopped (Deployment deleted; its database is kept) and its portal card disabled"
    fi
    policy_source_finish "$NAMESPACE" superset
    exit 0
fi
log "Sign-in roles (compiled): $SUPERSET_ROLES_MAPPING"
_need_secrets
_db_login
_logout_return
_wheel_dir
_own_wheel_dir

# Importing dashboards is not built (owner decision N9, 7 Nov 2026: deferred). A bundle
# would have to carry databases/MedCEA.yaml with bootstrap.py's DB_UUID (a bundle without
# it silently drops every dataset and chart), and the importers need a user holding
# can_write (dashboards/README.md).
_extra="$(find "$SCRIPT_DIR/dashboards" -type f ! -name README.md -print -quit 2>/dev/null || true)"
[[ -z "$_extra" ]] || die "apps/superset/dashboards/ holds ${_extra#"$SCRIPT_DIR/"}: importing dashboards is not built"

# =============================================================================
# 1. The wheel cache (N10): the pods install from it, never from PyPI. First, so a
#    failed download leaves everything the running pod reads as it was.
# =============================================================================
log "Wheel cache $SUPERSET_WHEEL_DIR..."
_fill_wheels

# =============================================================================
# 2. Metadata database: superset, owned by superset_meta
# =============================================================================
log "Metadata database 'superset' (owner superset_meta)..."
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -n "$PG_POD" ]] || die "PostgreSQL is not running (./deploy-infra.sh)"
_META_SCRAM="$(printf '%s' "$SUPERSET_META_DB_PASS" | python3 "$REPO_ROOT/infra/pg-scram.py")"
# The verifier only, on stdin, in a session that logs no statement. Instance-wide
# objects outside the platform database: no grant in medcea_db, and the database deploy
# never compiles them (as Keycloak's database).
{
    echo "SET log_statement = 'none';"
    printf "\\\\set pw '%s'\n" "$_META_SCRAM"
    cat <<'SQL'
SELECT 'CREATE ROLE superset_meta' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'superset_meta') \gexec
ALTER ROLE superset_meta WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 20 PASSWORD :'pw';
SELECT 'CREATE DATABASE superset OWNER superset_meta' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'superset') \gexec
ALTER DATABASE superset OWNER TO superset_meta;
REVOKE ALL ON DATABASE superset FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE superset TO superset_meta;
SQL
} | _DBA_NS="$NAMESPACE" _DBA_POD="$PG_POD" _dba_psql postgres -q -v ON_ERROR_STOP=1 -f - >/dev/null \
    || die "could not create the metadata database (psql in $PG_POD)"
unset _META_SCRAM

# =============================================================================
# 3. Secret and ConfigMap. From here a failure leaves them newer than the running pod:
#    health supersetroles FAILs, and --gate-only (apply.sh) re-renders, until a deploy ends.
# =============================================================================
log "Secret superset-secrets and ConfigMap superset-config..."
_apply_cm
_apply_secret
SUPERSET_CONFIG_CHECKSUM="$(_checksum)"

# =============================================================================
# 4. Init Job: db upgrade, init, bootstrap.py
# =============================================================================
log "Init Job (db upgrade, init, the MedCEA connection and roles)..."
$KUBECTL delete job superset-init -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
render "$SCRIPT_DIR/k8s/superset-init.yaml" "${_POD_VARS[@]}" | $KUBECTL apply -f - >/dev/null
_deadline=$(( SECONDS + 1260 ))
while :; do
    _st="$($KUBECTL get job superset-init -n "$NAMESPACE" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || true)"
    [[ "$_st" == 1/* ]] && break
    if [[ "$_st" == */1 || $SECONDS -ge $_deadline ]]; then
        warn "the init Job failed (or took over 21 min); its last lines:"
        $KUBECTL logs job/superset-init -n "$NAMESPACE" --all-containers --tail=40 >&2 2>/dev/null || true
        die "Superset's init Job did not complete; Secret superset-secrets and ConfigMap superset-config are applied, the running Superset (if any) still runs the earlier ones: fix the cause and run this again"
    fi
    sleep 5
done
log "  init Job complete."

# =============================================================================
# 5. Web Deployment, Service, Ingress
# =============================================================================
log "Deploying Superset..."
_apply_web
$KUBECTL scale deployment superset -n "$NAMESPACE" --replicas=1 >/dev/null
$KUBECTL rollout status deployment/superset -n "$NAMESPACE" --timeout=12m
_pods_current || die "a running Superset pod still carries another configuration (kubectl -n $NAMESPACE get pod -l app=superset): run this again"
wait_for_http "https://$SUPERSET_DOMAIN/health" 180 "Superset" || exit 1

# =============================================================================
# 6. Portal card (the MedCEA Dashboard view)
# =============================================================================
source "$REPO_ROOT/infra/lib-portal.sh"
portal_card enable "https://$SUPERSET_DOMAIN"

log ""
log "Superset deployed: https://$SUPERSET_DOMAIN"

# The last command of the success path: ends an open policy break-glass for superset (IAM 4.2a)
policy_source_finish "$NAMESPACE" superset
