#!/usr/bin/env bash
# infra/lib-postgrest.sh — config-api (PostgREST) with or without token
# verification (IAM plan Phase 2b, IAM_POSTGREST_JWT), and authenticator's
# password, which must change in the same step.
#
#   pgrst_live_mode NS                  absent | rolling | jwt | legacy (exit 2: kubectl failed)
#   pgrst_template_mode NS              absent | jwt | legacy, whatever the rollout state
#   pgrst_db_auth_pass NS FLAG          the password apps/database/deploy.sh gives authenticator
#   pgrst_db_present NS POD DB          0 when medcea_auth.pre_request() exists in DB
#   pgrst_db_enforcing NS POD DB        0 when DB's medcea.iam_db_roles is 'true'
#   pgrst_preflight MODE NS POD DB      refusals only, before anything is written
#   pgrst_set_auth_password NS POD DB   authenticator's password := $PGRST_NEW_AUTH_PASS
#   jwks_checksum NS                    sha256 of Secret medcea-jwks's jwks-sig.json
#   pgrst_roll_if_changed NS            restart config-api when the realm's keys changed
#   pgrst_deploy MODE NS POD DB         the switch (MODE = IAM_POSTGREST_JWT: true|false)
#
# Sourced by apps/frontend/deploy.sh (the switch), apps/database/deploy.sh (which
# password authenticator gets), apps/database/uninstall.sh, deploy-infra.sh (the
# key roll) and the IAM tests. Takes no lock: its callers hold medcea_lock.
# Needs KUBECTL and REPO_ROOT; pgrst_deploy also POSTGRES_PASS and, for true,
# AUTHENTICATOR_DB_PASS. POD may be empty (no PostgreSQL yet): then nothing is
# read from or written to the database, and the reason is printed.
#
# Who owns authenticator's password: while config-api runs the JWT template it
# reads it from Secret db-authenticator, so apps/frontend/deploy.sh alone writes
# that Secret and the role's password; apps/database/deploy.sh then takes the
# password from the Secret (it follows the live mode, never config.env alone).
# In legacy mode the role keeps POSTGRES_PASS, as before Phase 2b.
#
# Switch order (both directions), so a failure leaves a working config-api:
#   preflight -> [true: Secret db-authenticator] -> apply the template -> wait until
#   the new container has started -> rollout pause -> ALTER ROLE authenticator ->
#   restart the new pod -> rollout resume -> rollout status.
# A container that cannot start (missing Secret key, image) fails before the
# password changes, and the old pod keeps serving. PostgREST exits on a refused
# password, so the new pod, which tried the new password before the ALTER, is
# crash-looping in the kubelet's restart back-off; the old pod dies at its next
# new connection after the ALTER. The restart right after the ALTER makes the new
# pod connect at once, so the gap is a pod start plus its readiness probe (up to
# ~15 s, when the old pod happens to need a connection in that window), not a
# back-off. Both modes log in as authenticator: no order avoids that gap.
# A failure after the ALTER puts the previous password back and runs
# `rollout undo`. Never logs a secret.
#
# The JWT template carries Secret db-authenticator's resourceVersion as a pod
# annotation (medcea/auth-secret-version): a secretKeyRef is read only at
# container start, so a changed password must start a new pod, or the running one
# would keep the old password and fail at its next new connection.

if ! declare -F _dba_psql >/dev/null; then
    # shellcheck source=/dev/null
    source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # _dba_psql, _dba_scram
fi

_pgrst_log()  { echo -e "\033[0;32m[postgrest]\033[0m $*"; }
_pgrst_warn() { echo -e "\033[0;33m[postgrest] $*\033[0m" >&2; }

# The template config-api runs, from its env: PGRST_JWT_SECRET only exists in the
# JWT template. Exit 2 when kubectl cannot answer (never guessed as absent).
pgrst_template_mode() {
    local ns="$1" name envs
    name="$($KUBECTL get deployment config-api -n "$ns" --ignore-not-found -o name 2>/dev/null)" || return 2
    if [[ -z "$name" ]]; then echo absent; return 0; fi
    envs="$($KUBECTL get deployment config-api -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}' 2>/dev/null)" || return 2
    if grep -qx 'PGRST_JWT_SECRET' <<<"$envs"; then echo jwt; else echo legacy; fi
}

# rolling only when two pod templates can be live at once: the controller has not
# seen the newest spec yet, or more than one ReplicaSet still has pods. One
# template whose pod is unready (PostgREST cannot log in: a purged database, a
# PostgreSQL restart) is that template's mode — no running pod depends on another
# password, and the database deploy is what makes it ready again.
pgrst_live_mode() {
    local ns="$1" tmode st gen obs live
    tmode="$(pgrst_template_mode "$ns")" || return 2
    if [[ "$tmode" == absent ]]; then echo absent; return 0; fi
    st="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.metadata.generation} {.status.observedGeneration}' 2>/dev/null)" || return 2
    read -r gen obs <<<"$st"
    live="$($KUBECTL get rs -n "$ns" -l app=config-api -o jsonpath='{range .items[*]}{.status.replicas}{"\n"}{end}' 2>/dev/null)" || return 2
    live="$(grep -c '^[1-9]' <<<"$live" || true)"
    if [[ "${obs:-0}" != "${gen:-0}" || "${live:-0}" -gt 1 ]]; then
        echo rolling
    else
        echo "$tmode"
    fi
}

# The password apps/database/deploy.sh gives authenticator, following what
# config-api runs now (never config.env alone): legacy -> POSTGRES_PASS; jwt ->
# Secret db-authenticator (apps/frontend/deploy.sh owns it then), or
# AUTHENTICATOR_DB_PASS when the Secret is gone (a purge deletes it); absent -> the
# flag decides. Sets _PGRST_DB_AUTH_PASS (never printed), _PGRST_DB_LIVE and
# _PGRST_DB_WRITE_SECRET (true when the caller should write Secret db-authenticator:
# always except while a JWT config-api has one). Warnings on stderr; exit 1 with
# the refusal when two templates are live or kubectl cannot answer.
pgrst_db_auth_pass() {
    local ns="$1" flag="$2" live b64 sp="" want
    _PGRST_DB_AUTH_PASS=""; _PGRST_DB_WRITE_SECRET=true
    live="$(pgrst_live_mode "$ns")" || live=error
    _PGRST_DB_LIVE="$live"
    case "$live" in
        absent)
            if [[ "$flag" == true ]]; then _PGRST_DB_AUTH_PASS="${AUTHENTICATOR_DB_PASS:-}"
            else _PGRST_DB_AUTH_PASS="${POSTGRES_PASS:-}"; fi ;;
        legacy)
            _PGRST_DB_AUTH_PASS="${POSTGRES_PASS:-}" ;;
        jwt)
            b64="$($KUBECTL get secret db-authenticator -n "$ns" -o jsonpath='{.data.password}' 2>/dev/null || true)"
            [[ -n "$b64" ]] && sp="$(base64 -d <<<"$b64" 2>/dev/null || true)"
            if [[ -n "$sp" ]]; then
                _PGRST_DB_AUTH_PASS="$sp"; _PGRST_DB_WRITE_SECRET=false
                [[ "$sp" != "${AUTHENTICATOR_DB_PASS:-}" ]] && _pgrst_warn "Secret db-authenticator differs from AUTHENTICATOR_DB_PASS in config.env; keeping the Secret's (config-api uses it). ./apps/frontend/deploy.sh applies config.env's to both (and restarts config-api)."
            else
                _PGRST_DB_AUTH_PASS="${AUTHENTICATOR_DB_PASS:-}"
                _pgrst_warn "config-api runs the JWT template but Secret db-authenticator is missing; writing it from AUTHENTICATOR_DB_PASS"
            fi ;;
        *)
            echo "ERROR: config-api is rolling out (two pod templates live) or cannot be read (${live}); authenticator's password would fit only one pod." >&2
            echo "       Wait for: $KUBECTL rollout status deployment/config-api -n $ns   then re-run." >&2
            return 1 ;;
    esac
    want="$([[ "$flag" == true ]] && echo jwt || echo legacy)"
    if [[ "$live" != absent && "$live" != "$want" ]]; then
        _pgrst_warn "config-api still runs ${live} (IAM_POSTGREST_JWT=${flag}); ./apps/frontend/deploy.sh switches authenticator and config-api together"
    fi
    return 0
}

# psql in the PostgreSQL pod; nonzero when there is no pod
_pgrst_psql() {   # NS POD DB [psql args] — SQL on stdin
    local ns="$1" pod="$2" db="$3"; shift 3
    [[ -n "$pod" ]] || return 1
    _DBA_NS="$ns"; _DBA_POD="$pod"
    _dba_psql "$db" "$@"
}

pgrst_db_present() {
    local out
    out="$(_pgrst_psql "$1" "$2" "$3" -tAq -c "SELECT pg_catalog.to_regprocedure('medcea_auth.pre_request()') IS NOT NULL" 2>/dev/null)" || return 1
    [[ "$(tr -d '[:space:]' <<<"$out")" == t ]]
}

pgrst_db_enforcing() {
    local out
    out="$(_pgrst_psql "$1" "$2" "$3" -tAq -c "SELECT coalesce(current_setting('medcea.iam_db_roles', true), '')" 2>/dev/null)" || return 1
    [[ "$(tr -d '[:space:]' <<<"$out")" == true ]]
}

# The JWKS config-api would read, through infra/jwks-sig.py (exit 1: no signing key)
_pgrst_jwks_sig() {
    local ns="$1" b64
    b64="$($KUBECTL get secret medcea-jwks -n "$ns" -o jsonpath='{.data.jwks-sig\.json}' 2>/dev/null)" || return 1
    [[ -n "$b64" ]] || return 1
    base64 -d <<<"$b64" 2>/dev/null
}

pgrst_preflight() {
    local mode="$1" ns="$2" pod="$3" db="$4" refuse=()
    if [[ "$mode" == true ]]; then
        if [[ -z "${AUTHENTICATOR_DB_PASS:-}" || "${AUTHENTICATOR_DB_PASS:-}" == "${POSTGRES_PASS:-}" ]]; then
            refuse+=("AUTHENTICATOR_DB_PASS is empty or equals POSTGRES_PASS (run ./deploy-infra.sh, which generates it)")
        fi
        if ! _pgrst_jwks_sig "$ns" | python3 "$REPO_ROOT/infra/jwks-sig.py" >/dev/null 2>&1; then
            refuse+=("Secret medcea-jwks has no valid jwks-sig.json (run ./deploy-infra.sh)")
        fi
        pgrst_db_present "$ns" "$pod" "$db" \
            || refuse+=("database $db has no medcea_auth.pre_request() or cannot be read (run ./apps/database/deploy.sh)")
    else
        # a database enforcing per-role grants gives anon nothing: legacy config-api
        # would serve nothing at all
        if pgrst_db_enforcing "$ns" "$pod" "$db"; then
            refuse+=("database $db runs IAM_DB_ROLES=true (set IAM_DB_ROLES=false and run ./apps/database/deploy.sh first)")
        fi
    fi
    if [[ ${#refuse[@]} -gt 0 ]]; then
        echo "ERROR: IAM_POSTGREST_JWT=$mode refused; nothing was changed:" >&2
        local r; for r in "${refuse[@]}"; do echo "  - $r" >&2; done
        return 1
    fi
}

# authenticator's password := $PGRST_NEW_AUTH_PASS (environment, never argv): a SCRAM
# verifier on stdin, in a log_statement='none' session. No pod or no role: a note.
pgrst_set_auth_password() {
    local ns="$1" pod="$2" db="$3" have verifier
    if [[ -z "$pod" ]]; then
        _pgrst_log "no PostgreSQL pod: authenticator's password is set by ./apps/database/deploy.sh"
        return 0
    fi
    have="$(_pgrst_psql "$ns" "$pod" postgres -tAq -c "SELECT 1 FROM pg_roles WHERE rolname = 'authenticator'" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$have" != 1 ]]; then
        _pgrst_log "role authenticator does not exist yet (database $db): ./apps/database/deploy.sh creates it"
        return 0
    fi
    [[ -n "${PGRST_NEW_AUTH_PASS:-}" ]] || { echo "pgrst_set_auth_password: PGRST_NEW_AUTH_PASS is empty" >&2; return 1; }
    verifier="$(DBPW_authenticator="$PGRST_NEW_AUTH_PASS" _dba_scram authenticator)" || return 1
    [[ -n "$verifier" ]] || return 1
    {
        echo "SET log_statement = 'none';"
        printf "\\\\set pw '%s'\n" "$verifier"
        echo "ALTER ROLE authenticator PASSWORD :'pw';"
    } | _pgrst_psql "$ns" "$pod" postgres -q -v ON_ERROR_STOP=1 -f - >/dev/null
}

jwks_checksum() {
    local ns="$1" sum
    sum="$(set -o pipefail; _pgrst_jwks_sig "$ns" | sha256sum | cut -c1-64)" || return 1
    # the sha256 of nothing: the Secret or its key is missing
    [[ "$sum" != e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ]] || return 1
    echo "$sum"
}

_pgrst_annotation() {
    $KUBECTL get deployment config-api -n "$1" \
        -o jsonpath='{.spec.template.metadata.annotations.medcea/jwks-checksum}' 2>/dev/null
}

# After deploy-infra.sh rewrote medcea-jwks: a running JWT config-api read the old
# keys at start (secretKeyRef), so a changed checksum restarts it.
pgrst_roll_if_changed() {
    local ns="$1" mode sum
    mode="$(pgrst_template_mode "$ns")" || { _pgrst_warn "cannot read deployment config-api; not rolled"; return 0; }
    [[ "$mode" == jwt ]] || return 0
    sum="$(jwks_checksum "$ns")" || { _pgrst_warn "Secret medcea-jwks has no jwks-sig.json; config-api not rolled"; return 0; }
    [[ "$(_pgrst_annotation "$ns")" == "$sum" ]] && return 0
    $KUBECTL patch deployment config-api -n "$ns" --type=merge \
        -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"medcea/jwks-checksum\":\"$sum\"}}}}}" >/dev/null || return 1
    _pgrst_log "config-api rolled: realm keys changed"
}

# The pod of the deployment's current revision: wait until its container started.
# 0 = running or crash-looping (it ran: the password can follow), 1 = cannot start.
_pgrst_wait_started() {
    local ns="$1" i gen obs rev hash state
    for i in $(seq 1 45); do
        read -r gen obs <<<"$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.metadata.generation} {.status.observedGeneration}' 2>/dev/null)"
        if [[ -n "$gen" && "$gen" == "${obs:-}" ]]; then
            rev="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}' 2>/dev/null)"
            hash="$($KUBECTL get rs -n "$ns" -l app=config-api \
                -o jsonpath="{range .items[?(@.metadata.annotations.deployment\.kubernetes\.io/revision=='$rev')]}{.metadata.labels.pod-template-hash}{end}" 2>/dev/null)"
            if [[ -n "$hash" ]]; then
                state="$($KUBECTL get pods -n "$ns" -l "app=config-api,pod-template-hash=$hash" \
                    -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.state.running.startedAt}|{.state.waiting.reason}|{.state.terminated.reason}{"\n"}{end}{end}' 2>/dev/null | head -1)"
                local started waiting ended
                IFS='|' read -r started waiting ended <<<"$state"
                case "$waiting" in
                    CreateContainerConfigError|CreateContainerError|ErrImagePull|ImagePullBackOff|InvalidImageName)
                        _pgrst_warn "the new config-api container cannot start ($waiting)"
                        return 1 ;;
                esac
                # running, or it ran and exited (CrashLoopBackOff, terminated): started
                if [[ -n "$started" || -n "$ended" || "$waiting" == CrashLoopBackOff ]]; then
                    _PGRST_NEW_HASH="$hash"
                    return 0
                fi
            fi
        fi
        sleep 2
    done
    _pgrst_warn "the new config-api container did not start within 90 s"
    return 1
}

# Right after the ALTER: the new revision's pods that are not ready yet tried the
# new password too early and crash-loop; a fresh pod connects at once. A ready one (the password did not change) is left alone. Called with
# the rollout paused: otherwise the pod can turn ready between the read and the
# delete, the controller scales the old pod down, and the delete leaves no pod at
# all until the replacement passes its probe.
_pgrst_kick_unready() {
    local ns="$1" pods
    [[ -n "${_PGRST_NEW_HASH:-}" ]] || return 0
    pods="$($KUBECTL get pods -n "$ns" -l "app=config-api,pod-template-hash=$_PGRST_NEW_HASH" \
        -o jsonpath='{range .items[*]}{.metadata.name} {.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null \
        | awk '$2 != "true" && $1 != "" {print $1}')"
    [[ -n "$pods" ]] || return 0
    # shellcheck disable=SC2086 # pod names, one word each
    $KUBECTL delete pod -n "$ns" $pods --wait=false >/dev/null 2>&1 || return 0
    _pgrst_log "restarted the new config-api pod so it logs in now, not after its restart back-off"
}

# A run interrupted between pause and resume leaves the rollout paused, and a
# paused Deployment ignores every later apply: each pgrst_deploy resumes first.
_pgrst_resume() {
    $KUBECTL rollout resume deployment/config-api -n "$1" >/dev/null 2>&1 || true
}

# The password config-api in MODE logs in with, into _PGRST_PASS (absent: empty)
_pgrst_pass_for() {   # MODE [jwt password]
    case "$1" in
        legacy) _PGRST_PASS="${POSTGRES_PASS:-}" ;;
        jwt)    _PGRST_PASS="${2:-${AUTHENTICATOR_DB_PASS:-}}" ;;
        *)      _PGRST_PASS="" ;;
    esac
}

pgrst_deploy() {
    local mode="$1" ns="$2" pod="$3" db="$4" prev prev_jwt_pass="" b64 new_pass gen_before="" gen_after=""
    [[ "$mode" == true || "$mode" == false ]] || { echo "pgrst_deploy: MODE must be true or false" >&2; return 2; }
    prev="$(pgrst_template_mode "$ns")" || { echo "ERROR: cannot read deployment config-api in $ns" >&2; return 1; }
    [[ "$prev" != absent ]] && gen_before="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
    pgrst_preflight "$mode" "$ns" "$pod" "$db" || return 1
    [[ "$prev" != absent ]] && _pgrst_resume "$ns"
    _pgrst_log "config-api: ${prev} -> $([[ "$mode" == true ]] && echo jwt || echo legacy) (IAM_POSTGREST_JWT=$mode)"

    if [[ "$prev" == jwt ]]; then   # what the running pod logs in with, to put back on failure
        b64="$($KUBECTL get secret db-authenticator -n "$ns" -o jsonpath='{.data.password}' 2>/dev/null || true)"
        [[ -n "$b64" ]] && prev_jwt_pass="$(base64 -d <<<"$b64" 2>/dev/null || true)"
    fi

    if [[ "$mode" == true ]]; then
        SECRET_NAME=db-authenticator DB_ROLE=authenticator DB_PASS="$AUTHENTICATOR_DB_PASS" \
            render "$REPO_ROOT/apps/database/k8s/db-role-secret.yaml" SECRET_NAME DB_ROLE DB_PASS \
            | $KUBECTL apply -n "$ns" -f - >/dev/null || return 1
        JWKS_CHECKSUM="$(jwks_checksum "$ns")" || { echo "ERROR: Secret medcea-jwks has no jwks-sig.json" >&2; return 1; }
        # changes whenever the Secret's content does (an unchanged apply keeps it):
        # a rotated AUTHENTICATOR_DB_PASS starts a new pod before the ALTER
        AUTH_SECRET_VERSION="$($KUBECTL get secret db-authenticator -n "$ns" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null)" \
            && [[ -n "$AUTH_SECRET_VERSION" ]] || { echo "ERROR: cannot read Secret db-authenticator" >&2; return 1; }
        NAMESPACE="$ns" JWKS_CHECKSUM="$JWKS_CHECKSUM" AUTH_SECRET_VERSION="$AUTH_SECRET_VERSION" \
            render "$REPO_ROOT/apps/frontend/k8s/config-api-jwt.yaml" NAMESPACE JWKS_CHECKSUM AUTH_SECRET_VERSION \
            | $KUBECTL apply -n "$ns" -f - >/dev/null || return 1
        new_pass="$AUTHENTICATOR_DB_PASS"
    else
        NAMESPACE="$ns" render "$REPO_ROOT/apps/frontend/k8s/config-api.yaml" NAMESPACE POSTGRES_PASS \
            | $KUBECTL apply -n "$ns" -f - >/dev/null || return 1
        # kubectl apply removes only what it applied itself: the checksum annotation
        # that pgrst_roll_if_changed patched in stays unless removed here
        if [[ -n "$(_pgrst_annotation "$ns")" ]]; then
            $KUBECTL patch deployment config-api -n "$ns" --type=json \
                -p '[{"op":"remove","path":"/spec/template/metadata/annotations/medcea~1jwks-checksum"}]' >/dev/null || return 1
        fi
        new_pass="${POSTGRES_PASS:-}"
    fi

    # a template change bumps the generation; only then is there a revision to undo
    [[ "$prev" != absent ]] && gen_after="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"

    _PGRST_NEW_HASH=""
    # paused from the ALTER to the restart: the old pod stays until the new one is ready
    if _pgrst_wait_started "$ns" \
       && $KUBECTL rollout pause deployment/config-api -n "$ns" >/dev/null \
       && PGRST_NEW_AUTH_PASS="$new_pass" pgrst_set_auth_password "$ns" "$pod" "$db" \
       && { _pgrst_kick_unready "$ns"; _pgrst_resume "$ns"; true; } \
       && $KUBECTL rollout status deployment/config-api -n "$ns" --timeout=3m >/dev/null; then
        _pgrst_log "config-api runs $([[ "$mode" == true ]] && echo 'with token verification' || echo 'without token verification')"
        return 0
    fi

    _pgrst_warn "config-api did not come up in the new mode; restoring the previous one (${prev})"
    _pgrst_resume "$ns"   # rollout undo refuses a paused Deployment
    if [[ "$prev" != absent ]]; then
        _pgrst_pass_for "$prev" "$prev_jwt_pass"
        PGRST_NEW_AUTH_PASS="$_PGRST_PASS" pgrst_set_auth_password "$ns" "$pod" "$db" \
            || _pgrst_warn "could not restore authenticator's password"
        _PGRST_PASS=""
        if [[ "$prev" == jwt && -n "$prev_jwt_pass" ]]; then
            SECRET_NAME=db-authenticator DB_ROLE=authenticator DB_PASS="$prev_jwt_pass" \
                render "$REPO_ROOT/apps/database/k8s/db-role-secret.yaml" SECRET_NAME DB_ROLE DB_PASS \
                | $KUBECTL apply -n "$ns" -f - >/dev/null || true
        fi
    fi
    if [[ -n "$gen_before" && "$gen_after" != "$gen_before" ]]; then
        $KUBECTL rollout undo deployment/config-api -n "$ns" >/dev/null 2>&1 || _pgrst_warn "rollout undo failed"
        $KUBECTL rollout status deployment/config-api -n "$ns" --timeout=3m >/dev/null 2>&1 \
            || _pgrst_warn "config-api did not recover; check: $KUBECTL get pods -n $ns -l app=config-api"
    fi
    echo "ERROR: IAM_POSTGREST_JWT=$mode failed; config-api was put back to ${prev}" >&2
    return 1
}
