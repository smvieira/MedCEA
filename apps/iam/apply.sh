#!/usr/bin/env bash
# apps/iam/apply.sh — versions of the access policy (IAM Phase 4; design §6, §14.4.9).
#
# As of slice 4.2a:
#   apply.sh --bootstrap --by <username> [--check-only]   version 1, only while iam_policy.version
#                                                         is empty (apps/iam/deploy.sh runs it)
#   apply.sh --resume --by <username> [--check-only]      finish an apply that did not record its end
#   apply.sh --status                                     read-only
#   apply.sh <version> | --rollback-to <v>               refused: they arrive with IAM 4.5
#
# As of slice 4.4 (design §14.7.6):
#   apply.sh --propose-skeleton --by <username> --reason "<text>" --from-git <rev> [--check-only]
#                                                         a git skeleton that widens access becomes
#                                                         a submitted version of kind skeleton, for
#                                                         qa's approval in the Policy UI
#   apply.sh --withdraw-open --by <username> --reason "<text>" [--check-only]
#                                                         withdraw the open change or skeleton
#                                                         version from the host (no Keycloak)
#
# --propose-skeleton reads the proposed skeleton from a commit (--from-git, mandatory): the
# deploying tree stays at the accepted skeleton, so no deploy refuses and health does not FAIL
# while the version waits. Nothing is applied: applying an approved version arrives with 4.5.
# The proposer is the claimed --by (resolved in Keycloak, before the diff is built); the
# --by username and the OS user are appended to the reason, the only place they are recorded.
# --withdraw-open needs no Keycloak (withdrawing grants nothing; a rollback must not depend on
# it). Both: exit 0 done, would do (--check-only) or nothing to withdraw; 1 refused, nothing
# changed; 2 usage or a precondition. Nothing follows their commit, so there is no exit 3.
#
# --bootstrap seeds version 1 from the factory file (apps/iam/policy/defaults.yaml) and applies
# it at once. It changes no artefact: before its one database transaction it proves that every
# target compiled from version 1 (composed, and through a simulated host file) is byte-identical
# to its compile from defaults.yaml, and that the live route table and role_widening() already
# carry that compile's digest. Then, in one transaction (apps/database/lib-db-apply.sh
# dba_policy_bundle, actor system:apply): the git skeleton accepted and synced, version 1 built
# (its entries digest asserted), the grants bundle as the database deploy runs it, and version 1
# marked applied. After the COMMIT: state/policy-applied.yaml written and compiled again, the
# grants checked (health-check.sh, iamgrants only), bootstrap_applied recorded, iampolicy and
# iamartefacts reported. `--by` is a claim, resolved in Keycloak (exact username, enabled, its
# sub and person_id); a qa person of another person_id confirms version 1 in the Policy UI (4.3).
#
# Exit codes: 0 done; 1 refused before the commit, or failed, with nothing changed; 2 usage or a
# precondition (the bootstrap waits: no migration 008c, Keycloak down, an unknown --by, config.env
# and the database disagree on IAM_DB_ROLES); 3 any failure after the bundle's COMMIT: the
# version exists, `apply.sh --resume --by <you>` finishes it (the iam deploy does so itself).
#
# Logging and the lock (CLAUDE.md): it logs first in every mode (logs/apply-policy-<ts>.log, or
# the parent's log). --bootstrap and --resume take the deploy lock (inherited from the iam deploy
# or the guide, then verified); --status and --check-only take none and write nothing (no queue
# flush, no file, no database write). Secrets never reach argv or the log: the Keycloak admin
# token goes to curl as a header on a pipe, the database password never leaves its pod.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLI="$SCRIPT_DIR/compiler/cli.py"
CHECK="$SCRIPT_DIR/apply_check.py"

usage() {
    cat <<'EOF'
Usage:
  apps/iam/apply.sh --bootstrap --by <username> [--check-only]
        version 1 of the access policy (the factory file), only while no version exists;
        --check-only: would it bootstrap? (read-only)
  apps/iam/apply.sh --resume --by <username> [--check-only]
        finish an apply that was committed but did not record its end
  apps/iam/apply.sh --status
        the applied version, the skeleton, the host file, the last policy events (read-only)
  apps/iam/apply.sh --propose-skeleton --by <username> --reason "<text>" --from-git <rev> [--check-only]
        propose the skeleton of commit <rev> (it widens access) as a version for qa's approval
  apps/iam/apply.sh --withdraw-open --by <username> --reason "<text>" [--check-only]
        withdraw the open change or skeleton version (when the Policy UI cannot)
  apps/iam/apply.sh <version> | --rollback-to <version>
        arrive with IAM 4.5

--by is the username (realm $KEYCLOAK_REALM) of the person who applies: a claim on the record.
Exit: 0 done, 1 refused or failed (nothing changed), 2 usage or a precondition (the bootstrap
waits), 3 committed but not finished (run --resume; never for --propose-skeleton or --withdraw-open).
EOF
}

MODE="" BY="" CHECK_ONLY=false REFUSE="" ERR="" REASON="" REASON_SET=false REV="" REV_SET=false
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --bootstrap|--resume|--status|--propose-skeleton|--withdraw-open)
            [[ -z "$MODE" ]] || ERR="give one of --bootstrap, --resume, --status, --propose-skeleton, --withdraw-open"
            MODE="${1#--}" ;;
        --check-only) CHECK_ONLY=true ;;
        --by)
            if (($# < 2)); then ERR="--by needs a username"; else BY="$2"; shift; fi ;;
        --by=*) BY="${1#--by=}" ;;
        --reason)
            if (($# < 2)); then ERR="--reason needs a text"; else REASON="$2"; REASON_SET=true; shift; fi ;;
        --reason=*) REASON="${1#--reason=}"; REASON_SET=true ;;
        --from-git)
            if (($# < 2)); then ERR="--from-git needs a revision"; else REV="$2"; REV_SET=true; shift; fi ;;
        --from-git=*) REV="${1#--from-git=}"; REV_SET=true ;;
        --rollback-to|--rollback-to=*)
            REFUSE="--rollback-to arrives with IAM 4.5 (rollback to an approved or confirmed version)"
            [[ "$1" == --rollback-to && $# -ge 2 ]] && shift ;;
        [0-9]*) REFUSE="apply.sh <version> arrives with IAM 4.5 (applying an approved version)" ;;
        *) ERR="unknown argument '$1'" ;;
    esac
    shift
done

# Logs first, in every mode (before the lock: tee must not inherit fd 9).
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log apply-policy

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[apply]${NC} $*"; }
warn() { echo -e "${YELLOW}WARNING: [apply] $*${NC}" >&2; }
err()  { echo -e "${RED}ERROR: [apply] $*${NC}" >&2; }
die()  { local rc="$1"; shift; err "$*"; exit "$rc"; }

[[ -z "$REFUSE" ]] || die 2 "$REFUSE"
if [[ -n "$ERR" || -z "$MODE" ]]; then
    usage >&2
    die 2 "${ERR:-give --bootstrap, --resume, --status, --propose-skeleton or --withdraw-open}"
fi
if [[ "$MODE" == status ]]; then
    [[ -z "$BY" && "$CHECK_ONLY" == false ]] || die 2 "--status takes no --by and no --check-only"
elif [[ ! "$BY" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]*$ ]]; then
    die 2 "--$MODE needs --by <username> (letters, digits, . _ @ -; not starting with -)"
fi
case "$MODE" in
    propose-skeleton|withdraw-open)
        # the reason reaches psql only base64 in a \set variable (apply_check.py), never on argv
        [[ -n "${REASON//[[:space:]]/}" && "$REASON" != -* ]] \
            || die 2 "--$MODE needs --reason \"<text>\" (not empty, not starting with -)"
        if [[ "$MODE" == propose-skeleton ]]; then
            # break-glass changes the matrix, never the skeleton (design §3.5)
            [[ -z "${MEDCEA_POLICY_FILE:-}" ]] || die 2 "no skeleton proposal under break-glass: it changes the matrix, never the skeleton (unset MEDCEA_POLICY_FILE)"
            $REV_SET || die 2 "propose a skeleton change from a commit: --from-git <rev>; the deploying tree stays at the accepted skeleton until IAM 4.5 applies it"
            [[ "$REV" =~ ^[A-Za-z0-9][A-Za-z0-9._/~^-]*$ ]] || die 2 "--from-git '$REV' is not a revision (letters, digits, . _ / ~ ^ -; not starting with -)"
        else
            $REV_SET && die 2 "--withdraw-open takes no --from-git"
        fi ;;
    *)
        { $REASON_SET || $REV_SET; } && die 2 "--reason and --from-git belong to --propose-skeleton and --withdraw-open" ;;
esac
WRITES=false
[[ "$MODE" != status && "$CHECK_ONLY" == false ]] && WRITES=true

source "$REPO_ROOT/infra/lib-lock.sh"
if $WRITES; then
    medcea_lock          # a no-op under the iam deploy or the guide (inherited), then verified
    medcea_lock_verify || die 1 "apply.sh writes the policy only under the deploy lock held by this run (MEDCEA_LOCK_HELD=${MEDCEA_LOCK_HELD:-unset} is not a live holder of .medcea.lock above this process): nothing was done"
fi

[[ -f "$REPO_ROOT/config.env" ]] || die 2 "config.env not found at $REPO_ROOT/config.env"
source "$REPO_ROOT/config.env"
NAMESPACE="${NAMESPACE:-medcea}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"
CEA_DB="$POSTGRES_DB"
PROJECT_NAME="${PROJECT_NAME:-medcea}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-medcea}"
source "$REPO_ROOT/infra/lib-mk8s.sh"           # mk8s / $KUBECTL
source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # dba_policy_bundle, _dba_psql
source "$REPO_ROOT/infra/lib-db-roles.sh"       # _dbr_pg_pod, db_clients_live (dba_service_logins)
KC_PORT=18092                                    # its own port (units.sh uses 18091, deploys 18080)
KC_URL="http://localhost:$KC_PORT"
source "$REPO_ROOT/infra/lib-keycloak-admin.sh"
source "$REPO_ROOT/infra/lib-policy-source.sh"  # policy_db_state, _ps_host_present, _ps_flush_seed_facts

STAGE="$(mktemp -d)"; chmod 700 "$STAGE"
PF_PID=""
# The temp dir first and nothing that can fail: the script's own status is kept.
cleanup() {
    local rc=$?
    rm -rf "$STAGE" || true
    kc_admin_done || true
    [[ -z "$PF_PID" ]] || kill "$PF_PID" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
# A signal before the bundle's COMMIT is 130 (nothing changed); after it (VERSION is set
# only once the database holds the version) it is 3, like every post-commit failure.
VERSION=""
on_signal() {
    if [[ -n "$VERSION" ]]; then
        echo "ERROR: interrupted: version $VERSION is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you> (a later ./apps/iam/deploy.sh does it itself)" >&2
        exit 3
    fi
    exit 130
}
trap on_signal INT TERM HUP

# python3 with no inherited break-glass variable: every compile here names its source.
py() {
    env -u MEDCEA_POLICY_FILE -u MEDCEA_POLICY_BREAK_GLASS -u MEDCEA_POLICY_BREAK_GLASS_EVENT \
        -u MEDCEA_POLICY_BREAK_GLASS_SHA256 -u MEDCEA_POLICY_ACCEPTED_SKELETON python3 "$@"
}
jget() {   # FILE EXPR — one value of a JSON document (EXPR over d), printed
    python3 -c 'import json, sys
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d})
print(json.dumps(v) if isinstance(v, (list, dict)) else ("" if v is None else v))' "$1" "$2"
}
POD=""
q() { _DBA_NS="$NAMESPACE" _DBA_POD="$POD" _dba_psql "$POSTGRES_DB" -q -tA -v ON_ERROR_STOP=1 "$@"; }

# ── Keycloak (read-only here: --by and who holds which role) ──────────────────────────
kc_start() {   # TRIES — the port-forward and an admin identity; 1 when Keycloak cannot be reached
    local i
    $KUBECTL port-forward svc/keycloak "$KC_PORT:80" -n "$NAMESPACE" &>/dev/null 9>&- &
    PF_PID=$!
    for ((i = 0; i < $1; i++)); do
        kc_admin_select && return 0
        sleep 2
    done
    return 1
}
kc_get() {   # PATH OUT — the body into OUT, the HTTP status on stdout (000: no answer)
    local code
    code="$(curl -s -o "$2" -w '%{http_code}' -H @<(_kc_bearer "$(kc_admin_token)") "$KC_URL/admin/$1" 2>/dev/null)" || true
    printf '%s' "${code:-000}"
}
BY_SUB="" BY_PERSON=""
resolve_by() {
    local enc code out
    enc="$(U="$BY" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["U"], safe=""))')"
    code="$(kc_get "realms/$KEYCLOAK_REALM/users?username=$enc&exact=true&briefRepresentation=false" "$STAGE/kc-by.json")"
    [[ "$code" == 200 ]] || die 2 "Keycloak's admin API answered HTTP $code for --by $BY: nothing was changed"
    out="$(py "$CHECK" by-user --in "$STAGE/kc-by.json" --username "$BY")" || exit 2
    BY_SUB="${out%%$'\t'*}"; BY_PERSON="${out#*$'\t'}"
    log "--by $BY: account $BY_SUB, person $BY_PERSON (a claim, recorded as claimed_by_*)"
}
fetch_accounts() {   # STAGE/accounts.json: every holder of a platform role, roles expanded
    local role code id
    mkdir -p "$STAGE/kc/users"
    for role in $(py -c 'import sys; sys.path.insert(0, sys.argv[1])
from compiler import source
print(" ".join(source.factory()["roles"]))' "$SCRIPT_DIR"); do
        code="$(kc_get "realms/$KEYCLOAK_REALM/roles/$role/users?first=0&max=10000" "$STAGE/kc/$role.json")"
        case "$code" in
            200) ;;
            404) echo '[]' > "$STAGE/kc/$role.json" ;;
            *) return 1 ;;
        esac
        # each holder in full (a brief representation has no person_id), once
        for id in $(python3 -c 'import json, sys; print(" ".join(u["id"] for u in json.load(open(sys.argv[1]))))' "$STAGE/kc/$role.json"); do
            [[ "$id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
            [[ -s "$STAGE/kc/users/$id.json" ]] && continue
            [[ "$(kc_get "realms/$KEYCLOAK_REALM/users/$id" "$STAGE/kc/users/$id.json")" == 200 ]] || return 1
        done
    done
    py "$CHECK" accounts --dir "$STAGE/kc" > "$STAGE/accounts.json"
}
someone_can_approve() {   # step 4: problems are WARNINGs (OA-b, G2)
    local line n=0
    py "$CLI" --defaults compile routes > "$STAGE/routes-now.json"
    if ! fetch_accounts; then
        warn "cannot read who holds the platform roles in Keycloak: who can approve policy changes is not checked"
        return 0
    fi
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        warn "$line"; n=$((n + 1))
    done < <(py "$CHECK" can-approve --dual-control "$STAGE/routes-now.json" --accounts "$STAGE/accounts.json")
    if ((n)); then
        warn "fix this in the User Manager before policy approvals arrive (IAM 4.5); version 1 goes on (OA-b)"
    else
        log "someone can approve: iam_policy and iam_users each have an approver of another person than every maker"
    fi
}

# ── the database ───────────────────────────────────────────────────────────────────────
STATE="$STAGE/state.json"
read_state() {   # [--full] — policy_db_state into $STATE; sets ST and POD
    ST="$(policy_db_state "$NAMESPACE" "$STATE" "$@")" || die 1 "cannot read the policy versions (above): nothing was changed"
    POD="$(_ps_doc_pod "$STATE")"   # POLICY_DB_POD is lost in the $(...) above
}
HEAD=""
check_chain() {   # verify_chain() and the head before anything is appended (step 3)
    local row ok hid hhash
    row="$(q -F'|' -c "SELECT (SELECT vc.ok FROM iam_policy.verify_chain() vc),
                              coalesce((SELECT h.event_id || '|' || h.hash FROM iam_policy.history h
                                         ORDER BY h.event_id DESC LIMIT 1), '|')" </dev/null)" \
        || die 1 "cannot read the policy history: nothing was changed"
    IFS='|' read -r ok hid hhash <<<"$(tr -d '[:space:]' <<<"$row")"
    [[ "$ok" == t ]] || die 1 "verify_chain() is false: the policy history was altered (./apps/iam/apply.sh --status); nothing was changed"
    HEAD="$hid:$hhash"
}
sysas() { jget "$STATE" '(d.get("system_functions") or {}).get("system_as")'; }
seed_queue() {   # step 3: flushed (a failure only warns: eligibility never depends on it, OA-b)
    local n
    n="$(python3 -c 'import sys
try:
    print(sum(1 for l in open(sys.argv[1]) if l.strip()))
except FileNotFoundError:
    print(0)' "$REPO_ROOT/state/seed-facts.jsonl" 2>/dev/null)" || n="?"
    if [[ "$n" == 0 ]]; then
        return 0
    elif $CHECK_ONLY; then
        log "$n queued account fact(s) in state/seed-facts.jsonl would be recorded (account_seeded)"
    elif ! _ps_flush_seed_facts "$NAMESPACE" "$POD" "$(sysas)"; then
        warn "the queued account facts stay in state/seed-facts.jsonl (the next deploy tries again); the bootstrap goes on"
    fi
}
confirm() {   # PROMPT WORD — unless MEDCEA_CONFIRMED=1 (the iam deploy, the guide after its own question)
    local a
    [[ "${MEDCEA_CONFIRMED:-}" == 1 ]] && return 0
    [[ -t 0 ]] || die 1 "refusing without a terminal to confirm on (or MEDCEA_CONFIRMED=1): nothing was changed"
    read -r -p "$1" a || a=""
    if [[ "$2" == y ]]; then [[ "$a" == y || "$a" == Y ]]; else [[ "$a" == "$2" ]]; fi \
        || { log "Aborted: nothing was changed."; exit 1; }
}
# after the COMMIT every failure is exit 3 (critique ops-9)
fail3() {
    err "$*"
    err "version ${VERSION:-?} is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you> (a later ./apps/iam/deploy.sh does it itself)"
    exit 3
}
verify_grants() {   # step 9: the grants just committed, and nothing else (design §6.1, G2)
    printf '%s\n' '# apps/iam/apply.sh step 9 (design §14.4.9): the grants the bundle committed' \
        'Database grants | iamgrants | $POSTGRES_DB |' > "$STAGE/verify.conf"
    "$REPO_ROOT/health-check.sh" -c "$STAGE/verify.conf" \
        || fail3 "version $VERSION is committed but the grants check failed (above)"
}
record() {   # EVENT [--resumed] — step 10 (no log hash: tee still writes the log, critique sec-13c)
    local ev="$1" id dg=()
    shift
    [[ -s "$STAGE/targets/digests.json" ]] && dg=(--digests "$STAGE/targets/digests.json")
    py "$CHECK" apply-record --event "$ev" --state "$STATE" --by-sub "$BY_SUB" --by-person "$BY_PERSON" \
        --log "${MEDCEA_LOG_FILE:-}" --commit "$COMMIT" --chain-head "$HEAD" "${dg[@]}" "$@" --out "$STAGE/record.sql" \
        || fail3 "cannot build the $ev record (above)"
    id="$(q -1 < "$STAGE/record.sql" | tr -d '[:space:]')" || id=""
    [[ "$id" =~ ^[0-9]+$ ]] || fail3 "could not record $ev in iam_policy.history (above)"
    log "version $VERSION recorded: $ev, event $id (chain head before the apply: ${HEAD%%:*})"
}
report() {   # step 11: printed, never changes the exit code
    printf '%s\n' '# apps/iam/apply.sh step 11 (design §14.4.9): report only' \
        'Access policy version    | iampolicy    | $POSTGRES_DB |' \
        'Policy artefacts         | iamartefacts | $NAMESPACE   |' > "$STAGE/report.conf"
    "$REPO_ROOT/health-check.sh" -c "$STAGE/report.conf" || true
}
live_digests() {   # step 6: the live route table and role_widening() against version 1's compile
    local want="$1" cm rc=0 row exists comment
    cm="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" \
             -o jsonpath='{.metadata.annotations.medcea/routes-digest}' 2>"$STAGE/cm.err")" || rc=$?
    if ((rc)); then
        grep -qiE 'NotFound|not found' "$STAGE/cm.err" \
            || die 1 "cannot read ConfigMap medcea-iam-lib: $(head -n1 "$STAGE/cm.err")"
        log "ConfigMap medcea-iam-lib: not deployed yet, not compared"
    elif [[ "$cm" != "$want" ]]; then
        die 1 "version 1 would not be what is live: the route table's digest is ${cm:-missing}, version 1 compiles to ${want:0:12}: run ./deploy-infra.sh and ./apps/database/deploy.sh from this commit first"
    else
        log "the live route table carries version 1's digest (${want:0:12})"
    fi
    row="$(q -F'|' -c "SELECT pg_catalog.to_regprocedure('medcea_auth.role_widening(text,text)') IS NOT NULL,
                              coalesce(pg_catalog.obj_description(pg_catalog.to_regprocedure('medcea_auth.role_widening(text,text)'),
                                                                  'pg_proc'), '')" </dev/null)" \
        || die 1 "cannot read medcea_auth.role_widening()'s comment: nothing was changed"
    IFS='|' read -r exists comment <<<"$row"
    if [[ "$exists" != t ]]; then
        log "medcea_auth.role_widening(): not compiled yet, not compared"
    elif [[ "$(tr -d '\n' <<<"$comment")" != "policy $want" ]]; then
        die 1 "version 1 would not be what is live: medcea_auth.role_widening() says '${comment:-no comment}', version 1 compiles to policy ${want:0:12}: run ./deploy-infra.sh and ./apps/database/deploy.sh from this commit first"
    else
        log "medcea_auth.role_widening() carries version 1's digest"
    fi
}

COMMIT="unknown" VERSION=""

# =============================================================================
# --status (read-only, no lock)
# =============================================================================
if [[ "$MODE" == status ]]; then
    unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS
    read_state --full
    [[ "$ST" == unreachable ]] && die 1 "PostgreSQL is not Ready: $(jget "$STATE" 'd.get("detail")')"
    gate=()
    if [[ "$ST" == version-* ]]; then
        rc=0
        py "$CLI" skeleton-gate --state "$STATE" --check >"$STAGE/gate.json" 2>"$STAGE/gate.err" || rc=$?
        if ((rc == 3 || rc == 2)); then sed 's/^/  /' "$STAGE/gate.err"; fi
        gate=(--gate "$STAGE/gate.json" --gate-rc "$rc")
    fi
    live=()
    if _ps_kubectl_usable; then
        lr="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.medcea/routes-digest}' 2>/dev/null)" || lr=""
        lm="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.medcea/mqtt-digest}' 2>/dev/null)" || lm=""
        live=(--live-routes "$lr" --live-mqtt "$lm")
    fi
    py "$CHECK" status --state "$STATE" "${gate[@]}" "${live[@]}"
    if kc_start 3 && fetch_accounts; then
        py "$CLI" --defaults compile routes > "$STAGE/routes-now.json"
        probs="$(py "$CHECK" can-approve --dual-control "$STAGE/routes-now.json" --accounts "$STAGE/accounts.json")"
        echo "who can approve: ${probs:-iam_policy and iam_users each have an approver of another person than every maker}"
    else
        echo "who can approve: Keycloak not reachable, not shown"
    fi
    exit 0
fi

# =============================================================================
# --bootstrap (design §14.4.9, the bootstrap column)
# =============================================================================
if [[ "$MODE" == bootstrap ]]; then
    log "Policy bootstrap: version 1 from apps/iam/policy/defaults.yaml$($CHECK_ONLY && echo ' (--check-only: nothing is written)')"
    # 2. the state, the host file, break-glass, the tree; no gate (nothing is accepted yet)
    read_state
    case "$ST" in
        empty) ;;
        none) die 2 "the bootstrap waits: $(jget "$STATE" 'd.get("detail")') (no migration 008c: ./apps/database/deploy.sh)" ;;
        unreachable) die 2 "the bootstrap waits: PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")'))" ;;
        *) die 2 "policy versions exist: --bootstrap is only for an empty iam_policy.version; see ./apps/iam/apply.sh --status" ;;
    esac
    pres="$(_ps_host_present)" || die 1 "cannot read state/ (above): run as the account that deploys the platform"
    [[ "$pres" == absent ]] || die 2 "state/policy-applied.yaml exists but the database has no applied version: after a restore see docs/manual (admin: Policy source) and backups.sh restore-help step 2a"
    [[ -z "${MEDCEA_POLICY_FILE:-}" ]] || die 2 "no bootstrap under break-glass: version 1 is the committed factory policy (unset MEDCEA_POLICY_FILE)"
    COMMIT="$(py -c 'import sys; sys.path.insert(0, sys.argv[1])
from compiler import source
print(source.git_commit())' "$SCRIPT_DIR")"
    case "$COMMIT" in
        *-dirty) die 1 "apps/iam has uncommitted changes: version 1 is the committed factory policy; commit or stash them first" ;;
        unknown) warn "no git commit can be read (no .git): version 1 is recorded with git_commit unknown" ;;
    esac
    log "state empty, no host file, tree $COMMIT"
    # 3. the chain, the seed queue, --by
    check_chain
    seed_queue
    kc_start 12 || die 2 "Keycloak's admin API cannot be reached (port-forward on $KC_PORT): the bootstrap waits; health FAILs 'no applied version' until a later ./apps/iam/deploy.sh"
    resolve_by
    # 4. someone can approve (a WARNING only, OA-b)
    someone_can_approve
    # 5. the checker and every target from three sources
    py "$CLI" --defaults check >/dev/null || die 1 "defaults.yaml fails the checker (python3 apps/iam/compiler/cli.py --defaults check): nothing was changed"
    py "$CLI" bootstrap-targets --out "$STAGE/targets" > "$STAGE/targets.json" || die 1 "nothing was changed"
    WANT="$(jget "$STAGE/targets.json" 'd["routes_digest"]')"
    # 6. the diff: none (step 5), and the two live content digests
    live_digests "$WANT"
    if $CHECK_ONLY; then
        log "would bootstrap version 1 (entries_digest $(jget "$STAGE/targets.json" 'd["entries_digest"]')), $(jget "$STAGE/targets.json" 'd["targets"]') targets identical, live routes and grants digests equal"
        exit 0
    fi
    log "version 1 compiles to exactly what defaults.yaml compiles to ($(jget "$STAGE/targets.json" 'd["targets"]') targets): nothing is re-rendered"
    confirm "Version 1 is a permanent record of the access policy, claimed by $BY. Type yes to bootstrap it: " yes
    # 7. one transaction
    py "$CHECK" bundle-sql --kind bootstrap --state "$STAGE/targets/sim-state.json" --by-sub "$BY_SUB" \
        --by-person "$BY_PERSON" --log "${MEDCEA_LOG_FILE:-}" --commit "$COMMIT" \
        --digests "$STAGE/targets/digests.json" --out "$STAGE/bundle" || die 1 "cannot build the bundle (above): nothing was changed"
    rc=0
    DBA_ACTOR=system:apply dba_policy_bundle "$NAMESPACE" "$POD" auto "$STAGE/bundle/pre.sql" "$STAGE/bundle/post.sql" --with-functions || rc=$?
    case $rc in
        0) ;;
        3) die 2 "the bootstrap waits (above): nothing was changed" ;;
        *)
            # psql runs through kubectl exec: a stream that broke after the COMMIT reached
            # PostgreSQL also fails here. Ask the database before saying nothing changed.
            ST2="$(policy_db_state "$NAMESPACE" "$STAGE/after.json")" || ST2=error
            case "$ST2" in
                empty) die 1 "the bootstrap bundle was rolled back (above): nothing was changed" ;;
                version-*|partial)
                    VERSION="${ST2#version-}"; [[ "$ST2" == partial ]] && VERSION=1
                    fail3 "the bundle reported a failure (above), but the database holds the version: its COMMIT reached PostgreSQL" ;;
                *) die 1 "the bootstrap bundle failed (above) and the database cannot tell now whether it committed ($ST2): run ./apps/iam/apply.sh --status before anything else" ;;
            esac ;;
    esac
    VERSION=1
    # from here every failure is exit 3
    ST2="$(policy_db_state "$NAMESPACE" "$STATE")" || fail3 "cannot read the policy versions after the commit"
    [[ "$ST2" == version-1 ]] || fail3 "after the commit the database answers $ST2, not version-1"
    py "$CLI" write-applied --state "$STATE" || fail3 "cannot write state/policy-applied.yaml (above)"
    py "$CLI" bootstrap-targets --out "$STAGE/targets" --source host || fail3 "the written host file does not compile to version 1 (above)"
    # 8. artefacts: none (step 6 proved nothing changes)
    # 9. the grants just committed
    verify_grants
    # 10. the record
    record bootstrap_applied
    # 11. the report
    report
    log "version 1 (bootstrap) applied: nothing was re-rendered. qa confirms it in the Policy UI once it exists (IAM 4.3)."
    exit 0
fi

# The reason as recorded (design §14.7.6): the --by username and the OS user appended, the only
# place they are kept (the database functions take neither); into a file, never on argv.
reason_file() {   # MODE-FLAG — $STAGE/reason
    printf '%s [apply.sh --%s, --by %s (claimed), OS user %s]' "$REASON" "$1" "$BY" "$(id -un)" > "$STAGE/reason"
}

# =============================================================================
# --propose-skeleton (IAM 4.4, design §14.7.6): a git skeleton that widens access becomes a
# submitted version of kind skeleton; qa approves it in the Policy UI, 4.5 applies it
# =============================================================================
if [[ "$MODE" == propose-skeleton ]]; then
    log "Skeleton proposal from $REV$($CHECK_ONLY && echo ' (--check-only: nothing is written)')"
    # 1. the revision (the compiler stays this tree's)
    COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "$REV^{commit}" 2>/dev/null)" \
        || die 2 "--from-git $REV: no such commit in this repository"
    # 2. the state (the full document: the open versions), then the chain
    read_state --full
    case "$ST" in
        version-*) VERSION="" ;;
        none|empty) die 2 "no applied version: ./apps/iam/deploy.sh bootstraps it" ;;
        partial) die 2 "policy versions exist but none is applied: ./apps/iam/apply.sh --status" ;;
        unreachable) die 1 "PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")')): nothing was changed" ;;
        *) die 1 "cannot read the policy versions ($ST): nothing was changed" ;;
    esac
    LAST="$(jget "$STATE" '(d.get("last_apply_event") or {}).get("event", "")')"
    case "$LAST" in
        apply_started|partial_apply)
            die 1 "version ${ST#version-} is being applied ($LAST): wait for apply.sh, or run ./apps/iam/apply.sh --resume first; nothing was changed" ;;
    esac
    check_chain
    # 3. --by, before anything uses the proposer
    kc_start 12 || die 2 "Keycloak's admin API cannot be reached (port-forward on $KC_PORT): nothing was changed"
    resolve_by
    py "$CLI" --defaults compile routes > "$STAGE/routes-now.json"
    if [[ "$(kc_get "realms/$KEYCLOAK_REALM/users/$BY_SUB/role-mappings/realm/composite" "$STAGE/kc-by-roles.json")" == 200 ]]; then
        w="$(py "$CHECK" maker-warn --dual-control "$STAGE/routes-now.json" --roles "$STAGE/kc-by-roles.json" --username "$BY")"
        [[ -z "$w" ]] || warn "$w"
    else
        warn "cannot read --by $BY's realm roles in Keycloak: whether it holds a maker role of iam_policy is not checked"
    fi
    # 4. the gate, the checker, the open version, the diff and its transaction (apply_check.py)
    NEXT="$(q -c "SELECT coalesce(max(x.version), 0) + 1 FROM iam_policy.version x" </dev/null | tr -d '[:space:]')" \
        || die 1 "cannot read the policy versions: nothing was changed"
    [[ "$NEXT" =~ ^[1-9][0-9]*$ ]] || die 1 "cannot read the next version number ('$NEXT'): nothing was changed"
    reason_file propose-skeleton
    out=()
    $CHECK_ONLY || out=(--out "$STAGE/propose.sql")
    rc=0
    py "$CHECK" propose --state "$STATE" --rev "$REV" --commit "$COMMIT" --by-sub "$BY_SUB" --by-person "$BY_PERSON" \
        --reason-file "$STAGE/reason" --version "$NEXT" "${out[@]}" || rc=$?
    ((rc == 0)) || exit "$rc"
    if $CHECK_ONLY; then
        log "would submit skeleton version $NEXT for qa's approval (claimed by $BY)"
        exit 0
    fi
    # 5. a [y/N]: withdrawing or returning closes the version
    confirm "Submit skeleton version $NEXT (commit ${COMMIT:0:12}) for qa's approval, claimed by $BY? [y/N] " y
    # 6. one transaction as postgres, actor system:apply; the proposer is the claimed --by
    v="$(q -1 -f - < "$STAGE/propose.sql" | tr -d '[:space:]')" \
        || die 1 "the proposal was rolled back (above): nothing was changed (./apps/iam/apply.sh --status)"
    [[ "$v" == "$NEXT" ]] || die 1 "the proposal answered '$v', not version $NEXT (above): ./apps/iam/apply.sh --status"
    # 7. the report
    log "version $NEXT (skeleton) submitted: a qa person other than $BY, who did not run this proposal, approves it in the Policy UI (Approval); applying it arrives with IAM 4.5 (./apps/iam/apply.sh $NEXT); until then the change stays on $REV's branch."
    exit 0
fi

# =============================================================================
# --withdraw-open (IAM 4.4, design §14.7.6): the host path when the Policy UI cannot
# withdraw (a rollback of 4.4, an aborted live test). No Keycloak: withdrawing grants nothing.
# =============================================================================
if [[ "$MODE" == withdraw-open ]]; then
    log "Withdraw the open policy version$($CHECK_ONLY && echo ' (--check-only: nothing is written)')"
    read_state --full
    [[ "$ST" == unreachable ]] && die 1 "PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")')): nothing was changed"
    OPEN="$(py "$CHECK" open-version --state "$STATE")" || die 1 "cannot read the open versions (above): nothing was changed"
    if [[ -z "$OPEN" ]]; then
        log "nothing is open: no change or skeleton version to withdraw"
        exit 0
    fi
    IFS=$'\t' read -r OV OKIND OSTATUS OREASON OAUTHORS <<<"$OPEN"
    [[ "$OV" =~ ^[1-9][0-9]*$ ]] || die 1 "cannot read the open version ('$OV'): nothing was changed"
    log "open: version $OV ($OKIND, $OSTATUS), reason: $OREASON"
    log "      authors: $OAUTHORS"
    if $CHECK_ONLY; then
        log "would withdraw version $OV (system:apply)"
        exit 0
    fi
    confirm "Withdraw version $OV ($OKIND, $OSTATUS)? [y/N] " y
    reason_file withdraw-open
    py "$CHECK" withdraw-sql --version "$OV" --reason-file "$STAGE/reason" --out "$STAGE/withdraw.sql" \
        || die 1 "cannot build the withdraw (above): nothing was changed"
    w="$(q -1 -f - < "$STAGE/withdraw.sql" | tr -d '[:space:]')" \
        || die 1 "the withdraw was rolled back (above): nothing was changed"
    [[ "$w" == "$OV" ]] || die 1 "the withdraw answered '$w', not version $OV (above): ./apps/iam/apply.sh --status"
    log "version $OV withdrawn (system:apply)"
    exit 0
fi

# =============================================================================
# --resume (design §14.4.9): finish an apply whose COMMIT happened but whose record did not
# =============================================================================
[[ -z "${MEDCEA_POLICY_FILE:-}" ]] || die 2 "no resume under break-glass (unset MEDCEA_POLICY_FILE)"
log "Policy resume$($CHECK_ONLY && echo ' (--check-only: nothing is written)')"
read_state
case "$ST" in
    version-*) VERSION="${ST#version-}" ;;
    unreachable) die 1 "PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")')): nothing was changed" ;;
    partial) die 2 "policy versions exist but none is applied: ./apps/iam/apply.sh --status" ;;
    *) log "nothing to resume: no applied version ($ST)"; exit 0 ;;
esac
KIND="$(jget "$STATE" 'd.get("kind")')"
LAST="$(jget "$STATE" '(d.get("last_apply_event") or {}).get("event", "")')"
case "$LAST" in
    apply_started) ;;
    apply_deferred) log "version $VERSION has a deferred target (apply_deferred): re-rendering it now" ;;
    partial_apply) die 2 "version $VERSION ended in partial_apply: resuming it arrives with IAM 4.5" ;;
    *)
        py "$CHECK" health --state "$STATE" --host-file "$REPO_ROOT/state/policy-applied.yaml" 2>/dev/null \
            | grep -E '^(FAIL|WARN)\|' | grep -i 'policy-applied' | sed 's/^[A-Z]*|/  host file: /' || true
        log "nothing to resume (latest: ${LAST:-none} $(jget "$STATE" '(d.get("last_apply_event") or {}).get("event_id", "")'))"
        exit 0 ;;
esac
rc=0
py "$CLI" skeleton-gate --state "$STATE" --check >"$STAGE/gate.json" || rc=$?
case $rc in
    0) [[ "$(jget "$STAGE/gate.json" 'd["verdict"]')" == equal ]] \
           || die 1 "the git skeleton narrows over the accepted one: a deploy accepts it first (./apps/iam/deploy.sh runs --resume after its own gate)" ;;
    3) die 1 "the git skeleton widens over the accepted one (above): nothing was changed" ;;
    *) die 1 "the skeleton gate refused the git skeleton or could not be computed (above): nothing was changed" ;;
esac
COMMIT="$(py -c 'import sys; sys.path.insert(0, sys.argv[1])
from compiler import source
print(source.git_commit())' "$SCRIPT_DIR")"
check_chain
kc_start 12 || die 2 "Keycloak's admin API cannot be reached (port-forward on $KC_PORT): nothing was changed"
resolve_by
EVENT=applied
[[ "$KIND" == bootstrap ]] && EVENT=bootstrap_applied
if $CHECK_ONLY; then
    log "would finish version $VERSION ($KIND): the host file, the grants check and the $EVENT record"
    exit 0
fi
confirm "Finish the apply of version $VERSION ($KIND), claimed by $BY? [y/N] " y
# 7. the database is committed: the host file from the current state, then its compile
py "$CLI" write-applied --state "$STATE" --if-different || fail3 "cannot write state/policy-applied.yaml (above)"
if [[ "$KIND" == bootstrap ]]; then
    # the reference is the committed version itself (its rows from the database), never the
    # current defaults.yaml: a matrix edit in git since the commit must not block the resume
    py "$CLI" bootstrap-targets --out "$STAGE/targets" --state "$STATE" > "$STAGE/targets.json" \
        || fail3 "version $VERSION cannot be compiled from the database's rows (above)"
    py "$CLI" bootstrap-targets --out "$STAGE/targets" --source host || fail3 "the written host file does not compile to version $VERSION (above)"
fi
# 8. the artefacts (IAM 4.2b): every scoped mode under this lock, each re-rendering only
# what drifted from version $VERSION's compile; the wizard's exit 4 (a flash running) is
# recorded as apply_deferred and closed by the next --resume. grants: step 9.
DEFERRED=()
while IFS= read -r cmd; do
    [[ -n "$cmd" ]] || continue
    log "step 8: $cmd"
    rc=0
    # shellcheck disable=SC2086  # "./path --mode": the command and its one option
    MEDCEA_CONFIRMED=1 "$REPO_ROOT/"${cmd#./} </dev/null || rc=$?
    case $rc in
        0) ;;
        4) DEFERRED+=("$cmd") ;;
        *) fail3 "$cmd failed (exit $rc): version $VERSION is committed; fix the cause above and run --resume again" ;;
    esac
done < <(py "$CHECK" owners --scoped)
# 9. the grants, and the artefacts reported
verify_grants
printf '%s\n' 'Policy artefacts | iamartefacts | $NAMESPACE |' > "$STAGE/artefacts.conf"
if ! "$REPO_ROOT/health-check.sh" -c "$STAGE/artefacts.conf"; then
    warn "the live artefacts are still not version $VERSION's compile after the scoped modes; a full deploy re-renders them (in this order):"
    py "$CHECK" owners --deploys | sed 's/^/  /' >&2
fi
# 10. the record, then each deferral after it (open until the next applied record)
record "$EVENT" --resumed
for cmd in "${DEFERRED[@]}"; do
    py "$CHECK" deferred-record --state "$STATE" --target "$(basename "$(dirname "${cmd%% *}")")" \
        --reason "an onboarding run is in progress" --command "$cmd" --out "$STAGE/deferred.sql" \
        || fail3 "cannot build the apply_deferred record (above)"
    id="$(q -1 < "$STAGE/deferred.sql" | tr -d '[:space:]')" || id=""
    [[ "$id" =~ ^[0-9]+$ ]] || fail3 "could not record apply_deferred in iam_policy.history (above)"
    warn "deferred: $cmd (apply_deferred, event $id): run ./apps/iam/apply.sh --resume --by <you> once the onboarding run has finished"
done
report
log "version $VERSION ($KIND): the apply is finished."
