#!/usr/bin/env bash
# apps/iam/apply.sh — versions of the access policy (IAM Phase 4; design §6, §14.4.9).
#
# As of slice 4.2a:
#   apply.sh --bootstrap --by <username> [--check-only]   version 1, only while iam_policy.version
#                                                         is empty (apps/iam/deploy.sh runs it)
#   apply.sh --resume --by <username> [--check-only]      finish an apply that did not record its end
#   apply.sh --status                                     read-only
#
# As of slice 4.5 (design §14.8):
#   apply.sh <N> --by <username> [--check-only]           apply change or skeleton version N,
#                                                         approved by qa in the Policy UI
#   apply.sh --rollback-to <K> --by <username> --reason "<text>" [--check-only]
#                                                         restore version K as a new version of
#                                                         kind rollback (OA-c); qa confirms it
#   apply.sh --audit <N>                                  read-only: cli.py audit-version on N
#
# <N> proves on the host what the database cannot, before anything changes: the approval's
# token is a realm signature (RS256, stdlib, apply_check.py verify_rs256) with the claims of
# §14.8.5; the approver is eligible now in Keycloak (enabled, an approver role, the approved
# person_id, no author's person, no enabled maker's person: OA-b, I17), read again right
# before the bundle (step 6c); the version widens no role an account of the approver's
# person holds (S-B4); the recomputed diff is byte for byte the approved one (G8); and the
# file the bundle compiles is version N's rows (staged in this run's mode-700 directory,
# bound to the database rows, pinned by sha256: cli.py --staged through DBA_STAGED,
# §14.8.4.1). A step-9 check FAILing before the apply refuses it (exit 2: fix it first).
# Then one transaction commits the version with its grants and functions compiled from it;
# after the COMMIT the host file is rewritten, every scoped mode re-renders what drifted
# (IAM 4.2b) and step 9's nine checks run against that baseline, up to 3 attempts 20 s
# apart. A change or rollback version whose rollout still fails is reverted (a second
# bundle puts the previous version back, files partial_apply {reverting} under it, re-renders
# it, then partial_apply {reverted} under N and applied {reverted_from} under the previous:
# exit 1); a skeleton version is never reverted (partial_apply {mixed}, exit 3, --resume
# converges forward). Every post-commit state, a revert's included, is resumable.
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
# while the version waits. Once qa approves it, HEAD is moved to that commit and apply.sh N
# applies it (the gate's exception admits exactly that digest, IAM 4.5).
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
# Exit codes: 0 done; 1 refused before the commit, or failed, with nothing changed (4.5: also a
# step 8/9 failure fully reverted); 2 usage or a precondition (the bootstrap waits: no migration
# 008c, Keycloak down, an unknown --by, config.env and the database disagree on IAM_DB_ROLES;
# 4.5: no applied version, an unknown commit, a narrowing git skeleton, a step-9 check already
# failing); 3 any failure after the bundle's COMMIT: the version exists, `apply.sh --resume --by
# <you>` finishes it (the iam deploy does so itself after apply_started); 130 a signal before it.
#
# Logging and the lock (CLAUDE.md): it logs first in every mode (logs/apply-policy-<ts>.log, or
# the parent's log). The writing modes take the deploy lock (inherited from the iam deploy or the
# guide, then verified); --status, --audit and --check-only take none and write nothing (no
# queue flush, no file, no database write; 4.5's --check-only sends only READ ONLY transactions
# and writes only its mode-700 stage). Secrets never reach argv or the log: the Keycloak admin
# token goes to curl as a header on a pipe, the database password never leaves its pod, the
# stored approval token is read into the stage and never printed.

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
  apps/iam/apply.sh <N> --by <username> [--check-only]
        apply change or skeleton version N, approved by qa in the Policy UI
  apps/iam/apply.sh --rollback-to <K> --by <username> --reason "<text>" [--check-only]
        restore version K as a new rollback version; a qa person confirms it afterwards
  apps/iam/apply.sh --audit <N>
        re-check applied version N offline (cli.py audit-version; read-only)

--by is the username (realm $KEYCLOAK_REALM) of the person who applies: a claim on the record.
Exit: 0 done, 1 refused or failed (nothing changed; a reverted apply), 2 usage or a precondition
(the bootstrap waits; fix a failing check first), 3 committed but not finished (run --resume;
never for --propose-skeleton or --withdraw-open), 130 interrupted before the commit.
EOF
}

MODE="" NUM="" BY="" CHECK_ONLY=false ERR="" REASON="" REASON_SET=false REV="" REV_SET=false
ONE="give one of <N>, --rollback-to, --audit, --bootstrap, --resume, --status, --propose-skeleton, --withdraw-open"
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --bootstrap|--resume|--status|--propose-skeleton|--withdraw-open)
            [[ -z "$MODE" ]] || ERR="$ONE"
            MODE="${1#--}" ;;
        --rollback-to|--audit)
            [[ -z "$MODE" ]] || ERR="$ONE"
            MODE="${1#--}"
            if (($# < 2)); then ERR="$1 needs a version number"; else NUM="$2"; shift; fi ;;
        --rollback-to=*|--audit=*)
            [[ -z "$MODE" ]] || ERR="$ONE"
            MODE="${1%%=*}"; MODE="${MODE#--}"; NUM="${1#*=}" ;;
        [0-9]*)
            [[ -z "$MODE" ]] || ERR="$ONE"
            MODE=apply NUM="$1" ;;
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

if [[ -n "$ERR" || -z "$MODE" ]]; then
    usage >&2
    die 2 "${ERR:-$ONE}"
fi
if [[ -n "$NUM" || "$MODE" == apply || "$MODE" == rollback-to || "$MODE" == audit ]]; then
    [[ "$NUM" =~ ^[1-9][0-9]{0,8}$ ]] || die 2 "'$NUM' is not a version number (1 to 999999999)"
fi
if [[ "$MODE" == status || "$MODE" == audit ]]; then
    [[ -z "$BY" && "$CHECK_ONLY" == false ]] || die 2 "--$MODE takes no --by and no --check-only"
elif [[ ! "$BY" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]*$ ]]; then
    [[ "$MODE" == apply ]] && die 2 "apply.sh $NUM needs --by <username> (letters, digits, . _ @ -; not starting with -)"
    die 2 "--$MODE needs --by <username> (letters, digits, . _ @ -; not starting with -)"
fi
case "$MODE" in
    rollback-to)
        # the reason reaches psql only base64 in a \set variable (apply_check.py), never on argv
        [[ -n "${REASON//[[:space:]]/}" && "$REASON" != -* ]] \
            || die 2 "--rollback-to needs --reason \"<text>\" (not empty, not starting with -)"
        $REV_SET && die 2 "--rollback-to takes no --from-git" ;;
    apply)
        # the approval carries the reason (design §14.8.2)
        { $REASON_SET || $REV_SET; } && die 2 "apply.sh $NUM takes no --reason and no --from-git: the approval carries the reason" ;;
    audit)
        { $REASON_SET || $REV_SET; } && die 2 "--audit takes no --reason and no --from-git" ;;
esac
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
    bootstrap|resume|status)
        { $REASON_SET || $REV_SET; } && die 2 "--reason and --from-git belong to --propose-skeleton, --withdraw-open and --rollback-to" ;;
esac
WRITES=false
[[ "$MODE" != status && "$MODE" != audit && "$CHECK_ONLY" == false ]] && WRITES=true

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
KEYCLOAK_DOMAIN="${KEYCLOAK_DOMAIN:-keycloak.${DOMAIN:-}}"
ISSUER="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM"   # infra/lib-policy-artefacts.sh's
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
# IAM 4.5 (design §14.8.6): BUNDLE_SENT is set just before each bundle, so a signal that
# arrived while one ran asks the database what it holds (BUNDLE_TARGET: the version the
# bundle makes applied; BUNDLE_FROM: the one applied before it); PHASE names the version
# --resume finishes (forward: VERSION; reverting: PREV, the version a revert puts back).
BUNDLE_SENT="" BUNDLE_TARGET="" BUNDLE_FROM="" PHASE=forward PREV=""
VERSION=""
on_signal() {
    local st
    if [[ -n "$BUNDLE_SENT" ]]; then
        st="$(policy_db_state "$NAMESPACE" "$STAGE/signal.json" 2>/dev/null)" || st=error
        if [[ "$st" == "version-$BUNDLE_TARGET" ]]; then
            echo "ERROR: interrupted: the bundle's COMMIT reached PostgreSQL; version $BUNDLE_TARGET is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you>" >&2
            exit 3
        elif [[ "$st" == "version-$BUNDLE_FROM" || ( -z "$BUNDLE_FROM" && "$st" == empty ) ]]; then
            if [[ -n "$VERSION" ]]; then   # the revert bundle was rolled back: the version stays applied
                echo "ERROR: interrupted: the revert was rolled back; version $VERSION is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you>" >&2
                exit 3
            fi
            echo "ERROR: interrupted: the bundle was rolled back: nothing was changed" >&2
            exit 130
        fi
        echo "ERROR: interrupted while the bundle ran, and the database cannot tell now whether it committed ($st): run ./apps/iam/apply.sh --status before anything else" >&2
        exit 1
    fi
    if [[ -n "$VERSION" ]]; then
        if [[ "$PHASE" == reverting ]]; then
            echo "ERROR: interrupted: the revert of version $VERSION to version $PREV is committed but not finished: ./apps/iam/apply.sh --resume --by <you> finishes version $PREV" >&2
        else
            echo "ERROR: interrupted: version $VERSION is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you> (a later ./apps/iam/deploy.sh does it itself)" >&2
        fi
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
fetch_accounts() {   # [DIR [SKELETON]] — DIR/accounts.json (default $STAGE/kc; also $STAGE/accounts.json):
    # every holder of a role of SKELETON (a JSON skeleton; default the git tree's), roles expanded
    local d="${1:-$STAGE/kc}" skel="${2:-}" role code id roles
    mkdir -p "$d/users"
    if [[ -n "$skel" ]]; then
        roles="$(python3 -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["roles"]))' "$skel")" || return 1
    else
        roles="$(py -c 'import sys; sys.path.insert(0, sys.argv[1])
from compiler import source
print(" ".join(source.factory()["roles"]))' "$SCRIPT_DIR")" || return 1
    fi
    for role in $roles; do
        code="$(kc_get "realms/$KEYCLOAK_REALM/roles/$role/users?first=0&max=10000" "$d/$role.json")"
        case "$code" in
            200) ;;
            404) echo '[]' > "$d/$role.json" ;;
            *) KC_CODE="$code"; return 1 ;;
        esac
        # each holder in full (a brief representation has no person_id), once
        for id in $(python3 -c 'import json, sys; print(" ".join(u["id"] for u in json.load(open(sys.argv[1]))))' "$d/$role.json"); do
            [[ "$id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
            [[ -s "$d/users/$id.json" ]] && continue
            code="$(kc_get "realms/$KEYCLOAK_REALM/users/$id" "$d/users/$id.json")"
            [[ "$code" == 200 ]] || { KC_CODE="$code"; return 1; }
        done
    done
    py "$CHECK" accounts --dir "$d" ${skel:+--skeleton "$skel"} > "$d/accounts.json" || return 1
    [[ "$d" != "$STAGE/kc" ]] || cp "$d/accounts.json" "$STAGE/accounts.json"
}
KC_CODE=""
kc_dump() {   # DIR MODE — step 4's Keycloak reads (design §14.8.5): the holders of every role of
    # $STAGE/acc-skel.json in full; with MODE apply also the approver (users/<sub> and its
    # effective realm roles: it may hold its role through a composite, or have lost it), each
    # author sub's account now (its person_id) and every role's composites. 1 on any answer
    # other than 200 (404 for the approver or an author: the account is gone, a fact).
    local d="$1" mode="$2" sub code r
    rm -rf "$d"
    mkdir -p "$d/authors" "$d/composites"
    cp "$STAGE/acc-skel.json" "$d/skeleton.json"
    fetch_accounts "$d" "$d/skeleton.json" || return 1
    [[ "$mode" == apply ]] || return 0
    sub="$(jget "$DOC" '(d.get("version") or {}).get("approved_by_sub") or ""')"
    if [[ "$sub" =~ ^[0-9a-fA-F-]{36}$ ]]; then
        code="$(kc_get "realms/$KEYCLOAK_REALM/users/$sub" "$d/approver.json")"
        case "$code" in
            200) code="$(kc_get "realms/$KEYCLOAK_REALM/users/$sub/role-mappings/realm/composite" "$d/approver-roles.json")"
                 [[ "$code" == 200 ]] || { KC_CODE="$code"; return 1; } ;;
            404) rm -f "$d/approver.json" ;;
            *) KC_CODE="$code"; return 1 ;;
        esac
    fi
    for sub in $(jget "$DOC" '" ".join(str(a.get("sub")) for a in d.get("authors") or [] if a.get("sub"))'); do
        [[ "$sub" =~ ^[0-9a-fA-F-]{36}$ ]] || continue
        code="$(kc_get "realms/$KEYCLOAK_REALM/users/$sub" "$d/authors/$sub.json")"
        case "$code" in
            200) ;;
            404) rm -f "$d/authors/$sub.json" ;;
            *) KC_CODE="$code"; return 1 ;;
        esac
    done
    for r in $(jget "$d/skeleton.json" '" ".join(r for r, x in (d.get("roles") or {}).items() if (x or {}).get("includes"))'); do
        code="$(kc_get "realms/$KEYCLOAK_REALM/roles/$r/composites" "$d/composites/$r.json")"
        [[ "$code" == 200 ]] || { KC_CODE="$code"; return 1; }
    done
}
fetch_jwks() {   # OUT — the realm's RS256 signing keys now (the certs endpoint, no admin token)
    local code
    code="$(curl -s -o "$STAGE/certs.json" -w '%{http_code}' "$KC_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/certs" 2>/dev/null)" || true
    [[ "${code:-000}" == 200 ]] || die 2 "cannot read the realm's signing keys (HTTP ${code:-000}): nothing was changed"
    py "$CHECK" signing-keys --in "$STAGE/certs.json" --out "$1" || die 2 "cannot read the realm's signing keys: nothing was changed"
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
check_chain() {   # verify_chain() and the head before anything is appended (step 3), READ ONLY
    local row ok hid hhash
    row="$(q -F'|' <<'SQL'
BEGIN TRANSACTION READ ONLY;
SELECT (SELECT vc.ok FROM iam_policy.verify_chain() vc),
       coalesce((SELECT h.event_id || '|' || h.hash FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1), '|');
COMMIT;
SQL
)" || die 1 "cannot read the policy history: nothing was changed"
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
# after the COMMIT every failure is exit 3 (critique ops-9); the version --resume finishes is
# the one PHASE names (IAM 4.5: a revert puts PREV back)
fail3() {
    err "$*"
    if [[ "$PHASE" == reverting ]]; then
        err "the revert of version $VERSION to version $PREV is committed but not finished: ./apps/iam/apply.sh --resume --by <you> finishes version $PREV"
    elif [[ "$PHASE" == mixed ]]; then
        err "version $VERSION is committed but its rollout is not finished (partial_apply): ./apps/iam/apply.sh --resume --by <you> converges it"
    else
        err "version ${VERSION:-?} is committed but its apply is not finished: ./apps/iam/apply.sh --resume --by <you> (a later ./apps/iam/deploy.sh does it itself)"
    fi
    exit 3
}
verify_grants() {   # step 9: the grants just committed, and nothing else (design §6.1, G2)
    printf '%s\n' '# apps/iam/apply.sh step 9 (design §14.4.9): the grants the bundle committed' \
        'Database grants | iamgrants | $POSTGRES_DB |' > "$STAGE/verify.conf"
    "$REPO_ROOT/health-check.sh" -c "$STAGE/verify.conf" \
        || fail3 "version $VERSION is committed but the grants check failed (above)"
}
RECORD_DIGESTS=""
record() {   # EVENT [--resumed] [--extra F] — step 10 (the bootstrap and --resume: no log hash,
    # tee still writes the log, critique sec-13c; 4.5's --extra: the sha256 of a copy taken now)
    local ev="$1" id dg=()
    shift
    [[ -s "$STAGE/targets/digests.json" ]] && dg=(--digests "$STAGE/targets/digests.json")
    [[ -n "$RECORD_DIGESTS" ]] && dg=(--digests "$RECORD_DIGESTS")
    py "$CHECK" apply-record --event "$ev" --state "$STATE" --by-sub "$BY_SUB" --by-person "$BY_PERSON" \
        --log "${MEDCEA_LOG_FILE:-}" --commit "$COMMIT" --chain-head "$HEAD" "${dg[@]}" "$@" --out "$STAGE/record.sql" \
        || fail3 "cannot build the $ev record (above)"
    id="$(q -1 < "$STAGE/record.sql" | tr -d '[:space:]')" || id=""
    [[ "$id" =~ ^[0-9]+$ ]] || fail3 "could not record $ev in iam_policy.history (above)"
    log "recorded: $ev, event $id; chain head before the apply: $HEAD"
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

# ── IAM 4.5 (design §14.8) ─────────────────────────────────────────────────────────────
DOC="$STAGE/approval.json"
read_doc() {   # VERSION OUT [--audit] — the version document of step 3, one READ ONLY transaction
    py "$CHECK" approval-sql --version "$1" --out "$STAGE/doc.sql" "${@:3}" || die 1 "cannot build the version read"
    ( umask 077; q < "$STAGE/doc.sql" > "$2" ) || die 1 "cannot read version $1 (above): nothing was changed"
}
post_state() {   # WANT — after a COMMIT: the state again (fail3 unless version WANT is applied)
    local st
    st="$(policy_db_state "$NAMESPACE" "$STATE" --full)" || fail3 "cannot read the policy versions after the commit"
    [[ "$st" == "version-$1" ]] || fail3 "after the commit the database answers $st, not version-$1"
}
git_commit() {
    py -c 'import sys; sys.path.insert(0, sys.argv[1])
from compiler import source
print(source.git_commit())' "$SCRIPT_DIR"
}
reproducible_commit() {   # §14.8.2: <N> and --rollback-to record a commit audit-version can reproduce
    COMMIT="$(git_commit)"
    case "$COMMIT" in
        *-dirty) die 1 "apps/iam has uncommitted changes: a version is applied from a committed tree; commit or stash them first" ;;
        unknown) die 2 "cannot record a reproducible commit (no .git, or git failed): audit-version could not reproduce this apply; nothing was changed" ;;
    esac
}
host_file_first() {   # §14.8.4 step 2.3: the host file is the applied version's before anything is
    # staged, composed with the accepted skeleton (HEAD carries the proposed one for a
    # skeleton version); --check-only composes it the same way and writes nothing
    local out co=()
    $CHECK_ONLY && co=(--check-only)
    out="$(py "$CHECK" host-file --state "$STATE" "${co[@]}")" \
        || die 1 "cannot write state/policy-applied.yaml (above): nothing was changed"
    [[ -z "$out" || "$out" == *unchanged ]] || log "$out"
}
verify_run() {   # OUT [--drop=T]... — step 9's conf (nine checks) through health-check.sh; the results into OUT
    local out="$1"
    shift
    py "$CHECK" verify-conf --out "$STAGE/verify9.conf" "$@" || return 1
    "$REPO_ROOT/health-check.sh" -c "$STAGE/verify9.conf" > "$STAGE/verify9.log" 2>&1 || true
    sed 's/^/  /' "$STAGE/verify9.log"
    py "$CHECK" health-results --in "$STAGE/verify9.log" --out "$out" >/dev/null
}
WAIT_LAGGING=""
wait_routes() {   # DIGEST — every Ready pod of each service that checks routes reads routes.json of
    # DIGEST (design §14.8.6 step 8; the list of tests/iam-schema.sh); only a Deployment the API
    # answers NotFound for is skipped: any other error (the API down, a refusal) lags, so the
    # wait never passes unasked. Polled every 5 s up to MEDCEA_APPLY_ROUTES_WAIT (150) seconds;
    # 1 names the laggards.
    local want="$1" dc dep ctr js sel pods pod got n tries lag=() err="$STAGE/wait-routes.err"
    tries=$(( ${MEDCEA_APPLY_ROUTES_WAIT:-150} / 5 ))
    for ((n = 0; n <= tries; n++)); do
        lag=()
        for dc in scheduler:api monitor:api dbmgmt:api config-ui:recipe-fileserver access:api iam-api:iam-api; do
            dep="${dc%%:*}" ctr="${dc#*:}"
            if ! js="$($KUBECTL get deployment "$dep" -n "$NAMESPACE" -o json 2>"$err")"; then
                grep -q 'NotFound' "$err" 2>/dev/null || lag+=("$dep (unreadable)")
                continue
            fi
            sel="$(python3 -c 'import json, sys
m = (json.load(sys.stdin).get("spec") or {}).get("selector", {}).get("matchLabels") or {}
print(",".join(f"{k}={v}" for k, v in sorted(m.items())))' <<<"$js" 2>/dev/null)" || sel=""
            [[ -n "$sel" ]] || { lag+=("$dep (unreadable)"); continue; }
            if ! pods="$($KUBECTL get pods -n "$NAMESPACE" -l "$sel" -o json 2>/dev/null | python3 -c 'import json, sys
for p in json.load(sys.stdin).get("items") or []:
    if any(c.get("type") == "Ready" and c.get("status") == "True" for c in (p.get("status") or {}).get("conditions") or []):
        print(p["metadata"]["name"])' 2>/dev/null)"; then
                lag+=("$dep (pods unreadable)")
                continue
            fi
            for pod in $pods; do
                got="$($KUBECTL exec -n "$NAMESPACE" -c "$ctr" "$pod" -- cat /iam/routes.json 2>/dev/null \
                         | python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' 2>/dev/null)" || got=""
                [[ "$got" == "$want" ]] || lag+=("$pod")
            done
        done
        ((${#lag[@]})) || return 0
        ((n < tries)) && sleep 5
    done
    WAIT_LAGGING="routes.json on ${lag[*]}"
    return 1
}
DEFERRED=() DROPS=() FAILED_TARGETS=() ATTEMPTS=0
rollout() {   # ROUTES_DIGEST JUDGE — steps 8 and 9 (design §14.8.6): every scoped mode under this
    # lock (each a no-op where nothing drifted), wait_routes after deploy-infra's; a failed
    # command and every later one again, at most 3 attempts in all, 20 s apart. JUDGE judge:
    # step 9 against the baseline counts too (a counted FAIL runs step 8 again); report:
    # --resume's, which checks afterwards. Exit 4 of a command is a deferral (DEFERRED), whose
    # check leaves step 9 (DROPS). 0 done, 1 still failing (FAILED_TARGETS names what).
    local want="$1" judge="$2" cmds=() i start=0 rc failed attempt cmd c bad=()
    mapfile -t cmds < <(py "$CHECK" owners --scoped)
    DEFERRED=() DROPS=() FAILED_TARGETS=() ATTEMPTS=0
    for ((attempt = 1; attempt <= 3; attempt++)); do
        ATTEMPTS=$attempt failed=""
        for ((i = start; i < ${#cmds[@]}; i++)); do
            cmd="${cmds[$i]}"
            log "step 8${attempt:+ (attempt $attempt)}: $cmd"
            rc=0
            # shellcheck disable=SC2086  # "./path --mode": the command and its one option
            MEDCEA_CONFIRMED=1 "$REPO_ROOT/"${cmd#./} </dev/null || rc=$?
            case $rc in
                0) ;;
                4) if [[ ! " ${DEFERRED[*]} " == *" $cmd "* ]]; then
                       DEFERRED+=("$cmd")
                       c="$(py "$CHECK" deferred-check --command "$cmd")"
                       [[ -z "$c" ]] || DROPS+=("--drop=$c")
                   fi ;;
                *) failed="$cmd"; warn "$cmd failed (exit $rc)"; break ;;
            esac
            if [[ "$cmd" == "./deploy-infra.sh --policy-only" ]] && ! wait_routes "$want"; then
                failed="$WAIT_LAGGING"; warn "$WAIT_LAGGING lags behind ${want:0:12} after the wait"; break
            fi
        done
        start=$i
        if [[ -z "$failed" ]]; then
            [[ "$judge" == judge ]] || return 0
            log "step 9 (attempt $attempt): the checks of what the version changes"
            verify_run "$STAGE/verify-now.json" "${DROPS[@]}" || return 1
            mapfile -t bad < <(py "$CHECK" verify-judge --baseline "$STAGE/baseline.json" --now "$STAGE/verify-now.json" "${DROPS[@]}")
            ((${#bad[@]})) || return 0
            failed="step 9: ${bad[*]}"; start=0
            warn "step 9 FAILs that the baseline did not: ${bad[*]}"
        fi
        FAILED_TARGETS=("$failed")
        if ((attempt < 3)); then
            warn "attempt $attempt of 3 failed ($failed): again in 20 s"
            sleep 20
        fi
    done
    return 1
}
run_bundle() {   # FILE SHA256 DIR TARGET FROM — one dba_policy_bundle (actor system:apply) whose
    # grants and functions are compiled from FILE (cli.py --staged, its sha256 pinned; only
    # this run's verified lock may name it, §14.8.4.1). 0 committed; a failure asks the
    # database (psql runs through kubectl exec: a stream broken after the COMMIT also fails
    # here): FROM still applied → 1, TARGET applied → fail3 "its COMMIT reached PostgreSQL"
    # (design §14.8.4 step 7), unreadable → 2. 3: dba_policy_bundle's mode refusal.
    local rc=0 st
    BUNDLE_TARGET="$4" BUNDLE_FROM="$5" BUNDLE_SENT=1
    DBA_ACTOR=system:apply DBA_STAGED="$1" DBA_STAGED_BY="$MEDCEA_LOCK_HELD" DBA_STAGED_SHA256="$2" \
        dba_policy_bundle "$NAMESPACE" "$POD" auto "$3/pre.sql" "$3/post.sql" --with-functions || rc=$?
    if ((rc == 0)); then
        bundle_committed
        return 0
    fi
    ((rc == 3)) && { BUNDLE_SENT=""; return 3; }
    st="$(policy_db_state "$NAMESPACE" "$STAGE/after.json")" || st=error
    case "$st" in
        "version-$4") bundle_committed
                      fail3 "the bundle reported a failure (above), but the database holds version $4: its COMMIT reached PostgreSQL" ;;
        "version-$5") BUNDLE_SENT=""
                      return 1 ;;
    esac
    BUNDLE_SENT=""
    return 2
}
bundle_committed() {   # what on_signal and fail3 name once a bundle committed, set before
    # BUNDLE_SENT is cleared so no signal falls between: the forward bundle makes its target
    # VERSION; the revert bundle (VERSION already set) puts PREV back, PHASE=reverting
    if [[ -n "$VERSION" ]]; then
        PHASE=reverting
    else
        VERSION="$BUNDLE_TARGET" PHASE=forward
    fi
    BUNDLE_SENT=""
}
pa_json() {   # OUTCOME — partial_apply's extra (§14.8.6) for version $VERSION into $STAGE/pa.json,
    # with its own reason and based_on (the record's state may be another version's) and
    # failed_targets from $STAGE/failed.txt
    py -c 'import json, sys
fail = [l.strip() for l in open(sys.argv[6]) if l.strip()]
v, kind, outcome, prev = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[5])
what = {"mixed": "left mixed, ./apps/iam/apply.sh --resume converges it",
        "reverted": f"reverted to version {prev}"}[outcome]
names = ", ".join(fail)
json.dump({"version": v, "kind": kind, "outcome": outcome, "attempts": int(sys.argv[4]), "failed_targets": fail,
           "based_on": prev,
           "reason": f"version {v} ({kind}): its rollout failed after {sys.argv[4]} attempt(s) ({names}); {what}"},
          open(sys.argv[7], "w"))' "$VERSION" "$KIND_B" "$1" "${2:-$ATTEMPTS}" "$A" "$STAGE/failed.txt" "$STAGE/pa.json"
}
defer_records() {   # each deferral after the applied record (open until the next applied record)
    local cmd id why=()
    for cmd in "${DEFERRED[@]}"; do
        # the reason, then when --resume closes it; read in full first, so a broken
        # deferred-reason never records an apply_deferred without a reason
        why="$(py "$CHECK" deferred-reason --command "$cmd")" || why=""
        mapfile -t why <<<"$why"
        [[ ${#why[@]} -eq 2 && -n "${why[0]}" && -n "${why[1]}" ]] \
            || fail3 "cannot tell why $cmd deferred (apply_check.py deferred-reason, above)"
        py "$CHECK" deferred-record --state "$STATE" --target "$(basename "$(dirname "${cmd%% *}")")" \
            --reason "${why[0]}" --command "$cmd" --out "$STAGE/deferred.sql" \
            || fail3 "cannot build the apply_deferred record (above)"
        id="$(q -1 < "$STAGE/deferred.sql" | tr -d '[:space:]')" || id=""
        [[ "$id" =~ ^[0-9]+$ ]] || fail3 "could not record apply_deferred in iam_policy.history (above)"
        warn "deferred: $cmd (apply_deferred, event $id): run ./apps/iam/apply.sh --resume --by <you> ${why[1]}"
    done
}
follow_report() {   # V SINCE — step 9's reported part (design §14.8.6): iam-api's /healthz
    # applied_version (cached 30 s) and the broker sidecar's last database read follow the
    # commit; polled every 10 s up to 60 s, a WARNING when not, never revert-driving (iam-api
    # down must not revert a correct apply). An absent component is not asked.
    local v="$1" since="$2" n api db
    for ((n = 0; n <= 6; n++)); do
        api="$($KUBECTL exec -n "$NAMESPACE" -c iam-api deployment/iam-api -- python3 -c 'import json, urllib.request
print(json.loads(urllib.request.urlopen("http://127.0.0.1:8083/healthz", timeout=5).read()).get("applied_version"))' 2>/dev/null)" || api=""
        db="$($KUBECTL exec -n "$NAMESPACE" -c mqtt-auth-sync deployment/mosquitto -- cat /mosquitto/auth/status.json 2>/dev/null \
                | python3 -c 'import datetime, json, sys
print(int(datetime.datetime.fromisoformat(json.load(sys.stdin)["last_db_ok"]).timestamp()))' 2>/dev/null)" || db=""
        { [[ -z "$api" || "$api" == "$v" ]] && [[ -z "$db" || "$db" -ge "$since" ]]; } && return 0
        ((n < 6)) && sleep 10
    done
    [[ -z "$api" || "$api" == "$v" ]] || warn "iam-api's Policy UI still reports applied version $api after 60 s (its cache is 30 s): kubectl -n $NAMESPACE logs deployment/iam-api"
    [[ -z "$db" || "$db" -ge "$since" ]] || warn "the broker's credential sync has not read the database since the commit (mqtt-auth-sync's status.json): kubectl -n $NAMESPACE logs deployment/mosquitto -c mqtt-auth-sync"
    return 0
}
routes_digest_of() {   # DIR — the routes digest of a saved compile
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["digest"])' "$1/routes.out"
}

COMMIT="unknown" VERSION=""

# =============================================================================
# --audit N (IAM 4.5, design §14.8.10): read-only, no lock
# =============================================================================
if [[ "$MODE" == audit ]]; then
    unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS
    read_state
    case "$ST" in
        unreachable) die 2 "PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")'))" ;;
        none) die 2 "no policy versions ($(jget "$STATE" 'd.get("detail")'))" ;;
    esac
    read_doc "$NUM" "$STAGE/audit-raw.json" --audit
    py "$CHECK" audit-doc --in "$STAGE/audit-raw.json" --issuer "$ISSUER" --out "$STAGE/audit.json" || exit 2
    rc=0
    py "$CLI" audit-version --record "$STAGE/audit.json" || rc=$?
    exit "$rc"
fi

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
    BUNDLE_SENT=1 BUNDLE_TARGET=1 BUNDLE_FROM=""
    DBA_ACTOR=system:apply dba_policy_bundle "$NAMESPACE" "$POD" auto "$STAGE/bundle/pre.sql" "$STAGE/bundle/post.sql" --with-functions || rc=$?
    BUNDLE_SENT=""
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
    log "version $NEXT (skeleton) submitted: a qa person other than $BY, who did not run this proposal, approves it in the Policy UI (Approval); then check out $REV's commit and run ./apps/iam/apply.sh $NEXT --by <you>; until then the change stays on $REV's branch."
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
# <N> and --rollback-to K (IAM 4.5, design §14.8.4-§14.8.7)
# =============================================================================
if [[ "$MODE" == apply || "$MODE" == rollback-to ]]; then
    if [[ "$MODE" == apply ]]; then WHAT="version $NUM"; AMODE=apply; else WHAT="a rollback to version $NUM"; AMODE=rollback; fi
    log "Policy apply: $WHAT$($CHECK_ONLY && echo ' (--check-only: nothing is written)')"
    # 2.1 break-glass never applies a version; the state
    [[ -z "${MEDCEA_POLICY_FILE:-}" ]] || die 2 "no apply under break-glass: it changes the compiled matrix, never the applied version (unset MEDCEA_POLICY_FILE)"
    read_state --full
    case "$ST" in
        version-*) A="${ST#version-}" ;;
        unreachable) die 2 "PostgreSQL is not Ready ($(jget "$STATE" 'd.get("detail")')): nothing was changed" ;;
        none|empty) die 2 "no applied version: ./apps/iam/deploy.sh bootstraps it; nothing was changed" ;;
        partial) die 2 "policy versions exist but none is applied: ./apps/iam/apply.sh --status" ;;
        *) die 2 "cannot read the policy versions ($ST): nothing was changed" ;;
    esac
    # 2.2 a commit audit-version can reproduce; 2.3 the host file is version A's
    reproducible_commit
    host_file_first
    # the version read (step 3's document, READ ONLY; the gate exception needs it)
    read_doc "$NUM" "$DOC"
    KIND="$(jget "$DOC" '(d.get("version") or {}).get("kind") or ""')"
    # 2.4 the skeleton gate (<N>: the exception for exactly an approved skeleton version)
    rc=0
    py "$CLI" skeleton-gate --state "$STATE" --check >"$STAGE/gate.json" 2>"$STAGE/gate.err" || rc=$?
    head_has=unknown
    if ((rc == 3)) && [[ "$KIND" == skeleton ]]; then
        c="$(jget "$DOC" '((d.get("skeletons") or {}).get((d.get("version") or {}).get("skeleton_digest")) or {}).get("git_commit") or ""')"
        if [[ "$c" =~ ^[0-9a-f]{7,40}$ ]]; then
            head_has=no
            git -C "$REPO_ROOT" merge-base --is-ancestor "$c" HEAD 2>/dev/null && head_has=yes
        fi
    fi
    grc=0
    py "$CHECK" gate --state "$STATE" --doc "$DOC" --gate "$STAGE/gate.json" --gate-rc "$rc" --mode "$AMODE" \
        --version "$NUM" --head-has "$head_has" || grc=$?
    if ((grc)); then
        ((rc == 3 || rc == 2)) && sed 's/^/  /' "$STAGE/gate.err" >&2
        exit "$grc"
    fi
    # 3 the state and the chain
    if [[ "$AMODE" == apply ]]; then
        py "$CHECK" state-check --state "$STATE" --doc "$DOC" --version "$NUM" || exit $?
    fi
    check_chain
    # --by, the Keycloak reads of step 4, the realm's keys
    kc_start 12 || die 2 "Keycloak's admin API cannot be reached (port-forward on $KC_PORT): nothing was changed"
    resolve_by
    fetch_jwks "$STAGE/jwks.json"
    STAGE_DIR="$STAGE/stage"
    if [[ "$AMODE" == rollback ]]; then
        K="$NUM"
        # 3 K eligible, and the bound (OA-c); pending decisions listed, not refused
        py "$CHECK" rollback-check --state "$STATE" --doc "$DOC" --jwks "$STAGE/jwks.json" --version "$K" || exit $?
        V="$(q <<'SQL' | tr -d '[:space:]'
BEGIN TRANSACTION READ ONLY;
SELECT coalesce(max(x.version), 0) + 1 FROM iam_policy.version x;
COMMIT;
SQL
)" || die 1 "cannot read the next version number: nothing was changed"
        [[ "$V" =~ ^[1-9][0-9]*$ ]] || die 1 "cannot read the next version number ('$V'): nothing was changed"
        reason_file rollback-to
        # 5 the staged rollback version (K's rows, the accepted skeleton's keys), body-bound, checked, compiled
        py "$CHECK" stage --state "$STATE" --doc "$DOC" --out "$STAGE_DIR" --commit "$COMMIT" --rollback "$K" --next "$V" || exit 1
        # 6 the diff against applied (shown, not hashed for anyone); the open version it withdraws
        py "$CHECK" rollback-diff --state "$STATE" --stage "$STAGE_DIR"
        OPEN="$(py "$CHECK" open-version --state "$STATE")" || OPEN=""
        if [[ -n "$OPEN" ]]; then
            IFS=$'\t' read -r OV _ OSTATUS _ <<<"$OPEN"
            warn "version $OV ($OSTATUS) will be withdrawn"
        fi
        # 4 someone can still approve after it (a WARNING, owner decision 7)
        py "$CHECK" account-skeleton --state "$STATE" --out "$STAGE/acc-skel.json"
        kc_dump "$STAGE/kc4" rollback || die 2 "Keycloak's admin API answered HTTP ${KC_CODE:-000}: nothing was changed"
        py "$CHECK" check-approval --doc "$DOC" --kc "$STAGE/kc4" --jwks "$STAGE/jwks.json" --stage "$STAGE_DIR" \
            --issuer "$ISSUER" --mode rollback --version "$K" --state "$STATE" || exit 1
        TARGET="$V" KIND_B=rollback
    else
        V="$NUM" TARGET="$NUM" KIND_B="$KIND"
        # 5 the checker and the staged compile (before step 4, which reads its compiles)
        py "$CHECK" stage --state "$STATE" --doc "$DOC" --out "$STAGE_DIR" --commit "$COMMIT" || exit 1
        # 4 the evidence, the approver now, dual control
        py "$CHECK" account-skeleton --state "$STATE" --doc "$DOC" --out "$STAGE/acc-skel.json"
        kc_dump "$STAGE/kc4" apply || die 2 "Keycloak's admin API answered HTTP ${KC_CODE:-000}: nothing was changed"
        py "$CHECK" check-approval --doc "$DOC" --kc "$STAGE/kc4" --jwks "$STAGE/jwks.json" --stage "$STAGE_DIR" \
            --issuer "$ISSUER" --mode apply --version "$V" --state "$STATE" --out "$STAGE/check.json" || exit $?
        # 6 the diff qa saw, byte for byte, and the summary
        py "$CHECK" diff-check --state "$STATE" --doc "$DOC" --stage "$STAGE_DIR" || exit 1
    fi
    # 6b the health baseline (§14.8.6 step 9's checks before anything changes)
    log "step 6b: the checks of step 9, before the apply"
    verify_run "$STAGE/baseline.json" || die 1 "cannot read the health baseline (above): nothing was changed"
    mapfile -t PRE_FAILING < <(jget "$STAGE/baseline.json" '"\n".join(sorted(k for k, s in d.items() if s == "FAIL"))' | sed '/^$/d')
    if ((${#PRE_FAILING[@]})); then
        [[ "$AMODE" == apply ]] && die 2 "these checks fail before the apply (above: ${PRE_FAILING[*]}): fix them first; nothing was changed"
        warn "pre-failing, reported and never revert-driving: ${PRE_FAILING[*]}"
    fi
    if $CHECK_ONLY; then
        if [[ "$AMODE" == apply ]]; then log "version $V would apply"; else log "version $V (rollback to version $K) would apply"; fi
        exit 0
    fi
    if [[ "$AMODE" == apply ]]; then
        confirm "Apply version $V ($KIND) of the access policy, claimed by $BY? [y/N] " y
    else
        confirm "Version $V is a permanent record that restores version $K, claimed by $BY. Type yes to roll back to version $K: " yes
    fi
    # 6c the re-read: nothing may change while the confirmation waited (no prompt from here)
    read_doc "$NUM" "$STAGE/approval2.json"
    py -c 'import json, sys
def load(p):
    return json.loads([l for l in open(p).read().splitlines() if l.strip()][-1])
a, b = load(sys.argv[1]), load(sys.argv[2])
bad = [k for k in ("version", "applied_version", "entries_digest_sql") if a.get(k) != b.get(k)]
if sys.argv[3] == "apply" and (b.get("pending") or []) != (a.get("pending") or []):
    bad.append("pending account decisions")
for k in bad:
    print(f"ERROR: changed while the confirmation waited: {k}", file=sys.stderr)
for p in (b.get("pending") or []) if sys.argv[3] == "rollback" else []:
    print("  pending: #%s %s %s" % (p.get("decision_id"), p.get("kind"), p.get("username")), file=sys.stderr)
sys.exit(1 if bad else 0)' "$DOC" "$STAGE/approval2.json" "$AMODE" \
        || die 1 "something changed while the confirmation waited (above): nothing was changed; run it again"
    if [[ "$AMODE" == apply ]]; then
        kc_dump "$STAGE/kc6" apply || die 2 "Keycloak's admin API answered HTTP ${KC_CODE:-000}: nothing was changed"
        fetch_jwks "$STAGE/jwks6.json"
        py "$CHECK" check-approval --doc "$STAGE/approval2.json" --kc "$STAGE/kc6" --jwks "$STAGE/jwks6.json" \
            --stage "$STAGE_DIR" --issuer "$ISSUER" --mode apply --version "$V" --state "$STATE" >/dev/null \
            || die 1 "something changed while the confirmation waited (above): nothing was changed; run it again"
    fi
    # 7 one transaction, compiled from the staged version (--staged, pinned)
    rb=()
    [[ "$AMODE" == rollback ]] && rb=(--reason-file "$STAGE/reason")
    py "$CHECK" bundle-sql --kind "$KIND_B" --stage "$STAGE_DIR" --doc "$DOC" --by-sub "$BY_SUB" --by-person "$BY_PERSON" \
        --log "${MEDCEA_LOG_FILE:-}" --commit "$COMMIT" --digests "$STAGE_DIR/digests.json" "${rb[@]}" --out "$STAGE/bundle" \
        || die 1 "cannot build the bundle (above): nothing was changed"
    rc=0
    SINCE="$(date +%s)"
    run_bundle "$STAGE_DIR/staged/policy-applied.yaml" "$(jget "$STAGE_DIR/stage.json" 'd["staged_sha256"]')" \
        "$STAGE/bundle" "$TARGET" "$A" || rc=$?
    case $rc in
        0) ;;
        1) die 1 "the bundle was rolled back (above): nothing was changed" ;;
        3) die 2 "config.env and the database disagree on IAM_DB_ROLES, or migration 008b is missing (above): nothing was changed" ;;
        *) die 1 "the bundle failed (above) and the database cannot tell now whether it committed: run ./apps/iam/apply.sh --status before anything else" ;;
    esac
    VERSION="$TARGET" PHASE=forward
    # from here every failure is exit 3
    post_state "$VERSION"
    py "$CLI" write-applied --state "$STATE" || fail3 "cannot write state/policy-applied.yaml (above)"
    py "$CHECK" verify-host --reference "$STAGE_DIR/staged-outs" || fail3 "the written host file does not compile to version $VERSION (above)"
    # 8-9 the artefacts and the checks, 3 attempts
    if ! rollout "$(routes_digest_of "$STAGE_DIR/staged-outs")" judge; then
        printf '%s\n' "${FAILED_TARGETS[@]}" > "$STAGE/failed.txt"
        if [[ "$KIND_B" == skeleton ]]; then
            # owner decision 3: a skeleton version is never reverted; --resume converges forward
            PHASE=mixed
            pa_json mixed
            record partial_apply --extra "$STAGE/pa.json"
            fail3 "the rollout of skeleton version $VERSION failed after $ATTEMPTS attempts (${FAILED_TARGETS[*]}): a skeleton version is not reverted"
        fi
        # the revert (design §14.8.6), change and rollback versions: the previous version back.
        # PHASE stays mixed until the revert bundle commits (bundle_committed sets reverting)
        PHASE=mixed PREV="$A"
        warn "the rollout of version $VERSION failed after $ATTEMPTS attempts (${FAILED_TARGETS[*]}): putting version $PREV back"
        printf 'step 8/9 failed after 3 attempts: %s' "${FAILED_TARGETS[*]}" > "$STAGE/revert-why"
        rc=0
        py "$CHECK" bundle-sql --kind revert --stage "$STAGE_DIR" --reason-file "$STAGE/revert-why" --failed "$STAGE/failed.txt" \
            --out "$STAGE/revert" || rc=$?
        if ((rc)); then
            pa_json mixed
            record partial_apply --extra "$STAGE/pa.json"
            fail3 "cannot build the revert bundle (above): version $VERSION stays applied with an unfinished rollout (partial_apply mixed)"
        fi
        run_bundle "$STAGE_DIR/prev.yaml" "$(jget "$STAGE_DIR/stage.json" 'd["prev_sha256"]')" "$STAGE/revert" "$PREV" "$VERSION" || rc=$?
        if ((rc)); then
            # rolled back as a whole: version N stays applied, its rollout not finished
            st="$(policy_db_state "$NAMESPACE" "$STATE" --full)" || st=error
            if [[ "$st" == "version-$VERSION" ]]; then
                pa_json mixed
                record partial_apply --extra "$STAGE/pa.json"
            fi
            fail3 "the revert bundle failed (above): version $VERSION stays applied with an unfinished rollout (partial_apply mixed)"
        fi
        post_state "$PREV"
        py "$CLI" write-applied --state "$STATE" || fail3 "cannot write state/policy-applied.yaml (above)"
        py "$CHECK" verify-host --reference "$STAGE_DIR/prev" || fail3 "the written host file does not compile to version $PREV (above)"
        FAILED_N=("${FAILED_TARGETS[@]}") ATTEMPTS_N="$ATTEMPTS"
        rollout "$(routes_digest_of "$STAGE_DIR/prev")" judge \
            || fail3 "the rollout of version $PREV failed too (${FAILED_TARGETS[*]})"
        # the records: N approved again (or a rollback withdrawn), then the previous one applied
        printf '%s\n' "${FAILED_N[@]}" > "$STAGE/failed.txt"
        pa_json reverted "$ATTEMPTS_N"
        RECORD_DIGESTS="$STAGE_DIR/digests.json"
        record partial_apply --extra "$STAGE/pa.json"
        py -c 'import json, sys
json.dump({"reverted_from": int(sys.argv[1]), "resumed": False, "attempts": int(sys.argv[2]),
           "reason": f"version {sys.argv[3]} put back: the apply of version {sys.argv[1]} was reverted"}, open(sys.argv[4], "w"))' \
            "$VERSION" "$ATTEMPTS" "$PREV" "$STAGE/back.json"
        RECORD_DIGESTS="$STAGE_DIR/prev-digests.json"
        record applied --extra "$STAGE/back.json"
        report
        warn "what a revert does not undo (design §6.3): retired MQTT person credentials stay retired; pgAdmin lost its sessions if its claims changed; pure narrowings access-api applied in the window stay applied (health WARNs until qa reviews them)"
        PHASE=forward
        if [[ "$AMODE" == rollback ]]; then
            again="./apps/iam/apply.sh --rollback-to $K --by <you> --reason \"<why>\""
        else
            again="./apps/iam/apply.sh $NUM --by <you>"
        fi
        die 1 "version $VERSION was not applied: the rollout failed (${FAILED_N[*]}) and the previous version $PREV is back. Fix the cause and run $again again"
    fi
    follow_report "$VERSION" "$SINCE"
    # 10 the record, then each deferral after it
    xs=()
    [[ "$AMODE" == apply ]] && xs=(--check "$STAGE/check.json")
    for c in "${DEFERRED[@]}"; do xs+=(--deferred "$c"); done
    for c in "${PRE_FAILING[@]}"; do xs+=(--pre-failing "$c"); done
    [[ "$AMODE" == rollback ]] && xs+=(--reason-file "$STAGE/reason")
    py "$CHECK" apply-extra --doc "$DOC" --stage "$STAGE_DIR" --mode "$AMODE" --attempts "$ATTEMPTS" "${xs[@]}" \
        --out "$STAGE/extra.json" || fail3 "cannot build the applied record (above)"
    RECORD_DIGESTS="$STAGE_DIR/digests.json"
    record applied --extra "$STAGE/extra.json"
    defer_records
    # 11 the report
    report
    if [[ "$AMODE" == rollback ]]; then
        log "version $VERSION (rollback to $K) applied: a qa person other than $BY confirms it in the Policy UI (Confirm). Health WARNs until then; a dispute FAILs until a newer approved version supersedes it."
    else
        log "version $VERSION ($KIND) applied."
        [[ "$KIND" == skeleton ]] && log "the Policy UI still ships the old skeleton: ./apps/iam/deploy.sh"
    fi
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
    partial_apply)
        # IAM 4.5 (design §14.8.6): a rollout left mixed, or a revert left reverting (the version
        # it put back is the applied one): converged forward, never reverted
        case "$(jget "$STATE" '(d.get("last_apply_event") or {}).get("outcome") or ""')" in
            reverted) die 1 "version $VERSION's latest apply event is partial_apply {reverted}, which never ends an applied version: ./apps/iam/apply.sh --status" ;;
            reverting) log "version $VERSION was put back by a revert that did not finish (partial_apply reverting): finishing it" ;;
            *) log "version $VERSION ended in partial_apply: converging its rollout" ;;
        esac
        PHASE=mixed ;;
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
# the reference is the committed version itself (its rows from the database), never the
# current defaults.yaml: a matrix edit in git since the commit must not block the resume
py "$CLI" bootstrap-targets --out "$STAGE/targets" --state "$STATE" > "$STAGE/targets.json" \
    || fail3 "version $VERSION cannot be compiled from the database's rows (above)"
py "$CLI" bootstrap-targets --out "$STAGE/targets" --source host || fail3 "the written host file does not compile to version $VERSION (above)"
# 8. the artefacts (IAM 4.2b): every scoped mode under this lock, each re-rendering only
# what drifted from version $VERSION's compile, with 4.5's retries and wait_routes; the
# wizard's exit 4 (a flash running) is recorded as apply_deferred and closed by the next
# --resume. grants: step 9. --resume never reverts.
rollout "$(jget "$STAGE/targets.json" 'd["routes_digest"]')" report \
    || fail3 "${FAILED_TARGETS[*]} still failing after $ATTEMPTS attempts: version $VERSION is committed; fix the cause above and run --resume again"
# 9. the grants (exit 3 when they fail), the other checks reported (a deferred target's dropped)
verify_grants
verify_run "$STAGE/verify-now.json" --drop=iamgrants "${DROPS[@]}" || true
mapfile -t bad < <(jget "$STAGE/verify-now.json" '"\n".join(sorted(k for k, s in d.items() if s == "FAIL"))' | sed '/^$/d')
if ((${#bad[@]})); then
    warn "still FAILing after the scoped modes: ${bad[*]}; a full deploy re-renders the policy's artefacts (in this order):"
    py "$CHECK" owners --deploys | sed 's/^/  /' >&2
fi
# 10. the record, then each deferral after it (open until the next applied record)
record "$EVENT" --resumed
defer_records
report
log "version $VERSION ($KIND): the apply is finished."
