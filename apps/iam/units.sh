#!/usr/bin/env bash
# apps/iam/units.sh — which units an operator works in (IAM plan 2.8, own_unit)
#
#   apps/iam/units.sh assign <username> <UNIT>... [--reason TEXT]
#   apps/iam/units.sh remove <username> <UNIT>... [--reason TEXT]
#   apps/iam/units.sh remove --sub <uuid> <UNIT>... [--reason TEXT]
#   apps/iam/units.sh list [<username>]
#
# Under IAM_DB_ROLES=true an operator sees the telemetry, runs and run logs of every zone
# of their units (zones added later included) and starts or stops runs only there; with no
# unit they see nothing. Assign units before turning IAM_DB_ROLES on.
#
# Each change writes iam_policy.user_unit and one iam.account_decision row per unit, in one
# transaction, as system:deploy (made_by_sub NULL); the policy hash chain gets a
# unit_assigned / unit_removed event. An assignment is a widening and, as a bootstrap
# exception like the policy's --bootstrap, takes effect at once while it is recorded
# pending_qa: IAM 2.7's confirm screen confirms or refuses it, and a refusal removes the
# unit. A removal is a narrowing: applied at once. Idempotent: a unit already assigned (or
# not assigned) writes nothing. Units are unit codes, case-insensitive. The account is
# found through Keycloak's admin API (infra/lib-keycloak-admin.sh, realm $KEYCLOAK_REALM);
# only operator accounts are filtered by units, so another role is warned about and
# recorded anyway. remove --sub removes the units of an account that no longer exists in
# Keycloak (list prints the command). Takes the deploy lock; not run by deploy-apps.sh.
#
# Exit 0 on success (also when nothing changed); 1 for an unknown user or unit, an SQL
# failure, or another deploy holding the lock; 2 for a usage error, a database or access
# deploy that has not been run yet, or Keycloak unreachable.
# Run from anywhere:  apps/iam/units.sh list

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
    [[ -n "${1:-}" ]] && exit 0
    exit 2   # no arguments is a usage error
fi

YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
warn() { echo -e "${YELLOW}[units] $*${NC}" >&2; }
die()  { local c="$1"; shift; echo -e "${RED}[units] $*${NC}" >&2; exit "$c"; }
usage() { die 2 "$*  (apps/iam/units.sh --help)"; }

UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# ── Arguments (before the lock, so a usage error needs none) ─────────────────
CMD="$1"; shift
USER_ARG=""; SUB_ARG=""; REASON=""; REASON_SET=0; CODES=()
case "$CMD" in
    assign|remove|list) ;;
    *) usage "unknown command '$CMD'" ;;
esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason)
            [[ $# -ge 2 ]] || usage "--reason needs a text"
            REASON="$2"; REASON_SET=1; shift 2 ;;
        --sub)
            [[ "$CMD" == remove ]] || usage "--sub is for remove only"
            [[ $# -ge 2 && "$2" =~ $UUID_RE ]] || usage "--sub needs a Keycloak user id (uuid)"
            SUB_ARG="${2,,}"; shift 2 ;;
        -*) usage "unknown option '$1'" ;;
        *)
            if [[ -z "$USER_ARG" && -z "$SUB_ARG" ]]; then
                USER_ARG="$1"
            else
                [[ "$CMD" != list ]] || usage "list takes at most one username"
                [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]] || usage "'$1' is not a unit code ([A-Za-z0-9_-])"
                _dup=0
                for _c in "${CODES[@]}"; do [[ "${_c,,}" == "${1,,}" ]] && _dup=1; done
                [[ $_dup == 1 ]] || CODES+=("$1")
            fi
            shift ;;
    esac
done
if [[ "$CMD" != list ]]; then
    [[ -n "$USER_ARG" || -n "$SUB_ARG" ]] || usage "$CMD needs a username"
    [[ ${#CODES[@]} -gt 0 ]] || usage "$CMD needs at least one unit code"
    if [[ $REASON_SET == 1 ]]; then
        [[ -n "${REASON//[[:space:]]/}" ]] || usage "--reason must not be empty"
    elif [[ "$CMD" == assign ]]; then
        REASON="IAM 2.8: unit assigned with apps/iam/units.sh (awaiting qa confirmation, IAM 2.7)"
    else
        REASON="IAM 2.8: unit removed with apps/iam/units.sh"
    fi
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
# shellcheck disable=SC1091
source config.env
set -euo pipefail
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh
source apps/database/lib-db-apply.sh   # _dba_psql: psql in the pod, password read there

# ── Database ──────────────────────────────────────────────────────────────────
NAMESPACE="${NAMESPACE:-medcea}"
PG_RELEASE="${PG_RELEASE:-rdbms}"
DB="${POSTGRES_DB:-medcea_db}"
PG_POD=$($KUBECTL get pod -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=$PG_RELEASE" \
    -o jsonpath='{.items[0].metadata.name}' || true)
[[ -n "$PG_POD" ]] || die 2 "No PostgreSQL pod found (instance=$PG_RELEASE, namespace=$NAMESPACE)."
_DBA_NS="$NAMESPACE"; _DBA_POD="$PG_POD"

q() { _dba_psql "$DB" -qtA -F'|' -v ON_ERROR_STOP=1 "$@"; }   # read-only queries, SQL on stdin

PRE="$(q <<'SQL'
SELECT pg_catalog.to_regclass('iam_policy.user_unit') IS NOT NULL,
       pg_catalog.to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL,
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'iam'
                AND table_name = 'account_decision' AND column_name = 'unit_id'),
       coalesce((SELECT pg_catalog.pg_get_constraintdef(oid) LIKE '%unit_assign%' FROM pg_catalog.pg_constraint
                  WHERE conname = 'account_decision_kind_check'
                    AND conrelid = pg_catalog.to_regclass('iam.account_decision')), false);
SQL
)" || die 2 "Cannot query database '$DB' in pod $PG_POD."
IFS='|' read -r _p1 _p2 _p3 _p4 <<<"$PRE"
[[ "$_p1" == t && "$_p2" == t ]] || die 2 "iam_policy.user_unit is missing: run ./apps/database/deploy.sh first."
[[ "$_p3" == t && "$_p4" == t ]] || die 2 "iam.account_decision has no unit decisions yet: run ./apps/access/deploy.sh first."

# Unit codes → ids (assign/remove). Nothing is written before every code resolves.
UNIT_IDS=""
if [[ "$CMD" != list ]]; then
    _codes="$(IFS=,; echo "${CODES[*]}")"
    _rows="$(q -v codes="$_codes" <<'SQL'
SELECT unit_id, unit_code FROM medcea.cea_unit
 WHERE lower(unit_code) = ANY (pg_catalog.string_to_array(lower(:'codes'), ','))
SQL
)" || die 1 "Cannot read medcea.cea_unit."
    _missing=()
    for _c in "${CODES[@]}"; do
        grep -qi -- "^[0-9]*|${_c}\$" <<<"$_rows" || _missing+=("$_c")
    done
    [[ ${#_missing[@]} -eq 0 ]] || die 1 "unknown unit(s): $(IFS=,; echo "${_missing[*]}" | sed 's/,/, /g')"
    UNIT_IDS="$(cut -d'|' -f1 <<<"$_rows" | paste -sd,)"
fi

# ── Keycloak ──────────────────────────────────────────────────────────────────
KC_PORT=18091
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"
TMP="$(mktemp -d)"; chmod 700 "$TMP"
PF_PID=""
# Under set -e a failing command in the trap (kill of a forward that already
# exited) would end it early, keep $TMP and turn the exit status into 1: the temp
# dir goes first, nothing here can fail, and the script's own status is kept.
cleanup() {
    local rc=$?
    rm -rf "$TMP" || true
    kc_admin_done || true
    [[ -z "$PF_PID" ]] || kill "$PF_PID" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

$KUBECTL port-forward svc/keycloak "$KC_PORT:80" -n "$NAMESPACE" &>/dev/null 9>&- &
PF_PID=$!
for _ in $(seq 1 12); do
    kc_admin_select && break
    sleep 2
done
[[ -n "$KC_ADMIN_MODE" ]] || die 2 "Cannot reach Keycloak's admin API (port-forward on $KC_PORT)."

# kc PATH → the body in $TMP/body, the HTTP status on stdout (000: no answer).
# _kc_get's curl -f cannot tell a 404 from a dead port-forward. The token goes to
# curl as a header on a pipe (-H @<(...)), never in its argv or in a file;
# lib-keycloak-admin.sh does the same, and sends the grant's secret on stdin.
kc() {
    local code
    code="$(curl -s -o "$TMP/body" -w '%{http_code}' -H @<(_kc_bearer "$(kc_admin_token)") "$KC_URL/admin/$1" 2>/dev/null)" || true
    printf '%s' "${code:-000}"
}
kc_ok() {   # PATH → the body on stdout; any status but 200 ends the run (exit 2)
    local code; code="$(kc "$1")"
    [[ "$code" == 200 ]] || die 2 "Keycloak admin API: GET $1 answered HTTP $code."
    cat "$TMP/body"
}
PLATFORM_ROLES="$(python3 -c '
import sys; sys.path.insert(0, "apps/iam")
from compiler import model
print(" ".join(model.load().roles))')"
# platform_role ID → the account's platform role(s), comma-separated, or -
platform_role() {
    kc_ok "realms/$R/users/$1/role-mappings/realm" | ROLES="$PLATFORM_ROLES" python3 -c '
import json, os, sys
mine = {r["name"] for r in json.load(sys.stdin)} & set(os.environ["ROLES"].split())
print(",".join(sorted(mine)) or "-")'
}
# user_fields → id<TAB>username<TAB>enabled<TAB>person_id ('-' when empty) from one
# UserRepresentation (or the first of a list) on stdin
user_fields() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
if isinstance(d, list):
    d = d[0] if d else None
if not d:
    sys.exit(0)
pid = ((d.get("attributes") or {}).get("person_id") or [""])[0]
print("\t".join([d["id"], d["username"], "true" if d.get("enabled") else "false", pid or "-"]))'
}
# find_user USERNAME → user_fields of that exact account, or nothing
find_user() {
    local enc
    enc="$(U="$1" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["U"], safe=""))')"
    kc_ok "realms/$R/users?username=$enc&exact=true&briefRepresentation=false" | user_fields
}

# ── list ──────────────────────────────────────────────────────────────────────
if [[ "$CMD" == list ]]; then
    ONLY=""
    if [[ -n "$USER_ARG" ]]; then
        _f="$(find_user "$USER_ARG")"
        [[ -n "$_f" ]] || die 1 "No account '$USER_ARG' in realm $R."
        ONLY="${_f%%$'\t'*}"
    fi
    # pending: a unit_assign still pending_qa that is the latest unit_* decision for a
    # unit still assigned (assign, remove, assign leaves an older pending row behind)
    ROWS="$(q <<'SQL'
SELECT a.person_sub, string_agg(u.unit_code, ',' ORDER BY u.unit_code),
       count(*) FILTER (WHERE EXISTS (
           SELECT 1 FROM iam.account_decision d
            WHERE d.keycloak_user_id = a.person_sub::text AND d.unit_id = a.unit_id
              AND d.kind = 'unit_assign' AND d.status = 'pending_qa'
              AND NOT EXISTS (SELECT 1 FROM iam.account_decision l
                               WHERE l.keycloak_user_id = d.keycloak_user_id AND l.unit_id = d.unit_id
                                 AND l.kind IN ('unit_assign', 'unit_remove') AND l.decision_id > d.decision_id)))
  FROM iam_policy.user_unit a JOIN medcea.cea_unit u USING (unit_id)
 GROUP BY 1 ORDER BY 1
SQL
)" || die 1 "Cannot read iam_policy.user_unit."
    declare -A UNITS=() PENDING=()
    SUBS=()
    while IFS='|' read -r _s _u _n; do
        [[ -n "$_s" ]] || continue
        UNITS[$_s]="$_u"; PENDING[$_s]="$_n"; SUBS+=("$_s")
    done <<<"$ROWS"
    # accounts that hold operator directly, with or without a unit
    _opsjson="$(kc_ok "realms/$R/roles/operator/users?first=0&max=1000")"
    mapfile -t _ops < <(python3 -c 'import json, sys; [print(u["id"]) for u in json.load(sys.stdin)]' <<<"$_opsjson")
    for _s in "${_ops[@]}"; do
        [[ -n "${UNITS[$_s]+x}" ]] || SUBS+=("$_s")
    done
    printf 'USERNAME\tROLE\tENABLED\tUNITS\tPENDING_QA\n'
    for _s in "${SUBS[@]}"; do
        [[ -z "$ONLY" || "$_s" == "$ONLY" ]] || continue
        _code="$(kc "realms/$R/users/$_s")"
        if [[ "$_code" == 404 ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' "(no such account)" "-" "-" "${UNITS[$_s]:--}" "${PENDING[$_s]:-0}"
            warn "account $_s no longer exists; remove its units with: apps/iam/units.sh remove --sub $_s ${UNITS[$_s]//,/ }"
            continue
        fi
        [[ "$_code" == 200 ]] || die 2 "Keycloak admin API: GET realms/$R/users/$_s answered HTTP $_code."
        IFS=$'\t' read -r _id _name _en _pid < <(user_fields < "$TMP/body")
        _role="$(platform_role "$_s")"
        printf '%s\t%s\t%s\t%s\t%s\n' "$_name" "$_role" "$_en" "${UNITS[$_s]:--}" "${PENDING[$_s]:-0}"
        if [[ "$_role" == operator && "$_en" == true && -z "${UNITS[$_s]:-}" ]]; then
            warn "$_name: no unit — sees no telemetry or runs under IAM_DB_ROLES=true"
        fi
    done
    exit 0
fi

# ── assign / remove ───────────────────────────────────────────────────────────
if [[ -n "$SUB_ARG" ]]; then
    _code="$(kc "realms/$R/users/$SUB_ARG")"
    case "$_code" in
        200) IFS=$'\t' read -r SUB NAME ENABLED PID < <(user_fields < "$TMP/body") ;;
        404) SUB="$SUB_ARG"; NAME="(deleted)"; ENABLED=false; PID="-"
             warn "account $SUB_ARG is not in realm $R: recorded as (deleted)" ;;
        *)   die 2 "Keycloak admin API: GET realms/$R/users/$SUB_ARG answered HTTP $_code." ;;
    esac
else
    _f="$(find_user "$USER_ARG")"
    [[ -n "$_f" ]] || die 1 "No account '$USER_ARG' in realm $R."
    IFS=$'\t' read -r SUB NAME ENABLED PID <<<"$_f"
fi
[[ "$PID" == "-" ]] && PID=""
if [[ "$NAME" != "(deleted)" ]]; then
    ROLE="$(platform_role "$SUB")"
    [[ "$ROLE" == operator ]] \
        || warn "$NAME holds ${ROLE/#-/no platform role}, not operator: only operator accounts are filtered by units; recorded anyway"
    [[ "$ENABLED" == true ]] || warn "$NAME is disabled; recorded anyway"
    [[ -n "$PID" ]] || warn "$NAME has no person_id: recorded with subject_person empty"
fi

ASSIGN=false; [[ "$CMD" == assign ]] && ASSIGN=true
OUT="$(_dba_psql "$DB" -qtA -F'|' -1 -v ON_ERROR_STOP=1 -v assign="$ASSIGN" \
        -v sub="$SUB" -v username="$NAME" -v person="$PID" -v units="$UNIT_IDS" -v reason="$REASON" \
        -f - < apps/iam/units.sql)" || die 1 "The change was refused by the database; nothing was written."
while IFS='|' read -r _act _unit _dec; do
    [[ -n "$_act" ]] || continue
    case "$_act" in
        assigned)  echo "assigned $_unit to $NAME — decision #$_dec, pending qa confirmation (IAM 2.7)" ;;
        removed)   echo "removed $_unit from $NAME — decision #$_dec" ;;
        unchanged) if [[ "$CMD" == assign ]]; then echo "$_unit: already assigned to $NAME — nothing written"
                   else echo "$_unit: not assigned to $NAME — nothing written"; fi ;;
    esac
done <<<"$OUT"
