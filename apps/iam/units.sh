#!/usr/bin/env bash
# apps/iam/units.sh — which units an operator works in (IAM plan 2.8, own_unit)
#
#   apps/iam/units.sh assign <username> <UNIT>... --by <your username> [--reason TEXT] [--bootstrap]
#   apps/iam/units.sh remove <username> <UNIT>... --by <your username> [--reason TEXT]
#   apps/iam/units.sh remove --sub <uuid> <UNIT>... --by <your username> [--reason TEXT]
#   apps/iam/units.sh list [<username>]
#
# Under IAM_DB_ROLES=true an operator sees the telemetry, runs and run logs of every zone
# of their units (zones added later included) and starts or stops runs only there; with no
# unit they see nothing. Assign units, and have them confirmed, before turning
# IAM_DB_ROLES on.
#
# Each change writes one iam.account_decision row per unit, in one transaction, as
# system:deploy; --by names the person running it (your own Keycloak account in realm
# $KEYCLOAK_REALM), recorded as the decision's maker ("system:deploy (by <username>)"), so
# you cannot confirm it yourself in the User Manager (IAM 2.7). An assignment is a
# widening: it waits for qa (pending_qa) and is NOT in effect until a qa person other than
# you confirms it in the User Manager's Decisions tab, which writes iam_policy.user_unit
# (the policy hash chain gets unit_assigned); a refusal applies nothing. A removal is a
# narrowing: the unit goes at once (unit_removed on the chain), reviewed there afterwards;
# removing a unit still waiting for qa withdraws that decision instead. Idempotent: a unit
# already assigned (or not assigned, and not waiting) writes nothing, and assigning a unit
# that already waits reports the waiting decision.
# --bootstrap: only while no enabled qa account but yours (and the subject's) exists, so
# nobody could ever confirm: the unit is in effect at once, before any check, and its
# decision ("system:deploy (bootstrap, by <username>)") still waits for qa; a refusal then
# removes the unit. Refused (exit 2) when another qa person could confirm instead.
# Units are unit codes, case-insensitive. The account is found through Keycloak's admin
# API (infra/lib-keycloak-admin.sh, realm $KEYCLOAK_REALM); only operator accounts are
# filtered by units, so another role is warned about and recorded anyway. remove --sub
# removes the units of an account that no longer exists in Keycloak (list prints the
# command). list: UNITS are in effect (* = in effect before the check, its decision still
# waiting for qa), WAITING_QA are waiting for qa and not in effect. Takes the deploy lock;
# not run by deploy-apps.sh.
#
# Exit 0 on success (also when nothing changed); 1 for an unknown user (--by included) or
# unit, an SQL failure, or another deploy holding the lock; 2 for a usage error (a missing
# --by included), --bootstrap while another qa person could confirm, a database or access
# deploy that has not been run yet, or Keycloak unreachable.
# Run from anywhere:  apps/iam/units.sh list

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then
    sed -n "2,$(grep -n '^# Run from anywhere' "$0" | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'
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
USER_ARG=""; SUB_ARG=""; BY_ARG=""; REASON=""; REASON_SET=0; CODES=(); BOOTSTRAP=false
case "$CMD" in
    assign|remove|list) ;;
    *) usage "unknown command '$CMD'" ;;
esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason)
            [[ $# -ge 2 ]] || usage "--reason needs a text"
            REASON="$2"; REASON_SET=1; shift 2 ;;
        --by)
            [[ "$CMD" != list ]] || usage "--by is for assign and remove"
            [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || usage "--by needs your Keycloak username"
            BY_ARG="$2"; shift 2 ;;
        --bootstrap)
            [[ "$CMD" == assign ]] || usage "--bootstrap is for assign only"
            BOOTSTRAP=true; shift ;;
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
    # IAM 2.7: the decision names the person who made it (not_own_author)
    [[ -n "$BY_ARG" ]] || usage "$CMD needs --by <your Keycloak username>: the decision records who made it"
    if [[ $REASON_SET == 1 ]]; then
        [[ -n "${REASON//[[:space:]]/}" ]] || usage "--reason must not be empty"
    elif [[ "$CMD" == assign ]]; then
        REASON="IAM 2.8: unit assigned with apps/iam/units.sh (awaiting qa confirmation)"
        [[ "$BOOTSTRAP" == false ]] || REASON="IAM 2.8: unit assigned with apps/iam/units.sh --bootstrap (no other qa person could confirm; in effect before the check)"
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
    # waits: a unit_assign still pending_qa that is the latest unit_* decision for its
    # (user, unit) (assign, remove, assign leaves an older pending row behind). In effect:
    # the user_unit row, '*' while its decision still waits (bootstrap, backfill, or made
    # before assignments waited for qa); WAITING_QA: waiting and not in effect yet.
    ROWS="$(q <<'SQL'
WITH latest AS (
    SELECT DISTINCT ON (d.keycloak_user_id, d.unit_id) d.keycloak_user_id, d.unit_id, d.kind, d.status
      FROM iam.account_decision d WHERE d.kind IN ('unit_assign', 'unit_remove')
     ORDER BY d.keycloak_user_id, d.unit_id, d.decision_id DESC),
waits AS (SELECT l.keycloak_user_id AS sub, l.unit_id FROM latest l
           WHERE l.kind = 'unit_assign' AND l.status = 'pending_qa'),
ent AS (
    SELECT a.person_sub::text AS sub, a.unit_id, true AS in_effect,
           EXISTS (SELECT 1 FROM waits w WHERE w.sub = a.person_sub::text AND w.unit_id = a.unit_id) AS pending
      FROM iam_policy.user_unit a
    UNION ALL
    SELECT w.sub, w.unit_id, false, true FROM waits w
     WHERE NOT EXISTS (SELECT 1 FROM iam_policy.user_unit a
                        WHERE a.person_sub::text = w.sub AND a.unit_id = w.unit_id))
SELECT e.sub,
       coalesce(string_agg(coalesce(u.unit_code, '#' || e.unit_id) || CASE WHEN e.pending THEN '*' ELSE '' END, ','
                           ORDER BY u.unit_code) FILTER (WHERE e.in_effect), ''),
       coalesce(string_agg(coalesce(u.unit_code, '#' || e.unit_id), ',' ORDER BY u.unit_code)
                FILTER (WHERE NOT e.in_effect), '')
  FROM ent e LEFT JOIN medcea.cea_unit u USING (unit_id)
 GROUP BY 1 ORDER BY 1
SQL
)" || die 1 "Cannot read iam_policy.user_unit."
    declare -A UNITS=() WAITING=()
    SUBS=()
    while IFS='|' read -r _s _u _w; do
        [[ -n "$_s" ]] || continue
        UNITS[$_s]="$_u"; WAITING[$_s]="$_w"; SUBS+=("$_s")
    done <<<"$ROWS"
    # accounts that hold operator directly, with or without a unit
    _opsjson="$(kc_ok "realms/$R/roles/operator/users?first=0&max=1000")"
    mapfile -t _ops < <(python3 -c 'import json, sys; [print(u["id"]) for u in json.load(sys.stdin)]' <<<"$_opsjson")
    for _s in "${_ops[@]}"; do
        [[ -n "${UNITS[$_s]+x}" ]] || SUBS+=("$_s")
    done
    # _wgone (set per account below) → one warning naming the account
    gone_warn() {
        [[ -z "$_wgone" ]] || warn "$1: waiting assignment(s) of unit(s) that no longer exist (${_wgone}): a qa person refuses those decisions in the User Manager (Decisions); units.sh cannot withdraw them, and confirming them fails"
    }
    _star=0
    printf 'USERNAME\tROLE\tENABLED\tUNITS\tWAITING_QA\n'
    for _s in "${SUBS[@]}"; do
        [[ -z "$ONLY" || "$_s" == "$ONLY" ]] || continue
        _u="${UNITS[$_s]:-}"; _w="${WAITING[$_s]:-}"
        [[ "$_u" != *'*'* ]] || _star=1
        # '#<id>': a waiting assignment whose unit was deleted since (account_decision has
        # no foreign key; only user_unit's RESTRICT stops a delete). Neither remove nor
        # confirm can act on it (22023): qa refuses it in the User Manager.
        _wok=""; _wgone=""
        IFS=, read -r -a _wl <<<"$_w"
        for _x in "${_wl[@]}"; do
            [[ -n "$_x" ]] || continue
            if [[ "$_x" == '#'* ]]; then _wgone+="${_wgone:+, }$_x"; else _wok+="${_wok:+,}$_x"; fi
        done
        _code="$(kc "realms/$R/users/$_s")"
        if [[ "$_code" == 404 ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' "(no such account)" "-" "-" "${_u:--}" "${_w:--}"
            gone_warn "account $_s"
            _all="${_u//\*/}${_u:+${_wok:+,}}$_wok"
            [[ -n "$_all" ]] || continue
            warn "account $_s no longer exists; remove its units (and withdraw any waiting) with: apps/iam/units.sh remove --sub $_s ${_all//,/ } --by <your username>"
            continue
        fi
        [[ "$_code" == 200 ]] || die 2 "Keycloak admin API: GET realms/$R/users/$_s answered HTTP $_code."
        IFS=$'\t' read -r _id _name _en _pid < <(user_fields < "$TMP/body")
        _role="$(platform_role "$_s")"
        printf '%s\t%s\t%s\t%s\t%s\n' "$_name" "$_role" "$_en" "${_u:--}" "${_w:--}"
        gone_warn "$_name"
        if [[ "$_role" == operator && "$_en" == true && -z "$_u" ]]; then
            if [[ -n "$_wok" ]]; then
                warn "$_name: no unit in effect — sees no telemetry or runs under IAM_DB_ROLES=true until a qa person confirms ${_wok//,/, } (User Manager → Decisions)"
            else
                warn "$_name: no unit — sees no telemetry or runs under IAM_DB_ROLES=true"
            fi
        fi
    done
    [[ $_star == 0 ]] || echo "(* in effect before the check: its decision still waits for qa — bootstrap, backfill or made before assignments waited)" >&2
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
# --by: who runs this, as an account of the realm (its person_id, else its id: the
# person_id it gets on first enable). Nothing proves the runner holds that account, so
# confirming a units.sh row needs the qa person's attestation all the same (rule 6).
_f="$(find_user "$BY_ARG")"
[[ -n "$_f" ]] || die 1 "--by: no account '$BY_ARG' in realm $R."
IFS=$'\t' read -r BY_SUB BY_NAME _by_en BY_PID <<<"$_f"
[[ "$BY_PID" == "-" ]] && BY_PID="$BY_SUB"
[[ "$_by_en" == true ]] || warn "--by $BY_NAME is a disabled account; recorded anyway"
[[ "$BY_SUB" != "$SUB" ]] || warn "--by $BY_NAME is the account whose units change; recorded anyway (a qa person other than you confirms it)"
if [[ "$NAME" != "(deleted)" ]]; then
    ROLE="$(platform_role "$SUB")"
    [[ "$ROLE" == operator ]] \
        || warn "$NAME holds ${ROLE/#-/no platform role}, not operator: only operator accounts are filtered by units; recorded anyway"
    [[ "$ENABLED" == true ]] || warn "$NAME is disabled; recorded anyway"
    [[ -n "$PID" ]] || warn "$NAME has no person_id: recorded with subject_person empty"
fi

# --bootstrap: only when no qa person but the one running this (and the subject, who
# may not confirm their own units) could ever confirm. Direct holders of realm role qa:
# no role includes qa. Another account of the same person (person_id) cannot confirm
# either (rule 5), so it does not count as someone else. Each holder is read in full by
# its id (attributes included, whatever the role listing returns); the filter is
# apps/iam/units_bootstrap.py (tests/test_units_bootstrap.py).
if [[ "$BOOTSTRAP" == true ]]; then
    _qaids="$(kc_ok "realms/$R/roles/qa/users?first=0&max=1000" \
        | python3 -c 'import json, sys; [print(u["id"]) for u in json.load(sys.stdin)]')"
    _qafull="["
    for _q in $_qaids; do
        [[ "$_q" =~ $UUID_RE ]] || die 2 "Keycloak admin API: unexpected user id '$_q' in role qa."
        [[ "$_qafull" == "[" ]] || _qafull+=","
        _qafull+="$(kc_ok "realms/$R/users/$_q")"
    done
    _qafull+="]"
    _others="$(BY="$BY_SUB" BYP="$BY_PID" SUBJ="$SUB" SUBP="${PID:-$SUB}" \
        python3 apps/iam/units_bootstrap.py <<<"$_qafull")" || die 2 "Cannot check the qa accounts for --bootstrap."
    if [[ -n "$_others" ]]; then
        die 2 "--bootstrap refused: these enabled qa accounts can confirm the assignment instead: $(paste -sd, <<<"$_others" | sed 's/,/, /g'). Run assign without --bootstrap and ask one of them to confirm it in the User Manager (Decisions)."
    fi
fi

ASSIGN=false; [[ "$CMD" == assign ]] && ASSIGN=true
OUT="$(_dba_psql "$DB" -qtA -F'|' -1 -v ON_ERROR_STOP=1 -v assign="$ASSIGN" -v bootstrap="$BOOTSTRAP" \
        -v sub="$SUB" -v username="$NAME" -v person="$PID" -v units="$UNIT_IDS" -v reason="$REASON" \
        -v by_sub="$BY_SUB" -v by_person="$BY_PID" -v by_name="$BY_NAME" \
        -f - < apps/iam/units.sql)" || die 1 "The change was refused by the database; nothing was written."
_boot=0
while IFS='|' read -r _act _unit _dec; do
    [[ -n "$_act" ]] || continue
    case "$_act" in
        proposed)  echo "$_unit: waiting for qa (decision #$_dec) — not in effect until a qa person other than you confirms it in the User Manager (Decisions)" ;;
        waiting)   if [[ "$CMD" == assign && "$BOOTSTRAP" == true ]]; then
                       echo "$_unit: decision #$_dec already waits for qa — nothing written; to bootstrap it, withdraw it first: apps/iam/units.sh remove $NAME $_unit --by $BY_NAME"
                   else
                       echo "$_unit: already waiting for qa (decision #$_dec) — nothing written; not in effect until a qa person confirms it"
                   fi ;;
        assigned)  _boot=1
                   echo "assigned $_unit to $NAME — decision #$_dec, IN EFFECT BEFORE ANY CHECK (bootstrap), pending qa confirmation (User Manager → Decisions)" ;;
        removed)   echo "removed $_unit from $NAME — decision #$_dec" ;;
        withdrawn) echo "$_unit: was waiting for qa, never in effect — decision #$_dec withdrawn" ;;
        unchanged) if [[ "$CMD" == assign ]]; then echo "$_unit: already assigned to $NAME — nothing written"
                   else echo "$_unit: not assigned to $NAME and not waiting — nothing written"; fi ;;
    esac
done <<<"$OUT"
if [[ $_boot == 1 ]]; then
    warn "--bootstrap: no other enabled qa account exists, so nobody else could confirm. The unit(s) above are IN EFFECT NOW, before any check; each decision still waits for qa, and a refusal removes the unit. Have a second qa person confirm or refuse them as soon as one exists."
fi
