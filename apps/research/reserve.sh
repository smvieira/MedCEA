#!/usr/bin/env bash
# apps/research/reserve.sh — hold measurements out of the research lake (research sandbox
# Phase 2a; plan "Phase 2a", item 4).
#
#   apps/research/reserve.sh add --by <your qa username> --unit <UNIT> [--zone <ZONE>]
#                                --from <TIME> --to <TIME> --reason "<why, 10+ characters>"
#   apps/research/reserve.sh list
#
# A reservation keeps the unit's measurements (or one zone's) with a measurement time in
# [--from, --to) out of every research snapshot from then on: the export drops them before
# they reach the lake, so a model can later be judged on data it never saw. Reservations
# are never changed or removed (vault.reservation is append-only), and a range whose
# measurements are already in the lake is refused ("already exported: it is no longer
# held out"): make the reservation before the first export that would carry them.
#
# --by names the qa person making it, as their account in realm $KEYCLOAK_REALM: it must
# exist, be enabled and hold the realm role qa; its username and id (the token's sub)
# are recorded. Only qa reserves (the vault is qa's). TIME is ISO 8601, e.g. 2026-12-01
# or 2026-12-01T06:00 (UTC unless it carries an offset: 2026-12-01T06:00+01:00).
#
# add takes the deploy lock and asks for a typed `yes` (MEDCEA_CONFIRMED=1 skips it,
# for a caller that asked already; without a terminal it is refused). list is read-only.
# Both log to logs/app-research-reserve-<ts>.log. The SQL runs as rs_owner in the research
# database (psql in research-postgresql-0, SQL on stdin, the values as psql variables).
#
# Exit 0 done; 1 refused (the account, the database's checks, not confirmed, a held
# lock); 2 a usage error, the research database or Keycloak not reachable.
# Run from anywhere:  apps/research/reserve.sh list

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then
    sed -n "2,$(grep -n '^# Run from anywhere' "$0" | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'
    [[ -n "${1:-}" ]] && exit 0
    exit 2   # no arguments is a usage error
fi

YELLOW='\033[0;33m'; RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log()  { echo -e "${GREEN}[reserve]${NC} $*"; }
warn() { echo -e "${YELLOW}[reserve] $*${NC}" >&2; }
die()  { local c="$1"; shift; echo -e "${RED}[reserve] $*${NC}" >&2; exit "$c"; }
usage() { die 2 "$*  (apps/research/reserve.sh --help)"; }

CODE_RE='^[A-Za-z0-9_][A-Za-z0-9_-]*$'
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
# YYYY-MM-DD, optionally THH:MM[:SS[.frac]], optionally Z or ±HH:MM
TIME_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]{1,6})?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?$'

# ── Arguments (before the log and the lock, so a usage error needs neither) ──────
CMD="$1"; shift
BY=""; UNIT=""; ZONE=""; FROM=""; TO=""; REASON=""
case "$CMD" in
    add|list) ;;
    *) usage "unknown command '$CMD' (add or list)" ;;
esac
_value() { [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || usage "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    [[ "$CMD" == add ]] || usage "list takes no arguments"
    case "$1" in
        --by)     _value "$@"; BY="$2" ;;
        --unit)   _value "$@"; UNIT="$2" ;;
        --zone)   _value "$@"; ZONE="$2" ;;
        --from)   _value "$@"; FROM="$2" ;;
        --to)     _value "$@"; TO="$2" ;;
        --reason) _value "$@"; REASON="$2" ;;
        *) usage "unknown argument '$1'" ;;
    esac
    shift 2
done
if [[ "$CMD" == add ]]; then
    [[ -n "$BY" ]]     || usage "add needs --by <your qa username>: the reservation records who made it"
    [[ -n "$UNIT" ]]   || usage "add needs --unit <UNIT>"
    [[ -n "$FROM" && -n "$TO" ]] || usage "add needs --from and --to"
    [[ -n "$REASON" ]] || usage "add needs --reason \"<why>\""
    [[ "$BY" =~ $CODE_RE || "$BY" =~ ^[A-Za-z0-9_][A-Za-z0-9._@-]*$ ]] || usage "--by '$BY' is not a username"
    [[ "$UNIT" =~ $CODE_RE ]] || usage "--unit '$UNIT' is not a unit code (letters, digits, _ and -)"
    [[ -z "$ZONE" || "$ZONE" =~ $CODE_RE ]] || usage "--zone '$ZONE' is not a zone code (letters, digits, _ and -)"
    [[ "$FROM" =~ $TIME_RE ]] || usage "--from '$FROM' is not an ISO 8601 time (2026-12-01 or 2026-12-01T06:00[Z|+01:00])"
    [[ "$TO" =~ $TIME_RE ]]   || usage "--to '$TO' is not an ISO 8601 time (2026-12-01 or 2026-12-01T06:00[Z|+01:00])"
    _r="$(printf '%s' "$REASON" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    (( ${#_r} >= 10 )) || usage "--reason must be at least 10 characters: say why this range is held out"
    [[ "$REASON" != *[[:cntrl:]]* ]] || usage "--reason must be one line of text"
    # the order, in UTC (the database checks it again)
    _order="$(F="$FROM" T="$TO" python3 -c '
import datetime, os
def p(s):
    d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
print("ok" if p(os.environ["T"]) > p(os.environ["F"]) else "bad")' 2>/dev/null)" || _order=""
    [[ -n "$_order" ]] || usage "--from/--to: not a valid date or time"
    [[ "$_order" == ok ]] || usage "--to must be after --from"
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
source infra/lib-log.sh; medcea_log app-research-reserve   # logs/app-research-reserve-<ts>.log
if [[ "$CMD" == add ]]; then
    source infra/lib-lock.sh; medcea_lock
fi
source infra/lib-mk8s.sh
source apps/database/lib-db-apply.sh   # _dba_psql: psql in the pod, password read there

NAMESPACE="${NAMESPACE:-medcea}"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
RS_POD=research-postgresql-0
RS_DB=medcea_research
_DBA_NS="$RESEARCH_NAMESPACE"; _DBA_POD="$RS_POD"

_phase="$($KUBECTL get pod "$RS_POD" -n "$RESEARCH_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)" || _phase=""
[[ "$_phase" == Running ]] \
    || die 2 "The research database is not running (pod $RS_POD in $RESEARCH_NAMESPACE): ./apps/research/deploy.sh first."

# ── list ──────────────────────────────────────────────────────────────────────
if [[ "$CMD" == list ]]; then
    _rows="$(_dba_psql "$RS_DB" -qtA -F'|' -v ON_ERROR_STOP=1 -f - <<'SQL'
BEGIN READ ONLY;
SET LOCAL TimeZone = 'UTC';
SELECT r.reservation_id, r.unit_code, coalesce(r.zone_code, '*'),
       pg_catalog.to_char(r.from_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       pg_catalog.to_char(r.to_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       r.by_username, pg_catalog.to_char(r.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       pg_catalog.replace(r.reason, '|', '/')
  FROM vault.reservation r ORDER BY r.reservation_id;
COMMIT;
SQL
)" || die 2 "Cannot read vault.reservation in $RS_DB."
    if [[ -z "${_rows//[[:space:]]/}" ]]; then
        echo "No reservations: nothing is held out of the research lake."
        exit 0
    fi
    { echo "ID|UNIT|ZONE|FROM|TO|BY|MADE|REASON"; echo "$_rows"; } | column -t -s'|'
    echo "ZONE * = every zone of the unit; measurements in [FROM, TO) never reach the lake."
    exit 0
fi

# ── add: who reserves it (Keycloak) ───────────────────────────────────────────
KC_PORT=18094
KC_URL="http://localhost:$KC_PORT"
source infra/lib-keycloak-admin.sh
R="$KEYCLOAK_REALM"
TMP="$(mktemp -d)"; chmod 700 "$TMP"
PF_PID=""
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

# kc PATH → the body in $TMP/body, the HTTP status on stdout (000: no answer). The token
# goes to curl as a header on a pipe, never in its argv (as apps/iam/units.sh).
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
# find_user USERNAME → id<TAB>username<TAB>enabled of that exact account, or nothing
find_user() {
    local enc
    enc="$(U="$1" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["U"], safe=""))')"
    kc_ok "realms/$R/users?username=$enc&exact=true&briefRepresentation=false" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if isinstance(d, list):
    d = d[0] if d else None
if not d:
    sys.exit(0)
print("\t".join([d["id"], d["username"], "true" if d.get("enabled") else "false"]))'
}

_f="$(find_user "$BY")"
[[ -n "$_f" ]] || die 1 "--by: no account '$BY' in realm $R."
IFS=$'\t' read -r BY_SUB BY_NAME _by_en <<<"$_f"
[[ "$BY_SUB" =~ $UUID_RE ]] || die 1 "--by $BY_NAME: its account id '$BY_SUB' is not a uuid (no sub to record)."
[[ "$_by_en" == true ]] || die 1 "--by $BY_NAME is a disabled account: only an enabled qa account may reserve."
_qa="$(kc_ok "realms/$R/users/$BY_SUB/role-mappings/realm/composite" | python3 -c '
import json, sys
print("yes" if any(r.get("name") == "qa" for r in json.load(sys.stdin)) else "no")')"
[[ "$_qa" == yes ]] || die 1 "--by $BY_NAME does not hold the realm role qa: only qa reserves held-out data."

# ── Confirm ───────────────────────────────────────────────────────────────────
echo "Hold out of the research lake:"
echo "  unit    $UNIT"
echo "  zone    ${ZONE:-(every zone)}"
echo "  from    $FROM   (inclusive; UTC unless it says otherwise)"
echo "  to      $TO   (exclusive)"
echo "  reason  $REASON"
echo "  by      $BY_NAME ($BY_SUB)"
echo "This cannot be changed or removed afterwards."
if [[ "${MEDCEA_CONFIRMED:-}" != 1 ]]; then
    [[ -t 0 ]] || die 1 "No terminal to confirm on: run it at a terminal (or set MEDCEA_CONFIRMED=1 once you have confirmed it yourself). Nothing was written."
    read -r -p "Type yes to make the reservation: " _ans
    [[ "$_ans" == yes ]] || die 1 "Not confirmed; nothing was written."
fi

_out="$(_dba_psql "$RS_DB" -qtA -v ON_ERROR_STOP=1 \
        -v unit="$UNIT" -v zone="$ZONE" -v from_at="$FROM" -v to_at="$TO" -v reason="$REASON" \
        -v by_username="$BY_NAME" -v by_sub="$BY_SUB" -f - 2>&1 <<'SQL'
SET TimeZone = 'UTC';
SET ROLE rs_owner;
SELECT vault.reserve(:'unit', NULLIF(:'zone', ''), CAST(:'from_at' AS timestamptz), CAST(:'to_at' AS timestamptz),
                     :'reason', :'by_username', CAST(:'by_sub' AS uuid));
SQL
)" || {
    _msg="$(grep -m1 -E 'ERROR:' <<<"$_out" | sed 's/^.*ERROR: *//')"
    die 1 "Refused by the research database: ${_msg:-$_out}. Nothing was written."
}
_id="$(grep -E '^[0-9]+$' <<<"$_out" | tail -n1)"
[[ -n "$_id" ]] || die 1 "The research database answered no reservation id: $_out"
log "Reservation #$_id made: unit $UNIT ${ZONE:+zone $ZONE }[$FROM, $TO) is held out of every snapshot from now on (apps/research/reserve.sh list)."
